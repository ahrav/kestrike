//! A tool [`SysfsKernel`](super::host::SysfsKernel) started, and the
//! envelope its run stays inside on Linux.
//!
//! [`Running::feed`] gives the tool its input: it writes what the tool's
//! input pipe takes at once, and closes the pipe when that is all of it,
//! so the tool acts on its input from then on. [`Running::run`] writes the
//! rest of the input while it drains the tool's standard output and error,
//! all on one thread through `poll(2)` over nonblocking pipes, so the run
//! returns within its bounds even when the tool leaves its input unread or
//! fills either pipe. A tool that fills an output pipe between its feed and
//! its run waits there until the run drains it. Each captured stream holds
//! at most its byte bound, and the run reaches its total deadline 30
//! seconds after spawn. A tool past either bound is killed, then awaited for
//! its reap for up to the cleanup bound, so a refused run returns within
//! the deadline plus that bound. The refusal is a [`Stopped`] that records
//! the tool's PID, the bound it passed and whether the reap completed.
//!
//! The run's wait for a tool's exit and the stop's wait for its reap each
//! sleep in `poll(2)` on the tool's PID file descriptor, which the kernel
//! reports readable once the tool has exited, so each ends at the exit or
//! at its bound. The drop's reap of a killed tool blocks in `wait` until
//! the exit.
//!
//! A stopped tool may already have changed host state. The refusal leaves
//! that state as the tool left it, and the caller reconciles it under the
//! binder's safety procedure.

use std::fmt;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::process::{Child, ChildStdin, ExitStatus};
use std::time::{Duration, Instant};

/// The envelope one tool run stays inside.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Limits {
    /// The most standard-output bytes a run captures.
    pub(crate) stdout: usize,
    /// The most standard-error bytes a run captures.
    pub(crate) stderr: usize,
    /// The run's time from spawn to its exit.
    pub(crate) total: Duration,
    /// How long a stopped tool's reap is awaited after its kill.
    pub(crate) cleanup: Duration,
}

/// The production envelope: 1 MiB of each stream, 30 seconds from spawn
/// and 5 seconds of reaping after a kill.
pub(crate) const LIMITS: Limits = Limits {
    stdout: 1 << 20,
    stderr: 1 << 20,
    total: Duration::from_secs(30),
    cleanup: Duration::from_secs(5),
};

/// The bound a stopped tool passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Bound {
    /// The run reached its total deadline while one of the tool's pipes was
    /// still open or its exit was still pending.
    Deadline,
    /// The tool wrote more standard output than the run captures.
    Stdout,
    /// The tool wrote more standard error than the run captures.
    Stderr,
}

/// A tool killed for passing `bound`: its PID, and whether its reap
/// completed within the cleanup bound. Its effect on the host is unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Stopped {
    pub(crate) pid: u32,
    pub(crate) bound: Bound,
    pub(crate) reaped: bool,
}

impl fmt::Display for Stopped {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bound = match self.bound {
            Bound::Deadline => "passed its deadline",
            Bound::Stdout => "passed its standard-output bound",
            Bound::Stderr => "passed its standard-error bound",
        };
        let reap = if self.reaped {
            "killed and reaped"
        } else {
            "killed, its reap incomplete"
        };
        write!(
            f,
            "tool {} {bound}: {reap}; its host effect is unknown",
            self.pid
        )
    }
}

impl std::error::Error for Stopped {}

impl Stopped {
    /// The refusal that carries this record: `TimedOut` for the deadline,
    /// `FileTooLarge` for an output bound.
    fn error(self) -> io::Error {
        let kind = match self.bound {
            Bound::Deadline => io::ErrorKind::TimedOut,
            Bound::Stdout | Bound::Stderr => io::ErrorKind::FileTooLarge,
        };
        io::Error::new(kind, self)
    }
}

/// A started tool, its spawn time and the input it was fed; a refused run
/// stays inside [`LIMITS`]. Dropping it before
/// [`finish`](super::host::Fed::finish) completes kills and reaps the tool.
pub(crate) struct Running {
    child: Option<Child>,
    started: Instant,
    input: Input,
}

/// A tool's input and the write of it to the tool's standard input.
#[derive(Default)]
struct Input {
    bytes: Vec<u8>,
    /// How many of `bytes` the pipe has taken.
    sent: usize,
    /// The tool's standard input, open while bytes remain to write.
    pipe: Option<ChildStdin>,
    /// The error that ended the write early.
    failed: Option<io::Error>,
}

impl Input {
    /// Writes what the pipe takes of the unsent bytes without waiting, and
    /// closes the pipe once every byte is written or a write fails.
    fn write(&mut self) {
        let Some(pipe) = self.pipe.as_mut() else {
            return;
        };
        match pipe.write(&self.bytes[self.sent..]) {
            Ok(count) => self.sent += count,
            Err(error) if blocked(&error) => {}
            Err(error) => {
                self.failed = Some(error);
                self.pipe = None;
            }
        }
        if self.sent == self.bytes.len() {
            self.pipe = None;
        }
    }

    /// How the write ended.
    ///
    /// # Errors
    ///
    /// The error that ended the write, or `WriteZero` for input left
    /// unwritten without one.
    fn written(&mut self) -> io::Result<()> {
        match self.failed.take() {
            Some(error) => Err(error),
            None if self.sent < self.bytes.len() => Err(io::ErrorKind::WriteZero.into()),
            None => Ok(()),
        }
    }
}

/// One of the tool's two output pipes while the run still uses it.
struct Pipe<T> {
    pipe: Option<T>,
}

impl<T: AsRawFd> Pipe<T> {
    /// `pipe`, switched to nonblocking I/O.
    ///
    /// # Errors
    ///
    /// The `fcntl` error.
    fn new(pipe: Option<T>) -> io::Result<Self> {
        if let Some(pipe) = &pipe {
            nonblocking(pipe.as_raw_fd())?;
        }
        Ok(Self { pipe })
    }

    fn fd(&self) -> Option<RawFd> {
        self.pipe.as_ref().map(AsRawFd::as_raw_fd)
    }
}

/// Sets `O_NONBLOCK` on `fd`.
///
/// # Errors
///
/// The `fcntl` error.
fn nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: `fd` is a pipe descriptor the caller's `ChildStd*` owns for
    // the call's duration; `F_GETFL` and `F_SETFL` read and set its status
    // flags and touch no memory.
    let set = unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 {
            flags
        } else {
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK)
        }
    };
    if set < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

impl Running {
    /// `child`, spawned just now.
    pub(crate) fn new(child: Child) -> Self {
        Self {
            child: Some(child),
            started: Instant::now(),
            input: Input::default(),
        }
    }

    /// Gives the tool `input` as its whole standard input: writes what the
    /// tool's input pipe takes without waiting, which is all of an input of
    /// at most `PIPE_BUF` bytes, and closes the pipe when that is all of
    /// `input`, so the tool reads the input's end. [`run`](Self::run)
    /// writes the rest. An error setting the pipe nonblocking or writing to
    /// it returns from `run` as the input write's error.
    pub(crate) fn feed(&mut self, input: &str) {
        let pipe = self.child.as_mut().and_then(|child| child.stdin.take());
        self.input = Input {
            bytes: input.as_bytes().to_vec(),
            ..Input::default()
        };
        match pipe.as_ref().map(|pipe| nonblocking(pipe.as_raw_fd())) {
            Some(Err(error)) => self.input.failed = Some(error),
            _ => self.input.pipe = pipe,
        }
        self.input.write();
    }

    /// Runs the fed tool to its exit inside [`LIMITS`]: writes the input
    /// [`feed`](Self::feed) left unwritten, closing standard input once it
    /// is written, while it captures both output streams, then waits for
    /// the exit. A tool never fed reads an empty input. A run past a bound
    /// ends in the stop's kill and bounded reap, which releases the tool
    /// with [`Stopped::reaped`] recording whether its exit was observed; a
    /// run that returns on a `pidfd_open`, `poll`, `fcntl` or wait error
    /// keeps the tool for the drop's kill and reap. A tool that exits while
    /// a background child it started holds an output pipe open runs to the
    /// deadline.
    ///
    /// A nonzero exit takes precedence over an error writing the input.
    ///
    /// # Errors
    ///
    /// `Other` with the captured standard error for a nonzero exit, the
    /// error of a write that left the input short, `TimedOut` with a
    /// [`Stopped`] at the deadline, `FileTooLarge` with a [`Stopped`] for
    /// an output past its bound, or a `pidfd_open`, `poll`, `fcntl` or wait
    /// error.
    pub(crate) fn run(&mut self) -> io::Result<String> {
        let deadline = self.started + LIMITS.total;
        let child = self.child.as_mut().ok_or(io::ErrorKind::Other)?;
        drop(child.stdin.take());
        let (stdout, stderr) = match capture(child, &mut self.input, deadline) {
            Ok(captured) => captured,
            Err(Capture::Stopped(bound)) => return Err(self.stop(bound)),
            Err(Capture::Failed(error)) => return Err(error),
        };
        let Some(status) = exit(child, deadline)? else {
            return Err(self.stop(Bound::Deadline));
        };
        if !status.success() {
            return Err(io::Error::other(
                String::from_utf8_lossy(&stderr).into_owned(),
            ));
        }
        self.input.written()?;
        Ok(String::from_utf8(stdout)
            .unwrap_or_else(|invalid| String::from_utf8_lossy(invalid.as_bytes()).into_owned()))
    }

    /// Kills the tool for passing `bound`, awaits its reap for the cleanup
    /// bound, and returns the refusal recording both. A wait that fails
    /// records the reap as incomplete.
    fn stop(&mut self, bound: Bound) -> io::Error {
        let Some(mut child) = self.child.take() else {
            return io::ErrorKind::Other.into();
        };
        let _killed = child.kill();
        let until = Instant::now() + LIMITS.cleanup;
        let reaped = matches!(exit(&mut child, until), Ok(Some(_)));
        Stopped {
            pid: child.id(),
            bound,
            reaped,
        }
        .error()
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _killed = child.kill();
            let _reaped = child.wait();
        }
    }
}

/// Why a capture ended before the tool's pipes closed.
enum Capture {
    Stopped(Bound),
    Failed(io::Error),
}

/// Writes the unsent part of `input` to `child` and drains both its output
/// streams until every pipe closes, by `deadline`, each stream within its
/// bound in [`LIMITS`], and returns the two streams. The write's outcome
/// shows in [`Input::written`].
///
/// # Errors
///
/// `Stopped(Deadline)` at `deadline`, `Stopped(Stdout)` or
/// `Stopped(Stderr)` for a stream past its bound, and `Failed` with the
/// `fcntl` or `poll` error.
fn capture(
    child: &mut Child,
    input: &mut Input,
    deadline: Instant,
) -> Result<(Vec<u8>, Vec<u8>), Capture> {
    let failed = Capture::Failed;
    let mut stdout = Pipe::new(child.stdout.take()).map_err(failed)?;
    let mut stderr = Pipe::new(child.stderr.take()).map_err(failed)?;
    let (mut out, mut err) = (Vec::new(), Vec::new());
    while input.pipe.is_some() || stdout.pipe.is_some() || stderr.pipe.is_some() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(Capture::Stopped(Bound::Deadline));
        }
        let ready = poll(
            [
                (input.pipe.as_ref().map(AsRawFd::as_raw_fd), libc::POLLOUT),
                (stdout.fd(), libc::POLLIN),
                (stderr.fd(), libc::POLLIN),
            ],
            left,
        )
        .map_err(failed)?;
        if ready[0] {
            input.write();
        }
        drain(
            ready[1],
            &mut stdout,
            &mut out,
            LIMITS.stdout,
            Bound::Stdout,
        )?;
        drain(
            ready[2],
            &mut stderr,
            &mut err,
            LIMITS.stderr,
            Bound::Stderr,
        )?;
    }
    Ok((out, err))
}

/// Reads what `pipe` holds when `ready`, appending it to `captured`, whose
/// capacity stays within `limit`, and closes the pipe at its end or on a
/// read error.
///
/// # Errors
///
/// `Stopped(bound)` for a read that would carry the stream past `limit`
/// bytes.
fn drain<T: Read>(
    ready: bool,
    pipe: &mut Pipe<T>,
    captured: &mut Vec<u8>,
    limit: usize,
    bound: Bound,
) -> Result<(), Capture> {
    let Some(stream) = pipe.pipe.as_mut().filter(|_| ready) else {
        return Ok(());
    };
    let mut chunk = [0; 8192];
    // One byte past the bound shows the stream passed it.
    let room = (limit + 1 - captured.len()).min(chunk.len());
    match stream.read(&mut chunk[..room]) {
        Ok(0) => pipe.pipe = None,
        Ok(count) if captured.len() + count > limit => return Err(Capture::Stopped(bound)),
        Ok(count) => {
            // Growth stops at the bound, so a stream's capture requests at
            // most `limit` bytes of capacity.
            let wanted = (captured.len() + count).max(captured.capacity().saturating_mul(2));
            captured.reserve_exact(wanted.min(limit) - captured.len());
            captured.extend_from_slice(&chunk[..count]);
        }
        Err(error) if blocked(&error) => {}
        Err(_) => pipe.pipe = None,
    }
    Ok(())
}

/// Whether `error` means the call would block or was interrupted, so the
/// next poll retries it.
fn blocked(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}

/// Waits up to `left` for any of `fds` to be ready for its event, and
/// returns which are ready; a closed or failed descriptor counts as ready,
/// so its next read or write reports it, and an absent one never is.
///
/// # Errors
///
/// The `poll` error other than `EINTR`, which returns no descriptor ready.
fn poll<const N: usize>(
    fds: [(Option<RawFd>, libc::c_short); N],
    left: Duration,
) -> io::Result<[bool; N]> {
    let mut polled = fds.map(|(fd, events)| libc::pollfd {
        fd: fd.unwrap_or(-1),
        events,
        revents: 0,
    });
    let millis = libc::c_int::try_from(left.as_millis().max(1)).unwrap_or(libc::c_int::MAX);
    // SAFETY: `polled` is an initialized array of `N` `pollfd` records that
    // outlives the call, and `poll` writes only their `revents`. Each
    // nonnegative descriptor is owned by the `Input`, a `Pipe` or an
    // `OwnedFd` the caller holds across the call; `poll` skips a negative
    // one.
    let count = unsafe { libc::poll(polled.as_mut_ptr(), polled.len() as libc::nfds_t, millis) };
    if count < 0 {
        let error = io::Error::last_os_error();
        return match error.kind() {
            io::ErrorKind::Interrupted => Ok([false; N]),
            _ => Err(error),
        };
    }
    Ok(polled.map(|fd| fd.fd >= 0 && fd.revents != 0))
}

/// A descriptor of `child`'s process, which `poll` reports readable once
/// that process has exited. `pidfd_open` needs Linux 5.3 or later.
///
/// # Errors
///
/// The `pidfd_open` error.
fn pidfd(child: &Child) -> io::Result<OwnedFd> {
    let pid = libc::pid_t::try_from(child.id()).map_err(io::Error::other)?;
    // SAFETY: `pidfd_open` takes a PID and flags by value and touches no
    // memory. `exit` calls this only after a `try_wait` found `child`
    // running, so the PID names it.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = RawFd::try_from(fd).map_err(io::Error::other)?;
    // SAFETY: `fd` is the open descriptor `pidfd_open` just returned, which
    // nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Waits for `child`'s exit until `deadline`: a child found running sleeps
/// this thread in `poll` on its PID file descriptor until it exits or the
/// deadline comes; `None` when it is still running then.
///
/// # Errors
///
/// The `pidfd_open`, `poll` or wait error.
fn exit(child: &mut Child, deadline: Instant) -> io::Result<Option<ExitStatus>> {
    if let Some(status) = child.try_wait()? {
        return Ok(Some(status));
    }
    let exited = pidfd(child)?;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Ok(None);
        }
        let [exited] = poll([(Some(exited.as_raw_fd()), libc::POLLIN)], left)?;
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if exited {
            // The kernel reports a traced child's exit here before its
            // tracer releases the status, and the descriptor stays
            // readable until then.
            std::thread::sleep(left.min(Duration::from_millis(1)));
        }
    }
}
