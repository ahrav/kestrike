//! Signals and child processes that two tools share: the record of the first handled signal and its
//! handlers, the reading of a child's exit, the wait for a child that sees a recorded signal, and the
//! captured child.
//!
//! The handlers of SIGINT, SIGTERM and SIGHUP record the first of them in [`INTERRUPT`]; a later signal
//! changes nothing. A tool reads the record between its steps and while it waits for a child, so a signal
//! that arrives while a child is being started is acted on once that child has started. A wait polls the
//! child and the record at pauses that start at 0.5 ms and double up to 20 ms, on the monotonic clock.

use std::io::{self, Read};
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub const SIGNALS: [i32; 3] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP];
/// The wait for a captured child after SIGKILL, and each of the two waits of `mutants-diff` for its
/// group leader, after SIGTERM and after SIGKILL.
pub(crate) const GRACE: Duration = Duration::from_secs(10);
/// The longest pause between two checks of a child and of the record while a tool waits; the pause
/// starts at [`FIRST_PAUSE`] and doubles up to this bound.
const POLL: Duration = Duration::from_millis(20);
const FIRST_PAUSE: Duration = Duration::from_micros(500);

/// The first handled signal, or 0 while none has arrived.
#[derive(Debug, Default)]
pub struct Interrupt(AtomicI32);

/// The handlers [`install_handlers`] installs record into this value.
pub static INTERRUPT: Interrupt = Interrupt::new();

/// A recorded signal that ended a step: the signal's number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Interrupted(pub i32);

impl Interrupt {
    pub const fn new() -> Self {
        Self(AtomicI32::new(0))
    }

    /// `record` keeps `signal` unless a signal is already recorded. It makes no allocation and takes no
    /// lock, so a signal handler may call it.
    pub fn record(&self, signal: i32) {
        let _ = self
            .0
            .compare_exchange(0, signal, Ordering::SeqCst, Ordering::SeqCst);
    }

    pub fn recorded(&self) -> Option<i32> {
        Some(self.0.load(Ordering::SeqCst)).filter(|&signal| signal != 0)
    }

    /// `check` is the interruption of a recorded signal.
    ///
    /// # Errors
    ///
    /// A signal is recorded.
    pub fn check(&self) -> Result<(), Interrupted> {
        self.recorded()
            .map_or(Ok(()), |signal| Err(Interrupted(signal)))
    }
}

/// `ignored` holds when the signal's disposition is to ignore it.
fn ignored(signal: i32) -> io::Result<bool> {
    // SAFETY: `sigaction` is a plain C struct for which all-zero bytes are a valid value. A null new
    // action makes `sigaction` only write the current disposition into `current`, which outlives the call.
    let (status, current) = unsafe {
        let mut current: libc::sigaction = std::mem::zeroed();
        let status = libc::sigaction(signal, std::ptr::null(), &mut current);
        (status, current)
    };
    if status != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(current.sa_sigaction == libc::SIG_IGN)
}

/// `handled_set` is the signal set that holds each of [`SIGNALS`].
pub(crate) fn handled_set() -> libc::sigset_t {
    // SAFETY: `sigemptyset` initializes the set that `set` points to, and `sigaddset` adds a valid signal
    // number to that initialized set; neither can fail on these arguments.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for signal in SIGNALS {
            libc::sigaddset(&mut set, signal);
        }
        set
    }
}

/// `install_handlers` makes each of [`SIGNALS`] that is not ignored record into [`INTERRUPT`], then
/// unblocks the three in the calling thread, so a run started with one of them blocked still receives it
/// and the threads and children started from that thread start with none of the three blocked. A signal
/// ignored at the start stays ignored, so a run under `nohup` outlives its terminal.
///
/// After blocking [`SIGNALS`], the calling thread attempts to unblock them whether registration
/// succeeds or fails.
///
/// # Errors
///
/// Reading a disposition, installing a handler or changing the signal mask fails.
pub fn install_handlers() -> io::Result<()> {
    let handled = handled_set();
    mask(libc::SIG_BLOCK, &handled)?;
    let installed = SIGNALS.into_iter().try_for_each(|signal| {
        if ignored(signal)? {
            return Ok(());
        }
        // SAFETY: the action only calls `Interrupt::record`, one atomic compare-exchange on a static,
        // which is async-signal-safe.
        unsafe { signal_hook::low_level::register(signal, move || INTERRUPT.record(signal)) }
            .map(drop)
    });
    let unblocked = mask(libc::SIG_UNBLOCK, &handled);
    installed.and(unblocked)
}

fn mask(how: libc::c_int, set: &libc::sigset_t) -> io::Result<()> {
    // SAFETY: `set` is an initialized signal set that outlives the call, and a null old set makes
    // `pthread_sigmask` write nothing back.
    let status = unsafe { libc::pthread_sigmask(how, set, std::ptr::null_mut()) };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status));
    }
    Ok(())
}

/// `child_defaults` resets caught signals in [`SIGNALS`] to `SIG_DFL` and unblocks the signals in
/// `handled`; it calls only async-signal-safe functions, so a `pre_exec` hook may call it.
///
/// # Errors
///
/// A `sigaction` or `sigprocmask` call fails.
pub(crate) fn child_defaults(handled: &libc::sigset_t) -> io::Result<()> {
    for signal in SIGNALS {
        // SAFETY: zero is a valid value of `current`; the query writes the disposition into it, and
        // the update reads it with `sa_sigaction` set to `SIG_DFL`. `sigaction` is async-signal-safe.
        unsafe {
            let mut current: libc::sigaction = std::mem::zeroed();
            if libc::sigaction(signal, std::ptr::null(), &mut current) != 0 {
                return Err(io::Error::last_os_error());
            }
            if current.sa_sigaction != libc::SIG_IGN && current.sa_sigaction != libc::SIG_DFL {
                current.sa_sigaction = libc::SIG_DFL;
                if libc::sigaction(signal, &current, std::ptr::null_mut()) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
        }
    }
    // SAFETY: `handled` is an initialized signal set, and a null old set makes `sigprocmask` write
    // nothing back; the call is async-signal-safe.
    if unsafe { libc::sigprocmask(libc::SIG_UNBLOCK, handled, std::ptr::null_mut()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `ignore_file_size_signal` sets SIGXFSZ to be ignored in this process, so a write past the soft
/// file size limit returns `EFBIG` to its caller and ends no process.
///
/// # Errors
///
/// The disposition cannot be set.
pub(crate) fn ignore_file_size_signal() -> io::Result<()> {
    // SAFETY: `signal` takes a signal number and a disposition constant and touches no memory of the
    // caller.
    if unsafe { libc::signal(libc::SIGXFSZ, libc::SIG_IGN) } == libc::SIG_ERR {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `file_size_signal_default` sets SIGXFSZ back to its default action; it calls only
/// async-signal-safe functions, so a `pre_exec` hook may call it before a child runs its program.
///
/// # Errors
///
/// The disposition cannot be set.
pub(crate) fn file_size_signal_default() -> io::Result<()> {
    // SAFETY: `signal` takes a signal number and a disposition constant, touches no memory of the
    // caller, and is async-signal-safe.
    if unsafe { libc::signal(libc::SIGXFSZ, libc::SIG_DFL) } == libc::SIG_ERR {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `exit_code` is the child's exit status, or the negated number of the signal that ended it.
pub(crate) fn exit_code(status: ExitStatus) -> i32 {
    status
        .code()
        .or_else(|| status.signal().map(|signal| -signal))
        .expect("an exited child has a code or a signal")
}

/// `exited_within` waits up to `limit` for the child to exit and returns its status, polling it with a
/// pause that grows to [`POLL`]; an `interrupt` that holds a signal ends the wait early with `Ok(None)`.
///
/// # Errors
///
/// The wait fails.
pub(crate) fn exited_within(
    child: &mut Child,
    limit: Duration,
    interrupt: Option<&Interrupt>,
) -> io::Result<Option<ExitStatus>> {
    let start = Instant::now();
    let mut pause = FIRST_PAUSE;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        let waited = start.elapsed();
        if waited >= limit || interrupt.is_some_and(|interrupt| interrupt.recorded().is_some()) {
            return Ok(None);
        }
        thread::sleep(pause.min(limit - waited));
        pause = (pause * 2).min(POLL);
    }
}

fn drain(
    stream: Option<impl Read + Send + 'static>,
) -> io::Result<JoinHandle<io::Result<Vec<u8>>>> {
    thread::Builder::new().spawn(move || {
        let mut bytes = Vec::new();
        if let Some(mut stream) = stream {
            stream.read_to_end(&mut bytes)?;
        }
        Ok(bytes)
    })
}

fn joined(reader: JoinHandle<io::Result<Vec<u8>>>) -> io::Result<Vec<u8>> {
    reader.join().expect("a reader thread returns its bytes")
}

/// `capture` runs `command` with standard input inherited and returns its output once the child has
/// exited and both of its output pipes have closed. A signal recorded in `interrupt` before then kills a
/// child that still runs with SIGKILL, waits up to [`GRACE`] for it and returns the interruption, leaving
/// a pipe that a descendant holds to its reader.
/// The kill by process id is sound only while the caller holds the child unreaped and is its one
/// waiter: no other code of the process waits for any child, and SIGCHLD is not ignored.
///
/// # Errors
///
/// The outer error is a recorded signal; the inner one a start, a reader thread, a read or a wait that
/// fails.
pub(crate) fn capture(
    command: &mut Command,
    interrupt: &Interrupt,
) -> Result<io::Result<Output>, Interrupted> {
    let spawned = command
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    match spawned {
        Ok(child) => captured(child, interrupt),
        Err(error) => Ok(Err(error)),
    }
}

/// `captured` reads a started child's piped output streams and waits for it as [`capture`] does.
/// The kill by process id is sound only while the caller holds the child unreaped and is its one
/// waiter: no other code of the process waits for any child, and SIGCHLD is not ignored.
///
/// # Errors
///
/// The outer error is a recorded signal; the inner one a reader thread, a read or a wait that fails.
pub(crate) fn captured(
    mut child: Child,
    interrupt: &Interrupt,
) -> Result<io::Result<Output>, Interrupted> {
    let readers = drain(child.stdout.take()).and_then(|out| Ok((out, drain(child.stderr.take())?)));
    let (out, err) = match readers {
        Ok(readers) => readers,
        Err(error) => {
            let _ = child.kill();
            let _ = exited_within(&mut child, GRACE, None);
            return Ok(Err(error));
        }
    };
    let mut status = None;
    let mut pause = FIRST_PAUSE;
    loop {
        if status.is_none() {
            match child.try_wait() {
                Ok(exited) => status = exited,
                Err(error) => return Ok(Err(error)),
            }
        }
        if let Some(status) = status
            && out.is_finished()
            && err.is_finished()
        {
            let output = joined(out).and_then(|stdout| Ok((stdout, joined(err)?)));
            return Ok(output.map(|(stdout, stderr)| Output {
                status,
                stdout,
                stderr,
            }));
        }
        if let Err(stop) = interrupt.check() {
            if status.is_none() {
                let _ = child.kill();
                let _ = exited_within(&mut child, GRACE, None);
            }
            return Err(stop);
        }
        thread::sleep(pause);
        pause = (pause * 2).min(POLL);
    }
}

#[cfg(test)]
#[path = "process_tests.rs"]
mod tests;
