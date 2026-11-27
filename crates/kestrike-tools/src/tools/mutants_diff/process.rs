//! Signals and child processes.
//!
//! The handlers of SIGINT, SIGTERM and SIGHUP record the first of them in [`INTERRUPT`]; a later signal
//! changes nothing. The run reads the record between its steps and while it waits for a child, so a signal
//! that arrives while a child is being started is acted on once that child has started. A supervised child
//! leads a new session and group, starts with no signal blocked, and receives SIGTERM when the thread that
//! started it ends; the run starts every child from its main thread.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::Duration;

use super::stop::{Fault, Stop};

pub const SIGNALS: [i32; 3] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP];
/// Each of the two waits for the group leader after SIGTERM and after SIGKILL, and the wait for a plain
/// child after SIGKILL.
const GRACE: Duration = Duration::from_secs(10);
/// The longest time between two readings of the interrupt while the run waits for a child.
const POLL: Duration = Duration::from_millis(20);

/// The first handled signal, or 0 while none has arrived.
#[derive(Debug, Default)]
pub struct Interrupt(AtomicI32);

/// The handlers [`install_handlers`] installs record into this value.
pub static INTERRUPT: Interrupt = Interrupt::new();

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

    /// `check` is the stop of a recorded signal.
    pub(super) fn check(&self) -> Result<(), Stop> {
        self.recorded()
            .map_or(Ok(()), |signal| Err(Stop::interrupted(signal)))
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

/// `install_handlers` makes each of [`SIGNALS`] that is not ignored record into [`INTERRUPT`]. A signal
/// ignored at the start stays ignored, so a run under `nohup` outlives its terminal.
///
/// # Errors
///
/// Reading a disposition or installing a handler fails.
pub fn install_handlers() -> io::Result<()> {
    for signal in SIGNALS {
        if ignored(signal)? {
            continue;
        }
        // SAFETY: the action only calls `Interrupt::record`, one atomic compare-exchange on a static,
        // which is async-signal-safe.
        unsafe { signal_hook::low_level::register(signal, move || INTERRUPT.record(signal)) }?;
    }
    Ok(())
}

/// `ignore_signals` sets each of [`SIGNALS`] to be ignored, so the children started after it inherit that
/// disposition.
///
/// # Errors
///
/// Setting a disposition fails.
pub fn ignore_signals() -> io::Result<()> {
    for signal in SIGNALS {
        // SAFETY: all-zero bytes are a valid `sigaction`; with `SIG_IGN` as its handler and an empty mask
        // it is a disposition that ignores the signal, and the old action is not read.
        let status = unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = libc::SIG_IGN;
            libc::sigaction(signal, &action, std::ptr::null_mut())
        };
        if status != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// `exit_code` is the child's exit status, or the negated number of the signal that ended it.
pub(super) fn exit_code(status: ExitStatus) -> i32 {
    status
        .code()
        .or_else(|| status.signal().map(|signal| -signal))
        .expect("an exited child has a code or a signal")
}

/// A started child that a reaper thread waits for. `ended` receives what the wait returned once the child
/// has exited; until then the child's process id stays its own.
struct Reaped<T> {
    pid: libc::pid_t,
    ended: Receiver<io::Result<T>>,
    exited: bool,
    result: Option<io::Result<T>>,
}

impl<T: Send + 'static> Reaped<T> {
    fn new(child: Child, wait: impl FnOnce(Child) -> io::Result<T> + Send + 'static) -> Self {
        let pid = libc::pid_t::try_from(child.id()).expect("a process id fits pid_t");
        let (send, ended) = mpsc::channel();
        thread::spawn(move || {
            let _ = send.send(wait(child));
        });
        Self {
            pid,
            ended,
            exited: false,
            result: None,
        }
    }

    /// `exited_within` waits up to `limit` for the child to exit.
    fn exited_within(&mut self, limit: Duration) -> bool {
        if !self.exited {
            self.result = match self.ended.recv_timeout(limit) {
                Ok(result) => Some(result),
                Err(RecvTimeoutError::Timeout) => return false,
                Err(RecvTimeoutError::Disconnected) => Some(Err(io::Error::other(
                    "the reaper thread ended without a result",
                ))),
            };
            self.exited = true;
        }
        true
    }

    /// `wait` returns what the wait returned once the child exits, or the interruption of a signal recorded
    /// in `interrupt` first.
    fn wait(&mut self, interrupt: &Interrupt) -> Result<io::Result<T>, Stop> {
        loop {
            interrupt.check()?;
            if self.exited_within(POLL) {
                return Ok(self.result.take().expect("a child's result is taken once"));
            }
        }
    }
}

/// `signal_group` sends `signal` to the process group `group` and returns false when no member is left.
fn signal_group(group: libc::pid_t, signal: i32) -> bool {
    // SAFETY: `killpg` takes two integers and touches no memory of the caller.
    let sent = unsafe { libc::killpg(group, signal) } == 0;
    sent || io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

/// `stop_group` stops the group the child leads. When the group is gone at SIGTERM it returns. Otherwise
/// it waits up to [`GRACE`] for the leader, sends SIGKILL to the group if the leader still runs and waits
/// up to [`GRACE`] again, and ends with SIGKILL to the group in every case. A member the leader left
/// behind after it exited gets SIGTERM and SIGKILL with no wait between them.
fn stop_group<T: Send + 'static>(child: &mut Reaped<T>) {
    for signal in [libc::SIGTERM, libc::SIGKILL] {
        if !signal_group(child.pid, signal) {
            return;
        }
        if child.exited_within(GRACE) {
            break;
        }
    }
    signal_group(child.pid, libc::SIGKILL);
}

/// `lead_new_session` makes the child started by `command` lead a new session and receive SIGTERM when
/// the starting thread ends; a child whose parent already changed exits 1 before it runs the program.
fn lead_new_session(command: &mut Command) {
    // SAFETY: `getpid` takes no argument and cannot fail.
    let parent = unsafe { libc::getpid() };
    // SAFETY: the hook runs in the forked child before `exec` and calls only `setsid`, `prctl`, `getppid`
    // and `_exit`, which are async-signal-safe and touch no memory shared with the parent.
    unsafe {
        command.pre_exec(move || {
            libc::setsid();
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM, 0, 0, 0);
            if libc::getppid() != parent {
                libc::_exit(1);
            }
            Ok(())
        });
    }
}

/// `supervise` runs `argv` with standard input from `/dev/null`, standard output and standard error written
/// to the two files and the environment `env`, in a new session, and returns its exit code as
/// [`exit_code`] gives it. A signal recorded in `interrupt` before the child started or while it runs
/// stops the child's group and returns the interruption. Once the leader has exited, the members of its
/// group it left behind are stopped.
///
/// # Errors
///
/// A recorded signal, or an output file, the start or the wait that fails.
pub fn supervise(
    interrupt: &Interrupt,
    argv: &[&OsStr],
    stdout: &Path,
    stderr: &Path,
    cwd: Option<&Path>,
    env: &[(OsString, OsString)],
) -> Result<i32, Stop> {
    let create = |path: &Path| {
        File::create(path).map_err(|error| Stop::failed(&Fault::os(&error, Some(path.as_os_str()))))
    };
    let (out, err) = (create(stdout)?, create(stderr)?);
    let mut command = Command::new(argv[0]);
    command
        .args(&argv[1..])
        .stdin(Stdio::null())
        .stdout(out)
        .stderr(err)
        .env_clear()
        .envs(env.iter().cloned());
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    lead_new_session(&mut command);
    let child = command
        .spawn()
        .map_err(|error| Stop::failed(&Fault::os(&error, Some(argv[0]))))?;
    let mut child = Reaped::new(child, |mut child| child.wait());
    let ended = child.wait(interrupt);
    stop_group(&mut child);
    match ended? {
        Ok(status) => Ok(exit_code(status)),
        Err(error) => Err(Stop::failed(&Fault::os(&error, None))),
    }
}

/// `capture` runs `command` with standard input inherited and returns its output. A signal recorded in
/// `interrupt` while it runs kills the child with SIGKILL, waits up to [`GRACE`] for it and returns the
/// interruption.
///
/// # Errors
///
/// The outer error is a recorded signal; the inner one a start or a wait that fails.
pub(super) fn capture(
    command: &mut Command,
    interrupt: &Interrupt,
) -> Result<io::Result<Output>, Stop> {
    let spawned = command
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let child = match spawned {
        Ok(child) => child,
        Err(error) => return Ok(Err(error)),
    };
    let mut child = Reaped::new(child, Child::wait_with_output);
    let ended = child.wait(interrupt);
    if ended.is_err() && !child.exited_within(Duration::ZERO) {
        // SAFETY: `kill` takes two integers; the child is not reaped yet, so its process id is its own.
        unsafe { libc::kill(child.pid, libc::SIGKILL) };
        child.exited_within(GRACE);
    }
    ended
}
