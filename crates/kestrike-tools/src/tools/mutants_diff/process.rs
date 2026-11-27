//! Signals and child processes.
//!
//! The handlers of SIGINT, SIGTERM and SIGHUP record the first of them in [`INTERRUPT`]; a later signal
//! changes nothing. The run reads the record between its steps and while it waits for a child, so a signal
//! that arrives while a child is being started is acted on once that child has started. A supervised child
//! leads a new session and group, starts with the three signals unblocked and each handled one at its
//! default action, and receives SIGTERM when the thread that started it ends; the run starts every child
//! from its main thread.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Read};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::stop::{Fault, Stop};

pub const SIGNALS: [i32; 3] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP];
/// Each of the two waits for the group leader after SIGTERM and after SIGKILL, and the wait for a plain
/// child after SIGKILL.
const GRACE: Duration = Duration::from_secs(10);
/// The longest pause between two checks of a child and of the interrupt while the run waits; the pause
/// starts at [`FIRST_PAUSE`] and doubles up to this bound.
const POLL: Duration = Duration::from_millis(20);
const FIRST_PAUSE: Duration = Duration::from_micros(500);

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

/// `handled_set` is the signal set that holds each of [`SIGNALS`].
fn handled_set() -> libc::sigset_t {
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
/// # Errors
///
/// Reading a disposition, installing a handler or changing the signal mask fails.
pub fn install_handlers() -> io::Result<()> {
    for signal in SIGNALS {
        if ignored(signal)? {
            continue;
        }
        // SAFETY: the action only calls `Interrupt::record`, one atomic compare-exchange on a static,
        // which is async-signal-safe.
        unsafe { signal_hook::low_level::register(signal, move || INTERRUPT.record(signal)) }?;
    }
    let handled = handled_set();
    // SAFETY: `handled` is an initialized signal set that outlives the call, and a null old set makes
    // `pthread_sigmask` write nothing back.
    let status =
        unsafe { libc::pthread_sigmask(libc::SIG_UNBLOCK, &handled, std::ptr::null_mut()) };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status));
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

/// `exited_within` waits up to `limit` for the child to exit and returns its status, polling it with a
/// pause that grows to [`POLL`]; an `interrupt` that holds a signal ends the wait early with `Ok(None)`.
///
/// # Errors
///
/// The wait fails.
fn exited_within(
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

/// `signal_group` sends `signal` to the process group `group` and returns false when no member is left.
///
/// # Errors
///
/// `killpg` fails with an error other than `ESRCH`.
fn signal_group(group: libc::pid_t, signal: i32) -> Result<bool, Fault> {
    // SAFETY: `killpg` takes two integers and touches no memory of the caller.
    if unsafe { libc::killpg(group, signal) } == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        return Ok(false);
    }
    Err(Fault::os(&error, None))
}

/// `stop_group` stops the group the child leads. When the group is gone at SIGTERM it returns. Otherwise
/// it waits up to [`GRACE`] for the leader, sends SIGKILL to the group if the leader still runs and waits
/// up to [`GRACE`] again, and ends with SIGKILL to the group in every case. A member the leader left
/// behind after it exited gets SIGTERM and SIGKILL with no wait between them.
///
/// # Errors
///
/// A signal cannot be sent for a reason other than an empty group, or the wait fails.
fn stop_group(child: &mut Child) -> Result<(), Fault> {
    let group = libc::pid_t::try_from(child.id()).expect("a process id fits pid_t");
    for signal in [libc::SIGTERM, libc::SIGKILL] {
        if !signal_group(group, signal)? {
            return Ok(());
        }
        let exited = exited_within(child, GRACE, None).map_err(|error| Fault::os(&error, None))?;
        if exited.is_some() {
            break;
        }
    }
    signal_group(group, libc::SIGKILL).map(drop)
}

/// `lead_new_session` makes the child started by `command` lead a new session, return each of [`SIGNALS`]
/// that has a handler to its default action, unblock the three and receive SIGTERM when the starting thread
/// ends. A failed `setsid`, signal-mask change or `prctl` fails the start; a child whose parent already
/// changed exits 1 before it runs the program.
fn lead_new_session(command: &mut Command) {
    // SAFETY: `getpid` takes no argument and cannot fail.
    let parent = unsafe { libc::getpid() };
    let handled = handled_set();
    // SAFETY: the hook runs in the forked child before `exec` and calls only `setsid`, `sigaction`,
    // `sigprocmask`, `prctl`, `getppid` and `_exit`, which are async-signal-safe. It reads `handled`, its
    // own copy of an initialized set, and writes only `current`, a local all-zero `sigaction` (a valid
    // value) that each `sigaction` call overwrites.
    unsafe {
        command.pre_exec(move || {
            if libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            for signal in SIGNALS {
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
            if libc::sigprocmask(libc::SIG_UNBLOCK, &handled, std::ptr::null_mut()) != 0 {
                return Err(io::Error::last_os_error());
            }
            let (death, unused): (libc::c_ulong, libc::c_ulong) =
                (libc::SIGTERM as libc::c_ulong, 0);
            if libc::prctl(libc::PR_SET_PDEATHSIG, death, unused, unused, unused) != 0 {
                return Err(io::Error::last_os_error());
            }
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
/// group it left behind are stopped. The run passes [`INTERRUPT`].
///
/// # Errors
///
/// An empty `argv`, a recorded signal, or an output file, the start, the wait or a stop of the group that
/// fails. An empty `argv` fails before either output file is opened.
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
    let Some((&program, args)) = argv.split_first() else {
        let error = io::Error::new(io::ErrorKind::InvalidInput, "an empty command");
        return Err(Stop::failed(&Fault::os(&error, None)));
    };
    let (out, err) = (create(stdout)?, create(stderr)?);
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(out)
        .stderr(err)
        .env_clear()
        .envs(env.iter().cloned());
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    lead_new_session(&mut command);
    let mut child = command
        .spawn()
        .map_err(|error| Stop::failed(&Fault::os(&error, Some(program))))?;
    let ended = interrupt.check().and_then(|()| {
        match exited_within(&mut child, Duration::MAX, Some(interrupt)) {
            Ok(Some(status)) => Ok(exit_code(status)),
            Ok(None) => interrupt
                .check()
                .map(|()| unreachable!("a wait ends early only on a signal")),
            Err(error) => Err(Stop::failed(&Fault::os(&error, None))),
        }
    });
    stop_group(&mut child).map_err(|fault| Stop::failed(&fault))?;
    ended
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
///
/// # Errors
///
/// The outer error is a recorded signal; the inner one a start, a reader thread, a read or a wait that
/// fails.
pub(super) fn capture(
    command: &mut Command,
    interrupt: &Interrupt,
) -> Result<io::Result<Output>, Stop> {
    let spawned = command
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match spawned {
        Ok(child) => child,
        Err(error) => return Ok(Err(error)),
    };
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
                Err(error) => {
                    let _ = child.kill();
                    let _ = exited_within(&mut child, GRACE, None);
                    return Ok(Err(error));
                }
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
