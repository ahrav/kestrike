//! Signals and child processes.
//!
//! The handlers of SIGINT, SIGTERM and SIGHUP record the first of them in [`INTERRUPT`]; a later signal
//! changes nothing. The run reads the record between its steps and while it waits for a child, so a signal
//! that arrives while a child is being started is acted on once that child has started. A supervised child
//! leads a new session and group, starts with the three signals unblocked and each handled one at its
//! default action, and receives SIGTERM when the thread that started it ends; the run starts every child
//! from its main thread.

use std::ffi::{OsStr, OsString};
use std::fs::OpenOptions;
use std::io;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::process::{
    GroupStop, Interrupted, Leader, Stopped, handled_set, leader_left_within, stop_group,
};
pub use crate::process::{INTERRUPT, Interrupt, SIGNALS, install_handlers};
pub(super) use crate::process::{capture, exit_code};

use super::stop::{Fault, Stop};

impl From<Interrupted> for Stop {
    fn from(Interrupted(signal): Interrupted) -> Self {
        Self::interrupted(signal)
    }
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

/// The stop of a supervised child's group: two graces of 10 s, a reap of up to 10 s and pauses of up to
/// 20 ms between two reads of the leader's state.
const STOP: GroupStop<'static> = GroupStop::new(
    Duration::from_secs(10),
    true,
    Some(Duration::from_secs(10)),
    Duration::from_millis(20),
);
/// The longest pause between two reads of a supervised child's state while the run waits for its exit.
const POLL: Duration = Duration::from_millis(20);

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
/// to the two files, each created new, and the environment `env`, in a new session, and returns its exit code as
/// [`exit_code`] gives it. A signal recorded in `interrupt` before the child started or while it runs
/// stops the child's group and returns the interruption. Once the leader has exited, the members of its
/// group it left behind are stopped. The run reads the leader's state while it waits and reaps the leader
/// only after the group's last signal, and the exit code is that reap's. The run passes [`INTERRUPT`].
///
/// # Errors
///
/// An empty `argv`, a recorded signal, or an output file, the start, the wait or a stop of the group that
/// fails; a leader that a wait outside the run reaped fails as a wait with `ECHILD`. An empty `argv` fails
/// before either output file is opened.
pub fn supervise(
    interrupt: &Interrupt,
    argv: &[&OsStr],
    stdout: &Path,
    stderr: &Path,
    cwd: Option<&Path>,
    env: &[(OsString, OsString)],
) -> Result<i32, Stop> {
    let create = |path: &Path| {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|error| Stop::failed(&Fault::os(&error, Some(path.as_os_str()))))
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
    let recorded = || interrupt.recorded().is_some();
    let ended = interrupt.check().map_err(Stop::from).and_then(|()| {
        match leader_left_within(child.id(), Duration::MAX, POLL, &recorded) {
            Ok(Leader::Exited | Leader::Reaped) => Ok(()),
            Ok(Leader::Running) => interrupt
                .check()
                .map_err(Stop::from)
                .map(|()| unreachable!("a wait ends early only on a signal")),
            Err(error) => Err(Stop::failed(&Fault::os(&error, None))),
        }
    });
    let stopped =
        stop_group(&mut child, &STOP).map_err(|error| Stop::failed(&Fault::os(&error, None)))?;
    ended?;
    match stopped {
        Stopped::Reaped(status) => Ok(exit_code(status)),
        Stopped::ReapedElsewhere => {
            let error = io::Error::from_raw_os_error(libc::ECHILD);
            Err(Stop::failed(&Fault::os(&error, None)))
        }
        Stopped::Running => {
            let error = io::Error::new(io::ErrorKind::TimedOut, "the child outlived its stop");
            Err(Stop::failed(&Fault::os(&error, None)))
        }
    }
}
