//! Each test runs as a child that leads a session of its own, its output in a new file, under a deadline
//! on the monotonic clock; its process group is then stopped with SIGTERM and SIGKILL.
//!
//! The handled signals are held from before the child starts until its group has ended. A signal
//! recorded before the start starts no child. The wait reads, at each poll, the leader's state, then the
//! record, then the clock: a signal the poll reads ends the wait, and the stop's grace then lasts until a
//! further signal; after a wait the deadline or the leader's exit ended, the first signal ends the grace.
//! A poll that finds the leader running with time left pauses its whole pause, so the poll that sees the
//! deadline can come up to one pause after it. The leader stays unreaped until the stop's last signal,
//! and its exit code comes from that reap.

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use super::halt::Halt;
use crate::json::Value;
use crate::ownership::PathError;
use crate::process::{
    FIRST_PAUSE, GroupStop, GroupStopped, Interrupt, Leader, child_defaults, exit_code,
    file_size_signal_default, handled_set, leader, stop_group,
};
use crate::python::round;

/// A loom test's deadline.
pub(super) const LOOM_DEADLINE: Duration = Duration::from_secs(3600);
/// The GenMC lane runs a case's `cargo check` under `deadline 5m` and its checker under `deadline 15m`,
/// and provisions the checker under `deadline 40m`. A lane call's deadline is the sum over its cases plus
/// 5 minutes for the lane's other steps.
pub(super) const GENMC_DEADLINE: Duration = Duration::from_secs((5 + 15) * 60);
pub(super) const GENMC_SETUP: Duration = Duration::from_secs((40 + 5) * 60);
/// The lane gives a stopped session 30 seconds before SIGKILL; this grace outlasts it.
pub(super) const STOP_GRACE: Duration = Duration::from_secs(45);
/// The longest pause between two checks of a child's exit and of the record.
pub(super) const POLL: Duration = Duration::from_millis(50);

/// Where a child's run reads the record and what its stop grants: the record, the stop's grace, and
/// three points a test acts at, after the start, before the stop and after it.
pub(super) struct Launch<'a> {
    pub(super) interrupt: &'a Interrupt,
    pub(super) grace: Duration,
    pub(super) started: &'a dyn Fn(&Child),
    pub(super) stopping: &'a dyn Fn(),
    pub(super) stopped: &'a dyn Fn(),
}

impl<'a> Launch<'a> {
    /// The run's launch: `interrupt`, the grace [`STOP_GRACE`] and no action at the three points.
    pub(super) fn new(interrupt: &'a Interrupt) -> Self {
        Self {
            interrupt,
            grace: STOP_GRACE,
            started: &|_| {},
            stopping: &|| {},
            stopped: &|| {},
        }
    }
}

/// `with_defaults` makes the child reset each handled signal it catches to its default action, keep one
/// it inherited ignored as ignored, unblock the three and take SIGXFSZ at its default before it runs its
/// program.
pub(super) fn with_defaults(command: &mut Command) {
    let handled = handled_set();
    // SAFETY: the hook runs in the forked child before `exec` and calls only `sigaction`, `sigprocmask`
    // and `signal`, which are async-signal-safe, on its own copy of an initialized set.
    unsafe {
        command.pre_exec(move || {
            child_defaults(&handled)?;
            file_size_signal_default()
        });
    }
}

/// `lead_session` makes the child lead a new session, and so a process group of its own, with the signals
/// as [`with_defaults`] leaves them.
fn lead_session(command: &mut Command) {
    // SAFETY: the hook runs in the forked child before `exec` and calls only `setsid`, which is
    // async-signal-safe.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    with_defaults(command);
}

/// `stop` ends the process group that `child` leads: SIGTERM, then SIGKILL once the leader has exited,
/// the launch's grace has passed or the deliveries pass `spent`, and a reap with no bound.
///
/// # Errors
///
/// A read of the leader's state, a signal or the reap fails.
pub(super) fn stop(
    child: &mut Child,
    launch: &Launch<'_>,
    spent: usize,
) -> io::Result<GroupStopped> {
    let ends = || launch.interrupt.deliveries() > spent;
    stop_group(
        child,
        &GroupStop::new(launch.grace, Some(&ends), None, POLL),
    )
}

/// `seconds` is `elapsed` in seconds rounded to a tenth as Python's `round` rounds a float.
pub(super) fn seconds(elapsed: Duration) -> f64 {
    match round(&Value::Float(elapsed.as_secs_f64()), 1) {
        Some(Value::Float(rounded)) => rounded,
        _ => unreachable!("a finite float rounds to a float"),
    }
}

/// `execute` runs `argv` in `cwd` with `env`, or this process's environment where it is `None`, its
/// standard output and standard error written to `output`, a new file, and returns the leader's exit
/// code, `None` when the deadline ended the wait first, with the seconds from before the output's creation
/// to the end of the stop, rounded to a tenth. A child a signal ended gives the negated signal number; a
/// handled signal recorded during the wait gives its interruption.
///
/// # Errors
///
/// A recorded signal, before the start or by the end of the stop, or one recorded while this is the
/// outermost hold whatever else failed; an output that cannot be created new, a child that cannot start,
/// or a wait or stop that fails.
pub(super) fn execute(
    launch: &Launch<'_>,
    argv: &[OsString],
    cwd: &Path,
    env: Option<&[(OsString, OsString)]>,
    deadline: Duration,
    output: &Path,
) -> Result<(Option<i32>, f64), Halt> {
    let started = Instant::now();
    let sink = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .map_err(|error| Halt::failed(PathError::new(output, error)))?;
    let code = holding(launch.interrupt, || {
        supervised(launch, argv, cwd, env, deadline, sink, started)
    })?;
    Ok((code, seconds(started.elapsed())))
}

fn supervised(
    launch: &Launch<'_>,
    argv: &[OsString],
    cwd: &Path,
    env: Option<&[(OsString, OsString)]>,
    deadline: Duration,
    sink: File,
    started: Instant,
) -> Result<Option<i32>, Halt> {
    launch.interrupt.check()?;
    let Some((program, args)) = argv.split_first() else {
        return Err(Halt::failed("an empty command"));
    };
    let mut command = Command::new(program);
    command
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::inherit())
        .stdout(sink.try_clone()?)
        .stderr(sink);
    if let Some(env) = env {
        command.env_clear().envs(env.iter().cloned());
    }
    lead_session(&mut command);
    let mut child = command
        .spawn()
        .map_err(|error| Halt::failed(format!("{}: {error}", program.to_string_lossy())))?;
    (launch.started)(&child);
    let waited = waited(child.id(), started.checked_add(deadline), launch.interrupt);
    let spent = waited.as_ref().map_or(0, |&(_, spent)| spent);
    (launch.stopping)();
    let stopped = stop(&mut child, launch, spent);
    (launch.stopped)();
    let exited = matches!(waited?.0, Leader::Exited | Leader::Reaped);
    let code = match stopped? {
        GroupStopped::Reaped(status) => exited.then(|| exit_code(status)),
        GroupStopped::Running | GroupStopped::ReapedElsewhere => {
            return Err(Halt::failed(
                "the test's leader was reaped outside its stop",
            ));
        }
    };
    launch.interrupt.check()?;
    Ok(code)
}

/// `waited` waits for the leader `pid` to leave [`Leader::Running`], for a signal in `interrupt` or for
/// `cutoff`, `None` for none, and returns the last state read with the deliveries the wait spent: one
/// where the last poll read a recorded signal, else none. Each poll reads the leader's state, then the
/// record, then the clock, and a poll that finds the leader running with no signal and time left pauses
/// for a time that starts at [`FIRST_PAUSE`] and doubles up to [`POLL`], uncut by the cutoff. It reaps
/// nothing.
///
/// # Errors
///
/// A read of the leader's state fails as [`leader`] states.
fn waited(pid: u32, cutoff: Option<Instant>, interrupt: &Interrupt) -> io::Result<(Leader, usize)> {
    let mut pause = FIRST_PAUSE;
    loop {
        let state = leader(pid)?;
        let spent = usize::from(interrupt.deliveries() > 0);
        let passed = cutoff.is_some_and(|cutoff| Instant::now() >= cutoff);
        if state != Leader::Running || spent > 0 || passed {
            return Ok((state, spent));
        }
        thread::sleep(pause);
        pause = (pause * 2).min(POLL);
    }
}

/// `holding` runs `body` under a hold of `interrupt`. Where the hold is the outermost one and a signal is
/// recorded by its release, the result is that signal's interruption, unless `body` ended by an
/// interruption of its own, which stays.
///
/// # Errors
///
/// `body`'s error, or the interruption of the release.
pub(super) fn holding<T>(
    interrupt: &Interrupt,
    body: impl FnOnce() -> Result<T, Halt>,
) -> Result<T, Halt> {
    let hold = interrupt.hold();
    let ran = body();
    match (ran, hold.release()) {
        (Err(halt), _) if halt.is_interrupt() => Err(halt),
        (_, Err(interrupted)) => Err(interrupted.into()),
        (ran, Ok(())) => ran,
    }
}

#[cfg(test)]
#[path = "execute_tests.rs"]
mod tests;
