//! The handlers record the first signal from [`SIGNALS`] in [`RECORD`]. If the check leader is still
//! unreaped when the tool observes the record, the tool sends SIGKILL to the process group and its leader
//! before reaping the leader.
//!
//! Each of the four signals records into [`RECORD`], whatever disposition the tool inherited, and a later
//! signal changes nothing. A check leads a process group of its own, so the terminal's signals to the
//! foreground group reach the tool and not the check: while the check's leader is the tool's child and not
//! yet reaped, its process id cannot name another process, and on a record the group and the leader get
//! SIGKILL, and the reap comes last. Off Linux a process that a member forks while the group's SIGKILL is
//! delivered can run on. A
//! leader already reaped gets no signal. [`install`] sets SIGCHLD to its default disposition
//! before the tool starts any child, so the kernel keeps each ended child until the tool reaps it.
//!
//! [`install`] blocks [`SIGNALS`] while it registers their handlers. Unblocking [`SIGNALS`] permits
//! delivery of pending signals. [`RECORD`] retains the first signal a handler records.
//!
//! A check starts with [`SIGNALS`] at their default dispositions, since `execve` resets each caught signal
//! to its default, and with SIGCHLD at its default, which [`install`] set and `execve` keeps. It starts
//! with the signal mask of the thread that starts it, since `Command` passes that mask on: [`install`]
//! unblocked [`SIGNALS`] there, and any other signal the tool's starter blocked stays blocked in the check.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::process::{Child, ExitStatus};
use std::sync::atomic::{AtomicI32, Ordering};
use std::thread;
use std::time::Duration;

#[cfg(test)]
#[path = "cancel_tests.rs"]
mod tests;

const SIGNALS: [i32; 4] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT];

/// The first pause of the wait on a check; each later pause doubles, up to [`LONGEST_PAUSE`].
const FIRST_PAUSE: Duration = Duration::from_micros(500);
const LONGEST_PAUSE: Duration = Duration::from_millis(20);

/// The first handled signal, or 0 while none has arrived.
static RECORD: AtomicI32 = AtomicI32::new(0);

/// `install` blocks [`SIGNALS`] in the calling thread and registers a handler that records into
/// [`RECORD`] for every signal in [`SIGNALS`], including any previously ignored signal. It restores
/// SIGCHLD's default disposition before it unblocks [`SIGNALS`].
///
/// # Errors
///
/// `install` returns an error if a mask change, a handler registration or the SIGCHLD disposition change
/// fails. An error after the block can leave [`SIGNALS`] blocked in the calling thread.
pub(super) fn install() -> io::Result<()> {
    // SAFETY: `sigemptyset` initializes the all-zero set and `sigaddset` adds valid signal numbers to it.
    let set = unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for signal in SIGNALS {
            libc::sigaddset(&mut set, signal);
        }
        set
    };
    mask(libc::SIG_BLOCK, &set)?;
    for signal in SIGNALS {
        // SAFETY: the action is one atomic compare-exchange on a static, which is async-signal-safe.
        unsafe {
            signal_hook::low_level::register(signal, move || {
                let _ = RECORD.compare_exchange(0, signal, Ordering::SeqCst, Ordering::SeqCst);
            })
        }?;
    }
    // SAFETY: `action` selects `SIG_DFL` with zero flags, `sigemptyset` initializes `action.sa_mask`, and
    // `sigaction` accepts a null old action.
    let status = unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = libc::SIG_DFL;
        libc::sigemptyset(&mut action.sa_mask);
        libc::sigaction(libc::SIGCHLD, &action, std::ptr::null_mut())
    };
    if status != 0 {
        return Err(io::Error::last_os_error());
    }
    mask(libc::SIG_UNBLOCK, &set)
}

fn mask(how: libc::c_int, set: &libc::sigset_t) -> io::Result<()> {
    // SAFETY: `pthread_sigmask` reads the set, which outlives the call, and accepts a null old set.
    let status = unsafe { libc::pthread_sigmask(how, set, std::ptr::null_mut()) };
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(status))
    }
}

/// `check` is `Err` with the exit code `128 + n` once the signal `n` is recorded.
pub(super) fn check() -> Result<(), u8> {
    match RECORD.load(Ordering::SeqCst) {
        0 => Ok(()),
        signal => Err(code(signal)),
    }
}

/// `writable` returns once `stream` can take a write, polling it every [`LONGEST_PAUSE`] and reading the
/// record between polls. A stream that reports an error or a hang-up, and a failed poll, return at once,
/// so the write that follows reports the failure.
///
/// # Errors
///
/// A signal was recorded while `stream` could not take a write; the field is the exit code.
pub(super) fn writable(stream: BorrowedFd<'_>) -> Result<(), u8> {
    let timeout = libc::c_int::try_from(LONGEST_PAUSE.as_millis()).expect("the pause fits c_int");
    loop {
        let mut polled = libc::pollfd {
            fd: stream.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        };
        // SAFETY: `polled` is one initialized `pollfd` that outlives the call, and the count is 1.
        let ready = unsafe { libc::poll(&mut polled, 1, timeout) };
        if ready != 0 {
            let interrupted =
                ready < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted;
            if !interrupted {
                return Ok(());
            }
        }
        check()?;
    }
}

/// `code` is the exit code of the recorded `signal`, one of [`SIGNALS`].
fn code(signal: i32) -> u8 {
    u8::try_from(128 + signal).expect("each of SIGNALS is below 128")
}

/// Why a check gave no exit status.
pub(super) enum Unwaited {
    /// On a recorded signal, `wait` sent SIGKILL to the check's group and leader, then reaped the leader;
    /// the field is the exit code.
    Cancelled(u8),
    /// On a recorded signal, the SIGKILL or the reap failed, so the check's group may still run and its
    /// leader may stand unreaped; the fields are the exit code and the error.
    Unstopped(u8, io::Error),
    /// The `waitid` probe of the check or the final reap failed. A probe that fails with `ECHILD` finds the
    /// check no longer this process's child, and then its process id may name another process, so `wait`
    /// signals neither the leader nor its group. A probe that fails with another error leaves the leader
    /// the tool's unreaped child, so `wait` first sends SIGKILL to its group and leader and reaps it; the
    /// error then names the probe's failure and, where that stop failed too, the stop's.
    Failed(io::Error),
}

/// `wait` returns `child`'s status once `child` has ended and `done` holds, with `done` asked only after
/// `child` ended. `child` leads its own process group. Each poll keeps an exited leader waitable through
/// `check()`, preserving its process group id for [`stop`], so a signal recorded while `done` does not
/// hold still stops the group.
pub(super) fn wait(child: &mut Child, done: impl FnMut() -> bool) -> Result<ExitStatus, Unwaited> {
    waited(child, ended, done)
}

/// `waited` is [`wait`] with `probe` in place of [`ended`].
fn waited(
    child: &mut Child,
    probe: impl Fn(&Child) -> io::Result<bool>,
    mut done: impl FnMut() -> bool,
) -> Result<ExitStatus, Unwaited> {
    let mut pause = FIRST_PAUSE;
    loop {
        let ended = match probe(child) {
            Ok(ended) => ended,
            Err(error) if error.raw_os_error() == Some(libc::ECHILD) => {
                return Err(Unwaited::Failed(error));
            }
            Err(error) => return Err(abandoned(child, error)),
        };
        if let Err(code) = check() {
            return Err(match stop(child, ended) {
                Ok(()) => Unwaited::Cancelled(code),
                Err(error) => Unwaited::Unstopped(code, error),
            });
        }
        if ended && done() {
            return child.wait().map_err(Unwaited::Failed);
        }
        thread::sleep(pause);
        pause = (pause * 2).min(LONGEST_PAUSE);
    }
}

/// `abandoned` stops `child`, still the tool's unreaped child, after its probe failed with `error`. A
/// signal recorded by then gives its exit code.
fn abandoned(child: &mut Child, error: io::Error) -> Unwaited {
    let stopped = stop(child, false);
    match (check(), stopped) {
        (Err(code), Ok(())) => Unwaited::Cancelled(code),
        (Err(code), Err(failed)) => Unwaited::Unstopped(code, failed),
        (Ok(()), Ok(())) => Unwaited::Failed(error),
        (Ok(()), Err(failed)) => Unwaited::Failed(io::Error::other(format!(
            "{error}; the stop that followed failed: {failed}"
        ))),
    }
}

/// `ended` holds once `child` has exited or died of a signal; a stopped or continued child reads as running.
/// `waitid` with `WNOWAIT` keeps the child waitable.
///
/// # Errors
///
/// `waitid` fails with `ECHILD` where `child` is no longer this process's child.
fn ended(child: &Child) -> io::Result<bool> {
    let pid = libc::id_t::from(child.id());
    loop {
        // SAFETY: `info` is a zeroed `siginfo_t` that outlives the call; `waitid` writes it only where a
        // child changed state, so a zero `si_signo` reads as no change.
        let (status, info) = unsafe {
            let mut info: libc::siginfo_t = std::mem::zeroed();
            let status = libc::waitid(
                libc::P_PID,
                pid,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            );
            (status, info)
        };
        if status == 0 {
            return Ok(info.si_signo != 0 && terminal(info.si_code));
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

/// `terminal` holds for the `si_code` of a child that exited or died of a signal, and not for one that
/// stopped, was trapped or continued.
fn terminal(code: libc::c_int) -> bool {
    matches!(code, libc::CLD_EXITED | libc::CLD_KILLED | libc::CLD_DUMPED)
}

/// `stop` sends SIGKILL to the group `child` leads and to the leader, which the caller has not reaped, so
/// its process id still names it and its group, and then reaps the leader. A leader that left its group
/// still ends, and `killpg` finding no process in the group reads as a group already ended. On Apple's
/// systems an `EPERM` beside a leader that has ended, as `ended` says before the call or a second probe
/// after it, also reads as a group already ended: those systems give it for a group holding only its ended
/// leader, and also for a group whose only live members the tool may not signal, which then run on. Linux
/// gives success in both cases. The reap waits only on a leader whose SIGKILL was sent.
///
/// # Errors
///
/// `killpg` fails otherwise, or the kill or the reap of the leader fails; the first error is returned.
pub(super) fn stop(child: &mut Child, exited: bool) -> io::Result<()> {
    let group = libc::pid_t::try_from(child.id()).expect("a process id fits pid_t");
    // SAFETY: `killpg` takes two integers and touches no memory of the caller.
    let grouped = if unsafe { libc::killpg(group, libc::SIGKILL) } == 0 {
        Ok(())
    } else {
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::ESRCH) => Ok(()),
            Some(libc::EPERM)
                if cfg!(target_vendor = "apple") && (exited || ended(child).unwrap_or(false)) =>
            {
                Ok(())
            }
            _ => Err(error),
        }
    };
    let reaped = child.kill().and_then(|()| child.wait().map(drop));
    grouped.and(reaped)
}
