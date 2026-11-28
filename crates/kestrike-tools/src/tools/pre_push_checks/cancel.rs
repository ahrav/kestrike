//! The record of the first SIGINT, SIGTERM or SIGHUP, and the wait on a check that acts on it.
//!
//! Each of the three signals records into [`RECORD`], whatever disposition the tool inherited, and a later
//! signal changes nothing. A check leads a process group of its own, so the tool alone decides what the
//! group receives: while the check's leader is the tool's child and not yet reaped, its process id cannot
//! name another process, and on a record the group and the leader get SIGKILL, and the reap comes last. A
//! leader already reaped gets no signal. [`install`] sets SIGCHLD to its default disposition
//! before the tool starts any child, so the kernel keeps each ended child until the tool reaps it.
//!
//! [`install`] blocks the three signals while it registers their handlers. Unblocking [`SIGNALS`] permits
//! delivery of pending signals. [`RECORD`] retains the first signal a handler records.
//!
//! A check starts with the three signals and SIGCHLD at their default dispositions, since `execve` resets
//! each caught signal to its default, and with the signal mask of the thread that starts it, since
//! `Command` passes that mask on: [`install`] unblocked the three there, and any other signal the tool's
//! starter blocked stays blocked in the check.

use std::io;
use std::process::{Child, ExitStatus};
use std::sync::atomic::{AtomicI32, Ordering};
use std::thread;
use std::time::Duration;

#[cfg(test)]
#[path = "cancel_tests.rs"]
mod tests;

const SIGNALS: [i32; 3] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP];

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

/// `code` is the exit code of the recorded `signal`, one of [`SIGNALS`].
fn code(signal: i32) -> u8 {
    u8::try_from(128 + signal).expect("SIGINT, SIGTERM and SIGHUP are below 128")
}

/// Why a check gave no exit status.
pub(super) enum Unwaited {
    /// On a recorded signal, `wait` sent SIGKILL to the check's group and leader, then reaped the leader;
    /// the field is the exit code.
    Cancelled(u8),
    /// On a recorded signal, the SIGKILL or the reap failed, so the check's group may still run and its
    /// leader may stand unreaped; the fields are the exit code and the error.
    Unstopped(u8, io::Error),
    /// Polling the check failed. With `WNOHANG`, `waitpid` fails with `ECHILD` alone: the check is no
    /// longer this process's child and its process id may name another process, so `wait` signals
    /// neither the leader nor its group.
    Failed(io::Error),
}

/// `child` leads its own process group. Each poll keeps an exited leader waitable through `check()`,
/// preserving its process group id for [`stop`].
pub(super) fn wait(child: &mut Child) -> Result<ExitStatus, Unwaited> {
    let mut pause = FIRST_PAUSE;
    loop {
        let ended = ended(child).map_err(Unwaited::Failed)?;
        if let Err(code) = check() {
            return Err(match stop(child) {
                Ok(()) => Unwaited::Cancelled(code),
                Err(error) => Unwaited::Unstopped(code, error),
            });
        }
        if ended {
            return child.wait().map_err(Unwaited::Failed);
        }
        thread::sleep(pause);
        pause = (pause * 2).min(LONGEST_PAUSE);
    }
}

/// `ended` holds once `child` has exited; `waitid` with `WNOWAIT` keeps the child waitable.
///
/// # Errors
///
/// `waitid` fails with `ECHILD` where `child` is no longer this process's child.
fn ended(child: &Child) -> io::Result<bool> {
    let pid = libc::id_t::from(child.id());
    loop {
        // SAFETY: `info` is a zeroed `siginfo_t` that outlives the call, and `waitid` fills it.
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
            return Ok(info.si_signo != 0);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

/// `stop` sends SIGKILL to the group `child` leads and to the leader, which the caller has not reaped, so
/// its process id still names it and its group, and then reaps the leader. A leader that left its group
/// still ends, and `killpg` finding no process in the group reads as a group already ended. The reap waits
/// only on a leader whose SIGKILL was sent.
///
/// # Errors
///
/// `killpg` fails otherwise, or the kill or the reap of the leader fails; the first error is returned.
fn stop(child: &mut Child) -> io::Result<()> {
    let group = libc::pid_t::try_from(child.id()).expect("a process id fits pid_t");
    // SAFETY: `killpg` takes two integers and touches no memory of the caller.
    let grouped = if unsafe { libc::killpg(group, libc::SIGKILL) } == 0 {
        Ok(())
    } else {
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::ESRCH) => Ok(()),
            _ => Err(error),
        }
    };
    let reaped = child.kill().and_then(|()| child.wait().map(drop));
    grouped.and(reaped)
}
