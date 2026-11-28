//! The record of the first SIGINT, SIGTERM or SIGHUP, and the wait on a check that acts on it.
//!
//! Each of the three signals records into [`RECORD`], whatever disposition the tool inherited, and a later
//! signal changes nothing. A check leads a process group of its own, so the tool alone decides what the
//! group receives: while the check's leader is the tool's child and not yet reaped, its process id cannot
//! name another process, and on a record the group and the leader get SIGKILL, and the reap comes last. A
//! leader already reaped gets no signal.

use std::io;
use std::process::{Child, ExitStatus};
use std::sync::atomic::{AtomicI32, Ordering};
use std::thread;
use std::time::Duration;

const SIGNALS: [i32; 3] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP];

/// The first pause of the wait on a check; each later pause doubles, up to [`LONGEST_PAUSE`].
const FIRST_PAUSE: Duration = Duration::from_micros(500);
const LONGEST_PAUSE: Duration = Duration::from_millis(20);

/// The first handled signal, or 0 while none has arrived.
static RECORD: AtomicI32 = AtomicI32::new(0);

/// `install` makes each of [`SIGNALS`] record into [`RECORD`], an ignored one included, and unblocks the
/// three in the calling thread, so a tool started with one of them blocked still records it.
///
/// # Errors
///
/// Installing a handler or changing the signal mask fails.
pub(super) fn install() -> io::Result<()> {
    for signal in SIGNALS {
        // SAFETY: the action is one atomic compare-exchange on a static, which is async-signal-safe.
        unsafe {
            signal_hook::low_level::register(signal, move || {
                let _ = RECORD.compare_exchange(0, signal, Ordering::SeqCst, Ordering::SeqCst);
            })
        }?;
    }
    // SAFETY: `sigemptyset` initializes the all-zero set and `sigaddset` adds valid signal numbers to it;
    // `pthread_sigmask` reads the set, which outlives the call, and a null old set makes it write nothing.
    let status = unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for signal in SIGNALS {
            libc::sigaddset(&mut set, signal);
        }
        libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut())
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status));
    }
    Ok(())
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
    /// A signal was recorded: the check's group was stopped and its leader reaped; the field is the exit
    /// code.
    Cancelled(u8),
    /// The wait failed; the check's group was sent SIGKILL.
    Failed(io::Error),
}

/// `wait` returns the exit status of `check`, a leader of its own process group, polling it with a pause
/// that grows from [`FIRST_PAUSE`] to [`LONGEST_PAUSE`] and reading the record after each poll.
pub(super) fn wait(check: &mut Child) -> Result<ExitStatus, Unwaited> {
    let mut pause = FIRST_PAUSE;
    loop {
        match check.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {}
            Err(error) => {
                stop(check);
                return Err(Unwaited::Failed(error));
            }
        }
        if let Err(code) = self::check() {
            stop(check);
            let _ = check.wait();
            return Err(Unwaited::Cancelled(code));
        }
        thread::sleep(pause);
        pause = (pause * 2).min(LONGEST_PAUSE);
    }
}

/// `stop` sends SIGKILL to the group `check` leads and to the leader, which the caller has not reaped, so
/// its process id still names it and its group. A leader that left its group still ends.
fn stop(check: &mut Child) {
    let group = libc::pid_t::try_from(check.id()).expect("a process id fits pid_t");
    // SAFETY: `killpg` takes two integers and touches no memory of the caller.
    unsafe { libc::killpg(group, libc::SIGKILL) };
    let _ = check.kill();
}
