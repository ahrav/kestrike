//! Once [`install`] installs `stop` for SIGTERM and SIGINT, receiving either signal sets the process-wide stop
//! flag, which [`stopping`] reads and [`wait_until`] polls. [`wait_until`] interprets deadlines in microseconds on
//! the clock it is given, in the service `CLOCK_BOOTTIME` ([`boot_us`]).
//!
//! The flag and the dispositions belong to the process: the handlers remain installed after the run returns, and
//! once `stop` sets the flag, later calls to [`wait_until`] return `Ok(true)` before checking the deadline.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn stop(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

/// Installs the stop handler for SIGTERM and SIGINT with `SA_RESTART`, so the kernel restarts eligible interrupted
/// system calls. The handler stays installed after the run returns.
///
/// # Errors
///
/// The error of the first `sigaction` call that fails.
pub fn install() -> io::Result<()> {
    let handler = stop as extern "C" fn(libc::c_int) as libc::sighandler_t;
    for signal in [libc::SIGTERM, libc::SIGINT] {
        // SAFETY: an all-zero `sigaction` is a valid value with an empty mask and no flags.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        // SAFETY: `sa_mask` is a valid `sigset_t` the call empties.
        unsafe { libc::sigemptyset(&mut action.sa_mask) };
        action.sa_sigaction = handler;
        action.sa_flags = libc::SA_RESTART;
        // SAFETY: `action` is a valid `sigaction` for the call, and `stop` only stores to an atomic, which is
        // async-signal-safe.
        if unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// [`stopping`] returns `true` once the handler sets the flag and on every later call.
pub fn stopping() -> bool {
    STOP.load(Ordering::SeqCst)
}

/// [`boot_us`] returns microseconds on `CLOCK_BOOTTIME`, a nondecreasing clock that includes time spent suspended.
///
/// # Errors
///
/// The `clock_gettime` call's error.
pub fn boot_us() -> io::Result<u64> {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `now` is a valid `timespec` the call writes.
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut now) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let seconds = u64::try_from(now.tv_sec).unwrap_or(0);
    let micros = u64::try_from(now.tv_nsec).unwrap_or(0) / 1_000;
    Ok(seconds.saturating_mul(1_000_000).saturating_add(micros))
}

/// [`wait_until`] returns `Ok(true)` when it observes the stop flag, or `Ok(false)` when it observes `clock` at
/// `until_us` or later first. Between checks, [`wait_until`] requests a sleep of at most 100 ms.
///
/// # Errors
///
/// `clock`'s error.
pub fn wait_until(until_us: u64, mut clock: impl FnMut() -> io::Result<u64>) -> io::Result<bool> {
    while !stopping() {
        let now = clock()?;
        if now >= until_us {
            return Ok(false);
        }
        std::thread::sleep(Duration::from_micros(until_us - now).min(Duration::from_millis(100)));
    }
    Ok(true)
}
