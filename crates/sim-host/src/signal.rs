//! The runner's signal dispositions. SIGTERM and SIGINT set a stop flag
//! that the runner polls; SIGCHLD has its default disposition, so every
//! child stays waitable until the runner reaps it and a child's pid names
//! that child until then.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn stop(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

/// Installs the stop handler for SIGTERM and SIGINT and restores the
/// default SIGCHLD disposition with no flags, so an ignored SIGCHLD or
/// `SA_NOCLDWAIT` inherited from the parent does not reap children before
/// the runner waits for them. Call it before the first child starts.
pub fn install() -> std::io::Result<()> {
    let handler = stop as extern "C" fn(libc::c_int) as libc::sighandler_t;
    for (signal, disposition, flags) in [
        (libc::SIGTERM, handler, libc::SA_RESTART),
        (libc::SIGINT, handler, libc::SA_RESTART),
        (libc::SIGCHLD, libc::SIG_DFL, 0),
    ] {
        // SAFETY: an all-zero `sigaction` is a valid value with an empty
        // mask and no flags.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = disposition;
        action.sa_flags = flags;
        // SAFETY: `action` is a valid `sigaction` for the call, and `stop`
        // only stores to an atomic, which is async-signal-safe.
        if unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

pub fn stopping() -> bool {
    STOP.load(Ordering::SeqCst)
}

/// Sleeps `seconds`, polling the stop flag every 100 ms, and returns
/// within one poll of a stop request. A wait whose end the monotonic clock
/// cannot represent lasts until a stop.
pub fn wait(seconds: u64) {
    let until = Instant::now().checked_add(Duration::from_secs(seconds));
    while !stopping() && until.is_none_or(|until| Instant::now() < until) {
        std::thread::sleep(Duration::from_millis(100));
    }
}

pub fn request_stop() {
    STOP.store(true, Ordering::SeqCst);
}
