//! The SIGTERM handler sets `REQUESTED` through an async-signal-safe atomic
//! store. `start` saves the whole inherited `sigaction`, handler, flags and
//! mask, and `drop` restores it, so a process that inherited a non-default
//! action keeps it once the loop ends.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
#[cfg(test)]
use std::time::Instant;

static REQUESTED: AtomicBool = AtomicBool::new(false);

/// Whether a [`Serving`] holds the SIGTERM disposition; at most one does.
static ACTIVE: AtomicBool = AtomicBool::new(false);

extern "C" fn request_close(_: libc::c_int) {
    REQUESTED.store(true, Ordering::Relaxed);
}

pub(crate) struct Serving {
    #[cfg(test)]
    start: Instant,
    #[cfg(test)]
    limit: Duration,
    #[cfg(test)]
    reported: bool,
    previous: libc::sigaction,
}

impl Serving {
    pub(crate) fn start(limit: Duration) -> Self {
        assert!(
            !ACTIVE.swap(true, Ordering::Relaxed),
            "one serving loop owns SIGTERM at a time"
        );
        REQUESTED.store(false, Ordering::Relaxed);
        // SAFETY: the handler performs one atomic store, which is async-signal-safe; a zeroed
        // `sigaction` is a valid value to fill, and `previous` receives the action replaced.
        let (installed, previous) = unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = request_close as extern "C" fn(libc::c_int) as libc::sighandler_t;
            action.sa_flags = libc::SA_RESTART;
            libc::sigemptyset(&mut action.sa_mask);
            let mut previous: libc::sigaction = std::mem::zeroed();
            (
                libc::sigaction(libc::SIGTERM, &action, &mut previous),
                previous,
            )
        };
        if installed != 0 {
            // No `Serving` exists yet to release the flag from `Drop`.
            ACTIVE.store(false, Ordering::Relaxed);
            panic!("SIGTERM accepts the close handler");
        }
        eprintln!("owner serving until {limit:?} or SIGTERM");
        Self {
            #[cfg(test)]
            start: Instant::now(),
            #[cfg(test)]
            limit,
            #[cfg(test)]
            reported: false,
            previous,
        }
    }

    /// Whether a SIGTERM ended the loop: `keep` saw the request and printed the
    /// close line. A signal that arrives after the time limit ended the loop
    /// leaves this false, so a run that timed out keeps its completion checks.
    #[cfg(test)]
    pub(crate) fn signalled(&self) -> bool {
        self.reported
    }

    /// Whether a SIGTERM arrived since the live [`Serving`] started, read
    /// by a loop that runs under a guard another scope holds.
    pub(crate) fn requested() -> bool {
        REQUESTED.load(Ordering::Relaxed)
    }

    /// Whether the loop runs on: no SIGTERM yet and the limit not reached.
    #[cfg(test)]
    pub(crate) fn keep(&mut self) -> bool {
        if REQUESTED.load(Ordering::Relaxed) {
            if !self.reported {
                self.reported = true;
                eprintln!(
                    "close requested by SIGTERM after {:?}",
                    self.start.elapsed()
                );
            }
            return false;
        }
        self.start.elapsed() < self.limit
    }
}

impl Drop for Serving {
    fn drop(&mut self) {
        // SAFETY: restores the action `start` replaced, handler, flags and mask alike.
        unsafe { libc::sigaction(libc::SIGTERM, &self.previous, std::ptr::null_mut()) };
        ACTIVE.store(false, Ordering::Relaxed);
    }
}
