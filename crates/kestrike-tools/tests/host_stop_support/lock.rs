//! The bounded wait for a directory's lock that its holder in the test process has dropped.
//!
//! The lock is an `flock` of an open file description. A child that another thread of the test
//! process forks shares each open description until its `exec`, so a lock reads as taken for that
//! span after its holder dropped it. A lock that a descriptor of the test process still holds
//! stays taken for as long as the descriptor is open, which is past the wait's bound.

use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use kestrike_tools::host_stop::{Disk, Lock, LockError, lock};

/// The pause between two attempts of [`free_lock`].
const PAUSE: Duration = Duration::from_millis(10);
/// How long after its first attempt [`free_lock`] answers a taken lock with another attempt.
const LIMIT: Duration = Duration::from_secs(5);

/// The lock of `directory`, taken within a bound. An attempt that the system refuses with
/// `EWOULDBLOCK` runs again after a pause of 10 ms ([`PAUSE`]) until 5 s ([`LIMIT`]) have passed
/// since the first attempt on the monotonic clock ([`Instant`]); the last refusal is then the
/// panic's message. A refusal of the open, and a refusal of the `flock` with another error, panics
/// at once.
///
/// A forked child can share the returned lock's description as well, so a command that takes the
/// same lock after the returned one drops can read it as taken until that child's `exec`.
pub(crate) fn free_lock(directory: &Path) -> Lock {
    let start = Instant::now();
    loop {
        match lock(&Disk, directory) {
            Ok(held) => return held,
            Err(LockError::Taken(error))
                if error.raw_os_error() == Some(libc::EWOULDBLOCK) && start.elapsed() < LIMIT =>
            {
                thread::sleep(PAUSE);
            }
            Err(refusal) => panic!(
                "the lock of {} is free within {LIMIT:?}: {refusal:?}",
                directory.display()
            ),
        }
    }
}

/// The panic's message of `work`, which panics.
fn refusal(work: impl FnOnce() -> Lock + std::panic::UnwindSafe) -> String {
    let payload = std::panic::catch_unwind(work).expect_err("the lock is refused");
    payload
        .downcast_ref::<String>()
        .expect("the refusal is a formatted message")
        .clone()
}

/// A lock that a descriptor of the test process holds is refused once the bound has passed, with
/// the system's `EWOULDBLOCK` in the message, so a holder that keeps its lock fails the case that
/// waits for it.
#[test]
fn a_lock_that_stays_held_is_refused_once_the_bound_has_passed() {
    let scratch = super::Scratch::new("lock-held");
    let held = lock(&Disk, &scratch.0).expect("the holder locks");
    let start = Instant::now();
    let message = refusal(|| free_lock(&scratch.0));
    let waited = start.elapsed();
    assert!(waited >= LIMIT, "{waited:?}");
    assert!(
        message.contains("Taken(") && message.contains("WouldBlock"),
        "{message}"
    );
    drop(held);
}

/// A lock that its holder drops during the wait is taken: the wait returns the lock only once the
/// holder's three pauses have passed.
#[test]
fn a_lock_dropped_during_the_wait_is_taken() {
    let scratch = super::Scratch::new("lock-dropped");
    let held = lock(&Disk, &scratch.0).expect("the holder locks");
    let hold = PAUSE * 3;
    let start = Instant::now();
    let holder = thread::spawn(move || {
        thread::sleep(hold);
        drop(held);
    });
    let taken = free_lock(&scratch.0);
    let waited = start.elapsed();
    assert!(waited >= hold, "{waited:?}");
    holder.join().expect("the holder ends");
    drop(taken);
}

/// A directory that does not open is refused at once with the open's error.
#[test]
fn a_directory_that_does_not_open_is_refused_at_once() {
    let scratch = super::Scratch::new("lock-missing");
    let start = Instant::now();
    let message = refusal(|| free_lock(&scratch.0.join("missing")));
    assert!(message.contains("Open("), "{message}");
    assert!(start.elapsed() < LIMIT, "{:?}", start.elapsed());
}
