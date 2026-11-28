//! The bounded wait for a directory's lock that its holder in the test process has dropped.
//!
//! The lock is an `flock` of an open file description. A child forked by another test thread
//! inherits a descriptor for the same open file description, so a lock that its holder in the test
//! process dropped can still read as taken.

use std::cell::{Cell, RefCell};
use std::fs::File;
use std::io;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use kestrike_tools::host_stop::{Disk, Files, Links, Lock, LockError, lock};

use super::{Scratch, bounded};

const PAUSE: Duration = Duration::from_millis(10);
/// How long after its first attempt [`free_lock`] answers a taken lock with another attempt.
const LIMIT: Duration = Duration::from_secs(5);

/// `lock_within` retries on `EWOULDBLOCK` while elapsed time is below `limit`, regardless of which
/// process holds the lock. It checks `limit` only after [`lock`] returns [`LockError::Taken`] with
/// `EWOULDBLOCK`, so a retry can succeed after the deadline.
fn lock_within(files: &impl Files, directory: &Path, limit: Duration) -> Result<Lock, LockError> {
    let start = Instant::now();
    loop {
        match lock(files, directory) {
            Err(LockError::Taken(error))
                if error.raw_os_error() == Some(libc::EWOULDBLOCK) && start.elapsed() < limit =>
            {
                thread::sleep(PAUSE);
            }
            ended => return ended,
        }
    }
}

/// When `flock` returns `EWOULDBLOCK` less than 5 s ([`LIMIT`]) after the first attempt,
/// `free_lock` waits 10 ms ([`PAUSE`]) before retrying. The retry can succeed after the deadline.
/// Elapsed time comes from the monotonic clock ([`Instant`]). An `EWOULDBLOCK` at or past the
/// deadline, an open error, or any other `flock` error causes `free_lock` to panic. The panic
/// message includes the directory, [`LIMIT`], and the refusal.
///
/// A forked child can share the returned lock's description as well, so a command that takes the
/// same lock after the returned one drops can read it as taken until that child's `exec`.
pub(crate) fn free_lock(directory: &Path) -> Lock {
    lock_within(&Disk, directory, LIMIT).unwrap_or_else(|refusal| {
        panic!(
            "the lock of {} is free within {LIMIT:?}: {refusal:?}",
            directory.display()
        )
    })
}

/// `Counted` makes contention reproducible by releasing `held` on the first `EWOULDBLOCK` from
/// `Disk.try_lock`.
#[derive(Default)]
struct Counted {
    opens: Cell<usize>,
    attempts: Cell<usize>,
    refusals: Cell<usize>,
    planted: Cell<Option<i32>>,
    held: RefCell<Option<Lock>>,
}

impl Files for Counted {
    fn open_directory(&self, path: &Path, links: Links) -> io::Result<File> {
        self.opens.set(self.opens.get() + 1);
        Disk.open_directory(path, links)
    }

    fn try_lock(&self, directory: &File) -> io::Result<()> {
        self.attempts.set(self.attempts.get() + 1);
        if let Some(code) = self.planted.take() {
            return Err(io::Error::from_raw_os_error(code));
        }
        let ended = Disk.try_lock(directory);
        if let Err(error) = &ended
            && error.raw_os_error() == Some(libc::EWOULDBLOCK)
        {
            self.refusals.set(self.refusals.get() + 1);
            drop(self.held.borrow_mut().take());
        }
        ended
    }
}

/// [`bounded`] fails the case when the deadline check is lost and the call never returns.
#[test]
fn a_lock_that_stays_held_is_refused_once_the_limit_has_passed() {
    let scratch = Scratch::new("lock-held");
    let held = lock(&Disk, &scratch.0).expect("the holder locks");
    let (directory, limit) = (scratch.0.clone(), PAUSE * 3);
    let (waited, ended) = bounded("the wait for a held lock", move || {
        let start = Instant::now();
        let ended = lock_within(&Disk, &directory, limit);
        (start.elapsed(), ended)
    });
    assert!(waited >= limit, "{waited:?}");
    assert!(waited < LIMIT, "{waited:?}");
    match ended {
        Err(LockError::Taken(error)) => assert_eq!(error.raw_os_error(), Some(libc::EWOULDBLOCK)),
        other => panic!("{other:?}"),
    }
    drop(held);
}

/// The holder's drop follows the first refusal, so a wait that returns the lock made a later
/// attempt.
#[test]
fn a_lock_dropped_after_a_refusal_is_taken_by_a_later_attempt() {
    let scratch = Scratch::new("lock-dropped");
    let files = Counted::default();
    *files.held.borrow_mut() = Some(lock(&Disk, &scratch.0).expect("the holder locks"));
    let taken = lock_within(&files, &scratch.0, LIMIT).expect("a later attempt takes the lock");
    assert!(files.refusals.get() >= 1);
    assert_eq!(files.attempts.get(), files.refusals.get() + 1);
    assert!(files.held.borrow().is_none());
    drop(taken);
}

/// A second attempt after the planted `ENOLCK` would take the free lock, and a second attempt at
/// the missing directory would increment `opens` again even though the open fails with `ENOENT`.
#[test]
fn an_error_other_than_a_taken_lock_ends_the_wait_at_its_first_attempt() {
    let scratch = Scratch::new("lock-errors");
    let files = Counted::default();
    files.planted.set(Some(libc::ENOLCK));
    match lock_within(&files, &scratch.0, LIMIT) {
        Err(LockError::Taken(error)) => assert_eq!(error.raw_os_error(), Some(libc::ENOLCK)),
        other => panic!("{other:?}"),
    }
    assert_eq!((files.opens.get(), files.attempts.get()), (1, 1));
    let files = Counted::default();
    match lock_within(&files, &scratch.0.join("missing"), LIMIT) {
        Err(LockError::Open(error)) => assert_eq!(error.raw_os_error(), Some(libc::ENOENT)),
        other => panic!("{other:?}"),
    }
    assert_eq!((files.opens.get(), files.attempts.get()), (1, 0));
}

#[test]
fn a_refusal_panics_with_the_directory_the_limit_and_the_error() {
    let scratch = Scratch::new("lock-missing");
    let missing = scratch.0.join("missing");
    let payload = std::panic::catch_unwind(|| free_lock(&missing)).expect_err("the open fails");
    let message = payload
        .downcast_ref::<String>()
        .expect("the panic carries a formatted message");
    let start = format!("the lock of {} is free within 5s: Open(", missing.display());
    assert!(message.starts_with(&start), "{message}");
}
