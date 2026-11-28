//! An exclusive file lock with a bounded, cancellable wait.
//!
//! Dropping [`Held`] closes its descriptor. The kernel releases the `flock` when the last descriptor for the locked open file description closes.
//! A forked child inherits the close-on-exec descriptor; the kernel closes that descriptor on successful `exec`.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use crate::text::Text;

use super::cancel;

#[cfg(test)]
#[path = "lock_tests.rs"]
mod tests;

/// The longest [`take`] waits for the lock, counted from its first attempt.
pub(super) const LIMIT: Duration = Duration::from_secs(600);

/// The first pause between two attempts; each later pause doubles, up to [`LONGEST_PAUSE`].
const FIRST_PAUSE: Duration = Duration::from_millis(1);
const LONGEST_PAUSE: Duration = Duration::from_millis(50);

#[derive(Debug)]
pub(super) struct Held {
    _file: File,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Unheld {
    /// `Cancelled` carries the exit code for the recorded signal.
    Cancelled(u8),
    /// `Unsaid` carries the exit code of the failed `note`.
    Unsaid(u8),
    /// `Refused` names the lock path and reports why `open` rejected the entry or that `waited` reached
    /// the limit.
    Refused(String),
    /// `Fault` carries the path and the system's error of a failed open, status read or attempt.
    Fault(String),
}

/// The clock a wait reads and pauses on, so a test advances time itself.
trait Clock {
    /// The time since the wait's first attempt.
    fn elapsed(&self) -> Duration;
    fn pause(&mut self, span: Duration);
}

struct Monotonic(Instant);

impl Clock for Monotonic {
    fn elapsed(&self) -> Duration {
        self.0.elapsed()
    }

    fn pause(&mut self, span: Duration) {
        thread::sleep(span);
    }
}

/// `take` calls `note` once on the first contended attempt so the caller can report the wait.
pub(super) fn take(path: &Path, note: impl FnOnce() -> Result<(), u8>) -> Result<Held, Unheld> {
    let file = open(path)?;
    let mut clock = Monotonic(Instant::now());
    waited(&file, path, LIMIT, &mut clock, cancel::check, note)?;
    Ok(Held { _file: file })
}

/// `O_NOFOLLOW` fails the open of a link, and `O_NONBLOCK` returns from the open of a FIFO at once, so
/// `fstat` on the open descriptor decides whether the entry is a regular file.
fn open(path: &Path) -> Result<File, Unheld> {
    let fault = |error: &io::Error| Unheld::Fault(format!("{}: {error}", shown(path)));
    let opened = OpenOptions::new()
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path);
    let other = || Unheld::Refused(format!("the lock {} is no regular file", shown(path)));
    let file = match opened {
        Ok(file) => file,
        Err(error) => {
            return Err(match fs::symlink_metadata(path) {
                Ok(found) if found.is_symlink() => {
                    Unheld::Refused(format!("the lock {} is a link", shown(path)))
                }
                Ok(found) if !found.is_file() => other(),
                _ => fault(&error),
            });
        }
    };
    let found = file.metadata().map_err(|error| fault(&error))?;
    if found.is_file() {
        Ok(file)
    } else {
        Err(other())
    }
}

/// `waited` measures `limit` from the first attempt and caps each pause at the remaining time.
fn waited(
    file: &File,
    path: &Path,
    limit: Duration,
    clock: &mut impl Clock,
    cancelled: impl Fn() -> Result<(), u8>,
    note: impl FnOnce() -> Result<(), u8>,
) -> Result<(), Unheld> {
    let mut note = Some(note);
    let mut pause = FIRST_PAUSE;
    loop {
        match attempt(file) {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(error) => return Err(Unheld::Fault(format!("{}: {error}", shown(path)))),
        }
        cancelled().map_err(Unheld::Cancelled)?;
        if let Some(note) = note.take() {
            let said = note();
            cancelled().map_err(Unheld::Cancelled)?;
            said.map_err(Unheld::Unsaid)?;
        }
        let rest = limit.saturating_sub(clock.elapsed());
        if rest.is_zero() {
            return Err(Unheld::Refused(format!(
                "another push held the lock {} for {} seconds",
                shown(path),
                limit.as_secs()
            )));
        }
        clock.pause(pause.min(rest));
        pause = (pause * 2).min(LONGEST_PAUSE);
    }
}

fn attempt(file: &File) -> io::Result<bool> {
    loop {
        // SAFETY: `flock` takes an open descriptor and integer flags and touches no memory of the caller.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(true);
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EWOULDBLOCK) => return Ok(false),
            Some(libc::EINTR) => {}
            _ => return Err(error),
        }
    }
}

fn shown(path: &Path) -> Text {
    Text::from_os(path.as_os_str())
}
