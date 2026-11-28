//! The host reservation: an exclusive `flock` of `<directory>/fis.lock`, held for the holder's life and
//! passed to a child the holder starts.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command};

/// The reservation's descriptor, open with its lock until the value drops. A child started through
/// [`Reservation::spawn_holding`] holds a copy of the descriptor, and with it the lock, until the child
/// and every process that inherits that copy ends.
#[derive(Debug)]
#[must_use = "the reservation frees when the value drops and no child holds it"]
pub struct Reservation {
    file: File,
}

/// Opens `<directory>/fis.lock` for reading and writing, made with mode 0644 when absent and refused
/// where a link stands at the name, and takes `flock(LOCK_EX | LOCK_NB)`. A `flock` that a signal
/// interrupts runs again; every other failed attempt closes the file and gives none.
///
/// # Errors
///
/// The open's error.
pub fn reserve_host(directory: &Path) -> io::Result<Option<Reservation>> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW)
        .open(directory.join("fis.lock"))?;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(Some(Reservation { file })),
            Err(std::fs::TryLockError::Error(error))
                if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Ok(None),
        }
    }
}

impl Reservation {
    /// Starts `command` with the reservation's descriptor left open in the child at the same number:
    /// the child clears the descriptor's close-on-exec flag after its fork and before its exec. The
    /// command is consumed, so no later start reuses the descriptor's number after the value drops.
    ///
    /// # Errors
    ///
    /// The error of the start, the flag's change in the child included.
    pub fn spawn_holding(&self, mut command: Command) -> io::Result<Child> {
        let fd = self.file.as_raw_fd();
        // SAFETY: the closure runs in the child between fork and exec and calls `fcntl` alone, which is
        // async-signal-safe and allocates nothing. `fd` is the reservation's descriptor, open in the
        // parent for the whole of `spawn` because `self` is borrowed across it, so the child's copy
        // stands at the same number when the closure runs.
        unsafe {
            command.pre_exec(move || {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        command.spawn()
    }
}

impl AsFd for Reservation {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.file.as_fd()
    }
}

#[cfg(test)]
#[path = "reservation_tests.rs"]
mod tests;
