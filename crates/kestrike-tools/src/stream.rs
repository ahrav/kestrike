//! [`emit`] writes a tool's text to a standard stream so that every failed write reaches the caller.

use std::fs::File;
use std::io::{self, Write};
use std::os::fd::BorrowedFd;

/// `emit` writes `text` to a duplicate of `stream`, so a write error such as `EBADF` on a descriptor opened
/// read-only reaches the caller. If duplication returns `EBADF`, `emit` discards `text` and returns `Ok(())`.
pub fn emit(stream: BorrowedFd<'_>, text: &str) -> io::Result<()> {
    match stream.try_clone_to_owned() {
        Ok(owned) => File::from(owned).write_all(text.as_bytes()),
        Err(error) if error.raw_os_error() == Some(libc::EBADF) => Ok(()),
        Err(error) => Err(error),
    }
}
