//! Regular files opened for reading, and the identities of filesystem
//! entries. A file opened here is checked to be a regular file before any
//! byte of it is read, and its open never blocks, so a FIFO or device in
//! its place is refused at once. [`Opened`] reads pass through the step
//! seam one `read` at a time.

use std::fs::{File, Metadata};
use std::io;
use std::os::unix::fs::{FileExt, MetadataExt};

use super::Unreadable;
use crate::step::{self, Step};

/// What tells one version of a filesystem entry from another: its device,
/// inode, size, and modification and status-change times in nanoseconds.
/// A replacement gives the entry another inode, and every write or
/// attribute change sets its status-change time to the filesystem's
/// current timestamp, which no unprivileged call can set back, so
/// restoring an entry's modification time still leaves it another
/// identity. The filesystem timestamp advances in ticks of its clock, so
/// a same-size rewrite within the tick of the previous change, with its
/// modification time restored, keeps the identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Identity {
    device: u64,
    inode: u64,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl From<&Metadata> for Identity {
    fn from(status: &Metadata) -> Self {
        Self {
            device: status.dev(),
            inode: status.ino(),
            size: status.size(),
            modified: (status.mtime(), status.mtime_nsec()),
            changed: (status.ctime(), status.ctime_nsec()),
        }
    }
}

/// A regular file opened for reading, with the identity it had when it
/// was opened. It reads as a stream from its start and at any offset.
#[derive(Debug)]
pub struct Opened {
    pub(super) file: File,
    identity: Identity,
    mode: u32,
}

impl Opened {
    /// `file` as an opened regular file.
    ///
    /// # Errors
    ///
    /// [`Unreadable::NotRegular`] for another kind of file;
    /// [`Unreadable::Io`] for a failed status query.
    pub(super) fn new(file: File) -> Result<Self, Unreadable> {
        let status = step::call(Step::Stat, || file.metadata())?;
        if !status.is_file() {
            return Err(Unreadable::NotRegular);
        }
        let identity = Identity::from(&status);
        let mode = status.mode() & 0o7777;
        Ok(Self {
            file,
            identity,
            mode,
        })
    }

    /// The identity the file had when it was opened.
    pub fn identity(&self) -> Identity {
        self.identity
    }

    pub(crate) fn len(&self) -> u64 {
        self.identity.size
    }

    /// The file's permission bits when it was opened.
    pub fn mode(&self) -> u32 {
        self.mode
    }

    /// Fills `buffer` with the file's bytes from `offset`.
    ///
    /// # Errors
    ///
    /// `UnexpectedEof` when the file ends first; any failed read.
    pub fn read_exact_at(&self, buffer: &mut [u8], offset: u64) -> io::Result<()> {
        step::call(Step::Read, || self.file.read_exact_at(buffer, offset))
    }
}

impl io::Read for Opened {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        step::call(Step::Read, || self.file.read(buffer))
    }
}
