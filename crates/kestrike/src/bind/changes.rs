//! Watches directories for additions while a check reads their entries one
//! after another.
//!
//! Invariant: [`Pass::still`] answers `true` only when, since the pass began
//! and since each of its directories' [`Pass::watch`] call, no entry was
//! created in or moved into that directory and no file directly in it was
//! written or truncated through the file system. A reading taken between the
//! calls then holds every use that a write under a watched directory could
//! have added, and a pass kept after its reading answers for every such
//! write made since. It answers `true` only while every directory that was
//! absent at its `watch` call is still absent: the kernel registers a
//! configfs subsystem's directory with no event, so a listing that appears
//! is seen by its presence alone.

use std::cell::RefCell;
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// The events that add an entry to a directory or change a file in it.
const ADDITIONS: u32 = libc::IN_CREATE | libc::IN_MOVED_TO | libc::IN_MODIFY;

/// One inotify instance and the watch of every event it has reported, in
/// the order the kernel queued them. A queue that overflowed reports the
/// kernel's overflow event, which names no watch and counts against every
/// [`Pass`], so a lost event still reads as a change.
pub(super) struct Changes {
    queue: File,
    reported: RefCell<Vec<i32>>,
}

/// The directories one pass over a listing watches, and the place in the
/// instance's reports where the pass began. Two passes that watch one
/// directory share its watch, so a pass answers for a change another pass's
/// read took off the queue.
pub(super) struct Pass<'a> {
    changes: &'a Changes,
    began: usize,
    watches: RefCell<Vec<i32>>,
    /// The directories that did not exist when the pass asked to watch
    /// them.
    absent: RefCell<Vec<PathBuf>>,
}

impl Changes {
    /// # Errors
    ///
    /// The kernel's error when it grants no inotify instance.
    pub(super) fn new() -> io::Result<Self> {
        // SAFETY: the call takes flags only.
        let descriptor = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        if descriptor < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a non-negative result is a descriptor the kernel opened
        // for this call, which nothing else owns.
        let queue = unsafe { File::from_raw_fd(descriptor) };
        Ok(Self {
            queue,
            reported: RefCell::new(Vec::new()),
        })
    }

    /// A pass that begins now, with no directory watched: an event queued
    /// before this call is no change to it.
    ///
    /// # Errors
    ///
    /// The kernel's error when the queue cannot be read.
    pub(super) fn pass(&self) -> io::Result<Pass<'_>> {
        self.report()?;
        Ok(Pass {
            changes: self,
            began: self.reported.borrow().len(),
            watches: RefCell::new(Vec::new()),
            absent: RefCell::new(Vec::new()),
        })
    }

    /// Moves every queued event's watch to the reports.
    fn report(&self) -> io::Result<()> {
        /// The bytes of an event before its name: the watch, the mask, the
        /// cookie and the name's length, four bytes each.
        const HEADER: usize = 16;
        let mut events = [0u8; 4096];
        let mut reported = self.reported.borrow_mut();
        loop {
            let read = match (&self.queue).read(&mut events) {
                Ok(read) => read,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) => return Err(error),
            };
            // The kernel returns whole events, each a header and its name.
            let mut rest = &events[..read];
            while let Some((header, after)) = rest.split_first_chunk::<HEADER>() {
                let [w0, w1, w2, w3, .., l0, l1, l2, l3] = *header;
                reported.push(i32::from_ne_bytes([w0, w1, w2, w3]));
                let name = u32::from_ne_bytes([l0, l1, l2, l3]) as usize;
                rest = after.get(name..).unwrap_or_default();
            }
        }
    }
}

impl Pass<'_> {
    /// Starts reporting additions under `dir`. The caller lists or reads
    /// `dir` after this returns, so an addition is in the listing or in the
    /// reports.
    ///
    /// # Errors
    ///
    /// `NotFound` when `dir` does not exist, and otherwise the kernel's
    /// error when it adds no watch.
    pub(super) fn watch(&self, dir: &Path) -> io::Result<()> {
        let path = CString::new(dir.as_os_str().as_bytes())?;
        // SAFETY: `path` is a NUL-terminated string that outlives the call,
        // and the descriptor is the instance the pass borrows.
        let watch = unsafe {
            libc::inotify_add_watch(self.changes.queue.as_raw_fd(), path.as_ptr(), ADDITIONS)
        };
        if watch < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::NotFound {
                self.absent.borrow_mut().push(dir.to_owned());
            }
            return Err(error);
        }
        self.watches.borrow_mut().push(watch);
        Ok(())
    }

    /// Whether the instance has reported no event on a watch of this pass,
    /// and no overflow, since the pass began, and every directory the pass
    /// found absent is absent now.
    ///
    /// # Errors
    ///
    /// The kernel's error when the queue cannot be read.
    pub(super) fn still(&self) -> io::Result<bool> {
        self.changes.report()?;
        let watches = self.watches.borrow();
        let reported = self.changes.reported.borrow();
        let changed = reported[self.began..]
            .iter()
            .any(|watch| *watch < 0 || watches.contains(watch));
        let appeared = (self.absent.borrow().iter()).any(|dir| dir.symlink_metadata().is_ok());
        Ok(!changed && !appeared)
    }
}
