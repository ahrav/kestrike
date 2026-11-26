//! Read-only views of a directory a store published, such as an archive
//! that many commands use at once. A view writes nothing. Its path is
//! resolved to its canonical form once, symlinks included, and every entry
//! it opens resolves beneath its handles under the store's confined
//! resolution: no symlink, magic link or mount crossing, so an entry
//! replaced by a symlink is refused rather than followed. The viewed
//! directory meets the read side of the store's filesystem contract: it
//! lies on an ext4 or xfs mount, every ancestor passes the ownership and
//! mode policy of [`ancestors`], and the running user owns it with mode
//! 0700, checked at the open and by each [`View::status`]. [`View::open`]
//! takes no lock; [`View::snapshot`] holds the state directory's lock
//! shared while it lives, so snapshots run beside each other and a
//! controller's `Store::open` is refused with [`Error::Busy`] while one
//! lives. [`View::current`] tells
//! whether the path still names the viewed directory, as a caller that
//! hands the path to another process requires. A durability barrier that
//! fails is sticky per inode: every later barrier on that file or
//! directory fails too, so a reader cannot trust a record whose sync
//! failed once. Durability guarantees require a view from [`View::open`]:
//! on a view from [`View::unfenced`], `barrier` and `sync_file` return
//! `Ok` at once.

use std::ffi::CStr;
use std::fs::{OpenOptions, TryLockError};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use super::dir::{names, open_dir};
use super::file::{Identity, Opened};
use super::read::{absent_as_none, bounded, listed, shared};
use super::{Dir, Error, Name, Read, Refusal, Unreadable, mount};
use crate::step::{self, Step};
use crate::sys;

/// A read-only view of one directory and the entries beneath it.
#[derive(Debug)]
pub struct View {
    root: Dir,
    path: PathBuf,
    fenced: bool,
    failed_syncs: std::sync::Mutex<std::collections::BTreeSet<(u64, u64)>>,
    read_fault: std::sync::Mutex<Option<std::io::Error>>,
}

impl View {
    /// Opens the directory `path` resolves to.
    ///
    /// # Errors
    ///
    /// [`Error::Unreadable`] when the path does not resolve or names no
    /// directory; [`Error::Refused`] for a directory on another filesystem
    /// type than ext4 or xfs, or one another user owns or whose mode is
    /// not 0700, or holding [`Refusal::Ancestor`] when an ancestor is a
    /// symlink, is owned by another non-root user, or is group- or
    /// world-writable without the sticky bit; [`Error::Io`] when the mount
    /// table or an ancestor's status cannot be read.
    pub fn open(path: &Path) -> Result<Self, Error> {
        let unreadable = |error| Error::Unreadable(Unreadable::from(error));
        let path = step::call(Step::Open, || path.canonicalize()).map_err(unreadable)?;
        ancestors(&path)?;
        let file = step::call(Step::Open, || {
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
                .open(&path)
        })
        .map_err(unreadable)?;
        let status = step::call(Step::Stat, || file.metadata()).map_err(unreadable)?;
        mount::viewable(&file, &status)?;
        let root = Dir {
            file,
            ino: status.ino(),
            state: (status.dev(), status.ino()),
        };
        Ok(Self {
            root,
            path,
            fenced: true,
            failed_syncs: Default::default(),
            read_fault: Default::default(),
        })
    }

    /// Opens as [`View::open`] does, for a reader whose barriers run no
    /// `fsync`: [`View::barrier`], [`View::sync_file`] and
    /// [`View::evidence_digest`] read and return without syncing.
    ///
    /// # Errors
    ///
    /// As [`View::open`].
    pub(crate) fn unfenced(path: &Path) -> Result<Self, Error> {
        Ok(Self {
            fenced: false,
            ..Self::open(path)?
        })
    }

    /// Takes the state-directory lock through a read-only descriptor for the snapshot lifetime.
    pub(crate) fn snapshot(path: &Path) -> Result<Self, Error> {
        let view = Self::open(path)?;
        let status = step::call(Step::Stat, || view.root.file.metadata())?;
        mount::check(&view.root.file, &status)?;
        let locked = step::call(Step::Lock, || match view.root.file.try_lock_shared() {
            Ok(()) => Ok(true),
            Err(TryLockError::WouldBlock) => Ok(false),
            Err(TryLockError::Error(error)) => Err(error),
        })?;
        if !locked {
            return Err(Error::Busy);
        }
        if !view.current()? {
            return Err(Error::Replaced);
        }
        Ok(view)
    }

    pub(crate) fn require_state_marker(&self) -> Result<(), Error> {
        match bounded(&self.root, super::MARKER, super::MARKER_BYTES.len() as u64) {
            Ok(Some(marker)) if marker.bytes() == super::MARKER_BYTES => Ok(()),
            Ok(None) => Err(Refusal::Unmarked.into()),
            Ok(Some(_)) | Err(Unreadable::Oversize) => Err(Refusal::Marker.into()),
            Err(error) => Err(error.into()),
        }
    }

    /// The processes that hold the viewed directory's `flock`, read from
    /// `/proc/locks` without touching the lock. The table names only
    /// holders visible in this process's PID namespace, and a holder's
    /// command is read after its pid, so a reused pid can lend its command
    /// to an entry. `Ok(Err)` carries the reason the holders are unknown:
    /// the table is absent, refused to this user, no regular file, or
    /// larger than 1 MiB.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] for a host fault reading the table or a holder's
    /// command line.
    pub fn lock_holders(&self) -> Result<Result<Vec<super::Holder>, String>, Error> {
        super::holders::holders(self.root.state)
    }

    /// The canonical path of the viewed directory.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether the view's canonical path still names the directory the
    /// view opened.
    ///
    /// # Errors
    ///
    /// Any failed status query other than a missing entry, which is
    /// `false`.
    pub fn current(&self) -> std::io::Result<bool> {
        names(&self.path, self.root.state).inspect_err(|error| self.note_io(error))
    }

    /// The viewed directory's handle.
    pub fn root(&self) -> &Dir {
        &self.root
    }

    /// The bytes and inodes available to unprivileged users on the viewed
    /// directory's filesystem (`f_bavail`, `f_favail`), as `(bytes,
    /// inodes)`.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] for a failed `fstatvfs` or a zero fragment size.
    pub fn free_space(&self) -> Result<(u64, u64), Error> {
        let (bytes, inodes, _) = self
            .root
            .free_space()
            .inspect_err(|error| self.note_io(error))?;
        Ok((bytes, inodes))
    }

    /// The viewed directory's own identity, after checking that the
    /// running user still owns it with mode 0700. A rename of the
    /// directory sets its status-change time, so a directory moved away
    /// and back has another identity.
    ///
    /// # Errors
    ///
    /// [`Error::Refused`] for another owner or mode; [`Error::Io`] for a
    /// failed status query.
    pub fn status(&self) -> Result<Identity, Error> {
        (|| {
            ancestors(&self.path)?;
            let status = step::call(Step::Stat, || self.root.file.metadata())?;
            mount::owned(status.uid(), status.mode(), sys::euid())?;
            Ok(Identity::from(&status))
        })()
        .inspect_err(|error| self.note_store(error))
    }

    /// Opens directory `name` beneath `dir`; `None` when no entry has the
    /// name.
    ///
    /// # Errors
    ///
    /// As [`Store::open_dir`](super::Store::open_dir).
    ///
    /// # Panics
    ///
    /// When `dir` lies under another view.
    pub fn open_dir(&self, dir: &Dir, name: &Name) -> Result<Option<Dir>, Unreadable> {
        self.owns(dir);
        absent_as_none(open_dir(dir, name.as_c_str()))
            .inspect_err(|error| self.note_unreadable(error))
    }

    /// Opens the regular file `name` beneath `dir`; `None` when no entry
    /// has the name.
    ///
    /// # Errors
    ///
    /// As [`Store::read`](super::Store::read), past-bound refusal aside.
    ///
    /// # Panics
    ///
    /// When `dir` lies under another view.
    pub fn open_file(&self, dir: &Dir, name: &Name) -> Result<Option<Opened>, Unreadable> {
        self.owns(dir);
        let flags = libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOCTTY;
        (|| match absent_as_none(open(dir, name.as_c_str(), flags))? {
            Some(file) => Opened::new(file).map(Some),
            None => Ok(None),
        })()
        .inspect_err(|error| self.note_unreadable(error))
    }

    /// The identity of entry `name` beneath `dir`, of any kind, without
    /// opening it for reading; `None` when no entry has the name.
    ///
    /// # Errors
    ///
    /// [`Unreadable::Symlink`] for a symlink, [`Unreadable::CrossMount`]
    /// for a mount point, and [`Unreadable::Io`] for a failed call.
    ///
    /// # Panics
    ///
    /// When `dir` lies under another view.
    pub fn identity(&self, dir: &Dir, name: &Name) -> Result<Option<Identity>, Unreadable> {
        self.owns(dir);
        (|| {
            let Some(file) = absent_as_none(open(dir, name.as_c_str(), libc::O_PATH))? else {
                return Ok(None);
            };
            let status = step::call(Step::Stat, || file.metadata())?;
            Ok(Some(Identity::from(&status)))
        })()
        .inspect_err(|error| self.note_unreadable(error))
    }

    /// Reads the regular file `name` beneath `dir`, as
    /// [`Store::read`](super::Store::read) does.
    ///
    /// # Errors
    ///
    /// As [`Store::read`](super::Store::read).
    ///
    /// # Panics
    ///
    /// When `dir` lies under another view.
    pub fn read(&self, dir: &Dir, name: &Name, bound: u64) -> Result<Option<Read>, Unreadable> {
        self.owns(dir);
        shared(dir, name.as_c_str(), bound).inspect_err(|error| self.note_unreadable(error))
    }

    pub(crate) fn raw_list(&self, dir: &Dir, bound: usize) -> Result<Vec<Vec<u8>>, Error> {
        self.owns(dir);
        super::read::entries(dir, bound).inspect_err(|error| self.note_store(error))
    }

    /// The names of `dir`'s entries, sorted, without the store's own
    /// entries of the viewed directory, as
    /// [`Store::list`](super::Store::list) lists them.
    ///
    /// # Errors
    ///
    /// As [`Store::list`](super::Store::list).
    ///
    /// # Panics
    ///
    /// When `dir` lies under another view.
    pub fn list(&self, dir: &Dir, bound: usize) -> Result<Vec<Name>, Error> {
        self.owns(dir);
        listed(dir, self.root.ino, bound).inspect_err(|error| self.note_store(error))
    }

    /// Makes the file `read` came from and its directory durable, so a
    /// record a reader trusts survives a crash after the read. On a view
    /// from [`View::unfenced`], returns `Ok` at once; the durability
    /// guarantee requires a view from [`View::open`].
    ///
    /// # Panics
    ///
    /// When `read` lies under another view.
    pub(crate) fn barrier(&self, read: &Read) -> Result<(), Error> {
        self.sync(&read.dir, &read.file)
            .inspect_err(|error| self.note_store(error))
    }

    /// Makes an opened evidence file and its directory durable. On a view
    /// from [`View::unfenced`], returns `Ok` at once; the durability
    /// guarantee requires a view from [`View::open`].
    pub(crate) fn sync_file(&self, dir: &Dir, file: &Opened) -> Result<(), Error> {
        self.sync(dir, &file.file)
            .inspect_err(|error| self.note_store(error))
    }

    fn sync(&self, dir: &Dir, file: &std::fs::File) -> Result<(), Error> {
        self.owns(dir);
        if !self.fenced {
            return Ok(());
        }
        let metadata = step::call(Step::Stat, || file.metadata())?;
        let identity = (metadata.dev(), metadata.ino());
        let failed = |identity| {
            self.failed_syncs
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .contains(&identity)
        };
        if failed(identity) || failed(dir.identity()) {
            return Err(Error::Barrier(std::io::Error::from_raw_os_error(libc::EIO)));
        }
        let record = |identity| {
            self.failed_syncs
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(identity);
        };
        if let Err(error) = step::call(Step::Sync, || file.sync_all()) {
            record(identity);
            return Err(Error::Barrier(error));
        }
        if let Err(error) = super::dir::sync(dir) {
            record(dir.identity());
            return Err(match error {
                Error::Io(error) => Error::Barrier(error),
                error => error,
            });
        }
        Ok(())
    }

    pub(super) fn note_unreadable(&self, error: &Unreadable) {
        if error.faulted()
            && let Unreadable::Io(error) = error
        {
            self.note_io(error);
        }
    }

    fn note_store(&self, error: &Error) {
        match error {
            Error::Io(error) | Error::Barrier(error) => self.note_io(error),
            Error::Unreadable(error) => self.note_unreadable(error),
            _ => {}
        }
    }

    fn note_io(&self, error: &std::io::Error) {
        let mut fault = self
            .read_fault
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if fault.is_none() {
            *fault = Some(copy_io(error));
        }
    }

    /// Returns the first host read or synchronization failure observed by this view.
    pub(crate) fn check_faults(&self) -> Result<(), Error> {
        let fault = self
            .read_fault
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match fault.as_ref() {
            Some(error) => Err(Error::Io(copy_io(error))),
            None => Ok(()),
        }
    }

    #[cfg(test)]
    pub(crate) fn barriers_succeeded(&self) -> bool {
        self.failed_syncs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty()
    }

    fn owns(&self, dir: &Dir) {
        assert_eq!(
            dir.state, self.root.state,
            "a view uses only its own directory handles"
        );
    }
}

fn copy_io(error: &std::io::Error) -> std::io::Error {
    match error.raw_os_error() {
        Some(errno) => std::io::Error::from_raw_os_error(errno),
        None => std::io::Error::new(error.kind(), error.to_string()),
    }
}

/// Checks every proper ancestor of `path`, as spelled: each is a directory
/// the running user or root owns, and is either free of group and other
/// write permission or carries the sticky bit. An ancestor that reads as a
/// symlink is refused, so a `..` component in `path` is checked at the
/// directory it is spelled beneath.
///
/// # Errors
///
/// [`Error::Refused`] holding [`Refusal::Ancestor`] naming the nearest
/// ancestor that fails; [`Error::Io`] for a failed status query.
pub(crate) fn ancestors(path: &Path) -> Result<(), Error> {
    for ancestor in path.ancestors().skip(1) {
        let status = step::call(Step::Stat, || ancestor.symlink_metadata())?;
        admit(ancestor, &status)?;
    }
    Ok(())
}

/// Checks `path` as given and every existing ancestor of it by the rule of
/// [`ancestors`], after making it absolute against the working directory
/// without resolving a symlink; a missing component passes, since the
/// caller creates it. The check runs before the caller creates anything,
/// so a symlink in the given prefix is refused while every component below
/// the first existing ancestor is still absent; the canonical path's check
/// at the call site then covers the created path.
///
/// # Errors
///
/// [`Error::Refused`] holding [`Refusal::Ancestor`] naming the nearest
/// component that fails; [`Error::Io`] for a failed status query.
pub(crate) fn given_ancestors(path: &Path) -> Result<(), Error> {
    let absolute = step::call(Step::Open, || std::path::absolute(path))?;
    for ancestor in absolute.ancestors() {
        match step::call(Step::Stat, || ancestor.symlink_metadata()) {
            Ok(status) => admit(ancestor, &status)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

/// Admits `ancestor` with `status` as a directory the running user or root
/// owns that is either free of group and other write permission or
/// carries the sticky bit, and is no symlink.
fn admit(ancestor: &Path, status: &std::fs::Metadata) -> Result<(), Error> {
    let linked = status.file_type().is_symlink();
    let foreign = status.uid() != 0 && status.uid() != sys::euid();
    let shared = status.mode() & 0o022 != 0 && status.mode() & 0o1000 == 0;
    if linked || foreign || shared {
        return Err(Refusal::Ancestor(ancestor.display().to_string()).into());
    }
    Ok(())
}

fn open(dir: &Dir, name: &CStr, flags: libc::c_int) -> Result<std::fs::File, Unreadable> {
    step::call(Step::Open, || sys::open_beneath(&dir.file, name, flags, 0))
        .map_err(Unreadable::from)
}
