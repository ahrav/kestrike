//! Opening a store: the lock, the filesystem contract, the startup barrier,
//! the state marker and the staging sweep; and the guard every mutation
//! runs under.

use std::cell::Cell;
use std::ffi::{CStr, CString};
use std::fs::{OpenOptions, TryLockError};
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use super::dir::{Dir, changed, names, open_dir, sync};
use super::publish::{FILE_MODE, Source, staging_name};
use super::{
    Error, MARKER, MARKER_BYTES, PROBE, PROBED, Refusal, STAGING, SWEEP_BOUND, Store, Unreadable,
    mount, read,
};
use crate::step::{self, Step};
use crate::sys;

/// The locked state directory handle: proof that this process holds the
/// directory's exclusive lock, released when the store drops. The store
/// keeps the lock's open file description to itself: every other handle it
/// opens, a read's directory handle included, is a fresh open.
#[derive(Debug)]
pub(super) struct Lock(Dir);

impl Store {
    pub(crate) fn for_collection(path: &Path) -> Result<Self, Error> {
        let (lock, path) = locked(path)?;
        let root = &lock.0;
        sync_root(root)?;
        if !marked(root)? {
            return Err(Refusal::Unmarked.into());
        }
        let staging = open_dir(root, STAGING)?;
        let store = Self {
            lock,
            path,
            staging,
            poisoned: Cell::new(false),
        };
        store.check_path()?;
        Ok(store)
    }
}

impl Store {
    /// Locks and opens the state directory at `path`, which must exist and
    /// meet the [store's filesystem contract](super#durability). Opening
    /// writes to the directory: it syncs the directory and its parent,
    /// creates `.staging` when absent, removes every staged file, creates
    /// and removes the rename probe's files, and writes the `.state`
    /// marker into a directory that holds nothing but `.staging`.
    ///
    /// # Errors
    ///
    /// [`Error::Refused`] for a directory that fails the
    /// [filesystem contract](super#durability), for an ancestor that is a
    /// symlink, is owned by another non-root user, or is group- or
    /// world-writable without the sticky bit, for an unmarked directory
    /// that holds entries other than what an interrupted startup leaves,
    /// and for a marker of other bytes;
    /// [`Error::Busy`] while another controller holds the directory;
    /// [`Error::ScanBound`] for a staging directory past its sweep bound;
    /// [`Error::Unreadable`] for a `.state` or `.staging` entry of the
    /// wrong kind or a symlink; [`Error::Replaced`] when the path stops
    /// naming the locked directory during startup; [`Error::Io`] for a
    /// failed call, a symlink at `path` included.
    pub fn open(path: &Path) -> Result<Self, Error> {
        let (lock, path) = locked(path)?;
        let root = &lock.0;
        sync_root(root)?;
        // The marker check precedes the first write, so a refused directory
        // is left unchanged.
        let marked = marked(root)?;
        // The root was synced above, so only a staging directory this call
        // created needs another root sync.
        if changed(
            step::call(Step::Mkdir, || sys::mkdir(&root.file, STAGING, 0o700)),
            io::ErrorKind::AlreadyExists,
        )? {
            sync(root)?;
        }
        let staging = open_dir(root, STAGING)?;
        let store = Self {
            lock,
            path,
            staging,
            poisoned: Cell::new(false),
        };
        store.guard(store.root(), || store.startup(marked))?;
        Ok(store)
    }

    /// The state directory's handle.
    pub fn root(&self) -> &Dir {
        &self.lock.0
    }

    /// The state directory's canonical path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Empties the staging directory, probes no-replace rename, and writes
    /// the state marker unless the directory is `marked`. An unmarked
    /// directory's staging directory may hold only what an interrupted
    /// startup leaves: the probe's files and the marker's staged file. Any
    /// other entry refuses the directory before the sweep removes anything.
    fn startup(&self, marked: bool) -> Result<(), Error> {
        let staged = read::entries(&self.staging, SWEEP_BOUND)?;
        let marker = staging_name(self.root(), MARKER);
        let own = [PROBE, PROBED, &marker].map(CStr::to_bytes);
        if !marked && !staged.iter().all(|name| own.contains(&name.as_slice())) {
            return Err(Refusal::Unmarked.into());
        }
        for staged in staged {
            let staged = CString::new(staged).expect("directory entries hold no NUL");
            step::call(Step::Unlink, || sys::unlink(&self.staging.file, &staged))?;
        }
        sync(&self.staging)?;
        let probe = step::call(Step::Open, || {
            sys::open_beneath(
                &self.staging.file,
                PROBE,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                0o600,
            )
        })?;
        step::last(Step::Close, || sys::close(probe))?;
        step::call(Step::Rename, || {
            sys::rename(&self.staging.file, PROBE, &self.staging.file, PROBED, true)
        })?;
        step::call(Step::Unlink, || sys::unlink(&self.staging.file, PROBED))?;
        if !marked {
            self.publish(
                self.root(),
                MARKER,
                Source::Bytes(MARKER_BYTES),
                FILE_MODE,
                true,
            )?;
        }
        Ok(())
    }

    /// Runs mutation `op` through `dir` between two checks that the state
    /// directory's path names the locked inode and that the running user
    /// owns the directory with mode 0700. Any failure poisons the store, so
    /// no later mutation runs.
    ///
    /// # Panics
    ///
    /// When `dir` lies under another state directory, which no correct
    /// caller passes.
    pub(super) fn guard<T>(
        &self,
        dir: &Dir,
        op: impl FnOnce() -> Result<T, Error>,
    ) -> Result<T, Error> {
        self.writable(dir)?;
        let result = self
            .check()
            .and_then(|()| op())
            .and_then(|value| self.check().map(|()| value));
        if result.is_err() {
            self.poisoned.set(true);
        }
        result
    }

    /// The checks every mutation through `dir` passes before it starts:
    /// `dir` is this store's, and the store is unpoisoned.
    ///
    /// # Errors
    ///
    /// [`Error::Poisoned`] when an earlier mutation failed.
    ///
    /// # Panics
    ///
    /// When `dir` lies under another state directory.
    pub(crate) fn writable(&self, dir: &Dir) -> Result<(), Error> {
        self.owns(dir);
        if self.poisoned.get() {
            return Err(Error::Poisoned);
        }
        Ok(())
    }

    /// Asserts that `dir` lies under this store's state directory. A handle
    /// from an earlier store over the same directory passes.
    ///
    /// # Panics
    ///
    /// When `dir` lies under another state directory, which no correct
    /// caller passes.
    pub(super) fn owns(&self, dir: &Dir) {
        assert_eq!(
            dir.state,
            self.root().state,
            "a store uses only its own directory handles"
        );
    }

    /// Checks that no ancestor of the state directory is a symlink,
    /// foreign-owned or shared, then runs the check every mutation runs. A
    /// failure leaves the store unpoisoned, so a caller can still write a
    /// record that names the refusal.
    ///
    /// # Errors
    ///
    /// [`Error::Refused`] for a refused ancestor, owner or mode,
    /// [`Error::Replaced`] when the path names another inode, and
    /// [`Error::Io`] for a failed status query.
    pub(crate) fn check_path(&self) -> Result<(), Error> {
        super::view::ancestors(&self.path)?;
        self.check()
    }

    /// The check every mutation runs before and after its work: the running
    /// user owns the state directory with permission bits 0700, and its path
    /// still names the locked inode.
    ///
    /// # Errors
    ///
    /// [`Error::Refused`] holding [`Refusal::Owner`] or [`Refusal::Mode`]
    /// for another owner or mode, [`Error::Replaced`] when the path names
    /// another inode, and [`Error::Io`] when the directory's status or the
    /// path fails to read.
    fn check(&self) -> Result<(), Error> {
        let status = step::call(Step::Stat, || self.root().file.metadata())?;
        mount::owned(status.uid(), status.mode(), sys::euid())?;
        if names(&self.path, self.root().state)? {
            Ok(())
        } else {
            Err(Error::Replaced)
        }
    }
}

/// Whether `root` holds this store's state marker. A directory without the
/// marker is refused unless it holds nothing but the staging directory, so
/// the store initializes only a directory it alone has written.
fn marked(root: &Dir) -> Result<bool, Error> {
    match read::bounded(root, MARKER, MARKER_BYTES.len() as u64) {
        Ok(Some(marker)) if marker.bytes() == MARKER_BYTES => Ok(true),
        Ok(Some(_)) | Err(Unreadable::Oversize) => Err(Refusal::Marker.into()),
        Err(unreadable) => Err(unreadable.into()),
        Ok(None) if read::holds_only(root, &[STAGING])? => Ok(false),
        Ok(None) => Err(Refusal::Unmarked.into()),
    }
}

fn locked(path: &Path) -> Result<(Lock, PathBuf), Error> {
    // The path is made absolute once, so a later working-directory
    // change leaves the identity check on the same directory, and its
    // `.` components and trailing separator are dropped, so
    // `O_NOFOLLOW` applies to the real final name.
    let path: PathBuf = step::call(Step::Open, || std::path::absolute(path))?
        .components()
        .collect();
    let file = step::call(Step::Open, || {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(&path)
    })?;
    let locked = step::call(Step::Lock, || match file.try_lock() {
        Ok(()) => Ok(true),
        Err(TryLockError::WouldBlock) => Ok(false),
        Err(TryLockError::Error(error)) => Err(error),
    })?;
    if !locked {
        return Err(Error::Busy);
    }
    super::view::ancestors(&path)?;
    let path = step::call(Step::Open, || path.canonicalize())?;
    let status = step::call(Step::Stat, || file.metadata())?;
    mount::check(&file, &status)?;
    let pinned = (status.dev(), status.ino());
    let root = Dir {
        file,
        ino: status.ino(),
        state: pinned,
    };
    Ok((Lock(root), path))
}

fn sync_root(root: &Dir) -> Result<(), Error> {
    // The directory's own entry and its entries are durable before any
    // record is acknowledged, whatever an earlier controller left.
    sync(root)?;
    let parent = step::call(Step::Open, || sys::open_parent(&root.file))?;
    step::call(Step::Sync, || parent.sync_all())?;
    Ok(())
}
