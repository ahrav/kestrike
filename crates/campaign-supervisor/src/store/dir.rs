//! Directory handles beneath the state directory, and the calls every
//! mutation shares: a confined directory open, a directory `fsync`, and the
//! reading of an errno that means the entry already had its target state.

use std::ffi::CStr;
use std::fs::File;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use super::{Error, Unreadable};
use crate::step::{self, Step};
use crate::sys;

/// A directory handle beneath one state directory, opened by a store or a
/// [view](super::View) over it. It carries that state directory's
/// `(device, inode)` identity, so a store refuses a handle from another
/// state directory for every operation.
#[derive(Debug)]
pub struct Dir {
    pub(super) file: File,
    pub(super) ino: u64,
    pub(super) state: (u64, u64),
}

impl Dir {
    pub(crate) fn duplicate(&self) -> Result<Self, Error> {
        open_dir(self, c".").map_err(Error::from)
    }

    /// The returned handle shares `self.file`'s open file description.
    ///
    /// # Errors
    ///
    /// Returns `Unreadable` if duplicating `self.file`'s descriptor fails.
    pub(super) fn share(&self) -> Result<Self, Unreadable> {
        let file = step::call(Step::Open, || self.file.try_clone())?;
        Ok(Self {
            file,
            ino: self.ino,
            state: self.state,
        })
    }

    /// Device and inode of the pinned directory handle.
    pub(crate) fn identity(&self) -> (u64, u64) {
        (self.state.0, self.ino)
    }
}

/// Opens directory `name` beneath `dir`, confined.
pub(super) fn open_dir(dir: &Dir, name: &CStr) -> Result<Dir, Unreadable> {
    let file = step::call(Step::Open, || {
        sys::open_beneath(&dir.file, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)
    })?;
    let status = step::call(Step::Stat, || file.metadata())?;
    Ok(Dir {
        file,
        ino: status.ino(),
        state: dir.state,
    })
}

/// Whether `path` names the directory of `(device, inode)` identity
/// `state`, without following a symlink at its final name; a missing
/// entry names none.
pub(super) fn names(path: &Path, state: (u64, u64)) -> io::Result<bool> {
    match step::call(Step::Check, || path.symlink_metadata()) {
        Ok(status) => Ok((status.dev(), status.ino()) == state),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// Makes `dir`'s entries durable.
pub(super) fn sync(dir: &Dir) -> Result<(), Error> {
    step::call(Step::Sync, || dir.file.sync_all()).map_err(Error::from)
}

/// Whether the call that returned `result` made its change, given that it
/// fails with `already` when its entry already had the target state.
pub(super) fn changed(result: io::Result<()>, already: io::ErrorKind) -> io::Result<bool> {
    match result {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == already => Ok(false),
        Err(error) => Err(error),
    }
}
