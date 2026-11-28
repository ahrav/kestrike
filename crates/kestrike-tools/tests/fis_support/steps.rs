//! [`Steps`], the file steps of the system with a failure a case chooses at the file's sync, at a
//! directory's open or at a directory's sync, and a record of each directory opened to be synced.

use std::cell::RefCell;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

use kestrike_tools::host_stop::{Files, Links};

/// The system's file steps, but for the failures a case sets.
#[derive(Default)]
pub(crate) struct Steps {
    /// The file's sync fails with `EIO`.
    pub(crate) file_sync: bool,
    /// The open of this directory fails with `EACCES`.
    pub(crate) open: Option<PathBuf>,
    /// The sync of this directory, once opened, fails with `EIO`.
    pub(crate) directory_sync: Option<PathBuf>,
    /// Each directory opened, in order.
    pub(crate) opened: RefCell<Vec<PathBuf>>,
}

impl Files for Steps {
    fn open_directory(&self, path: &Path, links: Links) -> io::Result<File> {
        self.opened.borrow_mut().push(path.to_path_buf());
        if self.open.as_deref() == Some(path) {
            return Err(io::Error::from_raw_os_error(libc::EACCES));
        }
        kestrike_tools::host_stop::Disk.open_directory(path, links)
    }

    fn fsync(&self, file: &File) -> io::Result<()> {
        if self.file_sync {
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
        file.sync_all()
    }

    fn fsync_directory(&self, directory: &File) -> io::Result<()> {
        let last = self.opened.borrow().last().cloned();
        if last.is_some() && last == self.directory_sync {
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
        directory.sync_all()
    }
}
