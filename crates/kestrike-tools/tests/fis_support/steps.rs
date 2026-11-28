//! [`Steps`], the file steps of the system with a failure a case chooses at the file's sync, at a
//! directory's open, at a directory's sync, at a `mkdir` or at a path's `lstat`, a record of each directory opened
//! to be synced, and whether a path stood when the file's sync failed.

use std::cell::RefCell;
use std::fs::{self, File};
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
    /// The `mkdir` of this path fails with `EEXIST`, having made the directory first where the flag
    /// is set, as another maker's `mkdir` between the check and this one does.
    pub(crate) mkdir: Option<(PathBuf, bool)>,
    /// The `lstat` of this path fails with `EACCES`.
    pub(crate) lstat: Option<PathBuf>,
    /// The path whose entry the failing file sync looks for.
    pub(crate) probe: Option<PathBuf>,
    /// Whether an entry stood at [`Steps::probe`] when the file's sync failed.
    pub(crate) probed: RefCell<Option<bool>>,
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
            if let Some(probe) = &self.probe {
                *self.probed.borrow_mut() = Some(fs::symlink_metadata(probe).is_ok());
            }
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
        file.sync_all()
    }

    fn mkdir(&self, path: &Path) -> io::Result<()> {
        match &self.mkdir {
            Some((raced, made)) if raced == path => {
                if *made {
                    fs::create_dir(path)?;
                }
                Err(io::Error::from_raw_os_error(libc::EEXIST))
            }
            _ => fs::create_dir(path),
        }
    }

    fn lstat(&self, path: &Path) -> io::Result<fs::Metadata> {
        if self.lstat.as_deref() == Some(path) {
            return Err(io::Error::from_raw_os_error(libc::EACCES));
        }
        fs::symlink_metadata(path)
    }

    fn fsync_directory(&self, directory: &File) -> io::Result<()> {
        let last = self.opened.borrow().last().cloned();
        if last.is_some() && last == self.directory_sync {
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
        directory.sync_all()
    }
}
