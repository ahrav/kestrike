//! The owner lock: one exclusive lock per owner state directory, which that
//! owner's binding, release and run share. Owners on one host use distinct
//! directories, so distinct locks.
//!
//! The device locks: one exclusive lock per PCI address. Every holder of a
//! device lock, an owner's bind or release or a running SPDK driver, must use
//! the same lock directory for host-wide device exclusion. The directory must
//! have all group and other permission bits cleared, which restricts
//! unprivileged directory traversal to the directory's owner.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use super::mappings::{Mappings, MappingsError};

pub(crate) const DEVICE_LOCKS: &str = "/run/kestrike-bind";

fn lock_file(path: &Path, mode: u32) -> io::Result<File> {
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    file.try_lock()?;
    Ok(file)
}

/// `OwnerLock` holds one state directory's lock for the lifetime of its open file.
///
/// The file lock excludes other processes. Within the process the lock stays on one thread: it is not `Sync`, so
/// readers and the one records writer that borrow it shared, such as the fresh path's local records beside the driver
/// its connect attaches, run on the thread that holds it and never at once.
///
/// ```compile_fail,E0277
/// fn shared_across_threads<T: Sync>() {}
/// shared_across_threads::<kestrike::bind::OwnerLock>();
/// ```
#[derive(Debug)]
pub struct OwnerLock {
    _file: File,
    state_dir: PathBuf,
    _one_thread: std::marker::PhantomData<std::cell::Cell<()>>,
}

/// If [`OwnerLock`] implements `Sync`, two `AmbiguousIfSync` implementations apply and the lookup becomes ambiguous.
/// Stable rustdoc accepts any compile error for the `OwnerLock` doctest, including a stale path.
#[cfg(test)]
const _: () = {
    trait AmbiguousIfSync<A> {
        fn item() {}
    }
    impl<T: ?Sized> AmbiguousIfSync<()> for T {}
    impl<T: ?Sized + Sync> AmbiguousIfSync<u8> for T {}
    let _ = <OwnerLock as AmbiguousIfSync<_>>::item;
};

impl OwnerLock {
    /// Takes the lock in `state_dir` without waiting.
    ///
    /// # Errors
    ///
    /// `acquire` returns `WouldBlock` while another holder has the lock, `PermissionDenied` for an opened non-regular lock entry such as a FIFO with a reader, and the open error otherwise; a FIFO without a reader fails the open with `ENXIO`.
    pub fn acquire(state_dir: &Path) -> io::Result<Self> {
        // `Path::parent` of a bare file name is the empty path, which
        // `canonicalize` refuses; the current directory holds the file then.
        let state_dir = if state_dir.as_os_str().is_empty() {
            Path::new(".")
        } else {
            state_dir
        };
        let state_dir = fs::canonicalize(state_dir)?;
        let file = lock_file(&state_dir.join("bind.lock"), 0o666)?;
        Ok(Self {
            _file: file,
            state_dir,
            _one_thread: std::marker::PhantomData,
        })
    }

    pub(crate) fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    /// Reads the mappings file of the locked directory, so the binding a
    /// driver attaches is the one this lock serializes.
    ///
    /// # Errors
    ///
    /// [`Mappings::read_regular`]'s errors: `Io` for an absent or unreadable
    /// file, `ELOOP` for a final symbolic link, `InvalidData` for a
    /// non-regular, oversized or non-UTF-8 file, then the parse errors of
    /// [`Mappings::read`].
    pub fn mappings(&self) -> Result<Mappings, MappingsError> {
        Mappings::read_regular(&self.state_dir.join("mappings"))
    }
}

/// A device's lock, held as long as the open file it was taken on.
#[derive(Debug)]
pub struct DeviceLock {
    _file: File,
}

impl DeviceLock {
    /// Takes `bdf`'s lock in `dir` without waiting. A `dir` that is not
    /// already a directory goes through recursive creation with mode
    /// `0o700` first.
    ///
    /// # Errors
    ///
    /// Creation errors propagate before validation: an existing regular
    /// file, a dangling symlink or a symlink to a non-directory yields
    /// `AlreadyExists`. Returns `PermissionDenied` when validation finds a
    /// non-directory, such as a symlink to a directory, or group/other
    /// permission bits. `WouldBlock` while another holder has the lock.
    /// `acquire` returns `PermissionDenied` for an opened non-regular lock entry such as a FIFO with a reader, and `ENXIO` for a FIFO without a reader.
    /// An initial metadata error leads to creation. Metadata errors after
    /// creation, open errors, and other locking errors propagate; opening a
    /// symlink lock file yields `ELOOP`.
    pub fn acquire(dir: &Path, bdf: &str) -> io::Result<Self> {
        let meta = match fs::symlink_metadata(dir) {
            Ok(meta) if meta.is_dir() => meta,
            _ => {
                DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
                fs::symlink_metadata(dir)?
            }
        };
        if !meta.is_dir() || meta.mode() & 0o077 != 0 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let mut path = PathBuf::with_capacity(dir.as_os_str().len() + bdf.len() + "/.lock".len());
        path.push(dir);
        path.push(bdf);
        path.as_mut_os_string().push(".lock");
        let file = lock_file(&path, 0o600)?;
        Ok(Self { _file: file })
    }
}
