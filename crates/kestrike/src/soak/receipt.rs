//! A receipt file is distinct from every state record before the soak truncates or writes it.
//!
//! - RECEIPT-NOT-A-RECORD: the soak refuses a receipt that aliases the mappings, an authority file, a retained
//!   refusal record, their staging files or a soak-store entry before it truncates or writes the receipt.
//! - CREATED-ONLY-REMOVAL: [`Entry`] anchors cleanup to the opened creation directory even if a directory link in
//!   the receipt path changes.

use std::ffi::CString;
use std::fs::{File, Metadata, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::Path;

use super::store::STORE_DIR;
use crate::bind::REFUSAL_PREFIX;

/// `state` must be the locked state directory.
///
/// # Errors
///
/// Returns an error if the receipt names a block device, cannot be opened or created, aliases a state record, or
/// fails metadata inspection or truncation. State-directory read errors also propagate. Cleanup failures are
/// appended to the original error.
pub fn open_receipt(path: &Path, state: &Path) -> Result<File, String> {
    let block = "KESTRIKE_SOAK_RECEIPT names a block device";
    if std::fs::metadata(path).is_ok_and(|named| named.file_type().is_block_device()) {
        return Err(block.to_owned());
    }
    let cannot = || format!("{} cannot be created", path.to_string_lossy());
    let entry = Entry::of(path).map_err(|_| cannot())?;
    let (file, created) = match entry.open(libc::O_WRONLY) {
        Ok(file) => (file, false),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let file = entry
                .open(libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL)
                .map_err(|_| cannot())?;
            (file, true)
        }
        Err(_) => return Err(cannot()),
    };
    let checked = file
        .metadata()
        .map_err(|error| format!("receipt: {error}"))
        .and_then(|own| {
            if own.file_type().is_block_device() {
                return Err(block.to_owned());
            }
            alias(state, &own).map(|()| own)
        });
    let own = match checked {
        Ok(own) => own,
        Err(error) if created => {
            #[cfg(test)]
            if let Some(pause) = BEFORE_REMOVAL.take() {
                pause();
            }
            let own = file
                .metadata()
                .map_err(|failed| format!("{error}; receipt: {failed}"))?;
            return Err(match entry.remove(&own) {
                Ok(()) => error,
                Err(failed) => format!("{error}; {failed}"),
            });
        }
        Err(error) => return Err(error),
    };
    if own.is_file() {
        file.set_len(0)
            .map_err(|error| format!("receipt: {error}"))?;
    }
    Ok(file)
}

/// `Entry` anchors receipt opens and cleanup to the same opened directory.
struct Entry {
    directory: File,
    name: CString,
}

impl Entry {
    fn of(path: &Path) -> io::Result<Self> {
        let bytes = path.as_os_str().as_bytes();
        let (directory, name) = match bytes.iter().rposition(|&byte| byte == b'/') {
            Some(0) => (&b"/"[..], &bytes[1..]),
            Some(at) => (&bytes[..at], &bytes[at + 1..]),
            None => (&b"."[..], bytes),
        };
        if matches!(name, b"" | b"." | b"..") {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let name = CString::new(name).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY)
            .open(Path::new(std::ffi::OsStr::from_bytes(directory)))?;
        Ok(Self { directory, name })
    }

    fn open(&self, flags: libc::c_int) -> io::Result<File> {
        let mode: libc::mode_t = 0o666;
        // SAFETY: `name` is NUL-terminated and `directory` is an open directory descriptor this entry owns.
        let fd = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                self.name.as_ptr(),
                flags | libc::O_CLOEXEC,
                mode,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a nonnegative result is a descriptor this process now owns.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    fn remove(&self, own: &Metadata) -> Result<(), String> {
        let failed = |error: io::Error| format!("removing the receipt: {error}");
        let named = self
            .open(libc::O_PATH | libc::O_NOFOLLOW)
            .and_then(|named| named.metadata())
            .map_err(failed)?;
        if (named.dev(), named.ino()) != (own.dev(), own.ino()) {
            return Err(
                "removing the receipt: its name links another file, which stays".to_owned(),
            );
        }
        // SAFETY: `name` is NUL-terminated and `directory` is an open directory descriptor.
        if unsafe { libc::unlinkat(self.directory.as_raw_fd(), self.name.as_ptr(), 0) } != 0 {
            return Err(failed(io::Error::last_os_error()));
        }
        self.directory
            .sync_all()
            .map_err(|error| format!("syncing the receipt's directory: {error}"))
    }
}

/// `alias` rejects receipts that alias records in the locked state directory `state`: the mappings, an authority
/// file, a retained refusal record, the atomic writer's staging file of one of them, or an entry of the soak
/// store, matched by device and inode through any link.
///
/// # Errors
///
/// Returns an error if the receipt aliases a state record, listing the state directory fails, opening the store
/// directory or reading a record's metadata fails with an error other than `NotFound`, or reading a store entry
/// fails.
fn alias(state: &Path, own: &Metadata) -> Result<(), String> {
    let same = |path: &Path| match std::fs::metadata(path) {
        Ok(record) => Ok((record.dev(), record.ino()) == (own.dev(), own.ino())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("receipt: {}: {error}", path.display())),
    };
    for name in ["mappings", "host.key", "assignment", "authority"] {
        for staged in [name.to_owned(), format!("{name}.tmp")] {
            if same(&state.join(&staged))? {
                return Err(format!("KESTRIKE_SOAK_RECEIPT names the {staged} record"));
            }
        }
    }
    // A retained refusal record and its staging file carry a digest in their names, so a prefix finds them.
    let records = std::fs::read_dir(state)
        .map_err(|error| format!("receipt: the state directory: {error}"))?;
    for entry in records {
        let entry = entry.map_err(|error| format!("receipt: the state directory: {error}"))?;
        let name = entry.file_name();
        if name.as_bytes().starts_with(REFUSAL_PREFIX.as_bytes()) && same(&entry.path())? {
            return Err(format!(
                "KESTRIKE_SOAK_RECEIPT names the {} record",
                name.to_string_lossy()
            ));
        }
    }
    let entries = match std::fs::read_dir(state.join(STORE_DIR)) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("receipt: the {STORE_DIR} directory: {error}")),
    };
    for entry in entries {
        let entry =
            entry.map_err(|error| format!("receipt: the {STORE_DIR} directory: {error}"))?;
        if same(&entry.path())? {
            return Err(format!(
                "KESTRIKE_SOAK_RECEIPT names the {STORE_DIR}/{} record",
                entry.file_name().to_string_lossy()
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
thread_local! {
    static BEFORE_REMOVAL: std::cell::Cell<Option<Box<dyn FnOnce()>>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
#[path = "receipt_tests.rs"]
mod tests;
