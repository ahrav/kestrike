//! The removal of a directory the run made, walked by directory descriptors, going past what it cannot
//! remove.

use std::ffi::{CStr, CString};
use std::fs::{self, File, OpenOptions};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

/// The deepest directory level `remove` walks below its root; a directory deeper than this stays in
/// place with everything under it.
pub(super) const REMOVAL_DEPTH: usize = 512;

/// `remove` removes `path` and everything under it, going past each entry it cannot remove; a link at
/// `path` stays. The walk opens each directory relative to its parent's descriptor with `O_NOFOLLOW`
/// and unlinks a link inside the tree itself. After `remove` opens the parent of `path` as a path
/// descriptor, which needs search permission on it and no read permission, each `openat` and
/// `unlinkat` call resolves a single name relative to a directory descriptor. The root is walked
/// only when the directory opened at `path` has the device and inode that the status read of `path`
/// gave; a directory put in its place between the two stays as it is. The walk goes at most
/// [`REMOVAL_DEPTH`] levels below the root.
pub(crate) fn remove(path: &Path) {
    remove_with(path, || {});
}

/// `remove_with` is [`remove`] with `between` run after the status read of `path` and before the open
/// of its directory.
pub(super) fn remove_with(path: &Path, between: impl FnOnce()) {
    let Ok(status) = fs::symlink_metadata(path) else {
        return;
    };
    if !status.is_dir() {
        return;
    }
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return;
    };
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    let opened = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY)
        .open(parent);
    let (Ok(parent), Ok(name)) = (opened, CString::new(name.as_bytes())) else {
        return;
    };
    between();
    remove_at(&parent, &name, Some((status.dev(), status.ino())), 0);
}

/// `remove_at` removes the directory `name` of the open directory `parent` with its entries. With
/// `root`, the device and inode of the root's status read, it walks the opened directory only when its
/// own status matches them and never unlinks `name` as a non-directory; otherwise, if `openat` fails,
/// it attempts to unlink `name` as a non-directory entry. Below [`REMOVAL_DEPTH`] levels it leaves
/// `name` as it is. The caller continues with the remaining siblings.
fn remove_at(parent: &File, name: &CStr, root: Option<(u64, u64)>, depth: usize) {
    if depth > REMOVAL_DEPTH {
        return;
    }
    let flags =
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;
    // SAFETY: `parent` is an open descriptor and `name` a NUL-terminated string, both live for the call.
    let descriptor = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if descriptor < 0 {
        if root.is_none() {
            // SAFETY: `parent` is open and `name` points to a live NUL-terminated string.
            unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) };
        }
        return;
    }
    // SAFETY: `descriptor` is a new open descriptor that this call alone owns.
    let directory = unsafe { File::from_raw_fd(descriptor) };
    if let Some((device, inode)) = root {
        let same = directory
            .metadata()
            .is_ok_and(|opened| opened.dev() == device && opened.ino() == inode);
        if !same {
            return;
        }
    }
    for inner in entries(&directory) {
        remove_at(&directory, &inner, None, depth + 1);
    }
    drop(directory);
    // SAFETY: dropping `directory` leaves `parent` open. `name` points to a live NUL-terminated string
    // throughout `unlinkat`.
    unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) };
}

/// `entries` lists the names in the open directory `directory`, `.` and `..` left out; a failed
/// listing lists the names read before it.
fn entries(directory: &File) -> Vec<CString> {
    // SAFETY: `directory` keeps the descriptor open, and `F_DUPFD_CLOEXEC` takes an integer minimum
    // descriptor as its third argument.
    let copy = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if copy < 0 {
        return Vec::new();
    }
    // SAFETY: `copy` is an open descriptor of a directory that `fdopendir` takes over on success.
    let stream = unsafe { libc::fdopendir(copy) };
    if stream.is_null() {
        // SAFETY: `fdopendir` failed, so `copy` is still this call's to close, once.
        unsafe { libc::close(copy) };
        return Vec::new();
    }
    let mut names = Vec::new();
    loop {
        // SAFETY: `stream` is an open directory stream that this loop alone reads.
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            break;
        }
        // SAFETY: `readdir` returned a live entry whose `d_name` is NUL-terminated. The raw place
        // projection addresses the first byte of `d_name` even when the record holds fewer than 256
        // bytes for the field.
        let name = unsafe { CStr::from_ptr((&raw const (*entry).d_name).cast::<libc::c_char>()) };
        if name != c"." && name != c".." {
            names.push(name.to_owned());
        }
    }
    // SAFETY: `stream` is open and closed here once, which closes `copy`.
    unsafe { libc::closedir(stream) };
    names
}

#[cfg(test)]
#[path = "removal_tests.rs"]
mod tests;
