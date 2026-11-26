//! The state directory's file primitives. A record replaced by [`replace`]
//! holds its old or its new bytes after a crash, every read and every
//! staged or log file opens a regular file and never blocks on a FIFO or a
//! device, and a read uses memory proportional to the caller's `bound`.
//! The runner is the one writer of its state directory: [`lock`] makes a
//! second runner fail before it reads or writes a record.

use std::ffi::{CString, OsStr};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

/// The directory that holds `path`: its parent, or `.` for a bare name.
fn parent_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

/// Creates `path` as a new regular file with mode 0600. An entry already
/// at `path`, a symlink or a link to another file included, is removed
/// first, so the bytes go to a file this call made.
pub fn create_fresh(path: &Path) -> io::Result<File> {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

/// Removes the entry at `path` by itself; a symlink is removed without
/// following it. Nothing at `path` is done. A directory at `path` fails
/// the call and stays with everything in it.
pub fn remove_file(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        removed => removed,
    }
}

/// A reader of `path` sees its old content or `bytes`. Once this returns
/// `Ok(())`, `bytes` survive a host crash: they are synced in a staged
/// file that this call created, renamed over `path`, and the parent
/// directory is synced. A failure before the rename leaves `path` as it
/// was. If writing, syncing the staged file, or renaming fails, the call
/// attempts to remove the staged file and returns the original error. The
/// staged name is fixed, so the caller must be the one writer of `path`.
pub fn replace(path: &Path, bytes: &[u8]) -> io::Result<()> {
    replace_with(path, |file| file.write_all(bytes))
}

/// [`replace`] with the new content written by `write` into the staged
/// file, so a caller can stream it from several buffers.
pub fn replace_with(
    path: &Path,
    write: impl FnOnce(&mut File) -> io::Result<()>,
) -> io::Result<()> {
    let Some(name) = path.file_name() else {
        return Err(io::Error::other(format!(
            "{} names no file in a directory",
            path.display()
        )));
    };
    let parent = parent_dir(path);
    let mut staged = std::ffi::OsString::from(".");
    staged.push(name);
    staged.push(".staged");
    let staged = parent.join(staged);
    let mut file = create_fresh(&staged)?;
    let written = write(&mut file)
        .and_then(|()| file.sync_all())
        .and_then(|()| {
            drop(file);
            fs::rename(&staged, path)
        });
    if let Err(error) = written {
        let _ = fs::remove_file(&staged);
        return Err(error);
    }
    File::open(parent)?.sync_all()
}

/// Opens `path` for reading without blocking on a FIFO or a device, and
/// refuses anything but a regular file. `Ok(None)` means nothing is at
/// `path`.
pub fn open_regular(path: &Path) -> io::Result<Option<File>> {
    open_flagged(path, 0)
}

/// `open_plain` applies the [`open_regular`] contract and returns an error
/// when the final component of `path` is a symlink.
pub fn open_plain(path: &Path) -> io::Result<Option<File>> {
    open_flagged(path, libc::O_NOFOLLOW)
}

fn open_flagged(path: &Path, flags: libc::c_int) -> io::Result<Option<File>> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY | flags)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is not a regular file", path.display()),
        ));
    }
    Ok(Some(file))
}

/// The bytes of the regular file at `path`, `Ok(None)` when nothing is
/// there, or an error when it holds more than `bound` bytes.
pub fn read(path: &Path, bound: u64) -> io::Result<Option<Vec<u8>>> {
    read_opened(open_regular(path)?, path, bound)
}

/// [`read`], with an error when the final component of `path` is a
/// symlink.
pub fn read_plain(path: &Path, bound: u64) -> io::Result<Option<Vec<u8>>> {
    read_opened(open_plain(path)?, path, bound)
}

fn read_opened(file: Option<File>, path: &Path, bound: u64) -> io::Result<Option<Vec<u8>>> {
    let Some(file) = file else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    file.take(bound.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > bound {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} holds more than {bound} bytes", path.display()),
        ));
    }
    Ok(Some(bytes))
}

/// Replaces the JSON record at `path` with `value`, refusing an encoding
/// longer than `bound`, the bound its reader applies, so every record this
/// writes reads back. A refusal leaves `path` as it was.
pub fn save_json<T: serde::Serialize>(path: &Path, value: &T, bound: u64) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    if bytes.len() as u64 > bound {
        return Err(format!(
            "{} would hold {} bytes, past its bound of {bound}",
            path.display(),
            bytes.len()
        ));
    }
    replace(path, &bytes).map_err(|error| format!("{}: {error}", path.display()))
}

/// A symlink at `name` makes `open_dir_at` return `ENOTDIR`.
fn open_dir_at(parent: &File, name: &OsStr) -> io::Result<File> {
    let name = CString::new(name.as_bytes())?;
    let flags = libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    // SAFETY: `parent` is an open descriptor and `name` a NUL-terminated
    // string, both alive for the call.
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `openat` returned `fd` to this call alone.
    Ok(File::from(unsafe { OwnedFd::from_raw_fd(fd) }))
}

fn make_dir_at(parent: &File, name: &OsStr) -> io::Result<()> {
    let name = CString::new(name.as_bytes())?;
    // SAFETY: `parent` is an open descriptor and `name` a NUL-terminated
    // string, both alive for the call.
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Creates the directory `path` with mode 0700 when it is absent, then
/// refuses it unless it is a directory, not a symlink, owned by this
/// process's user, and writable by no group or other user.
///
/// The walk opens each component by name in a handle on its parent. Before
/// it opens or creates a child, it checks that the parent's handle belongs
/// to root or this process's user and is writable by its group or others
/// only when sticky, so a component another user plants during the call is
/// refused by its handle's owner or type.
pub fn private_dir(path: &Path) -> io::Result<()> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    // SAFETY: `geteuid` reads this process's effective user id.
    let euid = unsafe { libc::geteuid() };
    let refused = |text: String| io::Error::new(io::ErrorKind::PermissionDenied, text);
    let names: Vec<&OsStr> = absolute
        .components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(name),
            Component::ParentDir => Some(OsStr::new("..")),
            _ => None,
        })
        .collect();
    let mut walked = PathBuf::from("/");
    let mut dir = File::open(&walked)?;
    for (index, name) in names.iter().enumerate() {
        let meta = dir.metadata()?;
        let refusal = if meta.uid() != 0 && meta.uid() != euid {
            Some("belongs to another user")
        } else if meta.mode() & 0o022 != 0 && meta.mode() & 0o1000 == 0 {
            Some("is writable by its group or other users and not sticky")
        } else {
            None
        };
        if let Some(refusal) = refusal {
            return Err(refused(format!(
                "{} holds {} and {refusal}",
                walked.display(),
                path.display()
            )));
        }
        walked.push(name);
        let opened = match open_dir_at(&dir, name) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                match make_dir_at(&dir, name) {
                    Err(error) if error.kind() != io::ErrorKind::AlreadyExists => {
                        return Err(error);
                    }
                    _ => open_dir_at(&dir, name),
                }
            }
            opened => opened,
        };
        dir = match opened {
            Ok(dir) => dir,
            Err(error) if error.raw_os_error() == Some(libc::ENOTDIR) => {
                return Err(refused(if index + 1 == names.len() {
                    format!("{} is not a directory", path.display())
                } else {
                    format!(
                        "{} holds {} and is not a directory",
                        walked.display(),
                        path.display()
                    )
                }));
            }
            Err(error) => return Err(error),
        };
    }
    let meta = dir.metadata()?;
    let refusal = if meta.uid() != euid {
        Some("belongs to another user")
    } else if meta.mode() & 0o022 != 0 {
        Some("is writable by its group or other users")
    } else {
        None
    };
    match refusal {
        Some(refusal) => Err(refused(format!("{} {refusal}", path.display()))),
        None => Ok(()),
    }
}

/// Takes an exclusive lock on `path`, created with mode 0600 when absent,
/// and returns the file that holds it; the lock lasts until the file is
/// dropped. The descriptor is close-on-exec, so no child keeps the lock.
/// Another holder makes this fail at once with `WouldBlock`.
pub fn lock(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is not a regular file", path.display()),
        ));
    }
    file.try_lock()?;
    Ok(file)
}

/// Whether an entry is at `path`, without following a final symlink.
/// Only `NotFound` reads as absence; every other error is returned.
pub fn exists(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// Removes the entry at `path`: a directory with everything under it, any
/// other entry, a symlink included, by itself. Nothing at `path` is done.
/// When a directory's removal meets `PermissionDenied`, each entry under it
/// whose own type is a directory gets owner read, write and search, and the
/// removal runs again.
pub fn remove_entry(path: &Path) -> io::Result<()> {
    let removed = match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_dir() => fs::remove_dir_all(path).or_else(|error| {
            if error.kind() == io::ErrorKind::PermissionDenied {
                open_dirs(path)?;
                fs::remove_dir_all(path)
            } else {
                Err(error)
            }
        }),
        Ok(_) => fs::remove_file(path),
        Err(error) => Err(error),
    };
    match removed {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        removed => removed,
    }
}

fn open_dirs(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let mut pending = vec![dir.to_owned()];
    while let Some(next) = pending.pop() {
        let mode = fs::symlink_metadata(&next)?.permissions().mode();
        fs::set_permissions(&next, fs::Permissions::from_mode(mode | 0o700))?;
        for entry in fs::read_dir(&next)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                pending.push(entry.path());
            }
        }
    }
    Ok(())
}

/// `lock_dir` attempts an exclusive lock on the directory `path` and
/// returns at once: `Ok(None)` when opening `path` returns `NotFound`, and
/// `WouldBlock` when the lock is held. The open is nonblocking and takes
/// only a directory: a FIFO, a device, a regular file or a symlink at
/// `path` fails it with `ENOTDIR` or `ELOOP` before any lock.
pub fn lock_dir(path: &Path) -> io::Result<Option<File>> {
    let dir = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)
    {
        Ok(dir) => dir,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    match dir.try_lock() {
        Ok(()) => Ok(Some(dir)),
        Err(fs::TryLockError::WouldBlock) => Err(io::ErrorKind::WouldBlock.into()),
        Err(fs::TryLockError::Error(error)) => Err(error),
    }
}

/// Renames the entry at `path` to `.trash-<name>` beside it, after removing
/// an earlier trash entry of that name, and syncs the parent, so `path` is
/// gone in one rename. Returns the trash path; [`sweep_trash`] or
/// [`discard`] removes it. Nothing at `path` is done.
pub fn detach(path: &Path) -> io::Result<PathBuf> {
    let Some(name) = path.file_name() else {
        return Err(io::Error::other(format!(
            "{} names no entry in a directory",
            path.display()
        )));
    };
    let parent = parent_dir(path);
    let mut trash = std::ffi::OsString::from(".trash-");
    trash.push(name);
    let trash = parent.join(trash);
    remove_entry(&trash)?;
    if exists(path)? {
        fs::rename(path, &trash)?;
    }
    File::open(parent)?.sync_all()?;
    Ok(trash)
}

/// Removes the entry at `path`. A rename to `.trash-<name>` makes the
/// removal atomic to readers of `path`; [`sweep_trash`] finishes a removal
/// that a kill interrupted. Nothing at `path` is done.
pub fn discard(path: &Path) -> io::Result<()> {
    remove_entry(&detach(path)?)
}

/// Removes every `.trash-*` entry of `dir`.
pub fn sweep_trash(dir: &Path) -> io::Result<()> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    for entry in entries {
        let entry = entry?;
        if entry.file_name().as_bytes().starts_with(b".trash-") {
            remove_entry(&entry.path())?;
        }
    }
    Ok(())
}

/// Syncs every regular file under `dir`, then every directory from the
/// deepest up, `dir` last, so a rename of `dir` that follows publishes a
/// tree whose bytes and entries survive a host crash.
pub fn sync_tree(dir: &Path) -> io::Result<()> {
    let mut dirs = vec![dir.to_owned()];
    let mut index = 0;
    while index < dirs.len() {
        for entry in fs::read_dir(&dirs[index])? {
            let entry = entry?;
            let kind = entry.file_type()?;
            if kind.is_dir() {
                dirs.push(entry.path());
            } else if kind.is_file() {
                File::open(entry.path())?.sync_all()?;
            }
        }
        index += 1;
    }
    for dir in dirs.iter().rev() {
        File::open(dir)?.sync_all()?;
    }
    Ok(())
}

/// Creates a new directory with mode 0700 under `parent`, named `prefix`
/// and 32 random hexadecimal digits. The create fails when anything is at
/// that name, so the directory is one this call made.
pub fn fresh_dir(parent: &Path, prefix: &str) -> io::Result<std::path::PathBuf> {
    let path = parent.join(format!("{prefix}{}", crate::host::random_hex(16)?));
    DirBuilder::new().mode(0o700).create(&path)?;
    Ok(path)
}

/// The SHA-256 of the regular file at `path`, read in chunks; `Ok(None)`
/// when nothing is there.
pub fn sha256_file(path: &Path) -> io::Result<Option<String>> {
    use sha2::Digest as _;
    let Some(mut file) = open_regular(path)? else {
        return Ok(None);
    };
    let mut hasher = sha2::Sha256::new();
    let mut chunk = vec![0u8; 1 << 20];
    loop {
        let read = file.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        hasher.update(&chunk[..read]);
    }
    let digest: [u8; 32] = hasher.finalize().into();
    Ok(Some(hex(&digest)))
}

/// The bytes an unprivileged writer may still allocate on the filesystem
/// that holds `path`: `f_bavail` blocks of `f_frsize` bytes.
pub fn free_bytes(path: &Path) -> io::Result<u64> {
    free_space(path).map(|(bytes, _)| bytes)
}

/// `free_space` returns the bytes and inodes available to an unprivileged
/// writer on the filesystem containing `path`: `f_bavail` blocks of
/// `f_frsize` bytes, and `f_favail`.
pub fn free_space(path: &Path) -> io::Result<(u64, u64)> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::other("a path holds a NUL byte"))?;
    let mut stats = std::mem::MaybeUninit::<libc::statvfs>::zeroed();
    // SAFETY: `path` is a NUL-terminated string and `stats` is valid for
    // writes of one `statvfs`, which the call fills on success.
    if unsafe { libc::statvfs(path.as_ptr(), stats.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `stats` started zeroed, a valid `statvfs`, and the call
    // returned 0.
    let stats = unsafe { stats.assume_init() };
    Ok((
        stats.f_bavail.saturating_mul(stats.f_frsize),
        stats.f_favail,
    ))
}

pub fn sha256(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    let digest: [u8; 32] = sha2::Sha256::digest(bytes).into();
    hex(&digest)
}

pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}

/// Whether `text` is `length` lowercase hexadecimal digits.
pub fn is_hex(text: &str, length: usize) -> bool {
    text.len() == length
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn is_sha256(text: &str) -> bool {
    is_hex(text, 64)
}

/// `text` cut to at most `limit` bytes on a character boundary.
pub fn cut(text: &str, limit: usize) -> String {
    text[..text.floor_char_boundary(limit)].to_owned()
}

#[cfg(test)]
pub(crate) fn scratch(name: &str) -> std::path::PathBuf {
    let base = fs::canonicalize(std::env::temp_dir()).expect("the temporary directory");
    let dir = base.join(format!("sim-host-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    private_dir(&dir).expect("the directory is created");
    dir
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mkfifo(path: &Path) {
        let name = CString::new(path.as_os_str().as_bytes()).expect("a path");
        // SAFETY: `name` is a NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    }

    fn within<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> T {
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(work());
        });
        receiver
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the call returns without blocking")
    }

    /// The largest bound reads a whole file, and a bound refuses one byte
    /// more than itself; a symlink at the path is refused by `read_plain`
    /// alone.
    #[test]
    fn a_read_takes_the_whole_file_at_any_bound_and_read_plain_refuses_a_link() {
        let dir = scratch("bounded");
        let path = dir.join("record");
        fs::write(&path, b"bytes").expect("a record");
        for reader in [read, read_plain] {
            assert_eq!(
                reader(&path, u64::MAX).expect("it reads"),
                Some(b"bytes".to_vec())
            );
            assert_eq!(reader(&path, 5).expect("it reads"), Some(b"bytes".to_vec()));
            assert!(reader(&path, 4).is_err(), "one byte past the bound");
            assert_eq!(reader(&dir.join("absent"), 5).expect("no file"), None);
        }
        let link = dir.join("link");
        std::os::unix::fs::symlink(&path, &link).expect("a link");
        assert_eq!(
            read(&link, 5).expect("read follows it"),
            Some(b"bytes".to_vec())
        );
        assert!(read_plain(&link, 5).is_err(), "read_plain refuses the link");
        fs::remove_dir_all(&dir).expect("the directory is removed");
    }

    #[test]
    fn a_replaced_file_holds_the_new_bytes_and_no_staged_file_remains() {
        let dir = scratch("file");
        let path = dir.join("record.json");
        replace(&path, b"old").expect("the first write");
        replace(&path, b"new").expect("the replacement");
        assert_eq!(read(&path, 16).expect("it reads"), Some(b"new".to_vec()));
        let names: Vec<_> = fs::read_dir(&dir)
            .expect("the listing")
            .map(|entry| entry.expect("an entry").file_name())
            .collect();
        assert_eq!(names, ["record.json"]);
        assert!(read(&path, 2).is_err(), "a file past its bound is refused");
        fs::remove_dir_all(&dir).expect("the directory is removed");
    }

    #[test]
    fn a_failed_replacement_leaves_no_staged_file() {
        let dir = scratch("failed-replace");
        let held = dir.join("held");
        fs::create_dir(&held).expect("a directory no rename can replace");
        fs::write(held.join("inside"), b"kept").expect("a file under it");
        assert!(replace(&held, b"new").is_err(), "the rename fails");
        assert_eq!(fs::read(held.join("inside")).expect("kept"), b"kept");
        let path = dir.join("record.json");
        replace(&path, b"old").expect("the first write");
        let failed = replace_with(&path, |file| {
            file.write_all(b"part")?;
            Err(io::Error::other("the disk is full"))
        });
        assert_eq!(
            failed.map_err(|error| error.to_string()),
            Err("the disk is full".to_owned()),
            "the writer's error is returned"
        );
        assert_eq!(read(&path, 16).expect("it reads"), Some(b"old".to_vec()));
        let mut names: Vec<_> = fs::read_dir(&dir)
            .expect("the listing")
            .map(|entry| entry.expect("an entry").file_name())
            .collect();
        names.sort();
        assert_eq!(names, ["held", "record.json"]);
        fs::remove_dir_all(&dir).expect("the directory is removed");
    }

    // A link planted at the staged name keeps its target: the replacement
    // writes a file it created.
    #[test]
    fn a_link_at_the_staged_name_keeps_its_target() {
        let dir = scratch("staged-link");
        let victim = dir.join("victim");
        fs::write(&victim, b"evidence").expect("the victim");
        std::os::unix::fs::symlink(&victim, dir.join(".record.json.staged")).expect("a link");
        let path = dir.join("record.json");
        replace(&path, b"new").expect("the replacement");
        assert_eq!(fs::read(&victim).expect("the victim"), b"evidence");
        assert_eq!(fs::read(&path).expect("the record"), b"new");
        fs::hard_link(&victim, dir.join(".record.json.staged")).expect("a hard link");
        replace(&path, b"newer").expect("the replacement");
        assert_eq!(fs::read(&victim).expect("the victim"), b"evidence");
        assert_eq!(fs::read(&path).expect("the record"), b"newer");
        fs::remove_dir_all(&dir).expect("the directory is removed");
    }

    #[test]
    fn a_path_through_a_link_planted_during_the_call_is_refused() {
        use std::sync::{Arc, Barrier};
        use std::time::{Duration, Instant};

        let base = scratch("planted");
        let real = base.join("real");
        let top = base.join("top");
        let deep = (0..400).fold(top.clone(), |path, _| path.join("d"));
        for step in 0..300u64 {
            let _ = fs::remove_file(&top);
            let _ = fs::remove_dir_all(&top);
            let _ = fs::remove_dir_all(&real);
            private_dir(&real).expect("the link's target");
            let barrier = Arc::new(Barrier::new(2));
            let planter = {
                let (barrier, real, top) = (Arc::clone(&barrier), real.clone(), top.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    let until = Instant::now() + Duration::from_micros(step * 4);
                    while Instant::now() < until {
                        std::hint::spin_loop();
                    }
                    std::os::unix::fs::symlink(&real, &top).is_ok()
                })
            };
            barrier.wait();
            let made = private_dir(&deep);
            let planted = planter.join().expect("the planter");
            assert!(
                !(planted && made.is_ok()),
                "step {step}: the directory was made through a planted link"
            );
        }
        fs::remove_dir_all(&base).expect("the directory is removed");
    }

    #[test]
    fn a_bare_name_lives_in_the_working_directory() {
        assert_eq!(parent_dir(Path::new("state.json")), Path::new("."));
        assert_eq!(parent_dir(Path::new("a/state.json")), Path::new("a"));
        assert_eq!(parent_dir(Path::new("/state.json")), Path::new("/"));
    }

    #[test]
    fn a_bare_name_is_discarded_from_the_working_directory() {
        let name = format!(".sim-host-discard-{}", std::process::id());
        let path = Path::new(&name);
        fs::create_dir(path).expect("a directory in the working directory");
        fs::write(path.join("member"), b"x").expect("a member");
        discard(path).expect("a bare name is discarded");
        assert!(!exists(path).expect("the entry is read"));
        let trash = format!(".trash-{name}");
        assert!(!exists(Path::new(&trash)).expect("the trash is read"));
        discard(path).expect("an absent bare name is discarded");
        assert!(discard(Path::new("/")).is_err(), "the root names no entry");
    }

    #[test]
    fn a_tree_with_a_read_only_directory_is_removed() {
        let dir = scratch("read-only");
        let tree = dir.join("tree");
        fs::create_dir_all(tree.join("closed/inner")).expect("the tree");
        fs::write(tree.join("closed/inner/file"), b"x").expect("a file");
        let mode = |path: &Path, mode| {
            fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(mode))
                .expect("its mode");
        };
        mode(&tree.join("closed/inner"), 0o600);
        mode(&tree.join("closed"), 0o500);
        // SAFETY: `geteuid` reads this process's effective user id.
        if unsafe { libc::geteuid() } != 0 {
            // Root bypasses directory permissions, so only another user
            // sees the denial that the repair answers.
            let plain = fs::remove_dir_all(&tree).expect_err("a read-only directory blocks it");
            assert_eq!(plain.kind(), io::ErrorKind::PermissionDenied);
        }
        remove_entry(&tree).expect("the tree is removed");
        assert!(!exists(&tree).expect("the tree is read"));
        fs::remove_dir_all(&dir).expect("the directory is removed");
    }

    #[test]
    fn a_file_removal_leaves_a_directory_and_a_links_target() {
        let dir = scratch("remove-file");
        let named = dir.join("named");
        fs::create_dir(&named).expect("a directory");
        fs::write(named.join("sentinel"), b"x").expect("a sentinel");
        assert!(remove_file(&named).is_err(), "a directory is refused");
        assert_eq!(
            fs::read(named.join("sentinel")).expect("the sentinel"),
            b"x"
        );
        let link = dir.join("link");
        std::os::unix::fs::symlink(named.join("sentinel"), &link).expect("a link");
        remove_file(&link).expect("a link is removed");
        assert!(!exists(&link).expect("the link is read"));
        assert!(named.join("sentinel").exists(), "the target stays");
        remove_file(&link).expect("an absent entry is done");
        fs::remove_dir_all(&dir).expect("the directory is removed");
    }

    #[test]
    fn the_largest_bound_reads_the_whole_file() {
        let dir = scratch("unbounded");
        let path = dir.join("record");
        fs::write(&path, b"bytes").expect("a record");
        assert_eq!(
            read(&path, u64::MAX).expect("a read").as_deref(),
            Some(&b"bytes"[..])
        );
        assert!(read(&path, 4).is_err(), "a file past a smaller bound");
        assert_eq!(
            read(&path, 5).expect("a read").as_deref(),
            Some(&b"bytes"[..])
        );
        fs::remove_dir_all(&dir).expect("the directory is removed");
    }

    #[test]
    fn a_root_lock_refuses_a_fifo_or_a_link_without_blocking() {
        let dir = scratch("lock-dir");
        let fifo = dir.join("fifo");
        mkfifo(&fifo);
        let path = fifo.clone();
        let kind = within(move || lock_dir(&path).map(|_| ()).map_err(|error| error.kind()));
        assert_eq!(kind, Err(io::ErrorKind::NotADirectory), "a FIFO");
        let target = dir.join("target");
        fs::create_dir(&target).expect("a directory");
        let link = dir.join("link");
        std::os::unix::fs::symlink(&target, &link).expect("a link");
        let refused = lock_dir(&link).map(|_| ()).expect_err("a link");
        assert_eq!(refused.raw_os_error(), Some(libc::ENOTDIR));
        assert!(target.exists(), "the link's target stays");
        let held = lock_dir(&target).expect("a lock").expect("a directory");
        assert_eq!(
            lock_dir(&target)
                .map(|_| ())
                .expect_err("a held lock")
                .kind(),
            io::ErrorKind::WouldBlock
        );
        drop(held);
        assert!(lock_dir(&dir.join("absent")).expect("absent").is_none());
        fs::remove_dir_all(&dir).expect("the directory is removed");
    }

    #[test]
    fn a_fifo_is_refused_without_blocking() {
        let dir = scratch("fifo");
        let fifo = dir.join("fifo");
        mkfifo(&fifo);
        let path = fifo.clone();
        let result = within(move || read(&path, 16).map(|_| ()));
        assert_eq!(
            result.expect_err("a FIFO is refused").kind(),
            io::ErrorKind::InvalidData
        );
        assert!(read(&dir.join("absent"), 16).expect("absent").is_none());
        fs::remove_dir_all(&dir).expect("the directory is removed");
    }

    #[test]
    fn a_shared_or_linked_directory_is_refused() {
        let dir = scratch("private");
        let open = dir.join("open");
        fs::create_dir(&open).expect("a directory");
        fs::set_permissions(&open, std::os::unix::fs::PermissionsExt::from_mode(0o777))
            .expect("its mode");
        assert!(private_dir(&open).is_err(), "a world-writable directory");
        let link = dir.join("link");
        std::os::unix::fs::symlink(dir.join("made"), &link).expect("a link");
        private_dir(&dir.join("made")).expect("a private directory");
        assert!(private_dir(&link).is_err(), "a symlink to a directory");
        assert!(
            private_dir(&open.join("state")).is_err(),
            "a directory under a world-writable parent"
        );
        assert!(!open.join("state").exists(), "the refusal creates nothing");
        assert!(
            private_dir(&link.join("state")).is_err(),
            "a directory under a symlink"
        );
        assert!(
            !dir.join("made/state").exists(),
            "the refusal creates nothing"
        );
        let sticky = dir.join("sticky");
        fs::create_dir(&sticky).expect("a directory");
        fs::set_permissions(
            &sticky,
            std::os::unix::fs::PermissionsExt::from_mode(0o1777),
        )
        .expect("its mode");
        private_dir(&sticky.join("state")).expect("a directory under a sticky parent");
        fs::remove_dir_all(&dir).expect("the directory is removed");
    }

    #[test]
    fn a_fifo_at_the_lock_is_refused_without_blocking() {
        let dir = scratch("lock-fifo");
        let fifo = dir.join("runner.lock");
        mkfifo(&fifo);
        let path = fifo.clone();
        assert!(
            within(move || lock(&path).is_err()),
            "a FIFO with no reader"
        );
        let reader = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&fifo)
            .expect("a reader");
        let path = fifo.clone();
        let kind = within(move || lock(&path).map(|_| ()).map_err(|error| error.kind()));
        assert_eq!(
            kind,
            Err(io::ErrorKind::InvalidData),
            "a FIFO with a reader"
        );
        drop(reader);
        fs::remove_dir_all(&dir).expect("the directory is removed");
    }

    #[test]
    fn a_second_lock_fails_at_once() {
        let dir = scratch("lock");
        let held = lock(&dir.join("runner.lock")).expect("the first lock");
        let second = lock(&dir.join("runner.lock")).expect_err("the second lock");
        assert_eq!(second.kind(), io::ErrorKind::WouldBlock);
        // A child another test thread forks keeps a copy of this descriptor
        // until it execs, so the lock is released explicitly.
        held.unlock().expect("the lock is released");
        drop(held);
        lock(&dir.join("runner.lock")).expect("the lock after release");
        fs::remove_dir_all(&dir).expect("the directory is removed");
    }

    #[test]
    fn a_record_past_its_bound_is_refused_and_the_old_one_stays() {
        let dir = scratch("bound");
        let path = dir.join("record.json");
        save_json(&path, &"short", 64).expect("a record in its bound");
        assert!(save_json(&path, &"x".repeat(100), 64).is_err());
        assert_eq!(fs::read(&path).expect("the record"), b"\"short\"");
        fs::remove_dir_all(&dir).expect("the directory is removed");
    }

    #[test]
    fn a_fresh_directory_is_private_and_randomly_named() {
        let base = scratch("fresh");
        let dir = fresh_dir(&base, "sim-host-").expect("a fresh directory");
        let mode = fs::metadata(&dir).expect("its metadata").permissions();
        assert_eq!(
            std::os::unix::fs::PermissionsExt::mode(&mode) & 0o777,
            0o700
        );
        let other = fresh_dir(&base, "sim-host-").expect("another");
        assert_ne!(dir, other, "names are random");
        fs::remove_dir_all(&base).expect("the directory is removed");
    }

    #[test]
    fn the_digest_of_empty_input_is_the_known_value() {
        let digest = sha256(b"");
        assert_eq!(
            digest,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert!(is_sha256(&digest));
        assert!(!is_sha256(&digest.to_uppercase()));
        assert_eq!(cut("a\u{e9}", 2), "a");
        assert_eq!(cut("abc", 9), "abc");
        assert_eq!(cut("abc", 0), "");
    }
}
