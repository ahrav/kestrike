//! Host paths: files and directories, such
//! as a build's executable, its shared libraries, its program interpreter,
//! its lockfile and a new archive's directory. [`open_host`] follows
//! symlinks, as the program interpreter and the dynamic loader do when
//! they open the same paths. [`canonical_host`] resolves host path symlinks too.

use std::ffi::CString;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use super::Unreadable;
use super::file::Opened;
use super::read::capped;
use crate::step::{self, Step};
use crate::sys;

pub(crate) fn absolute_host(path: &Path) -> io::Result<PathBuf> {
    step::call(Step::Open, || std::path::absolute(path))
}

pub(crate) struct HardwareCustody {
    path: PathBuf,
    directory: fs::File,
    identity: (u64, u64),
}

/// `status` qualifies when it identifies a directory owned by the effective
/// UID with all group and other permission bits cleared. Linux permits
/// `flock` on read-only file descriptors, so another UID that can traverse
/// the directory and open the lock file can contend for the controller's
/// host reservation lock.
fn custody_exclusive(status: &fs::Metadata) -> bool {
    status.is_dir() && status.uid() == sys::euid() && status.mode() & 0o077 == 0
}

fn custody_status(path: &Path) -> Result<fs::Metadata, super::Error> {
    super::given_ancestors(path)?;
    let status = step::call(Step::Stat, || path.symlink_metadata())?;
    if !custody_exclusive(&status) {
        return Err(super::Refusal::Ancestor(format!(
            "custody directory {} requires current-UID ownership and owner-only permissions",
            path.display()
        ))
        .into());
    }
    Ok(status)
}

/// A handle on a directory [`private_dir`] admitted.
#[derive(Debug)]
pub struct PrivateDir(fs::File);

impl PrivateDir {
    /// Takes the directory's exclusive `flock`, which this handle holds
    /// until it drops.
    ///
    /// # Errors
    ///
    /// [`super::Error::Busy`] while another open of the directory holds a
    /// lock on it; [`super::Error::Io`] for a failed lock call.
    pub fn lock(&self) -> Result<(), super::Error> {
        let locked = step::call(Step::Lock, || match self.0.try_lock() {
            Ok(()) => Ok(true),
            Err(fs::TryLockError::WouldBlock) => Ok(false),
            Err(fs::TryLockError::Error(error)) => Err(error),
        })?;
        if locked {
            Ok(())
        } else {
            Err(super::Error::Busy)
        }
    }
}

/// Creates the directory at host path `path` and each missing ancestor,
/// with mode 0700, and returns a handle on it. Before anything is
/// created, the path and each existing ancestor must be a directory that
/// the effective UID or root owns, that is free of group and other write
/// permission or sticky, and that is no symlink. The opened directory is
/// owned by the effective UID with every group and other permission bit
/// clear, so no other user can create, replace or lock an entry in it. It
/// lies on a filesystem a state directory accepts, a read-write xfs or
/// journaled ext4 mount, so a state directory can be opened under it.
///
/// # Errors
///
/// [`super::Error::Refused`] for a path, ancestor or directory that fails
/// those rules, a symlink at `path` included, or for a directory on
/// another filesystem, which the call has created when it was absent;
/// [`super::Error::Io`] for a failed status query, creation, open or read
/// of the mount tables, such as the `ELOOP` of a symlink that takes the
/// path's place after the ancestor check.
pub fn private_dir(path: &Path) -> Result<PrivateDir, super::Error> {
    super::given_ancestors(path)?;
    create_dirs(path)?;
    let directory = step::call(Step::Open, || {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(path)
    })?;
    super::mount::writable(&directory)?;
    let status = step::call(Step::Stat, || directory.metadata())?;
    if !custody_exclusive(&status) {
        return Err(super::Refusal::Ancestor(format!(
            "directory {} requires current-UID ownership and owner-only permissions",
            path.display()
        ))
        .into());
    }
    Ok(PrivateDir(directory))
}

impl HardwareCustody {
    pub(crate) fn validate_path(path: &Path) -> Result<(), super::Error> {
        let bytes = path.as_os_str().as_encoded_bytes();
        if !path.is_absolute()
            || (bytes != b"/"
                && bytes
                    .split(|byte| *byte == b'/')
                    .skip(1)
                    .any(|part| part.is_empty() || part == b"." || part == b".."))
        {
            return Err(super::Refusal::Ancestor(format!(
                "custody path {} requires canonical absolute spelling",
                path.display()
            ))
            .into());
        }
        Ok(())
    }

    pub(crate) fn open(path: &Path) -> Result<Self, super::Error> {
        Self::validate_path(path)?;
        if let Some(parent) = path.parent() {
            match step::call(Step::Stat, || parent.symlink_metadata()) {
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                    ) =>
                {
                    return Err(super::Refusal::Ancestor(format!(
                        "custody parent {} requires an existing directory",
                        parent.display()
                    ))
                    .into());
                }
                Ok(status) if !status.is_dir() => {
                    return Err(super::Refusal::Ancestor(format!(
                        "custody parent {} requires a directory",
                        parent.display()
                    ))
                    .into());
                }
                result => {
                    result?;
                }
            }
        }
        super::given_ancestors(path)?;
        match step::call(Step::Stat, || path.symlink_metadata()) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                match step::call(Step::Mkdir, || DirBuilder::new().mode(0o700).create(path)) {
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    result => {
                        result?;
                    }
                }
            }
            result => {
                result?;
            }
        }
        let before = custody_status(path)?;
        let directory = step::call(Step::Open, || {
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
                .open(path)
        })?;
        let status = step::call(Step::Stat, || directory.metadata())?;
        let identity = (status.dev(), status.ino());
        if !custody_exclusive(&status) {
            return Err(super::Refusal::Ancestor(format!(
                "custody directory {} permissions changed during open",
                path.display()
            ))
            .into());
        }
        if identity != (before.dev(), before.ino()) {
            return Err(super::Error::Io(io::Error::other(
                "custody directory changed during admission",
            )));
        }
        Ok(Self {
            path: path.to_owned(),
            directory,
            identity,
        })
    }

    fn current(&self) -> io::Result<()> {
        let status = custody_status(&self.path).map_err(|error| {
            io::Error::other(format!(
                "custody directory {}: {error}",
                self.path.display()
            ))
        })?;
        if self.identity != (status.dev(), status.ino()) {
            return Err(io::Error::other(
                "custody directory identity changed during controller run",
            ));
        }
        Ok(())
    }
}

pub(crate) fn hardware_markers(custody: &HardwareCustody) -> io::Result<bool> {
    custody.current()?;
    let listing = step::call(Step::Open, || {
        sys::open_beneath(
            &custody.directory,
            c".",
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )
    })?;
    let mut buffer = vec![0; 32 << 10];
    let mut count = 0;
    let mut marker = false;
    loop {
        let filled = step::call(Step::List, || sys::entries(&listing, &mut buffer))?;
        if filled == 0 {
            break;
        }
        for name in sys::names(&buffer[..filled]).filter(|&name| name != b"." && name != b"..") {
            if count == crate::scan_bound() {
                return Err(io::Error::other("custody directory exceeds scan bound"));
            }
            count += 1;
            marker |= name.ends_with(b".json");
        }
    }
    custody.current()?;
    Ok(marker)
}

/// Opens the regular file at host path `path`, following symlinks.
///
/// # Errors
///
/// [`Unreadable::NotRegular`] for another kind of file, and
/// [`Unreadable::Io`] for a failed open, `NotFound` included.
pub fn open_host(path: &Path) -> Result<Opened, Unreadable> {
    let file = step::call(Step::Open, || {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
            .open(path)
    })?;
    Opened::new(file)
}

/// The bytes of the regular file at host path `path` when it holds at most
/// `bound`; `None` when no entry has the path.
///
/// # Errors
///
/// As [`open_host`], and [`Unreadable::Oversize`] past `bound`.
pub fn read_host(path: &Path, bound: u64) -> Result<Option<Vec<u8>>, Unreadable> {
    read_host_sized(path, bound, 0)
}

/// [`read_host`] with a buffer that starts with room for `size` bytes, for
/// a file whose status reports no size, such as a `/proc` file.
///
/// # Errors
///
/// As [`read_host`].
pub(super) fn read_host_sized(
    path: &Path,
    bound: u64,
    size: u64,
) -> Result<Option<Vec<u8>>, Unreadable> {
    let opened = match open_host(path) {
        Err(Unreadable::Io(error)) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        opened => opened?,
    };
    let bytes = capped(&opened.file, bound, size)?.ok_or(Unreadable::Oversize)?;
    Ok(Some(bytes))
}

/// `path` as an absolute path whose parent is canonical, for an entry that
/// does not exist yet.
///
/// # Errors
///
/// `AlreadyExists` when an entry, a dangling symlink included, has the
/// path; `InvalidInput` for a path with no final name; any failed
/// resolution of the parent.
pub fn new_path(path: &Path) -> io::Result<PathBuf> {
    let absolute = step::call(Step::Open, || std::path::absolute(path))?;
    let (Some(parent), Some(name)) = (absolute.parent(), absolute.file_name()) else {
        return Err(io::ErrorKind::InvalidInput.into());
    };
    let resolved = step::call(Step::Open, || parent.canonicalize())?.join(name);
    match step::call(Step::Stat, || resolved.symlink_metadata()) {
        Ok(_) => Err(io::ErrorKind::AlreadyExists.into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(resolved),
        Err(error) => Err(error),
    }
}

/// `evidence_parent` checks every proper ancestor of `path` using
/// [`super::ancestors`], then opens the parent directory, refusing a
/// symlink in the parent's final component.
///
/// # Errors
///
/// [`super::Error::Refused`] for an ancestor that fails the rule;
/// [`super::Error::Io`] for a failed status query of an ancestor, a path
/// with no parent, or a failed open.
pub(crate) fn evidence_parent(path: &Path) -> Result<std::fs::File, super::Error> {
    super::ancestors(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    step::call(Step::Open, || {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(parent)
    })
    .map_err(super::Error::Io)
}

/// `vacant_evidence` returns an absolute path with a canonical parent for
/// an evidence entry the caller creates, once the parent passes the mount
/// rules of [`super::mount::writable`] and the default ACL check, so the
/// new entry's permissions follow the caller's requested mode filtered by
/// the process umask.
///
/// # Errors
///
/// [`super::Error::Unreadable`] when an entry already has the path, the
/// path has no final name, or the parent does not resolve;
/// [`super::Error::Refused`] for an ancestor or
/// mount that fails, or a parent that carries a default ACL;
/// [`super::Error::Io`] for a failed open or query.
pub(crate) fn vacant_evidence(path: &Path) -> Result<PathBuf, super::Error> {
    let path = new_path(path).map_err(|error| super::Error::Unreadable(Unreadable::from(error)))?;
    let parent = evidence_parent(&path)?;
    super::mount::writable(&parent)?;
    if step::call(Step::Stat, || sys::has_default_acl(&parent))? {
        return Err(super::Refusal::DefaultAcl(path.display().to_string()).into());
    }
    Ok(path)
}

/// `open_evidence` opens `path` through [`crate::sys::open_beneath`] on
/// its parent, and returns the file with the parent's handle.
///
/// # Errors
///
/// As [`evidence_parent`]; [`super::Error::Io`] for a path with no file
/// name, a name holding a NUL byte, or a failed open;
/// [`super::Error::Unreadable`] for an entry that
/// is no regular file or whose status query failed.
pub(crate) fn open_evidence(path: &Path) -> Result<(Opened, std::fs::File), super::Error> {
    let parent = evidence_parent(path)?;
    let name = CString::new(
        path.file_name()
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?
            .as_encoded_bytes(),
    )
    .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let file = step::call(Step::Open, || {
        sys::open_beneath(
            &parent,
            &name,
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOCTTY,
            0,
        )
    })?;
    Opened::new(file)
        .map(|opened| (opened, parent))
        .map_err(super::Error::Unreadable)
}

/// The directory handle's permission change clears the inherited set-group-ID bit.
///
/// # Errors
///
/// The call returns `AlreadyExists` when an entry has the path.
/// A failed open, status query or permission change after creation leaves the new directory in place.
pub fn create_dir(path: &Path) -> io::Result<()> {
    step::call(Step::Mkdir, || DirBuilder::new().mode(0o700).create(path))?;
    let dir = step::call(Step::Open, || {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(path)
    })
    .map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("directory created; opening it failed: {error}"),
        )
    })?;
    let mode = step::call(Step::Stat, || dir.metadata())
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("directory created; reading its mode failed: {error}"),
            )
        })?
        .permissions()
        .mode()
        & 0o777;
    step::call(Step::Chmod, || {
        dir.set_permissions(fs::Permissions::from_mode(mode))
    })
    .map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("directory created; setting its mode failed: {error}"),
        )
    })?;
    step::call(Step::Chmod, || sys::clear_default_acl(&dir)).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("directory created; clearing its default ACL failed: {error}"),
        )
    })?;
    Ok(())
}

/// Creates directory `path` and each missing parent, each with mode 0700;
/// an existing directory stays as it is. The deepest existing component is
/// opened with no symlink followed in any component of its path. Each
/// missing component is then created by name in a handle on its parent,
/// the parent is made durable, and the new directory is entered under the
/// confined resolution, so a symlink anywhere in `path`, present before
/// the call or placed after the existence scan, is refused rather than
/// followed.
///
/// # Errors
///
/// `ELOOP` when a component of `path` is a symlink, `ENOTDIR` when an
/// existing or planted component is another non-directory, `InvalidInput`
/// when a missing component has no file name or a component holds a NUL
/// byte; any failed status query, creation, open or `fsync`.
pub fn create_dirs(path: &Path) -> io::Result<()> {
    let mut missing = Vec::new();
    let mut base = Path::new(".");
    for ancestor in path.ancestors().filter(|path| !path.as_os_str().is_empty()) {
        match step::call(Step::Stat, || ancestor.symlink_metadata()) {
            Ok(_) => {
                base = ancestor;
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => missing.push(ancestor),
            Err(error) => return Err(error),
        }
    }
    let base = CString::new(base.as_os_str().as_encoded_bytes())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let mut dir = step::call(Step::Open, || sys::open_dir_nofollow(&base))?;
    for created in missing.into_iter().rev() {
        let name = created
            .file_name()
            .and_then(|name| CString::new(name.as_encoded_bytes()).ok())
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        match step::call(Step::Mkdir, || sys::mkdir(&dir, &name, 0o700)) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        step::call(Step::Sync, || dir.sync_all())?;
        dir = step::call(Step::Open, || {
            sys::open_beneath(&dir, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0)
        })?;
    }
    Ok(())
}

/// Removes the empty directory `path` and makes the removal durable with
/// its parent's `fsync`.
///
/// # Errors
///
/// `DirectoryNotEmpty` when it holds an entry; any failed removal or
/// `fsync`.
pub fn remove_dir(path: &Path) -> io::Result<()> {
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(io::ErrorKind::InvalidInput.into());
    };
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    let name = CString::new(name.as_encoded_bytes())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let parent = step::call(Step::Open, || {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY)
            .open(parent)
    })?;
    step::call(Step::Unlink, || sys::rmdir(&parent, &name))?;
    step::call(Step::Sync, || parent.sync_all())
}

/// Resolves an existing host path to its absolute canonical path for a worker
/// launched in another directory. Resolution follows symlinks.
///
/// # Errors
///
/// A missing path component, a symlink loop, or a failed host path lookup.
pub fn canonical_host(path: &Path) -> io::Result<PathBuf> {
    step::call(Step::Open, || path.canonicalize())
}

/// Collapses the `.` and `..` components of `path` in memory; a `..` at the
/// root stays at the root.
pub fn lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            other => out.push(other),
        }
    }
    out
}
fn cgroup_path_error(reason: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, reason)
}

pub(crate) fn launch_paths(gate: &Path, directory: &Path) -> io::Result<()> {
    if !gate.is_absolute() || !directory.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "launch paths must be absolute",
        ));
    }
    let executable = step::call(Step::Stat, || fs::metadata(gate))?;
    let working = step::call(Step::Stat, || fs::metadata(directory))?;
    if !executable.is_file() || !working.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "launch paths require an executable file and directory",
        ));
    }
    step::call(Step::Stat, || sys::searchable(gate))?;
    step::call(Step::Stat, || sys::searchable(directory))?;
    Ok(())
}

pub(crate) fn cgroup_directory(path: &Path) -> io::Result<std::fs::File> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(cgroup_path_error(
            "cgroup path must be absolute and traversal-safe",
        ));
    }
    let name = CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| cgroup_path_error("cgroup path contains NUL"))?;
    let directory = step::call(Step::Open, || sys::open_dir_nofollow(&name))?;
    if !step::call(Step::Stat, || sys::cgroup_v2(&directory))? {
        return Err(cgroup_path_error("path is not a cgroup"));
    }
    Ok(directory)
}

pub(crate) fn cgroup_present(path: &Path) -> io::Result<bool> {
    match cgroup_directory(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// Replaces the file at host path `path` with `bytes`: creates a sibling
/// `<name>.tmp`, writes and syncs it, renames it over `path` and syncs the
/// directory that holds them, so the replacement outlasts a power loss
/// once the call returns. An entry
/// already at the sibling's name, which an interrupted replacement leaves,
/// is removed first, and the sibling is created exclusively, so the bytes
/// go to a file this call made and through no symlink.
///
/// # Errors
///
/// `InvalidInput` for a path with no file name; `AlreadyExists` when an
/// entry takes the sibling's name between its removal and its creation;
/// any failed removal, write, `fsync` or rename.
pub fn replace_host(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let mut staged = name.to_owned();
    staged.push(".tmp");
    let staged = path.with_file_name(staged);
    match fs::remove_file(&staged) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
        _ => {}
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&staged)?;
    file.write_all(bytes)?;
    step::call(Step::Sync, || file.sync_all())?;
    step::call(Step::Rename, || fs::rename(&staged, path))?;
    sync_parent(path)
}

/// Syncs the directory that holds host path `path`, which makes an entry
/// created or renamed there outlast a power loss.
pub fn sync_parent(path: &Path) -> io::Result<()> {
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let parent = step::call(Step::Open, || fs::File::open(parent))?;
    step::call(Step::Sync, || parent.sync_all())
}

/// Syncs pending changes across the filesystem containing host path
/// `path`, including changes outside the subtree rooted at `path`.
pub fn sync_filesystem_host(path: &Path) -> io::Result<()> {
    let opened = step::call(Step::Open, || fs::File::open(path))?;
    step::call(Step::Sync, || crate::sys::sync_filesystem(&opened))
}

/// Removes the file at host path `path` when one is there.
///
/// # Errors
///
/// Any failed removal of a file that is there.
pub fn remove_host(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

/// Removes the directory tree at host path `path` and unlinks each symlink
/// in the tree. A missing `path` counts as removed.
pub fn remove_tree(path: &Path) -> io::Result<()> {
    match step::call(Step::Unlink, || fs::remove_dir_all(path)) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

pub fn rename_host(from: &Path, to: &Path) -> io::Result<()> {
    step::call(Step::Rename, || fs::rename(from, to))
}

/// Whether host path `path` names an entry, a dangling symlink included.
/// Only `NotFound` counts as absence; another failed query is an error.
pub fn present_host(path: &Path) -> io::Result<bool> {
    match step::call(Step::Stat, || path.symlink_metadata()) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        status => status.map(|_| true),
    }
}

/// `regular_files` counts the immediate entries in `dir`. A directory,
/// symlink or special file among them causes `regular_files` to return
/// `InvalidData`.
pub fn regular_files(dir: &Path) -> io::Result<u64> {
    let file = |entry: io::Result<fs::DirEntry>| match entry?.file_type()?.is_file() {
        true => Ok(1),
        false => Err(io::ErrorKind::InvalidData.into()),
    };
    step::call(Step::List, || fs::read_dir(dir)?.map(file).sum())
}

pub fn subdirectories(dir: &Path) -> io::Result<Vec<std::ffi::OsString>> {
    step::call(Step::List, || {
        let mut names = Vec::new();
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                names.push(entry.file_name());
            }
        }
        Ok(names)
    })
}

/// The names of the entries of the directory `dir`, of every type.
pub fn names_host(dir: &Path) -> io::Result<Vec<std::ffi::OsString>> {
    step::call(Step::List, || {
        fs::read_dir(dir)?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect()
    })
}

/// Whether host path `path` names a directory, when `directory` is set,
/// or else a regular file, by the entry's own type. `NotFound` alone
/// reads as absent; an entry of another type is `InvalidData`.
pub fn typed_host(path: &Path, directory: bool) -> io::Result<bool> {
    match step::call(Step::Stat, || path.symlink_metadata()) {
        Ok(status) if status.is_dir() == directory && (directory || status.is_file()) => Ok(true),
        Ok(_) => Err(io::ErrorKind::InvalidData.into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// Creates a file for writing at host path `path`, requesting mode 0600,
/// and refuses an existing entry at `path`, a symlink included.
pub fn create_host(path: &Path) -> io::Result<fs::File> {
    step::call(Step::Open, || {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
    })
}

/// Cuts the file at host path `path` after its last newline and syncs it,
/// so a record an append left without its newline, as a process killed
/// during the append leaves, is gone before the next append joins it. A
/// file that ends in a newline, an empty one and a path with no entry are
/// left as they are. A symlink at `path` is refused.
///
/// # Errors
///
/// `ELOOP` for a symlink at `path`; any other failed open, status query,
/// read, truncation or sync.
pub fn trim_host(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    let opened = step::call(Step::Open, || {
        OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
    });
    let file = match opened {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        opened => opened?,
    };
    let length = step::call(Step::Stat, || file.metadata())?.len();
    let mut end = length;
    let mut bytes = [0; 1 << 16];
    while end > 0 {
        let start = end.saturating_sub(bytes.len() as u64);
        let read = &mut bytes[..(end - start) as usize];
        file.read_exact_at(read, start)?;
        if let Some(at) = read.iter().rposition(|&byte| byte == b'\n') {
            end = start + at as u64 + 1;
            break;
        }
        end = start;
    }
    if end == length {
        return Ok(());
    }
    file.set_len(end)?;
    step::call(Step::Sync, || file.sync_all())
}

/// Appends `bytes` to the file at host path `path`, creating it with mode
/// 0600, and syncs the file. An append to a file that was empty, as one
/// the call created is, then syncs the directory that holds it, so the
/// file's name outlasts a power loss with its first bytes. A symlink at
/// `path` is refused. A failed write or sync truncates the file to the
/// length it had before the call and syncs that, so a failed append
/// leaves the bytes that were there, across a power loss as well. The
/// caller appends to one path from one place at a time.
///
/// # Errors
///
/// `ELOOP` for a symlink at `path`; `WriteZero` for a write that takes no
/// byte; any other failed open, status query, write or sync. When the
/// truncation or its sync fails as well, the error names both failures
/// and the file may keep bytes the failed append wrote.
pub fn append_host(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let file = step::call(Step::Open, || {
        OpenOptions::new()
            .append(true)
            .create(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(path)
    })?;
    let length = step::call(Step::Stat, || file.metadata())?.len();
    let appended = super::publish::write_all(&file, bytes)
        .and_then(|()| step::call(Step::Sync, || file.sync_all()))
        .and_then(|()| {
            if length == 0 {
                sync_parent(path)
            } else {
                Ok(())
            }
        });
    let Err(error) = appended else {
        return Ok(());
    };
    let undone = file
        .set_len(length)
        .and_then(|()| step::call(Step::Sync, || file.sync_all()));
    match undone {
        Ok(()) => Err(error),
        Err(kept) => Err(io::Error::new(
            error.kind(),
            format!("{error}; the partial append may stay, since undoing it failed: {kept}"),
        )),
    }
}
