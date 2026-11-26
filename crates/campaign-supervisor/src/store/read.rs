//! Bounded reads and listings through the store's confined handles.

use std::ffi::CStr;
use std::fs::File;
use std::io::{self, Read as _};
use std::os::unix::fs::MetadataExt;

use super::dir::open_dir;
use super::file::Opened;
use super::{Dir, Error, Name, Store, Unreadable};
use crate::step::{self, Step};
use crate::sys;

/// The bytes of one bounded regular-file read, with the descriptors of the
/// file and its directory, which [`Store::barrier`] makes durable before a
/// record that depends on these bytes is published, within the barrier's
/// stated precondition. Its bytes come only from the read, and a holder
/// sees them only through [`Read::bytes`].
///
/// ```compile_fail,E0616
/// fn rewrite(read: &mut campaign_supervisor::store::Read) {
///     read.bytes.clear();
/// }
/// ```
///
/// ```compile_fail,E0277
/// let read: campaign_supervisor::store::Read = Default::default();
/// ```
#[derive(Debug)]
pub struct Read {
    bytes: Vec<u8>,
    modified_ms: Option<u64>,
    pub(super) file: File,
    pub(super) dir: Dir,
}

impl Read {
    pub(crate) fn directory_identity(&self) -> (u64, u64) {
        self.dir.identity()
    }

    /// The file's bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The read file's modification time in Unix milliseconds, from the
    /// status query of the descriptor opened for the read; `None` for a
    /// time before the Unix epoch.
    pub fn modified_ms(&self) -> Option<u64> {
        self.modified_ms
    }
}

impl Store {
    /// Opens directory `name` beneath `dir`; `None` when no entry has the
    /// name.
    ///
    /// # Errors
    ///
    /// [`Unreadable::Symlink`] for a symlink, [`Unreadable::CrossMount`]
    /// for a mount point, and [`Unreadable::Io`] for a non-directory
    /// (`ENOTDIR`) or a failed call.
    ///
    /// # Panics
    ///
    /// When `dir` lies under another state directory.
    pub fn open_dir(&self, dir: &Dir, name: &Name) -> Result<Option<Dir>, Unreadable> {
        self.owns(dir);
        absent_as_none(open_dir(dir, name.as_c_str()))
    }

    /// Reads the regular file `name` beneath `dir` when it holds at most
    /// `bound` bytes, consuming at most `bound + 1`; `None` when no entry
    /// has the name. The open never blocks, so a FIFO is refused at once.
    ///
    /// # Errors
    ///
    /// [`Unreadable`] for a symlink, a mount point, another file kind, a
    /// file past `bound` or a failed call. A socket fails the open
    /// (`ENXIO`) and is [`Unreadable::Io`]; other kinds that open are
    /// [`Unreadable::NotRegular`].
    ///
    /// # Panics
    ///
    /// When `dir` lies under another state directory.
    pub fn read(&self, dir: &Dir, name: &Name, bound: u64) -> Result<Option<Read>, Unreadable> {
        self.owns(dir);
        bounded(dir, name.as_c_str(), bound)
    }

    /// Opens the regular file `name` beneath `dir` for reading, as
    /// [`Store::read`] opens it, for a file too large to read whole, such
    /// as one another process wrote; `None` when no entry has the name.
    ///
    /// # Errors
    ///
    /// As [`Store::read`], past-bound refusal aside.
    ///
    /// # Panics
    ///
    /// When `dir` lies under another state directory.
    pub fn open_file(&self, dir: &Dir, name: &Name) -> Result<Option<Opened>, Unreadable> {
        self.owns(dir);
        let flags = libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOCTTY;
        let opened = step::call(Step::Open, || {
            sys::open_beneath(&dir.file, name.as_c_str(), flags, 0)
        });
        match absent_as_none(opened.map_err(Unreadable::from))? {
            Some(file) => Opened::new(file).map(Some),
            None => Ok(None),
        }
    }

    /// The names of `dir`'s entries, sorted. The state directory's own
    /// `.state` and `.staging` entries are left out and count toward the
    /// bound.
    ///
    /// # Errors
    ///
    /// [`Error::ScanBound`] when `dir` holds more than `bound` entries and
    /// [`Error::Foreign`] for any other entry whose name breaks the
    /// [`Name`] rules, so a caller never acts on a listing that omits an
    /// entry; [`Error::Io`] for a failed call.
    ///
    /// # Panics
    ///
    /// When `dir` lies under another state directory.
    pub fn list(&self, dir: &Dir, bound: usize) -> Result<Vec<Name>, Error> {
        self.owns(dir);
        listed(dir, self.root().ino, bound)
    }
    /// The names of the entries of `dir`, a state directory nested in this
    /// one, without its marker and staging directory, sorted.
    ///
    /// # Errors
    ///
    /// As [`Store::list`].
    ///
    /// # Panics
    ///
    /// When `dir` lies under another state directory.
    pub(crate) fn list_nested(&self, dir: &Dir, bound: usize) -> Result<Vec<Name>, Error> {
        self.owns(dir);
        listed(dir, dir.ino, bound)
    }
}

/// The names of `dir`'s entries, sorted, without the store's own entries
/// when `dir` is the directory of inode `root`.
pub(super) fn listed(dir: &Dir, root: u64, bound: usize) -> Result<Vec<Name>, Error> {
    names(entries(dir, bound)?, dir.ino == root)
}

pub(super) fn names(entries: Vec<Vec<u8>>, own: bool) -> Result<Vec<Name>, Error> {
    let mut names = Vec::new();
    for entry in entries {
        if !(own
            && super::HOUSEKEEPING_ENTRIES
                .iter()
                .any(|name| name.to_bytes() == entry))
        {
            let foreign = || Error::Foreign(String::from_utf8_lossy(&entry).into_owned());
            names.push(Name::from_bytes(&entry).ok_or_else(foreign)?);
        }
    }
    names.sort();
    Ok(names)
}

/// Reads the regular file `name` beneath `dir`, as [`Store::read`] does.
pub(super) fn bounded(dir: &Dir, name: &CStr, bound: u64) -> Result<Option<Read>, Unreadable> {
    // Opening `dir` afresh gives the read an open file description
    // independent of the store lock.
    bounded_with(dir, name, bound, |dir| open_dir(dir, c"."))
}

/// [`bounded`] for a view. A read beneath a subdirectory shares that
/// handle's open file description; a read in the state directory itself
/// opens the state directory afresh, giving the read an open file
/// description independent of the store lock.
pub(super) fn shared(dir: &Dir, name: &CStr, bound: u64) -> Result<Option<Read>, Unreadable> {
    bounded_with(dir, name, bound, |dir| {
        if dir.ino == dir.state.1 {
            open_dir(dir, c".")
        } else {
            dir.share()
        }
    })
}

fn bounded_with(
    dir: &Dir,
    name: &CStr,
    bound: u64,
    directory: impl FnOnce(&Dir) -> Result<Dir, Unreadable>,
) -> Result<Option<Read>, Unreadable> {
    let flags = libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOCTTY;
    let opened = step::call(Step::Open, || sys::open_beneath(&dir.file, name, flags, 0));
    let Some(file) = absent_as_none(opened.map_err(Unreadable::from))? else {
        return Ok(None);
    };
    let status = step::call(Step::Stat, || file.metadata())?;
    if !status.is_file() {
        return Err(Unreadable::NotRegular);
    }
    let modified_ms = match (
        u64::try_from(status.mtime()),
        u64::try_from(status.mtime_nsec()),
    ) {
        (Ok(seconds), Ok(nanos)) => seconds
            .checked_mul(1000)
            .and_then(|ms| ms.checked_add(nanos / 1_000_000)),
        _ => None,
    };
    let bytes = capped(&file, bound, status.len())?.ok_or(Unreadable::Oversize)?;
    let dir = directory(dir)?;
    Ok(Some(Read {
        bytes,
        modified_ms,
        file,
        dir,
    }))
}

/// The bytes of `file` when it holds at most `bound`, read in one
/// [`Step::Read`] that consumes at most `bound + 1` bytes; `None` past the
/// bound. The buffer starts with room for `size` bytes, capped at the
/// bound, plus the one byte that detects the end of the file.
pub(super) fn capped(file: &File, bound: u64, size: u64) -> io::Result<Option<Vec<u8>>> {
    let mut bytes =
        Vec::with_capacity(usize::try_from(size.min(bound).saturating_add(1)).unwrap_or(0));
    step::call(Step::Read, || {
        file.take(bound.saturating_add(1)).read_to_end(&mut bytes)
    })?;
    Ok((bytes.len() as u64 <= bound).then_some(bytes))
}

/// Every entry name of `dir` but `.` and `..`, in listing order.
///
/// # Errors
///
/// [`Error::ScanBound`] when `dir` holds more than `bound` entries;
/// [`Error::Io`] for a failed call.
pub(super) fn entries(dir: &Dir, bound: usize) -> Result<Vec<Vec<u8>>, Error> {
    // A fresh open gives the listing its own offset.
    let listing = step::call(Step::Open, || {
        sys::open_beneath(&dir.file, c".", libc::O_RDONLY | libc::O_DIRECTORY, 0)
    })?;
    let mut buffer = vec![0; 32 << 10];
    let mut entries = Vec::new();
    loop {
        let filled = step::call(Step::List, || sys::entries(&listing, &mut buffer))?;
        if filled == 0 {
            return Ok(entries);
        }
        for name in sys::names(&buffer[..filled]).filter(|&name| name != b"." && name != b"..") {
            if entries.len() == bound {
                return Err(Error::ScanBound);
            }
            entries.push(name.to_vec());
        }
    }
}

pub(super) fn holds_only(dir: &Dir, own: &[&CStr]) -> Result<bool, Error> {
    match entries(dir, own.len()) {
        Ok(entries) => Ok(entries
            .iter()
            .all(|entry| own.iter().any(|name| entry.as_slice() == name.to_bytes()))),
        Err(Error::ScanBound) => Ok(false),
        Err(error) => Err(error),
    }
}

pub(super) fn absent_as_none<T>(opened: Result<T, Unreadable>) -> Result<Option<T>, Unreadable> {
    match opened {
        Ok(value) => Ok(Some(value)),
        Err(Unreadable::Io(error)) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(refusal) => Err(refusal),
    }
}
