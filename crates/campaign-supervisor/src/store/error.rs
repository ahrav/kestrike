//! The store's failures and refusals, and the supervisor exit each maps to.

use std::fmt;
use std::io;

use crate::exit::Supervisor;

/// A store failure or refusal. Every variant but [`Error::Oversize`] ends
/// the controller's use of its store.
#[derive(Debug)]
pub enum Error {
    /// Another controller holds the state directory's lock.
    Busy,
    /// An earlier mutation failed, so the store writes nothing more.
    Poisoned,
    /// The state directory's path names another inode than the one this
    /// store locked, so the last mutation is unacknowledged.
    Replaced,
    /// The state directory breaks the store's contract.
    Refused(Refusal),
    /// A listing holds more entries than its bound, so its contents are
    /// never acted on.
    ScanBound,
    /// A census reached a directory nested 64 levels deep, so the tree
    /// below it is never counted.
    DepthBound,
    /// A record's encoding is larger than its reader's bound, so it was
    /// never written.
    Oversize,
    /// A listed entry, this name decoded lossily, breaks the
    /// [`super::Name`] rules, so the listing is never acted on.
    Foreign(String),
    /// An entry the store needs is a symlink, the wrong kind of entry, or
    /// failed to open; [`super::Store::open`] raises it for the `.state`
    /// marker file and the `.staging` directory.
    Unreadable(Unreadable),
    /// A read-only view's durability barrier failed.
    Barrier(io::Error),
    /// A system call failed.
    Io(io::Error),
}

/// Why a state directory is refused.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// It lies on this filesystem type rather than ext4 or xfs.
    Filesystem(String),
    /// Its mount, ext4 option list or block device fails the contract, for
    /// the reason given: a missing record, a refused option, a missing
    /// data mode or device name, or a kernel table past its read bound. A
    /// kernel table that fails to read is [`Error::Io`] instead.
    Mount(String),
    /// A path ancestor is a symlink, is owned by another non-root user, or
    /// is group- or world-writable without the sticky bit.
    Ancestor(String),
    /// The parent of this path carries a default ACL, which an entry
    /// created there would inherit.
    DefaultAcl(String),
    /// It is owned by this user ID rather than the running one.
    Owner(u32),
    /// Its permission bits are these rather than 0700.
    Mode(u32),
    /// The process umask clears an owner permission bit, or the process
    /// status reports no umask (`None`).
    Umask(Option<u32>),
    /// This operation requires a state marker in the directory.
    Unmarked,
    /// Its state marker holds other bytes than this store writes.
    Marker,
}

/// Why a record or directory read was refused. A read refusal leaves the
/// store writable; the caller holds the record it names.
#[derive(Debug)]
pub enum Unreadable {
    /// The name is a symlink or resolves through one.
    Symlink,
    /// The name is a mount point or resolves across one.
    CrossMount,
    /// The name opened as a FIFO, device or directory where a regular file
    /// belongs. An entry whose open fails, a socket included, is
    /// [`Unreadable::Io`].
    NotRegular,
    /// The file holds more bytes than the read's bound.
    Oversize,
    /// A system call failed.
    Io(io::Error),
}

impl Error {
    /// The supervisor exit this failure ends the command with.
    pub fn exit(&self) -> Supervisor {
        match self {
            Self::Busy => Supervisor::Busy,
            Self::Oversize => Supervisor::Rejected,
            Self::Poisoned
            | Self::Replaced
            | Self::Refused(_)
            | Self::ScanBound
            | Self::DepthBound
            | Self::Foreign(_)
            | Self::Unreadable(_)
            | Self::Barrier(_)
            | Self::Io(_) => Supervisor::Held,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<Refusal> for Error {
    fn from(refusal: Refusal) -> Self {
        Self::Refused(refusal)
    }
}

impl From<Unreadable> for Error {
    fn from(unreadable: Unreadable) -> Self {
        Self::Unreadable(unreadable)
    }
}

impl From<io::Error> for Unreadable {
    fn from(error: io::Error) -> Self {
        match error.raw_os_error() {
            Some(libc::ELOOP) => Self::Symlink,
            Some(libc::EXDEV) => Self::CrossMount,
            _ => Self::Io(error),
        }
    }
}

impl Unreadable {
    /// Whether the read failed through a fault of the host, such as `EIO`
    /// or `EMFILE`, which leaves the file's own fitness unknown.
    pub(crate) fn faulted(&self) -> bool {
        let Self::Io(error) = self else {
            return false;
        };
        if error
            .get_ref()
            .is_some_and(|error| matches!(error.downcast_ref::<Error>(), Some(Error::Barrier(_))))
        {
            return false;
        }
        host_fault(error)
    }
}

/// Whether `error` is a fault of the host, such as `EIO` or `EMFILE`,
/// rather than a refusal that names the file or this user's access to it.
pub(crate) fn host_fault(error: &io::Error) -> bool {
    !matches!(
        error.kind(),
        io::ErrorKind::NotFound
            | io::ErrorKind::NotADirectory
            | io::ErrorKind::PermissionDenied
            | io::ErrorKind::InvalidInput
            | io::ErrorKind::InvalidFilename
    ) && !matches!(error.raw_os_error(), Some(libc::ENXIO | libc::ELOOP))
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Busy => f.write_str("another process holds the state directory lock"),
            Self::Poisoned => f.write_str("an earlier write failed; the store writes nothing more"),
            Self::Replaced => {
                f.write_str("the state directory was replaced; the last write is unacknowledged")
            }
            Self::Refused(refusal) => write!(f, "the state directory is refused: {refusal:?}"),
            Self::ScanBound => f.write_str("a listing exceeds its scan bound"),
            Self::DepthBound => f.write_str("a census found a directory nested 64 levels deep"),
            Self::Oversize => f.write_str("a record is larger than its reader's bound"),
            Self::Foreign(name) => write!(f, "a listing holds the foreign entry {name:?}"),
            Self::Unreadable(unreadable) => {
                write!(f, "a store entry is unreadable: {unreadable}")
            }
            Self::Barrier(error) => write!(f, "the view barrier failed: {error}"),
            Self::Io(error) => write!(f, "the store failed: {error}"),
        }
    }
}

impl std::error::Error for Error {}

impl fmt::Display for Unreadable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Symlink => f.write_str("the name is a symlink or resolves through one"),
            Self::CrossMount => f.write_str("the name is a mount point or resolves across one"),
            Self::NotRegular => f.write_str("the name is no regular file"),
            Self::Oversize => f.write_str("the file holds more bytes than the read's bound"),
            Self::Io(error) => write!(f, "a system call failed: {error}"),
        }
    }
}

impl std::error::Error for Unreadable {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

/// Writes the scan-bound hold for `root`: its `entries`, or more than
/// `bound` when `entries` is `None`, and the remedy.
pub(crate) fn bound_text(
    f: &mut std::fmt::Formatter<'_>,
    root: &str,
    entries: Option<usize>,
    bound: usize,
) -> std::fmt::Result {
    match entries {
        Some(entries) => write!(
            f,
            "{root} holds {entries} entries at bound {bound}; collect or shard"
        ),
        None => write!(
            f,
            "{root} holds more than {bound} entries at bound {bound}; collect or shard"
        ),
    }
}
