//! Why an archive is refused or its build fails, and the `sim` exit each
//! maps to.

use std::fmt;
use std::io;

use crate::exit::Sim;
use crate::record::Held;
use crate::store::{self, Refusal, Unreadable};

/// Why an archive or its build fails verification. `Invalid::exit` maps
/// each reason to its `sim` exit: 2 for a refused archive, 4 for a host
/// fault or a failure after a worker ran.
#[derive(Debug)]
pub enum Invalid {
    /// The archive path holds `:`, `;` or `$`, which the loader's library
    /// search path splits or expands, or a byte outside printable ASCII.
    Path(String),
    /// The archive's output path already names an entry.
    Exists,
    /// The archive holds no entry of this name.
    Missing(String),
    /// This entry is a symlink, the wrong kind of file, or fails to open
    /// or read.
    Unreadable(String, Unreadable),
    /// The archive's directory lies on another filesystem type than ext4
    /// or xfs, has a missing or oversized mount record, has a refused ancestor, or the running user
    /// does not own it with mode 0700.
    Refused(Refusal),
    /// The build record fails the record read rule.
    Record(Held),
    /// This entry's bytes have another digest than the build record names.
    Digest(String),
    /// The library directory holds other names than the build record
    /// lists, or the record names a library whose name fails the file-name rules.
    Libraries,
    /// The build record names this machine, and the host is another.
    Machine(String),
    /// The worker or library is no ELF64 little-endian executable for this host's
    /// machine, or the host machine is unknown, has program headers of another size or none, a segment
    /// past its read bound or a truncated one, names more than one, an
    /// unterminated, relative or non-printable-ASCII program interpreter, or another one than
    /// the build record, needs libraries and names no interpreter, names
    /// an `RPATH` without `RUNPATH` in the worker or a library, has a static entry point outside executable load segments, ends its dynamic section with no terminating entry, or
    /// lacks its owner execute permission, for the reason given.
    Elf(String),
    /// The worker's or a library's dynamic section names an audit module, which the
    /// loader runs before the program and the archive holds no copy of.
    Audit,
    /// The host names an active system preload, or the loader's library
    /// listing exits nonzero, writes to standard error, passes its output
    /// bound, reports a statically linked executable, holds a row naming
    /// no path or more libraries than an archive holds, resolves a library
    /// by path, nowhere, twice or outside the archive, or names a library
    /// no archive file name can hold, for the reason given.
    Resolution(String),
    /// A file's identity changed while it was verified or since the
    /// verification before a use, or the archive's path names another
    /// directory than the one loaded.
    Changed,
    /// A call the verification makes failed, such as the loader's spawn,
    /// or the host's machine name is no printable ASCII.
    Io(io::Error),
}

impl Invalid {
    /// The `sim` exit this reason ends a command with; `used` is whether a
    /// worker ran before the archive failed. A failure after a use, a
    /// failed call ([`Invalid::Io`]), or an entry unreadable through a host
    /// fault ([`Unreadable::faulted`]) is incomplete evidence, exit 4;
    /// every other reason found before a use refuses the archive, exit 2.
    pub(crate) fn exit(&self, used: bool) -> Sim {
        let io = match self {
            Self::Io(_) => true,
            Self::Unreadable(_, unreadable) | Self::Record(Held::Unreadable(unreadable)) => {
                unreadable.faulted()
            }
            _ => false,
        };
        if used || io {
            Sim::Incomplete
        } else {
            Sim::Rejected
        }
    }

    /// The reason a store failure of the archive's view gives.
    pub(super) fn store(error: store::Error) -> Self {
        match error {
            store::Error::Refused(refusal) => Self::Refused(refusal),
            store::Error::Io(error) => Self::Io(error),
            error => Self::Io(io::Error::other(error.to_string())),
        }
    }
}

/// The [`Invalid`] reason for an archive's post-use verification failure.
#[derive(Debug)]
pub struct Unfinished(pub Invalid);

/// Why `sim archive` failed.
#[derive(Debug)]
pub enum Error {
    Interrupted(i32),
    /// The output, the executable or its library resolution is refused,
    /// exit 2, or a host fault failed a check, exit 4, as
    /// `Invalid::exit` decides before a use.
    Invalid(Invalid),
    /// The build or a probe before the build failed, exit 3.
    Build(String),
    /// A build input or output changed or vanished, a closing checkout probe failed,
    /// output creation or removal failed, or publication or its verification failed, exit 4.
    Incomplete(String),
    /// The archive's store failed to open for a reason other than a
    /// refusal, or failed after it opened, exit 4; the output directory
    /// stays in place.
    Store(store::Error),
}

impl Error {
    /// The `sim` exit this failure ends the command with.
    pub fn exit(&self) -> Sim {
        match self {
            Self::Interrupted(_) => Sim::Interrupted,
            Self::Invalid(invalid) => invalid.exit(false),
            Self::Build(_) => Sim::BuildFailure,
            Self::Incomplete(_) | Self::Store(_) => Sim::Incomplete,
        }
    }
}

impl From<Invalid> for Error {
    fn from(invalid: Invalid) -> Self {
        Self::Invalid(invalid)
    }
}

impl From<Unfinished> for Error {
    fn from(unfinished: Unfinished) -> Self {
        Self::Incomplete(unfinished.to_string())
    }
}

impl From<store::Error> for Error {
    fn from(error: store::Error) -> Self {
        Self::Store(error)
    }
}

impl fmt::Display for Invalid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Path(path) => write!(
                f,
                "the archive path {path:?} holds `:`, `;`, `$` or a byte outside printable ASCII"
            ),
            Self::Exists => {
                f.write_str("an entry has the output path; an archive is never replaced")
            }
            Self::Missing(name) => write!(f, "the archive holds no {name}"),
            Self::Unreadable(name, why) => write!(f, "the archive's {name} is unreadable: {why}"),
            Self::Refused(refusal) => write!(f, "the archive's directory is refused: {refusal:?}"),
            Self::Record(held) => write!(f, "the build record is held: {held}"),
            Self::Digest(name) => write!(f, "the archive's {name} differs from its build record"),
            Self::Libraries => f.write_str("the archive holds other libraries than its record"),
            Self::Machine(machine) => write!(f, "the archive was built on {machine}"),
            Self::Elf(why) => write!(f, "the ELF object is refused: {why}"),
            Self::Audit => f.write_str("a worker or library names an audit module"),
            Self::Resolution(why) => write!(f, "the loader's resolution is refused: {why}"),
            Self::Changed => {
                f.write_str("the archive's files or the directory its path names changed")
            }
            Self::Io(error) => write!(f, "the archive check failed: {error}"),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Interrupted(signal) => write!(f, "archive interrupted by signal {signal}"),
            Self::Invalid(invalid) => invalid.fmt(f),
            Self::Build(why) => write!(f, "build failure: {why}"),
            Self::Incomplete(why) => write!(f, "incomplete archive: {why}"),
            Self::Store(error) => error.fmt(f),
        }
    }
}

impl fmt::Display for Unfinished {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the archive failed its check after the use: {}", self.0)
    }
}

impl std::error::Error for Invalid {}

impl std::error::Error for Unfinished {}

impl std::error::Error for Error {}
