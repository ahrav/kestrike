//! Custody failures and their supervisor exit codes. `Rejected` is a refused
//! input, exit 2; a busy store lock is exit 3; every other variant maps to
//! `Supervisor::Held`, exit 4.

use crate::store;
use std::io;

#[derive(Debug)]
pub enum Error {
    Rejected(&'static str),
    Io(io::Error),
    Store(store::Error),
    Record(crate::record::Held),
    Held(&'static str),
    /// A listing or pre-write projection at the scan bound, under the store
    /// root or nested directory that `root` names; `None` means the listing
    /// holds more than `bound` entries.
    Bound {
        root: String,
        entries: Option<usize>,
        bound: usize,
    },
}

impl Error {
    /// Holds a root at its projected count or past its listing bound.
    pub(crate) fn bound(root: &str, entries: Option<usize>) -> Self {
        Self::Bound {
            root: root.to_owned(),
            entries,
            bound: crate::scan_bound(),
        }
    }

    pub fn exit(&self) -> crate::exit::Supervisor {
        match self {
            Self::Rejected(_) => crate::exit::Supervisor::Rejected,
            Self::Store(store::Error::Busy) => crate::exit::Supervisor::Busy,
            Self::Io(_) | Self::Store(_) | Self::Record(_) | Self::Held(_) | Self::Bound { .. } => {
                crate::exit::Supervisor::Held
            }
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
impl From<store::Error> for Error {
    fn from(error: store::Error) -> Self {
        Self::Store(error)
    }
}
impl From<crate::record::Held> for Error {
    fn from(error: crate::record::Held) -> Self {
        Self::Record(error)
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected(reason) => write!(f, "custody rejected: {reason}"),
            Self::Io(error) => write!(f, "custody held: {error}"),
            Self::Store(error) => write!(f, "custody held: {error}"),
            Self::Record(error) => write!(f, "custody record held: {error:?}"),
            Self::Held(reason) => write!(f, "custody held: {reason}"),
            Self::Bound {
                root,
                entries,
                bound,
            } => store::bound_text(f, root, *entries, *bound),
        }
    }
}
impl std::error::Error for Error {}

impl Error {
    pub(crate) fn draining(&self) -> bool {
        matches!(
            self,
            Self::Held(
                "controller interruption requires drain" | "dispatch deadline requires drain"
            )
        )
    }
}
