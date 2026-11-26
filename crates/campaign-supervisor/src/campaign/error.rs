#[derive(Debug)]
pub enum Error {
    Rejected(String),
    Held(String),
    Custody(String),
    Record(crate::record::Held),
    Unreadable(crate::store::Unreadable),
    Store(crate::store::Error),
    /// A state-wide census hold with its path and typed cause.
    Census {
        path: String,
        cause: Box<Error>,
    },
    /// A root's count or settlement-inclusive projection at the bound;
    /// `None` means its listing holds more than `bound` entries.
    Bound {
        root: String,
        entries: Option<usize>,
        bound: usize,
    },
}

impl Error {
    pub(super) fn authority_full(kind: &str) -> String {
        format!(
            "{kind} authority scan bound ({}) reached; this state directory accepts no more {kind} records; preserve it and start a new state directory (authority retention is a follow-up)",
            crate::scan_bound()
        )
    }

    /// Holds `root` at `entries`, including projected settlement reservations.
    pub(crate) fn bound(root: &str, entries: usize) -> Self {
        Self::Bound {
            root: root.to_owned(),
            entries: Some(entries),
            bound: crate::scan_bound(),
        }
    }

    /// The hold for `root`, found to hold more than the scan bound entries.
    pub(crate) fn over(root: &str) -> Self {
        Self::Bound {
            root: root.to_owned(),
            entries: None,
            bound: crate::scan_bound(),
        }
    }

    /// Names a scan-bound listing hold; other store errors propagate.
    pub(crate) fn listing(root: &str, error: crate::store::Error) -> Self {
        match error {
            crate::store::Error::ScanBound => Self::over(root),
            error => Self::Store(error),
        }
    }

    /// Whether this is a store or root-named scan-bound hold.
    pub(crate) fn at_scan_bound(&self) -> bool {
        matches!(
            self,
            Self::Store(crate::store::Error::ScanBound) | Self::Bound { .. }
        )
    }

    /// Names a damaged record's subject while preserving host and bound errors.
    pub(crate) fn about(self, subject: impl std::fmt::Display) -> Self {
        match self {
            Self::Held(_)
            | Self::Record(_)
            | Self::Unreadable(_)
            | Self::Store(crate::store::Error::Unreadable(_))
                if !self.host_fault() =>
            {
                Self::Held(format!("{subject}: {self}"))
            }
            error => error,
        }
    }

    pub(crate) fn exit(&self) -> crate::exit::Supervisor {
        use crate::exit::Supervisor;
        match self {
            Self::Rejected(_) => Supervisor::Rejected,
            Self::Held(_)
            | Self::Custody(_)
            | Self::Record(_)
            | Self::Unreadable(_)
            | Self::Bound { .. } => Supervisor::Held,
            Self::Store(error) => error.exit(),
            Self::Census { cause, .. } => cause.exit(),
        }
    }

    pub(super) fn custody(error: crate::custody::Error) -> Self {
        match error {
            error @ (crate::custody::Error::Held(_) | crate::custody::Error::Io(_)) => {
                Self::Custody(error.to_string())
            }
            error => error.into(),
        }
    }

    pub(crate) fn input_path(error: crate::store::Error) -> Self {
        match error {
            crate::store::Error::Refused(_) => Self::Rejected(error.to_string()),
            error => Self::Store(error),
        }
    }

    pub(crate) fn held_code(&self) -> &'static str {
        match self {
            Self::Census { cause, .. } => cause.held_code(),
            Self::Record(error) => error.code(),
            Self::Unreadable(_) | Self::Store(crate::store::Error::Unreadable(_)) => "unreadable",
            Self::Store(crate::store::Error::ScanBound) | Self::Bound { .. } => "scan-bound",
            Self::Store(_) => "store",
            Self::Held(_) => "binding",
            Self::Custody(_) => "custody",
            Self::Rejected(_) => "rejected",
        }
    }

    pub(crate) fn host_fault(&self) -> bool {
        match self {
            Self::Census { cause, .. } => cause.host_fault(),
            Self::Record(crate::record::Held::Unreadable(error))
            | Self::Unreadable(error)
            | Self::Store(crate::store::Error::Unreadable(error)) => error.faulted(),
            Self::Store(crate::store::Error::Io(_) | crate::store::Error::Poisoned) => true,
            _ => false,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(crate::store::Error::Io(error))
            | Self::Store(crate::store::Error::Unreadable(crate::store::Unreadable::Io(error)))
            | Self::Unreadable(crate::store::Unreadable::Io(error))
            | Self::Record(crate::record::Held::Unreadable(crate::store::Unreadable::Io(error)))
                if crate::sys::descriptor_limit(error) =>
            {
                write!(f, "descriptor limit reached (RLIMIT_NOFILE): {error}")
            }
            Self::Rejected(reason) | Self::Held(reason) | Self::Custody(reason) => {
                f.write_str(reason)
            }
            Self::Census { path, cause } => write!(f, "census of {path}: {cause}"),
            Self::Record(error) => error.fmt(f),
            Self::Unreadable(error) => error.fmt(f),
            Self::Store(error) => error.fmt(f),
            Self::Bound {
                root,
                entries,
                bound,
            } => crate::store::bound_text(f, root, *entries, *bound),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Store(crate::store::Error::Io(error))
    }
}

impl From<crate::store::Error> for Error {
    fn from(error: crate::store::Error) -> Self {
        Self::Store(error)
    }
}
impl From<crate::store::Unreadable> for Error {
    fn from(error: crate::store::Unreadable) -> Self {
        Self::Unreadable(error)
    }
}
impl From<crate::record::Held> for Error {
    fn from(error: crate::record::Held) -> Self {
        Self::Record(error)
    }
}
impl From<crate::custody::Error> for Error {
    fn from(error: crate::custody::Error) -> Self {
        match error {
            error @ crate::custody::Error::Rejected(_) => Self::Rejected(error.to_string()),
            crate::custody::Error::Store(error) => Self::Store(error),
            crate::custody::Error::Record(error) => Self::Record(error),
            crate::custody::Error::Bound {
                root,
                entries,
                bound,
            } => Self::Bound {
                root,
                entries,
                bound,
            },
            crate::custody::Error::Io(error) => {
                let error = crate::store::Unreadable::Io(error);
                if error.faulted() {
                    Self::Store(crate::store::Error::Unreadable(error))
                } else {
                    Self::Held(error.to_string())
                }
            }
            error => Self::Held(error.to_string()),
        }
    }
}

#[cfg(test)]
#[path = "error_tests.rs"]
mod tests;
