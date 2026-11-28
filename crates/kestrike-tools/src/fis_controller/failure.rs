//! [`Failure`] classifies the errors of an episode's steps, and [`SystemError`] holds a failed system
//! call as Python's `str` of an `OSError` words it.

use std::fmt;
use std::io;
use std::path::Path;

use crate::hardware_host::{Observer, ObserverError};
use crate::host_stop::Interrupted;
use crate::plants::files::strerror;
use crate::text::Text;

/// A failed system call, held as its error number and the text Python's `str` gives an `OSError`:
/// `[Errno N] <the system's text>`, then `: '<name>'` for a call that names one file and
/// `: '<name>' -> '<other>'` for one that names two. An error with no number is its text alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemError {
    errno: Option<i32>,
    text: Text,
}

impl SystemError {
    /// The error of a call that named `names`, each written as Python's `repr` of its text.
    pub fn of(error: &io::Error, names: &[&Path]) -> Self {
        Self::worded(error.raw_os_error(), &strerror(error), names)
    }

    /// An error of the number `errno` whose text is `words`.
    pub fn worded(errno: Option<i32>, words: &str, names: &[&Path]) -> Self {
        let mut text = Text::new();
        if let Some(code) = errno {
            text.push_str(&format!("[Errno {code}] "));
        }
        text.push_str(words);
        for (at, name) in names.iter().enumerate() {
            text.push_str(if at == 0 { ": " } else { " -> " });
            text.push_str(&Text::from_os(name.as_os_str()).repr());
        }
        Self { errno, text }
    }

    pub fn errno(&self) -> Option<i32> {
        self.errno
    }

    pub fn text(&self) -> &Text {
        &self.text
    }
}

impl fmt::Display for SystemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.text.fmt(f)
    }
}

impl std::error::Error for SystemError {}

/// Why a step ended without its result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failure {
    /// A system call failed.
    System(SystemError),
    /// The lane's rules refuse what the step met; the text says what.
    Refused(Text),
    /// A reply, a file or a record the step reads has no shape the step takes; the text says which.
    Unreadable(Text),
    /// The signal record raised the signal.
    Interrupted(Interrupted),
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::System(error) => error.fmt(f),
            Self::Refused(text) | Self::Unreadable(text) => text.fmt(f),
            Self::Interrupted(signal) => write!(f, "{signal} arrived"),
        }
    }
}

impl std::error::Error for Failure {}

impl From<SystemError> for Failure {
    fn from(error: SystemError) -> Self {
        Self::System(error)
    }
}

impl From<Interrupted> for Failure {
    fn from(signal: Interrupted) -> Self {
        Self::Interrupted(signal)
    }
}

/// An observer log's failure by its kind: a signal is [`Failure::Interrupted`]; a log or an event of
/// another shape, and a field nested past what a read takes, are [`Failure::Unreadable`]; a lock
/// another holder kept past the limit is the system error of its refused attempt, worded as the
/// observer's error names the wait; a failed open of the log is the system error naming the log's
/// path, and a log that cannot seek is the error naming none; every other failure is the system
/// error it carries, which names no file.
pub fn observed(error: ObserverError, observer: &Observer) -> Failure {
    let named = |cause: &io::Error| cause.raw_os_error() != Some(libc::ESPIPE);
    match (error, observer.path()) {
        (ObserverError::Open(cause), Some(path)) if named(&cause) => {
            Failure::System(SystemError::of(&cause, &[path]))
        }
        (ObserverError::Interrupted(signal), _) => Failure::Interrupted(signal),
        (error @ ObserverError::Held { errno, .. }, _) => {
            Failure::System(SystemError::worded(Some(errno), &error.to_string(), &[]))
        }
        (
            ObserverError::Directory(cause)
            | ObserverError::Open(cause)
            | ObserverError::Lock(cause)
            | ObserverError::Clock(cause)
            | ObserverError::Read(cause)
            | ObserverError::Node(cause)
            | ObserverError::Write(cause),
            _,
        ) => Failure::System(SystemError::of(&cause, &[])),
        (
            error @ (ObserverError::Undecodable { .. }
            | ObserverError::Malformed { .. }
            | ObserverError::Line { .. }
            | ObserverError::Depth { .. }
            | ObserverError::Event(_)),
            _,
        ) => Failure::Unreadable(Text::from(error.to_string())),
    }
}
