//! Why a step leaves its plant with no verdict: a [`NoVerdict`] holds its reason and its [`Kind`], from
//! which the run decides what later plants get.

use std::io;
use std::path::Path;

use super::files::strerror;
use crate::text::{Text, text};

/// What a no verdict means for the plants after it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// The plant's own.
    Plain,
    /// A proof rerun exited 3: the head's library tests do not build, so no test id reruns.
    Unbuilt,
    /// A proof rerun left the proof's worktree without the run's `Cargo.lock`.
    Relocked,
}

/// A step's ending without a verdict: the reason the record states, and its kind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoVerdict {
    kind: Kind,
    reason: Text,
}

impl NoVerdict {
    pub fn plain(reason: impl Into<Text>) -> Self {
        Self::of(Kind::Plain, reason)
    }

    pub fn of(kind: Kind, reason: impl Into<Text>) -> Self {
        Self {
            kind,
            reason: reason.into(),
        }
    }

    /// `failed` is the plain no verdict `the run failed: WORDS` of a step that met a value of another
    /// shape than it reads.
    pub fn failed(words: impl Into<Text>) -> Self {
        Self::plain(text!("the run failed: ", words.into()))
    }

    /// `unreadable` is the plain no verdict of a file at `path` that a step cannot read: `the run failed:
    /// `, the system's text and the path, from the work directory `work` when it lies there.
    pub fn unreadable(path: &Path, error: &io::Error, work: &Path) -> Self {
        let named = path
            .strip_prefix(work)
            .ok()
            .filter(|rest| !rest.as_os_str().is_empty());
        let named = Text::from_os(named.unwrap_or(path).as_os_str());
        Self::failed(text!(strerror(error), " (", named, ")"))
    }

    pub fn kind(&self) -> Kind {
        self.kind
    }

    pub fn reason(&self) -> &Text {
        &self.reason
    }
}
