//! Before checks start, [`Plan`] determines each pushed tip's checks in run order, the ranges of the
//! weakened-test scan and the failures of the chaos record guard, or returns the [`Failure`] that ends the
//! push.
//!
//! [`Plan::line`] reads one ref line of Git's pre-push input, `<local ref> <local sha> <remote ref>
//! <remote sha>`, and states the states of a line. [`Plan::guard`] reads the chaos records after the scans.
//! [`crate::git::push_environ`] makes every Git child read the original objects even when `refs/replace/`
//! entries exist, and read each pathspec with its magic whatever pathspec mode the caller set.

mod guard;
mod members;
mod plan;
mod reads;
mod table;

pub use guard::{Record, account_number, account_numbers, record_values};
pub use members::Members;
pub use plan::{Plan, Skipped};
pub use reads::{destination_refs, ignored_tests};
pub use table::{Check, Held, ORDER, Row, checks_for};

use std::fmt;

use crate::git::GitError;
use crate::text::Text;

/// The reason a push ends before its checks start.
#[derive(Debug)]
pub enum Failure {
    /// A ref line without exactly four fields; `Display` writes `malformed ref line: ` and its `repr`.
    Malformed(Text),
    /// A failed Git read; `Display` writes the read's own text.
    Git(GitError),
    /// A tree entry or a raw diff record of a form that Git's manual does not give.
    Form(String),
    /// A commit named in a batch read whose text is not UTF-8, as a ref line's field read from bytes
    /// outside UTF-8 can be.
    Unencodable(Text),
}

impl From<GitError> for Failure {
    fn from(error: GitError) -> Self {
        Self::Git(error)
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(line) => write!(f, "malformed ref line: {}", line.repr()),
            Self::Git(error) => error.fmt(f),
            Self::Form(text) => f.write_str(text),
            Self::Unencodable(commit) => {
                write!(f, "the batch name of {} is not UTF-8", commit.repr())
            }
        }
    }
}

impl std::error::Error for Failure {}

/// `short` writes the first twelve code points of `commit`.
fn short(commit: &Text) -> String {
    Text::from_code_points(commit.code_points().take(12))
        .expect("a prefix of a text holds its code points")
        .to_string()
}

/// `shown` writes `path` as it is when it is printable, else as its `repr`.
fn shown(path: &str) -> String {
    let text = Text::from(path);
    if text.is_printable() {
        path.to_owned()
    } else {
        text.repr()
    }
}

#[cfg(test)]
#[path = "../hook_tests.rs"]
mod tests;
