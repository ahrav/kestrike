//! [`Failure`], the reason a push ends before its checks start, and the texts the hook's failures write: a
//! commit's twelve-code-point prefix, a path as a failure line shows it, and a text as a Git argument.

use std::ffi::OsString;
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
    /// A commit named in a batch read whose text is not UTF-8, as a ref line's field the caller decoded
    /// from bytes outside UTF-8 can be.
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

/// `argument` is `text` as a Git argument. The texts the plan passes to Git are read from bytes or from
/// Git's UTF-8 output, so each encodes as bytes.
pub(crate) fn argument(text: &Text) -> OsString {
    text.to_os()
        .expect("a text read from bytes encodes as those bytes")
}

/// `short` writes the first twelve code points of `commit`.
pub(crate) fn short(commit: &Text) -> String {
    Text::from_code_points(commit.code_points().take(12))
        .expect("a prefix of a text holds its code points")
        .to_string()
}

/// `shown` writes `path` as it is when it is printable, else as its `repr`.
pub(super) fn shown(path: &str) -> String {
    let text = Text::from(path);
    if text.is_printable() {
        path.to_owned()
    } else {
        text.repr()
    }
}
