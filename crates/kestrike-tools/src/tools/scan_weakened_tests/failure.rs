use std::fmt;

use crate::git::GitError;
use crate::json::MAX_INTEGER_DIGITS;

#[derive(Debug)]
pub enum Failure {
    Git(GitError),
    Refused(String),
    Digits(usize),
}

impl From<GitError> for Failure {
    fn from(error: GitError) -> Self {
        Self::Git(error)
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Git(error) => error.fmt(f),
            Self::Refused(text) => f.write_str(text),
            Self::Digits(count) => write!(
                f,
                "a run of {count} digits passes the limit of {MAX_INTEGER_DIGITS} for integer conversion"
            ),
        }
    }
}
