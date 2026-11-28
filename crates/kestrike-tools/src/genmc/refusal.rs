//! The GenMC judge distinguishes rule refusals from errors raised while evaluating a rule. Each error
//! class has its own variant, so a caller can catch some classes and pass the rest on.

use std::fmt;
use std::io;
use std::path::Path;

use regex::{Captures, Regex};

pub(crate) use super::input::{
    lines, listed, open_file, openable, replaced, strict, strings, texts,
};
pub use super::input::{
    lookup, member, parse_json, read_error, read_replaced, read_strict, string,
};
use crate::genmc::read_text;
use crate::json::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Code {
    Mismatch,
    ToolFailure,
    Incomplete,
}

impl Code {
    pub fn exit(self) -> u8 {
        match self {
            Self::Mismatch => 1,
            Self::ToolFailure => 2,
            Self::Incomplete => 3,
        }
    }

    fn completion(self) -> &'static str {
        match self {
            Self::Mismatch => "completed",
            Self::ToolFailure => "tool failure",
            Self::Incomplete => "exhausted",
        }
    }
}

/// The exit codes of a run that a signal or a deadline interrupted.
pub const INTERRUPTED: [u64; 3] = [124, 130, 143];

pub const DRIFT: &str = "correspondence drift";

/// A result quotes the refusal's `reason` in full.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    code: Code,
    reason: String,
    completion: &'static str,
}

impl Refusal {
    /// A refusal whose completion follows its code: `completed` for a mismatch, `tool failure` for a
    /// tool failure and `exhausted` for an incomplete run.
    pub fn new(code: Code, reason: String) -> Self {
        Self {
            code,
            reason,
            completion: code.completion(),
        }
    }

    pub(crate) fn with_completion(code: Code, reason: String, completion: &'static str) -> Self {
        Self {
            code,
            reason,
            completion,
        }
    }

    /// The tool failure whose reason is `correspondence drift: ` followed by the lines of `drift` joined
    /// by `; `, with the completion [`DRIFT`].
    pub fn drift(drift: &[String]) -> Self {
        Self::with_completion(
            Code::ToolFailure,
            format!("{DRIFT}: {}", drift.join("; ")),
            DRIFT,
        )
    }

    pub fn code(&self) -> Code {
        self.code
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }

    pub fn completion(&self) -> &'static str {
        self.completion
    }

    pub fn is_drift(&self) -> bool {
        self.completion == DRIFT
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.reason)
    }
}

/// The class of an error a rule raises. `Refusal` is the judge's own refusal and displays its reason.
/// `Os` is a failed lookup, open or read. `Value` is bytes that are no UTF-8, JSON the reader refuses,
/// an integer past the digit limit, a path that holds a NUL byte and an identity record of another
/// shape. `Key` is a member a value lacks and displays the key as Python's `repr` writes it. `Type` is
/// a value of another JSON type than a rule reads. `Runtime` is JSON nesting past
/// [`MAX_DEPTH`](crate::json::MAX_DEPTH) and a path lookup that meets a link loop or links nested past
/// [`crate::paths::DEPTH`]. `Index` is a binding whose `matching` count leaves no occurrence to read.
#[derive(Debug)]
pub enum Error {
    Refusal(Refusal),
    Os(io::Error),
    Value(String),
    Key(String),
    Type(String),
    Runtime(String),
    Index(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refusal(refusal) => refusal.fmt(f),
            Self::Os(error) => error.fmt(f),
            Self::Value(text)
            | Self::Key(text)
            | Self::Type(text)
            | Self::Runtime(text)
            | Self::Index(text) => f.write_str(text),
        }
    }
}

impl std::error::Error for Error {}

impl From<Refusal> for Error {
    fn from(refusal: Refusal) -> Self {
        Self::Refusal(refusal)
    }
}

/// # Errors
///
/// `read_json` returns [`Error::Runtime`] when JSON nesting exceeds [`MAX_DEPTH`](crate::json::MAX_DEPTH). Read failures,
/// invalid UTF-8 and other JSON parse failures produce the tool failure `unreadable <path>: <error>`.
pub fn read_json(path: &Path) -> Result<Value, Error> {
    let unreadable = |error: &dyn fmt::Display| {
        Error::Refusal(Refusal::new(
            Code::ToolFailure,
            format!("unreadable {}: {error}", path.display()),
        ))
    };
    let text = read_text(path).map_err(|error| unreadable(&error))?;
    match parse_json(&text) {
        Err(Error::Value(error)) => Err(unreadable(&error)),
        parsed => parsed,
    }
}

/// The one line of `lines` that `pattern` matches at its start.
///
/// # Errors
///
/// `single` returns the tool failure `<name> prints <count> <what> lines` for any count of matching
/// lines other than one.
pub fn single<'l>(
    lines: &'l [String],
    pattern: &Regex,
    name: &str,
    what: &str,
) -> Result<Captures<'l>, Refusal> {
    let mut found: Vec<Captures<'l>> = lines
        .iter()
        .filter_map(|line| pattern.captures(line))
        .filter(|captures| captures.get_match().start() == 0)
        .collect();
    if found.len() != 1 {
        return Err(Refusal::new(
            Code::ToolFailure,
            format!("{name} prints {} {what} lines", found.len()),
        ));
    }
    Ok(found.remove(0))
}

pub(crate) fn tool_failure(reason: String) -> Error {
    Error::Refusal(Refusal::new(Code::ToolFailure, reason))
}
