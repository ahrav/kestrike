//! The GenMC judge distinguishes rule refusals from errors raised while evaluating a rule. Each error
//! class has its own variant, so a caller can catch some classes and pass the rest on.

use std::fmt;
use std::io;
use std::path::Path;

use regex::{Captures, Regex};

use crate::genmc::read_text;
use crate::json::{self, Text, Value};

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

    pub fn completed(code: Code, reason: String, completion: &'static str) -> Self {
        Self {
            code,
            reason,
            completion,
        }
    }

    /// The tool failure whose reason is `correspondence drift: ` followed by the lines of `drift` joined
    /// by `; `, with the completion [`DRIFT`].
    pub fn drift(drift: &[String]) -> Self {
        Self::completed(
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
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.reason)
    }
}

/// `Error::Refusal` displays the refusal's reason, and `Error::Key` displays the missing key as Python's
/// `repr` writes it. Other variants display their error text. `Value` covers invalid UTF-8, invalid
/// JSON and integers past the digit limit; `Runtime` covers JSON nesting past [`json::MAX_DEPTH`].
#[derive(Debug)]
pub enum Error {
    Refusal(Refusal),
    Os(io::Error),
    Value(String),
    Key(String),
    Type(String),
    Runtime(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refusal(refusal) => refusal.fmt(f),
            Self::Os(error) => error.fmt(f),
            Self::Value(text) | Self::Key(text) | Self::Type(text) | Self::Runtime(text) => {
                f.write_str(text)
            }
        }
    }
}

impl std::error::Error for Error {}

impl From<Refusal> for Error {
    fn from(refusal: Refusal) -> Self {
        Self::Refusal(refusal)
    }
}

/// `read_error` maps invalid UTF-8 to [`Error::Value`] and other read failures to [`Error::Os`].
pub fn read_error(error: io::Error) -> Error {
    if error.kind() == io::ErrorKind::InvalidData {
        Error::Value(error.to_string())
    } else {
        Error::Os(error)
    }
}

/// # Errors
///
/// `read_strict` distinguishes invalid UTF-8 ([`Error::Value`]) from I/O failures ([`Error::Os`]).
pub fn read_strict(path: &Path) -> Result<String, Error> {
    read_text(path).map_err(read_error)
}

/// The file at `path` decoded as UTF-8 with each ill-formed sequence as U+FFFD, and with `\r\n` and a
/// lone `\r` read as `\n`.
///
/// # Errors
///
/// `read_replaced` returns the error of opening or reading the file.
pub fn read_replaced(path: &Path) -> io::Result<String> {
    let bytes = std::fs::read(path)?;
    Ok(String::from_utf8_lossy(&bytes)
        .replace("\r\n", "\n")
        .replace('\r', "\n"))
}

/// # Errors
///
/// `parse_json` returns [`Error::Runtime`] for nesting deeper than [`json::MAX_DEPTH`] and
/// [`Error::Value`] for any other text [`json::parse`] refuses.
pub fn parse_json(text: &str) -> Result<Value, Error> {
    json::parse(text).map_err(|error| {
        if error.reason() == json::DEPTH_REASON {
            Error::Runtime(error.to_string())
        } else {
            Error::Value(error.to_string())
        }
    })
}

/// # Errors
///
/// `read_json` returns [`Error::Runtime`] when JSON nesting exceeds [`json::MAX_DEPTH`]. Read failures,
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

/// Python's `value[key]`.
///
/// # Errors
///
/// `member` returns [`Error::Key`] for an object without `key` and [`Error::Type`] for non-object
/// values.
pub fn member<'v>(value: &'v Value, key: &str) -> Result<&'v Value, Error> {
    lookup(value, key)?.ok_or_else(|| Error::Key(Text::from(key).repr()))
}

/// Python's `value.get(key)`.
///
/// # Errors
///
/// `lookup` returns [`Error::Type`] for non-object values.
pub fn lookup<'v>(value: &'v Value, key: &str) -> Result<Option<&'v Value>, Error> {
    match value {
        Value::Object(object) => Ok(object.get(key)),
        _ => Err(Error::Type(format!(
            "the member {key} of a value that is no object"
        ))),
    }
}

/// The text of the string `value`, which `what` names in an error.
///
/// # Errors
///
/// `string` returns [`Error::Type`] for non-string values and for a string with a lone surrogate.
pub fn string<'v>(value: &'v Value, what: &str) -> Result<&'v str, Error> {
    match value {
        Value::String(text) => text
            .to_str()
            .ok_or_else(|| Error::Type(format!("{what} holds a lone surrogate"))),
        _ => Err(Error::Type(format!("{what} is no string"))),
    }
}
