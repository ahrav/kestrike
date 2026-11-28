//! The GenMC judge distinguishes rule refusals from errors raised while evaluating a rule. Each error
//! class has its own variant, so a caller can catch some classes and pass the rest on.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use regex::{Captures, Regex};

use crate::genmc::read_text;
use crate::json::{self, Text, Value};
use crate::ownership::ignored;
use crate::text::newlines;

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
/// [`json::MAX_DEPTH`] and a path lookup that meets a link loop or links nested past
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
    Ok(newlines(String::from_utf8_lossy(&bytes).into_owned()))
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

/// A path that holds a NUL byte names no file, and a read of one is [`Error::Value`] with the text
/// `embedded null byte`.
///
/// # Errors
///
/// `openable` returns that error for such a path.
pub(crate) fn openable(path: &Path) -> Result<&Path, Error> {
    if path.as_os_str().as_bytes().contains(&0) {
        Err(Error::Value("embedded null byte".to_owned()))
    } else {
        Ok(path)
    }
}

pub(crate) fn tool_failure(reason: String) -> Error {
    Error::Refusal(Refusal::new(Code::ToolFailure, reason))
}

pub(crate) fn listed<'v>(value: &'v Value, what: &str) -> Result<&'v [Value], Error> {
    match value {
        Value::Array(items) => Ok(items),
        _ => Err(Error::Type(format!("{what} is no array"))),
    }
}

/// The strings of the array `value`, which `what` names in an error.
///
/// # Errors
///
/// `texts` returns [`Error::Type`] for a value that is no array and for an item that is no string or
/// holds a lone surrogate.
pub(crate) fn texts(value: &Value, what: &str) -> Result<Vec<String>, Error> {
    listed(value, what)?
        .iter()
        .map(|item| string(item, what).map(str::to_owned))
        .collect()
}

pub(crate) fn lines(text: &str) -> Vec<String> {
    Text::from(text)
        .splitlines()
        .iter()
        .map(ToString::to_string)
        .collect()
}

pub(crate) fn strings(items: &[String]) -> Value {
    Value::Array(
        items
            .iter()
            .map(|item| Value::String(item.as_str().into()))
            .collect(),
    )
}

pub(crate) fn open_file(path: &Path) -> io::Result<Option<File>> {
    if path.as_os_str().as_bytes().contains(&0) {
        return Ok(None);
    }
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if ignored(&error) => return Ok(None),
        Err(error) => return Err(error),
    };
    Ok(file.metadata()?.is_file().then_some(file))
}

pub(crate) fn replaced(mut file: File) -> io::Result<String> {
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(newlines(String::from_utf8_lossy(&bytes).into_owned()))
}

pub(crate) fn strict(mut file: File) -> Result<String, Error> {
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(Error::Os)?;
    let text = String::from_utf8(bytes).map_err(|error| Error::Value(error.to_string()))?;
    Ok(newlines(text))
}
