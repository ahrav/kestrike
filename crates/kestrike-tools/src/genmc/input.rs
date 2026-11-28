//! This module reads input files for the GenMC judge and provides access to JSON values.

use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use super::refusal::Error;
use crate::genmc::read_text;
use crate::json::{self, Text, Value};
use crate::ownership::ignored;
use crate::text::newlines;

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
