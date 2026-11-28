//! The controller's read of an input file: the judge's read of one regular file, then its strict UTF-8
//! JSON.

use std::path::Path;

use super::words::sentence;
use crate::gameday::{ReadError, Refusal, parsed, read_file};
use crate::json::Value;
use crate::text::Text;

/// The words for a path that holds a NUL byte, the Rust standard library's for that fact.
pub(super) const NUL: &str = "file name contained an unexpected NUL byte";

/// `read_bytes` is the bytes of the regular file at `path`, at most `limit` of them, read as
/// [`read_file`] reads them: opened without following a link at the last component and without
/// blocking, so a named pipe is refused as no regular file.
///
/// # Errors
///
/// `<what> has a path no file can have: <reason>` for a path with a NUL byte, then each refusal of
/// [`read_file`] naming `what`, and `<what> cannot be read: <reason>` for a failed close.
pub fn read_bytes(path: &Path, what: &Text, limit: u64) -> Result<Vec<u8>, Refusal> {
    read_file(path, None, what, limit, false).map_err(|error| match error {
        ReadError::Refused(refusal) => refusal,
        ReadError::Nul => Refusal::new(sentence!(what, " has a path no file can have: ", NUL)),
        ReadError::Closed(reason) => Refusal::new(sentence!(what, " cannot be read: ", reason)),
    })
}

/// `read_json` is the JSON value of the file at `path`, read by [`read_bytes`] and decoded by
/// [`parsed`] under the name `what`.
///
/// # Errors
///
/// Each refusal of [`read_bytes`], then each of [`parsed`].
pub fn read_json(path: &Path, what: &Text, limit: u64) -> Result<Value, Refusal> {
    parsed(&read_bytes(path, what, limit)?, what)
}
