//! The record envelope and its read rule.
//!
//! A record file is the compact JSON of `{"format", "kind", "record",
//! "sha256"}`, keys in byte order, where `sha256` is the SHA-256 of the
//! compact JSON of `{"format", "kind", "record"}`, so the checksum covers
//! the format and the kind as well as the record.
//!
//! [`decode`] accepts a file only when every step passes, in this order:
//! the bytes parse as JSON of the record domain; no object repeats a key
//! and every string is printable ASCII; the top-level `format` is
//! [`FORMAT`]; the envelope has exactly its four fields and the expected
//! kind; the record decodes as its type with no unknown field; the bytes
//! equal the record's re-encoding under the stored checksum; and the
//! checksum matches the re-encoding. The first step that fails names the
//! file's [`Held`] code. Equality with the re-encoding makes the stored
//! bytes canonical, so a verified record's bytes are a pure function of
//! its value.
//!
//! A file equal to its record's canonical encoding passes every step, and
//! a file that passes every step is that encoding. [`decode`] therefore
//! first parses the envelope and record typed in one pass and accepts the
//! file when its bytes equal the re-encoding under the stored checksum and
//! the checksum matches; any other file takes the steps in order, which
//! name its code.
//!
//! A record decodes against its kind's current field set, apart from
//! options the type omits when `None`. A record holding a
//! field its type lacks is held as [`Held::UnknownField`], one lacking a
//! field other than an option as [`Held::Mismatch`], and one lacking an
//! option field its type writes as `null` as [`Held::NonCanonical`], since
//! it re-encodes with `null`.
//! An option a type declares with `skip_serializing_if = "Option::is_none"`
//! encodes `None` as an absent key, so a file lacking that key re-encodes
//! to its own bytes, and an explicit `null` there is [`Held::NonCanonical`].
//!
//! The typed decode precedes the byte and checksum comparisons, so damage
//! that still decodes but breaks a record's derived fields, such as a
//! changed frozen field of a job, reads as [`Held::Mismatch`];
//! [`Held::Checksum`] names damage to canonical bytes that the typed decode
//! accepts.
//!
//! Every stored record names its format and kind, and this reader takes
//! [`FORMAT`] alone. A new format therefore either keeps a decoder for each
//! earlier format a marked state directory can hold, or changes the state
//! marker so that startup refuses older directories before any record is
//! read. Kind names are part of every stored envelope and stay fixed.
//! The format check precedes the envelope decode, so a file of another
//! format reads as [`Held::UnknownFormat`] whatever its other fields are.
//! The scan precedes the format check, so a file of any format holding a
//! repeated key or non-ASCII text reads as [`Held::DuplicateKey`] or
//! [`Held::NonAscii`].

use std::fmt;

use serde::de::IgnoredAny;
use serde::{Deserialize, Serialize};

use super::Digest;
use super::kind::Record;
use super::text::printable;
use super::value::{Fault, Value};
use crate::exit::Supervisor;
use crate::store::Unreadable;

/// The envelope format this codec writes and reads.
pub const FORMAT: u64 = 1;

/// Why a record file is held rather than verified. Each read fault has its
/// own code.
#[derive(Debug)]
pub enum Held {
    /// The bounded read of the file failed.
    Unreadable(Unreadable),
    /// The bytes are no JSON of the record domain: a syntax error, invalid
    /// UTF-8, nesting past the parser's limit, a float, or an integer
    /// outside 0 to `u64::MAX`.
    Malformed,
    /// An object names one key twice.
    DuplicateKey,
    /// A string or key holds a byte outside printable ASCII.
    NonAscii,
    /// The file names another format than [`FORMAT`], or none.
    UnknownFormat,
    /// An object holds a field its type does not declare.
    UnknownField,
    /// The decoded record fails its field types, static rules or derivations.
    Mismatch,
    /// The envelope names another kind than the one read.
    WrongKind,
    /// The checksum differs from the record's.
    Checksum,
    /// The bytes decode, but differ from the record's canonical encoding.
    NonCanonical,
}

impl Held {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unreadable(_) => "unreadable",
            Self::Malformed => "malformed",
            Self::DuplicateKey => "duplicate-key",
            Self::NonAscii => "non-ascii",
            Self::UnknownFormat => "unknown-format",
            Self::UnknownField => "unknown-field",
            Self::Mismatch => "mismatch",
            Self::WrongKind => "wrong-kind",
            Self::Checksum => "checksum",
            Self::NonCanonical => "non-canonical",
        }
    }

    /// The supervisor exit a command that needs the record ends with.
    pub fn exit(&self) -> Supervisor {
        Supervisor::Held
    }
}

impl fmt::Display for Held {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreadable(unreadable) => write!(f, "the record is unreadable: {unreadable}"),
            Self::Malformed => f.write_str("the record is no JSON of the record domain"),
            Self::DuplicateKey => f.write_str("the record repeats a key"),
            Self::NonAscii => f.write_str("the record holds text outside printable ASCII"),
            Self::UnknownFormat => f.write_str("the record names another format or none"),
            Self::UnknownField => f.write_str("the record holds an unknown field"),
            Self::Mismatch => {
                f.write_str("the record fails its field types, static rules or derivations")
            }
            Self::WrongKind => f.write_str("the record is of another kind"),
            Self::Checksum => f.write_str("the record fails its checksum"),
            Self::NonCanonical => f.write_str("the record's bytes are not its canonical encoding"),
        }
    }
}

impl std::error::Error for Held {}

impl From<Fault> for Held {
    fn from(fault: Fault) -> Self {
        match fault {
            Fault::UnknownField => Self::UnknownField,
            Fault::Mismatch => Self::Mismatch,
        }
    }
}

/// The envelope fields the checksum covers.
#[derive(Serialize)]
struct Unsealed<'a, R> {
    format: u64,
    kind: &'static str,
    record: &'a R,
}

/// The envelope as the canonical check parses it. The byte comparison
/// covers `format` and `kind`, so the parse reads past them.
#[derive(Deserialize)]
struct Canonical<R> {
    #[serde(rename = "format")]
    _format: IgnoredAny,
    #[serde(rename = "kind")]
    _kind: IgnoredAny,
    record: R,
    sha256: Digest,
}

/// The envelope as decoded. [`decode`] has already checked that `format`
/// is [`FORMAT`]; the field is declared so that `deny_unknown_fields`
/// admits it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Opened {
    #[serde(rename = "format")]
    _format: IgnoredAny,
    kind: String,
    record: Value,
    sha256: Digest,
}

/// The compact JSON of `record`'s checksummed envelope fields: one object,
/// so its last byte is the closing brace.
fn unsealed<R: Record>(record: &R) -> Vec<u8> {
    let unsealed = Unsealed {
        format: FORMAT,
        kind: R::KIND.name(),
        record,
    };
    // Serialization fails only on a non-string map key or a failing
    // `Serialize` impl, and no record type holds either.
    serde_json::to_vec(&unsealed).expect("a record encodes")
}

/// The key that follows the checksummed fields in a file.
const SEAL_KEY: &[u8] = b",\"sha256\":\"";
/// The bytes that close a file after the checksum's digits.
const SEAL_END: &[u8] = b"\"}";

/// The file bytes of the checksummed fields `unsealed` with `sha256` as
/// their checksum: the same object with a last `sha256` entry.
fn sealed(unsealed: &[u8], sha256: Digest) -> Vec<u8> {
    let fields = &unsealed[..unsealed.len() - 1];
    let mut bytes = Vec::with_capacity(unsealed.len() + SEAL_KEY.len() + 64 + SEAL_END.len());
    bytes.extend_from_slice(fields);
    bytes.extend_from_slice(SEAL_KEY);
    bytes.extend_from_slice(&sha256.hex());
    bytes.extend_from_slice(SEAL_END);
    bytes
}

/// Whether `bytes` equal [`sealed`] of `unsealed` and `sha256`.
fn seals(bytes: &[u8], unsealed: &[u8], sha256: Digest) -> bool {
    bytes
        .strip_prefix(&unsealed[..unsealed.len() - 1])
        .and_then(|rest| rest.strip_prefix(SEAL_KEY))
        .and_then(|rest| rest.strip_suffix(SEAL_END))
        == Some(&sha256.hex()[..])
}

/// The canonical file bytes of `record`.
pub(crate) fn encode<R: Record>(record: &R) -> Vec<u8> {
    let unsealed = unsealed(record);
    sealed(&unsealed, Digest::of(&unsealed))
}

/// The record that `bytes` holds when they pass the read rule.
///
/// # Errors
///
/// The [`Held`] code of the first failed step.
pub(crate) fn decode<R: Record>(bytes: &[u8]) -> Result<R, Held> {
    match canonical(bytes) {
        Some(record) => Ok(record),
        None => stepwise(bytes),
    }
}

/// The record whose canonical file bytes `bytes` are.
pub(super) fn canonical<R: Record>(bytes: &[u8]) -> Option<R> {
    let envelope: Canonical<R> = serde_json::from_slice(bytes).ok()?;
    let unsealed = unsealed(&envelope.record);
    (seals(bytes, &unsealed, envelope.sha256) && Digest::of(&unsealed) == envelope.sha256)
        .then_some(envelope.record)
}

/// The record that `bytes` holds when every step of the read rule passes,
/// in order.
///
/// # Errors
///
/// The [`Held`] code of the first failed step.
fn stepwise<R: Record>(bytes: &[u8]) -> Result<R, Held> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| Held::Malformed)?;
    scan(&value)?;
    let Value::Object(entries) = &value else {
        return Err(Held::UnknownFormat);
    };
    let format =
        |(key, value): &(String, Value)| key == "format" && *value == Value::Integer(FORMAT);
    if !entries.iter().any(format) {
        return Err(Held::UnknownFormat);
    }
    let opened = Opened::deserialize(value)?;
    if opened.kind != R::KIND.name() {
        return Err(Held::WrongKind);
    }
    let record = R::deserialize(opened.record)?;
    let unsealed = unsealed(&record);
    if !seals(bytes, &unsealed, opened.sha256) {
        return Err(Held::NonCanonical);
    }
    if Digest::of(&unsealed) != opened.sha256 {
        return Err(Held::Checksum);
    }
    Ok(record)
}

/// Checks every object in `value` for a repeated key and every string and
/// key for printable ASCII.
fn scan(value: &Value) -> Result<(), Held> {
    let ascii = |text: &str| {
        if printable(text) {
            Ok(())
        } else {
            Err(Held::NonAscii)
        }
    };
    match value {
        Value::Null | Value::Bool(_) | Value::Integer(_) => Ok(()),
        Value::Text(text) => ascii(text),
        Value::Array(items) => items.iter().try_for_each(scan),
        Value::Object(entries) => {
            let mut keys: Vec<&str> = entries.iter().map(|(key, _)| key.as_str()).collect();
            keys.sort_unstable();
            if keys.windows(2).any(|pair| pair[0] == pair[1]) {
                return Err(Held::DuplicateKey);
            }
            entries.iter().try_for_each(|(key, value)| {
                ascii(key)?;
                scan(value)
            })
        }
    }
}
