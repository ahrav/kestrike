//! `receipt.json` matches Python's `json.dumps(record, indent=2, sort_keys=True)` followed by a newline.
//!
//! Each leg reports wall time in seconds rounded to three decimal places.

use std::path::Path;

use super::evidence::Evidence;
use super::options::Options;
use crate::json::{self, Integer, NonFinite, Object, Value};
use crate::python;
use crate::text::{Text, text};

#[derive(Clone, Debug, PartialEq)]
pub struct Leg {
    pub exit: i32,
    pub verdict: Text,
    pub seconds: f64,
    pub evidence: Evidence,
    pub expect_streams: Option<Vec<&'static str>>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Record<'a> {
    pub options: &'a Options,
    pub base: &'a Text,
    pub head: &'a Text,
    /// Each carried path with its blob ID at the head.
    pub carried: &'a [(Text, Text)],
    pub cargo_target_dir: &'a Path,
    /// Each script the legs run, by file name, with the SHA-256 of its bytes.
    pub scripts: &'a [(&'a str, String)],
    /// The tool executable's SHA-256 digest.
    pub executable: Option<&'a str>,
    pub legs: &'a [(&'a str, Leg)],
    /// `None` for a proven run.
    pub reason: Option<&'a Text>,
    pub command: &'a Text,
}

fn string(text: &Text) -> Value {
    Value::String(text.clone())
}

fn integer(value: i32) -> Value {
    let digits = value.unsigned_abs().to_string();
    Value::Integer(Integer::from_digits(value < 0, &digits).expect("an i32 has at most ten digits"))
}

fn object<'a>(members: impl IntoIterator<Item = (&'a str, Value)>) -> Value {
    let mut object = Object::new();
    for (key, value) in members {
        object.insert(key, value);
    }
    Value::Object(object)
}

fn digest(data: &[u8]) -> Value {
    Value::String(Text::from(python::hexdigest(data)))
}

fn leg(leg: &Leg) -> Value {
    let seconds = python::round(&Value::Float(leg.seconds), 3).expect("a float rounds");
    let (artifact, sha256, outputs, error) = match &leg.evidence {
        Evidence::Absent => (Value::Null, Value::Null, object([]), None),
        Evidence::Unreadable(text) => (Value::Null, Value::Null, object([]), Some(string(text))),
        Evidence::Read(readings) => (
            string(&Text::from_os(readings.artifact.as_os_str())),
            digest(&readings.data),
            object(
                readings
                    .outputs
                    .iter()
                    .map(|(stream, data)| (*stream, digest(data))),
            ),
            None,
        ),
    };
    let mut entry = vec![
        ("exit", integer(leg.exit)),
        ("verdict", string(&leg.verdict)),
        ("seconds", seconds),
        ("artifact", artifact),
        ("sha256", sha256),
        ("attempt_sha256", outputs),
    ];
    entry.extend(error.map(|error| ("evidence_error", error)));
    if let Some(streams) = &leg.expect_streams {
        let streams = streams
            .iter()
            .map(|stream| Value::String(Text::from(*stream)));
        entry.push(("expect_streams", Value::Array(streams.collect())));
    }
    object(entry)
}

/// # Errors
///
/// `record` returns [`NonFinite`] if the watchdog value or any leg's `seconds` is NaN or infinite.
pub fn record(record: &Record) -> Result<String, NonFinite> {
    let options = record.options;
    let carried = record
        .carried
        .iter()
        .map(|(path, blob)| object([("path", string(path)), ("blob", string(blob))]));
    let scripts = record
        .scripts
        .iter()
        .map(|(name, digest)| (*name, Value::String(Text::from(digest.as_str()))));
    let executable = record
        .executable
        .map_or(Value::Null, |digest| Value::String(Text::from(digest)));
    let legs = record.legs.iter().map(|(name, entry)| (*name, leg(entry)));
    let result = match record.reason {
        None => Text::from("proven"),
        Some(reason) => text!("refused: ", reason),
    };
    let target_dir = Text::from_os(record.cargo_target_dir.as_os_str());
    let value = object([
        ("package", string(&options.package)),
        ("target", string(&options.target)),
        ("test", string(&options.test)),
        ("expect", string(&options.expect)),
        ("release", Value::Bool(options.release)),
        ("watchdog_seconds", Value::Float(options.watchdog)),
        ("base", string(record.base)),
        ("head", string(record.head)),
        ("carried", Value::Array(carried.collect())),
        ("cargo_target_dir", string(&target_dir)),
        ("scripts", object(scripts)),
        ("tool", object([("executable", executable)])),
        ("legs", object(legs)),
        ("result", string(&result)),
        ("command", string(record.command)),
    ]);
    let mut written = json::indented(&value)?;
    written.push('\n');
    Ok(written)
}

#[cfg(test)]
#[path = "record_tests.rs"]
mod tests;
