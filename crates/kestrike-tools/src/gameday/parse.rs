//! A file's bytes as the judge reads them: strict UTF-8, then one strict JSON value for a `.json` name and
//! one value per line for a `.jsonl` name.

use super::refusal::{Refusal, need, said};
use crate::json::{Value, parse_strict};
use crate::text::Text;

/// `decode` reads `text` as one strict JSON value: distinct keys in each object and every fractional
/// number the shortest form of a finite double.
///
/// # Errors
///
/// `<what> is not strict JSON: <reason>`, with the reader's reason for the first refusal in document
/// order.
pub fn decode(text: &str, what: &Text) -> Result<Value, Refusal> {
    parse_strict(text)
        .map_err(|error| Refusal::new(said!(what, " is not strict JSON: ", error.to_string())))
}

/// `parsed` reads a file named `rel`. A name ending in `.jsonl` gives an array of its lines, each decoded
/// under `<rel> line <n>` from 1; empty bytes give an empty array. Any other name gives one value.
///
/// # Errors
///
/// `<rel> is not UTF-8: <reason>` for bytes that are no strict UTF-8; for a `.jsonl` name,
/// `<rel> ends in a line with no newline: it may be truncated`, and a blank line refused as JSON; then
/// each refusal of [`decode`].
pub fn parsed(data: &[u8], rel: &Text) -> Result<Value, Refusal> {
    let text = std::str::from_utf8(data)
        .map_err(|error| Refusal::new(said!(rel, " is not UTF-8: ", error.to_string())))?;
    if !rel.as_bytes().ends_with(b".jsonl") {
        return decode(text, rel);
    }
    need(text.is_empty() || text.ends_with('\n'), || {
        said!(rel, " ends in a line with no newline: it may be truncated")
    })?;
    text.split_terminator('\n')
        .enumerate()
        .map(|(at, line)| decode(line, &said!(rel, " line ", (at + 1).to_string())))
        .collect::<Result<Vec<_>, _>>()
        .map(Value::Array)
}

#[cfg(test)]
#[path = "parse_tests.rs"]
mod tests;
