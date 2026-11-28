//! Python-style `len`, `int`, `round`, `repr`, `str` and truth for JSON values, `repr` for floats,
//! [`hexdigest`] for the SHA-256 hex of bytes, and [`say`], which writes one line with its control
//! characters and surrogates escaped.
//!
//! A JSON value stands for the Python value `json.loads` gives for it: an object is a `dict`, an array a
//! `list`, `null` is `None`, and an integer, a float, a boolean and a string are Python's own.

use std::io::{self, Write};
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;

use sha2::{Digest, Sha256};

use crate::classes::is_digit;
use crate::json::{Integer, MAX_INTEGER_DIGITS, Value};
use crate::text::{Text, is_space, push_backslashed, push_repr};

/// The smallest positive `f64` is 2⁻¹⁰⁷⁴, giving `MAX_ROUND_DIGITS` = ⌊1074 × log10(2)⌋.
pub const MAX_ROUND_DIGITS: usize = 323;

/// `len` counts a string's Unicode scalar values, an array's items and an object's members, and returns
/// `None` for an integer, a float, a boolean or `null`.
pub fn len(value: &Value) -> Option<usize> {
    match value {
        Value::String(text) => Some(text.len()),
        Value::Array(items) => Some(items.len()),
        Value::Object(object) => Some(object.len()),
        Value::Integer(_) | Value::Float(_) | Value::Bool(_) | Value::Null => None,
    }
}

/// `int` preserves integer values, maps `false` to 0 and `true` to 1, and truncates a finite float toward
/// zero. A string takes at most [`MAX_INTEGER_DIGITS`] ASCII digits with an optional leading sign and
/// optional single underscores between digits, after `int` strips `int_space` code points from both ends.
pub fn int(value: &Value) -> Result<Integer, String> {
    let text = match value {
        Value::Integer(integer) => return Ok(integer.clone()),
        Value::Bool(flag) => return Ok(Integer::from(u64::from(*flag))),
        Value::Float(value) if value.is_finite() => {
            let digits = format!("{:.0}", value.abs().trunc());
            return Ok(Integer::from_digits(*value < 0.0, &digits)
                .expect("a whole float prints its digits"));
        }
        Value::Float(value) => {
            return Err(format!(
                "int() takes a finite float, not {}",
                repr_float(*value)
            ));
        }
        Value::String(text) => text,
        Value::Array(_) | Value::Object(_) | Value::Null => {
            return Err("int() takes a string or a number".to_owned());
        }
    };
    let refused = || format!("invalid literal for int() with base 10: {}", text.repr());
    let trimmed = text
        .to_str()
        .ok_or_else(refused)?
        .trim_matches(|code: char| int_space(u32::from(code)));
    let (negative, body) = match trimmed.as_bytes().first() {
        Some(b'-') => (true, &trimmed[1..]),
        Some(b'+') => (false, &trimmed[1..]),
        _ => (false, trimmed),
    };
    let bytes = body.as_bytes();
    let mut end = 0;
    while end < bytes.len() {
        let joins =
            bytes[end] == b'_' && end > 0 && bytes.get(end + 1).is_some_and(u8::is_ascii_digit);
        if !bytes[end].is_ascii_digit() && !joins {
            break;
        }
        end += 1;
    }
    if bytes.get(end) == Some(&b'_') {
        return Err(refused());
    }
    let run = bytes[..end]
        .iter()
        .filter(|byte| byte.is_ascii_digit())
        .count();
    if run > MAX_INTEGER_DIGITS {
        return Err(format!(
            "a string of {run} digits passes the limit of {MAX_INTEGER_DIGITS} for integer conversion"
        ));
    }
    if end < bytes.len() || end == 0 {
        return Err(refused());
    }
    Integer::from_digits(negative, &body.replace('_', "")).ok_or_else(refused)
}

/// `int_space` holds for the code points `int()` strips: ASCII space, tab, line feed, vertical tab, form
/// feed and carriage return, and each non-ASCII code point [`is_space`] takes.
fn int_space(code: u32) -> bool {
    matches!(code, 0x9..=0xd | 0x20) || (code >= 0x80 && is_space(code))
}

/// `repr_float` follows Python's `repr` of a float: the shortest digits that read back to the value, in
/// fixed notation for decimal exponents -4 to 15 with at least one digit after the point (`53.0`, `-0.0`,
/// `0.0001`), else in scientific notation with a signed exponent of at least two digits (`1e+16`, `1e-05`,
/// `1.5e-07`); `nan`, `inf` and `-inf` for the non-finite floats.
pub fn repr_float(value: f64) -> String {
    if value.is_nan() {
        return "nan".to_owned();
    }
    if value.is_infinite() {
        return if value > 0.0 { "inf" } else { "-inf" }.to_owned();
    }
    // `{:e}` fixes how many digits the shortest form holds. Rounding the exact value to that many digits, half
    // to even, picks the even final digit when two shortest forms lie equally close. When `value.abs()` is
    // an exact power of two, the shorter spacing on its lower side can put the rounded decimal outside its
    // round-trip interval, and the `{:e}` form stands.
    let shortest = format!("{:e}", value.abs());
    let count = shortest.split_once('e').map_or(1, |(mantissa, _)| {
        mantissa.bytes().filter(u8::is_ascii_digit).count()
    });
    let scientific = Some(format!("{:.*e}", count - 1, value.abs()))
        .filter(|rounded| rounded.parse() == Ok(value.abs()))
        .unwrap_or(shortest);
    let (mantissa, exponent) = scientific
        .split_once('e')
        .expect("`{:e}` writes an exponent");
    let exponent: i32 = exponent.parse().expect("`{:e}` writes a decimal exponent");
    let digits = mantissa.replace('.', "");
    let sign = if value.is_sign_negative() { "-" } else { "" };
    if !(-4..16).contains(&exponent) {
        let (first, rest) = digits.split_at(1);
        let point = if rest.is_empty() { "" } else { "." };
        let exponent_sign = if exponent < 0 { '-' } else { '+' };
        return format!(
            "{sign}{first}{point}{rest}e{exponent_sign}{:02}",
            exponent.abs()
        );
    }
    let before = exponent + 1;
    if before <= 0 {
        let zeros = "0".repeat(before.unsigned_abs() as usize);
        return format!("{sign}0.{zeros}{digits}");
    }
    let before = before as usize;
    if before >= digits.len() {
        let zeros = "0".repeat(before - digits.len());
        return format!("{sign}{digits}{zeros}.0");
    }
    format!("{sign}{}.{}", &digits[..before], &digits[before..])
}

/// `repr` follows Python's `repr` of the value: `None`, `True` and `False`, an integer's digits, a float
/// as [`repr_float`] writes it, a string as [`Text::repr`] writes it, a list as `[a, b]` and an object as
/// `{'k': v}`, members in document order.
pub fn repr(value: &Value) -> String {
    let mut out = String::new();
    push_value_repr(value, &mut out);
    out
}

fn push_value_repr(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("None"),
        Value::Bool(true) => out.push_str("True"),
        Value::Bool(false) => out.push_str("False"),
        Value::Integer(integer) => out.push_str(&integer.to_string()),
        Value::Float(value) => out.push_str(&repr_float(*value)),
        Value::String(text) => out.push_str(&text.repr()),
        Value::Array(items) => {
            out.push('[');
            for (at, item) in items.iter().enumerate() {
                if at > 0 {
                    out.push_str(", ");
                }
                push_value_repr(item, out);
            }
            out.push(']');
        }
        Value::Object(object) => {
            out.push('{');
            for (at, (key, member)) in object.iter().enumerate() {
                if at > 0 {
                    out.push_str(", ");
                }
                out.push_str(&key.repr());
                out.push_str(": ");
                push_value_repr(member, out);
            }
            out.push('}');
        }
    }
}

/// `str_of` follows Python's `str` of the value: a string is itself, and every other value is its
/// [`repr`].
pub fn str_of(value: &Value) -> Text {
    match value {
        Value::String(text) => text.clone(),
        _ => Text::from(repr(value)),
    }
}

/// `truthy` follows Python's truth of the value: `None`, `False`, a zero integer, a zero float of either
/// sign, and an empty string, list or object are false, and every other value is true, `NaN` included.
pub fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Integer(integer) => *integer != Integer::from(0u64),
        Value::Float(value) => *value != 0.0,
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(object) => !object.is_empty(),
    }
}

/// `round` rounds the exact binary value of a finite float to `digits` decimal places, breaking ties to
/// even, as Python's `round(value, digits)` does. When `digits` exceeds [`MAX_ROUND_DIGITS`], the rounded
/// decimal converts back to the original `f64`. An integer stays as it is, a boolean becomes the integer 0
/// or 1, a non-finite float stays as it is, and a string, an array, an object or `null` gives `None`.
pub fn round(value: &Value, digits: usize) -> Option<Value> {
    match value {
        Value::Integer(integer) => Some(Value::Integer(integer.clone())),
        Value::Bool(flag) => Some(Value::Integer(Integer::from(u64::from(*flag)))),
        Value::Float(value) if value.is_finite() && digits <= MAX_ROUND_DIGITS => {
            let rounded = format!("{value:.digits$}");
            Some(Value::Float(
                rounded.parse().expect("a fixed decimal parses as an f64"),
            ))
        }
        Value::Float(value) => Some(Value::Float(*value)),
        Value::String(_) | Value::Array(_) | Value::Object(_) | Value::Null => None,
    }
}

/// `say` writes `line` and a newline. It escapes each code point of U+0000 to U+001F, U+007F to U+009F,
/// U+2028 and U+2029 as Python's `repr` escapes it, writes each surrogate as `\udXXX`, and writes every
/// other code point in UTF-8.
pub fn say(out: &mut impl Write, line: &Text) -> io::Result<()> {
    let mut said = String::new();
    for code in line.code_points() {
        match code {
            0..0x20 | 0x7f..0xa0 | 0x2028 | 0x2029 => push_repr(code, &mut said),
            _ => push_backslashed(code, &mut said),
        }
    }
    said.push('\n');
    out.write_all(said.as_bytes())
}

/// `hexdigest` writes the SHA-256 digest of `bytes` as 64 lowercase hexadecimal digits, as Python's
/// `hashlib.sha256(bytes).hexdigest()` does.
pub fn hexdigest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn returncode(status: ExitStatus) -> i32 {
    status
        .code()
        .or_else(|| status.signal().map(|signal| -signal))
        .or_else(|| status.stopped_signal().map(|signal| -signal))
        .expect("a waited child exited, or a signal ended or stopped it")
}

/// `equal` compares objects by their members in any order and arrays by their items in order, and uses
/// `Value`'s `PartialEq` implementation for scalar comparisons.
pub fn equal(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Object(left), Value::Object(right)) => {
            left.len() == right.len()
                && left.iter().all(|(key, value)| {
                    right
                        .iter()
                        .any(|(other, found)| other == key && equal(value, found))
                })
        }
        (Value::Array(left), Value::Array(right)) => {
            left.len() == right.len()
                && left
                    .iter()
                    .zip(right)
                    .all(|(left, right)| equal(left, right))
        }
        _ => left == right,
    }
}

/// The value of a decimal digit, a code point of category `Nd`. Those code points stand in runs of ten
/// from zero to nine, and adjoining runs each start at zero, so the count of digits right before it
/// gives its value modulo ten.
fn digit_value(c: char) -> Option<u32> {
    if c.is_ascii_digit() {
        return c.to_digit(10);
    }
    if !is_digit(c) {
        return None;
    }
    let mut before = 0;
    let mut code = u32::from(c);
    while let Some(previous) = code.checked_sub(1).and_then(char::from_u32) {
        if !is_digit(previous) {
            break;
        }
        before += 1;
        code -= 1;
    }
    Some(before % 10)
}

/// `text` with each non-ASCII decimal digit (category `Nd`) written as the ASCII digit of its value, the
/// form in which Python's `int` reads a string's digits.
pub fn ascii_digits(text: &str) -> String {
    text.chars()
        .map(|c| match digit_value(c) {
            Some(value) if !c.is_ascii() => char::from_digit(value, 10).unwrap_or(c),
            _ => c,
        })
        .collect()
}

/// `decimal` applies Python's `int` to `digits`, a run of Unicode decimal digits (category `Nd`).
///
/// # Errors
///
/// `decimal` accepts 1 through [`MAX_INTEGER_DIGITS`] digits, including leading zeros, and returns an
/// error for any other text.
pub fn decimal(digits: &str) -> Result<Integer, String> {
    let ascii: Option<String> = digits
        .chars()
        .map(|c| digit_value(c).and_then(|value| char::from_digit(value, 10)))
        .collect();
    let ascii = ascii
        .filter(|ascii| !ascii.is_empty())
        .ok_or_else(|| format!("no decimal digits: {}", Text::from(digits).repr()))?;
    if ascii.len() > MAX_INTEGER_DIGITS {
        return Err(format!(
            "a string of {} digits passes the limit of {MAX_INTEGER_DIGITS} for integer conversion",
            ascii.len()
        ));
    }
    Ok(Integer::from_digits(false, &ascii).expect("ASCII digits within the limit"))
}

#[cfg(test)]
#[path = "python_tests.rs"]
mod tests;
