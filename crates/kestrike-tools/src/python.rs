//! Python-style `len`, `int` and `round` for JSON values, `repr` for floats, [`hexdigest`] for the SHA-256
//! hex of bytes, and [`say`], which writes one line with its control characters and surrogates escaped.

use std::io::{self, Write};

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

/// `repr` returns Python's `repr` of the object `json.loads` gives for `value`, with object members in
/// document order.
pub fn repr(value: &Value) -> String {
    match value {
        Value::Object(object) => {
            let members: Vec<String> = object
                .iter()
                .map(|(key, value)| format!("{}: {}", key.repr(), repr(value)))
                .collect();
            format!("{{{}}}", members.join(", "))
        }
        Value::Array(items) => {
            let items: Vec<String> = items.iter().map(repr).collect();
            format!("[{}]", items.join(", "))
        }
        Value::String(text) => text.repr(),
        Value::Integer(integer) => integer.to_string(),
        Value::Float(value) => repr_float(*value),
        Value::Bool(true) => "True".to_owned(),
        Value::Bool(false) => "False".to_owned(),
        Value::Null => "None".to_owned(),
    }
}

/// For strings, `str_of` returns the text with each surrogate escaped as `\udXXX`; for other values, it
/// returns [`repr`].
pub fn str_of(value: &Value) -> String {
    match value {
        Value::String(text) => text.to_string(),
        _ => repr(value),
    }
}

fn integral(value: &Value) -> Option<Integer> {
    match value {
        Value::Integer(integer) => Some(integer.clone()),
        Value::Bool(flag) => Some(Integer::from(u64::from(*flag))),
        Value::Float(value) if value.is_finite() && value.fract() == 0.0 => {
            let digits = format!("{:.0}", value.abs());
            Integer::from_digits(*value < 0.0, &digits)
        }
        _ => None,
    }
}

/// `equal` is Python's `==` over `json.loads` objects. Objects hold the same keys with equal values in
/// any order, arrays equal items in order, and numbers and booleans compare by exact value, `true` being
/// 1. `equal` returns `false` when either operand is NaN.
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
        (Value::String(left), Value::String(right)) => left == right,
        (Value::Null, Value::Null) => true,
        (Value::Float(left), Value::Float(right)) => left == right,
        (Value::Integer(_) | Value::Bool(_) | Value::Float(_), _) => {
            matches!(right, Value::Integer(_) | Value::Bool(_) | Value::Float(_))
                && integral(left).is_some_and(|left| integral(right) == Some(left))
        }
        _ => false,
    }
}

/// `members` follows Python's iteration: an array yields its items, an object its keys, and a string one
/// string per code point. A number, a boolean and `null` give `None`.
pub fn members(value: &Value) -> Option<Vec<Value>> {
    match value {
        Value::Array(items) => Some(items.clone()),
        Value::Object(object) => Some(
            object
                .iter()
                .map(|(key, _)| Value::String(key.clone()))
                .collect(),
        ),
        Value::String(text) => Some(
            text.code_points()
                .map(|code| {
                    Value::String(Text::from_code_points([code]).expect("a code point of a text"))
                })
                .collect(),
        ),
        Value::Integer(_) | Value::Float(_) | Value::Bool(_) | Value::Null => None,
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
