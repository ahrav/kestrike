//! Python-style `len` and `int` for JSON values and `repr` for floats.

use std::io::{self, Write};

use crate::json::{Integer, MAX_INTEGER_DIGITS, Value};
use crate::text::{Text, is_space, push_backslashed, push_repr};

/// The smallest positive `f64` is 2⁻¹⁰⁷⁴, giving `MAX_ROUND_DIGITS` = ⌊1074 × log10(2)⌋.
pub const MAX_ROUND_DIGITS: usize = 323;

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
    let codes: Vec<u32> = text.code_points().collect();
    let start = codes
        .iter()
        .position(|&code| !int_space(code))
        .unwrap_or(codes.len());
    let end = codes
        .iter()
        .rposition(|&code| !int_space(code))
        .map_or(start, |at| at + 1);
    let trimmed = Text::from_code_points(codes[start..end].iter().copied())
        .expect("the code points of a text are at most U+10FFFF");
    let trimmed = trimmed.to_str().ok_or_else(refused)?;
    let (negative, body) = match trimmed.as_bytes().first() {
        Some(b'-') => (true, &trimmed[1..]),
        Some(b'+') => (false, &trimmed[1..]),
        _ => (false, trimmed),
    };
    if body.starts_with('_') || body.ends_with('_') || body.contains("__") {
        return Err(refused());
    }
    let digits = body.replace('_', "");
    if digits.len() > MAX_INTEGER_DIGITS {
        return Err(format!(
            "a string of {} digits passes the limit of {MAX_INTEGER_DIGITS} for integer conversion",
            digits.len()
        ));
    }
    Integer::from_digits(negative, &digits).ok_or_else(refused)
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
/// decimal converts back to the original `f64`.
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
