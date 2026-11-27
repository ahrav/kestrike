//! The trace checks count states with `len` and read picked integers with `int`; both take any JSON value.

use crate::json::{Integer, Value};

/// `len` counts a string's Unicode scalar values, an array's items and an object's members, and returns
/// `None` for an integer or a boolean.
pub fn len(value: &Value) -> Option<usize> {
    match value {
        Value::String(text) => Some(text.as_str().chars().count()),
        Value::Array(items) => Some(items.len()),
        Value::Object(object) => Some(object.len()),
        Value::Integer(_) | Value::Bool(_) => None,
    }
}

/// `int` returns an integer unchanged and maps `false` to 0 and `true` to 1. It trims Unicode `White_Space`
/// from both ends of a string, then reads an optional sign and decimal digits with optional single
/// underscores between digits.
///
/// # Errors
///
/// `int` returns an error for an array, an object, or a string of any other form.
pub fn int(value: &Value) -> Result<Integer, String> {
    let text = match value {
        Value::Integer(integer) => return Ok(integer.clone()),
        Value::Bool(flag) => return Ok(Integer::from(u64::from(*flag))),
        Value::String(text) => text.as_str(),
        Value::Array(_) | Value::Object(_) => {
            return Err("int() takes a string or a number".to_owned());
        }
    };
    let refused = || format!("invalid literal for int() with base 10: {text:?}");
    let trimmed = text.trim();
    let (negative, body) = match trimmed.as_bytes().first() {
        Some(b'-') => (true, &trimmed[1..]),
        Some(b'+') => (false, &trimmed[1..]),
        _ => (false, trimmed),
    };
    if body.starts_with('_') || body.ends_with('_') || body.contains("__") {
        return Err(refused());
    }
    Integer::from_digits(negative, &body.replace('_', "")).ok_or_else(refused)
}
