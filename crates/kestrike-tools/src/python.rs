use crate::json::{Integer, Value};

pub fn len(value: &Value) -> Option<usize> {
    match value {
        Value::String(text) => Some(text.as_str().chars().count()),
        Value::Array(items) => Some(items.len()),
        Value::Object(object) => Some(object.len()),
        Value::Integer(_) | Value::Bool(_) => None,
    }
}

/// `int` preserves integer values and maps `false` to 0 and `true` to 1. A string takes ASCII digits
/// with an optional leading sign and optional single underscores between digits. `int` trims
/// `space` characters from both ends before parsing the sign.
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
    let trimmed = text.trim_matches(space);
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

/// `space` matches Python's `str.isspace()` for a single character.
fn space(character: char) -> bool {
    matches!(
        character,
        '\t'..='\r'
            | '\u{1c}'..=' '
            | '\u{85}'
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
    )
}
