//! The value tests of a plant record, each a predicate on one JSON value: Python's `str.strip` decides
//! blank text and Python's `str.isspace` set is the whitespace.

use crate::json::{Integer, Value};
use crate::text::Text;

/// The causes a miss names.
pub const CAUSES: [&str; 4] = ["environment", "workload", "ordering", "property"];
/// The longest profile name `campaign` takes, in code points.
const PROFILE_BOUND: usize = 242;

/// `natural` holds for a JSON integer of at least `least`; a boolean or a float is none.
pub(crate) fn natural(value: &Value, least: u64) -> bool {
    matches!(value, Value::Integer(number) if *number >= Integer::from(least))
}

/// `count` holds for a positive JSON integer.
pub(crate) fn count(value: &Value) -> bool {
    natural(value, 1)
}

/// `text` holds for a string that holds a code point outside the whitespace set.
pub(crate) fn text(value: &Value) -> bool {
    matches!(value, Value::String(text) if !text.strip().is_empty())
}

/// `printable` holds when every code point of `text` lies from U+0020 to U+007E.
pub(crate) fn printable(text: &Text) -> bool {
    text.code_points().all(|code| (0x20..=0x7e).contains(&code))
}

/// `strings` holds for a list of [`text`] items with no item twice.
pub(crate) fn strings(value: &Value) -> bool {
    let Value::Array(items) = value else {
        return false;
    };
    items.iter().all(text)
        && items
            .iter()
            .enumerate()
            .all(|(at, item)| !items[..at].contains(item))
}

/// `profile_name` holds for text `campaign` can take as a profile name: printable ASCII without a comma or
/// a slash, at most [`PROFILE_BOUND`] code points, and neither `.` nor `..`.
pub(crate) fn profile_name(value: &Value) -> bool {
    let Value::String(name) = value else {
        return false;
    };
    text(value)
        && name.len() <= PROFILE_BOUND
        && printable(name)
        && !name
            .code_points()
            .any(|code| code == u32::from(b',') || code == u32::from(b'/'))
        && *name != "."
        && *name != ".."
}

/// `argument` holds for a string a process takes as one argument: free of NUL and of surrogates, so it
/// encodes as UTF-8, as a file name, and prints.
pub(crate) fn argument(value: &Value) -> bool {
    matches!(value, Value::String(text) if text.to_str().is_some_and(|text| !text.contains('\0')))
}

/// `keys` holds when the object's keys, sorted, are `expected`, sorted.
pub(crate) fn keys(object: &crate::json::Object, expected: &[&str]) -> bool {
    let mut found: Vec<&Text> = object.iter().map(|(name, _)| name).collect();
    found.sort();
    let mut wanted: Vec<&str> = expected.to_vec();
    wanted.sort_unstable();
    found.len() == wanted.len() && found.iter().zip(&wanted).all(|(name, want)| *name == want)
}

/// `cause` holds for an object of exactly `cause`, one of [`CAUSES`], and `evidence`, [`text`].
pub(crate) fn cause(value: &Value) -> bool {
    let Value::Object(object) = value else {
        return false;
    };
    keys(object, &["cause", "evidence"])
        && matches!(object.get("cause"), Some(Value::String(named)) if CAUSES.iter().any(|cause| named == cause))
        && object.get("evidence").is_some_and(text)
}
