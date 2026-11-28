//! The forms a value of the controller's files takes: an instance ID, an ISO time, a plain text, and
//! the end of an abort mark's detail. Each check refuses with a sentence that names its value by
//! `what`.

use super::calendar::posix_seconds;
use super::constants::{INSTANCE, ISO, STEPS_PREFIX};
use super::words::sentence;
use crate::gameday::Refusal;
use crate::json::Value;
use crate::python::{hexdigest, repr};
use crate::text::Text;

/// `instance_id` is the text of `value` when it is an instance ID.
///
/// # Errors
///
/// `<what> is no instance ID: <repr>` for any other value.
pub fn instance_id(value: &Value, what: &Text) -> Result<Text, Refusal> {
    match value {
        Value::String(text) if matches(&INSTANCE, text) => Ok(text.clone()),
        _ => Err(Refusal::new(sentence!(
            what,
            " is no instance ID: ",
            repr(value)
        ))),
    }
}

/// `iso_time` is the POSIX seconds of an ISO time `YYYY-MM-DDTHH:MM:SSZ` with seconds 00 to 59.
///
/// # Errors
///
/// `<what> <repr> is no time YYYY-MM-DDTHH:MM:SSZ` for a value off that form, then
/// `<what> <repr> is no calendar time` for a second the calendar lacks.
pub fn iso_time(value: &Value, what: &Text) -> Result<i64, Refusal> {
    let text = match value {
        Value::String(text) if matches(&ISO, text) => {
            text.to_str().expect("a matched time is ASCII")
        }
        _ => {
            return Err(Refusal::new(sentence!(
                what,
                " ",
                repr(value),
                " is no time YYYY-MM-DDTHH:MM:SSZ"
            )));
        }
    };
    posix_seconds(&text[..19])
        .ok_or_else(|| Refusal::new(sentence!(what, " ", repr(value), " is no calendar time")))
}

/// `plain` holds for a text with no control character (below U+0020, or U+007F) and a UTF-8 form,
/// which a text with a lone surrogate lacks.
pub fn plain(text: &Text) -> bool {
    text.to_str().is_some() && !text.code_points().any(|code| code < 0x20 || code == 0x7f)
}

/// `steps_tail` is the end of an abort mark's detail for the restoration steps `steps`: the words
/// `; restoration steps sha256 ` and the SHA-256 of the UTF-8 bytes of `steps`.
pub fn steps_tail(steps: &str) -> String {
    format!("{STEPS_PREFIX}{}", hexdigest(steps.as_bytes()))
}

/// Whether `pattern` matches the whole of `text`, which holds no surrogate.
pub(super) fn matches(pattern: &regex::Regex, text: &Text) -> bool {
    text.to_str().is_some_and(|text| pattern.is_match(text))
}
