//! A mark's bytes: the value's JSON with sorted keys and one space of indent per level, then a newline,
//! as Python's `json.dumps(value, indent=1, sort_keys=True)` writes it.

use super::words::sentence;
use crate::gameday::{Refusal, need};
use crate::json::{Value, indented_by};
use crate::text::Text;

/// `encoded` is the bytes a mark of `value` holds, at most `limit` of them; `what` names the mark.
///
/// # Errors
///
/// `<what> cannot be written: the float <repr> has no JSON form` for a non-finite float, and
/// `<what> would hold <n> bytes, more than the judge reads (<limit>)` past `limit`.
pub fn encoded(value: &Value, what: &Text, limit: u64) -> Result<Vec<u8>, Refusal> {
    let mut data = indented_by(value, 1)
        .map_err(|error| Refusal::new(sentence!(what, " cannot be written: ", error.to_string())))?
        .into_bytes();
    data.push(b'\n');
    let length = u64::try_from(data.len()).expect("a length fits a u64");
    need(length <= limit, || {
        sentence!(
            what,
            " would hold ",
            data.len().to_string(),
            " bytes, more than the judge reads (",
            limit.to_string(),
            ")"
        )
    })?;
    Ok(data)
}
