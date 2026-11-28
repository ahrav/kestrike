//! The members of a value a schema check has passed, read by the type that check gave them. Each
//! accessor panics on a value of another type, which marks a caller that skipped the check.

use super::number::Number;
use crate::json::{Object, Value};
use crate::text::Text;

/// The member `key` of `object`, which the check made present.
pub(super) fn get<'a>(object: &'a Object, key: &str) -> &'a Value {
    object
        .get(key)
        .unwrap_or_else(|| panic!("the check made {key} a member"))
}

pub(super) fn text(value: &Value) -> &Text {
    match value {
        Value::String(text) => text,
        _ => panic!("the check made {value:?} a string"),
    }
}

pub(super) fn object(value: &Value) -> &Object {
    match value {
        Value::Object(object) => object,
        _ => panic!("the check made {value:?} an object"),
    }
}

pub(super) fn list(value: &Value) -> &[Value] {
    match value {
        Value::Array(items) => items,
        _ => panic!("the check made {value:?} a list"),
    }
}

/// The number a time or a bound holds, which the check made a finite number.
pub(super) fn number(value: &Value) -> Number {
    Number::of(value).unwrap_or_else(|| panic!("the check made {value:?} a finite number"))
}

/// The member `key` of `object` as a text.
pub(super) fn text_at<'a>(object: &'a Object, key: &str) -> &'a Text {
    text(get(object, key))
}

/// The member `key` of `object` as an object.
pub(super) fn object_at<'a>(object: &'a Object, key: &str) -> &'a Object {
    self::object(get(object, key))
}

/// The member `key` of `object` as a number.
pub(super) fn number_at(object: &Object, key: &str) -> Number {
    number(get(object, key))
}

/// The member `key` of `object`, whatever code points the key holds.
pub(super) fn member<'a>(object: &'a Object, key: &Text) -> Option<&'a Value> {
    object
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value)
}
