use std::borrow::Cow;
use std::fmt;

use crate::json::{Integer, Object, Value};
use crate::python::repr;
use crate::text::Text;

pub(super) fn kind(value: &Value) -> &'static str {
    match value {
        Value::Object(_) => "an object",
        Value::Array(_) => "an array",
        Value::String(_) => "a string",
        Value::Integer(_) => "an integer",
        Value::Float(_) => "a float",
        Value::Bool(_) => "a boolean",
        Value::Null => "null",
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Fault {
    Keyed(&'static str),
    Iterated(&'static str),
    Hashed(&'static str),
    Counted(&'static str),
    Text(&'static str),
    Absent(String),
    Overflow,
}

impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Keyed(kind) => write!(f, "{kind} stands where an object is read by key"),
            Self::Iterated(kind) => write!(f, "{kind} stands where items are read"),
            Self::Hashed(kind) => write!(f, "{kind} stands where a key or a set member is read"),
            Self::Counted(kind) => write!(f, "{kind} stands where items are counted"),
            Self::Text(kind) => write!(f, "{kind} stands where a string is read"),
            Self::Absent(key) => write!(f, "no role {key} stands in the profile's roles"),
            Self::Overflow => {
                write!(f, "an integer too large for a float stands where a finite number is read")
            }
        }
    }
}

pub(super) enum Member {
    Text(Text),
    Other,
}

pub(super) fn members(value: &Value) -> Result<Vec<Member>, Fault> {
    match value {
        Value::Object(object) => Ok(object
            .iter()
            .map(|(key, _)| Member::Text(key.clone()))
            .collect()),
        Value::Array(items) => items
            .iter()
            .map(|item| match item {
                Value::String(text) => Ok(Member::Text(text.clone())),
                Value::Array(_) | Value::Object(_) => Err(Fault::Hashed(kind(item))),
                _ => Ok(Member::Other),
            })
            .collect(),
        Value::String(text) => Ok(code_point_texts(text).map(Member::Text).collect()),
        _ => Err(Fault::Iterated(kind(value))),
    }
}

fn code_point_texts(text: &Text) -> impl Iterator<Item = Text> + '_ {
    text.code_points().map(|code| {
        Text::from_code_points([code]).expect("a code point of a text is at most U+10FFFF")
    })
}

pub(super) fn holds_all(members: &[Member], names: &[&str]) -> bool {
    names
        .iter()
        .all(|name| members.iter().any(|member| matches!(member, Member::Text(text) if text == name)))
}

pub(super) fn within(members: &[Member], names: &[&str]) -> bool {
    members.iter().all(|member| match member {
        Member::Text(text) => names.iter().any(|name| text == name),
        Member::Other => false,
    })
}

pub(super) fn object(value: &Value) -> Result<&Object, Fault> {
    match value {
        Value::Object(object) => Ok(object),
        _ => Err(Fault::Keyed(kind(value))),
    }
}

pub(super) fn get<'a>(value: &'a Value, key: &str) -> Result<Option<&'a Value>, Fault> {
    object(value).map(|object| object.get(key))
}

pub(super) fn index_by<'a>(object: &'a Object, key: &Value) -> Result<&'a Value, Fault> {
    match key {
        Value::String(text) => object
            .get_text(text)
            .ok_or_else(|| Fault::Absent(text.repr())),
        Value::Array(_) | Value::Object(_) => Err(Fault::Hashed(kind(key))),
        _ => Err(Fault::Absent(repr(key))),
    }
}

pub(super) fn contains(value: &Value, item: &str) -> Result<bool, Fault> {
    match value {
        Value::Object(object) => Ok(object.get(item).is_some()),
        Value::Array(items) => Ok(items
            .iter()
            .any(|entry| matches!(entry, Value::String(text) if text == &item))),
        Value::String(text) => Ok(substring(text, item)),
        _ => Err(Fault::Iterated(kind(value))),
    }
}

fn substring(text: &Text, item: &str) -> bool {
    let hay: Vec<u32> = text.code_points().collect();
    let needle: Vec<u32> = item.chars().map(u32::from).collect();
    needle.is_empty() || hay.windows(needle.len()).any(|window| window == needle.as_slice())
}

pub(super) fn items(value: &Value) -> Result<Vec<Cow<'_, Value>>, Fault> {
    match value {
        Value::Object(object) => Ok(object
            .iter()
            .map(|(key, _)| Cow::Owned(Value::String(key.clone())))
            .collect()),
        Value::Array(items) => Ok(items.iter().map(Cow::Borrowed).collect()),
        Value::String(text) => Ok(code_point_texts(text)
            .map(|text| Cow::Owned(Value::String(text)))
            .collect()),
        _ => Err(Fault::Iterated(kind(value))),
    }
}

pub(super) fn count(value: &Value) -> Result<usize, Fault> {
    match value {
        Value::Object(object) => Ok(object.len()),
        Value::Array(items) => Ok(items.len()),
        Value::String(text) => Ok(text.len()),
        _ => Err(Fault::Counted(kind(value))),
    }
}

pub(super) fn is_integer(value: &Value) -> bool {
    matches!(value, Value::Integer(_) | Value::Bool(_))
}

pub(super) fn is_real(value: &Value) -> bool {
    matches!(value, Value::Integer(_) | Value::Float(_))
}

pub(super) fn finite(value: &Value) -> Result<bool, Fault> {
    match value {
        Value::Integer(integer) => integer
            .to_string()
            .parse::<f64>()
            .ok()
            .filter(|float| float.is_finite())
            .map(|_| true)
            .ok_or(Fault::Overflow),
        Value::Float(float) => Ok(float.is_finite()),
        Value::Bool(_) => Ok(true),
        _ => Ok(false),
    }
}

pub(super) fn compare(value: &Value, bound: u64) -> Option<std::cmp::Ordering> {
    match value {
        Value::Integer(integer) => Some(integer.cmp(&Integer::from(bound))),
        Value::Float(float) => float.partial_cmp(&(bound as f64)),
        Value::Bool(flag) => Some(u64::from(*flag).cmp(&bound)),
        _ => None,
    }
}

pub(super) fn equals(value: &Value, bound: u64) -> bool {
    compare(value, bound) == Some(std::cmp::Ordering::Equal)
}

pub(super) fn distinct(values: &[Option<&Value>]) -> Result<usize, Fault> {
    let mut kept: Vec<&Value> = Vec::new();
    for value in values {
        let value = value.unwrap_or(&Value::Null);
        if matches!(value, Value::Array(_) | Value::Object(_)) {
            return Err(Fault::Hashed(kind(value)));
        }
        if !kept.iter().any(|other| same_key(other, value)) {
            kept.push(value);
        }
    }
    Ok(kept.len())
}

enum Number<'a> {
    Integer(Cow<'a, Integer>),
    Float(f64),
}

fn number(value: &Value) -> Option<Number<'_>> {
    match value {
        Value::Integer(integer) => Some(Number::Integer(Cow::Borrowed(integer))),
        Value::Bool(flag) => Some(Number::Integer(Cow::Owned(Integer::from(u64::from(*flag))))),
        Value::Float(float) => Some(Number::Float(*float)),
        _ => None,
    }
}

fn same_key(left: &Value, right: &Value) -> bool {
    match (number(left), number(right)) {
        (Some(Number::Integer(left)), Some(Number::Integer(right))) => left == right,
        (Some(Number::Float(left)), Some(Number::Float(right))) => {
            left == right || (left.is_nan() && right.is_nan())
        }
        (Some(Number::Integer(integer)), Some(Number::Float(float)))
        | (Some(Number::Float(float)), Some(Number::Integer(integer))) => {
            whole(float).is_some_and(|whole| whole == *integer)
        }
        (None, None) => left == right,
        _ => false,
    }
}

fn whole(float: f64) -> Option<Integer> {
    if !float.is_finite() || float.fract() != 0.0 {
        return None;
    }
    Integer::from_digits(float < 0.0, &format!("{:.0}", float.abs()))
}
