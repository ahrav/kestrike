//! The layout's schemas and the walk that checks a decoded value against one, refusing at the first value
//! off its shape with the file, the keys on the way and Python's `repr` of the value.

use std::collections::{BTreeMap, BTreeSet};

use super::constants::{ATTEMPTS_MAX, WRITTEN_GUARDRAILS};
use super::refusal::{Refusal, said};
use crate::json::{Integer, Object, Value};
use crate::python::repr;
use crate::text::Text;

/// 2^53, the largest magnitude of a JSON number the layout takes.
const MOST: u64 = 1 << 53;

/// `Schema` states the shape of a decoded value.
#[derive(Clone, Copy, Debug)]
pub enum Schema {
    /// One scalar check; with `true`, null also passes, as a trailing `?` marks it.
    Scalar(Scalar, bool),
    /// An object with exactly these keys, each value of its schema. The keys are distinct.
    Object(&'static [(&'static str, Schema)]),
    /// One of these objects: the first whose keys are the value's keys, else the first. The list is not
    /// empty.
    OneOf(&'static [&'static [(&'static str, Schema)]]),
    /// A list whose every item has this schema.
    List(&'static Schema),
    /// A string that is one of these.
    Member(&'static [&'static str]),
    Each(Each),
}

impl Schema {
    pub const fn scalar(scalar: Scalar) -> Self {
        Self::Scalar(scalar, false)
    }

    pub const fn nullable(scalar: Scalar) -> Self {
        Self::Scalar(scalar, true)
    }
}

/// `Each` is a map whose keys are names of the kind `keys`: all of them with `exact`, else a subset; each
/// value has the schema `value`.
#[derive(Clone, Copy, Debug)]
pub struct Each {
    pub keys: &'static str,
    pub value: &'static Schema,
    pub exact: bool,
}

/// The scalar checks of the layout, each named in a refusal by [`Scalar::name`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scalar {
    /// A string with a code point outside Python's whitespace and no surrogate.
    Name,
    /// A number of at most 2^53 in magnitude.
    Time,
    Positive,
    Nonnegative,
    /// An integer from 0 to 2^53.
    Count,
    /// A count from 1 to 2^32 - 1.
    Generation,
    /// A count of at most [`ATTEMPTS_MAX`].
    Attempts,
    /// A count of at most twice [`ATTEMPTS_MAX`].
    Epoch,
    /// 64 lowercase hexadecimal digits.
    Digest,
    /// 40 lowercase hexadecimal digits.
    Commit,
    /// A calendar date `YYYY-MM-DD`.
    Date,
    /// `[A-Za-z0-9][A-Za-z0-9._-]*` other than `receipts`.
    FileName,
    /// One of GD-2's guardrails.
    Guardrail,
    /// One of the package's hosts.
    Host,
    /// One of the package's shards.
    Shard,
    /// One of the package's witness keys.
    Key,
}

impl Scalar {
    pub fn name(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Time => "time",
            Self::Positive => "positive",
            Self::Nonnegative => "nonnegative",
            Self::Count => "count",
            Self::Generation => "generation",
            Self::Attempts => "attempts",
            Self::Epoch => "epoch",
            Self::Digest => "digest",
            Self::Commit => "commit",
            Self::Date => "date",
            Self::FileName => "file-name",
            Self::Guardrail => "guardrail",
            Self::Host => "host",
            Self::Shard => "shard",
            Self::Key => "key",
        }
    }

    /// Whether `value` passes the check. A member check reads `names` only for a string.
    pub fn holds(self, value: &Value, names: &Names) -> bool {
        let count = |least: u64, most: u64| {
            matches!(value, Value::Integer(integer)
                if !negative(integer) && magnitude(integer).is_some_and(|n| least <= n && n <= most))
        };
        match self {
            Self::Name => matches!(value, Value::String(text)
                if !text.strip().is_empty() && encodable(text)),
            Self::Time => finite(value),
            Self::Positive => finite(value) && sign(value) > 0,
            Self::Nonnegative => finite(value) && sign(value) >= 0,
            Self::Count => count(0, MOST),
            Self::Generation => count(1, (1 << 32) - 1),
            Self::Attempts => count(0, ATTEMPTS_MAX),
            Self::Epoch => count(0, 2 * ATTEMPTS_MAX),
            Self::Digest => string(value).is_some_and(|text| hexadecimal(text, 64)),
            Self::Commit => string(value).is_some_and(|text| hexadecimal(text, 40)),
            Self::Date => calendar(value),
            Self::FileName => {
                string(value).is_some_and(|text| file_name(text) && *text != "receipts")
            }
            Self::Guardrail => {
                string(value).is_some_and(|text| WRITTEN_GUARDRAILS.iter().any(|g| text == g))
            }
            Self::Host => member_of("host", value, names),
            Self::Shard => member_of("shard", value, names),
            Self::Key => member_of("key", value, names),
        }
    }
}

/// `Names` holds the package's names of each kind (`host`, `shard`, `key` and the kinds an [`Each`]
/// names) that a file is read against.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Names(BTreeMap<&'static str, BTreeSet<Text>>);

impl Names {
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the names of `kind`, replacing any earlier set.
    pub fn insert(&mut self, kind: &'static str, names: BTreeSet<Text>) {
        self.0.insert(kind, names);
    }

    pub fn get(&self, kind: &str) -> Option<&BTreeSet<Text>> {
        self.0.get(kind)
    }

    fn of(&self, kind: &str) -> &BTreeSet<Text> {
        self.get(kind)
            .unwrap_or_else(|| panic!("the caller of conform supplies the names of kind {kind}"))
    }
}

fn string(value: &Value) -> Option<&Text> {
    match value {
        Value::String(text) => Some(text),
        _ => None,
    }
}

fn negative(integer: &Integer) -> bool {
    integer.to_string().starts_with('-')
}

/// The magnitude of `integer` when it fits a `u64`.
fn magnitude(integer: &Integer) -> Option<u64> {
    integer.to_string().trim_start_matches('-').parse().ok()
}

/// The sign of a number of [`finite`]: -1, 0 or 1, with -0.0 as 0.
fn sign(value: &Value) -> i8 {
    match value {
        Value::Integer(integer) if negative(integer) => -1,
        Value::Integer(integer) if magnitude(integer) == Some(0) => 0,
        Value::Float(float) if *float < 0.0 => -1,
        Value::Float(float) if *float == 0.0 => 0,
        _ => 1,
    }
}

/// `finite` holds for a JSON number of at most 2^53 in magnitude, so a NaN, an infinity and a boolean fail.
pub fn finite(value: &Value) -> bool {
    match value {
        Value::Integer(integer) => magnitude(integer).is_some_and(|n| n <= MOST),
        Value::Float(float) => float.abs() <= 9_007_199_254_740_992.0,
        _ => false,
    }
}

/// `encodable` holds for text with no surrogate, which UTF-8 encodes.
pub fn encodable(text: &Text) -> bool {
    text.to_str().is_some()
}

/// `calendar` holds for a string `YYYY-MM-DD` of ASCII digits that names a day of the proleptic
/// Gregorian calendar from year 1 to 9999.
pub fn calendar(value: &Value) -> bool {
    let Some(text) = string(value).and_then(Text::to_str) else {
        return false;
    };
    let bytes = text.as_bytes();
    let shaped = bytes.len() == 10
        && bytes.iter().enumerate().all(|(at, byte)| match at {
            4 | 7 => *byte == b'-',
            _ => byte.is_ascii_digit(),
        });
    if !shaped {
        return false;
    }
    let number = |range: std::ops::Range<usize>| text[range].parse::<u32>().expect("ASCII digits");
    let (year, month, day) = (number(0..4), number(5..7), number(8..10));
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    year >= 1 && (1..=days).contains(&day)
}

fn hexadecimal(text: &Text, length: usize) -> bool {
    text.len() == length
        && text
            .code_points()
            .all(|code| matches!(code, 0x30..=0x39 | 0x61..=0x66))
}

/// `[A-Za-z0-9][A-Za-z0-9._-]*`.
fn file_name(text: &Text) -> bool {
    let alphanumeric =
        |code: u32| u8::try_from(code).is_ok_and(|byte| byte.is_ascii_alphanumeric());
    let mut codes = text.code_points();
    codes.next().is_some_and(alphanumeric)
        && codes.all(|code| alphanumeric(code) || matches!(code, 0x2e | 0x5f | 0x2d))
}

/// Whether `value` is a string among the names of `kind`.
fn member_of(kind: &str, value: &Value, names: &Names) -> bool {
    string(value).is_some_and(|text| names.of(kind).contains(text))
}

/// `conform` refuses `value` unless it has the shape `schema` states; `what` names it in a refusal.
///
/// # Errors
///
/// `<what> <key> ... <reason>`, with the keys from the outermost to the refused value, `[i]` for a list
/// index, and the reason of the first value off its shape: `is no <scalar> of the layout: <repr>`,
/// `is no object`, `holds the keys <sorted keys>, not <sorted keys>`, `is no list`,
/// `names <sorted keys>, not exactly the <kind>s <sorted names>` (`only` for a subset) or
/// `<repr> is none of <sorted members>`.
///
/// # Panics
///
/// When `names` lacks a kind that an [`Each`] of the schema reaches, or that a member check reaches with
/// a string: the caller supplies every kind its schema reads.
pub fn conform(value: &Value, schema: &Schema, what: &Text, names: &Names) -> Result<(), Refusal> {
    walk(value, schema, what, names, &mut Vec::new())
}

fn walk(
    value: &Value,
    schema: &Schema,
    what: &Text,
    names: &Names,
    path: &mut Vec<Text>,
) -> Result<(), Refusal> {
    let refuse = |path: &[Text], reason: Text| {
        let mut parts = vec![what.clone()];
        parts.extend_from_slice(path);
        parts.push(reason);
        Err(Refusal::new(Text::join(" ", &parts)))
    };
    match *schema {
        Schema::Scalar(scalar, nullable) => {
            if !(nullable && *value == Value::Null) && !scalar.holds(value, names) {
                let reason = said!("is no ", scalar.name(), " of the layout: ", repr(value));
                return refuse(path, reason);
            }
        }
        Schema::Object(fields) => {
            let Value::Object(object) = value else {
                return refuse(path, said!("is no object"));
            };
            if !same_keys(object, fields) {
                let reason = said!(
                    "holds the keys ",
                    sorted(object.iter().map(|(key, _)| key.clone())),
                    ", not ",
                    sorted(fields.iter().map(|(key, _)| Text::from(*key))),
                );
                return refuse(path, reason);
            }
            for (key, field) in fields {
                let member = object.get(key).expect("the keys are the schema's");
                path.push(Text::from(*key));
                walk(member, field, what, names, path)?;
                path.pop();
            }
        }
        Schema::OneOf(options) => {
            let chosen = options
                .iter()
                .find(|fields| matches!(value, Value::Object(object) if same_keys(object, fields)))
                .unwrap_or(&options[0]);
            walk(value, &Schema::Object(chosen), what, names, path)?;
        }
        Schema::List(item) => {
            let Value::Array(items) = value else {
                return refuse(path, said!("is no list"));
            };
            for (at, entry) in items.iter().enumerate() {
                path.push(said!("[", at.to_string(), "]"));
                walk(entry, item, what, names, path)?;
                path.pop();
            }
        }
        Schema::Each(each) => {
            let Value::Object(object) = value else {
                return refuse(path, said!("is no object"));
            };
            let kinds = names.of(each.keys);
            let keys: BTreeSet<&Text> = object.iter().map(|(key, _)| key).collect();
            let fits = if each.exact {
                keys.len() == kinds.len() && keys.iter().all(|key| kinds.contains(*key))
            } else {
                keys.iter().all(|key| kinds.contains(*key))
            };
            if !fits {
                let reason = said!(
                    "names ",
                    sorted(keys.into_iter().cloned()),
                    ", not ",
                    if each.exact { "exactly" } else { "only" },
                    " the ",
                    each.keys,
                    "s ",
                    sorted(kinds.iter().cloned()),
                );
                return refuse(path, reason);
            }
            for (key, member) in object.iter() {
                path.push(key.clone());
                walk(member, each.value, what, names, path)?;
                path.pop();
            }
        }
        Schema::Member(members) => {
            if !string(value).is_some_and(|text| members.iter().any(|member| text == member)) {
                let reason = said!(
                    repr(value),
                    " is none of ",
                    sorted(members.iter().map(|member| Text::from(*member))),
                );
                return refuse(path, reason);
            }
        }
    }
    Ok(())
}

fn same_keys(object: &Object, fields: &[(&str, Schema)]) -> bool {
    object.len() == fields.len() && fields.iter().all(|(key, _)| object.get(key).is_some())
}

/// Python's `repr` of the sorted list of `items`.
pub(crate) fn sorted(items: impl IntoIterator<Item = Text>) -> String {
    let mut items: Vec<Text> = items.into_iter().collect();
    items.sort();
    let shown: Vec<String> = items.iter().map(Text::repr).collect();
    format!("[{}]", shown.join(", "))
}

#[cfg(test)]
#[path = "schema_tests.rs"]
mod tests;
