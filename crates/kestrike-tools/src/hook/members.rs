//! [`Members`] is the set of values a JSON document names where a path is looked up in it, and the reads
//! of the Verus inventory and the links registry that build one. Each read follows the typing rules of a
//! dynamically typed reader: an object iterates over its keys and a string over its code points, a member
//! is taken by key from an object alone, and an array or an object cannot stand in a set. A document of
//! another shape reads as `None`.

use std::collections::HashSet;

use crate::json::{self, Value};
use crate::text::Text;

use super::table::{LINKS_REGISTRY, LINKS_SCRIPTS};

/// The texts of a set of the values a document names; a number, a Boolean or `null` in the set equals no
/// path, so the set keeps none.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Members {
    texts: HashSet<Text>,
}

impl Members {
    /// `holds` holds when `path` is a member.
    pub fn holds(&self, path: &str) -> bool {
        self.texts.contains(&Text::from(path))
    }

    /// `is_empty` holds for a set with no text.
    pub fn is_empty(&self) -> bool {
        self.texts.is_empty()
    }

    /// `insert` adds `value` and returns `None` for an array or an object, which no set holds.
    fn insert(&mut self, value: &Value) -> Option<()> {
        match value {
            Value::String(text) => {
                self.texts.insert(text.clone());
            }
            Value::Array(_) | Value::Object(_) => return None,
            Value::Integer(_) | Value::Float(_) | Value::Bool(_) | Value::Null => {}
        }
        Some(())
    }
}

impl<S: AsRef<str>> FromIterator<S> for Members {
    fn from_iter<I: IntoIterator<Item = S>>(paths: I) -> Self {
        Self {
            texts: paths
                .into_iter()
                .map(|path| Text::from(path.as_ref()))
                .collect(),
        }
    }
}

/// `each` gives `visit` each value iterating `value` yields, in order, and stops at the first `None`: an
/// object's keys, an array's items, and a string's code points, each a one-code-point string. A number, a
/// Boolean and `null` cannot be iterated and read as `None`.
fn each(value: &Value, mut visit: impl FnMut(&Value) -> Option<()>) -> Option<()> {
    match value {
        Value::Object(object) => object
            .iter()
            .try_for_each(|(key, _)| visit(&Value::String(key.clone()))),
        Value::Array(items) => items.iter().try_for_each(visit),
        Value::String(text) => text.code_points().try_for_each(|code| {
            visit(&Value::String(
                Text::from_code_points([code]).expect("a code point of a text is one"),
            ))
        }),
        Value::Integer(_) | Value::Float(_) | Value::Bool(_) | Value::Null => None,
    }
}

/// `path` is the value of the key `path` of an object, and `None` for another value or a missing key.
fn path(item: &Value) -> Option<&Value> {
    match item {
        Value::Object(object) => object.get("path"),
        _ => None,
    }
}

/// `document` reads `bytes` as strict UTF-8 and then as one JSON document.
fn document(bytes: &[u8]) -> Option<Value> {
    json::parse(std::str::from_utf8(bytes).ok()?).ok()
}

/// `verus_sources` reads the Verus inventory `bytes`: the members of the value of its `sources` key, or
/// none when the key is absent. An inventory that is no object, or whose `sources` is a number, a Boolean,
/// `null`, or an array that holds an array or an object, reads as `None`.
pub(super) fn verus_sources(bytes: &[u8]) -> Option<Members> {
    let Value::Object(inventory) = document(bytes)? else {
        return None;
    };
    let mut members = Members::default();
    if let Some(sources) = inventory.get("sources") {
        each(sources, |item| members.insert(item))?;
    }
    Some(members)
}

/// `link_inputs` reads the links registry `bytes`: the registry, the scripts the check loads, the `path` of
/// each item of `models`, and the `path` of each item of each row's `anchors`. A registry that is no object
/// or lacks `models` or `rows`, a model or an anchor that is no object or lacks `path`, a row that is no
/// object, a list that cannot be iterated, and a `path` that is an array or an object read as `None`.
pub(super) fn link_inputs(bytes: &[u8]) -> Option<Members> {
    let Value::Object(registry) = document(bytes)? else {
        return None;
    };
    let mut members: Members = [LINKS_REGISTRY].into_iter().chain(LINKS_SCRIPTS).collect();
    each(registry.get("models")?, |model| {
        members.insert(path(model)?)
    })?;
    each(registry.get("rows")?, |row| {
        let Value::Object(row) = row else {
            return None;
        };
        match row.get("anchors") {
            Some(anchors) => each(anchors, |anchor| members.insert(path(anchor)?)),
            None => Some(()),
        }
    })?;
    Some(members)
}
