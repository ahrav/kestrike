//! Inputs of the module's tests: the tree's top, the held fixture, and JSON values changed at a path.

use std::path::PathBuf;

use crate::json::{Object, Value, parse_strict};
use crate::text::Text;

/// The checkout's top level.
pub(crate) fn tree() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the checkout's top resolves")
}

pub(crate) fn value(text: &str) -> Value {
    parse_strict(text).unwrap_or_else(|error| panic!("{text}: {error}"))
}

/// The file `rel` of the held fixture, decoded.
pub(crate) fn held(rel: &str) -> Value {
    let path = tree().join("scripts/gameday-fixtures/held").join(rel);
    let data = std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    value(std::str::from_utf8(&data).expect("the fixture is UTF-8"))
}

pub(crate) fn object(value: &Value) -> &Object {
    match value {
        Value::Object(object) => object,
        _ => panic!("{value:?} is an object"),
    }
}

/// `patched` is `value` with each `(path, new)` applied in turn: the member or item at the `/`-separated
/// path takes the JSON value `new`, or is removed when `new` is `None`.
pub(crate) fn patched(value: &Value, patches: &[(&str, Option<&str>)]) -> Value {
    let mut value = value.clone();
    for &(path, new) in patches {
        let mut steps: Vec<&str> = path.split('/').collect();
        let last = steps.pop().expect("a path has a step");
        let mut at = &mut value;
        for step in steps {
            at = match at {
                Value::Object(object) => object.get_mut(step).expect("the path exists"),
                Value::Array(items) => &mut items[step.parse::<usize>().expect("an index")],
                _ => panic!("{path} passes through a container"),
            };
        }
        match (at, new) {
            (Value::Object(object), Some(new)) => object.insert(Text::from(last), self::value(new)),
            (Value::Object(object), None) => {
                object.remove(last).expect("the member exists");
            }
            (Value::Array(items), Some(new)) => {
                items[last.parse::<usize>().expect("an index")] = self::value(new)
            }
            (Value::Array(items), None) => {
                items.remove(last.parse::<usize>().expect("an index"));
            }
            _ => panic!("{path} ends in a container"),
        }
    }
    value
}
