//! `check_correspondence` reads litmus declarations from `verification/rc11/expected.json` relative
//! to `root`.

use std::path::Path;

use super::refusal::{Code, Error, Refusal, lookup, member, read_json};
use crate::json::Value;
use crate::python::{equal, members, repr, str_of};

const LITMUS: &str = "verification/rc11/expected.json";

fn tool_failure(reason: String) -> Error {
    Error::Refusal(Refusal::new(Code::ToolFailure, reason))
}

fn object_items<'v>(value: &'v Value, what: &str) -> Result<Vec<(String, &'v Value)>, Error> {
    match value {
        Value::Object(object) => Ok(object
            .iter()
            .map(|(name, value)| (name.to_string(), value))
            .collect()),
        _ => Err(Error::Type(format!("{what} is no object"))),
    }
}

pub fn check_correspondence(root: &Path, expected: &Value) -> Result<(), Error> {
    let litmus = read_json(&root.join(LITMUS))?;
    let declared = member(&litmus, "tests")?;
    let mut cases = object_items(member(expected, "cases")?, "the declared cases")?;
    cases.sort_by(|left, right| left.0.cmp(&right.0));
    for (name, case) in cases {
        let listed = match lookup(case, "litmus")? {
            Some(listed @ Value::Array(_)) => listed,
            _ => return Err(tool_failure(format!("{name} names no litmus list"))),
        };
        let mut outcomes = Vec::new();
        for test in members(listed).expect("an array is iterable") {
            let found = match &test {
                Value::String(test) => match declared {
                    Value::Object(tests) => {
                        tests.iter().find(|(key, _)| key == test).map(|(_, v)| v)
                    }
                    _ => return Err(Error::Type("the litmus tests are no object".into())),
                },
                Value::Array(_) | Value::Object(_) => {
                    return Err(Error::Type("a litmus test name is unhashable".into()));
                }
                _ => None,
            };
            let outcome = match found {
                Some(test) => lookup(test, "outcome")?.cloned().unwrap_or(Value::Null),
                None => Value::Null,
            };
            outcomes.push(outcome);
        }
        if outcomes.iter().any(|outcome| equal(outcome, &Value::Null)) {
            return Err(tool_failure(format!(
                "{name} names an undeclared litmus test among {}",
                repr(listed)
            )));
        }
        let expect = member(case, "expect")?;
        let wanted = if equal(expect, &Value::String("positive".into())) {
            "Never"
        } else {
            "Sometimes"
        };
        let wanted = Value::String(wanted.into());
        if !outcomes.iter().all(|outcome| equal(outcome, &wanted)) {
            return Err(tool_failure(format!(
                "{name} is declared {} and its litmus tests {} are {}",
                str_of(expect),
                repr(listed),
                repr(&Value::Array(outcomes))
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "correspondence_tests.rs"]
mod tests;
