//! The correspondence check holds each GenMC case to the RC11 litmus tests it names, read from
//! `verification/rc11/expected.json` under the root.

use std::path::Path;

use super::refusal::{Error, lookup, member, read_json, tool_failure};
use crate::json::Value;
use crate::python::{equal, repr, str_of};

const LITMUS: &str = "verification/rc11/expected.json";

/// Refuses a declaration whose cases disagree with their litmus tests: a positive case's tests must
/// all be declared `Never` and any other case's all `Sometimes`. Cases are read in code point order.
///
/// # Errors
///
/// `check_correspondence` returns a tool failure for a case without a litmus list, with an undeclared
/// test or with a test of the other outcome, the errors of [`read_json`], and [`Error::Key`] or
/// [`Error::Type`] for a declaration or a litmus list without a member it reads.
pub fn check_correspondence(root: &Path, expected: &Value) -> Result<(), Error> {
    let litmus = read_json(&root.join(LITMUS))?;
    let declared = member(&litmus, "tests")?;
    let Value::Object(cases) = member(expected, "cases")? else {
        return Err(Error::Type("the declared cases are no object".to_owned()));
    };
    let mut cases: Vec<_> = cases.iter().collect();
    cases.sort_by(|left, right| left.0.cmp(&right.0));
    for (name, case) in cases {
        let (listed, tests) = match lookup(case, "litmus")? {
            Some(listed @ Value::Array(tests)) => (listed, tests),
            _ => return Err(tool_failure(format!("{name} names no litmus list"))),
        };
        let mut outcomes = Vec::new();
        for test in tests {
            let Value::Object(declared) = declared else {
                return Err(Error::Type("the litmus tests are no object".to_owned()));
            };
            let found = match test {
                Value::String(test) => declared
                    .iter()
                    .find(|(key, _)| key == test)
                    .map(|(_, found)| found),
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
