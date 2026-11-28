//! GD-2 of the game-day catalog, taken only while its mode and texts are the ones the judge's rules were
//! written from.

use super::constants::{
    PACKAGE, WITNESS, WRITTEN_CLAUSES, WRITTEN_EXPECTED, WRITTEN_GUARDRAILS, WRITTEN_REACH,
};
use super::refusal::{Refusal, need, said};
use super::schema::encodable;
use crate::json::{Object, Value};
use crate::python::hexdigest;

const WRITTEN: &str = "the texts the judge's rules were written from";

/// `gd2_entry` is GD-2 of the decoded catalog.
///
/// # Errors
///
/// In order: `the game-day catalog holds no entries, budgets and run rule`;
/// `the game-day catalog holds <n> entries GD-2, not one`; `GD-2 is not a causal package`;
/// `GD-2's hypothesis clauses or their bounds differ from the texts the judge's rules were written from`;
/// `GD-2's guardrails differ from the texts the judge's rules were written from`;
/// `GD-2's oracle.reach differs from the texts the judge's rules were written from`; and
/// `GD-2's oracle.expected differs from the texts the judge's rules were written from`, which also
/// refuses an `oracle.expected` that does not hold the witness sentence.
pub fn gd2_entry(catalog: &Value) -> Result<&Object, Refusal> {
    let shaped = match catalog {
        Value::Object(catalog) => match (
            catalog.get("entries"),
            catalog.get("budgets"),
            catalog.get("run_rule"),
        ) {
            (Some(Value::Array(entries)), Some(Value::Object(_)), Some(Value::String(_))) => {
                Some(entries)
            }
            _ => None,
        },
        _ => None,
    };
    let entries = shaped.ok_or_else(|| {
        Refusal::new(said!(
            "the game-day catalog holds no entries, budgets and run rule"
        ))
    })?;
    let found: Vec<&Object> = entries
        .iter()
        .filter_map(|entry| match entry {
            Value::Object(entry) if is(entry.get("id"), PACKAGE) => Some(entry),
            _ => None,
        })
        .collect();
    need(found.len() == 1, || {
        said!(
            "the game-day catalog holds ",
            found.len().to_string(),
            " entries ",
            PACKAGE,
            ", not one"
        )
    })?;
    let gd2 = found[0];
    need(is(gd2.get("mode"), "causal"), || {
        said!(PACKAGE, " is not a causal package")
    })?;
    need(clauses_written(gd2.get("hypothesis")), || {
        said!(
            PACKAGE,
            "'s hypothesis clauses or their bounds differ from ",
            WRITTEN
        )
    })?;
    let guardrails = matches!(gd2.get("guardrail"), Some(Value::Array(items))
        if items.len() == WRITTEN_GUARDRAILS.len()
            && items.iter().zip(WRITTEN_GUARDRAILS).all(|(item, written)| is(Some(item), written)));
    need(guardrails, || {
        said!(PACKAGE, "'s guardrails differ from ", WRITTEN)
    })?;
    let oracle = [
        ("reach", WRITTEN_REACH, None),
        ("expected", WRITTEN_EXPECTED, Some(WITNESS)),
    ];
    for (key, digest, holds) in oracle {
        let text = match gd2.get("oracle") {
            Some(Value::Object(oracle)) => oracle.get(key),
            _ => None,
        };
        let written = match text {
            Some(Value::String(text)) if encodable(text) => {
                let text = text.to_str().expect("an encodable text is UTF-8");
                hexdigest(text.as_bytes()) == digest
                    && holds.is_none_or(|sentence| text.contains(sentence))
            }
            _ => false,
        };
        need(written, || {
            said!(PACKAGE, "'s oracle.", key, " differs from ", WRITTEN)
        })?;
    }
    Ok(gd2)
}

/// Whether `value` is the string `text`.
fn is(value: Option<&Value>, text: &str) -> bool {
    matches!(value, Some(Value::String(found)) if *found == text)
}

/// Whether `hypothesis` is a list of objects, each with a `bound`, whose clauses and bounds are the
/// written ones in order.
fn clauses_written(hypothesis: Option<&Value>) -> bool {
    let Some(Value::Array(clauses)) = hypothesis else {
        return false;
    };
    clauses.len() == WRITTEN_CLAUSES.len()
        && clauses
            .iter()
            .zip(WRITTEN_CLAUSES)
            .all(|(clause, (text, bound))| {
                let Value::Object(clause) = clause else {
                    return false;
                };
                is(clause.get("clause"), text)
                    && match bound {
                        Some(bound) => is(clause.get("bound"), bound),
                        None => clause.get("bound") == Some(&Value::Null),
                    }
            })
}

#[cfg(test)]
#[path = "catalog_tests.rs"]
mod tests;
