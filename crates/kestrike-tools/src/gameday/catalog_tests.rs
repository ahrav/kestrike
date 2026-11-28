//! Each row's expected result is the judge's at the base under Python 3.9.25 for the same call: the
//! function the test calls, on the committed catalog with the row's changes applied.

use super::gd2_entry;
use crate::gameday::parsed;
use crate::gameday::test_support::{object, patched, tree};
use crate::json::{Object, Value};
use crate::text::Text;

/// The committed catalog, decoded.
fn committed() -> Value {
    let path = tree().join("verification/readiness/gamedays.json");
    let data = std::fs::read(path).expect("the catalog is read");
    parsed(&data, &Text::from("catalog")).expect("the catalog is strict JSON")
}

/// The one entry of `catalog` whose id is GD-2, found apart from the function the rows test.
fn gd2_of(catalog: &Value) -> &Object {
    let Some(Value::Array(entries)) = object(catalog).get("entries") else {
        panic!("the catalog holds entries");
    };
    let mut found = entries.iter().filter_map(|entry| match entry {
        Value::Object(entry) if entry.get("id") == Some(&Value::String(Text::from("GD-2"))) => {
            Some(entry)
        }
        _ => None,
    });
    found.next().expect("the catalog holds GD-2")
}

type Patches = &'static [(&'static str, Option<&'static str>)];
/// A label, the changes to the catalog, and the judge's result.
type Row = (&'static str, Patches, Result<&'static str, &'static str>);

#[test]
fn gd2_entry_takes_the_committed_catalog_and_refuses_each_changed_copy() {
    let catalog = committed();
    #[rustfmt::skip]
    let rows: &[Row] = &[
    (r#"committed"#, &[], Ok(r#"GD-2"#)),
    (r#"no run rule"#, &[(r#"run_rule"#, None)], Err(r#"the game-day catalog holds no entries, budgets and run rule"#)),
    (r#"budgets no object"#, &[(r#"budgets"#, Some(r#"[]"#))], Err(r#"the game-day catalog holds no entries, budgets and run rule"#)),
    (r#"entries no list"#, &[(r#"entries"#, Some(r#"{}"#))], Err(r#"the game-day catalog holds no entries, budgets and run rule"#)),
    (r#"no GD-2"#, &[(r#"entries/1/id"#, Some(r#""GD-0""#))], Err(r#"the game-day catalog holds 0 entries GD-2, not one"#)),
    (r#"two GD-2"#, &[(r#"entries/0/id"#, Some(r#""GD-2""#))], Err(r#"the game-day catalog holds 2 entries GD-2, not one"#)),
    (r#"mode"#, &[(r#"entries/1/mode"#, Some(r#""rehearsal""#))], Err(r#"GD-2 is not a causal package"#)),
    (r#"clause"#, &[(r#"entries/1/hypothesis/0/clause"#, Some(r#""x""#))], Err(r#"GD-2's hypothesis clauses or their bounds differ from the texts the judge's rules were written from"#)),
    (r#"bound"#, &[(r#"entries/1/hypothesis/3/bound"#, Some(r#"null"#))], Err(r#"GD-2's hypothesis clauses or their bounds differ from the texts the judge's rules were written from"#)),
    (r#"bound absent"#, &[(r#"entries/1/hypothesis/0/bound"#, None)], Err(r#"GD-2's hypothesis clauses or their bounds differ from the texts the judge's rules were written from"#)),
    (r#"clauses short"#, &[(r#"entries/1/hypothesis/4"#, None)], Err(r#"GD-2's hypothesis clauses or their bounds differ from the texts the judge's rules were written from"#)),
    (r#"guardrail"#, &[(r#"entries/1/guardrail/7"#, Some(r#""x""#))], Err(r#"GD-2's guardrails differ from the texts the judge's rules were written from"#)),
    (r#"guardrails short"#, &[(r#"entries/1/guardrail/7"#, None)], Err(r#"GD-2's guardrails differ from the texts the judge's rules were written from"#)),
    (r#"reach"#, &[(r#"entries/1/oracle/reach"#, Some(r#""x""#))], Err(r#"GD-2's oracle.reach differs from the texts the judge's rules were written from"#)),
    (r#"reach surrogate"#, &[(r#"entries/1/oracle/reach"#, Some(r#""\ud800""#))], Err(r#"GD-2's oracle.reach differs from the texts the judge's rules were written from"#)),
    (r#"expected"#, &[(r#"entries/1/oracle/expected"#, Some(r#""x""#))], Err(r#"GD-2's oracle.expected differs from the texts the judge's rules were written from"#)),
    (r#"oracle no object"#, &[(r#"entries/1/oracle"#, Some(r#"[]"#))], Err(r#"GD-2's oracle.reach differs from the texts the judge's rules were written from"#)),
        (r#"two defects: mode, clause"#, &[(r#"entries/1/mode"#, Some(r#""x""#)), (r#"entries/1/hypothesis/0/clause"#, Some(r#""x""#))], Err(r#"GD-2 is not a causal package"#)),
        (r#"two defects: clause, guardrail"#, &[(r#"entries/1/hypothesis/0/clause"#, Some(r#""x""#)), (r#"entries/1/guardrail/0"#, Some(r#""x""#))], Err(r#"GD-2's hypothesis clauses or their bounds differ from the texts the judge's rules were written from"#)),
        (r#"two defects: guardrail, reach"#, &[(r#"entries/1/guardrail/0"#, Some(r#""x""#)), (r#"entries/1/oracle/reach"#, Some(r#""x""#))], Err(r#"GD-2's guardrails differ from the texts the judge's rules were written from"#)),
        (r#"two defects: reach, expected"#, &[(r#"entries/1/oracle/reach"#, Some(r#""x""#)), (r#"entries/1/oracle/expected"#, Some(r#""x""#))], Err(r#"GD-2's oracle.reach differs from the texts the judge's rules were written from"#)),
        (r#"hypothesis no list"#, &[(r#"entries/1/hypothesis"#, Some(r#"{}"#))], Err(r#"GD-2's hypothesis clauses or their bounds differ from the texts the judge's rules were written from"#)),
        (r#"hypothesis item no object"#, &[(r#"entries/1/hypothesis/0"#, Some(r#""x""#))], Err(r#"GD-2's hypothesis clauses or their bounds differ from the texts the judge's rules were written from"#)),
        (r#"run rule no string"#, &[(r#"run_rule"#, Some(r#"1"#))], Err(r#"the game-day catalog holds no entries, budgets and run rule"#)),
        (r#"an entry no object"#, &[(r#"entries/0"#, Some(r#"1"#))], Ok(r#"GD-2"#)),
        (r#"a clause unbudgeted in the texts with a bound"#, &[(r#"entries/1/hypothesis/0/bound"#, Some(r#""x""#))], Err(r#"GD-2's hypothesis clauses or their bounds differ from the texts the judge's rules were written from"#)),
    ];
    for &(label, patches, expected) in rows {
        let changed = patched(&catalog, patches);
        let found = gd2_entry(&changed)
            .map(|gd2| {
                assert_eq!(gd2, gd2_of(&changed), "the whole entry of {label}");
                match gd2.get("id") {
                    Some(Value::String(id)) => id.to_string(),
                    _ => panic!("GD-2 has an id"),
                }
            })
            .map_err(|refusal| refusal.to_string());
        assert_eq!(
            found,
            expected.map(str::to_owned).map_err(str::to_owned),
            "gd2_entry of {label}"
        );
    }
    assert_eq!(
        gd2_entry(&Value::Array(Vec::new())).map_err(|refusal| refusal.to_string()),
        Err("the game-day catalog holds no entries, budgets and run rule".to_owned()),
        "gd2_entry([])"
    );
}

/// Copies changed by moving intact items or by a digest alone: two clauses swapped, two guardrails
/// swapped, and `oracle.expected` with a space appended, which keeps the witness sentence.
#[test]
fn gd2_entry_refuses_texts_out_of_order_and_an_expected_text_of_another_digest() {
    let catalog = committed();
    let changed = |change: &dyn Fn(&mut Object)| {
        let mut catalog = catalog.clone();
        let Value::Object(top) = &mut catalog else {
            panic!("the catalog is an object");
        };
        let Some(Value::Array(entries)) = top.get_mut("entries") else {
            panic!("the catalog holds entries");
        };
        let Value::Object(gd2) = &mut entries[1] else {
            panic!("the second entry is GD-2");
        };
        change(gd2);
        catalog
    };
    let swapped = |key: &'static str| {
        move |gd2: &mut Object| {
            let Some(Value::Array(items)) = gd2.get_mut(key) else {
                panic!("GD-2 holds the list {key}");
            };
            items.swap(0, 1);
        }
    };
    let spaced = |gd2: &mut Object| {
        let Some(Value::Object(oracle)) = gd2.get_mut("oracle") else {
            panic!("GD-2 holds an oracle");
        };
        let Some(Value::String(expected)) = oracle.get_mut("expected") else {
            panic!("the oracle holds an expected text");
        };
        expected.push_str(" ");
    };
    #[rustfmt::skip]
    let rows: &[(&str, Value, &str)] = &[
        ("gd2_entry with hypothesis[0] and [1] swapped", changed(&swapped("hypothesis")), "GD-2's hypothesis clauses or their bounds differ from the texts the judge's rules were written from"),
        ("gd2_entry with guardrail[0] and [1] swapped", changed(&swapped("guardrail")), "GD-2's guardrails differ from the texts the judge's rules were written from"),
        ("gd2_entry with oracle.expected + ' '", changed(&spaced), "GD-2's oracle.expected differs from the texts the judge's rules were written from"),
    ];
    for (expression, catalog, judged) in rows {
        assert_eq!(
            gd2_entry(catalog).map_err(|refusal| refusal.to_string()),
            Err((*judged).to_owned()),
            "{expression}"
        );
    }
}
