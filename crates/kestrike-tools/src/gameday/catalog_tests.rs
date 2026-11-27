//! Each row's expected result is the judge's own function's at the base under Python 3.9.25, as the
//! expression beside it gives it.

use super::gd2_entry;
use crate::gameday::parsed;
use crate::gameday::test_support::patched;
use crate::gameday::test_support::tree;
use crate::json::Value;
use crate::text::Text;

type Patches = &'static [(&'static str, Option<&'static str>)];
/// A label, the changes to the catalog, and the judge's result.
type Row = (&'static str, Patches, Result<&'static str, &'static str>);

#[test]
fn gd2_entry_takes_the_committed_catalog_and_refuses_each_changed_copy() {
    let path = tree().join("verification/readiness/gamedays.json");
    let data = std::fs::read(path).expect("the catalog is read");
    let catalog = parsed(&data, &Text::from("catalog")).expect("the catalog is strict JSON");
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
    ];
    for &(label, patches, expected) in rows {
        let changed = patched(&catalog, patches);
        let found = gd2_entry(&changed)
            .map(|gd2| match gd2.get("id") {
                Some(Value::String(id)) => id.to_string(),
                _ => panic!("GD-2 has an id"),
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
