use super::outcomes::read_outcomes;
use crate::json::{self, Value};

const BASELINE: &str = r#"{"scenario":"Baseline","summary":"Success","phase_results":[]}"#;

fn mutant(name: &str, summary: &str, phases: &str) -> String {
    format!(
        r#"{{"scenario":{{"Mutant":{{"name":{name}}}}},"summary":{summary},"phase_results":{phases}}}"#
    )
}

fn caught(name: &str) -> String {
    mutant(
        name,
        r#""CaughtMutant""#,
        r#"[{"phase":"Test","duration":0.5}]"#,
    )
}

fn file(records: &[String]) -> String {
    format!(r#"{{"outcomes":[{}]}}"#, records.join(","))
}

/// `phases` reads the outcome file and returns the compact JSON of the one judged mutant's phases.
fn phases(phases: &str) -> String {
    let text = file(&[
        BASELINE.to_owned(),
        mutant(r#""a""#, r#""CaughtMutant""#, phases),
    ]);
    let read = read_outcomes(text.as_bytes()).expect("the file reads");
    let [(_, _, phases)] = read.judged.as_slice() else {
        panic!("one judged mutant: {read:?}");
    };
    json::text(&Value::Object(phases.clone()))
}

#[test]
fn outcomes_hold_an_array_an_empty_object_or_an_empty_string() {
    for (document, readable) in [
        (r#"{"outcomes":{}}"#, true),
        (r#"{"outcomes":""}"#, true),
        (r#"{"outcomes":"x"}"#, false),
        (r#"{"outcomes":{"a":1}}"#, false),
        (r#"{"outcomes":null}"#, false),
        ("[]", false),
    ] {
        assert_eq!(
            read_outcomes(document.as_bytes()).is_some(),
            readable,
            "read_outcomes({document})"
        );
    }
}

#[test]
fn names_compare_by_value_whatever_their_json_form() {
    for (first, second) in [("1", "1.0"), ("true", "1"), ("NaN", "NaN"), ("0", "-0.0")] {
        let text = file(&[BASELINE.to_owned(), caught(first), caught(second)]);
        assert!(
            read_outcomes(text.as_bytes()).is_none(),
            "{first} and {second} are one name: None"
        );
    }
    let unjudged = mutant(r#""a""#, r#""Failure""#, "[]");
    let text = file(&[BASELINE.to_owned(), unjudged, caught(r#""a""#)]);
    assert!(
        read_outcomes(text.as_bytes()).is_none(),
        "an unjudged name repeated: None"
    );
    for unreadable in [caught("[1]"), mutant(r#""a""#, "[1]", "[]")] {
        let text = file(&[BASELINE.to_owned(), unreadable]);
        assert!(
            read_outcomes(text.as_bytes()).is_none(),
            "an unhashable name or summary: None"
        );
    }
    let text = file(&[BASELINE.to_owned(), caught("null")]);
    assert!(
        read_outcomes(text.as_bytes()).is_some(),
        "the name None is judged"
    );
}

#[test]
fn phase_times_round_to_three_places_and_integers_keep_their_digits() {
    let big = format!("1{}", "0".repeat(300));
    let duplicate =
        format!(r#"[{{"phase":"Test","duration":5}},{{"phase":"TEST","duration":{big}}}]"#);
    assert_eq!(
        phases(&duplicate),
        format!(r#"{{"test":{big}}}"#),
        "the later of two equal names stands"
    );
    assert_eq!(
        phases(r#"[{"phase":"\u0130X","duration":1e-4}]"#),
        r#"{"i\u0307x":0.0}"#,
        "'\\u0130X'.lower()"
    );
    assert_eq!(
        phases(r#"[{"phase":"T","duration":-0.0}]"#),
        r#"{"t":-0.0}"#,
        "round(-0.0, 3)"
    );
    assert_eq!(
        phases(r#"[{"phase":"T","duration":1.0005}]"#),
        r#"{"t":1.0}"#,
        "round(1.0005, 3)"
    );
    for refused in [
        "true",
        "-1",
        &format!("1{}", "0".repeat(400)),
        "NaN",
        "Infinity",
        "\"1\"",
    ] {
        let text = file(&[
            BASELINE.to_owned(),
            mutant(
                r#""a""#,
                r#""CaughtMutant""#,
                &format!(r#"[{{"phase":"T","duration":{refused}}}]"#),
            ),
        ]);
        assert!(
            read_outcomes(text.as_bytes()).is_none(),
            "a duration of {refused}: None"
        );
    }
}
