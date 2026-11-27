//! The record's value tests: `natural` holds for a JSON integer of at least its bound, and a boolean or a
//! float is none; `count` holds for a positive integer; `text` holds for a string with a code point outside
//! the whitespace `str.isspace` takes.

use crate::json::{Value, parse};
use crate::plants::values::{count, natural, text};

fn value(json: &str) -> Value {
    parse(json).expect("a JSON value")
}

#[test]
fn natural_and_count_take_integers_alone() {
    let rows: &[(&str, u64, bool, bool)] = &[
        ("0", 0, true, false),
        ("1", 0, true, true),
        ("-1", 0, false, false),
        ("1.0", 0, false, false),
        ("true", 0, false, false),
        ("\"1\"", 0, false, false),
        ("null", 0, false, false),
        ("5", 6, false, true),
        ("6", 6, true, true),
        ("123456789012345678901234567890", 6, true, true),
    ];
    for &(json, least, holds, counted) in rows {
        assert_eq!(
            natural(&value(json), least),
            holds,
            "natural({json}, {least})"
        );
        assert_eq!(count(&value(json)), counted, "count({json})");
    }
}

#[test]
fn text_is_a_string_with_a_code_point_outside_the_whitespace() {
    let rows: &[(&str, bool)] = &[
        ("\"a\"", true),
        ("\" a \"", true),
        ("\"\"", false),
        ("\" \\t\\n\"", false),
        ("\"\\u001c\\u00a0\\u3000\"", false),
        ("\"\\u200b\"", true),
        ("\"\\udc80\"", true),
        ("1", false),
        ("[\"a\"]", false),
    ];
    for &(json, holds) in rows {
        assert_eq!(text(&value(json)), holds, "text({json})");
    }
}

/// `unlisted_replay` on a status and the lines of each profile and key, recorded from the script's own
/// function: every reason it gives, in its order of checks, and `None` where the status accounts for
/// every suspect of the profile. A truthy `profiles` of another shape is the run's failure, and a total of
/// another number type than an integer reads as unequal to the sum by key.
#[test]
fn a_status_may_hide_a_differing_replay_for_each_of_its_reasons() {
    use std::collections::BTreeMap;

    use crate::plants::status::unlisted_replay;
    use crate::text::Text;

    let named = "`campaign sweep-status` names no profile smoke";
    let no_keys = "`campaign sweep-status` gives smoke no count of its suspects by key";
    type Lines = &'static [(&'static str, &'static str, usize)];
    type Reason = Result<Option<&'static str>, &'static str>;
    let rows: &[(&str, Lines, Reason)] = &[
        (r#"{"profiles": {}}"#, &[], Ok(Some(named))),
        (r#"{"profiles": null}"#, &[], Ok(Some(named))),
        (r#"{"profiles": []}"#, &[], Ok(Some(named))),
        (r#"{"profiles": {"smoke": [1]}}"#, &[], Ok(Some(named))),
        (
            r#"{"profiles": {"smoke": {"suspects": 1}}}"#,
            &[],
            Ok(Some(no_keys)),
        ),
        (
            r#"{"profiles": {"smoke": {"suspects": 1, "suspect_keys": []}}}"#,
            &[],
            Ok(Some(no_keys)),
        ),
        (
            r#"{"profiles": {"smoke": {"suspects": 1, "suspect_keys": {"a": 1.0}}}}"#,
            &[],
            Ok(Some(no_keys)),
        ),
        (
            r#"{"profiles": {"smoke": {"suspects": 1.0, "suspect_keys": {"a": 1}}}}"#,
            &[],
            Ok(Some(
                "`campaign sweep-status` counts 1.0 suspects of smoke and 1 by key",
            )),
        ),
        (
            r#"{"profiles": {"smoke": {"suspects": null, "suspect_keys": {}}}}"#,
            &[],
            Ok(Some(
                "`campaign sweep-status` counts None suspects of smoke and 0 by key",
            )),
        ),
        (
            r#"{"profiles": {"smoke": {"suspects": 3, "suspect_keys": {"b": 1, "a": 2}}}}"#,
            &[("smoke", "b", 2), ("smoke", "a", 3)],
            Ok(Some(
                "`suspects.jsonl` lists 3 suspects of smoke under `a` and `campaign sweep-status` counts 2",
            )),
        ),
        (
            r#"{"profiles": {"smoke": {"suspects": 3, "suspect_keys": {"b": 1, "a": 2}}}}"#,
            &[("smoke", "a", 2), ("other-p", "z", 9)],
            Ok(None),
        ),
        (
            r#"{"profiles": {"smoke": {"suspects": 3, "suspect_keys": {"replay differs: z": 1, "other": 2}}}}"#,
            &[("smoke", "other", 1)],
            Ok(Some(
                "`campaign sweep-status` counts 2 suspects of smoke under `other` and `suspects.jsonl` lists 1",
            )),
        ),
        (
            r#"{"profiles": {"smoke": {"suspects": 3, "suspect_keys": {"replay differs: z": 1, "other": 2}}}}"#,
            &[("smoke", "other", 2), ("smoke", "replay differs: z", 1)],
            Ok(None),
        ),
        (
            r#"{"profiles": {"smoke": {"suspects": 1, "suspect_keys": {"replay differs": 1}}}}"#,
            &[],
            Ok(None),
        ),
        (
            r#"{"profiles": [1]}"#,
            &[],
            Err("the run failed: `campaign sweep-status` profiles is no object"),
        ),
    ];
    for (status, shown, expected) in rows {
        let Value::Object(status) = value(status) else {
            panic!("an object");
        };
        let shown: BTreeMap<(Text, Text), usize> = shown
            .iter()
            .map(|&(profile, key, lines)| ((Text::from(profile), Text::from(key)), lines))
            .collect();
        let got = unlisted_replay(&status, &Text::from("smoke"), &shown);
        let got = got
            .map(|reason| reason.map(|reason| reason.to_string()))
            .map_err(|ending| ending.reason().to_string());
        let expected = expected
            .map(|reason| reason.map(str::to_owned))
            .map_err(str::to_owned);
        assert_eq!(got, expected, "{status:?} {shown:?}");
    }
}
