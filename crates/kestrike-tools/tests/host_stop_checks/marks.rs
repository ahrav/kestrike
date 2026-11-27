//! A mark's bytes against the bytes the controller wrote for the same value: keys sorted, one space
//! of indent per level, Python's escapes and number forms, and a final newline.

use kestrike_tools::gameday::FILE_LIMIT;
use kestrike_tools::host_stop::encoded;
use kestrike_tools::json::{Text, Value};

use crate::host_stop_support::value;

/// The nested value: empty containers, nested lists and objects, a string of non-ASCII code points, a
/// lone surrogate, a pair beyond the BMP and the escaped characters, and numbers in Python's forms.
const NESTED: &str = r#"{"b": [], "a": {}, "c": [1, {"z": null, "y": [true, false]}], "d": "\u00e9\u2028\ud800\ud83d\ude00\"\\\n", "e": 1e16, "f": -0.0, "g": 0.1, "h": 123456789012345678901234567890}"#;

/// Each value's bytes are the bytes the controller wrote for it.
#[test]
fn a_marks_bytes_are_the_bytes_the_controller_writes() {
    let identity = "arn:aws:sts::account:assumed-role/gameday-operator/gd2-run";
    let stop = format!(r#"{{"instance": "i-h1", "time": 104.0, "identity": "{identity}"}}"#);
    let rows = [
        (
            stop.as_str(),
            "{\n \"identity\": \"arn:aws:sts::account:assumed-role/gameday-operator/gd2-run\",\n \"instance\": \"i-h1\",\n \"time\": 104.0\n}\n",
        ),
        (
            NESTED,
            "{\n \"a\": {},\n \"b\": [],\n \"c\": [\n  1,\n  {\n   \"y\": [\n    true,\n    false\n   ],\n   \"z\": null\n  }\n ],\n \"d\": \"\\u00e9\\u2028\\ud800\\ud83d\\ude00\\\"\\\\\\n\",\n \"e\": 1e+16,\n \"f\": -0.0,\n \"g\": 0.1,\n \"h\": 123456789012345678901234567890\n}\n",
        ),
        ("{}", "{}\n"),
    ];
    for (json, bytes) in rows {
        let data =
            encoded(&value(json), &Text::from("a mark"), FILE_LIMIT).expect("the mark encodes");
        assert_eq!(String::from_utf8(data).expect("ASCII"), bytes, "{json}");
    }
}

/// A non-finite float has no JSON form, so its mark is refused.
#[test]
fn a_mark_that_holds_a_non_finite_float_is_refused() {
    let refusal = encoded(&Value::Float(f64::NAN), &Text::from("a mark"), FILE_LIMIT)
        .expect_err("NaN has no JSON form");
    assert_eq!(
        *refusal.message(),
        "a mark cannot be written: the float nan has no JSON form"
    );
}
