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
