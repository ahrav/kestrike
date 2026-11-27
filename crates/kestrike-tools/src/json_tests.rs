//! For texts with integers of at most 4,300 digits, each expected text is what Python 3.9.25 prints for
//! `json.dumps(json.loads(text), separators=(",", ":"))`. Python 3.9.25 refuses a longer integer under its
//! default conversion limit; the reader takes it.

use crate::json::{Error, MAX_DEPTH, Value, dump, parse};

fn round_trip(text: &str) -> String {
    dump(&parse(text).unwrap_or_else(|error| panic!("{text:?} parses: {error}")))
}

#[test]
fn objects_keep_first_appearance_order_and_a_repeated_key_takes_its_last_value() {
    assert_eq!(round_trip(r#"{"b":1,"a":2,"b":3}"#), "{\"b\":3,\"a\":2}\n");
    assert_eq!(
        round_trip(r#" {"a" : [ true , false ] , "c":{}} "#),
        "{\"a\":[true,false],\"c\":{}}\n"
    );
}

#[test]
fn escapes_read_every_form_and_write_python_escapes() {
    assert_eq!(
        round_trip(r#"{"s":"\u00e9\ud83d\ude00\u007f\t\n\r\b\f\"\\\/ \u0001"}"#),
        "{\"s\":\"\\u00e9\\ud83d\\ude00\\u007f\\t\\n\\r\\b\\f\\\"\\\\/ \\u0001\"}\n"
    );
    assert_eq!(round_trip("\"\u{e9}\u{2028}\""), "\"\\u00e9\\u2028\"\n");
    assert_eq!(round_trip(r#""\u00E9""#), "\"\\u00e9\"\n");
}

#[test]
fn integers_keep_their_digits_and_minus_zero_reads_as_zero() {
    assert_eq!(
        round_trip("[123456789012345678901234567890,-5,0,-0]"),
        "[123456789012345678901234567890,-5,0,0]\n"
    );
    let digits = "9".repeat(5000);
    assert_eq!(round_trip(&digits), format!("{digits}\n"));
}

#[test]
fn each_form_outside_the_reader_is_refused() {
    let refused = [
        "null",
        "1.5",
        "1e3",
        "1E3",
        "NaN",
        "Infinity",
        "-Infinity",
        "\"\\ud800\"",
        "\"\\udc00\"",
        "\"\\ud800\\u0041\"",
        "[1,]",
        "{\"a\":1,}",
        "\"a\nb\"",
        "01",
        "-",
        "\"\\x\"",
        "\"\\u12\"",
        "\"open",
        "{\"a\" 1}",
        "[1 2]",
        "",
        "\u{feff}1",
        "1 2",
    ];
    for text in refused {
        assert!(parse(text).is_err(), "{text:?} is refused");
    }
    assert_eq!(
        parse("01"),
        Err(Error {
            offset: 1,
            reason: "text after the value"
        })
    );
}

#[test]
fn nesting_past_the_limit_is_refused() {
    let deep = |depth: usize| format!("{}{}", "[".repeat(depth), "]".repeat(depth));
    assert!(matches!(parse(&deep(MAX_DEPTH)), Ok(Value::Array(_))));
    assert!(parse(&deep(MAX_DEPTH + 1)).is_err());
}
