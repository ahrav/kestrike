//! For texts with integers of at most 4,300 digits, each expected text is what Python 3.9.25 prints for
//! `json.dumps(json.loads(text), separators=(",", ":"))`. Python 3.9.25 refuses a longer integer under its
//! default conversion limit; the reader takes it.

use crate::json::{MAX_DEPTH, Value, dump, parse};

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

/// Each row: the text, whether Python 3.9.25's `json.loads` takes it, and the reader's reason. The forms Python
/// takes and the reader refuses are the JSON a Quint trace lacks.
#[test]
fn each_form_outside_the_reader_is_refused_with_its_reason() {
    let refused: [(&str, bool, &str); 23] = [
        ("null", true, "null is refused"),
        ("1.5", true, "a fraction or an exponent is refused"),
        ("1e3", true, "a fraction or an exponent is refused"),
        ("1E3", true, "a fraction or an exponent is refused"),
        ("NaN", true, "a number beyond the integers is refused"),
        ("Infinity", true, "a number beyond the integers is refused"),
        ("-Infinity", true, "a number beyond the integers is refused"),
        ("\"\\ud800\"", true, "a lone surrogate escape is refused"),
        ("\"\\udc00\"", true, "a lone surrogate escape is refused"),
        (
            "\"\\ud800\\u0041\"",
            true,
            "a lone surrogate escape is refused",
        ),
        ("[1,]", false, "expected a value"),
        ("{\"a\":1,}", false, "expected a key"),
        ("\"a\nb\"", false, "a control character in a string"),
        ("01", false, "text after the value"),
        ("-", false, "expected a digit"),
        ("\"\\x\"", false, "an invalid escape"),
        ("\"\\u12\"", false, "an invalid \\u escape"),
        ("\"open", false, "an unterminated string"),
        ("{\"a\" 1}", false, "expected ':'"),
        ("[1 2]", false, "expected ',' or ']'"),
        ("", false, "expected a value"),
        ("\u{feff}1", false, "expected a value"),
        ("1 2", false, "text after the value"),
    ];
    for (text, python_takes_it, reason) in refused {
        let error = parse(text).expect_err(text);
        assert_eq!(
            error.reason(),
            reason,
            "{text:?}, which Python takes: {python_takes_it}"
        );
    }
    let error = parse("01").expect_err("01");
    assert_eq!(
        (error.offset(), error.reason()),
        (1, "text after the value")
    );
}

#[test]
fn nesting_past_the_limit_is_refused() {
    let deep = |depth: usize| format!("{}{}", "[".repeat(depth), "]".repeat(depth));
    assert!(matches!(parse(&deep(MAX_DEPTH)), Ok(Value::Array(_))));
    assert!(parse(&deep(MAX_DEPTH + 1)).is_err());
}
