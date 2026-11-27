//! Each expected text is the text of `json.dumps(value, separators=(",", ":"))` for the value the input holds.
//! Python converts an integer to and from text up to 4,300 digits by default. The reader and the writer have
//! no such limit, and the round trip of the 5,000-digit integer keeps all 5,000 digits.

use crate::json::{Integer, MAX_DEPTH, Value, dump, parse};

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

/// Each row: the text, whether it is a form the reader leaves out rather than malformed text, and the reader's
/// offset and reason.
#[test]
fn each_form_outside_the_reader_is_refused_with_its_reason() {
    #[rustfmt::skip]
    let refused: [(&str, bool, usize, &str); 23] = [
        ("null", true, 0, "null is refused"),
        ("1.5", true, 0, "a fraction or an exponent is refused"),
        ("1e3", true, 0, "a fraction or an exponent is refused"),
        ("1E3", true, 0, "a fraction or an exponent is refused"),
        ("NaN", true, 0, "a number beyond the integers is refused"),
        ("Infinity", true, 0, "a number beyond the integers is refused"),
        ("-Infinity", true, 1, "a number beyond the integers is refused"),
        ("\"\\ud800\"", true, 1, "a lone surrogate escape is refused"),
        ("\"\\udc00\"", true, 1, "a lone surrogate escape is refused"),
        ("\"\\ud800\\u0041\"", true, 1, "a lone surrogate escape is refused"),
        ("[1,]", false, 3, "expected a value"),
        ("{\"a\":1,}", false, 7, "expected a key"),
        ("\"a\nb\"", false, 2, "a control character in a string"),
        ("01", false, 1, "text after the value"),
        ("-", false, 1, "expected a digit"),
        ("\"\\x\"", false, 2, "an invalid escape"),
        ("\"\\u12\"", false, 2, "an invalid \\u escape"),
        ("\"open", false, 5, "an unterminated string"),
        ("{\"a\" 1}", false, 5, "expected ':'"),
        ("[1 2]", false, 3, "expected ',' or ']'"),
        ("", false, 0, "expected a value"),
        ("\u{feff}1", false, 0, "expected a value"),
        ("1 2", false, 2, "text after the value"),
    ];
    for (text, left_out, offset, reason) in refused {
        let error = parse(text).expect_err(text);
        let found = (error.offset(), error.reason());
        assert_eq!(
            found,
            (offset, reason),
            "{text:?}, a form left out: {left_out}"
        );
    }
}

#[test]
fn integers_order_by_sign_then_magnitude() {
    let mut integers: Vec<Integer> = ["10", "-2", "9", "0", "-10", "100", "-0", "2"]
        .iter()
        .map(|text| match parse(text) {
            Ok(Value::Integer(integer)) => integer,
            other => panic!("{text} reads as an integer: {other:?}"),
        })
        .collect();
    integers.sort();
    let sorted: Vec<String> = integers.iter().map(ToString::to_string).collect();
    assert_eq!(sorted, ["-10", "-2", "0", "0", "2", "9", "10", "100"]);
}

#[test]
fn nesting_past_the_limit_is_refused() {
    let deep = |depth: usize| format!("{}{}", "[".repeat(depth), "]".repeat(depth));
    assert!(matches!(parse(&deep(MAX_DEPTH)), Ok(Value::Array(_))));
    assert!(parse(&deep(MAX_DEPTH + 1)).is_err());
}
