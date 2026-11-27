use crate::json::{MAX_DEPTH, MAX_INTEGER_DIGITS, NonFinite, Text, Value, dump, indented, parse};

fn round_trip(text: &str) -> String {
    dump(&parse(text).unwrap_or_else(|error| panic!("{text:?} parses: {error}")))
}

#[test]
fn objects_keep_first_appearance_order_and_a_repeated_key_takes_its_last_value() {
    let expression = "json.dumps(json.loads('{\"b\":1,\"a\":2,\"b\":3}'), separators=(',', ':'))";
    assert_eq!(
        round_trip(r#"{"b":1,"a":2,"b":3}"#),
        "{\"b\":3,\"a\":2}\n",
        "{expression}"
    );
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
fn each_python_form_reads_and_writes_back_compactly() {
    #[rustfmt::skip]
    let rows: &[(&str, &str, &str)] = &[
        ("json.dumps(json.loads('null'), separators=(',', ':'))", "null", "null"),
        ("json.dumps(json.loads('[1.5,-0.0,1e3,1E-7,2.5e+20,0.1]'), separators=(',', ':'))", "[1.5,-0.0,1e3,1E-7,2.5e+20,0.1]", "[1.5,-0.0,1000.0,1e-07,2.5e+20,0.1]"),
        ("json.dumps(json.loads('[NaN,Infinity,-Infinity]'), separators=(',', ':'))", "[NaN,Infinity,-Infinity]", "[NaN,Infinity,-Infinity]"),
        ("json.dumps(json.loads('\"\\\\ud800\"'), separators=(',', ':'))", "\"\\ud800\"", "\"\\ud800\""),
        ("json.dumps(json.loads('\"\\\\udc00x\"'), separators=(',', ':'))", "\"\\udc00x\"", "\"\\udc00x\""),
        ("json.dumps(json.loads('\"\\\\ud800\\\\u0041\"'), separators=(',', ':'))", "\"\\ud800\\u0041\"", "\"\\ud800A\""),
        ("json.dumps(json.loads('\"\\\\ud83d\\\\ude00\"'), separators=(',', ':'))", "\"\\ud83d\\ude00\"", "\"\\ud83d\\ude00\""),
        ("json.dumps(json.loads('\"\\\\ud800\\\\ud800\"'), separators=(',', ':'))", "\"\\ud800\\ud800\"", "\"\\ud800\\ud800\""),
        ("json.dumps(json.loads('\"\\\\udbff\\\\udfff\"'), separators=(',', ':'))", "\"\\udbff\\udfff\"", "\"\\udbff\\udfff\""),
        ("json.dumps(json.loads('[-0,0,-12]'), separators=(',', ':'))", "[-0,0,-12]", "[0,0,-12]"),
        ("json.dumps(json.loads('1e400'), separators=(',', ':'))", "1e400", "Infinity"),
        ("json.dumps(json.loads('-1e400'), separators=(',', ':'))", "-1e400", "-Infinity"),
        ("json.dumps(json.loads('{\"a\":null}'), separators=(',', ':'))", "{\"a\":null}", "{\"a\":null}"),
        ("json.dumps(json.loads('[1E400, 123456789012345678901234567890.5]'), separators=(',', ':'))", "[1E400, 123456789012345678901234567890.5]", "[Infinity,1.2345678901234568e+29]"),
    ];
    for &(expression, text, python) in rows {
        assert_eq!(round_trip(text), format!("{python}\n"), "{expression}");
    }
    let Ok(Value::String(lone)) = parse(r#""\udc80""#) else {
        panic!("a lone surrogate escape reads as a string");
    };
    assert_eq!(
        lone,
        Text::from_code_points([0xdc80]).expect("a code point")
    );
    assert!(matches!(parse("NaN"), Ok(Value::Float(value)) if value.is_nan()));
}

#[test]
fn integers_keep_their_digits_up_to_the_conversion_limit() {
    let digits = "9".repeat(MAX_INTEGER_DIGITS);
    let expression = "json.loads('9' * 4300)";
    assert_eq!(round_trip(&digits), format!("{digits}\n"), "{expression}");
    let expression = "json.loads('9' * 4301) raises ValueError";
    for text in [
        format!("{digits}9"),
        format!("-{digits}9"),
        format!("[{digits}9]"),
    ] {
        let error = parse(&text).expect_err(expression);
        assert_eq!(
            error.reason(),
            "an integer of more digits than the reader takes"
        );
    }
    assert_eq!(MAX_INTEGER_DIGITS, 4300);
}

#[test]
fn each_form_python_refuses_is_refused_with_its_reason() {
    #[rustfmt::skip]
    let refused: &[(&str, usize, &str)] = &[
        ("[1,]", 3, "expected a value"),
        ("{\"a\":1,}", 7, "expected a key"),
        ("\"a\nb\"", 2, "a control character in a string"),
        ("01", 1, "text after the value"),
        ("-", 1, "expected a digit"),
        ("-NaN", 1, "expected a digit"),
        ("\"\\x\"", 2, "an invalid escape"),
        ("\"\\u12\"", 2, "an invalid \\u escape"),
        ("\"\\ud800\\u12\"", 8, "an invalid \\u escape"),
        ("\"open", 5, "an unterminated string"),
        ("{\"a\" 1}", 5, "expected ':'"),
        ("[1 2]", 3, "expected ',' or ']'"),
        ("", 0, "expected a value"),
        ("\u{feff}1", 0, "expected a value"),
        ("1 2", 2, "text after the value"),
        ("1.", 1, "text after the value"),
        ("1e", 1, "text after the value"),
        ("1e+", 1, "text after the value"),
        (".5", 0, "expected a value"),
        ("+1", 0, "expected a value"),
        ("nul", 0, "expected a value"),
    ];
    for &(text, offset, reason) in refused {
        let error = parse(text).expect_err(text);
        assert_eq!(
            (error.offset(), error.reason()),
            (offset, reason),
            "json.loads({text:?}) raises JSONDecodeError"
        );
    }
}

#[test]
fn nesting_past_the_limit_is_refused_without_exhausting_the_stack() {
    let deep = |depth: usize| format!("{}{}", "[".repeat(depth), "]".repeat(depth));
    assert!(matches!(parse(&deep(MAX_DEPTH)), Ok(Value::Array(_))));
    let error = parse(&deep(MAX_DEPTH + 1)).expect_err("one level past the limit");
    assert_eq!(error.reason(), "nesting deeper than the reader takes");
    let error = parse(&"[".repeat(200_000)).expect_err("200,000 open brackets");
    assert_eq!(
        (error.offset(), error.reason()),
        (MAX_DEPTH, "nesting deeper than the reader takes")
    );
}

#[test]
fn indented_writes_sorted_keys_two_spaces_deep() {
    let expression = "json.dumps(json.loads('{\"b\":[1,2.5,{\"z\":null,\"\u{e9}\":\"x\",\"a\":[]}],\"a\":{},\"A\":true,\"\\\\ud800\":\"\\\\udcff\",\"\u{1f600}\":-0.0,\"aa\":[[]],\"n\":1e16,\"m\":1e-05,\"s\":\"tab\\\\tq\\\\\"\\\\\\\\\\\\u007f\\\\u2028\"}'), indent=2, sort_keys=True, allow_nan=False)";
    let text = "{\"b\":[1,2.5,{\"z\":null,\"\u{e9}\":\"x\",\"a\":[]}],\"a\":{},\"A\":true,\"\\ud800\":\"\\udcff\",\"\u{1f600}\":-0.0,\"aa\":[[]],\"n\":1e16,\"m\":1e-05,\"s\":\"tab\\tq\\\"\\\\\\u007f\\u2028\"}";
    let python = "{\u{a}  \"A\": true,\u{a}  \"a\": {},\u{a}  \"aa\": [\u{a}    []\u{a}  ],\u{a}  \"b\": [\u{a}    1,\u{a}    2.5,\u{a}    {\u{a}      \"a\": [],\u{a}      \"z\": null,\u{a}      \"\\u00e9\": \"x\"\u{a}    }\u{a}  ],\u{a}  \"m\": 1e-05,\u{a}  \"n\": 1e+16,\u{a}  \"s\": \"tab\\tq\\\"\\\\\\u007f\\u2028\",\u{a}  \"\\ud800\": \"\\udcff\",\u{a}  \"\\ud83d\\ude00\": -0.0\u{a}}";
    let value = parse(text).expect("the document parses");
    assert_eq!(indented(&value), Ok(python.to_owned()), "{expression}");
    #[rustfmt::skip]
    let rows: &[(&str, &str, &str)] = &[
        ("json.dumps(json.loads('[]'), indent=2, sort_keys=True, allow_nan=False)", "[]", "[]"),
        ("json.dumps(json.loads('{}'), indent=2, sort_keys=True, allow_nan=False)", "{}", "{}"),
        ("json.dumps(json.loads('7'), indent=2, sort_keys=True, allow_nan=False)", "7", "7"),
        ("json.dumps(json.loads('\"a\"'), indent=2, sort_keys=True, allow_nan=False)", "\"a\"", "\"a\""),
        ("json.dumps(json.loads('[[]]'), indent=2, sort_keys=True, allow_nan=False)", "[[]]", "[\u{a}  []\u{a}]"),
    ];
    for &(expression, text, python) in rows {
        let value = parse(text).expect("the value parses");
        assert_eq!(indented(&value), Ok(python.to_owned()), "{expression}");
    }
    for text in ["NaN", "[Infinity]", "{\"a\":-Infinity}"] {
        let value = parse(text).expect("the value parses");
        let refused =
            indented(&value).expect_err("json.dumps(..., allow_nan=False) raises ValueError");
        assert!(!refused.0.is_finite(), "{text}");
    }
    assert_eq!(
        indented(&Value::Float(f64::INFINITY)),
        Err(NonFinite(f64::INFINITY))
    );
}
