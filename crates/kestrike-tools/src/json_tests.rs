//! Each expected text of a round trip is the text of `json.dumps(value, separators=(",", ":"))` for the value
//! the input holds. The reader and [`Integer`] hold an integer of at most 4,300 digits, the length up to which
//! Python converts an integer to and from text by default; a longer integer token is refused.

use crate::json::{
    Integer, MAX_DEPTH, MAX_INTEGER_DIGITS, Text, UniqueError, Value, dump, indented,
    indented_in_order, parse, parse_members, parse_unique, text,
};

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
fn an_integer_holds_no_more_digits_than_the_reader_takes() {
    let digits = "9".repeat(4300);
    for negative in [false, true] {
        let sign = if negative { "-" } else { "" };
        let held = Integer::from_digits(negative, &format!("000{digits}")).expect("4,300 digits");
        let value = Value::Array(vec![Value::Integer(held)]);
        let expression = format!("json.dumps([int('{sign}' + '9' * 4300)])");
        assert_eq!(dump(&value), format!("[{sign}{digits}]\n"), "{expression}");
        assert_eq!(
            indented(&value).expect("an integer writes"),
            format!("[\n  {sign}{digits}\n]"),
            "{expression}"
        );
        assert_eq!(
            Integer::from_digits(negative, &format!("{digits}9")),
            None,
            "int('{sign}' + '9' * 4301) raises ValueError"
        );
    }
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
            "json.loads({text:?}) raises JSONDecodeError; the offset and the reason are the reader's own"
        );
    }
}

#[test]
fn nesting_past_the_limit_is_refused_without_exhausting_the_stack() {
    let arrays = |depth: usize| format!("{}1{}", "[".repeat(depth), "]".repeat(depth));
    let objects = |depth: usize| format!("{}1{}", "{\"a\":".repeat(depth), "}".repeat(depth));
    assert!(matches!(parse(&arrays(1000)), Ok(Value::Array(_))));
    assert!(matches!(parse(&objects(1000)), Ok(Value::Object(_))));
    for (text, offset) in [(arrays(1001), 1000), (objects(1001), 5000)] {
        let error = parse(&text).expect_err("one level past the limit");
        assert_eq!(
            (error.offset(), error.reason()),
            (offset, "nesting deeper than the reader takes")
        );
    }
    let error = parse(&"[".repeat(200_000)).expect_err("200,000 open brackets");
    assert_eq!(
        (error.offset(), error.reason()),
        (1000, "nesting deeper than the reader takes")
    );
    let error = parse(&"{\"a\":".repeat(200_000)).expect_err("200,000 open objects");
    assert_eq!(
        (error.offset(), error.reason()),
        (5000, "nesting deeper than the reader takes")
    );
    assert_eq!(MAX_DEPTH, 1000);
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
        assert!(!refused.value().is_finite(), "{text}");
    }
    let refused = indented(&Value::Float(f64::INFINITY)).expect_err("infinity has no JSON form");
    assert_eq!(refused.value(), f64::INFINITY);
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
fn an_escaped_surrogate_pair_joins_and_other_surrogates_stand_alone() {
    #[rustfmt::skip]
    let rows: &[(&str, &str, &[u32])] = &[
        ("[hex(ord(c)) for c in json.loads(r'\"\\ud800\\udc00\"')] == ['0x10000']", r#""\ud800\udc00""#, &[0x10000]),
        ("[hex(ord(c)) for c in json.loads(r'\"\\udbff\\udfff\"')] == ['0x10ffff']", r#""\udbff\udfff""#, &[0x10_ffff]),
        ("[hex(ord(c)) for c in json.loads(r'\"\\udc00\\ud800\"')] == ['0xdc00', '0xd800']", r#""\udc00\ud800""#, &[0xdc00, 0xd800]),
        ("[hex(ord(c)) for c in json.loads(r'\"\\ud800\\u0041\"')] == ['0xd800', '0x41']", r#""\ud800\u0041""#, &[0xd800, 0x41]),
    ];
    for &(python, text, codes) in rows {
        let Ok(Value::String(found)) = parse(text) else {
            panic!("{python}");
        };
        assert_eq!(found.code_points().collect::<Vec<u32>>(), codes, "{python}");
    }
}

#[test]
fn the_digit_limit_counts_digits_and_leaves_floats_alone() {
    let digits = "9".repeat(4300);
    let expression = "json.loads('-' + '9' * 4300) == -int('9' * 4300)";
    let Ok(Value::Integer(found)) = parse(&format!("-{digits}")) else {
        panic!("{expression}");
    };
    assert_eq!(found.to_string(), format!("-{digits}"), "{expression}");
    let expression = "json.loads('9' * 4301 + '.5') == float('inf')";
    assert!(
        matches!(parse(&format!("{digits}9.5")), Ok(Value::Float(value)) if value == f64::INFINITY),
        "{expression}"
    );
}

/// A repeated key is refused when its object closes: a repeat in a nested object, and a syntax error
/// before the close, come first, and the name refused is the first key of the object that repeats an
/// earlier one.
#[test]
fn the_unique_read_refuses_the_first_repeat_of_the_first_object_to_close() {
    let rows: &[(&str, Result<(), &str>)] = &[
        (
            r#"{"a": 1, "b": 2, "b": 3, "a": 4}"#,
            Err("repeated member b"),
        ),
        (
            r#"{"a": 1, "a": 2, "x": {"b": 1, "b": 2}}"#,
            Err("repeated member b"),
        ),
        (r#"[{"a": 1}, {"c": 1, "c": 2}]"#, Err("repeated member c")),
        (
            r#"{"\ud800": 1, "\ud800": 2}"#,
            Err("repeated member \\ud800"),
        ),
        (r#"{"a": 1, "a": 2,"#, Err("expected a key at byte 16")),
        (r#"{"a": 1, "a": 2} x"#, Err("repeated member a")),
        (r#"{"a": {"a": 1}, "b": [{"a": 2}]}"#, Ok(())),
    ];
    for &(text, expected) in rows {
        let found = parse_unique(text)
            .map(drop)
            .map_err(|error| error.to_string());
        assert_eq!(found, expected.map_err(str::to_owned), "{text}");
    }
    let Err(UniqueError::Repeated(name, keys)) = parse_unique(r#"{"k": 1, "j": 2, "k": 1}"#) else {
        panic!("the repeat is refused");
    };
    assert_eq!(name, Text::from("k"));
    assert_eq!(
        keys,
        [("k", 1), ("j", 1), ("k", 1)].map(|(key, count)| (Text::from(key), count))
    );
    let Err(UniqueError::Repeated(name, keys)) =
        parse_unique(r#"{"k": 1, "j": 2, "k": 3, "m": 4, "k": 5, "k": 6, "j": 7}"#)
    else {
        panic!("the repeat is refused");
    };
    assert_eq!(name, Text::from("k"));
    assert_eq!(
        keys,
        [("k", 1), ("j", 1), ("k", 1), ("m", 1), ("k", 2), ("j", 1)]
            .map(|(key, count)| (Text::from(key), count))
    );
    let Err(UniqueError::Repeated(_, keys)) = parse_unique(r#"{"a": 0, "a": 0, "a": 0}"#) else {
        panic!("the repeat is refused");
    };
    assert_eq!(keys, [(Text::from("a"), 3)]);
    assert_eq!(
        parse(r#"{"a": 1, "a": 2}"#).map(|value| text(&value)),
        Ok(r#"{"a":2}"#.to_owned()),
        "the present read keeps the last value"
    );
}

/// The read that keeps every member turns each object into the array of its keys and values in document
/// order, a repeated key's members and nested objects included, and refuses what `parse` refuses.
#[test]
fn parse_members_keeps_every_member_of_each_object() {
    let read = parse_members(r#"{"a": 1, "b": {"c": []}, "a": "x"}"#).expect("the document reads");
    let string = |text: &str| Value::String(Text::from(text));
    assert_eq!(
        read,
        Value::Array(vec![
            string("a"),
            Value::Integer(Integer::from(1_u64)),
            string("b"),
            Value::Array(vec![string("c"), Value::Array(vec![])]),
            string("a"),
            string("x"),
        ])
    );
    assert_eq!(parse_members("{}"), Ok(Value::Array(vec![])));
    for refused in ["{\"a\": 1,}", "[", "{\"a\" 1}"] {
        assert_eq!(
            parse_members(refused).map_err(|error| error.reason()),
            parse(refused).map_err(|error| error.reason()),
            "{refused}"
        );
    }
}

/// With no repeated key, the unique read reads each number as the read that keeps repeats does: the three
/// constants, an overflow, an underflow and a form longer than its double's shortest one.
#[test]
fn the_unique_read_takes_the_numbers_a_strict_read_refuses() {
    let text = "[NaN, Infinity, -Infinity, 1e999, -1e999, 1e-400, 0.10000000000000001]";
    let unique = parse_unique(text).expect("no key repeats");
    assert_eq!(dump(&unique), dump(&parse(text).expect("the text parses")));
    assert_eq!(
        dump(&unique),
        "[NaN,Infinity,-Infinity,Infinity,-Infinity,0.0,0.1]\n"
    );
}

fn integer(text: &str) -> Integer {
    match parse(text) {
        Ok(Value::Integer(integer)) => integer,
        other => panic!("{text} reads as {other:?}"),
    }
}

/// Sums and differences carry and borrow across every digit, change sign through zero, and refuse a
/// result of more than `MAX_INTEGER_DIGITS` digits, where Python 3.9.25's `str` of the integer raises.
#[test]
fn integers_add_and_step_down_by_one() {
    let rows: &[(&str, &str, &str)] = &[
        ("0", "0", "0"),
        ("999", "1", "1000"),
        ("1000", "-1", "999"),
        ("-1000", "1", "-999"),
        ("5", "-7", "-2"),
        ("-5", "-7", "-12"),
        ("7", "-7", "0"),
        (
            "123456789012345678901234567890",
            "987654321098765432109876543210",
            "1111111110111111111011111111100",
        ),
    ];
    for (left, right, sum) in rows {
        assert_eq!(
            integer(left).checked_add(&integer(right)),
            Some(integer(sum)),
            "{left} + {right}"
        );
        assert_eq!(
            integer(right).checked_add(&integer(left)),
            Some(integer(sum)),
            "{right} + {left}"
        );
    }
    for (value, below) in [
        ("1", "0"),
        ("0", "-1"),
        ("-1", "-2"),
        ("1000", "999"),
        ("100000", "99999"),
    ] {
        assert_eq!(
            integer(value).minus_one(),
            Some(integer(below)),
            "{value} - 1"
        );
    }
    let nines = "9".repeat(MAX_INTEGER_DIGITS);
    assert_eq!(integer(&nines).checked_add(&Integer::from(1u64)), None);
    assert_eq!(integer(&format!("-{nines}")).minus_one(), None);
    assert_eq!(
        integer(&nines)
            .checked_add(&integer("-1"))
            .map(|n| n.to_string().len()),
        Some(MAX_INTEGER_DIGITS)
    );
    let items = [integer("2"), integer("40"), integer("0")];
    assert_eq!(Integer::sum(&items), Some(integer("42")));
    assert_eq!(Integer::sum(&[]), Some(integer("0")));
    assert_eq!(
        Integer::sum(&[integer(&nines), integer("1"), integer("-1")]),
        None
    );
}

/// `indented_in_order` keeps document order and writes non-finite floats, as
/// `json.dumps(value, indent=2)` does.
#[test]
fn indented_in_order_keeps_members_in_document_order() {
    let value = parse(r#"{"b": [1, {}], "a": {"y": [], "x": NaN}, "c": "\u00e9", "d": Infinity}"#)
        .expect("JSON");
    let python = "{\n  \"b\": [\n    1,\n    {}\n  ],\n  \"a\": {\n    \"y\": [],\n    \"x\": NaN\n  },\n  \
                  \"c\": \"\\u00e9\",\n  \"d\": Infinity\n}";
    assert_eq!(indented_in_order(&value), python);
}

/// Each expected line was recorded from Python 3.9's `json.dumps` of the same value.
#[test]
fn line_writes_python_s_default_separators_on_one_line() {
    let rows = [
        (
            r#"{"report": "/w/report.json", "mismatched": [], "no verdict": ["a", "b"]}"#,
            r#"{"report": "/w/report.json", "mismatched": [], "no verdict": ["a", "b"]}"#,
        ),
        ("[]", "[]"),
        ("{}", "{}"),
        (
            "{\"a\": {\"b\": [1, 2.5, null, true, false]}, \"\u{e9}\": \"\u{2028}\u{1f600}\"}",
            r#"{"a": {"b": [1, 2.5, null, true, false]}, "\u00e9": "\u2028\ud83d\ude00"}"#,
        ),
        (
            "[NaN, Infinity, -Infinity, 1e100, -0.0]",
            "[NaN, Infinity, -Infinity, 1e+100, -0.0]",
        ),
    ];
    for (source, expected) in rows {
        let value = super::parse(source).unwrap_or_else(|error| panic!("{source}: {error}"));
        assert_eq!(super::line(&value), expected, "{source}");
    }
}
