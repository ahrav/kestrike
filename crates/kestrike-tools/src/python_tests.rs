use crate::json::{Integer, Text, Value, parse};
use crate::python::{self, int, repr_float, round};

#[test]
fn repr_float_writes_the_shortest_digits_in_python_notation() {
    #[rustfmt::skip]
    let rows: &[(&str, f64, &str)] = &[
        ("repr(0.0)", f64::from_bits(0x0000000000000000), "0.0"),
        ("repr(-0.0)", f64::from_bits(0x8000000000000000), "-0.0"),
        ("repr(53.0)", f64::from_bits(0x404a800000000000), "53.0"),
        ("repr(1.5)", f64::from_bits(0x3ff8000000000000), "1.5"),
        ("repr(0.1)", f64::from_bits(0x3fb999999999999a), "0.1"),
        ("repr(0.0001)", f64::from_bits(0x3f1a36e2eb1c432d), "0.0001"),
        ("repr(1e-05)", f64::from_bits(0x3ee4f8b588e368f1), "1e-05"),
        ("repr(1.5e-07)", f64::from_bits(0x3e8421f5f40d8376), "1.5e-07"),
        ("repr(1000000000000000.0)", f64::from_bits(0x430c6bf526340000), "1000000000000000.0"),
        ("repr(1e+16)", f64::from_bits(0x4341c37937e08000), "1e+16"),
        ("repr(9999999999999998.0)", f64::from_bits(0x4341c37937e07fff), "9999999999999998.0"),
        ("repr(1.2345678901234568e+17)", f64::from_bits(0x437b69b4ba630f35), "1.2345678901234568e+17"),
        ("repr(1e+22)", f64::from_bits(0x4480f0cf064dd592), "1e+22"),
        ("repr(5e-324)", f64::from_bits(0x0000000000000001), "5e-324"),
        ("repr(1.7976931348623157e+308)", f64::from_bits(0x7fefffffffffffff), "1.7976931348623157e+308"),
        ("repr(-2.5)", f64::from_bits(0xc004000000000000), "-2.5"),
        ("repr(0.3333333333333333)", f64::from_bits(0x3fd5555555555555), "0.3333333333333333"),
        ("repr(9007199254740992.0)", f64::from_bits(0x4340000000000000), "9007199254740992.0"),
        ("repr(0.00030000000000000003)", f64::from_bits(0x3f33a92a30553262), "0.00030000000000000003"),
        ("repr(12345.678)", f64::from_bits(0x40c81cd6c8b43958), "12345.678"),
        ("repr(16074132311784.812)", f64::from_bits(0x42ad3d19e49dd1a0), "16074132311784.812"),
        ("repr(-638608141482010.2)", f64::from_bits(0xc302267c5b63c0d2), "-638608141482010.2"),
        ("repr(2.0 ** -1017)", f64::from_bits(0x0060000000000000), "7.120236347223045e-307"),
        ("repr(float('nan'))", f64::NAN, "nan"),
        ("repr(float('inf'))", f64::INFINITY, "inf"),
        ("repr(float('-inf'))", f64::NEG_INFINITY, "-inf"),
    ];
    for &(expression, value, python) in rows {
        assert_eq!(repr_float(value), python, "{expression}");
    }
}

#[test]
fn round_rounds_the_exact_binary_value_half_to_even() {
    #[rustfmt::skip]
    let rows: &[(&str, f64, &str)] = &[
        ("round(0.0625, 3)", f64::from_bits(0x3fb0000000000000), "0.062"),
        ("round(2.0005, 3)", f64::from_bits(0x4000010624dd2f1b), "2.001"),
        ("round(0.1875, 3)", f64::from_bits(0x3fc8000000000000), "0.188"),
        ("round(0.3125, 3)", f64::from_bits(0x3fd4000000000000), "0.312"),
        ("round(1.0005, 3)", f64::from_bits(0x3ff0020c49ba5e35), "1.0"),
        ("round(2.675, 3)", f64::from_bits(0x4005666666666666), "2.675"),
        ("round(-0.0001, 3)", f64::from_bits(0xbf1a36e2eb1c432d), "-0.0"),
        ("round(-0.0, 3)", f64::from_bits(0x8000000000000000), "-0.0"),
        ("round(0.0005, 3)", f64::from_bits(0x3f40624dd2f1a9fc), "0.001"),
        ("round(1e+308, 3)", f64::from_bits(0x7fe1ccf385ebc8a0), "1e+308"),
        ("round(123.4565, 3)", f64::from_bits(0x405edd374bc6a7f0), "123.457"),
        ("round(-1.0005, 3)", f64::from_bits(0xbff0020c49ba5e35), "-1.0"),
        ("round(5e-324, 3)", f64::from_bits(0x0000000000000001), "0.0"),
        ("round(12345678.9995, 3)", f64::from_bits(0x41678c29dffbe76d), "12345679.0"),
    ];
    for &(expression, value, python) in rows {
        let Some(Value::Float(rounded)) = round(&Value::Float(value), 3) else {
            panic!("{expression} is a float");
        };
        assert_eq!(repr_float(rounded), python, "{expression}");
    }
    let rows: [(&str, Value, Option<Value>); 5] = [
        (
            "round(7, 3)",
            Value::Integer(Integer::from(7_u64)),
            Some(Value::Integer(Integer::from(7_u64))),
        ),
        (
            "round(True, 3)",
            Value::Bool(true),
            Some(Value::Integer(Integer::from(1_u64))),
        ),
        (
            "round(float('inf'), 3)",
            Value::Float(f64::INFINITY),
            Some(Value::Float(f64::INFINITY)),
        ),
        (
            "round('1', 3) raises TypeError",
            Value::String(Text::from("1")),
            None,
        ),
        ("round(None, 3) raises TypeError", Value::Null, None),
    ];
    for (expression, value, python) in rows {
        assert_eq!(round(&value, 3), python, "{expression}");
    }
}

#[test]
fn int_truncates_a_finite_float_toward_zero() {
    let rows: [(&str, f64, &str); 3] = [
        ("int(-2.7)", -2.7, "-2"),
        ("int(1e20)", 1e20, "100000000000000000000"),
        ("int(0.5)", 0.5, "0"),
    ];
    for (expression, value, python) in rows {
        let found = int(&Value::Float(value)).expect("a finite float converts");
        assert_eq!(found.to_string(), python, "{expression}");
    }
    assert!(
        int(&Value::Float(f64::NAN)).is_err(),
        "int(float('nan')) raises ValueError"
    );
    assert!(int(&Value::Null).is_err(), "int(None) raises TypeError");
}

#[test]
fn int_strips_python_int_whitespace_and_refuses_past_the_digit_limit() {
    let rows: [(&str, String, Option<String>); 12] = [
        (
            "int('\\x1c12') raises ValueError",
            "\u{1c}12".to_owned(),
            None,
        ),
        (
            "int('12\\x1f') raises ValueError",
            "12\u{1f}".to_owned(),
            None,
        ),
        (
            "int('\\u300012')",
            "\u{3000}12".to_owned(),
            Some("12".to_owned()),
        ),
        (
            "int('\\x8512')",
            "\u{85}12".to_owned(),
            Some("12".to_owned()),
        ),
        (
            "int(' -1_2 \\u3000')",
            " -1_2 \u{3000}".to_owned(),
            Some("-12".to_owned()),
        ),
        ("int('-007')", "-007".to_owned(), Some("-7".to_owned())),
        ("int('0' * 4301) raises ValueError", "0".repeat(4301), None),
        (
            "int('1_' * 2150 + '1') has 2151 digits",
            format!("{}1", "1_".repeat(2150)),
            Some("1".repeat(2151)),
        ),
        (
            "int('ab' * 3000) raises ValueError",
            "ab".repeat(3000),
            None,
        ),
        (
            "int('1' * 4300 + 'x') raises ValueError",
            format!("{}x", "1".repeat(4300)),
            None,
        ),
        (
            "int('1' * 4301 + '_') raises ValueError",
            format!("{}_", "1".repeat(4301)),
            None,
        ),
        (
            "int(' ' + '1' * 4300 + ' ')",
            format!(" {} ", "1".repeat(4300)),
            Some("1".repeat(4300)),
        ),
    ];
    for (expression, given, python) in rows {
        let found = int(&Value::String(Text::from(given)));
        match python {
            Some(digits) => assert_eq!(
                found.map(|value| value.to_string()),
                Ok(digits),
                "{expression}"
            ),
            None => assert!(found.is_err(), "{expression}"),
        }
    }
    for (expression, digits) in [
        ("round(1.5, 400)", 400),
        ("round(1.5, 2**64 - 1)", usize::MAX),
    ] {
        assert_eq!(
            round(&Value::Float(1.5), digits),
            Some(Value::Float(1.5)),
            "{expression} == 1.5"
        );
    }
}

#[test]
fn int_reports_the_digit_limit_only_for_a_run_of_digits_past_it() {
    #[rustfmt::skip]
    let rows: [(&str, String, bool); 5] = [
        ("int('1' * 4301 + 'x') raises 'Exceeds the limit (4300)'", format!("{}x", "1".repeat(4301)), true),
        ("int('-' + '1' * 4301 + 'x') raises 'Exceeds the limit (4300)'", format!("-{}x", "1".repeat(4301)), true),
        ("int('x' + '1' * 4301) raises 'invalid literal'", format!("x{}", "1".repeat(4301)), false),
        ("int('1 ' * 3000) raises 'invalid literal'", "1 ".repeat(3000), false),
        ("int('1' * 4301 + '__1') raises 'invalid literal'", format!("{}__1", "1".repeat(4301)), false),
    ];
    for (expression, given, limit) in rows {
        let message = int(&Value::String(Text::from(given))).expect_err(expression);
        assert_eq!(message.contains("limit"), limit, "{expression}: {message}");
    }
}

#[test]
fn python_int_reads_the_forms_python_reads() {
    let int = |text: &str| python::int(&parse(text).expect("the value parses"));
    let integer = |negative, digits: &str| Integer::from_digits(negative, digits).expect("digits");
    assert_eq!(int(r#""1_0""#), Ok(integer(false, "10")));
    assert_eq!(int(r#"" +7 ""#), Ok(integer(false, "7")));
    assert_eq!(int(r#""\u00a0-0\u3000""#), Ok(integer(false, "0")));
    assert_eq!(
        int(r#""\t\n\u000b\f\r\u0085 -12\u2028""#),
        Ok(integer(true, "12"))
    );
    assert_eq!(int(r#""007""#), Ok(integer(false, "7")));
    assert_eq!(int("true"), Ok(integer(false, "1")));
    assert_eq!(int("12"), Ok(integer(false, "12")));
    assert_eq!(int("-12"), Ok(integer(true, "12")));
    for refused in [
        r#""1__0""#,
        r#""_1""#,
        r#""1_""#,
        r#""""#,
        r#""0x1""#,
        "[]",
        "{}",
        r#""- 1""#,
    ] {
        assert!(int(refused).is_err(), "{refused}");
    }
    // U+001C to U+001F are white space to `str.isspace()` but stay in the string `int()` reads, so a
    // digit string that carries one at either end is refused.
    for separator in ["\\u001c", "\\u001d", "\\u001e", "\\u001f"] {
        for refused in [format!("\"{separator}5\""), format!("\"5{separator}\"")] {
            assert!(int(&refused).is_err(), "{refused}");
        }
    }
}

#[test]
fn python_len_counts_characters_items_and_members() {
    let len = |text: &str| python::len(&parse(text).expect("the value parses"));
    assert_eq!(len(r#""\u00e9a""#), Some(2));
    assert_eq!(len("[1,[2,3]]"), Some(2));
    assert_eq!(len(r#"{"a":1}"#), Some(1));
    assert_eq!(len("7"), None);
    assert_eq!(python::len(&Value::Bool(true)), None);
}

#[test]
fn int_refuses_a_surrogate_at_an_edge_and_a_string_of_spaces_naming_the_whole_text() {
    #[rustfmt::skip]
    let rows: [(&str, &[u32], &str); 4] = [
        ("int('\\ud800 1') raises ValueError", &[0xd800, 0x20, 0x31], "invalid literal for int() with base 10: '\\ud800 1'"),
        ("int(' 1\\udc80') raises ValueError", &[0x20, 0x31, 0xdc80], "invalid literal for int() with base 10: ' 1\\udc80'"),
        ("int('   ') raises ValueError", &[0x20, 0x20, 0x20], "invalid literal for int() with base 10: '   '"),
        ("int('') raises ValueError", &[], "invalid literal for int() with base 10: ''"),
    ];
    for (expression, codes, python) in rows {
        let text =
            Text::from_code_points(codes.iter().copied()).expect("each code is at most U+10FFFF");
        assert_eq!(
            int(&Value::String(text)),
            Err(python.to_owned()),
            "{expression}"
        );
    }
}

#[test]
fn repr_and_str_write_values_as_python_writes_the_loaded_objects() {
    let value = |text: &str| parse(text).expect("the value parses");
    #[rustfmt::skip]
    let rows: [(&str, &str, &str); 4] = [
        (r#"{"a": [1, 2.5, true, null, "x'y"], "b": {}}"#,
         r#"{'a': [1, 2.5, True, None, "x'y"], 'b': {}}"#, r#"{'a': [1, 2.5, True, None, "x'y"], 'b': {}}"#),
        ("[]", "[]", "[]"),
        (r#""\u00e9\n""#, "'\u{e9}\\n'", "\u{e9}\n"),
        ("1e400", "inf", "inf"),
    ];
    for (text, repr, str_of) in rows {
        assert_eq!(python::repr(&value(text)), repr, "{text}");
        assert_eq!(python::str_of(&value(text)), str_of, "{text}");
    }
}

#[test]
fn equal_compares_numbers_by_value_and_objects_by_members() {
    let value = |text: &str| parse(text).expect("the value parses");
    #[rustfmt::skip]
    let rows: [(&str, &str, bool); 8] = [
        ("1", "1.0", true),
        ("1.0", "true", true),
        (r#"{"a": 1, "b": 2}"#, r#"{"b": 2, "a": 1.0}"#, true),
        ("[1]", "[true]", true),
        ("0", "false", true),
        ("2", "2.5", false),
        (r#"{"a": 1}"#, r#"{"a": 1, "b": 2}"#, false),
        (r#""1""#, "1", false),
    ];
    for (left, right, equal) in rows {
        assert_eq!(
            python::equal(&value(left), &value(right)),
            equal,
            "{left} == {right}"
        );
    }
    assert!(!python::equal(
        &Value::Float(f64::NAN),
        &Value::Float(f64::NAN)
    ));
}

#[test]
fn members_iterate_items_keys_and_code_points() {
    let value = |text: &str| parse(text).expect("the value parses");
    let text = |item: &str| Value::String(item.into());
    assert_eq!(
        python::members(&value("[1, 2]")),
        Some(vec![value("1"), value("2")])
    );
    assert_eq!(
        python::members(&value(r#"{"a": 1, "b": 2}"#)),
        Some(vec![text("a"), text("b")])
    );
    assert_eq!(
        python::members(&value(r#""ab""#)),
        Some(vec![text("a"), text("b")])
    );
    assert_eq!(python::members(&value("1")), None);
}

#[test]
fn decimal_reads_digits_of_any_script_up_to_the_limit() {
    let digits = |text: &str| python::decimal(text).map(|integer| integer.to_string());
    assert_eq!(digits("0042"), Ok("42".to_owned()));
    assert_eq!(digits("\u{664}\u{662}"), Ok("42".to_owned()));
    assert_eq!(digits("\u{1d7d7}"), Ok("9".to_owned()));
    assert!(digits("").is_err());
    assert!(digits("4a").is_err());
    assert!(digits(&"1".repeat(4301)).is_err());
    assert_eq!(digits(&"1".repeat(4300)).map(|text| text.len()), Ok(4300));
}
