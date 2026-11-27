use crate::json::{Integer, Text, Value};
use crate::python::{int, repr_float, round};

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
    let rows: [(&str, String, Option<&str>); 6] = [
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
        ("int('\\u300012')", "\u{3000}12".to_owned(), Some("12")),
        ("int('\\x8512')", "\u{85}12".to_owned(), Some("12")),
        ("int('0' * 4301) raises ValueError", "0".repeat(4301), None),
        (
            "int('1_' * 2150 + '1') has 2151 digits",
            format!("{}1", "1_".repeat(2150)),
            Some("1"),
        ),
    ];
    for (expression, given, python) in rows {
        let found = int(&Value::String(Text::from(given)));
        match python {
            Some(digits) => assert!(
                found.is_ok_and(|value| value.to_string().starts_with(digits)),
                "{expression}"
            ),
            None => assert!(found.is_err(), "{expression}"),
        }
    }
    let expression = "round(1.5, 400)";
    assert_eq!(
        round(&Value::Float(1.5), 400),
        Some(Value::Float(1.5)),
        "{expression}"
    );
}
