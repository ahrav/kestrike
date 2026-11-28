//! Each row's judge column is the result of the judge's own function at the base under Python 3.9.25, as
//! the expression beside it gives it; the tool column holds the tool's words where the judge's come from
//! the interpreter.

use super::{decode, parsed};
use crate::python::repr;
use crate::text::Text;

/// `ours` is the tool's text for the judge's `judged`: the judge's words for its own three checks without
/// the exception's wrapper, else the row's own tool text, which keeps the judge's words up to the reason.
fn ours(judged: &str, tool: Option<&'static str>) -> String {
    if let Some(tool) = tool {
        let fixed = |text: &str| {
            let at = text.find(" is not ").expect("a decoding refusal");
            let colon = text[at..].find(": ").expect("a reason follows") + at + 2;
            text[..colon].to_owned()
        };
        assert_eq!(fixed(judged), fixed(tool), "the fixed part of {judged}");
        return tool.to_owned();
    }
    for wrapper in ["ValueError('", "ValueError(\""] {
        if let Some((head, rest)) = judged.split_once(wrapper) {
            return format!("{head}{}", &rest[..rest.len() - 2]);
        }
    }
    judged.to_owned()
}

fn shown(result: Result<crate::json::Value, super::Refusal>) -> Result<String, String> {
    result
        .map(|value| repr(&value))
        .map_err(|refusal| refusal.to_string())
}

type Judged = Result<&'static str, &'static str>;
/// An expression, its text, the judge's result, and the tool's words where they differ.
type Decoded = (&'static str, &'static str, Judged, Option<&'static str>);
/// An expression, its bytes, the file's name, the judge's result, and the tool's words where they differ.
type Parsed = (
    &'static str,
    &'static [u8],
    &'static str,
    Judged,
    Option<&'static str>,
);

#[test]
fn decode_reads_strict_json_and_refuses_the_first_defect_in_document_order() {
    #[rustfmt::skip]
    let rows: &[Decoded] = &[
    (r#"decode('0.1', 'f')"#, r#"0.1"#, Ok(r#"0.1"#), None),
    (r#"decode('1E2', 'f')"#, r#"1E2"#, Ok(r#"100.0"#), None),
    (r#"decode('-0', 'f')"#, r#"-0"#, Ok(r#"0"#), None),
    (r#"decode('-0.0', 'f')"#, r#"-0.0"#, Ok(r#"-0.0"#), None),
    (r#"decode('5e-324', 'f')"#, r#"5e-324"#, Ok(r#"5e-324"#), None),
    (r#"decode('1.7976931348623157e308', 'f')"#, r#"1.7976931348623157e308"#, Ok(r#"1.7976931348623157e+308"#), None),
    (r#"decode('0e400', 'f')"#, r#"0e400"#, Ok(r#"0.0"#), None),
    (r#"decode('100e-2', 'f')"#, r#"100e-2"#, Ok(r#"1.0"#), None),
    (r#"decode('1e999', 'f')"#, r#"1e999"#, Err(r#"f is not strict JSON: ValueError("the number 1e999 is beyond a double's range")"#), None),
    (r#"decode('9007199254740993.0', 'f')"#, r#"9007199254740993.0"#, Err(r#"f is not strict JSON: ValueError('the number 9007199254740993.0 holds more digits than a double carries')"#), None),
    (r#"decode('1e-99999', 'f')"#, r#"1e-99999"#, Err(r#"f is not strict JSON: ValueError('the number 1e-99999 holds more digits than a double carries')"#), None),
    (r#"decode('0.10000000000000001', 'f')"#, r#"0.10000000000000001"#, Err(r#"f is not strict JSON: ValueError('the number 0.10000000000000001 holds more digits than a double carries')"#), None),
    (r#"decode('4e-324', 'f')"#, r#"4e-324"#, Err(r#"f is not strict JSON: ValueError('the number 4e-324 holds more digits than a double carries')"#), None),
    (r#"decode('0e1000000000000000000', 'f')"#, r#"0e1000000000000000000"#, Err(r#"f is not strict JSON: InvalidOperation([<class 'decimal.InvalidOperation'>])"#), Some(r#"f is not strict JSON: the number 0e1000000000000000000 holds more digits than a double carries"#)),
    (r#"decode('0.0e-1999999999999999998', 'f')"#, r#"0.0e-1999999999999999998"#, Err(r#"f is not strict JSON: InvalidOperation([<class 'decimal.InvalidOperation'>])"#), Some(r#"f is not strict JSON: the number 0.0e-1999999999999999998 holds more digits than a double carries"#)),
    (r#"decode('NaN', 'f')"#, r#"NaN"#, Err(r#"f is not strict JSON: ValueError('the constant NaN is no number')"#), None),
    (r#"decode('Infinity', 'f')"#, r#"Infinity"#, Err(r#"f is not strict JSON: ValueError('the constant Infinity is no number')"#), None),
    (r#"decode('-Infinity', 'f')"#, r#"-Infinity"#, Err(r#"f is not strict JSON: ValueError('the constant -Infinity is no number')"#), None),
    (r#"decode('{"a": 1, "a": 2}', 'f')"#, r#"{"a": 1, "a": 2}"#, Err(r#"f is not strict JSON: ValueError('an object repeats a key')"#), None),
    (r#"decode('[{"a": 1, "a": 2}, NaN]', 'f')"#, r#"[{"a": 1, "a": 2}, NaN]"#, Err(r#"f is not strict JSON: ValueError('an object repeats a key')"#), None),
    (r#"decode('{"a": 1, "a": NaN}', 'f')"#, r#"{"a": 1, "a": NaN}"#, Err(r#"f is not strict JSON: ValueError('the constant NaN is no number')"#), None),
    (r#"decode('[1e999, {"a": 1, "a": 2}]', 'f')"#, r#"[1e999, {"a": 1, "a": 2}]"#, Err(r#"f is not strict JSON: ValueError("the number 1e999 is beyond a double's range")"#), None),
    (r#"decode('{"k": {"a": 1, "a": 2}, "k": 3}', 'f')"#, r#"{"k": {"a": 1, "a": 2}, "k": 3}"#, Err(r#"f is not strict JSON: ValueError('an object repeats a key')"#), None),
    (r#"decode('"\\ud800"', 'f')"#, r#""\ud800""#, Ok(r#"'\ud800'"#), None),
    (r#"decode('"\\ud83d\\ude00"', 'f')"#, r#""\ud83d\ude00""#, Ok(r#"'😀'"#), None),
    (r#"decode('{"b": [1, 2.5, true, null], "a": "x"}', 'f')"#, r#"{"b": [1, 2.5, true, null], "a": "x"}"#, Ok(r#"{'b': [1, 2.5, True, None], 'a': 'x'}"#), None),
    (r#"decode('[1,]', 'f')"#, r#"[1,]"#, Err(r#"f is not strict JSON: JSONDecodeError('Expecting value: line 1 column 4 (char 3)')"#), Some(r#"f is not strict JSON: expected a value at byte 3"#)),
    (r#"decode('01', 'f')"#, r#"01"#, Err(r#"f is not strict JSON: JSONDecodeError('Extra data: line 1 column 2 (char 1)')"#), Some(r#"f is not strict JSON: text after the value at byte 1"#)),
    (r#"decode('', 'f')"#, r#""#, Err(r#"f is not strict JSON: JSONDecodeError('Expecting value: line 1 column 1 (char 0)')"#), Some(r#"f is not strict JSON: expected a value at byte 0"#)),
        (r#"decode('0e999999999999999999', 'f')"#, r#"0e999999999999999999"#, Ok(r#"0.0"#), None),
        (r#"decode('0e-1999999999999999997', 'f')"#, r#"0e-1999999999999999997"#, Ok(r#"0.0"#), None),
        (r#"decode('0.000e-1999999999999999994', 'f')"#, r#"0.000e-1999999999999999994"#, Ok(r#"0.0"#), None),
        (r#"decode('0.000e-1999999999999999995', 'f')"#, r#"0.000e-1999999999999999995"#, Err(r#"f is not strict JSON: InvalidOperation([<class 'decimal.InvalidOperation'>])"#), Some(r#"f is not strict JSON: the number 0.000e-1999999999999999995 holds more digits than a double carries"#)),
        (r#"decode('0e10000000000000000000000000000000000000000', 'f')"#, r#"0e10000000000000000000000000000000000000000"#, Err(r#"f is not strict JSON: InvalidOperation([<class 'decimal.InvalidOperation'>])"#), Some(r#"f is not strict JSON: the number 0e10000000000000000000000000000000000000000 holds more digits than a double carries"#)),
        (r#"decode('0e-10000000000000000000000000000000000000000', 'f')"#, r#"0e-10000000000000000000000000000000000000000"#, Err(r#"f is not strict JSON: InvalidOperation([<class 'decimal.InvalidOperation'>])"#), Some(r#"f is not strict JSON: the number 0e-10000000000000000000000000000000000000000 holds more digits than a double carries"#)),
        (r#"decode('1e10000000000000000000000000000000000000000', 'f')"#, r#"1e10000000000000000000000000000000000000000"#, Err(r#"f is not strict JSON: ValueError("the number 1e10000000000000000000000000000000000000000 is beyond a double's range")"#), None),
        (r#"decode('1e-10000000000000000000000000000000000000000', 'f')"#, r#"1e-10000000000000000000000000000000000000000"#, Err(r#"f is not strict JSON: InvalidOperation([<class 'decimal.InvalidOperation'>])"#), Some(r#"f is not strict JSON: the number 1e-10000000000000000000000000000000000000000 holds more digits than a double carries"#)),
        (r#"decode('-1e-400', 'f')"#, r#"-1e-400"#, Err(r#"f is not strict JSON: ValueError('the number -1e-400 holds more digits than a double carries')"#), None),
    ];
    for &(expression, text, judged, tool) in rows {
        let found = shown(decode(text, &Text::from("f")));
        let expected = judged
            .map(str::to_owned)
            .map_err(|judged| ours(judged, tool));
        assert_eq!(found, expected, "{expression}");
    }
}

#[test]
fn parsed_reads_a_json_file_as_one_value_and_a_jsonl_file_as_its_lines() {
    #[rustfmt::skip]
    let rows: &[Parsed] = &[
    (r#"parsed(b'', 'a.jsonl')"#, b"", r#"a.jsonl"#, Ok(r#"[]"#), None),
    (r#"parsed(b'{"a": 1}\n[2]\n', 'a.jsonl')"#, b"{\x22a\x22: 1}\x0a[2]\x0a", r#"a.jsonl"#, Ok(r#"[{'a': 1}, [2]]"#), None),
    (r#"parsed(b'{"a": 1}', 'a.jsonl')"#, b"{\x22a\x22: 1}", r#"a.jsonl"#, Err(r#"a.jsonl ends in a line with no newline: it may be truncated"#), None),
    (r#"parsed(b'{"a": 1}\n\n', 'a.jsonl')"#, b"{\x22a\x22: 1}\x0a\x0a", r#"a.jsonl"#, Err(r#"a.jsonl line 2 is not strict JSON: JSONDecodeError('Expecting value: line 1 column 1 (char 0)')"#), Some(r#"a.jsonl line 2 is not strict JSON: expected a value at byte 0"#)),
    (r#"parsed(b'1\nNaN\n', 'a.jsonl')"#, b"1\x0aNaN\x0a", r#"a.jsonl"#, Err(r#"a.jsonl line 2 is not strict JSON: ValueError('the constant NaN is no number')"#), None),
    (r#"parsed(b'1\r\n', 'a.jsonl')"#, b"1\x0d\x0a", r#"a.jsonl"#, Ok(r#"[1]"#), None),
    (r#"parsed(b'[1]\n', 'a.json')"#, b"[1]\x0a", r#"a.json"#, Ok(r#"[1]"#), None),
    (r#"parsed(b'', 'a.json')"#, b"", r#"a.json"#, Err(r#"a.json is not strict JSON: JSONDecodeError('Expecting value: line 1 column 1 (char 0)')"#), Some(r#"a.json is not strict JSON: expected a value at byte 0"#)),
    (r#"parsed(b'\xff', 'a.json')"#, b"\xff", r#"a.json"#, Err(r#"a.json is not UTF-8: 'utf-8' codec can't decode byte 0xff in position 0: invalid start byte"#), Some(r#"a.json is not UTF-8: invalid utf-8 sequence of 1 bytes from index 0"#)),
    (r#"parsed(b'"\xed\xa0\x80"', 'a.json')"#, b"\x22\xed\xa0\x80\x22", r#"a.json"#, Err(r#"a.json is not UTF-8: 'utf-8' codec can't decode byte 0xed in position 1: invalid continuation byte"#), Some(r#"a.json is not UTF-8: invalid utf-8 sequence of 1 bytes from index 1"#)),
    (r#"parsed(b'x\n1', 'a.jsonl')"#, b"x\x0a1", r#"a.jsonl"#, Err(r#"a.jsonl ends in a line with no newline: it may be truncated"#), None),
    (r#"parsed(b'\xff\n1', 'a.jsonl')"#, b"\xff\x0a1", r#"a.jsonl"#, Err(r#"a.jsonl is not UTF-8: 'utf-8' codec can't decode byte 0xff in position 0: invalid start byte"#), Some(r#"a.jsonl is not UTF-8: invalid utf-8 sequence of 1 bytes from index 0"#)),
    (r#"parsed(b'\n', 'a.jsonl')"#, b"\x0a", r#"a.jsonl"#, Err(r#"a.jsonl line 1 is not strict JSON: JSONDecodeError('Expecting value: line 1 column 1 (char 0)')"#), Some(r#"a.jsonl line 1 is not strict JSON: expected a value at byte 0"#)),
    (r#"parsed(b'1\n\xc3\n', 'a.jsonl')"#, b"1\x0a\xc3\x0a", r#"a.jsonl"#, Err(r#"a.jsonl is not UTF-8: 'utf-8' codec can't decode byte 0xc3 in position 2: invalid continuation byte"#), Some(r#"a.jsonl is not UTF-8: invalid utf-8 sequence of 1 bytes from index 2"#)),
    ];
    for &(expression, data, rel, judged, tool) in rows {
        let found = shown(parsed(data, &Text::from(rel)));
        let expected = judged
            .map(str::to_owned)
            .map_err(|judged| ours(judged, tool));
        assert_eq!(found, expected, "{expression}");
    }
}

/// A sweep over fixed-seed bit patterns: every finite double's shortest form reads back as that double,
/// and the same form with a digit added past the seventeenth significant one is refused, since no shortest
/// form holds that many. The SHA-256 of the forms, each followed by a newline, is that of Python 3.9.25's
/// `repr` of the same 20,000 doubles (the same sequence, each read as `struct.unpack('<d', ...)`, with
/// non-finite values and both zeros passed over).
#[test]
fn strict_json_takes_each_shortest_form_and_refuses_one_digit_more() {
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    let mut checked = 0;
    let mut forms = String::new();
    while checked < 20_000 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let value = f64::from_bits(state);
        if !value.is_finite() || value == 0.0 {
            continue;
        }
        let shortest = crate::python::repr_float(value);
        forms.push_str(&shortest);
        forms.push('\n');
        let read = decode(&shortest, &Text::from("f")).expect("a shortest form is strict JSON");
        assert_eq!(read, crate::json::Value::Float(value), "{shortest}");
        let (mantissa, power) = shortest
            .split_once('e')
            .map_or((shortest.as_str(), ""), |(m, p)| (m, p));
        let point = if mantissa.contains('.') { "" } else { "." };
        let power = if power.is_empty() {
            String::new()
        } else {
            format!("e{power}")
        };
        let longer = format!("{mantissa}{point}00000000000000000001{power}");
        let refused = decode(&longer, &Text::from("f")).map_err(|refusal| refusal.to_string());
        let words = format!(
            "f is not strict JSON: the number {longer} holds more digits than a double carries"
        );
        assert_eq!(refused, Err(words));
        checked += 1;
    }
    assert_eq!(
        crate::python::hexdigest(forms.as_bytes()),
        "83c7f7939c6873af92a9f38234fcbbcf67646e53d87b075a890170ed022be6ff",
        "hashlib.sha256(''.join(repr(v) + '\\n' for v in values).encode()).hexdigest()"
    );
}

/// Tokens whose run of digits and exponent cancel: the judge reads the first two as 1.0, and the third,
/// whose value is 10^589824, as past a double's range.
#[test]
fn a_long_mantissa_and_an_exponent_that_cancel_read_as_the_value_they_spell() {
    let small = format!("0.{}1e655360", "0".repeat(655_359));
    let large = format!("1{}e-655360", "0".repeat(655_360));
    let past = format!("0.{}1e655360", "0".repeat(65_535));
    let f = Text::from("f");
    assert_eq!(
        decode(&small, &f),
        Ok(crate::json::Value::Float(1.0)),
        "decode('0.' + '0' * 655359 + '1e655360', 'f')"
    );
    assert_eq!(
        decode(&large, &f),
        Ok(crate::json::Value::Float(1.0)),
        "decode('1' + '0' * 655360 + 'e-655360', 'f')"
    );
    assert_eq!(
        decode(&past, &f).map_err(|refusal| refusal.to_string()),
        Err(format!(
            "f is not strict JSON: the number {past} is beyond a double's range"
        )),
        "decode('0.' + '0' * 65535 + '1e655360', 'f')"
    );
}
