use crate::json::{Integer, Value, parse};
use crate::python;

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
