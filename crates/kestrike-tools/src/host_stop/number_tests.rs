use std::cmp::Ordering;

use super::Number;
use crate::json::parse;

fn of(text: &str) -> Option<Number> {
    Number::of(&parse(text).expect("JSON"))
}

/// An integer and a float compare by exact value, also where the integer has no double of its own.
#[test]
fn an_integer_and_a_float_compare_by_exact_value() {
    let cases = [
        (
            Number::from(100),
            Number::from(100.0),
            Some(Ordering::Equal),
        ),
        (Number::from(100), Number::from(100.5), Some(Ordering::Less)),
        (Number::from(-1), Number::from(-0.5), Some(Ordering::Less)),
        (Number::from(0), Number::from(-0.0), Some(Ordering::Equal)),
        (
            Number::from(9_007_199_254_740_993),
            Number::from(9_007_199_254_740_992.0),
            Some(Ordering::Greater),
        ),
        (
            Number::from(i64::MAX),
            Number::from(9_223_372_036_854_775_808.0),
            Some(Ordering::Less),
        ),
        (
            Number::from(i64::MIN),
            Number::from(-9_223_372_036_854_775_808.0),
            Some(Ordering::Equal),
        ),
        (Number::from(1), Number::from(f64::NAN), None),
    ];
    for (integer, float, order) in cases {
        assert_eq!(
            integer.partial_cmp(&float),
            order,
            "{integer} against {float}"
        );
        assert_eq!(
            float.partial_cmp(&integer),
            order.map(Ordering::reverse),
            "{float} against {integer}"
        );
    }
}

/// A sum or a difference of two integers stays an integer; one with a float is a float.
#[test]
fn a_sum_keeps_the_kind_python_gives_it() {
    let shown = |number: Number| number.to_string();
    assert_eq!(shown(Number::from(60).plus(Number::from(45))), "105");
    assert_eq!(shown(Number::from(104.0).plus(Number::from(300))), "404.0");
    assert_eq!(shown(Number::from(104.2).minus(Number::from(60))), "44.2");
    assert_eq!(shown(Number::from(10).minus(Number::from(0.5))), "9.5");
    assert_eq!(shown(Number::from(1e16)), "1e+16");
}

/// A JSON number of at most 2^53 in magnitude reads as its kind; a boolean and a larger number read
/// as none.
#[test]
fn a_json_number_of_the_layout_reads_as_its_kind() {
    assert_eq!(
        of("9007199254740992").map(|n| n.to_string()),
        Some("9007199254740992".into())
    );
    assert_eq!(of("-7").map(|n| n.to_string()), Some("-7".into()));
    assert_eq!(of("2.5").map(|n| n.to_string()), Some("2.5".into()));
    assert!(of("9007199254740993").is_none());
    assert!(of("true").is_none());
    assert!(of("\"1\"").is_none());
    assert_eq!(Number::from(-7).value(), parse("-7").expect("JSON"));
    assert_eq!(Number::from(2.5).value(), parse("2.5").expect("JSON"));
}
