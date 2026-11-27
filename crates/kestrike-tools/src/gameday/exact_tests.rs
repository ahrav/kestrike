//! Each expected value is the judge's at the base under Python 3.9.25, as the expression beside it gives
//! it.

use super::{Decimal, exact, shown};
use crate::json::{Integer, Value};

fn e(text: &str) -> Decimal {
    exact(&crate::gameday::test_support::value(text)).expect("a finite number")
}

#[test]
fn sums_and_differences_are_exact_across_the_whole_range() {
    let (most, least) = (e("9007199254740992"), e("5e-324"));
    let sum = &most + &least;
    assert_eq!(
        shown(&sum),
        "9007199254740992.0",
        "sh(e(2**53) + e(5e-324))"
    );
    assert_eq!(
        &sum - &most,
        least,
        "e(2**53) + e(5e-324) - e(2**53) == e(5e-324)"
    );
    assert_eq!(
        shown(&(&least - &most)),
        "-9007199254740992.0",
        "sh(e(5e-324) - e(2**53))"
    );
    assert_eq!(
        shown(&(&e("0.1") - &e("0.3"))),
        "-0.2",
        "sh(e(0.1) - e(0.3))"
    );
    assert_eq!(
        shown(&(&e("0.1") + &e("0.2"))),
        "0.3",
        "sh(e(0.1) + e(0.2))"
    );
    assert_eq!(&e("0.5") - &e("0.5"), e("0"), "e(0.5) - e(0.5) == 0");
}

#[test]
fn a_quotient_is_whole_only_from_one_to_the_most() {
    let most = 1_000_000;
    #[rustfmt::skip]
    let rows: &[(&str, (&str, &str), Option<u32>)] = &[
        ("e(0.3) / e(0.1) == Fraction(3, 1)", ("0.3", "0.1"), Some(3)),
        ("e(1) / e(3) == Fraction(1, 3)", ("1", "3"), None),
        ("e(0.0003) / e(3e-10) == Fraction(1000000, 1)", ("0.0003", "3e-10"), Some(most)),
        ("e(2000000) / e(1) == Fraction(2000000, 1)", ("2000000", "1"), None),
        ("e(0) / e(1) == Fraction(0, 1)", ("0", "1"), None),
        ("e(-3) / e(1) == Fraction(-3, 1)", ("-3", "1"), None),
        ("e(-3) / e(-1) == Fraction(3, 1)", ("-3", "-1"), Some(3)),
        ("e(1) / e(2) == Fraction(1, 2)", ("1", "2"), None),
        ("e(1) / e(1) == Fraction(1, 1)", ("1", "1"), Some(1)),
        ("e(1000001) / e(1) == Fraction(1000001, 1)", ("1000001", "1"), None),
        ("e(1.5e300) / e(1.5e300) == Fraction(1, 1)", ("1.5e300", "1.5e300"), Some(1)),
    ];
    for &(expression, (dividend, divisor), quotient) in rows {
        assert_eq!(
            e(dividend).whole_quotient(&e(divisor), most),
            quotient,
            "{expression}"
        );
    }
    assert_eq!(
        (&e("20.5") - &e("10")).whole_quotient(&e("0.1"), most),
        Some(105),
        "(e(20.5) - e(10)) / e(0.1)"
    );
    // The judge divides by no zero, which its positive interval rules out; the library gives `None`.
    assert_eq!(
        e("8589934592").whole_quotient(&e("1"), u32::MAX),
        None,
        "a quotient past the largest bound a u32 holds"
    );
    assert_eq!(
        e("4294967295").whole_quotient(&e("1"), u32::MAX),
        Some(u32::MAX)
    );
    assert_eq!(e("1").whole_quotient(&e("0"), most), None, "a zero divisor");
}

#[test]
fn shown_writes_a_whole_number_as_digits_and_any_other_as_its_nearest_double() {
    #[rustfmt::skip]
    let rows: &[(&str, &str, &str)] = &[
        ("sh(e(7))", "7", "7"),
        ("sh(e(-7))", "-7", "-7"),
        ("sh(e(0.5))", "0.5", "0.5"),
        ("sh(e(-2.5))", "-2.5", "-2.5"),
        ("sh(e(1e16))", "1e16", "10000000000000000"),
        ("sh(e(0))", "0", "0"),
        ("sh(e(-0.0))", "-0.0", "0"),
        ("sh(e(1e-7))", "1e-7", "1e-07"),
    ];
    for &(expression, number, written) in rows {
        assert_eq!(shown(&e(number)), written, "{expression}");
    }
    let large = shown(&e("1.5e300"));
    assert_eq!((large.len(), &large[..2]), (301, "15"), "sh(e(1.5e300))");
}

#[test]
fn decimals_order_by_value() {
    assert!(e("0.1") < e("0.2"), "e(0.1) < e(0.2)");
    assert_eq!(
        e("9007199254740992"),
        e("9007199254740992.0"),
        "e(2**53) == e(9007199254740992.0)"
    );
    assert_eq!(e("-0.0"), e("0"), "e(-0.0) == e(0)");
    assert!(e("-1") < e("-0.5"), "e(-1) < e(-0.5)");
    assert!(
        e("1e16") > e("9999999999999998.0"),
        "e(1e16) > e(9999999999999998.0)"
    );
    assert!(e("-0.5") < e("0"), "e(-0.5) < e(0)");
    assert!(e("100") > e("99.99"), "e(100) > e(99.99)");
}

/// The library's own contract: the judge calls `exact` only on numbers its schema checked, and on a
/// boolean or a NaN it would give `Fraction(1, 1)` or raise.
#[test]
fn exact_takes_finite_numbers_only() {
    assert_eq!(exact(&Value::Float(f64::NAN)), None);
    assert_eq!(exact(&Value::Bool(true)), None);
    assert_eq!(
        exact(&Value::Integer(Integer::from(12_u64))),
        Some(Decimal::from_integer(&Integer::from(12_u64)))
    );
}
