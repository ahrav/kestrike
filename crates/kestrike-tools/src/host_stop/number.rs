//! A time or a duration keeps the kind Python gives it: an integer read from a file stays an integer, a
//! clock's reading is a float, a sum with a float is a float, and an integer compares with a float by
//! exact value. `Display` writes an integer's digits and a float's shortest form, as Python's `str`
//! does.

use std::cmp::Ordering;
use std::fmt;

use crate::gameday::finite;
use crate::json::{Integer, Value};
use crate::python::repr_float;

/// `Number` is an integer or a float, as a JSON number or a clock reading holds it. An integer is held
/// in an `i128`, so a sum or a difference of integers stays exact while its result fits an `i128`.
#[derive(Clone, Copy, Debug)]
pub struct Number(Kind);

#[derive(Clone, Copy, Debug)]
enum Kind {
    Integer(i128),
    Float(f64),
}

impl Number {
    /// `of` is the number a JSON value holds when it is a number of at most 2^53 in magnitude, which
    /// a boolean is not.
    pub fn of(value: &Value) -> Option<Self> {
        if !finite(value) {
            return None;
        }
        match value {
            Value::Integer(integer) => integer
                .to_string()
                .parse::<i64>()
                .ok()
                .map(|integer| Self(Kind::Integer(i128::from(integer)))),
            Value::Float(float) => Some(Self(Kind::Float(*float))),
            _ => None,
        }
    }

    /// `value` is the JSON number of the same kind and value.
    pub fn value(self) -> Value {
        match self.0 {
            Kind::Integer(integer) => {
                let digits = integer.unsigned_abs().to_string();
                Value::Integer(
                    Integer::from_digits(integer < 0, &digits).expect("an i128 has few digits"),
                )
            }
            Kind::Float(float) => Value::Float(float),
        }
    }

    /// `plus` is the sum Python makes: exact for two integers, else in floats.
    ///
    /// # Panics
    ///
    /// When both are integers and their exact sum lies outside the range of an `i128`. An operand may
    /// already lie outside an `i64`; a float operand makes the sum in floats, which does not panic.
    #[must_use]
    pub fn plus(self, other: Self) -> Self {
        match (self.0, other.0) {
            (Kind::Integer(a), Kind::Integer(b)) => Self(Kind::Integer(
                a.checked_add(b)
                    .expect("the exact integer sum fits an i128"),
            )),
            _ => Self(Kind::Float(self.float() + other.float())),
        }
    }

    /// `minus` is the difference Python makes: exact for two integers, else in floats.
    ///
    /// # Panics
    ///
    /// When both are integers and their exact difference lies outside the range of an `i128`.
    #[must_use]
    pub fn minus(self, other: Self) -> Self {
        match (self.0, other.0) {
            (Kind::Integer(a), Kind::Integer(b)) => Self(Kind::Integer(
                a.checked_sub(b)
                    .expect("the exact integer difference fits an i128"),
            )),
            _ => Self(Kind::Float(self.float() - other.float())),
        }
    }

    /// The nearest float, ties to even, as Python converts an integer in a sum with a float.
    fn float(self) -> f64 {
        match self.0 {
            Kind::Integer(integer) => integer as f64,
            Kind::Float(float) => float,
        }
    }
}

impl From<f64> for Number {
    fn from(float: f64) -> Self {
        Self(Kind::Float(float))
    }
}

impl From<i64> for Number {
    fn from(integer: i64) -> Self {
        Self(Kind::Integer(i128::from(integer)))
    }
}

/// The order of an integer and a float by their exact values; `None` for a NaN.
fn integer_against_float(integer: i128, float: f64) -> Option<Ordering> {
    /// 2^127, the least float past every `i128`.
    const PAST: f64 = 170_141_183_460_469_231_731_687_303_715_884_105_728.0;
    if float.is_nan() {
        return None;
    }
    if float >= PAST {
        return Some(Ordering::Less);
    }
    if float < -PAST {
        return Some(Ordering::Greater);
    }
    let whole = float.trunc();
    // `whole` lies in the range of an i128 and has no fraction, so the conversion is exact.
    match integer.cmp(&(whole as i128)) {
        Ordering::Equal => 0.0_f64.partial_cmp(&(float - whole)),
        unequal => Some(unequal),
    }
}

impl PartialEq for Number {
    fn eq(&self, other: &Self) -> bool {
        self.partial_cmp(other) == Some(Ordering::Equal)
    }
}

impl PartialOrd for Number {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (self.0, other.0) {
            (Kind::Integer(a), Kind::Integer(b)) => Some(a.cmp(&b)),
            (Kind::Float(a), Kind::Float(b)) => a.partial_cmp(&b),
            (Kind::Integer(a), Kind::Float(b)) => integer_against_float(a, b),
            (Kind::Float(a), Kind::Integer(b)) => {
                integer_against_float(b, a).map(Ordering::reverse)
            }
        }
    }
}

impl fmt::Display for Number {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Kind::Integer(integer) => write!(f, "{integer}"),
            Kind::Float(float) => f.write_str(&repr_float(float)),
        }
    }
}

#[cfg(test)]
#[path = "number_tests.rs"]
mod tests;
