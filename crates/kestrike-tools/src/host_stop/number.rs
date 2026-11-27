//! A time or a duration keeps the kind Python gives it: an integer read from a file stays an integer, a
//! clock's reading is a float, a sum with a float is a float, and an integer compares with a float by
//! exact value. `Display` writes an integer's digits and a float's shortest form, as Python's `str`
//! does.

use std::cmp::Ordering;
use std::fmt;

use crate::gameday::finite;
use crate::json::{Integer, Value};
use crate::python::repr_float;

/// `Number` is an integer or a float, as a JSON number or a clock reading holds it.
#[derive(Clone, Copy, Debug)]
pub enum Number {
    Integer(i64),
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
            Value::Integer(integer) => integer.to_string().parse().ok().map(Self::Integer),
            Value::Float(float) => Some(Self::Float(*float)),
            _ => None,
        }
    }

    /// `value` is the JSON number of the same kind and value.
    pub fn value(self) -> Value {
        match self {
            Self::Integer(integer) => {
                let digits = integer.unsigned_abs().to_string();
                Value::Integer(
                    Integer::from_digits(integer < 0, &digits).expect("an i64 has few digits"),
                )
            }
            Self::Float(float) => Value::Float(float),
        }
    }

    /// `plus` is the sum Python makes: exact for two integers, else in floats.
    ///
    /// # Panics
    ///
    /// When the sum of two integers passes an `i64`, which no sum of values of [`Number::of`] and the
    /// controller's constants reaches.
    #[must_use]
    pub fn plus(self, other: Self) -> Self {
        match (self, other) {
            (Self::Integer(a), Self::Integer(b)) => {
                Self::Integer(a.checked_add(b).expect("a sum of two times fits an i64"))
            }
            (a, b) => Self::Float(a.float() + b.float()),
        }
    }

    /// `minus` is the difference Python makes: exact for two integers, else in floats.
    ///
    /// # Panics
    ///
    /// When the difference of two integers passes an `i64`, as [`Number::plus`] states.
    #[must_use]
    pub fn minus(self, other: Self) -> Self {
        match (self, other) {
            (Self::Integer(a), Self::Integer(b)) => Self::Integer(
                a.checked_sub(b)
                    .expect("a difference of two times fits an i64"),
            ),
            (a, b) => Self::Float(a.float() - b.float()),
        }
    }

    /// The nearest float, ties to even, as Python converts an integer in a sum with a float.
    fn float(self) -> f64 {
        match self {
            Self::Integer(integer) => integer as f64,
            Self::Float(float) => float,
        }
    }
}

impl From<f64> for Number {
    fn from(float: f64) -> Self {
        Self::Float(float)
    }
}

impl From<i64> for Number {
    fn from(integer: i64) -> Self {
        Self::Integer(integer)
    }
}

/// The order of an integer and a float by their exact values; `None` for a NaN.
fn integer_against_float(integer: i64, float: f64) -> Option<Ordering> {
    const PAST: f64 = 9_223_372_036_854_775_808.0;
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
    // `whole` lies in the range of an i64 and has no fraction, so the conversion is exact.
    match integer.cmp(&(whole as i64)) {
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
        match (*self, *other) {
            (Self::Integer(a), Self::Integer(b)) => Some(a.cmp(&b)),
            (Self::Float(a), Self::Float(b)) => a.partial_cmp(&b),
            (Self::Integer(a), Self::Float(b)) => integer_against_float(a, b),
            (Self::Float(a), Self::Integer(b)) => {
                integer_against_float(b, a).map(Ordering::reverse)
            }
        }
    }
}

impl fmt::Display for Number {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Integer(integer) => write!(f, "{integer}"),
            Self::Float(float) => f.write_str(&repr_float(*float)),
        }
    }
}

#[cfg(test)]
#[path = "number_tests.rs"]
mod tests;
