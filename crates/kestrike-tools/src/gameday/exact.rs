//! The judge's exact value of a JSON number, and the text of a time, a duration or a count.

use crate::decimal::Decimal;
use crate::json::Value;
use crate::python::repr_float;

/// `exact` is the decimal value of a JSON number: an integer's own value, or the value of a float's
/// shortest form. A non-finite float and a value of another type give `None`.
pub fn exact(value: &Value) -> Option<Decimal> {
    match value {
        Value::Integer(integer) => Some(Decimal::from_integer(integer)),
        Value::Float(float) => Decimal::from_float(*float),
        _ => None,
    }
}

/// `shown` writes a time, a duration or a count: a whole number as its digits, any other value as the
/// shortest form of its nearest double. A value past the largest double writes `inf` or `-inf`.
pub fn shown(value: &Decimal) -> String {
    value
        .whole_digits()
        .unwrap_or_else(|| repr_float(value.nearest()))
}

#[cfg(test)]
#[path = "exact_tests.rs"]
mod tests;
