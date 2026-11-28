//! Seconds as the controller's arithmetic reads a JSON number: a whole number, which `true` and `false`
//! join as 1 and 0, or a float.
//!
//! A sum of whole numbers stays exact up to [`crate::json::MAX_INTEGER_DIGITS`] digits. A sum that a
//! float joins is a float: the whole number converts to the nearest float, half to even, and a whole
//! number past the largest float is [`Error::Overflow`]. A comparison of a whole number with a float is
//! exact, and a comparison with `nan` is false.

use std::cmp::Ordering;

use super::error::Error;
use crate::json::{Integer, Value};

#[derive(Clone, Debug)]
pub(super) enum Seconds {
    Whole(Integer),
    Real(f64),
}

impl Seconds {
    /// The number `value` holds, or none for a string, an array, an object or null.
    pub(super) fn of(value: &Value) -> Option<Self> {
        match value {
            Value::Integer(whole) => Some(Self::Whole(whole.clone())),
            Value::Bool(flag) => Some(Self::Whole(Integer::from(u64::from(*flag)))),
            Value::Float(real) => Some(Self::Real(*real)),
            Value::String(_) | Value::Array(_) | Value::Object(_) | Value::Null => None,
        }
    }

    /// The float nearest the number.
    ///
    /// # Errors
    ///
    /// [`Error::Overflow`] for a whole number that rounds past the largest float.
    pub(super) fn float(&self) -> Result<f64, Error> {
        match self {
            Self::Real(real) => Ok(*real),
            Self::Whole(whole) => whole_float(whole),
        }
    }

    /// The order of the number against `other`, none where either is `nan`.
    pub(super) fn order(&self, other: &Self) -> Option<Ordering> {
        match (self, other) {
            (Self::Whole(left), Self::Whole(right)) => Some(left.cmp(right)),
            (Self::Real(left), Self::Real(right)) => left.partial_cmp(right),
            (Self::Real(left), Self::Whole(right)) => against(*left, right),
            (Self::Whole(left), Self::Real(right)) => against(*right, left).map(Ordering::reverse),
        }
    }

    /// Whether the number is above `other`.
    pub(super) fn exceeds(&self, other: &Self) -> bool {
        self.order(other) == Some(Ordering::Greater)
    }
}

/// `left + right`: exact for two whole numbers, else the sum of their floats.
///
/// # Errors
///
/// [`Error::Overflow`] where a whole number converts to a float past the largest, or where two whole
/// numbers sum past [`crate::json::MAX_INTEGER_DIGITS`] digits, a value past every float.
pub(super) fn plus(left: &Seconds, right: &Seconds) -> Result<Seconds, Error> {
    match (left, right) {
        (Seconds::Whole(left), Seconds::Whole(right)) => {
            whole_sum(&[left, right]).map(Seconds::Whole)
        }
        _ => Ok(Seconds::Real(left.float()? + right.float()?)),
    }
}

/// The exact sum of `terms`.
///
/// The terms are added in an order that keeps each partial sum within the larger of the total and the
/// largest term: while the partial sum is at least zero a negative term comes next, while it is below zero
/// a positive one, and once one sign is used up the partial sums move toward the total. So a partial sum
/// past [`crate::json::MAX_INTEGER_DIGITS`] digits means a total past them.
///
/// # Errors
///
/// [`Error::Overflow`] for a total past [`crate::json::MAX_INTEGER_DIGITS`] digits, a value past every
/// float.
pub(super) fn whole_sum(terms: &[&Integer]) -> Result<Integer, Error> {
    let zero = Integer::from(0u64);
    let (mut below, mut above): (Vec<&Integer>, Vec<&Integer>) =
        terms.iter().partition(|term| **term < &zero);
    let mut total = zero.clone();
    while let Some(term) = if total >= zero {
        below.pop().or_else(|| above.pop())
    } else {
        above.pop().or_else(|| below.pop())
    } {
        total = Integer::sum([&total, term]).ok_or(Error::Overflow)?;
    }
    Ok(total)
}

/// The float nearest `whole`, half to even.
///
/// # Errors
///
/// [`Error::Overflow`] for a whole number that rounds past the largest float.
pub(super) fn whole_float(whole: &Integer) -> Result<f64, Error> {
    let real: f64 = whole
        .to_string()
        .parse()
        .expect("an integer's digits read as a float");
    if real.is_finite() {
        Ok(real)
    } else {
        Err(Error::Overflow)
    }
}

/// The order of the float `real` against the whole number `whole`, none for `nan`. A finite float lies
/// at or above its floor and below the next whole number, so its floor, a whole float whose digits print
/// exactly, decides the order unless the floor equals `whole`.
fn against(real: f64, whole: &Integer) -> Option<Ordering> {
    if real.is_nan() {
        return None;
    }
    if real.is_infinite() {
        return Some(if real > 0.0 {
            Ordering::Greater
        } else {
            Ordering::Less
        });
    }
    let floor = real.floor();
    let digits = format!("{:.0}", floor.abs());
    let floor_whole = Integer::from_digits(floor < 0.0, &digits)
        .expect("a finite float's floor has fewer digits than an integer holds");
    Some(match floor_whole.cmp(whole) {
        Ordering::Equal if real > floor => Ordering::Greater,
        order => order,
    })
}
