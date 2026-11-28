//! The scan reads a run of decimal digits and underscores with the library's digit rules, and a run of more
//! than [`crate::json::MAX_INTEGER_DIGITS`] digits as [`Failure::Digits`].

use crate::json::Integer;
use crate::python::{DigitsError, int_digits};

use super::Failure;

/// `integer` reads `digits`, decimal digits and underscores, as a nonnegative integer.
///
/// # Errors
///
/// [`Failure::Digits`] when `digits` holds more than [`crate::json::MAX_INTEGER_DIGITS`] digits, and
/// [`Failure::Refused`] when it holds no digit or a code point that is neither a decimal digit nor `_`.
pub fn integer(digits: &str) -> Result<Integer, Failure> {
    int_digits(digits).map_err(|error| match error {
        DigitsError::TooMany(count) => Failure::Digits(count),
        DigitsError::Empty => Failure::Refused("a run of digits holds no digit".to_owned()),
        DigitsError::NotDecimal(c) => Failure::Refused(format!(
            "a run of digits holds U+{:04X}, which is no decimal digit",
            u32::from(c)
        )),
    })
}
