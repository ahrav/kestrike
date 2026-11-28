//! The reader of a duration above zero, the pause between polls that every retry loop sleeps before its
//! next call.

use crate::hardware_lane::{Error, finite_seconds};
use crate::text::{Text, text};

/// `positive_seconds` reads a duration above zero as [`finite_seconds`] reads seconds.
///
/// # Errors
///
/// The errors of [`finite_seconds`], then [`Error::Refused`] with the text's repr for zero, `-0.0`
/// included.
pub fn positive_seconds(text: &Text) -> Result<f64, Error> {
    let seconds = finite_seconds(text)?;
    if seconds <= 0.0 {
        return Err(Error::Refused(text!(
            text.repr(),
            " is not a duration above zero"
        )));
    }
    Ok(seconds)
}
