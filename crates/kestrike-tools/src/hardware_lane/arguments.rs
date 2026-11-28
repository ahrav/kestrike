//! The readers of a run's episode name and seconds values, and the sentence for a platform row the
//! manifest lacks.

use super::constants::is_episode_name;
use super::error::Error;
use crate::decimal::nearest_double;
use crate::python::int_space;
use crate::text::{Text, text};

/// Where the lane's own command reads a platform row's name.
pub const PLATFORM_NAMED_BY: &str = "--platform or KESTRIKE_HARDWARE_PLATFORM";

/// `episode_name` takes a name that is one whole [`super::EPISODE_NAME`], one plain file name component, so
/// a log named for the episode stays inside its directory.
///
/// # Errors
///
/// [`Error::Refused`] with the name's repr for any other text.
pub fn episode_name(name: &Text) -> Result<&Text, Error> {
    if is_episode_name(name) {
        Ok(name)
    } else {
        Err(Error::Refused(text!(
            name.repr(),
            " is not an episode name of letters, digits, '.', '_' and '-' starting with a letter or digit"
        )))
    }
}

/// `finite_seconds` reads a duration of zero or more seconds. It strips from both ends ASCII space, tab,
/// line feed, vertical tab, form feed and carriage return, and each non-ASCII code point Python's
/// `str.isspace` takes, and parses the rest in Rust's float syntax, where each run of digits consists of
/// ASCII digits alone, beside `inf`, `infinity` and `nan` in any case. A number written in digits reads as
/// the `f64` nearest its decimal value.
///
/// # Errors
///
/// [`Error::NoNumber`] for text that spells no float, and [`Error::Refused`] with the text's repr for a
/// value that is not finite or is below 0. `-0.0` is no value below 0.
pub fn finite_seconds(seconds: &Text) -> Result<f64, Error> {
    let number = seconds
        .to_str()
        .map(|text| text.trim_matches(|code: char| int_space(u32::from(code))))
        .filter(|number| !number.is_empty())
        .ok_or(Error::NoNumber)?;
    let mut value = number.parse::<f64>().map_err(|_| Error::NoNumber)?;
    let unsigned = number.strip_prefix('+').unwrap_or(number);
    let digits = unsigned.strip_prefix('-').unwrap_or(unsigned);
    if digits.starts_with(|code: char| code.is_ascii_digit() || code == '.') {
        value = nearest_double(unsigned);
    }
    if !value.is_finite() || value < 0.0 {
        return Err(Error::Refused(text!(
            seconds.repr(),
            " is not a finite duration of zero or more seconds"
        )));
    }
    Ok(value)
}

/// `platform_refusal` is the refusal for the platform row `name`, or for no name, that the manifest lacks,
/// with `named_by`, the caller's words for where the name comes from, such as [`PLATFORM_NAMED_BY`].
pub fn platform_refusal(name: Option<&Text>, named_by: &str) -> Error {
    let named = match name {
        None => Text::from("no platform row named"),
        Some(name) => text!("no platform row ", name.repr()),
    };
    Error::Refused(text!(named, "; name the host's row with ", named_by))
}

#[cfg(test)]
#[path = "arguments_tests.rs"]
mod tests;
