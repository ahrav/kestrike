//! The readers of a run's episode name and seconds values, and the sentence for a platform row the
//! manifest lacks.

use super::constants::is_episode_name;
use super::error::Error;
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

/// `finite_seconds` reads a duration of zero or more seconds, so a wait reaches its timeout path and a
/// budget binds. It strips the code points [`int_space`] holds at both ends and reads the rest in Rust's
/// float syntax, which takes `inf`, `infinity` and `nan` in any case and holds no `_` between digits and no
/// digit outside ASCII.
///
/// # Errors
///
/// [`Error::NoNumber`] for text that spells no float, and [`Error::Refused`] with the text's repr for a
/// value that is not finite or is below 0. `-0.0` is no value below 0.
pub fn finite_seconds(seconds: &Text) -> Result<f64, Error> {
    let codes: Vec<u32> = seconds.code_points().collect();
    let start = codes.iter().position(|&code| !int_space(code));
    let end = codes.iter().rposition(|&code| !int_space(code));
    let number = match (start, end) {
        (Some(start), Some(end)) => Text::from_code_points(codes[start..=end].iter().copied()),
        _ => None,
    };
    let value = number
        .as_ref()
        .and_then(Text::to_str)
        .and_then(|number| number.parse::<f64>().ok())
        .ok_or(Error::NoNumber)?;
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
