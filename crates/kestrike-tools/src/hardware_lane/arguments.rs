use super::constants::is_episode_name;
use super::refusal::Refusal;
use crate::text::{Text, text};

pub const PLATFORM_NAMED_BY: &str = "--platform or KESTRIKE_HARDWARE_PLATFORM";

pub fn episode_name(name: &Text) -> Result<&Text, Refusal> {
    if is_episode_name(name) {
        Ok(name)
    } else {
        Err(Refusal::new(text!(
            name.repr(),
            " is not an episode name of letters, digits, '.', '_' and '-' starting with a letter or digit"
        )))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecondsError {
    NoNumber,
    Refused(Refusal),
}

pub fn finite_seconds(seconds: &Text) -> Result<f64, SecondsError> {
    let value = seconds
        .strip()
        .to_str()
        .and_then(|number| number.parse::<f64>().ok())
        .ok_or(SecondsError::NoNumber)?;
    if !value.is_finite() || value < 0.0 {
        return Err(SecondsError::Refused(Refusal::new(text!(
            seconds.repr(),
            " is not a finite duration of zero or more seconds"
        ))));
    }
    Ok(value)
}

pub fn platform_refusal(name: Option<&Text>, named_by: &str) -> Refusal {
    let named = match name {
        None => Text::from("no platform row named"),
        Some(name) => text!("no platform row ", name.repr()),
    };
    Refusal::new(text!(named, "; name the host's row with ", named_by))
}
