//! Replay and reduction result lines. Each form supplies one terminated line
//! whose marker and fields determine its worker verdict.

use super::{
    Error,
    pairs::{Pairs, count, owned},
};

/// The replay worker’s verdict. The launcher compares its bundle independently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayResult {
    Reproduced(String),
    Diverged { at: Option<u64>, reason: String },
    Panicked(String),
}
impl ReplayResult {
    pub fn agrees(&self, summary: &super::Summary) -> bool {
        let Self::Reproduced(claim) = self else {
            return true;
        };
        let terminal = summary.terminal.to_string();
        let breach = summary.cause.as_deref().and_then(|cause| {
            cause.strip_prefix("violation, ").or_else(|| {
                cause
                    .strip_prefix(&format!("{terminal}, "))
                    .and_then(|cause| cause.rsplit_once(", stop ").map(|(claim, _)| claim))
            })
        });
        let expected = match breach {
            Some(breach)
                if breach.starts_with("violating ") || breach.starts_with("a failing ") =>
            {
                format!("{terminal}, {breach}")
            }
            _ => terminal,
        };
        claim == &expected
    }

    /// Parses one replay line. Torn, repeated, foreign or malformed fields
    /// return the corresponding protocol error.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let mut lines = Pairs::lines(text)?;
        let value = lines.one("replay")?;
        let parsed = if let Some(claim) = value.strip_prefix("reproduced, ") {
            Self::Reproduced(owned(claim, "replay")?)
        } else if let Some(panic) = value.strip_prefix("the run panicked at ") {
            Self::Panicked(owned(panic, "replay")?)
        } else if let Some(diverged) = value.strip_prefix("diverged at ") {
            let (position, reason) = diverged.split_once(": ").ok_or(Error::Value("replay"))?;
            let at = if position == "the result" {
                None
            } else {
                Some(count(
                    position
                        .strip_prefix("semantic record ")
                        .ok_or(Error::Value("replay"))?,
                    "replay",
                )?)
            };
            Self::Diverged {
                at,
                reason: owned(reason, "replay")?,
            }
        } else {
            return Err(Error::Value("replay"));
        };
        lines.finish()?;
        Ok(parsed)
    }
}

/// The reducer’s successful result and its bounded-search qualification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReduceResult {
    pub records: u64,
    pub scenario: String,
    pub bounded: bool,
    pub panic: Option<String>,
}
impl ReduceResult {
    /// Parses one reduction line. Torn, repeated, foreign or malformed fields
    /// return the corresponding protocol error.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let mut lines = Pairs::lines(text)?;
        let value = lines
            .one("reduce")?
            .strip_prefix("reduced to ")
            .ok_or(Error::Value("reduce"))?;
        let (records, rest) = value
            .split_once(" records, scenario ")
            .ok_or(Error::Value("reduce"))?;
        let (scenario, mut rest) = rest
            .split_once(", ")
            .map_or((rest, None), |(scenario, rest)| (scenario, Some(rest)));
        let bounded = rest.is_some_and(|rest| rest == "bounded" || rest.starts_with("bounded, "));
        if bounded {
            rest = rest.and_then(|rest| rest.strip_prefix("bounded, "));
        }
        let panic = rest
            .map(|rest| {
                rest.strip_prefix("the run panicked at ")
                    .ok_or(Error::Value("reduce"))
                    .and_then(|panic| owned(panic, "reduce"))
            })
            .transpose()?;
        let parsed = Self {
            records: count(records, "reduce")?,
            scenario: owned(scenario, "reduce")?,
            bounded,
            panic,
        };
        lines.finish()?;
        Ok(parsed)
    }
}
