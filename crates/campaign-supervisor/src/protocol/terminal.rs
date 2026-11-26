//! A run's terminal: `complete OUTCOME fired=HEX required=HEX` or
//! `infrastructure CLASS`, where each mask is two lowercase hexadecimal
//! digits.

use std::fmt;

use super::Error;
use super::pairs::{fill, hex, words};

/// The names of how a run stopped, as the worker prints them.
pub const STOPS: [&str; 9] = [
    "goal",
    "limit turns",
    "limit same_time",
    "limit no_progress",
    "quiescent",
    "defect choice",
    "defect entropy",
    "defect due",
    "halted",
];

/// How a run ended: with a verdict over its obligations, or stopped by
/// the harness before one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Terminal {
    /// The run reached a verdict; `fired` and `required` are obligation
    /// masks, one bit per obligation.
    Complete {
        outcome: Outcome,
        fired: u8,
        required: u8,
    },
    /// The run stopped before a verdict.
    Infrastructure(Infrastructure),
}

words! {
    /// A complete run's verdict.
    Outcome {
        /// The run ended at its goal with no failed check.
        Pass = "pass",
        /// A check or the audit found a violation.
        Violation = "violation",
        /// The run hit a limit, or a check or the audit reached no
        /// verdict.
        Inconclusive = "inconclusive",
        /// The run failed to exercise what it declares: a check ended
        /// unsuccessful or truncated, or a run that declares PUTs made
        /// none.
        Unsuccessful = "unsuccessful",
    }
}

words! {
    /// Why a run stopped before a verdict.
    Infrastructure {
        /// A write to the sink failed, or a hook halted the run.
        Sink = "sink",
        /// The record maximum was reached.
        Cap = "cap",
        /// The stream ends before its terminal's checkpoint.
        Truncated = "truncated",
        /// The harness broke its own contract.
        Defect = "defect",
    }
}

impl Terminal {
    pub(crate) fn parse(text: &str, key: &'static str) -> Result<Self, Error> {
        if let Some(class) = text.strip_prefix("infrastructure ") {
            return Ok(Self::Infrastructure(Infrastructure::parse(class, key)?));
        }
        let [outcome, fired, required] = fill(text, "complete {} fired={} required={}", key)?;
        let mask =
            |digits| u8::from_str_radix(&hex(digits, 2, key)?, 16).map_err(|_| Error::Value(key));
        let outcome = Outcome::parse(outcome, key)?;
        Ok(Self::Complete {
            outcome,
            fired: mask(fired)?,
            required: mask(required)?,
        })
    }

    /// Whether the run passed with every required obligation fired: a
    /// complete pass whose `required` mask is nonzero and whose `fired`
    /// mask covers it. Only such a terminal can count for credit.
    pub fn passes(&self) -> bool {
        matches!(*self, Self::Complete { outcome: Outcome::Pass, fired, required }
            if required != 0 && fired & required == required)
    }

    pub fn defect(&self) -> bool {
        *self == Self::Infrastructure(Infrastructure::Defect)
    }
}

/// The terminal as the worker prints it.
impl fmt::Display for Terminal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Complete {
                outcome,
                fired,
                required,
            } => write!(
                f,
                "complete {} fired={fired:02x} required={required:02x}",
                outcome.name()
            ),
            Self::Infrastructure(class) => write!(f, "infrastructure {}", class.name()),
        }
    }
}
