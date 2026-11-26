//! Retained failures run in the triage reserve through one executor.
//! Ordinary automatic selection retries incomplete outcomes once, then holds equal outcomes.
//! Targeted replay waits after absent facts, two insufficient results or two interruptions.
//! Explicit steps mint fresh records within the same limits and custody checks.

mod candidate;
mod executor;
mod history;
mod report;
mod verdict;

#[cfg(test)]
#[path = "triage_tests.rs"]
mod tests;

use crate::record::{Finding, TriageStep, Verified};
use crate::store::Dir;

use super::{Error, name, text};
#[cfg(test)]
pub(crate) use executor::start;
pub use executor::{Admission, Outcome, Request, execute};
pub(crate) use executor::{Occupancy, admit, controller_limit};
#[cfg(test)]
pub(crate) use history::reconcile;
pub(in crate::campaign) use history::{bound_step, step_entries};
pub(crate) use history::{global, reconcile_counted, select};

pub struct Step {
    directory: Dir,
    finding: Verified<Finding>,
    record: Verified<TriageStep>,
}

pub(in crate::campaign) use report::project;

pub(in crate::campaign) use history::facts_settled;

pub(in crate::campaign) use history::stalled_for;

pub(in crate::campaign) use history::targeted_stall_reason;
