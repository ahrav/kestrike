//! Read-only report modules project coverage, history and resource measurements.

mod calibrations;
mod coverage;
mod measurement;
mod projection;

pub(in crate::campaign) use super::projection::{each_shard, held, root};
use super::{Error, name};
pub use projection::report;

#[cfg(test)]
#[path = "report_tests.rs"]
pub(in crate::campaign) mod tests;

#[cfg(test)]
pub(in crate::campaign) use projection::project;
pub(in crate::campaign) use projection::{UNDECLARED, VerifiedAttempt, VerifiedHistory, snapshot};
