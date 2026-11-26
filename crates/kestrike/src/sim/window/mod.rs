//! Crash-window coverage within a recovery profile.

mod census;
mod tests;

pub(crate) use census::{Row, Status, census};

/// Rebuilds the recognized recovery profile's ledger into stage counts and window rows.
/// Counts follow planned, reached, activated, recovered, checked, skipped order.
/// Returns `None` for an unknown or live profile or a refused rebuild.
/// The inspecting executable uses the profile name recorded in the bundle to select its own cut table.
pub(crate) use census::recorded;
