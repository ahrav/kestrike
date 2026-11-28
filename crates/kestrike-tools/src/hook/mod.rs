//! Before checks start, [`Plan`] determines each pushed tip's checks in run order, the ranges of the
//! weakened-test scan and the failures of the chaos record guard, or returns the [`Failure`] that ends the
//! push.
//!
//! [`Plan::line`] reads one ref line of Git's pre-push input, `<local ref> <local sha> <remote ref>
//! <remote sha>`, and plans its checks and scan or returns its failure. [`Plan::guard`] reads the chaos
//! records after the scans.
//! Every Git read starts in [`crate::git::push_environ`], so each Git child reads each pathspec with its
//! magic whatever pathspec mode the caller set, and [`crate::git`] makes it read the original objects even
//! when `refs/replace/` entries exist.

mod failure;
mod guard;
mod members;
mod plan;
mod reads;
mod table;

pub use failure::Failure;
pub use guard::{Record, account_number, account_numbers, record_values};
pub use members::Members;
pub use plan::{Plan, Skipped};
pub use reads::{Probe, destination_refs, ignored_tests};
pub use table::{Check, Held, ORDER, Row, TOOLS_TARGET, checks_for};

use failure::shown;
pub(crate) use failure::{argument, short};

#[cfg(test)]
#[path = "../hook_tests.rs"]
mod tests;
