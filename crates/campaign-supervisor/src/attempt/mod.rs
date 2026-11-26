//! Numbered attempt histories bind custody outcomes to frozen jobs.

mod binding;
mod capture;
mod classify;
mod launch;
mod lifecycle;
mod settle;
pub(crate) mod targeted;

#[cfg(test)]
#[path = "attempt_tests.rs"]
pub(crate) mod tests;

pub use crate::custody::Error;
pub use crate::store::EVIDENCE_BOUND;
pub use binding::BoundArtifact;
pub(crate) use capture::capture;
pub(crate) use capture::dependencies;
pub(crate) use capture::recorded as capture_recorded;
pub(crate) use classify::{classify_stopped, finding_kind};
pub use launch::Launch;
pub(crate) use launch::scaled;
pub(crate) use lifecycle::pending_started;
pub use lifecycle::{Attempt, Completed, start};
pub(crate) use lifecycle::{
    Execution, Publisher, completed_at, frozen_manifest, history, queued_target, read_attempt,
    read_completed, settlement_entries, start_calibration,
};
pub use settle::settle;
pub(crate) use settle::{pins, selected_failure, settle_pinning};

fn name(text: &str) -> crate::store::Name {
    crate::store::Name::new(text).expect("attempt paths use canonical identifiers")
}
