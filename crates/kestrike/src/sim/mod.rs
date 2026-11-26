//! Deterministic foundations of the simulation harness: the choice
//! contract every nondeterministic decision goes through, the
//! initialization entropy drawn through it, the turn controller that selects
//! every event through it, the composed fixture rounds it runs, the
//! workload's action vocabulary, the manifest and bundle that fix and record
//! one worker run, the forked children that branch a run at a stopped
//! boundary, and the long-run gate's manifest, phases and high-water marks.
//! The `cut` core enumerates recovery cuts from a workload's descriptor,
//! `recovery` holds the record a recovery profile's run carries, and
//! `unwind` names a run's panic by its location and payload. `attach_tests`
//! drives the shard simulation's stale and unrecorded attach arms.
//! `chaos` holds the macro production code asks a seeded chaos point
//! through, and in test builds the points' catalog and decisions.

#[cfg_attr(
    not(test),
    allow(dead_code, reason = "replay serves the simulation harness")
)]
pub(crate) mod action;

#[cfg_attr(
    not(test),
    allow(dead_code, reason = "replay serves the simulation harness")
)]
pub(crate) mod choice;

#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod activation_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod attach_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod capture_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod coverage_tests;

pub(crate) mod chaos;

#[cfg(test)]
mod chaos_guard_tests;

#[cfg(test)]
pub(crate) mod choice_tests;

#[cfg(test)]
pub(crate) mod cut;

#[cfg(test)]
pub(crate) mod cut_guard_tests;

#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod device_tests;

#[cfg(test)]
pub(crate) mod cut_tests;

#[cfg(test)]
pub(crate) mod entropy;

#[cfg(test)]
pub(crate) mod entropy_tests;

#[cfg(test)]
#[allow(
    clippy::disallowed_methods,
    reason = "child watchdog deadlines, reap polling and usage diagnostics use host time outside simulation decisions"
)]
pub(crate) mod fork;

#[cfg(test)]
#[allow(
    clippy::disallowed_methods,
    reason = "these fixtures exercise child watchdog deadlines and refusal to fork a multithreaded process"
)]
pub(crate) mod fork_tests;

#[cfg(test)]
pub(crate) mod fuzz;

#[cfg(test)]
pub(crate) mod ledger;

#[cfg(test)]
pub(crate) mod ledger_tests;

#[cfg(test)]
mod lint_tests;

#[cfg(test)]
pub(crate) mod long_run_tests;

#[cfg(test)]
pub(crate) mod manifest;

#[cfg(test)]
pub(crate) mod manifest_tests;

#[cfg(test)]
pub(crate) mod recovery;

#[cfg(test)]
pub(crate) mod recovery_tests;

#[cfg(test)]
pub(crate) mod round;

#[cfg(test)]
pub(crate) mod round_tests;

#[cfg(test)]
pub(crate) mod trace;

#[cfg(test)]
pub(crate) mod trace_tests;

#[cfg(test)]
pub(crate) mod turn;

#[cfg(test)]
pub(crate) mod turn_tests;

#[cfg(test)]
pub(crate) mod unwind;

#[cfg(test)]
pub(crate) mod window;
