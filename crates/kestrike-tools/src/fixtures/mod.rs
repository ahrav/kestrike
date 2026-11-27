//! The fixture writers share the command line, the case text, the `quint run` call and the rewrite of each
//! trace's `#meta`.
//!
//! A writer runs its traces in order. For each trace it creates `<output>/<name>/`, which must be new, writes
//! the model and `case.qnt` there, runs Quint in that directory to write the trace to
//! `<output>/<name>.itf.json`, checks that the trace contains `trace.steps + 1` states, and writes the trace
//! again with `#meta` replaced as the model's [`Style`] states. The first failure ends the run with exit 1 and
//! a diagnostic on standard error; earlier traces remain on disk.

pub mod args;
pub mod case;
pub mod quint;

#[cfg(test)]
mod args_tests;

mod write;

#[cfg(test)]
pub(crate) use write::generate;
pub use write::{Model, Rewrite, Style, Trace, keep, traces, write};
