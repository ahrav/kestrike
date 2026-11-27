//! The fixture writers share the command line, the case text, the `quint run` call and the rewrite of each
//! trace's `#meta`.
//!
//! A writer reads `quint/<model>.qnt` once: its digest and every model copy, which holds the same bytes,
//! come from that read. It runs its traces in order. For each trace it creates `<output>/<name>/`, which
//! must be new, and writes the model and `case.qnt` there. It removes an entry at `<output>/<name>.itf.json`,
//! so the trace it reads next is one this run's Quint wrote, and runs Quint in `<output>/<name>/` with
//! `--out-itf ../<name>.itf.json`: Quint expands `{seq}` in that argument, which holds the trace's name and
//! no part of `<output>`. It checks that the trace contains `trace.steps + 1` states, writes the trace with
//! `#meta` replaced as the model's [`Style`] states to a new file in `<output>/<name>/`, and renames that
//! file over `<output>/<name>.itf.json`. The first failure ends the run with exit 1 and a diagnostic on
//! standard error, or exit 120 when that diagnostic cannot be written; earlier traces remain on disk.
//!
//! The writer opens every path by name and trusts `<output>`: a process that changes entries there during
//! a run can redirect the writer's and Quint's files.

pub mod args;
pub mod case;
pub mod quint;

#[cfg(test)]
mod args_tests;
#[cfg(test)]
#[path = "../fixtures_tests.rs"]
mod tests;

mod write;

pub use write::{Model, Rewrite, Style, Trace, keep, traces, write};
#[cfg(test)]
pub(crate) use write::{generate, replace};
