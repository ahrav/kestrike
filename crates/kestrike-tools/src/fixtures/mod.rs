//! The fixture writers share the command line, the case text, the `quint run` call and the rewrite of each
//! trace's `#meta`.
//!
//! A writer reads `quint/<model>.qnt` once: its digest and every model copy come from that read. It runs its
//! traces in order. For each trace it creates `<output>/<name>/`, which must be new, writes the model and
//! `case.qnt` there, removes an entry at `<output>/<name>.itf.json`, and runs Quint in that directory with
//! `--out-itf ../<name>.itf.json`, an argument that holds no part of `<output>`. It checks that the trace
//! contains `trace.steps + 1` states, writes the trace with `#meta` replaced as the model's [`Style`] states
//! to a new file in `<output>/<name>/`, and renames that file over `<output>/<name>.itf.json`. The first
//! failure ends the run with exit 1 and a diagnostic on standard error; earlier traces remain on disk.

pub mod args;
pub mod case;
pub mod quint;

#[cfg(test)]
mod args_tests;

mod write;

#[cfg(test)]
pub(crate) use write::generate;
pub use write::{Model, Rewrite, Style, Trace, keep, traces, write};
