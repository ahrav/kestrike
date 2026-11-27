//! The checks of a plant run, before any worktree: the command line, the Git environment, the checkout,
//! the plant store under `verification/plants/`, the checkout's `Cargo.lock`, the `campaign` binary and
//! the work directory.
//!
//! [`prepare`] takes the arguments, the environment and the invoking directory as values and returns the
//! checked inputs, the help, the argument reader's refusal, the first refusal of the run's input in a
//! fixed order, or a failure outside a plant: the checks are judged in turn and the first that fails is
//! returned. It makes the work directory last,
//! and with `--work` its missing ancestors just before it; a refusal of the work directory itself can
//! leave those ancestors, and every earlier refusal leaves no path.
//!
//! A plant is a patch, `plant.patch`, that puts a fixed defect back into the checkout, and its record,
//! `plant.json`: the defect's `row` in the table of fixed defects, the `fix` that removed it
//! (`pull_request` and `commit`), the `files` the patch changes, a sentence of what it `restores`, the
//! `proof` (the fix's regression test, which passes at the head and fails on the plant), the `expected`
//! profiles a run sweeps for it, and the `miss_cause` (null, or a cause with evidence). A plant is
//! named by its store directory, equal to its record's `id`, and is the bytes the head commit holds at
//! its two paths as regular files of mode 100644. [`git`] is the Git call of every check of the checkout
//! and the store.

mod campaign;
pub(crate) mod files;
pub mod git;
mod lock;
mod options;
mod prepare;
mod record;
mod stop;
mod store;
pub(crate) mod values;
mod work;

pub use options::{FLOOR, Options};
pub use prepare::{Inputs, Outcome, prepare};
pub use record::{FIELDS, Plant, RECORD_BOUND};
pub use store::{SCORE, STORE};

#[cfg(test)]
#[path = "../plants_tests.rs"]
mod tests;
