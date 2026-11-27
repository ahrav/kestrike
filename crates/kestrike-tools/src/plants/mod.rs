//! The checks of a plant run, before any worktree: the command line, the Git environment, the checkout,
//! the plant store under `verification/plants/`, the checkout's `Cargo.lock`, the `campaign` binary and
//! the work directory.
//!
//! [`prepare`] takes the arguments, the environment and the invoking directory as values and returns the
//! checked inputs, the help, the argument reader's refusal, the first refusal of the run's input in a
//! fixed order, or a failure outside a plant. It adds no check of its own to those orders: each refusal
//! is one check, judged in turn, and the first that fails is returned. It writes nothing but the work
//! directory, which it makes last.
//!
//! A plant is its store directory's name, equal to its record's `id`, and the bytes the head commit holds
//! at its two paths as regular files of mode 100644. [`git`] is the Git call every check and every later
//! step of a run makes.

mod campaign;
mod files;
pub mod git;
pub mod options;
mod prepare;
pub mod record;
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
