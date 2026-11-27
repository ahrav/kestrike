//! The checks of a plant run, before any worktree: the command line, the Git environment, the checkout,
//! the plant store under `verification/plants/`, the checkout's `Cargo.lock`, the `campaign` binary and
//! the work directory.
//!
//! [`prepare`] takes the arguments, the environment and the invoking directory as values and returns the
//! checked inputs, the help, the argument reader's refusal, the first refusal of the run's input in a
//! fixed order, or a failure outside a plant. It adds no check of its own to those orders: each refusal
//! is one check, judged in turn, and the first that fails is returned. It makes the work directory last,
//! and with `--work` its missing ancestors just before it; a refusal of the work directory itself can
//! leave those ancestors, and every earlier refusal leaves no path.
//!
//! A plant is its store directory's name, equal to its record's `id`, and the bytes the head commit holds
//! at its two paths as regular files of mode 100644. [`git`] is the Git call every check and every later
//! step of a run makes.
//!
//! From what a run's children print and write, the module also gives each plant's result with its reason
//! and the score: [`judge_rerun`] judges a proof rerun, [`archive_pins`] and [`confirmed`] read `campaign`'s
//! documents, [`seed`] reads a seed check's manifest and ending, [`judge`] judges a plant after its sweeps,
//! and [`score`] composes the score, its bytes, its lines and the exit code. These functions start no
//! process and read no clock and no environment variable; each child a judgment needs, it asks of its
//! caller.

mod campaign;
mod entry;
mod files;
pub mod git;
mod judgment;
mod lock;
mod options;
mod output;
mod prepare;
mod record;
mod rerun;
pub mod score;
pub mod seed;
mod status;
mod stop;
mod store;
mod suspects;
pub(crate) mod values;
mod verdict;
mod words;
mod work;

pub use entry::{Entry, Verdict};
pub use judgment::{Ask, Sweep, judge};
pub use options::{FLOOR, Options};
pub use output::{Confirmed, PINS, Pins, archive_pins, confirmed, first_object, last_object};
pub use prepare::{Inputs, Outcome, prepare};
pub use record::{FIELDS, Plant, RECORD_BOUND};
pub use rerun::{HelperVerdict, Rerun, judge_rerun};
pub use status::{Runs, profile_runs};
pub use store::{SCORE, STORE};
pub use suspects::Suspect;
pub use verdict::{Kind, NoVerdict};

#[cfg(test)]
#[path = "../plants_tests.rs"]
mod tests;
