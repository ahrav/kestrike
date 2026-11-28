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
//!
//! From what a run's children print and write, the module also gives each plant's result with its reason
//! and the score: [`judge_rerun`] judges a proof rerun, [`archive_pins`] reads an archive's pins,
//! [`first_object`] and [`last_object`] read a command's JSON line, [`judge`] judges a plant after its
//! sweeps with what `campaign confirm` and each seed check printed, and [`score`] composes the score, its
//! bytes, its lines and the exit code. These functions read the three files a judgment reads
//! (`suspects.jsonl`, `confirm.err` and a profile's manifest) and take every other input as a value;
//! each child a judgment needs, it asks of its caller.
//!
//! [`Run`] holds a run's worktrees, the proof's state and the base archive, and starts each child by
//! [`logged`] or by the Git call that reads the signal record.

mod campaign;
mod child;
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
mod run;
pub mod score;
mod seed;
mod status;
mod stop;
mod store;
mod suspects;
pub(crate) mod values;
mod verdict;
mod work;

pub use child::{GitFailed, Halt, Logged, Step, logged};
pub use entry::{Entry, Finished};
pub use judgment::{Ask, Sweep, judge};
pub use options::{FLOOR, Options};
pub use output::{Pins, archive_pins, first_object, last_object};
pub use prepare::{Inputs, Outcome, prepare};
pub use record::{FIELDS, Plant, RECORD_BOUND};
pub use rerun::{HelperVerdict, Rerun, judge_rerun};
pub use run::{Remained, Run, remove};
pub use seed::Manifest;
pub use status::{Runs, profile_runs};
pub use store::{SCORE, STORE};
pub use suspects::Suspect;
pub use verdict::{Kind, NoVerdict, Verdict};

#[cfg(test)]
#[path = "../plants_tests.rs"]
mod tests;
