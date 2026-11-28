//! The cases of a plant run's library: its checks before any worktree, the judgment of a swept plant,
//! the readers of a command's output, and the entries and the score. A case of the checks builds a
//! [`repository::Repository`] and calls `kestrike_tools::plants::prepare` with the fixture's environment
//! and directory as values; a judgment case takes its plant from such a fixture and calls
//! `kestrike_tools::plants::judge` with the row's files and outputs. A case of a run builds a
//! [`fixture::Fixture`] and starts the tool as a child process, beside stand-ins of `campaign` and
//! `python3` that are this test executable started again in a role ([`standins`]); a case that installs
//! the signal handlers starts this test executable again for itself. No case changes the test process's
//! directory, environment, umask or signal dispositions, and a Git command the fixture runs is a child
//! process.
//!
//! An expected reason holds the text a refusal composes from its words and values. Where the reason
//! carries the text of another reader (the JSON reader's errors, an operating system error), it is that
//! reader's text in this crate.
#![cfg(target_os = "linux")]

mod checkout;
mod exits;
mod fixture;
mod git_call;
mod inputs;
mod judgment;
mod judgment_rows;
mod options;
mod outputs;
mod planted;
mod plants;
mod proofs;
mod repository;
mod scores;
mod signals;
mod standins;
mod store;
mod swept;
