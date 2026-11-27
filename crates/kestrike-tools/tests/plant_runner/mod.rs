//! The cases of the plant run's checks. Each case builds a [`repository::Repository`] and calls
//! `kestrike_tools::plants::prepare` in the test process with the fixture's environment and directory as
//! values, so no case changes the process's directory, environment, umask or signal dispositions; a Git
//! command the fixture itself runs is a child process.
//!
//! An expected reason was recorded from the check of the same state on Python 3.9.25 under a UTF-8
//! locale, apart from the places the pull request lists where the tool composes its own text.
#![cfg(target_os = "linux")]

mod git_call;
mod inputs;
mod options;
mod plants;
mod repository;
mod store;
