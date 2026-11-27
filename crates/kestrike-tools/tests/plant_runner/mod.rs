//! The cases of the plant run's checks. Each case builds a [`repository::Repository`] and calls
//! `kestrike_tools::plants::prepare` in the test process with the fixture's environment and directory as
//! values, so no case changes the process's directory, environment, umask or signal dispositions; a Git
//! command the fixture itself runs is a child process.
//!
//! An expected reason holds the text a refusal composes from its words and values. Where the reason
//! carries the text of another reader (the JSON reader's errors, an operating system error), it is that
//! reader's text in this crate.
#![cfg(target_os = "linux")]

mod git_call;
mod inputs;
mod judgment;
mod judgment_rows;
mod options;
mod outputs;
mod plants;
mod repository;
mod scores;
mod store;
