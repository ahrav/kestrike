//! The host stop controller's checks as library functions, each called alone: the operator file, the
//! package, the snapshot, the roles mark, the marks `restore` reads, each AWS reply, a mark's bytes
//! and the call through a stand-in `aws`. Each case asserts what its doc comment states, and each
//! expected value and sentence is a literal of the case.

#![cfg(target_os = "linux")]

mod command_line;
mod marks;
mod replies;
mod review;
mod run;
mod snapshot;
