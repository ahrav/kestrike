//! The host stop controller's checks as library functions, each called alone: the operator file, the
//! package, the snapshot, the roles mark, the marks `restore` reads, each AWS reply, a mark's bytes
//! and the call through a stand-in `aws`. A case named as the self-test names it asserts what that
//! case asserts; every other case is named by the self-test case that plants the same input.

#![cfg(target_os = "linux")]

mod command_line;
mod marks;
mod replies;
mod review;
mod run;
mod snapshot;
