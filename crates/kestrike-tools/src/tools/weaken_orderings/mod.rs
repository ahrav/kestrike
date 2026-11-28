#![doc = include_str!("help.md")]
//!
//! # Trust
//!
//! `run` acts with the authority of the user who starts it: it trusts the checkout it is started from and
//! the work directory it is given, makes the copy and the evidence directories there with the mode a
//! plain `mkdir` gets under the umask, and runs each test the catalog names on the copy.

pub const NAME: &str = "weaken-orderings";

#[cfg(target_os = "linux")]
mod command;
#[cfg(target_os = "linux")]
mod execute;
#[cfg(target_os = "linux")]
mod files;
#[cfg(target_os = "linux")]
mod halt;
#[cfg(target_os = "linux")]
mod pins;
#[cfg(target_os = "linux")]
mod run;
#[cfg(target_os = "linux")]
mod runner;

#[cfg(target_os = "linux")]
pub use command::run;

/// `run` refuses the run with exit 2 on a host other than Linux, whose process and file controls the run
/// needs.
#[cfg(not(target_os = "linux"))]
pub fn run(_top: &std::path::Path, _args: &[std::ffi::OsString]) -> u8 {
    use std::io::Write;
    let _ = std::io::stderr().write_all(b"weaken-orderings: error: the tool needs Linux\n");
    2
}
