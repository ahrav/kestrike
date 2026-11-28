#![doc = include_str!("help.md")]

pub const NAME: &str = "mutants-diff";

#[cfg(target_os = "linux")]
mod config;
#[cfg(target_os = "linux")]
mod options;
#[cfg(target_os = "linux")]
mod outcomes;
#[cfg(target_os = "linux")]
mod preflight;
#[cfg(target_os = "linux")]
mod process;
#[cfg(target_os = "linux")]
mod rundir;
#[cfg(target_os = "linux")]
mod runner;
#[cfg(target_os = "linux")]
mod stop;

#[cfg(all(test, target_os = "linux"))]
mod config_tests;
#[cfg(all(test, target_os = "linux"))]
mod options_tests;
#[cfg(all(test, target_os = "linux"))]
mod outcomes_tests;
#[cfg(all(test, target_os = "linux"))]
mod process_tests;
#[cfg(all(test, target_os = "linux"))]
mod rundir_tests;
#[cfg(all(test, target_os = "linux"))]
mod stop_tests;

#[cfg(target_os = "linux")]
pub use config::{debug_assertions, pins, stables};
#[cfg(target_os = "linux")]
pub use options::{Options, parse};
#[cfg(target_os = "linux")]
pub use preflight::{Prepared, preflight};
#[cfg(target_os = "linux")]
pub use process::{INTERRUPT, Interrupt, install_handlers, supervise};
#[cfg(target_os = "linux")]
pub use runner::{Run, run};
#[cfg(target_os = "linux")]
pub use stop::Stop;

/// `run` refuses the run with exit 2 on a host other than Linux, whose process controls (a parent-death
/// signal, `getrandom`) the runner needs.
#[cfg(not(target_os = "linux"))]
pub fn run(_top: &std::path::Path, _args: &[std::ffi::OsString]) -> u8 {
    use std::io::Write;
    let _ = std::io::stderr().write_all(b"mutants-diff: error: the runner needs Linux\n");
    2
}
