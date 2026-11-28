#![doc = include_str!("../../plants/help.md")]

pub const NAME: &str = "plant-runner";

#[cfg(target_os = "linux")]
mod runner;

#[cfg(target_os = "linux")]
pub use runner::run;

/// `run` refuses the run with exit 2 on a host other than Linux, whose process and file controls the run
/// needs.
#[cfg(not(target_os = "linux"))]
pub fn run(_top: &std::path::Path, _args: &[std::ffi::OsString]) -> u8 {
    use std::io::Write;
    let _ = std::io::stderr().write_all(b"plant-runner: error: the runner needs Linux\n");
    2
}
