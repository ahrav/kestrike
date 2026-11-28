#![doc = include_str!("../red_green/help.md")]

pub const NAME: &str = "red-green";

#[cfg(target_os = "linux")]
pub use crate::red_green::run::run;

/// `run` rejects the run with exit 2 on a host other than Linux, whose process and file controls the run
/// needs.
#[cfg(not(target_os = "linux"))]
pub fn run(_top: &std::path::Path, _args: &[std::ffi::OsString]) -> u8 {
    use std::io::Write;
    let _ = std::io::stderr().write_all(b"red-green: error: the run needs Linux\n");
    2
}
