//! The launcher's commands against a fake worker, through the real
//! `campaign` binary and a real archive.
//!
//! This target has no test harness. Started with `CAMPAIGN_FAKE_WORKER`
//! naming a case directory, it is the worker: the archive holds a copy of
//! this executable as its `worker`, and the launcher runs it with that
//! variable inherited. Started without the variable, it runs its cases and
//! prints libtest's listing and result lines, so the workspace lane lists
//! and judges it as any other target. The launcher runs on 64-bit Linux
//! only; elsewhere this target lists and runs no case.

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod cases;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod runner;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod worker;

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
fn main() -> std::process::ExitCode {
    match std::env::var_os(worker::PLAN) {
        Some(dir) => worker::worker(std::path::Path::new(&dir)),
        None => runner::runner(),
    }
}

#[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
fn main() {
    println!("0 tests, 0 benchmarks");
}
