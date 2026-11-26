//! The `host` test target. Invoked under a fake's name inside a case it
//! runs that fake; otherwise it runs the host cases.

mod cases;
mod fake;
mod runner;

fn main() -> std::process::ExitCode {
    let invoked = std::env::args_os().next().unwrap_or_default();
    let name = std::path::Path::new(&invoked)
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or("");
    if fake::NAMES.contains(&name) && std::env::var_os(fake::CASE).is_some() {
        fake::fake(name)
    } else {
        runner::runner()
    }
}
