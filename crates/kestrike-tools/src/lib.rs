//! The repository's tools, each a module under `tools`, and the library modules they share.
//!
//! The binary starts a tool as `kestrike-tools <top> <tool> <arguments>`; `top` is the checkout's top
//! level, from which a tool reads its inputs.

pub mod args;
pub mod classes;
pub mod decimal;
pub mod environ;
pub mod fixtures;
#[cfg(target_os = "linux")]
pub mod gameday;
pub mod genmc;
pub mod git;
pub mod hook;
#[cfg(target_os = "linux")]
pub mod host_stop;
pub mod json;
pub mod orderings;
pub mod ownership;
pub mod paths;
#[cfg(target_os = "linux")]
pub mod plants;
pub mod production_text;
pub mod python;
pub mod rust_text;
pub mod shell;
pub mod stream;
#[cfg(target_os = "linux")]
pub mod temp_dir;
pub mod text;
pub mod tools;
