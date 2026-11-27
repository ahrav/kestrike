//! The repository's tools, each a module under `tools`, and the library modules they share.
//!
//! The binary starts a tool as `kestrike-tools <top> <tool> <arguments>`; `top` is the checkout's top
//! level, from which a tool reads its inputs.

pub mod args;
pub mod classes;
pub mod fixtures;
pub mod genmc;
pub mod git;
pub mod json;
pub mod orderings;
pub mod ownership;
pub mod paths;
pub mod production_text;
pub mod python;
pub mod rust_text;
pub mod shell;
pub mod stream;
pub mod text;
pub mod tools;
