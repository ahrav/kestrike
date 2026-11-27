//! The repository's tools, each a module under `tools`, and the library modules they share.
//!
//! The binary starts a tool as `kestrike-tools <top> <tool> <arguments>`; `top` is the checkout's top
//! level, from which a tool reads its inputs.

pub mod fixtures;
pub mod json;
pub mod paths;
pub mod python;
pub mod tools;

#[cfg(test)]
mod fixtures_tests;
#[cfg(test)]
mod json_tests;
#[cfg(test)]
mod paths_tests;
#[cfg(test)]
mod python_tests;
#[cfg(test)]
mod tools_tests;
