mod cli;
mod controller;
mod runs;
mod target;
#[cfg(test)]
mod target_tests;

pub(crate) use crate::campaign::Error;
use crate::campaign::{name, text};
pub use cli::run;
pub(crate) use controller::gate;
pub(crate) use runs::rows;
