#![doc = include_str!("help.md")]

mod config;
mod options;
mod outcomes;
pub(crate) mod pieces;
mod preflight;
mod process;
mod runner;
mod stop;

#[cfg(test)]
mod config_tests;
#[cfg(test)]
mod options_tests;
#[cfg(test)]
mod outcomes_tests;

pub use config::{debug_assertions, pins, stables};
pub use options::{Options, parse};
pub use outcomes::{Listed, read_listing};
pub use preflight::{Prepared, preflight};
pub use process::{INTERRUPT, Interrupt, SIGNALS, ignore_signals, install_handlers, supervise};
pub use runner::{Run, run};
pub use stop::Stop;
