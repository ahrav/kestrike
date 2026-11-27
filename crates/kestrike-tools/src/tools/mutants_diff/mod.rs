#![doc = include_str!("help.md")]

mod config;
mod options;
mod outcomes;
pub(crate) mod pieces;
mod preflight;
mod process;
mod rundir;
mod runner;
mod stop;

#[cfg(test)]
mod config_tests;
#[cfg(test)]
mod options_tests;
#[cfg(test)]
mod outcomes_tests;
#[cfg(test)]
mod process_tests;
#[cfg(test)]
mod rundir_tests;
#[cfg(test)]
mod stop_tests;

pub use config::{debug_assertions, pins, stables};
pub use options::{Options, parse};
pub use preflight::{Prepared, preflight};
pub use process::{INTERRUPT, Interrupt, install_handlers, supervise};
pub use runner::{Run, run};
pub use stop::Stop;
