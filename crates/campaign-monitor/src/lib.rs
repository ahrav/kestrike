//! The campaign monitor: it reads a format-1 `campaign status` snapshot
//! from a bounded source, attributes each outcome to a domain, derives
//! ranked signals, keeps a local history of samples, and renders them for
//! `check` and the terminal monitor. The crate only reads campaign state;
//! its one write is the history file.

pub mod check;
pub mod cli;
pub mod history;
pub mod model;
pub mod outcome;
mod parallel;
pub mod poll;
mod rows;
pub mod signals;
pub mod snapshot;
pub mod source;
pub mod state;
pub mod tui;
pub mod view;
