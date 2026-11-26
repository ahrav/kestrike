mod execute;
mod history;
mod projection;
mod verify;

use super::{Error, name, once, text};
use history::{directory, probe_directory, retained_bytes};

pub(super) use execute::add;

pub(crate) use history::Catalog;
pub(super) use history::PROBE_PREFIX;
pub(in crate::campaign) use history::is_probe;

pub(in crate::campaign) use history::target_input;
pub(super) use history::{reconcile, remove};
pub(in crate::campaign) use projection::project;

#[cfg(test)]
#[path = "corpus_tests.rs"]
mod tests;
