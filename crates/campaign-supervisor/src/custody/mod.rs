//! The custody module manages attempt cgroups and their processes.

mod configuration;
mod error;
pub(crate) mod gate;
mod run;

#[cfg(test)]
pub(crate) mod run_tests;

use crate::record::Text;
use crate::store;
use crate::sys;

pub use crate::store::cgroup::Counters;
pub use configuration::{Launch, Limits, Timing};
pub use error::Error;
pub use run::{EvidenceTree, Running, Stopped, Waited};
pub(crate) use run::{MAX_PIDS, charge, charged};

pub(crate) const LAUNCHER_STDOUT: &str = "launcher.stdout";
pub(crate) const LAUNCHER_STDERR: &str = "launcher.stderr";
pub(crate) const LAUNCHER_OUTPUTS: [&str; 2] = [LAUNCHER_STDOUT, LAUNCHER_STDERR];

pub struct Custody {
    root: store::cgroup::Root,
    boot: Text,
    signals: sys::Signals,
    timing: Timing,
    interrupted: Option<i32>,
    release_deadline: Option<std::time::Instant>,
    held: Option<Text>,
    resource_faults: std::collections::BTreeSet<Text>,
    retained: Vec<Running>,
}
