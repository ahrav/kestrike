//! Record types for the custody lifecycle. `Custody::launch` creates the
//! `Intent` record before the attempt's cgroup directory and the `Started`
//! record before the gate receives its go byte. `Started` carries the
//! cgroup's inode, and `Custody::reconcile` stops membership only in a
//! directory whose inode matches it.

use serde::{Deserialize, Serialize};

use super::{Kernel, Text};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    pub attempt: Text,
    pub boot: Text,
    pub cgroup: Text,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Started {
    pub attempt: Text,
    pub baseline: Kernel,
    pub boot: Text,
    pub cgroup: Text,
    pub cgroup_inode: u64,
    pub launcher_pid: u64,
}

impl Started {
    pub(crate) fn agrees_with(&self, intent: &Intent) -> bool {
        self.attempt == intent.attempt && self.boot == intent.boot && self.cgroup == intent.cgroup
    }
}
