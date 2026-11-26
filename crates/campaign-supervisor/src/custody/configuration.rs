//! Caller-supplied custody inputs. `Custody::open` validates `Timing`, and
//! `Custody::launch` validates `Limits` and refuses a command word or
//! environment entry holding a NUL byte, each before any record is written
//! or any cgroup is created.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

use crate::record::Text;
use crate::store::Name;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub cpu_quota_us: u64,
    pub memory_bytes: u64,
    pub pids: u64,
    pub file_bytes: u64,
    pub cpu_seconds: u64,
    pub output_bytes: u64,
    pub output_inodes: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct Timing {
    pub poll: Duration,
    pub kill_wait: Duration,
    pub watchdog: Duration,
}

pub struct Launch {
    pub attempt: Text,
    pub name: Name,
    pub gate: PathBuf,
    pub launcher: PathBuf,
    pub args: Vec<OsString>,
    pub directory: PathBuf,
    pub environment: BTreeMap<OsString, OsString>,
    pub limits: Limits,
}
