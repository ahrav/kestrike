//! One sweep thread's cgroup, or one fuzz worker's.
//!
//! A pen is a child group of the `sweep` child of the delegated cgroup
//! root, with one CPU, a memory limit with swap off and group
//! out-of-memory kill, and a process limit. A sweep thread creates one pen
//! and runs each of its worker processes in it, one at a time. The thread
//! moves a worker into the pen before it sends the worker its first root,
//! and a `--sweep` worker starts a run only after it reads a root. A
//! replay's worker starts behind the `gate` subcommand, which the thread
//! moves into the pen before it sends the go byte. So every run and every
//! process a run starts executes inside the pen's limits. The worker's
//! capability listing runs before any pen exists, in the sweep's own
//! group, bounded by its wait and by the archive's output bound.
//!
//! [`claim`] locks the `sweep` child for the command's lifetime, so one
//! sweep or fuzz run at a time owns the pens under a delegated root, and
//! removes the pens an earlier command left there. Custody scans the delegated root and
//! skips its `sweep` child, so a supervised command and a sweep use one
//! delegated root at the same time.
//!
//! The kernel kills every process of a pen whose memory use reaches its
//! limit when it can reclaim none of it. The thread sees its worker's
//! output end and reads the pen's out-of-memory kill count to name the
//! cause. That count also rises when the kernel kills a process of the pen
//! at the memory limit of an ancestor cgroup, so such a kill has the same
//! class. The sweep kills a pen whose run passes the wall limit. After
//! each worker the thread empties the pen: it kills every process the
//! worker left and waits until the pen holds none, so the next worker
//! starts alone.

use std::io;
use std::path::Path;
use std::process::Child;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::store::Name;
use crate::store::cgroup::{CPU_PERIOD_US, Group, Root};

/// How long [`Pen::empty`] waits for killed processes to leave the pen.
const EMPTY_WAIT: Duration = Duration::from_secs(5);

/// The limits of each pen: its memory in bytes and its process count.
#[derive(Clone, Copy, Debug)]
pub(super) struct Limits {
    pub(super) memory: u64,
    pub(super) processes: u64,
}

/// Moves this process into `sweep/controller` under `cgroup` and locks
/// `sweep`. `Some` is the locked root with every group an earlier sweep
/// left there killed and removed. `None` means another sweep holds the
/// lock. A child of the pens' root that is itself named `sweep` stays: it
/// holds the pens of a sweep that took the pens' root as its own cgroup
/// root, and that sweep's lock, on that child, guards them.
///
/// # Errors
///
/// `TimedOut` when a group found under the pens' root still holds a
/// process [`EMPTY_WAIT`] after its kill, or a failed cgroup operation.
pub(super) fn claim(cgroup: &Path) -> io::Result<Option<Root>> {
    let root = Root::open(cgroup)?.sweep()?;
    if !root.try_lock()? {
        return Ok(None);
    }
    for path in root.children(crate::scan_bound())? {
        if let Some(left) = root.recorded(&path)? {
            emptied(&left)?;
            left.remove()?;
        }
    }
    Ok(Some(root))
}

/// One thread's cgroup, which holds at most one worker and the processes
/// that worker started. The thread that created it admits workers and
/// empties it; the sweep's monitor may kill it at the wall limit.
pub(super) struct Pen {
    group: Group,
    /// The out-of-memory kills [`Pen::out_of_memory`] last read.
    kills: AtomicU64,
}

impl Pen {
    pub(super) fn create(root: &Root, index: usize, limits: Limits) -> io::Result<Self> {
        let name = Name::new(&format!("sweep-{index:04}")).expect("a pen name is a component");
        let group = root.create(&name, CPU_PERIOD_US, limits.memory, limits.processes)?;
        Ok(Self {
            group,
            kills: AtomicU64::new(0),
        })
    }

    /// Moves `worker` into the pen.
    ///
    /// # Errors
    ///
    /// A failed write of the pen's process list.
    pub(super) fn admit(&self, worker: &Child) -> io::Result<()> {
        self.group.move_gate(worker)
    }

    /// Whether the kernel killed a process of the pen for its memory use
    /// since the last call.
    ///
    /// # Errors
    ///
    /// A failed read of the pen's counters.
    pub(super) fn out_of_memory(&self) -> io::Result<bool> {
        let kills = self
            .group
            .snapshot()?
            .memory
            .get("oom_kill")
            .copied()
            .unwrap_or(0);
        Ok(self.kills.swap(kills, Ordering::Relaxed) < kills)
    }

    /// Kills every process the pen holds.
    ///
    /// # Errors
    ///
    /// A failed write of the pen's kill file.
    pub(super) fn kill(&self) -> io::Result<()> {
        self.group.kill()
    }

    /// Kills every process the pen holds and waits until it holds none.
    /// Returns whether it held one.
    ///
    /// # Errors
    ///
    /// A failed cgroup operation, or `TimedOut` when the pen still holds a
    /// process [`EMPTY_WAIT`] after the kill.
    pub(super) fn empty(&self) -> io::Result<bool> {
        emptied(&self.group)
    }

    /// Empties and removes the pen.
    ///
    /// # Errors
    ///
    /// As [`Pen::empty`], or a failed removal, as of a pen in which a
    /// worker made a child cgroup, which stays for inspection.
    pub(super) fn remove(self) -> io::Result<()> {
        emptied(&self.group)?;
        self.group.remove()
    }
}

/// Kills every process `group` holds and waits until it holds none; whether
/// it held one.
fn emptied(group: &Group) -> io::Result<bool> {
    if !group.populated()? {
        return Ok(false);
    }
    group.kill()?;
    let deadline = Instant::now() + EMPTY_WAIT;
    while group.populated()? {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "a pen holds a process after its kill",
            ));
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    Ok(true)
}
