//! A walk whose witness thread execs between the read of that thread's own
//! table and the recheck of its process.
//!
//! The walk's module documentation states what these tests judge: once
//! every queued table of a process's threads is read, the walk checks the
//! first thread the `task` directory listed again, and reads the table
//! under the process's ID when that thread is gone, since an exec may have
//! replaced the leader whose table it read.
//!
//! An exec by a thread other than the leader swaps the two tasks' IDs
//! before it releases the old leader. Until the release, the thread's
//! former ID names the old leader, which holds no descriptor table and
//! reports its own start time. Its `stat` line shows state `Z` first and
//! `X` once the exec marks it dead. [`Swapped`] answers the walk from that
//! state: the exec lands when the walk stats the thread's table, so the
//! table reads empty, and the recheck then reads the old leader's `stat`
//! line under the witness ID. A kernel shows `Z` there only inside the
//! section that swaps the IDs. A host has shown that order of reads all the
//! same: a `stat` of the thread's table that reports size zero, then a
//! `stat` line in state `Z` under the thread's ID.

use std::ffi::{CStr, CString};
use std::io;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use super::{
    Facts, Node, Os, Queue, Status, TASK_LINKS, Walker, answer, start_tick_field, start_ticks,
};

/// Above every ID the kernel assigns, so the process is not the test's own.
const PID: u32 = 1 << 23;
const TID: u32 = PID + 1;
/// The clock tick the walk began in; the leader and the thread started in
/// earlier ones.
const BEGUN: u64 = 1_000;
const LEADER_STARTED: u64 = 800;
const THREAD_STARTED: u64 = 900;
/// The minor of the device the leader's table holds.
const LEADERS: u32 = 1;
/// The minor of the device the thread's own table holds.
const THREADS: u32 = 7;

fn device(minor: u32) -> Node {
    Node::Device {
        block: true,
        major: 259,
        minor,
    }
}

fn enoent() -> io::Error {
    io::Error::from_raw_os_error(libc::ENOENT)
}

/// A `stat` line of task `id` in `state` that started in tick `started`.
fn stat_line(id: u32, state: char, started: u64) -> String {
    let middle: Vec<String> = (4..22).map(|field| field.to_string()).collect();
    format!(
        "{id} (walked) {state} {} {started} 23 24\n",
        middle.join(" ")
    )
}

/// One process whose leader and one other thread each use a table of one
/// device. The thread execs when the walk stats the thread's table; from
/// then the process's ID names the thread's table and the thread's ID
/// names the old leader in `after`, the state its `stat` line shows.
struct Swapped {
    execed: AtomicBool,
    after: char,
}

impl Swapped {
    fn minors(&self, path: &str) -> Option<Vec<u32>> {
        let execed = self.execed.load(Ordering::Acquire);
        if path == format!("{PID}/fd") {
            Some(vec![if execed { THREADS } else { LEADERS }])
        } else if path == format!("{PID}/task/{TID}/fd") {
            Some(if execed { Vec::new() } else { vec![THREADS] })
        } else {
            None
        }
    }

    /// Walks the table with one walker on a kernel that reports table sizes
    /// and resolves `kcmp`.
    fn walk(after: char) -> Option<Vec<Node>> {
        let tasks = Self {
            execed: AtomicBool::new(false),
            after,
        };
        let facts = Facts {
            reports_count: true,
            kcmp: true,
            begun: Some(BEGUN),
            walkers: 1,
        };
        let queue = Queue::<String>::default();
        let found = Mutex::new(Some(Vec::new()));
        let listed = queue.list(&tasks, &String::new(), &mut Default::default());
        Walker::new(&tasks, &queue, &|_| true, facts).walk(&found);
        assert!(tasks.execed.load(Ordering::Acquire), "the thread execed");
        answer(found, listed)
    }
}

impl Os for Swapped {
    type Table = String;

    fn status(&self, path: &CStr) -> io::Result<Status> {
        let path = path.to_str().map_err(|_| enoent())?;
        if path == format!("{PID}/task") {
            // The old leader stays listed under the thread's ID until the
            // exec releases it.
            return Ok(Status {
                size: 0,
                links: TASK_LINKS + 2,
            });
        }
        if path == format!("{PID}/task/{TID}/fd") {
            self.execed.store(true, Ordering::Release);
        }
        let minors = self.minors(path).ok_or_else(enoent)?;
        Ok(Status {
            size: libc::off_t::try_from(minors.len()).unwrap(),
            links: 2,
        })
    }

    fn open(&self, path: &CStr) -> io::Result<String> {
        let path = path.to_str().map_err(|_| enoent())?.to_owned();
        if self.minors(&path).is_none() && path != format!("{PID}/task") {
            return Err(enoent());
        }
        Ok(path)
    }

    fn entries(
        &self,
        table: &String,
        _records: &mut [u8],
        mut visit: impl FnMut(&CStr),
    ) -> io::Result<()> {
        let names: Vec<String> = if table.is_empty() {
            vec![PID.to_string()]
        } else if *table == format!("{PID}/task") {
            vec![PID.to_string(), TID.to_string()]
        } else {
            let count = self.minors(table).ok_or_else(enoent)?.len();
            (0..count).map(|fd| fd.to_string()).collect()
        };
        for name in names {
            visit(&CString::new(name).unwrap());
        }
        Ok(())
    }

    fn node(&self, table: &String, name: &CStr) -> io::Result<Option<Node>> {
        let fd = name.to_str().unwrap().parse::<usize>().unwrap();
        let minors = self.minors(table).ok_or_else(enoent)?;
        minors
            .get(fd)
            .map(|minor| Some(device(*minor)))
            .ok_or_else(enoent)
    }

    /// The thread uses its own table, and after the exec the old leader
    /// uses none.
    fn shares_leader_table(&self, _pid: u32, _tid: u32) -> bool {
        false
    }

    fn started(&self, _pid: u32, tid: u32) -> Option<u64> {
        let line = if self.execed.load(Ordering::Acquire) {
            stat_line(tid, self.after, LEADER_STARTED)
        } else {
            stat_line(tid, 'S', THREAD_STARTED)
        };
        start_ticks(&line)
    }

    fn last_task(&self) -> Option<u32> {
        Some(0)
    }
}

const REREAD_RULE: &str =
    "the walk reads the table under the process's ID again when its witness thread is gone";

/// The sibling without the fault: the recheck finds the old leader already
/// marked dead under the witness ID, and the walk reads the table the exec
/// left under the process's ID.
#[test]
fn a_witness_id_that_names_the_exec_s_dead_leader_rereads_the_process_s_table() {
    assert_eq!(
        Swapped::walk('X'),
        Some(vec![device(LEADERS), device(THREADS)]),
        "{REREAD_RULE}"
    );
}

/// The recheck finds the old leader under the witness ID before the exec
/// marks it dead. The witness thread is gone all the same, so the walk
/// reads the table the exec left under the process's ID.
#[test]
fn a_witness_id_that_names_the_exec_s_zombie_leader_rereads_the_process_s_table() {
    assert_eq!(
        Swapped::walk('Z'),
        Some(vec![device(LEADERS), device(THREADS)]),
        "{REREAD_RULE}"
    );
}

/// A zombie holds no descriptor table and is not a thread that is still
/// present, so `start_ticks` reports no start time from its `stat` line,
/// as from a dead task's.
#[test]
fn start_ticks_report_none_for_a_zombie() {
    assert_eq!(start_ticks(&stat_line(TID, 'S', THREAD_STARTED)), Some(900));
    assert_eq!(start_ticks(&stat_line(TID, 'X', LEADER_STARTED)), None);
    assert_eq!(start_ticks(&stat_line(TID, 'Z', LEADER_STARTED)), None);
}

/// The `stat` line of a task that has exited still holds the tick the task
/// started in, which a listing reads to tell the process from a later one
/// under its ID.
#[test]
fn the_start_tick_field_is_read_whatever_the_task_s_state() {
    for state in ['S', 'Z', 'X'] {
        assert_eq!(
            start_tick_field(&stat_line(TID, state, THREAD_STARTED)),
            Some(900),
            "state {state}"
        );
    }
    assert_eq!(start_tick_field("31 (name) Z 1 2"), None);
}
