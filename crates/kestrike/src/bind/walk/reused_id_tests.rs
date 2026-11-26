//! Walks over a constructed process table in which the host gives the ID of
//! a process that exited to the process that inherits the device, and no
//! listing reads a start tick for either process under that ID.
//!
//! The walk's module documentation states what these tests judge: "A
//! descriptor that passes from parent to child by `fork` alone through the
//! whole walk is then reported", where "a listing tells processes apart by
//! ID and the clock tick the leader started in". `Host::check_unused` asks
//! the walk alone for open descriptors, so a device the walk misses reads
//! as unused.
//!
//! [`Table`] reads no file: it stands behind the walk's own [`Os`] trait,
//! and one walker walks it in the rounds of [`settled`]. A process of the
//! table has a start tick, and the tick reads as `None` once the process is
//! gone, as procfs answers for a process that exited after the listing
//! returned its ID. The table gives each new process the lowest free ID
//! above the last ID given, as the kernel's cursor does, so an ID is given
//! again only when its process exited and the cursor stands just below it.
//!
//! The schedule holds three forks and exits and no more:
//!
//! 1. The first listing returns the bystander, the holder of the device and
//!    a third process, the leaver. The leaver exits before the listing reads
//!    its start tick.
//! 2. The holder forks a child and exits before the walk reads the holder's
//!    table. The host gives the child the lowest free ID above the last,
//!    which is the leaver's.
//! 3. The second listing returns the child's ID. The child forks a
//!    grandchild and exits before the listing reads its start tick.
//!
//! The device is open at every instant, the cursor never turns back, each
//! child's ID lies above its parent's, and no process takes the ID of one
//! that started in its own clock tick: the leaver started before the walk
//! and the child within it.
//!
//! A second form keeps steps 1 and 2 and changes step 3: the child forks
//! nothing and lives on with the device, and the table cannot read the
//! child's start tick while it lives. The second listing returns the child
//! under the leaver's ID, with no start tick, as the first returned the
//! leaver.
//!
//! Both forms also run over a table that reads no start tick at all through
//! the walk, of the bystander either. Each process still starts in the tick
//! the schedule gives it, so the child does not start in the leaver's tick.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString};
use std::io;
use std::sync::Mutex;

use super::{Facts, Listed, Node, Os, Queue, Status, TASK_LINKS, Walker, answer, settled};

/// The first process ID of the constructed table, above every ID the kernel assigns, so no
/// process of the table is the test's own.
const FIRST_PID: u32 = 1 << 23;
/// A process that lives through the walk and holds no device.
const BYSTANDER: u32 = FIRST_PID + 10;
/// The process that holds the device when the walk begins.
const HOLDER: u32 = FIRST_PID + 20;
/// A process that holds no device and, in one of the two walks, exits while the first listing
/// is read.
const LEAVER: u32 = FIRST_PID + 30;
/// The clock tick the walk began in.
const BEGUN: u64 = 1_000;

const DEVICE: Node = Node::Device {
    block: true,
    major: 259,
    minor: 1,
};
const FILE: Node = Node::File {
    major: 8,
    minor: 1,
    inode: 7,
};

/// A single-threaded process: its one descriptor and the clock tick it started in, or `None`
/// when the table cannot read that tick while the process lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Process {
    node: Node,
    started: Option<u64>,
}

#[derive(Debug)]
struct State {
    processes: BTreeMap<u32, Process>,
    /// Whether the leaver exits once the first listing has returned every ID.
    leaver_exits: bool,
    /// Whether the holder's child lives on with the device, under a start tick the table
    /// cannot read, where it otherwise hands the device to a grandchild.
    child_stays_unread: bool,
    /// Whether the table reads the start tick of no process through the whole walk.
    reads_no_tick: bool,
    /// Listings of the process table begun so far.
    listings: u32,
    /// The ID of the task started last.
    last: u32,
    /// Each fork so far: the parent's ID and the child's.
    forks: Vec<(u32, u32)>,
}

impl State {
    /// `parent` forks a child, which holds a copy of its table, and exits. The child takes the
    /// lowest free ID above the last ID given and starts in a clock tick after the walk began,
    /// which the table reads unless the child is one that stays unread.
    fn hand_on(&mut self, parent: u32) {
        let Some(held) = self.processes.remove(&parent) else {
            return;
        };
        let child = (self.last + 1..)
            .find(|id| !self.processes.contains_key(id))
            .unwrap();
        let started = (!self.child_stays_unread).then_some(BEGUN + 1 + self.forks.len() as u64);
        self.processes.insert(
            child,
            Process {
                node: held.node,
                started,
            },
        );
        self.last = child;
        self.forks.push((parent, child));
    }

    /// The process that holds the device.
    fn holder(&self) -> u32 {
        let mut holders = self
            .processes
            .iter()
            .filter(|(_, process)| process.node == DEVICE);
        let holder = holders.next().expect("the device is open at every instant");
        assert!(holders.next().is_none());
        *holder.0
    }

    /// What happens once a listing has returned every ID and before it reads a start tick.
    fn listed(&mut self, listing: u32) {
        match listing {
            1 if self.leaver_exits => {
                self.processes.remove(&LEAVER);
            }
            2 if !self.child_stays_unread => self.hand_on(self.holder()),
            _ => {}
        }
    }

    /// What happens when the walk first asks for the table or the threads of `pid`: the holder
    /// forks and exits before the walk of the first round reads its table.
    fn asked(&mut self, pid: u32) {
        if pid == HOLDER && self.forks.is_empty() {
            self.hand_on(HOLDER);
        }
    }
}

/// A process table of single-threaded processes, each with one descriptor.
struct Table(Mutex<State>);

/// The process whose descriptor table or `task` directory `path` names.
fn process(path: &CStr) -> Option<(u32, bool)> {
    let (pid, rest) = path.to_str().ok()?.split_once('/')?;
    Some((pid.parse().ok()?, rest == "fd"))
}

fn gone() -> io::Error {
    io::Error::from_raw_os_error(libc::ENOENT)
}

impl Os for Table {
    /// The process table, or the descriptor table of this process.
    type Table = Option<u32>;

    fn status(&self, path: &CStr) -> io::Result<Status> {
        let mut state = self.0.lock().unwrap();
        let (pid, _) = process(path).ok_or_else(gone)?;
        state.asked(pid);
        state.processes.get(&pid).ok_or_else(gone)?;
        Ok(Status {
            size: 1,
            links: TASK_LINKS + 1,
        })
    }

    fn open(&self, path: &CStr) -> io::Result<Option<u32>> {
        let mut state = self.0.lock().unwrap();
        let (pid, table) = process(path).ok_or_else(gone)?;
        state.asked(pid);
        let present = table && state.processes.contains_key(&pid);
        present.then_some(Some(pid)).ok_or_else(gone)
    }

    /// Lists the process table as the kernel does: in ascending ID order, one record a read,
    /// each read resuming above the last ID the read before returned.
    fn entries(
        &self,
        table: &Option<u32>,
        _: &mut [u8],
        mut visit: impl FnMut(&CStr),
    ) -> io::Result<()> {
        let Some(pid) = *table else {
            let listing = {
                let mut state = self.0.lock().unwrap();
                state.listings += 1;
                state.listings
            };
            let mut position = 0;
            loop {
                let next = {
                    let state = self.0.lock().unwrap();
                    state.processes.range(position + 1..).next().map(|at| *at.0)
                };
                let Some(pid) = next else {
                    break;
                };
                visit(&CString::new(pid.to_string()).unwrap());
                position = pid;
            }
            self.0.lock().unwrap().listed(listing);
            return Ok(());
        };
        let present = self.0.lock().unwrap().processes.contains_key(&pid);
        if !present {
            return Err(gone());
        }
        visit(c"0");
        Ok(())
    }

    fn node(&self, table: &Option<u32>, _: &CStr) -> io::Result<Option<Node>> {
        let state = self.0.lock().unwrap();
        let pid = table.ok_or_else(gone)?;
        state
            .processes
            .get(&pid)
            .map(|process| Some(process.node))
            .ok_or_else(gone)
    }

    fn shares_leader_table(&self, _: u32, _: u32) -> bool {
        unreachable!("no process of the table has a second thread")
    }

    /// The tick a present process started in, where the table can read it, and `None` for a
    /// process that is gone and for every process of a table that reads no tick.
    fn started(&self, pid: u32, task: u32) -> Option<u64> {
        assert_eq!(pid, task, "no process of the table has a second thread");
        let state = self.0.lock().unwrap();
        let started = state.processes.get(&pid)?.started;
        started.filter(|_| !state.reads_no_tick)
    }

    fn last_task(&self) -> Option<u32> {
        Some(self.0.lock().unwrap().last)
    }
}

/// What one walk showed: its answer, the forks that ran, and the process table as the walk
/// left it.
struct Walked {
    answer: Option<Vec<Node>>,
    forks: Vec<(u32, u32)>,
    end: BTreeMap<u32, Process>,
}

/// The walk of [`walk_of`] in which the holder's child hands the device to a grandchild.
fn walk(leaver_exits: bool) -> Walked {
    walk_of(leaver_exits, false)
}

/// The walk of [`walk_over`] over a table that reads the start tick of each process the
/// schedule lets it read.
fn walk_of(leaver_exits: bool, child_stays_unread: bool) -> Walked {
    walk_over(leaver_exits, child_stays_unread, false)
}

/// One walker's walk for the device, in the rounds of [`settled`], over the bystander, the
/// holder and the leaver. The last ID the host gave before the walk is the one below the
/// leaver's.
fn walk_over(leaver_exits: bool, child_stays_unread: bool, reads_no_tick: bool) -> Walked {
    let before = |node, started| Process {
        node,
        started: Some(started),
    };
    let table = Table(Mutex::new(State {
        processes: BTreeMap::from([
            (BYSTANDER, before(FILE, 10)),
            (HOLDER, before(DEVICE, 20)),
            (LEAVER, before(FILE, 30)),
        ]),
        leaver_exits,
        child_stays_unread,
        reads_no_tick,
        listings: 0,
        last: LEAVER - 1,
        forks: Vec::new(),
    }));
    let facts = Facts {
        reports_count: true,
        kcmp: true,
        begun: Some(BEGUN),
        walkers: 1,
    };
    let found = Mutex::new(Some(Vec::new()));
    let matches = |node| node == DEVICE;
    let round = |seen: &mut BTreeSet<Listed>| {
        let queue = Queue::<Option<u32>>::default();
        let listed = queue.list(&table, &None, seen);
        Walker::new(&table, &queue, &matches, facts).walk(&found);
        listed
    };
    let walked = settled(round, || table.last_task());
    let state = table.0.into_inner().unwrap();
    Walked {
        answer: answer(found, walked),
        forks: state.forks,
        end: state.processes,
    }
}

/// The premise: while the leaver lives, the host gives the holder's child and its grandchild
/// IDs no listing has returned, and the walk reports the device from the grandchild's table.
#[test]
fn a_device_handed_on_twice_under_ids_no_listing_returned_is_reported() {
    let walked = walk(false);
    assert_eq!(
        walked.forks,
        [(HOLDER, LEAVER + 1), (LEAVER + 1, LEAVER + 2)],
        "premise: the holder handed the device to its child, and the child to the grandchild"
    );
    assert_eq!(
        walked.end[&(LEAVER + 2)].node,
        DEVICE,
        "premise: the grandchild holds the device when the walk ends"
    );
    assert_eq!(walked.answer, Some(vec![DEVICE]));
}

/// The leaver exits before the first listing reads its start tick, and the host gives its ID
/// to the holder's child, which exits before the second listing reads its start tick. The
/// device was open at every instant, in the holder, its child or its grandchild, so the walk
/// fails or reports it.
#[test]
fn a_device_handed_to_a_child_under_the_id_of_a_process_that_exited_unread_is_reported() {
    let walked = walk(true);
    assert_eq!(
        walked.forks,
        [(HOLDER, LEAVER), (LEAVER, LEAVER + 1)],
        "premise: the child took the ID the leaver left, and the grandchild the next"
    );
    assert_eq!(
        walked.end[&(LEAVER + 1)].node,
        DEVICE,
        "premise: the grandchild holds the device when the walk ends"
    );
    assert!(
        walked
            .answer
            .as_ref()
            .is_none_or(|found| found.contains(&DEVICE)),
        "a device open through the whole walk, handed from parent to child by fork alone, \
         was reported as open in no process: the walk answered {:?}",
        walked.answer
    );
}

/// The leaver exits before the first listing reads its start tick, and the host gives its ID
/// to the holder's child, which lives on with the device under a start tick the table cannot
/// read. The second listing returns the child as the first returned the leaver, under one ID
/// with no start tick. The device was open at every instant, in the holder or its child, and
/// the child holds it when the walk ends, so the walk fails or reports it.
#[test]
fn a_device_held_by_a_live_child_with_no_readable_start_tick_under_a_reused_id_is_reported() {
    let walked = walk_of(true, true);
    assert_eq!(
        walked.forks,
        [(HOLDER, LEAVER)],
        "premise: the child took the ID the leaver left and forked nothing"
    );
    assert_eq!(
        walked.end[&LEAVER],
        Process {
            node: DEVICE,
            started: None
        },
        "premise: the child holds the device when the walk ends, and its start tick cannot be read"
    );
    assert!(
        walked
            .answer
            .as_ref()
            .is_none_or(|found| found.contains(&DEVICE)),
        "a device open through the whole walk, in a process that lives when the walk ends, \
         was reported as open in no process: the walk answered {:?}",
        walked.answer
    );
}

/// The schedule of the second test over a table that reads no start tick through the whole
/// walk. The leaver started before the walk and the child that takes its ID within it, the
/// cursor never turns back and each child's ID lies above its parent's. The device was open at
/// every instant, in the holder, its child or its grandchild, so the walk fails or reports it.
#[test]
fn a_device_handed_to_a_child_under_a_reused_id_is_reported_when_no_start_tick_is_read() {
    let walked = walk_over(true, false, true);
    assert_eq!(
        walked.forks,
        [(HOLDER, LEAVER), (LEAVER, LEAVER + 1)],
        "premise: the child took the ID the leaver left, and the grandchild the next"
    );
    assert_eq!(
        walked.end[&(LEAVER + 1)],
        Process {
            node: DEVICE,
            started: Some(BEGUN + 2)
        },
        "premise: the grandchild holds the device when the walk ends, and started within the walk"
    );
    assert!(
        walked
            .answer
            .as_ref()
            .is_none_or(|found| found.contains(&DEVICE)),
        "a device open through the whole walk, handed from parent to child by fork alone, \
         was reported as open in no process by a walk that read no start tick: the walk \
         answered {:?}",
        walked.answer
    );
}

/// The schedule of the third test over a table that reads no start tick through the whole
/// walk: the child takes the ID the leaver left and lives on with the device. The device was
/// open at every instant, in the holder or its child, so the walk fails or reports it.
#[test]
fn a_device_held_by_a_live_child_under_a_reused_id_is_reported_when_no_start_tick_is_read() {
    let walked = walk_over(true, true, true);
    assert_eq!(
        walked.forks,
        [(HOLDER, LEAVER)],
        "premise: the child took the ID the leaver left and forked nothing"
    );
    assert_eq!(
        walked.end[&LEAVER].node, DEVICE,
        "premise: the child holds the device when the walk ends"
    );
    assert!(
        walked
            .answer
            .as_ref()
            .is_none_or(|found| found.contains(&DEVICE)),
        "a device open through the whole walk, in a process that lives when the walk ends, \
         was reported as open in no process by a walk that read no start tick: the walk \
         answered {:?}",
        walked.answer
    );
}
