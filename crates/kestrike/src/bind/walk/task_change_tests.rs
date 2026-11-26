//! Walks over a constructed process table whose processes and threads
//! change while one walker reads it.
//!
//! The walk reads the table of each process's leader and of each of its
//! other threads. It uses `kcmp` to skip a thread from the initial `task`
//! listing only when the first listed thread started before the walk and is
//! still present after the comparisons. In the recheck it uses `kcmp` to
//! skip a thread a later listing names only while a thread that started
//! before the walk, or one listed before the walk last read the table under
//! the process's ID, is still present after the comparisons. It reads the
//! table under the process's ID again when the first listed thread is gone,
//! or when the process had other threads and none remains, since an exec
//! may have replaced the leader whose table it read.
//!
//! [`Tasks`] answers every listing, `stat`, `statx` and `kcmp` from its
//! current state and applies each scheduled change before the read it is
//! due at. It lists a `task` directory as the kernel does: in calls of as
//! many records as the walker's buffer holds, a read apart, each later call
//! resuming at the thread the call before could not return while that
//! thread is present, and otherwise at the count of tasks already returned.
//! Each test schedules changes under which every table a task uses when the
//! walk ends held its descriptors through the whole walk. The judgment is
//! that the walk reports each of those descriptors' nodes, and no node that
//! no table held.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString};
use std::io;
use std::sync::Mutex;

use super::{
    Facts, LISTINGS, Listed, Node, Os, Queue, RECORDS, SHARE, Status, TASK_LINKS, Walker, answer,
    settled,
};

/// The first process ID of a constructed table, above every ID the kernel
/// assigns, so no process of the table is the test's own.
const FIRST_PID: u32 = 1 << 23;
/// The first ID of a thread that starts during a walk.
const FIRST_STARTED: u32 = FIRST_PID + 1_000;
/// The clock tick the walk began in; every constructed thread started in an
/// earlier one.
const BEGUN: u64 = 1_000;

/// An open directory of a constructed table. A descriptor table is named by
/// its task, as procfs resolves an open `fd` directory through the task it
/// was opened for.
#[derive(Debug, Clone, Copy)]
enum Opened {
    Root,
    Task(u32),
    /// The table of a process's leader, or the path of a thread's table.
    Descriptors(u32, Option<u32>),
    /// The open table of the thread of this process and ID born at this
    /// read. It names nothing once that thread is gone, whatever thread
    /// takes the ID afterward.
    Held(u32, u32, u64),
}

#[derive(Debug, Clone)]
struct Thread {
    tid: u32,
    /// The index in [`State::tables`] of the table the thread uses.
    table: usize,
    /// The clock tick the thread started in.
    started: u64,
    /// The read the thread started before, zero for a thread of the
    /// constructed table: with the ID, the thread's identity.
    born: u64,
}

#[derive(Debug, Clone)]
struct Process {
    /// The index in [`State::tables`] of the leader's table.
    table: usize,
    threads: Vec<Thread>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Change {
    /// The thread exits.
    Exit(u32, u32),
    /// The thread execs: every other thread of its process is gone, and the
    /// process's ID names the thread's table.
    Exec(u32, u32),
    /// A thread with this ID starts in the process, in the tick the walk
    /// began in, on the table the process's ID names.
    Start(u32, u32),
    /// The process forks a child with this ID, which holds a copy of its
    /// leader's table, and exits with every thread it has.
    Fork(u32, u32),
    /// A thread with this ID starts in the process, in the tick the walk
    /// began in, on a table of its own that holds every descriptor of the
    /// table the process's ID names, as a `clone` without `CLONE_FILES`
    /// copies them, and the leader then closes each of its own.
    Apart(u32, u32),
    /// Thread `.1` of process `.0` starts thread `.2` on its own table, as
    /// `pthread_create` does from a thread whose table is private, in the
    /// clock tick as many ticks after the one the walk began in as reads
    /// came before it.
    Spawn(u32, u32, u32),
    /// The leader copies the table the process's ID names, as
    /// `unshare(CLONE_FILES)` does, and closes every descriptor of its
    /// copy. The process's other threads keep the table.
    Unshare(u32),
}

#[derive(Debug, Clone)]
struct State {
    processes: BTreeMap<u32, Process>,
    /// Each descriptor table's nodes, by descriptor number.
    tables: Vec<Vec<Node>>,
    /// Reads answered so far.
    reads: u64,
    /// Each change and the read it is applied before.
    changes: Vec<(u64, Change)>,
    /// The changes that found their thread present, in the order applied.
    applied: Vec<Change>,
    /// How many times the walk opened each process's leader table.
    opens: BTreeMap<u32, u32>,
    /// Nodes the walk read from tables it opened under a thread's ID.
    through: usize,
}

impl State {
    /// Counts one read and applies every change due before it.
    fn read(&mut self) {
        let due: Vec<Change> = self
            .changes
            .iter()
            .filter(|(at, _)| *at == self.reads)
            .map(|(_, change)| *change)
            .collect();
        self.reads += 1;
        for change in due {
            match change {
                Change::Exit(pid, tid) => {
                    let Some(process) = self.processes.get_mut(&pid) else {
                        continue;
                    };
                    let before = process.threads.len();
                    process.threads.retain(|thread| thread.tid != tid);
                    if process.threads.len() < before {
                        self.applied.push(change);
                    }
                }
                Change::Exec(pid, tid) => {
                    let Some(process) = self.processes.get_mut(&pid) else {
                        continue;
                    };
                    if let Some(thread) = process.threads.iter().find(|thread| thread.tid == tid) {
                        process.table = thread.table;
                        process.threads.clear();
                        self.applied.push(change);
                    }
                }
                Change::Spawn(pid, from, tid) => {
                    let Some(table) = self.thread(pid, from).map(|thread| thread.table) else {
                        continue;
                    };
                    let process = self.processes.get_mut(&pid).unwrap();
                    process.threads.push(Thread {
                        tid,
                        table,
                        started: BEGUN + self.reads,
                        born: self.reads,
                    });
                    self.applied.push(change);
                }
                Change::Start(pid, tid) => {
                    let Some(process) = self.processes.get_mut(&pid) else {
                        continue;
                    };
                    process.threads.push(Thread {
                        tid,
                        table: process.table,
                        started: BEGUN,
                        born: self.reads,
                    });
                    self.applied.push(change);
                }
                Change::Fork(pid, child) => {
                    let Some(parent) = self.processes.remove(&pid) else {
                        continue;
                    };
                    self.tables.push(self.tables[parent.table].clone());
                    self.processes.insert(
                        child,
                        Process {
                            table: self.tables.len() - 1,
                            threads: Vec::new(),
                        },
                    );
                    self.applied.push(change);
                }
                Change::Apart(pid, tid) => {
                    let Some(process) = self.processes.get_mut(&pid) else {
                        continue;
                    };
                    process.threads.push(Thread {
                        tid,
                        table: process.table,
                        started: BEGUN,
                        born: self.reads,
                    });
                    process.table = self.tables.len();
                    self.tables.push(Vec::new());
                    self.applied.push(change);
                }
                Change::Unshare(pid) => {
                    let Some(process) = self.processes.get_mut(&pid) else {
                        continue;
                    };
                    process.table = self.tables.len();
                    self.tables.push(Vec::new());
                    self.applied.push(change);
                }
            }
        }
    }

    /// The thread `tid` of `pid`, while it is present.
    fn thread(&self, pid: u32, tid: u32) -> Option<&Thread> {
        let process = self.processes.get(&pid)?;
        process.threads.iter().find(|thread| thread.tid == tid)
    }

    /// The clock tick the leader of `pid` started in, while the process is
    /// present: the tick the walk began in for a child forked during the
    /// walk, and an earlier tick otherwise.
    fn leader_started(&self, pid: u32) -> Option<u64> {
        self.processes.get(&pid)?;
        let forked = self
            .applied
            .iter()
            .any(|change| matches!(*change, Change::Fork(_, child) if child == pid));
        Some(if forked { BEGUN } else { BEGUN - 1 })
    }

    /// The table the task names now, or `None` once the task is gone.
    fn table(&self, pid: u32, tid: Option<u32>) -> Option<usize> {
        match tid {
            None => self.processes.get(&pid).map(|process| process.table),
            Some(tid) => self.thread(pid, tid).map(|thread| thread.table),
        }
    }

    /// The table an open directory names now, and whether it was opened
    /// under a thread's ID; `None` once its task is gone.
    fn opened(&self, opened: Opened) -> Option<(usize, bool)> {
        match opened {
            Opened::Descriptors(pid, tid) => Some((self.table(pid, tid)?, tid.is_some())),
            Opened::Held(pid, tid, born) => {
                let thread = self.thread(pid, tid).filter(|thread| thread.born == born)?;
                Some((thread.table, true))
            }
            Opened::Root | Opened::Task(_) => None,
        }
    }

    /// Every node of a table some task uses.
    fn held(&self) -> BTreeSet<Node> {
        self.processes
            .values()
            .flat_map(|process| {
                process
                    .threads
                    .iter()
                    .map(|thread| thread.table)
                    .chain([process.table])
            })
            .flat_map(|table| self.tables[table].iter().copied())
            .collect()
    }
}

/// A constructed process table.
struct Tasks {
    state: Mutex<State>,
    /// A control's plant: `kcmp` reports every thread sharing its leader's
    /// table.
    kcmp_lies: bool,
    /// How many calls after the first the listings of `task` directories
    /// took.
    resumed: Mutex<u32>,
    /// Thread IDs whose own `fd` directory the walk stat-ed or opened.
    addressed: Mutex<BTreeSet<u32>>,
    /// Nodes read through each thread's own `fd` directory, by the thread's
    /// ID and the read it started before.
    read_under: Mutex<BTreeMap<(u32, u64), usize>>,
}

/// Bytes of one `task` directory record of a seven-digit name.
const TASK_RECORD: usize = 32;

/// The directory `path` names in a constructed table.
fn parse(path: &CStr) -> Option<Opened> {
    let path = path.to_str().ok()?;
    let mut parts = path.split('/');
    let pid = parts.next()?.parse().ok()?;
    match (parts.next()?, parts.next(), parts.next(), parts.next()) {
        ("fd", None, ..) => Some(Opened::Descriptors(pid, None)),
        ("task", None, ..) => Some(Opened::Task(pid)),
        ("task", Some(tid), Some("fd"), None) => {
            Some(Opened::Descriptors(pid, Some(tid.parse().ok()?)))
        }
        _ => None,
    }
}

fn gone() -> io::Error {
    io::Error::from_raw_os_error(libc::ENOENT)
}

impl Tasks {
    /// Records the thread whose own `fd` directory `opened` names.
    fn address(&self, opened: Opened) {
        if let Opened::Descriptors(_, Some(tid)) = opened {
            self.addressed.lock().unwrap().insert(tid);
        }
    }
}

impl Os for Tasks {
    type Table = Opened;

    fn status(&self, path: &CStr) -> io::Result<Status> {
        let mut state = self.state.lock().unwrap();
        state.read();
        let opened = parse(path).ok_or_else(gone)?;
        self.address(opened);
        match opened {
            Opened::Task(pid) => {
                let process = state.processes.get(&pid).ok_or_else(gone)?;
                Ok(Status {
                    size: 0,
                    links: TASK_LINKS + 1 + process.threads.len() as libc::nlink_t,
                })
            }
            Opened::Descriptors(pid, tid) => {
                let table = state.table(pid, tid).ok_or_else(gone)?;
                Ok(Status {
                    size: state.tables[table].len() as libc::off_t,
                    links: 2,
                })
            }
            Opened::Root | Opened::Held(..) => Err(gone()),
        }
    }

    fn open(&self, path: &CStr) -> io::Result<Opened> {
        let mut state = self.state.lock().unwrap();
        state.read();
        let opened = parse(path).ok_or_else(gone)?;
        self.address(opened);
        let present = match opened {
            Opened::Root => true,
            Opened::Task(pid) => state.processes.contains_key(&pid),
            Opened::Descriptors(pid, tid) => state.table(pid, tid).is_some(),
            Opened::Held(..) => false,
        };
        if let (true, Opened::Descriptors(pid, None)) = (present, opened) {
            *state.opens.entry(pid).or_default() += 1;
        }
        let opened = match opened {
            Opened::Descriptors(pid, Some(tid)) => state
                .thread(pid, tid)
                .map_or(opened, |thread| Opened::Held(pid, tid, thread.born)),
            opened => opened,
        };
        present.then_some(opened).ok_or_else(gone)
    }

    fn entries(
        &self,
        table: &Opened,
        records: &mut [u8],
        mut visit: impl FnMut(&CStr),
    ) -> io::Result<()> {
        let names: Vec<String> = {
            let mut state = self.state.lock().unwrap();
            state.read();
            match *table {
                Opened::Root => state.processes.keys().map(u32::to_string).collect(),
                Opened::Task(pid) => {
                    // One `getdents64` call fills `records` with the 32-byte
                    // records of seven-digit names, the first call after
                    // `.` and `..`.
                    let mut room = records.len() / TASK_RECORD - 2;
                    let mut listed: Vec<u32> = Vec::new();
                    let mut cached = None;
                    loop {
                        let process = state.processes.get(&pid).ok_or_else(gone)?;
                        let tasks: Vec<u32> = [pid]
                            .into_iter()
                            .chain(process.threads.iter().map(|thread| thread.tid))
                            .collect();
                        // The kernel resumes at the thread the last call
                        // could not return while it is present, and
                        // otherwise at the count of tasks it returned.
                        let from = cached
                            .and_then(|tid| tasks.iter().position(|task| *task == tid))
                            .unwrap_or(listed.len());
                        let call = tasks.get(from..).unwrap_or_default();
                        listed.extend(call.iter().take(room));
                        cached = call.get(room).copied();
                        if cached.is_none() {
                            break;
                        }
                        room = records.len() / TASK_RECORD;
                        *self.resumed.lock().unwrap() += 1;
                        state.read();
                    }
                    listed.iter().map(u32::to_string).collect()
                }
                Opened::Descriptors(..) | Opened::Held(..) => {
                    let (table, _) = state.opened(*table).ok_or_else(gone)?;
                    (0..state.tables[table].len())
                        .map(|fd| fd.to_string())
                        .collect()
                }
            }
        };
        for name in names {
            visit(&CString::new(name).unwrap());
        }
        Ok(())
    }

    fn node(&self, opened: &Opened, name: &CStr) -> io::Result<Option<Node>> {
        let mut state = self.state.lock().unwrap();
        state.read();
        let (table, thread) = state.opened(*opened).ok_or_else(gone)?;
        let fd: usize = name.to_str().unwrap().parse().unwrap();
        let node = state.tables[table].get(fd).copied().ok_or_else(gone)?;
        state.through += usize::from(thread);
        if let Opened::Held(_, tid, born) = *opened {
            let mut read_under = self.read_under.lock().unwrap();
            *read_under.entry((tid, born)).or_default() += 1;
        }
        Ok(Some(node))
    }

    fn shares_leader_table(&self, pid: u32, tid: u32) -> bool {
        let mut state = self.state.lock().unwrap();
        state.read();
        let leader = state.table(pid, None);
        let thread = state.table(pid, Some(tid));
        thread.is_some() && (self.kcmp_lies || thread == leader)
    }

    /// The listing reads the start tick of each listed process's leader.
    /// Like [`last_task`](Self::last_task) that counts as no read of the
    /// table and applies no change, so the reads a change is due before
    /// number as they did before the listing read it.
    fn started(&self, pid: u32, tid: u32) -> Option<u64> {
        let mut state = self.state.lock().unwrap();
        if tid == pid {
            return state.leader_started(pid);
        }
        state.read();
        state.thread(pid, tid).map(|thread| thread.started)
    }

    /// The count of threads started so far. It is no read of the table, so
    /// it applies no change.
    fn last_task(&self) -> Option<u32> {
        let state = self.state.lock().unwrap();
        let started = |change: &&Change| {
            matches!(
                change,
                Change::Start(..) | Change::Apart(..) | Change::Spawn(..)
            )
        };
        Some(state.applied.iter().filter(started).count() as u32)
    }
}

/// What one walk over a constructed table showed.
struct Walked {
    answer: Option<Vec<Node>>,
    /// The table as the walk left it.
    end: State,
    /// Every node some table held.
    all: BTreeSet<Node>,
    /// How many calls after the first the listings of `task` directories
    /// took.
    resumed: u32,
    /// Thread IDs whose own `fd` directory the walk stat-ed or opened.
    addressed: BTreeSet<u32>,
    /// Nodes read through each thread's own `fd` directory, by the thread's
    /// ID and the read it started before.
    read_under: BTreeMap<(u32, u64), usize>,
}

/// One walker's walk over `state` in the rounds of [`settled`], each after
/// its round's listing, begun in the clock tick `begun`, or with the boot
/// clock unreadable when `begun` is `None`.
fn walk(
    state: State,
    kcmp: bool,
    reports_count: bool,
    kcmp_lies: bool,
    begun: Option<u64>,
) -> Walked {
    let all = state.tables.iter().flatten().copied().collect();
    let tasks = Tasks {
        state: Mutex::new(state),
        kcmp_lies,
        resumed: Mutex::new(0),
        addressed: Mutex::default(),
        read_under: Mutex::default(),
    };
    let facts = Facts {
        reports_count,
        kcmp,
        begun,
        walkers: 1,
    };
    let found = Mutex::new(Some(Vec::new()));
    let matches = |_| true;
    let round = |seen: &mut BTreeSet<Listed>| {
        let queue = Queue::<Opened>::default();
        let listed = queue.list(&tasks, &Opened::Root, seen);
        Walker::new(&tasks, &queue, &matches, facts).walk(&found);
        listed
    };
    let walked = settled(round, || tasks.last_task());
    Walked {
        answer: answer(found, walked),
        end: tasks.state.into_inner().unwrap(),
        all,
        resumed: tasks.resumed.into_inner().unwrap(),
        addressed: tasks.addressed.into_inner().unwrap(),
        read_under: tasks.read_under.into_inner().unwrap(),
    }
}

/// Judges one walk: it answers, in ascending order and each node once,
/// with every node of a table some task uses at its end and no node that no
/// table held.
fn judge(seed: u64, walked: &Walked) {
    let found = walked
        .answer
        .as_ref()
        .unwrap_or_else(|| panic!("seed {seed}: the walk failed over readable tables"));
    assert!(
        found.windows(2).all(|pair| pair[0] < pair[1]),
        "seed {seed}: the answer is unsorted or repeats a node"
    );
    let found: BTreeSet<Node> = found.iter().copied().collect();
    let missed: Vec<Node> = walked.end.held().difference(&found).copied().collect();
    assert!(
        missed.is_empty(),
        "seed {seed}: a node held through the walk was not reported: {} missed, the first {:?}, after {:?}",
        missed.len(),
        missed.first(),
        walked.end.applied
    );
    assert!(
        found.is_subset(&walked.all),
        "seed {seed}: the walk reported a node no table held"
    );
}

/// One process holds one device open. After the listing, and before the
/// walk reads the process's table, the process forks a child that inherits
/// the descriptor, and exits. The child's table holds the device when the
/// walk ends, and the open file was held at every instant of the walk.
#[test]
fn a_descriptor_inherited_by_a_child_forked_after_the_listing_is_reported() {
    let device = Node::Device {
        block: true,
        major: 259,
        minor: 1,
    };
    let state = |changes| State {
        processes: BTreeMap::from([(
            FIRST_PID,
            Process {
                table: 0,
                threads: Vec::new(),
            },
        )]),
        tables: vec![vec![device]],
        reads: 0,
        changes,
        applied: Vec::new(),
        opens: BTreeMap::new(),
        through: 0,
    };
    let unchanged = walk(state(Vec::new()), true, true, false, Some(BEGUN));
    assert_eq!(
        unchanged.answer,
        Some(vec![device]),
        "premise: the holder is found"
    );
    // Read 0 is the listing; the fork is due before each later read in turn.
    for at in 1..unchanged.end.reads {
        let fork = Change::Fork(FIRST_PID, FIRST_PID + 1);
        let walked = walk(state(vec![(at, fork)]), true, true, false, Some(BEGUN));
        assert_eq!(
            walked.end.applied,
            [fork],
            "premise: the fork ran at read {at}"
        );
        judge(at, &walked);
    }
}

/// The module documentation promises that a descriptor that passes from
/// parent to child by `fork` alone through the whole walk is reported. Two
/// processes are listed: the holder of the device, and a second process
/// with an empty table under the higher ID, which the walker reads first.
/// Before read `at` the second process exits, the holder forks a child that
/// the host numbers with the second process's former ID, and the holder
/// exits; [`Change::Fork`] onto an ID in use applies the three together. The
/// child holds the device when the walk ends, and some process held it at
/// every instant of the walk.
#[test]
fn a_descriptor_inherited_by_a_child_under_a_departed_process_s_id_is_reported() {
    let device = Node::Device {
        block: true,
        major: 259,
        minor: 1,
    };
    let (holder, departed) = (FIRST_PID, FIRST_PID + 1);
    let process = |table| Process {
        table,
        threads: Vec::new(),
    };
    let state = |changes| State {
        processes: BTreeMap::from([(holder, process(0)), (departed, process(1))]),
        tables: vec![vec![device], Vec::new()],
        reads: 0,
        changes,
        applied: Vec::new(),
        opens: BTreeMap::new(),
        through: 0,
    };
    let unchanged = walk(state(Vec::new()), true, true, false, Some(BEGUN));
    assert_eq!(
        unchanged.answer,
        Some(vec![device]),
        "premise: the holder is found"
    );
    // Read 0 is the listing; the fork is due before each later read in turn.
    let mut missed = Vec::new();
    for at in 1..unchanged.end.reads {
        let fork = Change::Fork(holder, departed);
        let walked = walk(state(vec![(at, fork)]), true, true, false, Some(BEGUN));
        assert_eq!(
            walked.end.applied,
            [fork],
            "premise: the fork ran at read {at}"
        );
        assert_eq!(
            walked.end.held(),
            BTreeSet::from([device]),
            "premise: the child holds the device when the walk ends"
        );
        if walked.answer != Some(vec![device]) {
            missed.push((at, walked.answer));
        }
    }
    assert!(
        missed.is_empty(),
        "the device was not reported with the fork before reads {missed:?}"
    );
}

/// The hand-off of the test above, twice in one walk. Three processes are
/// listed: the holder of the device and two with empty tables under higher
/// IDs. Before read `first` the second process exits, the holder forks a
/// child under the second's former ID and exits; before read `then` the
/// third process exits, that child forks a child of its own under the
/// third's former ID and exits. Some process held the device at every
/// instant of the walk, and one holds it when the walk ends.
#[test]
fn a_descriptor_inherited_twice_under_departed_processes_ids_is_reported() {
    let device = Node::Device {
        block: true,
        major: 259,
        minor: 1,
    };
    let (holder, second, third) = (FIRST_PID, FIRST_PID + 1, FIRST_PID + 2);
    let process = |table| Process {
        table,
        threads: Vec::new(),
    };
    let state = |changes| State {
        processes: BTreeMap::from([
            (holder, process(0)),
            (second, process(1)),
            (third, process(2)),
        ]),
        tables: vec![vec![device], Vec::new(), Vec::new()],
        reads: 0,
        changes,
        applied: Vec::new(),
        opens: BTreeMap::new(),
        through: 0,
    };
    let unchanged = walk(state(Vec::new()), true, true, false, Some(BEGUN));
    assert_eq!(
        unchanged.answer,
        Some(vec![device]),
        "premise: the holder is found"
    );
    // A hand-off lengthens the walk by a round, so the second is due before
    // reads past the unchanged walk's last; one the walk ends before is not
    // applied, and the first fork's child then holds the device.
    let (child, grandchild) = (Change::Fork(holder, second), Change::Fork(second, third));
    let mut missed = Vec::new();
    let mut both = 0;
    for first in 1..unchanged.end.reads {
        for then in first..3 * unchanged.end.reads {
            let changes = vec![(first, child), (then, grandchild)];
            let walked = walk(state(changes), true, true, false, Some(BEGUN));
            assert_eq!(
                walked.end.applied.first(),
                Some(&child),
                "premise: the first fork ran at read {first}"
            );
            assert_eq!(
                walked.end.held(),
                BTreeSet::from([device]),
                "premise: a descendant holds the device when the walk ends"
            );
            both += usize::from(walked.end.applied == [child, grandchild]);
            if walked.answer != Some(vec![device]) {
                missed.push((first, then, walked.answer));
            }
        }
    }
    assert!(both > 0, "premise: some walk saw both forks");
    assert!(
        missed.is_empty(),
        "the device was not reported with the forks before reads {missed:?}"
    );
}

/// One process of one thread whose table holds one descriptor. Before read
/// `start` a thread starts on a table of its own with that descriptor and
/// the leader closes its own; before read `exec` that thread execs, so the
/// process's ID names the thread's table.
fn parting(start: u64, exec: Option<u64>) -> State {
    let node = Node::File {
        major: 0,
        minor: 0,
        inode: 1,
    };
    let process = Process {
        table: 0,
        threads: Vec::new(),
    };
    let mut changes = vec![(start, Change::Apart(FIRST_PID, FIRST_STARTED))];
    changes.extend(exec.map(|at| (at, Change::Exec(FIRST_PID, FIRST_STARTED))));
    State {
        processes: BTreeMap::from([(FIRST_PID, process)]),
        tables: vec![vec![node]],
        reads: 0,
        changes,
        applied: Vec::new(),
        opens: BTreeMap::new(),
        through: 0,
    }
}

/// A descriptor stays open in some table of a process through the whole
/// walk while the process's one thread starts a second on a table of its
/// own, closes its own copy, and the second thread execs. The walk reports
/// the descriptor's node wherever the start and the exec fall among its
/// reads, with and without `kcmp` and counted table sizes. Returns how many
/// walks saw the thread start, and how many of those saw it exec.
fn parted_and_execed() -> (u32, u32) {
    let (mut started, mut execed) = (0, 0);
    for (kcmp, reports_count) in [(true, false), (true, true), (false, false), (false, true)] {
        let reads = walk(
            parting(u64::MAX, None),
            kcmp,
            reports_count,
            false,
            Some(BEGUN),
        )
        .end
        .reads;
        for start in 0..=reads + 2 {
            for exec in (start..=reads + 4).map(Some).chain([None]) {
                let walked = walk(
                    parting(start, exec),
                    kcmp,
                    reports_count,
                    false,
                    Some(BEGUN),
                );
                let applied = &walked.end.applied;
                started += u32::from(!applied.is_empty());
                execed += u32::from(applied.len() == 2);
                judge(start << 8 | exec.unwrap_or(0xff), &walked);
            }
        }
    }
    (started, execed)
}

/// The walk's module documentation reads the table under a process's ID
/// again "since an exec may have replaced the leader whose table it read".
/// A thread that starts after the walk counted the process's threads, on a
/// table of its own, and execs before the walk lists them, replaces that
/// leader the same way.
#[test]
fn a_thread_that_starts_apart_and_execs_leaves_its_table_reported() {
    let (started, execed) = parted_and_execed();
    assert!(
        started > 0 && execed > 0,
        "premise: some walk saw the start and some the exec"
    );
}

/// A process whose leader holds no descriptor and whose one other thread,
/// started before the walk, holds `nodes` on a table of its own. Before read
/// `exec` that thread execs, so the process's ID names its table; before
/// read `start` the process starts a thread, on a table of its own when
/// `apart` and on the table the process's ID names otherwise.
fn execed_then_started(nodes: u64, exec: u64, start: u64, apart: bool) -> State {
    let (pid, tid) = (FIRST_PID, FIRST_PID + 101);
    let held = (1..=nodes).map(|inode| Node::File {
        major: 0,
        minor: 0,
        inode,
    });
    let thread = Thread {
        tid,
        table: 1,
        started: BEGUN - 1,
        born: 0,
    };
    let process = Process {
        table: 0,
        threads: vec![thread],
    };
    let started = if apart {
        Change::Apart(pid, FIRST_STARTED)
    } else {
        Change::Start(pid, FIRST_STARTED)
    };
    State {
        processes: BTreeMap::from([(pid, process)]),
        tables: vec![Vec::new(), held.collect()],
        reads: 0,
        changes: vec![(exec, Change::Exec(pid, tid)), (start, started)],
        applied: Vec::new(),
        opens: BTreeMap::new(),
        through: 0,
    }
}

/// Every walk of [`execed_then_started`] in which both changes applied,
/// over each pair of reads and each setting of `kcmp` and counted table
/// sizes: how many there were, and the `(kcmp, counts, exec, start)` of each
/// that did not report every node the table holds.
fn execed_then_started_walks(nodes: u64, apart: bool) -> (u32, Vec<(bool, bool, u64, u64)>) {
    let (mut both, mut missed) = (0, Vec::new());
    for (kcmp, reports_count) in [(true, false), (true, true), (false, false), (false, true)] {
        let quiet = execed_then_started(nodes, u64::MAX, u64::MAX, apart);
        let reads = walk(quiet, kcmp, reports_count, false, Some(BEGUN))
            .end
            .reads;
        for exec in 0..=reads + 4 {
            for start in exec..=reads + 6 {
                let state = execed_then_started(nodes, exec, start, apart);
                let walked = walk(state, kcmp, reports_count, false, Some(BEGUN));
                if walked.end.applied.len() != 2 {
                    continue;
                }
                both += 1;
                let found: BTreeSet<Node> = walked.answer.iter().flatten().copied().collect();
                if !walked.end.held().is_subset(&found) {
                    missed.push((kcmp, reports_count, exec, start));
                }
            }
        }
    }
    (both, missed)
}

/// The walk's module documentation compares a process's other threads with
/// its leader "only once every share of the leader's table is read, so a
/// thread that leaves the table afterward holds only descriptors the walk
/// read there or opened later", and reads the table under the process's ID
/// again after an exec. A thread the exec'd image starts on a table of its
/// own, the leader then closing its descriptors, holds a descriptor that was
/// open through the whole walk, so the walk reports its node wherever the
/// exec and the start fall among its reads.
#[test]
fn a_thread_started_apart_after_an_exec_leaves_its_table_reported() {
    let (both, missed) = execed_then_started_walks(1, true);
    assert!(both > 0, "premise: some walk saw the exec and the start");
    assert!(
        missed.is_empty(),
        "{} of {both} walks missed the node; (kcmp, counts, exec read, start read) of the first: {:?}",
        missed.len(),
        missed.first()
    );
}

/// Sibling without the fault: the thread the exec'd image starts shares the
/// table the process's ID names, and every walk reports the node.
#[test]
fn a_thread_started_on_the_shared_table_after_an_exec_leaves_it_reported() {
    let (both, missed) = execed_then_started_walks(1, false);
    assert!(both > 0, "premise: some walk saw the exec and the start");
    assert_eq!(missed, Vec::new());
}

/// The module documentation's order, every share of a table read before the
/// process's threads are compared with it, holds for the table the walk
/// reads again under the process's ID after an exec. That table here holds
/// more descriptors than one share, so the walk queues a share of it. A
/// thread the exec'd image starts on a table of its own, the leader then
/// closing its descriptors, holds descriptors that were open through the
/// whole walk, so the walk reports every node wherever the exec and the
/// start fall among its reads.
#[test]
fn a_thread_started_apart_while_a_share_of_the_reread_table_is_queued_leaves_it_reported() {
    let (both, missed) = execed_then_started_walks(SHARE as u64 + 2, true);
    assert!(both > 0, "premise: some walk saw the exec and the start");
    assert!(
        missed.is_empty(),
        "{} of {both} walks missed a node; (kcmp, counts, exec read, start read) of the first: {:?}",
        missed.len(),
        missed.first()
    );
}

/// Sibling without the fault: the thread the exec'd image starts shares the
/// table of more than one share, and every walk reports every node.
#[test]
fn a_thread_started_on_a_shared_table_of_two_shares_after_an_exec_leaves_it_reported() {
    let (both, missed) = execed_then_started_walks(SHARE as u64 + 2, false);
    assert!(both > 0, "premise: some walk saw the exec and the start");
    assert_eq!(missed, Vec::new());
}

/// [`execed_then_started`] with the started thread on the table the
/// process's ID names. Before read `leave` the leader takes a copy of that
/// table and closes every descriptor of the copy, so the started thread
/// alone holds the node.
fn execed_started_then_left(exec: u64, start: u64, leave: u64) -> State {
    let mut state = execed_then_started(1, exec, start, false);
    state.changes.push((leave, Change::Unshare(FIRST_PID)));
    state
}

/// A comparison shows that a thread shares the table the process's ID names
/// at that instant. After an exec that table is the exec'ing thread's, which
/// the walk reads under the process's ID only once it reads that table
/// again. A thread the exec'd image starts on that table holds the node
/// through the whole walk while the leader leaves the table and closes its
/// copy, so the walk reports the node wherever the exec, the start and the
/// leave fall among its reads.
#[test]
fn a_thread_on_an_execed_leader_s_table_that_the_leader_leaves_is_reported() {
    for (kcmp, reports_count) in [(true, true), (true, false), (false, true), (false, false)] {
        let quiet = execed_started_then_left(u64::MAX, u64::MAX, u64::MAX);
        let reads = walk(quiet, kcmp, reports_count, false, Some(BEGUN))
            .end
            .reads;
        let (mut ran, mut missed) = (0, Vec::new());
        for exec in 0..reads {
            // Each change adds reads to the walk, so the start and the leave
            // may fall past the reads of the walk without them.
            for start in exec..2 * reads {
                for leave in start..2 * reads {
                    let state = execed_started_then_left(exec, start, leave);
                    let walked = walk(state, kcmp, reports_count, false, Some(BEGUN));
                    if walked.end.applied.len() != 3 {
                        continue;
                    }
                    ran += 1;
                    let reported = walked.answer.is_some_and(|answer| {
                        walked.end.held().iter().all(|node| answer.contains(node))
                    });
                    if !reported {
                        missed.push((exec, start, leave));
                    }
                }
            }
        }
        assert!(
            ran > 0,
            "premise: some walk saw the exec, the start and the leave"
        );
        assert!(
            missed.is_empty(),
            "kcmp {kcmp}, counts {reports_count}: {} of {ran} walks missed the node; (exec read, start read, leave read) of the first: {:?}",
            missed.len(),
            missed.first()
        );
    }
}

/// One process whose leader's table holds one node and whose one other
/// thread, started before the walk, holds a table of its own of one node.
/// Before each read in `ats`, in order, the thread on that table starts a
/// thread on it and exits, so the table is in use at every instant of the
/// walk.
fn handed_off(ats: &[u64]) -> State {
    let (pid, tid) = (FIRST_PID, FIRST_PID + 101);
    let node = |table: u64| Node::File {
        major: 0,
        minor: 0,
        inode: table << 20,
    };
    let process = Process {
        table: 0,
        threads: vec![Thread {
            tid,
            table: 1,
            started: BEGUN - 1,
            born: 0,
        }],
    };
    let mut holder = tid;
    let mut changes = Vec::new();
    for (next, at) in (FIRST_STARTED..).zip(ats) {
        changes.push((*at, Change::Spawn(pid, holder, next)));
        changes.push((*at, Change::Exit(pid, holder)));
        holder = next;
    }
    State {
        processes: BTreeMap::from([(pid, process)]),
        tables: vec![vec![node(0)], vec![node(1)]],
        reads: 0,
        changes,
        applied: Vec::new(),
        opens: BTreeMap::new(),
        through: 0,
    }
}

/// Whether the walk of [`handed_off`] with handoffs before reads `ats`
/// reported the handed-off table, or `None` when the walk ended before
/// every handoff ran.
fn reported(ats: &[u64], kcmp: bool, reports_count: bool) -> Option<bool> {
    let walked = walk(handed_off(ats), kcmp, reports_count, false, Some(BEGUN));
    if walked.end.applied.len() != 2 * ats.len() {
        return None;
    }
    let found: BTreeSet<Node> = walked.answer.unwrap().into_iter().collect();
    Some(walked.end.held().is_subset(&found))
}

/// A private table handed from a listed thread to a thread it starts after
/// the `task` listing, before the walk reads it, is still reported.
#[test]
fn a_private_table_handed_to_a_thread_started_after_the_task_listing_is_reported() {
    for (kcmp, reports_count) in [(true, true), (false, false)] {
        let reads = walk(handed_off(&[]), kcmp, reports_count, false, Some(BEGUN))
            .end
            .reads;
        let missed: Vec<u64> = (0..reads)
            .filter(|at| {
                let reported = reported(&[*at], kcmp, reports_count);
                assert!(reported.is_some(), "premise: the handoff ran");
                reported == Some(false)
            })
            .collect();
        assert!(
            missed.is_empty(),
            "kcmp {kcmp}: the handed-off table was not reported with the handoff before reads {missed:?} of {reads}"
        );
    }
}

/// A private table handed on twice, the second time by the thread the first
/// handoff started, is reported wherever the two handoffs fall.
#[test]
fn a_private_table_handed_on_twice_is_reported() {
    for (kcmp, reports_count) in [(true, true), (false, false)] {
        let reads = walk(handed_off(&[]), kcmp, reports_count, false, Some(BEGUN))
            .end
            .reads;
        let mut ran = 0;
        let mut missed = Vec::new();
        for first in 0..reads {
            // A handoff adds reads to the walk, so the second may fall past
            // the reads of the walk without one.
            for second in first..2 * reads {
                match reported(&[first, second], kcmp, reports_count) {
                    Some(true) => ran += 1,
                    Some(false) => missed.push((first, second)),
                    None => {}
                }
            }
        }
        assert!(
            ran > reads,
            "premise: both handoffs ran in more walks than one handoff has places"
        );
        assert!(
            missed.is_empty(),
            "kcmp {kcmp}: the table was not reported with handoffs before reads {missed:?}"
        );
    }
}

/// A table handed to a new thread before every read never rests with a
/// thread a listing named, and the walk fails instead of answering without
/// it.
#[test]
fn a_private_table_handed_on_before_every_read_fails_the_walk() {
    let ats: Vec<u64> = (0..1_000).collect();
    for (kcmp, reports_count) in [(true, true), (false, false)] {
        let walked = walk(handed_off(&ats), kcmp, reports_count, false, Some(BEGUN));
        assert!(
            walked.end.reads < 1_000,
            "premise: a handoff preceded every read"
        );
        assert_eq!(walked.answer, None, "kcmp {kcmp}");
    }
}

/// Threads beside the leader of the process [`crowded`] builds: more than
/// one call of a `task` listing returns.
const CROWD: u32 = 1_100;

/// One process of [`CROWD`] threads on its leader's empty table, but for
/// the thread at `apart`, in creation order, which holds one descriptor on
/// a table of its own. The threads at `leaving` exit before read `at`.
fn crowded(apart: u32, leaving: &[u32], at: u64) -> State {
    let node = Node::File {
        major: 0,
        minor: 0,
        inode: 1,
    };
    let tid = |index: u32| FIRST_PID + 100 + index;
    let threads = (0..CROWD)
        .map(|index| Thread {
            tid: tid(index),
            table: usize::from(index == apart),
            started: BEGUN - 1,
            born: 0,
        })
        .collect();
    State {
        processes: BTreeMap::from([(FIRST_PID, Process { table: 0, threads })]),
        tables: vec![Vec::new(), vec![node]],
        reads: 0,
        changes: leaving
            .iter()
            .map(|index| (at, Change::Exit(FIRST_PID, tid(*index))))
            .collect(),
        applied: Vec::new(),
        opens: BTreeMap::new(),
        through: 0,
    }
}

/// Walks [`crowded`] with the threads at `leaving` exiting before each
/// read in turn, judges every walk, and returns how many walks listed the
/// `task` directory in more than one call with every exit applied.
fn crowded_walks(apart: u32, leaving: &[u32]) -> u32 {
    let mut resumed = 0;
    for kcmp in [true, false] {
        let reads = walk(
            crowded(apart, &[], u64::MAX),
            kcmp,
            true,
            false,
            Some(BEGUN),
        )
        .end
        .reads;
        for at in 0..=reads {
            let walked = walk(crowded(apart, leaving, at), kcmp, true, false, Some(BEGUN));
            resumed += u32::from(walked.resumed > 0 && walked.end.applied.len() == leaving.len());
            judge(at, &walked);
        }
    }
    resumed
}

/// The walk "reads the table of each process's leader and of each of its
/// other threads". The first call of a `task` listing returns the leader
/// and 1,021 threads. A thread on a table of its own, third among those the
/// first call left, stays present through the walk while the first thread
/// the call left and one thread it returned exit. The walk reports that
/// thread's descriptor wherever the exits fall among its reads.
#[test]
fn a_thread_present_through_a_task_listing_others_leave_stays_reported() {
    let first_left = (RECORDS / TASK_RECORD - 3) as u32;
    let resumed = crowded_walks(first_left + 1, &[first_left, 5]);
    assert!(
        resumed > 0,
        "premise: some listing took a second call after the exits"
    );
}

/// The sibling: with the first thread the call left still present, the
/// listing resumes at it, and the walk reports the descriptor of the
/// thread on a table of its own though two returned threads exit.
#[test]
fn a_task_listing_that_resumes_at_a_present_thread_reports_every_thread() {
    let first_left = (RECORDS / TASK_RECORD - 3) as u32;
    let resumed = crowded_walks(first_left + 1, &[5, 6]);
    assert!(
        resumed > 0,
        "premise: some listing took a second call after the exits"
    );
}

/// A listing of a `task` directory that an exit falls in or beside is not
/// kept, since the kernel may have passed over a thread that stays. With a
/// thread exiting before every read, no listing agrees with the link count
/// before and after it, and the walk fails instead of answering from a
/// listing that may lack a thread.
#[test]
fn threads_that_exit_through_every_task_listing_fail_the_walk() {
    for kcmp in [true, false] {
        let mut state = crowded(CROWD - 1, &[], 0);
        state.changes = (0..CROWD - 1)
            .map(|index| {
                let exit = Change::Exit(FIRST_PID, FIRST_PID + 100 + index);
                (u64::from(index), exit)
            })
            .collect();
        let walked = walk(state, kcmp, true, false, Some(BEGUN));
        assert_eq!(walked.answer, None);
        assert!(
            walked.end.applied.len() >= LISTINGS,
            "premise: an exit for every listing"
        );
        assert!(
            !walked.end.held().is_empty(),
            "premise: the thread on a table of its own stays"
        );
    }
}

/// One full share and one descriptor more.
const QUEUED: usize = SHARE + 1;

/// One process whose leader and first other thread use one table of two
/// queued shares beyond the first, and whose second other thread uses that
/// table too, or with `apart` a table of its own that holds another file
/// under each descriptor number, as after `unshare(CLONE_FILES)` and a
/// `dup2` over each. Both threads started before the walk, which reads the
/// second queued share through the second thread's directory. That thread
/// exits before read `exit`, and a thread with its ID starts on the leader's
/// table before read `start`, after the exit when both fall before one read.
fn reusing(apart: bool, exit: u64, start: u64) -> State {
    let (pid, first, second) = (FIRST_PID, FIRST_PID + 101, FIRST_PID + 102);
    let thread = |tid, table| Thread {
        tid,
        table,
        started: BEGUN - 1,
        born: 0,
    };
    let held = (2 * SHARE + QUEUED) as u64;
    let nodes = |from: u64| {
        (from..from + held)
            .map(|inode| Node::File {
                major: 0,
                minor: 0,
                inode,
            })
            .collect()
    };
    State {
        processes: BTreeMap::from([(
            pid,
            Process {
                table: 0,
                threads: vec![thread(first, 0), thread(second, usize::from(apart))],
            },
        )]),
        tables: vec![nodes(0), nodes(held)],
        reads: 0,
        changes: vec![
            (exit, Change::Exit(pid, second)),
            (start, Change::Start(pid, second)),
        ],
        applied: Vec::new(),
        opens: BTreeMap::new(),
        through: 0,
    }
}

/// The in-use check refuses a node open in any process, and the walk keeps
/// a share read through a thread's directory only when that thread still
/// uses its leader's table. A thread that exits leaves its directory naming
/// nothing, and a thread that then starts under the same ID on the leader's
/// table is another thread: the comparison that follows the reads says
/// nothing of the table they were made of. The walk still reports every
/// node of the leader's table, at every pair of reads the exit and the
/// start can fall before, whether the thread that left used the leader's
/// table or one of its own. A thread on its own table answers every read
/// of the share, so no read tells the walk that it left.
#[test]
fn a_share_read_through_a_thread_whose_id_another_thread_takes_is_read_again() {
    for apart in [false, true] {
        let reads = walk(
            reusing(apart, u64::MAX, u64::MAX),
            true,
            true,
            false,
            Some(BEGUN),
        )
        .end
        .reads;
        let (mut reused, mut answered) = (0, 0);
        for exit in 0..reads {
            // A thread on its own table hides its exit only from a walk that
            // makes no read between the exit and the start, so there the
            // start falls at the exit's read and the next. Otherwise it
            // falls at the read after the exit and at every 17th read from
            // there, which keeps the pairs to a few thousand walks.
            let starts = if apart {
                (exit..=exit + 1).step_by(1)
            } else {
                (exit + 1..=reads).step_by(17)
            };
            for start in starts {
                let state = reusing(apart, exit, start);
                let second = state.processes[&FIRST_PID].threads[1].tid;
                let walked = walk(state, true, true, false, Some(BEGUN));
                let taken = walked.end.applied.len() == 2;
                reused += usize::from(taken);
                // Of the two threads that hold the ID `second`, only the
                // departed one has `Thread::born == 0`, so `(second, 0)`
                // counts its reads.
                let whole = walked.read_under.get(&(second, 0)) == Some(&SHARE);
                answered += usize::from(taken && whole);
                judge(u64::from(apart) << 63 | exit << 32 | start, &walked);
            }
        }
        assert!(reused > 0, "premise: the thread left and its ID was taken");
        assert!(
            answered > 0,
            "premise: the thread left after it answered a whole share"
        );
    }
}

/// The thread on a table of its own hands it to a thread it starts and
/// exits before read `ats[0]`. Before each later read in `ats`, the thread
/// holding the table hands it on the same way, to a thread under the first
/// thread's former ID and to a thread under a new ID in turn. The table is
/// in use at every instant of the walk.
fn handed_back(ats: &[u64]) -> State {
    let mut state = handed_off(&[]);
    let (pid, first) = (FIRST_PID, FIRST_PID + 101);
    let mut holder = first;
    let mut changes = Vec::new();
    for (hop, at) in (0u32..).zip(ats) {
        let next = if hop % 2 == 0 {
            FIRST_STARTED + hop / 2
        } else {
            first
        };
        changes.push((*at, Change::Spawn(pid, holder, next)));
        changes.push((*at, Change::Exit(pid, holder)));
        holder = next;
    }
    state.changes = changes;
    state
}

/// Walks [`handed_back`] with the first handoff before read `first` and
/// `hops` handoffs in all, one before each of every rising choice of later
/// reads, up to twice the reads of the walk without a handoff. Returns how
/// many walks ran every handoff and the reads of each such walk that did
/// not answer with every node a table held at its end.
fn handed_back_walks(
    first: u64,
    hops: usize,
    kcmp: bool,
    reports_count: bool,
) -> (u64, Vec<Vec<u64>>) {
    fn place(
        ats: &mut Vec<u64>,
        hops: usize,
        last: u64,
        kcmp: bool,
        reports_count: bool,
        walks: &mut (u64, Vec<Vec<u64>>),
    ) {
        if ats.len() == hops {
            let walked = walk(handed_back(ats), kcmp, reports_count, false, Some(BEGUN));
            if walked.end.applied.len() != 2 * hops {
                return;
            }
            walks.0 += 1;
            let reported = walked
                .answer
                .is_some_and(|answer| walked.end.held().iter().all(|node| answer.contains(node)));
            if !reported {
                walks.1.push(ats.clone());
            }
            return;
        }
        for at in ats[ats.len() - 1] + 1..last {
            ats.push(at);
            place(ats, hops, last, kcmp, reports_count, walks);
            ats.pop();
        }
    }
    let reads = walk(handed_off(&[]), kcmp, reports_count, false, Some(BEGUN))
        .end
        .reads;
    let mut walks = (0, Vec::new());
    place(
        &mut vec![first],
        hops,
        2 * reads,
        kcmp,
        reports_count,
        &mut walks,
    );
    walks
}

/// A thread ID names one thread only while that thread lives: a private
/// table handed to a thread that takes a departed listed thread's ID is
/// another thread's table, and the walk still reports it wherever the two
/// handoffs fall.
#[test]
fn a_private_table_handed_to_a_thread_under_a_departed_thread_s_id_is_reported() {
    for (kcmp, reports_count) in [(true, true), (false, false)] {
        let reads = walk(handed_off(&[]), kcmp, reports_count, false, Some(BEGUN))
            .end
            .reads;
        let mut ran = 0;
        let mut missed = Vec::new();
        for first in 0..reads {
            let (walks, misses) = handed_back_walks(first, 2, kcmp, reports_count);
            ran += walks;
            missed.extend(misses);
        }
        assert!(ran > 0, "premise: both handoffs ran");
        assert!(
            missed.is_empty(),
            "kcmp {kcmp}: the table was not reported with handoffs before reads {missed:?}"
        );
    }
}

/// A thread whose start tick the walk reads after it has gone is not the
/// thread an earlier relisting named under its ID: a private table that
/// returns to a departed listed thread's ID twice, each time through a
/// thread under a new ID, is reported with the first of five handoffs
/// before the walk's first read, wherever the four others fall.
#[test]
fn a_private_table_handed_back_to_a_departed_thread_s_id_twice_is_reported() {
    for (kcmp, reports_count) in [(true, true), (false, false)] {
        let (ran, missed) = handed_back_walks(0, 5, kcmp, reports_count);
        assert!(ran > 0, "premise: all five handoffs ran");
        assert!(
            missed.is_empty(),
            "kcmp {kcmp}: the table was not reported in {} of {ran} walks, the first with handoffs before reads {:?}",
            missed.len(),
            missed.first()
        );
    }
}

fn starting_steadily(held: u64, every: u64) -> State {
    let (pid, tid) = (FIRST_PID, FIRST_PID + 101);
    let nodes = (0..held)
        .map(|inode| Node::File {
            major: 0,
            minor: 0,
            inode,
        })
        .collect();
    let process = Process {
        table: 0,
        threads: vec![Thread {
            tid,
            table: 0,
            started: BEGUN - 1,
            born: 0,
        }],
    };
    State {
        processes: BTreeMap::from([(pid, process)]),
        tables: vec![nodes],
        reads: 0,
        changes: (0..1_000)
            .map(|start| {
                let at = 5 + u64::from(start) * every;
                (at, Change::Start(pid, FIRST_STARTED + start))
            })
            .collect(),
        applied: Vec::new(),
        opens: BTreeMap::new(),
        through: 0,
    }
}

/// When `kcmp` confirms that a thread started during the walk shares its
/// leader's table, reads of that table cover the thread's descriptors.
/// The walk completes even when the process starts another thread on the
/// leader's table every `2 * held + 2` reads.
#[test]
fn threads_started_steadily_on_the_leader_s_table_are_compared_and_not_read() {
    for held in [8, 64] {
        let state = starting_steadily(held, 2 * held + 2);
        let walked = walk(state, true, true, false, Some(BEGUN));
        assert!(
            walked.end.applied.len() > 1,
            "premise: threads started while the walk read the process"
        );
        judge(held, &walked);
        assert_eq!(
            walked.end.through, 0,
            "{held} nodes: the walk read a table under the ID of a thread on its leader's table"
        );
    }
}

/// The first thread the walk lists is the witness, which shares the
/// leader's table and predates the walk. The private table passes to an
/// heir before read `first` and to the heir's own heir before read
/// `second`, when a thread on the leader's table takes the first heir's ID.
fn handed_on_and_replaced(first: u64, second: u64) -> State {
    let mut state = handed_off(&[first]);
    let (pid, heir) = (FIRST_PID, FIRST_STARTED);
    let witness = Thread {
        tid: FIRST_PID + 100,
        table: 0,
        started: BEGUN - 1,
        born: 0,
    };
    let process = state.processes.get_mut(&pid).unwrap();
    process.threads.insert(0, witness);
    state.changes.extend([
        (second, Change::Spawn(pid, heir, heir + 1)),
        (second, Change::Exit(pid, heir)),
        (second, Change::Start(pid, heir)),
    ]);
    state
}

/// A listing and a comparison each name a thread by its ID. After a
/// listing names a thread on a private table, that thread can hand the
/// table on and exit, and a replacement on the leader's table can take
/// its ID. `kcmp` reports that the replacement shares the leader's table,
/// while the next heir holds the private table.
#[test]
fn a_private_table_handed_on_while_a_sharing_thread_takes_the_heir_s_id_is_reported() {
    for (kcmp, reports_count) in [(true, true), (true, false), (false, false)] {
        let quiet = handed_on_and_replaced(u64::MAX, u64::MAX);
        let reads = walk(quiet, kcmp, reports_count, false, Some(BEGUN))
            .end
            .reads;
        let (mut ran, mut missed) = (0, Vec::new());
        for first in 0..reads {
            for second in first..2 * reads {
                let state = handed_on_and_replaced(first, second);
                let walked = walk(state, kcmp, reports_count, false, Some(BEGUN));
                if walked.end.applied.len() != 5 {
                    continue;
                }
                ran += 1;
                let reported = walked.answer.is_some_and(|answer| {
                    walked.end.held().iter().all(|node| answer.contains(node))
                });
                if !reported {
                    missed.push((first, second));
                }
            }
        }
        assert!(
            ran > 0,
            "premise: both handoffs and the start under the heir's ID ran"
        );
        assert!(
            missed.is_empty(),
            "kcmp {kcmp}: the table was not reported in {} of {ran} walks, the first with the handoffs before reads {:?}",
            missed.len(),
            missed.first()
        );
    }
}

/// [`handed_off`] with a thread listed first that started before the walk,
/// uses the leader's table and stays. Before read `handoff` the thread on
/// the private table starts a thread on it and exits. Before read `start` a
/// thread starts on the leader's table, under the departed thread's ID when
/// `retaken` is set and under an ID no thread has held otherwise. The
/// private table is in use at every instant of the walk.
fn handed_on_and_started(handoff: u64, start: u64, retaken: bool) -> State {
    let mut state = handed_off(&[]);
    let (pid, holder) = (FIRST_PID, FIRST_PID + 101);
    let witness = Thread {
        tid: FIRST_PID + 50,
        table: 0,
        started: BEGUN - 1,
        born: 0,
    };
    let process = state.processes.get_mut(&pid).unwrap();
    process.threads.insert(0, witness);
    let taken = if retaken { holder } else { FIRST_STARTED + 1 };
    state.changes = vec![
        (handoff, Change::Spawn(pid, holder, FIRST_STARTED)),
        (handoff, Change::Exit(pid, holder)),
        (start, Change::Start(pid, taken)),
    ];
    state
}

/// Judges every walk of [`handed_on_and_started`] in which the handoff and
/// the start both ran, with the handoff before each read of the walk, the
/// start before that read and each later one, and each setting of `kcmp`
/// and counted table sizes.
fn judge_handed_on_and_started(retaken: bool) {
    for (kcmp, reports_count) in [(true, true), (true, false), (false, true), (false, false)] {
        let quiet = handed_on_and_started(u64::MAX, u64::MAX, retaken);
        let reads = walk(quiet, kcmp, reports_count, false, Some(BEGUN))
            .end
            .reads;
        let mut ran = 0;
        for handoff in 0..reads {
            // A handoff adds reads to the walk, so the start has no fixed
            // last place. Walks agree up to the earlier of their starts, so
            // once a walk ends before its start, it ends before every later
            // one.
            for start in handoff.. {
                let state = handed_on_and_started(handoff, start, retaken);
                let walked = walk(state, kcmp, reports_count, false, Some(BEGUN));
                if walked.end.applied.len() != 3 {
                    break;
                }
                ran += 1;
                let setting = u64::from(kcmp) << 63 | u64::from(reports_count) << 62;
                judge(setting | handoff << 32 | start, &walked);
            }
        }
        assert!(
            ran > 0,
            "premise: kcmp {kcmp}, counts {reports_count}: some walk saw the handoff and the start"
        );
    }
}

/// While the thread started on the leader's table takes an ID no thread
/// has held, the walk reports the handed-on table wherever the handoff and
/// the start fall among its reads.
#[test]
fn a_private_table_handed_on_is_reported_while_every_started_thread_takes_a_new_id() {
    judge_handed_on_and_started(false);
}

/// A comparison names a thread by its ID. The thread started on the
/// leader's table under the departed thread's ID shares the leader's table,
/// while the thread the departed one started uses the private table. That
/// table is in use at every instant of the walk, so every walk reports it.
#[test]
fn a_private_table_handed_on_is_reported_when_a_sharing_thread_takes_the_departed_thread_s_id() {
    judge_handed_on_and_started(true);
}

/// [`handed_off`] with its one handoff before read `at` and the private
/// table holding `devices` character devices. The thread the handoff
/// starts execs before read `exec`.
fn handed_then_execed(at: u64, exec: u64, devices: u32) -> State {
    let mut state = handed_off(&[at]);
    state.tables[1] = (0..devices)
        .map(|minor| Node::Device {
            block: false,
            major: 10,
            minor,
        })
        .collect();
    state
        .changes
        .push((exec, Change::Exec(FIRST_PID, FIRST_STARTED)));
    state
}

/// Walks [`handed_then_execed`] with the handoff and the exec before every
/// rising pair of reads up to twice the reads of the walk without them,
/// with and without `kcmp` and counted table sizes. A walk counts when
/// the handoff and exec both ran and `counted` accepts whether the walk
/// addressed the `fd` directory of the thread that execs and the walk's
/// node count from that directory. Returns the number of counted walks and the
/// `(kcmp, counts, handoff read, exec read)` of each counted walk that
/// missed a node held by a table when the walk ended.
fn handed_then_execed_walks(
    devices: u32,
    counted: impl Fn(bool, usize) -> bool,
) -> (u32, Vec<(bool, bool, u64, u64)>) {
    let (mut walks, mut missed) = (0, Vec::new());
    for (kcmp, reports_count) in [(true, true), (false, false)] {
        let reads = walk(handed_off(&[]), kcmp, reports_count, false, Some(BEGUN))
            .end
            .reads;
        for at in 0..reads {
            for exec in at..2 * reads {
                let state = handed_then_execed(at, exec, devices);
                let walked = walk(state, kcmp, reports_count, false, Some(BEGUN));
                let addressed = walked.addressed.contains(&FIRST_STARTED);
                let under: usize = walked
                    .read_under
                    .iter()
                    .filter(|((tid, _), _)| *tid == FIRST_STARTED)
                    .map(|(_, read)| read)
                    .sum();
                if walked.end.applied.len() != 3 || !counted(addressed, under) {
                    continue;
                }
                walks += 1;
                let found: BTreeSet<Node> = walked.answer.iter().flatten().copied().collect();
                if !walked.end.held().is_subset(&found) {
                    missed.push((kcmp, reports_count, at, exec));
                }
            }
        }
    }
    (walks, missed)
}

/// A thread on a private table starts a thread on it and exits before the
/// walk reads that table, so a later `task` listing names the new thread.
/// That thread execs before the walk reads a node of its table: the exec
/// moves the table under the process's ID, which keeps its start tick and
/// so its place among the processes the walk listed. The table holds its
/// device through the whole walk, and the walk reports it.
#[test]
fn a_relisted_thread_that_execs_before_its_table_is_read_leaves_its_table_reported() {
    let (walks, missed) = handed_then_execed_walks(1, |addressed, read| addressed && read == 0);
    assert!(
        walks > 0,
        "premise: the walk addressed the thread's table, and the thread execed before a node of it was read"
    );
    assert!(
        missed.is_empty(),
        "{} of {walks} walks missed the device; (kcmp, counts, handoff read, exec read) of the first: {:?}",
        missed.len(),
        missed.first()
    );
}

/// The sibling of the test above in which the thread execs after the walk
/// read some but not all of its table's nodes, so the rest read as gone.
#[test]
fn a_relisted_thread_that_execs_while_its_table_is_read_leaves_its_table_reported() {
    let (walks, missed) =
        handed_then_execed_walks(3, |addressed, read| addressed && (1..3).contains(&read));
    assert!(
        walks > 0,
        "premise: the walk addressed the thread's table, and the thread execed after the walk read part of it"
    );
    assert!(
        missed.is_empty(),
        "{} of {walks} walks missed a device; (kcmp, counts, handoff read, exec read) of the first: {:?}",
        missed.len(),
        missed.first()
    );
}

/// The sibling of the tests above in which the thread execs before the
/// walk addresses its table: after the walk reads the table under the
/// process's ID again and before a `task` listing it keeps names the
/// thread. The process's ID then names the handed-off table, and the walk
/// reports its device.
#[test]
fn a_thread_that_execs_before_a_kept_listing_names_it_leaves_its_table_reported() {
    let (walks, missed) = handed_then_execed_walks(1, |addressed, _| !addressed);
    assert!(
        walks > 0,
        "premise: the thread execed before the walk addressed its table"
    );
    assert!(
        missed.is_empty(),
        "{} of {walks} walks missed the device; (kcmp, counts, handoff read, exec read) of the first: {:?}",
        missed.len(),
        missed.first()
    );
}
