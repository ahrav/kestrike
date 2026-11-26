//! Walks over a constructed process table whose one device descriptor
//! passes from parent to child by `fork` while the process table is listed.
//!
//! The walk's module documentation states what these tests judge: "A
//! descriptor that passes from parent to child by `fork` alone through the
//! whole walk is then reported".
//!
//! [`Relays`] lists the process table as the kernel does: in ascending ID
//! order, over several reads, each read resuming above the last ID the read
//! before returned, so a process whose ID lies below that position when it
//! starts is in no later read of the listing. Each read returns one record,
//! which keeps the table small; a larger buffer moves the same position in
//! larger steps. Each relay forks a child that holds a copy of its parent's
//! table and ends the parent, at a named point of a named listing. The
//! kernel takes each new ID from a cursor that returns to its lowest ID
//! after its highest, so a child's ID lies below its parent's whenever the
//! cursor passed the highest ID between the two forks.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString};
use std::io;
use std::sync::Mutex;

use super::{Facts, Listed, Node, Os, Queue, Status, TASK_LINKS, Walker, answer, settled};

/// The first process ID of a constructed table, above every ID the kernel
/// assigns, so no process of the table is the test's own.
const FIRST_PID: u32 = 1 << 23;
/// A process that lives through the walk and holds no device.
const BYSTANDER: u32 = FIRST_PID + 10;
/// The process that holds the device when the walk begins.
const HOLDER: u32 = FIRST_PID + 20;
/// The holder's child.
const CHILD: u32 = FIRST_PID + 21;
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

/// A point of the walk's reads of the process table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum When {
    /// After this read of this listing, both counted from one.
    Read(u32, u32),
    /// After the last read of this listing.
    Listed(u32),
}

/// One fork: at `when`, `parent` forks `child`, which holds a copy of its
/// table, and exits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Relay {
    when: When,
    parent: u32,
    child: u32,
}

#[derive(Debug)]
struct State {
    /// Each process's one descriptor.
    processes: BTreeMap<u32, Node>,
    relays: Vec<Relay>,
    /// The relays that found their parent present, in the order applied.
    applied: Vec<Relay>,
    /// Listings of the process table begun so far.
    listings: u32,
    /// The ID of the task started last.
    last: u32,
}

impl State {
    fn apply(&mut self, when: When) {
        let due: Vec<Relay> = (self.relays.iter().copied())
            .filter(|relay| relay.when == when)
            .collect();
        for relay in due {
            if let Some(node) = self.processes.remove(&relay.parent) {
                self.processes.insert(relay.child, node);
                self.last = relay.child;
                self.applied.push(relay);
            }
        }
    }
}

/// A process table of single-threaded processes, each with one descriptor.
struct Relays(Mutex<State>);

/// The process whose descriptor table or `task` directory `path` names.
fn process(path: &CStr) -> Option<(u32, bool)> {
    let (pid, rest) = path.to_str().ok()?.split_once('/')?;
    Some((pid.parse().ok()?, rest == "fd"))
}

fn gone() -> io::Error {
    io::Error::from_raw_os_error(libc::ENOENT)
}

impl Os for Relays {
    /// The process table, or the descriptor table of this process.
    type Table = Option<u32>;

    fn status(&self, path: &CStr) -> io::Result<Status> {
        let state = self.0.lock().unwrap();
        let (pid, _) = process(path).ok_or_else(gone)?;
        state.processes.get(&pid).ok_or_else(gone)?;
        Ok(Status {
            size: 1,
            links: TASK_LINKS + 1,
        })
    }

    fn open(&self, path: &CStr) -> io::Result<Option<u32>> {
        let state = self.0.lock().unwrap();
        let (pid, table) = process(path).ok_or_else(gone)?;
        let present = table && state.processes.contains_key(&pid);
        present.then_some(Some(pid)).ok_or_else(gone)
    }

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
            let (mut position, mut reads) = (0, 0);
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
                reads += 1;
                self.0.lock().unwrap().apply(When::Read(listing, reads));
            }
            self.0.lock().unwrap().apply(When::Listed(listing));
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
            .copied()
            .map(Some)
            .ok_or_else(gone)
    }

    fn shares_leader_table(&self, _: u32, _: u32) -> bool {
        unreachable!("no process of the table has a second thread")
    }

    /// One start tick for every process the table holds, so a listing
    /// tells this table's processes apart by ID alone; no walk here reuses
    /// an ID.
    fn started(&self, pid: u32, task: u32) -> Option<u64> {
        assert_eq!(pid, task, "no process of the table has a second thread");
        let state = self.0.lock().unwrap();
        state.processes.contains_key(&pid).then_some(0)
    }

    fn last_task(&self) -> Option<u32> {
        Some(self.0.lock().unwrap().last)
    }
}

/// What one walk showed: its answer, the relays that ran, and the process
/// table as the walk left it.
struct Walked {
    answer: Option<Vec<Node>>,
    applied: Vec<Relay>,
    end: BTreeMap<u32, Node>,
}

/// One walker's walk, in the rounds of [`settled`], over a bystander and a
/// process holding the device, with `relays` applied.
fn walk(relays: &[Relay]) -> Walked {
    let table = Relays(Mutex::new(State {
        processes: BTreeMap::from([(BYSTANDER, FILE), (HOLDER, DEVICE)]),
        relays: relays.to_vec(),
        applied: Vec::new(),
        listings: 0,
        last: HOLDER,
    }));
    let facts = Facts {
        reports_count: true,
        kcmp: true,
        begun: Some(BEGUN),
        walkers: 1,
    };
    let found = Mutex::new(Some(Vec::new()));
    let matches = |_| true;
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
        applied: state.applied,
        end: state.processes,
    }
}

/// The holder forks the child and exits after the first listing, before the
/// walk reads the holder's table. The child, the device's holder when the
/// second listing begins, forks `grandchild` and exits after that listing's
/// first read, which returned the bystander.
fn handed_on_twice(grandchild: u32) -> [Relay; 2] {
    [
        Relay {
            when: When::Listed(1),
            parent: HOLDER,
            child: CHILD,
        },
        Relay {
            when: When::Read(2, 1),
            parent: CHILD,
            child: grandchild,
        },
    ]
}

/// Judges a walk over `relays`, each of which must run: the device was held
/// at every instant, by the holder or by a descendant that inherited it at
/// its fork, so the walk fails or reports it.
fn judge(relays: &[Relay]) {
    let walked = walk(relays);
    assert_eq!(walked.applied, relays, "premise: every relay ran");
    assert!(
        walked.end.values().any(|node| *node == DEVICE),
        "premise: a process holds the device when the walk ends"
    );
    assert!(
        (walked.answer.as_ref()).is_none_or(|found| found.contains(&DEVICE)),
        "the walk answered {:?} without the device a process held throughout, after {:?}",
        walked.answer,
        walked.applied
    );
}

/// With no fork the walk reports both descriptors, and with the first
/// relay alone it reports the device from the child's table.
#[test]
fn a_device_held_by_one_process_or_handed_to_its_child_is_reported() {
    assert_eq!(walk(&[]).answer, Some(vec![DEVICE, FILE]));
    let relays = handed_on_twice(CHILD + 1);
    judge(&relays[..1]);
    assert_eq!(walk(&relays[..1]).answer, Some(vec![DEVICE, FILE]));
}

/// The grandchild's ID lies above its parent's, so the second listing
/// reaches it after the fork and the walk reads its table.
#[test]
fn a_device_handed_on_twice_to_children_of_higher_ids_is_reported() {
    let relays = handed_on_twice(CHILD + 1);
    judge(&relays);
    assert_eq!(walk(&relays).answer, Some(vec![DEVICE, FILE]));
}

/// The grandchild's ID lies below its parent's and below the bystander's,
/// which the second listing had passed when the grandchild started. The
/// device was held throughout, so the walk fails or reports it.
#[test]
fn a_device_handed_to_a_child_whose_id_the_listing_passed_is_reported() {
    judge(&handed_on_twice(BYSTANDER - 1));
}
