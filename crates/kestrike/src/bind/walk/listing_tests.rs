//! The walk's listing of a constructed process table: the start ticks of
//! the listed processes, read on several threads, and the processes the
//! listing queues.

use std::collections::{BTreeSet, HashSet};
use std::ffi::{CStr, CString};
use std::io;
use std::num::NonZero;
use std::sync::Mutex;
use std::sync::atomic::Ordering;
use std::thread::{self, ThreadId};

use super::{Listed, Node, Os, PER_READER, Queue, Status, started};

/// A process table that lists `pids` among the names procfs lists beside
/// them, and records each thread that reads a start tick.
struct Table {
    pids: Vec<u32>,
    /// The process whose leader started one tick later than [`tick`] says.
    replaced: Option<u32>,
    readers: Mutex<HashSet<ThreadId>>,
}

impl Table {
    fn of(pids: impl IntoIterator<Item = u32>) -> Self {
        Self {
            pids: pids.into_iter().collect(),
            replaced: None,
            readers: Mutex::new(HashSet::new()),
        }
    }

    fn listed(&self) -> BTreeSet<Listed> {
        self.pids
            .iter()
            .map(|&pid| (pid, self.started(pid, pid)))
            .collect()
    }
}

/// The start tick of process `pid`'s leader, unreadable for every seventh
/// process.
fn tick(pid: u32) -> Option<u64> {
    (!pid.is_multiple_of(7)).then_some(u64::from(pid) * 3)
}

impl Os for Table {
    type Table = ();

    fn status(&self, _: &CStr) -> io::Result<Status> {
        unreachable!("a listing reads no status")
    }

    fn open(&self, _: &CStr) -> io::Result<()> {
        unreachable!("a listing opens no table")
    }

    fn entries(&self, _: &(), _: &mut [u8], mut visit: impl FnMut(&CStr)) -> io::Result<()> {
        visit(c"self");
        for pid in &self.pids {
            visit(&CString::new(pid.to_string()).unwrap());
        }
        visit(c"uptime");
        Ok(())
    }

    fn node(&self, _: &(), _: &CStr) -> io::Result<Option<Node>> {
        unreachable!("a listing reads no descriptor")
    }

    fn shares_leader_table(&self, _: u32, _: u32) -> bool {
        unreachable!("a listing compares no tables")
    }

    fn started(&self, pid: u32, tid: u32) -> Option<u64> {
        assert_eq!(pid, tid, "a listing reads the leader's start tick");
        self.readers.lock().unwrap().insert(thread::current().id());
        let later = u64::from(self.replaced == Some(pid));
        tick(pid).map(|tick| tick + later)
    }

    fn last_task(&self) -> Option<u32> {
        None
    }
}

/// Every process the queue's process lane holds, in ascending order.
fn queued(queue: &Queue<()>) -> Vec<u32> {
    let mut pids: Vec<u32> = std::iter::from_fn(|| queue.pop(&queue.processes)).collect();
    pids.sort_unstable();
    pids
}

/// The start ticks of a table larger than one reader's share come back in
/// listing order, each the tick its process's `stat` holds, from at most as
/// many threads as the host runs at once; a table of fewer than two shares
/// is read by the calling thread alone.
#[test]
fn start_ticks_read_on_several_threads_come_back_in_listing_order() {
    let table = Table::of((1..=1000).rev().map(|pid| 50_000 + pid * 13));
    let ticks = started(&|pid| table.leader_started(pid), &table.pids);
    let expected: Vec<Option<u64>> = table.pids.iter().map(|&pid| tick(pid)).collect();
    assert_eq!(ticks, expected);
    assert!(
        ticks.iter().any(Option::is_none) && ticks.iter().any(Option::is_some),
        "premise: some ticks are readable and some are not"
    );
    let parallelism = thread::available_parallelism().map_or(1, NonZero::get);
    let readers = table.readers.lock().unwrap().len();
    assert!(
        (1..=parallelism).contains(&readers),
        "{readers} threads read on a host of {parallelism}"
    );

    let few = Table::of(1..u32::try_from(2 * PER_READER).unwrap());
    assert_eq!(
        started(&|pid| few.leader_started(pid), &few.pids),
        few.pids.iter().map(|&pid| tick(pid)).collect::<Vec<_>>()
    );
    assert_eq!(
        *few.readers.lock().unwrap(),
        HashSet::from([thread::current().id()]),
        "fewer than two shares are read by the calling thread"
    );
}

/// A listing adds each listed process to the seen set with the tick its
/// leader started in and queues it once; a second listing over the same
/// set queues nothing, and a process that comes back under a listed ID with
/// another start tick is queued again.
#[test]
fn a_listing_queues_each_process_the_seen_set_lacks_once() {
    let mut table = Table::of((100..700).filter(|&pid| tick(pid).is_some()));
    let mut seen = BTreeSet::new();
    let queue = Queue::<()>::default();
    assert!(queue.list(&table, &(), &mut seen));
    assert_eq!(seen, table.listed());
    assert_eq!(queue.queued.load(Ordering::Acquire), 515);
    assert_eq!(queued(&queue), table.pids);

    let queue = Queue::<()>::default();
    assert!(queue.list(&table, &(), &mut seen));
    assert_eq!(
        queue.queued.load(Ordering::Acquire),
        0,
        "every process was seen"
    );

    table.replaced = Some(345);
    let queue = Queue::<()>::default();
    assert!(queue.list(&table, &(), &mut seen));
    assert_eq!(queued(&queue), [345]);
    assert_eq!(
        seen.len(),
        516,
        "the process under a listed ID is a new one"
    );
}

/// A process whose start tick the listing cannot read is queued and added
/// to the seen set as one no listing found before. The next listing that
/// finds a process without a tick under its ID cannot tell whether the
/// host gave the ID to another process since, so it fails and queues none
/// of them. A later listing that finds none of those processes succeeds.
#[test]
fn a_listing_fails_on_a_process_without_a_start_tick_under_an_id_listed_without_one() {
    let table = Table::of(100..700);
    let unread = table.pids.iter().filter(|&&pid| tick(pid).is_none());
    assert_eq!(unread.count(), 85, "premise: some ticks cannot be read");
    let mut seen = BTreeSet::new();
    let queue = Queue::<()>::default();
    assert!(queue.list(&table, &(), &mut seen));
    assert_eq!(seen, table.listed());
    assert_eq!(queued(&queue), table.pids);

    let queue = Queue::<()>::default();
    assert!(
        !queue.list(&table, &(), &mut seen),
        "a process without a tick under an ID listed without one is not identified"
    );
    assert_eq!(queue.queued.load(Ordering::Acquire), 0);
    assert_eq!(seen, table.listed());

    let readable = Table::of(
        table
            .pids
            .iter()
            .copied()
            .filter(|&pid| tick(pid).is_some()),
    );
    let queue = Queue::<()>::default();
    assert!(
        queue.list(&readable, &(), &mut seen),
        "a listing that no longer finds the processes without a tick succeeds"
    );
    assert_eq!(queue.queued.load(Ordering::Acquire), 0);
}

/// A listing that reads no start tick at all identifies no process an
/// earlier listing found: a second listing over the same set fails and
/// queues nothing, as it does when other start ticks are read.
#[test]
fn a_listing_that_reads_no_start_tick_fails_under_the_ids_listed_before() {
    let table = Table::of((100..200).map(|pid| pid * 7));
    assert!(
        table.listed().iter().all(|listed| listed.1.is_none()),
        "premise: no tick can be read"
    );
    let mut seen = BTreeSet::new();
    let queue = Queue::<()>::default();
    assert!(queue.list(&table, &(), &mut seen));
    assert_eq!(queued(&queue), table.pids);

    let queue = Queue::<()>::default();
    assert!(
        !queue.list(&table, &(), &mut seen),
        "a process without a tick under an ID listed without one is not identified"
    );
    assert_eq!(queue.queued.load(Ordering::Acquire), 0);
    assert_eq!(seen, table.listed());
}
