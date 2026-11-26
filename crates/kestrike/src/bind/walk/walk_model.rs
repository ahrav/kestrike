//! Loom model of the walk's queue and leader accounting: a listing actor
//! and two walkers drain a constructed process table through the
//! production [`Queue`], [`Walker`] and leader steps, with every directory
//! listing, `stat`, `statx` and `kcmp` answered by [`Table`].
//!
//! The oracle is an item ledger kept beside the production counters: the
//! pending count's every addition and subtraction, recorded at the
//! transition that makes it, and every descriptor read, recorded at the
//! read. Each walker's return is checked at that point and the aggregate
//! once every walker has joined: no transition finishes more items than
//! the walk counted, a walk that drained without an abort has finished as
//! many items as it counted and read each descriptor its table holds, and
//! an aborted walk fails its result with its unfinished work still
//! counted. Continuation work is queued without a pending addition,
//! so the ledger counts pending items alone.
//!
//! Every [`Word`], [`Flag`] and pending-count access uses
//! `Ordering::SeqCst` whatever `Ordering` the walk passes, so loom has each
//! load read the latest store, or the location's initial value until a
//! later store happens before the load or the reader read that value
//! before a yield. The model checks the walk's accounting under that
//! order, stronger than the production `Ordering` arguments give. Each of
//! those locations keeps a shadow of its latest value, which the idle wait
//! reads without a loom access. A walker's idle wait parks it while the
//! shadows leave it nothing to do, and a store that gives a parked walker
//! work unparks it, so idle walkers block. A walker with nothing to do
//! once the listing ended, beside a walker that is parked or has returned,
//! has stalled: no thread can change the walk again, and the planted
//! missing finish reaches it.
//!
//! Bounds: loom 0.7.2 with a preemption bound of 2, or 1 for the
//! four-share tables; one listing actor and two walkers; one or two
//! processes; a finite constructed table; procfs reads that return; and
//! actors the harness joins; `max_branches` 10,000,000, which loom
//! reports when an execution passes it. A continuation, a last share read
//! ahead by a walker other than its table's lister and queued as the next
//! step without a pending addition, takes leader tables of one queued
//! share and three at a preemption bound of 2: one test reaches it
//! concurrently, and another drives it on one thread through the
//! production steps from a seeded queue. The walk shares tables and
//! leaders through `std::sync::Arc` here as in production, so loom
//! schedules the walk's atomics, lane locks and `listed` cells, and the
//! reference counts of tables and leaders stay outside its checks. The
//! ledger, the reads and the stall state are `std` thread-locals that
//! every model thread shares, since loom runs its threads on one OS
//! thread.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::io;
use std::sync::atomic::Ordering;

use loom::sync::Mutex;
use loom::sync::atomic::{AtomicBool, AtomicUsize};
use loom::thread;

use super::{
    Count, Facts, FirstListing, Node, Os, Queue, SHARE, Status, TASK_LINKS, Walker, answer,
};

/// The walk's queue under the model's pending count.
type ModelQueue = Queue<usize, Ledger>;

thread_local! {
    /// The current execution's queue, read for the latest values of its
    /// counts and flags.
    static QUEUE: RefCell<Option<std::sync::Arc<ModelQueue>>> = const { RefCell::new(None) };
    /// Each walker, and whether it runs, is parked or has returned.
    static WALKERS: RefCell<Vec<(thread::Thread, Idle)>> = const { RefCell::new(Vec::new()) };
    /// Set once the listing actor has listed every process.
    static LISTED: Cell<bool> = const { Cell::new(false) };
    /// Set when the walk stalled.
    static STALLED: Cell<bool> = const { Cell::new(false) };
    /// The first ledger violation a transition made. A walker's panic is
    /// its walk's failure, so the ledger records the violation for the
    /// joined check.
    static VIOLATION: RefCell<Option<String>> = const { RefCell::new(None) };
    /// The pending count's additions and subtractions in this execution.
    static LEDGER: Cell<(usize, usize)> = const { Cell::new((0, 0)) };
    /// Reads of each descriptor, by its index in [`Table`]'s descriptors.
    static READS: RefCell<Vec<Visits>> = const { RefCell::new(Vec::new()) };
    /// Each `task` directory's `stat`s, by its index in [`Table`]'s
    /// listings: a process's thread count read at its start and at its
    /// threads' step.
    static COMPARED: RefCell<Vec<Visits>> = const { RefCell::new(Vec::new()) };
    /// The descriptor whose read panics its walker, by its [`Table`] index.
    static FAILING: Cell<Option<usize>> = const { Cell::new(None) };
    /// The walker, by [`View`] index, that queued a process's next step on
    /// the queue's `threads` lane, which only a share read ahead does, and
    /// the table of the last descriptor it read before.
    static CONTINUED: Cell<Option<(usize, usize)>> = const { Cell::new(None) };
    /// Each walker's thread and [`View`] index.
    static ACTORS: RefCell<Vec<(thread::ThreadId, usize)>> = const { RefCell::new(Vec::new()) };
    /// The table of the last descriptor each actor read, by [`View`] index.
    static LAST_READ: RefCell<[Option<usize>; 3]> = const { RefCell::new([None; 3]) };
}

/// Where a walker known to [`WALKERS`] is.
#[derive(Clone, Copy, PartialEq)]
enum Idle {
    Running,
    Parked,
    Returned,
}

/// Sets the calling walker's place in [`WALKERS`].
fn place(idle: Idle) {
    let me = thread::current();
    WALKERS.with(|walkers| {
        let mut walkers = walkers.borrow_mut();
        walkers.retain(|(walker, _)| walker.id() != me.id());
        walkers.push((me, idle));
    });
}

/// Whether the latest stores give a walker whose queue looked empty more
/// to do: queued work, or the drain [`Queue::drained`] reports, read from
/// the shadows so the check makes no loom access.
fn progress() -> bool {
    QUEUE.with(|queue| {
        queue.borrow().as_ref().is_some_and(|queue| {
            queue.queued.latest() > 0
                || queue.aborted.latest()
                || queue.listed.latest() && queue.pending.latest() == 0
        })
    })
}

/// Whether no thread but `caller` can change the walk again: the listing
/// ended, both walkers have registered, and every walker but `caller` is
/// parked or has returned, so none holds work.
fn quiescent(caller: Option<thread::ThreadId>) -> bool {
    LISTED.with(Cell::get)
        && WALKERS.with(|walkers| {
            let walkers = walkers.borrow();
            walkers.len() == 2
                && walkers
                    .iter()
                    .all(|(walker, idle)| Some(walker.id()) == caller || *idle != Idle::Running)
        })
}

/// Unparks every parked walker once the latest stores give it more to do,
/// or once no thread can change the walk again, so it reports the stall.
fn wake() {
    WALKERS.with(|walkers| {
        let walkers = walkers.borrow();
        if walkers.iter().any(|(_, idle)| *idle == Idle::Parked) && (progress() || quiescent(None))
        {
            for (walker, idle) in walkers.iter() {
                if *idle == Idle::Parked {
                    walker.unpark();
                }
            }
        }
    });
}

/// The walkers' idle wait. When the latest stores give the walker more to
/// do than its loads read, it yields and returns, and its next loads read
/// past the stores it saw before the yield. Otherwise it parks until a
/// store gives it more to do. When no thread can change the walk again and
/// the walk has not drained, the walk has stalled, and the walker panics
/// so the walk ends.
pub(super) fn idle() {
    if progress() {
        thread::yield_now();
        return;
    }
    if quiescent(Some(thread::current().id())) {
        STALLED.with(|stalled| stalled.set(true));
        panic!("the walk never drained");
    }
    place(Idle::Parked);
    thread::park();
    place(Idle::Running);
}

/// A loom word, with its latest value kept beside it for the idle wait:
/// the walk's `AtomicUsize`.
pub(super) struct Word(AtomicUsize, std::sync::atomic::AtomicUsize);

impl Word {
    pub(super) fn new(value: usize) -> Self {
        Self(
            AtomicUsize::new(value),
            std::sync::atomic::AtomicUsize::new(value),
        )
    }

    /// The value of the word's last store in modification order.
    fn latest(&self) -> usize {
        self.1.load(Ordering::Relaxed)
    }

    pub(super) fn load(&self, _order: Ordering) -> usize {
        self.0.load(Ordering::SeqCst)
    }

    pub(super) fn store(&self, value: usize, _order: Ordering) {
        self.0.store(value, Ordering::SeqCst);
        self.1.store(value, Ordering::Relaxed);
        wake();
    }

    pub(super) fn fetch_add(&self, value: usize, _order: Ordering) -> usize {
        let previous = self.0.fetch_add(value, Ordering::SeqCst);
        self.1
            .store(previous.wrapping_add(value), Ordering::Relaxed);
        // An addition to the `threads` lane's length queues a process's next
        // step: record the calling walker and the table it last read.
        let continued = QUEUE.with(|queue| {
            queue
                .borrow()
                .as_ref()
                .is_some_and(|queue| std::ptr::eq(self, &queue.threads.len))
        });
        if continued {
            let me = thread::current().id();
            let actor = ACTORS.with(|actors| {
                actors
                    .borrow()
                    .iter()
                    .find_map(|&(id, actor)| (id == me).then_some(actor))
            });
            let table = actor.and_then(|actor| LAST_READ.with(|last| last.borrow()[actor]));
            CONTINUED.with(|current| current.set(actor.zip(table)));
        }
        wake();
        previous
    }

    pub(super) fn fetch_sub(&self, value: usize, _order: Ordering) -> usize {
        let previous = self.0.fetch_sub(value, Ordering::SeqCst);
        self.1
            .store(previous.wrapping_sub(value), Ordering::Relaxed);
        wake();
        previous
    }
}

impl Default for Word {
    fn default() -> Self {
        Self::new(0)
    }
}

/// A once-set cell over a loom mutex that stands in for the walk's
/// `OnceLock` under loom. The mutex orders the set before every get that sees
/// it, as `OnceLock` does.
pub(super) struct Once<T> {
    order: Mutex<()>,
    value: std::sync::OnceLock<T>,
}

impl<T> Once<T> {
    pub(super) fn new() -> Self {
        Self {
            order: Mutex::new(()),
            value: std::sync::OnceLock::new(),
        }
    }

    pub(super) fn get(&self) -> Option<&T> {
        let _order = self.order.lock().unwrap();
        self.value.get()
    }

    pub(super) fn set(&self, value: T) -> Result<(), T> {
        let _order = self.order.lock().unwrap();
        self.value.set(value)
    }
}

/// A loom flag, with its latest value kept beside it for the idle wait:
/// the walk's `AtomicBool`.
pub(super) struct Flag(AtomicBool, std::sync::atomic::AtomicBool);

impl Flag {
    pub(super) fn new(value: bool) -> Self {
        Self(
            AtomicBool::new(value),
            std::sync::atomic::AtomicBool::new(value),
        )
    }

    /// The value of the flag's last store in modification order.
    fn latest(&self) -> bool {
        self.1.load(Ordering::Relaxed)
    }

    pub(super) fn load(&self, _order: Ordering) -> bool {
        self.0.load(Ordering::SeqCst)
    }

    pub(super) fn store(&self, value: bool, _order: Ordering) {
        self.0.store(value, Ordering::SeqCst);
        self.1.store(value, Ordering::Relaxed);
        wake();
    }
}

/// Clears every thread-local of the model for an execution over `table`
/// under `fault`.
fn reset(table: &Table, fault: Fault) {
    FAULT.with(|current| current.set(fault));
    QUEUE.with(|queue| queue.borrow_mut().take());
    WALKERS.with(|walkers| walkers.borrow_mut().clear());
    CONTINUED.with(|continued| continued.set(None));
    ACTORS.with(|actors| actors.borrow_mut().clear());
    LAST_READ.with(|last| *last.borrow_mut() = [None; 3]);
    LISTED.with(|listed| listed.set(false));
    STALLED.with(|stalled| stalled.set(false));
    VIOLATION.with(|violation| violation.borrow_mut().take());
    LEDGER.with(|ledger| ledger.set((0, 0)));
    READS.with(|reads| {
        let mut reads = reads.borrow_mut();
        reads.clear();
        reads.resize(table.descriptors.len(), Visits::default());
    });
    COMPARED.with(|compared| {
        let mut compared = compared.borrow_mut();
        compared.clear();
        compared.resize(table.listings.len(), Visits::default());
    });
    FAILING.with(|failing| {
        failing.set(
            table
                .failing
                .as_ref()
                .map(|failing| table.descriptor(&failing.path, &failing.name)),
        );
    });
}

/// How often one descriptor was read, or one `task` directory stat-ed, and
/// the actors, by [`View`] index, that made the first two of those visits.
#[derive(Clone, Copy, Default)]
struct Visits {
    count: usize,
    by: [Option<usize>; 4],
}

impl Visits {
    fn record(visits: &RefCell<Vec<Self>>, index: usize, actor: usize) {
        let visit = &mut visits.borrow_mut()[index];
        if let Some(by) = visit.by.get_mut(visit.count) {
            *by = Some(actor);
        }
        visit.count += 1;
    }
}

/// Counted items not yet finished, by the ledger.
fn outstanding() -> usize {
    let (added, finished) = LEDGER.with(Cell::get);
    added.saturating_sub(finished)
}

#[derive(Clone, Copy, PartialEq)]
enum Fault {
    None,
    /// The last finish subtracts twice.
    DuplicateFinish,
    /// The last finish subtracts nothing.
    MissingFinish,
    /// A load reports one item fewer than the count holds.
    EarlyDrain,
    /// The failing descriptor's share finishes before its walker panics.
    FinishedFailure,
}

thread_local! {
    static FAULT: Cell<Fault> = const { Cell::new(Fault::None) };
}

/// The pending count, recording each addition and subtraction in the
/// ledger at the transition that makes it, then waking any walker the new
/// count gives work.
#[derive(Default)]
struct Ledger(AtomicUsize, std::sync::atomic::AtomicUsize);

impl Ledger {
    /// The count's value after its last transition. A planted duplicate
    /// finish wraps it past zero to near `usize::MAX`, where the walk stays
    /// undrained and the stall check ends the execution.
    fn latest(&self) -> usize {
        self.1.load(Ordering::Relaxed)
    }
}

impl Count for Ledger {
    fn load(&self, _order: Ordering) -> usize {
        let value = self.0.load(Ordering::SeqCst);
        if FAULT.with(Cell::get) == Fault::EarlyDrain {
            return value.saturating_sub(1);
        }
        value
    }

    fn fetch_add(&self, value: usize, _order: Ordering) -> usize {
        let previous = self.0.fetch_add(value, Ordering::SeqCst);
        LEDGER.with(|ledger| {
            let (added, finished) = ledger.get();
            ledger.set((added + value, finished));
        });
        self.1
            .store(previous.wrapping_add(value), Ordering::Relaxed);
        wake();
        previous
    }

    fn fetch_sub(&self, value: usize, _order: Ordering) -> usize {
        let fault = FAULT.with(Cell::get);
        let last = fault != Fault::None && self.0.load(Ordering::SeqCst) == value;
        let value = match fault {
            Fault::DuplicateFinish if last => 2 * value,
            Fault::MissingFinish if last => 0,
            _ => value,
        };
        let previous = self.0.fetch_sub(value, Ordering::SeqCst);
        LEDGER.with(|ledger| {
            let (added, finished) = ledger.get();
            if finished + value > added {
                VIOLATION.with(|violation| {
                    violation.borrow_mut().get_or_insert(format!(
                        "a finish without a counted item: {added} counted, {} finished",
                        finished + value
                    ));
                });
            }
            ledger.set((added, finished + value));
        });
        self.1
            .store(previous.wrapping_sub(value), Ordering::Relaxed);
        wake();
        previous
    }
}

/// A constructed process table: each directory's entries, the `task` link
/// counts, and every descriptor by index, built once per test. Every
/// descriptor names its own file. An open directory is its index in
/// `listings`.
struct Table {
    listings: Vec<Listing>,
    paths: BTreeMap<CString, usize>,
    /// Each descriptor's node, and whether its table is a leader's.
    descriptors: Vec<(Node, bool)>,
    /// Every descriptor's node once, in ascending order.
    nodes: Vec<Node>,
    failing: Option<Failing>,
}

/// The descriptor of a [`Table`] whose read panics its walker.
struct Failing {
    path: String,
    name: String,
    /// The counted items the panic leaves unfinished: the share being read
    /// and every item that finishes only after that share.
    stranded: usize,
}

/// One directory of a [`Table`]: its entry names, its link count when it is
/// a `task` directory, and the index of its first descriptor when it is a
/// descriptor table. Descriptor `fd` of a table names the file whose inode
/// is the sum of the table path's bytes shifted left 20 bits, ORed with
/// `fd`.
struct Listing {
    names: Vec<CString>,
    links: Option<libc::nlink_t>,
    first: Option<usize>,
}

impl Table {
    /// Process 1 with a leader table of `descriptors` names and, for each
    /// of `threads`, a thread with a private table of one name.
    fn new(descriptors: usize, threads: &[u32]) -> Self {
        Self::processes(&[(1, descriptors, threads)])
    }

    /// Each process `(pid, descriptors, threads)`: a leader table of
    /// `descriptors` names and, for each of `threads`, a thread with a
    /// private table of one name.
    fn processes(processes: &[(u32, usize, &[u32])]) -> Self {
        let mut table = Self {
            listings: Vec::new(),
            paths: BTreeMap::new(),
            descriptors: Vec::new(),
            nodes: Vec::new(),
            failing: None,
        };
        let mut listing = vec!["self".to_owned()];
        listing.extend(processes.iter().map(|(pid, _, _)| pid.to_string()));
        table.insert(String::new(), listing, None);
        for &(pid, descriptors, threads) in processes {
            table.insert(
                format!("{pid}/fd"),
                (0..descriptors).map(|fd| fd.to_string()).collect(),
                None,
            );
            let mut task = vec![pid.to_string()];
            for tid in threads {
                task.push(tid.to_string());
                table.insert(format!("{pid}/task/{tid}/fd"), vec!["0".to_owned()], None);
            }
            let links = TASK_LINKS + 1 + threads.len() as libc::nlink_t;
            table.insert(format!("{pid}/task"), task, Some(links));
        }
        table.nodes = table.descriptors.iter().map(|(node, _)| *node).collect();
        table.nodes.sort_unstable();
        table.nodes.dedup();
        table
    }

    /// Adds the directory at `path` holding `names`. Each entry of an `fd`
    /// directory becomes a descriptor, a leader's when `path` holds one `/`.
    fn insert(&mut self, path: String, names: Vec<String>, links: Option<libc::nlink_t>) {
        let fds = path.ends_with("/fd");
        let leader = path.matches('/').count() == 1;
        let inode = path.bytes().map(u64::from).sum::<u64>() << 20;
        let first = fds.then_some(self.descriptors.len());
        if fds {
            self.descriptors.extend((0..names.len()).map(|fd| {
                let node = Node::File {
                    major: 0,
                    minor: 0,
                    inode: inode | fd as u64,
                };
                (node, leader)
            }));
        }
        self.paths
            .insert(CString::new(path).unwrap(), self.listings.len());
        self.listings.push(Listing {
            names: names
                .into_iter()
                .map(|name| CString::new(name).unwrap())
                .collect(),
            links,
            first,
        });
    }

    /// The directory at `path`.
    fn index(&self, path: &str) -> usize {
        self.paths[CString::new(path).unwrap().as_c_str()]
    }

    /// The index of descriptor `name` of the table at `path`.
    fn descriptor(&self, path: &str, name: &str) -> usize {
        self.listings[self.index(path)].first.unwrap() + name.parse::<usize>().unwrap()
    }

    /// Whether every descriptor was read as often as the walk must read it:
    /// each table twice, its first listing and the listing after its last
    /// read, and the leader's twice again when the recheck reads it.
    fn read_as_expected(&self, rechecked: bool) -> bool {
        READS.with(|reads| {
            let reads = reads.borrow();
            reads
                .iter()
                .zip(&self.descriptors)
                .all(|(read, &(_, leader))| read.count == if leader && rechecked { 4 } else { 2 })
        })
    }
}

/// One actor's view of a [`Table`]: the table's answers, with each read
/// and `stat` recorded against the actor's index.
struct View<'t> {
    table: &'t Table,
    actor: usize,
}

impl Os for View<'_> {
    type Table = usize;

    fn status(&self, path: &CStr) -> io::Result<Status> {
        let found = self.table.paths.get(path).copied();
        let links = found
            .and_then(|index| self.table.listings[index].links)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))?;
        COMPARED.with(|compared| Visits::record(compared, found.unwrap(), self.actor));
        Ok(Status { size: 0, links })
    }

    fn open(&self, path: &CStr) -> io::Result<usize> {
        self.table
            .paths
            .get(path)
            .copied()
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))
    }

    fn entries(
        &self,
        table: &usize,
        _records: &mut [u8],
        mut visit: impl FnMut(&CStr),
    ) -> io::Result<()> {
        for name in &self.table.listings[*table].names {
            visit(name);
        }
        Ok(())
    }

    fn node(&self, table: &usize, name: &CStr) -> io::Result<Option<Node>> {
        let listing = &self.table.listings[*table];
        let fd = name.to_str().unwrap().parse::<usize>().unwrap();
        let descriptor = listing.first.unwrap() + fd;
        if FAILING.with(Cell::get) == Some(descriptor) {
            if FAULT.with(Cell::get) == Fault::FinishedFailure {
                // Cloning the queue releases the thread-local's borrow before
                // `finish`, a loom access that can schedule a thread that
                // borrows `QUEUE`.
                let queue = QUEUE.with(|queue| queue.borrow().clone());
                if let Some(queue) = queue {
                    queue.finish();
                }
            }
            panic!("a planted walker failure");
        }
        READS.with(|reads| Visits::record(reads, descriptor, self.actor));
        LAST_READ.with(|last| last.borrow_mut()[self.actor] = Some(*table));
        Ok(Some(self.table.descriptors[descriptor].0))
    }

    fn shares_leader_table(&self, _pid: u32, _tid: u32) -> bool {
        false
    }

    fn started(&self, _pid: u32, _tid: u32) -> Option<u64> {
        None
    }

    fn last_task(&self) -> Option<u32> {
        Some(0)
    }
}

/// Releases an execution's queue, whose loom objects live only as long
/// as the execution: on the walk's return or unwind, and on a walker's
/// unwind, which ends the execution.
struct Execution {
    walker: bool,
}

impl Drop for Execution {
    fn drop(&mut self) {
        if !self.walker || std::thread::panicking() {
            QUEUE.with(|queue| queue.borrow_mut().take());
        }
    }
}

/// What one execution showed, for the witnesses across executions.
#[derive(Default)]
struct Seen {
    /// A share of process 1's leader table read by the walker that did not
    /// list it.
    split: bool,
    /// Process 1's threads step taken by a walker other than the one that
    /// listed its leader table.
    handed: bool,
    /// Process 1's leader table read again by the walker that read its
    /// thread's table, which takes the recheck as its last unread.
    rechecked_by_thread: bool,
    /// A process's next step queued by a walker that read its leader
    /// table's last share ahead without having listed that table.
    continued: bool,
}

/// Runs the listing actor and two walkers over `table` under `fault`, and
/// checks each walker's return and the joined result. Returns what the
/// execution showed.
fn walk(table: &std::sync::Arc<Table>, rechecked: bool, fault: Fault) -> Seen {
    reset(table, fault);
    let _execution = Execution { walker: false };
    let stranded = table.failing.as_ref().map(|failing| failing.stranded);
    let table = std::sync::Arc::clone(table);
    let queue = std::sync::Arc::new(ModelQueue::default());
    QUEUE.with(|current| *current.borrow_mut() = Some(queue.clone()));
    let found = std::sync::Arc::new(Mutex::new(Some(Vec::new())));
    let walkers: Vec<_> = (0..2)
        .map(|actor| {
            let (table, queue, found) = (table.clone(), queue.clone(), found.clone());
            thread::spawn(move || {
                let _execution = Execution { walker: true };
                place(Idle::Running);
                ACTORS.with(|actors| actors.borrow_mut().push((thread::current().id(), actor)));
                let matches = |_| true;
                let view = View {
                    table: &table,
                    actor,
                };
                Walker::new(&view, &*queue, &matches, facts()).walk(&found);
                place(Idle::Returned);
                wake();
                if !queue.aborted.load(Ordering::Acquire) {
                    // A successful drain: every counted item finished and
                    // every descriptor read.
                    assert_eq!(
                        outstanding(),
                        0,
                        "drained before every counted item finished"
                    );
                    assert!(
                        table.read_as_expected(rechecked),
                        "drained before every descriptor was read"
                    );
                }
            })
        })
        .collect();
    let lister = View {
        table: &table,
        actor: 2,
    };
    let listed = queue.list(&lister, &table.index(""), &mut Default::default());
    LISTED.with(|done| done.set(true));
    wake();
    for walker in walkers {
        walker.join().unwrap();
    }
    if let Some(violation) = VIOLATION.with(|violation| violation.borrow_mut().take()) {
        panic!("{violation}");
    }
    assert!(
        !STALLED.with(Cell::get),
        "counted work never finished: the walk never drained"
    );
    let aborted = queue.aborted.load(Ordering::Acquire);
    QUEUE.with(|current| current.borrow_mut().take());
    let queue = std::sync::Arc::try_unwrap(queue).ok().unwrap();
    let found = std::sync::Arc::try_unwrap(found).ok().unwrap();
    let answer = answer(found, listed);
    if let Some(stranded) = stranded {
        assert!(
            aborted && answer.is_none(),
            "a failed walker yielded an answer"
        );
        assert_eq!(
            outstanding(),
            stranded,
            "the failed walker's work was finished"
        );
    } else {
        assert!(!aborted, "a walk without a failure aborted");
        assert_eq!(
            answer.as_deref(),
            Some(&table.nodes[..]),
            "the walk's answer"
        );
        assert_eq!(outstanding(), 0, "counted work left at quiescence");
        assert_eq!(
            queue.queued.load(Ordering::Relaxed),
            0,
            "queued work left at quiescence"
        );
    }
    Seen::observe(&table)
}

impl Seen {
    /// What the finished execution over `table` showed, from its reads and
    /// `stat`s.
    fn observe(table: &Table) -> Self {
        let first = |path: &str| table.listings[table.index(path)].first.unwrap();
        READS.with(|reads| {
            let reads = reads.borrow();
            let leader = first("1/fd");
            let lister = reads[leader].by[0];
            let thread_reader = table
                .paths
                .get(c"1/task/2/fd")
                .map(|&index| reads[table.listings[index].first.unwrap()].by[0]);
            let compared = COMPARED.with(|compared| compared.borrow()[table.index("1/task")]);
            let leader_names = table.listings[table.index("1/fd")].names.len();
            let continued = CONTINUED.with(Cell::get).is_some_and(|(actor, read)| {
                let read = table.listings[read].first.unwrap();
                reads[read].by[0] != Some(actor)
            });
            Self {
                split: reads[leader..leader + leader_names]
                    .iter()
                    .any(|read| read.count > 0 && read.by[0] != lister),
                // The first `stat` of the task directory counts the threads as
                // the process starts; the second is the threads step.
                handed: compared.count > 1 && compared.by[1] != lister,
                rechecked_by_thread: reads[leader].count == 4
                    && thread_reader.is_some_and(|reader| reads[leader].by[2] == reader),
                continued,
            }
        })
    }
}

/// What each walker knows about the model's walk: two walkers, with every
/// table read and no `kcmp` or start-time facts.
fn facts() -> Facts {
    Facts {
        reports_count: false,
        kcmp: false,
        begun: None,
        walkers: 2,
    }
}

fn model(test: impl Fn() + Sync + Send + 'static) {
    model_bounded(2, test);
}

fn model_bounded(preemptions: usize, test: impl Fn() + Sync + Send + 'static) {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(preemptions);
    builder.max_branches = 10_000_000;
    builder.check(test);
}

/// A process whose leader table splits into four shares: the walk drains
/// only once listing ended and every counted item finished, each item
/// finishes once, some execution reads a share the lister leaves on the
/// other walker, and some execution has that walker take the process's
/// threads step.
#[test]
fn a_split_table_drains_once_every_counted_item_finished() {
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Seen::default()));
    let record = seen.clone();
    let table = std::sync::Arc::new(Table::new(4 * SHARE, &[]));
    model_bounded(1, move || {
        let execution = walk(&table, false, Fault::None);
        let mut seen = record.lock().unwrap();
        seen.split |= execution.split;
        seen.handed |= execution.handed;
    });
    let seen = seen.lock().unwrap();
    assert!(seen.split, "no execution split the table across walkers");
    assert!(
        seen.handed,
        "no execution handed the threads step to the share reader"
    );
}

/// Two processes whose leader tables each split into four shares: the
/// walk drains once every counted item of both finished.
#[test]
fn two_split_tables_drain_once_every_counted_item_finished() {
    let table = Table::processes(&[(1, 4 * SHARE, &[]), (3, 4 * SHARE, &[])]);
    let table = std::sync::Arc::new(table);
    model_bounded(1, move || {
        walk(&table, false, Fault::None);
    });
}

/// A threaded process whose thread holds a private table: the thread's
/// table is queued as counted work, and the walker that reads it takes
/// the last unread and the recheck, which reads the leader's table again
/// before the process finishes.
#[test]
fn a_private_thread_table_is_read_before_the_process_finishes() {
    let table = std::sync::Arc::new(Table::new(2, &[2]));
    model(move || {
        let execution = walk(&table, true, Fault::None);
        assert!(
            execution.rechecked_by_thread,
            "the recheck went past the thread table's reader"
        );
    });
}

/// Two processes whose leader tables split into one queued share and
/// three: some execution has a walker, reading shares ahead while more
/// shares are queued than walkers, read the last share of a table it did
/// not list once that table's lister finished its own part. That read
/// queues the process's next step without a pending addition, and every
/// execution drains once every counted item finished.
#[test]
fn a_share_read_ahead_by_another_walker_queues_the_next_step_uncounted() {
    let seen = std::sync::Arc::new(std::sync::Mutex::new(false));
    let record = seen.clone();
    let table = Table::processes(&[(1, SHARE + 1, &[]), (3, 3 * SHARE + 1, &[])]);
    let table = std::sync::Arc::new(table);
    model(move || {
        let execution = walk(&table, false, Fault::None);
        *record.lock().unwrap() |= execution.continued;
    });
    assert!(
        *seen.lock().unwrap(),
        "no execution queued a next step from a share read ahead"
    );
}

/// A share whose read is the last of its leader table's, read ahead by a
/// walker that did not list the table: the read lists the table again and
/// reads every descriptor of that listing, then queues the process's next
/// step without a pending addition, the share finishes alone, and the
/// queued step finishes the process. One thread drives the production
/// steps from a seeded queue, so the test checks the pending count after
/// each step.
#[test]
fn a_last_share_read_ahead_queues_the_next_step_uncounted() {
    let table = Table::new(SHARE + 1, &[]);
    loom::model(move || {
        reset(&table, Fault::None);
        let _execution = Execution { walker: false };
        let queue = std::sync::Arc::new(ModelQueue::default());
        QUEUE.with(|current| *current.borrow_mut() = Some(queue.clone()));
        ACTORS.with(|actors| actors.borrow_mut().push((thread::current().id(), 0)));
        // The process is counted and its lister has read its own part.
        queue.pending.fetch_add(1, Ordering::AcqRel);
        let leader = std::sync::Arc::new(super::Leader {
            pid: 1,
            threaded: false,
            last: Some(0),
            unread: Word::new(0),
            listed: Once::new(),
        });
        let mut names = vec![CString::new(SHARE.to_string()).unwrap()];
        let listing = std::sync::Arc::new(FirstListing {
            unread: Word::new(0),
        });
        queue.share(
            (&std::sync::Arc::new(table.index("1/fd")), &listing),
            &mut names,
            Some(&leader),
            None,
        );
        let matches = |_| true;
        let view = View {
            table: &table,
            actor: 0,
        };
        let mut walker = Walker::new(&view, &*queue, &matches, facts());
        assert!(walker.read_share(false));
        let reads: Vec<usize> =
            READS.with(|reads| reads.borrow().iter().map(|read| read.count).collect());
        let mut reread = vec![1; SHARE + 1];
        reread[SHARE] = 2;
        assert_eq!(
            reads, reread,
            "the last read of the first listing did not list the table again"
        );
        assert_eq!(
            queue.threads.len.load(Ordering::Acquire),
            1,
            "the next step was not queued"
        );
        assert_eq!(
            CONTINUED.with(Cell::get),
            Some((0, table.index("1/fd"))),
            "the continuation witness missed the queued next step"
        );
        assert_eq!(
            LEDGER.with(Cell::get),
            (2, 1),
            "the continuation changed the pending count"
        );
        assert_eq!(
            outstanding(),
            1,
            "the process left the count before its next step"
        );
        let due = queue.pop(&queue.threads).expect("the queued next step");
        walker.next(&due);
        assert_eq!(outstanding(), 0, "the next step left the process counted");
        assert_eq!(
            queue.queued.load(Ordering::Acquire),
            0,
            "queued work left at quiescence"
        );
    });
}

/// A walker that panics while it holds a share: the walk fails, the share
/// stays counted, and both walkers finish before the result.
#[test]
fn a_walker_panic_fails_the_walk_with_its_work_unfinished() {
    let table = failing_share();
    model(move || {
        walk(&table, false, Fault::None);
    });
}

#[test]
#[should_panic(expected = "the failed walker's work was finished")]
fn a_failure_that_finishes_its_share_uncounts_its_work() {
    let table = failing_share();
    model(move || {
        walk(&table, false, Fault::FinishedFailure);
    });
}

fn failing_share() -> std::sync::Arc<Table> {
    let mut table = Table::new(2 * SHARE, &[]);
    table.failing = Some(Failing {
        path: "1/fd".to_owned(),
        name: SHARE.to_string(),
        stranded: 2,
    });
    std::sync::Arc::new(table)
}

/// Control: a drain check that reads one item fewer lets a walker return
/// while an item is in flight.
#[test]
#[should_panic(expected = "drained before every counted item finished")]
fn an_early_drain_returns_before_its_work_finished() {
    let table = std::sync::Arc::new(Table::new(2 * SHARE, &[]));
    model(move || {
        walk(&table, false, Fault::EarlyDrain);
    });
}

/// Control: a last finish that subtracts twice finishes more items than
/// the walk counted.
#[test]
#[should_panic(expected = "a finish without a counted item")]
fn a_duplicate_finish_finishes_an_uncounted_item() {
    let table = std::sync::Arc::new(Table::new(2 * SHARE, &[]));
    model(move || {
        walk(&table, false, Fault::DuplicateFinish);
    });
}

/// Control: a last finish that subtracts nothing leaves the walk counting
/// work that never finishes, so it never drains.
#[test]
#[should_panic(expected = "counted work never finished")]
fn a_missing_finish_never_drains() {
    let table = std::sync::Arc::new(Table::new(2 * SHARE, &[]));
    model(move || {
        walk(&table, false, Fault::MissingFinish);
    });
}
