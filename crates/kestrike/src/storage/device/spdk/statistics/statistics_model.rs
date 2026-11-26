//! Loom model of the statistics request flag and stop: two requesters and
//! one owner that serializes service and stop run the production
//! [`StatisticsHandle::request`], [`Shared::take_request`],
//! [`Shared::publish`] and [`Shared::stop`] over a loom flag and mutex.
//!
//! The owner services the flag twice, submitting a command for a consumed
//! request and publishing its reading at the next call, then stops as a
//! quiescing driver does: it consumes any pending flag, answers its
//! outstanding command or that flag with one `DeviceGone`, and calls
//! [`Shared::stop`]. Its own command state is the model's, kept apart from
//! the flag. The oracle is a log of the flag's stores and consumptions and
//! of the `latest` mutex's acquisitions by the stop and by requests, by
//! thread and phase, recorded at each operation. Each requester checks
//! that it reads no sequence decrease and that a request it made after
//! the stop returned sees a `DeviceGone` published after it began; after
//! every actor joins, no
//! request flag stays set, every request has a reading published after
//! it, and the published sequence counts exactly the owner's publications
//! and the consumptions that publish `DeviceGone`. The flag is relaxed:
//! for a request that runs before or during the stop, the model checks
//! that the `latest` mutex alone orders its store and stop check against
//! the stop's mark and consumption.
//!
//! Bounds: loom 0.7.2 with a preemption bound of 2, one owner and two
//! requesters, two service calls and one stop, each requester requesting
//! once.

use std::cell::{Cell, RefCell};
use std::fmt;
use std::sync::atomic::Ordering;

use loom::sync::atomic::AtomicBool;
use loom::thread;

use super::{
    Arc, EbsStatistics, HISTOGRAM_BINS, LatencyBin, LatencyHistogram, Shared, StatisticsFailure,
    StatisticsHandle,
};

/// What one operation did, and in which actor's phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Event {
    /// A requester stored the flag.
    Store(usize),
    /// A consumption inside a requester's `request`.
    TakenByRequest(usize),
    /// A consumption by the owner's service call.
    TakenByService,
    /// A consumption by the owner's quiesce, before its stop.
    TakenByQuiesce,
    /// A consumption inside the owner's stop.
    TakenByStop,
    /// The owner's stop took the `latest` mutex.
    StopLocked,
    /// A requester's `request` took the `latest` mutex.
    RequestLocked(usize),
}

/// The actor running on a thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Actor {
    Owner,
    Quiescing,
    Stopping,
    /// A requester inside `request`.
    Requester(usize),
    /// A requester reading the latest reading around its request.
    Reader,
}

/// How the history runs: the production bodies, or one planted fault.
#[derive(Clone, Copy, PartialEq)]
enum Control {
    Production,
    /// A consumption that reads the flag and leaves it set.
    SkipClear,
    /// A request that reads the stop mark before it stores its flag.
    DecidedOutsideTheMutex,
}

// Loom runs every model thread on one OS thread, so these cells hold one
// execution's history shared by all its threads.
thread_local! {
    static LOG: RefCell<Vec<Event>> = const { RefCell::new(Vec::new()) };
    static ACTORS: RefCell<Vec<(thread::ThreadId, Actor)>> = const { RefCell::new(Vec::new()) };
    static SKIP_CLEAR: Cell<bool> = const { Cell::new(false) };
}

fn actor() -> Actor {
    let me = thread::current().id();
    ACTORS.with(|actors| {
        actors
            .borrow()
            .iter()
            .rev()
            .find(|(id, _)| *id == me)
            .map(|(_, actor)| *actor)
            .expect("an actor of the model")
    })
}

fn become_actor(actor: Actor) {
    let me = thread::current().id();
    ACTORS.with(|actors| actors.borrow_mut().push((me, actor)));
}

fn log(event: Event) {
    LOG.with(|log| log.borrow_mut().push(event));
}

/// The request flag over a loom atomic, recording each store and each
/// consumption at the operation.
#[derive(Default)]
pub(super) struct Flag(AtomicBool);

impl fmt::Debug for Flag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Flag")
    }
}

impl Flag {
    pub(super) fn load(&self, order: Ordering) -> bool {
        self.0.load(order)
    }

    pub(super) fn store(&self, value: bool, order: Ordering) {
        self.0.store(value, order);
        if let Actor::Requester(id) = actor() {
            log(Event::Store(id));
        }
    }

    pub(super) fn swap(&self, value: bool, order: Ordering) -> bool {
        let previous = if SKIP_CLEAR.with(Cell::get) {
            self.0.load(order)
        } else {
            self.0.swap(value, order)
        };
        if previous {
            log(match actor() {
                Actor::Requester(id) => Event::TakenByRequest(id),
                Actor::Owner => Event::TakenByService,
                Actor::Quiescing => Event::TakenByQuiesce,
                Actor::Stopping => Event::TakenByStop,
                Actor::Reader => unreachable!("a reader consumes no flag"),
            });
        }
        previous
    }
}

/// The `latest` mutex over a loom mutex, recording the stop's and each
/// request's acquisition.
#[derive(Default)]
pub(super) struct Lock<T>(loom::sync::Mutex<T>);

impl<T> fmt::Debug for Lock<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Lock")
    }
}

impl<T> Lock<T> {
    pub(super) fn lock(&self) -> std::sync::LockResult<loom::sync::MutexGuard<'_, T>> {
        let guard = self.0.lock();
        match actor() {
            Actor::Stopping => log(Event::StopLocked),
            Actor::Requester(id) => log(Event::RequestLocked(id)),
            Actor::Owner | Actor::Quiescing | Actor::Reader => {}
        }
        guard
    }
}

fn reading() -> EbsStatistics {
    let empty = LatencyHistogram {
        bins: [LatencyBin::default(); HISTOGRAM_BINS],
        len: 0,
    };
    EbsStatistics {
        read_ops: 1,
        write_ops: 0,
        read_bytes: 0,
        write_bytes: 0,
        read_time_us: 0,
        write_time_us: 0,
        volume_exceeded_iops_us: 0,
        volume_exceeded_throughput_us: 0,
        instance_exceeded_iops_us: 0,
        instance_exceeded_throughput_us: 0,
        queue_length: 0,
        read_latency: empty,
        write_latency: empty,
    }
}

fn gone() -> Result<EbsStatistics, StatisticsFailure> {
    Err(StatisticsFailure::DeviceGone(None))
}

/// What one execution showed, for the witnesses across executions.
#[derive(Debug, Default, Clone, Copy)]
struct Seen {
    store_before_stop: bool,
    store_after_stop: bool,
    /// A request stored its flag before the stop took the mutex and took
    /// the mutex itself after.
    overlapped: bool,
    /// A request began after the stop returned.
    request_after_stop: bool,
    taken_by_stop: bool,
    taken_by_request: bool,
    /// The owner's first service consumption took a flag both requests had
    /// set.
    coalesced: bool,
}

impl Seen {
    fn merge(&mut self, other: Seen) {
        self.store_before_stop |= other.store_before_stop;
        self.store_after_stop |= other.store_after_stop;
        self.overlapped |= other.overlapped;
        self.request_after_stop |= other.request_after_stop;
        self.taken_by_stop |= other.taken_by_stop;
        self.taken_by_request |= other.taken_by_request;
        self.coalesced |= other.coalesced;
    }
}

fn request(handle: &StatisticsHandle, control: Control) {
    if control == Control::DecidedOutsideTheMutex {
        let stopped = handle.0.latest().stopped;
        handle.0.requested.store(true, Ordering::Relaxed);
        if stopped && handle.0.take_request() {
            handle.0.publish(gone());
        }
    } else {
        handle.request();
    }
}

/// The owner: two service calls, then a quiesce that returns `Stopped`.
/// Returns the readings it published.
fn owner(shared: &Shared, stop_returned: &AtomicBool) -> u64 {
    let mut outstanding = false;
    let mut published = 0;
    for _ in 0..2 {
        if outstanding {
            shared.publish(Ok(reading()));
            outstanding = false;
            published += 1;
        } else if shared.take_request() {
            outstanding = true;
        }
    }
    // `SpdkDisk::quiesce` returning `Stopped`: `abandon_statistics` gives
    // the outstanding command, with any flag coalesced behind it, or a
    // pending flag one `DeviceGone`, then `Shared::stop` sets the mark.
    become_actor(Actor::Quiescing);
    let owed = if outstanding {
        shared.take_request();
        true
    } else {
        shared.take_request()
    };
    if owed {
        shared.publish(gone());
        published += 1;
    }
    become_actor(Actor::Stopping);
    shared.stop();
    stop_returned.store(true, Ordering::Release);
    become_actor(Actor::Owner);
    published
}

/// The witnesses the log and the requesters' starts show.
fn witnesses(log: &[Event], starts: &[(u64, bool)]) -> Seen {
    let at = |event: Event| log.iter().position(|logged| *logged == event);
    let stop = at(Event::StopLocked);
    let stores: Vec<usize> = (0..2).filter_map(|id| at(Event::Store(id))).collect();
    let first_take = log.iter().position(|event| *event == Event::TakenByService);
    Seen {
        store_before_stop: stop.is_some_and(|stop| stores.iter().any(|at| *at < stop)),
        store_after_stop: stop.is_some_and(|stop| stores.iter().any(|at| *at > stop)),
        overlapped: stop.is_some_and(|stop| {
            (0..2).any(|id| {
                at(Event::Store(id)).is_some_and(|at| at < stop)
                    && at(Event::RequestLocked(id)).is_some_and(|at| at > stop)
            })
        }),
        request_after_stop: starts.iter().any(|&(_, after_stop)| after_stop),
        taken_by_stop: log.contains(&Event::TakenByStop),
        taken_by_request: log
            .iter()
            .any(|event| matches!(event, Event::TakenByRequest(_))),
        coalesced: first_take
            .is_some_and(|take| stores.iter().filter(|at| **at < take).count() == 2),
    }
}

/// Runs the owner and two requesters under `control`, checks the joined
/// history, and returns what it showed.
fn history(control: Control) -> Seen {
    LOG.with(|log| log.borrow_mut().clear());
    ACTORS.with(|actors| actors.borrow_mut().clear());
    SKIP_CLEAR.with(|skip| skip.set(control == Control::SkipClear));
    let handle = StatisticsHandle(Arc::new(Shared::default()));
    let stop_returned = Arc::new(AtomicBool::new(false));
    let requesters: Vec<_> = (0..2)
        .map(|id| {
            let (handle, stop_returned) = (handle.clone(), stop_returned.clone());
            thread::spawn(move || {
                become_actor(Actor::Reader);
                let after_stop = stop_returned.load(Ordering::Acquire);
                let before = handle.latest().map_or(0, |reading| reading.sequence);
                become_actor(Actor::Requester(id));
                request(&handle, control);
                become_actor(Actor::Reader);
                let reading = handle.latest();
                let after = reading.map_or(0, |reading| reading.sequence);
                assert!(after >= before, "a requester read the sequence decrease");
                // A planted fault changes what a request after the stop does,
                // so the production bodies alone carry this check.
                if after_stop && control == Control::Production {
                    // A request made after the stop returned sees a
                    // `DeviceGone` published after it began.
                    assert!(
                        after > before && reading.is_some_and(|reading| reading.outcome == gone()),
                        "a request after the stop published no DeviceGone"
                    );
                }
                (before, after_stop)
            })
        })
        .collect();
    become_actor(Actor::Owner);
    let shared = &handle.0;
    let published = owner(shared, &stop_returned);
    let starts: Vec<(u64, bool)> = requesters.into_iter().map(|r| r.join().unwrap()).collect();
    let log = LOG.with(|log| log.borrow().clone());
    assert!(
        !shared.requested.load(Ordering::Relaxed),
        "a pending request flag stranded after settling"
    );
    let last = handle.latest().map_or(0, |reading| reading.sequence);
    for &(before, _) in &starts {
        assert!(
            last > before,
            "a request without a reading published after it"
        );
    }
    let gone_by_flag = log
        .iter()
        .filter(|event| matches!(event, Event::TakenByRequest(_) | Event::TakenByStop))
        .count() as u64;
    assert_eq!(
        last,
        published + gone_by_flag,
        "the sequence counts other than the published readings"
    );
    witnesses(&log, &starts)
}

fn model(test: impl Fn() + Sync + Send + 'static) {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(2);
    builder.check(test);
}

/// The production bodies: no flag stays set after settling, every request
/// has a reading after it, the sequence counts the publications in mutex
/// order, and a request after the stop sees `DeviceGone` published after
/// it.
/// Some execution stores a flag before the stop takes the mutex and some
/// after, some request stores its flag before the stop takes the mutex
/// and takes the mutex after, some request begins after the stop
/// returned, some stop consumes a requester's flag, some request consumes
/// a flag after the stop, and some service call takes one flag both
/// requests set, so their requests share one reading.
#[test]
fn requests_and_the_stop_strand_no_flag_and_answer_every_request() {
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Seen::default()));
    let witnessed = seen.clone();
    model(move || {
        witnessed
            .lock()
            .unwrap()
            .merge(history(Control::Production));
    });
    let seen = *seen.lock().unwrap();
    assert!(seen.store_before_stop, "no flag was stored before the stop");
    assert!(seen.store_after_stop, "no flag was stored after the stop");
    assert!(seen.overlapped, "no request overlapped the stop");
    assert!(
        seen.request_after_stop,
        "no request began after the stop returned"
    );
    assert!(seen.taken_by_stop, "the stop consumed no requester's flag");
    assert!(
        seen.taken_by_request,
        "no request answered itself after the stop"
    );
    assert!(
        seen.coalesced,
        "no service call answered both requests at once"
    );
}

/// Control: a consumption that leaves the flag set strands it.
#[test]
#[should_panic(expected = "a pending request flag stranded after settling")]
fn a_consumption_that_keeps_the_flag_strands_it() {
    model(|| {
        history(Control::SkipClear);
    });
}

/// Control: a request that reads the stop mark before storing its flag
/// misses a stop that runs between the two, which leaves its flag set.
#[test]
#[should_panic(expected = "a pending request flag stranded after settling")]
fn a_stop_decision_outside_the_mutex_strands_a_request() {
    model(|| {
        history(Control::DecidedOutsideTheMutex);
    });
}
