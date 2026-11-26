use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};

use super::{DEPTH, Done, Job, Lane, Mode, Monitors};
use crate::failover::records::{NamedCheckpoint, ShardRecord};
use crate::failover::restart::tests::{volume_id, volume_record};
use crate::failover::retire::Target;
use crate::host::HostGate;
use crate::storage::checkpoint::tests::SESSION;
use crate::storage::checkpoint::{PossiblyNamed, SuffixBounds, SuffixLimits};
use crate::storage::page_coverage::PageRequest;
use crate::storage::store::sim::{Arm, Shared, SimStore};
use crate::storage::store::{
    Client, Item, Key, Outcome, Read, Store, StoreError, Tallied, Unavailable, Watermark,
    WatermarkLog, Write,
};
use crate::storage::store_tests::{client, record, shard};
use crate::storage::test_platform::TestPlatform;
use crate::storage::warm_sim::{layout, storage};
use crate::storage::{Bomb, CpuSet, Dropped, Storage};

/// One store request as [`Locked`] saw it: the issuing thread's name and affinity mask, whether it wrote, and its key.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Request {
    pub(crate) thread: Option<String>,
    pub(crate) cpus: CpuSet,
    pub(crate) write: bool,
    pub(crate) key: Key,
}

#[derive(Clone)]
pub(crate) struct Locked {
    store: Arc<Mutex<SimStore>>,
    requests: Arc<Mutex<Vec<Request>>>,
    panic: Arc<AtomicBool>,
    bomb: Arc<AtomicBool>,
    dropped: Dropped,
}

impl Locked {
    pub(crate) fn of(shared: &Shared) -> Self {
        Self {
            store: Arc::new(Mutex::new(shared.0.borrow().clone())),
            requests: Arc::default(),
            panic: Arc::default(),
            bomb: Arc::default(),
            dropped: Arc::default(),
        }
    }

    fn issue(&self, write: bool, key: &Key) {
        let request = Request {
            thread: std::thread::current().name().map(str::to_owned),
            cpus: CpuSet::current().expect("the issuing thread's mask"),
            write,
            key: *key,
        };
        self.requests.lock().unwrap().push(request);
        assert!(!self.panic.load(Ordering::Acquire), "a planted store panic");
        if self.bomb.swap(false, Ordering::AcqRel) {
            std::panic::panic_any(Bomb(Arc::clone(&self.dropped)));
        }
    }

    pub(crate) fn requests(&self) -> Vec<Request> {
        self.requests.lock().unwrap().clone()
    }

    pub(crate) fn threads(&self) -> Vec<Option<String>> {
        (self.requests().into_iter())
            .map(|request| request.thread)
            .collect()
    }
}

impl Store for Locked {
    fn read(&mut self, key: &Key) -> Result<Option<Item>, Unavailable> {
        self.issue(false, key);
        self.store.lock().unwrap().read(key)
    }

    fn write(&mut self, key: &Key, write: &Write) -> Outcome {
        self.issue(true, key);
        self.store.lock().unwrap().write(key, write)
    }

    fn namespace(&self) -> crate::failover::records::Namespace {
        self.store.lock().unwrap().namespace
    }
}

#[derive(Clone, Default)]
pub(crate) struct SharedLog(Arc<Mutex<Watermark>>);

impl WatermarkLog for SharedLog {
    fn load(&self) -> std::io::Result<Watermark> {
        Ok(self.0.lock().unwrap().clone())
    }

    fn record(&mut self, mark: &Watermark) -> std::io::Result<()> {
        *self.0.lock().unwrap() = mark.clone();
        Ok(())
    }
}

pub(crate) fn locked_client(store: &Locked) -> Client<Locked, SharedLog> {
    Client::open(store.clone(), SharedLog::default()).unwrap()
}

fn seeded() -> Locked {
    Locked::of(&crate::storage::store_tests::seeded())
}

/// The checkpoint the [`tenured`] record names.
fn checkpoint() -> NamedCheckpoint {
    NamedCheckpoint {
        slot: 0,
        session: SESSION,
        capture: 0,
        units: 1,
    }
}

/// A store whose shard record names the tenure `SESSION` (`E = 1`) and the checkpoint [`checkpoint`], so a Confirm commits
/// and an Open reserves the tenure's suffix.
fn tenured() -> Locked {
    let store = Shared::new();
    let tenure = ShardRecord {
        attempts: 1,
        checkpoint: Some(checkpoint()),
        ..record()
    };
    client(&store).create_shard(tenure).unwrap();
    Locked::of(&store)
}

pub(crate) fn bounds() -> SuffixBounds {
    SuffixBounds {
        limits: SuffixLimits {
            flush_ns: 1,
            queue_blocks: 8,
            oldest_ns: 1 << 40,
            uncertified: 16,
        },
        step: 2,
        margin: 1,
    }
}

fn shard_read(store: &Locked) -> Read<ShardRecord> {
    locked_client(store)
        .read::<ShardRecord>(Key::Shard(shard()))
        .unwrap()
}

fn set() -> PossiblyNamed {
    PossiblyNamed::new((shard(), 2), layout(), None)
}

fn view() -> Job {
    Job::View {
        volume: volume_id(),
        shard: shard(),
        sent_at: 7,
    }
}

fn confirm(store: &Locked) -> Job {
    let read = shard_read(store);
    let own = Target::of(read.value());
    Job::Confirm {
        possible: set(),
        read,
        own,
    }
}

fn open(store: &Locked) -> Job {
    let read = shard_read(store);
    let own = Target::of(read.value());
    Job::Open {
        possible: set(),
        read,
        own,
        ends: Vec::new(),
        bounds: bounds(),
    }
}

fn cpus() -> CpuSet {
    CpuSet::current().expect("the test thread's mask")
}

/// Runs `body` on a lane [`Lane::start`] built over `store` and placed on the test thread's mask: threaded, or
/// inline under `INLINE_RECOVERY`.
fn started<R>(
    store: &Locked,
    body: impl FnOnce(&mut Lane<'_, Locked, SharedLog, TestPlatform>) -> R,
) -> R {
    started_on(store, cpus(), body)
}

/// [`started`] with the lane placed on `on`.
fn started_on<R>(
    store: &Locked,
    on: CpuSet,
    body: impl FnOnce(&mut Lane<'_, Locked, SharedLog, TestPlatform>) -> R,
) -> R {
    let storage: Storage<TestPlatform> = storage(1);
    std::thread::scope(|scope| {
        let mut lane = Lane::start(
            &HostGate::qualified(),
            scope,
            locked_client(store),
            &storage,
            on,
        )
        .expect("a started lane");
        let result = body(&mut lane);
        drop(lane.end());
        result
    })
}

fn named(done: &Done) -> &'static str {
    match done {
        Done::View { .. } => "view",
        Done::Confirm { .. } => "confirm",
        Done::Open { .. } => "open",
        Done::Listing { .. } => "listing",
        Done::Page { .. } => "page",
        Done::Step { .. } => "step",
        Done::Publish { .. } => "publish",
        Done::Certify { .. } => "certify",
        Done::Drop { .. } => "drop",
        Done::Transfer { .. } => "transfer",
        Done::Held => "held",
        Done::Marked => "marked",
        Done::Panicked => "panicked",
    }
}

/// Submits a [`Job::Hold`], waits until the lane thread runs it, and returns the sender that releases it.
fn hold(lane: &mut Lane<'_, Locked, SharedLog, TestPlatform>) -> mpsc::Sender<()> {
    let (started, running) = mpsc::channel();
    let (release, held) = mpsc::channel();
    lane.submit(Job::Hold {
        started,
        release: held,
    })
    .unwrap();
    running.recv().unwrap();
    release
}

/// BOUNDED, VIEW-FIRST: a second Mark and a fifth job return unrun, and the View queued last runs first.
#[test]
fn a_full_lane_refuses_and_a_queued_view_runs_first() {
    let store = seeded();
    started(&store, |lane| {
        let release = hold(lane);
        lane.submit(Job::Mark).unwrap();
        let second = lane.submit(Job::Mark).expect_err("a second Mark");
        assert!(matches!(*second, Job::Mark));
        lane.submit(confirm(&store)).unwrap();
        lane.submit(view()).unwrap();
        assert_eq!(lane.outstanding(), DEPTH);
        let fifth = lane.submit(open(&store)).expect_err("a fifth job");
        assert!(matches!(*fifth, Job::Open { .. }));
        release.send(()).unwrap();
        let order: Vec<_> = (0..DEPTH)
            .map(|_| named(&lane.wait().expect("a completion")))
            .collect();
        assert_eq!(order, ["held", "view", "marked", "confirm"]);
        assert_eq!(lane.outstanding(), 0);
        assert!(lane.poll().is_none(), "each completion lands once");
    });
}

/// STORE-OFF-POLL, READ-ORDER: a View reads the volume record, then the shard record; a Confirm commits a
/// shard-record write and an Open over its read and set reserves the tenure's suffix; every request of each job names
/// the lane thread, and each completion arrives once.
#[test]
fn each_job_kind_runs_on_the_lane_thread_and_completes_once() {
    let store = tenured();
    let read = shard_read(&store);
    let own = Target::of(read.value());
    let possible = PossiblyNamed::new((shard(), SESSION), layout(), Some(checkpoint()));
    let mut requests = store.requests().len();
    let mut issued = |store: &Locked| {
        let all = store.requests();
        let new: Vec<_> = (all[requests..].iter())
            .map(|request| (request.write, request.key))
            .collect();
        assert!(
            (all[requests..].iter()).all(|request| request.thread.as_deref() == Some("store-lane")),
            "{all:?}"
        );
        requests = all.len();
        new
    };
    started(&store, |lane| {
        lane.submit(view()).unwrap();
        match lane.wait() {
            Some(Done::View {
                sent_at: 7,
                volume: Err(StoreError::Absent),
                shard: Ok(shard_read),
            }) => assert_eq!(shard_read.value(), read.value()),
            other => panic!("{other:?}"),
        }
        assert_eq!(
            issued(&store),
            [
                (false, Key::Volume(volume_id())),
                (false, Key::Shard(shard()))
            ],
            "the volume record, then the shard record"
        );
        lane.submit(Job::Confirm {
            possible,
            read,
            own,
        })
        .unwrap();
        let Some(Done::Confirm {
            possible,
            confirmed: Ok(confirmed),
        }) = lane.wait()
        else {
            panic!("a committed Confirm");
        };
        assert!(issued(&store).contains(&(true, Key::Shard(shard()))));
        lane.submit(Job::Open {
            possible,
            read: confirmed,
            own,
            ends: Vec::new(),
            bounds: bounds(),
        })
        .unwrap();
        let Some(Done::Open {
            opened: Ok((reserved, _)),
            ..
        }) = lane.wait()
        else {
            panic!("a reserved Open");
        };
        let last = reserved.value().ancestry.as_slice().last().copied();
        assert_eq!(last.map(|suffix| suffix.session), Some(SESSION));
        assert!(issued(&store).contains(&(true, Key::Shard(shard()))));
        lane.submit(Job::Page {
            request: PageRequest::reread(shard(), 0),
        })
        .unwrap();
        assert!(matches!(lane.wait(), Some(Done::Page { .. })));
        assert_eq!(issued(&store), [(false, Key::Page(shard(), 0))]);
        assert!(lane.poll().is_none());
    });
}

/// READ-ORDER: a View over a store that holds the volume record and no shard record returns the volume read and the
/// shard read's own error, from one volume read and then one shard read.
#[test]
fn a_view_returns_each_read_whatever_the_other_returned() {
    let shared = Shared::new();
    let created = client(&shared)
        .create(Key::Volume(volume_id()), volume_record())
        .unwrap();
    let store = Locked::of(&shared);
    started(&store, |lane| {
        lane.submit(view()).unwrap();
        match lane.wait() {
            Some(Done::View {
                volume: Ok(volume),
                shard: Err(StoreError::Absent),
                ..
            }) => assert_eq!(volume.value(), created.value()),
            other => panic!("{other:?}"),
        }
    });
    let keys: Vec<_> = (store.requests().into_iter())
        .map(|request| (request.write, request.key))
        .collect();
    assert_eq!(
        keys,
        [
            (false, Key::Volume(volume_id())),
            (false, Key::Shard(shard()))
        ]
    );
}

/// CONTAINED: after a job completes `Panicked`, the next View on the same lane completes.
#[test]
fn a_panicking_job_completes_panicked_and_the_lane_runs_on() {
    let store = seeded();
    started(&store, |lane| {
        store.panic.store(true, Ordering::Release);
        lane.submit(view()).unwrap();
        assert!(matches!(lane.wait(), Some(Done::Panicked)));
        store.panic.store(false, Ordering::Release);
        lane.submit(view()).unwrap();
        assert!(matches!(lane.wait(), Some(Done::View { shard: Ok(_), .. })));
    });
}

/// CONTAINED: a job whose panic payload panics again as it drops completes `Panicked` once, on a threaded and on an
/// inline lane, and the next View on the same lane completes. The first payload's destructor runs once and the
/// second payload's never runs.
#[test]
fn a_panic_whose_payload_panics_on_drop_completes_panicked() {
    let store = seeded();
    let contained = |lane: &mut Lane<'_, Locked, SharedLog, TestPlatform>| {
        store.dropped.lock().unwrap().clear();
        store.bomb.store(true, Ordering::Release);
        lane.submit(view()).unwrap();
        assert!(matches!(lane.wait(), Some(Done::Panicked)));
        assert_eq!(lane.outstanding(), 0);
        assert!(lane.poll().is_none(), "the panic completes once");
        lane.submit(view()).unwrap();
        assert!(matches!(lane.wait(), Some(Done::View { shard: Ok(_), .. })));
    };
    let dropped = || store.dropped.lock().unwrap().clone();
    started(&store, contained);
    assert_eq!(dropped(), ["bomb"], "threaded");
    let storage: Storage<TestPlatform> = storage(1);
    let mut lane = Lane::inline(locked_client(&store), &storage);
    contained(&mut lane);
    drop(lane.end());
    assert_eq!(dropped(), ["bomb"], "inline");
}

/// The lane thread runs on the CPU set `start` takes, and the owner thread keeps its own mask.
#[test]
fn the_lane_thread_runs_on_its_cpu_set() {
    let owner = cpus();
    let first = owner
        .cpus()
        .next()
        .expect("a CPU in the test thread's mask");
    assert!(
        owner.len() >= 2,
        "the case needs two allowed CPUs: {owner:?}"
    );
    let one = CpuSet::from_cpus(&[first]).unwrap();
    let store = seeded();
    let before = store.requests().len();
    started_on(&store, one, |lane| {
        lane.submit(view()).unwrap();
        assert!(matches!(lane.wait(), Some(Done::View { .. })));
    });
    let requests = store.requests();
    assert!(requests.len() > before);
    assert!(
        (requests[before..].iter()).all(|request| request.cpus == one),
        "{requests:?}"
    );
    assert_eq!(cpus(), owner, "the owner thread's mask is unchanged");
}

/// A CPU set the kernel refuses ends the start with its error, and no store request runs.
#[test]
fn a_refused_placement_ends_the_start_with_no_request() {
    let store = seeded();
    let storage: Storage<TestPlatform> = storage(1);
    let before = store.requests().len();
    let refused = std::thread::scope(|scope| {
        Lane::start(
            &HostGate::qualified(),
            scope,
            locked_client(&store),
            &storage,
            CpuSet::empty(),
        )
        .err()
    });
    let error = refused.expect("an empty CPU set refuses the start");
    assert_eq!(error.raw_os_error(), Some(libc::EINVAL));
    assert_eq!(store.requests().len(), before);
}

/// JOINED: closing the lane, by `end` or by `Drop`, while a job runs drops the shard-record write and the View queued
/// behind it unrun, and returns only after the thread ended and its client dropped.
#[test]
fn closing_a_lane_drops_its_queued_jobs_unrun() {
    for by_end in [true, false] {
        let store = tenured();
        let read = shard_read(&store);
        let own = Target::of(read.value());
        let possible = PossiblyNamed::new((shard(), SESSION), layout(), Some(checkpoint()));
        let storage: Storage<TestPlatform> = storage(1);
        std::thread::scope(|scope| {
            let mut lane = Lane::start(
                &HostGate::qualified(),
                scope,
                locked_client(&store),
                &storage,
                cpus(),
            )
            .expect("a started lane");
            let release = hold(&mut lane);
            let before = store.requests().len();
            lane.submit(Job::Confirm {
                possible,
                read,
                own,
            })
            .unwrap();
            lane.submit(view()).unwrap();
            let Mode::Thread { waiting, .. } = &lane.mode else {
                panic!("a threaded lane");
            };
            let waiting = Arc::clone(waiting);
            let releaser = scope.spawn(move || {
                while !waiting.queue().ended {
                    std::thread::yield_now();
                }
                release.send(()).unwrap();
            });
            if by_end {
                drop(lane.end());
            } else {
                drop(lane);
            }
            assert_eq!(
                Arc::strong_count(&store.requests),
                1,
                "the close joined the thread and dropped its client"
            );
            releaser.join().unwrap();
            assert_eq!(
                store.requests().len(),
                before,
                "the queued Confirm and View ran no request"
            );
        });
    }
}

/// BOUNDED: `end` returns with [`DEPTH`] completions landed and none adopted, and while they wait a fifth kind and a
/// second View come back unrun.
#[test]
fn a_lane_ends_with_every_completion_unadopted() {
    let store = seeded();
    started(&store, |lane| {
        lane.submit(Job::Mark).unwrap();
        lane.submit(view()).unwrap();
        lane.submit(confirm(&store)).unwrap();
        let release = hold(lane);
        let before = store.requests().len();
        let fifth = lane.submit(open(&store)).expect_err("a fifth kind");
        assert!(matches!(*fifth, Job::Open { .. }));
        let second = lane.submit(view()).expect_err("a second View");
        assert!(matches!(*second, Job::View { .. }));
        assert_eq!(lane.outstanding(), DEPTH);
        assert_eq!(
            store.requests().len(),
            before + 1,
            "only the fixture's read ran"
        );
        release.send(()).unwrap();
    });
}

/// CONTAINED, BOUNDED: once the lane thread ended with jobs it never took, `poll` delivers the completion the thread
/// sent, then one `Panicked` for each job with none, and a later submit returns its job unrun.
#[test]
fn a_lane_whose_thread_ended_completes_the_rest_panicked_and_refuses() {
    let store = seeded();
    started(&store, |lane| {
        let release = hold(lane);
        lane.submit(Job::Mark).unwrap();
        lane.submit(view()).unwrap();
        let Mode::Thread { waiting, .. } = &lane.mode else {
            panic!("a threaded lane");
        };
        waiting.end();
        release.send(()).unwrap();
        assert!(matches!(lane.wait(), Some(Done::Held)));
        assert!(matches!(lane.wait(), Some(Done::Panicked)));
        assert!(matches!(lane.wait(), Some(Done::Panicked)));
        assert_eq!(lane.outstanding(), 0);
        assert!(lane.poll().is_none());
        let refused = lane.submit(Job::Mark).expect_err("an ended lane");
        assert!(matches!(*refused, Job::Mark));
        assert_eq!(lane.outstanding(), 0);
    });
}

/// BOUNDED: `poll` reports the lane thread gone only after the thread closed its queue, so a later `submit` returns
/// its job unrun. The failed send makes the thread leave its loop. While the test holds the queue lock, the thread
/// cannot close the queue, so `poll` keeps returning `None`.
#[test]
fn a_poll_reports_the_thread_gone_only_once_its_queue_closed() {
    let store = seeded();
    started(&store, |lane| {
        let release = hold(lane);
        let Mode::Thread { waiting, done, .. } = &mut lane.mode else {
            panic!("a threaded lane");
        };
        let waiting = Arc::clone(waiting);
        // The lane thread's sender has no receiver from here on, and the lane's receiver no sender.
        *done = mpsc::sync_channel(DEPTH).1;
        let queue = waiting.queue();
        release.send(()).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(50);
        let mut gone = None;
        while gone.is_none() && std::time::Instant::now() < deadline {
            gone = lane.poll();
            std::thread::yield_now();
        }
        assert!(
            gone.is_none(),
            "a poll reported the thread gone while its queue admits a job: {gone:?}"
        );
        assert!(!queue.ended);
        drop(queue);
        assert!(matches!(lane.wait(), Some(Done::Panicked)));
        let refused = lane.submit(Job::Mark).expect_err("an ended lane");
        assert!(matches!(*refused, Job::Mark));
        assert_eq!(lane.outstanding(), 0);
    });
}

/// A wake of the lane thread after the queue lock was poisoned leaves the thread waiting, and it runs the next job.
#[test]
fn a_poisoned_wake_keeps_the_lane_thread_waiting() {
    let store = seeded();
    started(&store, |lane| {
        let Mode::Thread { waiting, .. } = &lane.mode else {
            panic!("a threaded lane");
        };
        let waiting = Arc::clone(waiting);
        let poisoner = Arc::clone(&waiting);
        let poisoned = std::thread::spawn(move || {
            let _queue = poisoner.queue.lock();
            panic!("a panic while holding the queue lock");
        });
        assert!(poisoned.join().is_err());
        assert!(waiting.queue.is_poisoned());
        waiting.ready.notify_all();
        std::thread::sleep(std::time::Duration::from_millis(50));
        lane.submit(view()).unwrap();
        assert!(matches!(lane.wait(), Some(Done::View { shard: Ok(_), .. })));
    });
}

/// The lane thread copies the client's tally and alarm after each job and hands the copy back with the completion.
/// Until `poll` adopts that completion, `monitors` reads `None` and `tally` the client's tally at the lane's start,
/// though the thread has sent it; after the adoption both read the copy, which counts the job's unavailable volume
/// read and equals the client's own tally and alarm when `end` returns the client.
#[test]
fn a_threaded_lane_reads_the_monitors_its_adopted_completion_carried() {
    let shared = crate::storage::store_tests::seeded();
    shared.schedule(Arm::Pass);
    shared.schedule(Arm::Unavailable);
    let store = Locked::of(&shared);
    let mut client = locked_client(&store);
    assert!(client.read::<ShardRecord>(Key::Shard(shard())).is_ok());
    let started = client.outcomes();
    let storage: Storage<TestPlatform> = storage(1);
    std::thread::scope(|scope| {
        let mut lane = Lane::start(&HostGate::qualified(), scope, client, &storage, cpus())
            .expect("a started lane");
        lane.submit(view()).unwrap();
        let Mode::Thread { waiting, .. } = &lane.mode else {
            panic!("a threaded lane");
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        while waiting.landed.load(Ordering::Acquire) == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "the View never landed"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert_eq!(lane.monitors(), None, "the sent copy is not yet adopted");
        assert_eq!(lane.tally(), started);
        assert!(matches!(
            lane.poll(),
            Some(Done::View {
                volume: Err(StoreError::Unavailable),
                shard: Ok(_),
                ..
            })
        ));
        let monitors = lane.monitors().expect("the adopted copy");
        assert_eq!(
            monitors.outcomes.total(Tallied::Unavailable),
            started.total(Tallied::Unavailable) + 1,
            "the copy counts the View's unavailable read"
        );
        assert_eq!(lane.tally(), monitors.outcomes);
        let client = lane.end();
        assert_eq!(
            monitors,
            Monitors {
                outcomes: client.outcomes(),
                alarm: client.alarm(),
            },
            "the copy is the client's state after the job"
        );
    });
}

/// An inline lane issues a job's requests at its submit and lands each held completion, oldest first, only at its
/// release.
#[test]
fn an_inline_lane_runs_at_submit_and_holds_the_completion() {
    let store = seeded();
    let storage: Storage<TestPlatform> = storage(1);
    let mut lane = Lane::inline(locked_client(&store), &storage);
    lane.inline_mut().hold();
    let before = store.threads().len();
    lane.submit(view()).unwrap();
    assert_eq!(
        store.threads().len(),
        before + 2,
        "both reads ran at the submit"
    );
    lane.submit(Job::Mark).unwrap();
    lane.submit(confirm(&store)).unwrap();
    let issued = store.threads().len();
    for _ in 0..1_000 {
        assert!(lane.poll().is_none());
    }
    assert!(
        lane.submit(view()).is_err(),
        "the held View stays outstanding"
    );
    assert_eq!(lane.inline_mut().held(), 3);
    assert!(lane.inline_mut().release());
    assert!(
        lane.submit(view()).is_err(),
        "a released View stays outstanding until its adoption"
    );
    assert!(matches!(lane.poll(), Some(Done::View { .. })));
    assert!(lane.poll().is_none(), "one release lands one completion");
    assert!(lane.inline_mut().release());
    assert!(lane.inline_mut().release());
    assert!(matches!(lane.poll(), Some(Done::Marked)));
    assert!(matches!(lane.poll(), Some(Done::Confirm { .. })));
    assert!(!lane.inline_mut().release());
    assert!(lane.poll().is_none());
    assert_eq!(lane.outstanding(), 0);
    assert_eq!(store.threads().len(), issued, "releases issue no request");
    drop(lane.end());
}

#[test]
fn start_under_inline_recovery_runs_jobs_on_the_submitting_thread() {
    let store = seeded();
    let name = std::thread::current().name().map(str::to_owned);
    let before = store.threads().len();
    let was = crate::storage::INLINE_RECOVERY.with(|inline| inline.replace(true));
    started(&store, |lane| {
        lane.submit(view()).unwrap();
        assert!(matches!(lane.poll(), Some(Done::View { .. })));
    });
    crate::storage::INLINE_RECOVERY.with(|inline| inline.set(was));
    let threads = store.threads();
    assert!(threads.len() > before);
    assert!(threads[before..].iter().all(|thread| *thread == name));
}

#[test]
fn a_drop_job_replaces_the_volume_record_on_the_lane_thread_after_a_queued_view() {
    use crate::failover::records::EventKind;
    use crate::failover::takeover::tests::{b_host, b_pair, c_host, c_pair, with_c_and_b};
    use crate::storage::store::Refusal;
    let shared = Shared::new();
    let mut ended = with_c_and_b();
    for host in [c_host(), b_host()] {
        let at = ended.live(host).unwrap();
        let entry = (ended.events.iter_mut())
            .find(|event| event.seq == at)
            .unwrap();
        entry.kind = EventKind::Ended;
    }
    let read = client(&shared)
        .create(Key::Volume(volume_id()), ended)
        .unwrap();
    assert!(
        read.value().fence < SESSION,
        "a session above the fence tells a kept fence from a raised one"
    );
    let mut expected = read.value().clone();
    expected.pairs.retain(|recorded| recorded.pair != c_pair());
    let store = Locked::of(&shared);
    started(&store, |lane| {
        let release = hold(lane);
        lane.submit(Job::Drop {
            read: read.clone(),
            pairs: vec![c_pair()],
            session: SESSION,
        })
        .unwrap();
        lane.submit(view()).unwrap();
        assert!(
            lane.submit(Job::Drop {
                read: read.clone(),
                pairs: vec![c_pair()],
                session: SESSION,
            })
            .is_err(),
            "one drop job at a time"
        );
        release.send(()).unwrap();
        let order: Vec<_> = (0..3).map(|_| lane.wait().expect("a completion")).collect();
        assert_eq!(
            order.iter().map(named).collect::<Vec<_>>(),
            ["held", "view", "drop"]
        );
        let Done::Drop {
            dropped: Some(Ok(dropped)),
        } = &order[2]
        else {
            panic!("the drop committed: {:?}", order[2]);
        };
        assert_eq!(
            dropped.value(),
            &expected,
            "C's pair alone leaves, B's ended pair, the live pair, the events and the fence stay"
        );
        assert!(
            dropped
                .value()
                .pairs
                .iter()
                .any(|recorded| recorded.pair == b_pair())
        );
        lane.submit(Job::Drop {
            read: read.clone(),
            pairs: vec![c_pair()],
            session: SESSION,
        })
        .unwrap();
        assert!(
            matches!(
                lane.wait(),
                Some(Done::Drop {
                    dropped: Some(Err(StoreError::Refused(Refusal::Condition)))
                })
            ),
            "a replace over the old read loses its version condition"
        );
        lane.submit(Job::Drop {
            read: dropped.clone(),
            pairs: vec![c_pair()],
            session: SESSION,
        })
        .unwrap();
        assert!(
            matches!(lane.wait(), Some(Done::Drop { dropped: None })),
            "a pair the record no longer holds issues no request"
        );
    });
    let writes: Vec<_> = (store.requests().into_iter())
        .filter(|request| request.write)
        .collect();
    assert_eq!(writes.len(), 2);
    assert!(
        store
            .threads()
            .iter()
            .all(|thread| thread.as_deref() == Some("store-lane"))
    );
}

#[test]
fn a_drop_queued_before_a_takeover_runs_after_it_and_leaves_the_shard_recoverable() {
    use crate::failover::records::{EventKind, Record, VolumeRecord};
    use crate::failover::restart::tests::{Stored, shard_now, store as records_of};
    use crate::failover::takeover::tests::{
        Card, a_holds_c_registered, b_host, b_pair, c_host, c_pair, d_host, designate_fresh_host,
        fence_page_zero, shard_record, stored_c, taken, takeover_of, with_c_and_b,
    };
    use crate::storage::store::{Outcome, Store, Write};
    let shared = records_of(shard_record(), with_c_and_b());
    fence_page_zero(&shared);
    // The reconciler ends B's attach, which keeps B's pair recorded.
    let key = Key::Volume(volume_id());
    let item = shared.0.borrow().current(&key).cloned().unwrap();
    let mut ended = VolumeRecord::decode(&item.value).unwrap();
    let at = ended.live(b_host()).unwrap();
    let entry = ended
        .events
        .iter_mut()
        .find(|event| event.seq == at)
        .unwrap();
    entry.kind = EventKind::Ended;
    let write = Write::Exact {
        expect: item.version,
        value: ended.encode(),
    };
    assert!(matches!(
        Store::write(&mut shared.clone(), &key, &write),
        Outcome::Committed(_)
    ));
    // A's poll read the record, and A queued the drop of B's ended pair under A's session.
    let viewed = client(&shared).read::<VolumeRecord>(key).unwrap();
    let session = crate::net::ownership::session_of(shard_record().generation.get() as u32, 8);
    let queued = Job::Drop {
        read: viewed,
        pairs: vec![b_pair()],
        session,
    };
    // C takes the shard over before the lane runs the job; the takeover writes the shard record only.
    let reservation = a_holds_c_registered();
    let mut card = Card::new(c_pair(), &reservation);
    takeover_of(&shared, c_host())
        .run(&mut client(&shared), &stored_c(), &mut card)
        .expect("C's takeover");
    assert_eq!(shard_now(&shared), taken(&shard_record(), c_host()));
    let storage: Storage<TestPlatform> = storage(1);
    let mut lane = Lane::inline(client(&shared), &storage);
    lane.submit(queued).unwrap();
    let Some(Done::Drop {
        dropped: Some(Ok(dropped)),
    }) = lane.poll()
    else {
        panic!("the deposed owner's drop commits over an unchanged volume record");
    };
    drop(lane.end());
    // The drop removed B's ended pair alone: C's pair, which C's tenure judges as its own, and A's pair, which C
    // superseded, stay recorded, and the fence keeps C's lineage.
    let after = dropped.value();
    assert_eq!(after.enrolled(c_host()), Some(c_pair()));
    assert_eq!(after.pinned(b_host(), at), None);
    assert!(
        after
            .recorded()
            .any(|pair| *pair == crate::failover::restart::tests::own())
    );
    assert_eq!(after.events, ended.events, "the entries are unchanged");
    assert!(after.fence >= ended.fence);
    // The shard stays recoverable: after A and C are lost, a fresh host takes it over from C's tenure.
    let d_record = designate_fresh_host(&shared);
    let mut d_card = Card::new(d_record.pair(), &reservation);
    takeover_of(&shared, d_host())
        .run(&mut client(&shared), &Stored(Ok(d_record)), &mut d_card)
        .expect("D's takeover after the race");
    assert_eq!(shard_now(&shared).owner, d_host());
}

/// TRANSFER-OFF-POLL on the lane thread: a [`Job::Transfer`] reads the volume record after the shard read the job
/// carries, then writes the shard record, each request on the lane thread; its one completion returns the standby
/// gate with the committed record naming the target owner at the next `E`.
#[test]
fn a_transfer_runs_on_the_lane_thread_and_returns_its_gate() {
    use crate::failover::reconcile::StandbyGate;
    use crate::failover::takeover::tests::{c_host, shard_record, with_c};
    use crate::storage::Session;
    use crate::storage::store::Outgoing;
    let shared = crate::failover::restart::tests::store(shard_record(), with_c());
    let mut owner = client(&shared);
    let read = owner.read::<ShardRecord>(Key::Shard(shard())).unwrap();
    let session = Session::activate(owner.bump(&read).unwrap()).unwrap();
    let read = owner.read::<ShardRecord>(Key::Shard(shard())).unwrap();
    let store = Locked::of(&shared);
    let before = store.requests().len();
    started(&store, |lane| {
        lane.submit(Job::Transfer {
            gate: StandbyGate::qualified(),
            read: read.clone(),
            outgoing: Outgoing::of(&session),
            target: c_host(),
        })
        .unwrap();
        let Some(Done::Transfer {
            gate: _,
            transferred: Ok(transferred),
        }) = lane.wait()
        else {
            panic!("a committed transfer");
        };
        let committed = transferred.committed().value();
        assert_eq!(
            (committed.owner, committed.standby, committed.attempts),
            (c_host(), None, read.value().attempts + 1)
        );
        assert!(lane.poll().is_none(), "one completion");
    });
    let issued = store.requests()[before..].to_vec();
    let keys: Vec<_> = issued
        .iter()
        .map(|request| (request.write, request.key))
        .collect();
    assert_eq!(
        keys,
        [
            (false, Key::Volume(volume_id())),
            (true, Key::Shard(shard()))
        ]
    );
    assert!(
        (issued.iter()).all(|request| request.thread.as_deref() == Some("store-lane")),
        "{issued:?}"
    );
}

/// One [`Job::Transfer`] to C on a threaded lane over `shared` after an acknowledged bump, with `arm` scheduled for
/// the lane's first request: the completion's result and the `(write, key)` of each request the lane issued.
fn transfer_on_lane(
    shared: &Shared,
    arm: Option<Arm>,
) -> (
    Result<crate::storage::store::Transferred, StoreError>,
    Vec<(bool, Key)>,
) {
    use crate::failover::reconcile::StandbyGate;
    use crate::failover::takeover::tests::c_host;
    use crate::storage::Session;
    use crate::storage::store::Outgoing;
    let mut owner = client(shared);
    let read = owner.read::<ShardRecord>(Key::Shard(shard())).unwrap();
    let session = Session::activate(owner.bump(&read).unwrap()).unwrap();
    let read = owner.read::<ShardRecord>(Key::Shard(shard())).unwrap();
    let store = Locked::of(shared);
    if let Some(arm) = arm {
        store.store.lock().unwrap().schedule(arm);
    }
    let transferred = started(&store, |lane| {
        lane.submit(Job::Transfer {
            gate: StandbyGate::qualified(),
            read,
            outgoing: Outgoing::of(&session),
            target: c_host(),
        })
        .unwrap();
        let Some(Done::Transfer { transferred, .. }) = lane.wait() else {
            panic!("a transfer completion");
        };
        transferred
    });
    let keys = (store.requests().into_iter())
        .map(|request| (request.write, request.key))
        .collect();
    (transferred, keys)
}

/// ENDED-GRANTS-NOTHING on the lane thread: a [`Job::Transfer`] whose volume read fails returns that read's error,
/// and one whose target has a live attach on the shard's active volume with no pair pinned to it refuses
/// `Stale(Target)` while another volume of the same store enrolls the target. Each issues one request, the read of
/// the certified record's active volume, and issues no shard write.
#[test]
fn a_transfer_whose_enrollment_read_fails_or_finds_no_pair_on_the_active_volume_writes_nothing() {
    use crate::failover::records::VolumeId;
    use crate::failover::retire::Stale;
    use crate::failover::takeover::tests::{c_host, shard_record, with_c};
    let failing = crate::failover::restart::tests::store(shard_record(), with_c());
    let mut unpaired = with_c();
    unpaired.pairs.retain(|recorded| recorded.host != c_host());
    assert!(unpaired.live(c_host()).is_some() && unpaired.enrolled(c_host()).is_none());
    let elsewhere = crate::failover::restart::tests::store(shard_record(), unpaired);
    let mut other = with_c();
    other.volume = VolumeId::new("vol-0b").unwrap();
    assert_ne!(other.volume, volume_id());
    client(&elsewhere)
        .create(Key::Volume(other.volume), other)
        .unwrap();
    let rows = [
        (failing, Some(Arm::Unavailable), StoreError::Unavailable),
        (elsewhere, None, StoreError::Stale(Stale::Target)),
    ];
    for (shared, arm, refused) in rows {
        let (transferred, keys) = transfer_on_lane(&shared, arm);
        assert_eq!(transferred.err(), Some(refused), "{refused:?}");
        assert_eq!(
            keys,
            [(false, Key::Volume(volume_id()))],
            "{refused:?}: one volume read and no shard write"
        );
    }
}
