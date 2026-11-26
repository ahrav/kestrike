use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Condvar, Mutex};

use super::Duties;
use super::tests::{on_the_lane_thread, periods, records};
use crate::failover::attachments::{ControlPlane, Unlisted};
use crate::failover::evidence::Pair;
use crate::failover::fresh::tests::holder;
use crate::failover::reconcile::{Reconciler, StandbyGate};
use crate::failover::records::{
    EventKind, Record, ShardRecord, VolumeId, VolumeRecord, attachment_key,
};
use crate::failover::restart::tests::volume_id;
use crate::failover::takeover::tests::{c_host, c_pair, designate, instance_of, volume_now};
use crate::host::lane::tests::{Locked, SharedLog, bounds};
use crate::host::lane::{Lane, Plane};
use crate::host::recover_tests::{fresh_own, own_holds};
use crate::host::serve::loop_tests::{Rounds, Stage, staged, staged_over_on};
use crate::host::serve::tests::warm_volume_certified;
use crate::host::{Exit, HostGate};
use crate::net::{Outcome as Fetched, RequestId};
use crate::storage::gate_fixture::Control;
use crate::storage::store::sim::{Arm, MemLog, Recorder, Shared};
use crate::storage::store::{Client, Item, Key, Outcome, Store, Unavailable, Write};
use crate::storage::store_tests::{client as store_client, shard};
use crate::storage::test_platform::TestPlatform;
use crate::storage::warm_sim::storage;
use crate::storage::{CpuSet, ReservationCommand};

struct Attached;

impl ControlPlane for Attached {
    fn attachments(&mut self, volume: &VolumeId) -> Result<Vec<String>, Unlisted> {
        assert_eq!(*volume, volume_id());
        Ok([holder().instance, instance_of(c_host())]
            .iter()
            .map(|instance| instance.as_str().to_owned())
            .collect())
    }
}

/// C's pair under the key of its attach entry, entry 1 of the stage's volume record (KEY-PER-ATTACH).
fn keyed_c() -> Pair {
    Pair {
        key: attachment_key(1).expect("entry 1 has a key"),
        ..c_pair()
    }
}

/// [`staged`] over a volume record that enrolls A and C each under the key of its own attach entry, with the entry
/// bound to its host's instance, and over a reservation table that lists those two pairs. `end_attach` ends a live
/// attach only when it binds an instance and its pair stands under the entry's own key or a spent key. The takeover
/// fixture's record gives neither: its entries bind no instance, A's pair holds entry 1's key and C's an epoch-4
/// key.
fn staged_keyed<R>(body: impl for<'w> FnOnce(Stage<'w>) -> R) -> R {
    let (store, media) = warm_volume_certified(1);
    let key = Key::Volume(volume_id());
    let item = store.0.borrow().current(&key).cloned().unwrap();
    let mut record = VolumeRecord::decode(&item.value).unwrap();
    let hosts = [
        (holder().host, fresh_own(), holder().instance),
        (c_host(), keyed_c(), instance_of(c_host())),
    ];
    for (host, pair, instance) in hosts {
        let seq = record.live(host).expect("a live attach");
        assert_eq!(attachment_key(seq), Some(pair.key));
        let entry = record.events.iter_mut().find(|event| event.seq == seq);
        entry.expect("the live entry").instance = Some(instance);
        let recorded = (record.pairs.iter_mut()).find(|recorded| recorded.host == host);
        recorded.expect("the host's recorded pair").pair = pair;
    }
    let raw = Write::Exact {
        expect: item.version,
        value: record.encode(),
    };
    let written = store.clone().write(&key, &raw);
    assert!(matches!(written, Outcome::Committed(_)), "{written:?}");
    let registry = own_holds();
    for entry in &mut registry.borrow_mut().entries {
        entry.pair = match entry.pair == c_pair() {
            true => keyed_c(),
            false => fresh_own(),
        };
    }
    staged_over_on((store, media), registry, || storage(1), body)
}

/// The reconciler's end of C's attach on a [`staged_keyed`] stage, once the shard record names no standby.
fn end_c(store: &Shared) {
    designate(store, None);
    let seq = volume_now(store).live(c_host()).expect("C's live attach");
    Reconciler::new(store_client(store))
        .end_attach(
            &StandbyGate::qualified(),
            shard(),
            volume_id(),
            c_host(),
            seq,
        )
        .unwrap();
}

fn duties_on<'w, S: Store>(
    stage: &Stage<'w>,
    client: Client<S, MemLog>,
) -> Duties<'w, S, MemLog, TestPlatform> {
    Duties::new(
        (&HostGate::qualified(), StandbyGate::qualified()),
        Lane::inline(client, stage.storage),
        records(),
        Some(Plane(Box::new(Attached))),
        bounds(),
        periods(),
    )
}

fn preempts(registry: &Control) -> usize {
    (registry.borrow().log.iter())
        .filter(|command| matches!(command, ReservationCommand::PreemptEnded(_)))
        .count()
}

fn c_registered(registry: &Control) -> bool {
    (registry.borrow().entries.iter()).any(|entry| entry.pair.key == keyed_c().key)
}

/// Every store request of a run in issue order as `(write, key)`. A recorder's requests move into the list at each
/// read, since [`Recorder::take`] empties the recorder, so the list holds every request of the run.
#[derive(Clone, Default)]
struct Calls {
    list: Rc<RefCell<Vec<(bool, Key)>>>,
    recorder: Option<Recorder>,
}

impl Calls {
    fn borrow(&self) -> std::cell::Ref<'_, Vec<(bool, Key)>> {
        if let Some(recorder) = &self.recorder {
            (self.list.borrow_mut()).extend(crate::host::wait_tests::keyed(recorder));
        }
        self.list.borrow()
    }

    fn borrow_mut(&self) -> std::cell::RefMut<'_, Vec<(bool, Key)>> {
        self.list.borrow_mut()
    }
}

fn volume_writes(calls: &Calls) -> usize {
    (calls.borrow().iter())
        .filter(|&&(write, key)| write && key == Key::Volume(volume_id()))
        .count()
}

struct Run {
    exit: Exit,
    preempts: usize,
    writes: usize,
    registered_at_write: Option<bool>,
    /// The reservation log's length at the turn of the first volume write.
    log_at_write: Option<usize>,
    turns_at_write: Vec<u64>,
}

/// Serves until `settle` turns after the store first shows C's pair dropped.
fn serve_reclaim<S: Store>(
    stage: &mut Stage<'_>,
    duties: &mut Duties<'_, S, MemLog, TestPlatform>,
    calls: &Calls,
    settle: u64,
) -> Run {
    let (store, registry) = (stage.store.clone(), stage.registry.clone());
    let registered_at_write = Cell::new(None);
    let log_at_write = Cell::new(None);
    let turns_at_write = RefCell::new(Vec::new());
    let turn = Cell::new(0);
    let since = Cell::new(None::<u64>);
    let (served, _) = stage.serve_until(
        |_, at, stop| {
            turn.set(at);
            if dropped(&store) {
                let from = since.get().unwrap_or(at);
                since.set(Some(from));
                if at >= from + settle {
                    stop.store(true, Ordering::Release);
                }
            }
        },
        |owner, now| {
            let before = volume_writes(calls);
            let registered = c_registered(&registry);
            let logged = registry.borrow().log.len();
            let exit = duties.turn(owner, now);
            if volume_writes(calls) > before {
                if registered_at_write.get().is_none() {
                    registered_at_write.set(Some(registered));
                    log_at_write.set(Some(logged));
                }
                turns_at_write.borrow_mut().push(turn.get());
            }
            exit
        },
    );
    Run {
        exit: served.exit,
        preempts: preempts(&stage.registry),
        writes: volume_writes(calls),
        registered_at_write: registered_at_write.get(),
        log_at_write: log_at_write.get(),
        turns_at_write: turns_at_write.into_inner(),
    }
}

fn traced(stage: &Stage<'_>) -> (Recorder, Calls) {
    let recorder = Recorder::new(&stage.store);
    let calls = Calls {
        recorder: Some(recorder.clone()),
        ..Calls::default()
    };
    (recorder, calls)
}

fn dropped(store: &Shared) -> bool {
    volume_now(store)
        .pairs
        .iter()
        .all(|recorded| recorded.pair != keyed_c())
}

/// The serving tenure's session, which the drop job carries.
fn session(stage: &Stage<'_>) -> u64 {
    stage
        .owner
        .as_ref()
        .expect("a stage holds its owner")
        .tenure()
        .get()
}

#[test]
fn an_ended_successors_registered_pair_is_preempted_then_dropped_by_one_lane_job() {
    staged_keyed(|mut stage| {
        end_c(&stage.store);
        let fence = volume_now(&stage.store).fence;
        assert!(
            fence < session(&stage),
            "a session above the fence tells a kept fence from a raised one"
        );
        let (traced, calls) = traced(&stage);
        let mut duties = duties_on(&stage, Client::open(traced, MemLog::default()).unwrap());
        let run = serve_reclaim(&mut stage, &mut duties, &calls, 200);
        assert_eq!(run.exit, Exit::Stopped);
        assert_eq!(run.preempts, 1, "one preempt");
        assert_eq!(run.writes, 1, "one drop job");
        assert_eq!(
            run.registered_at_write,
            Some(false),
            "C's key was unregistered when the drop was written"
        );
        let log = stage.registry.borrow().log.clone();
        let preempt = (log.iter())
            .position(|command| matches!(command, ReservationCommand::PreemptEnded(_)))
            .expect("the preempt");
        let written = run.log_at_write.expect("the drop's write");
        assert!(
            log[preempt + 1..written]
                .iter()
                .any(|command| command.is_report()),
            "a Report follows the preempt before the drop is written"
        );
        let record = volume_now(&stage.store);
        assert!(dropped(&stage.store), "C's pair left the record");
        let c = record.latest(c_host()).unwrap().1;
        assert_eq!(c.kind, EventKind::Ended, "the entry stays ended");
        assert_eq!(record.fence, fence, "the drop keeps the fence it read");
        assert!(!c_registered(&stage.registry));
    });
}

#[test]
fn an_ended_standby_that_never_registered_drops_with_no_preempt() {
    staged_keyed(|mut stage| {
        end_c(&stage.store);
        stage
            .registry
            .borrow_mut()
            .entries
            .retain(|entry| entry.pair != keyed_c());
        let (traced, calls) = traced(&stage);
        let mut duties = duties_on(&stage, Client::open(traced, MemLog::default()).unwrap());
        let run = serve_reclaim(&mut stage, &mut duties, &calls, 200);
        assert_eq!(run.exit, Exit::Stopped);
        assert_eq!((run.preempts, run.writes), (0, 1));
        assert!(dropped(&stage.store));
    });
}

#[test]
fn polls_that_do_not_continue_preempt_and_drop_nothing() {
    for registered in [true, false] {
        staged_keyed(|mut stage| {
            end_c(&stage.store);
            if !registered {
                stage
                    .registry
                    .borrow_mut()
                    .entries
                    .retain(|entry| entry.pair != keyed_c());
            }
            let (traced, calls) = traced(&stage);
            let client = Client::open(traced, MemLog::default()).unwrap();
            let mut duties = Duties::new(
                (&HostGate::qualified(), StandbyGate::qualified()),
                Lane::inline(client, stage.storage),
                records(),
                None,
                bounds(),
                periods(),
            );
            let (served, _) = stage.serve_until(
                |_, at, stop| {
                    if at >= 400 {
                        stop.store(true, Ordering::Release);
                    }
                },
                |owner, now| duties.turn(owner, now),
            );
            assert_eq!(served.exit, Exit::Stopped);
            assert!(
                duties.unobserved() >= 4,
                "no listing: every poll is unobserved"
            );
            assert_eq!(duties.open(), super::Open::Opened, "the tenure serves");
            assert_eq!(
                (preempts(&stage.registry), volume_writes(&calls)),
                (0, 0),
                "registered: {registered}"
            );
            assert!(!dropped(&stage.store));
        });
    }
}

#[derive(Clone, Copy, Debug)]
enum Race {
    Unknown,
    Committed,
    Rewrite,
}

#[derive(Clone)]
struct Racing {
    inner: Shared,
    calls: Calls,
    race: Rc<Cell<Option<Race>>>,
}

impl Store for Racing {
    fn read(&mut self, key: &Key) -> Result<Option<Item>, Unavailable> {
        self.calls.borrow_mut().push((false, *key));
        self.inner.read(key)
    }

    fn write(&mut self, key: &Key, write: &Write) -> Outcome {
        if let Key::Volume(_) = key
            && let Some(race) = self.race.take()
        {
            match race {
                Race::Unknown => self.inner.schedule(Arm::Timeout { commit: false }),
                Race::Committed => self.inner.schedule(Arm::Timeout { commit: true }),
                Race::Rewrite => {
                    let mut reconciler = store_client(&self.inner);
                    let read = reconciler.read::<VolumeRecord>(*key).unwrap();
                    let same = read.value().clone();
                    let raw = Write::Exact {
                        expect: read.version(),
                        value: same.encode(),
                    };
                    assert!(matches!(self.inner.write(key, &raw), Outcome::Committed(_)));
                }
            }
        }
        self.calls.borrow_mut().push((true, *key));
        self.inner.write(key, write)
    }

    fn namespace(&self) -> crate::failover::records::Namespace {
        self.inner.namespace()
    }
}

#[test]
fn a_drop_of_unknown_outcome_or_lost_condition_waits_for_the_next_poll() {
    for race in [Race::Unknown, Race::Committed, Race::Rewrite] {
        staged_keyed(|mut stage| {
            end_c(&stage.store);
            stage
                .registry
                .borrow_mut()
                .entries
                .retain(|entry| entry.pair != keyed_c());
            let calls = Calls::default();
            let racing = Racing {
                inner: stage.store.clone(),
                calls: calls.clone(),
                race: Rc::new(Cell::new(Some(race))),
            };
            let mut duties = duties_on(&stage, Client::open(racing, MemLog::default()).unwrap());
            let run = serve_reclaim(&mut stage, &mut duties, &calls, 100);
            assert_eq!(run.exit, Exit::Stopped, "{race:?}");
            assert!(dropped(&stage.store), "{race:?}");
            assert_eq!(run.preempts, 0, "{race:?}");
            if let Race::Committed = race {
                assert_eq!(
                    run.writes, 1,
                    "a later poll reads the pair gone and writes nothing"
                );
                return;
            }
            assert_eq!(
                run.writes, 2,
                "{race:?}: the first drop is not retried before the next poll"
            );
            let [first, second] = run.turns_at_write[..] else {
                panic!("two drop writes: {:?}", run.turns_at_write);
            };
            assert!(second > first, "the second drop goes out on a later poll");
            let volume = Key::Volume(volume_id());
            let trace = calls.borrow();
            let writes: Vec<_> = (trace.iter().enumerate())
                .filter(|(_, call)| **call == (true, volume))
                .map(|(at, _)| at)
                .collect();
            assert!(
                trace[writes[0] + 1..writes[1]].contains(&(false, volume)),
                "{race:?}: a View reads the volume record between the two drops"
            );
        });
    }
}

#[derive(Clone)]
struct Gated {
    inner: Locked,
    gate: Arc<(Mutex<(bool, bool)>, Condvar)>,
}

impl Gated {
    fn release(&self) {
        let (held, ready) = &*self.gate;
        held.lock().unwrap().1 = true;
        ready.notify_all();
    }

    fn holding(&self) -> bool {
        self.gate.0.lock().unwrap().0
    }
}

/// Releases the held write when dropped, so an unwind releases it before the lane thread is joined.
struct Opens<'g>(&'g Gated);

impl Drop for Opens<'_> {
    fn drop(&mut self) {
        self.0.release();
    }
}

impl Store for Gated {
    fn read(&mut self, key: &Key) -> Result<Option<Item>, Unavailable> {
        self.inner.read(key)
    }

    fn write(&mut self, key: &Key, write: &Write) -> Outcome {
        if let Key::Volume(_) = key {
            let (held, ready) = &*self.gate;
            let mut state = held.lock().unwrap();
            state.0 = true;
            let timeout = std::time::Duration::from_secs(120);
            let (state, waited) = ready
                .wait_timeout_while(state, timeout, |state| !state.1)
                .unwrap();
            assert!(
                state.1 && !waited.timed_out(),
                "the held drop write was released"
            );
        }
        self.inner.write(key, write)
    }

    fn namespace(&self) -> crate::failover::records::Namespace {
        self.inner.namespace()
    }
}

fn gets_pump(rounds: &Rounds<'_>, pending: &mut Option<(RequestId, Vec<u8>)>, done: &mut usize) {
    if rounds.client.borrow().state() != crate::net::SessionState::Active {
        return;
    }
    if pending.is_none() {
        *pending = Some((rounds.get(1 + (*done % 4) as u8), Vec::new()));
    }
    let Some((id, bytes)) = pending.as_mut() else {
        return;
    };
    if let Some(outcome) = rounds.fetched(*id, bytes) {
        assert_eq!(outcome, Fetched::Complete);
        *done += 1;
        *pending = None;
    }
}

fn held_drop(threaded: bool) -> Locked {
    staged_keyed(|mut stage| {
        end_c(&stage.store);
        stage
            .registry
            .borrow_mut()
            .entries
            .retain(|entry| entry.pair != keyed_c());
        let locked = Locked::of(&stage.store);
        let gated = Gated {
            inner: locked.clone(),
            gate: Arc::default(),
        };
        let storage = stage.storage;
        let client = Client::open(gated.clone(), SharedLog::default()).unwrap();
        std::thread::scope(|scope| {
            let lane = match threaded {
                true => Lane::start(
                    &HostGate::qualified(),
                    scope,
                    client,
                    storage,
                    CpuSet::current().unwrap(),
                )
                .unwrap(),
                false => {
                    gated.release();
                    Lane::inline(client, storage)
                }
            };
            let mut duties = Duties::new(
                (&HostGate::qualified(), StandbyGate::qualified()),
                lane,
                records(),
                Some(Plane(Box::new(Attached))),
                bounds(),
                periods(),
            );
            let opens = Opens(&gated);
            let held_from = Cell::new(None::<(u64, usize)>);
            let at_release = Cell::new(None::<usize>);
            let (mut pending, mut done) = (None, 0);
            let gets = Cell::new(0);
            let (served, _) = stage.serve_until(
                |rounds, turn, stop| {
                    gets_pump(rounds, &mut pending, &mut done);
                    gets.set(done);
                    let drop_written = (locked.requests().iter())
                        .any(|request| request.write && request.key == Key::Volume(volume_id()));
                    if !threaded && drop_written {
                        stop.store(true, Ordering::Release);
                    }
                    if let Some((from, _)) = held_from.get() {
                        if turn >= from + 1_000 && at_release.get().is_none() {
                            at_release.set(Some(done));
                            gated.release();
                        }
                        if turn >= from + 1_200 {
                            stop.store(true, Ordering::Release);
                        }
                    }
                },
                |owner, now| {
                    // The lane thread runs a listing well inside its deadline of ten owner turns.
                    if threaded && duties.plane.is_none() {
                        std::thread::sleep(std::time::Duration::from_micros(200));
                    }
                    let exit = duties.turn(owner, now);
                    if threaded && held_from.get().is_none() && gated.holding() {
                        held_from.set(Some((
                            now / crate::host::serve::loop_tests::ROUND_US,
                            gets.get(),
                        )));
                    }
                    exit
                },
            );
            drop(opens);
            assert_eq!(served.exit, Exit::Stopped);
            if threaded {
                let (_, before) = held_from.get().expect("the drop's write was held");
                let during = at_release.get().expect("the hold ended by its release");
                assert!(
                    during >= before + 10,
                    "GETs were served while the drop was held"
                );
            }
            drop(duties.end());
        });
        let writes = (locked.requests().into_iter())
            .filter(|request| request.write && request.key == Key::Volume(volume_id()))
            .count();
        assert_eq!(writes, 1, "one drop job");
        locked
    })
}

#[test]
fn a_held_drop_keeps_every_store_request_on_the_lane_thread_while_gets_are_served() {
    let store = held_drop(true);
    on_the_lane_thread(&store).unwrap();
}

#[test]
#[should_panic(expected = "store requests off the lane thread")]
fn negative_control_a_drop_written_from_the_owner_thread_fails_the_lane_thread_check() {
    let store = held_drop(false);
    on_the_lane_thread(&store).expect("store requests off the lane thread");
}

thread_local! {
    /// The planted defect of the end-race control: [`super::droppable`] returns every pair it is given.
    pub(super) static UNGUARDED: Cell<bool> = const { Cell::new(false) };
}

pub(super) fn unguarded() -> bool {
    UNGUARDED.with(Cell::get)
}

/// Sets [`UNGUARDED`] for its lifetime.
struct Unguarded;

impl Unguarded {
    fn set() -> Self {
        UNGUARDED.with(|planted| planted.set(true));
        Self
    }
}

impl Drop for Unguarded {
    fn drop(&mut self) {
        UNGUARDED.with(|planted| planted.set(false));
    }
}

/// The reconciler's end of C's attach on a shard record that names C standby: the end's own shard read preceded
/// C's designation, so its write lands after it and END-RECORDED-FIRST reports C named.
fn end_named_c(store: &Shared) {
    assert_eq!(
        crate::failover::restart::tests::shard_now(store).standby,
        Some(c_host())
    );
    let mut writer = store_client(store);
    let read = writer
        .read::<VolumeRecord>(Key::Volume(volume_id()))
        .unwrap();
    let mut next = read.value().clone();
    let seq = next.live(c_host()).expect("C's live attach");
    let entry = next.events.iter_mut().find(|event| event.seq == seq);
    entry.expect("the live entry").kind = EventKind::Ended;
    writer.replace(&read, next).unwrap();
}

/// A store whose first volume-record read returns `earlier`, the item C's takeover read at its step 1 before the
/// end: C's step-1 reads precede the end and its CAS follows it.
#[derive(Clone)]
struct Earlier {
    inner: Shared,
    earlier: Rc<RefCell<Option<Item>>>,
}

impl Store for Earlier {
    fn read(&mut self, key: &Key) -> Result<Option<Item>, Unavailable> {
        if let Key::Volume(_) = key
            && let Some(item) = self.earlier.borrow_mut().take()
        {
            return Ok(Some(item));
        }
        self.inner.read(key)
    }

    fn write(&mut self, key: &Key, write: &Write) -> Outcome {
        self.inner.write(key, write)
    }

    fn namespace(&self) -> crate::failover::records::Namespace {
        self.inner.namespace()
    }
}

/// C's takeover whose step 1 read `earlier`, the volume record before C's end: its CAS commits, and its reread
/// refuses `Local(Ended)` with the committed target as the recovery hint.
fn c_takes_over_after_its_end(store: &Shared, earlier: Item) {
    use crate::failover::restart::Local;
    use crate::failover::takeover::Check;
    use crate::failover::takeover::tests::{Card, a_holds_c_registered, stored_c, takeover_of};
    let prior = crate::failover::restart::tests::shard_now(store);
    let earlier = Earlier {
        inner: store.clone(),
        earlier: Rc::new(RefCell::new(Some(earlier))),
    };
    let mut card = Card::new(c_pair(), &a_holds_c_registered());
    let refused = takeover_of(store, c_host())
        .run(
            &mut Client::open(earlier, MemLog::default()).unwrap(),
            &stored_c(),
            &mut card,
        )
        .expect_err("C's attach ended before its reread");
    assert_eq!(refused.check, Check::Local(Local::Ended));
    assert!(refused.recovery.is_some(), "C's CAS committed");
    let taken = crate::failover::restart::tests::shard_now(store);
    assert_eq!(
        (taken.owner, taken.attempts, taken.standby),
        (c_host(), prior.attempts + 1, None)
    );
}

/// A step that runs once, inside another writer's store call.
type Hook = Rc<RefCell<Option<Box<dyn FnOnce()>>>>;

/// A store that runs `hook` once, right after the `at`-th shard-record read it forwards, and counts the
/// volume-record writes it forwards.
#[derive(Clone)]
struct AtShardRead {
    inner: Shared,
    reads: Rc<Cell<usize>>,
    /// The volume-record writes before and after the hook ran.
    writes: Rc<Cell<(usize, usize)>>,
    at: usize,
    hook: Hook,
}

impl Store for AtShardRead {
    fn read(&mut self, key: &Key) -> Result<Option<Item>, Unavailable> {
        let read = self.inner.read(key);
        if let Key::Shard(_) = key {
            self.reads.set(self.reads.get() + 1);
            if self.reads.get() == self.at
                && let Some(hook) = self.hook.borrow_mut().take()
            {
                hook();
            }
        }
        read
    }

    fn write(&mut self, key: &Key, write: &Write) -> Outcome {
        if let Key::Volume(_) = key {
            let (before, after) = self.writes.get();
            self.writes.set(match self.hook.borrow().is_some() {
                true => (before + 1, after),
                false => (before, after + 1),
            });
        }
        self.inner.write(key, write)
    }

    fn namespace(&self) -> crate::failover::records::Namespace {
        self.inner.namespace()
    }
}

/// When C's takeover CAS commits against the owner's serving: after A stops, or right after the `n`-th shard
/// read of A's lane. A View reads the volume record, then the shard record, so the CAS then falls between that
/// View's reads and the drop job its poll can queue.
#[derive(Clone, Copy, Debug)]
enum Cas {
    AfterServing,
    AtShardRead(usize),
}

impl Cas {
    /// The orders the tests run: after A's serving, and after each of A's first eight shard reads.
    fn orders() -> impl Iterator<Item = Self> {
        std::iter::once(Self::AfterServing).chain((1..=8).map(Self::AtShardRead))
    }
}

/// What one run of the end race leaves.
#[derive(Debug)]
struct EndRace {
    /// The volume-record writes A's lane issued, its drop jobs, before C's CAS and after it.
    drops: (usize, usize),
    /// Whether C's pair stays recorded once C owns the shard.
    kept: bool,
    /// D's recovery after A and C are lost: the reconciler's attach record and designation of D, then D's takeover.
    d: Result<(), Stranded>,
}

/// Where D's recovery of C's tenure refuses.
#[derive(Debug, PartialEq, Eq)]
enum Stranded {
    /// The reconciler refuses D's attach record or designation.
    Reconciler(crate::failover::reconcile::ReconcileError),
    /// D's takeover refuses.
    Takeover(crate::failover::takeover::Check),
}

/// The end race: C, the named standby, prepares its takeover CAS over step-1 reads of its live attach; the
/// reconciler then ends C's attach on the record that still names C; A, the serving owner, polls and may drop C's
/// ended pair; C's CAS commits at `cas`; C's reread refuses `Local(Ended)`, and C's restart refuses the same, so
/// C's tenure owns the shard with no host serving it. A fresh host D is then designated over C's tenure and takes
/// over, which its Predecessor check admits only while the volume record holds a pair of C.
fn end_race(cas: Cas) -> EndRace {
    use crate::failover::takeover::tests::{takeover_of, try_designate_fresh_host};
    staged(|mut stage| {
        let store = stage.store.clone();
        let key = Key::Volume(volume_id());
        let earlier = store.0.borrow().current(&key).cloned().unwrap();
        end_named_c(&store);
        let hook: Hook = {
            let (store, earlier) = (store.clone(), earlier.clone());
            Rc::new(RefCell::new(Some(Box::new(move || {
                c_takes_over_after_its_end(&store, earlier);
            }))))
        };
        let at = match cas {
            Cas::AfterServing => usize::MAX,
            Cas::AtShardRead(n) => n,
        };
        let writes = Rc::new(Cell::new((0, 0)));
        let racing = AtShardRead {
            inner: store.clone(),
            reads: Rc::default(),
            writes: Rc::clone(&writes),
            at,
            hook: Rc::clone(&hook),
        };
        let mut duties = duties_on(&stage, Client::open(racing, MemLog::default()).unwrap());
        stage.serve_until(
            |_, at, stop| {
                if at >= 400 {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| duties.turn(owner, now),
        );
        drop(duties.end());
        if let Some(hook) = hook.borrow_mut().take() {
            assert!(
                matches!(cas, Cas::AfterServing),
                "{cas:?} ran after A's views"
            );
            hook();
        }
        let record = volume_now(&store);
        let kept = record
            .pairs
            .iter()
            .any(|recorded| recorded.pair == c_pair());
        let d = try_designate_fresh_host(&store)
            .map_err(Stranded::Reconciler)
            .and_then(|d_record| {
                let reservation = crate::failover::takeover::tests::a_holds_c_registered();
                let mut card =
                    crate::failover::takeover::tests::Card::new(d_record.pair(), &reservation);
                takeover_of(&store, crate::failover::takeover::tests::d_host())
                    .run(
                        &mut store_client(&store),
                        &crate::failover::restart::tests::Stored(Ok(d_record)),
                        &mut card,
                    )
                    .map(drop)
                    .map_err(|refused| Stranded::Takeover(refused.check))
            });
        EndRace {
            drops: writes.get(),
            kept,
            d,
        }
    })
}

/// NAMED-PAIR-KEPT over the end race and the queued drop: C's takeover CAS commits after the reconciler ended
/// C's attach, either after A's polls or right after any one of A's first eight shard reads, between a View's
/// reads and the drop job its poll can queue. A's views read a shard record that names C standby, then owner, so
/// no drop carries C's pair, the reconciler attaches and designates D over C's tenure, and D's takeover commits.
#[test]
fn a_standbys_takeover_cas_that_commits_after_its_end_leaves_the_shard_recoverable() {
    for cas in Cas::orders() {
        let race = end_race(cas);
        assert_eq!(race.drops, (0, 0), "{cas:?}: {race:?}");
        assert!(race.kept, "{cas:?}: {race:?}");
        assert_eq!(race.d, Ok(()), "{cas:?}: {race:?}");
    }
}

/// The control of NAMED-PAIR-KEPT: with [`super::droppable`] returning every pair, A drops C's ended pair while
/// the shard record names C standby, before C's CAS or by a job queued before the CAS and run after it. C's tenure
/// then owns the shard with no pair recorded, so the reconciler refuses D's attach record `Conflict` (`serving`
/// needs a pair of the owner, as D's takeover Predecessor check does), which strands the shard.
#[test]
fn negative_control_a_drop_of_a_named_standbys_pair_strands_the_shard() {
    let _planted = Unguarded::set();
    let refused = Err(Stranded::Reconciler(
        crate::failover::reconcile::ReconcileError::Conflict,
    ));
    let stranded: Vec<(Cas, EndRace)> = Cas::orders()
        .map(|cas| (cas, end_race(cas)))
        .filter(|(_, race)| !race.kept && race.d == refused)
        .collect();
    let before = |race: &EndRace| race.drops == (1, 0);
    let queued = |race: &EndRace| race.drops == (0, 1);
    assert!(
        matches!(stranded.first(), Some((Cas::AfterServing, race)) if before(race)),
        "a drop before the CAS strands the shard: {stranded:?}"
    );
    assert!(
        stranded
            .iter()
            .any(|(cas, race)| matches!(cas, Cas::AtShardRead(_)) && queued(race)),
        "a drop queued before the CAS and run after it strands the shard: {stranded:?}"
    );
}

/// A store that runs `hook` once, right after the first read it forwards, and records which record that read
/// named: a takeover over it reads its first step-1 record before the hook's events and its second after them.
struct Paused<'h> {
    inner: Shared,
    hook: Option<Box<dyn FnOnce() + 'h>>,
    first: Rc<Cell<Option<bool>>>,
}

impl Store for Paused<'_> {
    fn read(&mut self, key: &Key) -> Result<Option<Item>, Unavailable> {
        let read = self.inner.read(key);
        if let Some(hook) = self.hook.take() {
            self.first.set(Some(matches!(key, Key::Shard(_))));
            hook();
        }
        read
    }

    fn write(&mut self, key: &Key, write: &Write) -> Outcome {
        self.inner.write(key, write)
    }

    fn namespace(&self) -> crate::failover::records::Namespace {
        self.inner.namespace()
    }
}

/// What one run of the open end-race order leaves.
#[derive(Debug)]
struct OpenOrder {
    /// Whether C's takeover read the shard record first.
    shard_first: Option<bool>,
    /// C's takeover's refusal and whether its CAS committed.
    c: (crate::failover::takeover::Check, bool),
    /// Whether the owner's drop removed C's pair before C's takeover read its second step-1 record.
    dropped: bool,
    /// The owner the shard record names once C's takeover ended.
    owner: crate::failover::records::Host,
    /// D's recovery after A and C are lost: the reconciler's attach record and designation of D, then D's takeover.
    d: Result<(), Stranded>,
}

/// The order NAMED-PAIR-KEPT alone leaves open, with the real end, drop, designation and takeover: (1) C, the named
/// standby, starts its takeover and its step 1 reads its first record; (2) a sync drops C's designation and the
/// reconciler's `end_attach`, whose shard read names C in neither role, ends C's attach; (3) A's polls see the end
/// and the drop's View reads a shard record that names C in neither role, so the drop of C's pair commits; (4) a
/// designation of C whose volume read preceded the end writes the shard record, a raw exact-version write here;
/// (5) C's step 1 reads its second record, and its CAS conditions on the shard record it read. A fresh host D is
/// then designated and takes over, which its Predecessor check admits only while the volume record holds a pair
/// of the shard record's owner.
fn open_order() -> OpenOrder {
    use crate::failover::restart::tests::{Stored, shard_now};
    use crate::failover::takeover::tests::{
        Card, d_host, designate, holds_registered, successor_record, takeover_of,
        try_designate_fresh_host,
    };
    staged_keyed(|mut stage| {
        let store = stage.store.clone();
        designate(&store, Some(c_host()));
        let takeover = takeover_of(&store, c_host());
        let first = Rc::new(Cell::new(None));
        let dropped_before = Rc::new(Cell::new(false));
        let events: Box<dyn FnOnce() + '_> = {
            let (store, stage, dropped_before) =
                (store.clone(), &mut stage, Rc::clone(&dropped_before));
            Box::new(move || {
                end_c(&store);
                let mut duties = duties_on(stage, store_client(&store));
                stage.serve_until(
                    |_, at, stop| {
                        if at >= 400 {
                            stop.store(true, Ordering::Release);
                        }
                    },
                    |owner, now| duties.turn(owner, now),
                );
                drop(duties.end());
                dropped_before.set(dropped(&store));
                designate(&store, Some(c_host()));
            })
        };
        let paused = Paused {
            inner: store.clone(),
            hook: Some(events),
            first: Rc::clone(&first),
        };
        let local = successor_record(c_host(), keyed_c().key.encode(), 0x5c);
        assert_eq!(local.pair(), keyed_c());
        let mut card = Card::new(keyed_c(), &holds_registered(fresh_own(), &[keyed_c()]));
        let refused = takeover
            .run(
                &mut Client::open(paused, MemLog::default()).unwrap(),
                &Stored(Ok(local)),
                &mut card,
            )
            .expect_err("C's attach ended before its takeover ends");
        let owner = shard_now(&store).owner;
        let d = try_designate_fresh_host(&store)
            .map_err(Stranded::Reconciler)
            .and_then(|d_record| {
                let reservation = holds_registered(fresh_own(), &[keyed_c()]);
                let mut card = Card::new(d_record.pair(), &reservation);
                takeover_of(&store, d_host())
                    .run(&mut store_client(&store), &Stored(Ok(d_record)), &mut card)
                    .map(drop)
                    .map_err(|refused| Stranded::Takeover(refused.check))
            });
        OpenOrder {
            shard_first: first.get(),
            c: (refused.check, refused.recovery.is_some()),
            dropped: dropped_before.get(),
            owner,
            d,
        }
    })
}

/// The open order closes with the takeover's shard-first step 1: C's first read is the shard record, before the
/// designation's write, and its second the volume record, after the end, so step 1 refuses `Local(Ended)` before
/// the CAS though the owner's drop removed C's pair. A's tenure keeps the shard, and D is designated and takes it
/// over.
#[test]
fn the_open_end_race_order_refuses_the_takeover_before_its_cas_and_a_fresh_host_recovers() {
    let order = open_order();
    assert_eq!(order.shard_first, Some(true), "{order:?}");
    assert!(order.dropped, "the drop removed C's pair: {order:?}");
    assert_eq!(
        order.c,
        (
            crate::failover::takeover::Check::Local(crate::failover::restart::Local::Ended),
            false
        ),
        "{order:?}"
    );
    assert_eq!(order.owner, holder().host, "{order:?}");
    assert_eq!(order.d, Ok(()), "{order:?}");
}

/// The control of the shard-first step 1: with the volume record read first, C's first read shows its live attach
/// and its second the shard record the designation wrote, so C's CAS commits after the drop removed C's pair and
/// its reread refuses. C's tenure then owns the shard with no pair recorded, and the reconciler refuses D's attach
/// record `Conflict`, which strands the shard.
#[test]
fn negative_control_a_volume_first_takeover_strands_the_shard_in_the_open_order() {
    let _planted = crate::failover::takeover::tests::VolumeFirst::set();
    let order = open_order();
    assert_eq!(order.shard_first, Some(false), "{order:?}");
    assert!(order.dropped, "the drop removed C's pair: {order:?}");
    assert!(order.c.1, "C's CAS committed: {order:?}");
    assert_eq!(order.owner, c_host(), "{order:?}");
    assert_eq!(
        order.d,
        Err(Stranded::Reconciler(
            crate::failover::reconcile::ReconcileError::Conflict
        )),
        "{order:?}"
    );
}

/// NAMED-PAIR-KEPT at the selection: a failed shard read keeps every pair, and a read keeps the pairs of the host
/// it names owner or standby and returns the others.
#[test]
fn the_drop_keeps_every_pair_of_a_named_host_and_all_of_them_without_a_shard_read() {
    use crate::failover::restart::tests::shard_now;
    staged_keyed(|stage| {
        end_c(&stage.store);
        let volume = volume_now(&stage.store);
        let pairs = vec![keyed_c()];
        let shard = shard_now(&stage.store);
        assert_eq!(shard.standby, None);
        assert_eq!(
            super::droppable(Some(&shard), &volume, pairs.clone()),
            pairs
        );
        assert_eq!(super::droppable(None, &volume, pairs.clone()), []);
        for named in [
            ShardRecord {
                standby: Some(c_host()),
                ..shard
            },
            ShardRecord {
                owner: c_host(),
                ..shard
            },
        ] {
            assert_eq!(super::droppable(Some(&named), &volume, pairs.clone()), []);
        }
    });
}

/// Adopting a drop completion that leaves the client serving clears the outstanding drop. A store error that
/// withdrew the client stops the open and ends the incarnation.
#[test]
fn a_drop_completion_that_withdrew_the_client_ends_the_incarnation() {
    use crate::host::lane::Done;
    use crate::storage::store::StoreError;
    staged(|mut stage| {
        let client = Client::open(stage.store.clone(), MemLog::default()).unwrap();
        let mut duties = duties_on(&stage, client);
        let (served, _) = stage.serve_until(
            |_, _, _| {},
            |owner, now| {
                for kept in [None, Some(Err(StoreError::Unknown))] {
                    duties.dropping = true;
                    let done = Done::Drop { dropped: kept };
                    assert_eq!(duties.adopt(owner, done, now), None);
                    assert!(!duties.dropping);
                }
                let done = Done::Drop {
                    dropped: Some(Err(StoreError::Withdrawn)),
                };
                duties.adopt(owner, done, now)
            },
        );
        assert_eq!(served.exit, Exit::Rerun(crate::host::Rerun::Withdrawn));
        assert_eq!(duties.open(), super::Open::Stopped);
    });
}

/// While the volume record holds C's pair, each shard-record write through this store has an unknown outcome and
/// commits nothing, so the open retries its Confirm from every View until the drop is written.
#[derive(Clone)]
struct Retried {
    inner: Shared,
    calls: Calls,
}

impl Store for Retried {
    fn read(&mut self, key: &Key) -> Result<Option<Item>, Unavailable> {
        self.calls.borrow_mut().push((false, *key));
        self.inner.read(key)
    }

    fn write(&mut self, key: &Key, write: &Write) -> Outcome {
        if let Key::Shard(_) = key
            && !dropped(&self.inner)
        {
            self.inner.schedule(Arm::Timeout { commit: false });
        }
        self.calls.borrow_mut().push((true, *key));
        self.inner.write(key, write)
    }

    fn namespace(&self) -> crate::failover::records::Namespace {
        self.inner.namespace()
    }
}

#[test]
fn the_drop_is_submitted_after_the_opens_job_of_its_turn() {
    staged_keyed(|mut stage| {
        end_c(&stage.store);
        stage
            .registry
            .borrow_mut()
            .entries
            .retain(|entry| entry.pair != keyed_c());
        let calls = Calls::default();
        let store = Retried {
            inner: stage.store.clone(),
            calls: calls.clone(),
        };
        let mut duties = duties_on(&stage, Client::open(store, MemLog::default()).unwrap());
        let inner = stage.store.clone();
        let since = Cell::new(None::<u64>);
        let mut drop_turns = Vec::new();
        let (served, _) = stage.serve_until(
            |_, at, stop| {
                if dropped(&inner) {
                    let from = since.get().unwrap_or(at);
                    since.set(Some(from));
                    if at >= from + 400 {
                        stop.store(true, Ordering::Release);
                    }
                }
            },
            |owner, now| {
                let from = calls.borrow().len();
                let exit = duties.turn(owner, now);
                let made = calls.borrow()[from..].to_vec();
                if made.contains(&(true, Key::Volume(volume_id()))) {
                    drop_turns.push(made);
                }
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        let [turn] = &drop_turns[..] else {
            panic!("one drop write: {drop_turns:?}");
        };
        let confirm = (turn.iter()).position(|call| *call == (true, Key::Shard(shard())));
        let drop = (turn.iter()).position(|call| *call == (true, Key::Volume(volume_id())));
        assert!(
            confirm.is_some() && confirm < drop,
            "the open's shard-record write runs ahead of the drop in the turn that submits both: {turn:?}"
        );
        assert_eq!(
            duties.open(),
            super::Open::Opened,
            "the open completes once its write commits"
        );
    });
}

struct Counted(Arc<std::sync::atomic::AtomicUsize>);

impl ControlPlane for Counted {
    fn attachments(&mut self, volume: &VolumeId) -> Result<Vec<String>, Unlisted> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Attached.attachments(volume)
    }
}

/// The test holds the drop's completion through the turns in which a listing falls due with no view outstanding.
/// The duties submit the listing after they adopt the drop.
#[test]
fn a_listing_due_beside_an_outstanding_drop_waits_for_its_adoption() {
    staged_keyed(|mut stage| {
        end_c(&stage.store);
        stage
            .registry
            .borrow_mut()
            .entries
            .retain(|entry| entry.pair != keyed_c());
        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let listings = || counter.load(Ordering::Relaxed);
        let (traced, calls) = traced(&stage);
        let client = Client::open(traced, MemLog::default()).unwrap();
        let mut duties = Duties::new(
            (&HostGate::qualified(), StandbyGate::qualified()),
            Lane::inline(client, stage.storage),
            records(),
            Some(Plane(Box::new(Counted(Arc::clone(&counter))))),
            bounds(),
            super::Periods {
                listing_us: periods().view_us,
                ..periods()
            },
        );
        duties.lane.inline_mut().hold();
        let inner = stage.store.clone();
        let since = Cell::new(None::<u64>);
        let (mut due_beside, mut after) = (0, None);
        let (served, _) = stage.serve_until(
            |_, at, stop| {
                if dropped(&inner) {
                    let from = since.get().unwrap_or(at);
                    since.set(Some(from));
                    if at >= from + 400 {
                        stop.store(true, Ordering::Release);
                    }
                }
            },
            |owner, now| {
                let outstanding = duties.dropping;
                let due = duties.viewing.is_none() && now >= duties.listing_at;
                let before = listings();
                let exit = duties.turn(owner, now);
                if outstanding {
                    due_beside += usize::from(due);
                    assert_eq!(
                        listings(),
                        before,
                        "a listing was submitted beside the outstanding drop"
                    );
                } else if due_beside > 0 && after.is_none() && listings() > before {
                    after = Some(listings());
                }
                if !duties.dropping || now >= duties.view_at {
                    let inline = duties.lane.inline_mut();
                    while inline.release() {}
                }
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        assert_eq!(volume_writes(&calls), 1, "one drop job");
        assert!(
            due_beside > 0,
            "a listing fell due with no view outstanding while the drop was outstanding"
        );
        assert!(after.is_some(), "the listing ran once the drop was adopted");
    });
}
