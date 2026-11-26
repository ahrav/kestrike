//! The simulated store double. Each request takes the next scheduled [`Arm`], [`Arm::Pass`] when none is
//! scheduled, and the store keeps every committed version of every record so a stale read can return an older one.
//!
//! Contract arms: delay, duplication, reorder, a hold that a test releases, a timeout or failure that may commit,
//! size rejection (any value over [`SimStore::limit`]), a stale read and unavailability. Kill arms, which break the
//! store contract: a lost write (acknowledged, never applied), a double win (applied over a failed condition) and a
//! stale current read.
//!
//! The store counts the requests each key receives ([`SimStore::requests`]), so a test can show that an actor sent no
//! request on a key.
//!
//! [`Faulted`] scopes faults to one actor of a world that shares the store: each actor's requests take arms from that
//! actor's own queue in [`ActorFaults`], and an outage window of the actor stops its requests before they reach the
//! store.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::rc::Rc;

use super::{
    Item, Key, Outcome, Refusal, Store, Unavailable, Version, Watermark, WatermarkLog, Write,
};
use crate::failover::records::{Namespace, Record, ShardRecord};

/// The namespace a [`SimStore`] starts with.
pub(crate) const NAMESPACE: Namespace =
    Namespace::new(*b"simulated-store1").expect("nonzero namespace");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Arm {
    Pass,
    /// The write is held, its reply is unknown, and it applies at the next request that holds nothing.
    Delay,
    /// The write is held ahead of every held write, so held writes apply in the reverse of their order.
    Reorder,
    /// The write is parked, its reply is unknown, and it applies only at [`SimStore::release`], so later writes can
    /// commit and be acknowledged before it.
    Hold,
    /// The write applies and is acknowledged, and a second delivery of it is held.
    Duplicate,
    /// A timeout: the write applies when `commit`, and the reply is unknown.
    Timeout {
        commit: bool,
    },
    /// An error reply that may accompany a commit: the write applies when `commit`, and the reply is unknown.
    Failure {
        commit: bool,
    },
    /// A read returns no value; a write is unknown and does not apply.
    Unavailable,
    /// Contract arm: a read that overlaps a write's commit misses it and returns the record's previous version. A
    /// stale arm on a record with fewer than two committed versions panics, so a schedule that tests nothing fails.
    StaleRead,
    /// Kill arm: the write is acknowledged at the next version and never applies.
    LostWrite,
    /// Kill arm: the write applies at the next version whether or not its condition holds.
    DoubleWin,
    /// Kill arm: a read issued after a commit was acknowledged misses it and returns the record's previous version.
    StaleCurrentRead,
}

#[derive(Clone)]
pub(crate) struct SimStore {
    /// The largest value the store commits; a larger one is rejected.
    pub(crate) limit: usize,
    pub(crate) namespace: Namespace,
    arms: VecDeque<Arm>,
    held: VecDeque<(Key, Write)>,
    parked: VecDeque<(Key, Write)>,
    history: BTreeMap<Key, Vec<Item>>,
    /// The outcome of every held write a later request applied, in order.
    pub(crate) drained: Vec<Outcome>,
    pub(crate) replied: BTreeMap<Key, usize>,
    /// The source generation of every committed shard-record write that changed the generation, in commit order:
    /// the generation of the value at the write's expected version, or of the value it replaced when that version
    /// was never stored.
    pub(crate) flips: Vec<u64>,
    /// The store counts each read and write on receipt, regardless of arm or outcome.
    requests: BTreeMap<Key, u64>,
}

impl SimStore {
    pub(crate) fn new() -> Self {
        Self {
            limit: super::contract::ITEM_LIMIT,
            namespace: NAMESPACE,
            arms: VecDeque::new(),
            held: VecDeque::new(),
            parked: VecDeque::new(),
            history: BTreeMap::new(),
            drained: Vec::new(),
            replied: BTreeMap::new(),
            flips: Vec::new(),
            requests: BTreeMap::new(),
        }
    }

    pub(crate) fn requests(&self, key: &Key) -> u64 {
        self.requests.get(key).copied().unwrap_or(0)
    }

    /// Every key that holds a committed version.
    pub(crate) fn keys(&self) -> impl Iterator<Item = &Key> {
        self.history.keys()
    }

    /// Every committed version of `key`, oldest first.
    pub(crate) fn versions(&self, key: &Key) -> &[Item] {
        self.history.get(key).map_or(&[], Vec::as_slice)
    }

    pub(crate) fn schedule(&mut self, arm: Arm) {
        self.arms.push_back(arm);
    }

    /// Schedules `arm` ahead of every scheduled arm, so the next request takes it.
    fn schedule_next(&mut self, arm: Arm) {
        self.arms.push_front(arm);
    }

    pub(crate) fn unschedule(&mut self) {
        self.arms.clear();
    }

    /// Applies every parked write in its order and returns each outcome.
    pub(crate) fn release(&mut self) -> Vec<Outcome> {
        let parked: Vec<_> = self.parked.drain(..).collect();
        parked
            .iter()
            .map(|(key, write)| self.apply(key, write, false))
            .collect()
    }

    /// The parked writes, in the order [`SimStore::release`] applies them.
    pub(crate) fn parked(&self) -> &VecDeque<(Key, Write)> {
        &self.parked
    }

    /// The number of commits of `key`.
    pub(crate) fn commit_count(&self, key: &Key) -> usize {
        self.history.get(key).map_or(0, Vec::len)
    }

    pub(crate) fn current(&self, key: &Key) -> Option<&Item> {
        self.history.get(key).and_then(|versions| versions.last())
    }

    fn arm(&mut self) -> Arm {
        let arm = self.arms.pop_front().unwrap_or(Arm::Pass);
        if !matches!(arm, Arm::Delay | Arm::Reorder | Arm::Hold) {
            while let Some((key, write)) = self.held.pop_front() {
                let outcome = self.apply(&key, &write, false);
                self.drained.push(outcome);
            }
        }
        arm
    }

    /// Applies `write` when its condition holds, or regardless when `force`; returns the committed version.
    fn apply(&mut self, key: &Key, write: &Write, force: bool) -> Outcome {
        let current = self.current(key).cloned();
        let next = current
            .as_ref()
            .map_or(Some(Version::FIRST), |item| item.version.next());
        let Some(next) = next else {
            return Outcome::NotCommitted(Refusal::Rejected);
        };
        let (Write::Create(bytes) | Write::Exact { value: bytes, .. }) = write;
        if bytes.len() > self.limit {
            return Outcome::NotCommitted(Refusal::Rejected);
        }
        let value = match (write, &current) {
            (Write::Create(value), None) => Some(value.clone()),
            (Write::Exact { expect, value }, Some(item)) if item.version == *expect => {
                Some(value.clone())
            }
            (Write::Create(value) | Write::Exact { value, .. }, _) if force => Some(value.clone()),
            _ => None,
        };
        let Some(value) = value else {
            return Outcome::NotCommitted(Refusal::Condition);
        };
        let generation = |bytes: &[u8]| ShardRecord::decode(bytes).ok().map(|r| r.generation.get());
        let source = match (key, write) {
            (Key::Shard(_), Write::Exact { expect, .. }) => {
                let versions = self.history.get(key).map_or(&[][..], Vec::as_slice);
                let at = usize::try_from(expect.get() - 1).ok();
                let replaced = at.and_then(|at| versions.get(at)).or(versions.last());
                replaced.and_then(|item| generation(&item.value))
            }
            _ => None,
        };
        let written = generation(&value);
        if let Some(source) = source.filter(|&source| written.is_some_and(|g| g != source)) {
            self.flips.push(source);
        }
        self.history.entry(*key).or_default().push(Item {
            version: next,
            value,
        });
        Outcome::Committed(next)
    }
}

impl Store for SimStore {
    fn read(&mut self, key: &Key) -> Result<Option<Item>, Unavailable> {
        *self.requests.entry(*key).or_default() += 1;
        let arm = self.arm();
        let versions = self.history.get(key).map_or(&[][..], Vec::as_slice);
        match arm {
            Arm::Pass => Ok(self.current(key).cloned()),
            Arm::Unavailable => Err(Unavailable),
            Arm::StaleRead | Arm::StaleCurrentRead => {
                assert!(
                    versions.len() >= 2,
                    "{arm:?} on {key:?} with fewer than two versions"
                );
                Ok(Some(versions[versions.len() - 2].clone()))
            }
            arm => panic!("{arm:?} scheduled on a read of {key:?}"),
        }
    }

    fn write(&mut self, key: &Key, write: &Write) -> Outcome {
        *self.requests.entry(*key).or_default() += 1;
        let outcome = self.reply(key, write);
        if matches!(outcome, Outcome::Committed(_)) {
            *self.replied.entry(*key).or_default() += 1;
        }
        outcome
    }

    fn namespace(&self) -> Namespace {
        self.namespace
    }
}

impl SimStore {
    fn reply(&mut self, key: &Key, write: &Write) -> Outcome {
        match self.arm() {
            Arm::Delay => {
                self.held.push_back((*key, write.clone()));
                Outcome::Unknown
            }
            Arm::Reorder => {
                self.held.push_front((*key, write.clone()));
                Outcome::Unknown
            }
            Arm::Hold => {
                self.parked.push_back((*key, write.clone()));
                Outcome::Unknown
            }
            Arm::Duplicate => {
                self.held.push_back((*key, write.clone()));
                self.apply(key, write, false)
            }
            Arm::Timeout { commit } | Arm::Failure { commit } => {
                if commit {
                    self.apply(key, write, false);
                }
                Outcome::Unknown
            }
            Arm::Unavailable => Outcome::Unknown,
            Arm::LostWrite => {
                let next = self
                    .current(key)
                    .map_or(Some(Version::FIRST), |item| item.version.next());
                next.map_or(Outcome::Unknown, Outcome::Committed)
            }
            Arm::DoubleWin => self.apply(key, write, true),
            Arm::Pass => self.apply(key, write, false),
            arm @ (Arm::StaleRead | Arm::StaleCurrentRead) => {
                panic!("{arm:?} scheduled on a write of {key:?}")
            }
        }
    }
}

/// A [`SimStore`] several clients share, as several hosts share one table.
#[derive(Clone)]
pub(crate) struct Shared(pub(crate) Rc<RefCell<SimStore>>);

impl Shared {
    pub(crate) fn new() -> Self {
        Self(Rc::new(RefCell::new(SimStore::new())))
    }

    pub(crate) fn schedule(&self, arm: Arm) {
        self.0.borrow_mut().schedule(arm);
    }

    pub(crate) fn release(&self) -> Vec<Outcome> {
        self.0.borrow_mut().release()
    }
}

impl Store for Shared {
    fn read(&mut self, key: &Key) -> Result<Option<Item>, Unavailable> {
        self.0.borrow_mut().read(key)
    }

    fn write(&mut self, key: &Key, write: &Write) -> Outcome {
        self.0.borrow_mut().write(key, write)
    }

    fn namespace(&self) -> Namespace {
        self.0.borrow().namespace
    }
}

/// A store whose requests can take an arm scheduled for the next request alone.
pub(crate) trait Armed: Store {
    /// Schedules `arm` for the next request and returns the arms scheduled before it.
    fn arm_next(&mut self, arm: Arm) -> usize;

    /// Removes the arm [`Armed::arm_next`] scheduled when no request took it, given the count that call returned.
    fn disarm(&mut self, before: usize);
}

impl Armed for Shared {
    fn arm_next(&mut self, arm: Arm) -> usize {
        let mut store = self.0.borrow_mut();
        let before = store.arms.len();
        store.schedule_next(arm);
        before
    }

    fn disarm(&mut self, before: usize) {
        let mut store = self.0.borrow_mut();
        if store.arms.len() > before {
            store.arms.pop_front();
        }
    }
}

impl<S: Armed> Armed for AsReconciler<S> {
    fn arm_next(&mut self, arm: Arm) -> usize {
        self.0.arm_next(arm)
    }

    fn disarm(&mut self, before: usize) {
        self.0.disarm(before);
    }
}

/// The store faults of every actor that reaches one store through [`Faulted`]: an arm queue per actor, and outage
/// windows over the time [`ActorFaults::set_now`] last set.
#[derive(Debug, Default)]
pub(crate) struct ActorFaults {
    /// Each actor's queued arms, each with the ticket [`ActorFaults::arm`] returned for it.
    arms: BTreeMap<u32, VecDeque<(u64, Arm)>>,
    /// The tickets given so far.
    tickets: u64,
    /// Arms that only a write takes, after the arms of `arms`.
    writes: BTreeMap<u32, VecDeque<Arm>>,
    /// Each window's actor, `None` for every actor, and its half-open span `[from, until)`.
    outages: Vec<(Option<u32>, u64, u64)>,
    now: u64,
}

impl ActorFaults {
    /// Queues `arm` for `actor`'s next request that finds no earlier arm of its own, and returns the arm's ticket.
    pub(crate) fn arm(&mut self, actor: u32, arm: Arm) -> u64 {
        self.tickets += 1;
        let queue = self.arms.entry(actor).or_default();
        queue.push_back((self.tickets, arm));
        self.tickets
    }

    /// Queues `arm` for `actor`'s next write that finds no earlier arm of its own; reads pass it by.
    pub(crate) fn arm_write(&mut self, actor: u32, arm: Arm) {
        self.writes.entry(actor).or_default().push_back(arm);
    }

    /// Drops the write arms `actor` has yet to take.
    pub(crate) fn withdraw_writes(&mut self, actor: u32) {
        self.writes.remove(&actor);
    }

    /// Takes the arm of `ticket` off `actor`'s queue when no request took it.
    pub(crate) fn withdraw(&mut self, actor: u32, ticket: u64) {
        if let Some(queue) = self.arms.get_mut(&actor) {
            queue.retain(|(of, _)| *of != ticket);
        }
    }

    /// Stops `actor`'s requests, every actor's for `None`, from `from` until `until`.
    pub(crate) fn outage(&mut self, actor: Option<u32>, from: u64, until: u64) {
        self.outages.push((actor, from, until));
    }

    pub(crate) fn set_now(&mut self, now: u64) {
        self.now = now;
    }

    /// The arms `actor` has yet to take, write arms included.
    pub(crate) fn queued(&self, actor: u32) -> usize {
        let arms = self.arms.get(&actor).map_or(0, VecDeque::len);
        arms + self.writes.get(&actor).map_or(0, VecDeque::len)
    }

    pub(crate) fn out(&self, actor: u32) -> bool {
        let now = self.now;
        (self.outages.iter()).any(|&(of, from, until)| {
            of.is_none_or(|of| of == actor) && (from..until).contains(&now)
        })
    }

    fn take(&mut self, actor: u32, write: bool) -> Option<Arm> {
        let taken = self.arms.get_mut(&actor).and_then(VecDeque::pop_front);
        match (taken, write) {
            (None, true) => self.writes.get_mut(&actor).and_then(VecDeque::pop_front),
            (taken, _) => taken.map(|(_, arm)| arm),
        }
    }
}

/// One actor's reach of a shared store. Inside an outage window of the actor a read returns no value and a write is
/// unknown, and neither reaches the store, so the store counts neither. Otherwise the request takes the actor's next
/// queued arm, a write then its next write arm, [`Arm::Pass`] when none is queued, and a request of another actor
/// never takes it.
pub(crate) struct Faulted<S> {
    pub(crate) inner: S,
    pub(crate) actor: u32,
    pub(crate) faults: Rc<RefCell<ActorFaults>>,
}

impl<S: Armed> Faulted<S> {
    /// Runs `request` on the inner store under the actor's next arm, or returns `outage` inside an outage window.
    fn reach<T>(&mut self, write: bool, outage: T, request: impl FnOnce(&mut S) -> T) -> T {
        let arm = {
            let mut faults = self.faults.borrow_mut();
            if faults.out(self.actor) {
                return outage;
            }
            faults.take(self.actor, write)
        };
        let Some(arm) = arm else {
            return request(&mut self.inner);
        };
        let before = self.inner.arm_next(arm);
        let reply = request(&mut self.inner);
        self.inner.disarm(before);
        reply
    }
}

impl<S: Armed> Store for Faulted<S> {
    fn read(&mut self, key: &Key) -> Result<Option<Item>, Unavailable> {
        self.reach(false, Err(Unavailable), |inner| inner.read(key))
    }

    fn write(&mut self, key: &Key, write: &Write) -> Outcome {
        self.reach(true, Outcome::Unknown, |inner| inner.write(key, write))
    }

    fn namespace(&self) -> Namespace {
        self.inner.namespace()
    }
}

/// One request a [`Recorder`] passed to its store, or a device command a test's device double traced beside them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Request {
    Read(Key),
    Write(Key, Write),
    Device(&'static str),
}

/// A store over [`Shared`] that records every request it passes on, in order, with each write's whole value.
#[derive(Clone)]
pub(crate) struct Recorder {
    inner: Shared,
    requests: Rc<RefCell<Vec<Request>>>,
}

impl Recorder {
    pub(crate) fn new(inner: &Shared) -> Self {
        Self {
            inner: inner.clone(),
            requests: Rc::default(),
        }
    }

    /// The requests recorded so far, which leaves the record empty.
    pub(crate) fn take(&self) -> Vec<Request> {
        self.requests.take()
    }

    /// Traces the device command `name` in order with the store requests.
    pub(crate) fn device(&self, name: &'static str) {
        self.requests.borrow_mut().push(Request::Device(name));
    }
}

impl Store for Recorder {
    fn read(&mut self, key: &Key) -> Result<Option<Item>, Unavailable> {
        self.requests.borrow_mut().push(Request::Read(*key));
        self.inner.read(key)
    }

    fn write(&mut self, key: &Key, write: &Write) -> Outcome {
        self.requests
            .borrow_mut()
            .push(Request::Write(*key, write.clone()));
        self.inner.write(key, write)
    }

    fn namespace(&self) -> Namespace {
        self.inner.namespace()
    }
}

/// Where a [`Hook`] runs its step inside a request on its key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Point {
    /// After the inner read returned, before the caller sees it.
    AfterRead,
    /// Before the write is forwarded to the inner store.
    BeforeWrite,
    /// After the inner write replied, before the caller sees the reply.
    AfterWrite,
}

/// A store over [`Shared`] that runs its step once, at the first request of its point's kind on its key, so
/// another actor's step runs inside one actor's request sequence. Requests on other keys pass through.
pub(crate) struct Hook {
    inner: Shared,
    key: Key,
    point: Point,
    then: Option<Box<dyn FnOnce()>>,
    /// The arm [`Armed::arm_next`] gave this store's next request, scheduled on the inner store only when that
    /// request is forwarded, after a `BeforeWrite` step, so a request the step makes cannot take it.
    armed: Option<Arm>,
}

impl Hook {
    fn run(&mut self, key: &Key, at: Point) {
        if self.point == at
            && *key == self.key
            && let Some(then) = self.then.take()
        {
            then();
        }
    }
}

impl Store for Hook {
    fn namespace(&self) -> Namespace {
        self.inner.namespace()
    }

    fn read(&mut self, key: &Key) -> Result<Option<Item>, Unavailable> {
        self.forward_arm();
        let read = self.inner.read(key);
        self.run(key, Point::AfterRead);
        read
    }

    fn write(&mut self, key: &Key, write: &Write) -> Outcome {
        self.run(key, Point::BeforeWrite);
        self.forward_arm();
        let outcome = self.inner.write(key, write);
        self.run(key, Point::AfterWrite);
        outcome
    }
}

impl Hook {
    fn forward_arm(&mut self) {
        if let Some(arm) = self.armed.take() {
            self.inner.0.borrow_mut().schedule_next(arm);
        }
    }
}

impl Armed for Hook {
    fn arm_next(&mut self, arm: Arm) -> usize {
        self.armed = Some(arm);
        self.inner.0.borrow().arms.len()
    }

    fn disarm(&mut self, before: usize) {
        self.armed = None;
        self.inner.disarm(before);
    }
}

/// A [`Hook`] over `store` that runs `then` at `point` of the first such request on `key`.
pub(crate) fn hooked(
    store: &Shared,
    key: Key,
    point: Point,
    then: impl FnOnce() + 'static,
) -> Hook {
    Hook {
        inner: store.clone(),
        key,
        point,
        then: Some(Box::new(then)),
        armed: None,
    }
}

/// The requests a store received: reads, then writes.
#[derive(Clone, Default)]
pub(crate) struct Requests {
    reads: Rc<Cell<usize>>,
    writes: Rc<Cell<usize>>,
}

impl Requests {
    pub(crate) fn seen(&self) -> (usize, usize) {
        (self.reads.get(), self.writes.get())
    }
}

/// A store that counts every read and write before handing it on, failed requests included.
pub(crate) struct Counting<S> {
    pub(crate) store: S,
    pub(crate) requests: Requests,
}

impl<S: Store> Store for Counting<S> {
    fn read(&mut self, key: &Key) -> Result<Option<Item>, Unavailable> {
        self.requests.reads.set(self.requests.reads.get() + 1);
        self.store.read(key)
    }

    fn write(&mut self, key: &Key, write: &Write) -> Outcome {
        self.requests.writes.set(self.requests.writes.get() + 1);
        self.store.write(key, write)
    }

    fn namespace(&self) -> Namespace {
        self.store.namespace()
    }
}

/// A host-local watermark log that survives a simulated crash of the client that wrote it. It starts holding the
/// empty watermark, and while `fail` is set every record fails and leaves the held watermark.
#[derive(Clone, Default)]
pub(crate) struct MemLog {
    mark: Rc<RefCell<Watermark>>,
    pub(crate) fail: Rc<Cell<bool>>,
}

impl MemLog {
    pub(crate) fn held(&self) -> Watermark {
        self.mark.borrow().clone()
    }
}

impl WatermarkLog for MemLog {
    fn load(&self) -> io::Result<Watermark> {
        Ok(self.held())
    }

    fn record(&mut self, mark: &Watermark) -> io::Result<()> {
        if self.fail.get() {
            return Err(io::ErrorKind::Other.into());
        }
        *self.mark.borrow_mut() = mark.clone();
        Ok(())
    }
}

/// One log write a [`Journal`] passed to its [`MemLog`]: the keys of a raise, or `None` for a whole record, and
/// the watermark it wrote.
pub(crate) type Entry = (Option<Vec<Key>>, Watermark);

/// A [`MemLog`] that keeps every log write it passes on, in order.
#[derive(Clone, Default)]
pub(crate) struct Journal {
    pub(crate) log: MemLog,
    writes: Rc<RefCell<Vec<Entry>>>,
}

impl Journal {
    /// The writes kept so far, which leaves the journal empty.
    pub(crate) fn take(&self) -> Vec<Entry> {
        self.writes.take()
    }
}

impl WatermarkLog for Journal {
    fn load(&self) -> io::Result<Watermark> {
        self.log.load()
    }

    fn record(&mut self, mark: &Watermark) -> io::Result<()> {
        self.writes.borrow_mut().push((None, mark.clone()));
        self.log.record(mark)
    }

    fn raise(&mut self, mark: &Watermark, keys: &[Key]) -> io::Result<()> {
        self.writes
            .borrow_mut()
            .push((Some(keys.to_vec()), mark.clone()));
        self.log.raise(mark, keys)
    }
}

/// A store as the long-running reconciler's principal reaches it under the deployed table policy: it writes shard and
/// volume records, standby censuses and replacement receipts and no coverage page, neither a create nor a replacement,
/// so it can write neither page entries nor fences nor a page's version.
pub(crate) struct AsReconciler<S>(pub(crate) S);

impl<S: Store> Store for AsReconciler<S> {
    fn read(&mut self, key: &Key) -> Result<Option<Item>, Unavailable> {
        self.0.read(key)
    }

    fn write(&mut self, key: &Key, write: &Write) -> Outcome {
        match key {
            Key::Page(..) => Outcome::NotCommitted(Refusal::Denied),
            Key::Shard(_) | Key::Volume(_) | Key::Standbys(_) | Key::Replacement(_) => {
                self.0.write(key, write)
            }
        }
    }

    fn namespace(&self) -> Namespace {
        self.0.namespace()
    }
}

/// A store as the shard-provisioning principal reaches it under the deployed table policy, which grants it shard
/// records and coverage pages. A write of a volume record, a standby census or a replacement receipt is denied, and a
/// read of one returns no value, since [`Store::read`] reports a refusal as unavailability.
pub(crate) struct AsProvisioner<S>(pub(crate) S);

impl<S: Store> Store for AsProvisioner<S> {
    fn read(&mut self, key: &Key) -> Result<Option<Item>, Unavailable> {
        match key {
            Key::Volume(_) | Key::Standbys(_) | Key::Replacement(_) => Err(Unavailable),
            Key::Shard(_) | Key::Page(..) => self.0.read(key),
        }
    }

    fn write(&mut self, key: &Key, write: &Write) -> Outcome {
        match key {
            Key::Volume(_) | Key::Standbys(_) | Key::Replacement(_) => {
                Outcome::NotCommitted(Refusal::Denied)
            }
            Key::Shard(_) | Key::Page(..) => self.0.write(key, write),
        }
    }

    fn namespace(&self) -> Namespace {
        self.0.namespace()
    }
}
