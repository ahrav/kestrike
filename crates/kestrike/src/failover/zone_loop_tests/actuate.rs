use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use crate::failover::attachments::{ControlPlane, InstanceId, Unlisted};
use crate::failover::bounds::Bounds;
use crate::failover::evidence::Pair;
use crate::failover::loss::{CreateError, Provider};
use crate::failover::poll::Holder;
use crate::failover::reconcile::{ReconcileError, Reconciler, StandbyGate, enroll_standby};
use crate::failover::record::{Binding, LocalRecord};
use crate::failover::records::{
    CoveragePage, EventKind, Host, Layout, Namespace, ShardRecord, VolumeId, VolumeRecord,
};
use crate::failover::report::{Gauge, Headroom};
use crate::failover::retire::Target;
use crate::failover::sim::host;
use crate::failover::standbys::{Census, Need, Population};
use crate::failover::zone_loop::ZoneLoop;
use crate::failover::zone_loop::actuate::{
    Discard, Outcome, Reason, Reclaim, Verdict, backoff_us, verdict_of,
};
use crate::failover::zone_loop::config::ZoneBounds;
use crate::failover::zone_loop::directory::{Color, DirectoryState};
use crate::failover::zone_loop::evidence::InstanceState;
use crate::failover::zone_loop::plan::{Step, Survey};
use crate::failover::zone_loop::sources::{
    AttachRefusal, AttachReply, Attacher, DetachReply, Witness,
};
use crate::failover::zone_loop::status::ShardState;
use crate::net::ownership::Shard;
use crate::storage::store::sim::{Arm, AsReconciler, MemLog, Shared};
use crate::storage::store::{
    Client, Item, Key, Outcome as Written, Store, Tracked, Unavailable, Write,
};

use super::config::{bounds, config_of};
use super::directory::{instance, listing};
use super::observe::{Fixture, S, START, ZONE, owner_of, volume};
use super::survey::roomy_fixture;
use super::world::{AttachFault, Event, Recording, World};

pub(super) fn shard(number: u32) -> Shard {
    Shard::new(number).unwrap()
}

pub(super) fn owner(store: &Shared) -> Client<Shared, MemLog> {
    Client::open(store.clone(), MemLog::default()).unwrap()
}

pub(super) fn reconciler_client(store: &Shared) -> Client<AsReconciler<Shared>, MemLog> {
    Client::open(AsReconciler(store.clone()), MemLog::default()).unwrap()
}

fn attach_pair(held: &VolumeRecord, n: u64) -> Pair {
    Pair {
        key: held.attach_key(host(n)).unwrap(),
        ..crate::failover::evidence_tests::pair(n as u8, n as u32, n as u32)
    }
}

pub(super) fn stored<R: Tracked>(store: &Shared, key: Key) -> R {
    let item = store.0.borrow().current(&key).cloned().unwrap();
    R::decode(&item.value).unwrap()
}

pub(super) fn census_of(store: &Shared) -> Option<Census> {
    let item = store.0.borrow().current(&Key::Standbys(ZONE)).cloned();
    item.map(|item| Census::decode_owned(item.value).unwrap())
}

#[derive(Default)]
pub(super) struct Crash {
    pub(super) effects: usize,
    pub(super) at: Option<(usize, Arm)>,
    pub(super) dead: bool,
    /// The loop keeps running after the armed effect.
    pub(super) survives: bool,
}

impl Crash {
    fn effect(&mut self) -> Option<Arm> {
        let seen = self.effects;
        self.effects += 1;
        match self.at {
            Some((at, arm)) if at == seen => {
                self.dead = !self.survives;
                Some(arm)
            }
            _ => None,
        }
    }
}

pub(super) type Faults = Rc<RefCell<Crash>>;
pub(super) type Hook = Rc<RefCell<Option<(Key, Box<dyn FnOnce()>)>>>;
pub(super) type After = Rc<RefCell<Option<(Key, Box<dyn FnOnce()>)>>>;

pub(super) struct Probe {
    inner: Recording<AsReconciler<Shared>>,
    store: Shared,
    faults: Faults,
    hook: Hook,
    after: After,
}

impl Store for Probe {
    fn read(&mut self, key: &Key) -> Result<Option<Item>, Unavailable> {
        if self.faults.borrow().dead {
            return Err(Unavailable);
        }
        self.inner.read(key)
    }

    fn write(&mut self, key: &Key, write: &Write) -> Written {
        if self.faults.borrow().dead {
            return Written::Unknown;
        }
        let due = matches!(&*self.hook.borrow(), Some((at, _)) if at == key);
        if due && let Some((_, hook)) = self.hook.borrow_mut().take() {
            hook();
        }
        if let Some(arm) = self.faults.borrow_mut().effect() {
            self.store.schedule(arm);
        }
        let outcome = self.inner.write(key, write);
        let due = matches!(&*self.after.borrow(), Some((at, _)) if at == key);
        if due && let Some((_, then)) = self.after.borrow_mut().take() {
            then();
        }
        outcome
    }

    fn namespace(&self) -> Namespace {
        self.inner.namespace()
    }
}

struct HostStore {
    store: Shared,
    faults: Faults,
}

impl Store for HostStore {
    fn read(&mut self, key: &Key) -> Result<Option<Item>, Unavailable> {
        self.store.read(key)
    }

    fn write(&mut self, key: &Key, write: &Write) -> Written {
        if let Some(arm) = self.faults.borrow_mut().effect() {
            self.store.schedule(arm);
        }
        self.store.write(key, write)
    }

    fn namespace(&self) -> Namespace {
        self.store.namespace()
    }
}

struct Calls<'a> {
    world: &'a mut World,
    faults: &'a Faults,
}

impl ControlPlane for Calls<'_> {
    fn attachments(&mut self, volume: &VolumeId) -> Result<Vec<String>, Unlisted> {
        if self.faults.borrow().dead {
            return Err(Unlisted);
        }
        self.world.attachments(volume)
    }
}

impl Provider for Calls<'_> {
    fn create(&mut self, token: &str, layout: Layout) -> Result<VolumeId, CreateError> {
        if self.faults.borrow().dead {
            return Err(CreateError::Unknown);
        }
        let arm = self.faults.borrow_mut().effect();
        match arm {
            None | Some(Arm::Pass) => Provider::create(self.world, token, layout),
            Some(Arm::Timeout { commit: true }) => {
                let _ = Provider::create(self.world, token, layout);
                Err(CreateError::Unknown)
            }
            Some(_) => Err(CreateError::Unknown),
        }
    }
}

impl Attacher for Calls<'_> {
    fn attach(&mut self, volume: VolumeId, instance: InstanceId) -> AttachReply {
        if self.faults.borrow().dead {
            return AttachReply::Unknown;
        }
        let arm = self.faults.borrow_mut().effect();
        match arm {
            None | Some(Arm::Pass) => Attacher::attach(self.world, volume, instance),
            Some(Arm::Timeout { commit: true }) => {
                Attacher::attach(self.world, volume, instance);
                AttachReply::Unknown
            }
            Some(_) => AttachReply::Unknown,
        }
    }

    fn detach(&mut self, witness: Witness<'_>) -> DetachReply {
        if self.faults.borrow().dead {
            return DetachReply::Unknown;
        }
        let arm = self.faults.borrow_mut().effect();
        match arm {
            None | Some(Arm::Pass) => Attacher::detach(self.world, witness),
            Some(Arm::Timeout { commit: true }) => {
                Attacher::detach(self.world, witness);
                DetachReply::Unknown
            }
            Some(_) => DetachReply::Unknown,
        }
    }
}

pub(super) type Loop = ZoneLoop<Probe, MemLog>;

#[derive(Clone)]
pub(super) struct Snapshot {
    pub(super) shards: Vec<(ShardRecord, VolumeRecord)>,
    pub(super) census: Option<Census>,
}

pub(super) struct Cell {
    pub(super) fixture: Fixture,
    pub(super) bounds: ZoneBounds,
    pub(super) zone: Loop,
    pub(super) faults: Faults,
    pub(super) hook: Hook,
    pub(super) after: After,
    pub(super) breaks: Vec<String>,
    pub(super) silent: Vec<u64>,
    pub(super) now_us: u64,
    pub(super) restarts: usize,
    pub(super) drops: bool,
    pub(super) unenrolled: Vec<u64>,
    pub(super) ends: bool,
    /// While false, `actuate` restores each re-reservation the plan withheld for a refused fresh need in place of
    /// its release (the planted control of FRESH-FIRST).
    pub(super) withholds: bool,
    /// While false, `actuate` restores the `Protected` reading of each shard whose live named standby another host's
    /// census entry at the record's target displaces, with none of its enrollment steps (the planted control of
    /// SLOT-HOST).
    pub(super) slot_host: bool,
}

impl Cell {
    pub(super) fn new(hosts: u64, shards: u32) -> Self {
        Self::with(hosts, shards, true, bounds())
    }

    pub(super) fn with(hosts: u64, shards: u32, fenced: bool, zone: ZoneBounds) -> Self {
        let mut fixture = roomy_fixture(hosts, shards);
        let mut client = owner(&fixture.store);
        for number in 1..=shards {
            let read = client
                .read::<VolumeRecord>(Key::Volume(volume(number)))
                .unwrap();
            let owner = owner_of(number, hosts).get();
            let pair = attach_pair(read.value(), owner);
            let enrolled = read.value().enroll(host(owner), pair, zone.bounds());
            client.replace(&read, enrolled.unwrap().unwrap()).unwrap();
            if fenced {
                fence(&fixture.store, number);
            }
        }
        fixture.world.store = Some(fixture.store.clone());
        let faults = Faults::default();
        let hook = Hook::default();
        let after = After::default();
        let bounds = zone;
        let zone = Self::open(&fixture, &faults, &hook, &after, &bounds);
        Self {
            fixture,
            bounds,
            zone,
            faults,
            hook,
            after,
            breaks: Vec::new(),
            silent: Vec::new(),
            now_us: START,
            restarts: 0,
            drops: true,
            unenrolled: Vec::new(),
            ends: true,
            withholds: true,
            slot_host: true,
        }
    }

    pub(super) fn open(
        fixture: &Fixture,
        faults: &Faults,
        hook: &Hook,
        after: &After,
        bounds: &ZoneBounds,
    ) -> Loop {
        let probe = Probe {
            inner: Recording {
                inner: AsReconciler(fixture.store.clone()),
                log: fixture.world.log.clone(),
            },
            store: fixture.store.clone(),
            faults: faults.clone(),
            hook: hook.clone(),
            after: after.clone(),
        };
        let client = Client::open(probe, MemLog::default()).unwrap();
        ZoneLoop::new(Reconciler::new(client), bounds.clone())
    }

    pub(super) fn restart(&mut self) {
        let mut faults = self.faults.borrow_mut();
        faults.dead = false;
        faults.at = None;
        drop(faults);
        self.zone = Self::open(
            &self.fixture,
            &self.faults,
            &self.hook,
            &self.after,
            &self.bounds,
        );
        self.restarts += 1;
    }

    pub(super) fn store(&self) -> &Shared {
        &self.fixture.store
    }

    pub(super) fn snapshot(&self) -> Snapshot {
        let shards = (1..=self.fixture.shards)
            .map(|number| (self.shard(number), self.volume(number)))
            .collect();
        Snapshot {
            shards,
            census: census_of(self.store()),
        }
    }

    pub(super) fn shard(&self, number: u32) -> ShardRecord {
        stored(self.store(), Key::Shard(shard(number)))
    }

    pub(super) fn volume(&self, number: u32) -> VolumeRecord {
        stored(self.store(), Key::Volume(self.shard(number).active))
    }

    pub(super) fn survey(&mut self) -> Survey {
        for number in 1..=self.fixture.hosts {
            if !self.silent.contains(&number) {
                self.fixture.publish(number, &[]);
            }
        }
        let directory = Ok(self.fixture.directory());
        (self.zone).survey(directory, &mut self.fixture.world, self.now_us)
    }

    pub(super) fn actuate(&mut self, survey: &Survey) -> Vec<Outcome> {
        let gate = StandbyGate::qualified();
        let before = self.snapshot();
        if let Ok(view) = &survey.observation.zone {
            for step in &survey.plan.steps {
                let (Step::End { shard, host }
                | Step::Detach { shard, host }
                | Step::ReleaseAttach { shard, host }) = *step
                else {
                    continue;
                };
                let found = view.shards.iter().find(|held| held.shard == shard);
                let records = found.and_then(|held| held.records.as_ref().ok()?.as_ref());
                let record = records.map(|records| records.record);
                if record.is_some_and(|record| record.owner == host || record.standby == Some(host))
                {
                    self.breaks
                        .push(format!("{shard:?}: {step:?} names role host {host:?}"));
                }
            }
        }
        let steps = &survey.plan.steps;
        let released = (steps.iter()).position(|step| matches!(step, Step::ReleaseAttach { .. }));
        let called = (steps.iter())
            .rposition(|step| matches!(step, Step::Attach { .. } | Step::Detach { .. }));
        if released
            .zip(called)
            .is_some_and(|(release, call)| call > release)
        {
            self.breaks
                .push(format!("a call step follows a gone mark: {steps:?}"));
        }
        let mut stripped = survey.clone();
        let ending = |step: &Step| matches!(step, Step::End { .. });
        stripped
            .plan
            .steps
            .retain(|step| self.ends || !ending(step));
        if !self.withholds {
            restore_withheld(&mut stripped);
        }
        if !self.slot_host {
            super::slot_host::restore_protected(&mut stripped);
        }
        let survey = &stripped;
        let mut calls = Calls {
            world: &mut self.fixture.world,
            faults: &self.faults,
        };
        let outcomes = self.zone.actuate(&gate, survey, self.now_us, &mut calls);
        let after = self.snapshot();
        self.breaks.extend(order_breaks(&before, &after));
        outcomes.unwrap()
    }

    pub(super) fn tick(&mut self) -> (Survey, Vec<Outcome>) {
        let survey = self.survey();
        let outcomes = self.actuate(&survey);
        self.enroll_listed();
        if self.drops {
            self.drop_ended_pairs();
        }
        if self.faults.borrow().dead {
            self.restart();
        }
        self.now_us += 10 * S;
        (survey, outcomes)
    }

    pub(super) fn enroll_listed(&mut self) {
        let gate = StandbyGate::qualified();
        let bounds: Bounds = *self.bounds.bounds();
        let store = HostStore {
            store: self.store().clone(),
            faults: self.faults.clone(),
        };
        let mut client = Client::open(store, MemLog::default()).unwrap();
        for number in 1..=self.fixture.shards {
            let active = self.shard(number).active;
            let held: VolumeRecord = stored(self.store(), Key::Volume(active));
            let attached = self.listed(number);
            let waiting: Vec<(Host, InstanceId)> = (held.live_hosts())
                .filter(|&live| held.enrolled(live).is_none())
                .filter(|live| !self.unenrolled.contains(&live.get()))
                .filter_map(|live| Some((live, held.event(held.live(live)?)?.instance?)))
                .filter(|(_, bound)| attached.iter().any(|id| id == bound.as_str()))
                .collect();
            for (standby, bound) in waiting {
                let holder = Holder {
                    volume: active,
                    host: standby,
                    instance: bound,
                };
                let persist = |key| {
                    let binding = Binding {
                        instance: bound.as_str().to_owned(),
                        volume: active.as_str().to_owned(),
                        attachment: format!("{}-attach", bound.as_str()),
                    };
                    let tag = standby.get() as u8;
                    Ok(LocalRecord::fresh(binding, key, || Some([tag; 16])).unwrap())
                };
                let held =
                    enroll_standby(&gate, shard(number), &holder, &bounds, &mut client, persist);
                drop(held);
            }
        }
    }

    pub(super) fn drop_ended_pairs(&mut self) {
        let mut client = owner(self.store());
        for number in 1..=self.fixture.shards {
            let active = self.shard(number).active;
            let read = client.read::<VolumeRecord>(Key::Volume(active)).unwrap();
            let held = read.value();
            let ended = |attach: u32| {
                (held.event(attach)).is_some_and(|event| event.kind == EventKind::Ended)
            };
            if held.pairs.iter().any(|pair| ended(pair.attach)) {
                let mut next = held.clone();
                next.pairs.retain(|pair| !ended(pair.attach));
                client.replace(&read, next).unwrap();
            }
        }
    }

    pub(super) fn run_until(&mut self, ticks: usize, done: impl Fn(&Self) -> bool) -> Vec<Outcome> {
        let mut seen = Vec::new();
        for _ in 0..ticks {
            let (_, outcomes) = self.tick();
            seen.extend(outcomes);
            if done(self) {
                return seen;
            }
        }
        panic!("no fixpoint within {ticks} ticks: {seen:?}");
    }

    pub(super) fn designated(&self) -> bool {
        (1..=self.fixture.shards).all(|number| self.shard(number).standby.is_some())
    }

    pub(super) fn lose(&mut self, n: u64) {
        let mut found = self.fixture.world.instances.iter_mut();
        let listed = found.find(|listed| listed.instance == instance(n)).unwrap();
        listed.state = InstanceState::Terminated;
        self.silent.push(n);
    }

    pub(super) fn attach_calls(&self) -> Vec<(VolumeId, InstanceId)> {
        let events = self.fixture.world.events();
        let calls = events.iter().filter_map(|event| match *event {
            Event::Attach(volume, instance) => Some((volume, instance)),
            _ => None,
        });
        calls.collect()
    }

    pub(super) fn listed(&self, number: u32) -> Vec<String> {
        let active = self.shard(number).active;
        let rows = self.fixture.world.volumes.iter();
        let row = rows.clone().find(|row| row.volume == active);
        row.map(|row| row.attachments.clone()).unwrap_or_default()
    }

    pub(super) fn planned(&mut self, wanted: impl Fn(&Step) -> bool) -> Survey {
        for _ in 0..60 {
            let survey = self.survey();
            if survey.plan.steps.iter().any(&wanted) {
                return survey;
            }
            self.actuate(&survey);
            self.enroll_listed();
            self.now_us += 10 * S;
        }
        panic!("no survey within 60 ticks plans the step");
    }

    fn move_slot(&self, from: Host) -> Host {
        let gate = StandbyGate::qualified();
        let mut other = Reconciler::new(reconciler_client(self.store()));
        let next = if from == host(1) { host(3) } else { host(1) };
        let report = crate::failover::standbys::tests::roomy(next);
        let population = Population { cap: 8 };
        let lost = |h| h == from;
        let zone = bounds();
        let slot = other.reserve(
            &gate,
            &population,
            zone.bounds(),
            ZONE,
            shard(1),
            &report,
            |_| None,
            lost,
        );
        assert_eq!(slot.unwrap().host(), next);
        next
    }

    pub(super) fn clean(&self) {
        assert!(self.breaks.is_empty(), "{:?}", self.breaks);
        let world = &self.fixture.world;
        assert!(world.breaks.is_empty(), "{:?}", world.breaks);
    }

    /// Arms `arm` for the loop's next store write or control-plane request; the loop keeps running after it.
    pub(super) fn fault_next(&mut self, arm: Arm) {
        let mut faults = self.faults.borrow_mut();
        faults.survives = true;
        faults.at = Some((faults.effects, arm));
    }

    /// Marks `host` draining in the directory the next survey reads.
    pub(super) fn drain(&mut self, host: Host) {
        let mut listing = self.fixture.listing.clone().unwrap();
        listing.version += 1;
        let at = listing.hosts.iter().position(|entry| entry.host == host);
        listing.hosts[at.unwrap()].state = DirectoryState::Draining;
        self.fixture.listing = Some(listing);
    }

    /// The number of store writes the loop's client made since `from`, an index into the world's event log.
    pub(super) fn writes_since(&self, from: usize) -> usize {
        let events = self.fixture.world.events();
        let writes = events[from..].iter();
        writes
            .filter(|seen| matches!(seen, Event::Write(_)))
            .count()
    }
}

pub(super) fn fence(store: &Shared, number: u32) {
    let mut client = owner(store);
    let record: ShardRecord = stored(store, Key::Shard(shard(number)));
    let page = client
        .read::<CoveragePage>(Key::Page(shard(number), 0))
        .unwrap();
    let fenced = CoveragePage {
        fence: (record.generation.get() << 32) | 2,
        ..page.value().clone()
    };
    client.replace(&page, fenced).unwrap();
}

/// Replaces the release of each shard whose plan reads an unreserved standby enrollment refused `CensusFull` with the
/// reservation the plan withheld, placed before the first release, as a planner without FRESH-FIRST plans it.
fn restore_withheld(survey: &mut Survey) {
    let Ok(view) = &survey.observation.zone else {
        return;
    };
    let plan = &mut survey.plan;
    let withheld: Vec<Step> = (plan.shards.iter())
        .filter(|held| {
            held.blocker == Some(crate::failover::zone_loop::status::Blocker::CensusFull)
        })
        .filter_map(|held| match held.state {
            ShardState::Enrolling {
                need: Need::Standby,
                phase: crate::failover::zone_loop::status::EnrollPhase::Unreserved,
                host,
            } => {
                let found = view.shards.iter().find(|shard| shard.shard == held.shard)?;
                let records = found.records.as_ref().ok()?.as_ref()?;
                let target = Target::of(&records.record);
                Some(Step::Reserve {
                    shard: held.shard,
                    host,
                    target,
                })
            }
            _ => None,
        })
        .collect();
    for step in withheld {
        let shard = step.shard();
        let releasing =
            |planned: &Step| matches!(planned, Step::Release { .. }) && planned.shard() == shard;
        plan.steps.retain(|planned| !releasing(planned));
        let at = (plan.steps.iter()).position(|planned| matches!(planned, Step::Release { .. }));
        plan.steps.insert(at.unwrap_or(plan.steps.len()), step);
    }
}

pub(super) fn order_breaks(before: &Snapshot, after: &Snapshot) -> Vec<String> {
    let mut breaks = Vec::new();
    for ((was, prior), (now, held)) in before.shards.iter().zip(&after.shards) {
        if now.active != was.active {
            continue;
        }
        for event in held.events.iter().filter(|event| event.seq >= prior.next) {
            let slot = (after.census.as_ref()).and_then(|census| census.slot(now.shard));
            if event.kind == EventKind::Attach && slot.is_none_or(|slot| slot.host != event.host) {
                breaks.push(format!(
                    "{:?}: {:?} entered before its slot",
                    now.shard, event.host
                ));
            }
        }
        if let Some(named) = now.standby.filter(|&named| was.standby != Some(named))
            && prior.enrolled(named).is_none()
        {
            breaks.push(format!("{:?}: {named:?} named before its pair", now.shard));
        }
    }
    breaks
}

pub(super) fn advanced(outcomes: &[Outcome]) -> Vec<&'static str> {
    let advance = outcomes
        .iter()
        .filter(|outcome| outcome.verdict == Verdict::Advance);
    advance
        .map(|outcome| match outcome.step {
            Step::Reserve { .. } => "reserve",
            Step::RecordAttach { .. } => "record",
            Step::Attach { .. } => "attach",
            Step::Designate { .. } => "designate",
            Step::Release { .. } => "release",
            Step::End { .. } => "end",
            Step::Detach { .. } => "detach",
            Step::ReleaseAttach { .. } => "gone",
            Step::Replace { .. } => "replace",
        })
        .collect()
}

pub(super) fn hosts_of(held: &VolumeRecord) -> Vec<Host> {
    held.events.iter().map(|event| event.host).collect()
}

pub(super) fn keeps_volume(cell: &Cell, before: &Snapshot) -> bool {
    let after = cell.snapshot();
    let kept = (before.shards.iter().zip(&after.shards))
        .all(|((was, _), (now, _))| (was.generation, was.active) == (now.generation, now.active));
    let held = cell.store().0.borrow();
    let receipts = (1..=cell.fixture.shards)
        .all(|number| held.commit_count(&Key::Replacement(shard(number))) == 0);
    kept && held.flips.is_empty() && receipts
}

#[test]
fn a_lost_standby_is_replaced_by_one_recorded_attached_enrolled_designated_host() {
    let mut cell = Cell::new(6, 1);
    let owner = owner_of(1, 6);
    let bound = |cell: &Cell| {
        let held = cell.volume(1);
        held.event(held.live(owner).unwrap()).unwrap().instance
    };
    assert_eq!(bound(&cell), None);
    let first = cell.run_until(40, |cell| cell.shard(1).standby.is_some());
    assert_eq!(
        advanced(&first),
        ["reserve", "record", "attach", "designate"]
    );
    assert_eq!(bound(&cell), Some(instance(owner.get())));
    let standby = cell.shard(1).standby.unwrap();
    let held = cell.volume(1);
    let entry = held.event(held.live(standby).unwrap()).unwrap();
    assert_eq!(entry.instance, Some(instance(standby.get())));
    assert!(held.enrolled(standby).is_some());
    let before = cell.snapshot();

    cell.lose(standby.get());
    let replaced = |cell: &Cell| cell.shard(1).standby.is_some_and(|named| named != standby);
    cell.run_until(60, replaced);
    let (after, successor) = (cell.shard(1), cell.shard(1).standby.unwrap());
    let was = before.shards[0].0;
    assert_eq!(
        (after.generation, after.active, after.owner, after.attempts),
        (was.generation, was.active, was.owner, was.attempts)
    );
    assert_eq!(
        hosts_of(&cell.volume(1)),
        [owner_of(1, 6), standby, successor]
    );
    assert_eq!(
        cell.attach_calls(),
        [
            (volume(1), instance(standby.get())),
            (volume(1), instance(successor.get()))
        ]
    );
    let listed = cell.listed(1);
    let rows = listed
        .iter()
        .filter(|id| *id == instance(successor.get()).as_str());
    assert_eq!(rows.count(), 1);
    cell.clean();
    assert!(keeps_volume(&cell, &before));
}

#[test]
fn an_attach_request_before_its_entry_fails_the_order_check() {
    let mut cell = Cell::new(6, 1);
    Attacher::attach(&mut cell.fixture.world, volume(1), instance(3));
    let breaks = cell.fixture.world.breaks.len();
    assert_eq!(breaks, 1, "an attach request before its recorded entry");
    let snapshot = cell.snapshot();
    let mut entered = snapshot.clone();
    entered.shards[0]
        .1
        .push(EventKind::Attach, host(3), 2)
        .unwrap();
    assert_eq!(order_breaks(&snapshot, &entered).len(), 1);
    let mut named = snapshot.clone();
    named.shards[0].0.standby = Some(host(3));
    assert_eq!(order_breaks(&snapshot, &named).len(), 1);
}

#[test]
fn owner_and_standby_loss_designates_a_fresh_host_on_the_retained_volume() {
    let mut cell = Cell::new(6, 2);
    cell.run_until(60, Cell::designated);
    let before = cell.snapshot();
    let (owner, standby) = (cell.shard(1).owner, cell.shard(1).standby.unwrap());
    cell.lose(owner.get());
    cell.lose(standby.get());
    let mut needs = Vec::new();
    let fresh = |cell: &Cell| cell.shard(1).standby.is_some_and(|named| named != standby);
    for _ in 0..80 {
        let (survey, _) = cell.tick();
        let states = survey
            .plan
            .shards
            .iter()
            .filter(|plan| plan.shard == shard(1));
        needs.extend(states.filter_map(|plan| match plan.state {
            ShardState::Enrolling { need, .. } => Some(need),
            _ => None,
        }));
        if fresh(&cell) {
            break;
        }
    }
    assert!(fresh(&cell));
    assert!(
        !needs.is_empty() && needs.iter().all(|&need| need == Need::Fresh),
        "{needs:?}"
    );
    assert_eq!(cell.shard(1).owner, owner);
    assert!(keeps_volume(&cell, &before));
    cell.clean();

    let spare = cell.fixture.spare();
    let release = crate::failover::reconcile::OperatorRelease::diagnosed();
    let record = cell.shard(2);
    let request = crate::failover::retire::Retirement::new(
        record.active,
        crate::failover::retire::Role::Active,
        Target::of(&record),
        crate::failover::retire::Trigger::VolumeState,
    );
    let mut planted = Reconciler::new(reconciler_client(cell.store()));
    let flipped = planted.flip_for(&release, shard(2), &request.unwrap());
    assert!(flipped.is_ok(), "{flipped:?} over {spare:?}");
    assert!(!keeps_volume(&cell, &before));
}

#[test]
fn an_unfenced_generation_waits_owner_not_ready_and_a_same_generation_takeover_proceeds() {
    let mut cell = Cell::with(6, 1, false, bounds());
    let mut waits = 0;
    for _ in 0..20 {
        let (_, outcomes) = cell.tick();
        let waiting = outcomes
            .iter()
            .filter(|outcome| outcome.verdict == Verdict::Wait(Reason::OwnerNotReady));
        waits += waiting.count();
    }
    assert!(waits > 0);
    assert!(cell.attach_calls().is_empty());
    assert_eq!(hosts_of(&cell.volume(1)), [owner_of(1, 6)]);
    fence(cell.store(), 1);
    cell.run_until(20, |cell| cell.shard(1).standby.is_some());
    let standby = cell.shard(1).standby.unwrap();
    let mut owner = owner(cell.store());
    let read = owner.read::<ShardRecord>(Key::Shard(shard(1))).unwrap();
    owner
        .take_over(&read, Target::of(read.value()), standby)
        .unwrap();
    let successor = cell.shard(1);
    assert_eq!((successor.owner, successor.standby), (standby, None));
    cell.run_until(40, |cell| cell.shard(1).standby.is_some());
    cell.clean();
}

#[test]
fn an_unknown_attach_reply_is_retried_only_while_unlisted_and_after_the_settle_time() {
    let settle_us = bounds().config().attach_settle_us;
    for attached in [true, false] {
        let mut cell = Cell::new(6, 1);
        let faults = &mut cell.fixture.world.faults.attach;
        faults.push_back(AttachFault::Unknown { attached });
        let mut requests = Vec::new();
        let mut unknown = Vec::new();
        for _ in 0..40 {
            let at = cell.now_us;
            let (_, outcomes) = cell.tick();
            let made = outcomes.iter().filter(|outcome| outcome.reply.is_some());
            requests.extend(made.clone().map(|_| at));
            let replied = made.filter(|outcome| outcome.reply == Some(AttachReply::Unknown));
            unknown.extend(replied.map(|outcome| outcome.verdict));
            if cell.shard(1).standby.is_some() {
                break;
            }
        }
        assert_eq!(unknown, [Verdict::Wait(Reason::Unknown)]);
        let standby = cell.shard(1).standby.unwrap();
        match attached {
            true => assert_eq!(requests.len(), 1),
            false => {
                assert_eq!(requests.len(), 2);
                assert!(requests[1] - requests[0] >= settle_us, "{requests:?}");
            }
        }
        let listed = cell.listed(1);
        let rows = listed
            .iter()
            .filter(|id| *id == instance(standby.get()).as_str());
        assert_eq!(rows.count(), 1);
        let calls = cell.attach_calls();
        assert_eq!(calls.len(), requests.len());
        assert!(
            calls
                .iter()
                .all(|&call| call == (volume(1), instance(standby.get())))
        );
        cell.clean();
    }
}

#[test]
fn a_refused_attach_retries_the_same_host_with_backoff_until_the_stuck_bound_moves_the_slot() {
    let run = |stuck_us: u64| {
        let mut config = config_of(8);
        config.attach_stuck_us = stuck_us;
        let mut cell = Cell::with(6, 1, true, config.validate().unwrap());
        cell.fixture
            .world
            .faults
            .attach
            .extend([AttachFault::Refuse; 64]);
        let mut requests = Vec::new();
        let mut ended = None;
        let mut candidate = None;
        for _ in 0..300 {
            let at = cell.now_us;
            let (_, outcomes) = cell.tick();
            for outcome in &outcomes {
                if outcome.reply.is_some() && ended.is_none() {
                    requests.push(at);
                    let refused = Verdict::Wait(Reason::AttachRefused(AttachRefusal::Other));
                    assert_eq!(outcome.verdict, refused);
                }
                if outcome.reclaim == Some(Reclaim::Ended) {
                    ended.get_or_insert(at);
                    let Step::End { host: stuck, .. } = outcome.step else {
                        panic!("{outcome:?}");
                    };
                    let reserved = outcomes.iter().any(|later| {
                        matches!(later.step, Step::Reserve { host, .. } if host != stuck)
                            && later.verdict == Verdict::Advance
                    });
                    assert!(reserved, "the slot moves in the end's tick: {outcomes:?}");
                    let census = census_of(cell.store()).unwrap();
                    assert_ne!(census.slot(shard(1)).unwrap().host, stuck);
                }
            }
            let slot = census_of(cell.store()).and_then(|census| census.slot(shard(1)));
            if candidate.is_none() && hosts_of(&cell.volume(1)).len() == 2 {
                candidate = slot.map(|slot| slot.host);
            }
            if ended.is_some() && cell.shard(1).standby.is_some() {
                break;
            }
            if ended.is_some() {
                cell.fixture.world.faults.attach.clear();
            }
        }
        (cell, requests, ended, candidate.unwrap())
    };
    let config = bounds().config().clone();
    let (cell, requests, ended, candidate) = run(config.attach_stuck_us);
    let gaps: Vec<u64> = requests.windows(2).map(|pair| pair[1] - pair[0]).collect();
    assert!(gaps.windows(2).all(|pair| pair[1] >= pair[0]), "{gaps:?}");
    assert!(gaps[0] >= config.attach_settle_us && gaps[1] >= 2 * config.attach_settle_us);
    let tick = 10 * S;
    let (settle, stuck) = (config.attach_settle_us, config.attach_stuck_us);
    let expected: Vec<u64> = (1..=gaps.len() as u32)
        .map(|refusals| backoff_us(settle, stuck, refusals).div_ceil(tick) * tick)
        .collect();
    assert_eq!(gaps, expected);
    let last = *requests
        .iter()
        .filter(|&&at| Some(at) < ended)
        .max()
        .unwrap();
    assert!(
        ended.is_some_and(|at| at - last >= config.attach_stuck_us),
        "{ended:?}"
    );
    let standby = cell.shard(1).standby.unwrap();
    assert_ne!(standby, candidate);
    assert_eq!(
        hosts_of(&cell.volume(1)),
        [owner_of(1, 6), candidate, standby]
    );
    assert!(cell.volume(1).ended(candidate));
    let listed = cell.listed(1);
    assert!(
        listed
            .iter()
            .any(|id| id == instance(standby.get()).as_str())
    );
    cell.clean();

    let (cell, _, ended, candidate) = run(u64::MAX / 4);
    assert_eq!(ended, None);
    let slot = census_of(cell.store()).unwrap().slot(shard(1)).unwrap();
    assert_eq!(slot.host, candidate);
    assert_eq!(hosts_of(&cell.volume(1)), [owner_of(1, 6), candidate]);
}

#[test]
fn the_backoff_doubles_the_settle_time_per_refusal_up_to_the_stuck_time() {
    let stuck = 1 << 20;
    assert_eq!(backoff_us(1, stuck, 0), 1);
    assert_eq!(backoff_us(1, stuck, 16), 1 << 16);
    assert_eq!(backoff_us(1, stuck, 17), 1 << 17);
    assert_eq!(backoff_us(1, stuck, 20), stuck);
    assert_eq!(backoff_us(1, stuck, 64), stuck);
    assert_eq!(backoff_us(3, u64::MAX, 70), u64::MAX);
    assert_eq!(backoff_us(3, 1000, 63), 1000);
}

#[test]
fn an_owner_bump_after_the_attach_entry_retargets_the_slot_with_no_new_entry() {
    let mut cell = Cell::new(6, 1);
    cell.run_until(40, |cell| hosts_of(&cell.volume(1)).len() == 2);
    let candidate = hosts_of(&cell.volume(1))[1];
    let mut owner = owner(cell.store());
    let read = owner.read::<ShardRecord>(Key::Shard(shard(1))).unwrap();
    owner.bump(&read).unwrap();
    let bumped = Target::of(&cell.shard(1));
    cell.run_until(40, |cell| cell.shard(1).standby.is_some());
    let record = cell.shard(1);
    assert_eq!(
        (record.standby, Target::of(&record)),
        (Some(candidate), bumped)
    );
    assert_eq!(hosts_of(&cell.volume(1)), [owner_of(1, 6), candidate]);
    let slot = census_of(cell.store()).unwrap().slot(shard(1)).unwrap();
    assert_eq!((slot.host, slot.target), (candidate, bumped));
    cell.clean();
}

#[test]
fn a_candidate_lost_after_its_entry_is_ended_and_its_slot_moves() {
    let mut cell = Cell::new(12, 1);
    cell.run_until(40, |cell| hosts_of(&cell.volume(1)).len() == 2);
    let first = hosts_of(&cell.volume(1))[1];
    cell.lose(first.get());
    cell.run_until(60, |cell| cell.shard(1).standby.is_some());
    let second = cell.shard(1).standby.unwrap();
    assert_ne!(first, second);
    let held = cell.volume(1);
    assert_eq!(hosts_of(&held), [owner_of(1, 12), first, second]);
    assert!(held.ended(first) && held.live(second).is_some());
    cell.clean();
}

fn converged(cell: &Cell, shard_commits: &BTreeMap<u32, usize>) -> Result<(), String> {
    for number in 1..=cell.fixture.shards {
        let record = cell.shard(number);
        let standby = record
            .standby
            .ok_or(format!("shard {number} names no standby"))?;
        let hosts = hosts_of(&cell.volume(number));
        if hosts != [owner_of(number, cell.fixture.hosts), standby] {
            return Err(format!("shard {number} entries {hosts:?}"));
        }
        let listed = cell.listed(number);
        let named = instance(standby.get());
        let ours = listed.iter().filter(|id| *id == named.as_str()).count();
        if ours != 1 || listed.len() != 2 {
            return Err(format!("shard {number} listing {listed:?}"));
        }
        let key = Key::Shard(shard(number));
        let commits = cell.store().0.borrow().commit_count(&key);
        if commits != shard_commits[&number] + 1 {
            return Err(format!("shard {number}: {commits} shard record commits"));
        }
    }
    let census = census_of(cell.store()).ok_or("no census")?;
    if census.len() > bounds().config().population_cap {
        return Err(format!("census of {}", census.len()));
    }
    Ok(())
}

#[test]
fn a_crash_at_every_enrollment_effect_converges_on_one_designation_and_attachment() {
    let mut baseline = Cell::new(4, 2);
    let commits: BTreeMap<u32, usize> = (1..=2)
        .map(|n| {
            let key = Key::Shard(shard(n));
            (n, baseline.store().0.borrow().commit_count(&key))
        })
        .collect();
    baseline.run_until(80, Cell::designated);
    for _ in 0..5 {
        baseline.tick();
    }
    converged(&baseline, &commits).unwrap();
    let effects = baseline.faults.borrow().effects;
    assert!(effects >= 10, "{effects} effects");
    let arms = [
        Arm::Pass,
        Arm::Timeout { commit: true },
        Arm::Timeout { commit: false },
    ];
    let mut failures = Vec::new();
    for at in 0..effects {
        for arm in arms {
            let mut cell = Cell::new(4, 2);
            cell.faults.borrow_mut().at = Some((at, arm));
            for _ in 0..120 {
                cell.tick();
                if cell.restarts > 0 && cell.designated() {
                    break;
                }
            }
            for _ in 0..8 {
                cell.tick();
            }
            let mut result = converged(&cell, &commits);
            if result.is_ok() && cell.restarts != 1 {
                result = Err(format!("{} restarts", cell.restarts));
            }
            if result.is_ok() && !cell.breaks.is_empty() {
                result = Err(format!("{:?}", cell.breaks));
            }
            if result.is_ok() && !cell.fixture.world.breaks.is_empty() {
                result = Err(format!("{:?}", cell.fixture.world.breaks));
            }
            let calls = cell.attach_calls();
            let distinct: std::collections::BTreeSet<_> = calls.iter().collect();
            if result.is_ok() && distinct.len() != calls.len() {
                result = Err(format!("repeated attach requests {calls:?}"));
            }
            if let Err(why) = result {
                failures.push(format!("effect {at} under {arm:?}: {why}"));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn two_loops_racing_at_the_census_designate_one_host() {
    let mut cell = Cell::new(6, 1);
    let (hook, after) = (Hook::default(), After::default());
    let other = Cell::open(&cell.fixture, &cell.faults, &hook, &after, &cell.bounds);
    let second = Rc::new(RefCell::new(other));
    let mut raced = None;
    for _ in 0..60 {
        let mine = cell.survey();
        let directory = Ok(cell.fixture.directory());
        let theirs = (second.borrow_mut()).survey(directory, &mut cell.fixture.world, cell.now_us);
        let reserving = (mine.plan.steps.iter()).any(|step| matches!(step, Step::Reserve { .. }));
        let race = reserving && raced.is_none();
        if race {
            let (other, now_us, theirs) = (second.clone(), cell.now_us, theirs.clone());
            *cell.hook.borrow_mut() = Some((
                Key::Standbys(ZONE),
                Box::new(move || {
                    let gate = StandbyGate::qualified();
                    let mut idle = World::new(ZONE);
                    let done = other
                        .borrow_mut()
                        .actuate(&gate, &theirs, now_us, &mut idle);
                    let done = done.unwrap();
                    assert!(
                        done.iter().all(|o| o.verdict == Verdict::Advance),
                        "{done:?}"
                    );
                }),
            ));
        }
        let outcomes = cell.actuate(&mine);
        if race {
            raced = Some(outcomes);
        } else {
            let gate = StandbyGate::qualified();
            let before = cell.snapshot();
            let world = &mut cell.fixture.world;
            let done = second
                .borrow_mut()
                .actuate(&gate, &theirs, cell.now_us, world);
            done.unwrap();
            let after = cell.snapshot();
            cell.breaks.extend(order_breaks(&before, &after));
        }
        cell.enroll_listed();
        cell.now_us += 10 * S;
        if cell.shard(1).standby.is_some() {
            break;
        }
    }
    let raced = raced.unwrap();
    let moved = raced
        .iter()
        .any(|o| o.verdict == Verdict::Wait(Reason::Moved));
    assert!(moved, "{raced:?}");
    let standby = cell.shard(1).standby.unwrap();
    assert_eq!(hosts_of(&cell.volume(1)), [owner_of(1, 6), standby]);
    let census = census_of(cell.store()).unwrap();
    assert_eq!(census.len(), 1);
    assert_eq!(census.slot(shard(1)).unwrap().host, standby);
    assert_eq!(cell.attach_calls().len(), 1);
    cell.clean();
}

/// C71: a second loop reads the designated host lost and moves the census slot between `designate`'s census read and
/// its shard write. The designation commits by its exact-version write over the unchanged shard read, so the shard
/// names a standby whose census slot names another host, at the same generation, owner and active volume. The next
/// ticks record, attach, enroll and designate the slot's host over it, and the shard never names a second owner.
#[test]
fn a_slot_moved_inside_a_designation_leaves_a_named_standby_the_slots_host_replaces() {
    let mut cell = Cell::new(6, 1);
    let designating = |step: &Step| matches!(step, Step::Designate { .. });
    let survey = cell.planned(designating);
    let Some(&Step::Designate { host: first, .. }) =
        survey.plan.steps.iter().find(|s| designating(s))
    else {
        unreachable!()
    };
    let before = cell.shard(1);
    let store = cell.store().clone();
    let next = if first == host(1) { host(3) } else { host(1) };
    *cell.hook.borrow_mut() = Some((
        Key::Shard(shard(1)),
        Box::new(move || {
            let gate = StandbyGate::qualified();
            let mut other = Reconciler::new(reconciler_client(&store));
            let report = crate::failover::standbys::tests::roomy(next);
            let population = Population { cap: 8 };
            let zone = bounds();
            let slot = other.reserve(
                &gate,
                &population,
                zone.bounds(),
                ZONE,
                shard(1),
                &report,
                |_| None,
                |h| h == first,
            );
            assert_eq!(slot.unwrap().host(), next);
        }),
    ));
    cell.lose(first.get());
    let outcomes = cell.actuate(&survey);
    assert!(cell.hook.borrow().is_none(), "the shard write ran");
    let designated = outcomes.iter().find(|o| designating(&o.step)).unwrap();
    assert_eq!(designated.verdict, Verdict::Advance);
    let raced = cell.shard(1);
    assert_eq!(raced.standby, Some(first));
    let slot = census_of(cell.store()).unwrap().slot(shard(1)).unwrap();
    assert_eq!((slot.host, slot.target), (next, Target::of(&raced)));
    let tenure = |record: &ShardRecord| (record.generation, record.owner, record.active);
    assert_eq!(tenure(&raced), tenure(&before));
    cell.enroll_listed();
    cell.now_us += 10 * S;
    for _ in 0..60 {
        if cell.shard(1).standby == Some(next) {
            break;
        }
        cell.tick();
        assert_eq!(tenure(&cell.shard(1)), tenure(&before));
    }
    assert_eq!(cell.shard(1).standby, Some(next));
    assert!(cell.volume(1).enrolled(next).is_some());
    let census = census_of(cell.store()).unwrap();
    assert_eq!(census.len(), 1);
    assert_eq!(census.slot(shard(1)).unwrap().host, next);
    cell.clean();
}

#[test]
fn a_stale_census_read_fails_the_reservation_and_the_next_tick_converges() {
    let mut cell = Cell::new(6, 2);
    cell.run_until(80, Cell::designated);
    let owners: Vec<Host> = (1..=2).map(|n| cell.shard(n).owner).collect();
    let lost = cell.shard(1).standby.unwrap();
    cell.lose(lost.get());
    let mut stale = None;
    for _ in 0..60 {
        let survey = cell.survey();
        let only_reserve = matches!(survey.plan.steps.as_slice(), [Step::Reserve { .. }]);
        if only_reserve && stale.is_none() {
            cell.store().schedule(Arm::StaleRead);
            stale = Some(cell.actuate(&survey));
        } else {
            cell.actuate(&survey);
        }
        cell.enroll_listed();
        cell.now_us += 10 * S;
        if cell.shard(1).standby.is_some_and(|named| named != lost) {
            break;
        }
    }
    let stale = stale.unwrap();
    assert_eq!(stale[0].verdict, Verdict::Wait(Reason::Moved), "{stale:?}");
    assert!(cell.shard(1).standby.is_some_and(|named| named != lost));
    let after: Vec<Host> = (1..=2).map(|n| cell.shard(n).owner).collect();
    assert_eq!(owners, after);
    cell.clean();
}

#[test]
fn the_loop_reserves_a_fresh_need_before_a_standby_need() {
    let mut cell = Cell::new(9, 3);
    cell.run_until(80, Cell::designated);
    let (standby, fresh) = (cell.shard(1), cell.shard(3));
    cell.lose(fresh.owner.get());
    cell.lose(fresh.standby.unwrap().get());
    cell.lose(standby.standby.unwrap().get());
    let mut order = None;
    for _ in 0..60 {
        let (survey, outcomes) = cell.tick();
        let reserves: Vec<u32> = (outcomes.iter())
            .filter_map(|outcome| match outcome.step {
                Step::Reserve { shard, .. } if outcome.verdict == Verdict::Advance => {
                    Some(shard.get())
                }
                _ => None,
            })
            .collect();
        if reserves.len() >= 2 {
            order = Some((survey, reserves));
            break;
        }
    }
    let (survey, order) = order.expect("one tick reserves for both needs");
    let need = |number: u32| {
        let plan = survey
            .plan
            .shards
            .iter()
            .find(|plan| plan.shard == shard(number));
        match plan.map(|plan| plan.state) {
            Some(ShardState::Enrolling { need, .. }) => Some(need),
            _ => None,
        }
    };
    assert_eq!((need(3), need(1)), (Some(Need::Fresh), Some(Need::Standby)));
    assert_eq!(order[0], 3, "{order:?}");
    let at = |number| order.iter().position(|&n| n == number);
    assert!(at(1).is_some_and(|one| one > 0), "{order:?}");
    cell.clean();

    let mut config = config_of(8);
    config.writes_per_tick = 1;
    let mut cell = Cell::with(9, 3, true, config.validate().unwrap());
    cell.run_until(200, Cell::designated);
    let (standby, fresh) = (cell.shard(1), cell.shard(3));
    cell.lose(fresh.owner.get());
    cell.lose(fresh.standby.unwrap().get());
    cell.lose(standby.standby.unwrap().get());
    let reserving = |step: &Step, number: u32| matches!(*step, Step::Reserve { shard: at, .. } if at == shard(number));
    let survey = cell.planned(|step| reserving(step, 1));
    assert!(
        reserving(&survey.plan.steps[0], 3),
        "{:?}",
        survey.plan.steps
    );
    let outcomes = cell.actuate(&survey);
    let verdict = |number| {
        let found = outcomes
            .iter()
            .find(|o| reserving(&o.step, number))
            .unwrap();
        found.verdict
    };
    assert_eq!(verdict(3), Verdict::Advance);
    assert_eq!(verdict(1), Verdict::Wait(Reason::Budget));
    let census = census_of(cell.store()).unwrap();
    let slot = |number| census.slot(shard(number)).map(|slot| slot.host);
    assert_ne!(slot(3), fresh.standby);
    assert_eq!(slot(1), standby.standby);
}

#[test]
fn actuate_refuses_a_superseded_rewound_overrun_or_repeated_survey() {
    let gate = StandbyGate::qualified();
    let mut cell = Cell::new(6, 1);
    cell.run_until(40, |cell| census_of(cell.store()).is_some());
    let older = cell.survey();
    let latest = cell.survey();
    let now_us = cell.now_us;
    let tick_us = bounds().config().tick_us;
    let events = cell.fixture.world.events().len();
    let world = &mut cell.fixture.world;
    let mut refused = |survey: &Survey, at: u64| cell.zone.actuate(&gate, survey, at, world).err();
    assert_eq!(refused(&older, now_us), Some(Discard::Superseded));
    assert_eq!(refused(&latest, now_us - 1), Some(Discard::Rewound));
    assert_eq!(refused(&latest, now_us + tick_us), Some(Discard::Overrun));
    assert_eq!(cell.fixture.world.events().len(), events);
    let world = &mut cell.fixture.world;
    let last = now_us + tick_us - 1;
    assert!(cell.zone.actuate(&gate, &latest, last, world).is_ok());
    let events = cell.fixture.world.events().len();
    let world = &mut cell.fixture.world;
    let again = cell.zone.actuate(&gate, &latest, now_us + 1, world);
    assert_eq!(again.err(), Some(Discard::Repeated));
    assert_eq!(cell.fixture.world.events().len(), events);
}

#[test]
fn each_store_error_maps_to_its_verdict() {
    use crate::failover::standbys::Refusal as PopulationRefusal;
    use crate::storage::store::{Refusal, StoreError};
    let rows = [
        (
            ReconcileError::Store(StoreError::Unknown),
            Verdict::Wait(Reason::Unknown),
        ),
        (
            ReconcileError::Store(StoreError::Refused(Refusal::Condition)),
            Verdict::Wait(Reason::Moved),
        ),
        (ReconcileError::Stale, Verdict::Wait(Reason::Moved)),
        (ReconcileError::Conflict, Verdict::Wait(Reason::Moved)),
        (ReconcileError::Held, Verdict::Wait(Reason::Held)),
        (
            ReconcileError::Store(StoreError::Unavailable),
            Verdict::Wait(Reason::Store),
        ),
        (
            ReconcileError::Store(StoreError::Absent),
            Verdict::Wait(Reason::Store),
        ),
        (
            ReconcileError::Store(StoreError::Withdrawn),
            Verdict::Alarm(Reason::Withdrawn),
        ),
        (
            ReconcileError::Store(StoreError::Namespace),
            Verdict::Alarm(Reason::Withdrawn),
        ),
        (
            ReconcileError::Store(StoreError::Log),
            Verdict::Alarm(Reason::Withdrawn),
        ),
        (
            ReconcileError::Population(PopulationRefusal::Full),
            Verdict::Wait(Reason::Population(PopulationRefusal::Full)),
        ),
        (
            ReconcileError::Store(StoreError::Refused(Refusal::Denied)),
            Verdict::Alarm(Reason::Step(ReconcileError::Store(StoreError::Refused(
                Refusal::Denied,
            )))),
        ),
        (
            ReconcileError::Retry,
            Verdict::Alarm(Reason::Step(ReconcileError::Retry)),
        ),
    ];
    for (error, verdict) in rows {
        assert_eq!(verdict_of(error), verdict, "{error:?}");
    }
}

fn in_flight(cell: &Cell) -> usize {
    let Some(census) = census_of(cell.store()) else {
        return 0;
    };
    let pending = (1..=cell.fixture.shards).filter(|&number| {
        let record = cell.shard(number);
        census.slot(shard(number)).is_some_and(|slot| {
            slot.target == Target::of(&record)
                && record.standby != Some(slot.host)
                && !cell.silent.contains(&slot.host.get())
        })
    });
    pending.count()
}

fn starts_in_window(starts: &[u64], window_us: u64) -> usize {
    let windows = starts.iter().map(|&from| {
        let within = starts
            .iter()
            .filter(|&&at| at >= from && at - from < window_us);
        within.count()
    });
    windows.max().unwrap_or_default()
}

fn entries(cell: &Cell) -> usize {
    (1..=cell.fixture.shards)
        .map(|number| cell.volume(number).events.len())
        .sum()
}

#[test]
fn a_host_loss_storm_designates_every_shard_within_the_in_flight_and_start_rate_bounds() {
    let mut cell = Cell::with(12, 9, true, config_of(9).validate().unwrap());
    let config = cell.bounds.config().clone();
    let mut starts = Vec::new();
    let mut check = |cell: &mut Cell, ticks: usize, done: fn(&Cell) -> bool| {
        for _ in 0..ticks {
            let (before, at) = (entries(cell), cell.now_us);
            let (survey, _) = cell.tick();
            starts.extend(std::iter::repeat_n(at, entries(cell) - before));
            assert!(survey.plan.inflight <= config.enroll_inflight_max as usize);
            assert!(in_flight(cell) <= config.enroll_inflight_max as usize);
            if done(cell) {
                return;
            }
        }
        let (survey, _) = cell.tick();
        panic!("the storm did not settle: {:?}", survey.plan.shards);
    };
    check(&mut cell, 200, Cell::designated);
    let standbys: Vec<Host> = (1..=9).filter_map(|n| cell.shard(n).standby).collect();
    let mut lost: Vec<Host> = standbys.clone();
    lost.sort();
    lost.dedup();
    for host in lost.iter().take(2) {
        cell.lose(host.get());
    }
    let replaced = |cell: &Cell| {
        (1..=cell.fixture.shards).all(|number| {
            let named = cell.shard(number).standby;
            named.is_some_and(|named| !cell.silent.contains(&named.get()))
        })
    };
    check(&mut cell, 300, replaced);
    let window = config.attach_window_us;
    assert!(starts_in_window(&starts, window) <= config.attach_starts_per_window as usize);
    cell.clean();
}

#[test]
fn the_start_rate_bounds_new_attach_entries_in_every_window() {
    let mut config = config_of(8);
    config.enroll_inflight_max = 8;
    config.calls_per_tick = 9;
    config.attach_starts_per_window = 2;
    let mut cell = Cell::with(12, 6, true, config.validate().unwrap());
    let window = cell.bounds.config().attach_window_us;
    let mut starts = Vec::new();
    for _ in 0..400 {
        let (before, at) = (entries(&cell), cell.now_us);
        cell.tick();
        starts.extend(std::iter::repeat_n(at, entries(&cell) - before));
        if cell.designated() {
            break;
        }
    }
    assert!(cell.designated());
    assert_eq!(starts.len(), 6);
    assert_eq!(starts_in_window(&starts, window), 2, "{starts:?}");
    cell.clean();
}

#[test]
fn recorded_enrollments_finish_under_the_zone_host_hold_and_none_starts() {
    for hold in [true, false] {
        let mut zone = config_of(8);
        if !hold {
            zone.host_hold = crate::failover::zone_loop::config::Fraction {
                numerator: 99,
                denominator: 100,
            };
        }
        let mut cell = Cell::with(16, 5, true, zone.validate().unwrap());
        cell.fixture
            .world
            .faults
            .attach
            .extend([AttachFault::Refuse; 64]);
        let count = |cell: &Cell| {
            (1..=5)
                .filter(|&n| hosts_of(&cell.volume(n)).len() == 2)
                .count()
        };
        cell.run_until(60, |cell| count(cell) == 4);
        let waiting = (1..=5)
            .find(|&n| hosts_of(&cell.volume(n)).len() == 1)
            .unwrap();
        let census = census_of(cell.store()).unwrap();
        assert!(census.slot(shard(waiting)).is_none());
        let mut roles: Vec<Host> = (1..=5).map(|n| cell.shard(n).owner).collect();
        roles.extend((1..=5).filter_map(|n| census.slot(shard(n)).map(|slot| slot.host)));
        let idle: Vec<u64> = (1..=16).filter(|&n| !roles.contains(&host(n))).collect();
        for &n in &idle[..7] {
            cell.lose(n);
        }
        if hold {
            let mut held = false;
            for _ in 0..30 {
                let (survey, _) = cell.tick();
                if survey.plan.holds.zone_host {
                    held = true;
                    break;
                }
            }
            assert!(held);
        }
        cell.fixture.world.faults.attach.clear();
        let others_designated = |cell: &Cell| {
            (1..=5)
                .filter(|&n| n != waiting)
                .all(|n| cell.shard(n).standby.is_some())
        };
        let mut after = 0;
        for _ in 0..120 {
            let (survey, _) = cell.tick();
            if hold {
                assert!(survey.plan.holds.zone_host);
                let reserving = survey.plan.steps.iter().any(
                    |step| matches!(step, Step::Reserve { shard: at, .. } if *at == shard(waiting)),
                );
                assert!(!reserving);
            }
            if others_designated(&cell) {
                after += 1;
            }
            if after > 20 {
                break;
            }
        }
        assert!(others_designated(&cell));
        let started = hosts_of(&cell.volume(waiting)).len() > 1;
        assert_eq!(started, !hold, "hold {hold}: shard {waiting}");
        cell.clean();
    }
}

#[test]
fn a_fresh_host_the_loop_designates_takes_the_retained_volume_over() {
    use super::directory::{host_key, report_keys, shard_entry};
    use super::observe::host_state;
    use crate::failover::restart::tests::{self as restart_tests, Stored, shard_now, volume_id};
    use crate::failover::takeover::tests as takeover;
    use crate::failover::zone_loop::directory::{
        Directory, DirectoryState, HostEntry, Placement, ReconcilerProjection,
    };
    use crate::failover::zone_loop::evidence::{Instance, StatusCheck};
    use crate::failover::zone_loop::sources::ListedVolume;

    use crate::storage::store_tests::record as store_record;
    let store = restart_tests::store(takeover::shard_record(), takeover::with_c());
    takeover::fence_page_zero(&store);
    let (a, c, d) = (
        restart_tests::host(),
        takeover::c_host(),
        takeover::d_host(),
    );
    let instance_of = |h: Host| takeover::holder_of(h).instance;
    let roles = [a, c, d];
    let extras = (13..=18).map(host);
    let entries: Vec<HostEntry> = (roles.into_iter().chain(extras))
        .enumerate()
        .map(|(at, h)| HostEntry {
            host: h,
            instance: match roles.contains(&h) {
                true => instance_of(h),
                false => instance(h.get()),
            },
            placement: Placement {
                zone: ZONE,
                partition: crate::failover::arbiter::Partition((at % 3) as u32),
                color: Color((at % 2) as u16),
            },
            state: match roles.contains(&h) {
                true => DirectoryState::Active,
                false => DirectoryState::Draining,
            },
        })
        .collect();
    let spare = store_record().spare.unwrap();
    let mut provisioner = Reconciler::new(reconciler_client(&store));
    provisioner
        .provision(spare.0, crate::failover::sim::layout())
        .unwrap();
    provisioner
        .record_attach(spare.0, spare.1, crate::failover::records::ERA)
        .unwrap();
    let mut placed = listing(0, 0);
    placed.hosts = entries.clone();
    placed.shards = vec![shard_entry(crate::storage::store_tests::shard().get())];
    let directory = || -> Directory<ReconcilerProjection> {
        Directory::new(placed.clone(), report_keys(&placed)).unwrap()
    };
    let mut world = World::new(ZONE);
    for entry in &entries {
        let lost = [a, c].contains(&entry.host);
        world.instances.push(Instance {
            instance: entry.instance,
            state: match lost {
                true => InstanceState::Terminated,
                false => InstanceState::Running,
            },
            system_check: StatusCheck::Ok,
            instance_check: StatusCheck::Ok,
        });
    }
    world.volumes.push(ListedVolume {
        volume: volume_id(),
        condition: crate::failover::zone_loop::evidence::VolumeCondition {
            state: crate::failover::zone_loop::evidence::ListedVolumeState::InUse,
            status: crate::failover::zone_loop::evidence::VolumeStatus::Ok,
        },
        attachments: vec![
            instance_of(a).as_str().to_owned(),
            instance_of(c).as_str().to_owned(),
        ],
    });
    world.store = Some(store.clone());
    let recording = Recording {
        inner: AsReconciler(store.clone()),
        log: world.log.clone(),
    };
    let client = Client::open(recording, MemLog::default()).unwrap();
    let mut zone = ZoneLoop::new(Reconciler::new(client), bounds());
    let period = core::num::NonZeroU64::new(super::config::REPORT_PERIOD_US).unwrap();
    let live: Vec<Host> = entries
        .iter()
        .map(|e| e.host)
        .filter(|h| ![a, c].contains(h))
        .collect();
    let mut writers: Vec<_> = (live.iter())
        .map(|&h| crate::failover::report::Writer::new(h, &host_key(h.get()), period).unwrap())
        .collect();
    let state = crate::failover::report::HostState {
        headroom: Headroom {
            attachments: Gauge::known(0, 64),
            recovery: Gauge::known(0, 2),
            ..host_state().headroom
        },
        ..host_state()
    };
    let gate = StandbyGate::qualified();
    let bounds = bounds();
    let mut d_record = None;
    let mut now_us = START;
    for _ in 0..80 {
        for (writer, h) in writers.iter_mut().zip(&live) {
            let sealed = writer.seal(&state, &[], now_us, now_us).unwrap();
            world.reports.insert(*h, sealed);
        }
        let survey = zone.survey(Ok(directory()), &mut world, now_us);
        let outcomes = zone.actuate(&gate, &survey, now_us, &mut world).unwrap();
        assert!(
            outcomes
                .iter()
                .all(|outcome| outcome.verdict == Verdict::Advance)
        );
        let held: VolumeRecord = stored(&store, Key::Volume(volume_id()));
        let listed = world.volumes[0]
            .attachments
            .iter()
            .any(|id| id == instance_of(d).as_str());
        if held.live(d).is_some() && held.enrolled(d).is_none() && listed {
            let mut host_client = crate::storage::store_tests::client(&store);
            let holder = takeover::holder_of(d);
            let persist = |key: crate::failover::identity::Key| {
                let binding = Binding {
                    instance: instance_of(d).as_str().to_owned(),
                    ..crate::failover::assignment_tests::record()
                        .binding()
                        .clone()
                };
                let made = LocalRecord::fresh(binding, key, || Some([0x5d; 16])).unwrap();
                Ok(d_record.insert(made).clone())
            };
            let shard = crate::storage::store_tests::shard();
            enroll_standby(
                &gate,
                shard,
                &holder,
                bounds.bounds(),
                &mut host_client,
                persist,
            )
            .unwrap();
        }
        now_us += 10 * S;
        if shard_now(&store).standby == Some(d) {
            break;
        }
    }
    let designated = shard_now(&store);
    assert_eq!((designated.owner, designated.standby), (a, Some(d)));
    assert_eq!(
        (designated.generation, designated.active),
        (takeover::shard_record().generation, volume_id())
    );
    let d_record = d_record.unwrap();
    let reservation = takeover::a_holds_c_registered();
    let mut card = takeover::card_after_cas(&store, d_record.pair(), d, &reservation);
    let taken = takeover::takeover_of(&store, d).run(
        &mut crate::storage::store_tests::client(&store),
        &Stored(Ok(d_record.clone())),
        &mut card,
    );
    assert!(taken.is_ok(), "{:?}", taken.err());
    let after = shard_now(&store);
    assert_eq!(after, takeover::taken(&designated, d));
    assert_eq!(
        (after.generation, after.active),
        (takeover::shard_record().generation, volume_id())
    );
    assert!(store.0.borrow().flips.is_empty());
    assert!(world.breaks.is_empty(), "{:?}", world.breaks);
}

#[test]
fn a_slot_moved_after_the_survey_records_no_attach_entry() {
    let mut cell = Cell::new(6, 1);
    let mut survey = cell.planned(|step| matches!(step, Step::RecordAttach { .. }));
    let step = *survey
        .plan
        .steps
        .iter()
        .find(|step| matches!(step, Step::RecordAttach { .. }))
        .unwrap();
    let Step::RecordAttach {
        host: candidate, ..
    } = step
    else {
        unreachable!()
    };
    survey.plan.steps.push(step);
    cell.move_slot(candidate);
    let events = cell.fixture.world.events().len();
    let outcomes = cell.actuate(&survey);
    let census = Event::Read(Key::Standbys(ZONE));
    let reads = cell.fixture.world.events()[events..]
        .iter()
        .filter(|seen| **seen == census)
        .count();
    let recorded: Vec<Verdict> = (outcomes.iter())
        .filter(|outcome| outcome.step == step)
        .map(|outcome| outcome.verdict)
        .collect();
    assert_eq!(recorded, [Verdict::Wait(Reason::Moved); 2]);
    assert_eq!(reads, 1);
    assert!(!hosts_of(&cell.volume(1)).contains(&candidate));
    cell.now_us += 10 * S;
    cell.run_until(40, |cell| cell.shard(1).standby.is_some());
    assert!(!hosts_of(&cell.volume(1)).contains(&candidate));
    cell.clean();
}

#[test]
fn one_tick_makes_at_most_its_write_and_call_budgets_of_effects() {
    let mut config = config_of(8);
    config.writes_per_tick = 1;
    let mut cell = Cell::with(12, 4, true, config.validate().unwrap().with_calls(1));
    let mut budgeted = 0;
    for _ in 0..200 {
        let events = cell.fixture.world.events().len();
        let (_, outcomes) = cell.tick();
        let seen = &cell.fixture.world.events()[events..];
        let writes = seen.iter().filter(|e| matches!(e, Event::Write(_))).count();
        let calls = seen
            .iter()
            .filter(|e| matches!(e, Event::Attach(..)))
            .count();
        assert!(
            writes <= 1 && calls <= 1,
            "{writes} writes and {calls} calls"
        );
        let waiting = outcomes
            .iter()
            .filter(|o| o.verdict == Verdict::Wait(Reason::Budget));
        budgeted += waiting.count();
        if cell.designated() {
            break;
        }
    }
    assert!(cell.designated());
    assert!(budgeted > 0);
    cell.clean();
}

#[test]
fn each_tick_stops_its_effects_at_the_write_and_call_caps_and_the_next_tick_continues() {
    let mut config = config_of(8);
    config.writes_per_tick = 3;
    let mut cell = Cell::with(12, 6, true, config.validate().unwrap().with_calls(2));
    let calling = |step: &Step| matches!(step, Step::Attach { .. } | Step::Detach { .. });
    let writing = |step: &Step| !calling(step);
    let mut capped = (None, None);
    let mut after_cap = (0, 0);
    for at in 0..200 {
        let events = cell.fixture.world.events().len();
        let (_, outcomes) = cell.tick();
        let seen = &cell.fixture.world.events()[events..];
        let writes = seen.iter().filter(|e| matches!(e, Event::Write(_))).count();
        let calls = seen
            .iter()
            .filter(|e| matches!(e, Event::Attach(..) | Event::Detach(..)))
            .count();
        assert!(
            writes <= 3 && calls <= 2,
            "{writes} writes and {calls} calls"
        );
        let budgeted = |kind: &dyn Fn(&Step) -> bool| {
            (outcomes.iter()).any(|o| kind(&o.step) && o.verdict == Verdict::Wait(Reason::Budget))
        };
        if capped.0.map(|tick| tick + 1) == Some(at) {
            after_cap.0 = writes;
        }
        if capped.1.map(|tick| tick + 1) == Some(at) {
            after_cap.1 = calls;
        }
        if capped.0.is_none() && budgeted(&writing) {
            assert_eq!(writes, 3, "{outcomes:?}");
            capped.0 = Some(at);
        }
        if capped.1.is_none() && budgeted(&calling) {
            assert_eq!(calls, 2, "{outcomes:?}");
            capped.1 = Some(at);
        }
        if cell.designated() {
            break;
        }
    }
    assert!(capped.0.is_some() && capped.1.is_some(), "{capped:?}");
    assert!(after_cap.0 > 0 && after_cap.1 > 0, "{after_cap:?}");
    assert!(cell.designated());
    cell.clean();
}

fn attaching(step: &Step) -> bool {
    matches!(step, Step::Attach { .. })
}

fn attach_outcome(outcomes: &[Outcome]) -> Outcome {
    *outcomes
        .iter()
        .find(|outcome| attaching(&outcome.step))
        .unwrap()
}

fn candidate_of(survey: &Survey) -> Host {
    let found = survey.plan.steps.iter().find_map(|step| match *step {
        Step::Attach { host, .. } | Step::RecordAttach { host, .. } => Some(host),
        _ => None,
    });
    found.unwrap()
}

#[test]
fn an_attach_step_spends_a_call_only_when_it_sends_a_request() {
    let config = config_of(8);
    let mut cell = Cell::with(12, 2, true, config.validate().unwrap().with_calls(1));
    cell.fixture
        .world
        .faults
        .attach
        .push_back(AttachFault::Refuse);
    let mut budgeted = false;
    let mut first: BTreeMap<VolumeId, u64> = BTreeMap::new();
    for _ in 0..40 {
        let (events, at) = (cell.fixture.world.events().len(), cell.now_us);
        let (survey, outcomes) = cell.tick();
        let sent: Vec<VolumeId> = cell.fixture.world.events()[events..]
            .iter()
            .filter_map(|seen| match *seen {
                Event::Attach(volume, _) => Some(volume),
                _ => None,
            })
            .collect();
        assert!(sent.len() <= 1, "{sent:?}");
        for volume in sent {
            first.entry(volume).or_insert(at);
        }
        let attaches: Vec<&Outcome> = (outcomes.iter()).filter(|o| attaching(&o.step)).collect();
        let planned = survey
            .plan
            .steps
            .iter()
            .filter(|step| attaching(step))
            .count();
        budgeted |=
            planned >= 2 && (attaches.iter()).any(|o| o.verdict == Verdict::Wait(Reason::Budget));
        if cell.designated() {
            break;
        }
    }
    let starts: Vec<u64> = first.values().copied().collect();
    assert!(budgeted, "no tick planned two attaches against one call");
    assert_eq!(starts.len(), 2);
    assert_eq!(starts[0].abs_diff(starts[1]), 10 * S, "{starts:?}");
    assert!(cell.designated());
    cell.clean();
}

#[test]
fn a_retried_entry_leaves_the_call_to_an_entry_that_never_sent() {
    let config = config_of(8);
    let mut cell = Cell::with(12, 4, true, config.validate().unwrap().with_calls(1));
    let faults = &mut cell.fixture.world.faults.attach;
    faults.extend([AttachFault::Unknown { attached: false }; 64]);
    let mut first: BTreeMap<VolumeId, u64> = BTreeMap::new();
    for _ in 0..30 {
        let (events, at) = (cell.fixture.world.events().len(), cell.now_us);
        cell.tick();
        for seen in &cell.fixture.world.events()[events..] {
            if let Event::Attach(volume, _) = *seen {
                first.entry(volume).or_insert(at);
            }
        }
        if first.len() == 4 {
            break;
        }
    }
    let starts: Vec<u64> = first.values().copied().collect();
    assert_eq!(starts.len(), 4, "{starts:?}");
    let spread = starts.iter().max().unwrap() - starts.iter().min().unwrap();
    assert_eq!(spread, 30 * S, "{starts:?}");
    cell.clean();
}

#[test]
fn an_attach_planned_before_a_slot_move_or_an_owner_bump_sends_no_request() {
    for bump in [false, true] {
        let mut cell = Cell::new(6, 1);
        let survey = cell.planned(attaching);
        let candidate = candidate_of(&survey);
        if bump {
            let mut owner = owner(cell.store());
            let read = owner.read::<ShardRecord>(Key::Shard(shard(1))).unwrap();
            owner.bump(&read).unwrap();
        } else {
            cell.move_slot(candidate);
        }
        let calls = cell.attach_calls().len();
        let outcomes = cell.actuate(&survey);
        let outcome = attach_outcome(&outcomes);
        assert_eq!(
            (outcome.verdict, outcome.reply),
            (Verdict::Wait(Reason::Moved), None)
        );
        assert_eq!(cell.attach_calls().len(), calls);
        cell.clean();
    }
}

#[test]
fn an_entry_enrolled_after_the_survey_takes_no_attach_request() {
    let mut cell = Cell::new(6, 1);
    let survey = cell.planned(attaching);
    let candidate = candidate_of(&survey);
    let id = instance(candidate.get());
    cell.fixture.world.attach(volume(1), id);
    cell.enroll_listed();
    cell.fixture.world.detach(volume(1), id);
    assert!(cell.volume(1).enrolled(candidate).is_some());
    let outcomes = cell.actuate(&survey);
    let outcome = attach_outcome(&outcomes);
    assert_eq!((outcome.verdict, outcome.reply), (Verdict::Advance, None));
    assert!(cell.attach_calls().is_empty());
    cell.clean();
}

#[test]
fn an_entry_bound_to_another_instance_or_none_takes_no_attach_request() {
    for other in [Some(instance(5)), None] {
        let mut cell = Cell::new(6, 1);
        let mut survey = cell.planned(attaching);
        let candidate = candidate_of(&survey);
        let step = *survey
            .plan
            .steps
            .iter()
            .find(|step| attaching(step))
            .unwrap();
        survey.plan.steps.push(step);
        let mut store = cell.store().clone();
        let item = store
            .0
            .borrow()
            .current(&Key::Volume(volume(1)))
            .cloned()
            .unwrap();
        let mut rebound: VolumeRecord = stored(&store, Key::Volume(volume(1)));
        let seq = rebound.live(candidate).unwrap();
        let entry = rebound.events.iter_mut().find(|event| event.seq == seq);
        entry.unwrap().instance = other;
        let write = Write::Exact {
            expect: item.version,
            value: rebound.encoded(&Key::Volume(volume(1))).unwrap(),
        };
        let written = store.write(&Key::Volume(volume(1)), &write);
        assert!(matches!(written, Written::Committed(_)), "{written:?}");
        let events = cell.fixture.world.events().len();
        let outcomes = cell.actuate(&survey);
        let outcome = attach_outcome(&outcomes);
        assert_eq!(
            (outcome.verdict, outcome.reply),
            (Verdict::Alarm(Reason::Binding), None)
        );
        let verdicts: Vec<Verdict> = (outcomes.iter())
            .filter(|outcome| outcome.step == step)
            .map(|outcome| outcome.verdict)
            .collect();
        let stopped = Verdict::Wait(Reason::Moved);
        assert_eq!(verdicts, [Verdict::Alarm(Reason::Binding), stopped]);
        let reads = cell.fixture.world.events()[events..]
            .iter()
            .filter(|seen| **seen == Event::Read(Key::Volume(volume(1))))
            .count();
        assert_eq!(reads, 1);
        assert!(cell.attach_calls().is_empty(), "{other:?}");
    }
}

#[test]
fn an_unreadable_identifier_or_a_failed_listing_holds_the_attach_request() {
    for unreadable in [true, false] {
        let mut cell = Cell::new(6, 1);
        let survey = cell.planned(attaching);
        let row = cell
            .fixture
            .world
            .volumes
            .iter_mut()
            .find(|row| row.volume == volume(1));
        let row = row.unwrap();
        match unreadable {
            true => row.attachments.push("not-an-instance".to_owned()),
            false => cell.fixture.world.faults.attachments = true,
        }
        let outcomes = cell.actuate(&survey);
        let outcome = attach_outcome(&outcomes);
        assert_eq!(
            (outcome.verdict, outcome.reply),
            (Verdict::Wait(Reason::Unlisted), None)
        );
        assert!(cell.attach_calls().is_empty());
        let row = cell
            .fixture
            .world
            .volumes
            .iter_mut()
            .find(|row| row.volume == volume(1));
        row.unwrap()
            .attachments
            .retain(|id| id != "not-an-instance");
        cell.fixture.world.faults.attachments = false;
        cell.now_us += 10 * S;
        cell.tick();
        assert_eq!(cell.attach_calls().len(), 1);
        cell.clean();
    }
}

#[test]
fn an_entry_ended_after_the_survey_takes_no_attach_request() {
    let mut cell = Cell::new(6, 1);
    let survey = cell.planned(attaching);
    let candidate = candidate_of(&survey);
    let gate = StandbyGate::qualified();
    let mut other = Reconciler::new(reconciler_client(cell.store()));
    let (seq, _) = cell.volume(1).latest(candidate).unwrap();
    other
        .end_attach(&gate, shard(1), volume(1), candidate, seq)
        .unwrap();
    let outcomes = cell.actuate(&survey);
    let outcome = attach_outcome(&outcomes);
    assert_eq!(
        (outcome.verdict, outcome.reply),
        (Verdict::Wait(Reason::Moved), None)
    );
    assert!(cell.attach_calls().is_empty());
}

#[test]
fn a_candidate_whose_instance_is_listed_without_an_entry_records_none() {
    let mut cell = Cell::new(6, 1);
    let first = cell.planned(|step| matches!(step, Step::RecordAttach { .. }));
    let candidate = candidate_of(&first);
    cell.fixture
        .world
        .attach(volume(1), instance(candidate.get()));
    let survey = cell.survey();
    assert_eq!(candidate_of(&survey), candidate);
    let before = cell.volume(1);
    let outcomes = cell.actuate(&survey);
    let recorded = outcomes
        .iter()
        .find(|o| matches!(o.step, Step::RecordAttach { .. }));
    assert_eq!(recorded.unwrap().verdict, Verdict::Wait(Reason::Binding));
    assert_eq!(cell.volume(1), before);
    assert!(cell.attach_calls().is_empty());
}

#[test]
fn a_record_step_without_a_usable_survey_listing_records_no_entry() {
    use crate::failover::attachments::Unlisted;
    let mut cell = Cell::new(6, 1);
    let mut survey = cell.planned(|step| matches!(step, Step::RecordAttach { .. }));
    survey.observation.zone.as_mut().unwrap().volumes = Err(Unlisted);
    let before = cell.volume(1);
    let outcomes = cell.actuate(&survey);
    let recorded = outcomes
        .iter()
        .find(|o| matches!(o.step, Step::RecordAttach { .. }));
    assert_eq!(recorded.unwrap().verdict, Verdict::Wait(Reason::Unlisted));
    assert_eq!(cell.volume(1), before);
    cell.now_us += 10 * S;
    cell.run_until(10, |cell| hosts_of(&cell.volume(1)).len() == 2);
    cell.clean();
}

#[test]
fn a_candidate_whose_report_falls_below_the_era_floor_records_no_entry() {
    let mut cell = Cell::new(6, 1);
    let mut survey = cell.planned(|step| matches!(step, Step::RecordAttach { .. }));
    let candidate = candidate_of(&survey);
    let view = survey.observation.zone.as_mut().unwrap();
    let held = view
        .hosts
        .iter_mut()
        .find(|held| held.entry.host == candidate)
        .unwrap();
    let report = held.report.as_mut().unwrap();
    std::sync::Arc::make_mut(report).host.build.era = crate::failover::records::MIN_ERA - 1;
    let before = cell.volume(1);
    let outcomes = cell.actuate(&survey);
    let recorded = outcomes
        .iter()
        .find(|o| matches!(o.step, Step::RecordAttach { .. }));
    assert_eq!(recorded.unwrap().verdict, Verdict::Alarm(Reason::Era));
    assert_eq!(cell.volume(1), before);
}

#[test]
fn a_release_drops_the_owners_stale_slot_and_waits_on_a_retargeted_one() {
    for retarget in [false, true] {
        let mut cell = Cell::new(6, 1);
        cell.run_until(40, |cell| cell.shard(1).standby.is_some());
        let standby = cell.shard(1).standby.unwrap();
        let mut owner = owner(cell.store());
        let read = owner.read::<ShardRecord>(Key::Shard(shard(1))).unwrap();
        owner
            .take_over(&read, Target::of(read.value()), standby)
            .unwrap();
        let others: Vec<u64> = (1..=6).filter(|&n| n != standby.get()).collect();
        for &n in &others {
            cell.lose(n);
        }
        let survey = cell.planned(|step| matches!(step, Step::Release { .. }));
        let stale = census_of(cell.store()).unwrap().slot(shard(1)).unwrap();
        assert_eq!(stale.host, standby);
        let target = Target::of(&cell.shard(1));
        assert_ne!(stale.target, target);
        let mut kept = None;
        if retarget {
            let gate = StandbyGate::qualified();
            let mut other = Reconciler::new(reconciler_client(cell.store()));
            let next = host(others[0]);
            let report = crate::failover::standbys::tests::roomy(next);
            let population = Population { cap: 8 };
            let slot = other.reserve(
                &gate,
                &population,
                bounds().bounds(),
                ZONE,
                shard(1),
                &report,
                |_| None,
                |_| false,
            );
            kept = Some(slot.unwrap().host());
        }
        let outcomes = cell.actuate(&survey);
        let released = outcomes
            .iter()
            .find(|o| matches!(o.step, Step::Release { .. }));
        let slot = census_of(cell.store()).unwrap().slot(shard(1));
        match kept {
            None => {
                assert_eq!(released.unwrap().verdict, Verdict::Advance);
                assert!(slot.is_none(), "{slot:?}");
            }
            Some(next) => {
                assert_eq!(released.unwrap().verdict, Verdict::Wait(Reason::Moved));
                let slot = slot.unwrap();
                assert_eq!((slot.host, slot.target), (next, target));
            }
        }
        cell.clean();
    }
}

#[test]
fn request_times_end_with_the_shards_volume_and_outlast_a_failed_read() {
    use crate::failover::zone_loop::observe::Source;
    use crate::storage::store::StoreError;
    let requested = || {
        let mut cell = Cell::new(6, 1);
        let faults = &mut cell.fixture.world.faults.attach;
        faults.push_back(AttachFault::Refuse);
        let survey = cell.planned(attaching);
        cell.actuate(&survey);
        assert_eq!(cell.zone.requests.len(), 1);
        cell
    };
    let next = |cell: &mut Cell, change: &dyn Fn(&mut Survey)| {
        cell.now_us += 10 * S;
        let mut survey = cell.survey();
        survey.plan.steps.clear();
        change(&mut survey);
        cell.actuate(&survey);
        cell.zone.requests.len()
    };
    let unread = |survey: &mut Survey| {
        let view = survey.observation.zone.as_mut().unwrap();
        view.shards[0].records = Err(Source::Store(StoreError::Unavailable));
    };
    let delisted = |survey: &mut Survey| {
        survey.observation.zone.as_mut().unwrap().shards.clear();
    };
    let mut cell = requested();
    let config = bounds().config().clone();
    let stuck_at = cell.now_us + config.attach_stuck_us + config.tick_us;
    assert_eq!(next(&mut cell, &unread), 1);
    assert_eq!(next(&mut cell, &delisted), 1);
    cell.now_us = stuck_at - 3 * 10 * S;
    assert_eq!(next(&mut cell, &unread), 1);
    assert_eq!(next(&mut cell, &delisted), 1);
    assert_eq!(next(&mut cell, &delisted), 0);
    assert_eq!(cell.now_us, stuck_at);
    let flipped = |survey: &mut Survey| {
        let view = survey.observation.zone.as_mut().unwrap();
        let records = view.shards[0].records.as_mut().unwrap().as_mut().unwrap();
        records.active.volume = VolumeId::new("vol-0f1").unwrap();
    };
    assert_eq!(next(&mut requested(), &flipped), 0);
    let gone = |survey: &mut Survey| {
        let view = survey.observation.zone.as_mut().unwrap();
        let records = view.shards[0].records.as_mut().unwrap().as_mut().unwrap();
        for event in &mut records.active.events {
            if event.kind == EventKind::Attach && event.host != records.record.owner {
                event.kind = EventKind::Gone;
            }
        }
    };
    assert_eq!(next(&mut requested(), &gone), 0);
}

pub(super) fn plant_volume(cell: &Cell, number: u32, change: impl FnOnce(&mut VolumeRecord)) {
    let key = Key::Volume(volume(number));
    let mut store = cell.store().clone();
    let item = store.0.borrow().current(&key).cloned().unwrap();
    let mut planted: VolumeRecord = stored(&store, key);
    change(&mut planted);
    let write = Write::Exact {
        expect: item.version,
        value: planted.encoded(&key).unwrap(),
    };
    let written = store.write(&key, &write);
    assert!(matches!(written, Written::Committed(_)), "{written:?}");
}

#[test]
fn an_unfenced_record_step_leaves_the_write_to_a_later_shard() {
    let mut config = config_of(8);
    config.writes_per_tick = 1;
    let mut cell = Cell::with(12, 2, false, config.validate().unwrap());
    fence(cell.store(), 2);
    let mut waited = false;
    for _ in 0..40 {
        let events = cell.fixture.world.events().len();
        let (_, outcomes) = cell.tick();
        let seen = &cell.fixture.world.events()[events..];
        let writes = seen.iter().filter(|e| matches!(e, Event::Write(_))).count();
        assert!(writes <= 1, "{writes} writes");
        waited |= outcomes.iter().any(|o| {
            matches!(o.step, Step::RecordAttach { shard: at, .. } if at == shard(1))
                && o.verdict == Verdict::Wait(Reason::OwnerNotReady)
        });
        if hosts_of(&cell.volume(2)).len() == 2 {
            break;
        }
    }
    assert!(waited);
    assert_eq!(hosts_of(&cell.volume(2)).len(), 2);
    assert_eq!(hosts_of(&cell.volume(1)), [owner_of(1, 12)]);
}

#[test]
fn an_attach_step_on_a_volume_that_left_service_sends_no_request() {
    let mut cell = Cell::new(6, 1);
    let survey = cell.planned(attaching);
    plant_volume(&cell, 1, |held| {
        held.state = crate::failover::records::VolumeState::Retired
    });
    let outcomes = cell.actuate(&survey);
    let outcome = attach_outcome(&outcomes);
    assert_eq!(
        (outcome.verdict, outcome.reply),
        (Verdict::Wait(Reason::Moved), None)
    );
    assert!(cell.attach_calls().is_empty());
}

#[test]
fn an_enrolled_entry_bound_to_another_instance_is_neither_attached_nor_designated() {
    let mut cell = Cell::new(6, 1);
    let survey = cell.planned(attaching);
    let candidate = candidate_of(&survey);
    let id = instance(candidate.get());
    cell.fixture.world.attach(volume(1), id);
    cell.enroll_listed();
    cell.fixture.world.detach(volume(1), id);
    let rebind = |held: &mut VolumeRecord| {
        let seq = held.live(candidate).unwrap();
        let entry = held.events.iter_mut().find(|event| event.seq == seq);
        entry.unwrap().instance = Some(instance(5));
    };
    plant_volume(&cell, 1, rebind);
    let outcome = attach_outcome(&cell.actuate(&survey));
    assert_eq!(
        (outcome.verdict, outcome.reply),
        (Verdict::Alarm(Reason::Binding), None)
    );
    assert!(cell.attach_calls().is_empty());
    cell.now_us += 10 * S;
    let designating = |step: &Step| matches!(step, Step::Designate { .. });
    let survey = cell.planned(designating);
    let outcomes = cell.actuate(&survey);
    let designated = outcomes.iter().find(|o| designating(&o.step)).unwrap();
    assert_eq!(designated.verdict, Verdict::Alarm(Reason::Binding));
    assert_eq!(cell.shard(1).standby, None);
}

#[test]
fn a_reservation_refused_by_a_full_or_taken_census_writes_nothing() {
    use crate::failover::standbys::Refusal as PopulationRefusal;
    for taken in [false, true] {
        let mut config = config_of(8);
        config.population_cap = 1;
        let mut cell = Cell::with(6, 2, true, config.validate().unwrap());
        let survey = cell.planned(|step| matches!(step, Step::Reserve { .. }));
        let (planned, candidate) = survey
            .plan
            .steps
            .iter()
            .find_map(|step| match *step {
                Step::Reserve { shard, host, .. } => Some((shard, host)),
                _ => None,
            })
            .unwrap();
        let at = if taken {
            planned
        } else {
            shard(3 - planned.get())
        };
        let owners: Vec<Host> = (1..=2).map(|n| cell.shard(n).owner).collect();
        let rival = (1..=6)
            .map(host)
            .find(|&h| h != candidate && !owners.contains(&h))
            .unwrap();
        let gate = StandbyGate::qualified();
        let mut other = Reconciler::new(reconciler_client(cell.store()));
        let report = crate::failover::standbys::tests::roomy(rival);
        let population = Population { cap: 1 };
        let zone = bounds();
        let held = other.reserve(
            &gate,
            &population,
            zone.bounds(),
            ZONE,
            at,
            &report,
            |_| None,
            |_| false,
        );
        held.unwrap();
        let before = cell.store().0.borrow().commit_count(&Key::Standbys(ZONE));
        let outcomes = cell.actuate(&survey);
        let refusal = match taken {
            true => PopulationRefusal::Taken,
            false => PopulationRefusal::Full,
        };
        let reserved = outcomes
            .iter()
            .find(|o| matches!(o.step, Step::Reserve { .. }));
        let expected = Verdict::Wait(Reason::Population(refusal));
        assert_eq!(reserved.unwrap().verdict, expected);
        let after = cell.store().0.borrow().commit_count(&Key::Standbys(ZONE));
        assert_eq!(after, before);
        let census = census_of(cell.store()).unwrap();
        assert_eq!(census.len(), 1);
        assert_eq!(census.slot(at).unwrap().host, rival);
    }
}

#[test]
fn two_census_releases_under_one_write_per_tick_take_two_ticks() {
    let mut config = config_of(8);
    config.writes_per_tick = 1;
    let mut cell = Cell::with(6, 2, true, config.validate().unwrap());
    cell.run_until(200, Cell::designated);
    let mut client = owner(cell.store());
    let mut owners = Vec::new();
    for number in 1..=2 {
        let read = client
            .read::<ShardRecord>(Key::Shard(shard(number)))
            .unwrap();
        let standby = read.value().standby.unwrap();
        client
            .take_over(&read, Target::of(read.value()), standby)
            .unwrap();
        owners.push(standby);
    }
    assert_ne!(owners[0], owners[1]);
    for n in (1..=6).filter(|&n| !owners.contains(&host(n))) {
        cell.lose(n);
    }
    let mut owning = cell.fixture.listing.clone().unwrap();
    owning.version += 1;
    owning.host_roles_max = 1;
    cell.fixture.listing = Some(owning);
    let listed = |cell: &Cell| census_of(cell.store()).map_or(0, |census| census.len());
    assert_eq!(listed(&cell), 2);
    let mut budgeted = false;
    for _ in 0..60 {
        let events = cell.fixture.world.events().len();
        let (_, outcomes) = cell.tick();
        assert!(cell.writes_since(events) <= 1, "{outcomes:?}");
        budgeted |= outcomes.iter().any(|outcome| {
            matches!(outcome.step, Step::Release { .. })
                && outcome.verdict == Verdict::Wait(Reason::Budget)
        });
        if listed(&cell) == 0 {
            break;
        }
    }
    assert!(budgeted);
    assert_eq!(listed(&cell), 0);
}

#[test]
fn a_step_planned_before_its_slot_took_a_later_target_waits_for_the_next_survey() {
    for designating in [false, true] {
        let mut cell = Cell::new(6, 1);
        let wanted = move |step: &Step| match designating {
            true => matches!(step, Step::Designate { .. }),
            false => matches!(step, Step::RecordAttach { .. }),
        };
        let survey = cell.planned(wanted);
        let planned = survey.plan.steps.iter().find_map(|step| match *step {
            Step::Designate { host, .. } | Step::RecordAttach { host, .. } => Some(host),
            _ => None,
        });
        let candidate = planned.unwrap();
        let mut client = owner(cell.store());
        let read = client.read::<ShardRecord>(Key::Shard(shard(1))).unwrap();
        client.bump(&read).unwrap();
        let bumped = Target::of(&cell.shard(1));
        let gate = StandbyGate::qualified();
        let mut other = Reconciler::new(reconciler_client(cell.store()));
        let report = crate::failover::standbys::tests::roomy(candidate);
        let population = Population { cap: 8 };
        let zone = bounds();
        let slot = other.reserve(
            &gate,
            &population,
            zone.bounds(),
            ZONE,
            shard(1),
            &report,
            |_| None,
            |_| false,
        );
        let slot = slot.unwrap();
        assert_eq!((slot.host(), slot.target()), (candidate, bumped));
        let before = (cell.shard(1), cell.volume(1));
        let outcomes = cell.actuate(&survey);
        let outcome = outcomes.iter().find(|o| wanted(&o.step)).unwrap();
        assert_eq!(outcome.verdict, Verdict::Wait(Reason::Moved));
        assert_eq!((cell.shard(1), cell.volume(1)), before);
        cell.enroll_listed();
        cell.now_us += 10 * S;
        cell.run_until(40, |cell| cell.shard(1).standby == Some(candidate));
        assert_eq!(Target::of(&cell.shard(1)), bumped);
        cell.clean();
    }
}

#[test]
fn a_record_step_on_a_volume_that_filled_after_the_survey_waits_owner_not_ready() {
    use crate::failover::reconcile::Binding as RecordBinding;
    let mut cell = Cell::new(8, 1);
    let recording = |step: &Step| matches!(step, Step::RecordAttach { .. });
    let mut survey = cell.planned(recording);
    let step = *survey
        .plan
        .steps
        .iter()
        .find(|step| recording(step))
        .unwrap();
    let candidate = candidate_of(&survey);
    survey.plan.steps.push(step);
    let owner = cell.shard(1).owner;
    let gate = StandbyGate::qualified();
    let mut other = Reconciler::new(reconciler_client(cell.store()));
    let others = (1..=8).filter(|&n| host(n) != owner && host(n) != candidate);
    let peers: Vec<crate::failover::attachments::Peer> = (1..=8)
        .map(|n| crate::failover::attachments::Peer {
            host: host(n),
            instance: instance(n),
        })
        .collect();
    for n in others.take(2) {
        let binding = RecordBinding {
            instance: instance(n),
            unbound: &peers,
            listing: None,
        };
        let era = crate::failover::records::ERA;
        let bounds = *cell.bounds.bounds();
        let recorded =
            other.record_standby(&gate, shard(1), volume(1), host(n), era, &bounds, &binding);
        recorded.unwrap();
    }
    let before = cell.volume(1);
    let outcomes = cell.actuate(&survey);
    let verdicts: Vec<Verdict> = (outcomes.iter())
        .filter(|outcome| outcome.step == step)
        .map(|outcome| outcome.verdict)
        .collect();
    assert_eq!(verdicts, [Verdict::Wait(Reason::OwnerNotReady); 2]);
    assert_eq!(cell.volume(1), before);
}

#[test]
fn a_full_record_sheds_its_oldest_unlisted_gone_entry_for_the_candidates_attach() {
    use crate::failover::records::{ERA, MAX_EVENTS};
    let mut cell = Cell::new(6, 1);
    let recording = |step: &Step| matches!(step, Step::RecordAttach { .. });
    let candidate = candidate_of(&cell.planned(recording));
    let gone = 40..40 + MAX_EVENTS as u64 - 1;
    plant_volume(&cell, 1, |held| {
        for n in gone.clone() {
            let seq = held.push(EventKind::Attach, host(n), ERA).unwrap();
            let event = held.events.iter_mut().find(|event| event.seq == seq);
            let event = event.unwrap();
            (event.kind, event.instance) = (EventKind::Gone, Some(instance(n)));
        }
    });
    assert_eq!(cell.volume(1).events.len(), MAX_EVENTS);
    cell.fixture.world.attach(volume(1), instance(gone.start));
    let seen = cell.run_until(20, |cell| cell.volume(1).live(candidate).is_some());
    let recorded = seen
        .iter()
        .find(|outcome| recording(&outcome.step) && outcome.verdict == Verdict::Advance);
    assert_eq!(recorded.unwrap().reclaim, Some(Reclaim::Removed));
    let held = cell.volume(1);
    assert_eq!(held.events.len(), MAX_EVENTS);
    let hosts = hosts_of(&held);
    assert!(hosts.contains(&host(gone.start)), "{hosts:?}");
    assert!(!hosts.contains(&host(gone.start + 1)), "{hosts:?}");
    let kept = hosts.iter().filter(|kept| gone.contains(&kept.get()));
    assert_eq!(kept.count(), MAX_EVENTS - 2, "{hosts:?}");
    cell.clean();
}

#[test]
fn a_release_keeps_the_stale_slot_of_a_live_attached_host() {
    assert_a_release_keeps_a_slot_reserved_after_the_survey(true);
}

#[test]
fn a_release_keeps_the_stale_slot_of_a_live_host_with_no_attach_entry() {
    assert_a_release_keeps_a_slot_reserved_after_the_survey(false);
}

/// A survey plans to release a stale slot. Another reconciler reserves the slot for a live host and records the
/// attach if `recorded` is true. The owner then bumps the shard target, making the reservation stale before the
/// planned release runs.
fn assert_a_release_keeps_a_slot_reserved_after_the_survey(recorded: bool) {
    use crate::failover::reconcile::Binding as RecordBinding;
    let mut cell = Cell::new(6, 1);
    cell.run_until(40, |cell| cell.shard(1).standby.is_some());
    let standby = cell.shard(1).standby.unwrap();
    let mut client = owner(cell.store());
    let read = client.read::<ShardRecord>(Key::Shard(shard(1))).unwrap();
    client
        .take_over(&read, Target::of(read.value()), standby)
        .unwrap();
    let same_color = |n: &u64| *n != standby.get() && n % 2 == standby.get() % 2;
    let kept = (1..=6).find(same_color).unwrap();
    for n in (1..=6).filter(|&n| n != standby.get() && n != kept) {
        cell.lose(n);
    }
    let survey = cell.planned(|step| matches!(step, Step::Release { .. }));
    let reserving = |step: &Step| matches!(step, Step::Reserve { .. });
    assert!(
        !survey.plan.steps.iter().any(reserving),
        "{:?}",
        survey.plan
    );
    let gate = StandbyGate::qualified();
    let mut other = Reconciler::new(reconciler_client(cell.store()));
    let report = crate::failover::standbys::tests::roomy(host(kept));
    let population = Population { cap: 8 };
    let bounds = *cell.bounds.bounds();
    let slot = other.reserve(
        &gate,
        &population,
        &bounds,
        ZONE,
        shard(1),
        &report,
        |_| None,
        |_| false,
    );
    let reserved = slot.unwrap().target();
    if recorded {
        let binding = RecordBinding {
            instance: instance(kept),
            unbound: &[],
            listing: None,
        };
        let era = crate::failover::records::ERA;
        let recorded = other.record_standby(
            &gate,
            shard(1),
            volume(1),
            host(kept),
            era,
            &bounds,
            &binding,
        );
        recorded.unwrap();
    }
    let read = client.read::<ShardRecord>(Key::Shard(shard(1))).unwrap();
    client.bump(&read).unwrap();
    assert_ne!(Target::of(&cell.shard(1)), reserved);
    let outcomes = cell.actuate(&survey);
    let released = outcomes
        .iter()
        .find(|o| matches!(o.step, Step::Release { .. }));
    assert_eq!(released.unwrap().verdict, Verdict::Wait(Reason::Moved));
    let slot = census_of(cell.store()).unwrap().slot(shard(1)).unwrap();
    assert_eq!((slot.host, slot.target), (host(kept), reserved));
}

#[test]
fn a_draining_slot_host_with_no_attach_yields_its_slot_to_another_candidate() {
    let mut cell = Cell::new(6, 1);
    let recording = |step: &Step| matches!(step, Step::RecordAttach { .. });
    let first = candidate_of(&cell.planned(recording));
    cell.drain(first);
    let (survey, outcomes) = cell.tick();
    let reserved = outcomes
        .iter()
        .find(|o| matches!(o.step, Step::Reserve { .. }));
    let reserved = reserved.unwrap_or_else(|| panic!("{:?}", survey.plan));
    assert_eq!(reserved.verdict, Verdict::Advance);
    let slot = census_of(cell.store()).unwrap().slot(shard(1)).unwrap();
    assert_ne!(slot.host, first);
    cell.run_until(40, |cell| cell.shard(1).standby.is_some());
    assert!(!hosts_of(&cell.volume(1)).contains(&first));
    cell.clean();
}

#[test]
fn a_repeat_attach_request_goes_out_at_the_settle_time_and_not_before() {
    let settle_us = bounds().config().attach_settle_us;
    let mut cell = Cell::new(6, 1);
    let faults = &mut cell.fixture.world.faults.attach;
    faults.push_back(AttachFault::Unknown { attached: false });
    let survey = cell.planned(attaching);
    let requested = cell.now_us;
    let first = attach_outcome(&cell.actuate(&survey));
    assert_eq!(first.reply, Some(AttachReply::Unknown));
    cell.now_us = requested + settle_us - 1;
    let survey = cell.survey();
    let early = attach_outcome(&cell.actuate(&survey));
    assert_eq!(
        (early.verdict, early.reply),
        (Verdict::Wait(Reason::Settling), None)
    );
    assert_eq!(cell.attach_calls().len(), 1);
    cell.now_us = requested + settle_us;
    let survey = cell.survey();
    let due = attach_outcome(&cell.actuate(&survey));
    assert_eq!(
        (due.verdict, due.reply),
        (Verdict::Advance, Some(AttachReply::Accepted))
    );
    assert_eq!(cell.attach_calls().len(), 2);
    cell.clean();
}

#[test]
fn an_accepted_request_that_does_not_land_is_retried_after_one_settle_time() {
    let settle_us = bounds().config().attach_settle_us;
    let mut cell = Cell::new(6, 1);
    let faults = &mut cell.fixture.world.faults.attach;
    faults.extend([AttachFault::Refuse, AttachFault::Unlanded]);
    let mut requests = Vec::new();
    for _ in 0..40 {
        let at = cell.now_us;
        let (_, outcomes) = cell.tick();
        let sent = outcomes.iter().filter(|outcome| outcome.reply.is_some());
        requests.extend(sent.map(|outcome| (at, outcome.reply.unwrap())));
        if requests.len() == 3 {
            break;
        }
    }
    let replies: Vec<AttachReply> = requests.iter().map(|(_, reply)| *reply).collect();
    let refused = AttachReply::Refused(AttachRefusal::Other);
    let accepted = AttachReply::Accepted;
    assert_eq!(replies, [refused, accepted, accepted]);
    assert_eq!(requests[1].0 - requests[0].0, 2 * settle_us);
    assert_eq!(requests[2].0 - requests[1].0, settle_us);
    cell.clean();
}

#[test]
fn the_fresh_needs_attach_takes_the_ticks_one_call_and_spends_none_while_it_settles() {
    let config = config_of(8);
    let mut cell = Cell::with(9, 3, true, config.validate().unwrap().with_calls(1));
    cell.run_until(200, Cell::designated);
    let (standby, fresh) = (cell.shard(1), cell.shard(3));
    cell.lose(fresh.owner.get());
    cell.lose(fresh.standby.unwrap().get());
    cell.lose(standby.standby.unwrap().get());
    let unlanded = AttachFault::Unknown { attached: false };
    cell.fixture.world.faults.attach.push_back(unlanded);
    let of = |outcomes: &[Outcome], number: u32| {
        let mine =
            |o: &&Outcome| matches!(o.step, Step::Attach { shard: at, .. } if at == shard(number));
        outcomes.iter().find(mine).copied()
    };
    let mut both = None;
    for _ in 0..80 {
        let calls = cell.attach_calls().len();
        let (_, outcomes) = cell.tick();
        if let (Some(first), Some(second)) = (of(&outcomes, 3), of(&outcomes, 1)) {
            both = Some((first, second, cell.attach_calls()[calls..].to_vec()));
            break;
        }
    }
    let (first, second, sent) = both.expect("one tick plans both attach requests");
    assert_eq!(first.reply, Some(AttachReply::Unknown));
    assert_eq!(
        (second.verdict, second.reply),
        (Verdict::Wait(Reason::Budget), None)
    );
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].0, volume(3));
    let (_, outcomes) = cell.tick();
    let settling = of(&outcomes, 3).unwrap();
    assert_eq!(
        (settling.verdict, settling.reply),
        (Verdict::Wait(Reason::Settling), None)
    );
    let sent = of(&outcomes, 1).unwrap();
    assert_eq!(sent.reply, Some(AttachReply::Accepted), "{outcomes:?}");
    cell.clean();
}

/// CALL-ROTATION, the fresh band over the standby band: with one call per tick and an attach wait of one tick, a
/// fresh need's attach that returned unknown is requested again on the next tick ahead of a standby need's attach
/// that was never requested.
#[test]
fn a_fresh_needs_retry_takes_the_ticks_one_call_ahead_of_a_standby_needs_first_request() {
    let mut config = config_of(8);
    config.attach_settle_us = config.tick_us;
    let mut cell = Cell::with(9, 3, true, config.validate().unwrap().with_calls(1));
    cell.run_until(200, Cell::designated);
    let (standby, fresh) = (cell.shard(1), cell.shard(3));
    cell.lose(fresh.owner.get());
    cell.lose(fresh.standby.unwrap().get());
    cell.lose(standby.standby.unwrap().get());
    let unlanded = [AttachFault::Unknown { attached: false }; 2];
    cell.fixture.world.faults.attach.extend(unlanded);
    let of = |outcomes: &[Outcome], number: u32| {
        let mine =
            |o: &&Outcome| matches!(o.step, Step::Attach { shard: at, .. } if at == shard(number));
        outcomes.iter().find(mine).copied()
    };
    let mut ticks = Vec::new();
    for _ in 0..80 {
        let (_, outcomes) = cell.tick();
        if let (Some(first), Some(second)) = (of(&outcomes, 3), of(&outcomes, 1)) {
            ticks.push((first.reply, second.verdict, second.reply));
            if ticks.len() == 2 {
                break;
            }
        } else {
            assert!(ticks.is_empty(), "{outcomes:?}");
        }
    }
    let retried = (
        Some(AttachReply::Unknown),
        Verdict::Wait(Reason::Budget),
        None,
    );
    assert_eq!(ticks, [retried, retried]);
}

#[test]
fn an_attach_entry_records_the_era_of_the_candidates_report() {
    let era = crate::failover::records::MIN_ERA + 5;
    let mut cell = Cell::new(6, 1);
    let recording = |step: &Step| matches!(step, Step::RecordAttach { .. });
    let mut survey = cell.planned(recording);
    let candidate = candidate_of(&survey);
    let view = survey.observation.zone.as_mut().unwrap();
    let held = view
        .hosts
        .iter_mut()
        .find(|held| held.entry.host == candidate);
    let report = held.unwrap().report.as_mut().unwrap();
    std::sync::Arc::make_mut(report).host.build.era = era;
    let outcomes = cell.actuate(&survey);
    let recorded = outcomes.iter().find(|o| recording(&o.step)).unwrap();
    assert_eq!(
        (recorded.verdict, recorded.reclaim),
        (Verdict::Advance, None)
    );
    let held = cell.volume(1);
    let entry = held.event(held.live(candidate).unwrap()).unwrap();
    assert_eq!(
        (entry.era, entry.instance),
        (era, Some(instance(candidate.get())))
    );
}

#[test]
fn an_already_listed_reply_advances_with_no_second_request() {
    let mut cell = Cell::new(6, 1);
    let faults = &mut cell.fixture.world.faults.attach;
    faults.push_back(AttachFault::Listed);
    let survey = cell.planned(attaching);
    let outcome = attach_outcome(&cell.actuate(&survey));
    assert_eq!(
        (outcome.verdict, outcome.reply),
        (Verdict::Advance, Some(AttachReply::AlreadyListed))
    );
    cell.enroll_listed();
    cell.now_us += 10 * S;
    cell.run_until(20, |cell| cell.shard(1).standby.is_some());
    assert_eq!(cell.attach_calls().len(), 1);
    cell.clean();
}

#[test]
fn an_unknown_attach_reply_stops_the_shards_later_steps_for_the_tick() {
    let mut cell = Cell::new(6, 1);
    let faults = &mut cell.fixture.world.faults.attach;
    faults.push_back(AttachFault::Unknown { attached: false });
    let mut survey = cell.planned(attaching);
    let step = *survey
        .plan
        .steps
        .iter()
        .find(|step| attaching(step))
        .unwrap();
    survey.plan.steps.push(step);
    let events = cell.fixture.world.events().len();
    let outcomes = cell.actuate(&survey);
    let seen: Vec<(Verdict, Option<AttachReply>)> = (outcomes.iter())
        .filter(|outcome| outcome.step == step)
        .map(|outcome| (outcome.verdict, outcome.reply))
        .collect();
    let unknown = (Verdict::Wait(Reason::Unknown), Some(AttachReply::Unknown));
    assert_eq!(seen, [unknown, (Verdict::Wait(Reason::Moved), None)]);
    let listings = cell.fixture.world.events()[events..]
        .iter()
        .filter(|seen| **seen == Event::Attachments(volume(1)))
        .count();
    assert_eq!(listings, 1);
    assert_eq!(cell.attach_calls().len(), 1);
}
