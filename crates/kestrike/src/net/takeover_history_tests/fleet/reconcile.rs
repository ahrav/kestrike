//! The fleet's reconciler actors. Each [`ReconcilerActor`] keeps a `ZoneLoop` in `zone_loop`; `Fleet::survey_turn`
//! calls its `tick` and `Fleet::actuate_turn` calls `ZoneLoop::actuate` with `StandbyGate::qualified()`, and [`Fleet::unnamed_waits`] runs
//! the production wait (`host::stand_by`) of each attached host the volume record does not enroll, whose unnamed or
//! standby arm calls `enroll_standby`. [`Fleet::collect`] logs each status row's changed blocker behind that row as its
//! refusal in [`ReconLog`]. [`Crashing`] and [`Effects`] apply a crash-table cell's arm to its effect and then set
//! `Effected::dead`.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::rc::Rc;

use crate::failover::attachments::{ControlPlane, InstanceId, Unlisted};
use crate::failover::bounds::Bounds;
use crate::failover::loss::{CreateError, Provider};
use crate::failover::reconcile::{Reconciler, StandbyGate};
use crate::failover::records::{
    Host, Layout, Namespace, Record, ShardRecord, VolumeId, VolumeRecord,
};
use crate::failover::report::ReportKey;
use crate::failover::standbys::{Census, Need, Refusal, Zone, need};
use crate::failover::takeover::tests::bound_record;
use crate::failover::zone_loop::ZoneLoop;
use crate::failover::zone_loop::actuate::{Discard, Outcome, Reason, Verdict};
use crate::failover::zone_loop::config::{
    DETACH_SETTLE_FLOOR_US, OwnerBounds, ZoneBounds, ZoneConfig,
};
use crate::failover::zone_loop::directory::{
    Color, DerivedKey, Directory, DirectoryState, HostEntry, Listing, Placement as Placed,
    ReconcilerProjection, ShardEntry,
};
use crate::failover::zone_loop::evidence::{
    Instance, InstanceState, ListedVolumeState, StatusCheck, VolumeCondition, VolumeStatus,
};
use crate::failover::zone_loop::plan::{Step, Survey};
use crate::failover::zone_loop::sources::{AttachReply, Attacher, DetachReply, Witness};
use crate::failover::zone_loop::status::{Blocker, ShardState};
use crate::failover::zone_loop::tests::world::World as ZoneDouble;
use crate::storage::store::sim::{Arm, Armed, AsReconciler, Faulted, MemLog, Shared};
use crate::storage::store::{
    Client, Item, Key, Outcome as Written, Refusal as StoreRefusal, Store, Unavailable, Write,
};

use super::super::ROUND_US;
use super::draws::{self, Draws, Tag};
use super::hosts::{REPORT_ROUNDS, Scenario, Up, host_key};
use super::owners::Decoding;
use super::{FIRST_HOST_ID, Fleet, Plant};

/// The rounds between two ticks of a reconciler's loop.
pub(crate) const TICK_ROUNDS: u64 = 2;
/// The rounds a crashed reconciler stays down before its next incarnation starts.
pub(crate) const RESTART_ROUNDS: u64 = 6;
/// Each run tests whether every shard settles within `REPAIR_SETTLE_ROUNDS` rounds of the settle phase's start.
pub(crate) const REPAIR_SETTLE_ROUNDS: u64 = 600;
/// The rounds a loop incarnation runs before the settle phase starts.
pub(crate) const AGE_ROUNDS: u64 = 2 * 3 * REPORT_ROUNDS;
/// The ticks of zone host hold after which the exhausted-attach case's operator retires the lost hosts.
pub(crate) const RETIRE_TICKS: u32 = 20;
/// A settled run may end when the fixpoint count reaches `FIXPOINT_TICKS`.
pub(crate) const FIXPOINT_TICKS: u32 = 3;

/// The effect of a need repair that a crash-table cell cuts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Call {
    /// The census write of the reservation.
    Reserve = 0,
    /// The volume-record write of the attach record.
    Record = 1,
    /// The attach request to the zone double.
    Attach = 2,
    /// The host's enrollment write of the volume record.
    Enroll = 3,
    /// The shard-record write of the designation.
    Designate = 4,
}

impl Call {
    pub(crate) const ALL: [Self; 5] = [
        Self::Reserve,
        Self::Record,
        Self::Attach,
        Self::Enroll,
        Self::Designate,
    ];
}

/// How a crash-table cell's effect ends before the incarnation dies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Ending {
    /// The effect lands and its reply arrives.
    Acknowledged = 0,
    /// The effect lands and its reply is unknown.
    Committed = 1,
    /// The target keeps its earlier state and the reply is unknown.
    Lost = 2,
}

impl Ending {
    pub(crate) const ALL: [Self; 3] = [Self::Acknowledged, Self::Committed, Self::Lost];

    pub(crate) fn arm(self) -> Arm {
        match self {
            Self::Acknowledged => Arm::Pass,
            Self::Committed => Arm::Timeout { commit: true },
            Self::Lost => Arm::Timeout { commit: false },
        }
    }
}

/// With `fresh` set, the cell cuts enrollment of a fresh host after the shard loses both owner and standby.
/// Otherwise, it cuts standby enrollment after the shard loses its standby host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CrashCell {
    pub(crate) fresh: bool,
    pub(crate) call: Call,
    pub(crate) ending: Ending,
}

impl CrashCell {
    pub(crate) fn all() -> Vec<Self> {
        let mut cells = Vec::new();
        for fresh in [false, true] {
            for call in Call::ALL {
                for ending in Ending::ALL {
                    cells.push(Self {
                        fresh,
                        call,
                        ending,
                    });
                }
            }
        }
        cells
    }

    pub(crate) fn code(self) -> u8 {
        u8::from(self.fresh) * 16 + self.call as u8 * 3 + self.ending as u8
    }

    pub(crate) fn name(self) -> String {
        let kind = if self.fresh { "fresh" } else { "enroll" };
        format!("{kind}-{:?}-{:?}", self.call, self.ending).to_lowercase()
    }
}

/// What a designation repaired: one need of the shard, or a standby the shard's record already named (`Cover`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Repair {
    Cover,
    Need(Need),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reclaim {
    End,
    Detach,
    Release,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Status {
    Running,
    Down { until: u64 },
}

pub(crate) type ReconStore = Faulted<AsReconciler<Crashing>>;
pub(crate) type Loop = ZoneLoop<ReconStore, MemLog>;

/// The incarnation opens `zone_loop` at its first turn and drops it at a crash. `effects` holds the incarnation's
/// crash and effect state, shared with its store and call wrappers; `ran` is the round of its last turn, `planned`
/// the step count of its last actuated plan, `started` the round its incarnation started, and `held` the survey
/// reconciler 1 of the two-reconciler case keeps for a later round.
pub(crate) struct ReconcilerActor {
    pub(crate) index: usize,
    pub(crate) zone: Zone,
    pub(crate) incarnation: u32,
    pub(crate) status: Status,
    pub(crate) cap: usize,
    pub(crate) zone_loop: Option<Loop>,
    pub(crate) effects: Rc<RefCell<Effected>>,
    pub(crate) ran: u64,
    pub(crate) planned: usize,
    pub(crate) started: u64,
    pub(crate) held: Option<Survey>,
}

impl ReconcilerActor {
    pub(crate) fn new(index: usize, zone: Zone, cap: usize) -> Self {
        Self {
            index,
            zone,
            incarnation: 0,
            status: Status::Running,
            cap,
            zone_loop: None,
            effects: Rc::new(RefCell::new(Effected::default())),
            ran: 0,
            planned: 0,
            started: 0,
            held: None,
        }
    }

    fn restart(&mut self) {
        let cap = self.cap;
        *self = Self {
            incarnation: self.incarnation + 1,
            ..Self::new(self.index, self.zone, cap)
        };
    }

    pub(crate) fn actor_id(&self, members: usize) -> u32 {
        (members + self.index) as u32
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Refused {
    Status(ShardState, Blocker),
    Step(Step, Verdict),
    Discarded(Step, Discard),
}

impl Refused {
    /// The status row of a blocked shard that names `blocker`.
    pub(crate) fn row(blocker: Blocker) -> Self {
        Self::Status(ShardState::NoCandidate, blocker)
    }
}

pub(crate) fn backs(blocker: Blocker, refused: &Refused) -> bool {
    match refused {
        Refused::Status(_, named) => *named == blocker,
        Refused::Step(Step::Reserve { .. }, Verdict::Wait(Reason::Population(refusal))) => {
            blocker_of(*refusal) == blocker
        }
        _ => false,
    }
}

fn blocker_of(refusal: Refusal) -> Blocker {
    match refusal {
        Refusal::Full => Blocker::CensusFull,
        Refusal::Closed => Blocker::AttachClosed,
        Refusal::Headroom => Blocker::Headroom,
        Refusal::Taken | Refusal::Ineligible => Blocker::NoEligibleHost,
    }
}

/// One designation step the loop advanced: the host it named, what it repaired, whether the host held a live attach
/// of the volume when the status first named it, and the round since the hosts started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Designation {
    pub(crate) shard: u32,
    pub(crate) host: u64,
    pub(crate) repair: Repair,
    pub(crate) attached: bool,
    pub(crate) after_loss: bool,
    pub(crate) round: u64,
}

/// The settle phase's start, in rounds since the hosts started, and its rounds to the first settled sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SettlePhase {
    pub(crate) started: u64,
    pub(crate) turns: Option<u64>,
}

/// Tuple fields, by position:
/// `reclaims` (shard, phase); `refusals` (sequence, shard, outcome); `blockers` (sequence, shard, blocker, the
/// sequence of the refusal it names); `crash_writes` (count before, count at the crash) of the cut effect, in commits
/// of the written key for a store write and in attachment-listing length for an attach request; `fulls` (shard,
/// need, whether the zone double lists the owner running, census length) at the first `CensusFull` row of each need;
/// `after_settle` (store writes, mutating calls) since the fixpoint count started; `breach` (store writes, mutating
/// calls) of the first fixpoint count that held any when an unsettled sample ended it; `slot_moved` (shard, planned
/// host, moved host); `effects` (store writes, mutating calls) of every loop over the run; `crash_aim` (shard, need)
/// of the repair a crash-table cell aims at; `cap_below` (cap, shards) as the loop's status reports it.
/// `calls` counts reconciler turns, one tick each; `covered` and `booted` hold the zones whose census covered every
/// live named standby and whose loop left its warm-up.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ReconLog {
    pub(crate) calls: u32,
    pub(crate) incarnations: Vec<u32>,
    pub(crate) covered: std::collections::BTreeSet<u16>,
    pub(crate) reservations: u32,
    pub(crate) at_cap: u32,
    pub(crate) refused_full: u32,
    pub(crate) condition: u32,
    pub(crate) releases: u32,
    pub(crate) reclaims: Vec<(u32, Reclaim)>,
    pub(crate) designations: Vec<Designation>,
    pub(crate) refusals: Vec<(u64, u32, Refused)>,
    pub(crate) blockers: Vec<(u64, u32, Blocker, Option<u64>)>,
    /// Each continuous run of the status rows that named one blocker for a shard: the shard, the blocker, the round
    /// of its first row and the round of the first row that named another or none, `None` when the run lasted to
    /// the end; rounds since the hosts started, as a designation's round is.
    pub(crate) runs: Vec<(u32, Blocker, u64, Option<u64>)>,
    pub(crate) crashed: Vec<String>,
    pub(crate) crash_writes: Vec<(usize, usize)>,
    pub(crate) crash_aim: Option<(u32, Need)>,
    pub(crate) restarts: u32,
    pub(crate) raced: bool,
    pub(crate) uncovered: Option<(u32, u64)>,
    pub(crate) settle: Option<SettlePhase>,
    pub(crate) settled: bool,
    pub(crate) planted: bool,
    pub(crate) premise_failed: bool,
    pub(crate) booted: std::collections::BTreeSet<u16>,
    pub(crate) contended: u32,
    pub(crate) race_shard: Option<usize>,
    pub(crate) fulls: Vec<(u32, Repair, bool, usize)>,
    pub(crate) first_nomination: Option<u64>,
    pub(crate) orders: u32,
    pub(crate) unordered: u32,
    pub(crate) rewrites: u32,
    pub(crate) after_settle: Option<(u64, u64)>,
    pub(crate) breach: Option<(u64, u64)>,
    pub(crate) fixpoint_ticks: u32,
    pub(crate) paused_ticks: u32,
    pub(crate) zone_held: u32,
    /// The rounds since the hosts started, the clock of [`Designation::round`], of the ticks whose status reported the
    /// zone host hold, over the whole run.
    pub(crate) zone_held_rounds: Vec<u64>,
    pub(crate) slot_moved: Option<(u32, u64, u64)>,
    pub(crate) retired: Vec<u64>,
    pub(crate) effects: (u64, u64),
    pub(crate) cap_below: Option<(usize, usize)>,
    /// The ticks whose status part counted a shard with no live named standby past the zone's standby target.
    pub(crate) past_target: u32,
    settled_effects: Option<(u64, u64)>,
    seq: u64,
}

impl ReconLog {
    pub(super) fn refuse(&mut self, shard: u32, refused: Refused) -> u64 {
        self.seq += 1;
        self.refusals.push((self.seq, shard, refused));
        self.seq
    }

    pub(super) fn block(&mut self, shard: u32, blocker: Blocker, refusal: Option<u64>) {
        self.seq += 1;
        self.blockers.push((self.seq, shard, blocker, refusal));
    }

    pub(crate) fn enter(&mut self, shard: u32, refused: Refused, blocker: Blocker) {
        let refusal = self.refuse(shard, refused);
        self.block(shard, blocker, Some(refusal));
    }

    /// Starts or ends the fixpoint count at a settle sample. The count starts at the first sample that finds every
    /// shard settled and every loop's plan empty, and a sample with an unsettled shard ends it. A planned step while
    /// every shard stays settled keeps the count, so its writes and calls count against LOOP-FIXPOINT. A count that
    /// held a write or a call at its last settled sample stays in `breach` when it ends, so a later quiet count
    /// leaves the rule failed; the writes and calls of the round whose sample is unsettled answer that shard and
    /// stay outside both.
    pub(crate) fn sample(&mut self, settled: bool, quiet: bool) {
        match (settled, quiet, self.settled_effects) {
            (true, true, None) => self.settled_effects = Some(self.effects),
            (false, ..) => {
                let counted = self
                    .after_settle
                    .filter(|(writes, calls)| writes + calls > 0);
                self.breach = self.breach.or(counted);
                self.settled_effects = None;
                self.fixpoint_ticks = 0;
            }
            _ => {}
        }
        self.after_settle = (self.settled_effects)
            .map(|(writes, calls)| (self.effects.0 - writes, self.effects.1 - calls));
    }

    pub(crate) fn tick_after_settle(&mut self) {
        self.fixpoint_ticks += u32::from(self.settled_effects.is_some());
    }

    pub(crate) fn stale(&self) -> usize {
        let refused = self.refusals.iter();
        refused
            .filter(|(_, _, refused)| {
                matches!(
                    refused,
                    Refused::Step(Step::Designate { .. }, Verdict::Wait(Reason::Moved))
                        | Refused::Discarded(Step::Designate { .. }, _)
                )
            })
            .count()
    }
}

/// Counts each request it forwards in `counts`, by key.
pub(crate) struct Counted<S> {
    pub(crate) inner: S,
    pub(crate) counts: Rc<RefCell<BTreeMap<Key, u64>>>,
}

impl<S: Store> Store for Counted<S> {
    fn read(&mut self, key: &Key) -> Result<Option<Item>, Unavailable> {
        *self.counts.borrow_mut().entry(*key).or_default() += 1;
        self.inner.read(key)
    }

    fn write(&mut self, key: &Key, write: &Write) -> Written {
        *self.counts.borrow_mut().entry(*key).or_default() += 1;
        self.inner.write(key, write)
    }

    fn namespace(&self) -> Namespace {
        self.inner.namespace()
    }
}

impl<S: Armed> Armed for Counted<S> {
    fn arm_next(&mut self, arm: Arm) -> usize {
        self.inner.arm_next(arm)
    }

    fn disarm(&mut self, before: usize) {
        self.inner.disarm(before);
    }
}

/// The effect a crash-table cell's arm waits for. `Write` takes the write to the key after skipping the count of
/// earlier writes to it; `Spare` takes a write to a volume record the run did not seed, after skipping the count;
/// `Reserve` takes the census write that names a new host in the shard's slot; `Attach` takes the attach request of
/// the volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Aim {
    Write(Key, u32),
    Spare(u32),
    Reserve(Zone, crate::net::ownership::Shard),
    Attach(VolumeId),
}

/// The effect state of one loop incarnation. `writes` and `calls` count its store writes and its attach, detach and
/// create calls since the last actuation; `taken` holds the (before, after) counts of the effect the arm cut, in
/// commits of the written key for a store write and in attachment-listing length for an attach request; `dead` is set
/// once the arm fired, after which every request of the incarnation fails; `condition` and `rewrites` count census
/// writes refused on their version condition and census writes that committed the value they found. `hook` runs once
/// at the first read of its key, after a read of `after` when that is set; `read` is the key the incarnation last
/// read.
#[derive(Default)]
pub(crate) struct Effected {
    pub(crate) writes: u64,
    pub(crate) calls: u64,
    pub(crate) aim: Option<(Aim, Arm)>,
    pub(crate) known: Vec<VolumeId>,
    pub(crate) taken: Option<(usize, usize)>,
    pub(crate) dead: bool,
    pub(crate) condition: u32,
    pub(crate) rewrites: u32,
    pub(crate) hook: Option<(Key, Box<dyn FnOnce()>)>,
    pub(crate) after: Option<Key>,
    pub(crate) read: Option<Key>,
}

/// A loop incarnation's crash boundary over the counted shared store: once the incarnation's arm fired, every read
/// is unavailable and every write unknown, and neither reaches the tally or the store.
pub(crate) struct Crashing {
    pub(crate) store: Counted<Shared>,
    pub(crate) effects: Rc<RefCell<Effected>>,
}

/// Whether `write` names a new host in `shard`'s slot of the census `current` holds.
fn reserves(current: Option<&Item>, write: &Write, shard: crate::net::ownership::Shard) -> bool {
    let value = match write {
        Write::Create(value) | Write::Exact { value, .. } => value,
    };
    let host = |bytes: &[u8]| {
        let census = Census::decode(bytes).ok()?;
        census.slot(shard).map(|entry| entry.host)
    };
    let proposed = host(value);
    proposed.is_some() && proposed != current.and_then(|item| host(&item.value))
}

impl Store for Crashing {
    fn read(&mut self, key: &Key) -> Result<Option<Item>, Unavailable> {
        if self.effects.borrow().dead {
            return Err(Unavailable);
        }
        let read = self.store.read(key);
        let due = {
            let effects = self.effects.borrow();
            let follows = effects
                .after
                .is_none_or(|after| effects.read == Some(after));
            follows && matches!(&effects.hook, Some((at, _)) if at == key)
        };
        self.effects.borrow_mut().read = Some(*key);
        let hook = match due {
            true => self.effects.borrow_mut().hook.take(),
            false => None,
        };
        if let Some((_, then)) = hook {
            then();
        }
        read
    }

    fn write(&mut self, key: &Key, write: &Write) -> Written {
        if self.effects.borrow().dead {
            return Written::Unknown;
        }
        let shared = &self.store.inner;
        let current = |store: &Shared| store.0.borrow().current(key).cloned();
        let before = current(shared);
        let arm = {
            let mut effects = self.effects.borrow_mut();
            effects.writes += 1;
            let spare = matches!(key, Key::Volume(volume) if !effects.known.contains(volume));
            let aimed = match &mut effects.aim {
                Some((Aim::Write(at, skip), arm)) if at == key => Some((Some(skip), *arm)),
                Some((Aim::Spare(skip), arm)) if spare => Some((Some(skip), *arm)),
                Some((Aim::Reserve(zone, shard), arm))
                    if *key == Key::Standbys(*zone) && reserves(before.as_ref(), write, *shard) =>
                {
                    Some((None, *arm))
                }
                _ => None,
            };
            match aimed {
                Some((Some(skip), _)) if *skip > 0 => {
                    *skip -= 1;
                    None
                }
                Some((_, arm)) => {
                    effects.aim = None;
                    effects.dead = true;
                    Some(arm)
                }
                None => None,
            }
        };
        let commits = shared.0.borrow().commit_count(key);
        let outcome = match arm {
            Some(arm) => {
                let held = self.store.arm_next(arm);
                let outcome = self.store.write(key, write);
                self.store.disarm(held);
                let after = self.store.inner.0.borrow().commit_count(key);
                self.effects.borrow_mut().taken = Some((commits, after));
                outcome
            }
            None => self.store.write(key, write),
        };
        let shared = &self.store.inner;
        let committed = shared.0.borrow().commit_count(key) > commits;
        let mut effects = self.effects.borrow_mut();
        let condition = Written::NotCommitted(StoreRefusal::Condition);
        let census = matches!(key, Key::Standbys(_));
        effects.condition += u32::from(census && outcome == condition);
        if census && committed {
            let value = |item: Option<Item>| item.map(|item| item.value);
            let unchanged = before.is_some() && value(before) == value(current(shared));
            effects.rewrites += u32::from(unchanged);
        }
        outcome
    }

    fn namespace(&self) -> Namespace {
        self.store.namespace()
    }
}

impl Armed for Crashing {
    fn arm_next(&mut self, arm: Arm) -> usize {
        self.store.arm_next(arm)
    }

    fn disarm(&mut self, before: usize) {
        self.store.disarm(before);
    }
}

/// A loop incarnation's calls on its zone double, through the incarnation's effect state: after the arm fired every
/// call fails unknown and reaches no double.
pub(crate) struct Effects<'a> {
    pub(crate) zone: &'a mut ZoneDouble,
    pub(crate) effects: Rc<RefCell<Effected>>,
}

impl Effects<'_> {
    fn call(&mut self, attaching: Option<VolumeId>) -> Option<Option<Arm>> {
        let mut effects = self.effects.borrow_mut();
        if effects.dead {
            return None;
        }
        effects.calls += 1;
        match (effects.aim, attaching) {
            (Some((Aim::Attach(at), arm)), Some(volume)) if at == volume => {
                effects.aim = None;
                effects.dead = true;
                Some(Some(arm))
            }
            _ => Some(None),
        }
    }
}

impl ControlPlane for Effects<'_> {
    fn attachments(&mut self, volume: &VolumeId) -> Result<Vec<String>, Unlisted> {
        if self.effects.borrow().dead {
            return Err(Unlisted);
        }
        ControlPlane::attachments(self.zone, volume)
    }
}

impl Provider for Effects<'_> {
    fn create(&mut self, token: &str, layout: Layout) -> Result<VolumeId, CreateError> {
        match self.call(None) {
            None => Err(CreateError::Unknown),
            Some(_) => Provider::create(self.zone, token, layout),
        }
    }
}

impl Attacher for Effects<'_> {
    /// An aimed request reaches the zone double once, under the double's own fault for the cell's ending, so the
    /// double logs it and checks its order whether or not it lands.
    fn attach(&mut self, volume: VolumeId, instance: InstanceId) -> AttachReply {
        use crate::failover::zone_loop::tests::world::AttachFault;
        let listed =
            |zone: &mut ZoneDouble| ControlPlane::attachments(zone, &volume).map_or(0, |l| l.len());
        let arm = match self.call(Some(volume)) {
            None => return AttachReply::Unknown,
            Some(None) => return Attacher::attach(self.zone, volume, instance),
            Some(Some(arm)) => arm,
        };
        let before = listed(self.zone);
        let fault = match arm {
            Arm::Pass => None,
            Arm::Timeout { commit } => Some(AttachFault::Unknown { attached: commit }),
            other => panic!("an attach cell's arm {other:?}"),
        };
        if let Some(fault) = fault {
            self.zone.faults.attach.push_front(fault);
        }
        let reply = Attacher::attach(self.zone, volume, instance);
        self.effects.borrow_mut().taken = Some((before, listed(self.zone)));
        reply
    }

    fn detach(&mut self, witness: Witness<'_>) -> DetachReply {
        match self.call(None) {
            None => DetachReply::Unknown,
            Some(_) => Attacher::detach(self.zone, witness),
        }
    }
}

struct Unreached;

impl ControlPlane for Unreached {
    fn attachments(&mut self, _: &VolumeId) -> Result<Vec<String>, Unlisted> {
        Err(Unlisted)
    }
}

impl Provider for Unreached {
    fn create(&mut self, _: &str, _: Layout) -> Result<VolumeId, CreateError> {
        Err(CreateError::Unknown)
    }
}

impl Attacher for Unreached {
    fn attach(&mut self, _: VolumeId, _: InstanceId) -> AttachReply {
        AttachReply::Unknown
    }

    fn detach(&mut self, _: Witness<'_>) -> DetachReply {
        DetachReply::Unknown
    }
}

pub(crate) type Raced = Rc<RefCell<Option<(Loop, Survey, Vec<Outcome>)>>>;

pub(crate) fn bounds() -> Bounds {
    crate::storage::gate_fixture::bounds_of(crate::storage::gate_fixture::limits())
}

pub(crate) fn loop_now(round: u64) -> u64 {
    round * ROUND_US
}

pub(crate) fn zone_config(zone: Zone, shards: usize, cap: usize) -> ZoneConfig {
    let held = bounds();
    let owner = OwnerBounds {
        registrant_max: held.registrant_max(),
        retry_max: held.retry_max(),
        window: held.window(),
        report_deadline: held.report_deadline(),
        report_period: held.report_period(),
        clock_error: 0,
    };
    let letter = char::from(b'a' + (zone.0 as u8).saturating_sub(1) % 26);
    let mut config = ZoneConfig::defaults(
        zone,
        format!("us-east-1{letter}"),
        shards,
        owner,
        crate::storage::warm_sim::layout(),
        PathBuf::from(format!("/etc/kestrike/zone-{}.directory", zone.0)),
        REPORT_ROUNDS * ROUND_US,
    );
    let rounds = |n: u64| n * ROUND_US;
    config.tick_us = rounds(TICK_ROUNDS);
    config.fresh_periods = 2;
    config.silent_periods = 3;
    config.stopped_dwell_us = rounds(20);
    config.impaired_dwell_us = rounds(20);
    config.attach_settle_us = rounds(5);
    config.attach_stuck_us = rounds(120);
    config.detach_settle_us = DETACH_SETTLE_FLOOR_US + ROUND_US;
    config.enroll_stuck_us = rounds(120);
    config.create_settle_us = rounds(10);
    config.standby_target_us = rounds(400);
    config.create_backoff_us = rounds(10);
    config.create_backoff_max_us = rounds(80);
    config.attach_window_us = rounds(100);
    config.population_cap = cap;
    config
}

pub(super) fn zone_double(fleet: &Fleet<'_>, zone: Zone) -> ZoneDouble {
    let mut double = ZoneDouble::new(zone);
    double.store = Some(fleet.store.clone());
    let members = fleet.topology.members.iter();
    for member in members.filter(|member| member.zone == zone) {
        double.instances.push(Instance {
            instance: member.instance,
            state: InstanceState::Running,
            system_check: StatusCheck::Ok,
            instance_check: StatusCheck::Ok,
        });
    }
    for cell in fleet
        .cells
        .iter()
        .filter(|cell| cell.placement.zone == zone)
    {
        let condition = VolumeCondition {
            state: ListedVolumeState::InUse,
            status: VolumeStatus::Ok,
        };
        double.volume(cell.placement.volume, condition);
        for member in cell.attached() {
            let instance = fleet.topology.members[member].instance;
            double.attach(cell.placement.volume, instance);
        }
    }
    double
}

impl Fleet<'_> {
    pub(super) fn repairs(&self) -> bool {
        !self.reconcilers.is_empty()
    }

    pub(super) fn quiet(&self) -> bool {
        let running = self
            .reconcilers
            .iter()
            .filter(|actor| actor.status == Status::Running);
        running
            .into_iter()
            .all(|actor| actor.zone_loop.is_some() && actor.planned == 0)
    }

    pub(super) fn booted_all(&self) -> bool {
        self.recon.booted.len() == usize::from(self.config.shape.zones)
    }

    pub(super) fn double(&mut self, zone: Zone) -> Option<&mut ZoneDouble> {
        self.zones.iter_mut().find(|double| double.zone == zone)
    }

    pub(super) fn zone_of(&self, at: usize) -> Zone {
        self.cells[at].placement.zone
    }

    pub(super) fn zone_cells(&self, zone: Zone) -> Vec<usize> {
        (0..self.cells.len())
            .filter(|&at| self.zone_of(at) == zone)
            .collect()
    }

    pub(super) fn cell_of(&self, shard: crate::net::ownership::Shard) -> Option<usize> {
        (self.cells.iter()).position(|cell| cell.placement.shard == shard)
    }

    pub(crate) fn lost(&self, host: Host) -> bool {
        if self.zones.is_empty() {
            return false;
        }
        let member = (self.topology.members.iter()).find(|of| of.host == host);
        member.is_none_or(|of| {
            let double = self.zones.iter().find(|double| double.zone == of.zone);
            let instances = double.map_or(&[][..], |double| double.instances.as_slice());
            let instance = instances.iter().find(|i| i.instance == of.instance);
            instance.is_none_or(|i| i.state != InstanceState::Running)
        })
    }

    pub(super) fn list_instance(&mut self, member: usize, state: InstanceState) {
        let of = self.topology.members[member];
        if let Some(double) = self.double(of.zone)
            && let Some(listed) = double
                .instances
                .iter_mut()
                .find(|i| i.instance == of.instance)
        {
            listed.state = state;
        }
    }

    pub(super) fn member_of(&self, host: Host) -> Option<usize> {
        self.topology.members.iter().position(|of| of.host == host)
    }

    pub(super) fn seed_census(&mut self) {
        use crate::failover::report::Gauge;
        use crate::failover::standbys::{Attach, Population};
        let population = Population {
            cap: usize::from(self.config.shape.cap),
        };
        for zone in (1..=self.config.shape.zones).map(Zone) {
            let mut census = Census::empty(zone);
            for at in self.zone_cells(zone) {
                let record = self.record_now(at);
                let Some(standby) = record.standby else {
                    continue;
                };
                let report = crate::failover::standbys::tests::report_of(
                    standby,
                    Gauge::known(0, 64),
                    Gauge::known(0, 2),
                );
                let admitted =
                    population.admit(&census, &record, &report, Attach::Live, |_| None, |_| false);
                if let Ok(Some(admitted)) = admitted {
                    census = admitted;
                }
            }
            let write = Write::Create(census.encode());
            let outcome = Store::write(&mut self.store.clone(), &Key::Standbys(zone), &write);
            assert!(matches!(outcome, Written::Committed(_)), "{outcome:?}");
        }
    }

    fn recon_store(&self, r: usize) -> ReconStore {
        let actor = &self.reconcilers[r];
        Faulted {
            inner: AsReconciler(Crashing {
                store: Counted {
                    inner: self.store.clone(),
                    counts: self.tallied.clone(),
                },
                effects: actor.effects.clone(),
            }),
            actor: actor.actor_id(self.topology.members.len()),
            faults: self.faults.store.clone(),
        }
    }

    pub(super) fn recon_client(&self, r: usize) -> Reconciler<ReconStore, MemLog> {
        let client = Client::open(self.recon_store(r), MemLog::default());
        Reconciler::new(client.expect("a reconciler's store client"))
    }

    /// `member`'s enrollment client, whose reads list in `failed` each key whose returned value fails its decode.
    pub(super) fn enroll_client(
        &self,
        member: usize,
        failed: &Rc<RefCell<Vec<Key>>>,
    ) -> Client<Decoding<Faulted<Counted<Shared>>>, MemLog> {
        let store = Faulted {
            inner: Counted {
                inner: self.store.clone(),
                counts: self.tallied.clone(),
            },
            actor: member as u32,
            faults: self.faults.store.clone(),
        };
        let store = Decoding {
            inner: store,
            failed: failed.clone(),
        };
        Client::open(store, self.hosts[member].log.clone()).expect("a host's store client")
    }

    pub(super) fn directory(&self, zone: Zone) -> Directory<ReconcilerProjection> {
        let hosts: Vec<HostEntry> = (self.topology.members.iter())
            .filter(|of| of.zone == zone)
            .map(|of| HostEntry {
                host: of.host,
                instance: of.instance,
                placement: Placed {
                    zone,
                    partition: of.partition,
                    color: Color(of.partition.0 as u16),
                },
                state: match self.recon.retired.contains(&of.host.get()) {
                    true => DirectoryState::Retired,
                    false => DirectoryState::Active,
                },
            })
            .collect();
        let shards = (self.zone_cells(zone).into_iter())
            .map(|at| ShardEntry {
                shard: self.cells[at].placement.shard,
                zone,
                layout: crate::storage::warm_sim::layout(),
            })
            .collect();
        let keys = (hosts.iter())
            .map(|entry| {
                let key = ReportKey::derive(&host_key(entry.host));
                (entry.host, DerivedKey::Report(key))
            })
            .collect();
        let listing = Listing {
            version: 1 + u64::from(!self.recon.retired.is_empty()),
            zone,
            zone_hold: false,
            host_roles_max: self.config.shape.roles_max,
            hosts,
            shards,
        };
        Directory::new(listing, keys).expect("the fleet's directory")
    }

    fn open_loop(&self, r: usize) -> Loop {
        let actor = &self.reconcilers[r];
        let shards = self.zone_cells(actor.zone).len();
        let config = zone_config(actor.zone, shards, actor.cap);
        let bounds: ZoneBounds = config.validate().expect("the fleet's zone configuration");
        ZoneLoop::new(self.recon_client(r), bounds)
    }

    fn drop_entry(&mut self) {
        let super::Profile::Hostile(Plant::UncoveredEntry, at) = self.config.profile else {
            return;
        };
        let Some(cell) = self.cells.get(at as usize) else {
            return;
        };
        let zone = cell.placement.zone;
        if self.recon.planted || !self.recon.covered.contains(&zone.0) {
            return;
        }
        let Some(census) = self.census_now(zone) else {
            return;
        };
        let shard = self.cells[at as usize].placement.shard;
        let Some(entry) = census.slot(shard) else {
            return;
        };
        let moved = ShardRecord {
            standby: None,
            owner: entry.host,
            attempts: entry.target.attempts + 1,
            ..self.record_now(at as usize)
        };
        let Some(dropped) = census.released(&moved, |_| false) else {
            return;
        };
        let key = Key::Standbys(zone);
        let item = (self.store.0.borrow().current(&key).cloned()).expect("a stored census");
        let write = Write::Exact {
            expect: item.version,
            value: dropped.encode(),
        };
        let outcome = Store::write(&mut self.store.clone(), &key, &write);
        self.recon.planted = matches!(outcome, Written::Committed(_));
        self.planted |= self.recon.planted;
    }

    pub(super) fn census_now(&self, zone: Zone) -> Option<Census> {
        let store = self.store.0.borrow();
        let item = store.current(&Key::Standbys(zone))?;
        Some(Census::decode(&item.value).expect("a stored census"))
    }

    pub(super) fn census_versions(&self) -> Vec<usize> {
        let store = self.store.0.borrow();
        let versions = (1..=self.config.shape.zones)
            .flat_map(|zone| store.versions(&Key::Standbys(Zone(zone))).iter());
        versions
            .map(|item| Census::decode(&item.value).expect("a stored census").len())
            .collect()
    }

    pub(super) fn record_now(&self, at: usize) -> ShardRecord {
        let store = self.store.0.borrow();
        let item = store.current(&Key::Shard(self.cells[at].placement.shard));
        ShardRecord::decode(&item.expect("a stored shard record").value).expect("a shard record")
    }

    pub(super) fn volume_now(&self, at: usize) -> VolumeRecord {
        let store = self.store.0.borrow();
        let item = store.current(&Key::Volume(self.cells[at].placement.volume));
        VolumeRecord::decode(&item.expect("a stored volume record").value).expect("a volume record")
    }

    pub(super) fn check_census(&mut self, r: usize) {
        self.drop_entry();
        let acting = self.reconcilers[r].zone;
        let mut censuses = vec![(acting, self.census_now(acting))];
        let len = censuses[0].1.as_ref().map_or(0, Census::len);
        self.recon.at_cap += u32::from(len >= usize::from(self.config.shape.cap));
        if self.recon.uncovered.is_some() {
            return;
        }
        for at in 0..self.cells.len() {
            let zone = self.zone_of(at);
            if !self.recon.covered.contains(&zone.0) {
                continue;
            }
            let record = self.record_now(at);
            if censuses.iter().all(|(of, _)| *of != zone) {
                censuses.push((zone, self.census_now(zone)));
            }
            let census = censuses.iter().find(|(of, _)| *of == zone);
            let census = census.and_then(|(_, census)| census.as_ref());
            let listed = census.and_then(|c| c.slot(record.shard));
            if record.standby.is_some() && listed.is_none() {
                let round = self.round - self.host_start;
                self.recon.uncovered = Some((record.shard.get(), round));
                return;
            }
        }
    }

    fn covers(&self, zone: Zone) -> bool {
        let census = self.census_now(zone);
        (self.zone_cells(zone).into_iter()).all(|at| {
            let record = self.record_now(at);
            let named = record.standby.is_some_and(|standby| !self.lost(standby));
            !named
                || census
                    .as_ref()
                    .is_some_and(|c| c.slot(record.shard).is_some())
        })
    }

    pub(crate) fn served_with_standby(&self, live: &super::Live<'_>, at: usize) -> bool {
        let record = self.record_now(at);
        let up = |host: Host| {
            (self.member_of(host))
                .is_some_and(|member| self.hosts[member].up == Up::Running && !self.lost(host))
        };
        let serving = up(record.owner)
            && (live[at].as_ref())
                .is_some_and(|serving| super::serves(&self.cells[at], serving, &record));
        let volume = self.volume_now(at);
        let listed = (self.census_now(self.zone_of(at))).and_then(|c| c.slot(record.shard));
        let standby = record.standby.is_some_and(|standby| {
            up(standby)
                && volume.enrolled(standby).is_some()
                && listed.is_some_and(|entry| entry.host == standby)
        });
        serving && standby
    }

    pub(crate) fn settled_at(&self, live: &super::Live<'_>, at: usize) -> super::oracles::Settled {
        super::oracles::Settled {
            shard: self.cells[at].placement.shard,
            served: self.served_with_standby(live, at),
            blocker: self.cells[at].blocker,
        }
    }

    pub(super) fn reconcile_round(&mut self) {
        if self.draws.is_none() || self.draw_refusal.is_some() {
            return;
        }
        let round = self.round;
        if !round.is_multiple_of(TICK_ROUNDS) {
            return;
        }
        for actor in &mut self.reconcilers {
            if let Status::Down { until } = actor.status
                && until <= round
            {
                actor.restart();
                actor.started = round;
                self.recon.restarts += 1;
            }
        }
        let mut ready: Vec<usize> = (0..self.reconcilers.len())
            .filter(|&r| self.reconcilers[r].status == Status::Running)
            .collect();
        let mut order = Vec::new();
        while ready.len() > 1 {
            let values: Vec<u64> = ready.iter().map(|&r| r as u64).collect();
            let settling = self.recon.settle.is_some();
            let oldest = (0..ready.len())
                .min_by_key(|&i| (self.reconcilers[ready[i]].ran, ready[i]))
                .expect("a ready reconciler");
            let picked = self.with_draws(|draws| match settling {
                true => draws.forced(draws::RECONCILER, Tag::Actor, &values, oldest),
                false => draws.pick(draws::RECONCILER, Tag::Actor, &values),
            });
            match picked {
                Ok(at) => {
                    self.recon.orders += 1;
                    order.push(ready.remove(at));
                }
                Err(refusal) => {
                    self.draw_refusal = Some(refusal);
                    return;
                }
            }
        }
        order.extend(ready);
        self.plant_loss();
        let mut surveyed = Vec::new();
        for r in order {
            self.reconcilers[r].ran = round;
            self.recon.calls += 1;
            self.actuate_held(r);
            surveyed.push((r, self.survey_turn(r)));
        }
        // The race runs reconciler 1's actuation inside reconciler 0's census read, so on a round it can fall due
        // reconciler 0 actuates first; reconciler 1's own survey of the round is then superseded.
        let racing = self.config.scenario == Scenario::Racing && !self.recon.raced;
        if racing && let Some(at) = surveyed.iter().position(|(r, _)| *r == 0) {
            let first = surveyed.remove(at);
            surveyed.insert(0, first);
        }
        for (r, survey) in surveyed {
            if self.reconcilers[r].status != Status::Running {
                continue;
            }
            if self.hold(r, &survey) {
                self.reconcilers[r].held = Some(survey);
                continue;
            }
            self.actuate_turn(r, survey);
            self.check_census(r);
        }
        self.unnamed_waits();
        self.provided();
        let breaks: usize = self.zones.iter().map(|double| double.breaks.len()).sum();
        self.recon.unordered = breaks as u32;
        self.recon.tick_after_settle();
        self.plant_settled_write();
        let paused = self.hosts.iter().any(|host| host.up == Up::Paused);
        self.recon.paused_ticks += u32::from(paused);
    }

    fn with_draws<T>(&mut self, f: impl FnOnce(&mut Draws) -> T) -> T {
        let mut draws = self.draws.take().expect("the run's decisions");
        let out = f(&mut draws);
        self.draws = Some(draws);
        out
    }

    /// In the two-reconciler scenario, after the race, reconciler 1 keeps the first survey that plans a designation
    /// and actuates it a round later.
    fn hold(&self, r: usize, survey: &Survey) -> bool {
        let racing = self.config.scenario == Scenario::Racing && r == 1 && self.recon.raced;
        let designates =
            (survey.plan.steps.iter()).any(|step| matches!(step, Step::Designate { .. }));
        let first = !self
            .recon
            .refusals
            .iter()
            .any(|(_, _, refused)| matches!(refused, Refused::Discarded(..)));
        racing && designates && first && self.reconcilers[r].held.is_none()
    }

    /// Actuates the survey reconciler `r` kept from an earlier round. TICK-ORDER refuses it before any effect, and
    /// each designation it planned is logged with the refusal.
    fn actuate_held(&mut self, r: usize) {
        let Some(survey) = self.reconcilers[r].held.take() else {
            return;
        };
        let now = loop_now(self.round);
        let gate = StandbyGate::qualified();
        let zone_loop = self.reconcilers[r]
            .zone_loop
            .as_mut()
            .expect("an open loop");
        let Err(discard) = zone_loop.actuate(&gate, &survey, now, &mut Unreached) else {
            panic!("an actuation over an earlier tick's survey applies");
        };
        for step in &survey.plan.steps {
            if let Step::Designate { shard, .. } = step {
                self.recon
                    .refuse(shard.get(), Refused::Discarded(*step, discard));
            }
        }
    }

    /// The index of `zone`'s double among the fleet's zone doubles.
    fn double_at(&self, zone: Zone) -> usize {
        let at = (self.zones.iter()).position(|double| double.zone == zone);
        at.expect("a repairing fleet's zone double")
    }

    fn survey_turn(&mut self, r: usize) -> Survey {
        if self.reconcilers[r].zone_loop.is_none() {
            let opened = self.open_loop(r);
            self.reconcilers[r].zone_loop = Some(opened);
            self.sealers.open(r, loop_now(TICK_ROUNDS));
        }
        let now = loop_now(self.round);
        let zone = self.reconcilers[r].zone;
        let directory = self.directory(zone);
        let at = self.double_at(zone);
        let tick = {
            let (actors, zones) = (&mut self.reconcilers, &mut self.zones);
            let zone_loop = actors[r].zone_loop.as_mut().expect("an open loop");
            zone_loop.tick(Ok(directory), &mut zones[at], now)
        };
        // The actor seals the tick's status part as the service shell does, before the plant and the actuation.
        (self.sealers).seal(r, &tick.part, now, &mut self.alarms);
        let past = crate::failover::report::status::Standby::Past as usize;
        self.recon.past_target += u32::from(tick.part.standby[past] > 0);
        let mut survey = tick.survey;
        self.plant_survey(&mut survey);
        survey
    }

    fn actuate_turn(&mut self, r: usize, survey: Survey) {
        let now = loop_now(self.round);
        let zone = self.reconcilers[r].zone;
        let at = self.double_at(zone);
        self.aim(r);
        self.race(r, &survey, now);
        self.move_slot(r, &survey);
        let gate = StandbyGate::qualified();
        let effects = self.reconcilers[r].effects.clone();
        let commits = |fleet: &Self| -> Vec<usize> {
            let store = fleet.store.0.borrow();
            let keys = fleet
                .cells
                .iter()
                .map(|cell| Key::Shard(cell.placement.shard));
            keys.map(|key| store.commit_count(&key)).collect()
        };
        let before = commits(self);
        let replacing = matches!(self.config.scenario, Scenario::Replace(_));
        let total = |fleet: &Self| -> usize {
            if !replacing {
                return 0;
            }
            let shard = fleet.cells[0].placement.shard;
            let seeded: Vec<VolumeId> = fleet
                .cells
                .iter()
                .map(|cell| cell.placement.volume)
                .collect();
            let store = fleet.store.0.borrow();
            let replaced = |key: &Key| match key {
                Key::Replacement(of) | Key::Shard(of) => *of == shard,
                Key::Volume(volume) => !seeded.contains(volume),
                _ => false,
            };
            let keys: Vec<Key> = store.keys().filter(|key| replaced(key)).copied().collect();
            keys.iter().map(|key| store.commit_count(key)).sum()
        };
        let committed = total(self);
        let outcomes = {
            let (actors, zones) = (&mut self.reconcilers, &mut self.zones);
            let zone_loop = actors[r].zone_loop.as_mut().expect("an open loop");
            let mut calls = Effects {
                zone: &mut zones[at],
                effects: effects.clone(),
            };
            zone_loop.actuate(&gate, &survey, now, &mut calls)
        };
        let outcomes = match outcomes {
            Ok(outcomes) => outcomes,
            Err(Discard::Superseded) if self.superseded == Some(r) => Vec::new(),
            Err(discard) => panic!("reconciler {r}'s actuation of its tick's survey: {discard:?}"),
        };
        if self.superseded == Some(r) {
            self.superseded = None;
        }
        self.raced_back();
        self.logged(r, &survey, &outcomes);
        self.step_commits = total(self) - committed;
        let after = commits(self);
        for at in (0..self.cells.len()).filter(|&at| after[at] != before[at]) {
            self.reread_hosts(at);
        }
        self.reconcilers[r].planned = survey.plan.steps.len();
        let status = survey.status;
        let (dead, taken, condition, rewrites) = {
            let mut held = effects.borrow_mut();
            let condition = std::mem::take(&mut held.condition);
            let rewrites = std::mem::take(&mut held.rewrites);
            self.recon.effects.0 += std::mem::take(&mut held.writes);
            self.recon.effects.1 += std::mem::take(&mut held.calls);
            (held.dead, held.taken.take(), condition, rewrites)
        };
        self.recon.condition += condition;
        self.recon.rewrites += rewrites;
        if dead && let Some(taken) = taken {
            self.crashed(r, taken);
        }
        let held = status.holds.zone_host;
        self.recon.zone_held = if held { self.recon.zone_held + 1 } else { 0 };
        if held {
            self.recon
                .zone_held_rounds
                .push(self.round - self.host_start);
        }
        self.retire_lost();
        let warm = !status.holds.warm_up;
        if self.covers(zone) {
            self.recon.covered.insert(zone.0);
            self.recon.booted.insert(zone.0);
        } else if warm {
            self.recon.booted.insert(zone.0);
        }
    }

    pub(super) fn drop_loop(&mut self, r: usize) {
        let until = self.round + RESTART_ROUNDS;
        let actor = &mut self.reconcilers[r];
        actor.zone_loop = None;
        actor.status = Status::Down { until };
    }

    fn aim(&mut self, r: usize) {
        if r != 0 || self.reconcilers[r].effects.borrow().aim.is_some() {
            return;
        }
        let aim = match self.config.scenario {
            Scenario::Crash(cell) => self.enroll_aim(cell).map(|aim| (aim, cell.ending)),
            Scenario::Replace(cell) => self.replace_aim(cell).map(|aim| (aim, cell.ending)),
            _ => None,
        };
        let Some((aim, ending)) = aim else {
            return;
        };
        let known = self
            .cells
            .iter()
            .map(|cell| cell.placement.volume)
            .collect();
        let mut effects = self.reconcilers[r].effects.borrow_mut();
        (effects.aim, effects.known) = (Some((aim, ending.arm())), known);
    }

    /// The cell of loop 0's zone whose record shows the first need after the loss, and that need: the repair a
    /// crash-table cell cuts.
    pub(super) fn repaired(&self) -> Option<(usize, Need)> {
        let zone = self.reconcilers.first()?.zone;
        (self.zone_cells(zone).into_iter())
            .find_map(|at| Some((at, need(&self.record_now(at), |host| self.lost(host))?)))
    }

    fn enroll_aim(&mut self, cell: CrashCell) -> Option<Aim> {
        let first = self.recon.crashed.is_empty() && self.log.host_losses > 0;
        if !first || cell.call == Call::Enroll {
            return None;
        }
        let (at, need) = self.repaired()?;
        let placement = self.cells[at].placement;
        self.recon.crash_aim = Some((placement.shard.get(), need));
        Some(match cell.call {
            Call::Reserve => Aim::Reserve(placement.zone, placement.shard),
            Call::Record => Aim::Write(Key::Volume(placement.volume), 0),
            Call::Attach => Aim::Attach(placement.volume),
            Call::Enroll | Call::Designate => Aim::Write(Key::Shard(placement.shard), 0),
        })
    }

    fn crashed(&mut self, r: usize, taken: (usize, usize)) {
        // An acknowledged reservation advanced its step, which `logged` counted; a committed one with an unknown
        // reply waits, so its count comes from the store.
        let reserved = matches!(self.config.scenario,
            Scenario::Crash(cell) if cell.call == Call::Reserve && cell.ending == Ending::Committed);
        self.recon.reservations += u32::from(reserved && taken.1 > taken.0);
        let name = match self.config.scenario {
            Scenario::Crash(cell) => cell.name(),
            Scenario::Replace(cell) => {
                self.replace_crashed(cell);
                cell.name()
            }
            _ => String::new(),
        };
        self.recon.crashed.push(name);
        self.recon.crash_writes.push(taken);
        self.drop_loop(r);
    }

    /// The operator retires the crashed hosts to end the zone host hold in the exhausted-attach case.
    fn retire_lost(&mut self) {
        let shard = super::hosts::ATTACH_CELL as u32 + 1;
        let acted = match self.config.scenario {
            Scenario::AttachClosed => self.recon.reclaims.contains(&(shard, Reclaim::End)),
            _ => false,
        };
        let due = self.recon.zone_held >= RETIRE_TICKS && acted && self.recon.retired.is_empty();
        if !due {
            return;
        }
        let crashed = (self.hosts.iter()).filter(|host| host.up == super::hosts::Up::Down);
        self.recon.retired = crashed.map(|host| host.host.get()).collect();
    }

    /// The settled-write plant: on the first reconciler round inside the fixpoint count, loop 0's store rewrites zone
    /// 1's census at its version with the value it holds, a store write the loop's effect counters count.
    fn plant_settled_write(&mut self) {
        let planted = self.config.planted(Plant::SettledWrite);
        if !planted || self.planted || self.recon.fixpoint_ticks == 0 {
            return;
        }
        let key = Key::Standbys(Zone(1));
        let Some(item) = self.store.0.borrow().current(&key).cloned() else {
            return;
        };
        let write = Write::Exact {
            expect: item.version,
            value: item.value,
        };
        let outcome = Store::write(&mut self.recon_store(0), &key, &write);
        self.planted = matches!(outcome, Written::Committed(_));
        let effects = self.reconcilers[0].effects.clone();
        self.recon.effects.0 += std::mem::take(&mut effects.borrow_mut().writes);
    }

    /// The loss-evidence plant: once the planted shard's host is lost and its takeover's load has swept, the zone
    /// double lists the shard's volume in state `error`, with the injector's lost volumes unchanged.
    fn plant_loss(&mut self) {
        let super::Profile::Hostile(Plant::LossEvidence, at) = self.config.profile else {
            return;
        };
        let at = at as usize;
        let swept = |cell: &super::Cell| cell.recoveries.len() >= 2;
        let taken = self.cells.get(at).is_some_and(swept) && self.takeover_loads().next().is_none();
        if self.planted || !taken || !self.host_lost.contains(&at) {
            return;
        }
        self.planted = true;
        let volume = self.cells[at].placement.volume;
        let lost = VolumeCondition {
            state: ListedVolumeState::Error,
            status: VolumeStatus::Impaired,
        };
        if let Some(double) = self.double(self.zone_of(at)) {
            double.volume(volume, lost);
        }
    }

    fn plant_survey(&mut self, survey: &mut Survey) {
        let super::Profile::Hostile(Plant::DropNeed, at) = self.config.profile else {
            return;
        };
        let Some(cell) = self.cells.get(at as usize) else {
            return;
        };
        let shard = cell.placement.shard;
        let enrolls = |step: &Step| {
            matches!(
                step,
                Step::Reserve { .. }
                    | Step::RecordAttach { .. }
                    | Step::Attach { .. }
                    | Step::Designate { .. }
            )
        };
        let before = survey.plan.steps.len();
        (survey.plan.steps).retain(|step| step.shard() != shard || !enrolls(step));
        if survey.plan.steps.len() < before {
            self.planted = true;
        }
    }

    fn race(&mut self, r: usize, survey: &Survey, now: u64) {
        let racing = self.config.scenario == Scenario::Racing;
        if !racing || r != 0 || self.reconcilers.len() < 2 || self.recon.raced {
            return;
        }
        if self.log.host_losses == 0 || self.census_now(self.reconcilers[0].zone).is_none() {
            return;
        }
        let reserves = (survey.plan.steps.iter()).find_map(|step| match step {
            Step::Reserve { shard, .. } => Some(*shard),
            _ => None,
        });
        let Some(shard) = reserves else {
            return;
        };
        let surveyed = self.survey_turn(1);
        let mut other = self.reconcilers[1].zone_loop.take().expect("an open loop");
        let raced = self.raced.clone();
        let then = move || {
            let gate = StandbyGate::qualified();
            let outcomes = other.actuate(&gate, &surveyed, now, &mut Unreached);
            let outcomes = outcomes.unwrap_or_else(|discard| {
                panic!("the race's actuation of its own tick's survey: {discard:?}")
            });
            *raced.borrow_mut() = Some((other, surveyed, outcomes));
        };
        let key = Key::Standbys(self.reconcilers[0].zone);
        self.reconcilers[0].effects.borrow_mut().hook = Some((key, Box::new(then)));
        self.recon.race_shard = self.cell_of(shard);
    }

    /// The slot-moved case: inside the census read of loop 0's first designation after the loss, a simulated second
    /// writer moves that shard's census slot to another running host of the zone, at the read version and with the
    /// slot's target unchanged. The witness is set once that write committed.
    fn move_slot(&mut self, r: usize, survey: &Survey) {
        let due = self.config.scenario == Scenario::SlotMoved && r == 0;
        if !due || self.log.host_losses == 0 || self.recon.slot_moved.is_some() {
            return;
        }
        let designated = (survey.plan.steps.iter()).find_map(|step| match step {
            Step::Designate { shard, host, .. } => Some((*shard, *host)),
            _ => None,
        });
        let Some((shard, host)) = designated else {
            return;
        };
        let zone = self.reconcilers[r].zone;
        let owner = self.cell_of(shard).map(|at| self.record_now(at).owner);
        let members = self.topology.members.iter();
        let other = members.into_iter().find(|of| {
            of.zone == zone
                && of.host != host
                && Some(of.host) != owner
                && !self.lost(of.host)
                && self
                    .member_of(of.host)
                    .is_some_and(|m| self.hosts[m].up == Up::Running)
        });
        let Some(other) = other.map(|of| of.host) else {
            return;
        };
        let (store, moved) = (self.store.clone(), self.moved.clone());
        let then = move || {
            let key = Key::Standbys(zone);
            let item = (store.0.borrow().current(&key).cloned()).expect("a stored census");
            let census = Census::decode(&item.value).expect("a stored census");
            let slot = census.slot(shard).expect("the designation's census slot");
            assert_eq!(slot.host, host, "the slot names the designation's host");
            let rehosted = crate::failover::standbys::tests::rehosted(&census, shard, other);
            let rehosted = rehosted.expect("the designation's census slot");
            let write = Write::Exact {
                expect: item.version,
                value: rehosted.encode(),
            };
            let outcome = Store::write(&mut store.clone(), &key, &write);
            assert!(matches!(outcome, Written::Committed(_)), "{outcome:?}");
            let after = (store.0.borrow().current(&key).cloned()).expect("a stored census");
            let after = Census::decode(&after.value).expect("a stored census");
            let slot = after.slot(shard).expect("the moved slot");
            assert_eq!((slot.host, after.len()), (other, census.len()));
            *moved.borrow_mut() = Some((shard.get(), host.get(), other.get()));
        };
        let mut effects = self.reconcilers[r].effects.borrow_mut();
        effects.hook = Some((Key::Standbys(zone), Box::new(then)));
        effects.after = Some(Key::Shard(shard));
    }

    /// Clears loop 0's read hook after its actuation, takes the slot-moved witness if that hook's write committed,
    /// and returns reconciler 1's loop from the race, whose survey of the round it superseded.
    fn raced_back(&mut self) {
        if self.reconcilers.is_empty() {
            return;
        }
        let mut effects = self.reconcilers[0].effects.borrow_mut();
        let unfired = effects.hook.take().is_some();
        effects.after = None;
        drop(effects);
        if let Some(moved) = self.moved.borrow_mut().take() {
            self.recon.slot_moved = Some(moved);
        }
        let Some((other, survey, outcomes)) = self.raced.borrow_mut().take() else {
            let lost = unfired && self.config.scenario == Scenario::Racing;
            assert!(!lost, "reconciler 0 read no census, so the race never ran");
            return;
        };
        self.reconcilers[1].zone_loop = Some(other);
        self.recon.raced = true;
        self.superseded = Some(1);
        self.logged(1, &survey, &outcomes);
    }

    fn logged(&mut self, r: usize, survey: &Survey, outcomes: &[Outcome]) {
        let after_loss = self.log.host_losses > 0;
        let round = self.round - self.host_start;
        let status = &survey.status;
        let need_of = |shard| {
            let row = status.shards.iter().find(|row| row.shard == shard);
            row.and_then(|row| match row.state {
                ShardState::Enrolling { need, .. } => Some(need),
                _ => None,
            })
        };
        for row in &status.shards {
            let Some(at) = self.cell_of(row.shard) else {
                continue;
            };
            if let ShardState::Enrolling { host, .. } = row.state
                && !self.cells[at].planned.iter().any(|(of, _)| *of == host)
            {
                let live = self.volume_now(at).live(host).is_some();
                self.cells[at].planned.push((host, live));
            }
        }
        self.recon.cap_below = (status.cap_below).map(|below| (below.cap, below.shards));
        for outcome in outcomes {
            let shard = outcome.step.shard();
            let Some(at) = self.cell_of(shard) else {
                continue;
            };
            if matches!(outcome.step, Step::Replace { .. }) {
                self.replace_logged(at, outcome);
            }
            match (outcome.step, outcome.verdict) {
                (Step::Reserve { .. }, Verdict::Advance) => {
                    self.recon.reservations += 1;
                    self.recon.contended += u32::from(r == 1 && after_loss);
                }
                (Step::Designate { host, .. }, Verdict::Advance) => {
                    let repair = need_of(shard).map_or(Repair::Cover, Repair::Need);
                    if repair == Repair::Need(Need::Fresh)
                        && let Some(member) = self.member_of(host)
                    {
                        let owner = self.cells[at].owner;
                        self.recon.premise_failed |= !self.prober_premise(member, owner);
                    }
                    let planned = self.cells[at].planned.iter();
                    let attached = planned.rev().find(|(of, _)| *of == host);
                    self.recon.designations.push(Designation {
                        shard: shard.get(),
                        host: host.get(),
                        repair,
                        attached: attached.is_some_and(|(_, live)| *live),
                        after_loss,
                        round,
                    });
                }
                (Step::Release { .. }, Verdict::Advance) => self.recon.releases += 1,
                (Step::End { .. }, Verdict::Advance) => {
                    self.recon.reclaims.push((shard.get(), Reclaim::End));
                }
                (Step::Detach { .. }, Verdict::Advance) => {
                    self.recon.reclaims.push((shard.get(), Reclaim::Detach));
                }
                (Step::ReleaseAttach { .. }, Verdict::Advance) => {
                    self.recon.reclaims.push((shard.get(), Reclaim::Release));
                }
                (step, verdict @ (Verdict::Wait(_) | Verdict::Alarm(_)))
                    if !matches!(verdict, Verdict::Wait(Reason::Budget | Reason::Settling)) =>
                {
                    self.recon.refuse(shard.get(), Refused::Step(step, verdict));
                }
                _ => {}
            }
        }
        if survey.status.holds.warm_up {
            return;
        }
        for row in &survey.status.shards {
            if let Some(at) = self.cell_of(row.shard) {
                self.full(at, row.blocker);
                self.collect(at, row.state, row.blocker);
            }
        }
    }

    /// Counts the first `CensusFull` row of each of cell `at`'s needs, with the need, whether the zone double lists the
    /// owner running, and the census entry count.
    fn full(&mut self, at: usize, blocker: Option<Blocker>) {
        if blocker != Some(Blocker::CensusFull) {
            return;
        }
        let record = self.record_now(at);
        let Some(need) = need(&record, |host| self.lost(host)) else {
            return;
        };
        let shard = record.shard.get();
        let repair = Repair::Need(need);
        if (self.recon.fulls.iter()).any(|&(of, held, ..)| of == shard && held == repair) {
            return;
        }
        let census = self.census_now(self.zone_of(at)).map_or(0, |c| c.len());
        let running = !self.lost(record.owner);
        self.recon.fulls.push((shard, repair, running, census));
        self.recon.refused_full += 1;
    }

    fn collect(&mut self, at: usize, state: ShardState, blocker: Option<Blocker>) {
        let shard = self.cells[at].placement.shard.get();
        let guard = state == ShardState::NoCandidate && blocker == Some(Blocker::DeviceFailureHold);
        self.volumes.guarded += u32::from(guard && self.cells[at].device_holds.len() >= 2);
        let round = self.round - self.host_start;
        let runs = &mut self.recon.runs;
        let open = (runs.iter()).rposition(|(of, .., to)| *of == shard && to.is_none());
        if open.map(|run| runs[run].1) != blocker {
            if let Some(run) = open {
                runs[run].3 = Some(round);
            }
            runs.extend(blocker.map(|blocker| (shard, blocker, round, None)));
        }
        if !self.recon.planted
            && blocker.is_none()
            && self.config.planted_at(Plant::UnbackedBlocker, at)
        {
            self.recon.planted = true;
            self.planted = true;
            self.recon.block(shard, Blocker::CensusFull, None);
            self.cells[at].blocker = Some(Blocker::CensusFull);
            return;
        }
        if self.cells[at].blocker == blocker {
            return;
        }
        let Some(blocker) = blocker else {
            self.cells[at].blocker = None;
            return;
        };
        if self.config.planted_at(Plant::SilentBlocker, at) {
            self.planted = true;
            return;
        }
        self.recon
            .enter(shard, Refused::Status(state, blocker), blocker);
        self.cells[at].blocker = Some(blocker);
        self.volumes.retained += u32::from(blocker == Blocker::VolumeImpaired);
    }

    /// Each running host of cell `at`'s zone reads the shard's record again, a record view
    /// ([`Fleet::read_record`]), and resyncs its agent.
    pub(super) fn reread_hosts(&mut self, at: usize) {
        let zone = self.cells[at].placement.zone;
        for host in 0..self.hosts.len() {
            if self.hosts[host].up == Up::Running && self.topology.members[host].zone == zone {
                self.read_record(host, at);
                self.sync(host);
            }
        }
    }

    fn prober_premise(&self, observer: usize, owner: Host) -> bool {
        let members = &self.topology.members;
        let Some(owner) = self.member_of(owner) else {
            return false;
        };
        let zone = members[observer].zone;
        let partitions: std::collections::BTreeSet<u32> = (0..members.len())
            .filter(|&p| p != observer && members[p].zone == zone)
            .filter(|&p| self.hosts[p].up == Up::Running)
            .map(|p| members[p].partition.0)
            .filter(|&p| p != members[owner].partition.0)
            .collect();
        partitions.len() >= 2
    }

    /// The local record `member` persists for its attach of cell `at`'s volume under `key`, the key
    /// `enroll_standby` hands its persist (KEY-PER-ATTACH), so a retried enrollment of the same attach persists the
    /// same pair.
    pub(super) fn local_record(
        &self,
        at: usize,
        member: usize,
        key: crate::failover::identity::Key,
    ) -> crate::failover::record::LocalRecord {
        let placement = self.cells[at].placement;
        let instance = self.topology.members[member].instance;
        bound_record(
            instance,
            placement.volume,
            key.encode(),
            member as u8 + FIRST_HOST_ID,
        )
    }
}
