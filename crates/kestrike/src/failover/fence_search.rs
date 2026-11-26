//! The fence world of the tenure search: the record world of `tenure_search` with the reservation of the retained
//! volume and each host's steps after its acknowledged takeover compare-and-swap.
//!
//! The root is the record world after the reconciler designated C and C's takeover was acknowledged, reached by
//! replaying [`ROOT`] from the record world's root, with A holding the reservation and C registered. The volume
//! record is fixed and enrolls both hosts for their live attaches. The reservation is a model value: which hosts are
//! registered and which one holds. The record half keeps the record world's reads, `Pass` takeovers, reconciler
//! reads and `Pass` designations, so the reconciler may designate the deposed host and a second takeover runs the
//! other way. The bound is the record world's: highest `E` 3, counted from the record root, and two designations,
//! one of them spent by [`ROOT`].
//! The alphabet includes `TakeOver(C, Pass)` and `Register(C)`. Both actions remain disabled in every state reachable
//! within this bound.
//!
//! A host's steps follow the ledger's `step-order` rule, copied from `Takeover::run`:
//! 1. `ReportOne`: Report #1 from the Report fixture encoder, judged by `restart::parse`, `restart::enrolled`
//!    against the volume record and `LineagePreempt::resolve` against `VolumeRecord::recorded_beside`.
//! 2. `Register`, when Report #1 listed no record of the own pair.
//! 3. `Preempt`: the ledger's `tenure-check` rule, copied from `Takeover::current`, and the preempt as one step.
//! 4. `ReportTwo`: Report #2, judged by `restart::parse`, `restart::enrolled` and `Fenced::restarted`, whose value
//!    is the fencing boundary, then the `tenure-check` rule again before the host is admitted.
//!
//! `ReportOne` and `ReportTwo` are one step each, placed at the instant the Report is taken. Their judgments read the
//! Report's bytes and the fixed volume record, so a judgment made later reads the same values. The tenure check
//! that ends `ReportTwo` reads the record at that instant. In this world each takeover raises `E` and every later
//! write keeps or advances the tenure, so a check that passes later also passes at the Report's instant, and the
//! step admits every host a later check admits. The holder clause of `FenceHolds` refers to the reservation that
//! Report #2 shows.
//!
//! After every step the search checks the record world's four monitors, then these two, and reports the first
//! violation:
//! 1. `NoPreemptOfForeignKey`, at each issued preempt: the preempted key belongs to a host whose tenure the
//!    issuer's acknowledged takeover superseded, directly or through committed takeover writes; the key is of a pair
//!    the volume record enrolls for the live attach of another host; and the store's record names the issuer's
//!    tenure and volume.
//! 2. `FenceHolds`: when a host obtains the fencing boundary, the reservation shows its pair as the one holder with
//!    every other registrant recorded, and the ghost history holds its own mint for the tenure; when the second
//!    tenure check admits it, the store's record names that tenure and volume. `Takeover::run` obtains the boundary
//!    value before that check and drops it on a superseded tenure, so the holder and mint clauses are judged where
//!    the value is obtained.
//!
//! World fields and the canonical form: the record world's form, each host's phase with the tenure and the key it
//! holds, the reservation, and the ghost history's takeover lineage. The volume record, the pairs and the limits are
//! constants of the model.
//!
//! With two hosts enrolled for live attaches, the first two clauses of `NoPreemptOfForeignKey` hold in every reached
//! state: a preempted key is the other host's, whose tenure the issuer superseded. The model's `tenure-check` copy
//! enforces the third clause, and the `skips-tenure-check` plant breaks it. `restart::parse` and `restart::enrolled`
//! accept every Report and the fixed volume record, and `LineagePreempt::resolve` refuses the own pair alone, so
//! `NoPreemptOfForeignKey` checks the preempt key when `LineagePreempt::resolve` returns one.
//! The search requires `restart::parse` and `restart::enrolled` to succeed.
//! A returned preempt must name the stepping host's pair.
//! `Fenced::restarted` judges the holder clause of `FenceHolds`, and the `report-two-unjudged` plant breaks it.
//! Every planted run satisfies the mint clause, the tenure clause and the recorded-registrant part of the holder
//! clause of `FenceHolds`: the `skips-tenure-check` plant drops the first use of the rule and keeps the second, and
//! the volume record records both pairs. The fence world has no flip, so the volume half of each tenure clause is
//! constant. The tenure check and the preempt are one step, so a pause between them lies outside the search, as do
//! a third host, a pair recorded for an ended attach, the device beyond reservation state, the volume checks
//! `Takeover::run` repeats at each reread, its driver, ready and host-ID steps, and the coverage fencing after
//! admission. The search checks safety and reachability within the bound.

use super::evidence::{NotSole, Pair, Registrant, Report};
use super::identity::Key;
use super::poll::Holder;
use super::records::{Host, ShardRecord, VolumeRecord};
use super::restart::tests::{host as owner_host, own as owner_pair};
use super::restart::{enrolled, parse};
use super::retire::Target;
use super::search::{End, Model, Seen, replay};
use super::takeover::tests::{c_host, c_pair, holder_of, lineage};
use super::tenure_search::{
    Action as RecordAction, Bound, Canon as RecordCanon, Commit, Event as RecordEvent, Kind,
    Plant as RecordPlant, Records, Side, World as RecordWorld,
};
use crate::failover::bounds::Bounds;
use crate::storage::device::ReservationLimits;
use crate::storage::gate_fixture::{bounds_of, encode_report, limits};
use crate::storage::store::StoreError;
use crate::storage::store::sim::Arm;
use crate::storage::{Fenced, HolderRefusal, LineagePreempt};

pub(crate) const NO_PREEMPT_OF_FOREIGN_KEY: &str = "NoPreemptOfForeignKey";
pub(crate) const FENCE_HOLDS: &str = "FenceHolds";

pub(crate) const SUCCESSOR_FENCED: &str = "successor-fenced";
pub(crate) const SUPERSEDED_BEFORE_PREEMPT: &str = "superseded-successor-refused/before-preempt";
pub(crate) const SUPERSEDED_BEFORE_ADMISSION: &str =
    "superseded-successor-refused/before-admission";
pub(crate) const OWN_PAIR_REFUSED: &str = "own-pair-refused";

pub(crate) const WITNESSES: [&str; 4] = [
    SUCCESSOR_FENCED,
    SUPERSEDED_BEFORE_PREEMPT,
    SUPERSEDED_BEFORE_ADMISSION,
    OWN_PAIR_REFUSED,
];

/// The four production functions the fence steps add to the record world's decisions.
pub(crate) const DECISIONS: [&str; 4] = [
    "restart::parse",
    "LineagePreempt::resolve",
    "restart::enrolled",
    "Fenced::restarted",
];

/// The record world's decisions the fence search reaches through its record actions. The `tenure-check` rule of the
/// `Preempt` and `ReportTwo` steps also calls `Client::read`.
pub(crate) const RECORD_DECISIONS: [&str; 4] = [
    "Client::read",
    "Client::take_over",
    "Client::designate",
    "Session::activate",
];

pub(crate) const KINDS: [&str; 8] = [
    "Read",
    "TakeOver",
    "ReconcilerRead",
    "Designate",
    "ReportOne",
    "Register",
    "Preempt",
    "ReportTwo",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Action {
    Record(RecordAction),
    ReportOne(Side),
    Register(Side),
    Preempt(Side),
    ReportTwo(Side),
}

use Action::{Preempt, Record, Register, ReportOne, ReportTwo};
use Side::{A, C};

const PASS: Arm = Arm::Pass;

pub(crate) const ALPHABET: [Action; 14] = [
    Record(RecordAction::Read(A)),
    Record(RecordAction::Read(C)),
    Record(RecordAction::TakeOver(A, PASS)),
    Record(RecordAction::TakeOver(C, PASS)),
    Record(RecordAction::ReconcilerRead),
    Record(RecordAction::Designate(PASS)),
    ReportOne(A),
    ReportOne(C),
    Register(A),
    Register(C),
    Preempt(A),
    Preempt(C),
    ReportTwo(A),
    ReportTwo(C),
];

/// The record actions that reach the record half of the fence root from the record world's root: the reconciler
/// designates C, and C's takeover is acknowledged.
pub(crate) const ROOT: [RecordAction; 4] = [
    RecordAction::ReconcilerRead,
    RecordAction::Designate(PASS),
    RecordAction::Read(C),
    RecordAction::TakeOver(C, PASS),
];

/// The record world's bound under the fence search: `E` up to 3, no lost or parked reply, and two designations, of
/// which [`ROOT`] spends one.
pub(crate) const BOUND: Bound = Bound {
    top: 3,
    faults: 0,
    designations: 2,
    transfers: 0,
    handoff: 0,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Plant {
    None,
    /// The host issues its preempt without the `tenure-check` rule's first use.
    SkipsTenureCheck,
    /// The host takes the fencing boundary from Report #2 without calling `Fenced::restarted`.
    ReportTwoUnjudged,
}

/// Where a host stands in its steps after an acknowledged takeover of the tenure each variant carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Idle,
    Taken(Target),
    Reported {
        tenure: Target,
        preempt: LineagePreempt,
        registered: bool,
    },
    Preempted(Target),
}

/// The reservation of the retained volume: the registered hosts and the one holder of the type-2 reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Reservation {
    registered: [bool; 2],
    holder: Option<Side>,
}

impl Reservation {
    fn held_by(self, side: Side) -> bool {
        self.holder == Some(side) && self.registered[side.index()]
    }
}

/// A committed takeover: the tenure it wrote and the tenure it replaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Superseded {
    by: Target,
    prior: Target,
}

impl Superseded {
    fn of(commit: &Commit) -> Option<Self> {
        (commit.pending.kind == Kind::TakeOver).then(|| Self {
            by: Target::of(&commit.written),
            prior: Target::of(&commit.below),
        })
    }
}

#[derive(Clone)]
pub(crate) struct World {
    records: RecordWorld,
    phases: [Phase; 2],
    reservation: Reservation,
    lineage: Vec<Superseded>,
}

impl World {
    pub(crate) fn record(&self) -> &ShardRecord {
        self.records.record()
    }

    pub(crate) fn reservation(&self) -> Reservation {
        self.reservation
    }

    pub(crate) fn vacate(&mut self) {
        self.reservation.holder = None;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Reply {
    Done,
    /// For `Reply::Record`, the event's `record` field carries the record world's reply.
    Record,
    Holder(HolderRefusal),
    /// The copied `tenure-check` rule refused: the record names another tenure or volume.
    Superseded,
    NotSole(NotSole),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Issued {
    issuer: Side,
    tenure: Target,
    /// The key the preempt names, as `LineagePreempt::resolve` returned it.
    key: Key,
}

/// A host that obtained the fencing boundary for `tenure`, and whether the second tenure check admitted it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Boundary {
    host: Side,
    tenure: Target,
    pub(crate) admitted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Event {
    pub(crate) reply: Reply,
    record: Option<RecordEvent>,
    pub(crate) preempt: Option<Issued>,
    pub(crate) boundary: Option<Boundary>,
}

impl Event {
    fn of(reply: Reply) -> Self {
        Self {
            reply,
            record: None,
            preempt: None,
            boundary: None,
        }
    }
}

pub(crate) struct Fence {
    pub(crate) plant: Plant,
    records: Records,
    volume: VolumeRecord,
    pairs: [Pair; 2],
    holders: [Holder; 2],
    limits: ReservationLimits,
    bounds: Bounds,
}

impl Fence {
    /// The volume record and both holders name the retained volume, the active volume of the record world's root.
    /// Each holder carries the record world's host of its side and the instance of the takeover fixture's host.
    pub(crate) fn new(plant: Plant) -> Self {
        let records = Records {
            bound: BOUND,
            ..Records::new(RecordPlant::None)
        };
        let [retained, _] = records.volumes;
        let pairs = [owner_pair(), c_pair()];
        let holders = [(A, owner_host()), (C, c_host())].map(|(side, fixture)| Holder {
            volume: retained,
            host: side.host(),
            instance: holder_of(fixture).instance,
        });
        Self {
            plant,
            records,
            volume: VolumeRecord {
                volume: retained,
                ..lineage(&[(C.host(), pairs[C.index()])])
            },
            pairs,
            holders,
            limits: limits(),
            bounds: bounds_of(limits()),
        }
    }

    pub(crate) fn volume(&self) -> &VolumeRecord {
        &self.volume
    }

    pub(crate) fn holder(&self, side: Side) -> &Holder {
        &self.holders[side.index()]
    }

    fn pair(&self, side: Side) -> Pair {
        self.pairs[side.index()]
    }

    /// The host whose enrolled pair carries `key`.
    fn side_of(&self, key: Key) -> Option<Side> {
        [A, C].into_iter().find(|side| self.pair(*side).key == key)
    }

    /// The monitors' tenure clause, read from the store's record: it names `tenure` and the retained volume.
    /// `named` and the `tenure-check` rule in `current` stay separate code, since the monitors judge that rule.
    fn named(&self, world: &World, tenure: Target) -> bool {
        let record = world.record();
        (record.generation, record.owner, record.attempts)
            == (tenure.generation, tenure.owner, tenure.attempts)
            && record.active == self.volume.volume
    }

    /// The Report the controller returns for `reservation`, from the Report fixture encoder.
    fn report(&self, reservation: &Reservation) -> Vec<u8> {
        let entries: Vec<Registrant> = [A, C]
            .into_iter()
            .filter(|side| reservation.registered[side.index()])
            .map(|side| Registrant {
                cntlid: side.index() as u16 + 1,
                pair: self.pair(side),
                holder: reservation.holder == Some(side),
            })
            .collect();
        encode_report(
            u8::from(entries.iter().any(|entry| entry.holder)) * 2,
            &entries,
        )
    }

    fn buffer(&self) -> Vec<Registrant> {
        let unset = Registrant {
            cntlid: 0,
            holder: false,
            pair: self.pair(A),
        };
        vec![unset; self.limits.registrants() as usize]
    }

    fn parsed<'e>(
        &self,
        reservation: Reservation,
        (step, side): (&str, Side),
        entries: &'e mut [Registrant],
        seen: &mut Seen,
    ) -> Result<Report<'e>, String> {
        let bytes = self.report(&reservation);
        seen.decision("restart::parse");
        let report = parse(self.limits, &bytes, entries)
            .map_err(|refusal| format!("{step}({side:?}) did not parse: {refusal:?}"))?;
        seen.decision("restart::enrolled");
        enrolled(self.holder(side), &self.volume, self.pair(side))
            .map_err(|refusal| format!("{step}({side:?}) lost its enrollment: {refusal:?}"))?;
        Ok(report)
    }

    /// The `tenure-check` rule: the record `side` reads names `tenure` and the volume of the holder of `side`.
    fn current(
        &self,
        world: &mut World,
        side: Side,
        tenure: Target,
        seen: &mut Seen,
    ) -> Result<bool, StoreError> {
        seen.decision("Client::read");
        let record = world.records.reread(side)?;
        Ok(Target::of(&record) == tenure && record.active == self.holder(side).volume)
    }

    fn report_one(
        &self,
        world: &mut World,
        side: Side,
        tenure: Target,
        seen: &mut Seen,
    ) -> Result<Event, String> {
        let own = self.pair(side);
        let mut entries = self.buffer();
        let report = self.parsed(world.reservation, ("ReportOne", side), &mut entries, seen)?;
        seen.decision("LineagePreempt::resolve");
        let admitted: Vec<_> = self.volume.admitted(report.entries).copied().collect();
        let resolved = LineagePreempt::resolve(
            &report,
            &admitted,
            self.volume.recorded_beside(side.host()),
            own,
            &self.bounds,
        );
        let holds = world.reservation.held_by(side);
        let phase = &mut world.phases[side.index()];
        match resolved {
            Ok(preempt) if preempt.pair() != own => Err(format!(
                "ReportOne({side:?}) resolved a preempt issued by {:?}",
                preempt.pair()
            )),
            Ok(_) if holds => Err(format!(
                "ReportOne({side:?}) resolved a preempt while its own pair holds"
            )),
            Ok(preempt) => {
                *phase = Phase::Reported {
                    tenure,
                    preempt,
                    registered: report.entries.iter().any(|entry| entry.pair == own),
                };
                Ok(Event::of(Reply::Done))
            }
            Err(HolderRefusal::Own) if holds => {
                seen.witness(OWN_PAIR_REFUSED);
                *phase = Phase::Idle;
                Ok(Event::of(Reply::Holder(HolderRefusal::Own)))
            }
            Err(refusal) => Err(format!("ReportOne({side:?}) returned {refusal:?}")),
        }
    }

    fn preempt(
        &self,
        world: &mut World,
        side: Side,
        (tenure, preempt): (Target, LineagePreempt),
        seen: &mut Seen,
    ) -> Result<Event, String> {
        let checked = self.plant != Plant::SkipsTenureCheck;
        if checked
            && !self
                .current(world, side, tenure, seen)
                .map_err(|error| format!("Preempt({side:?}) returned {error:?}"))?
        {
            seen.witness(SUPERSEDED_BEFORE_PREEMPT);
            world.phases[side.index()] = Phase::Idle;
            return Ok(Event::of(Reply::Superseded));
        }
        let key = preempt.preempted();
        let reservation = &mut world.reservation;
        let Some(preempted) = self.side_of(key) else {
            return Err(format!(
                "Preempt({side:?}) names {key:?}, the key of no host"
            ));
        };
        if !reservation.registered[side.index()] {
            return Err(format!(
                "Preempt({side:?}) issues from an unregistered pair"
            ));
        }
        // The controller's Preempt-and-Abort: the preempted key's registration leaves, and the registered issuer
        // becomes the holder when that key was the holder's.
        reservation.registered[preempted.index()] = false;
        if reservation.holder == Some(preempted) {
            reservation.holder = Some(side);
        }
        world.phases[side.index()] = Phase::Preempted(tenure);
        Ok(Event {
            preempt: Some(Issued {
                issuer: side,
                tenure,
                key,
            }),
            ..Event::of(Reply::Done)
        })
    }

    fn report_two(
        &self,
        world: &mut World,
        side: Side,
        tenure: Target,
        seen: &mut Seen,
    ) -> Result<Event, String> {
        let own = self.pair(side);
        world.phases[side.index()] = Phase::Idle;
        let mut entries = self.buffer();
        let report = self.parsed(world.reservation, ("ReportTwo", side), &mut entries, seen)?;
        if self.plant != Plant::ReportTwoUnjudged {
            seen.decision("Fenced::restarted");
            let recorded: Vec<_> = self.volume.admitted(report.entries).copied().collect();
            let foreign = world.reservation.held_by(side.other());
            match Fenced::restarted(&report, own, &recorded, &self.bounds) {
                Ok(fenced) if fenced.own() == own => {}
                Ok(fenced) => {
                    return Err(format!(
                        "ReportTwo({side:?}) returned a boundary for {:?}",
                        fenced.own()
                    ));
                }
                Err(NotSole::ForeignHolder) if foreign => {
                    return Ok(Event::of(Reply::NotSole(NotSole::ForeignHolder)));
                }
                Err(refusal) => return Err(format!("ReportTwo({side:?}) returned {refusal:?}")),
            }
        }
        let admitted = self
            .current(world, side, tenure, seen)
            .map_err(|error| format!("ReportTwo({side:?}) returned {error:?}"))?;
        let reply = if admitted {
            seen.witness(SUCCESSOR_FENCED);
            Reply::Done
        } else {
            seen.witness(SUPERSEDED_BEFORE_ADMISSION);
            Reply::Superseded
        };
        Ok(Event {
            boundary: Some(Boundary {
                host: side,
                tenure,
                admitted,
            }),
            ..Event::of(reply)
        })
    }

    /// Whether the takeover that wrote `tenure` superseded a tenure of `host`, directly or through the committed
    /// takeover writes below it.
    fn superseded(&self, world: &World, tenure: Target, host: Host) -> bool {
        let mut at = tenure;
        while let Some(entry) = world.lineage.iter().find(|entry| entry.by == at) {
            if entry.prior.owner == host {
                return true;
            }
            at = entry.prior;
        }
        false
    }

    fn preempt_holds(&self, world: &World, issued: &Issued) -> bool {
        let issuer = issued.issuer.host();
        let owner = self
            .volume
            .pairs
            .iter()
            .find(|recorded| recorded.pair.key == issued.key);
        owner.is_some_and(|recorded| {
            recorded.host != issuer && self.superseded(world, issued.tenure, recorded.host)
        }) && self.named(world, issued.tenure)
    }

    fn fence_holds(&self, world: &World, boundary: Boundary) -> bool {
        let Boundary {
            host: side,
            tenure,
            admitted,
        } = boundary;
        let reservation = &world.reservation;
        let recorded = |other: Side| {
            !reservation.registered[other.index()]
                || self.volume.recorded().any(|pair| *pair == self.pair(other))
        };
        let sole = reservation.held_by(side) && recorded(side.other());
        let minted = tenure.owner == side.host() && world.records.mints().contains(&tenure);
        sole && minted && (!admitted || self.named(world, tenure))
    }
}

type Tenure = (u64, u64, u32);

fn tenure_of(target: Target) -> Tenure {
    (target.generation.get(), target.owner.get(), target.attempts)
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
enum PhaseKey {
    Idle,
    Taken(Tenure),
    Reported {
        tenure: Tenure,
        preempted: Key,
        registered: bool,
    },
    Preempted(Tenure),
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Canon {
    records: RecordCanon,
    phases: [PhaseKey; 2],
    registered: [bool; 2],
    holder: Option<Side>,
    lineage: Vec<(Tenure, Tenure)>,
}

impl Model for Fence {
    type World = World;
    type Action = Action;
    type Event = Event;
    type Canon = Canon;

    fn root(&self) -> World {
        let replayed = replay(&self.records, &ROOT);
        assert!(
            replayed.end == End::Applied,
            "the record world reaches the fence root"
        );
        let lineage = replayed
            .events
            .iter()
            .filter_map(|event| event.commit.as_ref().and_then(Superseded::of))
            .collect();
        let tenure = Target::of(replayed.world.record());
        let mut phases = [Phase::Idle; 2];
        phases[C.index()] = Phase::Taken(tenure);
        World {
            records: replayed.world,
            phases,
            reservation: Reservation {
                registered: [true; 2],
                holder: Some(A),
            },
            lineage,
        }
    }

    fn alphabet(&self) -> &[Action] {
        &ALPHABET
    }

    fn enabled(&self, world: &World, action: Action) -> bool {
        let phase = |side: Side| world.phases[side.index()];
        match action {
            Record(action) => self.records.enabled(&world.records, action),
            ReportOne(side) => matches!(phase(side), Phase::Taken(_)),
            Register(side) => matches!(
                phase(side),
                Phase::Reported {
                    registered: false,
                    ..
                }
            ),
            Preempt(side) => matches!(
                phase(side),
                Phase::Reported {
                    registered: true,
                    ..
                }
            ),
            ReportTwo(side) => matches!(phase(side), Phase::Preempted(_)),
        }
    }

    fn kind(&self, action: Action) -> &'static str {
        match action {
            Record(action) => self.records.kind(action),
            ReportOne(_) => "ReportOne",
            Register(_) => "Register",
            Preempt(_) => "Preempt",
            ReportTwo(_) => "ReportTwo",
        }
    }

    fn step(
        &self,
        world: &World,
        action: Action,
        seen: &mut Seen,
    ) -> Result<(World, Event), String> {
        let mut next = world.clone();
        let phase = match action {
            Record(_) => Phase::Idle,
            ReportOne(side) | Register(side) | Preempt(side) | ReportTwo(side) => {
                next.phases[side.index()]
            }
        };
        let event = match (action, phase) {
            (Record(action), _) => {
                let (records, event) = self.records.step(&world.records, action, seen)?;
                next.records = records;
                let taken = event.commit.as_ref().and_then(Superseded::of);
                if let (Some(entry), RecordAction::TakeOver(side, _)) = (taken, action) {
                    next.lineage.push(entry);
                    next.phases[side.index()] = Phase::Taken(entry.by);
                }
                Event {
                    record: Some(event),
                    ..Event::of(Reply::Record)
                }
            }
            (ReportOne(side), Phase::Taken(tenure)) => {
                self.report_one(&mut next, side, tenure, seen)?
            }
            (
                Register(side),
                Phase::Reported {
                    tenure, preempt, ..
                },
            ) => {
                next.reservation.registered[side.index()] = true;
                next.phases[side.index()] = Phase::Reported {
                    tenure,
                    preempt,
                    registered: true,
                };
                Event::of(Reply::Done)
            }
            (
                Preempt(side),
                Phase::Reported {
                    tenure, preempt, ..
                },
            ) => self.preempt(&mut next, side, (tenure, preempt), seen)?,
            (ReportTwo(side), Phase::Preempted(tenure)) => {
                self.report_two(&mut next, side, tenure, seen)?
            }
            (action, phase) => unreachable!("{action:?} is disabled in {phase:?}"),
        };
        Ok((next, event))
    }

    fn monitor(&self, world: &World, event: Option<&Event>) -> Option<&'static str> {
        let record = event.and_then(|event| event.record.as_ref());
        if let Some(property) = self.records.monitor(&world.records, record) {
            return Some(property);
        }
        let event = event?;
        if let Some(issued) = &event.preempt
            && !self.preempt_holds(world, issued)
        {
            return Some(NO_PREEMPT_OF_FOREIGN_KEY);
        }
        if let Some(boundary) = event.boundary
            && !self.fence_holds(world, boundary)
        {
            return Some(FENCE_HOLDS);
        }
        None
    }

    fn canonical(&self, world: &World) -> Canon {
        let phases = world.phases.map(|phase| match phase {
            Phase::Idle => PhaseKey::Idle,
            Phase::Taken(tenure) => PhaseKey::Taken(tenure_of(tenure)),
            Phase::Reported {
                tenure,
                preempt,
                registered,
            } => PhaseKey::Reported {
                tenure: tenure_of(tenure),
                preempted: preempt.preempted(),
                registered,
            },
            Phase::Preempted(tenure) => PhaseKey::Preempted(tenure_of(tenure)),
        });
        Canon {
            records: self.records.canonical(&world.records),
            phases,
            registered: world.reservation.registered,
            holder: world.reservation.holder,
            lineage: world
                .lineage
                .iter()
                .map(|entry| (tenure_of(entry.by), tenure_of(entry.prior)))
                .collect(),
        }
    }
}
