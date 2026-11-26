//! [`ZoneLoop::actuate`] carries out one survey's plan through the gated `Reconciler` steps and the [`Attacher`].
//!
//! - TICK-ORDER: `actuate` acts only on the survey whose tick number is the loop's latest, once, at an elapsed time
//!   no earlier than that survey's and less than `tick_us` after it. Any other call returns a [`Discard`] before its
//!   first effect. `actuate` identifies the survey by its tick number alone and reads `now_us` once, at entry; the
//!   caller passes the survey this loop returned and keeps the call's steps within the tick.
//! - ONE-ATTEMPT: each planned step runs at most once per tick. A tick makes at most `writes_per_tick`
//!   store-writing steps and at most `calls_per_tick` attach requests, detach requests and replacement creates
//!   together; an attach or detach step spends a call only when it sends a request, and a replacement's create
//!   spends one write and one call before its provider call. An attachment listing read
//!   (`ControlPlane::attachments`) spends no call. A step past a budget waits for the next tick. After the planned
//!   steps `actuate` repeats the unfinished retirement of each volume a flip of this loop displaced
//!   (RETIRE-DISPLACED in `zone_loop::replace`), one write each from the tick's remaining writes, under either zone
//!   hold and with no `Outcome`.
//!   The write of a correlated hold (`plan::hold_due`) is the write budget's exception: it consumes one write if
//!   available and proceeds even at zero.
//! - WRITE-YIELD: a write step that was charged a write and did not advance is tried. In a call whose plan holds
//!   more write steps than `writes_per_tick`, a shard that holds a tried write step yields from its first such
//!   step on: that step and the shard's later write steps run, in plan order, after every other step of the call,
//!   and the yielding shards run in the order of the last charged call of their first tried step, the least recent
//!   first. A write that fails on every tick therefore takes a write only from the budget that the other shards'
//!   write steps leave. The write steps of one shard keep plan order in every call, the attach and detach steps
//!   keep their CALL-ROTATION positions, and every gone mark still follows every attach and detach. A step leaves
//!   the tried steps when it advances, leaves the plan, or runs without a charge; a step that waited on the budget
//!   or behind its shard's stop stays. The tried steps are process memory, so the first call of a process runs in
//!   plan order. A shard that enrolls for a fresh need yields nothing: its write steps keep their plan positions,
//!   ahead of the write steps the plan puts behind them, so its write that fails on every tick takes a write on
//!   every tick.
//! - CALL-ROTATION: the steps run in plan order, except that the `Attach` and `Detach` steps are permuted among
//!   their own positions, in three bands: a fresh need's attach that was never requested; then every other attach
//!   of a fresh need and every detach; then every other attach. Within a band the step whose last request is
//!   oldest runs first, a step never requested before any other. A fresh need's attach so stays ahead of every
//!   standby need's, and a detach that was never requested, or was requested earlier, runs ahead of a fresh need's
//!   retry and of every standby need's attach. A detach goes out once per volume and instance per
//!   `detach_settle_us`, so the detaches take a bounded share of the calls and a retrying attach cannot hold the
//!   call budget against them. Outcomes keep plan order.
//! - ACKNOWLEDGED-ONLY: a step advances only on the witness its `Reconciler` step returned in this call or on a read
//!   in this call that shows the effect made. After an unknown outcome or a record that moved, the steps of the
//!   shard that run later in the call wait for the next tick's survey, which rereads the records and listings
//!   first.
//! - STANDBY-WRITE-ORDER: `record_standby` follows a census read, made in the same step, that lists the slot for the
//!   host at the step's target, and a complete survey listing of the volume that omits the host's instance. The
//!   attach request follows, in the same step, a shard record read at the step's target and active volume, a census
//!   read that lists the slot for the host at that target, a volume record read that shows the host's live entry
//!   unenrolled and bound to its directory instance, and a volume listing that omits the instance. The volume record
//!   supplies the same evidence as the `StandbyRecorded` witness of `Reconciler::record_standby`, so a restarted
//!   loop requests from the stored record. `designate` follows a census read that lists the slot at the step's
//!   target; `Reconciler::designate` rereads the census after the shard record and requires the host's enrolled
//!   pair. Each check holds for the records at its read; a write that commits later is the next tick's to read.
//! - REQUEST-RETURNED: the loop reads a request as returned at the first survey after the call that sent it. The
//!   attach and detach calls are synchronous and a survey follows the previous `actuate` on the same loop, so a
//!   survey time that the caller reads at the survey's entry is at or after the request's return or deadline,
//!   however long the call ran. [`ZoneLoop::returned`] stamps it, never before the request's own `now_us`. A
//!   request with no stamp is still settling.
//! - RECORD-SETTLED: `record` writes no attach entry for an instance on a volume while the survey's time is less than
//!   `detach_settle_us` after the return (REQUEST-RETURNED) of this loop's last detach request for that volume and
//!   instance, whatever the reply, and `attach` sends no request for an entry recorded meanwhile, as by a write
//!   whose outcome was unknown, so an attach request follows the return of that detach by the settle time.
//!   The time is kept by volume and instance, apart from the volume record, whose entry of the detached
//!   instance another host's attach entry can remove. A loop that holds no such time waits
//!   `tick_us + detach_settle_us` from its first survey when the volume record is compacted or retains a gone entry
//!   bound to the instance: such a record cannot exclude a detach request that an earlier run of the process sent.
//! - ATTACH-SETTLE: the loop spaces requests for one entry by at least `attach_settle_us` between the `now_us`
//!   values of the calls that made them, doubles the wait after each refusal up to `attach_stuck_us`, and requests
//!   only while the volume's listing omits the instance.

use std::collections::{BTreeMap, BTreeSet};

use crate::failover::attachments::{ControlPlane, InstanceId, Peer, Unlisted};
use crate::failover::loss::Provider;
use crate::failover::reconcile::{Binding, ReconcileError, StandbyGate, reservable};
use crate::failover::records::{
    EventKind, Host, MAX_EVENTS, MIN_ERA, ShardRecord, VolumeId, VolumeRecord,
};
use crate::failover::report::HostReport;
use crate::failover::report::status::{AttachOutcome, Reclaim as Reclaimed};
use crate::failover::retire::Target;
use crate::failover::standbys::{
    Attach, Entry, Need, Population, Refusal as PopulationRefusal, Slot,
};
use crate::failover::zone_loop::ZoneLoop;
use crate::failover::zone_loop::directory::DirectoryState;
use crate::failover::zone_loop::evidence::HostEvidence;
use crate::failover::zone_loop::observe::{Observation, ShardRecords, ZoneView};
use crate::failover::zone_loop::plan::{Step, Survey, displaced, hold_due, pending, unreleased};
use crate::failover::zone_loop::replace::Replaced;
use crate::failover::zone_loop::sources::{AttachRefusal, AttachReply, Attacher};
use crate::failover::zone_loop::status::ShardState;
use crate::net::ownership::Shard;
use crate::storage::store::{Key, Refusal, Store, StoreError, WatermarkLog};

/// The TICK-ORDER refusal [`ZoneLoop::actuate`] returns before any effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Discard {
    /// The loop holds no survey, or the survey's tick number differs from the loop's latest.
    Superseded,
    /// The loop already actuated this survey.
    Repeated,
    /// `now_us` precedes the survey's time.
    Rewound,
    /// `now_us` is `tick_us` or more past the survey's time.
    Overrun,
}

/// The condition a step's `Wait` or `Alarm` names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// The step's write or attach request returned an unknown outcome.
    Unknown,
    /// The records moved off the step's reads: a lost version condition, another target or active volume, or a
    /// census, shard record or volume record that refuses the step. After a shard stops, the loop skips its remaining
    /// steps for the tick and assigns each `Wait(Moved)`.
    Moved,
    /// A store read failed.
    Store,
    /// `record_standby` returned `Conflict`. Possible causes include an unfenced generation and a volume at its attach
    /// limit. A `Conflict` from the reread after its write leaves the attach entry recorded.
    OwnerNotReady,
    /// [`Population::admit`] refused the reservation.
    Population(PopulationRefusal),
    /// The survey holds no accepted report of the host, no directory entry of it, or no records of the shard.
    Unreported,
    /// The volume's attachment listing failed or contains an invalid instance identifier.
    Unlisted,
    /// A timer of the step is running: the entry's last attach request is younger than its wait, the entry of a host
    /// the shard record does not name standby is `attach_stuck_us` past its first request and takes no further
    /// attach request, the entry's last detach request is younger than `detach_settle_us`, the release holds fewer
    /// than two listings `detach_settle_us` apart that follow the last request's return by `detach_settle_us`, a
    /// new attach entry or its attach request waits for a detach request of its volume and instance to settle
    /// (RECORD-SETTLED), or this loop's last create of the shard's replacement is younger than its wait.
    Settling,
    /// The control plane refused the attach request.
    AttachRefused(AttachRefusal),
    /// The host's live entry binds no instance or another instance than the directory's, or the survey's listing
    /// shows the host's instance while the volume record holds no live entry of the host.
    Binding,
    /// The host's accepted report names a binary era below [`MIN_ERA`].
    Era,
    /// The tick's write or call budget is spent.
    Budget,
    /// A store error withdrew the reconciler's client.
    Withdrawn,
    /// Any other refusal of a `Reconciler` step.
    Step(ReconcileError),
    /// The tick's evidence leaves the loss of the shard's active volume unconfirmed: the volume reads other than
    /// lost, or its shard's view has not been complete for `max(loss_ticks, LOSS_TICKS_MIN)` consecutive ticks.
    Unconfirmed,
    /// The shard's replacement receipt is held until the operator's release.
    Held,
    /// The replacement volume reads other than available in the tick's volume listing.
    Unhealthy,
    /// The plan found no host to attach the replacement volume.
    NoCandidate,
    /// The replacement volume's attachment listing shows another instance or a second attachment of its attaching
    /// host's instance, or, for a replacement the shard record names spare, no attachment of that instance; or the
    /// replacement's record reads retired, as after an earlier rejection.
    Foreign,
    /// The receipt's attempt is above `create_attempts_max`.
    Attempts,
    /// The shard record names a spare other than the volume the replacement receipt records as created.
    Spare,
    /// The replacement's attaching host reads other than live, or the directory lists it retired, or draining while
    /// it does not own the shard.
    Attacher,
}

/// A step's verdict. `Wait(Unknown)`, `Wait(Moved)` and every `Alarm` stop the shard's later steps in this tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The step produced or observed its effect. The next survey plans the next phase.
    Advance,
    /// The step waits for a record change or timer expiry.
    Wait(Reason),
    /// The step reports a condition for the operator.
    Alarm(Reason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Outcome {
    pub step: Step,
    pub verdict: Verdict,
    /// The control plane's reply when the step sent an attach request.
    pub reply: Option<AttachReply>,
    /// What the step did to an attach entry on the reclaim path, when it did or learned something there.
    pub reclaim: Option<Reclaim>,
    /// The effect a [`Step::Replace`] made or observed.
    pub replaced: Option<Replaced>,
}

/// The reclaim result an [`Outcome`] reports for an `End`, `Detach`, `ReleaseAttach` or `RecordAttach` step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reclaim {
    /// `Reconciler::end_attach` recorded the host's live entry ended, or found it ended.
    Ended,
    /// `Reconciler::end_attach` returned an ended entry of a host its reread names owner or standby. The step waits
    /// `Moved` and the tick's loss evidence leaves the host out.
    EndedNamed,
    /// `Reconciler::end_attach` refused the end and the shard record names the host owner.
    RefusedOwner,
    /// `Reconciler::end_attach` refused the end and the shard record names the host standby.
    RefusedStandby,
    /// The step sent a detach request and the control plane accepted it or reported the instance already detached.
    DetachRequested,
    /// The step sent a detach request whose outcome is unknown.
    DetachUnknown,
    /// `Reconciler::release_attach` recorded the ended entry gone.
    Gone,
    /// `Reconciler::record_standby` succeeded on a volume record the survey read with `MAX_EVENTS` entries and no
    /// live entry of the host, so the write removed a gone entry to make room for the new one.
    Removed,
}

/// One entry's request times: the `now_us` of the calls that sent its first and its last attach or detach request,
/// the time of the first survey after the last request (REQUEST-RETURNED), and the count of refused attach requests
/// since the last accepted one.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Requested {
    shard: Shard,
    first_us: u64,
    pub(super) last_us: u64,
    pub(super) returned_us: Option<u64>,
    pub(super) refusals: u32,
}

impl Requested {
    pub(super) fn wait_us(&self, settle_us: u64, stuck_us: u64) -> u64 {
        backoff_us(settle_us, stuck_us, self.refusals)
    }
}

/// The wait after `refusals` refused requests: `settle_us` doubled once per refusal, at most `stuck_us`.
pub(super) fn backoff_us(settle_us: u64, stuck_us: u64, refusals: u32) -> u64 {
    let factor = 1u64.checked_shl(refusals).unwrap_or(u64::MAX);
    settle_us.saturating_mul(factor).min(stuck_us)
}

pub(super) fn verdict_of(error: ReconcileError) -> Verdict {
    match error {
        ReconcileError::Store(StoreError::Unknown) => Verdict::Wait(Reason::Unknown),
        ReconcileError::Store(StoreError::Refused(Refusal::Condition) | StoreError::Stale(_))
        | ReconcileError::Stale
        | ReconcileError::Conflict => Verdict::Wait(Reason::Moved),
        ReconcileError::Store(StoreError::Unavailable | StoreError::Absent) => {
            Verdict::Wait(Reason::Store)
        }
        ReconcileError::Store(
            StoreError::Regression(_)
            | StoreError::Withdrawn
            | StoreError::Namespace
            | StoreError::Log,
        ) => Verdict::Alarm(Reason::Withdrawn),
        ReconcileError::Population(refusal) => Verdict::Wait(Reason::Population(refusal)),
        ReconcileError::Held => Verdict::Wait(Reason::Held),
        other => Verdict::Alarm(Reason::Step(other)),
    }
}

pub(super) fn records(view: &ZoneView, shard: Shard) -> Option<&ShardRecords> {
    let found = view.shards.iter().find(|held| held.shard == shard)?;
    found.records.as_ref().ok()?.as_ref()
}

fn report(view: &ZoneView, host: Host) -> Option<&HostReport> {
    let found = view.hosts.iter().find(|held| held.entry.host == host)?;
    found.report.as_deref()
}

fn lost(view: &ZoneView, host: Host) -> bool {
    let found = view.hosts.iter().find(|held| held.entry.host == host);
    found.is_some_and(|held| held.verdict == HostEvidence::Lost)
}

pub(super) fn listing(view: &ZoneView, volume: VolumeId) -> Option<&[String]> {
    view.listing(volume)
}

/// The attach and detach request times of each entry, keyed by its volume and its entry sequence number.
pub(crate) type Requests = BTreeMap<(VolumeId, u32), Requested>;

/// The entry's shard and the time of the survey that started a clock of [`ZoneLoop::stuck`] for it, keyed by its
/// volume and its entry sequence number.
pub(crate) type Sightings = BTreeMap<(VolumeId, u32), (Shard, u64)>;

/// WRITE-YIELD: the planned write steps that were charged a write in an earlier call and did not advance, each with
/// the tick number of the last such call.
pub(crate) type Tried = Vec<(Step, u64)>;

/// Whether `survey`'s plan reads `shard` as enrolling for a fresh need.
fn fresh(survey: &Survey, shard: Shard) -> bool {
    let plan = survey.plan.shards.iter().find(|plan| plan.shard == shard);
    plan.is_some_and(|plan| {
        matches!(
            plan.state,
            ShardState::Enrolling {
                need: Need::Fresh,
                ..
            }
        )
    })
}

/// Whether `step` is charged against `writes_per_tick`.
fn writes(step: &Step) -> bool {
    !matches!(step, Step::Attach { .. } | Step::Detach { .. })
}

/// The tick's remaining store-writing steps and its remaining attach and detach requests.
pub(super) struct Budget {
    writes: u32,
    calls: u32,
}

impl Budget {
    pub(super) fn spend_write(&mut self) -> bool {
        let left = self.writes > 0;
        self.writes -= u32::from(left);
        left
    }

    pub(super) fn spend_call(&mut self) -> bool {
        let left = self.calls > 0;
        self.calls -= u32::from(left);
        left
    }

    /// Spends one write and one call together, or neither when either budget is spent.
    pub(super) fn spend_write_and_call(&mut self) -> bool {
        let left = self.writes > 0 && self.calls > 0;
        self.writes -= u32::from(left);
        self.calls -= u32::from(left);
        left
    }
}

/// What the steps of one actuation share: the survey's view and time, the call's time, the loop's first survey time,
/// the attaches this call ended, and, per volume, the instance identifiers the listings read by this call's attach
/// and detach steps returned.
pub(super) struct Tick<'a> {
    pub(super) view: &'a ZoneView,
    pub(super) now_us: u64,
    pub(super) surveyed_us: u64,
    pub(super) started_us: u64,
    pub(super) ended: BTreeSet<(Shard, Host)>,
    pub(super) fresh: BTreeMap<VolumeId, Vec<String>>,
}

impl Tick<'_> {
    fn lost(&self, shard: Shard, host: Host) -> bool {
        let held = records(self.view, shard).map(|held| &held.active);
        let ended = held.is_some_and(|held| unreleased(held, host));
        let entry = self.view.directory.host(host);
        let retiring = entry.is_some_and(|entry| entry.state != DirectoryState::Active);
        let unattached = held.is_some_and(|held| held.live(host).is_none());
        lost(self.view, host)
            || ended
            || (retiring && unattached)
            || self.ended.contains(&(shard, host))
    }
}

impl<S: Store, L: WatermarkLog> ZoneLoop<S, L> {
    /// Runs `survey`'s plan at `now_us`, the loop's elapsed clock, and returns each step's outcome in plan order.
    ///
    /// # Errors
    ///
    /// A [`Discard`] before any effect when TICK-ORDER refuses the call.
    pub fn actuate(
        &mut self,
        gate: &StandbyGate,
        survey: &Survey,
        now_us: u64,
        effects: &mut (impl Attacher + ControlPlane + Provider),
    ) -> Result<Vec<Outcome>, Discard> {
        let (surveyed_us, started_us) = self.admits(survey, now_us)?;
        self.actuated = survey.status.tick;
        let Ok(view) = &survey.observation.zone else {
            return Ok(Vec::new());
        };
        self.forget(view, now_us);
        let settle_us = self.bounds.config().detach_settle_us;
        let settling = |returned: u64| surveyed_us < returned.saturating_add(settle_us);
        (self.detached).retain(|_, sent| sent.returned_us.is_none_or(settling));
        let mut tick = Tick {
            view,
            now_us,
            surveyed_us,
            started_us,
            ended: BTreeSet::new(),
            fresh: BTreeMap::new(),
        };
        let config = self.bounds.config();
        let mut budget = Budget {
            writes: config.writes_per_tick,
            calls: config.calls_per_tick,
        };
        let mut stopped = BTreeSet::new();
        let steps = &survey.plan.steps;
        let mut outcomes: Vec<Option<Outcome>> = vec![None; steps.len()];
        self.tried.retain(|(tried, _)| steps.contains(tried));
        let order = self.order(survey, view);
        for at in self.yielding(survey, order) {
            let step = steps[at];
            let shard = step.shard();
            let spent = match step {
                Step::Replace { .. } => {
                    let exhausted = budget.writes == 0 && budget.calls == 0;
                    exhausted && !records(view, shard).is_some_and(hold_due)
                }
                _ if writes(&step) => budget.writes == 0,
                _ => budget.calls == 0,
            };
            let left = budget.writes;
            let ran = !stopped.contains(&shard) && !spent;
            let (verdict, reply, reclaim, replaced) = if stopped.contains(&shard) {
                (Verdict::Wait(Reason::Moved), None, None, None)
            } else if spent {
                (Verdict::Wait(Reason::Budget), None, None, None)
            } else if let Step::Replace {
                shard,
                target,
                host,
            } = step
            {
                let planned = (shard, target, host);
                let (verdict, replaced) =
                    self.replace(gate, &mut tick, planned, &mut budget, effects);
                let reply = match replaced {
                    Some(Replaced::Requested(reply)) => Some(reply),
                    _ => None,
                };
                (verdict, reply, None, replaced)
            } else {
                let (verdict, reply, reclaim) =
                    self.step(gate, &mut tick, step, &mut budget, effects);
                (verdict, reply, reclaim, None)
            };
            self.count(step, verdict, reply, reclaim);
            if ran && writes(&step) {
                self.tried.retain(|(tried, _)| *tried != step);
                if budget.writes < left && verdict != Verdict::Advance {
                    self.tried.push((step, survey.status.tick));
                }
            }
            if matches!(
                verdict,
                Verdict::Wait(Reason::Unknown | Reason::Moved) | Verdict::Alarm(_)
            ) {
                stopped.insert(shard);
            }
            outcomes[at] = Some(Outcome {
                step,
                verdict,
                reply,
                reclaim,
                replaced,
            });
        }
        self.retire_displaced(view, &mut budget);
        Ok(outcomes.into_iter().flatten().collect())
    }

    /// Feeds a `Reconciler` step's error to the status's events and returns its verdict.
    pub(super) fn failed(&mut self, error: ReconcileError) -> Verdict {
        self.telemetry.events.failed(error);
        verdict_of(error)
    }

    /// Feeds a `Conflict` to the status's events and returns its alarm, for records that a retry cannot change.
    pub(super) fn conflicted(&mut self) -> Verdict {
        self.telemetry.events.failed(ReconcileError::Conflict);
        Verdict::Alarm(Reason::Step(ReconcileError::Conflict))
    }

    /// Feeds one step's reservation, attach record, attach request and reclamation results to the status's events.
    /// Each counts the step's result, which includes a result another loop's write already satisfied. `replace`
    /// counts its own decisions, creates and attach records; each `Reconciler` step's error counts where the step
    /// returns it (`ZoneLoop::failed`).
    fn count(
        &mut self,
        step: Step,
        verdict: Verdict,
        reply: Option<AttachReply>,
        reclaim: Option<Reclaim>,
    ) {
        let events = &mut self.telemetry.events;
        match (step, verdict) {
            (Step::Reserve { .. }, Verdict::Advance) => events.reserved(Ok(())),
            (Step::Reserve { .. }, Verdict::Wait(Reason::Population(refusal))) => {
                events.reserved(Err(refusal));
            }
            (Step::RecordAttach { .. }, Verdict::Advance) => {
                events.attached(AttachOutcome::Recorded)
            }
            _ => {}
        }
        match reply {
            Some(AttachReply::Accepted | AttachReply::AlreadyListed) => {
                events.attached(AttachOutcome::Requested);
            }
            Some(AttachReply::Refused(_)) => events.attached(AttachOutcome::Failed),
            Some(AttachReply::Unknown) => events.attached(AttachOutcome::Unknown),
            None => {}
        }
        if let Some(reclaim) = reclaim {
            events.reclaimed(match reclaim {
                Reclaim::Ended => Reclaimed::Ended,
                Reclaim::EndedNamed => Reclaimed::EndedNamed,
                Reclaim::RefusedOwner => Reclaimed::RefusedOwner,
                Reclaim::RefusedStandby => Reclaimed::RefusedStandby,
                Reclaim::DetachRequested => Reclaimed::DetachRequested,
                Reclaim::DetachUnknown => Reclaimed::DetachUnknown,
                Reclaim::Gone => Reclaimed::Gone,
                Reclaim::Removed => Reclaimed::Removed,
            });
        }
    }

    /// WRITE-YIELD: `order` with the yielding write steps moved after every other step, when the plan holds more
    /// write steps than `writes_per_tick`. A shard yields from its first tried write step on: that step and the
    /// shard's later write steps, in plan order. Yielding shards run in the order of the last charged call of
    /// their first tried step, the least recent first. A shard that enrolls for a fresh need keeps its places.
    fn yielding(&self, survey: &Survey, order: Vec<usize>) -> Vec<usize> {
        let steps = &survey.plan.steps;
        let budget = self.bounds.config().writes_per_tick as usize;
        if self.tried.is_empty() || steps.iter().filter(|step| writes(step)).count() <= budget {
            return order;
        }
        let mut yields: BTreeMap<Shard, (u64, usize)> = BTreeMap::new();
        for (step, tick) in &self.tried {
            let Some(at) = steps.iter().position(|held| held == step) else {
                continue;
            };
            if fresh(survey, step.shard()) {
                continue;
            }
            let held = yields.entry(step.shard()).or_insert((*tick, at));
            if at < held.1 {
                *held = (*tick, at);
            }
        }
        let yielded = |at: usize| {
            let first = yields.get(&steps[at].shard());
            writes(&steps[at]) && first.is_some_and(|&(_, first)| at >= first)
        };
        let mut last: Vec<usize> = (0..steps.len()).filter(|&at| yielded(at)).collect();
        last.sort_by_key(|&at| {
            let shard = steps[at].shard();
            (yields[&shard].0, shard, at)
        });
        let mut run: Vec<usize> = order.into_iter().filter(|&at| !yielded(at)).collect();
        run.extend(last);
        run
    }

    /// The order in which `actuate` runs the plan's steps: plan order, with the `Attach` and `Detach` steps permuted
    /// among their own positions by band, then last request time, then plan order (CALL-ROTATION). An attach's time
    /// is its entry's last request; a detach's is the last detach request for its volume and instance, which
    /// `actuate` drops `detach_settle_us` after its return, so a detach that is due again reads as never requested.
    fn order(&self, survey: &Survey, view: &ZoneView) -> Vec<usize> {
        let steps = &survey.plan.steps;
        let fresh = |shard: Shard| fresh(survey, shard);
        let attached = |shard: Shard, host: Host| {
            let active = &records(view, shard)?.active;
            let requested = self.requests.get(&(active.volume, active.live(host)?))?;
            Some(requested.last_us)
        };
        let detached = |shard: Shard, host: Host| {
            let active = &records(view, shard)?.active;
            let instance = active.latest(host)?.1.instance?;
            Some(self.detached.get(&(active.volume, instance))?.at_us)
        };
        let mut calls: Vec<usize> = (0..steps.len())
            .filter(|&at| matches!(steps[at], Step::Attach { .. } | Step::Detach { .. }))
            .collect();
        let slots = calls.clone();
        calls.sort_by_key(|&at| {
            let (band, last) = match steps[at] {
                Step::Attach { shard, host, .. } => {
                    let last = attached(shard, host);
                    let band = match (fresh(shard), last) {
                        (true, None) => 0,
                        (true, Some(_)) => 1,
                        (false, _) => 2,
                    };
                    (band, last)
                }
                Step::Detach { shard, host } => (1, detached(shard, host)),
                _ => (2, None),
            };
            (band, last.map_or(0, |at| at.saturating_add(1)), at)
        });
        let mut order: Vec<usize> = (0..steps.len()).collect();
        for (slot, at) in slots.into_iter().zip(calls) {
            order[slot] = at;
        }
        order
    }

    /// The live, unenrolled entries the plan treats as stuck at `now_us`. An entry with a request time is stuck once its
    /// last attach request is `attach_stuck_us` old. An entry with no request time is stuck `attach_stuck_us` after
    /// its first sighting: a survey that lists its instance, finds the shard's census slot on another host, or finds
    /// that `Attach::of` returns `Closed` for the entry, so the plan withholds its attach. While a census slot host
    /// displaces a live named standby (SLOT-HOST in `plan`), its entry with no request time is stuck `attach_stuck_us`
    /// after the first survey in the run that observes the displacement; a survey that reads the shard and finds the
    /// entry outside that state ends the run. An entry is also stuck once a
    /// survey listing has shown its instance for `enroll_stuck_us`.
    pub(super) fn stuck(
        &mut self,
        observation: &Observation,
        now_us: u64,
    ) -> BTreeSet<(VolumeId, u32)> {
        if let Ok(view) = &observation.zone {
            let mut read = BTreeMap::new();
            let mut waiting = BTreeMap::new();
            let mut shown_now = BTreeSet::new();
            let mut omitted = BTreeSet::new();
            let mut displacing = BTreeSet::new();
            let rows = view.volumes.as_ref().ok();
            let census = view.census.as_ref().ok();
            let live = |named: Host| {
                let mut hosts = view.hosts.iter();
                hosts.any(|seen| seen.entry.host == named && seen.verdict == HostEvidence::Live)
            };
            for held in &view.shards {
                let records = held.records.as_ref().ok().and_then(Option::as_ref);
                read.insert(held.shard, records.is_some());
                let Some(records) = records else {
                    continue;
                };
                let volume = &records.active;
                let slot = census.and_then(|census| census.slot(held.shard));
                for (seq, host) in volume.live_attaches() {
                    if volume.enrolled(host).is_some() {
                        continue;
                    }
                    let instance = volume.event(seq).and_then(|event| event.instance);
                    let shown = instance.is_some_and(|instance| {
                        let mut rows = rows.into_iter().flatten();
                        rows.any(|row| {
                            row.volume == volume.volume
                                && row.attachments.iter().any(|id| id == instance.as_str())
                        })
                    });
                    let withheld = Attach::of(volume, host, self.bounds.bounds()) == Attach::Closed;
                    let starts = shown || withheld || slot.is_none_or(|slot| slot.host != host);
                    waiting.insert((volume.volume, seq), (held.shard, starts));
                    if displaced(records, slot, live) == Some(host) {
                        displacing.insert((volume.volume, seq));
                    }
                    let listed = view.listing(volume.volume);
                    let omits = instance.is_some_and(|instance| {
                        listed.is_some_and(|ids| ids.iter().all(|id| id != instance.as_str()))
                    });
                    if shown {
                        shown_now.insert((volume.volume, seq));
                    } else if omits {
                        omitted.insert((volume.volume, seq));
                    }
                }
            }
            let kept = |entry: &(VolumeId, u32), shard: &Shard| match read.get(shard) {
                Some(true) => waiting.get(entry).is_some_and(|(held, _)| held == shard),
                Some(false) => true,
                None => false,
            };
            self.sighted.retain(|entry, (shard, _)| kept(entry, shard));
            (self.displacing).retain(|entry, (shard, _)| match read.get(shard) {
                Some(true) => displacing.contains(entry),
                Some(false) => true,
                None => false,
            });
            (self.attached)
                .retain(|entry, (shard, _)| kept(entry, shard) && !omitted.contains(entry));
            for (entry, (shard, starts)) in waiting {
                if starts {
                    self.sighted.entry(entry).or_insert((shard, now_us));
                }
                if shown_now.contains(&entry) {
                    self.attached.entry(entry).or_insert((shard, now_us));
                }
                if displacing.contains(&entry) {
                    self.displacing.entry(entry).or_insert((shard, now_us));
                }
            }
        }
        let config = self.bounds.config();
        let (stuck_us, enroll_us) = (config.attach_stuck_us, config.enroll_stuck_us);
        let old = |at: u64| now_us.saturating_sub(at) >= stuck_us;
        let requested = (self.requests.iter())
            .filter(|(_, requested)| old(requested.last_us))
            .map(|(&entry, _)| entry);
        let sighted = (self.sighted.iter().chain(&self.displacing))
            .filter(|(entry, (_, at))| !self.requests.contains_key(entry) && old(*at))
            .map(|(&entry, _)| entry);
        let attached = (self.attached.iter())
            .filter(|(_, (_, at))| now_us.saturating_sub(*at) >= enroll_us)
            .map(|(&entry, _)| entry);
        requested.chain(sighted).chain(attached).collect()
    }

    fn admits(&self, survey: &Survey, now_us: u64) -> Result<(u64, u64), Discard> {
        let Some((tick, started_us, surveyed_us)) = self.survey.times() else {
            return Err(Discard::Superseded);
        };
        if survey.status.tick != tick {
            return Err(Discard::Superseded);
        }
        if self.actuated >= tick {
            return Err(Discard::Repeated);
        }
        let elapsed = now_us.checked_sub(surveyed_us).ok_or(Discard::Rewound)?;
        if elapsed >= self.bounds.config().tick_us {
            return Err(Discard::Overrun);
        }
        Ok((surveyed_us, started_us))
    }

    /// Drops the request times of each entry whose shard `view` read with another active volume, or with the entry
    /// absent from the active volume's record, or marked gone in that record. The attach request of a shard's
    /// replacement, entry 0 of the volume its receipt of a later generation records as created, keeps its time while
    /// `view` reads that receipt. A shard that `view` lists with no records keeps its request times.
    /// A shard that `view` omits keeps them for the longer of `attach_stuck_us` and `detach_settle_us` after the
    /// last request's return (REQUEST-RETURNED), so a shard that returns to the directory still settles its last
    /// detach request from that return (RELEASE-SETTLED).
    /// Drops the kept listing when `view` omits the shard, reports a different active volume, or reports an active
    /// volume whose record marks the entry gone or omits it.
    fn forget(&mut self, view: &ZoneView, now_us: u64) {
        let read = || {
            (view.shards.iter())
                .filter_map(|held| Some((held.shard, held.records.as_ref().ok()?.as_ref()?)))
        };
        let by_shard: BTreeMap<Shard, &VolumeRecord> = read()
            .map(|(shard, records)| (shard, &records.active))
            .collect();
        let replacing: BTreeSet<(Shard, VolumeId)> = read()
            .filter_map(|(shard, records)| Some((shard, pending(records)?.phase.volume()?)))
            .collect();
        let kept = |held: &VolumeRecord, seq: u32| {
            (held.event(seq)).is_some_and(|event| event.kind != EventKind::Gone)
        };
        let listed: BTreeSet<Shard> = view.shards.iter().map(|held| held.shard).collect();
        let config = self.bounds.config();
        let (stuck_us, settle_us) = (config.attach_stuck_us, config.detach_settle_us);
        let delisted_us = stuck_us.max(settle_us);
        let recent = |returned: u64| now_us.saturating_sub(returned) < delisted_us;
        self.requests.retain(
            |(volume, seq), requested| match by_shard.get(&requested.shard) {
                Some(_) if *seq == 0 && replacing.contains(&(requested.shard, *volume)) => true,
                Some(held) => held.volume == *volume && kept(held, *seq),
                None if listed.contains(&requested.shard) => true,
                None => requested.returned_us.is_none_or(recent),
            },
        );
        self.clean.retain(
            |(volume, seq), listing| match by_shard.get(&listing.shard) {
                Some(held) => held.volume == *volume && kept(held, *seq),
                None => listed.contains(&listing.shard),
            },
        );
    }

    fn step(
        &mut self,
        gate: &StandbyGate,
        tick: &mut Tick<'_>,
        step: Step,
        budget: &mut Budget,
        effects: &mut (impl Attacher + ControlPlane),
    ) -> (Verdict, Option<AttachReply>, Option<Reclaim>) {
        let zone = self.bounds.config().zone;
        let view = tick.view;
        match step {
            Step::Reserve { shard, host, .. } => {
                let Some(report) = report(view, host) else {
                    return (Verdict::Wait(Reason::Unreported), None, None);
                };
                let cap = self.bounds.config().population_cap;
                let population = Population { cap };
                let bounds = self.bounds.bounds();
                let known = |held| view.active(held);
                let lost = |host| tick.lost(shard, host);
                budget.writes -= 1;
                let reserved = (self.reconciler).reserve(
                    gate,
                    &population,
                    bounds,
                    zone,
                    shard,
                    report,
                    known,
                    lost,
                );
                let verdict = match reserved {
                    Ok(_) => Verdict::Advance,
                    Err(ReconcileError::Population(refusal)) => {
                        Verdict::Wait(Reason::Population(refusal))
                    }
                    Err(error) => self.failed(error),
                };
                (verdict, None, None)
            }
            Step::RecordAttach {
                shard,
                host,
                target,
            } => {
                let planned = (shard, host, target);
                let (verdict, removed) = self.record(gate, tick, planned, &mut budget.writes);
                (verdict, None, removed.then_some(Reclaim::Removed))
            }
            Step::Attach {
                shard,
                host,
                target,
            } => {
                let planned = (shard, host, target);
                let at = (tick.now_us, &mut tick.fresh);
                let (verdict, reply) = self.attach(view, planned, at, budget, effects);
                (verdict, reply, None)
            }
            Step::Designate {
                shard,
                host,
                target,
            } => {
                let planned = (shard, host, target);
                let verdict = self.designate(gate, view, planned, &mut budget.writes);
                (verdict, None, None)
            }
            Step::Release {
                shard,
                host,
                target,
            } => {
                let held = Entry { target, host };
                let lost = |host| tick.lost(shard, host);
                budget.writes -= 1;
                let released = match self.reconciler.release(gate, zone, shard, held, lost) {
                    Ok(false) => Verdict::Advance,
                    Ok(true) => Verdict::Wait(Reason::Moved),
                    Err(error) => self.failed(error),
                };
                (released, None, None)
            }
            Step::End { shard, host } => {
                budget.writes -= 1;
                let (verdict, reclaim) = self.end(gate, tick, shard, host);
                (verdict, None, reclaim)
            }
            Step::Detach { shard, host } => {
                let (verdict, reclaim) = self.detach(tick, shard, host, budget, effects);
                (verdict, None, reclaim)
            }
            Step::ReleaseAttach { shard, host } => {
                let (verdict, reclaim) = self.release_attach(gate, tick, shard, host, budget);
                (verdict, None, reclaim)
            }
            Step::Replace { .. } => {
                unreachable!("`actuate` hands every `Step::Replace` to `replace` before `step`")
            }
        }
    }

    fn slot(&mut self, shard: Shard, host: Host, target: Target) -> Result<Slot, Verdict> {
        let zone = self.bounds.config().zone;
        let census = self.reconciler.read_census(zone);
        let census = census.map_err(|error| verdict_of(error.into()))?;
        let slot = Slot::held(&census, shard, host).filter(|slot| slot.target() == target);
        slot.ok_or(Verdict::Wait(Reason::Moved))
    }

    /// The span from a loop's first survey within which RECORD-SETTLED withholds a new attach entry that an earlier
    /// run's detach request could reach: `tick_us`, by which a call of that run that began before the survey has
    /// returned, and the settle time.
    fn settled_us(&self) -> u64 {
        let config = self.bounds.config();
        config.tick_us.saturating_add(config.detach_settle_us)
    }

    /// REQUEST-RETURNED: stamps `now_us`, a survey's time, as the return of every request sent since the last
    /// survey, or the request's own time when that is later.
    pub(super) fn returned(&mut self, now_us: u64) {
        for requested in self.requests.values_mut() {
            let returned = now_us.max(requested.last_us);
            requested.returned_us.get_or_insert(returned);
        }
        for sent in self.detached.values_mut() {
            sent.returned_us.get_or_insert(now_us.max(sent.at_us));
        }
    }

    fn record(
        &mut self,
        gate: &StandbyGate,
        tick: &Tick<'_>,
        (shard, host, target): (Shard, Host, Target),
        writes: &mut u32,
    ) -> (Verdict, bool) {
        let view = tick.view;
        let found = (
            records(view, shard),
            view.directory.host(host),
            report(view, host),
        );
        let (Some(records), Some(entry), Some(report)) = found else {
            return (Verdict::Wait(Reason::Unreported), false);
        };
        let era = report.host.build.era;
        if era < MIN_ERA {
            return (Verdict::Alarm(Reason::Era), false);
        }
        let volume = records.record.active;
        let Some(listed) = listing(view, volume) else {
            return (Verdict::Wait(Reason::Unlisted), false);
        };
        if listed.iter().any(|id| id == entry.instance.as_str()) {
            return (Verdict::Wait(Reason::Binding), false);
        }
        let held = &records.active;
        let unknown = !held.uncompacted()
            || (held.events.iter())
                .any(|e| e.kind == EventKind::Gone && e.instance == Some(entry.instance));
        let started = tick.started_us.saturating_add(self.settled_us());
        if self.detached.contains_key(&(volume, entry.instance))
            || (unknown && tick.surveyed_us < started)
        {
            return (Verdict::Wait(Reason::Settling), false);
        }
        if let Err(verdict) = self.slot(shard, host, target) {
            return (verdict, false);
        }
        match self.reconciler.standby_ready(shard, volume, host) {
            Ok(true) => {}
            Ok(false) => return (Verdict::Wait(Reason::OwnerNotReady), false),
            Err(error) => return (verdict_of(error.into()), false),
        }
        let unbound: Vec<Peer> = (view.directory.zone_hosts())
            .map(|entry| Peer {
                host: entry.host,
                instance: entry.instance,
            })
            .collect();
        let binding = Binding {
            instance: entry.instance,
            unbound: &unbound,
            listing: Some(listed),
        };
        let bounds = self.bounds.bounds();
        *writes -= 1;
        let recorded =
            (self.reconciler).record_standby(gate, shard, volume, host, era, bounds, &binding);
        let full = held.events.len() >= MAX_EVENTS && held.live(host).is_none();
        match recorded {
            Ok(_) => (Verdict::Advance, full),
            Err(ReconcileError::Conflict) => (Verdict::Wait(Reason::OwnerNotReady), false),
            Err(error) => (self.failed(error), false),
        }
    }

    fn attach(
        &mut self,
        view: &ZoneView,
        (shard, host, target): (Shard, Host, Target),
        (now_us, fresh): (u64, &mut BTreeMap<VolumeId, Vec<String>>),
        budget: &mut Budget,
        effects: &mut (impl Attacher + ControlPlane),
    ) -> (Verdict, Option<AttachReply>) {
        let (Some(records), Some(entry)) = (records(view, shard), view.directory.host(host)) else {
            return (Verdict::Wait(Reason::Unreported), None);
        };
        let (volume, instance) = (records.record.active, entry.instance);
        let tenure = match self.reconciler.read::<ShardRecord>(Key::Shard(shard)) {
            Ok(read) => read.into_value(),
            Err(error) => return (verdict_of(error.into()), None),
        };
        if Target::of(&tenure) != target || tenure.active != volume {
            return (Verdict::Wait(Reason::Moved), None);
        }
        if let Err(verdict) = self.slot(shard, host, target) {
            return (verdict, None);
        }
        let read = match self.reconciler.read::<VolumeRecord>(Key::Volume(volume)) {
            Ok(read) => read,
            Err(error) => return (verdict_of(error.into()), None),
        };
        let held = read.value();
        if !reservable(held) {
            return (Verdict::Wait(Reason::Moved), None);
        }
        let Some(seq) = held.live(host) else {
            return (Verdict::Wait(Reason::Moved), None);
        };
        let bound = held.event(seq).and_then(|event| event.instance);
        if bound.is_some_and(|bound| bound != instance) {
            return (Verdict::Alarm(Reason::Binding), None);
        }
        if held.enrolled(host).is_some() {
            return (Verdict::Advance, None);
        }
        if bound.is_none() {
            return (Verdict::Alarm(Reason::Binding), None);
        }
        let listed = effects.attachments(&volume);
        if let Ok(ids) = &listed {
            self.saw(fresh, volume, ids);
        }
        match listed {
            Err(Unlisted) => return (Verdict::Wait(Reason::Unlisted), None),
            Ok(ids) if ids.iter().any(|id| id == instance.as_str()) => {
                return (Verdict::Advance, None);
            }
            Ok(ids) if ids.iter().any(|id| InstanceId::new(id).is_none()) => {
                return (Verdict::Wait(Reason::Unlisted), None);
            }
            Ok(_) => {}
        }
        if self.detached.contains_key(&(volume, instance)) {
            return (Verdict::Wait(Reason::Settling), None);
        }
        let config = self.bounds.config();
        let (settle_us, stuck_us) = (config.attach_settle_us, config.attach_stuck_us);
        if let Some(requested) = self.requests.get(&(volume, seq)) {
            let waited = now_us.saturating_sub(requested.last_us);
            let ends = tenure.standby != Some(host);
            let window = ends && now_us.saturating_sub(requested.first_us) >= stuck_us;
            if window || waited < requested.wait_us(settle_us, stuck_us) {
                return (Verdict::Wait(Reason::Settling), None);
            }
        }
        if !budget.spend_call() {
            return (Verdict::Wait(Reason::Budget), None);
        }
        let reply = effects.attach(volume, instance);
        let requested = self.request(volume, seq, shard, now_us);
        let verdict = match reply {
            AttachReply::Accepted | AttachReply::AlreadyListed => {
                requested.refusals = 0;
                Verdict::Advance
            }
            AttachReply::Unknown => Verdict::Wait(Reason::Unknown),
            AttachReply::Refused(refusal) => {
                requested.refusals = requested.refusals.saturating_add(1);
                Verdict::Wait(Reason::AttachRefused(refusal))
            }
        };
        (verdict, Some(reply))
    }

    /// Stamps `now_us` as the last attach or detach request of entry `seq` of `volume`.
    pub(super) fn request(
        &mut self,
        volume: VolumeId,
        seq: u32,
        shard: Shard,
        now_us: u64,
    ) -> &mut Requested {
        let requested = self.requests.entry((volume, seq)).or_insert(Requested {
            shard,
            first_us: now_us,
            last_us: now_us,
            returned_us: None,
            refusals: 0,
        });
        (requested.last_us, requested.returned_us) = (now_us, None);
        requested
    }

    fn designate(
        &mut self,
        gate: &StandbyGate,
        view: &ZoneView,
        (shard, host, target): (Shard, Host, Target),
        writes: &mut u32,
    ) -> Verdict {
        let (Some(records), Some(entry)) = (records(view, shard), view.directory.host(host)) else {
            return Verdict::Wait(Reason::Unreported);
        };
        let volume = records.record.active;
        let slot = match self.slot(shard, host, target) {
            Ok(slot) => slot,
            Err(verdict) => return verdict,
        };
        let read = match self.reconciler.read::<VolumeRecord>(Key::Volume(volume)) {
            Ok(read) => read.into_value(),
            Err(error) => return verdict_of(error.into()),
        };
        let bound = (read.live(host)).and_then(|seq| read.event(seq)?.instance);
        if bound.is_some_and(|bound| bound != entry.instance) {
            return Verdict::Alarm(Reason::Binding);
        }
        *writes -= 1;
        match (self.reconciler).designate(gate, &slot, volume) {
            Ok(_) => Verdict::Advance,
            Err(error) => self.failed(error),
        }
    }
}
