//! The loop replaces a shard's lost active volume through the gated `Reconciler` replacement steps. Each
//! `Step::Replace` makes at most one replacement effect: the receipt's start or latch, one create, the replacement's
//! attach record, its attach request, the spare naming, the flip with the retirement of the volume it displaced, the
//! retirement of a rejected replacement, or the retirement of a lost replacement with the receipt's next attempt.
//!
//! - LOSS-NEEDS-EVIDENCE: an isolated receipt start, a create, the replacement's attach record and request, the spare
//!   naming and the flip each require `plan::complete_loss` to admit the survey's `VolumeJudgement`; the hold's start
//!   needs the loss `confirmed`. The check runs on every tick, so a receipt that opened on earlier evidence advances
//!   only while the loss still reads. A lost replacement is retired only on a complete view that ends a run of
//!   `loss_run` complete views, so each listing of the run that reads it lost is a complete one.
//! - CORRELATED-HOLD: with `others > 0`, the active volume's confirmed loss and an unreleased receipt, the step's one
//!   write is the hold, made by `Reconciler::replacement` for a new receipt or `Reconciler::latch` over a pending
//!   receipt of any phase that is neither held nor released. The operator's `Reconciler::release_hold` clears a hold,
//!   and a released receipt keeps its release. Each effect on a created replacement follows a receipt read in the
//!   same step that equals the survey's, so a hold latched between the survey and that read stops the attach record,
//!   the attach request, the naming, the flip, the rejection and the abandon.
//!   The hold's write proceeds on a tick whose write budget is spent (ONE-ATTEMPT in `zone_loop::actuate`). Writing
//!   the hold on the same tick preserves it even if the other volume's impairment clears before the next tick.
//! - CREATE-AFTER-ISSUE: the provider call happens inside `Reconciler::create_attempt`, after its issue write, for the
//!   request and attempt this step admitted at or below `create_attempts_max`; a higher attempt raises
//!   `Reason::Attempts`, and a stored receipt of another request or attempt sends nothing. A
//!   retry of the same request and attempt waits `create_settle_us` after the loop's previous call for that pair; a
//!   create of a later attempt waits `backoff_us(create_backoff_us, create_backoff_max_us, failures - 1)` over the
//!   request's failed creates. A create spends one write and one call of the tick's budget.
//!   `Reconciler::create_attempt` returns `Stale` before the provider call once the shard record holds the receipt's
//!   generation. The receipt keeps the issued token for the operator to settle.
//! - VERIFY-BEFORE-NAMING: `add_spare` and `flip_to` follow, in the same step, the survey's listing of the replacement
//!   as available, its record's check as unused for its attaching host, that host's check as live and admitted by the
//!   directory, and a fresh attachment listing that `attachments::check` admits for the host's instance alone
//!   (LISTED-SPARE). The replacement's attach record and its attach request each follow a shard read of the same
//!   step at the survey's `(g, owner, E)` and active volume. The step applies the same check first to the
//!   replacement's row of the survey's zone listing, as listed: a record whose instance ID the listing could not
//!   read is an empty entry and counts as foreign. When
//!   `Mismatch::retires` is true for either listing, the loop retires the replacement in the records
//!   through `Reconciler::retire_spare`, whose own shard read decides the spare removal, and raises
//!   `Reason::Foreign`. A retiring mismatch in the survey's listing rejects the replacement before the fresh
//!   attachment read; every other survey result leads to that read.
//!   The loop keeps the rejected volume in memory until that retirement settles and repeats it on
//!   later ticks whatever the listing then shows. A replacement whose record reads retired raises `Reason::Foreign`
//!   with no listing read, after the settling shard write while the shard record still names it spare. The receipt
//!   keeps a rejected volume as created until the volume reads lost, when ABANDON-ENTRY opens the next attempt, or
//!   until the operator settles the shard.
//! - FLIP-ENTRY: `flip_to` follows the step's receipt read, which equals the survey's receipt: the spare is the
//!   receipt's created volume, unheld, at the generation after the shard record's. `flip_to` conditions its write
//!   on a shard read that names the verified spare and refuses a hold it reads over that spare. A shard record that names another spare raises `Reason::Spare`. A receipt at any other
//!   later generation raises a step conflict.
//! - ABANDON-ENTRY: `abandon` follows this tick's listing of the created volume as lost under an unheld receipt, a
//!   receipt read in the same step equal to the survey's, and the retirement of that volume by
//!   `Reconciler::retire_spare`, which removes it as spare when its own shard read names it. The next attempt opens
//!   held only beside another impaired volume while the active volume's loss still reads confirmed
//!   (CORRELATED-HOLD); over an active volume that no longer reads lost it opens unheld.
//! - RETIRE-DISPLACED: `retire` of the displaced volume follows a flip this step committed. It writes the volume's
//!   retired state and the settling shard write; the volume stays attached. This loop keeps each displaced volume in
//!   memory, across later flips of the same shard, and repeats a failed retirement at the end of each later
//!   actuation while the shard record names another active volume, also after the directory omits the shard, when
//!   the retry reads the shard record itself. That retry runs outside the plan, within the tick's remaining writes,
//!   under the operator hold and the zone host hold too, and returns no `Outcome`; its errors reach the status
//!   events. A rejection's retry runs only inside a planned step, so it waits while the directory omits its shard.
//! - SUPERSEDED-RECEIPT: a receipt of an earlier request that still reads `Issued`, or records a created volume the
//!   shard names in no role and whose record is short of retired, refuses the start of a later replacement with a
//!   step conflict alarm on every tick. The operator settles it: `Reconciler::create_replacement` repeats the stored
//!   token and records the volume it made, and `Reconciler::retire` retires that volume.
//!
//! The create times, the displaced volumes and the rejected volumes live in this loop's memory. A restarted loop
//! repeats an issued token at once. A displaced volume whose retirement the earlier process left unfinished stays
//! recorded active and named by no shard; while it lists impaired or lost it counts beside every loss of the zone
//! (CORRELATED-HOLD), and the operator retires it with `Reconciler::retire`. A rejection lasts beyond its process
//! through the replacement's retired state: a restarted loop judges a replacement whose record reads short of
//! retired by that record and its own listings, and names and flips it when they read clean.

use std::collections::{BTreeMap, BTreeSet};

use crate::failover::attachments::{ControlPlane, InstanceId, Unlisted, check};
use crate::failover::loss::{
    CreateError, Decision, Health, Phase, Provider, Receipt, Request, decide,
};
use crate::failover::reconcile::{Flip, ReconcileError, StandbyGate, unused};
use crate::failover::records::{
    EventKind, Host, Layout, MIN_ERA, ShardRecord, VolumeId, VolumeRecord, VolumeState,
};
use crate::failover::report::status::AttachOutcome;
use crate::failover::retire::{Retirement, Role, Target, Trigger};
use crate::failover::zone_loop::ZoneLoop;
use crate::failover::zone_loop::actuate::{
    Budget, Reason, Tick, Verdict, backoff_us, records, verdict_of,
};
use crate::failover::zone_loop::directory::DirectoryState;
use crate::failover::zone_loop::evidence::{HostEvidence, loss_run};
use crate::failover::zone_loop::observe::ZoneView;
use crate::failover::zone_loop::plan::{complete_loss, hold_due, pending};
use crate::failover::zone_loop::sources::{AttachReply, Attacher};
use crate::net::ownership::Shard;
use crate::storage::store::{Key, Store, StoreError, WatermarkLog};

/// This loop's last provider call for one shard's replacement request: the attempt, the call's time, and the
/// request's failed creates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Create {
    request: Request,
    attempt: u32,
    last_us: u64,
    failures: u32,
}

/// Per shard, this loop's last provider call for its replacement request.
pub(crate) type Creates = BTreeMap<Shard, Create>;

/// Each shard with a volume one of its flips displaced, until that volume's retirement settles. A later flip of the
/// shard adds its own pair and keeps the earlier ones.
pub(crate) type Displaced = BTreeSet<(Shard, VolumeId)>;

/// The replacement volumes whose attachment listing showed a mismatch that retires, each with the trigger of its
/// retirement, until that retirement settles.
pub(crate) type Rejected = BTreeMap<VolumeId, Trigger>;

/// The effect one [`Step::Replace`](crate::failover::zone_loop::plan::Step::Replace) made or observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Replaced {
    /// `Reconciler::replacement` started or returned the receipt of this decision.
    Decided(Decision),
    /// The provider's reply to a create under the receipt's token.
    Created(Result<(), CreateError>),
    /// `Reconciler::latch` wrote the correlated hold over the pending receipt.
    Latched,
    /// The replacement's attach event, before its attach request.
    Recorded,
    /// The replacement's attach request for its attaching host, with the control plane's reply.
    Requested(AttachReply),
    /// `Reconciler::add_spare` named the replacement spare.
    Named,
    /// `Reconciler::flip_to` activated the replacement in this call. The step then calls `Reconciler::retire` for
    /// the displaced volume, and this loop repeats a failed retirement on later ticks.
    Flipped,
    /// The receipt's lost created volume is retired and the receipt stands at its next attempt.
    Abandoned,
    /// The replacement is retired in the records after its attachment listing showed another attachment.
    Rejected,
}

/// The provider `create_attempt` calls, which keeps the reply of that call.
struct Sent<'a, P> {
    provider: &'a mut P,
    reply: Option<Result<(), CreateError>>,
}

impl<P: Provider> Provider for Sent<'_, P> {
    fn create(&mut self, token: &str, layout: Layout) -> Result<VolumeId, CreateError> {
        let created = self.provider.create(token, layout);
        self.reply = Some(created.map(|_| ()));
        created
    }
}

impl<S: Store, L: WatermarkLog> ZoneLoop<S, L> {
    pub(super) fn replace(
        &mut self,
        gate: &StandbyGate,
        tick: &mut Tick<'_>,
        (shard, target, host): (Shard, Target, Option<Host>),
        budget: &mut Budget,
        effects: &mut (impl Attacher + ControlPlane + Provider),
    ) -> (Verdict, Option<Replaced>) {
        let Some(records) = records(tick.view, shard) else {
            return (Verdict::Wait(Reason::Unreported), None);
        };
        let record = records.record;
        if Target::of(&record) != target {
            return (Verdict::Wait(Reason::Moved), None);
        }
        let judged = records.judgement;
        let others = judged.others;
        let lost = judged.health == Some(Health::Lost) && judged.confirmed;
        let needed = loss_run(self.bounds.config().loss_ticks);
        let admitted = complete_loss(&judged, needed);
        let Some(receipt) = pending(records).cloned() else {
            if !lost || (others == 0 && !admitted) {
                return (Verdict::Wait(Reason::Unconfirmed), None);
            }
            return self.decide(gate, (shard, &record), others, budget);
        };
        if Some(receipt.request.generation.get()) != record.generation.get().checked_add(1) {
            return (self.conflicted(), None);
        }
        if receipt.held {
            return (Verdict::Wait(Reason::Held), None);
        }
        if hold_due(records) {
            return self.latch(gate, receipt.request, budget);
        }
        let volume = match receipt.phase {
            Phase::Created(volume) => volume,
            Phase::Open | Phase::Issued if !admitted => {
                return (Verdict::Wait(Reason::Unconfirmed), None);
            }
            Phase::Open | Phase::Issued => {
                return self.create(
                    gate,
                    tick.now_us,
                    (shard, &receipt, others),
                    budget,
                    effects,
                );
            }
        };
        let health = self.volumes.health(volume, self.ticks);
        if health == Some(Health::Lost) {
            if !judged.complete || judged.streak < needed {
                return (Verdict::Wait(Reason::Unconfirmed), None);
            }
            let beside = if lost { others } else { 0 };
            return self.abandon(gate, (shard, target), (&receipt, volume, beside), budget);
        }
        if let Some(trigger) = self.rejected.get(&volume).cloned() {
            if let Err(verdict) = self.unmoved(shard, &receipt) {
                return (verdict, None);
            }
            return self.reject((shard, target), volume, trigger, budget);
        }
        if !admitted {
            return (Verdict::Wait(Reason::Unconfirmed), None);
        }
        if health != Some(Health::Available) {
            return (Verdict::Wait(Reason::Unhealthy), None);
        }
        if let Err(verdict) = self.unmoved(shard, &receipt) {
            return (verdict, None);
        }
        let held = match self.reconciler.read::<VolumeRecord>(Key::Volume(volume)) {
            Ok(read) => read.into_value(),
            Err(error) => return (verdict_of(error.into()), None),
        };
        if held.state >= VolumeState::Retired {
            if record.spare.is_some_and(|(spare, _)| spare == volume) {
                return self.reject((shard, target), volume, Trigger::VolumeState, budget);
            }
            return (Verdict::Alarm(Reason::Foreign), None);
        }
        let event = (held.events.first()).filter(|event| event.kind == EventKind::Attach);
        let Some(attacher) = event.map(|event| event.host).or(host) else {
            return (Verdict::Wait(Reason::NoCandidate), None);
        };
        if held.state == VolumeState::Provisioning && held.events.is_empty() {
            return self.record_replacement(tick, (&record, volume, attacher), budget);
        }
        let Some(era) = event
            .map(|event| event.era)
            .filter(|_| unused(&held, attacher))
        else {
            return (self.conflicted(), None);
        };
        if let Some(verdict) = admits(tick.view, &record, attacher) {
            return (verdict, None);
        }
        let Some(entry) = tick.view.directory.host(attacher) else {
            return (Verdict::Wait(Reason::Unreported), None);
        };
        let instance = entry.instance;
        if record
            .spare
            .is_some_and(|spare| spare != (volume, attacher))
        {
            return (Verdict::Alarm(Reason::Spare), None);
        }
        let named = record.spare == Some((volume, attacher));
        let rows = tick.view.volumes.as_ref().ok();
        let row = rows.and_then(|rows| rows.iter().find(|row| row.volume == volume));
        let surveyed = row.map(|row| check(&row.attachments, &instance, []));
        let checked = match surveyed {
            Some(Err(mismatch)) if mismatch.retires() => Err(mismatch),
            _ => match effects.attachments(&volume) {
                Ok(listed) => check(&listed, &instance, []),
                Err(Unlisted) => return (Verdict::Wait(Reason::Unlisted), None),
            },
        };
        match checked {
            Ok(()) => {}
            Err(mismatch) if mismatch.retires() => {
                let trigger = Trigger::Attachment(mismatch);
                self.rejected.insert(volume, trigger.clone());
                return self.reject((shard, target), volume, trigger, budget);
            }
            Err(_) if named => return (Verdict::Alarm(Reason::Foreign), None),
            Err(_) => {
                return self.attach_replacement(
                    tick.now_us,
                    (&record, volume, instance),
                    budget,
                    effects,
                );
            }
        }
        if !named {
            return self.name((shard, target), (volume, attacher, era), budget);
        }
        self.promote(
            gate,
            (shard, target),
            (record.active, (volume, attacher)),
            budget,
        )
    }

    fn decide(
        &mut self,
        gate: &StandbyGate,
        (shard, record): (Shard, &ShardRecord),
        others: usize,
        budget: &mut Budget,
    ) -> (Verdict, Option<Replaced>) {
        if !budget.spend_write() && others == 0 {
            return (Verdict::Wait(Reason::Budget), None);
        }
        let evidence = (record.active, Health::Lost);
        let decision = decide(record, evidence, others);
        let layout = self.bounds.config().replacement;
        let started = (self.reconciler).replacement(gate, shard, evidence, others, layout);
        let verdict = match started {
            Ok(Some(read)) if read.value().held => Verdict::Wait(Reason::Held),
            Ok(Some(_)) => Verdict::Advance,
            Ok(None) => return (Verdict::Wait(Reason::Moved), None),
            Err(ReconcileError::Conflict) => return (self.conflicted(), None),
            Err(error) => return (self.failed(error), None),
        };
        self.telemetry.events.decided(decision);
        (verdict, Some(Replaced::Decided(decision)))
    }

    fn latch(
        &mut self,
        gate: &StandbyGate,
        request: Request,
        budget: &mut Budget,
    ) -> (Verdict, Option<Replaced>) {
        budget.spend_write();
        match self.reconciler.latch(gate, request) {
            Ok(read) if read.value().held => {
                self.telemetry.events.decided(Decision::Hold(Some(request)));
                (Verdict::Wait(Reason::Held), Some(Replaced::Latched))
            }
            Ok(_) => (Verdict::Wait(Reason::Moved), None),
            Err(error) => (self.failed(error), None),
        }
    }

    fn create(
        &mut self,
        gate: &StandbyGate,
        now_us: u64,
        (shard, receipt, others): (Shard, &Receipt, usize),
        budget: &mut Budget,
        effects: &mut impl Provider,
    ) -> (Verdict, Option<Replaced>) {
        let config = self.bounds.config();
        let settle_us = config.create_settle_us;
        let (backoff, backoff_max) = (config.create_backoff_us, config.create_backoff_max_us);
        if receipt.attempt > config.create_attempts_max {
            return (Verdict::Alarm(Reason::Attempts), None);
        }
        let last =
            (self.creates.get(&shard).copied()).filter(|last| last.request == receipt.request);
        if let Some(last) = last {
            let wait = match last.attempt == receipt.attempt {
                true => settle_us,
                false => backoff_us(backoff, backoff_max, last.failures.saturating_sub(1)),
            };
            if now_us.saturating_sub(last.last_us) < wait {
                return (Verdict::Wait(Reason::Settling), None);
            }
        }
        if !budget.spend_write_and_call() {
            return (Verdict::Wait(Reason::Budget), None);
        }
        let mut sent = Sent {
            provider: effects,
            reply: None,
        };
        let admitted = (receipt.request, receipt.attempt);
        let created = (self.reconciler).create_attempt(gate, admitted, others, &mut sent);
        let reply = sent.reply;
        if let Some(reply) = reply {
            let failed = u32::from(reply == Err(CreateError::Failed));
            let failures = last.map_or(0, |last| last.failures).saturating_add(failed);
            let create = Create {
                request: receipt.request,
                attempt: receipt.attempt,
                last_us: now_us,
                failures,
            };
            self.creates.insert(shard, create);
            self.telemetry.events.created(&reply);
        }
        let verdict = match created {
            Ok(_) => Verdict::Advance,
            Err(ReconcileError::Create(CreateError::Unknown)) => Verdict::Wait(Reason::Unknown),
            Err(ReconcileError::Create(CreateError::Failed)) => Verdict::Wait(Reason::Settling),
            Err(error) => self.failed(error),
        };
        (verdict, reply.map(Replaced::Created))
    }

    /// Writes the replacement's attach event for `host` after a read of the shard record, in this call, that holds
    /// `observed`'s tenure (`Self::tenure`).
    fn record_replacement(
        &mut self,
        tick: &Tick<'_>,
        (observed, volume, host): (&ShardRecord, VolumeId, Host),
        budget: &mut Budget,
    ) -> (Verdict, Option<Replaced>) {
        let found = tick.view.hosts.iter().find(|view| view.entry.host == host);
        let Some(report) = found.and_then(|view| view.report.as_deref()) else {
            return (Verdict::Wait(Reason::Unreported), None);
        };
        let era = report.host.build.era;
        if era < MIN_ERA {
            return (Verdict::Alarm(Reason::Era), None);
        }
        if let Err(verdict) = self.tenure(observed) {
            return (verdict, None);
        }
        if !budget.spend_write() {
            return (Verdict::Wait(Reason::Budget), None);
        }
        match self.reconciler.record_attach(volume, host, era) {
            Ok(_) => {
                self.telemetry.events.attached(AttachOutcome::Recorded);
                (Verdict::Advance, Some(Replaced::Recorded))
            }
            Err(error) => (self.failed(error), None),
        }
    }

    /// Sends the replacement's attach request after a read of the shard record, in this call, that holds
    /// `observed`'s tenure (`Self::tenure`).
    fn attach_replacement(
        &mut self,
        now_us: u64,
        (observed, volume, instance): (&ShardRecord, VolumeId, InstanceId),
        budget: &mut Budget,
        effects: &mut impl Attacher,
    ) -> (Verdict, Option<Replaced>) {
        let shard = observed.shard;
        let config = self.bounds.config();
        let (settle_us, stuck_us) = (config.attach_settle_us, config.attach_stuck_us);
        if let Some(requested) = self.requests.get(&(volume, 0)) {
            let waited = now_us.saturating_sub(requested.last_us);
            if waited < requested.wait_us(settle_us, stuck_us) {
                return (Verdict::Wait(Reason::Settling), None);
            }
        }
        if let Err(verdict) = self.tenure(observed) {
            return (verdict, None);
        }
        if !budget.spend_call() {
            return (Verdict::Wait(Reason::Budget), None);
        }
        let reply = effects.attach(volume, instance);
        let requested = self.request(volume, 0, shard, now_us);
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
        (verdict, Some(Replaced::Requested(reply)))
    }

    fn name(
        &mut self,
        (shard, target): (Shard, Target),
        (volume, host, era): (VolumeId, Host, u32),
        budget: &mut Budget,
    ) -> (Verdict, Option<Replaced>) {
        if !budget.spend_write() {
            return (Verdict::Wait(Reason::Budget), None);
        }
        let named = (self.reconciler.record_attach(volume, host, era))
            .and_then(|attached| self.reconciler.add_spare(shard, target, &attached));
        match named {
            Ok(_) => (Verdict::Advance, Some(Replaced::Named)),
            Err(error) => (self.failed(error), None),
        }
    }

    /// The step's read of the shard record: `Ok` while it holds the `(g, owner, E)` and active volume of `observed`,
    /// the survey's read, and `Moved` otherwise. A flip to another spare since the survey leaves the receipt as it
    /// stood, so the receipt read alone does not show it.
    fn tenure(&mut self, observed: &ShardRecord) -> Result<(), Verdict> {
        let tenure = |record: &ShardRecord| (Target::of(record), record.active);
        match self
            .reconciler
            .read::<ShardRecord>(Key::Shard(observed.shard))
        {
            Ok(read) if tenure(read.value()) == tenure(observed) => Ok(()),
            Ok(_) => Err(Verdict::Wait(Reason::Moved)),
            Err(error) => Err(verdict_of(error.into())),
        }
    }

    /// The step's read of `shard`'s receipt: `Ok` while it equals `observed`, the survey's read, and otherwise the
    /// wait for a hold that latched since the survey (`Held`) or for any other change (`Moved`). The effects that
    /// follow act on a receipt no hold had latched at this read; a hold that commits after it is the next step's to
    /// read.
    fn unmoved(&mut self, shard: Shard, observed: &Receipt) -> Result<(), Verdict> {
        let current = match self.reconciler.read::<Receipt>(Key::Replacement(shard)) {
            Ok(read) => read.into_value(),
            Err(error) => return Err(verdict_of(error.into())),
        };
        match current == *observed {
            true => Ok(()),
            false if current.held => Err(Verdict::Wait(Reason::Held)),
            false => Err(Verdict::Wait(Reason::Moved)),
        }
    }

    /// Retires the replacement `volume` in the records on `trigger`, the mismatch its attachment listing showed or
    /// the retired state its record already holds: `Reconciler::retire_spare` removes it as the shard's spare under
    /// `target` when its own shard read names it, writes its retired state and settles. The receipt keeps the volume
    /// as created, and the shard waits for the operator. The volume stays in this loop's memory until the retirement
    /// settles, so a later tick repeats a retirement that failed whatever its listing then shows.
    fn reject(
        &mut self,
        (shard, target): (Shard, Target),
        volume: VolumeId,
        trigger: Trigger,
        budget: &mut Budget,
    ) -> (Verdict, Option<Replaced>) {
        let Some(request) = Retirement::new(volume, Role::Spare, target, trigger) else {
            return (self.conflicted(), None);
        };
        if !budget.spend_write() {
            return (Verdict::Wait(Reason::Budget), None);
        }
        match self.reconciler.retire_spare(shard, &request) {
            Ok(_) => {
                self.rejected.remove(&volume);
                (Verdict::Alarm(Reason::Foreign), Some(Replaced::Rejected))
            }
            Err(error) => (self.failed(error), None),
        }
    }

    fn promote(
        &mut self,
        gate: &StandbyGate,
        (shard, target): (Shard, Target),
        (displaced, spare): (VolumeId, (VolumeId, Host)),
        budget: &mut Budget,
    ) -> (Verdict, Option<Replaced>) {
        if !budget.spend_write() {
            return (Verdict::Wait(Reason::Budget), None);
        }
        self.displaced.insert((shard, displaced));
        match self.reconciler.flip_to(gate, shard, target, spare) {
            Ok(Flip::Flipped(_)) => {}
            Ok(Flip::Past) => return (Verdict::Wait(Reason::Moved), None),
            Err(error) => return (self.failed(error), None),
        }
        match self.reconciler.retire(shard, displaced) {
            Ok(_) => {
                self.displaced.remove(&(shard, displaced));
                (Verdict::Advance, Some(Replaced::Flipped))
            }
            Err(error) => (self.failed(error), Some(Replaced::Flipped)),
        }
    }

    /// RETIRE-DISPLACED for each pair in this loop's memory whose shard record names another active volume than the
    /// pair's displaced one: one `Reconciler::retire` of the displaced volume, within `budget`'s writes. The shard
    /// record is the one `view` read, or, for a shard the tick's directory omits, a read of this call. A pair
    /// leaves the memory once its retirement settles.
    pub(super) fn retire_displaced(&mut self, view: &ZoneView, budget: &mut Budget) {
        let pairs: Vec<(Shard, VolumeId)> = self.displaced.iter().copied().collect();
        for (shard, volume) in pairs {
            let listed = view.shards.iter().any(|held| held.shard == shard);
            let active = match records(view, shard) {
                Some(records) => Some(records.record.active),
                None if listed => None,
                None => self.omitted_active(shard),
            };
            if active.is_none_or(|active| active == volume) {
                continue;
            }
            if !budget.spend_write() {
                return;
            }
            match self.reconciler.retire(shard, volume) {
                Ok(_) => {
                    self.displaced.remove(&(shard, volume));
                }
                Err(error) => {
                    self.failed(error);
                }
            }
        }
    }

    /// The active volume the record of `shard` names, by a read of this call, for a shard the tick's directory
    /// omits. `None` when the store holds no record of the shard or the read fails; a failed read reaches the
    /// status events.
    fn omitted_active(&mut self, shard: Shard) -> Option<VolumeId> {
        match self.reconciler.read::<ShardRecord>(Key::Shard(shard)) {
            Ok(read) => Some(read.value().active),
            Err(StoreError::Absent) => None,
            Err(error) => {
                self.failed(error.into());
                None
            }
        }
    }

    fn abandon(
        &mut self,
        gate: &StandbyGate,
        (shard, target): (Shard, Target),
        (observed, volume, others): (&Receipt, VolumeId, usize),
        budget: &mut Budget,
    ) -> (Verdict, Option<Replaced>) {
        if let Err(verdict) = self.unmoved(shard, observed) {
            return (verdict, None);
        }
        let request = Retirement::new(volume, Role::Spare, target, Trigger::VolumeState);
        let Some(request) = request else {
            return (self.conflicted(), None);
        };
        if !budget.spend_write() {
            return (Verdict::Wait(Reason::Budget), None);
        }
        let retired = self.reconciler.retire_spare(shard, &request);
        let abandoned = retired
            .and_then(|retired| (self.reconciler).abandon(gate, shard, observed, &retired, others));
        match abandoned {
            Ok(_) => (Verdict::Advance, Some(Replaced::Abandoned)),
            Err(error) => (self.failed(error), None),
        }
    }
}

/// The verdict that stops a replacement attached by `host`, or `None` when `view` reads `host` live and the directory
/// lists it active, or draining while it owns `record`'s shard. An unknown or conflicting verdict waits; a lost or
/// retired host, or a draining host that does not own the shard, raises an alarm and leaves the replacement volume
/// as it is.
fn admits(view: &ZoneView, record: &ShardRecord, host: Host) -> Option<Verdict> {
    let Some(found) = view.hosts.iter().find(|view| view.entry.host == host) else {
        return Some(Verdict::Wait(Reason::Unreported));
    };
    match (found.entry.state, found.verdict) {
        (DirectoryState::Retired, _) | (_, HostEvidence::Lost) => {
            Some(Verdict::Alarm(Reason::Attacher))
        }
        (DirectoryState::Draining, _) if host != record.owner => {
            Some(Verdict::Alarm(Reason::Attacher))
        }
        (_, HostEvidence::Live) => None,
        (_, HostEvidence::Unknown | HostEvidence::Conflict) => {
            Some(Verdict::Wait(Reason::Attacher))
        }
    }
}
