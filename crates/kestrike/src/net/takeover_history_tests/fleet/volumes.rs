//! Volume faults and the zone loop's replacement.
//!
//! A stall or a loss of one volume drops the shard's serving tenure without quiesce, and the holder's restart then
//! refuses at its device step and holds. The fleet sets the control plane's evidence on the zone double: status
//! `impaired` for an impairment and state `error` for a loss. The zone loop's survey judges that listing in its own
//! volume memory, and `ZoneLoop::actuate` runs each `Step::Replace` effect: the receipt, the create on the zone
//! double's provider, the attach record, the attach request, the spare and the flip. A restarted loop starts with an
//! empty memory and finds its earlier writes. The flipped shard's owner then runs `Fresh::run` at `E = 0` on the
//! replacement's blank media and reservation table and attaches cold. The operator's `release_hold` is a harness
//! action.
//!
//! The fleet takes each shard's blocker from the loop's status rows: `VolumeImpaired` for a retained impaired volume,
//! `CorrelatedHold` for a latched receipt and `DeviceFailureHold` for a shard whose restart or takeover holds at a
//! device step of a stalled or lost volume.

use crate::failover::fresh::{LocalRecords, Refusals};
use crate::failover::loss::{Phase, Receipt};
use crate::failover::poll::Holder;
use crate::failover::reconcile::OperatorRelease;
use crate::failover::record::LocalRecord;
use crate::failover::records::{Record, VolumeId, VolumeRecord};

use crate::failover::report::{RecoveryKind, RecoveryRefusal};
use crate::failover::takeover::tests::Reservation;
use crate::failover::zone_loop::actuate::Outcome;
use crate::failover::zone_loop::evidence::{ListedVolumeState, VolumeCondition, VolumeStatus};
use crate::failover::zone_loop::replace::Replaced;
use crate::storage::store::Key;

use super::super::{Event, Source};
use super::hosts::Up;
use super::reconcile::{Aim, Ending};
use super::{FIRST_KEY_EPOCH, Fleet, Live, Slots, Stopped, Stored};

/// The rounds the operator's release follows the latched hold by.
pub(crate) const RELEASE_ROUNDS: u64 = 20;
/// The rounds after the injector's last volume fault at which the operator releases with no hold read. They leave a
/// hold several survey turns to latch first.
pub(crate) const UNHELD_ROUNDS: u64 = 64;

/// The state of a shard's volume, as the injector set it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Device {
    Up,
    Stalled,
    Lost,
}

/// The write of the replacement steps that a crash-table cell ends. `CreateOpen` is the issue write of
/// `create_replacement`, `CreateIssued` its volume-record create and `CreateCreated` its write of the created volume
/// into the receipt. `Replacement`, `RecordAttach` and `AddSpare` are the one receipt or volume-record write of their
/// step. `Flip` is the shard-record write of the flip step; the volume-record writes that step makes before it pass
/// with no cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Boundary {
    Replacement,
    CreateOpen,
    CreateIssued,
    CreateCreated,
    RecordAttach,
    AddSpare,
    Flip,
}

impl Boundary {
    pub(crate) const ALL: [Self; 7] = [
        Self::Replacement,
        Self::CreateOpen,
        Self::CreateIssued,
        Self::CreateCreated,
        Self::RecordAttach,
        Self::AddSpare,
        Self::Flip,
    ];
}

/// On `tiny`, after the loss of s0's volume, reconciler 0 crashes in the step of `boundary`, right after that write
/// ends as `ending`, and restarts [`RESTART_ROUNDS`](super::reconcile::RESTART_ROUNDS) rounds later. After an
/// acknowledged write the step's next write, when it has one, does not commit, as when the crash precedes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ReplaceCell {
    pub(crate) boundary: Boundary,
    pub(crate) ending: Ending,
}

impl ReplaceCell {
    /// Every cell, each boundary's three endings in turn.
    pub(crate) fn all() -> Vec<Self> {
        let cells = Boundary::ALL.into_iter().flat_map(|boundary| {
            Ending::ALL
                .into_iter()
                .map(move |ending| Self { boundary, ending })
        });
        cells.collect()
    }

    /// The cell's byte in the run identity.
    pub(crate) fn code(self) -> u8 {
        let boundary = Boundary::ALL.iter().position(|&of| of == self.boundary);
        let ending = Ending::ALL.iter().position(|&of| of == self.ending);
        (boundary.expect("a boundary") * 3 + ending.expect("an ending")) as u8
    }

    pub(crate) fn name(self) -> String {
        format!("replace-{:?}-{:?}", self.boundary, self.ending).to_lowercase()
    }

    /// Whether the cell's crash follows the flip's landed shard-record write, acknowledged or with its reply unknown.
    /// Such a crash precedes the displaced volume's retirement and strands that volume.
    pub(crate) fn strands(self) -> bool {
        self.boundary == Boundary::Flip && self.ending != Ending::Lost
    }
}

/// What a host's restart of a shard ended in.
pub(super) enum Restarted {
    /// The tenure loaded warm and swept; `from` is the shard record's attempt count read just before the restart.
    Served {
        tenure: crate::oracle::Tenure,
        from: u32,
    },
    /// The record read before the incarnation named another owner. `check` is the waiting role from the role read,
    /// the blocker of a refusal, or the error of a failed role read; `None` when the incarnation acquired a tenure.
    /// `attempts` is that record's attempt count.
    Deposed {
        check: Option<String>,
        attempts: u32,
    },
    /// The host was down, the restart held at a refusal, or the load did not open.
    Held,
}

/// What a crash-table cell's step left when its crash ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CrashPoint {
    /// The store commits the step made.
    pub(crate) commits: usize,
    /// The provider's calls up to the crash.
    pub(crate) calls: usize,
    /// The phase of the shard's replacement receipt, `None` while the store holds no receipt.
    pub(crate) receipt: Option<Phase>,
}

/// The recovery a held restart or takeover reports: its kind and refusal, as the production mapping of the
/// refusal gives them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Held {
    pub(crate) kind: RecoveryKind,
    pub(crate) refusal: RecoveryRefusal,
}

impl Held {
    /// The hold of a production restart whose `Ended` carries `refusal`.
    pub(crate) fn of_restart(refusal: RecoveryRefusal) -> Self {
        Self {
            kind: RecoveryKind::Restart,
            refusal,
        }
    }

    pub(crate) fn status(self, now_us: u64) -> crate::failover::report::RecoveryStatus {
        let mut status = crate::failover::report::RecoveryStatus::NO_ATTEMPT;
        status.start(self.kind, now_us);
        status.refuse(self.refusal);
        status
    }
}

/// The volume faults and replacement steps of one run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct VolumeLog {
    /// Each volume whose record reads `Active` at the end of the run while no shard record names it active or spare:
    /// a displaced volume a crash between its replacement's flip and its retirement stranded. The operator clears
    /// it with `Reconciler::retire(shard, displaced)` and then `Reconciler::release_hold` for the latched receipt.
    pub(crate) stranded: Vec<VolumeId>,
    /// The shards whose volume stalled, and those whose volume the injector marked lost.
    pub(crate) stalled: Vec<u32>,
    pub(crate) lost: Vec<u32>,
    /// Status rows that newly named `VolumeImpaired` for a shard.
    pub(crate) retained: u32,
    /// Replacement receipts a decide call first read held.
    pub(crate) latched: u32,
    /// Create steps that refused `Held` over a receipt no decide call had read held: the step latched the hold itself.
    pub(crate) latched_at_create: u32,
    pub(crate) released: u32,
    /// The provider's calls when the operator released the hold.
    pub(crate) calls_at_release: Option<usize>,
    /// The provider's calls, the volumes it made, and each volume a create step returned with its shard.
    pub(crate) calls: usize,
    pub(crate) made: usize,
    pub(crate) created: Vec<(u32, String)>,
    /// The provider's volumes in creation order, each after the token of its create call.
    pub(crate) provided: Vec<(String, VolumeId)>,
    /// Flips this run's reconcilers committed and were acknowledged for.
    pub(crate) flipped: u32,
    /// The shards whose owner activated by the fresh path and attached cold.
    pub(crate) cold: Vec<u32>,
    /// Fresh activations that refused, by check.
    pub(crate) fresh_refused: Vec<String>,
    /// The crash-table cells whose crash ran, by name.
    pub(crate) crashed: Vec<String>,
    /// What the step of each crash that ran left, in the order of `crashed`.
    pub(crate) crash_points: Vec<CrashPoint>,
    /// Status rows that named `NoCandidate` with `DeviceFailureHold`, the loop's device-hold guard, for a shard whose
    /// restart or takeover held at a device step on two hosts.
    pub(crate) guarded: u32,
    /// The round a receipt was first read held or a create step first refused `Held`.
    pub(crate) held_since: Option<u64>,
    /// The round of the injector's last loss or impairment of a volume.
    pub(crate) faulted_at: Option<u64>,
    /// Each restart that served through its lineage arm: the shard, the host, and the round counted from the first
    /// host round, as a designation's round is.
    pub(crate) arm: Vec<(u32, u64, u64)>,
}

/// The local-record effects of one fresh activation: the record the host bound to the replacement volume, and
/// whether a refusal is retained.
struct FreshLocal(LocalRecord, bool);

impl crate::failover::restart::LocalSource for FreshLocal {
    fn local(&self) -> Result<LocalRecord, crate::failover::restart::Local> {
        Ok(self.0.clone())
    }
}

impl LocalRecords for FreshLocal {
    fn persist(
        &mut self,
        _: &Holder,
        attempt: u32,
        key: crate::failover::identity::Key,
    ) -> Result<LocalRecord, crate::failover::admission::AdmissionError> {
        use crate::failover::admission::AdmissionError;
        match (self.1, attempt) {
            (true, _) => Err(AdmissionError::Retained),
            (false, 0) if self.0.pair().key != key => Err(AdmissionError::Key),
            (false, 0) => Ok(self.0.clone()),
            (false, _) => Err(AdmissionError::AttemptConsumed),
        }
    }

    fn retain_refusal(
        &mut self,
        _: &LocalRecord,
    ) -> Result<(), crate::failover::admission::AdmissionError> {
        self.1 = true;
        Ok(())
    }

    fn release_refusal(
        &mut self,
        _: &LocalRecord,
    ) -> Result<(), crate::failover::admission::AdmissionError> {
        self.1 = false;
        Ok(())
    }
}

fn condition(state: ListedVolumeState, status: VolumeStatus) -> VolumeCondition {
    VolumeCondition { state, status }
}

impl Fleet<'_> {
    pub(super) fn receipt_now(&self, at: usize) -> Option<Receipt> {
        let store = self.store.0.borrow();
        let item = store.current(&Key::Replacement(self.cells[at].placement.shard))?;
        Some(Receipt::decode(&item.value).expect("a stored receipt"))
    }

    fn volume_record(&self, volume: VolumeId) -> Option<VolumeRecord> {
        let store = self.store.0.borrow();
        let item = store.current(&Key::Volume(volume))?;
        Some(VolumeRecord::decode(&item.value).expect("a stored volume record"))
    }

    fn set_condition(&mut self, at: usize, condition: VolumeCondition) {
        let volume = self.cells[at].placement.volume;
        if let Some(zone) = self.double(self.zone_of(at)) {
            zone.volume(volume, condition);
        }
    }

    /// The injector's stall or loss of cell `at`'s volume: the serving tenure drops without quiesce, the holder's
    /// incarnation runs its role read and `host::recover` over a device that completes no reservation command, and a
    /// loss window opens for the shards that serve. The faulted shard has no tenure, so the episode offers it no
    /// GET.
    pub(super) fn fail_volume<'w>(
        &mut self,
        live: &mut Live<'w>,
        slots: &mut Slots<'w>,
        at: usize,
        device: Device,
    ) -> Result<(), Stopped> {
        self.drain(live)?;
        if device == Device::Lost && live[at].is_some() {
            // The history's grouped judgement needs a tenure that read before a damage row to have read every object.
            let objects: Vec<u8> = self.cells[at].world.objects.iter().map(|o| o.n).collect();
            for n in objects {
                self.send(live, at, n, super::Purpose::Sweep);
                self.drain(live)?;
            }
        }
        if let Some(serving) = live[at].take() {
            self.cells[at].close(&serving, true);
        }
        let shard = self.cells[at].placement.shard;
        self.cells[at].device = device;
        self.cells[at].lost_at = Some(self.round);
        self.volumes.faulted_at = Some(self.round);
        match device {
            Device::Lost => {
                self.volumes.lost.push(shard.get());
                self.cells[at].world.events.push(Event::VolumeLost);
                let lost = condition(ListedVolumeState::Error, VolumeStatus::Impaired);
                self.set_condition(at, lost);
            }
            _ => self.volumes.stalled.push(shard.get()),
        }
        self.crashes += 1;
        let member = self.cells[at].holder;
        let (pair, local) = self.cells[at]
            .local_of(member)
            .expect("the holder's local record");
        let ground = slots.take(member);
        let mut client = self.client(member);
        let mut local = super::owners::OwnerLocal(local);
        let mut plane = crate::failover::fresh::tests::plane();
        let mut refusals = Refusals::default();
        let sources = (&mut local, &mut plane, &mut refusals);
        let of = self.topology.members[member];
        let cell = (&self.cells[at], of, pair);
        let ended = super::owners::incarnate(cell, self.round, ground.0, &mut client, sources);
        slots.put_back(member, ground.0);
        // A restart over a device that completes no reservation command acquires no tenure. A failed role read, or
        // a role that names another owner, is the shard's blocker; an incarnation that ended `Exit::Held` holds with
        // its refusal's class. The loss opens whichever check ended the incarnation.
        match ended {
            super::owners::Incarnation::Ended(exit, refusal) => {
                let flip = matches!(exit, crate::host::Exit::Retire(_));
                self.cells[at].refuse(super::owners::blocker(&exit, refusal), flip);
                if let (crate::host::Exit::Held { .. }, Some(refusal)) = (&exit, refusal) {
                    self.held(at, member, Held::of_restart(refusal));
                }
                self.queue_rerun(at, member, &exit, true);
            }
            super::owners::Incarnation::Unread(error) => {
                self.cells[at].refuse(format!("{error:?}"), false);
                let records = crate::host::Exit::Rerun(crate::host::Rerun::Records);
                self.queue_rerun(at, member, &records, true);
            }
            super::owners::Incarnation::Waits(role) => {
                self.cells[at].refuse(format!("{role:?}"), false);
                self.publish_role(at, member, role);
            }
            super::owners::Incarnation::Tenure(..) => {
                panic!(
                    "a restart over a device that completes no reservation command acquired a tenure"
                )
            }
        }
        self.open_loss(live, vec![at], super::hosts::Ends::Hosts)
    }

    /// The stall of cell `at`'s volume cleared: the host the shard record names owner is due its restart.
    pub(super) fn unstall(&mut self, at: usize) {
        self.cells[at].device = Device::Up;
        self.restarts.push_back(at);
    }

    pub(super) fn impair(&mut self, at: usize, on: bool) {
        let status = match on {
            true => VolumeStatus::Impaired,
            false => VolumeStatus::Ok,
        };
        if on {
            self.volumes.faulted_at = Some(self.round);
        }
        self.set_condition(at, condition(ListedVolumeState::InUse, status));
    }

    /// The operator's `release_hold` of cell `at`'s receipt, with the provider's call count before it. The count is
    /// taken with or without a receipt to release.
    pub(super) fn release_hold(&mut self, at: usize) {
        self.volumes.calls_at_release = Some(self.provider_calls());
        let Some(receipt) = self.receipt_now(at) else {
            return;
        };
        let mut reconciler = self.recon_client(0);
        let released = reconciler.release_hold(&OperatorRelease::diagnosed(), receipt.request);
        self.volumes.released += u32::from(released.is_ok_and(|read| read.value().released));
    }

    /// The zone doubles' provider calls.
    pub(super) fn provider_calls(&self) -> usize {
        self.zones.iter().map(|double| double.provider.calls).sum()
    }

    /// The provider calls of `zone`'s double, zero in a fleet without zone doubles.
    pub(super) fn zone_provider_calls(&self, zone: crate::failover::standbys::Zone) -> usize {
        let double = self.zones.iter().find(|double| double.zone == zone);
        double.map_or(0, |double| double.provider.calls)
    }

    /// Keeps the hold of a restart or takeover of cell `at` by `member` whose incarnation ended `Exit::Held`, with its
    /// refusal's class. `member`'s next report carries the held entry, from which the loop's status names the shard's
    /// blocker; a hold other than `RecordedHolder` while the volume is stalled or lost also joins the cell's device
    /// holds, which the survey's device-hold guard reads.
    pub(super) fn held(&mut self, at: usize, member: usize, recovery: Held) {
        // The new hold replaces the process's earlier one, a returned host's included.
        self.held_returns.remove(&(at, member));
        let check = recovery.status(0).recovery(0).check;
        let recorded = check == Some(crate::failover::report::RecoveryCheck::RecordedHolder);
        if self.repairs() && !recorded && self.cells[at].device != Device::Up {
            self.cells[at].device_holds.insert(member);
        }
        let cell = &mut self.cells[at];
        cell.held.retain(|(of, _)| *of != member);
        cell.held.push((member, recovery));
    }

    /// The restart of the host that cell `at`'s record names owner, after the stall cleared. A restart that returns
    /// loads warm, and it ends the member's device hold; a successor that held before its preempt returns through
    /// the restart's lineage arm. An incarnation that ends `Exit::Held` holds, `RecordedHolder` as
    /// `RecordedHolderHold`; a failed role read and an exit that names a rerun queue the next incarnation
    /// ([`Fleet::queue_rerun`]).
    pub(super) fn restart_named<'w>(
        &mut self,
        live: &mut Live<'w>,
        slots: &mut Slots<'w>,
        at: usize,
    ) -> Result<(), Stopped> {
        let record = self.record_now(at);
        let Some(member) = self.member_of(record.owner) else {
            return Ok(());
        };
        // An owner whose tenure already serves the shard runs no second restart over it.
        if live[at].is_some() && self.cells[at].holder == member {
            return Ok(());
        }
        self.restart_by(live, slots, (at, true), member).map(|_| ())
    }

    /// The next incarnation of `member`'s process, whose tenure `tenure` of cell `at` ended at its exit in round
    /// `ended`: its restart, once the record still names its host owner at that tenure, no tenure serves the cell and
    /// the host runs, on a free tenure slot of the host. It follows no loss or crash, so its recovery arms no loss
    /// plant, counts no drop and counts its rounds from `ended`. A rerun the record, the cell or the host no longer
    /// admits, and one with no free slot, runs no incarnation and is counted. The host loop calls this for a host
    /// that is not paused (`Fleet::rerun_due`), so a host that does not run here is a stopped one.
    pub(super) fn rerun<'w>(
        &mut self,
        live: &mut Live<'w>,
        slots: &mut Slots<'w>,
        (at, member, tenure, ended): (usize, usize, crate::oracle::Tenure, u64),
    ) -> Result<(), Stopped> {
        let record = self.record_now(at);
        let named = record.owner == self.topology.members[member].host
            && super::owners::tenure_at(crate::failover::retire::Target::of(&record)) == tenure;
        if !named || live[at].is_some() || self.hosts[member].up != Up::Running {
            self.log.rerun_dropped += 1;
            return Ok(());
        }
        if !slots.free(member) {
            self.log.unslotted += 1;
            return Ok(());
        }
        // The rerun's recovery counts its rounds from the round its tenure ended.
        self.cells[at].rerun_from = Some(ended);
        let restarted = self.restart_by(live, slots, (at, false), member);
        self.cells[at].rerun_from = None;
        restarted.map(|_| ())
    }

    /// The next incarnation of `member`'s process for cell `at`, whose restart ended with an exit that names a rerun
    /// ([`Fleet::queue_rerun`]): its role read and `host::recover` through [`Fleet::restart_by`], on a free tenure
    /// slot of the host, while the host runs and serves no tenure of the cell. The next incarnation of a returned
    /// host's restart ([`Fleet::returning`]) runs through [`Fleet::restart_returned`], which completes the return. A
    /// role read that names the member standby of another owner makes the process wait there (a retake). The next
    /// incarnation of a serving tenure's rerun ([`Fleet::rerun_starts`]) counts its recovery's rounds from the round
    /// that tenure ended, as [`Fleet::rerun`] does. An incarnation that ends with a rerun exit again is queued as a
    /// refusal that recurred ([`Fleet::recurred`]) and records no wait. A rerun of a host that stopped, already
    /// serves the cell or has the cell's restart queued as its return, and one with no free slot, runs no
    /// incarnation and is counted, as [`Fleet::rerun`] counts its own.
    pub(super) fn rerun_refused<'w>(
        &mut self,
        live: &mut Live<'w>,
        slots: &mut Slots<'w>,
        (at, member, after_loss): (usize, usize, bool),
    ) -> Result<(), Stopped> {
        let returning = self.returning.remove(&(at, member));
        let ended = self.rerun_starts.remove(&(at, member));
        self.recurred.remove(&(at, member));
        // A host that stopped runs no incarnation, and one that already serves the cell needs none. A host that
        // crashed and returned since the refusal runs the cell's restart as its return, which is queued.
        let serves = live[at].is_some() && self.cells[at].holder == member;
        let returns = self.returns.contains(&(at, member));
        if self.hosts[member].up != Up::Running || serves || returns {
            self.log.rerun_dropped += 1;
            return Ok(());
        }
        if !slots.free(member) {
            self.log.unslotted += 1;
            // A held process's rerun stays due, with its return marker, until a slot is free and its incarnation
            // starts.
            if (self.cells[at].held.iter()).any(|(of, _)| *of == member) {
                self.refused.insert((at, member), (self.round, after_loss));
                if returning {
                    self.returning.insert((at, member));
                }
                if let Some(ended) = ended {
                    self.rerun_starts.insert((at, member), ended);
                }
            }
            return Ok(());
        }
        self.log.refused_reruns += 1;
        // A hold belongs to the incarnation that returned `Exit::Held` and ends as the next one starts.
        let cell = &mut self.cells[at];
        cell.held.retain(|(of, _)| *of != member);
        cell.device_holds.remove(&member);
        cell.rerun_from = ended;
        let restarted = if returning {
            self.restart_returned(live, slots, (at, member))
        } else {
            (self.restart_by(live, slots, (at, after_loss), member)).map(|_| ())
        };
        self.cells[at].rerun_from = None;
        restarted?;
        if self.refused.contains_key(&(at, member)) {
            // The incarnation ended with a rerun exit of its own: the refusal recurred.
            self.recurred.insert((at, member));
        } else {
            // The incarnation's own role read decides: a record that names another owner makes it wait, and
            // `retake` records the wait when that record names the member standby.
            self.retake(at, member);
        }
        Ok(())
    }

    /// `member`'s incarnation for cell `at`, its role read and then `host::recover`, with the shard record read just
    /// before it. When that record names another owner the attempt returns [`Restarted::Deposed`] with the waiting
    /// role from the read, the refusal's blocker or the read error, or `None` for an incarnation that acquired a
    /// tenure. The fleet drops that incarnation unserved and leaves the cell unchanged. Under a record that names
    /// the member's host a refusal is the cell's blocker: an incarnation that ended `Exit::Held` holds as
    /// [`Fleet::restart_named`] states. An exit that names a rerun and a failed role read queue the next incarnation
    /// under either record ([`Fleet::queue_rerun`]).
    pub(super) fn restart_by<'w>(
        &mut self,
        live: &mut Live<'w>,
        slots: &mut Slots<'w>,
        (at, after_loss): (usize, bool),
        member: usize,
    ) -> Result<Restarted, Stopped> {
        if self.hosts[member].up != Up::Running {
            return Ok(Restarted::Held);
        }
        let of = self.topology.members[member];
        let cell = &self.cells[at];
        let (pair, local) = cell.local_of(member).expect("the owner's local record");
        let before = self.record_now(at);
        let ground = slots.take(member);
        let mut client = self.client(member);
        let mut local = super::owners::OwnerLocal(local);
        let mut plane = crate::failover::fresh::tests::plane();
        let mut refusals = Refusals::default();
        let sources = (&mut local, &mut plane, &mut refusals);
        let cell = (&self.cells[at], of, pair);
        let incarnation =
            super::owners::incarnate(cell, self.round, ground.0, &mut client, sources);
        drop(client);
        let (tenure, control, now) = match incarnation {
            // A tenure acquired under a record that named another owner is dropped unserved; its driver returned
            // every command, and the cell keeps its holder and its live tenure.
            super::owners::Incarnation::Tenure(tenure, ..) if before.owner != of.host => {
                drop(tenure);
                slots.put_back(member, ground.0);
                let attempts = before.attempts;
                return Ok(Restarted::Deposed {
                    check: None,
                    attempts,
                });
            }
            super::owners::Incarnation::Tenure(tenure, control, now) => (tenure, control, now),
            // A role read that names another owner starts no restart: the process waits as a standby or unnamed
            // host, and the cell stays as it was.
            super::owners::Incarnation::Waits(role) => {
                slots.put_back(member, ground.0);
                self.publish_role(at, member, role);
                let check = Some(format!("{role:?}"));
                let attempts = before.attempts;
                return Ok(Restarted::Deposed { check, attempts });
            }
            super::owners::Incarnation::Ended(exit, refusal) => {
                slots.put_back(member, ground.0);
                self.end_wait(at, member);
                // An exit that names a rerun ends the process under either record: its next incarnation reads its
                // role again.
                self.queue_rerun(at, member, &exit, after_loss);
                if before.owner != of.host {
                    let flip = matches!(exit, crate::host::Exit::Retire(_));
                    self.cells[at].flip_requests += usize::from(flip);
                    let check = Some(super::owners::blocker(&exit, refusal));
                    let attempts = before.attempts;
                    return Ok(Restarted::Deposed { check, attempts });
                }
                self.depose_other(live, at, member);
                self.cells[at].holder = member;
                let flip = matches!(exit, crate::host::Exit::Retire(_));
                self.cells[at].refuse(super::owners::blocker(&exit, refusal), flip);
                if let (crate::host::Exit::Held { .. }, Some(refusal)) = (&exit, refusal) {
                    self.held(at, member, Held::of_restart(refusal));
                }
                return Ok(Restarted::Held);
            }
            // A failed role read ends the incarnation with `Rerun::Records`, whichever owner the record names: the
            // process read no role, so its next incarnation runs.
            super::owners::Incarnation::Unread(error) => {
                slots.put_back(member, ground.0);
                self.end_wait(at, member);
                let check = format!("{error:?}");
                let records = crate::host::Exit::Rerun(crate::host::Rerun::Records);
                self.queue_rerun(at, member, &records, after_loss);
                if before.owner != of.host {
                    let attempts = before.attempts;
                    return Ok(Restarted::Deposed {
                        check: Some(check),
                        attempts,
                    });
                }
                self.cells[at].refuse(check, false);
                return Ok(Restarted::Held);
            }
        };
        self.depose_other(live, at, member);
        self.cells[at].holder = member;
        self.cells[at].blocked = false;
        let lost_at = (self.cells[at].rerun_from)
            .or(self.cells[at].lost_at)
            .unwrap_or(self.round);
        let lineage = tenure.lineage();
        let tenure = self.rise(
            live,
            ground,
            (at, pair),
            (*tenure, control, now),
            Source::Named,
        )?;
        self.reread_hosts(at);
        let Some(tenure) = tenure else {
            return Ok(Restarted::Held);
        };
        // The guard reads the owner's present state, as `failover::zone_loop::plan` does: a member that serves holds
        // at no device step.
        self.cells[at].device_holds.remove(&member);
        if lineage {
            let shard = self.cells[at].placement.shard;
            let round = self.round - self.host_start;
            self.volumes.arm.push((shard.get(), of.host.get(), round));
        }
        self.unhold(at);
        let rounds = self.round - lost_at;
        self.recovered(live, at, tenure, rounds, (after_loss, after_loss))?;
        let from = before.attempts;
        Ok(Restarted::Served { tenure, from })
    }

    /// Moves a live tenure of cell `at` that another member holds to the deposed slots, as `Fleet::take_over` does
    /// before its tenure rises. The record names `member`'s host owner, so that tenure is deposed: it steps under its
    /// own host until it withdraws, and the run's end counts it if it never does.
    fn depose_other<'w>(&mut self, live: &mut Live<'w>, at: usize, member: usize) {
        let holder = self.cells[at].holder;
        if holder != member
            && let Some(deposed) = live[at].take()
        {
            live.push(Some(deposed));
            self.deposed.push((at, holder));
        }
    }

    /// Drops the held entry of cell `at`'s holder once its tenure serves.
    fn unhold(&mut self, at: usize) {
        let holder = self.cells[at].holder;
        self.cells[at].held.retain(|(of, _)| *of != holder);
    }

    /// The cell whose record names a volume other than the one its cell runs, at `E = 0` with its owner running: a
    /// flip made the replacement active and its owner has not activated. A cell whose fresh activation's role read
    /// failed, or whose activation ended with an exit that names a rerun, in an earlier round is due again over its
    /// installed replacement while the record's owner is the member that began the activation. That exit can follow
    /// the activation's own bump, so the retry is due at any `E`, and its role read finds the record's current one.
    pub(super) fn fresh_due(&self) -> Option<usize> {
        let activated = self.volumes.cold.len() + self.volumes.fresh_refused.len();
        if self.store.0.borrow().flips.len() <= activated {
            return None;
        }
        (0..self.cells.len()).find(|&at| {
            let record = self.record_now(at);
            let owner = self.member_of(record.owner);
            let cell = &self.cells[at];
            let retry = (cell.fresh_unread).is_some_and(|round| self.round > round)
                && owner == Some(cell.holder);
            let pending = record.active != cell.placement.volume
                && !cell.fresh_refused
                && record.attempts == 0;
            (pending || retry) && owner.is_some_and(|owner| self.hosts[owner].up == Up::Running)
        })
    }

    /// The owner's fresh activation on cell `at`'s replacement volume: the cell moves to the replacement's blank
    /// media and empty reservation table, `Fresh::run` activates `E = 1` over the zone double's listing, and the
    /// tenure attaches cold and sweeps, with no object counted as retained. A retry after a failed role read or an
    /// exit that names a rerun keeps the installed media, reservation table and local record; a retry that follows
    /// the activation's bump reads the restart role, and its tenure attaches cold as the activation's would.
    pub(super) fn activate_fresh<'w>(
        &mut self,
        live: &mut Live<'w>,
        slots: &mut Slots<'w>,
        at: usize,
    ) -> Result<(), Stopped> {
        self.drain(live)?;
        // A replaced tenure whose `Rerun` or `Deposed` exit waited for a GET's outcome ends through `serve::teardown`,
        // and each open loss drops its watch of the shard. The fresh activation is the shard's next process.
        match live[at].take() {
            Some(serving) if super::awaits_teardown(&serving) => {
                self.tear_down(at, serving);
                self.release_watches(at);
            }
            Some(serving) => self.cells[at].close(&serving, true),
            None => {}
        }
        let record = self.record_now(at);
        let member = self.member_of(record.owner).expect("a running owner");
        let of = self.topology.members[member];
        // A retry's refusal is one that recurred; a first activation's refusal holds the host loop for its retry's
        // turn (`Fleet::fresh_first`).
        match self.cells[at].fresh_unread {
            Some(_) => self.recurred.insert((at, member)),
            None => self.recurred.remove(&(at, member)),
        };
        // A retry keeps the replacement's media, reservation table and local record.
        let local = match self.cells[at].fresh_unread.take() {
            Some(_) => (self.cells[at].local.0.clone()).expect("the replacement's local record"),
            None => {
                let cell = &mut self.cells[at];
                cell.placement.volume = record.active;
                (cell.owner, cell.holder, cell.device) = (of.host, member, Device::Up);
                (cell.seeded_standby, cell.third) = (false, None);
                cell.enrolled.clear();
                cell.device_holds.clear();
                cell.held.clear();
                cell.cold = true;
                cell.world.a.media =
                    crate::storage::device::sim::media(crate::storage::volume_fixture::MEDIA);
                cell.world.reservation =
                    std::rc::Rc::new(std::cell::RefCell::new(Reservation::default()));
                // KEY-PER-ATTACH: the owner's local record stands under the key `Fresh::run` hands its `persist`,
                // the key of the owner's live attach in the replacement's record. A record that gives no such key
                // refuses before any persist, and the local record then keeps the member's seeded key.
                let seeded =
                    ((member as u64 + FIRST_KEY_EPOCH) << 32) | u64::from(record.shard.get());
                let key = (self.volume_record(record.active))
                    .and_then(|held| held.enrollment_key(of.host))
                    .unwrap_or_else(|| {
                        crate::failover::identity::Key::decode(seeded)
                            .expect("a member's seeded key")
                    });
                let local = self.local_record(at, member, key);
                let cell = &mut self.cells[at];
                (cell.pair, cell.local) = (local.pair(), Stored(Ok(local.clone())));
                // The replacement's owner is found by its own member index, whichever host the seed placed as
                // owner.
                cell.enrolled(member, local.pair(), Stored(Ok(local.clone())));
                local
            }
        };
        let mut records = FreshLocal(local.clone(), false);
        let mut refusals = Refusals::default();
        let mut client = self.client(member);
        let zone = self.cells[at].placement.zone;
        let ground = slots.take(member);
        let incarnation = {
            let double = (self.zones.iter_mut()).find(|double| double.zone == zone);
            let double = double.expect("a repairing fleet's zone double");
            let sources = (&mut records, double, &mut refusals);
            let cell = (&self.cells[at], of, local.pair());
            super::owners::incarnate(cell, self.round, ground.0, &mut client, sources)
        };
        drop(client);
        let shard = self.cells[at].placement.shard.get();
        let (tenure, control, now) = match incarnation {
            super::owners::Incarnation::Tenure(tenure, control, now) => (tenure, control, now),
            // An exit that names a rerun keeps the activation due, as a failed role read does; any other exit ends
            // the replacement's activation.
            super::owners::Incarnation::Ended(exit @ crate::host::Exit::Rerun(_), refusal) => {
                slots.put_back(member, ground.0);
                self.cells[at].refuse(super::owners::blocker(&exit, refusal), false);
                self.cells[at].fresh_unread = Some(self.round);
                return Ok(());
            }
            super::owners::Incarnation::Ended(exit, refusal) => {
                slots.put_back(member, ground.0);
                let check = super::owners::blocker(&exit, refusal);
                let cell = &mut self.cells[at];
                cell.refuse(check.clone(), matches!(exit, crate::host::Exit::Retire(_)));
                cell.fresh_refused = true;
                self.volumes.fresh_refused.push(check);
                return Ok(());
            }
            super::owners::Incarnation::Waits(role) => {
                panic!("the replacement's owner reads {role:?}")
            }
            // The activation stays due and retries from a later round over the installed replacement.
            super::owners::Incarnation::Unread(error) => {
                slots.put_back(member, ground.0);
                self.cells[at].refuse(format!("{error:?}"), false);
                self.cells[at].fresh_unread = Some(self.round);
                return Ok(());
            }
        };
        let lost_at = self.cells[at].lost_at.unwrap_or(self.round);
        let opened = self.rise(
            live,
            ground,
            (at, local.pair()),
            (*tenure, control, now),
            Source::Cold,
        )?;
        self.reread_hosts(at);
        if opened.is_none() {
            return Ok(());
        }
        self.volumes.cold.push(shard);
        self.unhold(at);
        let tenure = opened.expect("the opened tenure");
        self.recovered(live, at, tenure, self.round - lost_at, (true, true))
    }

    /// The replacement crash-table cell's effect: the `n`-th write of the lost shard's receipt, shard record or new
    /// volume record that the cell's boundary names, counted from the volume loss.
    pub(super) fn replace_aim(&self, cell: ReplaceCell) -> Option<Aim> {
        if !self.recon.crashed.is_empty() || self.volumes.lost.is_empty() {
            return None;
        }
        let shard = self.cells[0].placement.shard;
        let (receipt, record) = (Key::Replacement(shard), Key::Shard(shard));
        Some(match cell.boundary {
            Boundary::Replacement => Aim::Write(receipt, 0),
            Boundary::CreateOpen => Aim::Write(receipt, 1),
            Boundary::CreateIssued => Aim::Spare(0),
            Boundary::CreateCreated => Aim::Write(receipt, 2),
            Boundary::RecordAttach => Aim::Spare(1),
            Boundary::AddSpare => Aim::Write(record, 0),
            Boundary::Flip => Aim::Write(record, 1),
        })
    }

    /// Records what the replacement cell's crash left: the commits of its aimed write, the provider's calls and the
    /// receipt's phase.
    pub(super) fn replace_crashed(&mut self, cell: ReplaceCell) {
        self.volumes.crashed.push(cell.name());
        self.volumes.crash_points.push(CrashPoint {
            commits: self.step_commits,
            calls: self.provider_calls(),
            receipt: self.receipt_now(0).map(|receipt| receipt.phase),
        });
    }

    /// Logs the effect a replacement step of cell `at` made or observed.
    pub(super) fn replace_logged(&mut self, at: usize, outcome: &Outcome) {
        let shard = self.cells[at].placement.shard.get();
        let held = self.receipt_now(at).is_some_and(|receipt| receipt.held);
        match outcome.replaced {
            Some(Replaced::Decided(_)) if held && self.volumes.held_since.is_none() => {
                self.volumes.latched += 1;
                self.volumes.held_since = Some(self.round);
            }
            Some(Replaced::Latched) if self.volumes.held_since.is_none() => {
                self.volumes.latched_at_create += 1;
                self.volumes.held_since = Some(self.round);
            }
            Some(Replaced::Created(Ok(()))) => {
                if let Some(Phase::Created(volume)) = self.receipt_now(at).map(|r| r.phase) {
                    let made = (shard, volume.as_str().to_owned());
                    if !self.volumes.created.contains(&made) {
                        self.volumes.created.push(made);
                    }
                }
            }
            Some(Replaced::Flipped) => self.volumes.flipped += 1,
            _ => {}
        }
    }

    /// The zone doubles' provider counts after a reconciler round.
    pub(super) fn provided(&mut self) {
        let providers = self.zones.iter().map(|double| &double.provider);
        let (mut calls, mut made, mut provided) = (0, 0, Vec::new());
        for provider in providers {
            calls += provider.calls;
            made += provider.created.len();
            provided.extend(provider.created.iter().cloned());
        }
        (self.volumes.calls, self.volumes.made) = (calls, made);
        self.volumes.provided = provided;
    }
}
