//! [`plan`] turns one observation into a [`Plan`] for the survey.
//!
//! - ADVISORY: enrollment steps carry the `Target` of the observed shard record. A release names its shard, and
//!   `Reconciler::release` reads the census, then the shard record, then the active volume's record, and drops the
//!   entry only when `Census::released` returns `Some(next)`.
//!   The census must list the same entry the plan judged and the release step carries.
//! - UNKNOWN-BLOCKS: `Zone::choose` considers only `Live` candidates whose host differs from `record.owner`. A
//!   standby need whose owner reads other than live gives `OwnerNotReady`, and a named standby or slot incumbent that
//!   reads unknown or in conflict gives `LossUnconfirmed`; neither plans a step.
//! - QUORUM-PREMISE: a shard whose owner reads `Lost` while its named standby's possible probers (the hosts outside
//!   the owner's partition, other than the owner and the standby, that do not read `Lost`, or are retired and not
//!   shown down by their evidence apart from the retirement) span fewer than [`QUORUM_MIN`] partitions carries
//!   `Blocker::QuorumUnreachable` (`Zone::quorum_unreachable`) in state `Protected`. The blocker names the condition
//!   and plans no step.
//! - HELD-RESTART: a shard whose owner's live report holds a held restart's diagnostic entry at the record's tenure or
//!   one attempt below it (`ShardRecords::held`) carries `Blocker::RestartHeld` as its host-side blocker, ahead of the
//!   owner entry's holds, with QUORUM-PREMISE's blockers first. The match is diagnostic evidence only: it inhibits no
//!   enrollment, no takeover and no other step, and orders no rerun; `device_hold` reads the entry as no device hold.
//! - ATTACH-EVIDENCE: host evidence and the active volume's record determine standby need. `Zone::protected` requires
//!   a live attach between the named standby and the active volume. A named standby whose attach of the active
//!   volume is ended and not yet gone loses its census slot to another candidate regardless of its host evidence;
//!   one whose entry is gone or absent keeps its slot and takes a new attach entry.
//! - ONE-CANDIDATE-PER-SLOT: a census slot keeps its host until that host reads `Lost`, the shard record names it
//!   owner, or ATTACH-EVIDENCE moves the slot (see ONE-HOST-PER-SLOT in `failover::standbys`). `plan` emits
//!   `Release` for a slot at a stale target whose host is the owner, reads `Lost` or holds an ended attach of the
//!   active volume.
//! - DEVICE-HOLD: `Zone::choose` excludes a host whose report shows a device-failure hold on the shard's active
//!   volume. A census slot at the record's target that names such a host keeps its in-flight unit, and
//!   `Zone::enroll` withholds the step for that census slot. Under SLOT-HOST, such a host with no live attach that
//!   displaces a live named standby holds no in-flight unit while the hold stands.
//! - HOST-SHARE: `Zone::admit` takes new starts in queue order and checks each host's limits and attachment
//!   headroom against the census plus the reservations it admitted before.
//! - DIRECTORY-SCOPE: only directory-listed shards contribute to `inflight`. A census entry of any other shard
//!   counts toward `Roles::named` for the host it names.
//! - ORDER: in-flight steps, fresh need first, by shard; then the `End` and `Detach` steps by shard; then the
//!   `ReleaseAttach` steps by shard, so each follows every `Attach` and `Detach` of the plan and the listings they
//!   read; then new reservations, fresh first, then oldest exposure, then the owner with the most shards lacking a
//!   live named standby, then shard; then releases by shard.
//! - FRESH-FIRST: `admit` counts a `Need::Fresh` start of a shard with no census entry as refused when the census
//!   alone stops it: its candidate passes the tick's tally, the holds and the start window. It judges these starts
//!   after the tick's other fresh starts, when the places the tick can free are known: the entries
//!   `Zone::releasing` drops whose shard no fresh start reserved, less the `e` entries above the cap. The first
//!   counted starts, one for each such place, keep that host's role and attachment, their start credit and an
//!   in-flight unit from the later starts of the tick; a counted start past them leaves all three to the later
//!   starts. A tick that counts `n` such starts, finds `e` entries above the cap and plans `r` releases withholds the
//!   reservation of up to `n + e - r` shards, by shard, whose `Need::Standby` start the tick reserves on an entry
//!   that `Zone::releasing` drops: [`Census::releases`] under the survey's loss evidence, which holds when the record
//!   names no standby, holds another target, and the entry's host is the owner, reads `Lost`, or has an ended attach
//!   of the active volume and no live one. Each such shard keeps its `Enrolling` state, reads `CensusFull`, and
//!   takes its release in place of its reservation; ordinary admission admits the fresh need on a later tick. The
//!   withheld reservation's tally, start credit and in-flight unit stay counted for the rest of the tick. An entry
//!   whose record names a standby stays listed, and a tick that counts no fresh start keeps the order above. The
//!   precedence covers the re-reservations this loop would make on the tick it counts the fresh need; a reservation
//!   already written stays, whoever wrote it. A fresh need that appears after another shard's re-reservation was
//!   written, or whose owner a loop does not yet read lost (a second loop whose view lags, or this loop after a
//!   restart, until its silence window passes), stays refused `CensusFull` while that reservation stands, until an
//!   entry becomes releasable or the cap rises.
//! - SLOT-HOST: the census entry selects the enrollment candidate, and the shard record names the standby authorized
//!   to take over. When the record names a live, attached standby S and the shard's entry names another host X than
//!   the owner, at the record's generation and owner and at its attempt or an earlier one, the shard needs a standby
//!   and does not read `Protected`. While X is not failed (`Zone::slot_failed`, or an attach of X the plan ends this
//!   tick), the plan resumes X's enrollment: a re-reservation of X at the record's target where the entry holds an
//!   earlier attempt, then attach, enrollment and `Designate` of X over S, each step only while `Zone::choose`
//!   accepts X alone; otherwise the shard carries the blocker `choose` returns, and an entry of X with no live attach
//!   holds no in-flight unit. `Zone::crowded` frees a full volume's reclaimable attach for X only when `choose`
//!   accepts X with a new attach on the freed volume. Once X is failed, the plan selects S alone for the entry.
//!   S stays named, with its takeover authority, until X's designation wins the shard record's exact-version write.
//!   When `Zone::protected` returns true for a displaced shard, its exposure clock stays closed and the start order
//!   counts it among its owner's shards with a live named standby.
//! - REPLACE: one `Replace` per shard that reads `Replacing` or `ReplacementHeld` with no held receipt, in shard
//!   order after the releases. Each unheld receipt of a later generation at an issued or created attempt holds one
//!   of `replacements_inflight_max` units, also when a release puts the count above the limit; an open receipt over
//!   a loss `complete_loss` admits and a new start take a free unit; an open receipt over any other reading gets its
//!   step with no unit, as does an open receipt above `create_attempts_max`, whose step raises its alarm and calls
//!   no provider; and the hold's start or latch takes none. A created replacement's host is the one its record's attach event names,
//!   else the live owner with attachment and recovery headroom, else the active, live, reporting host of fewest roles
//!   below `host_roles_max` with that headroom, a standby role a shard record names with no census entry counted, and
//!   the plan's reservations and earlier replacement hosts charged to the same tally. A host a pending replacement's
//!   attach event names holds a role until the flip names it owner.
//! - LOSS-NEEDS-EVIDENCE, CORRELATED-HOLD: for a shard with no retirement request and no receipt of a later
//!   generation (ONE-STATE in `zone_loop::status` orders those first), `Zone::assess` passes a lost active volume to
//!   `loss::decide` only once the loss is decided, and reads `LossUnconfirmed` before. A loss beside another
//!   impaired or lost volume of the zone is confirmed by `VolumeJudgement::confirmed`, whether or not this tick's
//!   view is complete, while this view still counts another impaired or lost volume and the same active volume
//!   still reads lost; a volume the tick could not judge leaves the view incomplete and adds nothing to the count.
//!   It then reads `ReplacementHeld`. An isolated loss is decided when the view is complete, no shard is unread, and the
//!   shard's `VolumeJudgement::streak` is at least `loss_run(loss_ticks)`; it then reads `Replacing` at `Open`. A
//!   decided loss of either kind reads `ReplacementExhausted` when no later generation remains. Each tick decides
//!   from its own count: a tick that counts no other impaired volume takes the isolated rule, so a confirmed loss
//!   whose only impaired neighbor reads unvalued on a tick reads `LossUnconfirmed` on that tick, and the hold
//!   returns on the next tick that counts the neighbor impaired. A hold that outlasts the count is the held
//!   receipt's, which ONE-STATE reads first.
//! - HOLDS: the operator hold withholds `RecordAttach`, `Attach` and reservations that need a new attach; the zone
//!   host hold withholds `RecordAttach` and those reservations. Under either hold a `Replace` runs only when its one
//!   write is the correlated hold: the start of a held receipt or the latch. A survey whose directory read fails or is refused
//!   reports the operator hold of the last admitted directory.

use core::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};

use crate::failover::arbiter::QUORUM_MIN;
use crate::failover::attachments::InstanceId;
use crate::failover::loss::{self, Decision, Health, Phase, Receipt};
use crate::failover::reconcile::{end_ready, relist_ready, reservable};
use crate::failover::records::{
    EventKind, Host, MAX_ATTACHED, MIN_ERA, RecordedPair, ShardRecord, VolumeId, VolumeRecord,
};
use crate::failover::report::{
    Gauge, Health as HostHealth, HostReport, Phase as OwnerPhase, RecoveryCheck, RecoveryKind,
    VolumeEntry, Withdrawal,
};
use crate::failover::retire::Target;
use crate::failover::serving::State as ServingState;
use crate::failover::standbys::{self, Attach, Census, Closed, Need, lists_standby, room};
use crate::failover::zone_loop::ZoneLoop;
use crate::failover::zone_loop::config::ZoneBounds;
use crate::failover::zone_loop::directory::{
    Directory, DirectoryState, ReconcilerProjection, ShardEntry,
};
use crate::failover::zone_loop::evidence::{HostEvidence, VolumeJudgement, loss_run};
use crate::failover::zone_loop::observe::{
    Completeness, HostView, Observation, ShardRecords, ShardView, Source, ZoneView,
};
use crate::failover::zone_loop::sources::{
    InstanceSource, ReportSource, Unreachable, VolumeSource,
};
use crate::failover::zone_loop::status::{
    Blocker, EnrollPhase, Exposure, Holds, ShardState, ShardStatus, VerdictCounts, ZoneStatus,
};
use crate::net::ownership::Shard;
use crate::storage::store::{Store, StoreError, WatermarkLog};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Reserve {
        shard: Shard,
        host: Host,
        target: Target,
    },
    RecordAttach {
        shard: Shard,
        host: Host,
        target: Target,
    },
    Attach {
        shard: Shard,
        host: Host,
        target: Target,
    },
    Designate {
        shard: Shard,
        host: Host,
        target: Target,
    },
    /// `host` and `target` are those of the census entry the plan judged, and `target` differs from the record's.
    Release {
        shard: Shard,
        host: Host,
        target: Target,
    },
    End {
        shard: Shard,
        host: Host,
    },
    Detach {
        shard: Shard,
        host: Host,
    },
    ReleaseAttach {
        shard: Shard,
        host: Host,
    },
    /// One effect of the replacement of the shard's lost active volume at `target`. `host` is `None` until the
    /// receipt records a created volume; from then on it is the host that volume's attach event names, else the
    /// host the plan chose to attach it, else `None` when no host qualifies.
    Replace {
        shard: Shard,
        target: Target,
        host: Option<Host>,
    },
}

impl Step {
    pub fn shard(&self) -> Shard {
        match *self {
            Self::Reserve { shard, .. }
            | Self::RecordAttach { shard, .. }
            | Self::Attach { shard, .. }
            | Self::Designate { shard, .. }
            | Self::Release { shard, .. }
            | Self::End { shard, .. }
            | Self::Detach { shard, .. }
            | Self::ReleaseAttach { shard, .. }
            | Self::Replace { shard, .. } => shard,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShardPlan {
    pub shard: Shard,
    pub state: ShardState,
    pub blocker: Option<Blocker>,
    pub target: Option<Target>,
    /// The exposure clock and the start order's per-owner count use the result of `Zone::protected`.
    pub protected: bool,
    /// For a shard in [`ShardState::Closed`] because its active volume admits no attach of the host the plan judged,
    /// the bound [`Closed::of`] names for that host: the slot host's, or the lowest-numbered candidate's when no
    /// candidate's attach is open. `None` for every other state and for a volume no census reservation accepts.
    pub closed: Option<Closed>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub steps: Vec<Step>,
    pub shards: Vec<ShardPlan>,
    pub holds: Holds,
    pub inflight: usize,
    pub starts: Vec<(Shard, Host, VolumeId)>,
}

pub struct Context<'a> {
    pub bounds: &'a ZoneBounds,
    pub now_us: u64,
    pub warming: bool,
    pub starts: &'a BTreeMap<(Shard, Host, VolumeId), u64>,
    pub exposure: &'a Exposure,
    pub stuck: &'a BTreeSet<(VolumeId, u32)>,
}

#[derive(Clone, Copy)]
struct Start<'a> {
    need: Need,
    incumbent: Option<Host>,
    records: &'a ShardRecords,
}

enum Work<'a> {
    Idle,
    InFlight(Need, Step),
    Start(Start<'a>),
}

/// A recorded-holder hold: a withdrawal for a recorded holder, or a held restart refused `recorded-holder`. A held
/// attempt of kind `lineage` refused `recorded-holder` failed a device command of the lineage arm, which is a device
/// hold.
fn recorded_holder(entry: &VolumeEntry) -> bool {
    withdrawn(entry.withdrawal) == Withdrawn::RecordedHolder
        || (entry.phase == Some(OwnerPhase::Held)
            && entry.recovery.check == Some(RecoveryCheck::RecordedHolder)
            && entry.recovery.kind != Some(RecoveryKind::Lineage))
}

/// What an owner entry's withdrawal label says about its hold: a recorded holder, a question of records with no
/// device in it (nobody holding, or a lapsed deferral's unverified registrant), or neither.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Withdrawn {
    RecordedHolder,
    Records,
    Other,
}

/// The reading of every withdrawal label, with no wildcard arm, so a new label compiles only with a reading.
fn withdrawn(withdrawal: Option<Withdrawal>) -> Withdrawn {
    use Withdrawal as W;
    #[cfg(test)]
    if withdrawal == Some(W::Unverified) && unverified_plant::AS_DEVICE.get() {
        return Withdrawn::Other;
    }
    match withdrawal {
        Some(W::RecordedHolder) => Withdrawn::RecordedHolder,
        Some(W::Unheld | W::Unverified) => Withdrawn::Records,
        None
        | Some(
            W::Report
            | W::Conflict
            | W::PreemptAborted
            | W::ForceDetach
            | W::Attachment
            | W::Modification
            | W::RestartCheck
            | W::ActivationRecord
            | W::Exhausted
            | W::Planned
            | W::Flipped
            | W::NewerFence
            | W::LaterTenure
            | W::Regression,
        ) => Withdrawn::Other,
    }
}

/// When `AS_DEVICE` is true, an entry with `OwnerPhase::Held` and `Withdrawal::Unverified` blocks its shard with
/// `Blocker::DeviceFailureHold`.
#[cfg(test)]
mod unverified_plant {
    thread_local! {
        pub(crate) static AS_DEVICE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }
}

#[cfg(test)]
pub(crate) use unverified_plant::AS_DEVICE as UNVERIFIED_AS_DEVICE;

#[cfg(test)]
thread_local! {
    /// When true, QUORUM-PREMISE counts hosts that read `Lost` among the possible probers.
    pub(crate) static LOST_PROBERS_COUNTED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// When true, QUORUM-PREMISE reads a retired host read `Lost` as silent while [`HostView::down`] is false.
    pub(crate) static RUNNING_RETIRED_SILENT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// A held entry with a device in it. A held restart's diagnostic entry ([`VolumeEntry::held_restart`]) is none: its
/// bump is a store write after Report #1 completed, so its fencer holds no device command.
pub(super) fn device_hold(entry: &VolumeEntry) -> bool {
    let unheld = withdrawn(entry.withdrawal) == Withdrawn::Records
        || entry.recovery.check == Some(RecoveryCheck::Unheld);
    entry.phase == Some(OwnerPhase::Held)
        && !recorded_holder(entry)
        && !unheld
        && !entry.held_restart()
}

fn serving(entry: &VolumeEntry) -> bool {
    entry.phase == Some(OwnerPhase::Serving)
        || (entry.phase.is_none()
            && entry.serving == Some(ServingState::Serving)
            && !entry.withheld)
}

fn reclaimable(record: &ShardRecord, host: Host) -> bool {
    record.attempts > 0 && host != record.owner && record.standby != Some(host)
}

pub(super) fn unreleased(volume: &VolumeRecord, host: Host) -> bool {
    volume
        .latest(host)
        .is_some_and(|(_, event)| event.kind == EventKind::Ended)
}

pub(super) fn displaced(
    records: &ShardRecords,
    slot: Option<standbys::Entry>,
    live: impl Fn(Host) -> bool,
) -> Option<Host> {
    let record = &records.record;
    let standby = record.standby?;
    let slot = slot?;
    let other = slot.host != standby && slot.host != record.owner;
    let tenure = slot.target.generation == record.generation
        && slot.target.owner == record.owner
        && slot.target.attempts <= record.attempts;
    let named = || live(standby) && records.active.live(standby).is_some();
    (other && tenure && named()).then_some(slot.host)
}

fn free(gauge: Gauge) -> u64 {
    match gauge {
        Gauge::Known { used, limit } => limit.get().saturating_sub(used),
        Gauge::Unavailable => 0,
    }
}

#[derive(Clone, Copy, Default)]
struct Roles {
    named: usize,
    owned: usize,
    designated: usize,
}

#[derive(Default)]
struct Tally {
    named: BTreeMap<Host, usize>,
    owed: BTreeMap<Host, u64>,
    added: usize,
}

impl Tally {
    fn named(&self, host: Host) -> usize {
        self.named.get(&host).copied().unwrap_or_default()
    }

    fn owed(&self, host: Host) -> u64 {
        self.owed.get(&host).copied().unwrap_or_default()
    }
}

struct Zone<'a> {
    view: &'a ZoneView,
    census: &'a Census,
    bounds: &'a ZoneBounds,
    hosts: BTreeMap<Host, &'a HostView>,
    roles: BTreeMap<Host, Roles>,
    /// The shards whose record names a standby that their census entry does not name, with that standby.
    designations: BTreeSet<(Shard, Host)>,
    unread: usize,
    stuck: &'a BTreeSet<(VolumeId, u32)>,
}

impl<'a> Zone<'a> {
    fn new(view: &'a ZoneView, census: &'a Census, context: &Context<'a>) -> Self {
        let bounds = context.bounds;
        let mut roles: BTreeMap<Host, Roles> = BTreeMap::new();
        for (_, entry) in census.entries() {
            roles.entry(entry.host).or_default().named += 1;
        }
        let mut designations = BTreeSet::new();
        let mut unread = 0;
        for shard in &view.shards {
            unread += usize::from(shard.unread(census));
            let Ok(Some(records)) = &shard.records else {
                continue;
            };
            let record = &records.record;
            roles.entry(record.owner).or_default().owned += 1;
            let slot = census.slot(record.shard).map(|slot| slot.host);
            if let Some(standby) = record.standby.filter(|&standby| slot != Some(standby)) {
                roles.entry(standby).or_default().designated += 1;
                designations.insert((record.shard, standby));
            }
            if let Some(host) = attacher(records).filter(|&host| host != record.owner) {
                roles.entry(host).or_default().designated += 1;
            }
        }
        let hosts = (view.hosts.iter())
            .map(|host| (host.entry.host, host))
            .collect();
        Self {
            view,
            census,
            bounds,
            hosts,
            roles,
            designations,
            unread,
            stuck: context.stuck,
        }
    }

    fn verdict(&self, host: Host) -> HostEvidence {
        self.hosts
            .get(&host)
            .map_or(HostEvidence::Unknown, |view| view.verdict)
    }

    fn lost(&self, host: Host) -> bool {
        self.verdict(host) == HostEvidence::Lost
    }

    fn unconfirmed(&self, record: &ShardRecord, host: Host) -> bool {
        let verdict = self.verdict(host);
        host != record.owner && matches!(verdict, HostEvidence::Unknown | HostEvidence::Conflict)
    }

    fn cap(&self) -> usize {
        self.bounds.config().population_cap
    }

    fn roles(&self, host: Host, shard: Shard) -> Roles {
        let mut roles = self.roles.get(&host).copied().unwrap_or_default();
        if self
            .census
            .slot(shard)
            .is_some_and(|slot| slot.host == host)
        {
            roles.named -= 1;
        }
        if self.designations.contains(&(shard, host)) {
            roles.designated -= 1;
        }
        roles
    }

    fn fits(&self, host: Host, shard: Shard, tally: &Tally) -> bool {
        let config = self.bounds.config();
        let roles_max = self.view.directory.host_roles_max().get() as usize;
        let roles = self.roles(host, shard);
        let named = roles.named + tally.named(host);
        named < config.standbys_per_host_max as usize
            && named + roles.owned + roles.designated + self.unread < roles_max
    }

    fn headroom(&self, view: &HostView, shard: Shard, attach: Attach, tally: &Tally) -> bool {
        let Some(report) = view.report.as_ref() else {
            return false;
        };
        let headroom = report.host.headroom;
        let owed = || {
            (self
                .census
                .pending(shard, report, |held| self.view.active(held)))
            .saturating_add(tally.owed(view.entry.host))
        };
        let attaches = || room(headroom.attachments, 0) && room(headroom.attachments, owed());
        room(headroom.recovery, 0) && (attach == Attach::Live || attaches())
    }

    fn listed(&self, records: &ShardRecords, host: Host) -> Option<bool> {
        let instance = self.view.directory.host(host)?.instance;
        self.shows(records, instance)
    }

    fn shows(&self, records: &ShardRecords, instance: InstanceId) -> Option<bool> {
        let ids = self.view.listing(records.record.active)?;
        Some(ids.iter().any(|id| id == instance.as_str()))
    }

    /// Whether `view`'s host can take a new attach entry: its report's era is `MIN_ERA` or later and `listing`, the
    /// active volume's readable listing, omits its directory instance.
    fn opens(&self, view: &HostView, listing: Option<&[String]>) -> bool {
        let era = view.report.as_ref().map(|report| report.host.build.era);
        let instance = self
            .view
            .directory
            .host(view.entry.host)
            .map(|entry| entry.instance);
        let unlisted = listing
            .zip(instance)
            .is_some_and(|(ids, instance)| ids.iter().all(|id| id != instance.as_str()));
        era.is_none_or(|era| era >= MIN_ERA) && unlisted
    }

    fn protected(&self, records: &ShardRecords) -> bool {
        let standby = records.record.standby;
        standby.is_some_and(|standby| {
            self.verdict(standby) == HostEvidence::Live
                && !standbys::standby_ended(&records.record, &records.active, standby)
        }) && !self.reenrolling(records)
    }

    /// SLOT-HOST: the host of the shard's census entry when the record names a live standby with a live attach of
    /// the active volume, the entry names another host than that standby and the owner, and the entry's target holds
    /// the record's generation and owner at the record's attempt or an earlier one, which an owner bump leaves.
    fn displaced(&self, records: &ShardRecords) -> Option<Host> {
        let slot = self.census.slot(records.record.shard);
        displaced(records, slot, |host| {
            self.verdict(host) == HostEvidence::Live
        })
    }

    /// When `reenrolling` is true, the shard still needs `Need::Standby` even if `standbys::need_of` returns `None`.
    /// The standby's slot qualifies even when its target differs from the record's target.
    fn reenrolling(&self, records: &ShardRecords) -> bool {
        let record = &records.record;
        let slot = self.census.slot(record.shard);
        record.standby.is_some_and(|standby| {
            records.active.live(standby).is_some()
                && records.active.enrolled(standby).is_none()
                && slot.is_some_and(|slot| slot.host == standby)
        })
    }

    fn retiring(&self, host: Host) -> bool {
        let entry = self.view.directory.host(host);
        entry.is_some_and(|entry| entry.state != DirectoryState::Active)
    }

    fn slot_failed(&self, volume: &VolumeRecord, host: Host) -> bool {
        self.lost(host)
            || unreleased(volume, host)
            || (volume.live(host).is_none() && self.retiring(host))
    }

    fn holds_slot(&self, records: &ShardRecords) -> bool {
        let record = &records.record;
        self.census.slot(record.shard).is_some_and(|slot| {
            slot.target == Target::of(record)
                && !self.slot_failed(&records.active, slot.host)
                && record.standby != Some(slot.host)
                && !self.stalled(records)
        })
    }

    /// SLOT-HOST: a displaced shard whose entry host holds no live attach and that `choose` refuses holds no
    /// in-flight unit, so its refusal leaves the unit to other starts.
    fn stalled(&self, records: &ShardRecords) -> bool {
        self.displaced(records).is_some_and(|host| {
            records.active.live(host).is_none()
                && !self.slot_failed(&records.active, host)
                && (self.choose(records, Need::Standby, Some(host), &Tally::default())).is_err()
        })
    }

    fn owner_entry(records: &ShardRecords) -> Option<&VolumeEntry> {
        let record = &records.record;
        let owned = |(host, entry): &&(Host, VolumeEntry)| {
            *host == record.owner && entry.volume == record.active
        };
        records.entries.iter().find(owned).map(|(_, entry)| entry)
    }

    /// The host-side blocker: `RestartHeld` for a HELD-RESTART-MATCH, then the owner entry's recorded-holder or
    /// device hold, then the named standby's `SelfSuspect`.
    fn host_side(&self, records: &ShardRecords, owner: Option<&VolumeEntry>) -> Option<Blocker> {
        if records.held.is_some() {
            return Some(Blocker::RestartHeld);
        }
        let owner_side = owner.and_then(|entry| {
            if recorded_holder(entry) {
                Some(Blocker::RecordedHolderHold)
            } else {
                device_hold(entry).then_some(Blocker::DeviceFailureHold)
            }
        });
        owner_side.or(self.standby_side(records))
    }

    /// The named standby's host-side blocker: `SelfSuspect` while its fresh report shows a self-suspicion dwell and
    /// the owner reads other than live or reports itself unhealthy.
    fn standby_side(&self, records: &ShardRecords) -> Option<Blocker> {
        let record = &records.record;
        let standby = record.standby.and_then(|standby| self.hosts.get(&standby));
        let live = standby.filter(|view| view.verdict == HostEvidence::Live);
        let report = live.and_then(|view| view.report.as_ref());
        let suspecting = report.and_then(|report| report.host.detector.self_suspect_us);
        let owner = self.hosts.get(&record.owner);
        let unhealthy = (owner.and_then(|view| view.report.as_ref()))
            .is_some_and(|report| report.host.health == Some(HostHealth::Unhealthy));
        let takes_over = self.verdict(record.owner) != HostEvidence::Live || unhealthy;
        (takes_over && suspecting.is_some_and(|left| left > 0)).then_some(Blocker::SelfSuspect)
    }

    /// QUORUM-PREMISE: true when the record's owner reads `Lost` and its named standby's possible probers span
    /// fewer than [`QUORUM_MIN`] partitions. A possible prober is a host of this zone's directory view outside the
    /// owner's partition, other than the owner and the standby, that is no silent host: a host read `Lost` is silent
    /// unless it is retired and [`HostView::down`] is false: its instance is listed short of ended or stopped for
    /// its dwell, or absent from fewer than `absent_ticks` listings, and its checks and report fall short of the
    /// impairment and silence that read an active host `Lost`. A retirement is a directory state, and a retired
    /// host's agent can still answer probes while its instance runs. A tick with no instance evidence reads the
    /// standby unknown, so its shard is not `Protected` and does not reach this premise. That set holds every host
    /// the standby's agent can draw probers from (`host::agent`) when the agent's
    /// synced placement is the zone's directory and a silent host answers no new probe; the loop reads neither the
    /// configured quorum `k`, the agent's probe keys, its accepted placement nor the votes it already holds. Every
    /// valid quorum counts at least [`QUORUM_MIN`] partitions, so a true result shows that the standby can gather
    /// fresh replies from fewer partitions than any quorum counts, and a nomination can form only from votes it
    /// already holds within their lifetime; a false result shows no quorum. An owner the view does not list gives
    /// false.
    fn quorum_unreachable(&self, record: &ShardRecord) -> bool {
        let (Some(standby), Some(owner)) = (record.standby, self.hosts.get(&record.owner)) else {
            return false;
        };
        if owner.verdict != HostEvidence::Lost {
            return false;
        }
        #[cfg(test)]
        let (counted, retired_silent) = (LOST_PROBERS_COUNTED.get(), RUNNING_RETIRED_SILENT.get());
        #[cfg(not(test))]
        let (counted, retired_silent) = (false, false);
        let owner_partition = owner.entry.placement.partition;
        let mut seen = [None; QUORUM_MIN];
        let mut distinct = 0;
        for view in &self.view.hosts {
            let host = view.entry.host;
            let partition = view.entry.placement.partition;
            let retired_prober = view.entry.state == DirectoryState::Retired && !view.down;
            let silent = view.verdict == HostEvidence::Lost && !(retired_prober && !retired_silent);
            let prober = host != record.owner
                && host != standby
                && (!silent || counted)
                && partition != owner_partition;
            if prober && !seen[..distinct].contains(&Some(partition)) {
                seen[distinct] = Some(partition);
                distinct += 1;
                if distinct == QUORUM_MIN {
                    return false;
                }
            }
        }
        true
    }

    /// The blocker of a `Protected` shard: under QUORUM-PREMISE the standby's own `SelfSuspect`, else
    /// `QuorumUnreachable`, so a lost owner's last held entry gives no label; otherwise the host-side blocker.
    fn protected_blocker(
        &self,
        records: &ShardRecords,
        host_side: Option<Blocker>,
    ) -> Option<Blocker> {
        match self.quorum_unreachable(&records.record) {
            true => self
                .standby_side(records)
                .or(Some(Blocker::QuorumUnreachable)),
            false => host_side,
        }
    }

    /// DEVICE-HOLD-GUARD: true while another attached host reports the device-failure hold for the shard's active
    /// volume and the owner's entry is absent, has a device hold, or is non-serving with phase `None`, `Starting`,
    /// or `Recovering`. A lost predecessor's device hold blocks standby reservation when the owner also has a device
    /// hold.
    fn device_guard(&self, records: &ShardRecords, owner: Option<&VolumeEntry>) -> bool {
        let record = &records.record;
        let unresolved = owner.is_none_or(|entry| {
            let early = matches!(
                entry.phase,
                None | Some(OwnerPhase::Starting | OwnerPhase::Recovering)
            );
            device_hold(entry) || (early && !serving(entry))
        });
        let attached = records.active.live_hosts();
        let mut others = attached.filter(|&host| host != record.owner);
        unresolved && others.any(|host| self.holds_device(host, records))
    }

    /// Whether `host`'s last accepted report holds the device-failure hold on `records`' shard and active volume.
    fn holds_device(&self, host: Host, records: &ShardRecords) -> bool {
        let record = &records.record;
        let report = self.hosts.get(&host).and_then(|view| view.report.as_ref());
        let mut entries = report.into_iter().flat_map(|report| report.entries.iter());
        entries.any(|entry| {
            entry.shard == record.shard && entry.volume == record.active && device_hold(entry)
        })
    }

    fn assess(&self, records: &'a ShardRecords, ends: &[Host]) -> (ShardPlan, Work<'a>) {
        let record = &records.record;
        let shard = record.shard;
        let target = self.census.slot(shard).map(|slot| slot.target);
        let protected = self.protected(records);
        let done = |state, blocker| {
            let plan = ShardPlan {
                shard,
                state,
                blocker,
                target,
                protected,
                closed: None,
            };
            (plan, Work::Idle)
        };
        let owner = Self::owner_entry(records);
        if owner.is_some_and(|entry| entry.flip) {
            return done(
                ShardState::RetirementRequested,
                Some(Blocker::RetirementRequested),
            );
        }
        if let Some(receipt) = pending(records) {
            return match receipt.held {
                true => done(ShardState::ReplacementHeld, Some(Blocker::CorrelatedHold)),
                false => done(
                    ShardState::Replacing {
                        phase: receipt.phase,
                    },
                    None,
                ),
            };
        }
        let judged = records.judgement;
        let decidable = match judged.others {
            0 => {
                let run = loss_run(self.bounds.config().loss_ticks);
                complete_loss(&judged, run) && self.unread == 0
            }
            _ => judged.confirmed,
        };
        match judged.health {
            Some(Health::Lost) if !decidable => {
                return done(ShardState::LossUnconfirmed, Some(Blocker::LossUnconfirmed));
            }
            Some(Health::Lost) => {
                match loss::decide(record, (record.active, Health::Lost), judged.others) {
                    Decision::Provision(_) => {
                        return done(ShardState::Replacing { phase: Phase::Open }, None);
                    }
                    Decision::Hold(Some(_)) => {
                        return done(ShardState::ReplacementHeld, Some(Blocker::CorrelatedHold));
                    }
                    Decision::Hold(None) => {
                        let blocker = Some(Blocker::ReplacementExhausted);
                        return done(ShardState::ReplacementExhausted, blocker);
                    }
                    Decision::Retain => {}
                }
            }
            Some(Health::Impaired) => {
                return done(ShardState::VolumeImpaired, Some(Blocker::VolumeImpaired));
            }
            Some(Health::Available) | None => {}
        }
        if record.attempts == 0 {
            return done(ShardState::Initial, None);
        }
        let host_side = self.host_side(records, owner);
        let need = match standbys::need_of(record, &records.active, |host| self.lost(host)) {
            Some(need) => need,
            None if self.reenrolling(records) || self.displaced(records).is_some() => Need::Standby,
            None => {
                return match protected {
                    true => done(
                        ShardState::Protected,
                        self.protected_blocker(records, host_side),
                    ),
                    false => done(ShardState::StandbyUnknown, Some(Blocker::LossUnconfirmed)),
                };
            }
        };
        if need == Need::Standby && self.verdict(record.owner) != HostEvidence::Live {
            return done(ShardState::OwnerUnknown, Some(Blocker::OwnerNotReady));
        }
        if need == Need::Standby && self.device_guard(records, owner) {
            return done(ShardState::NoCandidate, Some(Blocker::DeviceFailureHold));
        }
        let (state, blocker, work, closed) = match self.enroll(records, need, ends) {
            (state, blocker, Work::InFlight(..) | Work::Start(_), closed)
                if judged.health.is_none() =>
            {
                let blocker = blocker.or(Some(Blocker::ControlPlaneUnavailable));
                (state, blocker, Work::Idle, closed)
            }
            enrolled => enrolled,
        };
        let plan = ShardPlan {
            shard,
            state,
            blocker: blocker.or(host_side),
            target,
            protected,
            closed,
        };
        (plan, work)
    }

    fn enroll(
        &self,
        records: &'a ShardRecords,
        need: Need,
        ends: &[Host],
    ) -> (ShardState, Option<Blocker>, Work<'a>, Option<Closed>) {
        let record = &records.record;
        let shard = record.shard;
        let volume = &records.active;
        let target = Target::of(record);
        let blocked = |state, blocker| (state, Some(blocker), Work::Idle, None);
        let slot = self.census.slot(shard);
        let failed = |host| self.slot_failed(volume, host) || ends.contains(&host);
        let displaced = self.displaced(records);
        // SLOT-HOST: a failed entry host yields its entry to the named standby alone.
        let incumbent = (slot.map(|slot| slot.host))
            .filter(|&host| host != record.owner && !failed(host))
            .or_else(|| displaced.and(record.standby));
        if incumbent.is_some_and(|host| self.unconfirmed(record, host)) {
            return blocked(ShardState::NoCandidate, Blocker::LossUnconfirmed);
        }
        if slot.is_none() && self.census.len() >= self.cap() {
            let queued = need == Need::Fresh
                && reservable(volume)
                && self
                    .choose(records, need, incumbent, &Tally::default())
                    .is_ok();
            let start = Start {
                need,
                incumbent,
                records,
            };
            // `admit` refuses this start at the census check and counts it for FRESH-FIRST; it reserves nothing.
            let work = if queued {
                Work::Start(start)
            } else {
                Work::Idle
            };
            return (
                ShardState::NoCandidate,
                Some(Blocker::CensusFull),
                work,
                None,
            );
        }
        if !reservable(volume) {
            return blocked(ShardState::Closed, Blocker::AttachClosed);
        }
        if let Some(slot) = slot.filter(|slot| slot.target == target && !failed(slot.host)) {
            let host = slot.host;
            let (phase, blocker, step) = if volume.enrolled(host).is_some() {
                let step = Step::Designate {
                    shard,
                    host,
                    target,
                };
                (EnrollPhase::Enrolled, None, Some(step))
            } else if let Some(bound) = Closed::of(volume, host, self.bounds.bounds()) {
                let blocker = Some(Blocker::AttachClosed);
                return (ShardState::Closed, blocker, Work::Idle, Some(bound));
            } else if volume.live(host).is_some() {
                match self.listed(records, host) {
                    None => (
                        EnrollPhase::Recorded,
                        Some(Blocker::ControlPlaneUnavailable),
                        None,
                    ),
                    Some(true) => (EnrollPhase::Attached, None, None),
                    Some(false) => {
                        let step = Step::Attach {
                            shard,
                            host,
                            target,
                        };
                        (EnrollPhase::Recorded, None, Some(step))
                    }
                }
            } else if self.listed(records, host).is_none() {
                let blocker = Some(Blocker::ControlPlaneUnavailable);
                (EnrollPhase::Reserved, blocker, None)
            } else {
                let step = Step::RecordAttach {
                    shard,
                    host,
                    target,
                };
                (EnrollPhase::Reserved, None, Some(step))
            };
            let held = self.holds_device(host, records);
            // SLOT-HOST: an entry host that replaces the named standby takes each step only while `choose` accepts it.
            let refused = displaced
                .filter(|&named| named == host)
                .and_then(|_| {
                    self.choose(records, need, Some(host), &Tally::default())
                        .err()
                })
                .map(|(_, blocker, _)| blocker);
            let blocker = blocker
                .or(held.then_some(Blocker::DeviceFailureHold))
                .or(refused);
            let step = step.filter(|_| !held && refused.is_none());
            let work = step.map_or(Work::Idle, |step| Work::InFlight(need, step));
            return (
                ShardState::Enrolling { need, phase, host },
                blocker,
                work,
                None,
            );
        }
        match self.choose(records, need, incumbent, &Tally::default()) {
            Ok((host, _)) => {
                let phase = EnrollPhase::Unreserved;
                let start = Start {
                    need,
                    incumbent,
                    records,
                };
                let state = ShardState::Enrolling { need, phase, host };
                (state, None, Work::Start(start), None)
            }
            Err((state, blocker, bound)) => (state, Some(blocker), Work::Idle, bound),
        }
    }

    fn choose(
        &self,
        records: &ShardRecords,
        need: Need,
        fixed: Option<Host>,
        tally: &Tally,
    ) -> Result<(Host, Attach), (ShardState, Blocker, Option<Closed>)> {
        let record = &records.record;
        let shard = record.shard;
        let none = |blocker| (ShardState::NoCandidate, blocker, None);
        let mut hosts: Vec<&HostView> = (self.view.hosts.iter())
            .filter(|view| view.entry.state == DirectoryState::Active)
            .filter(|view| view.verdict == HostEvidence::Live && view.entry.host != record.owner)
            .filter(|view| fixed.is_none_or(|host| view.entry.host == host))
            .filter(|view| !self.stuck(records, view.entry.host))
            .collect();
        if hosts.is_empty() {
            return Err(none(Blocker::NoEligibleHost));
        }
        let owner = self.view.directory.host(record.owner);
        if let (Need::Standby, None, Some(owner)) = (need, fixed, owner) {
            let owner = owner.placement;
            hosts.retain(|view| {
                let placement = view.entry.placement;
                placement.partition != owner.partition && placement.color != owner.color
            });
            if hosts.is_empty() {
                return Err(none(Blocker::Placement));
            }
        }
        hosts.retain(|view| !self.holds_device(view.entry.host, records));
        if hosts.is_empty() {
            return Err(none(Blocker::DeviceFailureHold));
        }
        hosts.retain(|view| self.fits(view.entry.host, shard, tally));
        if hosts.is_empty() {
            return Err(none(Blocker::PerHostCap));
        }
        let pair_bounds = self.bounds.bounds();
        let first = hosts.iter().map(|view| view.entry.host).min();
        let mut attachable: Vec<(&HostView, Attach)> = (hosts.into_iter())
            .map(|view| {
                (
                    view,
                    Attach::of(&records.active, view.entry.host, pair_bounds),
                )
            })
            .filter(|(_, attach)| *attach != Attach::Closed)
            .collect();
        if attachable.is_empty() {
            let bound = first.and_then(|host| Closed::of(&records.active, host, pair_bounds));
            return Err((ShardState::Closed, Blocker::AttachClosed, bound));
        }
        let listing = self.view.listing(record.active);
        attachable.retain(|(view, attach)| *attach == Attach::Live || self.opens(view, listing));
        if attachable.is_empty() {
            let blocker = match listing {
                None => Blocker::ControlPlaneUnavailable,
                Some(_) => Blocker::NoEligibleHost,
            };
            return Err(none(blocker));
        }
        attachable.sort_by_cached_key(|(view, attach)| {
            let report = view.report.as_ref();
            let recovery = report.map_or(0, |report| free(report.host.headroom.recovery));
            let host = view.entry.host;
            let named = self.roles(host, shard).named + tally.named(host);
            (*attach != Attach::Live, named, Reverse(recovery), host)
        });
        let mut ranked = attachable.into_iter();
        let best = ranked.find(|(view, attach)| self.headroom(view, shard, *attach, tally));
        let best = best.map(|(view, attach)| (view.entry.host, attach));
        best.ok_or(none(Blocker::Headroom))
    }

    /// For hosts outside the record's owner and standby roles, the plan ends a live attach of the active volume when the
    /// record has at least one attempt and any of three conditions holds: the host has a Lost verdict, the directory
    /// marks the host as draining or retired, or `self.stuck(records, host)` returns true.
    fn ends(&self, records: &ShardRecords) -> Vec<Host> {
        let record = &records.record;
        let volume = &records.active;
        let retiring = |host| self.retiring(host);
        (volume.live_attaches())
            .filter(|&(_, host)| reclaimable(record, host))
            .filter(|&(_, host)| self.lost(host) || retiring(host) || self.stuck(records, host))
            .filter(|&(_, host)| end_ready(volume, host).is_some())
            .map(|(_, host)| host)
            .collect()
    }

    fn stuck(&self, records: &ShardRecords, host: Host) -> bool {
        let volume = &records.active;
        let seq = volume
            .live(host)
            .filter(|_| volume.enrolled(host).is_none());
        seq.is_some_and(|seq| self.stuck.contains(&(volume.volume, seq)))
    }

    fn crowded(
        &self,
        records: &ShardRecords,
        plan: &ShardPlan,
        ends: &[Host],
        held: bool,
    ) -> Option<Host> {
        let record = &records.record;
        let volume = &records.active;
        let closed = matches!(
            (plan.state, plan.blocker),
            (ShardState::Closed, Some(Blocker::AttachClosed))
                | (ShardState::NoCandidate, Some(Blocker::Headroom))
        );
        let full = volume.live_hosts().count() >= MAX_ATTACHED;
        let known = records.judgement.health.is_some();
        if !closed || !full || held || !known || !ends.is_empty() || !reservable(volume) {
            return None;
        }
        let (seq, host) = (volume.live_attaches())
            .find(|&(_, host)| reclaimable(record, host) && end_ready(volume, host).is_some())?;
        let need = standbys::need_of(record, volume, |host| self.lost(host))
            .or_else(|| self.displaced(records).map(|_| Need::Standby))?;
        let mut freed = records.clone();
        let entry = freed
            .active
            .events
            .iter_mut()
            .find(|event| event.seq == seq)?;
        entry.kind = EventKind::Ended;
        if need == Need::Standby && self.verdict(record.owner) == HostEvidence::Live {
            let pinned = |held: &RecordedPair| held.host == host && held.attach == seq;
            freed.active.pairs.retain(|held| !pinned(held));
        }
        let failed = |host| self.slot_failed(volume, host);
        let slot = self.census.slot(record.shard);
        let displaced = self.displaced(records);
        let incumbent = (slot.map(|slot| slot.host))
            .filter(|&host| host != record.owner && !failed(host))
            .or_else(|| displaced.and(record.standby));
        let current = slot.filter(|slot| slot.target == Target::of(record) && !failed(slot.host));
        let listing = self.view.listing(record.active);
        let open = match current {
            // SLOT-HOST: the entry host that replaces the named standby frees an attach only when `choose` accepts it
            // on the freed volume with a new attach.
            Some(slot) if displaced == Some(slot.host) => matches!(
                self.choose(&freed, need, Some(slot.host), &Tally::default()),
                Ok((_, Attach::Open))
            ),
            Some(slot) => {
                let view = self.hosts.get(&slot.host);
                Attach::of(&freed.active, slot.host, self.bounds.bounds()) == Attach::Open
                    && view.is_some_and(|view| self.opens(view, listing))
            }
            None => matches!(
                self.choose(&freed, need, incumbent, &Tally::default()),
                Ok((_, Attach::Open))
            ),
        };
        open.then_some(host)
    }

    /// For each host outside the record's owner and standby roles whose latest entry has ended and whose pair is gone,
    /// `unwinds` returns a `Detach` while the listing shows its instance and a `ReleaseAttach` once it omits it.
    fn unwinds(&self, records: &ShardRecords) -> Vec<Step> {
        let record = &records.record;
        let volume = &records.active;
        let shard = record.shard;
        let mut steps = Vec::new();
        let hosts: BTreeSet<Host> = volume.events.iter().map(|event| event.host).collect();
        for host in hosts.into_iter().filter(|&host| reclaimable(record, host)) {
            if let Some((_, instance)) = relist_ready(volume, host) {
                if self.shows(records, instance) == Some(true) {
                    steps.push(Step::Detach { shard, host });
                }
                continue;
            }
            let Some((seq, event)) = volume.latest(host) else {
                continue;
            };
            if event.kind != EventKind::Ended || volume.pinned(host, seq).is_some() {
                continue;
            }
            let Some(instance) = event.instance else {
                continue;
            };
            match self.shows(records, instance) {
                Some(true) => steps.push(Step::Detach { shard, host }),
                Some(false) => steps.push(Step::ReleaseAttach { shard, host }),
                None => {}
            }
        }
        steps
    }

    /// One `Replace` step per shard whose replacement advances on this tick, in shard order, under REPLACE and HOLDS.
    /// A receipt of a later generation that records an issued or created attempt holds one of the
    /// `replacements_inflight_max` units; an open receipt over a loss that `complete_loss` admits, and a shard with no
    /// receipt that provisions, take a free unit in shard order and wait with no step while none is free. A step whose
    /// one write is the hold takes no unit: the start of a held receipt, and the latch over a pending receipt of any
    /// phase that is neither held nor released beside another impaired volume. An open receipt above
    /// `create_attempts_max` gets its step, which raises `Reason::Attempts`, and takes no unit. Under the operator hold or the zone host hold only
    /// those hold steps run. `steps`, the plan's earlier steps, seeds the replacement hosts' tally with each
    /// reservation's host.
    fn replacements(
        &self,
        ordered: &[&ShardView],
        shards: &[ShardPlan],
        (holds, steps): (Holds, &[Step]),
    ) -> Vec<Step> {
        let config = self.bounds.config();
        let max = config.replacements_inflight_max as usize;
        let needed = loss_run(config.loss_ticks);
        let read = || {
            ordered
                .iter()
                .filter_map(|shard| shard.records.as_ref().ok()?.as_ref())
        };
        let unit = |receipt: &Receipt| !receipt.held && receipt.phase != Phase::Open;
        let mut inflight = read()
            .filter(|records| pending(records).is_some_and(unit))
            .count();
        let held = holds.operator || holds.zone_host;
        let mut picked: BTreeMap<Host, usize> = BTreeMap::new();
        for step in steps {
            if let Step::Reserve { host, .. } = step {
                *picked.entry(*host).or_default() += 1;
            }
        }
        let mut replaces = Vec::new();
        for (shard, plan) in ordered.iter().zip(shards) {
            let Ok(Some(records)) = &shard.records else {
                continue;
            };
            let judged = &records.judgement;
            let receipt = pending(records);
            let advances = match (plan.state, receipt) {
                (_, Some(receipt)) if receipt.held => false,
                (ShardState::ReplacementHeld, None) => true,
                (ShardState::Replacing { .. }, Some(_)) if hold_due(records) => true,
                _ if held => false,
                (ShardState::Replacing { .. }, Some(receipt)) if unit(receipt) => true,
                (ShardState::Replacing { .. }, Some(_)) if !complete_loss(judged, needed) => true,
                (ShardState::Replacing { .. }, Some(receipt))
                    if receipt.attempt > config.create_attempts_max =>
                {
                    true
                }
                (ShardState::Replacing { .. }, _) if inflight < max => {
                    inflight += 1;
                    true
                }
                _ => false,
            };
            if !advances {
                continue;
            }
            let created = receipt.is_some_and(|receipt| matches!(receipt.phase, Phase::Created(_)));
            replaces.push(Step::Replace {
                shard: shard.shard,
                target: Target::of(&records.record),
                host: created
                    .then(|| self.replacement_host(records, &mut picked))
                    .flatten(),
            });
        }
        replaces
    }

    /// The host that attaches `records`' replacement volume: the one its record's attach event names, else the shard
    /// record's owner while it reads live, is active in the directory, reports an era of `MIN_ERA` or later, holds no
    /// device-failure hold of the shard and shows attachment and recovery headroom, else the host of fewest roles that
    /// meets the same conditions and that `fits_owner` admits, lowest first among equals. A host the census or a shard
    /// record names standby holds that role in the count (`Zone::roles`). `picked` tallies the hosts this plan chose
    /// for earlier replacements and the hosts of its reservations; a chosen host that has no attach event yet joins
    /// it.
    fn replacement_host(
        &self,
        records: &ShardRecords,
        picked: &mut BTreeMap<Host, usize>,
    ) -> Option<Host> {
        let record = &records.record;
        if let Some(host) = attacher(records) {
            return Some(host);
        }
        let extra = |host: Host| picked.get(&host).copied().unwrap_or_default();
        let eligible = |view: &&HostView| {
            let era = view.report.as_ref().map(|report| report.host.build.era);
            view.entry.state == DirectoryState::Active
                && view.verdict == HostEvidence::Live
                && era.is_some_and(|era| era >= MIN_ERA)
                && !self.holds_device(view.entry.host, records)
                && self.attachable(view, record.shard, extra(view.entry.host))
        };
        let owner = (self.hosts.get(&record.owner).copied()).filter(eligible);
        let roles = |host: Host| {
            let roles = self.roles(host, record.shard);
            roles.named + roles.owned + roles.designated + extra(host)
        };
        let chosen = owner.map(|view| view.entry.host).or_else(|| {
            (self.view.hosts.iter())
                .filter(eligible)
                .filter(|view| self.fits_owner(view, record.shard, extra(view.entry.host)))
                .min_by_key(|view| (roles(view.entry.host), view.entry.host))
                .map(|view| view.entry.host)
        })?;
        *picked.entry(chosen).or_default() += 1;
        Some(chosen)
    }

    /// Whether `view`'s host can take one more role, the owner of a replacement volume: its roles, the unread shards
    /// and `extra` roles this plan gave it included, stay below the directory's `host_roles_max`.
    fn fits_owner(&self, view: &HostView, shard: Shard, extra: usize) -> bool {
        let roles_max = self.view.directory.host_roles_max().get() as usize;
        let roles = self.roles(view.entry.host, shard);
        roles.named + roles.owned + roles.designated + self.unread + extra < roles_max
    }

    /// Whether `view`'s report shows a recovery slot and an attachment slot beyond the census reservations of other
    /// shards its report does not list yet (HEADROOM) and the `extra` attachments this plan gave it.
    fn attachable(&self, view: &HostView, shard: Shard, extra: usize) -> bool {
        let Some(report) = view.report.as_ref() else {
            return false;
        };
        let headroom = report.host.headroom;
        let owed = (self
            .census
            .pending(shard, report, |held| self.view.active(held)))
        .saturating_add(extra as u64);
        room(headroom.recovery, 0)
            && room(headroom.attachments, 0)
            && room(headroom.attachments, owed)
    }

    /// Admits `queue`'s starts in order and returns the attach starts it admitted and the number of `Need::Fresh`
    /// starts the census alone refused. It judges those refused starts after the queue's other fresh starts and
    /// charges the first of them, one for each place the tick can free (FRESH-FIRST).
    fn admit(
        &self,
        context: &Context<'_>,
        holds: Holds,
        (inflight, exchanges): (usize, &BTreeSet<Shard>),
        (queue, ordered): (&[(usize, Start<'a>)], &[&ShardView]),
        shards: &mut [ShardPlan],
        steps: &mut Vec<Step>,
    ) -> (Vec<(Shard, Host, VolumeId)>, usize) {
        let config = self.bounds.config();
        let window = config.attach_window_us;
        let in_window = |at: u64| context.now_us.saturating_sub(at) < window;
        let mut opened = context.starts.values().filter(|&&at| in_window(at)).count();
        let mut reserved = inflight;
        let mut tally = Tally::default();
        let mut admitted = Vec::new();
        let mut refused = 0;
        let mut waiting: Vec<Start<'a>> = Vec::new();
        let fresh = queue.partition_point(|(_, start)| start.need == Need::Fresh);
        for index in 0..=queue.len() {
            if index == fresh && !waiting.is_empty() {
                // Every fresh start that keeps a census entry has reserved it by now, so the entries the release step
                // drops among the other shards, less those above the cap, are the places the tick can free: each is
                // released, or reserved by a `Need::Standby` start that `plan` can withhold.
                let reserving: BTreeSet<Shard> = steps
                    .iter()
                    .filter(|step| reserves(step))
                    .map(Step::shard)
                    .collect();
                let excess = self.census.len().saturating_sub(self.cap());
                let freeable = self.releases(ordered, shards, &reserving).len();
                let places = freeable.saturating_sub(excess);
                for start in waiting.drain(..) {
                    if reserved >= config.enroll_inflight_max as usize {
                        break;
                    }
                    let record = &start.records.record;
                    let shard = record.shard;
                    // A fresh start counts as refused only when the census alone stops it: its candidate passes the
                    // tally, the holds and the start window. A counted start the tick can free a place for keeps that
                    // host, start credit and in-flight unit from the later starts of the tick, so the start the freed
                    // place admits finds them next tick.
                    let Ok((host, attach)) =
                        self.choose(start.records, start.need, start.incumbent, &tally)
                    else {
                        continue;
                    };
                    let opens = attach == Attach::Open;
                    let key = (shard, host, record.active);
                    let known = (context.starts.get(&key)).is_some_and(|&at| in_window(at));
                    let held = opens && (holds.operator || holds.zone_host);
                    let paced =
                        opens && !known && opened >= config.attach_starts_per_window as usize;
                    if held || paced {
                        continue;
                    }
                    refused += 1;
                    if refused <= places {
                        opened += usize::from(opens && !known);
                        self.charge(&mut tally, host, record);
                        reserved += 1;
                    }
                }
            }
            let Some(&(at, start)) = queue.get(index) else {
                break;
            };
            let record = &start.records.record;
            let shard = record.shard;
            let exchange = exchanges.contains(&shard);
            if reserved >= config.enroll_inflight_max as usize && !exchange {
                continue;
            }
            let plan = &mut shards[at];
            let slot = self.census.slot(shard);
            if slot.is_none() && self.census.len() + tally.added >= self.cap() {
                (plan.state, plan.blocker) = (ShardState::NoCandidate, Some(Blocker::CensusFull));
                if start.need == Need::Fresh {
                    waiting.push(start);
                }
                continue;
            }
            let chosen = self.choose(start.records, start.need, start.incumbent, &tally);
            let (host, attach) = match chosen {
                Ok(chosen) => chosen,
                Err((state, blocker, bound)) => {
                    (plan.state, plan.blocker, plan.closed) = (state, Some(blocker), bound);
                    continue;
                }
            };
            let phase = EnrollPhase::Unreserved;
            plan.state = ShardState::Enrolling {
                need: start.need,
                phase,
                host,
            };
            let opens = attach == Attach::Open;
            if opens && (holds.operator || holds.zone_host) {
                continue;
            }
            if opens {
                let key = (shard, host, record.active);
                let known = (context.starts.get(&key)).is_some_and(|&at| in_window(at));
                if !known && opened >= config.attach_starts_per_window as usize {
                    continue;
                }
                opened += usize::from(!known);
                admitted.push(key);
            }
            if slot.is_none_or(|slot| slot.host != host) {
                self.charge(&mut tally, host, record);
            }
            tally.added += usize::from(slot.is_none());
            reserved += usize::from(!exchange);
            steps.push(Step::Reserve {
                shard,
                host,
                target: Target::of(record),
            });
        }
        (admitted, refused)
    }

    /// The tally counts a new census role on `host` for `record`'s shard. If `host`'s report lists that shard in the
    /// standby role on `record`'s active volume, the tally counts zero attachments owed; otherwise, it counts one.
    fn charge(&self, tally: &mut Tally, host: Host, record: &ShardRecord) {
        *tally.named.entry(host).or_default() += 1;
        let report = (self.hosts.get(&host)).and_then(|view| view.report.as_ref());
        let listed = |report: &HostReport| lists_standby(report, record.shard.get(), record.active);
        if !report.is_some_and(|report| listed(report)) {
            *tally.owed.entry(host).or_default() += 1;
        }
    }

    /// Whether the plan releases the census entry of `records`' shard: [`Census::releases`] under the survey's loss
    /// evidence and the active volume's ended attaches.
    fn releasing(&self, records: &ShardRecords) -> bool {
        let active = &records.active;
        let ended = |host| active.latest(host).is_some() && active.live(host).is_none();
        let stays = |host| !self.lost(host) && !ended(host);
        self.census.releases(&records.record, stays)
    }

    /// The releases of the shards outside `reserving` whose entry [`Zone::releasing`] drops, by shard.
    fn releases(
        &self,
        ordered: &[&ShardView],
        shards: &[ShardPlan],
        reserving: &BTreeSet<Shard>,
    ) -> Vec<Step> {
        let mut steps = Vec::new();
        for (shard, plan) in ordered.iter().zip(shards) {
            let Ok(Some(records)) = &shard.records else {
                continue;
            };
            if plan.state == ShardState::RetirementRequested || reserving.contains(&shard.shard) {
                continue;
            }
            if self.releasing(records)
                && let Some(held) = self.census.slot(shard.shard)
            {
                steps.push(Step::Release {
                    shard: shard.shard,
                    host: held.host,
                    target: held.target,
                });
            }
        }
        steps
    }
}

fn reserves(step: &Step) -> bool {
    matches!(step, Step::Reserve { .. })
}

fn zone_host_hold(view: &ZoneView, bounds: &ZoneBounds) -> bool {
    let bad = |host: &&HostView| matches!(host.verdict, HostEvidence::Lost | HostEvidence::Unknown);
    let present = || (view.hosts.iter()).filter(|host| host.entry.state != DirectoryState::Retired);
    let active = || present().filter(|host| host.entry.state == DirectoryState::Active);
    let beyond_partition = present().filter(bad).count() > view.directory.largest_partition();
    let fraction = bounds.config().host_hold;
    beyond_partition && fraction.exceeded_by(active().filter(bad).count(), active().count())
}

/// The shard's replacement receipt when it names a later generation than the shard record's.
pub(crate) fn pending(records: &ShardRecords) -> Option<&Receipt> {
    (records.receipt.as_ref())
        .filter(|receipt| receipt.request.generation > records.record.generation)
}

/// The host of the attach event of the volume `records`' pending receipt records as created, as its replacement or
/// spare record shows it. The flip names that host the shard's owner, so the plan counts it as holding a role.
fn attacher(records: &ShardRecords) -> Option<Host> {
    let made = pending(records).and_then(|receipt| receipt.phase.volume())?;
    let held = [records.replacement.as_ref(), records.spare.as_ref()]
        .into_iter()
        .flatten()
        .find(|volume| volume.volume == made)?;
    held.events.first().map(|event| event.host)
}

/// LOSS-NEEDS-EVIDENCE for a replacement's start and for each of its effects: `judged` reads the active volume lost on
/// a complete view whose run of complete views is at least `needed` (`loss_run`).
pub(crate) fn complete_loss(judged: &VolumeJudgement, needed: u32) -> bool {
    judged.health == Some(Health::Lost) && judged.complete && judged.streak >= needed
}

pub(crate) fn hold_due(records: &ShardRecords) -> bool {
    let judged = &records.judgement;
    let lost = judged.health == Some(Health::Lost) && judged.confirmed;
    let unheld = pending(records).is_none_or(|receipt| !receipt.held && !receipt.released);
    lost && judged.others > 0 && unheld
}

pub fn plan(observation: &Observation, context: &Context<'_>) -> Plan {
    let mut holds = Holds {
        warm_up: context.warming,
        ..Holds::default()
    };
    let idle = |holds, shards, inflight| Plan {
        steps: Vec::new(),
        shards,
        holds,
        inflight,
        starts: Vec::new(),
    };
    let Ok(view) = &observation.zone else {
        return idle(holds, Vec::new(), 0);
    };
    holds.operator = view.directory.zone_hold();
    holds.zone_host = zone_host_hold(view, context.bounds);
    let mut ordered: Vec<&ShardView> = view.shards.iter().collect();
    ordered.sort_by_key(|shard| shard.shard);
    let unobserved = |shard: &ShardView, source| ShardPlan {
        shard: shard.shard,
        state: ShardState::Unobserved(source),
        blocker: Some(Blocker::StoreUnavailable),
        target: None,
        protected: false,
        closed: None,
    };
    let census = match &view.census {
        Ok(census) => census,
        Err(source) => {
            let shards = ordered.iter().map(|shard| unobserved(shard, *source));
            return idle(holds, shards.collect(), 0);
        }
    };
    let zone = Zone::new(view, census, context);
    let slot_held = |shard: Shard| census.slot(shard).is_some_and(|slot| !zone.lost(slot.host));
    let mut inflight = 0;
    let mut bare = 0;
    let mut unprotected: BTreeMap<Host, usize> = BTreeMap::new();
    let mut shards = Vec::with_capacity(ordered.len());
    let mut works = Vec::new();
    let mut reclaims = Vec::new();
    let mut exchanges = BTreeSet::new();
    for shard in &ordered {
        match &shard.records {
            Err(source) => {
                inflight += usize::from(slot_held(shard.shard));
                shards.push(unobserved(shard, *source));
            }
            Ok(None) if census.slot(shard.shard).is_some() => {
                inflight += usize::from(slot_held(shard.shard));
                shards.push(unobserved(shard, Source::Store(StoreError::Absent)));
            }
            Ok(None) => shards.push(ShardPlan {
                shard: shard.shard,
                state: ShardState::Initial,
                blocker: None,
                target: None,
                protected: false,
                closed: None,
            }),
            Ok(Some(records)) => {
                let ends = zone.ends(records);
                let slot = census.slot(shard.shard);
                let held = zone.holds_slot(records);
                if held && slot.is_some_and(|slot| ends.contains(&slot.host)) {
                    exchanges.insert(shard.shard);
                }
                inflight += usize::from(held);
                let attached = slot.is_some_and(|slot| records.active.live(slot.host).is_some());
                bare += usize::from(held && !attached);
                let (plan, work) = zone.assess(records, &ends);
                let withheld = holds.operator || holds.zone_host;
                let crowded = zone.crowded(records, &plan, &ends, withheld);
                let shard = records.record.shard;
                let ended = ends.iter().chain(&crowded);
                reclaims.extend(ended.map(|&host| Step::End { shard, host }));
                reclaims.extend(zone.unwinds(records));
                if !plan.protected && records.record.attempts > 0 {
                    *unprotected.entry(records.record.owner).or_default() += 1;
                }
                if !matches!(work, Work::Idle) {
                    works.push((shards.len(), work));
                }
                shards.push(plan);
            }
        }
    }
    if holds.warm_up {
        return idle(holds, shards, inflight);
    }
    let mut steps = Vec::new();
    let mut flight = Vec::new();
    let mut queue = Vec::new();
    for (at, work) in works {
        match work {
            Work::InFlight(need, step) => flight.push((need, step)),
            Work::Start(start) => queue.push((at, start)),
            Work::Idle => {}
        }
    }
    flight.sort_by_key(|(need, step)| (*need != Need::Fresh, step.shard()));
    let budget = context.bounds.config().enroll_inflight_max as usize;
    let mut attaching_now = inflight - bare;
    for (_, step) in flight {
        let attaching = matches!(step, Step::RecordAttach { .. } | Step::Attach { .. });
        let recording = matches!(step, Step::RecordAttach { .. });
        if (holds.operator && attaching) || (holds.zone_host && recording) {
            continue;
        }
        if recording {
            if attaching_now >= budget {
                continue;
            }
            attaching_now += 1;
        }
        steps.push(step);
    }
    let gone = |step: &Step| matches!(step, Step::ReleaseAttach { .. });
    steps.extend(reclaims.iter().copied().filter(|step| !gone(step)));
    steps.extend(reclaims.iter().copied().filter(gone));
    queue.sort_by_key(|&(at, start)| {
        let shard = shards[at].shard;
        let exposure = context.exposure.of(shard, context.now_us);
        let owner = start.records.record.owner;
        let owner = unprotected.get(&owner).copied().unwrap_or_default();
        (
            start.need != Need::Fresh,
            Reverse(exposure),
            Reverse(owner),
            shard,
        )
    });
    let (mut admitted, refused) = zone.admit(
        context,
        holds,
        (inflight, &exchanges),
        (&queue, &ordered),
        &mut shards,
        &mut steps,
    );
    let mut reserving: BTreeSet<Shard> = (steps.iter())
        .filter(|step| reserves(step))
        .map(Step::shard)
        .collect();
    let mut releases = zone.releases(&ordered, &shards, &reserving);
    let wanted = (refused + census.len().saturating_sub(zone.cap())).saturating_sub(releases.len());
    if refused > 0 && wanted > 0 {
        let mut donors: Vec<usize> = (queue.iter())
            .filter(|(at, start)| {
                start.need == Need::Standby
                    && reserving.contains(&shards[*at].shard)
                    && zone.releasing(start.records)
            })
            .map(|&(at, _)| at)
            .collect();
        donors.sort_unstable();
        donors.truncate(wanted);
        let withheld: BTreeSet<Shard> = donors.iter().map(|&at| shards[at].shard).collect();
        if !withheld.is_empty() {
            steps.retain(|step| !reserves(step) || !withheld.contains(&step.shard()));
            admitted.retain(|(held, ..)| !withheld.contains(held));
            reserving.retain(|shard| !withheld.contains(shard));
            for at in donors {
                shards[at].blocker = Some(Blocker::CensusFull);
            }
            releases = zone.releases(&ordered, &shards, &reserving);
        }
    }
    steps.extend(releases);
    let replaces = zone.replacements(&ordered, &shards, (holds, &steps));
    steps.extend(replaces);
    Plan {
        steps,
        shards,
        holds,
        inflight,
        starts: admitted,
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct Memory {
    started_us: Option<u64>,
    last_us: Option<u64>,
    tick: u64,
    /// The sources warm-up has seen whole on some call: `reports`, `instances` and `volumes` from the flag of
    /// `Observation::complete`, and `store` from `Observation::answered`.
    seen: Completeness,
    starts: BTreeMap<(Shard, Host, VolumeId), u64>,
    pub(super) exposure: Exposure,
}

#[derive(Debug, Clone)]
pub struct Survey {
    pub observation: Observation,
    pub plan: Plan,
    pub status: ZoneStatus,
}

impl Memory {
    pub(crate) fn times(&self) -> Option<(u64, u64, u64)> {
        let (started_us, last_us) = self.started_us.zip(self.last_us)?;
        Some((self.tick, started_us, last_us))
    }

    /// Keeps the exposure clocks of the shards `directory` lists and drops every other clock.
    pub(crate) fn admit(&mut self, directory: &Directory<ReconcilerProjection>) {
        let shards = directory.shards();
        let listed = |shard| {
            shards
                .binary_search_by_key(&shard, |entry| entry.shard)
                .is_ok()
        };
        self.exposure.retain(listed);
    }
}

impl<S: Store, L: WatermarkLog> ZoneLoop<S, L> {
    pub fn survey(
        &mut self,
        directory: Result<Directory<ReconcilerProjection>, Unreachable>,
        sources: &mut (impl ReportSource + InstanceSource + VolumeSource),
        now_us: u64,
    ) -> Survey {
        self.returned(now_us);
        let observation = self.observe(directory, sources, now_us);
        self.forget_sighted(&observation);
        let stuck = self.stuck(&observation, now_us);
        let config = self.bounds.config();
        let memory = &mut self.survey;
        let started_us = *memory.started_us.get_or_insert(now_us);
        memory.tick += 1;
        memory.last_us = Some(now_us);
        let Completeness {
            reports,
            instances,
            volumes,
            ..
        } = observation.complete;
        let seen = &mut memory.seen;
        seen.reports |= reports;
        seen.instances |= instances;
        seen.volumes |= volumes;
        seen.store |= observation.answered;
        let Completeness {
            reports: seen_reports,
            instances: seen_instances,
            volumes: seen_volumes,
            store: seen_store,
        } = memory.seen;
        let settle = config
            .report_period_us
            .saturating_mul(2)
            .max(config.attach_settle_us);
        let settled = now_us.saturating_sub(started_us) >= settle;
        let warming = !(settled && seen_reports && seen_instances && seen_volumes && seen_store);
        let window = config.attach_window_us;
        memory
            .starts
            .retain(|_, at| now_us.saturating_sub(*at) < window);
        let context = Context {
            bounds: &self.bounds,
            now_us,
            warming,
            starts: &memory.starts,
            exposure: &memory.exposure,
            stuck: &stuck,
        };
        let mut plan = plan(&observation, &context);
        for &start in &plan.starts {
            memory.starts.entry(start).or_insert(now_us);
        }
        if let (Err(source), Some(held)) = (observation.zone.as_ref(), self.directory.as_ref()) {
            let unobserved = |entry: &ShardEntry| ShardPlan {
                shard: entry.shard,
                state: ShardState::Unobserved(*source),
                blocker: None,
                target: None,
                protected: false,
                closed: None,
            };
            plan.shards = held.shards().iter().map(unobserved).collect();
            plan.holds.operator = held.zone_hold();
        }
        let mut shards = Vec::with_capacity(plan.shards.len());
        for shard in &plan.shards {
            let protected = shard.protected || shard.state == ShardState::Initial;
            let exposure_us = match shard.state {
                ShardState::Unobserved(_) => memory.exposure.of(shard.shard, now_us),
                _ => memory.exposure.observe(shard.shard, protected, now_us),
            };
            shards.push(ShardStatus {
                shard: shard.shard,
                state: shard.state,
                blocker: shard.blocker,
                target: shard.target,
                closed: shard.closed,
                exposure_us,
                overdue: exposure_us.is_some_and(|exposure| exposure > config.standby_target_us),
            });
        }
        let (verdicts, census) = match &observation.zone {
            Ok(zone) => {
                let census = zone.census.as_ref().ok().map(|census| census.len());
                (Some(VerdictCounts::of(&zone.hosts)), census)
            }
            Err(_) => (None, None),
        };
        let held = self.directory.as_ref();
        let cap_below = held.and_then(|directory| self.bounds.cap_below_shards(directory));
        let status = ZoneStatus {
            shards,
            census,
            cap: config.population_cap,
            cap_below,
            inflight: census.map(|_| plan.inflight),
            holds: plan.holds,
            verdicts,
            complete: observation.complete,
            unnamed: (observation.zone.as_ref().ok()).and_then(|zone| zone.unnamed),
            tick: memory.tick,
            started_us,
        };
        Survey {
            observation,
            plan,
            status,
        }
    }

    pub fn deadline(&self) -> Option<u64> {
        let tick = self.bounds.config().tick_us;
        self.survey.last_us.map(|last| last.saturating_add(tick))
    }
}
