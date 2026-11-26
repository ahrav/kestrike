//! Each survey reports per-shard and zone-wide status for one tick.
//!
//! - ONE-STATE: every shard of the directory has exactly one [`ShardState`], and a shard whose need has no planned
//!   step and no enrollment in progress carries one [`Blocker`]. The planner takes the first state that holds, in this
//!   order: `Unobserved`, `Initial` for a shard with no record and no census slot, `RetirementRequested`
//!   (`RetirementRequested`), `ReplacementHeld` (`CorrelatedHold`) or `Replacing` from a receipt of a later
//!   generation, `LossUnconfirmed` (`LossUnconfirmed`), `Replacing`, `ReplacementHeld` or `ReplacementExhausted`
//!   (`ReplacementExhausted`) from a lost active volume, `VolumeImpaired` (`VolumeImpaired`), `Initial` for a record
//!   at `E = 0`, `Protected` or `StandbyUnknown` (`LossUnconfirmed`) for a shard with no need, `OwnerUnknown`
//!   (`OwnerNotReady`), `NoCandidate` (`DeviceFailureHold`) from the device-hold guard, then `Enrolling`,
//!   `NoCandidate` or `Closed` (`AttachClosed`) from the enrollment. `Unobserved` carries `StoreUnavailable` for a
//!   store read failure and for a shard with a census slot but no record; a directory read failure leaves it without
//!   a blocker. When the enrollment yields `NoCandidate`, the shard carries `LossUnconfirmed`, `CensusFull`,
//!   `NoEligibleHost`, `Placement`, `DeviceFailureHold`, `PerHostCap` or `Headroom`. An `Enrolling` shard in phase
//!   `Recorded` carries `ControlPlaneUnavailable` while the volume listing is unavailable. An `Enrolling` shard with a
//!   step or a start to plan and no other blocker carries `ControlPlaneUnavailable` while its active volume's health
//!   is unknown, and the plan withholds that step. `Protected` and `Enrolling` otherwise carry
//!   the shard's host-side blocker, `RestartHeld`, `RecordedHolderHold`, `DeviceFailureHold` or `SelfSuspect`, in
//!   that order, when it has one. A
//!   `Protected` shard whose owner reads lost carries `QuorumUnreachable` when its named standby's possible probers
//!   span fewer partitions than any detector quorum counts (QUORUM-PREMISE in `plan`), after the standby's own
//!   `SelfSuspect` and ahead of the owner-side holds of the lost owner's last report. A census slot host that reports the device-failure hold on the active volume gives its `Enrolling` shard
//!   `DeviceFailureHold`, after `ControlPlaneUnavailable` and ahead of the host-side blocker. A census slot host that
//!   displaces a live named standby (SLOT-HOST in `plan`) gives its `Enrolling` shard the blocker `Zone::choose`
//!   returns for that host, after `DeviceFailureHold` and ahead of the host-side blocker. An `Enrolling` shard in
//!   phase `Unreserved` whose reservation the plan withholds for a refused fresh need (FRESH-FIRST in `plan`)
//!   carries `CensusFull`, ahead of the host-side blocker. When a hold, warm-up or
//!   a limit withholds an `Enrolling` shard's step, the plan's holds and in-flight count report the reason.
//! - EXPOSURE: [`Exposure`] counts, per shard, from the first tick that observed it without a live named standby to
//!   the tick that observes one. A shard read `Initial` closes its clock. A tick that leaves the shard `Unobserved`
//!   preserves the clock's state: an open clock keeps counting and can cross the target. Strictly past
//!   `standby_target_us` the shard reads overdue. A shard that leaves the directory drops its clock. The clocks live
//!   in process memory: each loop starts with an empty set of clocks and reports the caller's elapsed time at its
//!   first survey.

use std::collections::BTreeMap;

use crate::failover::loss::Phase;
use crate::failover::records::Host;
use crate::failover::report::status::{Class, positions};
use crate::failover::retire::Target;
use crate::failover::standbys::{Closed, Need};
use crate::failover::zone_loop::config::CapBelowShards;
use crate::failover::zone_loop::evidence::HostEvidence;
use crate::failover::zone_loop::observe::{Completeness, HostView, Source};
use crate::net::ownership::Shard;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollPhase {
    /// The census lists no slot for the shard at its current target under a host that is not lost.
    Unreserved,
    /// The census slot names the host; the active volume's record holds no live attach of it.
    Reserved,
    /// The volume record holds the host's live attach; the host's instance is absent from the volume's attachment
    /// listing, or the listing is unavailable.
    Recorded,
    /// The listing shows the attachment; the host has not enrolled its pair.
    Attached,
    /// The volume record enrolls the host's pair; the shard record does not name it standby.
    Enrolled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShardState {
    /// The shard record names a standby whose host reads live and has a live attach of the active volume.
    Protected,
    /// The store holds no shard record and the census no slot for the shard, or the record is at `E = 0`.
    Initial,
    /// Enrollment covers both the standby and the fresh-host need.
    Enrolling {
        need: Need,
        phase: EnrollPhase,
        host: Host,
    },
    /// The need has no host to enroll; the blocker names the filter or the evidence that left none.
    NoCandidate,
    /// `Closed` applies when either condition holds:
    /// - [`Attach::of`](crate::failover::standbys::Attach::of) returns `Closed` for the host of the shard's current
    ///   census slot, or for every candidate host that reached the attach check when the shard has no current slot;
    ///   the slot's host, or the lowest-numbered such candidate, names the cause. Each host classified as `Closed`
    ///   needs a new attach that the active volume blocks, or holds an unpaired live attach whose derived key is
    ///   absent or held by a recorded pair.
    /// - The active volume's record blocks census reservations: it is neither fresh nor active, or its provisioned
    ///   origin changed. Such a shard names no cause.
    Closed,
    /// The named standby's host reads unknown or in conflict.
    StandbyUnknown,
    /// The owner's host reads unknown or in conflict while the shard needs a standby.
    OwnerUnknown,
    VolumeImpaired,
    /// The active volume reads lost and its loss is unconfirmed: beside another impaired or lost volume before
    /// `VolumeJudgement::confirmed`, or alone in a view that is incomplete this tick or whose
    /// `VolumeJudgement::streak` is below `loss_run(loss_ticks)`.
    LossUnconfirmed,
    Replacing {
        phase: Phase,
    },
    /// The replacement waits on the correlated-loss hold.
    ReplacementHeld,
    /// The active volume is lost at the last generation a replacement can activate.
    ReplacementExhausted,
    /// The owner's entry for the active volume at the record's tenure requests a flip.
    RetirementRequested,
    /// The survey could not read the shard's records, or the directory, from the source.
    Unobserved(Source),
}

impl ShardState {
    /// The serving class this state fixes whatever the owner's entry reads, the first rules of the reconciler
    /// status's ONE-CLASSIFICATION: `Silent` for an unread shard, `Fresh` at `E = 0`, `Cold` for a lost active
    /// volume's replacement, held replacement or exhausted generation, and `Blocked` for a retirement request, an
    /// impaired volume or an unconfirmed loss; `None` when the builder's owner rules decide: a lost owner, then the
    /// owner's entry from a fresh report, then `Silent`.
    pub fn class(&self) -> Option<Class> {
        match self {
            Self::Unobserved(_) => Some(Class::Silent),
            Self::Initial => Some(Class::Fresh),
            Self::Replacing { .. } | Self::ReplacementHeld | Self::ReplacementExhausted => {
                Some(Class::Cold)
            }
            Self::RetirementRequested | Self::VolumeImpaired | Self::LossUnconfirmed => {
                Some(Class::Blocked)
            }
            Self::Protected
            | Self::Enrolling { .. }
            | Self::NoCandidate
            | Self::Closed
            | Self::StandbyUnknown
            | Self::OwnerUnknown => None,
        }
    }
}

/// A `Blocker` identifies why the planner withholds a step for a shard's need.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Blocker {
    /// The shard needs a new census slot, and the census already lists `population_cap` shards including this plan's
    /// reservations; or the plan withholds the shard's re-reservation so its entry's release admits a fresh need.
    CensusFull,
    /// No active host of the zone other than the owner reads live.
    NoEligibleHost,
    AttachClosed,
    /// Every remaining candidate lacks recovery or attachment headroom.
    Headroom,
    ControlPlaneUnavailable,
    StoreUnavailable,
    SelfSuspect,
    /// The owner's entry reports the recorded-holder hold.
    RecordedHolderHold,
    DeviceFailureHold,
    VolumeImpaired,
    CorrelatedHold,
    RetirementRequested,
    /// A host or volume the need depends on reads unknown, in conflict or lost with its loss unconfirmed
    /// (`ShardState::LossUnconfirmed`): the named standby, a census slot's host, or the active volume.
    LossUnconfirmed,
    ReplacementExhausted,
    OwnerNotReady,
    /// Every candidate shares the owner's partition or color.
    Placement,
    /// Every candidate holds `standbys_per_host_max` census entries or `host_roles_max` roles.
    PerHostCap,
    /// The owner reads lost, and the named standby's possible probers, counted from the zone's directory, this
    /// tick's verdicts and a retired host's instance and report evidence, span fewer than
    /// [`QUORUM_MIN`](crate::failover::arbiter::QUORUM_MIN) partitions, so the standby can gather fresh replies from
    /// too few partitions for any detector quorum to nominate its takeover (QUORUM-PREMISE in `plan`, which states
    /// what the count leaves out, the votes the standby already holds among them).
    QuorumUnreachable,
    /// The owner's report holds the diagnostic entry of a restart held after a bump whose reply is unknown at the
    /// record's tenure or one attempt below it (HELD-RESTART-MATCH in `observe`), so the shard is unserved until the
    /// owner's next incarnation restarts and serves, a standby takes it over or an operator acts.
    RestartHeld,
}

impl Blocker {
    /// The number of blockers.
    pub const COUNT: usize = 19;

    /// Every blocker, at its [`Blocker::position`].
    pub const ALL: [Self; Self::COUNT] = [
        Self::CensusFull,
        Self::NoEligibleHost,
        Self::AttachClosed,
        Self::Headroom,
        Self::ControlPlaneUnavailable,
        Self::StoreUnavailable,
        Self::SelfSuspect,
        Self::RecordedHolderHold,
        Self::DeviceFailureHold,
        Self::VolumeImpaired,
        Self::CorrelatedHold,
        Self::RetirementRequested,
        Self::LossUnconfirmed,
        Self::ReplacementExhausted,
        Self::OwnerNotReady,
        Self::Placement,
        Self::PerHostCap,
        Self::QuorumUnreachable,
        Self::RestartHeld,
    ];

    /// The blocker's position in [`Blocker::ALL`], the closed table the reconciler status counts blockers by. The
    /// exhaustive match binds one of [`Blocker::COUNT`] positions per variant, so a new blocker compiles only with a
    /// longer table.
    pub const fn position(self) -> usize {
        let [
            census_full,
            no_eligible_host,
            attach_closed,
            headroom,
            control_plane_unavailable,
            store_unavailable,
            self_suspect,
            recorded_holder_hold,
            device_failure_hold,
            volume_impaired,
            correlated_hold,
            retirement_requested,
            loss_unconfirmed,
            replacement_exhausted,
            owner_not_ready,
            placement,
            per_host_cap,
            quorum_unreachable,
            restart_held,
        ] = positions::<{ Self::COUNT }>();
        match self {
            Self::CensusFull => census_full,
            Self::NoEligibleHost => no_eligible_host,
            Self::AttachClosed => attach_closed,
            Self::Headroom => headroom,
            Self::ControlPlaneUnavailable => control_plane_unavailable,
            Self::StoreUnavailable => store_unavailable,
            Self::SelfSuspect => self_suspect,
            Self::RecordedHolderHold => recorded_holder_hold,
            Self::DeviceFailureHold => device_failure_hold,
            Self::VolumeImpaired => volume_impaired,
            Self::CorrelatedHold => correlated_hold,
            Self::RetirementRequested => retirement_requested,
            Self::LossUnconfirmed => loss_unconfirmed,
            Self::ReplacementExhausted => replacement_exhausted,
            Self::OwnerNotReady => owner_not_ready,
            Self::Placement => placement,
            Self::PerHostCap => per_host_cap,
            Self::QuorumUnreachable => quorum_unreachable,
            Self::RestartHeld => restart_held,
        }
    }
}

const _: () = {
    let mut at = 0;
    while at < Blocker::COUNT {
        assert!(
            Blocker::ALL[at].position() == at,
            "Blocker::ALL lists each blocker at its position"
        );
        at += 1;
    }
};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Holds {
    /// Warm-up ends when the settle time since startup has elapsed and the loop has had, from each source, one
    /// call that read it whole: the reports, the instance listing, the volume listing, and for the store a call it
    /// answered every read of (`Observation::answered`), where a shard's record, a lookup or a receipt reread that
    /// does not decode counts as answered and a census that does not decode does not.
    pub warm_up: bool,
    /// More hosts read lost or unknown than both the largest partition holds and the configured fraction of active
    /// hosts.
    pub zone_host: bool,
    pub operator: bool,
}

/// `VerdictCounts` counts the zone's directory hosts by verdict for the tick. Retired hosts count as lost; the zone
/// host hold considers only hosts satisfying `host.entry.state != DirectoryState::Retired`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VerdictCounts {
    pub live: usize,
    pub lost: usize,
    pub conflict: usize,
    pub unknown: usize,
}

impl VerdictCounts {
    pub fn of(hosts: &[HostView]) -> Self {
        let mut counts = Self::default();
        for host in hosts {
            let count = match host.verdict {
                HostEvidence::Live => &mut counts.live,
                HostEvidence::Lost => &mut counts.lost,
                HostEvidence::Conflict => &mut counts.conflict,
                HostEvidence::Unknown => &mut counts.unknown,
            };
            *count += 1;
        }
        counts
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShardStatus {
    pub shard: Shard,
    pub state: ShardState,
    pub blocker: Option<Blocker>,
    /// The `(g, owner, E)` of the shard's census slot, when the plan read the shard's records and the census lists
    /// a slot for it.
    pub target: Option<Target>,
    /// The bound the shard's active volume stands at for the host the plan judged, when the plan reads the shard
    /// [`ShardState::Closed`] for that reason (`zone_loop::plan::ShardPlan::closed`).
    pub closed: Option<Closed>,
    /// The age of the shard's open exposure clock, `Some(0)` on the tick that opens it, and `None` while the clock is
    /// closed.
    pub exposure_us: Option<u64>,
    /// The open exposure is strictly past `standby_target_us`.
    pub overdue: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneStatus {
    /// One row per shard of the plan, ascending.
    pub shards: Vec<ShardStatus>,
    /// The census length, `None` when the census was unread.
    pub census: Option<usize>,
    pub cap: usize,
    /// The configured cap is below the shard count of the last directory this loop admitted.
    pub cap_below: Option<CapBelowShards>,
    pub inflight: Option<usize>,
    /// If the directory read fails or is refused, `operator` retains the last admitted directory's hold and
    /// `zone_host` is false.
    pub holds: Holds,
    /// The verdict counts, present when this tick admitted a directory and formed host verdicts.
    pub verdicts: Option<VerdictCounts>,
    pub complete: Completeness,
    /// [`ZoneView::unnamed`](crate::failover::zone_loop::observe::ZoneView::unnamed) of the tick's observation,
    /// `None` without one.
    pub unnamed: Option<u32>,
    /// The survey's sequence number in this loop, 1 for the first survey.
    pub tick: u64,
    /// The caller's elapsed time at the loop's first survey.
    pub started_us: u64,
}

#[derive(Debug, Clone, Default)]
pub struct Exposure {
    since: BTreeMap<Shard, u64>,
}

impl Exposure {
    pub fn observe(&mut self, shard: Shard, protected: bool, now_us: u64) -> Option<u64> {
        if protected {
            self.since.remove(&shard);
            return None;
        }
        let since = *self.since.entry(shard).or_insert(now_us);
        Some(now_us.saturating_sub(since))
    }

    pub fn of(&self, shard: Shard, now_us: u64) -> Option<u64> {
        let since = self.since.get(&shard)?;
        Some(now_us.saturating_sub(*since))
    }

    pub fn retain(&mut self, listed: impl Fn(Shard) -> bool) {
        self.since.retain(|&shard, _| listed(shard));
    }
}
