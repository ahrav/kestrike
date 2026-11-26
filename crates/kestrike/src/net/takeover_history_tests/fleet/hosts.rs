//! Each host runs the production `host::agent::Agent`. Once a round the agent reads the host's process statuses and
//! the heartbeats and probe messages [`HostLinks`] carried to it, and every `REPORT_ROUNDS` rounds it seals a report.
//! The agent revalidates each nomination its detector published and addresses the witness to the named shard's
//! standby process. The fleet queues the witness with the agent turn's time, the time the process reads it at. One
//! view period of `host::stand_by` reads its role, accepts the witness at that time and runs the takeover to its end
//! or refusal in one turn. The new tenure then loads warm over later turns, and at the load's start each other shard its host serves is
//! offered one GET, so the host log counts the GETs a loading host's shards serve while the load runs.
//!
//! [`HostLinks`]: super::faults::HostLinks

use std::collections::BTreeSet;
use std::num::NonZeroU64;

use crate::failover::arbiter::{ArbiterBounds, Clock};
use crate::failover::detect::DetectBounds;
use crate::failover::detect::beat::{self, BeatError, BeatKey};
use crate::failover::detect::host::{Reading, Revalidated, WatchBounds, WatchRefusal};
use crate::failover::detect::probe::{self, Message, ProbeError, ProbeKey};
use crate::failover::loss::Phase;
use crate::failover::records::{self, Host, ShardRecord, VolumeId};
use crate::failover::report::Phase as OwnerPhase;
use crate::failover::report::{self, BuildIdentity, Gauge};
use crate::failover::restart::tests as restart_tests;
use crate::failover::takeover::Takeover;
use crate::failover::takeover::tests::holder_on;
use crate::host::HostGate;
use crate::host::agent::{Agent, HostSample, Inputs as AgentInputs, Keys, Synced};
use crate::host::link::{Inbound, Status as LinkStatus};
use crate::oracle::Tenure;
use crate::storage::store::sim::{Faulted, MemLog, Shared};
use crate::storage::store::{Client, Key};
use crate::storage::warm_sim::share_of;

use super::super::super::client::SessionState;
use super::super::ROUND_US;
use super::faults::{Action, Effect, Episode, Faults, Pattern, Trigger};
use super::reconcile::{REPAIR_SETTLE_ROUNDS, Reclaim, ReconcilerActor, Repair, Status};
use super::zones::ZONE_DOWN_ROUNDS;
use super::{Fleet, Live, Plant, Purpose, Recovered, Slots, Stopped};
use crate::failover::standbys::{Need, Zone};
use crate::failover::zone_loop::evidence::InstanceState;
use crate::failover::zone_loop::status::Blocker;

const H: u64 = ROUND_US;
pub(crate) const REPORT_ROUNDS: u64 = 10;
pub(crate) const TAIL_ROUNDS: u64 = 60;
pub(super) const HORIZON_ROUNDS: u64 = 4_000;
pub(crate) const HANDOFF_GRACE_ROUNDS: u64 = 100;
const PAUSE_ROUNDS: u64 = 240;
const DETECT_HOSTS: usize = 12;
/// The attachment slots of every fleet instance.
const ATTACH_SLOTS: u64 = 64;
/// The build identity every fleet agent's reports carry.
const AGENT_BUILD: BuildIdentity = BuildIdentity {
    era: records::ERA,
    digest: None,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scenario {
    Restarts,
    HostLoss,
    /// H0 and H1, the hosts of one partition, crash at once. Two suspects stay below the host agent's self-suspicion
    /// threshold (`host::agent::SELF_SUSPECT`, 3), so the standbys take the lost shards over.
    PartitionLoss,
    /// H3, H4 and H5 lose their links to H0 for 30 rounds while H2 still reaches it. Each of the three suspects H0,
    /// and its probers answer DEAD from two partitions and ALIVE from H2, whose reply vetoes the cycle.
    FalseSuspicion,
    OwnerPause,
    OwnerIsolation,
    /// The reconciler actors run over the boot census with no fault.
    Settle,
    /// H0's loss of [`Scenario::HostLoss`], then the reconciler re-enrolls standbys.
    Reenroll,
    /// H5, standby of s2 and s4 and owner of none, crashes.
    StandbyLoss,
    /// H5, standby of s2 and s4 and owner of none, pauses for [`PAUSE_ROUNDS`] rounds: its reports stop while the
    /// zone double lists its instance running with healthy checks, and then it resumes.
    StandbySilent,
    /// H0 and H3 crash, so s0, s1 and s3 need a fresh host.
    DoubleLoss,
    /// H0 and H1 crash, as in [`Scenario::PartitionLoss`], with the reconciler running. The reconciler designates new
    /// standbys after the takeovers.
    PartitionRepair,
    /// s5 starts with no standby under a census cap of five; H4 crashes once s5's reservation refused `Full`, and H3
    /// once s5's `Fresh` need refused `Full` too.
    CensusFull,
    /// s2's volume holds a third attach, of H1; H0 and H5 crash.
    AttachSurvivor,
    /// s2's volume holds a third attach, of H1; H0, H1 and H5 crash.
    AttachClosed,
    /// An unknown registrant joins s0's reservation.
    Foreign,
    /// H0's loss under two reconciler actors over one census. Reconciler 1's actuation runs inside reconciler 0's
    /// census read at reconciler 0's first reservation after the loss; both then repair the needs the loss left.
    Racing,
    Crash(super::reconcile::CrashCell),
    /// s3's volume stalls and the control plane reports it impaired to the end of the run; the stall clears after
    /// [`STALL_ROUNDS`] rounds.
    Impaired,
    /// s3's volume stalls for [`BRIEF_ROUNDS`] rounds, short of a suspicion, and the control plane reports it impaired
    /// for [`IMPAIRED_ROUNDS`] rounds.
    ImpairedBrief,
    /// s3's volume stalls for [`STALL_ROUNDS`] rounds while the control plane reports it healthy.
    Stall,
    /// s3's volume is lost with every other volume healthy.
    LostAlone,
    /// s3's volume is lost while the control plane reports s4's volume impaired; the operator releases the hold
    /// [`RELEASE_ROUNDS`](super::volumes::RELEASE_ROUNDS) rounds after it latched, as [`release_due`] states.
    Correlated,
    /// s3's volume is lost with every other volume healthy; once its replacement receipt is written the control plane
    /// reports s4's volume impaired, and the operator releases the hold
    /// [`RELEASE_ROUNDS`](super::volumes::RELEASE_ROUNDS) rounds after the create step latched it.
    CorrelatedLate,
    /// s0's volume is lost on `tiny` and reconciler 0 crashes at the cell's write.
    Replace(super::volumes::ReplaceCell),
    /// Every host of zone 1 of `az` stops for [`ZONE_DOWN_ROUNDS`] rounds and returns.
    ZoneLoss,
    /// The zone loss of [`Scenario::ZoneLoss`] while the control plane reports each volume of zone 1 impaired.
    ZoneImpaired,
    /// H3 crashes and H0 takes s3 over; every host of zone 1 then stops and returns, H3 among them, since H3's own
    /// crash heals during the outage.
    ZoneDeposed,
    /// H0's loss of [`Scenario::Reenroll`]; inside the census read of loop 0's first designation after the loss,
    /// another writer moves that shard's census slot to another running host.
    SlotMoved,
    /// H0, H1 and H2 of `trio`, the hosts of its largest partition, crash at once. Three suspects reach the host
    /// agent's self-suspicion threshold (`host::agent::SELF_SUSPECT`), so no takeover starts (FC12).
    PartitionLossAt,
    /// The loss of [`Scenario::PartitionLossAt`] with the reconciler running. Self-suspicion holds the standbys'
    /// nominations until the reconciler's designation for s2 removes the lost H2 from s2's record, and the standbys
    /// may take over once that designation commits.
    PartitionRepairAt,
    /// H0's loss of [`Scenario::HostLoss`]; the serving duties of s4's boot tenure (cell [`DUTY_CELL`], on H2) meet a
    /// store timeout on one of their writes, which commits or not as the cell says.
    StoreUnknown(Unknown),
    /// H0's loss of [`Scenario::HostLoss`]; the coverage write of s4's boot tenure times out with its commit, and the
    /// re-read of that page returns the page's first version, whose fence lies below the tenure's own.
    PageRegressed,
    /// H0's loss of [`Scenario::HostLoss`]; once s4's boot tenure acknowledged its INVALIDATE, its next record view
    /// reads the shard record's version before the last.
    RecordRegressed,
    /// The planned handoff of [`HANDOFF_CELL`] on the small layout with one reconciler: the serving owner
    /// transfers the shard to its named standby, whose wait reads the restart role and whose next incarnation
    /// serves through the lineage arm.
    Handoff,
    /// [`Scenario::Handoff`] with the target's attach ended inside the transfer: the target's restart refuses and
    /// parks, every agent takes the scaled restart grace, and the host the zone loop designates takes the shard
    /// over.
    HandoffEnded,
}

/// The cell whose boot tenure's serving duties the store-result scenarios fault: s4, owned by H2, which H0's loss
/// leaves untouched.
pub(crate) const DUTY_CELL: usize = 4;
/// The shard number of [`DUTY_CELL`], s4.
pub(crate) const DUTY_SHARD: u32 = DUTY_CELL as u32 + 1;
/// H2 of `small`, the owner of [`DUTY_CELL`]'s shard.
pub(crate) const DUTY_HOST: u64 = 1003;

/// A write of a tenure's serving duties: the shard record's Confirm, the suffix reservation of the tenure open, and
/// the coverage write of a held INVALIDATE, in the order a boot tenure's duties issue them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DutyWrite {
    Confirm,
    Reserve,
    Page,
}

impl DutyWrite {
    pub(crate) const ALL: [Self; 3] = [Self::Confirm, Self::Reserve, Self::Page];

    /// The writes of the duties' actor before this one.
    pub(crate) fn before(self) -> usize {
        Self::ALL
            .iter()
            .position(|&of| of == self)
            .expect("a duty write")
    }
}

/// One store-result cell: the duty write whose reply is unknown, and whether the timed-out write committed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Unknown {
    pub(crate) write: DutyWrite,
    pub(crate) commit: bool,
}

impl Unknown {
    /// Every cell: each write timed out with its commit, then without.
    pub(crate) fn all() -> Vec<Self> {
        let cells = DutyWrite::ALL.into_iter().flat_map(|write| {
            [true, false]
                .into_iter()
                .map(move |commit| Self { write, commit })
        });
        cells.collect()
    }

    pub(crate) fn code(self) -> u8 {
        (self.write.before() * 2 + usize::from(!self.commit)) as u8
    }

    pub(crate) fn name(self) -> String {
        let ending = if self.commit { "committed" } else { "lost" };
        format!("unknown-{:?}-{ending}", self.write).to_lowercase()
    }
}

/// The cell whose volume the volume scenarios of `small` fault: s3, owned by H3 with H0 its standby. H3 owns no other
/// shard.
pub(crate) const FAULTED: usize = 3;
/// The cell whose volume the correlated case impairs: s4, owned by H2.
pub(crate) const BESIDE: usize = 4;
/// The cell whose volume the exhausted-attach scenarios seed with a third attach: s2.
pub(crate) const ATTACH_CELL: usize = 2;
/// The cell the handoff scenarios hand over: s6, owned by H4 with H1 its standby.
pub(crate) const HANDOFF_CELL: usize = 5;
pub(crate) const STALL_ROUNDS: u64 = 160;
pub(crate) const BRIEF_ROUNDS: u64 = 2;
pub(crate) const IMPAIRED_ROUNDS: u64 = 40;

impl Scenario {
    /// The scenario's identity bytes: its code and a crash-table cell's code.
    pub(crate) fn code(self) -> [u8; 2] {
        let code = match self {
            Self::Restarts => 0,
            Self::HostLoss => 1,
            Self::PartitionLoss => 2,
            Self::FalseSuspicion => 3,
            Self::OwnerPause => 4,
            Self::OwnerIsolation => 5,
            Self::Settle => 6,
            Self::Reenroll => 7,
            Self::StandbyLoss => 8,
            Self::DoubleLoss => 9,
            Self::PartitionRepair => 10,
            Self::CensusFull => 11,
            Self::AttachSurvivor => 12,
            Self::AttachClosed => 13,
            Self::Foreign => 14,
            Self::Racing => 15,
            Self::Crash(_) => 16,
            Self::Impaired => 17,
            Self::ImpairedBrief => 18,
            Self::Stall => 19,
            Self::LostAlone => 20,
            Self::Correlated => 21,
            Self::CorrelatedLate => 26,
            Self::Replace(_) => 22,
            Self::ZoneLoss => 23,
            Self::ZoneImpaired => 24,
            Self::ZoneDeposed => 25,
            Self::SlotMoved => 27,
            Self::StandbySilent => 28,
            Self::PartitionLossAt => 29,
            Self::PartitionRepairAt => 30,
            Self::StoreUnknown(_) => 31,
            Self::PageRegressed => 32,
            Self::RecordRegressed => 33,
            Self::Handoff => 34,
            Self::HandoffEnded => 35,
        };
        let cell = match self {
            Self::Crash(cell) => cell.code(),
            Self::Replace(cell) => cell.code(),
            Self::StoreUnknown(cell) => cell.code(),
            _ => 0,
        };
        [code, cell]
    }

    pub(crate) fn hosted(self) -> bool {
        self != Self::Restarts
    }

    /// Whether reconciler actors run.
    pub(crate) fn repairs(self) -> bool {
        !matches!(
            self,
            Self::Restarts
                | Self::HostLoss
                | Self::StoreUnknown(_)
                | Self::PageRegressed
                | Self::RecordRegressed
                | Self::PartitionLoss
                | Self::PartitionLossAt
                | Self::FalseSuspicion
                | Self::OwnerPause
                | Self::OwnerIsolation
        )
    }

    /// Refuses a shape the scenario's script cannot run: a reconciler scenario needs one zone outside the `az`
    /// layout, the two-reconciler scenario two reconcilers, and a script that names hosts or cells by index the
    /// layout containing those hosts or cells. An enrollment or replacement crash-table scenario
    /// needs one reconciler: `Fleet::aim` arms a cell only for reconciler 0.
    /// A hosted scenario needs at most `DETECT_HOSTS` hosts a zone, the placement bound `watch_bounds` gives each
    /// host's detector.
    pub(crate) fn admits(self, shape: &super::Shape) -> Result<(), super::bounds::Refused> {
        use super::bounds::Refused;
        use super::topology::Placing;
        if self.repairs() && shape.zones != 1 && shape.placing != Placing::Az {
            return Err(Refused::Zones(shape.zones));
        }
        let reconcilers = match self {
            Self::Racing => Some(2),
            Self::Crash(_) | Self::Replace(_) => Some(1),
            _ => None,
        };
        if reconcilers.is_some_and(|count| shape.reconcilers != count) {
            return Err(Refused::Reconcilers(shape.reconcilers));
        }
        if self.hosted() && shape.hosts as usize > DETECT_HOSTS {
            return Err(Refused::Hosts(shape.hosts));
        }
        let layout = match self {
            Self::Restarts | Self::Settle => None,
            Self::Crash(cell) if !cell.fresh => Some(Placing::Tiny),
            Self::Replace(_) => Some(Placing::Tiny),
            Self::ZoneLoss | Self::ZoneImpaired | Self::ZoneDeposed => Some(Placing::Az),
            Self::PartitionLossAt | Self::PartitionRepairAt => Some(Placing::Trio),
            _ => Some(Placing::Small),
        };
        match layout {
            Some(placing) if shape.placing != placing => Err(Refused::Placing(shape.placing)),
            _ => Ok(()),
        }
    }

    /// The tenure slots a run allocates: the boot and the next tenure of each shard, and, in a reconciler scenario,
    /// `REPAIR_SLOTS` more per host for loads of shards the host is designated for during the run.
    pub(crate) fn tenures(self, shape: &super::Shape) -> u32 {
        let repair = match self.repairs() {
            true => u32::from(shape.zones)
                .saturating_mul(shape.hosts)
                .saturating_mul(super::REPAIR_SLOTS as u32),
            false => 0,
        };
        // The faulted boot tenure of a store-result scenario reruns on its host once its duties end at their exit.
        let rerun = u32::from(self.duty_faulted());
        (shape.shards.saturating_mul(2))
            .saturating_add(repair)
            .saturating_add(rerun)
    }

    /// Whether the scenario faults the serving duties of [`DUTY_CELL`]'s boot tenure.
    pub(crate) fn duty_faulted(self) -> bool {
        matches!(
            self,
            Self::StoreUnknown(_) | Self::PageRegressed | Self::RecordRegressed
        )
    }

    /// How the scenario seeds cell `at`.
    pub(crate) fn seed(self, at: usize) -> super::Seed {
        let standby = !(self == Self::CensusFull && at == 5);
        let third = matches!(self, Self::AttachSurvivor | Self::AttachClosed) && at == ATTACH_CELL;
        super::Seed {
            standby,
            third: third.then_some(1),
            keyed: self.repairs(),
        }
    }

    /// Whether the scenario's loss leaves a need the loop reserves a census slot for, which F4's reservation witness
    /// reads. In the other scenarios the boot census already lists every named standby.
    pub(crate) fn reserves(self) -> bool {
        matches!(
            self,
            Self::Reenroll
                | Self::SlotMoved
                | Self::StandbyLoss
                | Self::DoubleLoss
                | Self::PartitionRepair
                | Self::PartitionRepairAt
                | Self::CensusFull
                | Self::AttachSurvivor
                | Self::AttachClosed
                | Self::Racing
                | Self::Crash(_)
        )
    }

    /// Whether the scenario's credit reads `verdict`; a failing verdict counts in every scenario.
    pub(crate) fn judges(self, verdict: &str) -> bool {
        if verdict == "census cap" && !self.reserves() {
            return false;
        }
        match self {
            Self::Restarts => true,
            Self::FalseSuspicion => !matches!(verdict, "volume kept" | "settle or blocker"),
            Self::HostLoss
            | Self::StoreUnknown(_)
            | Self::PageRegressed
            | Self::RecordRegressed
            | Self::PartitionLoss
            | Self::PartitionLossAt
            | Self::OwnerPause
            | Self::OwnerIsolation => verdict != "settle or blocker",
            Self::Settle | Self::Handoff | Self::HandoffEnded => {
                verdict != "volume kept" && verdict != "untouched shards"
            }
            Self::ImpairedBrief | Self::StandbySilent => verdict != "untouched shards",
            _ => true,
        }
    }

    /// The scenario's fault script. Every episode's scope names hosts by member index.
    pub(super) fn episodes(self, planted: bool) -> Vec<Episode> {
        let crash = |scope: Vec<usize>, trigger| Episode {
            trigger,
            scope,
            action: Action::Crash,
            heal: None,
        };
        let volume = |action, heal| Episode {
            trigger: Trigger::When(booted),
            scope: Vec::new(),
            action,
            heal,
        };
        let release = || Episode {
            trigger: Trigger::When(release_due),
            scope: Vec::new(),
            action: Action::Release(FAULTED),
            heal: None,
        };
        let zone_hosts: Vec<usize> =
            (0..super::topology::Placing::SMALL_PARTITIONS.len()).collect();
        let zone = |trigger| Episode {
            trigger,
            scope: zone_hosts.clone(),
            action: Action::Crash,
            heal: Some(ZONE_DOWN_ROUNDS),
        };
        let script = match self {
            Self::Restarts | Self::Settle => Vec::new(),
            Self::ZoneLoss => vec![zone(Trigger::When(booted))],
            Self::ZoneImpaired => {
                let impair = |at| Episode {
                    trigger: Trigger::When(|fleet| !fleet.zone_log.down.is_empty()),
                    scope: Vec::new(),
                    action: Action::Impair(at),
                    heal: Some(ZONE_DOWN_ROUNDS - 1),
                };
                let mut script = vec![zone(Trigger::When(booted))];
                script.extend((0..super::topology::Placing::SMALL.len()).map(impair));
                script
            }
            Self::ZoneDeposed => vec![
                Episode {
                    heal: Some(super::zones::DEPOSED_DOWN_ROUNDS),
                    ..crash(vec![FAULTED], Trigger::When(booted))
                },
                zone(Trigger::When(s3_taken_over)),
            ],
            Self::HostLoss
            | Self::StoreUnknown(_)
            | Self::PageRegressed
            | Self::RecordRegressed => {
                vec![crash(vec![0], Trigger::When(acknowledged_on_h0))]
            }
            Self::Reenroll | Self::SlotMoved => vec![crash(vec![0], Trigger::When(booted))],
            Self::StandbyLoss => vec![crash(vec![5], Trigger::When(booted))],
            Self::StandbySilent => vec![Episode {
                trigger: Trigger::When(booted),
                scope: vec![5],
                action: Action::Pause,
                heal: Some(PAUSE_ROUNDS),
            }],
            Self::DoubleLoss => vec![crash(vec![0, 3], Trigger::When(booted))],
            Self::PartitionRepair => vec![crash(vec![0, 1], Trigger::When(booted))],
            Self::PartitionRepairAt => vec![crash(
                super::topology::Placing::TRIO_LOST.to_vec(),
                Trigger::When(booted),
            )],
            Self::CensusFull => vec![
                crash(vec![4], Trigger::When(|fleet| s5_decided(fleet, 1))),
                crash(vec![3], Trigger::When(|fleet| s5_decided(fleet, 2))),
            ],
            Self::AttachSurvivor => vec![crash(vec![0, 5], Trigger::When(booted))],
            Self::AttachClosed => vec![crash(vec![0, 1, 5], Trigger::When(booted))],
            Self::Foreign => vec![Episode {
                trigger: Trigger::When(booted),
                scope: Vec::new(),
                action: Action::Register(0),
                heal: None,
            }],
            Self::Racing => vec![crash(vec![0], Trigger::When(booted))],
            Self::Crash(cell) if cell.fresh => vec![crash(vec![0, 3], Trigger::When(booted))],
            Self::Crash(_) => vec![crash(vec![1], Trigger::When(booted))],
            Self::Impaired => vec![
                volume(Action::Stall(FAULTED), Some(STALL_ROUNDS)),
                volume(Action::Impair(FAULTED), None),
            ],
            Self::ImpairedBrief => vec![
                volume(Action::Stall(FAULTED), Some(BRIEF_ROUNDS)),
                volume(Action::Impair(FAULTED), Some(IMPAIRED_ROUNDS)),
            ],
            Self::Stall => vec![volume(Action::Stall(FAULTED), Some(STALL_ROUNDS))],
            Self::LostAlone => vec![volume(Action::LoseVolume(FAULTED), None)],
            Self::Correlated => vec![
                volume(Action::Impair(BESIDE), None),
                volume(Action::LoseVolume(FAULTED), None),
                release(),
            ],
            Self::CorrelatedLate => vec![
                volume(Action::LoseVolume(FAULTED), None),
                Episode {
                    trigger: Trigger::When(|fleet| fleet.receipt_now(FAULTED).is_some()),
                    scope: Vec::new(),
                    action: Action::Impair(BESIDE),
                    heal: None,
                },
                release(),
            ],
            Self::Replace(_) => vec![volume(Action::LoseVolume(0), None)],
            Self::Handoff | Self::HandoffEnded => vec![Episode {
                trigger: Trigger::When(|fleet| {
                    booted(fleet) && fleet.cells[HANDOFF_CELL].waiting.is_some()
                }),
                scope: Vec::new(),
                action: Action::Handoff {
                    at: HANDOFF_CELL,
                    ended: self == Self::HandoffEnded,
                },
                heal: None,
            }],
            Self::PartitionLoss => vec![crash(vec![0, 1], Trigger::AtTime(1))],
            Self::PartitionLossAt => vec![crash(
                super::topology::Placing::TRIO_LOST.to_vec(),
                Trigger::AtTime(1),
            )],
            Self::FalseSuspicion => vec![Episode {
                trigger: Trigger::AtTime(1),
                scope: vec![3, 4, 5],
                action: Action::Drop(vec![0]),
                heal: Some(30),
            }],
            Self::OwnerPause => vec![Episode {
                trigger: Trigger::When(acknowledged_on_h0),
                scope: vec![0],
                action: Action::Pause,
                heal: Some(PAUSE_ROUNDS),
            }],
            Self::OwnerIsolation => vec![Episode {
                trigger: Trigger::When(acknowledged_on_h0),
                scope: vec![0],
                action: Action::Partition,
                heal: Some(PAUSE_ROUNDS),
            }],
        };
        let loss = |episode: &Episode| {
            matches!(episode.action, Action::Crash | Action::Pause)
                || episode.action == Action::Partition && episode.scope == [0]
        };
        (script.into_iter())
            .filter(|episode| !(planted && loss(episode)))
            .collect()
    }
}

/// s5's reservation refused `Full` `refusals` times, or a census lists s5 once H4 crashed `refusals - 1` times, and
/// every open loss has sent its drawn GETs, so no two episodes' GETs reach one peer together.
fn s5_decided(fleet: &Fleet<'_>, refusals: u32) -> bool {
    let s5 = fleet.cells[5].placement.shard;
    let listed = fleet
        .census_now(fleet.cells[5].placement.zone)
        .is_some_and(|census| census.slot(s5).is_some());
    let lost = u32::from(fleet.hosts[4].up == Up::Down);
    let sent = fleet.losses.iter().all(|loss| loss.episode.due.is_empty());
    sent && (fleet.recon.refused_full >= refusals || listed && lost + 1 >= refusals)
}

/// H0 holds s3 with its takeover's tenure swept, and every open loss has sent its drawn GETs.
fn s3_taken_over(fleet: &Fleet<'_>) -> bool {
    let cell = &fleet.cells[FAULTED];
    let sent = fleet.losses.iter().all(|loss| loss.episode.due.is_empty());
    sent && cell.holder == 0 && cell.recoveries.len() >= 2
}

/// The operator's release is due: [`RELEASE_ROUNDS`](super::volumes::RELEASE_ROUNDS) rounds after a replacement
/// receipt was first read held or a create step first refused `Held`, and, while neither happened,
/// [`UNHELD_ROUNDS`](super::volumes::UNHELD_ROUNDS) rounds after the injector's last volume fault. The second arm reads
/// the injector's state alone, so a run whose hold never latches still reaches its release and the
/// create-before-release rule judges the provider's calls.
fn release_due(fleet: &Fleet<'_>) -> bool {
    let volumes = &fleet.volumes;
    let (since, rounds) = match volumes.held_since {
        Some(held) => (Some(held), super::volumes::RELEASE_ROUNDS),
        None => (volumes.faulted_at, super::volumes::UNHELD_ROUNDS),
    };
    since.is_some_and(|since| fleet.round >= since + rounds)
}

/// Every owner acknowledged its workload and, in every zone, the census covered every live named standby or the
/// loop left its warm-up.
fn booted(fleet: &Fleet<'_>) -> bool {
    fleet.booted_all() && fleet.cells.iter().all(|cell| cell.acknowledged)
}

fn acknowledged_on_h0(fleet: &Fleet<'_>) -> bool {
    let mut owned = fleet
        .cells
        .iter()
        .filter(|cell| cell.holder == 0)
        .peekable();
    owned.peek().is_some() && owned.all(|cell| cell.acknowledged)
}

/// The detector bounds of every fleet agent at the fleet's time scale, with the agent's own self-suspicion threshold.
pub(crate) fn watch_bounds() -> WatchBounds {
    WatchBounds {
        detect: DetectBounds {
            h: H,
            d: 3,
            tau: 0,
            jitter: H / 2,
            peer_grace: 2 * H,
            exit_windows: 2,
            dwell: 3 * H,
            hosts: DETECT_HOSTS,
        },
        arbiter: ArbiterBounds {
            h: H,
            holder_grace: H / 2,
            k: 2,
            rounds: 3,
            clock_age: 100 * H,
            dwell: 2 * H,
            hosts: 8,
        },
        shards: 32,
        per_tick: 4,
        self_suspect: crate::host::agent::SELF_SUSPECT,
    }
}

pub(super) fn host_key(host: Host) -> [u8; 32] {
    let mut key = [0x5A; 32];
    key[..8].copy_from_slice(&host.get().to_le_bytes());
    key
}

type Outgoing = (Vec<(Host, Vec<u8>)>, Vec<(Host, [u8; probe::LEN])>);

fn count_u32(count: usize) -> u32 {
    u32::try_from(count).unwrap_or(u32::MAX)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Up {
    Running,
    Paused,
    Down,
}

pub(crate) struct HostActor {
    pub(crate) member: usize,
    pub(crate) host: Host,
    pub(crate) up: Up,
    pub(crate) boot: u8,
    pub(crate) agent: Option<Agent>,
    /// The shard records of the host's zone as the host last read them.
    pub(super) records: Vec<ShardRecord>,
    /// Whether the next turn passes the host's records and the zone's placement to the agent's sync.
    resync: bool,
    /// The heartbeats carried to the host, each with the round its agent reads it in.
    pub(super) inbox: Vec<(u64, Vec<u8>)>,
    probes: Vec<(u64, [u8; probe::LEN])>,
    /// Each process status the latest turn passed to the agent: its shard, volume, process id and phase.
    published: Vec<(crate::net::ownership::Shard, VolumeId, u32, OwnerPhase)>,
    /// The shards whose entry the host's last accepted report carried in phase `Held`.
    held: Vec<u32>,
    pub(super) log: MemLog,
}

impl HostActor {
    fn nonce(&self) -> [u8; 16] {
        let mut nonce = [0xB0; 16];
        nonce[0] = self.member as u8 + 1;
        nonce[1] = self.boot;
        nonce
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct HostLog {
    /// The nominations the agents' detectors published, read from each detector's publication count.
    pub(crate) nominations: u32,
    /// The nomination witnesses the agents addressed to standby processes, re-sends of a kept nomination included.
    pub(crate) addressed: u32,
    pub(crate) vetoes: u32,
    /// Probe requests that one prober answered ALIVE and another DEAD, counted as the probers sent the replies.
    pub(crate) contested: u32,
    pub(crate) repair_demands: u32,
    pub(crate) host_losses: u32,
    pub(crate) lapsed: u32,
    /// The reruns of an ended tenure that found no free tenure slot on their host and ran no incarnation.
    pub(crate) unslotted: u32,
    /// The reruns that ran no incarnation when their turn came: a serving tenure's rerun whose shard record named
    /// another owner or another tenure of its host, whose cell served a tenure, or whose host was down, and the
    /// rerun of an ended restart, takeover, standby wait or park whose host had stopped, already served the cell or
    /// had the cell's restart queued as its return. A paused host's rerun stays queued until the host resumes.
    pub(crate) rerun_dropped: u32,
    /// The next incarnations the host loop ran for a restart, takeover, held process, standby wait or park whose
    /// incarnation ended with an exit naming a rerun (`host::Exit::Rerun`, or a failed role read), each a role read
    /// and `host::recover`.
    pub(crate) refused_reruns: u32,
    /// The agent turns after which the observer's detector read a peer `Dead` with a failure that needs a second
    /// observer class (`Failure::Gray`), the evidence the arbiter declines with `GrayNeedsSecondClass` when every
    /// vote comes from one class.
    pub(crate) gray_readings: u32,
    /// Each observer host and the peer it read `Dead` with a gray failure, once a pair.
    pub(crate) gray: std::collections::BTreeSet<(u64, u64)>,
    pub(crate) takeovers: Vec<Attempt>,
    pub(crate) reports: u32,
    /// The inputs a host's own agent or the report reader refused: a heartbeat or a probe message the agent refused,
    /// a seal its writer refused and a sealed report the reader refused. A heartbeat refused `Sender` whose sender
    /// is a placed peer the receiver tracks no row for stays out, and so does a probe message that `stale_replies`
    /// or `unmatched_probes` counts.
    pub(crate) refused: u32,
    /// Probe replies a detector refused as stale.
    pub(crate) stale_replies: u32,
    /// Probe messages an agent refused as unmatched: a reply that matches no outstanding request to its sender
    /// (`Unrequested`) and a request whose suspect the receiver's detector tracks no row for (`Untracked`).
    pub(crate) unmatched_probes: u32,
    /// Each loss's drawn GETs as round offset, shard and object, in draw order.
    pub(crate) arrivals: Vec<(u64, u32, u8)>,
    /// The shards in their drawn boot order, and the round each episode fired at.
    pub(crate) boot: Vec<u32>,
    pub(crate) fired: Vec<Option<u64>>,
    pub(crate) exempt: BTreeSet<u32>,
    pub(crate) loads_beside_service: u32,
    /// GETs that a shard of a loading host served its object's bytes while that host's takeover load ran.
    pub(crate) served_beside_load: u32,
    pub(crate) twin_started: u32,
    /// Each deposed tenure's shard and the rounds from its host's resume to its withdrawal.
    pub(crate) withdrawals: Vec<(u32, u64)>,
    /// Deposed tenures still serving when the run ended.
    pub(crate) unwithdrawn: u32,
    /// GETs of an object an acknowledged INVALIDATE covered that a later tenure served its bytes.
    pub(crate) stale_hits: u32,
    /// Each change of a host's accepted sealed report in a volume entry's store watermark and counted unknown store
    /// results, a host's first entry of each shard included.
    pub(crate) stores: Vec<SealedStore>,
    /// Each change of a host's accepted report in its attachments, workers and recovery gauges: the round since the
    /// hosts started, the host and the three gauges, the host's first accepted report included.
    pub(crate) headrooms: Vec<(u64, u64, [Gauge; 3])>,
    /// Each start of a host's held entry: the round since the hosts started, the host and the shard, at the first
    /// accepted report of the host's boot that carries the shard's entry in phase `Held` after one that did not.
    pub(crate) held: Vec<(u64, u64, u32)>,
    pub(crate) handoffs: Vec<super::handoff::Handed>,
    pub(crate) parks: Vec<super::handoff::Park>,
    /// Each status a parked process published while its park stood: the round since the hosts started, the host and
    /// the shard. The `Withdrawn` the fleet publishes once for the ended wait's publication that stopped is the
    /// wait's and is not listed.
    pub(crate) parked_published: Vec<(u64, u64, u32)>,
    /// Each standby wait that read its host named owner, ended `Rerun::RoleChanged` and queued its process's next
    /// incarnation: the round since the hosts started, the shard and the host. A wait of a process whose next
    /// incarnation was already queued is not listed.
    pub(crate) role_changes: Vec<(u64, u32, u64)>,
}

/// One entry of [`HostLog::stores`]: the round since the hosts started, the host, the shard, and the entry's store
/// watermark and counted unknown store results.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SealedStore {
    pub(crate) round: u64,
    pub(crate) host: u64,
    pub(crate) shard: u32,
    pub(crate) watermark: report::Watermark,
    pub(crate) unknown: Option<u64>,
}

impl HostLog {
    /// `host`'s entries of [`HostLog::headrooms`] in order: the attachments, workers and recovery gauges of its
    /// first accepted report and of each later one that changed them.
    pub(crate) fn sealed(&self, host: u64) -> Vec<[Gauge; 3]> {
        (self.headrooms.iter())
            .filter(|(_, of, _)| *of == host)
            .map(|(_, _, gauges)| *gauges)
            .collect()
    }

    /// `host`'s entries of [`HostLog::stores`] for `shard`, in order.
    pub(crate) fn sealed_stores(
        &self,
        host: u64,
        shard: u32,
    ) -> impl Iterator<Item = &SealedStore> + Clone {
        (self.stores.iter()).filter(move |store| store.host == host && store.shard == shard)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Attempt {
    pub(crate) shard: u32,
    pub(crate) host: u64,
    /// The blocker a refused takeover names (`owners::blocker`: its refusal class's check, or its exit), or
    /// `Stopped` while the record names another owner, for a period that started no takeover or whose takeover
    /// refused with its compare-and-swap uncommitted and no device command issued; `None` once the takeover, or the
    /// next incarnation its refusal ended in, acquired a tenure. A takeover whose next incarnation refused too keeps
    /// its first refusal, whether or not its compare-and-swap committed; each record's version history holds every
    /// committed owner change.
    pub(crate) refused: Option<String>,
    /// The reservation commands the volume's table logged during the period, in order (`owners::commands_since`).
    pub(crate) commands: Vec<&'static str>,
}

pub(crate) const TAKEOVERS: &str = "witness takeovers missing";
pub(crate) const DUTY_RERUN: &str =
    "a store result with an unknown outcome ended the tenure's duties or reran its incarnation";
pub(crate) const ACK_BEFORE_COMMIT: &str =
    "a tenure acknowledged an INVALIDATE without a committed coverage write of its own";
pub(crate) const DUTY_FAULT: &str = "witness duty-store-fault missing";
pub(crate) const DUTY_EXIT: &str =
    "a tenure's serving duties ended at an exit its scenario does not script";
pub(crate) const DUTY_ACKNOWLEDGED: &str = "witness duty-acknowledged missing";
pub(crate) const UNKNOWN_REPORTED: &str = "witness unknown-store-result-reported missing";
pub(crate) const REGRESSION_WITHDRAWN: &str = "witness regression-withdrawn missing";
pub(crate) const REGRESSION_REPORTED: &str = "witness regression-alarm-reported missing";
pub(crate) const TAKEOVER_HOSTS: &str = "witness takeover-hosts missing";
pub(crate) const TWO_LOADS: &str = "witness two-loads-on-one-host missing";
pub(crate) const BESIDE_SERVICE: &str = "witness load-while-serving-own-shard missing";
pub(crate) const HOST_LOSSES: &str = "witness host-losses missing";
pub(crate) const PARTITION_LOST: &str = "witness partition-lost missing";
pub(crate) const REPAIR_DEMAND: &str = "witness repair-demand missing";
pub(crate) const VETO: &str = "witness veto missing";
pub(crate) const UNNAMED_SUCCESSOR: &str =
    "a lost shard recovered on a host other than its named standby";
pub(crate) const SUSPECT_TAKEOVER: &str =
    "an observer that a veto or its self-suspicion bars nominated or took a shard over";
pub(crate) const UNWITHDRAWN: &str = "a deposed owner kept serving to the end of the run";
pub(crate) const STALE_HIT: &str =
    "a later tenure served an object an acknowledged INVALIDATE covered";
pub(crate) const CHECKPOINT: &str = "a shard record dropped or replaced its named checkpoint";
pub(crate) const WITHDRAWN: &str = "witness withdrawn missing";
pub(crate) const REFUSED_INPUT: &str =
    "a detector, a report writer or the report reader refused a host's own input";
pub(crate) const OVER_ATTACHED: &str = "a volume record holds more live attaches than MAX_ATTACHED";
pub(crate) const UNRECORDED_ATTACH: &str =
    "an attach request preceded its attach record or a detach preceded its pair's drop";
pub(crate) const REWRITE: &str = "a reconciler's census write committed the census it found";
pub(crate) const STANDBY_LOSS_TAKEOVER: &str = "a shard whose owner survived was taken over";
pub(crate) const PROBER_PREMISE: &str = "premise prober-quorum missing";
pub(crate) const FULL_CENSUS: &str = "witness census-lists-every-shard missing";
pub(crate) const REENROLLED: &str = "witness reenrolled missing";
pub(crate) const REPLACED: &str = "witness standby-replaced missing";
pub(crate) const FRESH_HOSTS: &str = "witness fresh-hosts missing";
pub(crate) const SELF_SUSPECT: &str = "witness self-suspect-blockers missing";
pub(crate) const FIVE_DESIGNATIONS: &str = "witness five-designations missing";
pub(crate) const AT_CAP: &str = "witness census-at-cap missing";
pub(crate) const REFUSED_FULL: &str = "witness refused-full missing";
pub(crate) const REDESIGNATED: &str = "witness redesignated-attached-host missing";
pub(crate) const ATTACH_CLOSED: &str = "witness attach-ended missing";
pub(crate) const RETIREMENT: &str = "witness retirement-requested missing";
pub(crate) const CONDITION: &str = "witness census-write-refused-condition missing";
pub(crate) const STALE_DESIGNATION: &str = "witness stale-designation-refused missing";
pub(crate) const CRASH_CELL: &str = "witness crash-cell missing";
pub(crate) const VOLUME_STALLED: &str = "witness volume-stalled missing";
pub(crate) const STALLED_TAKEOVER: &str = "witness takeovers-of-stalled-shard missing";
pub(crate) const NO_TAKEOVER: &str = "witness stall-with-no-takeover missing";
pub(crate) const IMPAIRED: &str = "witness volume-impaired-blocker missing";
pub(crate) const DEVICE_HOLD: &str = "witness device-failure-hold missing";
pub(crate) const RESTART_AFTER_STALL: &str = "witness restart-after-stall missing";
pub(crate) const WARM_AFTER_STALL: &str = "witness warm-after-stall missing";
pub(crate) const VOLUME_LOST: &str = "witness volume-lost missing";
pub(crate) const FLIPS: &str = "witness flips missing";
pub(crate) const COLD_START: &str = "witness cold-start missing";
pub(crate) const HOLD_LATCHED: &str = "witness hold-latched missing";
pub(crate) const LATCHED_AT_CREATE: &str = "witness hold-latched-at-create missing";
pub(crate) const HOLD_RELEASED: &str = "witness hold-released missing";
pub(crate) const MOVED_TWICE: &str = "a shard on a stalled volume changed hands more than once";
pub(crate) const HEALTHY_MOVED: &str = "a shard whose volume is healthy changed hands";
pub(crate) const WAIT_DEVICE: &str = "a standby wait held a device";
/// The name of a host loop's horizon stall that [`Fleet::unsent`] attributes to a standby's wait.
pub(crate) const RESEND: &str =
    "a kept nomination was not sent again while its target stayed in the records";
/// The rounds without a witness after which [`Fleet::unsent`] names a waiting standby. The agents' window is one
/// round, and in the host-loss case with a store timeout on a takeover the agents address the waiting standby a
/// witness in four rounds of five, so the longest gap between two witnesses there is two rounds.
pub(crate) const RESEND_WINDOWS: u64 = 16;
pub(crate) const SECOND_VOLUME: &str = "a replacement receipt's create made a second volume";
pub(crate) const UNPROVIDED: &str =
    "a replacement receipt records a volume the provider did not make for its token";
pub(crate) const CREATE_BEFORE_RELEASE: &str =
    "a create reached the provider before the operator released the correlated hold";
pub(crate) const STRANDED: &str =
    "a volume no shard record names stayed active with no crash after its flip";
pub(crate) const DISPLACED_STRANDED: &str = "witness displaced-volume-stranded missing";
pub(crate) const AZ_DOWN: &str = "witness az-down missing";
pub(crate) const AZ_RESTARTS: &str = "witness az-restarts missing";
pub(crate) const FENCE_CHECKED: &str = "witness fence-before-admission checked missing";
pub(crate) const AZ_IMPAIRED: &str = "witness az-volumes-retained missing";
pub(crate) const AZ_DEPOSED: &str = "witness az-deposed missing";
pub(crate) const AZ_ACKNOWLEDGED: &str = "witness az-acknowledged missing";
pub(crate) const DOWN_ZONE_WRITE: &str =
    "a shard record, volume record or receipt of a zone with every host stopped was written";
pub(crate) const OTHER_ZONE: &str =
    "a zone loss changed another zone's shard record, volume record, census or tenure";
pub(crate) const DEPOSED_SERVED: &str = "a deposed host served after its zone returned";
pub(crate) const NO_BUMP: &str = "a returning owner restarted without an attempt bump";
pub(crate) const COLD_RETURN: &str = "a returning owner did not serve its retained set warm";
pub(crate) const HANDED_OFF: &str = "witness handoff-committed missing";
pub(crate) const TARGET_SERVED: &str = "witness target-lineage-served missing";
pub(crate) const TARGET_PARKED: &str = "witness target-parked missing";
pub(crate) const FRESH_DESIGNATED: &str = "witness fresh-host-designated missing";
pub(crate) const DESIGNATED_RECOVERED: &str = "witness designated-host-recovered missing";
pub(crate) const PARKED_DEVICE: &str =
    "a restart that refused its ended attach issued a reservation command";
pub(crate) const PARKED_STATUS: &str = "a parked process published a status";

/// The outcomes every zone scenario requires of its [`ZoneLog`](super::zones::ZoneLog): the outage wrote nothing for
/// the down zone and called no provider, changed nothing in another zone, each returning owner's tenure is one
/// attempt above the shard record its restart read and served its whole retained set, and no restart of a host
/// whose record named another owner returned a session.
fn zone_outcome(report: &super::Report) -> Option<super::Verdict> {
    use super::Verdict;
    let zones = &report.zones;
    if zones.down_writes + zones.down_calls > 0 {
        let at = format!("{} writes, {} calls", zones.down_writes, zones.down_calls);
        return Some(Verdict::Fail(DOWN_ZONE_WRITE, at));
    }
    if !zones.other_moved.is_empty() || !zones.other_censuses.is_empty() {
        let at = format!(
            "shards {:?} censuses {:?}",
            zones.other_moved, zones.other_censuses
        );
        return Some(Verdict::Fail(OTHER_ZONE, at));
    }
    for &(shard, host, tenure, from) in &zones.restarts {
        let recoveries = &report.shards[shard as usize - 1].recoveries;
        let at = recoveries.iter().rposition(|r| r.tenure == tenure);
        if at.is_none() || tenure.a != (u64::from(from) + 1) * 2 {
            return Some(Verdict::Fail(NO_BUMP, format!("shard {shard} host {host}")));
        }
        let swept = at.and_then(|at| recoveries[at].sweep);
        if swept.is_none_or(|(eligible, served)| eligible == 0 || served != eligible) {
            return Some(Verdict::Fail(
                COLD_RETURN,
                format!("shard {shard} swept {swept:?}"),
            ));
        }
    }
    let served = zones.deposed.iter();
    if let Some((shard, host, ..)) = served
        .into_iter()
        .find(|(.., check, _)| check == super::zones::RESTARTED)
    {
        return Some(Verdict::Fail(
            DEPOSED_SERVED,
            format!("shard {shard} host {host}"),
        ));
    }
    None
}

/// The returning tenures the fence-before-admission check judged: those with a logged first admission.
fn fence_checked(report: &super::Report) -> usize {
    let admitted = |shard: u32, tenure: Tenure| {
        let admissions = report.evidence.admissions.iter();
        admissions
            .into_iter()
            .any(|of| of.shard.get() == shard && of.tenure == tenure)
    };
    let returned = report.zones.restarts.iter();
    returned
        .filter(|&&(shard, _, tenure, _)| admitted(shard, tenure))
        .count()
}

pub(crate) const PROVISIONED: &str = "a host loss made a create call on the provider double";

/// Whether a reconciler run with no volume lost by the injector called the zone doubles' provider: LOSS-NEEDS-EVIDENCE
/// read on the provider double itself, beside fleet oracle F2's reading of the records and receipts.
fn config_provisions(report: &super::Report) -> bool {
    report.config.scenario.repairs() && report.volumes.lost.is_empty() && report.volumes.calls > 0
}

pub(crate) const CONTENDED: &str = "witness second-reconciler-after-loss missing";
pub(crate) const SLOT_MOVED: &str = "witness slot-moved-inside-designation missing";
pub(crate) const FIXPOINT: &str = "a settled zone's loop made a store write or a mutating call";
pub(crate) const FIXPOINT_TICKS: &str = "witness ticks-after-settle missing";
pub(crate) const SILENT_MOVED: &str =
    "a census slot or a shard record of a silent host whose instance runs changed";
pub(crate) const SILENT_WINDOW: &str = "witness silent-past-the-window missing";
pub(crate) const SEALED_RECORDS: &str = "witness sealed-reports-and-statuses missing";

/// The first exit a tenure's serving duties named that its scenario does not script, as a failed verdict. A
/// deposition's exit (`Deposed`, or `Rerun(RecordedHolder)` from the successor's reservation) of a tenure a later
/// tenure of its shard superseded is scripted; so are
/// `Rerun(Withdrawn)` of a regression scenario's faulted boot tenure of [`DUTY_CELL`] and the `Retire` of s0's
/// tenure when the foreign registrant's Report triggers its retirement, and `Stopped` of the outgoing tenure whose
/// planned handoff committed and whose `serve::ended` named `Stopped`. Any other exit of a shard's last tenure
/// fails, whatever the tenure's authority reads.
pub(crate) fn unscripted_exit(report: &super::Report) -> Option<super::Verdict> {
    let regressed = matches!(
        report.config.scenario,
        Scenario::PageRegressed | Scenario::RecordRegressed
    );
    let faulted = report.duties.faulted.as_ref().map(|faulted| faulted.tenure);
    let withdrawn = crate::host::Exit::Rerun(crate::host::Rerun::Withdrawn);
    let shard = DUTY_SHARD;
    let last = |at: u32| {
        let (_, history) = (report.evidence.histories.iter()).find(|(of, _)| of.get() == at)?;
        let record = history.last()?;
        Some((record.generation.get(), u64::from(record.attempts) * 2))
    };
    let (at, tenure, exit) = report.duties.exits.iter().find(|(at, tenure, exit)| {
        let regression =
            regressed && *at == shard && Some(*tenure) == faulted && *exit == withdrawn;
        let foreign = report.config.scenario == Scenario::Foreign
            && *at == 1
            && matches!(exit, crate::host::Exit::Retire(_));
        let handed = *exit == crate::host::Exit::Stopped
            && (report.hosts.handoffs.iter()).any(|handed| {
                handed.shard == *at
                    && handed.tenure == *tenure
                    && handed.committed
                    && handed.exit == Some(crate::host::Exit::Stopped)
            });
        let scripted = regression || foreign || handed;
        let deposition = matches!(
            exit,
            crate::host::Exit::Deposed
                | crate::host::Exit::Rerun(crate::host::Rerun::RecordedHolder)
        );
        let superseded = deposition && last(*at).is_some_and(|named| (tenure.g, tenure.a) < named);
        !superseded && !scripted
    })?;
    let at = format!("shard {at} tenure {tenure:?} exit {exit:?}");
    Some(super::Verdict::Fail(DUTY_EXIT, at))
}

/// The scenario's required outcome and witnesses: `Fail` for a required outcome the run broke, then `Unrun` for
/// the first witness the run did not reach.
pub(crate) fn expected(report: &super::Report) -> super::Verdict {
    use super::Verdict;
    let log = &report.hosts;
    let taken: Vec<(u32, u64)> = (log.takeovers.iter())
        .filter(|attempt| attempt.refused.is_none())
        .map(|attempt| (attempt.shard, attempt.host))
        .collect();
    let hosts: BTreeSet<u64> = taken.iter().map(|(_, host)| *host).collect();
    let twice = (hosts.iter()).any(|host| taken.iter().filter(|(_, of)| of == host).count() >= 2);
    for (shard, versions) in &report.evidence.histories {
        // Inside one generation a takeover moves the shard to the standby its record names; a flip moves it to the
        // host of the spare its record names.
        let unnamed = versions.windows(2).find(|pair| {
            let named = if pair[0].generation == pair[1].generation {
                pair[0].standby
            } else {
                pair[0].spare.map(|(_, host)| host)
            };
            pair[0].owner != pair[1].owner && named != Some(pair[1].owner)
        });
        if let Some(pair) = unnamed {
            let at = format!("shard {} on host {}", shard.get(), pair[1].owner.get());
            return Verdict::Fail(UNNAMED_SUCCESSOR, at);
        }
    }
    if let Some((shard, attached)) = (report.evidence.attached.iter())
        .find(|(_, attached)| *attached > crate::failover::records::MAX_ATTACHED)
    {
        let at = format!("shard {} holds {attached}", shard.get());
        return Verdict::Fail(OVER_ATTACHED, at);
    }
    if report.recon.unordered > 0 {
        let at = format!("{} requests", report.recon.unordered);
        return Verdict::Fail(UNRECORDED_ATTACH, at);
    }
    if config_provisions(report) {
        let at = format!("{} create calls", report.volumes.calls);
        return Verdict::Fail(PROVISIONED, at);
    }
    if let Some((writes, calls)) = report.recon.breach.or(report.recon.after_settle)
        && writes + calls > 0
    {
        let at = format!("{writes} writes, {calls} calls");
        return Verdict::Fail(FIXPOINT, at);
    }
    if report.recon.rewrites > 0 {
        return Verdict::Fail(REWRITE, format!("{} writes", report.recon.rewrites));
    }
    if log.unwithdrawn > 0 {
        return Verdict::Fail(UNWITHDRAWN, format!("{} tenures", log.unwithdrawn));
    }
    if log.stale_hits > 0 {
        return Verdict::Fail(STALE_HIT, format!("{} GETs", log.stale_hits));
    }
    for (shard, versions) in &report.evidence.histories {
        let changed = versions.first().is_some_and(|seed| {
            let mut seeded = versions.iter().filter(|r| r.generation == seed.generation);
            seeded.any(|record| record.checkpoint != seed.checkpoint)
        });
        if changed {
            return Verdict::Fail(CHECKPOINT, format!("shard {}", shard.get()));
        }
    }
    if log.refused > 0 {
        return Verdict::Fail(REFUSED_INPUT, format!("{} refused", log.refused));
    }
    let ended = crate::host::Exit::Refused(crate::host::Refusal::Restart(
        crate::failover::restart::Check::Local(crate::failover::restart::Local::Ended),
    ));
    if let Some(park) =
        (log.parks.iter()).find(|park| park.exit == ended && !park.commands.is_empty())
    {
        let at = format!(
            "shard {} host {}: {:?}",
            park.shard, park.host, park.commands
        );
        return Verdict::Fail(PARKED_DEVICE, at);
    }
    if let Some((round, host, shard)) = log.parked_published.first() {
        let at = format!("shard {shard} host {host} round {round}");
        return Verdict::Fail(PARKED_STATUS, at);
    }
    let config = report.config;
    let scenario = config.scenario;
    let silent = matches!(
        scenario,
        Scenario::FalseSuspicion | Scenario::PartitionLossAt
    );
    if silent && (!taken.is_empty() || log.nominations > 0) {
        let at = format!("{} nominations, {} takeovers", log.nominations, taken.len());
        return Verdict::Fail(SUSPECT_TAKEOVER, at);
    }
    let recon = &report.recon;
    if let Some(faulted) = &report.duties.faulted {
        let shard = DUTY_SHARD;
        let ended = (report.duties.exits.iter())
            .any(|(at, tenure, _)| *at == shard && *tenure == faulted.tenure);
        let unknown = matches!(scenario, Scenario::StoreUnknown(_));
        if unknown && (ended || faulted.recoveries != 1) {
            let at = format!(
                "shard {shard} exits {:?} recoveries {}",
                report.duties.exits, faulted.recoveries
            );
            return Verdict::Fail(DUTY_RERUN, at);
        }
        // Over a regressed coverage read the tenure acknowledges nothing; otherwise it acknowledges after a commit.
        let page_regressed = scenario == Scenario::PageRegressed;
        if let Some(acknowledged_at) = faulted.acknowledged_at
            && (acknowledged_at <= faulted.held_at || page_regressed)
        {
            let at = format!(
                "shard {shard} page commits {} at hold, {acknowledged_at} at ack",
                faulted.held_at
            );
            return Verdict::Fail(ACK_BEFORE_COMMIT, at);
        }
    }
    if scenario == Scenario::PartitionRepairAt {
        let s2 = (recon.designations.iter()).find(|d| d.shard == 3 && d.after_loss);
        // `Fleet::turn` calls `host_round` before `reconcile_round`, so a nomination stamped with the designation's
        // round was published before the designation.
        let early = match (recon.first_nomination, s2) {
            (Some(nominated), Some(designated)) => nominated <= designated.round,
            (Some(_), None) => true,
            (None, _) => false,
        };
        if early {
            let at = format!("first nomination at round {:?}", recon.first_nomination);
            return Verdict::Fail(SUSPECT_TAKEOVER, at);
        }
    }
    let census_versions = report.evidence.censuses.len();
    if config.scenario == Scenario::StandbySilent
        && (!recon.designations.is_empty() || census_versions > 1)
    {
        let at = format!(
            "{} designations, {census_versions} census versions",
            recon.designations.len()
        );
        return Verdict::Fail(SILENT_MOVED, at);
    }
    let standby_only = match scenario {
        Scenario::StandbyLoss | Scenario::StandbySilent => true,
        Scenario::Crash(cell) => !cell.fresh,
        _ => false,
    };
    if standby_only && !taken.is_empty() {
        let at = format!("{} takeovers", taken.len());
        return Verdict::Fail(STANDBY_LOSS_TAKEOVER, at);
    }
    if scenario.repairs() && recon.premise_failed {
        return Verdict::Unrun(PROBER_PREMISE);
    }
    let after_loss = |repair| {
        let designated = recon.designations.iter();
        designated
            .filter(|d| d.after_loss && d.repair == repair)
            .count()
    };
    let needed = after_loss(Repair::Need(Need::Standby)) + after_loss(Repair::Need(Need::Fresh));
    let fresh_hosts = (taken.iter())
        .filter(|(shard, host)| {
            (recon.designations.iter()).any(|d| {
                d.shard == *shard && d.host == *host && d.repair == Repair::Need(Need::Fresh)
            })
        })
        .count();
    let blocked = |blocker| {
        (recon.blockers.iter())
            .filter(|(_, _, b, _)| *b == blocker)
            .count()
    };
    let census = report.evidence.census_entries;
    let volumes = &report.volumes;
    let moved = |shard: u32| {
        let (_, versions) = &report.evidence.histories[shard as usize - 1];
        let changes = versions.windows(2).filter(|pair| {
            pair[0].generation == pair[1].generation && pair[0].owner != pair[1].owner
        });
        changes.count()
    };
    if let Some(&shard) = volumes.stalled.iter().find(|&&shard| moved(shard) > 1) {
        let at = format!("shard {shard} moved {} times", moved(shard));
        return Verdict::Fail(MOVED_TWICE, at);
    }
    // A waiting phase holds no device: a standby wait that ended `Exit::Fault` held one.
    if let Some(shard) = (report.shards.iter()).position(|shard| {
        shard
            .wait_exits
            .iter()
            .any(|exit| exit.starts_with("Fault"))
    }) {
        return Verdict::Fail(WAIT_DEVICE, format!("shard {}", shard + 1));
    }
    // The host health rule: in a stall scenario no host fails, so only a shard of a stalled volume
    // may change hands; a held process makes its host unhealthy only for a shard that names a standby elsewhere.
    // A log with no stalled volume reads the scenario's stall witness missing instead.
    let stall_only = matches!(
        report.config.scenario,
        Scenario::Stall | Scenario::Impaired | Scenario::ImpairedBrief
    ) && !volumes.stalled.is_empty();
    let shards = 1..=report.evidence.histories.len() as u32;
    let healthy = |shard: &u32| !volumes.stalled.contains(shard) && !volumes.lost.contains(shard);
    if stall_only && let Some(shard) = shards.filter(healthy).find(|&shard| moved(shard) > 0) {
        let at = format!("shard {shard} moved {} times", moved(shard));
        return Verdict::Fail(HEALTHY_MOVED, at);
    }
    if volumes.made > volumes.lost.len() {
        let at = format!("{} volumes for {} lost", volumes.made, volumes.lost.len());
        return Verdict::Fail(SECOND_VOLUME, at);
    }
    let unprovided = report.evidence.receipts.iter().flatten().find(|receipt| {
        let Phase::Created(volume) = receipt.phase else {
            return false;
        };
        !volumes.provided.contains(&(receipt.token(), volume))
    });
    if let Some(receipt) = unprovided {
        let at = format!("shard {}", receipt.request.shard.get());
        return Verdict::Fail(UNPROVIDED, at);
    }
    if volumes.calls_at_release.is_some_and(|calls| calls > 0) {
        let at = format!("{:?} calls", volumes.calls_at_release);
        return Verdict::Fail(CREATE_BEFORE_RELEASE, at);
    }
    // A crash cell whose flip landed strands the volume the flip displaced, the lost shard's first active volume.
    // A completed replacement retires the volume it displaces.
    let displaced = match scenario {
        Scenario::Replace(cell) if cell.strands() => (volumes.lost.first())
            .and_then(|&shard| report.evidence.histories[shard as usize - 1].1.first())
            .map(|seeded| seeded.active),
        _ => None,
    };
    let stranded = (volumes.stranded.iter()).find(|&&volume| Some(volume) != displaced);
    if let Some(volume) = stranded {
        return Verdict::Fail(STRANDED, format!("volume {}", volume.as_str()));
    }
    let stalled_moves = volumes.stalled.first().map(|&shard| moved(shard));
    let warm = |shard: u32| {
        let recoveries = &report.shards[shard as usize - 1].recoveries;
        let swept = |r: &Recovered| {
            r.after_crash && r.sweep.is_some_and(|(of, served)| of > 0 && of == served)
        };
        recoveries.iter().any(swept)
    };
    // The successor's restart after the stall: the shard's last recovery is by a host other than its first owner
    // and its sweep received every object.
    let succeeded = |shard: u32| {
        let (_, versions) = &report.evidence.histories[shard as usize - 1];
        let last = report.shards[shard as usize - 1].recoveries.last();
        (versions.first().zip(last)).is_some_and(|(first, last)| {
            last.host != first.owner
                && last
                    .sweep
                    .is_some_and(|(of, served)| of > 0 && of == served)
        })
    };
    let replaced = vec![
        (volumes.lost.len() == 1, VOLUME_LOST),
        (report.evidence.replaced == [(1, 1)], FLIPS),
        (volumes.cold.len() == 1, COLD_START),
    ];
    if let Some(failed) = zone_outcome(report) {
        return failed;
    }
    let zones = &report.zones;
    let down = super::topology::Placing::SMALL.len();
    let returned = vec![
        (zones.restarts.len() == down, AZ_RESTARTS),
        (zones.acknowledged as usize == down, AZ_ACKNOWLEDGED),
        (fence_checked(report) == down, FENCE_CHECKED),
    ];
    let suspected: BTreeSet<u32> = (recon.blockers.iter())
        .filter(|(_, _, blocker, _)| *blocker == Blocker::SelfSuspect)
        .map(|(_, shard, ..)| *shard)
        .collect();
    let witnesses: Vec<(bool, &'static str)> = match scenario {
        Scenario::Restarts => Vec::new(),
        Scenario::Settle => vec![
            (census == report.shards.len(), FULL_CENSUS),
            (
                recon.fixpoint_ticks >= super::reconcile::FIXPOINT_TICKS,
                FIXPOINT_TICKS,
            ),
        ],
        Scenario::StandbySilent => {
            let silent = u64::from(recon.paused_ticks) * super::reconcile::TICK_ROUNDS;
            vec![(silent >= super::reconcile::AGE_ROUNDS, SILENT_WINDOW)]
        }
        Scenario::Reenroll => vec![(taken.len() >= 3, TAKEOVERS), (needed >= 4, REENROLLED)],
        Scenario::SlotMoved => vec![(recon.slot_moved.is_some(), SLOT_MOVED)],
        Scenario::StandbyLoss => vec![(after_loss(Repair::Need(Need::Standby)) >= 1, REPLACED)],
        Scenario::DoubleLoss => vec![(fresh_hosts >= 2, FRESH_HOSTS)],
        Scenario::PartitionRepairAt => vec![
            (suspected == BTreeSet::from([1, 2]), SELF_SUSPECT),
            (taken.len() >= 2, TAKEOVERS),
        ],
        Scenario::PartitionRepair => vec![
            (taken.len() >= 3, TAKEOVERS),
            (needed >= 5, FIVE_DESIGNATIONS),
        ],
        Scenario::CensusFull => vec![
            (recon.at_cap >= 1, AT_CAP),
            (recon.refused_full >= 2, REFUSED_FULL),
            (fresh_hosts >= 1, FRESH_HOSTS),
        ],
        Scenario::AttachSurvivor => {
            let again = (recon.designations.iter())
                .any(|d| d.attached && d.after_loss && d.repair == Repair::Need(Need::Fresh));
            vec![(again, REDESIGNATED)]
        }
        Scenario::AttachClosed => {
            let shard = ATTACH_CELL as u32 + 1;
            let ended = recon.reclaims.contains(&(shard, Reclaim::End));
            vec![(ended, ATTACH_CLOSED)]
        }
        Scenario::Foreign => vec![(blocked(Blocker::RetirementRequested) >= 1, RETIREMENT)],
        Scenario::Racing => vec![
            (recon.condition >= 1, CONDITION),
            (recon.stale() >= 1, STALE_DESIGNATION),
            (recon.contended >= 1, CONTENDED),
        ],
        Scenario::Crash(_) => vec![(!recon.crashed.is_empty(), CRASH_CELL)],
        Scenario::Impaired => vec![
            (volumes.stalled.len() == 1, VOLUME_STALLED),
            (blocked(Blocker::VolumeImpaired) >= 1, IMPAIRED),
            (stalled_moves == Some(1), STALLED_TAKEOVER),
            (
                volumes.stalled.iter().all(|&shard| succeeded(shard)),
                RESTART_AFTER_STALL,
            ),
        ],
        Scenario::ImpairedBrief => vec![
            (volumes.stalled.len() == 1, VOLUME_STALLED),
            (blocked(Blocker::VolumeImpaired) >= 1, IMPAIRED),
            (stalled_moves == Some(0), NO_TAKEOVER),
            (
                volumes.stalled.iter().all(|&shard| warm(shard)),
                WARM_AFTER_STALL,
            ),
        ],
        Scenario::Stall => vec![
            (volumes.stalled.len() == 1, VOLUME_STALLED),
            (stalled_moves == Some(1), STALLED_TAKEOVER),
            (blocked(Blocker::DeviceFailureHold) >= 1, DEVICE_HOLD),
        ],
        Scenario::LostAlone => replaced,
        Scenario::Correlated => {
            let mut witnesses = replaced;
            witnesses.push((volumes.latched == 1, HOLD_LATCHED));
            witnesses.push((volumes.released == 1, HOLD_RELEASED));
            witnesses
        }
        Scenario::CorrelatedLate => {
            let mut witnesses = replaced;
            witnesses.push((volumes.latched_at_create == 1, LATCHED_AT_CREATE));
            witnesses.push((volumes.released == 1, HOLD_RELEASED));
            witnesses
        }
        Scenario::Replace(cell) => {
            let mut witnesses = replaced;
            witnesses.push((!volumes.crashed.is_empty(), CRASH_CELL));
            if cell.strands() {
                let listed = displaced.is_some_and(|volume| volumes.stranded == [volume]);
                witnesses.push((listed, DISPLACED_STRANDED));
            }
            witnesses
        }
        Scenario::ZoneLoss => {
            let mut witnesses = vec![(zones.returned && zones.unplaced.len() == down, AZ_DOWN)];
            witnesses.extend(returned);
            witnesses
        }
        Scenario::ZoneImpaired => {
            let retained = volumes.retained as usize == down && zones.impaired.len() == down;
            let mut witnesses = vec![(zones.returned, AZ_DOWN), (retained, AZ_IMPAIRED)];
            witnesses.extend(returned);
            witnesses
        }
        Scenario::ZoneDeposed => {
            let mut witnesses = vec![(zones.returned, AZ_DOWN)];
            witnesses.extend(returned);
            let refused = (zones.deposed.iter()).any(|(.., check, _)| super::zones::deposed(check));
            witnesses.push((refused, AZ_DEPOSED));
            witnesses
        }
        Scenario::OwnerPause | Scenario::OwnerIsolation => vec![
            (taken.len() >= 3, TAKEOVERS),
            (log.withdrawals.len() >= 3, WITHDRAWN),
        ],
        Scenario::StoreUnknown(_) | Scenario::PageRegressed | Scenario::RecordRegressed => {
            let faulted = report.duties.faulted.as_ref();
            let shard = DUTY_SHARD;
            let host = DUTY_HOST;
            let reported =
                |of: &dyn Fn(&SealedStore) -> bool| log.sealed_stores(host, shard).any(of);
            let cause = crate::failover::serving::Cause::Regression;
            let regressed = report.duties.exits.iter().any(|(at, tenure, exit)| {
                *at == shard
                    && faulted.is_some_and(|f| f.tenure == *tenure && f.withdrawal == Some(cause))
                    && *exit == crate::host::Exit::Rerun(crate::host::Rerun::Withdrawn)
            });
            // The cell's write took the timeout, and a regression scenario's duties store served its stale read.
            let faulted_write = match scenario {
                Scenario::StoreUnknown(cell) => Some(cell.write),
                Scenario::PageRegressed => Some(DutyWrite::Page),
                _ => None,
            };
            let stale = matches!(
                scenario,
                Scenario::PageRegressed | Scenario::RecordRegressed
            );
            let fault = faulted.is_some_and(|f| {
                f.taken && f.timed_out == faulted_write && (f.stale_served || !stale)
            });
            let mut witnesses = vec![(taken.len() >= 3, TAKEOVERS), (fault, DUTY_FAULT)];
            match scenario {
                Scenario::PageRegressed => witnesses.push((regressed, REGRESSION_WITHDRAWN)),
                Scenario::RecordRegressed => {
                    witnesses.push((regressed, REGRESSION_WITHDRAWN));
                    let alarmed =
                        reported(&|store| store.watermark == report::Watermark::Regression);
                    witnesses.push((alarmed, REGRESSION_REPORTED));
                }
                _ => {
                    let acknowledged = faulted.is_some_and(|f| f.acknowledged_at.is_some());
                    witnesses.push((acknowledged, DUTY_ACKNOWLEDGED));
                    let counted = reported(&|store| store.unknown.is_some_and(|count| count > 0));
                    witnesses.push((counted, UNKNOWN_REPORTED));
                }
            }
            witnesses
        }
        Scenario::HostLoss => vec![
            (taken.len() >= 3, TAKEOVERS),
            (hosts.len() >= 2, TAKEOVER_HOSTS),
            (twice, TWO_LOADS),
            (
                log.loads_beside_service >= 1 && log.served_beside_load >= 1,
                BESIDE_SERVICE,
            ),
            (log.host_losses >= 1, HOST_LOSSES),
        ],
        Scenario::PartitionLossAt => vec![
            (log.host_losses >= 3, PARTITION_LOST),
            (log.repair_demands >= 1, REPAIR_DEMAND),
        ],
        Scenario::PartitionLoss => vec![
            (log.host_losses >= 2, PARTITION_LOST),
            (taken.len() >= 3, TAKEOVERS),
        ],
        Scenario::FalseSuspicion => vec![(log.vetoes >= 1 && log.contested >= 1, VETO)],
        Scenario::Handoff | Scenario::HandoffEnded => handed_off(report),
    };
    match witnesses.into_iter().find(|(reached, _)| !reached) {
        Some((_, missing)) => Verdict::Unrun(missing),
        None => Verdict::Pass,
    }
}

fn handed_off(report: &super::Report) -> Vec<(bool, &'static str)> {
    let log = &report.hosts;
    let ended = report.config.scenario == Scenario::HandoffEnded;
    let Some(handed) = (log.handoffs.iter()).find(|handed| {
        handed.committed && handed.ended == ended && handed.exit == Some(crate::host::Exit::Stopped)
    }) else {
        return vec![(false, HANDED_OFF)];
    };
    let shard = handed.shard;
    let last = report.shards[shard as usize - 1].recoveries.last();
    // The recovery is a later tenure than the outgoing one.
    let full = |host: u64| {
        last.is_some_and(|last| {
            last.host.get() == host
                && (last.tenure.g, last.tenure.a) > (handed.tenure.g, handed.tenure.a)
                && last
                    .sweep
                    .is_some_and(|(of, served)| of > 0 && of == served)
        })
    };
    if !ended {
        let changed =
            (log.role_changes.iter()).any(|&(_, of, host)| of == shard && host == handed.to);
        let arm =
            (report.volumes.arm.iter()).any(|&(of, host, _)| of == shard && host == handed.to);
        return vec![
            (true, HANDED_OFF),
            (changed && arm && full(handed.to), TARGET_SERVED),
        ];
    }
    let parked = log.parks.iter().any(|park| {
        park.shard == shard
            && park.host == handed.to
            && park.exit
                == crate::host::Exit::Refused(crate::host::Refusal::Restart(
                    crate::failover::restart::Check::Local(crate::failover::restart::Local::Ended),
                ))
            && park.left.as_ref().is_some_and(|(_, exit)| {
                *exit == Some(crate::host::Exit::Rerun(crate::host::Rerun::RoleChanged))
            })
    });
    let designated: Vec<u64> = (report.recon.designations.iter())
        .filter(|d| {
            d.shard == shard && d.host != handed.to && d.repair == Repair::Need(Need::Fresh)
        })
        .map(|d| d.host)
        .collect();
    let recovered = designated.iter().any(|&host| {
        let taken = (log.takeovers.iter()).any(|attempt| {
            attempt.shard == shard && attempt.host == host && attempt.refused.is_none()
        });
        taken && full(host)
    });
    vec![
        (true, HANDED_OFF),
        (parked, TARGET_PARKED),
        (!designated.is_empty(), FRESH_DESIGNATED),
        (log.nominations > 0 && recovered, DESIGNATED_RECOVERED),
    ]
}

/// What ends the cause of a loss. A loss whose cause ended closes once its GETs drained and a tenure whose host
/// runs serves each lost shard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Ends {
    /// A crash or a pause: a serving tenure on a running host ends the loss of its shard.
    Hosts,
    /// A cut that heals at this round.
    Heal(u64),
    /// A cut with no heal: a tenure other than the one the shard held at the cut ends the loss of that shard.
    Takeover,
}

impl Ends {
    /// Whether the cause ended by `round`. `moved` tells whether a tenure other than the held one serves each
    /// lost shard.
    pub(super) fn reached(self, round: u64, moved: bool) -> bool {
        match self {
            Self::Hosts => true,
            Self::Heal(at) => round >= at,
            Self::Takeover => moved,
        }
    }
}

pub(super) struct Loss {
    round: u64,
    ends: Ends,
    lost: Vec<usize>,
    /// The tenure each lost cell served when the loss began, in `lost` order.
    held: Vec<Option<Tenure>>,
    pub(super) episode: super::Episode,
    refusing: bool,
}

/// A host's record read as the fleet takes it: an unavailable or absent record is no record, and any other error
/// stops the run.
fn viewed<R>(
    member: usize,
    read: Result<crate::storage::store::Read<R>, crate::storage::store::StoreError>,
) -> Option<crate::storage::store::Read<R>> {
    use crate::storage::store::StoreError;
    match read {
        Ok(read) => Some(read),
        Err(StoreError::Unavailable | StoreError::Absent) => None,
        Err(error) => panic!("a record view read of host {member}: {error:?}"),
    }
}

impl<'c> Fleet<'c> {
    pub(super) fn client(&self, member: usize) -> Client<Faulted<Shared>, MemLog> {
        let faulted = Faulted {
            inner: self.store.clone(),
            actor: member as u32,
            faults: self.faults.store.clone(),
        };
        Client::open(faulted, self.hosts[member].log.clone()).expect("a host's store client")
    }

    /// `member`'s store client for a takeover's period with its witness and for the incarnation after it:
    /// [`Fleet::client`]'s store under `owners::Returning`, which keeps in `returned` the records the first role read
    /// through the client returned.
    fn takeover_client(
        &self,
        member: usize,
        returned: &std::rc::Rc<std::cell::RefCell<super::owners::Returned>>,
    ) -> Client<super::owners::Returning<Faulted<Shared>>, MemLog> {
        let store = super::owners::Returning {
            inner: Faulted {
                inner: self.store.clone(),
                actor: member as u32,
                faults: self.faults.store.clone(),
            },
            returned: std::rc::Rc::clone(returned),
        };
        Client::open(store, self.hosts[member].log.clone()).expect("a host's store client")
    }

    fn detector_now(&self) -> u64 {
        self.round * H
    }

    pub(super) fn read_records(&mut self, member: usize) {
        let zone = self.topology.members[member].zone;
        let shards: Vec<usize> = (0..self.cells.len())
            .filter(|&at| self.cells[at].placement.zone == zone)
            .collect();
        for at in shards {
            self.read_record(member, at);
        }
    }

    pub(super) fn sync(&mut self, member: usize) {
        self.hosts[member].resync = true;
    }

    /// The zone's placement as `member`'s agent syncs it.
    fn placement(&self, member: usize) -> Vec<(Host, crate::failover::arbiter::Partition)> {
        let zone = self.topology.members[member].zone;
        (self.topology.members.iter())
            .filter(|of| of.zone == zone)
            .map(|of| (of.host, of.partition))
            .collect()
    }

    /// `member`'s agent keys: its own heartbeat and probe keys and those of every other host of its zone, each
    /// derived from the host's key.
    fn agent_keys(&self, member: usize) -> Keys {
        let of = self.topology.members[member];
        let peers: Vec<Host> = (self.topology.members.iter())
            .filter(|peer| peer.zone == of.zone && peer.host != of.host)
            .map(|peer| peer.host)
            .collect();
        let beat = |host: Host| BeatKey::derive(&host_key(host));
        let probe = |host: Host| ProbeKey::derive(&host_key(host));
        Keys {
            own: beat(of.host),
            probe: probe(of.host),
            peers: peers.iter().map(|&host| (host, beat(host))).collect(),
            probers: peers.iter().map(|&host| (host, probe(host))).collect(),
        }
    }

    fn boot_host(&mut self, member: usize) {
        let keys = self.agent_keys(member);
        let host = &mut self.hosts[member];
        host.boot += 1;
        host.up = Up::Running;
        host.inbox.clear();
        host.probes.clear();
        host.published.clear();
        host.held.clear();
        let period = NonZeroU64::new(REPORT_ROUNDS * ROUND_US).expect("a report period");
        let writer =
            report::tests::writer_for(host.host, &host_key(host.host), host.nonce(), period);
        let booted_at_us = u64::from(host.boot) * 1_000_000;
        let agent = Agent::new(
            &HostGate::qualified(),
            (host.host, host.nonce(), booted_at_us),
            watch_bounds(),
            keys,
            (writer, AGENT_BUILD),
        );
        let mut agent = agent.expect("the fleet's agent bounds");
        if let Some(grace) = self.grace_us {
            agent.set_restart_grace(grace);
        }
        let host = &mut self.hosts[member];
        host.agent = Some(agent);
        self.list_instance(member, InstanceState::Running);
        self.read_records(member);
        self.sync(member);
    }

    pub(super) fn start_hosts(&mut self) {
        self.hosts = (self.topology.members.iter().enumerate())
            .map(|(member, of)| HostActor {
                member,
                host: of.host,
                up: Up::Down,
                boot: 0,
                agent: None,
                records: Vec::new(),
                resync: false,
                inbox: Vec::new(),
                probes: Vec::new(),
                published: Vec::new(),
                held: Vec::new(),
                log: MemLog::default(),
            })
            .collect();
        let probe_key = |host: Host| ProbeKey::derive(&host_key(host)).keyed();
        self.probe_keys = (self.topology.members.iter())
            .map(|of| (of.host.get(), probe_key(of.host)))
            .collect();
        if self.config.scenario.repairs() {
            self.seed_census();
            let zones: Vec<Zone> = (1..=self.config.shape.zones).map(Zone).collect();
            self.zones = (zones.iter())
                .map(|&zone| super::reconcile::zone_double(self, zone))
                .collect();
            let cap = usize::from(self.config.shape.cap);
            let reconcilers = usize::from(self.config.shape.reconcilers);
            let per_zone = (zones.iter()).flat_map(|&zone| std::iter::repeat_n(zone, reconcilers));
            self.reconcilers = (per_zone.enumerate())
                .map(|(index, zone)| ReconcilerActor::new(index, zone, cap))
                .collect();
            if self.config.planted(Plant::WideCap) {
                self.planted = true;
                let index = self.reconcilers.len();
                (self.reconcilers).push(ReconcilerActor::new(index, Zone(1), cap + 1));
            }
        }
        for member in 0..self.hosts.len() {
            self.boot_host(member);
        }
        self.host_start = self.round;
        for actor in &mut self.reconcilers {
            actor.started = self.round;
        }
    }

    /// The fleet carries each agent's messages right after its turn, so a member later in the order reads a zero-delay
    /// message in the round it was sent.
    pub(super) fn host_round(&mut self, live: &mut Live<'_>) {
        let t = self.detector_now();
        let since = self.round - self.host_start;
        self.faults.store.borrow_mut().set_now(since);
        let running: Vec<usize> = (0..self.hosts.len())
            .filter(|&member| self.hosts[member].up == Up::Running)
            .collect();
        for &member in &running {
            let (heartbeats, probes) = self.agent_turn(live, member, t + self.agent_phase(member));
            self.carry(member, heartbeats, probes);
        }
    }

    /// `agent_phase` staggers turns in member order and returns `member`'s offset from the round start.
    pub(super) fn agent_phase(&self, member: usize) -> u64 {
        member as u64 * H / self.hosts.len().max(1) as u64
    }

    /// The inbox uses the current round for zero-delay messages, even when `receiver` has already turned. For
    /// positive `delay`, an earlier `receiver` adds one round to the arrival round.
    fn arrival(&self, member: usize, receiver: usize, delay: u64) -> u64 {
        let turned = receiver < member;
        self.round + delay + u64::from(turned && delay > 0)
    }

    /// One turn of `member`'s agent over its process statuses, the messages due at this round and, after a resync,
    /// its records. The turn's witnesses join the standby processes' inboxes and its report goes to the reader and
    /// the zone double; the heartbeats and probe messages it sealed return to [`Fleet::host_round`].
    fn agent_turn(&mut self, live: &mut Live<'_>, member: usize, t: u64) -> Outgoing {
        let statuses = self.statuses(live, member, t);
        let resync = std::mem::take(&mut self.hosts[member].resync);
        let placement = match resync {
            true => self.placement(member),
            false => Vec::new(),
        };
        let zone = self.topology.members[member].zone;
        let peers: Vec<Host> = (self.topology.members.iter())
            .filter(|of| of.zone == zone && of.host != self.hosts[member].host)
            .map(|of| of.host)
            .collect();
        let headroom = self.headroom(live, member, t);
        let round = self.round;
        let probe_keys = &self.probe_keys;
        let host = &mut self.hosts[member];
        let own = host.host;
        let (heartbeats, later): (Vec<_>, Vec<_>) =
            (host.inbox.drain(..)).partition(|(arrives, _)| *arrives <= round);
        host.inbox = later;
        let (probes, later): (Vec<_>, Vec<_>) =
            (host.probes.drain(..)).partition(|(arrives, _)| *arrives <= round);
        host.probes = later;
        let alive = (probes.iter())
            .filter(|(_, bytes)| {
                let opened =
                    probe::open(bytes, own, |sender| probe_keys.get(&sender.get()).copied());
                matches!(
                    opened,
                    Ok((
                        _,
                        _,
                        Message::Reply {
                            reading: Reading::Alive,
                            ..
                        }
                    ))
                )
            })
            .count();
        // `beat::decode` hands a well-formed heartbeat's sender field to its key lookup before any tag check.
        let senders: Vec<Host> = (heartbeats.iter())
            .filter_map(|(_, bytes)| {
                let mut sender = None;
                let _ = beat::decode(bytes, own, |field| {
                    sender = Some(field);
                    None
                });
                sender.filter(|field| peers.contains(field))
            })
            .collect();
        let heartbeat_bytes: Vec<&[u8]> = heartbeats.iter().map(|(_, b)| b.as_slice()).collect();
        let probe_bytes: Vec<&[u8]> = probes.iter().map(|(_, b)| b.as_slice()).collect();
        let sync = resync.then_some(Synced {
            records: &host.records,
            placement: &placement,
        });
        let sample = HostSample {
            headroom,
            recovery_io: Gauge::Unavailable,
        };
        let inputs = AgentInputs {
            statuses: &statuses,
            heartbeats: &heartbeat_bytes,
            probes: &probe_bytes,
            sync,
            clock: Clock::Trusted { sampled_at: t },
            wall_us: t,
            host: sample,
        };
        let agent = host.agent.as_mut().expect("a running host's agent");
        let published = agent.watch().census().nominations;
        let out = agent.turn(t, inputs);
        let healthy = agent.healthy(t);
        let watch = agent.watch();
        let own_host = self.topology.members[member].host.get();
        let gray: Vec<u64> = (self.topology.members.iter())
            .filter(|peer| {
                matches!(
                    watch.liveness(peer.host),
                    Some(crate::failover::detect::Liveness::Dead(suspicion))
                        if suspicion.failure.needs_second_class()
                )
            })
            .map(|peer| peer.host.get())
            .collect();
        self.log.gray_readings += u32::from(!gray.is_empty());
        self.log
            .gray
            .extend(gray.into_iter().map(|peer| (own_host, peer)));
        let nominated = watch.census().nominations.saturating_sub(published);
        // An authenticated heartbeat from a placed peer whose roles the receiver's records omit is refused `Sender`
        // at the detector's row lookup; every other `Sender` refusal counts against the run.
        let untracked = (senders.iter())
            .filter(|sender| watch.liveness(**sender).is_none())
            .count();
        if !healthy {
            for cell in self.cells.iter().filter(|cell| cell.holder == member) {
                self.log.exempt.insert(cell.placement.shard.get());
            }
        }
        let (mut sender_refused, mut reply_refused) = (0_usize, false);
        for refusal in &out.refused {
            match refusal {
                WatchRefusal::Stale => {
                    self.log.stale_replies += 1;
                    reply_refused = true;
                }
                WatchRefusal::Prober => {
                    self.log.refused += 1;
                    reply_refused = true;
                }
                WatchRefusal::Beat(BeatError::Sender) => sender_refused += 1,
                _ => self.log.refused += 1,
            }
        }
        self.log.refused += count_u32(sender_refused.saturating_sub(untracked));
        for refusal in &out.probes_refused {
            match refusal {
                ProbeError::Unrequested => {
                    self.log.unmatched_probes += 1;
                    reply_refused = true;
                }
                ProbeError::Untracked => self.log.unmatched_probes += 1,
                _ => self.log.refused += 1,
            }
        }
        // The outputs list refusals without their messages, so a turn that refused a probe reply credits no veto.
        if !reply_refused {
            self.log.vetoes += count_u32(alive);
        }
        self.log.refused += u32::from(out.seal_refused.is_some());
        self.alarms.unsealable += u32::from(out.seal_refused.is_some());
        self.log.repair_demands += u32::from(out.repair.is_some());
        if nominated > 0 {
            let nominated = u32::try_from(nominated).unwrap_or(u32::MAX);
            self.log.nominations = self.log.nominations.saturating_add(nominated);
            let round = self.round - self.host_start;
            self.recon.first_nomination.get_or_insert(round);
        }
        let crate::host::agent::Outputs {
            heartbeats,
            probes,
            messages,
            report,
            ..
        } = out;
        for (volume, message) in messages {
            let Inbound::Nominate(witness) = message else {
                continue;
            };
            self.log.addressed += 1;
            self.witness(member, witness.shard.get(), witness.target);
            self.deliver(member, volume, witness, t);
        }
        if let Some(bytes) = report {
            let at_us = self.round * ROUND_US;
            (self.alarms).receive(super::alarms::Source::Report, at_us, &bytes);
            let key = |host: Host| Some(report::ReportKey::derive(&host_key(host)));
            match self.reader.accept(&bytes, key) {
                Ok(accepted) => {
                    self.log.reports += 1;
                    let h = accepted.host.headroom;
                    let gauges = [h.attachments, h.workers, h.recovery];
                    let host = self.hosts[member].host.get();
                    let last = (self.log.headrooms.iter()).rfind(|(_, of, _)| *of == host);
                    if last.is_none_or(|(_, _, before)| *before != gauges) {
                        let round = self.round - self.host_start;
                        self.log.headrooms.push((round, host, gauges));
                    }
                    let held: Vec<u32> = (accepted.entries.iter())
                        .filter(|entry| entry.phase == Some(OwnerPhase::Held))
                        .map(|entry| entry.shard.get())
                        .collect();
                    let before = std::mem::replace(&mut self.hosts[member].held, held.clone());
                    for shard in held.into_iter().filter(|shard| !before.contains(shard)) {
                        let round = self.round - self.host_start;
                        self.log.held.push((round, host, shard));
                    }
                    for entry in &accepted.entries {
                        let store = SealedStore {
                            round: self.round - self.host_start,
                            host,
                            shard: entry.shard.get(),
                            watermark: entry.watermark,
                            unknown: entry.store.unknown,
                        };
                        let last = self.log.sealed_stores(host, store.shard).last();
                        let changed = |last: &SealedStore| {
                            (last.watermark, last.unknown) != (store.watermark, store.unknown)
                        };
                        if last.is_none_or(changed) {
                            self.log.stores.push(store);
                        }
                    }
                }
                Err(_) => self.log.refused += 1,
            }
            if let Some(zone) = self.double(zone) {
                zone.reports.insert(own, bytes);
            }
        }
        (heartbeats, probes)
    }

    /// Puts `witness` into the inbox of `member`'s standby process of `volume`. As a link's inbox does, the inbox
    /// keeps one witness: a queued one that expires no later is replaced.
    pub(super) fn deliver(
        &mut self,
        member: usize,
        volume: VolumeId,
        witness: Revalidated,
        at: u64,
    ) {
        let queued =
            (self.nominated.iter_mut()).find(|(of, on, ..)| (*of, *on) == (member, volume));
        match queued {
            Some(queued) if queued.2.until_us <= witness.until_us => {
                (queued.2, queued.3) = (witness, at)
            }
            Some(_) => {}
            None => self.nominated.push_back((member, volume, witness, at)),
        }
    }

    /// Whether `member`'s standby process of `volume` reads a witness for `shard`: the host runs and its records
    /// name it standby of `shard` on `volume`.
    pub(super) fn addressed(
        &self,
        member: usize,
        volume: VolumeId,
        shard: crate::net::ownership::Shard,
    ) -> bool {
        let host = &self.hosts[member];
        let named = (host.records.iter()).any(|record| {
            (record.shard, record.active, record.standby) == (shard, volume, Some(host.host))
        });
        host.up == Up::Running && named
    }

    /// `member`'s headroom by `Headroom::of` over the inputs the host's sampler reads at this turn. The procfs gauges
    /// `ram` and `cpu_load` read unavailable so a run stays deterministic and independent of the machine it runs on;
    /// `iops` and `bandwidth` read unavailable because the fleet supplies no device sample and no provisioned rate.
    ///
    /// - attachments: one bind mapping per volume the host serves and, exclusive of those, each other volume attached
    ///   to the host's instance ([`Fleet::attached_unbound`]), of [`ATTACH_SLOTS`];
    /// - workers: the shards whose record the host last read names it owner or standby, each counted once, of the
    ///   directory's `host_roles_max`;
    /// - recovery: the volumes whose recovery holds a slot, of one slot: each cell whose restart or takeover on the
    ///   host holds with a next step of hold or restart (the holds of [`Fleet::holds`] that the enroll-back plant
    ///   leaves visible, the ones [`Fleet::statuses`] publishes as `Held`, counted by [`report::recovering`]), and
    ///   the cell whose load runs on the host from its bring-up until its client session is active
    ///   (`Fleet::recovering`). A held cell the host serves is no hold, so the load and the holds never name one
    ///   volume twice.
    pub(super) fn headroom(&self, live: &Live<'_>, member: usize, now: u64) -> report::Headroom {
        let host = self.hosts[member].host;
        let serves = |at: usize| self.cells[at].holder == member && live[at].is_some();
        let mappings: Vec<crate::bind::Mappings> = (0..self.cells.len())
            .filter(|&at| serves(at))
            .map(|at| {
                let mut mapping = crate::bind::mappings_tests::sample(None);
                let nvme = mapping.nvme.as_mut().expect("the sample's NVMe binding");
                nvme.volume = self.cells[at].placement.volume.as_str().to_owned();
                mapping
            })
            .collect();
        let records = &self.hosts[member].records;
        let roles = (records.iter())
            .filter(|record| record.owner == host || record.standby == Some(host))
            .count() as u64;
        let loading = self.recovering.filter(|&at| {
            let active =
                |serving: &super::Serving<'_>| serving.client.state() == SessionState::Active;
            self.cells[at].holder == member && live[at].as_ref().is_some_and(|s| !active(s))
        });
        let held: Vec<report::RecoveryStatus> = (self.holds(live, member))
            .filter(|&(_, _, hidden)| !hidden)
            .map(|(_, held, _)| held.status(now))
            .collect();
        let recovering = report::recovering(held.iter().map(|status| Some((status, false))))
            .map(|holds| holds.saturating_add(u64::from(loading.is_some())));
        let inputs = report::HeadroomInputs {
            attached: report::attached(
                mappings.iter().map(Some),
                self.attached_unbound(member, live),
            ),
            attachment_slots: NonZeroU64::new(ATTACH_SLOTS),
            roles: Some(roles),
            host_roles_max: NonZeroU64::new(u64::from(self.config.shape.roles_max)),
            recovering,
            recovery_slots: NonZeroU64::new(1),
            ..report::HeadroomInputs::UNAVAILABLE
        };
        report::Headroom::of(Gauge::Unavailable, Gauge::Unavailable, &inputs)
    }

    /// The volumes attached to `member`'s instance that it serves through no bound tenure. In a reconciler scenario
    /// they are the zone double's attachment listings that name the instance, outside the volumes the host serves; a
    /// volume the zone double does not list is not attached. A host scenario attaches no volume after seeding, so its
    /// count is the seeded attaches of the cells the host does not serve.
    pub(super) fn attached_unbound(&self, member: usize, live: &Live<'_>) -> Option<u64> {
        let of = self.topology.members[member];
        let served: Vec<crate::failover::records::VolumeId> = (0..self.cells.len())
            .filter(|&at| self.cells[at].holder == member && live[at].is_some())
            .map(|at| self.cells[at].placement.volume)
            .collect();
        if !self.repairs() {
            let unbound = (self.cells.iter())
                .filter(|cell| !served.contains(&cell.placement.volume))
                .filter(|cell| cell.attached().contains(&member));
            return Some(unbound.count() as u64);
        }
        let double = self.zones.iter().find(|double| double.zone == of.zone)?;
        let unbound = (double.volumes.iter())
            .filter(|listed| !served.contains(&listed.volume))
            .filter(|listed| {
                listed
                    .attachments
                    .iter()
                    .any(|id| id == of.instance.as_str())
            });
        Some(unbound.count() as u64)
    }

    /// Carries `member`'s heartbeats and probe messages to the running hosts the links let them reach, each arriving
    /// at [`Fleet::arrival`], and counts each probe request one prober answered ALIVE and another
    /// DEAD as contested.
    fn carry(
        &mut self,
        member: usize,
        heartbeats: Vec<(Host, Vec<u8>)>,
        probes: Vec<(Host, [u8; probe::LEN])>,
    ) {
        let receiver_of = |fleet: &Self, host: Host| {
            let receiver = fleet.member_of(host)?;
            let up = fleet.hosts[receiver].up == Up::Running;
            (up && fleet.faults.links.reaches(member, receiver)).then_some(receiver)
        };
        for (to, bytes) in heartbeats {
            if let Some(receiver) = receiver_of(self, to) {
                let arrives =
                    self.arrival(member, receiver, self.faults.links.delay(member, receiver));
                self.hosts[receiver].inbox.push((arrives, bytes));
            }
        }
        for (to, bytes) in probes {
            let Some(receiver) = receiver_of(self, to) else {
                continue;
            };
            let keys = &self.probe_keys;
            let opened = probe::open(&bytes, to, |host| keys.get(&host.get()).copied());
            if let Ok((_, _, Message::Reply { request, reading })) = opened {
                let seen = self
                    .readings
                    .entry((to.get(), request.suspect.get(), request.issued));
                let held = seen.or_insert((false, false));
                let before = held.0 && held.1;
                match reading {
                    Reading::Alive => held.0 = true,
                    Reading::Dead(_) => held.1 = true,
                    Reading::Unknown => {}
                }
                self.log.contested += u32::from(!before && held.0 && held.1);
            }
            let arrives = self.arrival(member, receiver, self.faults.links.delay(member, receiver));
            self.hosts[receiver].probes.push((arrives, bytes));
        }
    }

    /// The statuses `member`'s processes publish this round, one per volume:
    ///
    /// - each tenure that runs on the host, a deposed one included, with its authority's phase, tenure and ages and
    ///   its report entry, as the serving duties publish it;
    /// - each restart or takeover of the host that holds ([`Fleet::holds`]), with `Held` and its held entry;
    /// - a standby wait, `Standby` with the target its last role read returned, in a view period of the wait, in a
    ///   takeover's period with its witness that ended `Exit::Stopped`, or in the incarnation that began the wait
    ///   ([`Cell::waiting`](super::Cell), [`Fleet::publish_read`], [`Fleet::publish_role`]), for each shard the host
    ///   waits on as standby and does not hold, on a volume no other process of the host publishes;
    /// - under the enroll-back plant, an entryless `Withdrawn` status for the hidden hold;
    /// - and an entryless `Withdrawn` status, once, for a process that published last turn and runs no more.
    fn statuses(&mut self, live: &Live<'_>, member: usize, t: u64) -> Vec<LinkStatus> {
        use crate::failover::serving::State;
        // The flat-progress plant freezes the counters of each tenure status the host publishes, with one command
        // pending, from its first turn.
        let flat = self.config.planted_at(Plant::FlatProgress, member);
        let pid = |at: usize| (member * 100 + at) as u32;
        let count = self.round;
        let cells = self.cells.len();
        let mut statuses: Vec<LinkStatus> = Vec::new();
        for (slot, serving) in live.iter().enumerate() {
            let (at, runs_on) = match slot.checked_sub(cells) {
                None => (slot, self.cells[slot].holder),
                Some(index) => self.deposed[index],
            };
            let Some(serving) = serving.as_ref().filter(|_| runs_on == member) else {
                continue;
            };
            let owner = &serving.owner;
            let authority = owner.authority_report();
            let phase = match owner.authority_state() {
                State::PreBoundary | State::Recovering => OwnerPhase::Recovering,
                State::Serving => OwnerPhase::Serving,
                State::Withdrawn => OwnerPhase::Withdrawn,
                State::Closed => OwnerPhase::Closing,
            };
            // The serving duties hold the store client's tally and alarm and the listing result; a tenure with no
            // duties holds none.
            let observed =
                (serving.duties.as_ref()).map_or(report::Observed::UNAVAILABLE, |d| d.observed());
            let entry = owner.report_entry_at(authority, t, &observed);
            let placement = &self.cells[at].placement;
            let volume = entry.map_or(placement.volume, |entry| entry.volume);
            statuses.push(LinkStatus {
                tenure: Some(authority.tenure),
                report_age_us: authority.report_age_us,
                read_age_us: authority.freshness_age_us,
                io: if flat { 0 } else { count },
                completions: if flat { 0 } else { count },
                pending: u64::from(flat),
                entry,
                ..LinkStatus::idle(placement.shard, volume, pid(at), phase)
            });
            self.planted |= flat;
        }
        let mut hidden = Vec::new();
        for (at, held, planted) in self.holds(live, member) {
            let placement = &self.cells[at].placement;
            let (shard, volume) = (placement.shard, placement.volume);
            if planted {
                hidden.push(LinkStatus::idle(
                    shard,
                    volume,
                    pid(at),
                    OwnerPhase::Withdrawn,
                ));
                continue;
            }
            let entry = report::VolumeEntry {
                shard,
                phase: Some(report::Phase::Held),
                recovery: held.status(t).recovery(t),
                ..report::tests::bare(volume.as_str(), report::RecordedRole::Owner)
            };
            statuses.push(LinkStatus {
                entry: Some(entry),
                ended: Some(report::Ended::Held),
                ..LinkStatus::idle(shard, volume, pid(at), OwnerPhase::Held)
            });
        }
        let mut published = false;
        for parked in self.parks.iter().filter(|parked| parked.member == member) {
            let cell = &self.cells[parked.at];
            let (shard, volume) = (cell.placement.shard, cell.placement.volume);
            if self.config.planted_at(Plant::ParkedWithdraws, parked.at) {
                let pid = pid(parked.at);
                statuses.push(LinkStatus::idle(shard, volume, pid, OwnerPhase::Withdrawn));
                published = true;
            }
            if !self.config.planted_at(Plant::ParkedPublishes, parked.at) {
                continue;
            }
            let entry = report::VolumeEntry {
                shard,
                phase: Some(report::Phase::Held),
                ..report::tests::bare(volume.as_str(), report::RecordedRole::Owner)
            };
            statuses.push(LinkStatus {
                entry: Some(entry),
                ended: Some(report::Ended::Held),
                ..LinkStatus::idle(shard, volume, pid(parked.at), OwnerPhase::Held)
            });
            published = true;
        }
        self.planted |= published || !hidden.is_empty();
        // Each standby process publishes `Standby` from its own wait, with the target its last role read returned.
        for at in 0..cells {
            let Some((of, target, volume)) = self.cells[at].waiting else {
                continue;
            };
            let published = statuses.iter().any(|status| status.volume == volume);
            if of != member || self.cells[at].holder == member || published {
                continue;
            }
            if self.config.planted_at(Plant::WaitUnpublished, at) {
                self.planted = true;
                continue;
            }
            let shard = self.cells[at].placement.shard;
            statuses.push(LinkStatus {
                target: Some(target),
                ..LinkStatus::idle(shard, volume, pid(at), OwnerPhase::Standby)
            });
        }
        for status in hidden {
            if !statuses
                .iter()
                .any(|published| published.volume == status.volume)
            {
                statuses.push(status);
            }
        }
        // The statuses pushed from here on are the fleet's own: one `Withdrawn` for each publication that stopped.
        let stopped = statuses.len();
        let last = std::mem::take(&mut self.hosts[member].published);
        for (shard, volume, pid, phase) in last {
            let ended = matches!(phase, OwnerPhase::Withdrawn | OwnerPhase::Closing);
            if !ended && !statuses.iter().any(|status| status.volume == volume) {
                statuses.push(LinkStatus::idle(shard, volume, pid, OwnerPhase::Withdrawn));
            }
        }
        self.hosts[member].published = (statuses.iter())
            .map(|status| (status.shard, status.volume, status.pid, status.phase))
            .collect();
        let since = self.round - self.host_start;
        for parked in self.parks.iter().filter(|parked| parked.member == member) {
            let shard = self.cells[parked.at].placement.shard;
            let pid = pid(parked.at);
            // The `Withdrawn` that follows the ended wait's last status is the wait's, not the park's.
            let parks = |status: &&LinkStatus| status.shard == shard && status.pid == pid;
            if statuses[..stopped].iter().any(|status| parks(&status)) {
                let host = self.topology.members[member].host.get();
                self.log.parked_published.push((since, host, shard.get()));
            }
        }
        statuses
    }

    /// The cells whose restart or takeover on `member` holds and which `member` does not serve, each with the hold
    /// and whether the enroll-back plant hides it. The plant hides the planted shard's hold of each host other than
    /// the shard's current holder. [`Fleet::statuses`] publishes a hidden hold as `Withdrawn` and every other hold as
    /// `Held`, and [`Fleet::headroom`] counts a recovery slot for each hold that is not hidden, so one report's
    /// `Held` entries and its recovery gauge select their holds by this one rule.
    pub(super) fn holds<'a>(
        &'a self,
        live: &'a Live<'_>,
        member: usize,
    ) -> impl Iterator<Item = (usize, super::volumes::Held, bool)> + 'a {
        (0..self.cells.len()).filter_map(move |at| {
            let cell = &self.cells[at];
            let (_, held) = cell.held.iter().find(|(of, _)| *of == member)?;
            let served = cell.holder == member && live[at].is_some();
            let hidden = cell.holder != member && self.config.planted_at(Plant::EnrollBack, at);
            (!served).then_some((at, *held, hidden))
        })
    }

    pub(super) fn episodes<'w>(
        &mut self,
        live: &mut Live<'w>,
        slots: &mut Slots<'w>,
    ) -> Result<(), Stopped> {
        let since = self.round - self.host_start;
        self.faults.store.borrow_mut().set_now(since);
        let taken = self
            .log
            .takeovers
            .iter()
            .filter(|attempt| attempt.refused.is_none());
        let log = (self.log.nominations, taken.count() as u32);
        let mut faults = std::mem::replace(&mut self.faults, Faults::new(Vec::new(), 0));
        let effects = {
            let fleet: &Fleet<'_> = self;
            faults.step(since, |trigger: &Trigger| match *trigger {
                Trigger::AtTime(at) => since >= at,
                Trigger::After(Pattern::Nominated, n) => log.0 >= n,
                Trigger::After(Pattern::TakeOver, n) => log.1 >= n,
                Trigger::When(predicate) => predicate(fleet),
            })
        };
        self.faults = faults;
        let mut lost = Vec::new();
        let (mut crashed, mut returned) = (false, false);
        let members = self.hosts.len();
        for effect in effects {
            match effect {
                Effect::Pause(member)
                | Effect::Crash(member)
                | Effect::Return(member)
                | Effect::Resume(member)
                    if member >= members =>
                {
                    unreachable!("`Scenario::episodes` scopes every episode to hosts")
                }
                Effect::Register(at) => {
                    let foreign = crate::storage::gate_fixture::foreign();
                    let reservation = &self.cells[at].world.reservation;
                    let cntlid = reservation.borrow().entries.len() as u16 + 1;
                    let entry = crate::failover::fresh::tests::registrant(foreign, cntlid, false);
                    // Every fleet tenure answers Reports from this table (`Fleet::rise`).
                    reservation.borrow_mut().entries.push(entry);
                    self.planted = true;
                }
                Effect::Stall(at) => {
                    self.fail_volume(live, slots, at, super::volumes::Device::Stalled)?
                }
                Effect::LoseVolume(at) => {
                    self.fail_volume(live, slots, at, super::volumes::Device::Lost)?
                }
                Effect::Unstall(at) => self.unstall(at),
                Effect::Impair(at, on) => self.impair(at, on),
                Effect::Release(at) => self.release_hold(at),
                Effect::Rerun(at) => self.rerun_held(at),
                Effect::Handoff(at, ended) => self.hand_off(live, at, ended)?,
                Effect::Crash(member) if self.hosts[member].up == Up::Down => {}
                Effect::Crash(member) => {
                    crashed = true;
                    lost.extend(self.lose_host(live, member, Up::Down)?);
                }
                Effect::Return(member) => {
                    returned = true;
                    self.boot_host(member);
                    self.queue_returns(member);
                }
                Effect::Pause(member) => lost.extend(self.lose_host(live, member, Up::Paused)?),
                Effect::Resume(member) => {
                    self.hosts[member].up = Up::Running;
                    self.resumed.push((member, self.round));
                    self.close_losses(live, false);
                    self.read_records(member);
                    self.sync(member);
                }
                Effect::Cut { until, isolated } => {
                    self.drain(live)?;
                    let ends = until.map_or(Ends::Takeover, |at| Ends::Heal(self.host_start + at));
                    let cut: Vec<usize> = (0..self.cells.len())
                        .filter(|&at| isolated.contains(&self.cells[at].holder))
                        .collect();
                    for &at in &cut {
                        self.cells[at].lost_at = Some(self.round);
                    }
                    self.host_lost.extend(cut.iter().copied());
                    self.log.host_losses += isolated.len() as u32;
                    self.crashes += isolated.len() as u32;
                    self.open_loss(live, cut, ends)?;
                }
            }
        }
        if crashed {
            self.zone_down(live);
        }
        if !lost.is_empty() || crashed && self.repairs() {
            self.open_loss(live, lost, Ends::Hosts)?;
        }
        if returned && self.zone_returned(live) {
            // The other zones' shards take another episode's GETs while the returning owners restart.
            self.open_loss(live, Vec::new(), Ends::Hosts)?;
        }
        Ok(())
    }

    fn lose_host(
        &mut self,
        live: &mut Live<'_>,
        member: usize,
        up: Up,
    ) -> Result<Vec<usize>, Stopped> {
        self.drain(live)?;
        let mut lost = Vec::new();
        for (at, (cell, serving)) in self.cells.iter_mut().zip(live.iter_mut()).enumerate() {
            if cell.holder != member {
                continue;
            }
            if up == Up::Down
                && let Some(serving) = serving.take()
            {
                cell.close(&serving, true);
            }
            cell.lost_at = Some(self.round);
            lost.push(at);
        }
        if up == Up::Down {
            (self.held_at_stop).extend(lost.iter().map(|&at| (at, member)));
        }
        self.host_lost.extend(lost.iter().copied());
        // A crash also drops each tenure the host still runs for a shard another host took over.
        for (index, &(at, of)) in self.deposed.iter().enumerate() {
            if up == Up::Down
                && of == member
                && let Some(serving) = live[self.cells.len() + index].take()
            {
                self.cells[at].close(&serving, false);
            }
        }
        if up == Up::Down {
            for cell in &mut self.cells {
                cell.held.retain(|(of, _)| *of != member);
            }
            while let Some(index) = self.parks.iter().position(|parked| parked.member == member) {
                self.leave_park(index, None);
            }
        }
        // A stopped or paused host's standby processes publish nothing until a later wait reads their role again.
        for cell in &mut self.cells {
            if cell.waiting.is_some_and(|(of, ..)| of == member) {
                cell.waiting = None;
            }
        }
        let host = &mut self.hosts[member];
        host.up = up;
        if up == Up::Down {
            host.agent = None;
            host.inbox.clear();
            host.probes.clear();
            self.nominated.retain(|(of, ..)| *of != member);
            self.list_instance(member, InstanceState::Stopped);
        }
        self.log.host_losses += 1;
        self.crashes += 1;
        Ok(lost)
    }

    pub(super) fn open_loss(
        &mut self,
        live: &mut Live<'_>,
        lost: Vec<usize>,
        ends: Ends,
    ) -> Result<(), Stopped> {
        self.window = true;
        let before: Vec<_> = (0..self.cells.len())
            .filter(|&at| {
                let holder = self.cells[at].holder;
                // A tenure whose serving duties ended at an exit serves through no loss.
                let serving =
                    (live[at].as_ref()).is_some_and(|serving| serving.duty_exit.is_none());
                serving && self.hosts[holder].up == Up::Running && !lost.contains(&at)
            })
            .map(|at| self.sample(at))
            .collect();
        let mut draws = self.draws.take().expect("the run's decisions");
        let due = self.draw_gets(&before, &mut draws);
        self.draws = Some(draws);
        let due = due?;
        for open in &mut self.losses {
            let taken = (open.episode.before.iter()).filter(|sampled| lost.contains(&sampled.at));
            self.released.extend(taken.map(|sampled| sampled.at));
            open.episode
                .before
                .retain(|sampled| !lost.contains(&sampled.at));
        }
        for due in &due {
            let shard = self.cells[due.at].placement.shard.get();
            (self.log.arrivals).push((due.round, shard, due.n));
        }
        let refusing = (lost.first()).is_some_and(|&at| {
            self.config
                .planted_at(Plant::NeighborRefusal, self.cells[at].holder)
        });
        let held = (lost.iter())
            .map(|&at| live[at].as_ref().map(|serving| serving.tenure))
            .collect();
        self.losses.push(Loss {
            round: self.round,
            ends,
            lost,
            held,
            episode: super::Episode {
                dropped: true,
                before,
                due,
            },
            refusing,
        });
        Ok(())
    }

    fn neighbour_gets(&mut self, live: &mut Live<'_>) {
        for loss in 0..self.losses.len() {
            let since = self.round - self.losses[loss].round;
            let (now, later): (Vec<_>, Vec<_>) =
                (self.losses[loss].episode.due.drain(..)).partition(|due| due.round <= since);
            self.losses[loss].episode.due = later;
            for super::Due { at: other, n, .. } in now {
                if live[other].is_none() {
                    continue;
                }
                if std::mem::take(&mut self.losses[loss].refusing) {
                    let serving = live[other].as_mut().expect("a serving neighbour");
                    self.planted |= serving.drop_entry(n);
                }
                self.cells[other].requested.push(n);
                self.send(live, other, n, Purpose::Neighbour);
            }
        }
    }

    fn close_losses(&mut self, live: &Live<'_>, ended: bool) {
        for loss in std::mem::take(&mut self.losses) {
            let moved = (loss.lost.iter().zip(&loss.held)).all(|(&at, held)| {
                (live[at].as_ref()).is_some_and(|serving| Some(serving.tenure) != *held)
            });
            let recovered = loss.ends.reached(self.round, moved)
                && loss.episode.due.is_empty()
                && (loss.lost.iter()).all(|&at| live[at].is_some() && self.stepping(at))
                && (!loss.lost.is_empty() || self.flights.is_empty());
            if recovered || ended {
                self.watch(live, &loss.episode);
            } else {
                self.losses.push(loss);
            }
        }
        self.window = !self.losses.is_empty() && !self.restored(live);
    }

    /// Whether every open loss is restored: each loss that took a shard has each lost shard served by a tenure
    /// other than the one it held at the loss, whose host runs and whose client session is active. A loss that
    /// took no shard, a false suspicion's cut, stays open until `close_losses` closes it.
    pub(super) fn restored(&self, live: &Live<'_>) -> bool {
        let active = |(&at, held): (&usize, &Option<Tenure>)| {
            live[at].as_ref().is_some_and(|serving| {
                Some(serving.tenure) != *held
                    && self.stepping(at)
                    && serving.client.state() == SessionState::Active
            })
        };
        (self.losses.iter())
            .all(|loss| !loss.lost.is_empty() && loss.lost.iter().zip(&loss.held).all(active))
    }

    pub(super) fn run_hosts<'w>(
        &mut self,
        live: &mut Live<'w>,
        slots: &mut Slots<'w>,
    ) -> Result<(), Stopped> {
        loop {
            self.free_unparked(slots);
            self.episodes(live, slots)?;
            if let Some(refusal) = self.draw_refusal.take() {
                return Err(Stopped::Choice(refusal));
            }
            if self.rerun_first
                && let Some(due) = self.refused_due()
            {
                self.rerun_refused(live, slots, due)?;
                continue;
            }
            if let Some((member, volume, witness, at)) = self.nominated.pop_front() {
                self.take_over(live, slots, member, (volume, witness, at))?;
                continue;
            }
            if let Some(at) = self.restarts.pop_front() {
                self.restart_named(live, slots, at)?;
                continue;
            }
            if let Some(due) = self.refused_due() {
                self.rerun_refused(live, slots, due)?;
                continue;
            }
            // A rerun waits until each open loss has sent its drawn GETs, so its load takes no round from them.
            let sent = self.losses.iter().all(|loss| loss.episode.due.is_empty());
            if sent && let Some(at) = self.rerun_due() {
                let (member, tenure, ended) = self.reruns.remove(&at).expect("the due rerun");
                self.rerun(live, slots, (at, member, tenure, ended))?;
                continue;
            }
            if let Some(at) = self.fresh_due() {
                self.activate_fresh(live, slots, at)?;
                continue;
            }
            if let Some(due) = self.next_return()? {
                self.neighbour_gets(live);
                self.restart_returned(live, slots, due)?;
                continue;
            }
            self.neighbour_gets(live);
            self.close_losses(live, false);
            self.zone_settled(live);
            let since = self.round - self.host_start;
            let last = self.faults.last_change().unwrap_or(0);
            let quiet = last + TAIL_ROUNDS;
            let due = self.losses.iter().any(|loss| !loss.episode.due.is_empty());
            let settled = !self.repairs() || self.recon.settled;
            let rerun = self.rerun_due().is_some();
            let waits = self.retaking(live);
            if self.faults.settled()
                && since >= quiet
                && !due
                && settled
                && !rerun
                && !waits
                && !self.refused_first()
                && !self.fresh_first()
            {
                // The GETs in flight settle first. A tenure whose exit waited for its GET is torn down in the turn
                // below, and a rerun queued meanwhile takes its turn at the top of the loop.
                self.drain(live)?;
                if self.rerun_due().is_none() && !self.ending(live) {
                    break;
                }
            }
            if since > self.horizon {
                // A standby that still waits to take its shard again, with no witness for `RESEND_WINDOWS` rounds,
                // names the stall.
                return Err(match self.unsent() {
                    Some(at) => self.stalled(Some(at), RESEND),
                    None => self.stalled(None, "the host scenario's settle"),
                });
            }
            self.turn(live);
            // A refused decision stops the run before the next fault step: a runnable-actor refusal before any actor
            // of the round stepped, a reconciler-order refusal before the round's reconcilers stepped.
            if let Some(refusal) = self.draw_refusal.take() {
                return Err(Stopped::Choice(refusal));
            }
        }
        if let Some(refusal) = self.draw_refusal.take() {
            return Err(Stopped::Choice(refusal));
        }
        self.close_losses(live, true);
        Ok(())
    }

    /// The first cell with a queued rerun whose host is not paused. A paused host's processes run nothing, so its
    /// rerun stays queued until the host resumes; a run that ends with the host still paused leaves it unrun.
    fn rerun_due(&self) -> Option<usize> {
        let mut queued = self.reruns.iter();
        queued.find_map(|(&at, &(member, ..))| (self.hosts[member].up != Up::Paused).then_some(at))
    }

    /// Tracks the settle phase of a run whose reconcilers run. The phase starts at the first round with every
    /// episode healed, every loop incarnation running for [`AGE_ROUNDS`](super::reconcile::AGE_ROUNDS) rounds, every
    /// zone's census covering its live named standbys or its loop out of warm-up and, in a crash-table cell, the cell's
    /// crash behind it. Each round it samples whether every shard serves with a standby or carries a blocker: the
    /// first settled round sets `turns`, and a later unsettled round clears it again. `ReconLog::settled` records
    /// whether the phase has stayed settled through the fixpoint count's ticks or has passed
    /// [`REPAIR_SETTLE_ROUNDS`]. The fixpoint count starts at a settled round on which every loop's plan is empty.
    /// A shard that both serves with a standby and carries a blocker other than `VolumeImpaired` counts as
    /// unsettled.
    pub(super) fn settle_phase(&mut self, live: &Live<'_>) {
        let since = self.round - self.host_start;
        let last = self.faults.last_change().unwrap_or(0);
        let healed = since >= last && self.faults.settled();
        let round = self.round;
        let running = (self.reconcilers.iter()).all(|actor| {
            actor.status == Status::Running && round >= actor.started + super::reconcile::AGE_ROUNDS
        });
        let crashed =
            !matches!(self.config.scenario, Scenario::Crash(_)) || !self.recon.crashed.is_empty();
        let phase = match self.recon.settle {
            Some(phase) => phase,
            None if healed && running && crashed && self.booted_all() => {
                let phase = super::reconcile::SettlePhase {
                    started: since,
                    turns: None,
                };
                self.recon.settle = Some(phase);
                phase
            }
            None => return,
        };
        let done = (0..self.cells.len()).all(|at| self.settled_at(live, at).settled());
        let turns = since - phase.started;
        let settled = match (done, phase.turns) {
            (true, None) => Some(turns),
            (true, held) => held,
            (false, _) => None,
        };
        self.recon.settle = Some(super::reconcile::SettlePhase {
            turns: settled,
            ..phase
        });
        // A settled run ends once the fixpoint count has covered `FIXPOINT_TICKS` ticks, or, in a run whose loops
        // keep planning steps, after four times as many rounds settled.
        let window = u64::from(super::reconcile::FIXPOINT_TICKS) * super::reconcile::TICK_ROUNDS;
        let counted = self.recon.fixpoint_ticks >= super::reconcile::FIXPOINT_TICKS;
        let long = settled.is_some_and(|first| turns - first >= 4 * window);
        self.recon.settled = (done && (counted || long)) || turns > REPAIR_SETTLE_ROUNDS;
        let quiet = self.quiet();
        self.recon.sample(done, quiet);
    }

    /// Queues the next incarnation of `member`'s process for cell `at` when `exit` names a rerun
    /// (`host::Exit::Rerun`); `after_loss` tells whether the incarnation that ended followed a loss. The entry keeps
    /// the round a serving tenure's rerun counts from (`Cell::rerun_from`) in [`Fleet::rerun_starts`]. Every other
    /// exit queues nothing: a hold holds, a parking exit parks, and `Deposed`, `Stopped` and `Fault` end the process.
    pub(super) fn queue_rerun(
        &mut self,
        at: usize,
        member: usize,
        exit: &crate::host::Exit,
        after_loss: bool,
    ) {
        if matches!(exit, crate::host::Exit::Rerun(_)) {
            self.refused.insert((at, member), (self.round, after_loss));
            // The refusal is a first one until the rerun of a refused incarnation marks it (`Fleet::rerun_refused`).
            self.recurred.remove(&(at, member));
            match self.cells[at].rerun_from {
                Some(ended) => self.rerun_starts.insert((at, member), ended),
                None => self.rerun_starts.remove(&(at, member)),
            };
        }
    }

    /// The device of cell `at`'s volume completes commands again, and each process that holds the shard
    /// (`Exit::Held`) is due its next incarnation from this round, ahead of the queue's later work. The process and
    /// device holds belong to the incarnation that returned `Exit::Held` and stand until the next one starts
    /// ([`Fleet::rerun_refused`]).
    pub(super) fn rerun_held(&mut self, at: usize) {
        self.cells[at].device = super::volumes::Device::Up;
        let ended = self.round.saturating_sub(1);
        let held: Vec<usize> = (self.cells[at].held.iter())
            .map(|(member, _)| *member)
            .collect();
        for member in held {
            self.refused.insert((at, member), (ended, true));
            // A returned host's held restart completes its return at this rerun.
            if self.held_returns.remove(&(at, member)) {
                self.returning.insert((at, member));
            }
        }
    }

    /// `member`'s incarnation for cell `at` read `role` and waits: a standby role publishes its `Standby` status
    /// ([`Fleet::publish_wait`]), and any other role ends the `Standby` status the member's process published
    /// before.
    pub(super) fn publish_role(&mut self, at: usize, member: usize, role: crate::host::Role) {
        match role {
            crate::host::Role::Standby { target } => self.publish_wait(at, member, target),
            _ => self.end_wait(at, member),
        }
    }

    /// Ends the `Standby` status `member`'s process published for cell `at`: its takeover acquired the shard's tenure,
    /// its incarnation read another role, or the process ended at an exit or at a failed role read, and its next
    /// incarnation, if any, publishes what it reads.
    pub(super) fn end_wait(&mut self, at: usize, member: usize) {
        if (self.cells[at].waiting).is_some_and(|(of, ..)| of == member) {
            self.cells[at].waiting = None;
        }
    }

    /// The wait of `member`'s incarnation for cell `at` publishes `Standby` with the target its role read
    /// returned and the active volume of the record version that read returned: the newest committed version with
    /// that target, read from the store with no request.
    pub(super) fn publish_wait(
        &mut self,
        at: usize,
        member: usize,
        target: crate::failover::retire::Target,
    ) {
        let versions = self.cells[at].history(&self.store);
        let read = (versions.iter().rev())
            .find(|record| crate::failover::retire::Target::of(record) == target)
            .expect("a committed version with the target the role read returned");
        self.cells[at].waiting = Some((member, target, read.active));
    }

    /// Records that `member`'s process waits as the named standby of cell `at` after the next incarnation of a
    /// takeover or of a refused restart, while the record names another owner.
    pub(super) fn retake(&mut self, at: usize, member: usize) {
        let record = self.record_now(at);
        let host = self.topology.members[member].host;
        if record.standby == Some(host) && record.owner != host {
            self.retakes.insert(at, member);
            self.retaken.insert(at, self.round);
        }
    }

    /// Records that an agent addressed `member`'s standby process of `shard` a witness for `target` this round.
    pub(super) fn witness(
        &mut self,
        member: usize,
        shard: u32,
        target: crate::failover::retire::Target,
    ) {
        let seen = self.witnessed.entry((member, shard)).or_default();
        match seen.iter_mut().find(|(of, _)| *of == target) {
            Some(last) => last.1 = self.round,
            None => seen.push((target, self.round)),
        }
    }

    /// The first cell of [`Fleet::retakes`] whose standby has waited, with the record naming a target an agent
    /// addressed it a witness for, for more than [`RESEND_WINDOWS`] rounds since the later of the last such witness
    /// and the start of its wait. The fleet reads the witnesses the agents addressed: a nomination reached the standby, the
    /// record still names its target, the standby still waits, and no witness followed in that many windows.
    /// `Fleet::turn` alone advances the round, after the agents' turns, so each round that passes is one window in
    /// which the agents turned. A standby that was never addressed a witness for the record's present target names
    /// no cell, whatever witnesses for other targets it was addressed.
    pub(super) fn unsent(&self) -> Option<usize> {
        self.retakes.iter().find_map(|(&at, &member)| {
            let since = *self.retaken.get(&at)?;
            let shard = self.cells[at].placement.shard.get();
            let present = crate::failover::retire::Target::of(&self.record_now(at));
            let seen = self.witnessed.get(&(member, shard))?;
            let &(_, last) = seen.iter().find(|(target, _)| *target == present)?;
            (self.round.saturating_sub(last.max(since)) > RESEND_WINDOWS).then_some(at)
        })
    }

    /// Whether a standby waits on a takeover still to run: some cell of [`Fleet::retakes`] has no tenure, or only
    /// the tenure an open loss took from it, which an isolated owner keeps unreachable; its record still names the
    /// waiting member standby of an owner other than its host, and that member runs.
    fn retaking(&mut self, live: &Live<'_>) -> bool {
        let pending: Vec<usize> = (self.retakes.iter())
            .filter(|&(&at, &member)| {
                let record = self.record_now(at);
                let host = self.topology.members[member].host;
                let tenure = live[at].as_ref().map(|serving| serving.tenure);
                let lost = (self.losses.iter())
                    .flat_map(|loss| loss.lost.iter().zip(&loss.held))
                    .any(|(&of, held)| of == at && *held == tenure);
                (tenure.is_none() || lost)
                    && record.standby == Some(host)
                    && record.owner != host
                    && self.hosts[member].up == Up::Running
            })
            .map(|(&at, _)| at)
            .collect();
        self.retakes.retain(|at, _| pending.contains(at));
        !self.retakes.is_empty()
    }

    /// Whether a process refused for the first time still waits for its next incarnation's turn: an entry of
    /// [`Fleet::refused`] outside [`Fleet::recurred`] whose host is not paused. The host loop runs that turn before
    /// it ends; a refusal that recurred holds no run open.
    fn refused_first(&self) -> bool {
        (self.refused.keys())
            .any(|key| !self.recurred.contains(key) && self.hosts[key.1].up != Up::Paused)
    }

    /// Whether a fresh activation refused for the first time still waits for its retry's turn: a cell whose
    /// activation stays due (`Cell::fresh_unread`) outside [`Fleet::recurred`], while the record's owner is the
    /// member that began the activation and its host runs, as [`Fleet::fresh_due`] requires of a retry. The host
    /// loop runs that turn before it ends; a retry that is refused again holds no run open.
    fn fresh_first(&self) -> bool {
        (0..self.cells.len()).any(|at| {
            let cell = &self.cells[at];
            cell.fresh_unread.is_some()
                && !self.recurred.contains(&(at, cell.holder))
                && self.member_of(self.record_now(at).owner) == Some(cell.holder)
                && self.hosts[cell.holder].up == Up::Running
        })
    }

    /// The first cell of [`Fleet::refused`] whose next incarnation is due: its incarnation ended before this round and
    /// its host is not paused. The next incarnation of a serving tenure's rerun ([`Fleet::rerun_starts`]) waits, as
    /// that rerun did, until each open loss has sent its drawn GETs, so its load takes no round from them.
    pub(super) fn refused_due(&mut self) -> Option<(usize, usize, bool)> {
        let round = self.round;
        let sent = self.losses.iter().all(|loss| loss.episode.due.is_empty());
        // A paused host's rerun stays queued until the host resumes.
        let key = (self.refused.iter())
            .find(|(key, (ended, _))| {
                *ended < round
                    && self.hosts[key.1].up != Up::Paused
                    && (sent || !self.rerun_starts.contains_key(key))
            })
            .map(|(&key, _)| key)?;
        let (_, after_loss) = self.refused.remove(&key)?;
        Some((key.0, key.1, after_loss))
    }

    pub(super) fn take_over<'w>(
        &mut self,
        live: &mut Live<'w>,
        slots: &mut Slots<'w>,
        member: usize,
        (volume, witness, received): (VolumeId, Revalidated, u64),
    ) -> Result<(), Stopped> {
        let Some(at) = self.cell_of(witness.shard) else {
            return Ok(());
        };
        if self.hosts[member].up != Up::Running || self.cells[at].holder == member {
            return Ok(());
        }
        let of = self.topology.members[member];
        let cell = &self.cells[at];
        let holder = holder_on(cell.placement.volume, of.host, of.instance);
        let shard = cell.placement.shard;
        // The production takeover's own acceptance of the witness, read for the lapse count alone. The standby
        // reads the witness at the agent turn's time: the fleet's queue holds a witness behind another takeover's
        // load only because the fleet runs bring-ups one at a time.
        let restart = restart_tests::restart_of(shard, holder);
        let addressed = self.addressed(member, volume, witness.shard);
        if !addressed || Takeover::nominated(restart, &witness, received).is_none() {
            self.log.lapsed += 1;
            return Ok(());
        }
        let (pair, local) = cell.local_of(member).expect("the standby's local record");
        let table = std::rc::Rc::clone(&cell.world.reservation);
        let from = table.borrow().log.len();
        // Under the plant the fencer starts the device before the period, while the record still names the lost
        // owner, and the period's CAS-BEFORE-DEVICE assertion fails.
        let early = self.config.planted_at(Plant::EarlyDevice, at);
        self.planted |= early;
        let ground = slots.take(member);
        // The period's client keeps the records its role read returned, as a view period's does.
        let returned = std::rc::Rc::default();
        let mut client = self.takeover_client(member, &returned);
        let persist = |_| Ok(local.0.clone().expect("the standby's local record"));
        let stood = super::owners::stand_by(
            (&self.cells[at], of, pair),
            (self.round, &self.store),
            ground.0,
            (&mut client, &local),
            (Some((witness, received)), early),
            persist,
        );
        let attempt = |refused| Attempt {
            shard: shard.get(),
            host: of.host.get(),
            refused,
            commands: super::owners::commands_since(&table, from),
        };
        // Whether the next incarnation after `Rerun::Takeover` restarted through its lineage arm.
        let mut lineage = false;
        let (tenure, control, now) = match stood {
            super::owners::Stood::Tenure(tenure, control, now) => {
                // The standby that acquired the tenure waits no more.
                self.end_wait(at, member);
                self.log.takeovers.push(attempt(None));
                (tenure, control, now)
            }
            // The takeover's refusal ends the incarnation, and the next one reads its role and recovers.
            super::owners::Stood::Ended(
                crate::host::Exit::Rerun(crate::host::Rerun::Takeover),
                refusal,
            ) => {
                let exit = crate::host::Exit::Rerun(crate::host::Rerun::Takeover);
                self.log
                    .takeovers
                    .push(attempt(Some(super::owners::blocker(&exit, refusal))));
                let mut local = super::owners::OwnerLocal(local);
                let mut plane = crate::failover::fresh::tests::plane();
                let mut refusals = crate::failover::fresh::Refusals::default();
                let sources = (&mut local, &mut plane, &mut refusals);
                let cell = (&self.cells[at], of, pair);
                // The next incarnation opens its own store client over the host's durable watermark log: a takeover
                // read that withdrew the ending incarnation's client withdraws none of the next one's.
                drop(client);
                client = self.takeover_client(member, &std::rc::Rc::default());
                match super::owners::incarnate(cell, self.round, ground.0, &mut client, sources) {
                    super::owners::Incarnation::Tenure(tenure, control, now) => {
                        self.end_wait(at, member);
                        let attempt = self.log.takeovers.last_mut().expect("the refused attempt");
                        attempt.refused = None;
                        lineage = tenure.lineage();
                        (tenure, control, now)
                    }
                    super::owners::Incarnation::Ended(exit, refusal) => {
                        slots.put_back(member, ground.0);
                        drop(client);
                        self.end_wait(at, member);
                        let held = self.cells[at].device != super::volumes::Device::Up
                            && self.record_now(at).owner == of.host;
                        self.queue_rerun(at, member, &exit, true);
                        if let (crate::host::Exit::Held { .. }, Some(refusal)) = (&exit, refusal) {
                            self.held(at, member, super::volumes::Held::of_restart(refusal));
                        }
                        let cell = &mut self.cells[at];
                        cell.flip_requests +=
                            usize::from(matches!(exit, crate::host::Exit::Retire(_)));
                        cell.blockers.push(super::owners::blocker(&exit, refusal));
                        if held {
                            (cell.holder, cell.blocked) = (member, true);
                            self.reread_hosts(at);
                        }
                        return Ok(());
                    }
                    // The next incarnation read the predecessor's record and waits as standby: the agent's next
                    // witness for the shard starts its takeover.
                    super::owners::Incarnation::Waits(role) => {
                        slots.put_back(member, ground.0);
                        self.publish_role(at, member, role);
                        self.retake(at, member);
                        return Ok(());
                    }
                    // A failed role read is the shard's blocker, which the settle check reads, and ends the
                    // incarnation with `Rerun::Records`.
                    super::owners::Incarnation::Unread(error) => {
                        slots.put_back(member, ground.0);
                        self.end_wait(at, member);
                        self.cells[at].blockers.push(format!("{error:?}"));
                        let records = crate::host::Exit::Rerun(crate::host::Rerun::Records);
                        self.queue_rerun(at, member, &records, true);
                        return Ok(());
                    }
                }
            }
            super::owners::Stood::Ended(exit, refusal) => {
                slots.put_back(member, ground.0);
                // `Stopped` ends a period that started no takeover, or whose takeover refused with its compare-and-swap
                // uncommitted and no device command issued: the wait goes on in place. `Rerun(RoleChanged)` and
                // `Rerun(Records)` end a period at its role read, before any takeover, and end the process; the
                // production supervisor then runs the standby process again. The fleet logs the attempt and queues
                // that next incarnation below. A takeover that unwound fails the period in `owners::stand_by`.
                if exit != crate::host::Exit::Stopped {
                    self.end_wait(at, member);
                    self.log
                        .takeovers
                        .push(attempt(Some(super::owners::blocker(&exit, refusal))));
                } else {
                    // The wait goes on, and its status comes from the role read this period made.
                    self.publish_read(at, member, &returned);
                    if self.record_now(at).owner != of.host {
                        self.log.takeovers.push(attempt(Some("Stopped".to_owned())));
                    }
                }
                // The host loop runs the next incarnation of a period that ended with a rerun exit: its role read
                // finds the wait again (`Fleet::retake`), or the restart role under a record that names its host
                // owner.
                self.queue_rerun(at, member, &exit, true);
                return Ok(());
            }
        };
        drop(client);
        if let Some(deposed) = live[at].take() {
            live.push(Some(deposed));
            self.deposed.push((at, self.cells[at].holder));
        }
        let serving_own = (self.cells.iter().zip(live.iter())).any(|(cell, serving)| {
            cell.holder == member && cell.placement.owner == member && serving.is_some()
        });
        self.log.loads_beside_service += u32::from(serving_own);
        self.cells[at].holder = member;
        let lost_at = self.cells[at].lost_at.unwrap_or(self.round);
        self.loading = Some(at);
        self.offer_beside(live, at);
        let rose = self.rise(
            live,
            ground,
            (at, pair),
            (*tenure, control, now),
            super::Source::Named,
        );
        self.loading = None;
        let tenure = rose?;
        if self.config.planted_at(Plant::TwinStart, at)
            && let Some(tenure) = tenure
        {
            let attempts = u32::try_from(tenure.a / 2 - 1).expect("an attempt count");
            let session = crate::storage::session_at(tenure.g, attempts);
            assert_eq!(super::tenure_of(session.get()), tenure);
            let _twin = crate::storage::ServingAuthority::fixture_under(session);
            let owner = self.cells[at].placement.owner;
            let other = (0..self.topology.members.len())
                .find(|&other| other != member && other != owner)
                .expect("a third host");
            (self.activations).push((at, tenure, self.topology.members[other].host));
            self.log.twin_started += 1;
            self.planted = true;
        }
        let rounds = self.round - lost_at;
        self.reread_hosts(at);
        let Some(tenure) = tenure else {
            return Ok(());
        };
        if lineage {
            let round = self.round - self.host_start;
            (self.volumes.arm).push((shard.get(), of.host.get(), round));
        }
        self.recovered(live, at, tenure, rounds, (true, true))
    }

    /// Offers one GET to each shard that the host loading cell `at` serves and that has no GET in flight, for the
    /// shard's first object outside its acknowledged INVALIDATE. The offer adds no request to a shard that holds
    /// one, so each shard stays inside the one-peer allowance `bounds::requests` keeps.
    fn offer_beside(&mut self, live: &mut Live<'_>, at: usize) {
        let member = self.cells[at].holder;
        for other in 0..self.cells.len() {
            let cell = &self.cells[other];
            let idle = self.flights.iter().all(|flight| flight.at != other);
            if other == at || cell.holder != member || live[other].is_none() || !idle {
                continue;
            }
            let objects = 1..=self.config.shape.objects;
            let Some(n) = objects.into_iter().find(|n| !cell.invalidated.contains(n)) else {
                continue;
            };
            let taken = (self.losses.iter()).any(|loss| loss.lost.contains(&other));
            let purpose = if taken {
                Purpose::Beside
            } else {
                Purpose::Neighbour
            };
            self.cells[other].requested.push(n);
            self.send(live, other, n, purpose);
        }
    }
    /// An unavailable or absent record keeps the host's last read of that record; any other read error stops the
    /// run, since the fleet does not model the client's withdrawal on it.
    pub(super) fn read_record(&mut self, member: usize, at: usize) {
        let shard = self.cells[at].placement.shard;
        let read = self.client(member).read::<ShardRecord>(Key::Shard(shard));
        let Some(read) = viewed(member, read) else {
            return;
        };
        let records = &mut self.hosts[member].records;
        match records.iter_mut().find(|record| record.shard == shard) {
            Some(slot) => *slot = *read.value(),
            None => records.push(*read.value()),
        }
    }

    /// Sweeps cell `at`'s recovered tenure and records its recovery and its charge. `after_loss` arms the plants of
    /// a recovery after a crash or a host loss; `dropped` records whether that fault dropped a live tenure.
    pub(super) fn recovered(
        &mut self,
        live: &mut Live<'_>,
        at: usize,
        tenure: Tenure,
        rounds: u64,
        (after_loss, dropped): (bool, bool),
    ) -> Result<(), Stopped> {
        let retained = match self.cells[at].cold {
            true => 0,
            false => self.config.shape.objects,
        };
        let objects = self.config.shape.objects;
        let first = (1..=objects).find(|n| !self.cells[at].invalidated.contains(n));
        let serving = live[at].as_mut().expect("the recovered tenure");
        let recovery = serving.owner.recovery_report();
        let (peak_bytes, saturated) = (recovery.io_peak_bytes, recovery.io_saturated_windows);
        let share = share_of(serving.storage);
        let mut read_bytes = super::device_reads(serving);
        if after_loss
            && self.config.planted_at(Plant::RestoredEntryMiss, at)
            && let Some(n) = first
        {
            self.planted |= super::drop_from_ram(serving, n);
        }
        let member = self.cells[at].holder;
        if self.config.planted_at(Plant::UnchargedRead, member) {
            read_bytes += 2 * share.bytes + 1;
            self.planted = true;
        }
        let sweep = if after_loss && self.config.planted_at(Plant::SkippedSweep, at) {
            self.planted = true;
            None
        } else {
            let objects: Vec<u8> = self.cells[at].world.objects.iter().map(|o| o.n).collect();
            let mut eligible = 0;
            self.swept = 0;
            for n in objects {
                let cell = &self.cells[at];
                let counted = n <= retained && !cell.invalidated.contains(&n);
                eligible += u32::from(counted);
                let before = self.swept;
                self.send(live, at, n, Purpose::Sweep);
                self.drain(live)?;
                if !counted {
                    let invalidated = self.cells[at].invalidated.contains(&n);
                    self.log.stale_hits += u32::from(invalidated && self.swept > before);
                    self.swept = before;
                } else if self.swept == before {
                    self.cells[at].unserved.push((tenure, n));
                }
            }
            Some((eligible, self.swept))
        };
        self.planted |= share.owners != self.divisor(member);
        let host = self.topology.members[member].host;
        let load = peak_bytes.max(read_bytes);
        (self.cells[at].charges).push(super::Charge { host, share, load });
        self.cells[at].recoveries.push(Recovered {
            tenure,
            host,
            after_crash: dropped,
            rounds,
            sweep,
            share,
            peak_bytes,
            read_bytes,
            saturated,
        });
        Ok(())
    }
}
