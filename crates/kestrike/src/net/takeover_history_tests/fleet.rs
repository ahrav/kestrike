//! Each shard's `Cell` contains a `World` that holds the shard's media, records, reservation table and history.
//! The cells share one store double, one shard-route table and the round counter `Fleet::round`.
//!
//! `Fleet::play` draws a topology inside [`bounds::LIMITS`], seeds each shard's records from the single-shard
//! fixtures, and recovers every owner once from its capturing tenure's media. Each owner then, in a drawn order,
//! drops without quiesce and recovers while the other shards serve the GETs drawn for the [`DOWN_ROUNDS`] rounds
//! the shard stays down. Each recovered tenure reads every object in its shard during the retained-set sweep.
//! The reconciler stand-ins survey after each recovery. Every fresh activation and every restart, the one that
//! follows a standby's refused takeover included, is an incarnation of the production owner process (`owners`): its
//! role read, `host::recover` through a fencer over the host's device double, and the production bring-up, one
//! `host::serve::turn_up` per owner turn of the round loop. A standby's takeover in a host scenario (`hosts`) runs
//! one `host::stand_by` view period (`owners::stand_by`) through a fencer over the standby's device double, and its
//! tenure starts through the same production bring-up (`Fleet::rise`). The `actors` module holds the owner turn and
//! the reconciler tick.
//!
//! A host scenario (`hosts`) instead boots every owner, has each acknowledge one FILL and one INVALIDATE, and runs
//! host actors that detect each other and take a lost owner's shards over; a reconciler scenario (`reconcile`) adds
//! reconciler actors that repair standbys over the zone's census.
//!
//! `Fleet::report` fills [`Verdicts`]: `one_owner` checks one owner per attempt and per activated tenure,
//! `keeps_volume` that no record, receipt or flip request moves the volume, `retained` RETAINED-OR-REFUSED over
//! each sweep and `World::judged`, `settles` the [`SETTLE_ROUNDS`] bound of a restart run and fleet oracle F5 over
//! `reconcile::REPAIR_SETTLE_ROUNDS` in a reconciler scenario, `within_share` HOST-SHARE over each host's seeded
//! roles, or in a reconciler scenario over the shape's static roles bound and the most roles each host held,
//! `untouched` the shards that serve through another shard's recovery, whose only store requests are their own
//! duties' record views and, in a host scenario, their standby's wait, at most two record reads and no write a view
//! period, and `census` fleet oracle F4 in a reconciler scenario.
//! A run on the `az` layout also fills `fenced` from `oracles::fenced_before_admission`: each tenure's fence commits
//! precede its first admitted operation.
//!
//! Every placement, recovery order and neighbour GET is a recorded decision, and so is the order of two reconcilers
//! in a round; the zone loop ranks its own candidate hosts. A replay refuses a decision whose candidates differ. The round
//! loop steps every live tenure in shard order each round, so the tape holds no runnable-actor choice among hosts
//! and tenures, and a replay does not detect a changed set of them.
//!
//! Once `Live`, every tenure runs the production serving duties, `host::Duties::turn` after each owner poll of a
//! fleet round over an inline store lane (`host::Lane::inline`) whose client reaches the store through the cell's own
//! fault actor (`duty_actor`) inside its holder host's outages (`HostOut`): a record view every `DUTY_VIEW_US`, the
//! tenure open's Confirm and suffix reservation, suffix steps and the coverage write of each held INVALIDATE. The
//! workload helpers that wait for a FILL, an INVALIDATE's acknowledgement or the duties' open step the tenure's owner
//! and duties inside one fleet round while the other actors wait. Each turn also reads the tenure's recovery line once
//! its first-safe-hit span closes, as `serve` writes it. The exit the duties or the owner's state names ends the
//! duties. From that turn the served check (`serves`) counts the tenure out, its owner keeps its slot of the live
//! table and is polled each round until the fleet ends the tenure, and an exit its scenario does not script fails the
//! run's credit. In a host scenario an exit that names a rerun or reads `Deposed` ends the shard's tenure as `serve`
//! does, through `serve::teardown`, whose drain runs the tenure's device rounds and ends with one more sample of the
//! device for the ownership monitor. A deposed tenure that withdrew in a slot past the cells ends the same way. After
//! a rerun exit the process's next incarnation, its role read and `host::recover`, runs once every open loss has sent
//! its drawn GETs and its host is not paused, and the host loop ends once every such tenure is torn down and every
//! queued rerun whose host is not paused has had its turn. A paused host's rerun waits for the host's resume, and a
//! run that ends with the host still paused leaves it queued, in no counter of the report. A restart run, which has
//! no hosts, runs no teardown and no next incarnation. A hold is the exit of a bring-up or a recovery, which ends
//! before its tenure serves.
//!
//! Each tenure serves under the `Honest` clock and the moving bounds from the fleet's round, so a live owner
//! renews its Report window every round it is stepped. The write guard stays unarmed in every run. A restart run
//! issues GETs alone. In a host scenario each boot tenure, and each tenure a zone's return restarts, also publishes
//! one FILL and acknowledges one INVALIDATE after its sweep.

use std::collections::{BTreeSet, VecDeque};
use std::num::NonZeroU32;
use std::sync::Arc;

use sha2::{Digest, Sha256};

use crate::failover::evidence::Pair;
use crate::failover::records::{Host, Record, ShardRecord, VolumeRecord};
use crate::failover::restart::tests::{self as restart_tests, Stored};
use crate::failover::route::HighWater;
use crate::failover::serving::State;
use crate::failover::takeover::tests::{
    bound_record, fence_page_zero_of, holder_on, holds_registered, lineage_on,
};
use crate::oracle::{NEVER_SERVED, Preserved, Tenure};
use crate::storage::store::sim::Shared;
use crate::storage::store::{Item, Key, Outcome, Store, Write};
use crate::storage::warm_sim::{layout, object_key, share_of, storage_shared, tenure_a_on};
use crate::storage::{EngineBudget, HostShare, MetadataOutcome, Readiness};

use super::super::ShardRoutes;
use super::super::client::{GetRefused, SessionState};
use super::super::fetch::Outcome as Fetched;
use super::super::requests::RequestId;
use super::cycles::{Plant as CyclePlant, Verdict, hex};
use super::{
    FleetDuties, Grounds, Inline, Pools, ROUND_US, Serving, Source, WINDOW, World, activate,
    closed, collect, content, first, honest, tenure_of,
};

pub(crate) mod actors;
pub(crate) mod bounds;
pub(crate) mod draws;
pub(crate) mod faults;
pub(crate) mod hosts;
pub(crate) mod oracles;
pub(crate) mod owners;
pub(crate) mod reconcile;
pub(crate) mod topology;
pub(crate) mod volumes;
pub(crate) mod zones;

#[cfg(test)]
mod driven;
#[cfg(test)]
mod host_tests;
#[cfg(test)]
mod repair_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod volume_tests;
#[cfg(test)]
mod zone_tests;

use self::draws::{Draws, Refusal, Tag};
use self::faults::{Faults, Hostile};
use self::hosts::{HostActor, HostLog, Loss, Scenario};
use self::oracles::{HostUse, Judged, Retention, Settle, Volumes, Watched};
use self::reconcile::{ReconLog, ReconcilerActor};
use self::topology::{Placement, Placing, Shape, Topology};

/// A crashed owner restarts after `DOWN_ROUNDS` rounds. During those rounds, the other shards serve the GETs drawn
/// for the recovery.
pub(crate) const DOWN_ROUNDS: u64 = 4;
/// `settles` bounds the rounds from an owner's crash until the recovered tenure has an active client session by
/// `SETTLE_ROUNDS`. The bound is a hypothesis.
pub(crate) const SETTLE_ROUNDS: u64 = 64;
/// The turns one wait for a GET's outcome, a bootstrap or a client session takes before the run stops `Stalled`.
const WAIT_ROUNDS: u32 = 8_000;
const FIRST_KEY_EPOCH: u64 = 16;
const FIRST_HOST_ID: u8 = 0x40;
const SHARE_BYTES: u64 = 1 << 22;
const SHARE_INTERVAL_US: u64 = 10 * ROUND_US;
/// The tenure slots each host holds beyond its seeded roles when reconcilers run, for loads of shards it was
/// designated for during the run.
const REPAIR_SLOTS: usize = 6;
/// The rounds `serve::teardown` drains an ended tenure's owner before it gives up and keeps the owner.
const TEARDOWN_ROUNDS: u64 = 64;
/// The static bound on a host's roles, owned shards and census entries together, in every fleet shape.
pub(crate) const ROLES_MAX: u32 = 6;

/// A deliberate defect of the world or the driver that one fleet check must detect, or that removes a check's
/// reach event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Plant {
    /// `Fleet::plant_records` rewrites the shard's record with its standby as owner, no standby and `attempts`
    /// unchanged.
    TwinTenure,
    /// In a scenario whose reconcilers run, `Fleet::plant_loss` lists the shard's volume in state `error` on the zone
    /// double after its host is lost. In any other scenario `Fleet::plant_records` rewrites the shard's record at the
    /// next generation with `attempts` zero.
    LossEvidence,
    /// The shard's recovery after its crash calls `drop_from_ram` before its sweep.
    RestoredEntryMiss,
    /// In a restart run the crashed owner stays down while `Fleet::restart` reports no blocker; in a reconciler
    /// scenario `Fleet::collect` keeps the shard at the index from taking a blocker.
    SilentBlocker,
    /// `Fleet::share` calculates the shard owner's share using an owner count of one.
    WholeShare,
    /// During the shard's crash episode, the target shard of the first GET sent calls `drop_from_ram` on the
    /// requested object. In a host scenario the index names the lost host by member index, and the first GET of
    /// that host's loss is refused.
    NeighborRefusal,
    /// The schedule holds each owner's first recovery alone, so the run ends before any crash. The plant applies
    /// to the whole run and ignores the profile's index.
    NoCrashEpisode,
    /// The shard's recovery after its crash leaves its `sweep` at `None`.
    SkippedSweep,
    /// A host scenario records a second activation of the shard's successor tenure, on a host other than the
    /// successor and the seeded owner, under an authority `ServingAuthority::fixture_under` builds at the
    /// successor's session.
    TwinStart,
    /// In a host scenario, the host at the index is charged twice its share and one byte more of device reads on
    /// each load, reads its storage never charged.
    UnchargedRead,
    /// A second loop under the census cap plus one runs beside the first. The plant applies to the whole run and
    /// ignores the profile's index.
    WideCap,
    /// `Fleet::plant_survey` removes the enrollment steps of the shard at the index from each survey.
    DropNeed,
    /// `Fleet::collect` enters `CensusFull` for the shard at the index with no refusal behind it.
    UnbackedBlocker,
    /// `Fleet::drop_entry` removes the shard's census entry at the index while its record still names the standby.
    UncoveredEntry,
    /// The host that takes the shard over starts its fencer's device before the standby's view period runs, so the
    /// device call precedes the takeover's compare-and-swap, and the period's CAS-BEFORE-DEVICE assertion over the
    /// record the fencer's connect met panics.
    EarlyDevice,
    /// `Fleet::held_entries` leaves the held entry of the shard at the index out of every report but its holder's.
    EnrollBack,
    /// The log of the first admitted operation of the first returning tenure of the shard at the index reads zero
    /// commits on every coverage page, so the operation precedes the tenure's fence commits.
    EarlyAdmission,
    /// Once the fixpoint count of a reconciler scenario has started, `Fleet::plant_settled_write` rewrites zone 1's
    /// census with the value it holds through loop 0's store, one store write of a settled zone. The plant ignores
    /// the profile's index.
    SettledWrite,
    /// Once a loss or a crash episode is open, the serving duties' store of the untouched shard at the index reads its
    /// shard record once more, beside its record views.
    ExtraRead,
    /// Once a loss or a crash episode is open, the serving duties' store of the untouched shard at the index rewrites
    /// its shard record at its version with the value it holds.
    DutyRewrite,
    /// The run's coverage writes acknowledge a held INVALIDATE on a write whose reply is unknown
    /// (`coverage::ACK_ON_UNKNOWN`). The plant ignores the profile's index. The report reads it planted once a
    /// coverage write of a tenure's duties reached the store and got an unknown reply; a write a holder host's
    /// outage answers unknown ([`HostOut`]) reaches no store and is not counted.
    AckOnUnknown,
    /// Each view period while waiting, the indexed shard's standby supplements its role read with one read of
    /// either its own shard record or the record named by `Fleet::standby_extra`.
    StandbyExtraRead,
}

impl Plant {
    pub(crate) const ALL: [Self; 22] = [
        Self::TwinTenure,
        Self::LossEvidence,
        Self::RestoredEntryMiss,
        Self::SilentBlocker,
        Self::WholeShare,
        Self::NeighborRefusal,
        Self::NoCrashEpisode,
        Self::SkippedSweep,
        Self::TwinStart,
        Self::UnchargedRead,
        Self::WideCap,
        Self::DropNeed,
        Self::UnbackedBlocker,
        Self::UncoveredEntry,
        Self::EarlyDevice,
        Self::EnrollBack,
        Self::EarlyAdmission,
        Self::SettledWrite,
        Self::ExtraRead,
        Self::DutyRewrite,
        Self::AckOnUnknown,
        Self::StandbyExtraRead,
    ];

    /// `Config::identity` encodes the hostile profile with the plant code.
    pub(crate) fn code(self) -> u8 {
        match self {
            Self::RestoredEntryMiss => CyclePlant::RestoredEntryMiss.code(),
            Self::TwinTenure => 13,
            Self::LossEvidence => 14,
            Self::SilentBlocker => 15,
            Self::WholeShare => 16,
            Self::NeighborRefusal => 17,
            Self::NoCrashEpisode => 18,
            Self::SkippedSweep => 19,
            Self::TwinStart => 20,
            Self::UnchargedRead => 21,
            Self::WideCap => 22,
            Self::DropNeed => 23,
            Self::UnbackedBlocker => 24,
            Self::UncoveredEntry => 25,
            Self::EarlyDevice => 26,
            Self::EnrollBack => 40,
            Self::EarlyAdmission => 45,
            Self::SettledWrite => 50,
            Self::ExtraRead => 51,
            Self::DutyRewrite => 52,
            Self::AckOnUnknown => 53,
            Self::StandbyExtraRead => 54,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Profile {
    /// A run that passes earns credit.
    Legal,
    /// The plant and the zero-based index of the cell it applies to; shard numbers start at one. For
    /// `NeighborRefusal` the index names the crashed shard whose episode sends the refused GET, and in a host
    /// scenario the lost host by member index, as it does for `WholeShare` and `UnchargedRead`. `NoCrashEpisode`
    /// and `WideCap` ignore the index, and any other plant with an index past the last cell plants nothing.
    /// `Config::identity` encodes the index of every plant.
    Hostile(Plant, u32),
    /// A hostile profile whose episodes may break a premise of the fleet's rules; it plants nothing.
    Arm(Hostile),
}

/// One run's inputs. `Draws::record` derives every decision from `root`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Config {
    pub(crate) root: u64,
    pub(crate) shape: Shape,
    /// The GETs drawn for each crash episode, sent to the shards that serve through it.
    pub(crate) requests: u32,
    pub(crate) profile: Profile,
    pub(crate) scenario: Scenario,
}

impl Config {
    /// One zone of six hosts in three partitions and six shards of eight objects: each host owns one shard.
    pub(crate) fn six(root: u64) -> Self {
        let shape = Shape {
            zones: 1,
            partitions: 3,
            hosts: 6,
            shards: 6,
            objects: 8,
            reconcilers: 2,
            placing: Placing::Drawn,
            cap: 6,
            roles_max: ROLES_MAX,
        };
        Self {
            root,
            shape,
            requests: 2,
            profile: Profile::Legal,
            scenario: Scenario::Restarts,
        }
    }

    /// Two zones of two hosts each and eight shards of four objects: each host holds four roles.
    pub(crate) fn dense(root: u64) -> Self {
        let shape = Shape {
            zones: 2,
            partitions: 2,
            hosts: 2,
            shards: 8,
            objects: 4,
            reconcilers: 2,
            placing: Placing::Drawn,
            cap: 4,
            roles_max: ROLES_MAX,
        };
        Self {
            shape,
            ..Self::six(root)
        }
    }

    /// The `small` layout of [`Placing::Small`] with eight objects per shard, under `Fleet::play`'s restarts.
    pub(crate) fn small(root: u64) -> Self {
        let shape = Shape {
            zones: 1,
            partitions: 4,
            hosts: 6,
            shards: 6,
            objects: 8,
            reconcilers: 2,
            placing: Placing::Small,
            cap: 6,
            roles_max: ROLES_MAX,
        };
        Self {
            shape,
            ..Self::six(root)
        }
    }

    /// The `trio` layout of [`Placing::Trio`] with eight objects per shard, under `Fleet::play`'s restarts.
    pub(crate) fn trio(root: u64) -> Self {
        let shape = Shape {
            hosts: 8,
            placing: Placing::Trio,
            ..Self::small(root).shape
        };
        Self {
            shape,
            ..Self::six(root)
        }
    }

    /// The `tiny` layout of [`Placing::Tiny`] with eight objects per shard and one reconciler.
    pub(crate) fn tiny(root: u64) -> Self {
        let shape = Shape {
            zones: 1,
            partitions: 3,
            hosts: 4,
            shards: 2,
            objects: 8,
            reconcilers: 1,
            placing: Placing::Tiny,
            cap: 2,
            roles_max: ROLES_MAX,
        };
        Self {
            shape,
            ..Self::six(root)
        }
    }

    /// The `az` layout of [`Placing::Az`] with eight objects per shard, one reconciler per zone and a census cap of
    /// six per zone, under `scenario`.
    pub(crate) fn az(root: u64, scenario: Scenario) -> Self {
        let shape = Shape {
            zones: 2,
            partitions: 4,
            hosts: 6,
            shards: 8,
            objects: 8,
            reconcilers: 1,
            placing: Placing::Az,
            cap: 6,
            roles_max: ROLES_MAX,
        };
        Self {
            shape,
            scenario,
            ..Self::six(root)
        }
    }

    /// `az` with no fault.
    pub(crate) fn az_settle(root: u64) -> Self {
        Self::az(root, Scenario::Settle)
    }

    /// `az` where every host of zone 1 stops and returns.
    pub(crate) fn zone_loss(root: u64) -> Self {
        Self::az(root, Scenario::ZoneLoss)
    }

    /// `az` where every host of zone 1 stops while the control plane reports the zone's volumes impaired.
    pub(crate) fn zone_impaired(root: u64) -> Self {
        Self::az(root, Scenario::ZoneImpaired)
    }

    /// `az` where H3 crashes, H0 takes s3 over, and every host of zone 1 then stops and returns.
    pub(crate) fn zone_deposed(root: u64) -> Self {
        Self::az(root, Scenario::ZoneDeposed)
    }

    /// The tenure slots the run allocates: one per owner and standby role, and in a host scenario two more per owned
    /// shard on `az` or [`REPAIR_SLOTS`] per host when reconcilers run.
    pub(crate) fn slots(&self) -> u32 {
        match self.scenario.hosted() && self.zoned() {
            true => self.shape.shards.saturating_mul(4),
            false => self.scenario.tenures(&self.shape),
        }
    }

    /// Whether the run holds two zones in the `az` layout, where the fleet judges the fence-before-admission check.
    pub(crate) fn zoned(&self) -> bool {
        self.shape.placing == Placing::Az
    }

    /// `small` with one reconciler actor under `scenario`.
    pub(crate) fn repair(root: u64, scenario: Scenario) -> Self {
        let mut config = Self {
            scenario,
            ..Self::small(root)
        };
        config.shape.reconcilers = 1;
        config
    }

    pub(crate) fn settle(root: u64) -> Self {
        Self::repair(root, Scenario::Settle)
    }

    pub(crate) fn reenroll(root: u64) -> Self {
        Self::repair(root, Scenario::Reenroll)
    }

    pub(crate) fn slot_moved(root: u64) -> Self {
        Self::repair(root, Scenario::SlotMoved)
    }

    pub(crate) fn standby_loss(root: u64) -> Self {
        Self::repair(root, Scenario::StandbyLoss)
    }

    pub(crate) fn standby_silent(root: u64) -> Self {
        Self::repair(root, Scenario::StandbySilent)
    }

    pub(crate) fn double_loss(root: u64) -> Self {
        Self::repair(root, Scenario::DoubleLoss)
    }

    /// The two-host loss of [`Config::partition_loss`] with the reconciler running.
    pub(crate) fn partition_repair(root: u64) -> Self {
        Self::repair(root, Scenario::PartitionRepair)
    }

    /// The three-host loss of [`Config::partition_loss_at`] with one reconciler running, on `trio`.
    pub(crate) fn partition_repair_at(root: u64) -> Self {
        let mut config = Self::repair(root, Scenario::PartitionRepairAt);
        config.shape = Shape {
            reconcilers: 1,
            ..Self::trio(root).shape
        };
        config
    }

    /// `small` with a census cap of five, where s5 starts with no standby.
    pub(crate) fn census_full(root: u64) -> Self {
        let mut config = Self::repair(root, Scenario::CensusFull);
        config.shape.cap = 5;
        config
    }

    /// `small` where s2's volume holds a third attach, of H1; H0 and H5 crash and H1 survives.
    pub(crate) fn attach_survivor(root: u64) -> Self {
        Self::repair(root, Scenario::AttachSurvivor)
    }

    /// `small` where s2's volume holds a third attach, of H1; H0, H1 and H5 crash.
    pub(crate) fn attach_closed(root: u64) -> Self {
        Self::repair(root, Scenario::AttachClosed)
    }

    pub(crate) fn foreign(root: u64) -> Self {
        Self::repair(root, Scenario::Foreign).arm(Hostile::ForeignRegistrant)
    }

    /// The host loss of `small` under two reconciler actors.
    pub(crate) fn racing(root: u64) -> Self {
        let mut config = Self::repair(root, Scenario::Racing);
        config.shape.reconcilers = 2;
        config
    }

    pub(crate) fn crash(root: u64, cell: reconcile::CrashCell) -> Self {
        let scenario = Scenario::Crash(cell);
        match cell.fresh {
            true => Self::repair(root, scenario),
            false => Self {
                scenario,
                ..Self::tiny(root)
            },
        }
    }

    pub(crate) fn impaired(root: u64) -> Self {
        Self::repair(root, Scenario::Impaired)
    }

    pub(crate) fn impaired_brief(root: u64) -> Self {
        Self::repair(root, Scenario::ImpairedBrief)
    }

    pub(crate) fn stall(root: u64) -> Self {
        Self::repair(root, Scenario::Stall)
    }

    pub(crate) fn lost_alone(root: u64) -> Self {
        Self::repair(root, Scenario::LostAlone)
    }

    pub(crate) fn correlated(root: u64) -> Self {
        Self::repair(root, Scenario::Correlated)
    }

    /// `small` where s3's volume is lost alone and s4's volume turns impaired before the create step.
    pub(crate) fn correlated_late(root: u64) -> Self {
        Self::repair(root, Scenario::CorrelatedLate)
    }

    /// `tiny` with no fault and its one reconciler running.
    pub(crate) fn tiny_settle(root: u64) -> Self {
        Self {
            scenario: Scenario::Settle,
            ..Self::tiny(root)
        }
    }

    pub(crate) fn replace(root: u64, cell: volumes::ReplaceCell) -> Self {
        Self {
            scenario: Scenario::Replace(cell),
            ..Self::tiny(root)
        }
    }

    /// H0's loss on `small`, with the store timeout of `cell` on one write of s4's boot tenure's serving duties.
    pub(crate) fn store_unknown(root: u64, cell: hosts::Unknown) -> Self {
        Self {
            scenario: Scenario::StoreUnknown(cell),
            ..Self::small(root)
        }
    }

    /// H0's loss on `small`, with s4's boot coverage write timed out and committed and the page's re-read returning
    /// the page's first version, under the store-kill profile: the read serves a version below one already
    /// committed, which a correct store never does.
    pub(crate) fn page_regressed(root: u64) -> Self {
        Self {
            scenario: Scenario::PageRegressed,
            ..Self::small(root)
        }
        .arm(faults::Hostile::StoreKill)
    }

    /// H0's loss on `small`, with the record view of s4's acknowledged boot tenure reading its shard record's version
    /// before the last, under the store-kill profile.
    pub(crate) fn record_regressed(root: u64) -> Self {
        Self {
            scenario: Scenario::RecordRegressed,
            ..Self::small(root)
        }
        .arm(faults::Hostile::StoreKill)
    }

    pub(crate) fn host_loss(root: u64) -> Self {
        Self {
            scenario: Scenario::HostLoss,
            ..Self::small(root)
        }
    }

    /// `small`'s two-host partition loss ([`Scenario::PartitionLoss`]), below the host agent's self-suspicion
    /// threshold.
    pub(crate) fn partition_loss(root: u64) -> Self {
        Self {
            scenario: Scenario::PartitionLoss,
            ..Self::small(root)
        }
    }

    /// The loss of `trio`'s three-host first partition ([`Scenario::PartitionLossAt`]), at the host agent's
    /// self-suspicion threshold.
    pub(crate) fn partition_loss_at(root: u64) -> Self {
        Self {
            scenario: Scenario::PartitionLossAt,
            ..Self::trio(root)
        }
    }

    pub(crate) fn owner_pause(root: u64) -> Self {
        Self {
            scenario: Scenario::OwnerPause,
            ..Self::small(root)
        }
    }

    pub(crate) fn owner_isolation(root: u64) -> Self {
        Self {
            scenario: Scenario::OwnerIsolation,
            ..Self::small(root)
        }
    }

    pub(crate) fn false_suspicion(root: u64) -> Self {
        Self {
            scenario: Scenario::FalseSuspicion,
            ..Self::small(root)
        }
    }

    pub(crate) fn arm(self, hostile: Hostile) -> Self {
        Self {
            profile: Profile::Arm(hostile),
            ..self
        }
    }

    #[cfg(test)]
    pub(crate) fn arm_legal(self) -> Self {
        Self {
            profile: Profile::Legal,
            ..self
        }
    }

    pub(crate) fn hostile(self, plant: Plant, at: u32) -> Self {
        Self {
            profile: Profile::Hostile(plant, at),
            ..self
        }
    }

    /// The first sixteen hex digits of the SHA-256 of the [`IDENTITY_TAG`] tag followed by a fixed-width encoding of
    /// every field. [`replay`] refuses a recording that carries another identity. The tag stands for the encoding and
    /// for the run's fixed behavior: the fixtures, the schedule of one boot and one crash per shard, each host
    /// scenario's script, the reconciler actor's steps, the `DOWN_ROUNDS`, `REPAIR_SLOTS`, `reconcile::RESTART_ROUNDS`,
    /// `reconcile::REPAIR_SETTLE_ROUNDS` and share constants, the draw sites and the report's lines. A change to
    /// any of them takes a new tag.
    pub(crate) fn identity(&self) -> String {
        self.identity_tagged(IDENTITY_TAG)
    }

    /// The identity of [`Config::identity`] over `tag`.
    fn identity_tagged(&self, tag: &[u8]) -> String {
        let Self {
            root,
            shape:
                Shape {
                    zones,
                    partitions,
                    hosts,
                    shards,
                    objects,
                    reconcilers,
                    placing,
                    cap,
                    roles_max,
                },
            requests,
            profile,
            scenario,
        } = *self;
        let mut bytes = tag.to_vec();
        bytes.extend(root.to_le_bytes());
        bytes.extend(zones.to_le_bytes());
        bytes.extend(partitions.to_le_bytes());
        bytes.extend(hosts.to_le_bytes());
        bytes.extend(shards.to_le_bytes());
        bytes.extend([objects, reconcilers, placing.code()]);
        bytes.extend(cap.to_le_bytes());
        bytes.extend(roles_max.to_le_bytes());
        bytes.extend(requests.to_le_bytes());
        bytes.extend(scenario.code());
        match profile {
            Profile::Legal => bytes.push(0),
            Profile::Hostile(plant, at) => {
                bytes.extend([1, plant.code()]);
                bytes.extend(at.to_le_bytes());
            }
            Profile::Arm(hostile) => bytes.extend([2, hostile.code()]),
        }
        hex(&Sha256::digest(&bytes)[..8])
    }

    fn planted(&self, plant: Plant) -> bool {
        matches!(self.profile, Profile::Hostile(of, _) if of == plant)
    }

    fn planted_at(&self, plant: Plant, at: usize) -> bool {
        self.profile == Profile::Hostile(plant, at as u32)
    }
}

/// The format tag [`Config::identity`] hashes first.
pub(crate) const IDENTITY_TAG: &[u8] = b"fleet-v20-inbox";

/// One tenure that restarted, loaded warm and opened its client session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Recovered {
    pub(crate) tenure: Tenure,
    pub(crate) host: Host,
    /// Whether the recovery follows the owner's process crash; the owner's first recovery of the run does not.
    pub(crate) after_crash: bool,
    /// The interval runs from recovery start until the client session becomes active. After a crash, the
    /// interval starts at the crash.
    pub(crate) rounds: u64,
    /// The objects the sweep requested and how many of them it received with exact bytes.
    pub(crate) sweep: Option<(u32, u32)>,
    pub(crate) share: HostShare,
    pub(crate) peak_bytes: u64,
    /// The read bytes the device double accepted from the attach until the client session opened.
    pub(crate) read_bytes: u64,
}

/// The GETs drawn for a shard while another shard recovered, and those it served with exact bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Neighbour {
    pub(crate) offered: u32,
    pub(crate) served: u32,
}

/// The reconciler stand-ins' ticks, and the shard records they read that name no standby, summed over the ticks.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Reconciled {
    pub(crate) ticks: u32,
    pub(crate) unnamed: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ShardReport {
    pub(crate) placement: Placement,
    pub(crate) owner: Host,
    pub(crate) standby: Host,
    pub(crate) recoveries: Vec<Recovered>,
    pub(crate) blockers: Vec<String>,
    pub(crate) attempts: u32,
    pub(crate) neighbour: Neighbour,
    /// The object each GET offered to the shard during another shard's recovery named, in send order.
    pub(crate) requested: Vec<u8>,
    /// The objects whose INVALIDATE a tenure of the shard acknowledged.
    pub(crate) invalidated: BTreeSet<u8>,
    /// Each eligible object a sweep's exact count excludes, with the sweeping tenure, in send order. A sweep's
    /// exact count is its eligible count less its entries here.
    pub(crate) unserved: Vec<(Tenure, u8)>,
    /// Each tenure of the shard that activated, with the host that restarted it, in activation order.
    pub(crate) activated: Vec<(Tenure, Host)>,
    /// The Reservation Reports logged on the shard's reservation table while each of its tenures served, counted once
    /// per tenure from its start: a fencer's or an overlapping tenure's Report on the same table in that interval
    /// counts too.
    pub(crate) reports: usize,
    /// The reads and the writes of each view period of the shard's standby wait, in period order.
    pub(crate) waits: Vec<(u64, u64)>,
    /// The exit of each view period of the shard's standby wait that ended other than `Exit::Stopped`.
    pub(crate) wait_exits: Vec<String>,
}

impl ShardReport {
    /// Whether the shard recovered at boot and again after its crash with no blocker, and both tenures served
    /// every object of their sweeps.
    fn restarted_twice(&self) -> bool {
        let swept = |recovered: &Recovered| {
            recovered
                .sweep
                .is_some_and(|(requested, served)| requested == served)
        };
        let order: Vec<bool> = self.recoveries.iter().map(|r| r.after_crash).collect();
        self.blockers.is_empty() && order == [false, true] && self.recoveries.iter().all(swept)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Verdicts {
    pub(crate) one_owner: Verdict,
    pub(crate) keeps_volume: Verdict,
    pub(crate) retained: Verdict,
    pub(crate) settles: Verdict,
    pub(crate) within_share: Verdict,
    pub(crate) untouched: Verdict,
    /// Fleet oracle F4, in a run whose reconciler actors write the census.
    pub(crate) census: Option<Verdict>,
    /// The fence-before-admission check, in a run on the `az` layout.
    pub(crate) fenced: Option<Verdict>,
}

impl Verdicts {
    pub(crate) fn named(&self) -> Vec<(&'static str, &Verdict)> {
        let mut named = vec![
            ("one owner per tenure", &self.one_owner),
            ("volume kept", &self.keeps_volume),
            ("retained set", &self.retained),
            ("settle or blocker", &self.settles),
            ("host share", &self.within_share),
            ("untouched shards", &self.untouched),
        ];
        named.extend(self.census.iter().map(|census| ("census cap", census)));
        let fenced = self.fenced.iter();
        named.extend(fenced.map(|fenced| ("fence before admission", fenced)));
        named
    }
}

pub(crate) const HOSTILE: &str = "a hostile profile earns no credit";
pub(crate) const INCOMPLETE: &str =
    "a shard of a legal run did not complete its boot and its restart after the crash";
pub(crate) const TOOK_OVER: &str = "a legal run recorded an owner change";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Report {
    pub(crate) identity: String,
    pub(crate) config: Config,
    pub(crate) shards: Vec<ShardReport>,
    pub(crate) verdicts: Verdicts,
    /// The owner changes between adjacent versions of the shard records.
    pub(crate) takeovers: u32,
    pub(crate) crashes: u32,
    pub(crate) rounds: u64,
    pub(crate) reconciled: Reconciled,
    /// Whether the profile's plant changed the run.
    pub(crate) planted: bool,
    pub(crate) decisions: u64,
    pub(crate) tape: Vec<u8>,
    pub(crate) hosts: HostLog,
    /// The oracles' inputs, which a control alters and judges again.
    pub(crate) evidence: Evidence,
    pub(crate) recon: ReconLog,
    pub(crate) volumes: volumes::VolumeLog,
    pub(crate) zones: zones::ZoneLog,
    pub(crate) duties: DutyLog,
}

/// What the tenures' serving duties did: the closed tenures whose duties' open ended `Opened` (a tenure whose record
/// names no checkpoint, as on a cold replacement volume, opens with its suffix log closed), the boot tenures that
/// acknowledged their FILL and their INVALIDATE, the duties' reads and writes over every key, and each exit the
/// duties named, with its shard and tenure.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct DutyLog {
    pub(crate) opened: u32,
    pub(crate) acknowledged: u32,
    pub(crate) reads: u64,
    pub(crate) writes: u64,
    pub(crate) exits: Vec<(u32, Tenure, crate::host::Exit)>,
    /// The faulted boot tenure of a store-result scenario, as the run ended.
    pub(crate) faulted: Option<FaultedDuty>,
    /// Each tenure that `serve::teardown` closed, with its shard and whether the owner shut down with its parts
    /// returned, in close order: a tenure whose turn named a `Rerun` or a `Deposed` exit, and a deposed tenure that
    /// withdrew in a slot past the cells. Only a tenure whose exit is `Rerun` and whose owner shut down reruns, and
    /// only while the record still names its host owner; a kept owner keeps its process from rerunning.
    pub(crate) torn: Vec<(u32, Tenure, bool)>,
    /// The tenures whose recovery line the serving turn read, by shard.
    pub(crate) lines: Vec<(u32, Tenure)>,
}

/// What the faulted boot tenure of a store-result scenario did: its tenure, whether a write took the armed fault
/// (the duties' actor holds no queued arm), which of the duties' writes on the shard's records first had an unknown
/// reply, whether the duties' store served the scenario's stale read, the duties' writes on the shard record and on
/// the coverage pages, the coverage pages' acknowledged commits when the INVALIDATE was held and when the duties
/// acknowledged it (`None` while unacknowledged), and the shard's recoveries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FaultedDuty {
    pub(crate) tenure: Tenure,
    pub(crate) taken: bool,
    pub(crate) timed_out: Option<hosts::DutyWrite>,
    pub(crate) stale_served: bool,
    pub(crate) record_writes: u64,
    pub(crate) page_writes: u64,
    pub(crate) held_at: usize,
    pub(crate) acknowledged_at: Option<usize>,
    pub(crate) recoveries: usize,
    /// The authority's withdrawal cause at run end; `None` if the authority reads `Serving` or the tenure has
    /// stopped. The duties also name `Rerun(Withdrawn)` when a coverage step fails under a serving authority, so
    /// this cause is the evidence that the owner withdrew.
    pub(crate) withdrawal: Option<crate::failover::serving::Cause>,
}

/// Every committed version of each shard record, each activation, and the volume counts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Evidence {
    pub(crate) histories: Vec<(crate::net::ownership::Shard, Vec<ShardRecord>)>,
    pub(crate) activations: Vec<(crate::net::ownership::Shard, Tenure, Host)>,
    pub(crate) volumes: Volumes,
    /// Each committed census version's entry count, zone by zone, and the entries the zones' censuses list when the
    /// run ends.
    pub(crate) censuses: Vec<usize>,
    pub(crate) census_entries: usize,
    /// The fence of every committed version of each coverage page, and each tenure's first admitted operation, in a
    /// run on the `az` layout.
    pub(crate) fences: Vec<oracles::PageFences>,
    pub(crate) admissions: Vec<oracles::Admission>,
    /// Each shard's settle state when the run ended.
    pub(crate) settled: Vec<oracles::Settled>,
    /// Each shard's largest count of live attaches over its volume record's committed versions.
    pub(crate) attached: Vec<(crate::net::ownership::Shard, usize)>,
    /// What the injector lost, which fleet oracle F2 judges against.
    pub(crate) losses: oracles::Losses,
    /// For each shard whose volume the injector marked lost: its generation's rise over the run and the volumes a
    /// create step returned for it.
    pub(crate) replaced: Vec<(u64, usize)>,
    /// Each shard's replacement receipt when the run ended.
    pub(crate) receipts: Vec<Option<crate::failover::loss::Receipt>>,
    /// Each shard's largest number of listings of one instance in its volume's attachment listing in the zone
    /// double, zero with no zone double.
    pub(crate) listed: Vec<(crate::net::ownership::Shard, usize)>,
    /// Each shard's largest number of attach requests the zone double logged for one instance on its volume, zero
    /// with no zone double.
    pub(crate) requests: Vec<(crate::net::ownership::Shard, usize)>,
    /// Each shard whose final record names a standby, and whether the cell holds a local record for that standby
    /// whose pair is the pair its volume record enrolls for it.
    pub(crate) standby_local: Vec<(crate::net::ownership::Shard, bool)>,
    /// Each shard's census slot host when the run ended, `None` with no slot or no census.
    pub(crate) slots: Vec<(crate::net::ownership::Shard, Option<Host>)>,
}

impl Report {
    /// In order: the first serving-duty exit the scenario does not script ([`hosts::unscripted_exit`]), in a host
    /// run and in a restart run; the first verdict that fails; for a legal run, `Fail(INCOMPLETE, ..)` when a shard
    /// reported a blocker or lacks one of its two swept recoveries, then `Fail(TOOK_OVER, ..)` when a record changed
    /// owner; the first verdict that is `Unrun` or `Inconclusive`; `Unrun(HOSTILE)` for a hostile run; `Pass`.
    pub(crate) fn credit(&self) -> Verdict {
        if let Some(failed) = hosts::unscripted_exit(self) {
            return failed;
        }
        let scenario = self.config.scenario;
        if scenario.hosted() {
            return self.hosted_credit();
        }
        let verdicts = self.verdicts.named();
        let failed = verdicts
            .iter()
            .find(|(_, verdict)| verdict.rule().is_some());
        if let Some((_, verdict)) = failed {
            return (*verdict).clone();
        }
        let legal = self.config.profile == Profile::Legal;
        let incomplete = self.shards.iter().find(|shard| !shard.restarted_twice());
        if let (true, Some(shard)) = (legal, incomplete) {
            let at = format!("shard {}", shard.placement.shard.get());
            return Verdict::Fail(INCOMPLETE, at);
        }
        if legal && self.takeovers != 0 {
            return Verdict::Fail(TOOK_OVER, format!("{} owner changes", self.takeovers));
        }
        let undecided = verdicts.iter().find(|(_, verdict)| !verdict.passed());
        match undecided {
            Some((_, verdict)) => (*verdict).clone(),
            None if legal => Verdict::Pass,
            None => Verdict::Unrun(HOSTILE),
        }
    }

    /// A host scenario's credit: the first failed verdict, then the scenario's first broken outcome or missing
    /// witness, then the first other verdict the scenario judges that did not pass, and for a hostile profile
    /// `Unrun(HOSTILE)`.
    fn hosted_credit(&self) -> Verdict {
        let scenario = self.config.scenario;
        let verdicts = self.verdicts.named();
        let excused = |name: &str, verdict: &Verdict| {
            self.recon.premise_failed
                && name == "settle or blocker"
                && verdict.rule() == Some(oracles::UNSETTLED)
        };
        let failed =
            (verdicts.iter()).find(|(name, v)| matches!(v, Verdict::Fail(..)) && !excused(name, v));
        if let Some((_, failed)) = failed {
            return (*failed).clone();
        }
        let expected = hosts::expected(self);
        if !expected.passed() {
            return expected;
        }
        let open = (verdicts.iter()).find(|(name, v)| !v.passed() && scenario.judges(name));
        match (open, self.config.profile) {
            (Some((_, verdict)), _) => (*verdict).clone(),
            (None, Profile::Hostile(..) | Profile::Arm(_)) => Verdict::Unrun(HOSTILE),
            (None, Profile::Legal) => Verdict::Pass,
        }
    }

    /// One line: the root, the host and shard counts, each verdict, the credit and the identity. A hostile run's
    /// line ends with its plant and index.
    pub(crate) fn summary(&self) -> String {
        let verdicts: Vec<String> = (self.verdicts.named().iter())
            .map(|(name, verdict)| format!("{name} {}", verdict.word()))
            .collect();
        let plant = match self.config.profile {
            Profile::Legal => String::new(),
            Profile::Hostile(plant, at) => format!("; plant {plant:?} at {at}"),
            Profile::Arm(hostile) => format!("; profile {}", hostile.name()),
        };
        format!(
            "fleet: root {} hosts {} shards {}: {}; credit {}; identity {}{plant}",
            self.config.root,
            self.config.shape.members(),
            self.config.shape.shards,
            verdicts.join("; "),
            self.credit().word(),
            self.identity,
        )
    }

    /// The output includes the summary, configuration, run counts, and tape hash. Host runs include one line with
    /// host log counts and lists. Reconciler runs include one line with reconciler counts and logs. Each shard has one
    /// line. The output also includes a hash of the entire report's `Debug` form, including oracle inputs and held
    /// starts (`HostLog::held`).
    pub(crate) fn lines(&self) -> Vec<String> {
        let id = &self.identity;
        let mut lines = vec![
            self.summary(),
            format!("fleet: {id} configuration {:?}", self.config),
            format!(
                "fleet: {id} takeovers {} crashes {} rounds {} reconciler ticks {} records without standby {} decisions {} tape {}",
                self.takeovers,
                self.crashes,
                self.rounds,
                self.reconciled.ticks,
                self.reconciled.unnamed,
                self.decisions,
                hex(&Sha256::digest(&self.tape)),
            ),
        ];
        let duties = &self.duties;
        lines.push(format!(
            "fleet: {id} duties opened {} acknowledged {} reads {} writes {} exits {:?} torn {:?} lines {:?}",
            duties.opened,
            duties.acknowledged,
            duties.reads,
            duties.writes,
            duties.exits,
            duties.torn,
            duties.lines
        ));
        if self.config.scenario.hosted() {
            let log = &self.hosts;
            lines.push(format!(
                "fleet: {id} hosts nominations {} addressed {} vetoes {} contested {} stale-replies {} unmatched-probes {} repair-demands {} host-losses {} lapsed {} unslotted {} rerun-dropped {} refused-reruns {} reports {} refused {} exempt {:?} loads-beside-service {} served-beside-load {} twins {} withdrawals {:?} unwithdrawn {} stale-hits {} headrooms {:?} stores {:?} takeovers {:?} boot {:?} fired {:?} arrivals {:?}",
                log.nominations,
                log.addressed,
                log.vetoes,
                log.contested,
                log.stale_replies,
                log.unmatched_probes,
                log.repair_demands,
                log.host_losses,
                log.lapsed,
                log.unslotted,
                log.rerun_dropped,
                log.refused_reruns,
                log.reports,
                log.refused,
                log.exempt,
                log.loads_beside_service,
                log.served_beside_load,
                log.twin_started,
                log.withdrawals,
                log.unwithdrawn,
                log.stale_hits,
                log.headrooms,
                log.stores,
                log.takeovers,
                log.boot,
                log.fired,
                log.arrivals,
            ));
        }
        if self.config.scenario.repairs() {
            let recon = &self.recon;
            lines.push(format!(
                "fleet: {id} reconciler ticks {} orders {} incarnations {:?} reservations {} contended {} at-cap {} refused-full {} condition {} stale {} releases {} reclaims {:?} restarts {} crashed {:?} crash-writes {:?} crash-aim {:?} unordered {} rewrites {} after-settle {:?} fixpoint-ticks {} cap-below {:?} uncovered {:?} settle {:?} designations {:?} blockers {:?} refusals {:?} census {:?}",
                recon.calls,
                recon.orders,
                recon.incarnations,
                recon.reservations,
                recon.contended,
                recon.at_cap,
                recon.refused_full,
                recon.condition,
                recon.stale(),
                recon.releases,
                recon.reclaims,
                recon.restarts,
                recon.crashed,
                recon.crash_writes,
                recon.crash_aim,
                recon.unordered,
                recon.rewrites,
                recon.after_settle,
                recon.fixpoint_ticks,
                recon.cap_below,
                recon.uncovered,
                recon.settle,
                recon.designations,
                recon.blockers,
                recon.refusals,
                self.evidence.censuses,
            ));
        }
        if self.config.scenario.repairs() {
            let volumes = &self.volumes;
            lines.push(format!(
                "fleet: {id} volumes stalled {:?} lost {:?} retained {} latched {} released {} calls-at-release {:?} calls {} made {} created {:?} flipped {} cold {:?} fresh-refused {:?} crashed {:?} guarded {} replaced {:?} stranded {:?}",
                volumes.stalled,
                volumes.lost,
                volumes.retained,
                volumes.latched,
                volumes.released,
                volumes.calls_at_release,
                volumes.calls,
                volumes.made,
                volumes.created,
                volumes.flipped,
                volumes.cold,
                volumes.fresh_refused,
                volumes.crashed,
                volumes.guarded,
                self.evidence.replaced,
                volumes.stranded,
            ));
        }
        if self.config.zoned() {
            let zones = &self.zones;
            lines.push(format!(
                "fleet: {id} zones down {:?} returned {} unplaced {:?} impaired {:?} down-writes {} down-calls {} other-moved {:?} other-censuses {:?} restarts {:?} deposed {:?} acknowledged {} fence-writes {} settled-in {:?} admissions {}",
                zones.down,
                zones.returned,
                zones.unplaced,
                zones.impaired,
                zones.down_writes,
                zones.down_calls,
                zones.other_moved,
                zones.other_censuses,
                zones.restarts,
                zones.deposed,
                zones.acknowledged,
                zones.fence_writes,
                zones.settled_in,
                self.evidence.admissions.len(),
            ));
        }
        for shard in &self.shards {
            lines.push(format!(
                "fleet: {id} shard {} zone {} owner {} standby {} attempts {} neighbour {}/{} objects {:?} reports {} blockers {:?} activated {:?} recoveries {:?} waits {:?} wait-exits {:?}",
                shard.placement.shard.get(),
                shard.placement.zone.0,
                shard.owner.get(),
                shard.standby.get(),
                shard.attempts,
                shard.neighbour.served,
                shard.neighbour.offered,
                shard.requested,
                shard.reports,
                shard.blockers,
                shard.activated,
                shard.recoveries,
                shard.waits,
                shard.wait_exits,
            ));
        }
        let whole = Sha256::digest(format!("{self:?}").as_bytes());
        lines.push(format!("fleet: {id} report {}", hex(&whole)));
        lines
    }

    /// The hash of [`Report::lines`].
    pub(crate) fn digest(&self) -> String {
        hex(&Sha256::digest(self.lines().join("\n").as_bytes()))
    }

    pub(crate) fn recording(&self) -> Recording {
        Recording {
            identity: self.identity.clone(),
            tape: self.tape.clone(),
        }
    }
}

/// A run's identity and its decision tape, which [`replay`] reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Recording {
    pub(crate) identity: String,
    pub(crate) tape: Vec<u8>,
}

/// A wait that spent its turn budget with its condition still false.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Stall {
    pub(crate) identity: String,
    /// The shard whose recovery waited, or `None` for a wait on GET outcomes.
    pub(crate) shard: Option<u32>,
    pub(crate) waited: &'static str,
    /// The fleet round the wait ended at.
    pub(crate) round: u64,
}

/// Why a run returned no report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Stopped {
    /// The shape or the request count is past a limit; no draw or allocation preceded the refusal.
    Shape(bounds::Refused),
    /// The replayed configuration's identity differs from the recording's; the tape was not read.
    Identity { recorded: String, replayed: String },
    /// The chooser refused a decision before it applied: its candidates differ from the tape's, the tape ran
    /// short, or its record is malformed or selects no candidate. A tape with bytes past the run's last decision
    /// is refused once that decision applied.
    Choice(Refusal),
    /// A wait passed its turn budget. The run's verdicts are undecided and its tape is dropped.
    Stalled(Stall),
    /// The profile refuses an episode of the scenario's script; no draw preceded the refusal.
    Inadmissible(faults::Inadmissible),
}

impl From<Refusal> for Stopped {
    fn from(refusal: Refusal) -> Self {
        Self::Choice(refusal)
    }
}

/// Runs `config` with decisions drawn from its root.
///
/// # Errors
///
/// `Stopped::Shape` and `Stopped::Stalled`, as [`Stopped`] states them.
///
/// # Panics
///
/// As `play_within` states.
pub(crate) fn run(config: &Config) -> Result<Report, Stopped> {
    play(config, || Draws::record(config.root))
}

/// One report for each configuration the fleet tests run through [`run_shared`], in first-run order.
#[cfg(test)]
type SharedRuns = Vec<(Config, Arc<std::sync::OnceLock<Result<Report, Stopped>>>)>;

/// [`run`] once per configuration in a test process: the first call for `config` runs it, and every later call
/// returns a copy of that report. A run is a function of its configuration, which the pinned runs show by digest in
/// fresh processes, so the tests that read an unplanted run's report share one run of it. A call waits only for a
/// first run of its own configuration. The calling thread's armed controls are refused before the lookup, as a run
/// refuses them, so a cached report never stands in for that check.
#[cfg(test)]
pub(crate) fn run_shared(config: &Config) -> Result<Report, Stopped> {
    refuse_armed_controls();
    static RUNS: std::sync::Mutex<SharedRuns> = std::sync::Mutex::new(Vec::new());
    let once = {
        let mut runs = RUNS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match runs.iter().find(|(of, _)| of == config) {
            Some((_, once)) => Arc::clone(once),
            None => {
                let once = Arc::new(std::sync::OnceLock::new());
                runs.push((*config, Arc::clone(&once)));
                once
            }
        }
    };
    once.get_or_init(|| run(config)).clone()
}

/// Runs `config` with the decisions of `recording`.
///
/// # Errors
///
/// Each [`Stopped`] variant, as it states. `Stopped::Identity` precedes every other check.
///
/// # Panics
///
/// As `play_within` states.
pub(crate) fn replay(config: &Config, recording: &Recording) -> Result<Report, Stopped> {
    let replayed = config.identity();
    if replayed != recording.identity {
        let recorded = recording.identity.clone();
        return Err(Stopped::Identity { recorded, replayed });
    }
    play(config, || Draws::replay(recording.tape.clone()))
}

fn play(config: &Config, draws: impl FnOnce() -> Draws) -> Result<Report, Stopped> {
    play_within(config, draws, WAIT_ROUNDS)
}

/// `play_within` checks the shape for the tenure slots the run allocates, the request count, the scenario's
/// admission of the shape and the profile's admission of every episode of the scenario's script before it calls
/// `draws`. Each wait of the run takes at most `wait` turns.
///
/// # Panics
///
/// When the thread's `checkpoint::PLANT`, recovery `PARK` or write guard is armed, before `draws` runs: the
/// first two change what a recovery does and the run's identity encodes neither, and a fleet tenure serves with
/// the guard unarmed. On a GET the driver's own client refuses for local pressure.
fn play_within(
    config: &Config,
    draws: impl FnOnce() -> Draws,
    wait: u32,
) -> Result<Report, Stopped> {
    config.shape.check().map_err(Stopped::Shape)?;
    bounds::tenures(config.slots()).map_err(Stopped::Shape)?;
    bounds::requests(config.requests).map_err(Stopped::Shape)?;
    config
        .scenario
        .admits(&config.shape)
        .map_err(Stopped::Shape)?;
    // Each owner of a host scenario acknowledges an INVALIDATE of object 1, and a GET draws among the others.
    if config.scenario.hosted() && config.requests > 0 && config.shape.objects < 2 {
        return Err(Stopped::Shape(bounds::Refused::Objects(
            config.shape.objects,
        )));
    }
    let planted = config.planted(Plant::NoCrashEpisode);
    let members = config.shape.hosts as usize * usize::from(config.shape.zones);
    let episodes = config.scenario.episodes(planted);
    let script = episodes.len();
    (Faults::new(episodes, members).admit(config.profile)).map_err(Stopped::Inadmissible)?;
    // A regressed read serves a version below one a client already read, a kill fault of the store.
    let regressed = matches!(
        config.scenario,
        Scenario::PageRegressed | Scenario::RecordRegressed
    );
    let kill = faults::Kind::Hostile(faults::Hostile::StoreKill);
    if regressed && !kill.admitted(config.profile) {
        let refused = faults::Inadmissible {
            episode: script,
            kind: kill,
        };
        return Err(Stopped::Inadmissible(refused));
    }
    refuse_armed_controls();
    let _inline = Inline::set();
    let _ack = AckOnUnknown::set(config.planted(Plant::AckOnUnknown));
    Fleet::play(config, draws(), wait)
}

/// Sets `coverage::ACK_ON_UNKNOWN` on the calling thread for the life of the value when the run plants
/// [`Plant::AckOnUnknown`], and clears it when dropped, an unwound run included.
struct AckOnUnknown(bool);

impl AckOnUnknown {
    fn set(planted: bool) -> Self {
        crate::storage::page_coverage::ACK_ON_UNKNOWN.with(|plant| plant.set(planted));
        Self(planted)
    }
}

impl Drop for AckOnUnknown {
    fn drop(&mut self) {
        if self.0 {
            crate::storage::page_coverage::ACK_ON_UNKNOWN.with(|plant| plant.set(false));
        }
    }
}

/// Panics by name when a thread-local test control that a fleet run would reach is armed on the calling thread.
fn refuse_armed_controls() {
    let plant = crate::storage::checkpoint::PLANT.with(std::cell::Cell::get);
    assert!(plant.is_none(), "checkpoint::PLANT is armed: {plant:?}");
    let parked = crate::storage::PARK_RECOVERY.with(std::cell::Cell::get);
    assert!(!parked, "the recovery helpers' PARK is armed: {parked}");
    let guarded = crate::storage::write_guard::armed();
    assert!(!guarded, "the write guard is armed: {guarded}");
    let planted = crate::host::agent::tests::armed();
    assert!(!planted, "a host agent plant is armed: {planted}");
    let planted = crate::host::duties::tests::armed();
    assert!(!planted, "a serving duties plant is armed: {planted}");
    use crate::storage::page_coverage::{ACK_ON_UNKNOWN, UNBOUND_REPLIES};
    let planted =
        ACK_ON_UNKNOWN.with(std::cell::Cell::get) || UNBOUND_REPLIES.with(std::cell::Cell::get);
    assert!(!planted, "a coverage plant is armed: {planted}");
}

/// What a watch compares of a shard between two samples: its record's generation, attempts and owner, and its
/// client's route with the route's kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Seen {
    named: (u64, u32, u64),
    route: Option<HighWater>,
}

/// One tenure's attach on its host: the share its storage holds and its load, the larger of its storage's peak
/// window bytes and the read bytes its device double accepted.
#[derive(Debug, Clone, Copy)]
struct Charge {
    host: Host,
    share: HostShare,
    load: u64,
}

struct Cell {
    world: World,
    placement: Placement,
    owner: Host,
    standby: Host,
    local: Stored,
    pair: Pair,
    standby_local: Stored,
    standby_pair: Pair,
    /// The member that holds the shard's current tenure, or held its last one.
    holder: usize,
    /// Whether the boot tenure acknowledged its FILL and its INVALIDATE.
    acknowledged: bool,
    invalidated: BTreeSet<u8>,
    /// Each INVALIDATE a tenure held and has not acknowledged: its object, its coverage page's key, and the tenure
    /// that held it. `Cell::close` resolves the entries of the tenure it closes.
    unsettled: Vec<(u8, Key, Tenure)>,
    /// The round the holder's host crashed in.
    lost_at: Option<u64>,
    /// The coverage pages the seeded shard record declares.
    pages: u16,
    recoveries: Vec<Recovered>,
    /// Each entry pairs a sweep's tenure with an eligible object that the sweep's exact count excludes.
    unserved: Vec<(Tenure, u8)>,
    /// Each tenure that attached, a load that did not open included.
    charges: Vec<Charge>,
    blockers: Vec<String>,
    /// Whether the shard's last recovery ended in a blocker.
    blocked: bool,
    flip_requests: usize,
    /// The tenures that opened a client session and closed with an authority other than `Serving`.
    withdrawals: usize,
    /// [`ShardReport::reports`].
    reports: usize,
    /// The tenures that closed with their serving duties' open at `Opened`.
    duty_opened: u32,
    /// Each closed tenure whose serving duties ended at an exit, with that exit, in close order.
    duty_exits: Vec<(Tenure, crate::host::Exit)>,
    /// Each closed tenure whose serving turn read its recovery line.
    lines: Vec<Tenure>,
    /// The store requests the shard's standby sent to each of the shard's records over the view periods of its
    /// wait, by key.
    waited: std::collections::BTreeMap<Key, u64>,
    /// The reads and the writes of each view period of the shard's standby wait, in period order.
    waits: Vec<(u64, u64)>,
    /// The exit of each view period of the shard's standby wait that ended other than `Exit::Stopped`.
    wait_exits: Vec<String>,
    /// While a rerun's restart runs, the round its tenure ended, which the recovery's rounds count from.
    rerun_from: Option<u64>,
    /// The object of each GET offered to the shard during another shard's recovery.
    requested: Vec<u8>,
    /// The member whose attach and enrolled pair the seeded volume record holds beside the owner's and the standby's.
    third: Option<(usize, Pair, Stored)>,
    /// Whether the seeded record names the standby.
    seeded_standby: bool,
    /// The hosts that enrolled a pair for the shard during the run, with their local records.
    enrolled: Vec<(usize, Pair, Stored)>,
    /// The blocker the shard carries.
    blocker: Option<crate::failover::zone_loop::status::Blocker>,
    /// The state of the volume the cell runs, as the injector set it.
    device: volumes::Device,
    /// The members whose restart or takeover held at a device step of the cell's volume.
    device_holds: BTreeSet<usize>,
    /// Whether the cell runs a replacement volume, which retains nothing.
    cold: bool,
    fresh_refused: bool,
    /// The round of a fresh activation whose role read failed or whose incarnation ended with an exit that names a
    /// rerun; the activation retries from a later round.
    fresh_unread: Option<u64>,
    /// Each host the loop's status first named in an enrollment of the shard, and whether the active volume held its
    /// live attach then.
    planned: Vec<(Host, bool)>,
    /// Each member whose restart or takeover of the shard holds, with the recovery its reports state.
    held: Vec<(usize, volumes::Held)>,
}

/// How a scenario seeds one shard: with or without its named standby, and with a third attached host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Seed {
    pub(crate) standby: bool,
    pub(crate) third: Option<usize>,
    /// Each seeded host's pair stands under its attach entry's key, as the zone loop's `end_attach` requires.
    pub(crate) keyed: bool,
}

impl Cell {
    fn new(
        store: &Shared,
        routes: &Arc<ShardRoutes>,
        topology: &Topology,
        placement: Placement,
        (objects, seed): (u8, Seed),
    ) -> Self {
        let local = |member: usize| {
            let key = ((member as u64 + FIRST_KEY_EPOCH) << 32) | u64::from(placement.shard.get());
            let instance = topology.members[member].instance;
            bound_record(
                instance,
                placement.volume,
                key,
                member as u8 + FIRST_HOST_ID,
            )
        };
        let (owner, standby) = (
            topology.members[placement.owner].host,
            topology.members[placement.standby].host,
        );
        let (mut own, mut other) = (local(placement.owner), local(placement.standby));
        let mut third = (seed.third).map(|member| (member, local(member)));
        let a = tenure_a_on(placement.shard, objects, |n| content(n, first(n)));
        let record = ShardRecord {
            shard: placement.shard,
            active: placement.volume,
            owner,
            spare: None,
            checkpoint: Some(a.named),
            standby: seed.standby.then_some(standby),
            ..restart_tests::shard_record(4)
        };
        let mut successors = Vec::new();
        if seed.standby {
            successors.push((standby, other.pair()));
        }
        if let Some((member, record)) = &third {
            successors.push((topology.members[*member].host, record.pair()));
        }
        let mut volume = VolumeRecord {
            layout: layout(),
            ..lineage_on(placement.volume, (owner, own.pair()), &successors)
        };
        // Each seeded attach binds its host's instance, as `Reconciler::record_standby` writes an entry
        // (BIND-AT-ATTACH).
        for event in &mut volume.events {
            event.instance = (topology.members.iter())
                .find(|member| member.host == event.host)
                .map(|member| member.instance);
        }
        // KEY-PER-ATTACH: each seeded host's pair stands under its own attach entry's key, as `enroll_standby` and
        // the owner's fresh activation write it, so the loop's `end_attach` can end any of them.
        let rekey = |volume: &mut VolumeRecord, member: usize| {
            let of = topology.members[member];
            let key = volume.attach_key(of.host).expect("a seeded attach's key");
            let keyed = bound_record(
                of.instance,
                placement.volume,
                key.encode(),
                member as u8 + FIRST_HOST_ID,
            );
            let attach = volume.live(of.host).expect("a seeded live attach");
            for recorded in volume.pairs.iter_mut() {
                if recorded.host == of.host && recorded.attach == attach {
                    recorded.pair = keyed.pair();
                }
            }
            keyed
        };
        if seed.keyed {
            own = rekey(&mut volume, placement.owner);
            if seed.standby {
                other = rekey(&mut volume, placement.standby);
            }
            if let Some((member, record)) = third.as_mut() {
                *record = rekey(&mut volume, *member);
            }
        }
        restart_tests::seed(store, record, volume);
        fence_page_zero_of(store, placement.shard, record.generation.get());
        let reservation = holds_registered(own.pair(), &[]);
        let held = (placement.shard, store.clone(), reservation);
        let mut world = World::assemble(a, held, Arc::clone(routes), |_| None);
        world.set_moving_clock(honest(0));
        Self {
            world,
            placement,
            owner,
            standby,
            pair: own.pair(),
            local: Stored(Ok(own)),
            standby_pair: other.pair(),
            standby_local: Stored(Ok(other)),
            holder: placement.owner,
            acknowledged: false,
            invalidated: BTreeSet::new(),
            unsettled: Vec::new(),
            lost_at: None,
            pages: record.pages.get(),
            recoveries: Vec::new(),
            unserved: Vec::new(),
            charges: Vec::new(),
            blockers: Vec::new(),
            blocked: false,
            flip_requests: 0,
            withdrawals: 0,
            reports: 0,
            duty_opened: 0,
            duty_exits: Vec::new(),
            lines: Vec::new(),
            waited: std::collections::BTreeMap::new(),
            waits: Vec::new(),
            wait_exits: Vec::new(),
            rerun_from: None,
            requested: Vec::new(),
            third: third.map(|(member, record)| (member, record.pair(), Stored(Ok(record)))),
            seeded_standby: seed.standby,
            enrolled: Vec::new(),
            blocker: None,
            device: volumes::Device::Up,
            device_holds: BTreeSet::new(),
            cold: false,
            fresh_refused: false,
            fresh_unread: None,
            planned: Vec::new(),
            held: Vec::new(),
        }
    }

    /// The pair and local record of a host whose pair the volume record enrolls: the seeded owner, the seeded
    /// standby, the seeded third host, or a host that enrolled during the run. A cell on a replacement volume holds
    /// its hosts in the enrolled list alone.
    fn local_of(&self, member: usize) -> Option<(Pair, Stored)> {
        let found =
            |of: &(usize, Pair, Stored)| (of.0 == member).then(|| (of.1, Stored(of.2.0.clone())));
        if let Some(enrolled) = self.enrolled.iter().rev().find_map(found) {
            return Some(enrolled);
        }
        let (pair, local) = if member == self.placement.owner && !self.cold {
            (self.pair, &self.local)
        } else if member == self.placement.standby && self.seeded_standby {
            (self.standby_pair, &self.standby_local)
        } else {
            return self.third.as_ref().and_then(found);
        };
        Some((pair, Stored(local.0.clone())))
    }

    /// The members the seeded volume record holds a live attach of.
    fn attached(&self) -> Vec<usize> {
        let mut attached = vec![self.placement.owner];
        if self.seeded_standby {
            attached.push(self.placement.standby);
        }
        attached.extend(self.third.as_ref().map(|(member, ..)| *member));
        attached
    }

    /// Keeps `member`'s enrolled pair and local record for its takeover.
    fn enrolled(&mut self, member: usize, pair: Pair, local: Stored) {
        if self.local_of(member).is_none_or(|(held, _)| held != pair) {
            self.enrolled.push((member, pair, local));
        }
    }

    /// Accounts a refused restart, takeover or fresh activation that holds the shard: the check joins the cell's
    /// blockers, a flip request the refusal carried is counted, and the cell reads blocked.
    fn refuse(&mut self, check: String, flip: bool) {
        self.flip_requests += usize::from(flip);
        self.blockers.push(check);
        self.blocked = true;
    }

    /// The requests the store received on the shard's record, volume record, replacement receipt and coverage
    /// pages. Reading the counters sends no request.
    fn requests(&self, store: &Shared) -> u64 {
        let store = store.0.borrow();
        self.keys().map(|key| store.requests(&key)).sum()
    }

    /// Adds the requests of one view period of the shard's standby wait on the shard's records to `waited`.
    fn excuse(&mut self, counts: &owners::WaitCounts) {
        let keys: Vec<Key> = self.keys().collect();
        for key in keys {
            let requests = counts.on(&key);
            if requests > 0 {
                *self.waited.entry(key).or_default() += requests;
            }
        }
    }

    /// The key of the coverage page that holds object `n`, from the page count the seeded shard record declares.
    /// The cell holds that count, so the store's request counters stay as they were.
    fn page_key(&self, n: u8) -> Key {
        let pages = std::num::NonZeroU16::new(self.pages).expect("seeded coverage pages");
        let page = crate::storage::page_coverage::page_of(&object_key(n), pages);
        Key::Page(self.placement.shard, page)
    }

    /// The shard's record, volume record, replacement receipt and coverage pages.
    fn keys(&self) -> impl Iterator<Item = Key> {
        let shard = self.placement.shard;
        let pages = (0..self.pages).map(move |page| Key::Page(shard, page));
        [
            Key::Shard(shard),
            Key::Volume(self.placement.volume),
            Key::Replacement(shard),
        ]
        .into_iter()
        .chain(pages)
    }

    fn decoded(&self, item: &Item) -> ShardRecord {
        let record = ShardRecord::decode(&item.value).expect("a stored shard record");
        assert_eq!(record.shard, self.placement.shard, "a record under its key");
        record
    }

    /// Every committed version of the shard's record, oldest first, read without a store request.
    fn history(&self, store: &Shared) -> Vec<ShardRecord> {
        let store = store.0.borrow();
        let versions = store.versions(&Key::Shard(self.placement.shard));
        versions.iter().map(|item| self.decoded(item)).collect()
    }

    /// Samples the record's latest version and the client's route without a store request.
    fn seen(&self, store: &Shared) -> Seen {
        let store = store.0.borrow();
        let current = store.current(&Key::Shard(self.placement.shard));
        let record = self.decoded(current.expect("a stored shard record"));
        Seen {
            named: (record.generation.get(), record.attempts, record.owner.get()),
            route: self.world.routes.route(self.placement.shard),
        }
    }

    /// Ends `serving`'s tenure in the cell's account: samples its device capture, counts a flip request its
    /// authority latched, settles the INVALIDATEs the tenure held and never acknowledged against the coverage pages
    /// committed under its fence, adds the Reports the volume's table logged since the tenure started and, when
    /// `counted`, counts an authority that no longer reads `Serving`. A caller counts a tenure whose client session
    /// opened and that no fault deposed. A tenure that ends at a `Rerun` or a `Deposed` exit closes uncounted:
    /// `hosts::unscripted_exit` judges its exit.
    fn close(&mut self, serving: &Serving<'_>, counted: bool) {
        closed(&self.world, serving);
        let opened = (serving.duties.as_ref())
            .is_some_and(|d| d.open() == crate::host::duties::Open::Opened);
        self.duty_opened += u32::from(opened);
        if let Some(exit) = &serving.duty_exit {
            self.duty_exits.push((serving.tenure, exit.clone()));
        }
        if serving.recovery_line.is_some() {
            self.lines.push(serving.tenure);
        }
        self.settle_held(serving.tenure);
        self.reports += serving.registry.borrow().reports() - serving.reports_from;
        let authority = serving.owner.authority_report();
        self.flip_requests += usize::from(authority.flip.is_some());
        self.withdrawals += usize::from(counted && authority.state != State::Serving);
    }

    /// Resolves each INVALIDATE `tenure` held and never acknowledged. It took effect when a committed version of its
    /// page, read with no store request, carries `tenure`'s own fence and either covers version 0 of the object's key
    /// by an entry whose interval holds it, or is saturated, which excludes every key on the page. A later version,
    /// such as a successor's fence, does not hide it. Each object such a version excludes leaves the retained set,
    /// and the history records its invalidation; an INVALIDATE no version covers leaves its object retained.
    fn settle_held(&mut self, tenure: Tenure) {
        use crate::failover::records::CoveragePage;
        use crate::storage::page_coverage::decode_entries;
        let (held, kept): (Vec<_>, Vec<_>) = std::mem::take(&mut self.unsettled)
            .into_iter()
            .partition(|entry| entry.2 == tenure);
        self.unsettled = kept;
        let fence = (tenure.g << 32) | tenure.a;
        let version = crate::storage::CacheVersion(0);
        for (n, page, _) in held {
            let (mut covered, mut saturated) = (false, false);
            {
                let store = self.world.records.0.borrow();
                for item in store.versions(&page) {
                    let value = CoveragePage::decode(&item.value).expect("a stored coverage page");
                    if value.fence != fence {
                        continue;
                    }
                    saturated |= value.saturated;
                    let entries = decode_entries(&value.entries).unwrap_or_default();
                    let key = object_key(n);
                    covered |= (entries.iter())
                        .any(|(of, interval)| *of == key && interval.contains(version));
                }
            }
            let mut excluded = Vec::new();
            if covered || saturated {
                excluded.push(n);
            }
            if saturated {
                let on_page = (self.world.objects.iter()).map(|object| object.n);
                let on_page: Vec<u8> = on_page.filter(|&m| self.page_key(m) == page).collect();
                excluded.extend(on_page);
            }
            excluded.sort_unstable();
            excluded.dedup();
            for m in excluded {
                if self.invalidated.insert(m) {
                    let tenure = Some(tenure);
                    self.world
                        .events
                        .push(super::Event::Invalidate { n: m, tenure });
                }
            }
        }
    }

    /// The recoveries the history oracle accounts for. A cold activation on a replacement volume names no cut, so
    /// the oracle holds no account of its tenure, and its sweep counts no object eligible.
    fn warm(&self) -> Vec<Recovered> {
        let cold = |r: &Recovered| self.cold && r.sweep.is_some_and(|(eligible, _)| eligible == 0);
        (self.recoveries.iter())
            .filter(|r| !cold(r))
            .copied()
            .collect()
    }

    /// The history oracle's judgment of the shard. A passing history must also account, for each swept recovery,
    /// one activation at that tenure whose members are the objects its sweep counted eligible, every one served
    /// and none excused.
    fn judged(&self) -> Judged {
        match self.world.judged() {
            Ok(accounts) if accounted(&accounts, &self.warm()) => Judged::Passed,
            Ok(_) => Judged::Violated(oracles::ACCOUNT),
            Err(verdict) => match verdict.violated() {
                Some((_, NEVER_SERVED)) => Judged::Unserved(NEVER_SERVED),
                Some((_, rule)) => Judged::Violated(rule),
                None => Judged::Undecided,
            },
        }
    }
}

fn accounted(accounts: &[Preserved], recoveries: &[Recovered]) -> bool {
    let whole = |account: &Preserved, eligible: u32| {
        account.members == eligible
            && account.served == account.members
            && account.excused.is_empty()
    };
    let swept = recoveries
        .iter()
        .filter_map(|r| r.sweep.map(|(eligible, _)| (r, eligible)));
    swept.into_iter().all(|(recovered, eligible)| {
        let account = accounts.iter().find(|a| a.tenure == recovered.tenure);
        account.is_some_and(|account| whole(account, eligible))
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Purpose {
    /// A GET to a shard that serves through another shard's recovery.
    Neighbour,
    /// A GET at a takeover's load start to a shard of the loading host that a loss took and a takeover restored;
    /// no watch covers such a shard.
    Beside,
    Sweep,
}

struct Flight {
    at: usize,
    id: RequestId,
    n: u8,
    purpose: Purpose,
    unrouted: u32,
    bytes: Vec<u8>,
    /// The tenure the GET was sent to, and [`Fleet::page_counts`] of its shard at the send.
    tenure: Tenure,
    pages: Vec<usize>,
}

/// One shard that served when an episode's owner crashed, as sampled at the crash.
struct Sampled {
    at: usize,
    requests: u64,
    seen: Seen,
    /// The round of the sample, and the requests the shard's serving duties made on its records by then.
    round: u64,
    duty: oracles::Views,
    /// The view periods of the shard's standby wait by then.
    waits: usize,
}

/// One GET drawn for an episode: the down round it goes out in, its target cell and its object.
struct Due {
    round: u64,
    at: usize,
    n: u8,
}

/// A crash episode from the crash on. `dropped` tells whether a live tenure was dropped.
struct Episode {
    dropped: bool,
    before: Vec<Sampled>,
    due: Vec<Due>,
}

/// One settled neighbour GET. `inside` tells whether it settled while its episode's window was open, and
/// `beside` whether it was a `Purpose::Beside` GET.
struct Settled {
    at: usize,
    served: bool,
    inside: bool,
    beside: bool,
}

struct Fleet<'c> {
    config: &'c Config,
    store: Shared,
    topology: Topology,
    cells: Vec<Cell>,
    round: u64,
    wait: u32,
    flights: Vec<Flight>,
    /// The exact-byte GETs of the sweep in progress.
    swept: u32,
    neighbours: Vec<Settled>,
    /// Open from a crash that dropped a tenure until the recovering tenure's client session is active or its
    /// recovery ends without one.
    window: bool,
    /// The cell whose restarted tenure has not yet an active client session.
    recovering: Option<usize>,
    watched: Vec<Watched>,
    activations: Vec<(usize, Tenure, Host)>,
    crashes: u32,
    reconciled: Reconciled,
    planted: bool,
    /// The volume-record commits in the store once every cell is seeded.
    seeded_volumes: usize,
    hosts: Vec<HostActor>,
    faults: Faults,
    log: HostLog,
    nominated: VecDeque<(
        usize,
        crate::failover::records::VolumeId,
        crate::failover::detect::host::Revalidated,
        u64,
    )>,
    /// Per probe request, by requester, suspect and issue time, whether a reply read ALIVE and whether one read DEAD.
    readings: std::collections::BTreeMap<(u64, u64, u64), (bool, bool)>,
    /// Each host's prepared probe key, by host, which the fleet opens probe replies under.
    probe_keys: std::collections::BTreeMap<u64, crate::failover::detect::probe::Keyed>,
    losses: Vec<Loss>,
    host_start: u64,
    reader: crate::failover::report::Reader,
    /// Each `live` slot past the cells holds a deposed tenure: its cell and its host.
    deposed: Vec<(usize, usize)>,
    /// Each resumed host and the round it resumed in.
    resumed: Vec<(usize, u64)>,
    reconcilers: Vec<ReconcilerActor>,
    recon: ReconLog,
    /// Each member's largest role count a reconciler scenario's samples read.
    peak_roles: Vec<u32>,
    /// The commits the last reconciler actuation made to s0's receipt and shard record and to volume records created
    /// in the run, which a replacement crash-table cell's step writes.
    step_commits: usize,
    /// One zone double per zone of a fleet whose reconcilers run, in zone order: instance and attachment listings,
    /// attach requests and the hosts' sealed reports.
    zones: Vec<crate::failover::zone_loop::tests::world::World>,
    /// The run's decisions while the hosts run, which the reconcilers' rounds draw from.
    draws: Option<Draws>,
    draw_refusal: Option<Refusal>,
    /// The store requests of the reconcilers and of the hosts' enrollments, by key.
    tallied: std::rc::Rc<std::cell::RefCell<std::collections::BTreeMap<Key, u64>>>,
    /// The cell whose takeover's warm load is in progress.
    loading: Option<usize>,
    /// The cells a later loss took while an earlier loss watched them; that loss's watch of them is dropped.
    released: BTreeSet<usize>,
    raced: reconcile::Raced,
    /// The slot-moved case's witness, which the census read hook of loop 0 writes once its move committed.
    moved: std::rc::Rc<std::cell::RefCell<Option<(u32, u64, u64)>>>,
    /// The reconciler whose survey of this round the race superseded.
    superseded: Option<usize>,
    volumes: volumes::VolumeLog,
    /// The cells whose stall cleared and whose named owner is due its restart.
    restarts: VecDeque<usize>,
    /// The cells whose holder's host was lost.
    host_lost: BTreeSet<usize>,
    zone_log: zones::ZoneLog,
    outage: Option<zones::Outage>,
    /// The round the stopped zone's hosts returned in.
    returned_at: Option<u64>,
    /// Each cell a stopped host held when it stopped, with that host, until the host returns.
    held_at_stop: Vec<(usize, usize)>,
    /// The restarts due to returned hosts, as cell and host, in ascending order.
    returns: Vec<(usize, usize)>,
    /// Each tenure's first admitted operation, in a run on the `az` layout.
    admissions: Vec<oracles::Admission>,
    /// The reads and the writes of every tenure's serving duties, by key.
    duty_counts: DutyCounts,
    /// The stale read the serving duties' store serves next, and whether it served one.
    stale_read: StaleRead,
    /// Each serving-duty write whose reply was unknown, by key, with whether it changed the value it conditioned on.
    duty_unknowns: DutyUnknowns,
    /// The faulted boot tenure of a store-result scenario, and its coverage pages' commits when its INVALIDATE was
    /// held and when the duties acknowledged it.
    faulted: Option<(Tenure, usize, Option<usize>)>,
    /// The withdrawal cause of the faulted boot tenure's authority, read when `Fleet::tear_down` took the tenure
    /// down; `None` while it serves or when its authority read `Serving` at its teardown.
    faulted_withdrawal: Option<crate::failover::serving::Cause>,
    /// [`DutyLog::torn`].
    torn: Vec<(u32, Tenure, bool)>,
    /// When a control targets another shard, [`Plant::StandbyExtraRead`] reads the record identified by this key.
    standby_extra: Option<Key>,
    /// The cells whose next incarnation a tenure's exit queued, each with its member, its ended tenure and the round
    /// it ended, until that restart runs. The host loop runs each once every open loss has sent its drawn GETs, so a
    /// rerun's load and sweep take no round from them, and while its host is not paused (`Fleet::rerun_due`).
    reruns: std::collections::BTreeMap<usize, (usize, Tenure, u64)>,
    /// The entries of `refused` whose restart was a returned host's (`Fleet::restart_returned`), by cell and member.
    /// The next incarnation runs as that restart again, so a tenure it serves, or a record that deposes it,
    /// completes the return in the zone log.
    returning: std::collections::BTreeSet<(usize, usize)>,
    /// The entries of `refused` that a serving tenure's rerun queued (`Fleet::rerun`), by cell and member, with the
    /// round that tenure ended. The next incarnation's recovery counts its rounds from that round.
    rerun_starts: std::collections::BTreeMap<(usize, usize), u64>,
    /// The refusals that recurred, by cell and member: an entry of `refused` that the rerun of a refused incarnation
    /// queued, and a fresh activation's retry that was refused again. The host loop runs on for a refusal outside
    /// this set until its next incarnation's turn, and ends over one inside it.
    recurred: std::collections::BTreeSet<(usize, usize)>,
    /// The processes whose restart, takeover or standby view period ended with an exit that names a rerun
    /// (`host::Exit::Rerun`, or a role read that failed), by cell and member, with the round it ended and whether it
    /// followed a loss. The host loop runs the next incarnation from the round after that, as the process's
    /// supervisor starts it.
    refused: std::collections::BTreeMap<(usize, usize), (u64, bool)>,
    /// The cells whose named standby waits again as a standby, by that standby's member: `Fleet::retake` records the
    /// wait after the next incarnation of a takeover that ended `Rerun::Takeover`, and after each rerun of a refused
    /// restart. While the record still names the member standby of an owner other than its host and the cell holds
    /// no tenure, or only the tenure an open loss took from it, the host loop runs on, so the agent's next witness
    /// reaches the wait; the agent sends one a window while the records name its target.
    retakes: std::collections::BTreeMap<usize, usize>,
}

/// Each tenure's grounds and pools, by the member whose load takes them.
struct Slots<'w> {
    grounds: &'w [Grounds],
    pools: &'w [Pools<'w>],
    members: Vec<usize>,
    used: Vec<bool>,
}

impl<'w> Slots<'w> {
    fn take(&mut self, member: usize) -> (&'w Grounds, &'w Pools<'w>) {
        let at = (0..self.members.len())
            .find(|&at| !self.used[at] && self.members[at] == member)
            .expect("a free tenure slot of the host");
        self.used[at] = true;
        (&self.grounds[at], &self.pools[at])
    }

    /// Whether `member` holds a tenure slot no tenure took.
    fn free(&self, member: usize) -> bool {
        (0..self.members.len()).any(|at| !self.used[at] && self.members[at] == member)
    }

    /// Frees the slot of `grounds`, which `member` took for an incarnation that acquired no tenure.
    fn put_back(&mut self, member: usize, grounds: &'w Grounds) {
        let at = (0..self.members.len())
            .find(|&at| self.used[at] && std::ptr::eq(&self.grounds[at], grounds))
            .expect("a taken tenure slot");
        assert_eq!(self.members[at], member, "the slot's own host");
        self.used[at] = false;
    }
}

/// The read bytes the tenure's device double accepted since its attach.
fn device_reads(serving: &Serving<'_>) -> u64 {
    let capture = serving.control.capture();
    let reads = capture.events.iter().filter_map(|event| match event {
        crate::storage::device::sim::Captured::Submitted {
            operation: crate::storage::Operation::Read,
            device,
            ..
        } => Some(u64::from(device.byte_len())),
        _ => None,
    });
    reads.sum()
}

type Live<'w> = Vec<Option<Serving<'w>>>;

impl<'c> Fleet<'c> {
    /// Draws the topology and seeds every cell's records and media.
    ///
    /// # Panics
    ///
    /// On a shape `Shape::check` refuses.
    fn seeded(config: &'c Config, draws: &mut Draws, wait: u32) -> Result<Self, Refusal> {
        let shape = &config.shape;
        let checked = shape.check();
        assert_eq!(checked, Ok(()), "a fleet is seeded from a checked shape");
        let topology = Topology::draw(shape, draws)?;
        let store = Shared::new();
        let capacity = NonZeroU32::new(shape.shards).expect("a checked shard count");
        let routes = ShardRoutes::new(capacity, &mut EngineBudget::new(1 << 20));
        let routes = Arc::new(routes.expect("the shard routes"));
        let cells: Vec<Cell> = (topology.placements.iter().enumerate())
            .map(|(at, placement)| {
                let seed = (shape.objects, config.scenario.seed(at));
                Cell::new(&store, &routes, &topology, *placement, seed)
            })
            .collect();
        let planted = config.planted(Plant::NoCrashEpisode);
        let members = topology.members.len();
        let faults = Faults::new(config.scenario.episodes(planted), members);
        let mut fleet = Self {
            config,
            store,
            topology,
            cells,
            round: 0,
            wait,
            flights: Vec::new(),
            swept: 0,
            neighbours: Vec::new(),
            window: false,
            recovering: None,
            watched: Vec::new(),
            activations: Vec::new(),
            crashes: 0,
            reconciled: Reconciled::default(),
            planted: false,
            seeded_volumes: 0,
            hosts: Vec::new(),
            faults,
            log: HostLog::default(),
            nominated: VecDeque::new(),
            readings: std::collections::BTreeMap::new(),
            probe_keys: std::collections::BTreeMap::new(),
            losses: Vec::new(),
            host_start: 0,
            reader: crate::failover::report::Reader::default(),
            deposed: Vec::new(),
            resumed: Vec::new(),
            reconcilers: Vec::new(),
            step_commits: 0,
            peak_roles: Vec::new(),
            recon: ReconLog::default(),
            zones: Vec::new(),
            draws: None,
            draw_refusal: None,
            tallied: Default::default(),
            loading: None,
            released: BTreeSet::new(),
            raced: Default::default(),
            moved: Default::default(),
            superseded: None,
            volumes: Default::default(),
            restarts: VecDeque::new(),
            host_lost: BTreeSet::new(),
            zone_log: Default::default(),
            outage: None,
            returned_at: None,
            held_at_stop: Vec::new(),
            returns: Vec::new(),
            admissions: Vec::new(),
            duty_counts: DutyCounts::default(),
            stale_read: StaleRead::default(),
            duty_unknowns: DutyUnknowns::default(),
            faulted: None,
            faulted_withdrawal: None,
            torn: Vec::new(),
            reruns: std::collections::BTreeMap::new(),
            returning: std::collections::BTreeSet::new(),
            rerun_starts: std::collections::BTreeMap::new(),
            recurred: std::collections::BTreeSet::new(),
            refused: std::collections::BTreeMap::new(),
            retakes: std::collections::BTreeMap::new(),
            standby_extra: None,
        };
        fleet.seeded_volumes = fleet.commits(|key| matches!(key, Key::Volume(_)));
        Ok(fleet)
    }

    fn play(config: &'c Config, mut draws: Draws, wait: u32) -> Result<Report, Stopped> {
        if config.scenario.hosted() {
            return Self::play_hosts(config, draws, wait);
        }
        let mut fleet = Self::seeded(config, &mut draws, wait)?;
        let mut schedule = fleet.order(&mut draws, false)?;
        if !config.planted(Plant::NoCrashEpisode) {
            schedule.extend(fleet.order(&mut draws, true)?);
        } else {
            fleet.planted = true;
        }
        let grounds: Vec<Grounds> = (schedule.iter())
            .map(|&(at, _)| Grounds::over(storage_shared(1, fleet.share(at))))
            .collect();
        let pools: Vec<Pools<'_>> = grounds.iter().map(Pools::new).collect();
        let mut live: Live<'_> = fleet.cells.iter().map(|_| None).collect();
        for (slot, &(at, after_crash)) in schedule.iter().enumerate() {
            let ground = (&grounds[slot], &pools[slot]);
            fleet.recover(&mut live, ground, (at, after_crash), &mut draws)?;
            fleet.reconcile();
        }
        fleet.plant_records();
        for (cell, serving) in fleet.cells.iter_mut().zip(&live) {
            if let Some(serving) = serving {
                cell.close(serving, true);
            }
        }
        let decisions = draws.decisions();
        let tape = draws.finish()?;
        Ok(fleet.report(&live, decisions, tape))
    }

    fn play_hosts(config: &'c Config, mut draws: Draws, wait: u32) -> Result<Report, Stopped> {
        Self::seeded(config, &mut draws, wait)?.play_script(draws)
    }

    /// Boots every owner as `play` does, has each acknowledge one FILL and one INVALIDATE, starts the hosts and
    /// runs the fault script the fleet holds, which `seeded` takes from the scenario.
    fn play_script(self, draws: Draws) -> Result<Report, Stopped> {
        self.play_script_with(draws, |fleet, live, slots| fleet.run_hosts(live, slots))
    }

    /// [`Fleet::play_script`] with `run` in place of the host loop: `run` takes the booted fleet, its live tenures
    /// and its tenure slots once the hosts started, and the report follows what it left.
    fn play_script_with(
        self,
        mut draws: Draws,
        run: impl for<'w> FnOnce(&mut Self, &mut Live<'w>, &mut Slots<'w>) -> Result<(), Stopped>,
    ) -> Result<Report, Stopped> {
        let mut fleet = self;
        let boot = fleet.order(&mut draws, false)?;
        let mut members: Vec<usize> = (fleet.cells.iter())
            .flat_map(|cell| [cell.placement.owner, cell.placement.standby])
            .collect();
        if fleet.config.zoned() {
            // Two more slots per owned shard bring `az` to 32 tenure slots.
            let owners = fleet.cells.iter().map(|cell| cell.placement.owner);
            members.extend(owners.flat_map(|owner| [owner; 2]));
        } else if fleet.config.scenario.repairs() {
            let hosts = fleet.topology.members.len();
            members.extend((0..hosts).flat_map(|member| [member; REPAIR_SLOTS]));
        }
        if fleet.config.scenario.duty_faulted() {
            members.push(fleet.cells[hosts::DUTY_CELL].placement.owner);
        }
        assert_eq!(
            members.len(),
            fleet.config.slots() as usize,
            "the checked slots"
        );
        let grounds: Vec<Grounds> = (members.iter())
            .map(|&member| Grounds::over(storage_shared(1, fleet.share_on(member))))
            .collect();
        let pools: Vec<Pools<'_>> = grounds.iter().map(Pools::new).collect();
        let mut slots = Slots {
            grounds: &grounds,
            pools: &pools,
            used: vec![false; members.len()],
            members,
        };
        let mut live: Live<'_> = fleet.cells.iter().map(|_| None).collect();
        for &(at, _) in &boot {
            (fleet.log.boot).push(fleet.cells[at].placement.shard.get());
            let ground = slots.take(fleet.cells[at].placement.owner);
            fleet.recover(&mut live, ground, (at, false), &mut draws)?;
        }
        fleet.workload(&mut live);
        fleet.start_hosts();
        fleet.draws = Some(draws);
        let ran = run(&mut fleet, &mut live, &mut slots);
        let draws = fleet.draws.take().expect("the run's decisions");
        ran?;
        fleet.log.fired = fleet
            .faults
            .fired
            .iter()
            .map(|fired| fired.map(|(at, _)| at))
            .collect();
        fleet.plant_records();
        fleet.plant_admission();
        for (cell, serving) in fleet.cells.iter_mut().zip(&live) {
            if let Some(serving) = serving {
                cell.close(serving, true);
            }
        }
        let slots = live.iter().skip(fleet.cells.len());
        for (&(at, _), serving) in fleet.deposed.iter().zip(slots) {
            if let Some(serving) = serving {
                fleet.cells[at].close(serving, false);
                fleet.log.unwithdrawn += 1;
            }
        }
        let decisions = draws.decisions();
        let tape = draws.finish()?;
        Ok(fleet.report(&live, decisions, tape))
    }

    /// Each serving tenure, in shard order, opens its suffix, publishes a FILL of a new object and acknowledges an
    /// INVALIDATE of its first checkpoint object.
    fn workload(&mut self, live: &mut Live<'_>) {
        let fill = self.config.shape.objects + 1;
        for at in 0..self.cells.len() {
            if live[at].is_some() {
                self.cells[at].acknowledged = self.acknowledge(live, at, (fill, 1));
            }
        }
    }

    /// Cell `at`'s serving tenure opens its suffix, publishes a FILL of object `fill` and acknowledges an INVALIDATE
    /// of object `invalidate`. Returns whether it acknowledged both.
    fn acknowledge(
        &mut self,
        live: &mut Live<'_>,
        at: usize,
        (fill, invalidate): (u8, u8),
    ) -> bool {
        let Some(serving) = live[at].as_mut() else {
            return false;
        };
        let tenure = serving.tenure;
        let opened = duties_opened(serving);
        let submitted = self.page_counts(at);
        let world = &mut self.cells[at].world;
        let filled = opened && filled(world, serving, fill);
        if filled {
            self.admit(at, tenure, oracles::Admitted::Fill, submitted);
        }
        let submitted = self.page_counts(at);
        let held = opened && super::hold(serving, invalidate) == Ok(true);
        let faulted = at == hosts::DUTY_CELL && self.faulted.is_some_and(|(of, ..)| of == tenure);
        let held_at = faulted.then(|| self.page_commits(at));
        let world = &mut self.cells[at].world;
        let acknowledged = held && duties_acknowledged(world, serving, invalidate);
        if let Some(held_at) = held_at {
            let acknowledged_at = acknowledged.then(|| self.page_commits(at));
            self.faulted = Some((tenure, held_at, acknowledged_at));
            if self.config.scenario == Scenario::RecordRegressed && acknowledged {
                // The next record view of the acknowledged tenure reads the shard record's version before its last.
                let shard = self.cells[at].placement.shard;
                self.stale_read.aim(shard, Stale::Record);
                duties_ended(serving);
            }
        }
        if acknowledged {
            self.cells[at].invalidated.insert(invalidate);
            self.admit(at, tenure, oracles::Admitted::Invalidate, submitted);
        } else if held {
            let page = self.cells[at].page_key(invalidate);
            self.cells[at].unsettled.push((invalidate, page, tenure));
        }
        filled && acknowledged
    }

    /// The stored keys `of` selects.
    fn keys(&self, of: impl Fn(&Key) -> bool) -> usize {
        self.store.0.borrow().keys().filter(|key| of(key)).count()
    }

    /// The commits of every stored key `of` selects, keys created after seeding included.
    fn commits(&self, of: impl Fn(&Key) -> bool) -> usize {
        let store = self.store.0.borrow();
        let keys = store.keys().filter(|key| of(key));
        keys.map(|key| store.commit_count(key)).sum()
    }

    /// When reconcilers run, their attach records and the hosts' enrollments rewrite volume records, so only the
    /// volume records created after seeding count as volume writes. The counts leave out each shard whose volume the
    /// injector marked lost: its generation-changing commits, the volume records its create steps returned, its
    /// receipts and its flip requests.
    fn volumes(&self) -> Volumes {
        let seeded = self.cells.len();
        let lost = &self.volumes.lost;
        let kept = |shard: &crate::net::ownership::Shard| !lost.contains(&shard.get());
        let lost_shards: BTreeSet<u32> = lost.iter().copied().collect();
        let made = (self.volumes.created.iter())
            .filter(|(shard, _)| lost_shards.contains(shard))
            .count();
        // The store's flip log counts commits, so a lost shard is excused one flip for each commit of its record
        // that changed the generation.
        let flipped: usize = (lost_shards.iter())
            .map(|&shard| {
                let history = self.cells[shard as usize - 1].history(&self.store);
                let changed = history.windows(2);
                changed
                    .filter(|pair| pair[0].generation != pair[1].generation)
                    .count()
            })
            .sum();
        let volume_writes = match self.repairs() {
            true => (self.keys(|key| matches!(key, Key::Volume(_))) - seeded).saturating_sub(made),
            false => self.commits(|key| matches!(key, Key::Volume(_))) - self.seeded_volumes,
        };
        Volumes {
            flips: (self.store.0.borrow().flips.len()).saturating_sub(flipped),
            volume_writes,
            receipts: self.commits(|key| matches!(key, Key::Replacement(shard) if kept(shard))),
            flip_requests: (self.cells.iter())
                .filter(|cell| kept(&cell.placement.shard))
                .map(|cell| cell.flip_requests)
                .sum(),
        }
    }

    /// For each shard whose volume the injector marked lost: its generation's rise over the run and the volumes a
    /// create step returned for it.
    fn replaced(&self) -> Vec<(u64, usize)> {
        let lost = self.volumes.lost.iter();
        lost.map(|&shard| {
            let history = self.cells[shard as usize - 1].history(&self.store);
            let generation =
                |record: Option<&ShardRecord>| record.map_or(0, |r| r.generation.get());
            let rise = generation(history.last()) - generation(history.first());
            let created = self.volumes.created.iter();
            (rise, created.filter(|(of, _)| *of == shard).count())
        })
        .collect()
    }

    fn losses(&self) -> oracles::Losses {
        let shard = |at: &usize| self.cells[*at].placement.shard.get();
        oracles::Losses {
            volumes: self.volumes.lost.clone(),
            hosts: self.host_lost.iter().map(shard).collect(),
        }
    }

    fn shard_of(&self, at: usize) -> u64 {
        u64::from(self.cells[at].placement.shard.get())
    }

    fn order(&self, draws: &mut Draws, after_crash: bool) -> Result<Vec<(usize, bool)>, Refusal> {
        let mut remaining: Vec<usize> = (0..self.cells.len()).collect();
        let mut order = Vec::new();
        while !remaining.is_empty() {
            let shards: Vec<u64> = remaining.iter().map(|&at| self.shard_of(at)).collect();
            let at = remaining.remove(draws.pick(draws::NEXT, Tag::Shard, &shards)?);
            order.push((at, after_crash));
        }
        Ok(order)
    }

    /// The share of cell `at`'s holder. `Fleet::play` plants the whole share by cell and a host scenario by host.
    fn share(&self, at: usize) -> HostShare {
        let member = self.cells[at].holder;
        let index = if self.config.scenario.hosted() {
            member
        } else {
            at
        };
        self.share_of(member, index)
    }

    fn share_on(&self, member: usize) -> HostShare {
        self.share_of(member, member)
    }

    /// The host share divided over `member`'s roles, or whole when the profile plants `WholeShare` at `index`.
    fn share_of(&self, member: usize, index: usize) -> HostShare {
        let whole = self.config.planted_at(Plant::WholeShare, index);
        HostShare {
            bytes: SHARE_BYTES,
            interval: SHARE_INTERVAL_US,
            owners: match whole {
                true => 1,
                false => self.divisor(member),
            },
        }
    }

    /// The divisor of `member`'s recovery share: the shape's static `roles_max` in a reconciler scenario, whose roles
    /// move, and the host's seeded roles otherwise.
    fn divisor(&self, member: usize) -> u32 {
        match self.config.scenario.repairs() {
            true => self.config.shape.roles_max,
            false => self.topology.roles(member),
        }
    }

    /// A tenure steps while its host runs.
    fn stepping(&self, slot: usize) -> bool {
        let member = match slot.checked_sub(self.cells.len()) {
            None => self.cells[slot].holder,
            Some(deposed) => self.deposed[deposed].1,
        };
        self.hosts.is_empty() || self.hosts[member].up == hosts::Up::Running
    }

    /// Ends each deposed tenure that withdrew as `serve` ends a `Deposed` exit ([`Fleet::tear_down`]), and records
    /// the rounds since its host resumed. The tenure's process is over: no rerun follows.
    fn withdraw(&mut self, live: &mut Live<'_>) {
        for index in 0..self.deposed.len() {
            let (at, member) = self.deposed[index];
            let slot = &mut live[self.cells.len() + index];
            let Some(serving) = slot.take_if(|serving| serving.withdrawn) else {
                continue;
            };
            self.tear_down(at, serving);
            let resumed = self.resumed.iter().rev().find(|(of, _)| *of == member);
            let rounds = resumed.map_or(0, |&(_, round)| self.round - round);
            (self.log.withdrawals).push((self.cells[at].placement.shard.get(), rounds));
        }
    }

    /// One round: in a host scenario the hosts act first; then every live tenure whose host runs steps in slot
    /// order, each deposed tenure that withdrew closes, and each GET in flight collects. The episode's window closes
    /// once the recovering tenure's client session is active, or in a host scenario once every open loss is
    /// restored, before the round's GETs collect, so a GET that completes in that round counts outside the window.
    fn turn(&mut self, live: &mut Live<'_>) {
        if self.repairs() {
            self.sample_roles();
        }
        if !self.hosts.is_empty() {
            self.host_round(live);
            if self.round.is_multiple_of(DUTY_VIEW_US / ROUND_US) {
                self.standby_waits();
            }
        }
        if self.repairs() {
            self.reconcile_round();
        }
        for (slot, serving) in live.iter_mut().enumerate() {
            if let Some(serving) = serving
                && self.stepping(slot)
            {
                // An exit ends the duties' store work, which `Cell::close` records; the owner keeps its state for the
                // fleet's own close of the tenure.
                let _ = actors::duties(serving);
            }
        }
        if !self.hosts.is_empty() {
            self.tear_down_ended(live);
        }
        if self.repairs() {
            self.settle_phase(live);
        }
        self.plant_views(live);
        if !self.deposed.is_empty() {
            self.withdraw(live);
        }
        self.round += 1;
        let recovered = match self.hosts.is_empty() {
            true => (self.recovering.and_then(|at| live[at].as_ref()))
                .is_some_and(|serving| serving.client.state() == SessionState::Active),
            false => self.restored(live),
        };
        if recovered {
            self.window = false;
        }
        for mut flight in std::mem::take(&mut self.flights) {
            let serving = live[flight.at].as_mut().expect("a flight's shard serves");
            collect(&mut serving.client, flight.id, &mut flight.bytes);
            let Some(outcome) = serving.client.outcome(flight.id) else {
                self.flights.push(flight);
                continue;
            };
            let _ = serving.client.retire(flight.id);
            let Flight { at, n, purpose, .. } = flight;
            let accepted = serving.unrouted == flight.unrouted;
            let exact = outcome == Fetched::Complete && flight.bytes == content(n, first(n));
            let world = &mut self.cells[at].world;
            serving.record(world, n, &[first(n)], (outcome, flight.bytes, accepted));
            if exact && accepted {
                assert_eq!(
                    serving.tenure, flight.tenure,
                    "a GET settles under the tenure it was sent to"
                );
                self.admit(at, flight.tenure, oracles::Admitted::Hit, flight.pages);
            }
            self.settle(at, purpose, exact && accepted);
        }
    }

    /// Ends `serving`, a tenure of cell `at`, as `serve` ends its process at an exit: the cell's close, then
    /// `serve::teardown`, which closes the owner and drains it inside [`TEARDOWN_ROUNDS`] while the drain's device
    /// rounds run and end with one more sample of the device (`Serving::tear_down`). Lists the tenure in
    /// [`DutyLog::torn`] and returns whether the owner shut down with its parts returned. The close counts no
    /// withdrawal, whichever caller ends the tenure: `hosts::unscripted_exit` judges its exit. A host crash, an
    /// injected volume loss and a bring-up that ends short of serving end a tenure with the cell's close alone.
    fn tear_down(&mut self, at: usize, serving: Serving<'_>) -> bool {
        self.cells[at].close(&serving, false);
        let tenure = serving.tenure;
        if at == hosts::DUTY_CELL && self.faulted.is_some_and(|(of, ..)| of == tenure) {
            self.faulted_withdrawal = withdrawn(serving.owner.authority_report());
        }
        let shut = serving.tear_down(TEARDOWN_ROUNDS);
        let shard = self.cells[at].placement.shard.get();
        self.torn.push((shard, tenure, shut));
        shut
    }

    /// Drops each open loss's watch of cell `at`, whose current tenure ended: an ended tenure serves through no open
    /// loss.
    fn release_watches(&mut self, at: usize) {
        for open in &mut self.losses {
            if open.episode.before.iter().any(|sampled| sampled.at == at) {
                self.released.insert(at);
                open.episode.before.retain(|sampled| sampled.at != at);
            }
        }
    }

    /// Ends each shard's current tenure whose serving turn named a `Rerun` or a `Deposed` exit, as `serve` does
    /// ([`Fleet::tear_down`]). A tenure with a GET in flight waits for the GET's outcome. A `Retire`, `Refused`,
    /// `Retired` or `Stopped` exit keeps the tenure in its slot. After a `Rerun` exit, when the owner shut down and the
    /// shard record still names the tenure's host owner, the process's next incarnation is queued (`Fleet::reruns`):
    /// its role read and `host::recover`, which the host loop runs once every open loss has sent its drawn GETs and
    /// its host is not paused (`Fleet::rerun`, `Fleet::rerun_due`). A `Deposed` exit queues none: a later tenure owns the shard. Each open loss drops its watch
    /// of the shard, which serves through no loss once its tenure ended. The cell's close counts no withdrawal for
    /// the tenure (`Settle::withdrawals`): its exit is in `DutyLog::exits`, and `Report::credit` fails first on an
    /// exit the scenario does not script (`hosts::unscripted_exit`), so the withdrawn rule judges the tenures whose
    /// duties named no such exit. A deposed tenure in a slot past the cells ends through [`Fleet::withdraw`].
    fn tear_down_ended(&mut self, live: &mut Live<'_>) {
        let ended: Vec<usize> = (0..self.cells.len())
            .filter(|&at| live[at].as_ref().is_some_and(awaits_teardown))
            .collect();
        for at in ended {
            if self.flights.iter().any(|flight| flight.at == at) || self.recovering == Some(at) {
                continue;
            }
            let serving = live[at].take().expect("the ended tenure");
            let reruns = matches!(serving.duty_exit, Some(crate::host::Exit::Rerun(_)));
            let tenure = serving.tenure;
            let shut = self.tear_down(at, serving);
            self.release_watches(at);
            // A kept owner holds its custody: `serve` returns it as `Served::Kept`, and its process neither parks nor
            // reruns. The fleet's device double needs no proven stop, so the kept owner drops here.
            let member = self.cells[at].holder;
            if reruns && shut && self.record_now(at).owner == self.topology.members[member].host {
                self.reruns.insert(at, (member, tenure, self.round));
            }
        }
    }

    /// Whether a shard's current tenure named an exit that waits for `Fleet::tear_down_ended`.
    fn ending(&self, live: &Live<'_>) -> bool {
        let mut current = live.iter().take(self.cells.len()).flatten();
        current.any(awaits_teardown)
    }

    fn settle(&mut self, at: usize, purpose: Purpose, served: bool) {
        match purpose {
            Purpose::Sweep => self.swept += u32::from(served),
            Purpose::Neighbour | Purpose::Beside => {
                self.neighbours.push(Settled {
                    at,
                    served,
                    inside: self.window,
                    beside: purpose == Purpose::Beside,
                });
                let beside = self.loading.is_some_and(|load| {
                    load != at && self.cells[load].holder == self.cells[at].holder
                });
                self.log.served_beside_load += u32::from(served && beside);
            }
        }
    }

    /// Offers a GET of object `n` to the shard's client. A client with no session or no bound route settles the
    /// GET unserved.
    ///
    /// # Panics
    ///
    /// On local request or receive pressure: [`bounds::requests`] keeps an episode's GETs within one peer's
    /// allowance and a sweep holds one GET in flight, so pressure is a driver defect and no answer of the shard.
    fn send(&mut self, live: &mut Live<'_>, at: usize, n: u8, purpose: Purpose) {
        let pages = self.page_counts(at);
        let serving = live[at].as_mut().expect("a request's shard serves");
        let now = serving.turn * ROUND_US;
        match (serving.client).get(object_key(n), 1 << 16, 1 << 20, now, 30_000_000) {
            Ok(id) => self.flights.push(Flight {
                at,
                id,
                n,
                purpose,
                unrouted: serving.unrouted,
                bytes: Vec::new(),
                tenure: serving.tenure,
                pages,
            }),
            Err(GetRefused::NoSession | GetRefused::Unrouted) => self.settle(at, purpose, false),
            Err(pressure) => panic!(
                "shard {}: the client refused the driver's GET locally: {pressure:?}",
                self.shard_of(at)
            ),
        }
    }

    fn stalled(&self, at: Option<usize>, waited: &'static str) -> Stopped {
        Stopped::Stalled(Stall {
            identity: self.config.identity(),
            shard: at.map(|at| self.cells[at].placement.shard.get()),
            waited,
            round: self.round,
        })
    }

    /// Takes turns while `pending` holds, `Fleet::wait` turns at most, and accepts a condition its last turn
    /// met.
    ///
    /// # Errors
    ///
    /// `Stopped::Stalled`, naming `shard` and `waited`, when `pending` still holds after the last turn.
    fn turns_while(
        &mut self,
        live: &mut Live<'_>,
        (shard, waited): (Option<usize>, &'static str),
        pending: impl Fn(&Self, &Live<'_>) -> bool,
    ) -> Result<(), Stopped> {
        let mut turns = 0;
        while pending(self, live) {
            if turns == self.wait {
                return Err(self.stalled(shard, waited));
            }
            self.turn(live);
            turns += 1;
        }
        Ok(())
    }

    fn drain(&mut self, live: &mut Live<'_>) -> Result<(), Stopped> {
        self.turns_while(live, (None, "a GET's outcome"), |fleet, _| {
            !fleet.flights.is_empty()
        })
    }

    fn turns_until(
        &mut self,
        live: &mut Live<'_>,
        (at, waited): (usize, &'static str),
        done: impl Fn(&Serving<'_>) -> bool,
    ) -> Result<(), Stopped> {
        self.turns_while(live, (Some(at), waited), |_, live| {
            !done(live[at].as_ref().expect("a recovering tenure"))
        })
    }

    /// One recovery of cell `at`. After a crash it follows the episode `Fleet::crash` opens. The owner stays down
    /// `DOWN_ROUNDS` rounds, in which the episode's GETs go out, and `Fleet::restart` then brings it back. Every
    /// exit of a crash episode closes its window, drains the GETs in flight and then records what each
    /// neighbour's records, route and authority did since the crash. A tenure whose client session opened then
    /// sweeps and is recorded; a recovery that ended in a blocker or in the silent plant records no `Recovered`
    /// and leaves `live[at]` empty.
    fn recover<'w>(
        &mut self,
        live: &mut Live<'w>,
        ground: (&'w Grounds, &'w Pools<'w>),
        (at, after_crash): (usize, bool),
        draws: &mut Draws,
    ) -> Result<(), Stopped> {
        let config = self.config;
        let episode = match after_crash {
            true => Some(self.crash(live, at, draws)?),
            false => None,
        };
        let dropped = episode.as_ref().is_some_and(|episode| episode.dropped);
        let crashed = self.round;
        let mut refusing = after_crash && config.planted_at(Plant::NeighborRefusal, at);
        for round in 0..DOWN_ROUNDS {
            let due = episode.iter().flat_map(|episode| &episode.due);
            for due in due.filter(|due| due.round == round) {
                if std::mem::take(&mut refusing) {
                    let serving = live[due.at].as_mut().expect("a serving neighbour");
                    self.planted |= drop_from_ram(serving, due.n);
                }
                self.cells[due.at].requested.push(due.n);
                self.send(live, due.at, due.n, Purpose::Neighbour);
            }
            self.turn(live);
        }
        let tenure = self.restart(live, ground, (at, after_crash))?;
        let rounds = self.round - crashed;
        (self.window, self.recovering) = (false, None);
        self.drain(live)?;
        if let Some(episode) = episode {
            self.watch(live, &episode);
        }
        let Some(tenure) = tenure else {
            return Ok(());
        };
        self.recovered(live, at, tenure, rounds, (after_crash, dropped))
    }

    /// Starts cell `at`'s crash episode. A live tenure drops without quiesce, which counts one crash and opens
    /// the episode's window. The episode's GETs are drawn among the shards that serve, whether or not a tenure
    /// dropped.
    fn crash(
        &mut self,
        live: &mut Live<'_>,
        at: usize,
        draws: &mut Draws,
    ) -> Result<Episode, Refusal> {
        assert!(
            self.flights.is_empty(),
            "a recovery ends with no GET in flight"
        );
        let dropped = live[at].take();
        if let Some(serving) = &dropped {
            self.cells[at].close(serving, true);
            self.crashes += 1;
            self.window = true;
        }
        // A tenure whose serving duties ended at an exit serves through no crash episode.
        let before: Vec<Sampled> = (live.iter().enumerate())
            .filter(|(_, serving)| (serving.as_ref()).is_some_and(|s| s.duty_exit.is_none()))
            .map(|(other, _)| self.sample(other))
            .collect();
        let due = self.draw_gets(&before, draws)?;
        Ok(Episode {
            dropped: dropped.is_some(),
            before,
            due,
        })
    }

    /// Draws each GET of an episode among the serving shards of `before`: a shard, a down round, and an object
    /// outside every acknowledged INVALIDATE of that shard.
    fn draw_gets(&self, before: &[Sampled], draws: &mut Draws) -> Result<Vec<Due>, Refusal> {
        let mut due = Vec::new();
        if before.is_empty() {
            return Ok(due);
        }
        let serving: Vec<u64> = (before.iter())
            .map(|neighbor| self.shard_of(neighbor.at))
            .collect();
        let rounds: Vec<u64> = (0..DOWN_ROUNDS).collect();
        for _ in 0..self.config.requests {
            let other = before[draws.pick(draws::NEIGHBOUR, Tag::Shard, &serving)?].at;
            let round = draws.value(draws::ROUND, Tag::Round, &rounds)?;
            let invalidated = &self.cells[other].invalidated;
            let objects: Vec<u64> = (1..=self.config.shape.objects)
                .filter(|n| !invalidated.contains(n))
                .map(u64::from)
                .collect();
            let n = draws.value(draws::OBJECT, Tag::Object, &objects)? as u8;
            due.push(Due {
                round,
                at: other,
                n,
            });
        }
        Ok(due)
    }

    /// Restarts cell `at`'s owner through an incarnation of the production owner process (`owners::incarnate`), which
    /// reads its role and runs `host::recover`, and brings its tenure up over `ground` (`Fleet::rise`) with the client
    /// session open. Returns the tenure whose session opened. A refused restart or a load that did not open reports a
    /// blocker and returns `None` with `live[at]` empty, and the silent plant returns `None` with no blocker.
    /// `Cell::blocked` describes this restart alone.
    fn restart<'w>(
        &mut self,
        live: &mut Live<'w>,
        ground: (&'w Grounds, &'w Pools<'w>),
        (at, after_crash): (usize, bool),
    ) -> Result<Option<Tenure>, Stopped> {
        let cell = &mut self.cells[at];
        cell.blocked = false;
        if after_crash && self.config.planted_at(Plant::SilentBlocker, at) {
            self.planted = true;
            return Ok(None);
        }
        let (member, pair) = (cell.placement.owner, cell.pair);
        let mut local = owners::OwnerLocal(Stored(cell.local.0.clone()));
        let mut client = crate::storage::store_tests::client(&self.store);
        let mut plane = crate::failover::fresh::tests::plane();
        let mut refusals = crate::failover::fresh::Refusals::default();
        let sources = (&mut local, &mut plane, &mut refusals);
        let of = self.topology.members[member];
        let cell = (&self.cells[at], of, pair);
        match owners::incarnate(cell, self.round, ground.0, &mut client, sources) {
            owners::Incarnation::Tenure(tenure, control, now) => self.rise(
                live,
                ground,
                (at, pair),
                (*tenure, control, now),
                Source::Named,
            ),
            owners::Incarnation::Ended(exit, refusal) => {
                let flip = matches!(exit, crate::host::Exit::Retire(_));
                self.cells[at].refuse(owners::blocker(&exit, refusal), flip);
                Ok(None)
            }
            owners::Incarnation::Waits(role) => {
                self.cells[at].refuse(format!("{role:?}"), false);
                Ok(None)
            }
            owners::Incarnation::Unread(error) => {
                self.cells[at].refuse(format!("{error:?}"), false);
                Ok(None)
            }
        }
    }

    /// Runs `serving`'s bootstrap, activates its load from `source` and opens its client session. Returns the tenure
    /// whose session opened; a load that did not open reports a blocker and returns `None` with `live[at]` empty.
    fn serve_opened<'w>(
        &mut self,
        live: &mut Live<'w>,
        at: usize,
        serving: Serving<'w>,
        source: Source,
    ) -> Result<Option<Tenure>, Stopped> {
        let tenure = serving.tenure;
        let host = self.topology.members[self.cells[at].holder].host;
        live[at] = Some(serving);
        self.recovering = Some(at);
        self.turns_until(live, (at, "the bootstrap"), |serving| {
            serving.rising.is_none() && !serving.owner.readiness().initializing()
        })?;
        let cell = &mut self.cells[at];
        let serving = live[at].as_mut().expect("the recovered tenure");
        let outcome = activate(&mut cell.world, serving, source);
        let short = match &serving.risen {
            Some(crate::host::serve::Rising::Short(exit)) => Some(exit.clone()),
            _ => None,
        };
        if outcome != MetadataOutcome::Open || short.is_some() {
            let charge = Charge {
                host,
                share: share_of(serving.storage),
                load: (serving.owner.recovery_report().io_peak_bytes).max(device_reads(serving)),
            };
            cell.close(serving, false);
            let blocker = match (outcome, short) {
                (MetadataOutcome::Open, Some(exit)) => format!("{exit:?}"),
                _ => format!("{outcome:?}"),
            };
            cell.blockers.push(blocker);
            cell.blocked = true;
            live[at] = None;
            self.cells[at].charges.push(charge);
            self.recovering = None;
            return Ok(None);
        }
        let holder = self.topology.members[cell.holder];
        let holder = holder_on(cell.placement.volume, holder.host, holder.instance);
        serving.duties = Some(Box::new(self.duties_of(at, serving, holder)));
        self.arm_duties(at, tenure);
        let serving = live[at].as_mut().expect("the recovered tenure");
        serving.client.session(serving.turn * ROUND_US);
        self.turns_until(live, (at, "the client session"), |serving| {
            serving.client.state() == SessionState::Active
        })?;
        self.recovering = None;
        Ok(Some(tenure))
    }

    /// The volumes whose record reads `Active` while no shard record names them active or spare, read without a store
    /// request. Every configured shard's record and every volume record must be stored, decode and sit under its own
    /// key, and no shard record of another shard may stand; a run that breaks that stops here.
    fn stranded(&self) -> Vec<crate::failover::records::VolumeId> {
        use crate::failover::records::{VolumeRecord, VolumeState};
        let store = self.store.0.borrow();
        for key in store.keys() {
            if let Key::Shard(shard) = key {
                let known = (self.cells.iter()).any(|cell| cell.placement.shard == *shard);
                assert!(known, "a shard record of an unknown shard {shard:?}");
            }
        }
        let named: Vec<crate::failover::records::VolumeId> = (self.cells.iter())
            .map(|cell| {
                let key = Key::Shard(cell.placement.shard);
                let item = store.current(&key).expect("each shard's record");
                let record = ShardRecord::decode(&item.value).expect("a shard record that decodes");
                assert_eq!(
                    record.shard, cell.placement.shard,
                    "a shard record under its key"
                );
                record
            })
            .flat_map(|record| [Some(record.active), record.spare.map(|(volume, _)| volume)])
            .flatten()
            .collect();
        let volumes = (store.keys()).filter_map(|key| match key {
            Key::Volume(volume) => Some(*volume),
            _ => None,
        });
        let records = volumes.map(|volume| {
            let item = store
                .current(&Key::Volume(volume))
                .expect("a stored volume record");
            let record = VolumeRecord::decode(&item.value).expect("a volume record that decodes");
            assert_eq!(record.volume, volume, "a volume record under its key");
            record
        });
        let records: Vec<VolumeRecord> = records.collect();
        (records.into_iter())
            .filter(|record| record.state == VolumeState::Active && !named.contains(&record.volume))
            .map(|record| record.volume)
            .collect()
    }

    /// In a store-result scenario, queues the scenario's fault for the first tenure of [`hosts::DUTY_CELL`], `tenure`:
    /// the duties' writes before the faulted one pass, and the faulted write times out, committing or not. The
    /// page-regression scenario also makes the duties' next coverage-page read of the cell's shard stale. A regression
    /// scenario's withdrawal of `tenure` for the regression is not counted ([`Cell::close`]).
    fn arm_duties(&mut self, at: usize, tenure: Tenure) {
        use crate::storage::store::sim::Arm;
        let timeout = match self.config.scenario {
            Scenario::StoreUnknown(cell) => Some((cell.write, cell.commit)),
            Scenario::PageRegressed => Some((hosts::DutyWrite::Page, true)),
            Scenario::RecordRegressed => None,
            _ => return,
        };
        if at != hosts::DUTY_CELL || self.faulted.is_some() {
            return;
        }
        if let Some((write, commit)) = timeout {
            let mut faults = self.faults.store.borrow_mut();
            for _ in 0..write.before() {
                faults.arm_write(duty_actor(at), Arm::Pass);
            }
            faults.arm_write(duty_actor(at), Arm::Timeout { commit });
        }
        if self.config.scenario == Scenario::PageRegressed {
            self.stale_read
                .aim(self.cells[at].placement.shard, Stale::Page);
        }
        self.faulted = Some((tenure, 0, None));
    }

    /// The coverage pages' acknowledged commits of cell `at`'s shard: the writes the store answered `Committed`, so a
    /// commit whose reply was unknown is not counted.
    fn page_commits(&self, at: usize) -> usize {
        let shard = self.cells[at].placement.shard;
        let store = self.store.0.borrow();
        (store.replied.iter())
            .filter(|(key, _)| matches!(key, Key::Page(of, _) if *of == shard))
            .map(|(_, replied)| replied)
            .sum()
    }

    /// The faulted boot tenure's evidence, read without a store request.
    fn faulted_duty(&self, live: &Live<'_>) -> Option<FaultedDuty> {
        let (tenure, held_at, acknowledged_at) = self.faulted?;
        let at = hosts::DUTY_CELL;
        let shard = self.cells[at].placement.shard;
        let serving = (live[at].as_ref()).filter(|serving| serving.tenure == tenure);
        let withdrawal = match serving {
            Some(serving) => withdrawn(serving.owner.authority_report()),
            None => self.faulted_withdrawal,
        };
        let timed_out =
            (self.duty_unknowns.borrow().iter()).find_map(|&(key, changed)| match key {
                Key::Shard(of) if of == shard && changed => Some(hosts::DutyWrite::Reserve),
                Key::Shard(of) if of == shard => Some(hosts::DutyWrite::Confirm),
                Key::Page(of, _) if of == shard => Some(hosts::DutyWrite::Page),
                _ => None,
            });
        let counts = self.duty_counts.borrow();
        let writes = |of: &dyn Fn(&Key) -> bool| -> u64 {
            counts
                .iter()
                .filter(|(key, _)| of(key))
                .map(|(_, (_, writes))| writes)
                .sum()
        };
        Some(FaultedDuty {
            tenure,
            taken: self.faults.store.borrow().queued(duty_actor(at)) == 0,
            timed_out,
            stale_served: self.stale_read.served(),
            record_writes: writes(&|key| *key == Key::Shard(shard)),
            page_writes: writes(&|key| matches!(key, Key::Page(of, _) if *of == shard)),
            held_at,
            acknowledged_at,
            recoveries: self.cells[at].recoveries.len(),
            withdrawal,
        })
    }

    /// The untouched-shard controls: once an episode's window is open, a store of the duties of the shard at the
    /// plant's index reads its shard record once (`ExtraRead`) or rewrites it at its version (`DutyRewrite`), while
    /// its tenure serves and its duties run.
    fn plant_views(&mut self, live: &Live<'_>) {
        let Profile::Hostile(plant @ (Plant::ExtraRead | Plant::DutyRewrite), at) =
            self.config.profile
        else {
            return;
        };
        let at = at as usize;
        let Some(cell) = self.cells.get(at) else {
            return;
        };
        let serving = live.get(at).and_then(Option::as_ref);
        let running =
            serving.is_some_and(|serving| serving.duties.is_some() && serving.duty_exit.is_none());
        if self.planted || !self.window || !running {
            return;
        }
        let key = Key::Shard(cell.placement.shard);
        let mut store = self.duty_store();
        let read = Store::read(&mut store, &key)
            .expect("a shard record read")
            .expect("a stored shard record");
        ShardRecord::decode(&read.value).expect("the planted shard's record");
        if plant == Plant::DutyRewrite {
            let write = Write::Exact {
                expect: read.version,
                value: read.value,
            };
            let _ = Store::write(&mut store, &key, &write);
        }
        self.planted = true;
    }

    /// The serving duties of cell `at`'s `Live` tenure `serving`, held by `holder`: an inline lane over a store client
    /// of the cell's own duty actor ([`duty_actor`]) inside the outage windows of the cell's holder host
    /// ([`HostOut`]), a watermark log of its own, which starts empty, and the tenure's storage; no attachment listing,
    /// the suffix bounds of the World's own suffix open ([`super::suffix_bounds`]) and [`duty_periods`] over the
    /// cell's bounds. The duties' storage samples one fixed clock reading, so a suffix step certifies no block, and
    /// the duties publish no checkpoint: they run with no capture policy.
    fn duties_of<'w>(
        &self,
        at: usize,
        serving: &Serving<'w>,
        holder: crate::failover::poll::Holder,
    ) -> FleetDuties<'w> {
        use crate::storage::store::sim::{Faulted, MemLog};
        let store = HostOut {
            holder: (self.config.scenario.hosted()).then(|| self.cells[at].holder as u32),
            faults: self.faults.store.clone(),
            inner: Faulted {
                inner: DutyCounted {
                    stale: self.stale_read.clone(),
                    ..self.duty_store()
                },
                actor: duty_actor(at),
                faults: self.faults.store.clone(),
            },
        };
        let client = crate::storage::store::Client::open(store, MemLog::default());
        let lane =
            crate::host::Lane::inline(client.expect("a duty's store client"), serving.storage);
        let records = crate::host::duties::Records {
            holder,
            instance: &fleet_instance,
        };
        let periods = duty_periods(&self.cells[at].world.bounds);
        let bounds = super::suffix_bounds();
        crate::host::Duties::new(
            (
                &crate::host::HostGate::qualified(),
                crate::failover::reconcile::StandbyGate::qualified(),
            ),
            lane,
            records,
            None,
            bounds,
            periods,
        )
    }

    /// `hosts_requests` subtracts reconciler, enrollment, serving-duty, and local standby-wait requests from the
    /// store's record-request count for cell `at`. `oracles::STANDBY_READS` checks the standby-wait budget.
    fn hosts_requests(&self, at: usize) -> u64 {
        let cell = &self.cells[at];
        let tallied = self.tallied.borrow();
        let reconciled: u64 = cell
            .keys()
            .map(|key| tallied.get(&key).copied().unwrap_or(0))
            .sum();
        let waited: u64 = cell
            .keys()
            .map(|key| cell.waited.get(&key).copied().unwrap_or(0))
            .sum();
        let duty = self.duty_views(at);
        cell.requests(&self.store)
            - reconciled
            - waited
            - duty.volume
            - duty.shard
            - duty.other
            - duty.writes
    }

    fn standby_client(
        &self,
        member: usize,
        counts: &owners::WaitCounts,
    ) -> crate::storage::store::Client<
        crate::storage::store::sim::Faulted<DutyCounted>,
        crate::storage::store::sim::MemLog,
    > {
        let store = crate::storage::store::sim::Faulted {
            inner: DutyCounted {
                inner: self.store.clone(),
                counts: counts.keys.clone(),
                unknowns: DutyUnknowns::default(),
                stale: StaleRead::default(),
            },
            actor: member as u32,
            faults: self.faults.store.clone(),
        };
        let client = crate::storage::store::Client::open(store, self.hosts[member].log.clone());
        client.expect("a host's store client")
    }

    /// A store of the serving duties' counts over the shared store, with no stale read aimed.
    fn duty_store(&self) -> DutyCounted {
        DutyCounted {
            inner: self.store.clone(),
            counts: self.duty_counts.clone(),
            unknowns: self.duty_unknowns.clone(),
            stale: StaleRead::default(),
        }
    }

    /// The serving duties' requests on cell `at`'s records as the untouched-shard check reads them, with zero rounds.
    fn duty_views(&self, at: usize) -> oracles::Views {
        let counts = self.duty_counts.borrow();
        let cell = &self.cells[at];
        let mut views = oracles::Views::default();
        for key in cell.keys() {
            let Some(&(reads, writes)) = counts.get(&key) else {
                continue;
            };
            views.writes += writes;
            match key {
                Key::Volume(_) => views.volume += reads,
                Key::Shard(_) => views.shard += reads,
                _ => views.other += reads,
            }
        }
        views
    }

    /// Cell `at`'s requests, records, duty requests and standby wait periods now, for the untouched-shard check.
    fn sample(&self, at: usize) -> Sampled {
        Sampled {
            at,
            requests: self.hosts_requests(at),
            seen: self.cells[at].seen(&self.store),
            round: self.round,
            duty: self.duty_views(at),
            waits: self.cells[at].waits.len(),
        }
    }

    /// Records, for each shard that served when the episode's owner crashed, whether its records took a store
    /// request other than its own serving duties' and its standby wait's since the crash, the periods of that wait, what those duties requested, and whether its record's tenure and owner or its route differ from the crash's
    /// sample or its authority no longer reads `Serving`. The samples are taken once the episode's GETs
    /// drained, so a change confined to the interval between is not seen.
    fn watch(&mut self, live: &Live<'_>, episode: &Episode) {
        for neighbor in &episode.before {
            let cell = &self.cells[neighbor.at];
            let serves = live[neighbor.at]
                .as_ref()
                .is_some_and(|serving| serving.owner.authority_report().state == State::Serving);
            let (now, then) = (self.duty_views(neighbor.at), neighbor.duty);
            self.watched.push(Watched {
                shard: cell.placement.shard,
                requested: self.hosts_requests(neighbor.at) != neighbor.requests,
                moved: cell.seen(&self.store) != neighbor.seen || !serves,
                views: oracles::Views {
                    volume: now.volume - then.volume,
                    shard: now.shard - then.shard,
                    other: now.other - then.other,
                    writes: now.writes - then.writes,
                    rounds: self.round - neighbor.round,
                },
                waits: (!self.hosts.is_empty())
                    .then(|| oracles::Waits::of(&cell.waits[neighbor.waits..])),
            });
        }
    }

    fn reconcile(&mut self) {
        for zone in 1..=self.config.shape.zones {
            let shards: Vec<_> = (self.cells.iter())
                .filter(|cell| cell.placement.zone.0 == zone)
                .map(|cell| cell.placement.shard)
                .collect();
            for _ in 0..self.config.shape.reconcilers {
                self.reconciled.ticks += 1;
                self.reconciled.unnamed += actors::reconcile(&self.store, &shards);
            }
        }
    }

    fn plant_records(&mut self) {
        let Profile::Hostile(plant, at) = self.config.profile else {
            return;
        };
        if plant == Plant::LossEvidence && self.config.scenario.repairs() {
            return;
        }
        let Some(cell) = self.cells.get(at as usize) else {
            return;
        };
        let key = Key::Shard(cell.placement.shard);
        let item = (self.store.0.borrow().current(&key).cloned()).expect("a stored shard record");
        let record = ShardRecord::decode(&item.value).expect("a stored shard record");
        let planted = match plant {
            Plant::TwinTenure => ShardRecord {
                owner: cell.standby,
                standby: None,
                ..record
            },
            Plant::LossEvidence => ShardRecord {
                generation: crate::net::ownership::ShardGeneration::new(
                    record.generation.get() + 1,
                )
                .expect("a next generation"),
                attempts: 0,
                // The tenure's duties recorded its suffix, which a record of the next generation holds none of.
                ancestry: crate::failover::records::Ancestry::default(),
                ..record
            },
            _ => return,
        };
        let write = Write::Exact {
            expect: item.version,
            value: planted.encode(),
        };
        let outcome = Store::write(&mut self.store.clone(), &key, &write);
        self.planted = matches!(outcome, Outcome::Committed(_));
    }

    /// Judges the run. The caller closed every tenure first.
    fn report(&self, live: &Live<'_>, decisions: u64, tape: Vec<u8>) -> Report {
        let histories: Vec<_> = (self.cells.iter())
            .map(|cell| (cell.placement.shard, cell.history(&self.store)))
            .collect();
        let activations: Vec<_> = (self.activations.iter())
            .map(|&(at, tenure, host)| (self.cells[at].placement.shard, tenure, host))
            .collect();
        let retention: Vec<Retention> = (self.cells.iter().enumerate())
            .map(|(at, cell)| Retention {
                shard: cell.placement.shard,
                activations: (self.activations.iter())
                    .filter(|(of, ..)| *of == at)
                    .count(),
                sweeps: cell.recoveries.iter().map(|r| r.sweep).collect(),
                judged: cell.judged(),
            })
            .collect();
        let hosted = self.config.scenario.hosted();
        let settle: Vec<Settle> = (self.cells.iter().zip(live).zip(&histories))
            .map(|((cell, serving), (_, history))| {
                let record = history.last().expect("a stored shard record");
                Settle {
                    shard: cell.placement.shard,
                    serving: (serving.as_ref())
                        .is_some_and(|serving| serves(cell, serving, record)),
                    standby: record.standby.is_some(),
                    blockers: usize::from(cell.blocked),
                    withdrawals: cell.withdrawals,
                    rounds: (cell.recoveries.iter())
                        .filter(|recovered| recovered.after_crash)
                        .map(|recovered| recovered.rounds)
                        .collect(),
                }
            })
            .collect();
        let hosts = self.host_use();
        let fences = match self.config.zoned() {
            true => self.page_fences(),
            false => Vec::new(),
        };
        let mut zones = self.zone_log.clone();
        zones.fence_writes = (zones.restarts.iter())
            .filter_map(|(shard, _, tenure, _)| {
                let (_, pages) = fences.iter().find(|(of, _)| of.get() == *shard)?;
                let commits = oracles::fence_commits(pages, *tenure);
                Some(commits.into_iter().flatten().count())
            })
            .sum();
        let censuses = self.census_versions();
        let cap = usize::from(self.config.shape.cap);
        let settled: Vec<oracles::Settled> = match self.repairs() {
            true => (0..self.cells.len())
                .map(|at| self.settled_at(live, at))
                .collect(),
            false => Vec::new(),
        };
        let watched: Vec<Watched> = (self.watched.iter())
            .filter(|watch| !self.log.exempt.contains(&watch.shard.get()))
            .copied()
            .collect();
        // The untouched check judges the GETs to shards a watch can cover, outside an exempt shard. A served
        // `Beside` GET goes to a shard a takeover restored, and a served GET to a released shard went out while
        // that shard was untouched; no watch covers either, and an unserved one still fails the check's refusal
        // rule.
        let covered = |at: usize| {
            let shard = self.cells[at].placement.shard;
            !self.released.contains(&at) || watched.iter().any(|watch| watch.shard == shard)
        };
        let judged: Vec<&Settled> = (self.neighbours.iter())
            .filter(|settled| (!settled.beside && covered(settled.at)) || !settled.served)
            .filter(|settled| {
                let shard = self.cells[settled.at].placement.shard.get();
                !self.log.exempt.contains(&shard)
            })
            .collect();
        let requests: Vec<_> = (judged.iter())
            .map(|settled| (self.cells[settled.at].placement.shard, settled.served))
            .collect();
        let overlapped = (judged.iter())
            .filter(|settled| settled.served && settled.inside)
            .count();
        let served = |at: usize| {
            let rows = self.neighbours.iter();
            rows.filter(|settled| settled.at == at && settled.served)
                .count() as u32
        };
        Report {
            identity: self.config.identity(),
            config: *self.config,
            verdicts: Verdicts {
                one_owner: oracles::one_owner(&histories, &activations),
                keeps_volume: oracles::keeps_volume(
                    &histories,
                    self.volumes(),
                    self.crashes,
                    &self.losses(),
                ),
                retained: oracles::retained(&retention),
                settles: match (hosted, self.repairs()) {
                    (_, true) => oracles::settled(&settled, &self.recon),
                    (true, false) => oracles::unsettled(&settle),
                    (false, false) => oracles::settles(&settle, SETTLE_ROUNDS, self.crashes),
                },
                within_share: oracles::within_share(&hosts),
                untouched: oracles::untouched(&watched, &requests, overlapped),
                census: (self.repairs()).then(|| {
                    oracles::census(&censuses, (cap, self.config.shape.zones), &self.recon)
                }),
                fenced: (self.config.zoned())
                    .then(|| oracles::fenced_before_admission(&fences, &self.admissions)),
            },
            takeovers: (histories.iter())
                .map(|(_, history)| owner_changes(history))
                .sum(),
            shards: (self.cells.iter().enumerate().zip(&histories))
                .map(|((at, cell), (_, history))| ShardReport {
                    placement: cell.placement,
                    owner: cell.owner,
                    standby: cell.standby,
                    recoveries: cell.recoveries.clone(),
                    blockers: cell.blockers.clone(),
                    attempts: history.last().map_or(0, |record| record.attempts),
                    neighbour: Neighbour {
                        offered: cell.requested.len() as u32,
                        served: served(at),
                    },
                    requested: cell.requested.clone(),
                    invalidated: cell.invalidated.clone(),
                    unserved: cell.unserved.clone(),
                    activated: (self.activations.iter())
                        .filter(|(of, ..)| *of == at)
                        .map(|&(_, tenure, host)| (tenure, host))
                        .collect(),
                    reports: cell.reports,
                    waits: cell.waits.clone(),
                    wait_exits: cell.wait_exits.clone(),
                })
                .collect(),
            crashes: self.crashes,
            rounds: self.round,
            reconciled: self.reconciled,
            // The planted ack changes a run once a duty coverage write's reply is unknown.
            planted: self.planted
                || (self.config.planted(Plant::AckOnUnknown)
                    && (self.duty_unknowns.borrow().iter())
                        .any(|(key, _)| matches!(key, Key::Page(..)))),
            decisions,
            tape,
            hosts: self.log.clone(),
            evidence: Evidence {
                histories,
                activations,
                volumes: self.volumes(),
                censuses,
                census_entries: (1..=self.config.shape.zones)
                    .filter_map(|zone| self.census_now(crate::failover::standbys::Zone(zone)))
                    .map(|census| census.len())
                    .sum(),
                fences,
                admissions: self.admissions.clone(),
                settled,
                attached: self.attached(),
                losses: self.losses(),
                replaced: self.replaced(),
                receipts: (0..self.cells.len())
                    .map(|at| self.receipt_now(at))
                    .collect(),
                listed: self.listed(),
                requests: self.requests(),
                standby_local: self.standby_local(),
                slots: (0..self.cells.len())
                    .map(|at| {
                        let shard = self.cells[at].placement.shard;
                        let census = self.census_now(self.zone_of(at));
                        (
                            shard,
                            census.and_then(|c| c.slot(shard)).map(|slot| slot.host),
                        )
                    })
                    .collect(),
            },
            recon: {
                let mut recon = self.recon.clone();
                recon.incarnations = self
                    .reconcilers
                    .iter()
                    .map(|actor| actor.incarnation)
                    .collect();
                recon
            },
            volumes: volumes::VolumeLog {
                stranded: self.stranded(),
                ..self.volumes.clone()
            },
            zones,
            duties: {
                let counts = self.duty_counts.borrow();
                let (reads, writes) = (counts.values())
                    .fold((0, 0), |(r, w), (reads, writes)| (r + reads, w + writes));
                let exits = (self.cells.iter())
                    .flat_map(|cell| {
                        let shard = cell.placement.shard.get();
                        (cell.duty_exits.iter())
                            .map(move |(tenure, exit)| (shard, *tenure, exit.clone()))
                    })
                    .collect();
                DutyLog {
                    opened: self.cells.iter().map(|cell| cell.duty_opened).sum(),
                    acknowledged: (self.cells.iter()).filter(|cell| cell.acknowledged).count()
                        as u32,
                    reads,
                    writes,
                    exits,
                    faulted: self.faulted_duty(live),
                    torn: self.torn.clone(),
                    lines: {
                        let lines = (self.cells.iter()).flat_map(|cell| {
                            let shard = cell.placement.shard.get();
                            cell.lines.iter().map(move |tenure| (shard, *tenure))
                        });
                        lines.collect()
                    },
                }
            },
        }
    }

    fn requests(&self) -> Vec<(crate::net::ownership::Shard, usize)> {
        use crate::failover::zone_loop::tests::world::Event;
        (self.cells.iter())
            .map(|cell| {
                let mut counts: std::collections::BTreeMap<String, usize> = Default::default();
                for zone in &self.zones {
                    for event in zone.log.borrow().iter() {
                        if let Event::Attach(volume, instance) = event
                            && *volume == cell.placement.volume
                        {
                            *counts.entry(instance.as_str().to_owned()).or_default() += 1;
                        }
                    }
                }
                (
                    cell.placement.shard,
                    counts.into_values().max().unwrap_or(0),
                )
            })
            .collect()
    }

    fn standby_local(&self) -> Vec<(crate::net::ownership::Shard, bool)> {
        let at = (0..self.cells.len()).filter_map(|at| {
            let standby = self.record_now(at).standby?;
            let member = self.member_of(standby)?;
            let enrolled = self.volume_now(at).enrolled(standby);
            let local = self.cells[at].local_of(member).map(|(pair, _)| pair);
            Some((
                self.cells[at].placement.shard,
                enrolled.is_some() && local == enrolled,
            ))
        });
        at.collect()
    }

    fn listed(&self) -> Vec<(crate::net::ownership::Shard, usize)> {
        (self.cells.iter())
            .map(|cell| {
                let volumes = self.zones.iter().flat_map(|zone| zone.volumes.iter());
                let listing = volumes.filter(|listed| listed.volume == cell.placement.volume);
                let attachments = listing.flat_map(|listed| listed.attachments.iter());
                let most = (attachments.clone())
                    .map(|instance| attachments.clone().filter(|of| *of == instance).count())
                    .max();
                (cell.placement.shard, most.unwrap_or(0))
            })
            .collect()
    }

    fn attached(&self) -> Vec<(crate::net::ownership::Shard, usize)> {
        let store = self.store.0.borrow();
        (self.cells.iter())
            .map(|cell| {
                let versions = store.versions(&Key::Volume(cell.placement.volume)).iter();
                let attached = versions.map(|item| {
                    let record = VolumeRecord::decode(&item.value).expect("a stored volume record");
                    record.live_hosts().count()
                });
                (cell.placement.shard, attached.max().unwrap_or(0))
            })
            .collect()
    }

    /// Each member's roles in the shard records and censuses the store holds now: the shards whose record names the
    /// member owner or standby, and the census slots of the member for shards whose record names it in no role.
    fn roles_now(&self) -> Vec<u32> {
        let store = self.store.0.borrow();
        let records: Vec<ShardRecord> = (self.cells.iter())
            .filter_map(|cell| store.current(&Key::Shard(cell.placement.shard)))
            .map(|item| ShardRecord::decode(&item.value).expect("a stored shard record"))
            .collect();
        let censuses: Vec<crate::failover::standbys::Census> = (1..=self.config.shape.zones)
            .filter_map(|zone| store.current(&Key::Standbys(crate::failover::standbys::Zone(zone))))
            .map(|item| {
                crate::failover::standbys::Census::decode(&item.value).expect("a stored census")
            })
            .collect();
        (self.topology.members.iter())
            .map(|of| {
                let host = of.host;
                let named =
                    |record: &ShardRecord| record.owner == host || record.standby == Some(host);
                let roles = records.iter().filter(|record| named(record)).count();
                let slots = (censuses.iter())
                    .flat_map(|census| {
                        records
                            .iter()
                            .filter_map(|r| census.slot(r.shard).map(|s| (r, s)))
                    })
                    .filter(|(record, slot)| !named(record) && slot.host == host)
                    .count();
                (roles + slots) as u32
            })
            .collect()
    }

    /// Keeps each member's largest role count over the samples of a reconciler scenario: the seeded records at the
    /// first round and the records and censuses at the end of every round after it, so a count that rises and falls
    /// within one round goes unsampled.
    fn sample_roles(&mut self) {
        let now = self.roles_now();
        self.peak_roles.resize(now.len(), 0);
        for (peak, roles) in self.peak_roles.iter_mut().zip(now) {
            *peak = (*peak).max(roles);
        }
    }

    /// Each host's roles (in a reconciler scenario the largest count the role samples read), the shares of the loads
    /// it ran, and the sum over its shards of each shard's largest load on it, a load counting the larger of its
    /// storage's peak window and its device double's read bytes and a load that did not open included. Loads of one
    /// shard never run together, so one shard adds one load. The loads of different shards may lie in different
    /// windows, so the sum is an upper bound of the host's window.
    fn host_use(&self) -> Vec<HostUse> {
        (self.topology.members.iter().enumerate())
            .map(|(member, of)| {
                let loads = |cell: &Cell| {
                    let on = cell.charges.iter().filter(|charge| charge.host == of.host);
                    on.map(|charge| charge.load).max()
                };
                HostUse {
                    host: of.host,
                    roles: match self.config.scenario.repairs() {
                        true => (self.peak_roles.get(member).copied())
                            .unwrap_or(0)
                            .max(self.roles_now()[member]),
                        false => self.topology.roles(member),
                    },
                    shares: (self.cells.iter())
                        .flat_map(|cell| cell.charges.iter())
                        .filter(|charge| charge.host == of.host)
                        .map(|charge| charge.share)
                        .collect(),
                    peak_bytes: self.cells.iter().filter_map(loads).sum(),
                }
            })
            .collect()
    }
}

/// Whether `serving` holds `cell`'s shard at `record`'s `(g, E)` with its serving duties at no exit, its authority
/// `Serving` inside its Report window, its owner `Live`, its client session active and the client's route bound to
/// that tenure.
fn serves(cell: &Cell, serving: &Serving<'_>, record: &ShardRecord) -> bool {
    let named = Tenure {
        g: record.generation.get(),
        a: u64::from(record.attempts) * 2,
    };
    let route = cell.world.routes.route(cell.placement.shard);
    let authority = serving.owner.authority_report();
    serving.tenure == named
        && serving.duty_exit.is_none()
        && authority.state == State::Serving
        && authority.report_age_us.is_some_and(|age| age < WINDOW)
        && serving.owner.readiness() == Readiness::Live
        && serving.client.state() == SessionState::Active
        && matches!(route, Some(HighWater::Bound(_)))
        && cell.world.high_water() == Some(named)
}

fn owner_changes(history: &[ShardRecord]) -> u32 {
    let moved = (history.windows(2)).filter(|pair| pair[0].owner != pair[1].owner);
    moved.count() as u32
}

/// Waits for the tenure's serving duties to open its suffix, which an invalidation requires, then invalidates object
/// `n` in RAM. Returns whether the invalidation removed an entry.
fn drop_from_ram(serving: &mut Serving<'_>, n: u8) -> bool {
    duties_opened(serving) && serving.drop_entry(n)
}

/// The rounds [`duties_opened`] steps a tenure for its duties' open.
const OPEN_ROUNDS: u32 = 64;

/// Steps `serving` with its serving duties, at most [`OPEN_ROUNDS`] rounds, until the duties' tenure open ends, and
/// returns whether it ended `Opened`, read after the last step as well: the duties viewed the records, confirmed the
/// shard record by an exact-version write and, when the record names a checkpoint, reserved the tenure's suffix. A
/// tenure with no duties, or whose duties named an exit, opens nothing.
fn duties_opened(serving: &mut Serving<'_>) -> bool {
    use crate::host::duties::Open;
    for _ in 0..OPEN_ROUNDS {
        let Some(duties) = serving
            .duties
            .as_ref()
            .filter(|_| serving.duty_exit.is_none())
        else {
            return false;
        };
        match duties.open() {
            Open::Opened => return true,
            Open::Stopped => return false,
            Open::Due | Open::Viewing | Open::Confirming | Open::Opening => {}
        }
        if actors::duties(serving).is_some() {
            return false;
        }
    }
    let opened = serving.duties.as_ref().map(|duties| duties.open());
    serving.duty_exit.is_none() && opened == Some(Open::Opened)
}

/// A local fill of object `n` on `serving`, stepped with its serving duties: one duty turn follows each owner poll
/// between the fill's writes, as in a fleet round. Returns whether the fill published.
fn filled(world: &mut World, serving: &mut Serving<'_>, n: u8) -> bool {
    serving.fill_stepped(world, n, crate::storage::CacheVersion(0), |serving| {
        let _ = actors::duties(serving);
    })
}

/// The withdrawal cause an authority report names, or `None` when the authority reads `Serving`.
fn withdrawn(
    authority: crate::storage::AuthorityReport,
) -> Option<crate::failover::serving::Cause> {
    (authority.state != State::Serving)
        .then_some(authority.withdrawal)
        .flatten()
}

/// Whether `serving`'s turn named an exit that ends its process with no park, a rerun or `Deposed`, which the fleet
/// tears down as `serve` does. `serve::ended` and `Duties::turn` name `Stopped`, `Deposed`, `Retire` or `Rerun`; a
/// `Held` exit comes from a bring-up or a recovery, before the tenure serves.
fn awaits_teardown(serving: &Serving<'_>) -> bool {
    use crate::host::Exit;
    matches!(serving.duty_exit, Some(Exit::Rerun(_) | Exit::Deposed))
}

/// Steps `serving` with its serving duties, at most [`OPEN_ROUNDS`] rounds, until an exit ends them.
fn duties_ended(serving: &mut Serving<'_>) {
    for _ in 0..OPEN_ROUNDS {
        if serving.duty_exit.is_some() || serving.duties.is_none() {
            return;
        }
        let _ = actors::duties(serving);
    }
}

/// Steps `serving` with its serving duties, at most [`OPEN_ROUNDS`] rounds, until a turn's duties acknowledge the
/// held INVALIDATE of object `n`: its coverage write's acknowledged commit, which the duties adopted (ACK-ON-COMMIT).
/// Records the INVALIDATE event in `world` and returns true then. A tenure whose duties named an exit acknowledges
/// nothing.
fn duties_acknowledged(world: &mut World, serving: &mut Serving<'_>, n: u8) -> bool {
    let key = crate::storage::warm_sim::object_key(n);
    for _ in 0..OPEN_ROUNDS {
        if serving.duty_exit.is_some() || actors::duties(serving).is_some() {
            return false;
        }
        let Some(duties) = serving.duties.as_ref() else {
            return false;
        };
        if duties.acknowledged().iter().any(|(of, _)| *of == key) {
            let tenure = Some(serving.tenure);
            world.events.push(super::Event::Invalidate { n, tenure });
            return true;
        }
    }
    false
}

/// The reads and the writes of the tenures' serving duties, or of one view period of a standby wait, by key.
pub(crate) type DutyCounts =
    std::rc::Rc<std::cell::RefCell<std::collections::BTreeMap<Key, (u64, u64)>>>;

/// Each serving-duty write whose reply was unknown, by key, with whether its value differs from the value at the
/// version it conditioned on: a Confirm writes the viewed value back, and a suffix reservation changes it.
pub(crate) type DutyUnknowns = std::rc::Rc<std::cell::RefCell<Vec<(Key, bool)>>>;

/// The stale read a [`DutyCounted`] store serves: the shard and the record kind of the next read it answers with an
/// earlier version ([`Stale`]), and whether it served one since the fleet started.
#[derive(Debug, Clone, Default)]
pub(crate) struct StaleRead {
    aimed: std::rc::Rc<std::cell::Cell<Option<(crate::net::ownership::Shard, Stale)>>>,
    served: std::rc::Rc<std::cell::Cell<bool>>,
}

impl StaleRead {
    /// Aims the next read of `stale`'s record kind of `shard` that finds two committed versions or more.
    pub(crate) fn aim(&self, shard: crate::net::ownership::Shard, stale: Stale) {
        self.aimed.set(Some((shard, stale)));
    }

    /// Whether a read returned the earlier version an aim named.
    pub(crate) fn served(&self) -> bool {
        self.served.get()
    }
}

/// The record a stale read of [`DutyCounted`] returns an earlier version of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stale {
    /// A coverage page of the shard: its first version, whose fence lies below every tenure that fenced it.
    Page,
    /// The shard record: the version before its last, below the mark a client that read the last one holds.
    Record,
}

/// Counts each read and each write it forwards in `counts`, by key: the store of a tenure's serving duties and of a
/// standby wait's view period, which aims no stale read. Each
/// write whose reply is unknown joins `unknowns`. While `stale` aims at a shard and a record kind, the next read of
/// such a record of the shard that holds two committed versions or more returns the earlier version [`Stale`] names,
/// clears the aim and marks the stale read served.
pub(crate) struct DutyCounted {
    pub(crate) inner: Shared,
    pub(crate) counts: DutyCounts,
    pub(crate) unknowns: DutyUnknowns,
    pub(crate) stale: StaleRead,
}

impl Store for DutyCounted {
    fn read(&mut self, key: &Key) -> Result<Option<Item>, crate::storage::store::Unavailable> {
        self.counts.borrow_mut().entry(*key).or_default().0 += 1;
        let read = self.inner.read(key);
        let aimed = match (key, self.stale.aimed.get()) {
            (Key::Page(shard, _), Some((of, Stale::Page))) => (*shard == of).then_some(Stale::Page),
            (Key::Shard(shard), Some((of, Stale::Record))) => {
                (*shard == of).then_some(Stale::Record)
            }
            _ => None,
        };
        let Some(aimed) = aimed else {
            return read;
        };
        let store = self.inner.0.borrow();
        let versions = store.versions(key);
        let at = match aimed {
            Stale::Page => 0,
            Stale::Record => versions.len().saturating_sub(2),
        };
        let Some(earlier) = versions.get(at).filter(|_| versions.len() >= 2).cloned() else {
            return read;
        };
        self.stale.aimed.set(None);
        self.stale.served.set(true);
        Ok(Some(earlier))
    }

    fn write(&mut self, key: &Key, write: &Write) -> Outcome {
        self.counts.borrow_mut().entry(*key).or_default().1 += 1;
        let conditioned = match write {
            Write::Create(_) => None,
            Write::Exact { expect, .. } => {
                let store = self.inner.0.borrow();
                let versions = store.versions(key);
                (versions.iter().find(|item| item.version == *expect))
                    .map(|item| item.value.clone())
            }
        };
        let outcome = self.inner.write(key, write);
        if outcome == Outcome::Unknown {
            let (Write::Create(value) | Write::Exact { value, .. }) = write;
            let changed = conditioned.as_ref() != Some(value);
            self.unknowns.borrow_mut().push((*key, changed));
        }
        outcome
    }

    fn namespace(&self) -> crate::failover::records::Namespace {
        self.inner.namespace()
    }
}

impl crate::storage::store::sim::Armed for DutyCounted {
    fn arm_next(&mut self, arm: crate::storage::store::sim::Arm) -> usize {
        self.inner.arm_next(arm)
    }

    fn disarm(&mut self, before: usize) {
        self.inner.disarm(before);
    }
}

/// The store of a tenure's serving duties inside its holder host's store outages: inside an outage window of
/// `holder`, or of every actor, a read returns no value and a write is unknown, and neither reaches `inner`, so no
/// arm of the duty actor is taken. A run with no hosts gives no holder.
pub(crate) struct HostOut<S> {
    pub(crate) holder: Option<u32>,
    pub(crate) faults: std::rc::Rc<std::cell::RefCell<crate::storage::store::sim::ActorFaults>>,
    pub(crate) inner: S,
}

impl<S> HostOut<S> {
    fn out(&self) -> bool {
        (self.holder).is_some_and(|holder| self.faults.borrow().out(holder))
    }
}

impl<S: Store> Store for HostOut<S> {
    fn read(&mut self, key: &Key) -> Result<Option<Item>, crate::storage::store::Unavailable> {
        match self.out() {
            true => Err(crate::storage::store::Unavailable),
            false => self.inner.read(key),
        }
    }

    fn write(&mut self, key: &Key, write: &Write) -> Outcome {
        match self.out() {
            true => Outcome::Unknown,
            false => self.inner.write(key, write),
        }
    }

    fn namespace(&self) -> crate::failover::records::Namespace {
        self.inner.namespace()
    }
}

/// The fault actor of cell `at`'s serving duties. Hosts take the actors from 0 and reconcilers the ones after the
/// hosts, so the duties take theirs from `DUTY_ACTORS`, one a cell: an arm queued for it reaches that cell's duties
/// alone, whichever host serves the cell.
pub(crate) fn duty_actor(at: usize) -> u32 {
    DUTY_ACTORS + at as u32
}

const DUTY_ACTORS: u32 = 1 << 16;

/// The record view period of a fleet tenure's duties, in microseconds on the owner's poll timeline: three rounds.
pub(crate) const DUTY_VIEW_US: u64 = 3 * ROUND_US;

/// The duties' periods over `bounds`: a view every [`DUTY_VIEW_US`], a listing period of ten views that no listing
/// uses, and store and listing deadlines of one microsecond, which `Periods::new` admits under the fleet's bounds.
fn duty_periods(bounds: &crate::failover::bounds::Bounds) -> crate::host::duties::Periods {
    let periods =
        crate::host::duties::Periods::new(bounds, DUTY_VIEW_US, 10 * DUTY_VIEW_US, (1, 1));
    periods.expect("the fleet's duty periods")
}

/// The instance of the fleet host `host`, as `Topology::draw` names every member's.
fn fleet_instance(host: Host) -> Option<crate::failover::attachments::InstanceId> {
    Some(crate::failover::sim::instance_of_host(host))
}

type Pinned = (&'static str, fn(u64) -> Config, u64);

pub(crate) const ROOTS: std::ops::RangeInclusive<u64> = 1..=16;

pub(crate) const PINNED: [Pinned; 6] = [
    ("six", Config::six, 1),
    ("six", Config::six, 2),
    ("dense", Config::dense, 1),
    ("dense", Config::dense, 2),
    ("host-loss", Config::host_loss, 1),
    ("host-loss", Config::host_loss, 2),
];

/// Runs `config` and replays its recording; returns the report when the run earns credit and its replay is equal.
///
/// # Errors
///
/// The run's report lines when it earns no credit, and the replay's result when it differs from the run.
fn credited_replay(name: &str, config: &Config) -> Result<Report, String> {
    let root = config.root;
    let report = run(config).map_err(|stopped| format!("{name} root {root}: {stopped:?}"))?;
    if !report.credit().passed() {
        return Err(report.lines().join("\n"));
    }
    let replayed = replay(config, &report.recording());
    alike(name, &report, &replayed)?;
    Ok(report)
}

/// Runs and replays each pinned configuration on root `only`, or every pinned configuration when `only` is `None`, and
/// returns one digest line per run. The fast tier runs root 1, the scheduled tier root 2, and the worker every one.
///
/// # Errors
///
/// The pin's name and root with the `Stopped` value when a run returns no report, the run's report lines when
/// it earns no credit, and the replay's result when it differs from the run.
pub(crate) fn pinned_runs(only: Option<u64>) -> Result<Vec<String>, String> {
    let mut lines = Vec::new();
    for (name, config, root) in PINNED
        .into_iter()
        .filter(|pin| only.is_none_or(|at| at == pin.2))
    {
        let report = credited_replay(name, &config(root))?;
        lines.push(format!(
            "fleet: pinned {name} root {root}: credit pass; digest {}",
            report.digest()
        ));
    }
    Ok(lines)
}

fn alike(name: &str, report: &Report, replayed: &Result<Report, Stopped>) -> Result<(), String> {
    if replayed.as_ref() == Ok(report) {
        return Ok(());
    }
    let root = report.config.root;
    Err(format!("{name} root {root} replayed to {replayed:?}"))
}

/// The root of the crash table's pinned line.
pub(crate) const CRASH_TABLE_ROOT: u64 = 1;

/// Runs and replays each of `cells` on `root` in order, and returns one digest line over the cells' digests. The
/// worker's pinned lines pass every cell of the crash table.
///
/// # Errors
///
/// As [`pinned_runs`], for the first cell that earns no credit or replays to another report.
pub(crate) fn crash_table(root: u64, cells: &[reconcile::CrashCell]) -> Result<String, String> {
    let mut digests = Sha256::new();
    for &cell in cells {
        let report = credited_replay(&cell.name(), &Config::crash(root, cell))?;
        digests.update(report.digest());
    }
    let digest = hex(&digests.finalize());
    Ok(format!(
        "fleet: pinned crash-table root {root}: credit pass; digest {digest}"
    ))
}

/// Runs both shapes on `roots` and returns each run's summary, then one line with the run count and the slowest
/// recovery after a crash, the recoveries [`SETTLE_ROUNDS`] bounds.
///
/// # Errors
///
/// The root with the `Stopped` value when a run returns no report, and the run's report lines when it earns no
/// credit. Credit refuses an owner change and a recovery past the settle bound.
pub(crate) fn roots(roots: std::ops::RangeInclusive<u64>) -> Result<Vec<String>, String> {
    let shapes = [Config::six, Config::dense].into_iter();
    sweep(shapes.flat_map(|config| roots.clone().map(config)))
}

fn sweep(configs: impl Iterator<Item = Config>) -> Result<Vec<String>, String> {
    let (mut lines, mut slowest) = (Vec::new(), 0);
    for config in configs {
        let root = config.root;
        let report = run(&config).map_err(|stopped| format!("root {root}: {stopped:?}"))?;
        let rounds = (report.shards.iter())
            .flat_map(|shard| shard.recoveries.iter())
            .filter(|recovered| recovered.after_crash)
            .map(|recovered| recovered.rounds);
        slowest = slowest.max(rounds.max().unwrap_or(0));
        if !report.credit().passed() {
            return Err(report.lines().join("\n"));
        }
        lines.push(report.summary());
    }
    lines.push(format!(
        "fleet: roots: {} runs passed, 0 takeovers, settle at most {slowest} of {SETTLE_ROUNDS} rounds",
        lines.len()
    ));
    Ok(lines)
}
