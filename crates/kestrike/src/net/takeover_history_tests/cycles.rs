//! Seeded multi-cycle histories of one shard: warm takeovers and same-host restarts composed under an open-loop
//! tape in the takeover history world, judged as four separate verdicts with a boundary ledger.
//!
//! A run starts from the capturing tenure's volume and record and runs `cycles` cycles. Each cycle recovers the
//! shard, serves, and ends in a cut:
//!
//! 1. A recovery, drawn from the tape: the owner's same-host restart after a process crash; the named standby's
//!    takeover after owner loss; a takeover by a host the reconciler designates after the owner and its standby
//!    are both lost, where the run's first designation names the fresh host, as standby or as the recovering host;
//!    a takeover that stops after its compare-and-swap and before its preempt, recovered by a third designated host;
//!    a takeover whose compare-and-swap committed with an unknown reply, recovered by the successor's own restart
//!    through its lineage arm; a successor
//!    lost after its preempt and before it attaches, recovered by its own restart; and a takeover formed under a
//!    designation the reconciler then replaced, which refuses before any write. Every recovery is the production
//!    `Restart::run` or `Takeover::run` over the store double and the one shared reservation, and every
//!    designation is the reconciler's own steps. Each recovered tenure attaches the same media warm. A recovery is
//!    classed `ReplacementAttach` when its host joined the run and recovers the shard for the first time. The host
//!    is the fresh host D, or in a slot-reuse run the generated standby the last replacement enrolled.
//! 2. An opening sweep that reads every object the history knows, the retention observation of the tenure.
//! 3. A serve phase of tape arrivals offered at their ticks: GETs through the client, FILLs through the owner, and
//!    INVALIDATEs held by the owner and acknowledged by their coverage page write. A FILL or INVALIDATE first
//!    waits for the GETs in flight, so the recorded order of a mutation and a read is the order they took effect.
//!    Arrivals that fall due while a mutation or its GET drain runs are offered once it completes: each keeps its
//!    tape tick, from which its wait is measured, and its operand is reduced against the state at its offer.
//! 4. A capture pass over the tenure's membership, and a closing sweep.
//! 5. A drain to the tenure's quiescent boundary and its ledger sample ([`ledger`]).
//! 6. The cut: the tape draws up to two GETs, which the client sends; the tenure drops without quiesce once its
//!    owner holds one of them or none is in flight, and the GETs with no outcome settle `interrupted`. Each arrival of the interval while
//!    no tenure serves settles `refused` at its tick. At rest the tape may flip a device unit, land one of the
//!    capturing tenure's own writes again, or do both to one unit.
//!
//! The verdicts are separate. Safety is the client judgment over the whole history, the tenure-ordered checker's rules
//! outside the `Restart` obligation, and the harness's check that no covered version is served. When the oracle's
//! judgment raised no violation and was conclusive, safety also carries the ownership monitor's verdict over the run's
//! steps, and an inconclusive ownership judgment reads safety inconclusive. A `Restart` rule of the oracle's checker
//! fails retention, or containment when it states a loss outside the cut's own entries. Containment is that every
//! refused or interrupted step left the record's manifest and the media as they were, that the generation, volume and
//! named checkpoint never change, and that the damage rows name exactly the injected units, which the recovery's own
//! loss report counts. Retention is the oracle's positive preservation judgment and the harness's own model of the
//! retained set: every entry of the cut, and every FILL an earlier tenure acknowledged before its boundary, that no
//! acknowledged INVALIDATE covers and no injected unit holds is served its exact bytes in every tenure's opening sweep,
//! the oracle's account of each tenure holds at least the entries the harness expects and served, and every FILL a
//! tenure acknowledged is served in that tenure. A legal miss satisfies safety and never retention. A verdict whose
//! oracle judgment did not run for some group of keys reads inconclusive. Progress is that every recovery reached
//! `Live`, every offered request settled in one bucket, every GET drain and every boundary finished within its round or
//! tick bound, every tenure started a capture pass that walked exactly its resident entries, the store refused a
//! tenure's suffix only at the chain cap, and every INVALIDATE and every FILL of the run's fill range a tenure with an
//! open suffix was offered was acknowledged; a FILL offered past the range settles refused under no progress rule.
//!
//! Limits of the composition. The owner runs no checkpoint or frontier writer, so the cut stays the capturing
//! tenure's checkpoint, no publication follows a boundary, and each ledger sample is a quiescent sample between
//! checkpoints: the publish-aligned conservation and plateau judgments read inconclusive unless the quiescent
//! judgment fails or the plateau leaves a declared band, whose failure they carry. The ledger records retired slots,
//! retired bytes and waste and judges none of them. Each recovered tenure adds
//! one suffix to the record's chain and certifies no predecessor suffix, so a FILL's retention is witnessed on landed,
//! uncertified suffix blocks. The chain reaches its cap after four suffixes; from then on the store refuses the
//! tenure's suffix and the storage refuses every FILL, and every INVALIDATE that removes a resident entry, before
//! acknowledgment while retained hits continue; the run counts these as chain-full tenures. Outside the slot-reuse
//! runs below, the volume admits three live attachments and records no detach, so one fresh host joins a run and
//! later designations name a host that returned. A stale designation and an unknown compare-and-swap are witnessed at the takeover's reads and in the
//! committed resolution; a superseded tenure takes no step after its successor's fence. A repeated landing writes a
//! capturing-tenure write again over a unit that still holds its bytes or was flipped, so it exercises the
//! repeated attempt and no overwrite of a reused unit. The cut falls after the boundary, so it holds no device write
//! and no unacknowledged publication. [`UNSCORED`] lists the in-scope cases the composition leaves unscored.
//!
//! SLOT-REUSE runs ([`Config::slot_reuse`]) replace a host in every cycle. The recovery is the owner's restart, which
//! replaces the standby, or the standby's takeover, which replaces the owner. After its opening sweep the recovered
//! tenure serves while [`replace`] runs one replacement:
//!
//! 1. the reconciler's `record_standby` records a generated host's attach, bound to an instance of its own, and the
//!    control plane attaches that instance;
//! 2. `enroll_standby` enrolls the host under its attach key, and the reconciler designates it standby;
//! 3. `end_attach` ends the replaced host's attach;
//! 4. [`reclaim`] runs the owner's production reclaim step until the ended pair leaves the record. Each poll copies
//!    the shared reservation's registrants into the tenure's Report table, steps the tenure through a Report, takes
//!    the control plane's listing and then reads the volume and shard records (READ-ORDER), and calls
//!    `Owner::owner_poll` and `Owner::owner_reclaim`. The tenure's device runs each ended-key preempt the poll
//!    submits. The harness removes the key from the shared reservation when the device table no longer lists it.
//!    `host::duties::droppable` selects the pairs to drop from the pairs `owner_reclaim` returns. It keeps the pair
//!    of a host the shard read names. The harness drops the selected pairs through `Job::Drop` on an inline store
//!    lane;
//! 5. the reconciler's `detachable` gives the detach witness, the control plane detaches the instance, and
//!    `release_attach` records the entry gone on two listings taken `SETTLE_US` and twice `SETTLE_US` after the
//!    detach request.

use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};

use crate::failover::records::{Host, MAX_ATTACHED, MAX_CHAIN, ShardRecord, VolumeRecord};
use crate::failover::restart::{self, Restarted};
use crate::failover::takeover::tests::{c_host, d_host, holder_of, takeover_of};
use crate::failover::takeover::{Check, Next};
use crate::oracle::{Obligation, Preserved, Tenure, Verdict as Judged, check_clients, preserved};
use crate::sim::cut::{Class, Site};
use crate::storage::page_coverage::{Limits as PageLimits, decode_entries, merged};
use crate::storage::store::sim::{Arm, Shared};
use crate::storage::store::{Key, StoreError};
use crate::storage::store_tests::{client as store_client, shard};
use crate::storage::warm_sim::{Manifest, manifest, object_key};
use crate::storage::{IO_UNIT, MetadataOutcome, Operation, WorkBudget};

use super::super::fetch::Outcome as Fetched;
use super::super::frame::Status;
use super::super::observe::{Lenses, tables};
use super::super::owner_tests::collect;
use super::super::requests::RequestId;
use super::{
    Event, Label, MAX_KEYS, Script, Serving, Source, World, add_account, hold, interval, publish,
    restart_tests, serve, serve_taken,
};

pub(crate) mod census;
pub(crate) mod ledger;
pub(crate) mod tape;
#[cfg(test)]
mod tests;

use self::ledger::{Accounted, Conservation, Sample};
use self::tape::{Arrival, Buckets, Kind, Mix, PhaseReport, Tape};

/// One judgment of a run. `Fail` names the rule that failed and where; `Inconclusive` and `Unrun` name why the
/// run decides nothing, and neither is a pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Verdict {
    Pass,
    Fail(&'static str, String),
    Inconclusive(&'static str),
    Unrun(&'static str),
}

impl Verdict {
    pub(crate) fn passed(&self) -> bool {
        *self == Self::Pass
    }

    /// The rule a failure names.
    pub(crate) fn rule(&self) -> Option<&'static str> {
        match self {
            Self::Fail(rule, _) => Some(rule),
            _ => None,
        }
    }

    pub(crate) fn word(&self) -> String {
        match self {
            Self::Pass => "pass".into(),
            Self::Fail(rule, at) => format!("FAIL [{rule}] at {at}"),
            Self::Inconclusive(why) => format!("inconclusive [{why}]"),
            Self::Unrun(why) => format!("unrun [{why}]"),
        }
    }
}

/// The most cycles a run admits. Each cycle serves one tenure, whose boot nonces take the world's one-byte count of
/// tenures served, and the leak control's coverage entry of cycle `c` is object `100 + c`'s, so below this bound
/// every tenure's nonces differ and every leaked entry is its own key, apart from the captured and filled objects.
pub(crate) const MAX_CYCLES: u32 = 128;

/// The in-scope cases the composition leaves unscored, as the discovery output lists them.
pub(crate) const UNSCORED: [&str; 10] = [
    "successor checkpoint publication and consolidation",
    "duplicate extents",
    "both roots affected",
    "log-full and quarantine-full",
    "missing REMOVE and REPLACE dependencies, covered by the directed suffix histories",
    "a delayed old-tenure write after its successor's fence",
    "a second fresh host",
    "a GET racing a mutation, excluded by the drain before each mutation",
    "every row unit of the checkpoint damaged, which the warm load refuses as a whole slot",
    "an INVALIDATE or a flip of a FILL the cycles published",
];

/// A defect a control plants at one cycle, or in every cycle for the leak.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Plant {
    /// The recovered tenure drops every restored entry from RAM with no record, so every GET misses.
    AlwaysMiss,
    /// The recovered tenure drops one restored entry from RAM with no record.
    RestoredEntryMiss,
    /// The warm load refuses the whole slot on one damaged unit.
    TotalEviction,
    /// The host-loss recovery attaches with no warm source, the treatment of an actual volume loss.
    SwappedClass,
    /// A payload unit is flipped and its damage row names another unit.
    Attribution,
    /// At the tenure's cut, a coverage write drops an acknowledged entry of its page.
    ShrunkCoverage,
    /// One coverage entry no INVALIDATE accounts for is written before every cycle, whatever cycle the plant names.
    Leak,
    /// The tenure's capture pass is started and never finished.
    StuckCapture,
    /// The tenure holds every INVALIDATE it takes and writes no coverage page.
    NoPublish,
    /// The tenure drops one FILL it acknowledged from RAM before its closing sweep.
    DroppedFill,
    /// A row unit is flipped at rest with no damage row and no account in the harness.
    UnreportedDamage,
    /// The recovered tenure, once its drain reaches the quiescent boundary, reserves one payload unit from its extent
    /// allocator and leaves it unassigned to any slot. [`conserved`](super::super::observe::conserved) detects the
    /// leak in that boundary's sample.
    LeakedUnit,
    /// SLOT-REUSE: the ended pair is still recorded when the cycle asks `detachable` for the detach witness.
    KeptPair,
    /// SLOT-REUSE: the replaced host's instance stays attached, and the release runs on two listings that omit it.
    EarlyRelease,
    /// SLOT-REUSE: after the cycle's attach the harness writes one more generated host's attach entry, a fourth live
    /// attach.
    FourthAttach,
    /// SLOT-REUSE: The shared reservation lists the replaced host's key at the owner's first preempt. The device
    /// reports preempt success and retains the registration. The owner's planted defect treats preempt success as
    /// proof of key removal.
    ListedDrop,
    /// The production owner encounters the same preempt fault as [`Plant::ListedDrop`].
    NoEffectPreempt,
    /// SLOT-REUSE: the cycle attaches the host the previous cycle replaced in place of a generated host.
    ReturnedHost,
    /// SLOT-REUSE: the store answers the first read of the cycle's restart or takeover unavailable.
    RefusedRecovery,
    /// SLOT-REUSE: the store answers the first read of the cycle's standby designation unavailable.
    RefusedDesignation,
    /// SLOT-REUSE: a raw write to the volume record ends the live attach of the standby the cycle designated.
    EndedRole,
    /// SLOT-REUSE: a raw write adds an attach entry of the replaced host, bound to its instance, beside its ended
    /// entry.
    EarlyReturn,
    /// SLOT-REUSE: a raw write records the replaced host's ended entry gone ahead of the first settled listing that
    /// omits its instance.
    UnsettledRelease,
}

impl Plant {
    /// The plant's code in a run identity.
    pub(crate) fn code(self) -> u8 {
        match self {
            Self::AlwaysMiss => 1,
            Self::RestoredEntryMiss => 2,
            Self::TotalEviction => 3,
            Self::SwappedClass => 4,
            Self::Attribution => 5,
            Self::ShrunkCoverage => 6,
            Self::Leak => 7,
            Self::StuckCapture => 8,
            Self::NoPublish => 9,
            Self::DroppedFill => 10,
            Self::UnreportedDamage => 11,
            Self::LeakedUnit => 12,
            Self::KeptPair => 13,
            Self::EarlyRelease => 14,
            Self::FourthAttach => 15,
            Self::ListedDrop => 16,
            Self::ReturnedHost => 17,
            Self::NoEffectPreempt => 18,
            Self::RefusedRecovery => 19,
            Self::RefusedDesignation => 20,
            Self::EndedRole => 21,
            Self::EarlyReturn => 22,
            Self::UnsettledRelease => 23,
        }
    }
}

/// A run's inputs. The identity of a run is the digest of these fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Config {
    pub(crate) seed: u64,
    pub(crate) cycles: u32,
    /// The objects the capturing tenure published and captured, at least one and below the run's fill numbers.
    pub(crate) objects: u8,
    /// The object numbers, inclusive, the run's FILLs take in order, each once over the whole run. Only an
    /// acknowledged FILL takes the next number; a FILL offered after the last is refused at the harness's admission
    /// and is held to no progress rule.
    pub(crate) fills: (u8, u8),
    /// The arrivals of a serve phase and the most ticks between two of them.
    pub(crate) arrivals: u32,
    pub(crate) gap: u64,
    pub(crate) mix: Mix,
    /// The units the tape may flip at rest and leave damaged.
    pub(crate) damage: u32,
    /// The ticks a drain may take to reach its boundary.
    pub(crate) drain_ticks: u32,
    /// The unaccounted coverage entries the run tolerates.
    pub(crate) epsilon: u64,
    /// The accepted band of resident bytes across boundaries, when its owner declared one.
    pub(crate) band: Option<u64>,
    pub(crate) plant: Option<(Plant, u32)>,
    /// When `reuse` is set, each cycle replaces either the standby or the owner ([`replace`]).
    pub(crate) reuse: bool,
}

impl Config {
    /// The discovery configuration of `seed` over `cycles` cycles: 44 captured objects on two row units, six fill
    /// numbers, 16 arrivals a phase, two units of permanent damage and a tolerance of four coverage entries.
    pub(crate) fn discovery(seed: u64, cycles: u32) -> Self {
        Self {
            seed,
            cycles,
            objects: 44,
            fills: (45, 50),
            arrivals: 16,
            gap: 3,
            mix: Mix {
                fill: 10,
                invalidate: 6,
            },
            damage: 2,
            drain_ticks: 2_000,
            epsilon: 4,
            band: None,
            plant: None,
            reuse: false,
        }
    }

    /// The slot-reuse configuration of `seed` over `cycles` cycles: the discovery configuration with a replacement in
    /// every cycle.
    pub(crate) fn slot_reuse(seed: u64, cycles: u32) -> Self {
        Self {
            reuse: true,
            ..Self::discovery(seed, cycles)
        }
    }

    /// The run identity: the first eight bytes, in hex, of the SHA-256 of a version tag and every field at a fixed
    /// width in a fixed order, an absent band or plant as a zero byte and a present one as a one byte before its
    /// value. The tag names the encoding and the run's seed-to-event policy: it changes with a field, the draw order
    /// or a draw range, a round or tick bound, or the leak slope. `reuse` follows the plant as the bytes `slot-reuse`
    /// when it is set and as zero bytes when it is unset, under the same tag, so a run with `reuse` unset has the
    /// identity of its other fields alone.
    pub(crate) fn identity(&self) -> String {
        let Self {
            seed,
            cycles,
            objects,
            fills,
            arrivals,
            gap,
            mix: Mix { fill, invalidate },
            damage,
            drain_ticks,
            epsilon,
            band,
            plant,
            reuse,
        } = *self;
        let mut bytes = b"warm-cycles-v3".to_vec();
        bytes.extend(seed.to_le_bytes());
        bytes.extend(cycles.to_le_bytes());
        bytes.extend([objects, fills.0, fills.1]);
        bytes.extend(arrivals.to_le_bytes());
        bytes.extend(gap.to_le_bytes());
        bytes.extend(fill.to_le_bytes());
        bytes.extend(invalidate.to_le_bytes());
        bytes.extend(damage.to_le_bytes());
        bytes.extend(drain_ticks.to_le_bytes());
        bytes.extend(epsilon.to_le_bytes());
        match band {
            None => bytes.push(0),
            Some(band) => {
                bytes.push(1);
                bytes.extend(band.to_le_bytes());
            }
        }
        match plant {
            None => bytes.push(0),
            Some((plant, at)) => {
                bytes.extend([1, plant.code()]);
                bytes.extend(at.to_le_bytes());
            }
        }
        if reuse {
            bytes.extend(b"slot-reuse");
        }
        hex(&Sha256::digest(&bytes)[..8])
    }
}

/// `bytes` in lowercase hex.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// How a cycle's tenure was recovered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Recovery {
    /// The owner's same-host restart after a process crash.
    Restart,
    /// The named standby's takeover after owner loss.
    Takeover,
    /// A takeover by a host designated after the owner and its standby were lost.
    Designated,
    /// A takeover that stopped after its compare-and-swap and before its preempt, recovered by a third host.
    Interrupted,
    /// A takeover whose compare-and-swap committed with an unknown reply, recovered by the successor's own restart
    /// through its lineage arm, which preempts the predecessor's recorded holder.
    Unknown,
    /// A successor lost after its preempt and before it attached, recovered by its own restart.
    AfterPreempt,
    /// A takeover under a replaced designation, refused before any write, then the designated host's takeover.
    Stale,
}

impl Recovery {
    pub(crate) const ALL: [Self; 7] = [
        Self::Restart,
        Self::Takeover,
        Self::Designated,
        Self::Interrupted,
        Self::Unknown,
        Self::AfterPreempt,
        Self::Stale,
    ];

    /// The recovery's label in the composition line.
    fn name(self) -> &'static str {
        match self {
            Self::Restart => "restarts",
            Self::Takeover => "takeovers",
            Self::Designated => "designated",
            Self::Interrupted => "interrupted",
            Self::Unknown => "unknown",
            Self::AfterPreempt => "after-preempt",
            Self::Stale => "stale",
        }
    }
}

/// One cycle's record: its recovery and failure class, the recovered tenure, the published cut it served from,
/// the retained set's account in its opening sweep, its phases and its boundary sample.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Cycle {
    pub(crate) recovery: Recovery,
    pub(crate) class: Class,
    pub(crate) tenure: Tenure,
    /// The named checkpoint's session and capture and the record's cut.
    pub(crate) cut: (u64, u32, u64),
    /// The entries the harness expects served, and those of them the opening sweep served.
    pub(crate) eligible: u32,
    pub(crate) served: u32,
    /// The units the recovery's own loss report counts failed.
    pub(crate) failed_units: u32,
    /// Whether the tenure recorded its suffix and opened its log; false once the chain is at its cap.
    pub(crate) suffix: bool,
    pub(crate) fills: u32,
    pub(crate) invalidations: u32,
    /// The serve phase, the cut and the interval with no tenure serving.
    pub(crate) phases: [PhaseReport; 3],
    pub(crate) sample: Option<Sample>,
    /// Whether the owner held a GET of the cut when the tenure dropped.
    pub(crate) response: bool,
}

/// What a run composed, counted over its cycles.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Composed {
    /// The recoveries of each kind, indexed by [`Recovery`].
    pub(crate) recoveries: [u32; 7],
    /// `fresh_hosts` counts recoveries that [`Run::recover`] classifies as `ReplacementAttach`.
    pub(crate) fresh_hosts: u32,
    /// Takeovers by an attached host the record does not name, each refused before any write.
    pub(crate) unauthorized: u32,
    pub(crate) damaged: u32,
    pub(crate) repaired: u32,
    pub(crate) landings: u32,
    pub(crate) chain_full: u32,
    pub(crate) fills: u32,
    pub(crate) invalidations: u32,
    pub(crate) captures: u32,
    /// SLOT-REUSE: the hosts replaced, the ended pairs the owner dropped from the record, the ended-key preempts the
    /// owner submitted, and the most live attaches a record held.
    pub(crate) replacements: u32,
    pub(crate) drops: u32,
    pub(crate) preempts: u32,
    pub(crate) live: u32,
}

/// A run's report, keyed by its identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Report {
    pub(crate) identity: String,
    pub(crate) config: Config,
    pub(crate) cycles: Vec<Cycle>,
    pub(crate) safety: Verdict,
    pub(crate) containment: Verdict,
    pub(crate) retention: Verdict,
    pub(crate) progress: Verdict,
    pub(crate) conservation: Conservation,
    pub(crate) composed: Composed,
    /// The failure classes and sites the run's cuts reached ([`reach`]).
    pub(crate) reached: BTreeSet<(Class, Site)>,
    /// Whether the run's plant changed the state it targets.
    pub(crate) planted: bool,
    /// The first rule the oracle failed under an obligation other than `Restart`, and the first `Restart` rule that
    /// states a loss of the cut's own entries or, when none failed, the first rule of [`UNCAPTURED`].
    pub(crate) oracle: [Option<&'static str>; 2],
    /// What the write guard saw over the run's tenures.
    pub(crate) guarded: crate::storage::write_guard::Guarded,
}

impl Report {
    /// Whether the four verdicts and the quiescent conservation judgment pass, and the plateau when the run declares a
    /// band. The publish-aligned judgment is reported and scores nothing.
    pub(crate) fn passed(&self) -> bool {
        let plateau = self
            .config
            .band
            .is_some()
            .then_some(&self.conservation.plateau);
        let verdicts = [
            &self.safety,
            &self.containment,
            &self.retention,
            &self.progress,
            &self.conservation.exact,
        ];
        verdicts.into_iter().chain(plateau).all(Verdict::passed)
    }

    /// Long-run discovery requires both [`passed`](Self::passed) and [`guard_held`](Self::guard_held) to return true.
    /// The published fill count sets the run-wide lower bound on checked writes.
    pub(crate) fn guard_held(&self) -> bool {
        self.guarded.clean() && self.guarded.checked >= u64::from(self.composed.fills)
    }

    /// The buckets of every phase, summed.
    pub(crate) fn buckets(&self) -> Buckets {
        let mut sum = Buckets::default();
        for phase in self.cycles.iter().flat_map(|cycle| cycle.phases.iter()) {
            let buckets = &phase.buckets;
            sum.offered += buckets.offered;
            sum.retained += buckets.retained;
            sum.fresh += buckets.fresh;
            sum.miss += buckets.miss;
            sum.applied += buckets.applied;
            sum.refused += buckets.refused;
            sum.timed_out += buckets.timed_out;
            sum.errored += buckets.errored;
            sum.interrupted += buckets.interrupted;
        }
        sum
    }

    /// The report's summary line, which names the seed and the cycle count, then each verdict.
    pub(crate) fn summary(&self) -> String {
        let Config { seed, cycles, .. } = self.config;
        format!(
            "cycles: seed {seed} cycles {cycles}: safety {}; containment {}; retention {}; progress {}; \
             quiescent conservation {}; publish-aligned conservation {}; plateau {}; identity {}",
            self.safety.word(),
            self.containment.word(),
            self.retention.word(),
            self.progress.word(),
            self.conservation.exact.word(),
            self.conservation.aligned.word(),
            self.conservation.plateau.word(),
            self.identity,
        )
    }

    /// The report's lines: the summary, the raw configuration, the counts and one line a cycle. Every quantity is
    /// a count, a byte total or a tick total of the simulation.
    pub(crate) fn lines(&self) -> Vec<String> {
        let buckets = self.buckets();
        let mut lines = vec![
            self.summary(),
            format!("cycles: {} configuration {:?}", self.identity, self.config),
            format!("cycles: {} composed {:?}", self.identity, self.composed),
            format!(
                "cycles: {} buckets {buckets:?} dropped {}",
                self.identity,
                buckets.dropped()
            ),
        ];
        for (at, cycle) in self.cycles.iter().enumerate() {
            let Cycle { tenure, cut, .. } = cycle;
            lines.push(format!(
                "cycles: {} cycle {at} {:?} {:?} tenure {}/{} cut {}/{}/{} served {}/{} failed-units {} suffix {} \
                 fills {} invalidations {} response {} phases {:?} sample {:?}",
                self.identity,
                cycle.recovery,
                cycle.class,
                tenure.g,
                tenure.a,
                cut.0,
                cut.1,
                cut.2,
                cycle.served,
                cycle.eligible,
                cycle.failed_units,
                cycle.suffix,
                cycle.fills,
                cycle.invalidations,
                cycle.response,
                cycle.phases,
                cycle.sample,
            ));
        }
        lines
    }

    /// The SHA-256 of the report's lines, in hex, which the discovery output prints beside each run's lines.
    pub(crate) fn digest(&self) -> String {
        hex(&Sha256::digest(self.lines().join("\n").as_bytes()))
    }
}

/// The reports of a set of runs by identity. A report of an identity the set holds is refused, so a second run
/// never replaces the first.
#[derive(Default)]
pub(crate) struct Outputs(BTreeMap<String, Report>);

impl Outputs {
    /// Keeps `report` under its identity.
    ///
    /// # Errors
    ///
    /// The identity, when the set already holds a report of it; the set is unchanged.
    pub(crate) fn keep(&mut self, report: Report) -> Result<(), String> {
        if self.0.contains_key(&report.identity) {
            return Err(report.identity);
        }
        self.0.insert(report.identity.clone(), report);
        Ok(())
    }

    pub(crate) fn reports(&self) -> Vec<&Report> {
        self.0.values().collect()
    }
}

/// The first owner's host.
fn a_host() -> Host {
    restart_tests::host()
}

fn record_now(world: &World) -> ShardRecord {
    restart_tests::shard_now(&world.records)
}

fn commits(world: &World) -> usize {
    world.records.0.borrow().commit_count(&Key::Shard(shard()))
}

/// `host`'s same-host restart over the record as it stands. A restart that returns `Restarted` emits its tenure's
/// `Fenced` step and starts the next loss window; a refusal emits nothing.
fn restart_of(world: &World, host: Host) -> Result<Restarted, restart::Refused> {
    let (mut card, local) = world.host(host);
    let restarted = restart_tests::restart_of(shard(), holder_of(host)).run(
        &mut store_client(&world.records),
        &local,
        &mut card,
    );
    if let Ok(restarted) = &restarted {
        world.fence(restarted);
    }
    restarted
}

/// The reconciler designates `host`, attached and enrolled, as the shard's standby: its census slot, then the
/// designation.
fn designate(world: &World, host: Host) {
    if let Err(refusal) = designated_as(world, host) {
        panic!("the designation of an attached host: {refusal}");
    }
}

/// `Err` identifies the failed `reserve` or `designate` call, or reports `record.standby` when it differs from
/// `Some(host)`.
fn designated_as(world: &World, host: Host) -> Result<(), String> {
    use crate::failover::reconcile::{Reconciler, StandbyGate};
    use crate::failover::standbys::{Population, Zone, tests::roomy};
    let gate = StandbyGate::qualified();
    let bounds = crate::storage::gate_fixture::bounds_of(crate::storage::gate_fixture::limits());
    let mut reconciler = Reconciler::new(store_client(&world.records));
    let slot = reconciler
        .reserve(
            &gate,
            &Population { cap: 1 },
            &bounds,
            Zone(1),
            shard(),
            &roomy(host),
            |_| None,
            |other| other != host,
        )
        .map_err(|refusal| format!("reserve: {refusal:?}"))?;
    reconciler
        .designate(&gate, &slot, restart_tests::volume_id())
        .map_err(|refusal| format!("designate: {refusal:?}"))?;
    match record_now(world).standby {
        Some(standby) if standby == host => Ok(()),
        standby => Err(format!("the record names standby {standby:?}")),
    }
}

/// The coverage entries the store's pages hold, and the encoded bytes of its largest page.
fn coverage_of(records: &Shared) -> (u64, u64) {
    let record = restart_tests::shard_now(records);
    let mut client = store_client(records);
    let (mut entries, mut bytes) = (0, 0);
    for page in 0..record.pages.get() {
        let read = client
            .read::<crate::failover::records::CoveragePage>(Key::Page(shard(), page))
            .expect("a coverage page");
        let decoded = decode_entries(&read.value().entries).expect("a decodable page");
        entries += decoded.len() as u64;
        bytes = bytes.max(read.value().encoded_len() as u64);
    }
    (entries, bytes)
}

/// Writes the coverage entry of `key` on its page, keeping the page's fence.
fn cover(records: &Shared, key: [u8; 32]) {
    let record = restart_tests::shard_now(records);
    let limits = PageLimits {
        intervals: 4,
        page_bytes: record.page_cap.get() as usize,
    };
    let page = crate::storage::page_coverage::page_of(&key, record.pages);
    let mut client = store_client(records);
    let read = client
        .read::<crate::failover::records::CoveragePage>(Key::Page(shard(), page))
        .expect("a coverage page");
    let covered = merged(read.value(), (key, interval()), limits).expect("room on the page");
    client.replace(&read, covered).expect("the page write");
}

/// The first failure of one verdict.
type Failure = Option<(&'static str, String)>;

fn fail(slot: &mut Failure, rule: &'static str, at: String) {
    slot.get_or_insert((rule, at));
}

/// The harness's account of the run. The retained and covered sets, the injected damage, the slot rows and the fill
/// cursor come from the steps the harness applied. The resident-slot account starts from the slots the storage holds
/// after each load and moves by the fills the harness published and the removals the owner reported, so the
/// boundary check of resident slots checks each tenure's change and the retention sweep checks the restored set.
/// The suffix count is the tenures whose `open_suffix` recorded a suffix and opened the log.
struct Run<'c> {
    config: &'c Config,
    tape: Tape,
    /// The captured objects no acknowledged INVALIDATE covers.
    uncovered: BTreeSet<u8>,
    /// The captured objects an acknowledged INVALIDATE covers.
    covered: BTreeSet<u8>,
    /// The device units flipped and not repaired.
    damaged: BTreeSet<u32>,
    /// The device units that hold the checkpoint's slot rows.
    rows: BTreeSet<u32>,
    /// The damage rows a correct run records: every unit the run flipped, in order.
    injected: Vec<u32>,
    next_fill: u8,
    /// The suffixes recovered tenures recorded with their logs opened.
    suffixes: u64,
    /// The host whose first recovery of the shard is still to come: D once designated, or in a slot-reuse run the
    /// generated standby once enrolled.
    first_attach: Option<Host>,
    generated: u64,
    /// The hosts a slot-reuse run replaced.
    replaced: Vec<Host>,
    /// The instances the control plane lists attached to the volume.
    attached: Vec<String>,
    start: Manifest,
    cycles: Vec<Cycle>,
    composed: Composed,
    planted: bool,
    safety: Failure,
    containment: Failure,
    retention: Failure,
    progress: Failure,
}

/// A GET in flight: its request, object, the labels it may return, its arrival tick and the client's count of
/// refused frames when it was sent.
struct Flight {
    id: RequestId,
    n: u8,
    labels: Vec<Label>,
    arrived: u64,
    unrouted: u32,
    bytes: Vec<u8>,
}

/// What a tenure's serve phase did: its acknowledged FILLs and INVALIDATEs and the resident entries it removed.
#[derive(Default)]
struct Served {
    fills: u32,
    invalidations: u32,
    removed: u64,
}

impl<'c> Run<'c> {
    /// The account of a run of `config` over `world` before its first cycle.
    fn new(config: &'c Config, world: &World) -> Self {
        Self {
            config,
            tape: Tape::new(config.seed),
            uncovered: (1..=config.objects).collect(),
            covered: BTreeSet::new(),
            damaged: BTreeSet::new(),
            rows: (1..=config.objects).map(|n| world.units(n).0).collect(),
            injected: Vec::new(),
            next_fill: config.fills.0,
            suffixes: 0,
            first_attach: None,
            generated: 0,
            replaced: Vec::new(),
            attached: (volume_now(world).live_hosts())
                .map(|host| {
                    crate::failover::takeover::tests::instance_of(host)
                        .as_str()
                        .to_owned()
                })
                .collect(),
            start: manifest(&world.records),
            cycles: Vec::new(),
            composed: Composed::default(),
            planted: false,
            safety: None,
            containment: None,
            retention: None,
            progress: None,
        }
    }
}

impl Run<'_> {
    fn planted(&self, plant: Plant) -> bool {
        let cycle = self.cycles.len() as u32;
        (self.config.plant).is_some_and(|(planted, at)| planted == plant && at == cycle)
    }

    /// Control-plane attach requests are idempotent for each `instance`.
    fn attach(&mut self, instance: &str) {
        if !self.attached.iter().any(|attached| attached == instance) {
            self.attached.push(instance.to_owned());
        }
    }

    /// The captured objects the harness expects a recovered tenure to serve: uncovered, on no damaged unit.
    fn eligible(&self, world: &World) -> BTreeSet<u8> {
        let intact = |n: &&u8| {
            let (row, payload) = world.units(**n);
            !self.damaged.contains(&row) && !self.damaged.contains(&payload)
        };
        self.uncovered.iter().filter(intact).copied().collect()
    }

    /// Checks that a step which must change nothing left the manifest, the media's metadata prefix and the
    /// record's commit count as `before` holds them.
    fn unchanged(&mut self, world: &World, before: &(Manifest, Vec<u8>, usize), step: &str) {
        let after = (world.evidence().0, world.evidence().1, commits(world));
        if after != *before {
            let rule = "a refused recovery step changed the record or the media";
            fail(
                &mut self.containment,
                rule,
                format!("cycle {}: {step}", self.cycles.len()),
            );
        }
    }

    /// The host the reconciler designates beside `excluded`: D when no fresh host has joined, which it attaches,
    /// enrolls and designates and whose first attach is then still to come, and otherwise the attached host outside
    /// `excluded`.
    fn designated(&mut self, world: &mut World, excluded: &[Host]) -> Host {
        if world.fresh.is_none() {
            world.designate_fresh();
            self.first_attach = Some(d_host());
            return d_host();
        }
        let hosts = [a_host(), c_host(), d_host()];
        let host = hosts.into_iter().find(|host| !excluded.contains(host));
        let host = host.expect("three attached hosts");
        designate(world, host);
        host
    }

    /// The standby the record names, designated first when it names none.
    fn standby(&mut self, world: &mut World) -> Host {
        let record = record_now(world);
        match record.standby {
            Some(standby) => standby,
            None => self.designated(world, &[record.owner]),
        }
    }

    /// The attached host the record names neither owner nor standby takes over: its takeover must refuse `Stale`
    /// with no write and no device command.
    fn unauthorized(&mut self, world: &World) {
        let record = record_now(world);
        if world.fresh.is_none() {
            return;
        }
        let named = [record.owner, record.standby.unwrap_or(record.owner)];
        let hosts = [a_host(), c_host(), d_host()];
        let Some(host) = hosts.into_iter().find(|host| !named.contains(host)) else {
            return;
        };
        let before = (world.evidence().0, world.evidence().1, commits(world));
        let (taken, commands) = world.takeover(host);
        let refused = taken.is_err_and(|refused| refused.check == Check::Stale);
        if !refused || !commands.is_empty() {
            let rule = "an attached host the record does not name was admitted to a takeover";
            fail(
                &mut self.containment,
                rule,
                format!("cycle {}", self.cycles.len()),
            );
        }
        self.unchanged(world, &before, "an unnamed host's takeover");
        self.composed.unauthorized += 1;
    }

    /// Recovers the shard as `recovery` says and returns the capability and the failure class: `ProcessDeath` for
    /// the owner's same-host restart, `ReplacementAttach` for the first recovery by D or by a slot-reuse run's
    /// generated standby, and `HostOrDevice` otherwise.
    fn recover(
        &mut self,
        world: &mut World,
        recovery: Recovery,
    ) -> Result<(Restarted, Class), String> {
        let (restarted, host) = self.recovered(world, recovery)?;
        let class = match host {
            None => Class::ProcessDeath,
            Some(host) if self.first_attach == Some(host) => {
                self.first_attach = None;
                self.composed.fresh_hosts += 1;
                Class::ReplacementAttach
            }
            Some(_) => Class::HostOrDevice,
        };
        Ok((restarted, class))
    }

    /// In slot-reuse runs, `refusable` returns a refused owner restart or standby takeover as an `Err` that names
    /// the step; other runs panic on it.
    fn refusable<E: std::fmt::Debug>(
        &self,
        taken: Result<Restarted, E>,
        step: &str,
    ) -> Result<Restarted, String> {
        match taken {
            Ok(taken) => Ok(taken),
            Err(refusal) if self.config.reuse => Err(format!("{step}: {refusal:?}")),
            Err(refusal) => panic!("{step}: {refusal:?}"),
        }
    }

    /// Under the refused-recovery plant the store answers the recovery's first read unavailable, after the `passed`
    /// reads the harness makes to form the recovery.
    fn outage(&mut self, world: &World, passed: usize) {
        if self.planted(Plant::RefusedRecovery) {
            for _ in 0..passed {
                world.records.schedule(Arm::Pass);
            }
            world.records.schedule(Arm::Unavailable);
            self.planted = true;
        }
    }

    /// Runs `recovery`'s steps. Returns the capability and the host that recovered the shard, `None` for the
    /// owner's same-host restart.
    fn recovered(
        &mut self,
        world: &mut World,
        recovery: Recovery,
    ) -> Result<(Restarted, Option<Host>), String> {
        let owner = record_now(world).owner;
        let third = |run: &mut Self, world: &mut World, successor: Host| {
            let host = run.designated(world, &[owner, successor]);
            let (taken, _) = world.takeover(host);
            Ok((taken.expect("the designated host's takeover"), Some(host)))
        };
        match recovery {
            Recovery::Restart => {
                self.outage(world, 0);
                let restarted = self.refusable(restart_of(world, owner), "the owner's restart")?;
                Ok((restarted, None))
            }
            Recovery::Takeover => {
                let standby = self.standby(world);
                self.unauthorized(world);
                self.outage(world, 1);
                let (taken, _) = world.takeover(standby);
                let taken = self.refusable(taken, "the standby's takeover")?;
                Ok((taken, Some(standby)))
            }
            Recovery::Designated => {
                let standby = self.standby(world);
                third(self, world, standby)
            }
            Recovery::Interrupted => {
                let standby = self.standby(world);
                let before = world.evidence();
                let (mut card, local) = world.host(standby);
                card.stop_at = Some(3);
                let path = takeover_of(&world.records, standby);
                let taken = path.run(&mut store_client(&world.records), &local, &mut card);
                let stopped = taken.is_err_and(|r| matches!(r.check, Check::FirstReport(_)));
                assert!(stopped, "the takeover stops at its first Report");
                let record = record_now(world);
                assert_eq!((record.owner, record.standby), (standby, None));
                if world.evidence() != before {
                    let rule = "an interrupted takeover changed the manifest or the media";
                    fail(
                        &mut self.containment,
                        rule,
                        format!("cycle {}", self.cycles.len()),
                    );
                }
                third(self, world, standby)
            }
            Recovery::Unknown => {
                let standby = self.standby(world);
                let before = world.evidence();
                let (mut card, local) = world.host(standby);
                let path = takeover_of(&world.records, standby);
                for arm in [Arm::Pass, Arm::Pass, Arm::Timeout { commit: true }] {
                    world.records.schedule(arm);
                }
                let refused = path
                    .run(&mut store_client(&world.records), &local, &mut card)
                    .expect_err("an unknown compare-and-swap refuses");
                assert_eq!(refused.check, Check::TakeOver(StoreError::Unknown));
                assert!(card.log.is_empty(), "an unknown outcome issues no command");
                let Next::Restart(restart) = path.next(&refused) else {
                    panic!("an unknown outcome continues by the restart alone");
                };
                assert_eq!(restart.holder, holder_of(standby));
                let restarted = restart_of(world, standby);
                let lineage = restarted.as_ref().is_ok_and(Restarted::lineage);
                if !lineage || world.evidence() != before {
                    let rule = "an unknown takeover write's successor did not recover through its lineage arm";
                    fail(
                        &mut self.containment,
                        rule,
                        format!("cycle {}", self.cycles.len()),
                    );
                }
                let restarted = self.refusable(restarted, "the successor's restart")?;
                Ok((restarted, Some(standby)))
            }
            Recovery::AfterPreempt => {
                let standby = self.standby(world);
                let (taken, _) = world.takeover(standby);
                drop(taken.expect("the standby's takeover"));
                let restarted = restart_of(world, standby).expect("the successor's restart");
                Ok((restarted, Some(standby)))
            }
            Recovery::Stale => {
                let standby = self.standby(world);
                let (mut card, local) = world.host(standby);
                let stale = takeover_of(&world.records, standby);
                let host = self.designated(world, &[owner, standby]);
                let before = (world.evidence().0, world.evidence().1, commits(world));
                let refused = stale.run(&mut store_client(&world.records), &local, &mut card);
                let stale = refused.is_err_and(|refused| refused.check == Check::Stale);
                if !stale || !card.log.is_empty() {
                    let rule = "a takeover under a replaced designation was admitted";
                    fail(
                        &mut self.containment,
                        rule,
                        format!("cycle {}", self.cycles.len()),
                    );
                }
                self.unchanged(world, &before, "a stale designation's takeover");
                let (taken, _) = world.takeover(host);
                Ok((taken.expect("the designated host's takeover"), Some(host)))
            }
        }
    }

    /// A slot-reuse cycle's recovery: the owner's restart, which replaces the standby, or the standby's takeover,
    /// which replaces the owner. `replacement` returns the replaced host for `tenure`.
    fn replacement(&mut self, world: &World) -> (Recovery, Option<Host>) {
        let record = record_now(world);
        match (self.tape.below(2), record.standby) {
            (0, _) | (_, None) => (Recovery::Restart, record.standby),
            (_, Some(_)) => (Recovery::Takeover, Some(record.owner)),
        }
    }

    /// The recovery the tape draws for a cycle.
    fn drawn(&mut self) -> Recovery {
        match self.tape.below(100) {
            0..30 => Recovery::Restart,
            30..55 => Recovery::Takeover,
            55..67 => Recovery::Designated,
            67..79 => Recovery::Interrupted,
            79..86 => Recovery::Unknown,
            86..93 => Recovery::AfterPreempt,
            _ => Recovery::Stale,
        }
    }

    /// What the tape does to the media at rest: flips a unit of an eligible object, lands the capturing tenure's
    /// own writes of a unit again, or flips a unit and lands its writes again. A permanent flip leaves one row unit
    /// of the checkpoint intact, since a warm load with every row unit damaged refuses the whole slot.
    fn at_rest(&mut self, world: &mut World) {
        let cycle = self.cycles.len() as u32;
        if self
            .config
            .plant
            .is_some_and(|(plant, _)| plant == Plant::Leak)
        {
            cover(&world.records, object_key(100 + cycle as u8));
            self.planted = true;
        }
        let captured = |n: &u8| *n <= self.config.objects;
        let eligible: Vec<u8> = self.eligible(world).into_iter().filter(captured).collect();
        if eligible.is_empty() {
            return;
        }
        let object = eligible[self.tape.below(eligible.len() as u64) as usize];
        let (row, payload) = world.units(object);
        let unit = if self.tape.below(4) == 0 {
            row
        } else {
            payload
        };
        // The action draw precedes the plants, so a planted cycle consumes the draws of its unplanted sibling.
        let action = self.tape.below(100);
        if self.planted(Plant::Attribution) {
            world.flip(payload);
            world.events.push(Event::Damaged { unit: 0 });
            self.injected.push(payload);
            self.damaged.insert(payload);
            self.planted = true;
            return;
        }
        if self.planted(Plant::UnreportedDamage) {
            world.flip(row);
            self.planted = true;
            return;
        }
        if self.planted(Plant::TotalEviction) {
            world.corrupt(row);
            self.injected.push(row);
            self.damaged.insert(row);
            return;
        }
        // Permanent damage leaves one row unit of the checkpoint intact.
        let last_row = self.rows.contains(&unit)
            && (self.rows.iter()).all(|row| *row == unit || self.damaged.contains(row));
        match action {
            0..8 if self.composed.damaged < self.config.damage && !last_row => {
                world.corrupt(unit);
                self.injected.push(unit);
                self.damaged.insert(unit);
                self.composed.damaged += 1;
            }
            8..20 => {
                world.corrupt(unit);
                self.injected.push(unit);
                assert!(
                    world.land_again(unit) > 0,
                    "the capturing tenure wrote the unit"
                );
                self.composed.repaired += 1;
            }
            20..45 => {
                assert!(
                    world.land_again(unit) > 0,
                    "the capturing tenure wrote the unit"
                );
                self.composed.landings += 1;
            }
            _ => {}
        }
    }
}

fn volume_now(world: &World) -> VolumeRecord {
    crate::failover::takeover::tests::volume_now(&world.records)
}

/// A release requires at least `SETTLE_US` microseconds on the control plane's clock from the detach request to the
/// first listing and from the first listing to the second: 300 s.
const SETTLE_US: u64 = 300_000_000;

/// The EXHID of a run's first generated host. A generated host's EXHID is this value plus its ordinal, above the
/// fixture EXHIDs A 0x09, B 0x5b, C 0x5c and D 0x5d. The assertion below keeps every EXHID of a run of
/// [`MAX_CYCLES`] cycles, the fourth-attach plant's extra host included, below 0x100.
const GENERATED_EXHID: u64 = 0x60;

const _: () = assert!(GENERATED_EXHID + MAX_CYCLES as u64 + 1 < 0x100);

/// `ended_stays` reserves this instance for its ended-entry probe.
const PROBE_INSTANCE: &str = "i-0eeeeeeeeeeeeeee0";

type Reconciling =
    crate::failover::reconcile::Reconciler<Shared, crate::storage::store::sim::MemLog>;

/// SLOT-REUSE: one replacement of `replaced` while the owner serves, steps 1 to 5 of the module documentation, under
/// one reconciler. `replaced` joins the run's replaced hosts once its attach ends, and the replacement counts once a
/// reread of the volume record shows its ended entry gone. A step that refuses fails progress and ends the
/// replacement. Under the kept-pair plant the ended pair stays recorded through the cycle, so `detachable` refuses
/// the detach witness.
fn replace(run: &mut Run<'_>, world: &mut World, serving: &mut Serving<'_>, replaced: Host) {
    let at = format!("cycle {}", run.cycles.len());
    let mut reconciler = Reconciling::new(store_client(&world.records));
    let Some((host, exhid)) = attached(run, world, &mut reconciler, &at) else {
        return;
    };
    if !enrolled(run, world, (host, exhid), &at) {
        return;
    }
    if !roles_kept(run, world, &mut reconciler, host, &at) {
        return;
    }
    match end_latest(&mut reconciler, world, replaced) {
        Ok(ended) if !ended.named() => {}
        ended => {
            let at = format!("{at}: {ended:?}");
            fail(
                &mut run.progress,
                "the replaced host's attach did not end",
                at,
            );
            return;
        }
    }
    if run.replaced.contains(&replaced) {
        fail(&mut run.containment, "a replaced host returned", at.clone());
    }
    run.replaced.push(replaced);
    let seq = (volume_now(world).latest(replaced)).map(|(seq, _)| seq);
    let seq = seq.expect("the ended entry is retained");
    if !ended_stays(run, world, &mut reconciler, (replaced, seq), &at) {
        return;
    }
    let kept = run.planted(Plant::KeptPair);
    run.planted |= kept;
    if !kept && !reclaim(run, world, serving, replaced, &at) {
        return;
    }
    if released(run, world, &mut reconciler, (replaced, seq), &at) {
        run.composed.replacements += 1;
    }
}

/// SLOT-REUSE: the run starts from a volume record that enrolls A and C each under the key of its own attach entry,
/// with the entry bound to its host's instance, as the reconciler's `record_standby` and `enroll_standby` leave a
/// generated host. The shared reservation lists those two pairs, and the world gives each host the local record of
/// its pair. `end_attach` ends a replaced host's live attach only when it binds an instance and its pair stands under
/// the entry's own key or a spent key. The takeover fixture's record gives neither: its entries bind no instance,
/// A's pair holds entry 1's key and C's an epoch-4 key.
fn enroll_by_attach_key(world: &mut World) {
    use crate::failover::records::attachment_key;
    use crate::failover::takeover::tests::{instance_of, successor_record};
    let held = volume_now(world);
    let keyed = |host: Host| {
        let seq = held.live(host).expect("a fixture host's live attach");
        attachment_key(seq).expect("the entry's key")
    };
    let c_exhid = (held.enrolled(c_host())).map(|pair| pair.exhid.bytes()[0]);
    let c_exhid = c_exhid.expect("C's enrolled pair");
    let records = [
        (a_host(), crate::failover::fresh::tests::local_record()),
        (
            c_host(),
            successor_record(c_host(), keyed(c_host()).encode(), c_exhid),
        ),
    ];
    for (host, record) in records {
        let prior = held.enrolled(host).expect("a fixture host's enrolled pair");
        let pair = record.pair();
        assert_eq!((pair.exhid, pair.key), (prior.exhid, keyed(host)));
        rewrite_volume(world, |volume| {
            let seq = volume.live(host).expect("the host's live attach");
            let entry = volume.events.iter_mut().find(|entry| entry.seq == seq);
            entry.expect("the live entry").instance = Some(instance_of(host));
            let recorded = (volume.pairs.iter_mut()).find(|recorded| recorded.host == host);
            recorded.expect("the host's recorded pair").pair = pair;
        });
        for entry in &mut world.reservation.borrow_mut().entries {
            if entry.pair == prior {
                entry.pair = pair;
            }
        }
        world.generated.push((host, record));
    }
}

fn generated_host(ordinal: u64) -> Host {
    use crate::failover::takeover::tests::GENERATED;
    Host::new(a_host().get() + GENERATED + ordinal).expect("a generated host")
}

/// `rewrite_volume` models an external writer committing `edit` at the volume record's observed version.
fn rewrite_volume(world: &World, edit: impl FnOnce(&mut VolumeRecord)) {
    use crate::failover::records::Record;
    use crate::storage::store::{Outcome, Store, Write};
    let key = Key::Volume(restart_tests::volume_id());
    let item = world.records.0.borrow().current(&key).cloned();
    let item = item.expect("the volume record");
    let mut record = VolumeRecord::decode(&item.value).expect("a volume record");
    edit(&mut record);
    let write = Write::Exact {
        expect: item.version,
        value: record.encode(),
    };
    let written = world.records.clone().write(&key, &write);
    assert!(matches!(written, Outcome::Committed(_)), "{written:?}");
}

fn end_latest(
    reconciler: &mut Reconciling,
    world: &World,
    host: Host,
) -> Result<crate::failover::reconcile::AttachEnded, crate::failover::reconcile::ReconcileError> {
    use crate::failover::reconcile::{ReconcileError, StandbyGate};
    let latest = volume_now(world).latest(host).map(|(seq, _)| seq);
    let seq = latest.ok_or(ReconcileError::Conflict)?;
    let volume_id = restart_tests::volume_id();
    reconciler.end_attach(&StandbyGate::qualified(), shard(), volume_id, host, seq)
}

fn roles_kept(
    run: &mut Run<'_>,
    world: &World,
    reconciler: &mut Reconciling,
    standby: Host,
    at: &str,
) -> bool {
    use crate::failover::reconcile::ReconcileError;
    use crate::failover::records::EventKind;
    let roles = [record_now(world).owner, standby];
    let mut refused = true;
    if run.planted(Plant::EndedRole) {
        rewrite_volume(world, |record| {
            let live = record.live(standby);
            let entry = (record.events.iter_mut()).find(|entry| Some(entry.seq) == live);
            entry.expect("the standby's live attach").kind = EventKind::Ended;
        });
        run.planted = true;
    } else {
        for host in roles {
            let ended = end_latest(reconciler, world, host);
            refused &= matches!(ended, Err(ReconcileError::Conflict));
        }
    }
    let volume = volume_now(world);
    let live = roles.iter().all(|host| volume.live(*host).is_some());
    if !refused || !live {
        let rule = "a host the shard record names was ended";
        fail(&mut run.containment, rule, at.to_owned());
    }
    refused && live
}

fn ended_stays(
    run: &mut Run<'_>,
    world: &World,
    reconciler: &mut Reconciling,
    (replaced, seq): (Host, u32),
    at: &str,
) -> bool {
    use crate::failover::attachments::InstanceId;
    use crate::failover::reconcile::{Binding, ReconcileError, StandbyGate};
    use crate::failover::records::{ERA, EventKind};
    use crate::failover::takeover::tests::instance_of;
    let mut refused = true;
    if run.planted(Plant::EarlyReturn) {
        rewrite_volume(world, |record| {
            let pushed = record.push(EventKind::Attach, replaced, ERA);
            pushed.expect("a free sequence number");
            if let Some(entry) = record.events.last_mut() {
                entry.instance = Some(instance_of(replaced));
            }
        });
        run.planted = true;
    } else {
        let listed = run.attached.clone();
        let probe = InstanceId::new(PROBE_INSTANCE).expect("an instance ID");
        let held = volume_now(world);
        assert!(
            held.events
                .iter()
                .all(|entry| entry.instance != Some(probe))
                && listed.iter().all(|row| row != PROBE_INSTANCE),
            "the probe's instance is bound or listed, so ATTACH-AFTER-GONE is one of several rules that refuse it"
        );
        let binding = Binding {
            instance: probe,
            unbound: &[],
            listing: Some(&listed),
        };
        let limits = crate::storage::gate_fixture::limits();
        let bounds = crate::storage::gate_fixture::bounds_of(limits);
        let (gate, volume_id) = (StandbyGate::qualified(), restart_tests::volume_id());
        let recorded =
            reconciler.record_standby(&gate, shard(), volume_id, replaced, ERA, &bounds, &binding);
        refused = matches!(recorded, Err(ReconcileError::Conflict));
    }
    let volume = volume_now(world);
    let latest = volume.latest(replaced);
    let ended = latest.is_some_and(|(at, entry)| at == seq && entry.kind == EventKind::Ended);
    if !refused || !ended {
        let rule = "a host attached again before its ended entry was gone";
        fail(&mut run.containment, rule, at.to_owned());
    }
    refused && ended
}

/// SLOT-REUSE: step 1 of the module documentation. The reconciler records the next generated host's attach, bound to
/// its own instance, and the control plane attaches that instance. Under the returned-host plant the host is the one
/// the run replaced last. Returns the host and its EXHID, or `None` after a progress failure. Containment fails when
/// a host the run replaced attaches again, and when the record holds more than three live attaches.
fn attached(
    run: &mut Run<'_>,
    world: &World,
    reconciler: &mut Reconciling,
    at: &str,
) -> Option<(Host, u8)> {
    use crate::failover::attachments::Peer;
    use crate::failover::reconcile::{Binding, StandbyGate};
    use crate::failover::records::ERA;
    use crate::failover::takeover::tests::instance_of;
    let ordinal = run.generated;
    let exhid = u8::try_from(GENERATED_EXHID + ordinal).expect("a generated EXHID");
    let returned = (run.planted(Plant::ReturnedHost))
        .then(|| run.replaced.last().copied())
        .flatten();
    let host = returned.unwrap_or_else(|| generated_host(ordinal));
    run.generated += 1;
    let held = volume_now(world);
    let unbound: Vec<Peer> = (held.live_hosts())
        .filter(|live| {
            held.live(*live)
                .and_then(|seq| held.event(seq))
                .is_some_and(|e| e.instance.is_none())
        })
        .map(|live| Peer {
            host: live,
            instance: instance_of(live),
        })
        .collect();
    let listed = run.attached.clone();
    let binding = Binding {
        instance: instance_of(host),
        unbound: &unbound,
        listing: Some(&listed),
    };
    let bounds = crate::storage::gate_fixture::bounds_of(crate::storage::gate_fixture::limits());
    let volume_id = restart_tests::volume_id();
    let gate = StandbyGate::qualified();
    let held = volume_now(world).live(host);
    let recorded =
        reconciler.record_standby(&gate, shard(), volume_id, host, ERA, &bounds, &binding);
    let after = volume_now(world);
    let entry = after.live(host).and_then(|seq| after.event(seq));
    if held.is_none() && entry.is_some_and(|entry| entry.instance == Some(binding.instance)) {
        run.planted |= returned.is_some();
        if run.replaced.contains(&host) {
            fail(
                &mut run.containment,
                "a replaced host returned",
                at.to_owned(),
            );
        }
    }
    if recorded.is_ok() {
        run.attach(instance_of(host).as_str());
        if run.planted(Plant::FourthAttach) {
            fourth_attach(run, world);
        }
    }
    let live = volume_now(world).live_hosts().count();
    run.composed.live = run.composed.live.max(live as u32);
    if live > MAX_ATTACHED {
        fail(
            &mut run.containment,
            "a record holds more than three live attaches",
            format!("{at}: {live}"),
        );
    }
    if let Err(error) = recorded {
        let at = format!("{at}: {error:?}");
        fail(
            &mut run.progress,
            "a generated host's attach was not recorded",
            at,
        );
        return None;
    }
    Some((host, exhid))
}

/// The fourth-attach plant writes the next generated host's attach entry, bound to its own instance, by an
/// exact-version replace. Once the write commits, the control plane attaches the instance and the plant counts as
/// applied.
fn fourth_attach(run: &mut Run<'_>, world: &World) {
    use crate::failover::records::{ERA, EventKind};
    use crate::failover::takeover::tests::instance_of;
    let extra = generated_host(run.generated);
    run.generated += 1;
    let mut client = store_client(&world.records);
    let read = client.read::<VolumeRecord>(Key::Volume(restart_tests::volume_id()));
    let read = read.expect("the volume record");
    let mut next = read.value().clone();
    if next.push(EventKind::Attach, extra, ERA).is_none() {
        return;
    }
    if let Some(entry) = next.events.last_mut() {
        entry.instance = Some(instance_of(extra));
    }
    if client.replace(&read, next).is_ok() {
        run.planted = true;
        run.attach(instance_of(extra).as_str());
    }
}

/// SLOT-REUSE: step 2 of the module documentation. `enroll_standby` enrolls `host` under its attach key with `exhid`,
/// the world keeps the host's local record, and the reconciler designates the host standby. Returns whether both
/// steps held; a refusal fails progress.
fn enrolled(run: &mut Run<'_>, world: &mut World, (host, exhid): (Host, u8), at: &str) -> bool {
    use crate::failover::reconcile::{StandbyGate, enroll_standby};
    use crate::failover::takeover::tests::successor_record;
    let bounds = crate::storage::gate_fixture::bounds_of(crate::storage::gate_fixture::limits());
    let mut persisted = None;
    let enrolled = enroll_standby(
        &StandbyGate::qualified(),
        shard(),
        &holder_of(host),
        &bounds,
        &mut store_client(&world.records),
        |key| {
            Ok(persisted
                .insert(successor_record(host, key.encode(), exhid))
                .clone())
        },
    );
    let Some(record) = persisted.filter(|_| enrolled.is_ok()) else {
        let at = format!("{at}: {enrolled:?}");
        fail(&mut run.progress, "a generated standby did not enroll", at);
        return false;
    };
    world.generated.retain(|(known, _)| *known != host);
    world.generated.push((host, record));
    if run.planted(Plant::RefusedDesignation) {
        world.records.schedule(Arm::Unavailable);
        run.planted = true;
    }
    if let Err(refusal) = designated_as(world, host) {
        let at = format!("{at}: {refusal}");
        fail(
            &mut run.progress,
            "a generated standby was not designated",
            at,
        );
        return false;
    }
    run.first_attach = Some(host);
    true
}

/// SLOT-REUSE: step 5 of the module documentation for `replaced`'s ended entry `seq`. The detach witness from
/// `detachable` must name the shard's volume and the entry's instance. The control plane detaches that instance, and
/// `release_attach` judges two listings taken `SETTLE_US` and twice `SETTLE_US` after the detach request. Under the
/// early-release plant the instance stays attached and both listings omit it. Returns whether a reread of the volume
/// record shows entry `seq` gone. Containment fails when the gone entry's instance is still attached.
fn released(
    run: &mut Run<'_>,
    world: &World,
    reconciler: &mut Reconciling,
    (replaced, seq): (Host, u32),
    at: &str,
) -> bool {
    use crate::failover::reconcile::{Listing, ReconcileError, Settle, StandbyGate};
    use crate::failover::records::EventKind;
    let volume_id = restart_tests::volume_id();
    let bound = volume_now(world)
        .event(seq)
        .and_then(|entry| entry.instance);
    let unreleased = "the replaced host was not detached and released";
    let witness = match reconciler.detachable(volume_id, replaced) {
        Ok(witness) => witness,
        Err(error) => {
            let at = format!("{at}: detachable: {error:?}");
            fail(&mut run.progress, unreleased, at);
            return false;
        }
    };
    if witness.volume() != volume_id || Some(witness.instance()) != bound {
        let rule = "a detach witness named another attachment";
        fail(&mut run.containment, rule, format!("{at}: {witness:?}"));
        return false;
    }
    let instance = witness.instance().as_str().to_owned();
    let early = run.planted(Plant::EarlyRelease);
    let gate = StandbyGate::qualified();
    let window = Settle {
        requested: 0,
        settle: SETTLE_US,
    };
    fn listings(at: [u64; 2], instances: &[String]) -> [Listing<'_>; 2] {
        at.map(|at| Listing { at, instances })
    }
    fn settled(instances: &[String]) -> [Listing<'_>; 2] {
        listings([SETTLE_US, 2 * SETTLE_US], instances)
    }
    let still_ended = |world: &World| {
        (volume_now(world).event(seq)).is_some_and(|entry| entry.kind == EventKind::Ended)
    };
    let attached_gone = "an entry was recorded gone while its instance is attached";
    if !early {
        let shown = run.attached.clone();
        let refused = reconciler.release_attach(&gate, &witness, &settled(&shown), window);
        if refused != Err(ReconcileError::Conflict) || !still_ended(world) {
            let at = format!("{at}: host {}: on listings that show it", replaced.get());
            fail(&mut run.containment, attached_gone, at);
            return false;
        }
        run.attached.retain(|attached| *attached != instance);
        let clean = run.attached.clone();
        let mut refused = true;
        if run.planted(Plant::UnsettledRelease) {
            rewrite_volume(world, |record| {
                let entry = record.events.iter_mut().find(|entry| entry.seq == seq);
                entry.expect("the ended entry").kind = EventKind::Gone;
            });
            run.planted = true;
        } else {
            for at in [
                [SETTLE_US - 1, 2 * SETTLE_US],
                [SETTLE_US, 2 * SETTLE_US - 1],
            ] {
                let early = listings(at, &clean);
                let released = reconciler.release_attach(&gate, &witness, &early, window);
                refused &= released == Err(ReconcileError::Conflict);
            }
        }
        if !refused || !still_ended(world) {
            let rule = "an entry was recorded gone on listings that are not settled";
            fail(&mut run.containment, rule, at.to_owned());
            return false;
        }
    }
    let listed: Vec<String> = (run.attached.iter())
        .filter(|attached| **attached != instance)
        .cloned()
        .collect();
    let released = reconciler.release_attach(&gate, &witness, &settled(&listed), window);
    run.planted |= early && released.is_ok();
    let after = volume_now(world);
    let gone =
        (after.event(seq)).filter(|entry| entry.kind == EventKind::Gone && entry.host == replaced);
    let attached = gone
        .and_then(|gone| gone.instance)
        .is_some_and(|gone| run.attached.iter().any(|listed| listed == gone.as_str()));
    if attached {
        let at = format!("{at}: host {}", replaced.get());
        fail(&mut run.containment, attached_gone, at);
    }
    if let Err(error) = released {
        let at = format!("{at}: release_attach: {error:?}");
        fail(&mut run.progress, unreleased, at);
        return false;
    }
    if gone.is_none() {
        let rule = "the replaced host's entry was not recorded gone";
        fail(&mut run.progress, rule, at.to_owned());
        return false;
    }
    !attached
}

/// Holds the reclaim step's planted EndOrder defect (`reclaim_plant::DROP_ON_STATUS`) on while it lives.
struct Defect;

impl Defect {
    fn set(planted: bool) -> Option<Self> {
        planted.then(|| {
            crate::storage::reclaim_plant::arm(true);
            Self
        })
    }
}

impl Drop for Defect {
    fn drop(&mut self) {
        crate::storage::reclaim_plant::arm(false);
    }
}

/// SLOT-REUSE: step 4 of the module documentation, at most six polls. Returns whether `replaced`'s pair left the
/// record. Containment fails if a poll returns a pair whose key appears in that poll's Report (EndOrder).
///
/// The no-effect-preempt and listed-drop plants register the replaced host's pair on the shared reservation before
/// the first poll and give the first ended-key preempt the success status with no effect on the device. The
/// listed-drop plant also turns on the owner's planted defect, which counts that status as the receipt that the key
/// left, so the owner's next reclaim call returns the pair while its Report lists the key.
fn reclaim(
    run: &mut Run<'_>,
    world: &mut World,
    serving: &mut Serving<'_>,
    replaced: Host,
    at: &str,
) -> bool {
    use crate::failover::evidence::Pair;
    use crate::failover::poll::Verdict;
    use crate::failover::reconcile::StandbyGate;
    use crate::failover::takeover::tests::instance_of;
    use crate::host::lane::{Done, Job, Lane};
    use crate::storage::ReservationCommand;
    use crate::storage::device::DeviceStatus;
    let gate = StandbyGate::qualified();
    let owner = record_now(world).owner;
    let holder = holder_of(owner);
    let pinned = |volume: &VolumeRecord| {
        (volume.pairs.iter())
            .find(|recorded| recorded.host == replaced)
            .map(|recorded| recorded.pair)
    };
    let listed_drop = run.planted(Plant::ListedDrop);
    let mut no_effect = listed_drop || run.planted(Plant::NoEffectPreempt);
    if no_effect && let Some(pair) = pinned(&volume_now(world)) {
        let mut reservation = world.reservation.borrow_mut();
        if !reservation.entries.iter().any(|entry| entry.pair == pair) {
            let registered = crate::failover::fresh::tests::registrant(pair, 9, false);
            reservation.entries.push(registered);
        }
    }
    let _defect = Defect::set(listed_drop);
    for _ in 0..6 {
        if pinned(&volume_now(world)).is_none() {
            return true;
        }
        let reports = serving.registry.borrow().reports();
        (serving.registry.borrow_mut().entries).clone_from(&world.reservation.borrow().entries);
        // The owner judges the Report it parsed last. The loop steps the tenure until a second Report is submitted
        // after the copy, so the first one has completed: it was submitted after the copy and after the previous
        // poll saw the end, as `owner_reclaim` requires before it returns a pair. The loop stops at 64 steps.
        let mut fresh = false;
        for _ in 0..64 {
            serving.step();
            if serving.registry.borrow().reports() > reports + 1 {
                fresh = true;
                break;
            }
        }
        if !fresh {
            let rule = "a reclaim poll's Report did not complete";
            fail(&mut run.progress, rule, at.to_owned());
            return false;
        }
        let polled = serving.owner.poll_report();
        let listed = run.attached.clone();
        let mut client = store_client(&world.records);
        let read = client
            .read::<VolumeRecord>(Key::Volume(restart_tests::volume_id()))
            .expect("the volume record");
        let shard_record = record_now(world);
        let peers =
            crate::host::inputs::peers(&holder, read.value(), |host| Some(instance_of(host)))
                .expect("the owner's volume");
        let reads = crate::host::inputs::reads(
            Some(&shard_record),
            Some(read.value()),
            Some(&listed),
            &peers,
        );
        let report = polled.as_ref().map(|polled| polled.report());
        let report = report.as_ref().map_err(|refusal| **refusal);
        let now = serving.time();
        let sent_at = serving.owner.serving_sample();
        let verdict = serving
            .owner
            .owner_poll(&holder, report, &reads, sent_at, now);
        if verdict != Verdict::Continue {
            fail(
                &mut run.progress,
                "a reclaim poll did not continue",
                format!("{at}: {verdict:?}"),
            );
            return false;
        }
        let logged = serving.registry.borrow().log.len();
        let reclaimed = serving
            .owner
            .owner_reclaim(&gate, &holder, &verdict, report, read.value());
        let pairs = crate::host::duties::droppable(Some(&shard_record), read.value(), reclaimed);
        let ended =
            (serving.registry.borrow().log[logged..].iter()).find_map(|command| match command {
                ReservationCommand::PreemptEnded(preempt) => Some(preempt.ended()),
                _ => None,
            });
        if let Some(ended) = ended {
            run.composed.preempts += 1;
            if no_effect {
                serving.registry.borrow_mut().mutation_status = Some(DeviceStatus::Nvme(0));
            }
            // Eight steps run the preempt on the device and its terminal at the authority. The shared reservation
            // then drops the key if the device's table dropped it.
            for _ in 0..8 {
                serving.step();
            }
            if no_effect && serving.registry.borrow().mutation_status.is_some() {
                let rule = "an ended-key preempt did not complete";
                fail(&mut run.progress, rule, at.to_owned());
                return false;
            }
            let keyed = |entry: &crate::failover::evidence::Registrant| entry.pair.key == ended;
            if !serving.registry.borrow().entries.iter().any(keyed) {
                (world.reservation.borrow_mut().entries).retain(|entry| !keyed(entry));
            } else if no_effect {
                run.planted |= !listed_drop;
            }
            no_effect = false;
        }
        if pairs.is_empty() {
            continue;
        }
        let unjustified = |pair: &Pair| {
            (report.ok()).is_none_or(|report| {
                (report.entries.iter()).any(|entry| entry.pair.key == pair.key)
            })
        };
        if pairs.iter().any(unjustified) {
            run.planted |= listed_drop;
            fail(
                &mut run.containment,
                "a pair dropped while its poll's Report lists its key",
                at.to_owned(),
            );
        }
        let mut lane = Lane::inline(store_client(&world.records), serving.storage);
        let before = read.value().pairs.clone();
        let requested = pairs.clone();
        let job = Job::Drop {
            read,
            pairs,
            session: serving.owner.tenure().get(),
        };
        lane.submit(job).expect("an idle lane");
        match lane.poll() {
            Some(Done::Drop {
                dropped: Some(Ok(written)),
            }) => {
                let kept = &written.value().pairs;
                let removed: Vec<Pair> = (before.iter())
                    .filter(|held| !kept.contains(held))
                    .map(|held| held.pair)
                    .collect();
                let exact = removed.len() == requested.len()
                    && requested.iter().all(|pair| removed.contains(pair))
                    && kept.iter().all(|held| before.contains(held));
                if !exact {
                    let rule = "a pair drop changed other pairs than its poll returned";
                    let at = format!("{at}: removed {removed:?} of {requested:?}");
                    fail(&mut run.containment, rule, at);
                }
                run.composed.drops += removed.len() as u32;
            }
            done => {
                fail(
                    &mut run.progress,
                    "the owner's pair drop did not commit",
                    format!("{at}: {done:?}"),
                );
                return false;
            }
        }
        drop(lane.end());
    }
    let left = pinned(&volume_now(world)).is_none();
    if !left {
        fail(
            &mut run.progress,
            "the replaced host's pair stayed recorded",
            at.to_owned(),
        );
    }
    left
}

/// A tenure's capture pass: its counter, and whether its walk emitted each entry resident at its start exactly once.
struct Pass {
    counter: u32,
    whole: bool,
}

/// Walks a capture pass over the tenure's membership and, unless `stuck`, finishes it. The walk runs no owner turn,
/// so the membership read from the slots before the pass starts is the membership it walks: the pass is whole when
/// the allocation, session and version of every emitted entry, sorted with repeats kept, equal those of the resident
/// slots. Returns `None` when the storage starts no pass.
fn capture(serving: &Serving<'_>, stuck: bool) -> Option<Pass> {
    let mut facts = Vec::new();
    (serving.storage.slot_facts_into(&mut facts)).expect("a live pool");
    let resident = facts.iter().enumerate().filter(|(_, fact)| fact.resident);
    let mut members: Vec<(u64, u64, u64)> = resident
        .map(|(slot, fact)| {
            let allocation = ((slot as u64) << 32) | u64::from(fact.incarnation);
            (allocation, fact.session, fact.version)
        })
        .collect();
    members.sort_unstable();
    let counter = serving.storage.start_capture(1024, true, 1024).ok()?;
    let mut entries = Vec::new();
    let mut batch = || {
        let walked = serving.storage.capture_visit(counter, 64, |entry| {
            entries.push((entry.allocation, entry.session, entry.version));
        });
        walked.expect("a capture batch")
    };
    while batch() > 0 {}
    if !stuck {
        crate::storage::finish_test_capture(serving.storage, counter).expect("the pass finishes");
    }
    entries.sort_unstable();
    Some(Pass {
        counter,
        whole: entries == members,
    })
}

/// The resident and reserved bytes the tenure's pool holds.
fn charged(serving: &Serving<'_>) -> u64 {
    let ledger = serving
        .storage
        .pool_report()
        .and_then(|report| report.ledger);
    ledger.map_or(0, |ledger| {
        (ledger.raw.resident + ledger.raw.reserved) as u64
    })
}

/// A phase's state: the report it fills and the GETs in flight.
struct Phase<'r> {
    report: &'r mut PhaseReport,
    flights: Vec<Flight>,
    base: u64,
}

impl Phase<'_> {
    fn now(&self, serving: &Serving<'_>) -> u64 {
        serving.turn - self.base
    }

    /// Raises the phase's peak to the bytes the pool charges now.
    fn charge(&mut self, serving: &Serving<'_>) {
        self.report.peak_charged = self.report.peak_charged.max(charged(serving));
    }

    /// One round of the tenure, then every GET in flight that reached its outcome settles in its bucket and is
    /// recorded in the history.
    fn step(&mut self, run: &mut Run<'_>, world: &mut World, serving: &mut Serving<'_>) {
        serving.step();
        self.charge(serving);
        let now = self.now(serving);
        let mut at = 0;
        while at < self.flights.len() {
            let flight = &mut self.flights[at];
            collect(&mut serving.client, flight.id, &mut flight.bytes);
            let Some(outcome) = serving.client.outcome(flight.id) else {
                at += 1;
                continue;
            };
            let _ = serving.client.retire(flight.id);
            let flight = self.flights.swap_remove(at);
            let accepted = serving.unrouted == flight.unrouted;
            let buckets = &mut self.report.buckets;
            match outcome {
                Fetched::Complete
                    if world
                        .objects
                        .iter()
                        .any(|o| o.n == flight.n && o.units.is_some()) =>
                {
                    buckets.retained += 1;
                    if run.covered.contains(&flight.n) {
                        let rule = "a covered version was served after its acknowledged INVALIDATE";
                        fail(&mut run.safety, rule, format!("object {}", flight.n));
                    }
                }
                Fetched::Complete => buckets.fresh += 1,
                Fetched::Missing => {
                    buckets.miss += 1;
                    self.report.origin_demand += 1;
                }
                Fetched::Pressure(_) => buckets.refused += 1,
                Fetched::Failed(Status::TimedOut) | Fetched::Incomplete(Status::TimedOut) => {
                    buckets.timed_out += 1;
                }
                Fetched::Failed(_) | Fetched::Incomplete(_) => buckets.errored += 1,
            }
            if outcome == Fetched::Complete {
                self.report.bytes += flight.bytes.len() as u64;
            }
            self.report.waited(flight.arrived, now);
            serving.record(
                world,
                flight.n,
                &flight.labels,
                (outcome, flight.bytes, accepted),
            );
        }
    }

    /// Runs rounds until no GET is in flight. Returns false when a GET has no outcome after 8,000 rounds; its flight
    /// stays open and unsettled.
    fn land(&mut self, run: &mut Run<'_>, world: &mut World, serving: &mut Serving<'_>) -> bool {
        for _ in 0..8_000 {
            if self.flights.is_empty() {
                return true;
            }
            self.step(run, world, serving);
        }
        self.flights.is_empty()
    }

    /// Sends a GET of object `n` that arrived at `arrived`, which settles `refused` at once when the client admits
    /// none.
    fn get(&mut self, world: &World, serving: &mut Serving<'_>, n: u8, arrived: u64) {
        let object = world.objects.iter().find(|object| object.n == n);
        let labels = object.expect("a known object").labels();
        let now = serving.time();
        match (serving.client).get(object_key(n), 1 << 16, 1 << 20, now, 30_000_000) {
            Ok(id) => self.flights.push(Flight {
                id,
                n,
                labels,
                arrived,
                unrouted: serving.unrouted,
                bytes: Vec::new(),
            }),
            Err(_) => {
                self.report.buckets.refused += 1;
                let now = self.now(serving);
                self.report.waited(arrived, now);
            }
        }
    }
}

/// One tenure from its activation to its cut, recorded as the run's next cycle. Returns `None` when the run cannot
/// continue past it: its load did not open, which records no cycle; or a GET drain exhausted its round bound, which
/// records the cycle as it stood with no sample; or its drain reached no boundary, so the next tenure's cut could not
/// be placed.
fn tenure(
    run: &mut Run<'_>,
    world: &mut World,
    serving: &mut Serving<'_>,
    outcome: MetadataOutcome,
    (recovery, class): (Recovery, Class),
    replaced: Option<Host>,
) -> Option<()> {
    let cycle = run.cycles.len();
    let at = |what: &str| format!("cycle {cycle}: {what}");
    if outcome != MetadataOutcome::Open {
        let rule = "a recovery's load did not open";
        fail(&mut run.progress, rule, at(&format!("{outcome:?}")));
        return None;
    }
    let named = manifest(&world.records);
    if (named.0, named.1, named.2) != (run.start.0, run.start.1, run.start.2) {
        let rule = "a recovery changed the generation, the volume or the named checkpoint";
        fail(&mut run.containment, rule, at("the manifest"));
    }
    let failed_units = serving.owner.recovery_report().warm.failed_units;
    if failed_units as usize != run.damaged.intersection(&run.rows).count() {
        let rule = "the recovery's loss report differs from the injected row units";
        fail(
            &mut run.containment,
            rule,
            at(&format!("{failed_units} failed units")),
        );
    }
    let restored = serving.resident().len() as u64;
    let suffix = serving.open_suffix(&world.records);
    let chain = record_now(world).ancestry.as_slice().len();
    if suffix {
        run.suffixes += 1;
    } else if chain < MAX_CHAIN {
        let rule = "the store refused a tenure's suffix below the chain cap";
        fail(&mut run.progress, rule, at(&format!("{chain} suffixes")));
    } else {
        run.composed.chain_full += 1;
    }
    let eligible = run.eligible(world);
    let dropped = plant_misses(run, serving, &eligible);
    let opening: BTreeSet<u8> = serving.read_all(world).into_iter().collect();
    if let Some(lost) = eligible.iter().find(|n| !opening.contains(n)) {
        let rule = "a retained entry was not served its exact bytes at the recovered tenure";
        fail(&mut run.retention, rule, at(&format!("object {lost}")));
    }
    if let Some(served) = run.covered.iter().find(|n| opening.contains(n)) {
        let rule = "a covered version was served after its acknowledged INVALIDATE";
        fail(&mut run.safety, rule, at(&format!("object {served}")));
    }
    if let Some(replaced) = replaced {
        replace(run, world, serving, replaced);
    }
    let mut record = Cycle {
        recovery,
        class,
        tenure: serving.tenure,
        cut: cut_of(&named),
        eligible: eligible.len() as u32,
        served: eligible.intersection(&opening).count() as u32,
        failed_units,
        suffix,
        fills: 0,
        invalidations: 0,
        phases: [PhaseReport::default(); 3],
        sample: None,
        response: false,
    };

    let drained = serve_phase(
        run,
        world,
        serving,
        &mut record.phases[0],
        (suffix, &eligible),
    );
    let (mut did, drained) = match drained {
        Ok(did) => (did, true),
        Err(did) => (did, false),
    };
    (record.fills, record.invalidations) = (did.fills, did.invalidations);
    run.composed.fills += did.fills;
    run.composed.invalidations += did.invalidations;
    if !drained {
        run.cycles.push(record);
        return None;
    }
    did.removed += dropped;

    let published = world.objects.iter().filter(|object| object.units.is_none());
    let first_fill = run.next_fill - did.fills as u8;
    let fresh: Vec<u8> = (published.map(|object| object.n))
        .filter(|n| *n >= first_fill)
        .collect();
    // The dropped fill's removal precedes the capture pass, whose start seals it with the tenure's other records.
    if run.planted(Plant::DroppedFill)
        && let Some(&n) = fresh.first()
    {
        let gone = serving.drop_entry(n);
        did.removed += u64::from(gone);
        run.planted = gone;
    }
    let pass = capture(serving, run.planted(Plant::StuckCapture));
    match &pass {
        None => {
            let rule = "a tenure started no capture pass";
            fail(&mut run.progress, rule, at("the capture pass"));
        }
        Some(pass) if !pass.whole => {
            let rule = "a capture pass walked other than the entries resident at its start";
            fail(&mut run.progress, rule, at("the capture pass"));
        }
        Some(_) => run.composed.captures += 1,
    }
    run.planted |= run.planted(Plant::StuckCapture) && pass.is_some();
    let closing: BTreeSet<u8> = serving.read_all(world).into_iter().collect();
    if let Some(lost) = fresh.iter().find(|n| !closing.contains(n)) {
        let rule = "an acknowledged FILL was not served in its own tenure";
        fail(&mut run.retention, rule, at(&format!("object {lost}")));
    }

    let account = (restored, did.fills, did.removed);
    let sample = drain(run, world, serving, pass.as_ref(), account);
    if sample.is_some() {
        join_fills(run, world, serving, &fresh);
    }
    let shrunk = run.planted(Plant::ShrunkCoverage);
    if shrunk {
        plant_shrunk_coverage(run, world, serving, &eligible);
    }
    // The shrunk-coverage plant's tenure drops with no round after its planted coverage writes.
    let rounds = if shrunk { 0 } else { 64 };
    record.response = cut(run, world, serving, &mut record.phases[1], rounds);
    let dead = run.tape.below(3) as u32;
    let mut downtime = (run.tape).phase(dead, run.config.gap, run.config.mix);
    let interval = &mut record.phases[2];
    for Arrival { tick, .. } in downtime.runnable(u64::MAX) {
        interval.buckets.offered += 1;
        interval.buckets.refused += 1;
        interval.waited(tick, tick);
    }
    if record.phases.iter().any(|phase| !phase.buckets.settled()) {
        let rule = "an offered request settled in no bucket";
        fail(&mut run.progress, rule, at("the buckets"));
    }
    record.sample = sample;
    run.cycles.push(record);
    sample.is_some().then_some(())
}

/// The always-miss and restored-entry-miss plants: the recovered tenure drops every restored entry, or the first,
/// from RAM. Returns the resident entries it removed.
fn plant_misses(run: &mut Run<'_>, serving: &mut Serving<'_>, eligible: &BTreeSet<u8>) -> u64 {
    let all = run.planted(Plant::AlwaysMiss);
    if !all && !run.planted(Plant::RestoredEntryMiss) {
        return 0;
    }
    let mut dropped = 0;
    for &n in eligible.iter().take(if all { usize::MAX } else { 1 }) {
        dropped += u64::from(serving.drop_entry(n));
    }
    run.planted = dropped > 0;
    dropped
}

/// The serve phase: the tape's arrivals offered at their ticks into `report`, GETs through the client and FILLs and
/// INVALIDATEs through the owner, each mutation after the GETs in flight land. `suffix` says whether the tenure's
/// log is open, under which every FILL in the run's range and every INVALIDATE must be acknowledged. Every GET drain,
/// before a mutation and after the last arrival, runs at most [`Phase::land`]'s rounds. Returns what the phase did,
/// as `Err` when a GET drain exhausted its round bound, which fails progress and leaves that GET unsettled.
fn serve_phase(
    run: &mut Run<'_>,
    world: &mut World,
    serving: &mut Serving<'_>,
    report: &mut PhaseReport,
    (suffix, eligible): (bool, &BTreeSet<u8>),
) -> Result<Served, Served> {
    let cycle = run.cycles.len();
    let at = |what: &str| format!("cycle {cycle}: {what}");
    let mut did = Served::default();
    let (reads, writes) = (Operation::Read, Operation::Write);
    let accepted = |serving: &Serving<'_>| {
        (serving.control.accepted(reads) + serving.control.accepted(writes)) as u64
    };
    let before = accepted(serving);
    let mut arrivals = (run.tape).phase(run.config.arrivals, run.config.gap, run.config.mix);
    let mut phase = Phase {
        report,
        flights: Vec::new(),
        base: serving.turn,
    };
    phase.charge(serving);
    // Under the no-publish plant the tenure holds every INVALIDATE it takes and writes no coverage page.
    let unpublished = run.planted(Plant::NoPublish);
    if unpublished {
        let first = *eligible.first().expect("an eligible object");
        did.removed += u64::from(hold(serving, first).unwrap_or(false));
        run.planted = serving.owner.held_invalidations() > 0;
    }
    let undecided = "a GET had no outcome within its drain's round bound";
    while !arrivals.exhausted() {
        let now = phase.now(serving);
        for Arrival { tick, kind } in arrivals.runnable(now) {
            phase.report.buckets.offered += 1;
            match kind {
                Kind::Get(draw) => {
                    let n = world.objects[(draw % world.objects.len() as u64) as usize].n;
                    phase.get(world, serving, n, tick);
                }
                Kind::Fill => {
                    if !phase.land(run, world, serving) {
                        fail(&mut run.progress, undecided, at("a FILL's drain"));
                        phase.report.operations = accepted(serving) - before;
                        return Err(did);
                    }
                    let n = run.next_fill;
                    let published = n <= run.config.fills.1 && serving.fill(world, n);
                    // The fill table's records of both index shards are released, as the storage's fill
                    // service does between fills.
                    for shard in 0..2 {
                        let shard = crate::index::ShardIndex(shard);
                        let mut budget = WorkBudget::new(1 << 20);
                        (serving.storage.service_fills(shard, 8, &mut budget))
                            .expect("the fill service");
                    }
                    if published {
                        run.next_fill += 1;
                        did.fills += 1;
                        phase.report.buckets.applied += 1;
                    } else {
                        phase.report.buckets.refused += 1;
                        if suffix && n <= run.config.fills.1 {
                            let rule =
                                "a FILL a tenure with an open suffix was offered did not publish";
                            fail(&mut run.progress, rule, at(&format!("object {n}")));
                        }
                    }
                    phase.charge(serving);
                    let now = phase.now(serving);
                    phase.report.waited(tick, now);
                }
                Kind::Invalidate(draw) => {
                    if !phase.land(run, world, serving) {
                        fail(&mut run.progress, undecided, at("an INVALIDATE's drain"));
                        phase.report.operations = accepted(serving) - before;
                        return Err(did);
                    }
                    let captured = u64::from(run.config.objects);
                    let n = 1 + (draw % captured) as u8;
                    match hold(serving, n) {
                        Err(refused) => {
                            phase.report.buckets.refused += 1;
                            if suffix {
                                let rule = "an INVALIDATE a tenure with an open suffix was offered was refused";
                                fail(
                                    &mut run.progress,
                                    rule,
                                    at(&format!("object {n}: {refused}")),
                                );
                            }
                        }
                        Ok(gone) => {
                            did.removed += u64::from(gone);
                            if unpublished {
                                phase.report.buckets.interrupted += 1;
                            } else if publish(world, serving, n, &mut store_client(&world.records))
                            {
                                did.invalidations += 1;
                                run.uncovered.remove(&n);
                                run.covered.insert(n);
                                phase.report.buckets.applied += 1;
                            } else {
                                phase.report.buckets.interrupted += 1;
                                if suffix {
                                    let rule = "an INVALIDATE a tenure with an open suffix was offered was not acknowledged";
                                    fail(&mut run.progress, rule, at(&format!("object {n}")));
                                }
                            }
                        }
                    }
                    phase.charge(serving);
                    let now = phase.now(serving);
                    phase.report.waited(tick, now);
                }
            }
        }
        debug_assert!(
            arrivals.next_due().is_none_or(|due| due > now),
            "every arrival due at {now} was offered"
        );
        phase.step(run, world, serving);
    }
    let landed = phase.land(run, world, serving);
    phase.report.operations = accepted(serving) - before;
    if !landed {
        fail(&mut run.progress, undecided, at("the phase's last drain"));
        return Err(did);
    }
    Ok(did)
}

/// Drains the tenure to its quiescent boundary: no request live, no device command and no INVALIDATE held. Returns
/// the boundary's sample, with what the harness accounts for from `(restored, fills, removed)`. When requests and
/// the device are quiet at the tick bound and an INVALIDATE is still held, the sample is taken there and the ledger
/// fails it by name; when they are not quiet, the drain reached no boundary and there is no sample.
fn drain(
    run: &mut Run<'_>,
    world: &World,
    serving: &mut Serving<'_>,
    pass: Option<&Pass>,
    account: (u64, u32, u64),
) -> Option<Sample> {
    let mut quiet = false;
    for _ in 0..run.config.drain_ticks {
        serving.step();
        let requests = serving.owner.census();
        quiet = requests.active + requests.draining == 0 && serving.control.pending() == 0;
        if quiet && serving.owner.held_invalidations() == 0 {
            break;
        }
    }
    if !quiet {
        return None;
    }
    if run.planted(Plant::LeakedUnit) {
        run.planted = crate::storage::owner_fixture::leak_unit(serving.storage);
    }
    Some(sampled(run, world, serving, pass, account))
}

/// Joins each of `fresh`, the FILLs the tenure acknowledged, to the retained set on its payload unit. A fill of a
/// tenure that reached its boundary has its suffix record on the media, which a later load replays; a fill the
/// tenure no longer holds resident has a removal record after it and joins nothing.
fn join_fills(run: &mut Run<'_>, world: &mut World, serving: &Serving<'_>, fresh: &[u8]) {
    let resident = serving.resident();
    for &n in fresh {
        let route = serving.storage.fingerprint_of(&object_key(n));
        let fingerprint = route.expect("a route").2;
        let Some(&(_, unit)) = resident.iter().find(|(of, _)| *of == fingerprint) else {
            continue;
        };
        let unit = unit as u32;
        let object = world.objects.iter_mut().find(|object| object.n == n);
        object.expect("a published fill").units = Some((unit, unit));
        world.events.push(Event::Captured {
            n,
            label: super::first(n),
            units: (unit, unit),
            cut: super::CUT,
        });
        run.uncovered.insert(n);
    }
}

/// The shrunk-coverage plant: two acknowledged INVALIDATEs of one coverage page at the cut, the second under a
/// coverage write that keeps its own entry alone. The tenure drops before another round, so the removals reach no
/// suffix block on the media and the dropped entry's object is restored with nothing covering it.
fn plant_shrunk_coverage(
    run: &mut Run<'_>,
    world: &mut World,
    serving: &mut Serving<'_>,
    eligible: &BTreeSet<u8>,
) {
    use crate::storage::page_coverage::{SHRINKS, page_of};
    let pages = record_now(world).pages;
    let page = |n: u8| page_of(&object_key(n), pages);
    let first = *eligible.first().expect("an eligible object");
    let second = eligible
        .iter()
        .find(|&&n| n != first && page(n) == page(first));
    let second = *second.expect("two objects on one coverage page");
    let kept = hold(serving, first).is_ok()
        && publish(world, serving, first, &mut store_client(&world.records));
    SHRINKS.with(|plant| plant.set(true));
    let shrunk = hold(serving, second).is_ok()
        && publish(world, serving, second, &mut store_client(&world.records));
    SHRINKS.with(|plant| plant.set(false));
    run.planted = kept && shrunk;
    for n in [first, second] {
        run.uncovered.remove(&n);
        run.covered.insert(n);
    }
}

/// The cut into `report`: up to two GETs the tape draws, sent to the tenure. The tenure runs at most `rounds`
/// rounds, until its owner holds one of them or none is in flight, and a GET that finishes settles in its bucket.
/// The GETs with no outcome then settle `interrupted`, each waiting until the drop. Returns whether the owner held a
/// GET of the cut when the tenure dropped.
fn cut(
    run: &mut Run<'_>,
    world: &mut World,
    serving: &mut Serving<'_>,
    report: &mut PhaseReport,
    rounds: u32,
) -> bool {
    let tail = run.tape.below(3);
    let mut cut = Phase {
        report,
        flights: Vec::new(),
        base: serving.turn,
    };
    cut.charge(serving);
    let accepted = |serving: &Serving<'_>| {
        (serving.control.accepted(Operation::Read) + serving.control.accepted(Operation::Write))
            as u64
    };
    let before = accepted(serving);
    for _ in 0..tail {
        cut.report.buckets.offered += 1;
        let n = world.objects[run.tape.below(world.objects.len() as u64) as usize].n;
        cut.get(world, serving, n, 0);
    }
    let held = |serving: &Serving<'_>| {
        let requests = serving.owner.census();
        requests.active + requests.draining > 0
    };
    for _ in 0..rounds {
        if cut.flights.is_empty() || held(serving) {
            break;
        }
        cut.step(run, world, serving);
    }
    cut.charge(serving);
    cut.report.operations = accepted(serving) - before;
    let now = cut.now(serving);
    for flight in &cut.flights {
        cut.report.waited(flight.arrived, now);
    }
    cut.report.buckets.interrupted += cut.flights.len() as u64;
    held(serving)
}

/// The named checkpoint's session and capture and the record's cut.
fn cut_of(manifest: &Manifest) -> (u64, u32, u64) {
    let named = manifest.2.expect("a named checkpoint");
    (named.session, named.capture, manifest.3)
}

/// The boundary sample of the live tenure, with what the harness accounts for from `(restored, fills, removed)`.
fn sampled(
    run: &Run<'_>,
    world: &World,
    serving: &Serving<'_>,
    pass: Option<&Pass>,
    (restored, fills, removed): (u64, u32, u64),
) -> Sample {
    let pool = serving.storage.pool_report().expect("a live pool");
    let ledger = pool.ledger.expect("an unpoisoned pool");
    let requests = serving.owner.census();
    let record = record_now(world);
    let volume = store_client(&world.records)
        .read::<VolumeRecord>(Key::Volume(record.active))
        .expect("the volume record");
    let (coverage_entries, page_bytes) = coverage_of(&world.records);
    let in_flight = |pass: &Pass| {
        use crate::storage::CaptureError;
        !matches!(
            serving.storage.capture_side_len(pass.counter),
            Err(CaptureError::Idle)
        )
    };
    Sample {
        cycle: run.cycles.len() as u32,
        capture: pass.is_some_and(in_flight),
        filling: ledger.slots.filling as u64,
        reserved_bytes: ledger.raw.reserved as u64,
        pending_marks: pool.pending_marks as u64,
        escrow_units: pool.escrow_units,
        held_invalidations: serving.owner.held_invalidations() as u64,
        requests: u64::from(requests.active + requests.draining),
        device_commands: serving.control.pending() as u64,
        resident_slots: ledger.slots.resident as u64,
        resident_bytes: ledger.raw.resident as u64,
        retired_slots: ledger.slots.retired as u64,
        retired_bytes: ledger.raw.retired as u64,
        quarantined_slots: ledger.slots.quarantined as u64,
        waste_bytes: ledger.raw.waste as u64,
        coverage_entries,
        page_bytes,
        page_cap: u64::from(record.page_cap.get()),
        suffixes: record.ancestry.as_slice().len() as u64,
        attachments: volume.value().live_hosts().count() as u64,
        accounted: Accounted {
            resident_slots: restored + u64::from(fills) - removed,
            coverage_entries: run.covered.len() as u64,
            suffixes: run.suffixes,
        },
        conservation: tables(serving.storage, &mut Lenses::default()),
    }
}

/// The history the oracle judges for the tenure whose events are `window` and the objects of `group`: every
/// publication, capture, invalidation and damage row before the tenure, recorded below every activation, then the
/// tenure's own events. The oracle admits at most `MAX_KEYS` keys and a bounded number of rows a history, so a run
/// is judged one tenure and one group at a time: an earlier tenure's activation, restores and reads are left out,
/// and its effects stay as effects below the judged tenure, which is how the retained set reads them.
fn windowed(
    world: &World,
    group: &[u8],
    window: &std::ops::Range<usize>,
) -> crate::oracle::History {
    let mut script = Script::new();
    for (at, event) in world.events[..window.end].iter().enumerate() {
        if event.object().is_some_and(|n| !group.contains(&n)) {
            continue;
        }
        if at >= window.start {
            event.record(&mut script);
            continue;
        }
        match *event {
            Event::Read { .. } | Event::Activate { .. } | Event::Restore { .. } => {}
            Event::Publish { n, label, .. } => {
                let tenure = None;
                Event::Publish { n, label, tenure }.record(&mut script);
            }
            Event::Invalidate { n, .. } => {
                Event::Invalidate { n, tenure: None }.record(&mut script)
            }
            _ => event.record(&mut script),
        }
    }
    script.finish()
}

/// The oracle's judgment of a run.
struct Judgment {
    /// Each tenure's account summed over its groups.
    accounts: Vec<Preserved>,
    /// The first rule failed under an obligation other than `Restart`.
    other: Option<&'static str>,
    /// The first `Restart` rule outside [`UNCAPTURED`], a loss of the retained cut's own entries.
    retained: Option<&'static str>,
    /// The first rule of [`UNCAPTURED`].
    uncaptured: Option<&'static str>,
    /// Whether a history was inconclusive.
    inconclusive: bool,
    /// Whether some group's judgment ended before its preservation judgment ran, with no retention rule failed.
    unjudged: bool,
    /// Whether some group's judgment ended before the checker's uncaptured-restore rules ran.
    uncontained: bool,
    /// The tenures with a group whose judgment returned no account.
    partial: BTreeSet<Tenure>,
}

/// The positive-preservation rule, which `preserved` judges after the tenure-ordered checker passed every rule.
const UNSERVED: &str = "a retained entry outside every damage set was never served after host loss";

/// The oracle's judgment of a run: the client acceptances over the whole history, then the positive-preservation
/// judgment of every tenure and every group of `MAX_KEYS` objects. Each slot of the judgment holds the first rule
/// of its kind the oracle returned; the oracle returns one violation a history, so a slot names one rule a run.
/// Every damage row of a run is recorded at rest, after the reads of the tenure before it, which the judgment
/// asserts. The checker judges its retention rules after every other rule, so a history that fails by a `Restart`
/// rule passed the rules before them; a checker loss rule can stop a history before its uncaptured-restore rules,
/// and only [`UNSERVED`] runs after the whole checker passed.
fn judged(world: &World) -> Judgment {
    let mut judgment = Judgment {
        accounts: Vec::new(),
        other: None,
        retained: None,
        uncaptured: None,
        inconclusive: false,
        unjudged: false,
        uncontained: false,
        partial: BTreeSet::new(),
    };
    let note = |judgment: &mut Judgment, verdict: Judged| match verdict.violated() {
        Some((Obligation::Restart, rule)) if UNCAPTURED.contains(&rule) => {
            judgment.uncaptured.get_or_insert(rule);
        }
        Some((Obligation::Restart, rule)) => {
            judgment.retained.get_or_insert(rule);
        }
        Some((_, rule)) => {
            judgment.other.get_or_insert(rule);
        }
        None => judgment.inconclusive = true,
    };
    if let Err(verdict) = check_clients(&world.history(None)) {
        note(&mut judgment, verdict);
    }
    let activations = (world.events.iter().enumerate())
        .filter(|(_, event)| matches!(event, Event::Activate { .. }))
        .map(|(at, _)| at);
    let starts: Vec<usize> = activations.chain([world.events.len()]).collect();
    let numbers: Vec<u8> = world.objects.iter().map(|object| object.n).collect();
    let row = |event: &Event| matches!(event, Event::Damaged { .. } | Event::VolumeLost);
    for window in starts.windows(2) {
        // Each tenure's opening sweep looks every retained key up before any damage row of its window, so a
        // member's damage bound is its own key's lookup in every group.
        let damaged = (world.events[window[0]..window[1]].iter()).position(row);
        let reads_after = damaged.is_some_and(|at| {
            let later = &world.events[window[0] + at..window[1]];
            later
                .iter()
                .any(|event| matches!(event, Event::Read { .. }))
        });
        assert!(
            !reads_after,
            "a damage row lies between two reads of one tenure"
        );
        let mut sum: Option<Preserved> = None;
        let activated = match world.events[window[0]] {
            Event::Activate { tenure, .. } => Some(tenure),
            _ => None,
        };
        for group in numbers.chunks(MAX_KEYS) {
            match preserved(&windowed(world, group, &(window[0]..window[1]))) {
                Ok(judged) => {
                    for account in judged {
                        match sum.as_mut() {
                            Some(sum) => add_account(sum, account),
                            None => sum = Some(account),
                        }
                    }
                }
                Err(verdict) => {
                    let violated = verdict.violated();
                    let retention = violated.is_some_and(|(obligation, rule)| {
                        obligation == Obligation::Restart && !UNCAPTURED.contains(&rule)
                    });
                    let contained = violated.is_some_and(|(obligation, rule)| {
                        obligation == Obligation::Restart
                            && (rule == UNSERVED || UNCAPTURED.contains(&rule))
                    });
                    judgment.unjudged |= !retention;
                    judgment.uncontained |= !contained;
                    judgment.partial.extend(activated);
                    note(&mut judgment, verdict);
                }
            }
        }
        judgment.accounts.extend(sum);
    }
    judgment
}

/// The rules of the oracle's `Restart` obligation that state a loss outside the retained cut's own entries: a
/// restore of an entry the cut never captured and an activation of a cut no capture recorded.
const UNCAPTURED: [&str; 2] = [
    "a recovery restored an entry its cut never captured",
    "host loss activated a cut no capture recorded",
];

impl Run<'_> {
    /// Judges the finished run's history and closes the report.
    fn report(mut self, world: &World) -> Report {
        let at = || "the history".to_owned();
        let recorded: Vec<Option<u32>> = (world.events.iter())
            .filter_map(|event| match event {
                Event::Damaged { unit } => Some(Some(*unit)),
                Event::VolumeLost => Some(None),
                _ => None,
            })
            .collect();
        let injected: Vec<Option<u32>> = self.injected.iter().copied().map(Some).collect();
        if recorded != injected {
            let rule = "a damage row names a unit no fault was injected on";
            fail(&mut self.containment, rule, format!("rows {recorded:?}"));
        }
        let judgment = judged(world);
        if let Some(rule) = judgment.other {
            fail(&mut self.safety, rule, at());
        }
        if let Some(rule) = judgment.retained {
            fail(&mut self.retention, rule, at());
        }
        if let Some(rule) = judgment.uncaptured {
            fail(&mut self.containment, rule, at());
        }
        let on_injected = |n: u8| {
            let (row, payload) = world.units(n);
            self.injected.contains(&row) || self.injected.contains(&payload)
        };
        let excused = (judgment.accounts.iter()).flat_map(|account| account.excused.iter());
        if let Some((key, _)) = excused.clone().find(|(key, _)| !on_injected(key.0)) {
            let rule = "a loss was excused on a unit no fault was injected on";
            fail(&mut self.containment, rule, format!("object {}", key.0));
        }
        for cycle in (self.cycles.iter()).filter(|cycle| !judgment.partial.contains(&cycle.tenure))
        {
            let account = (judgment.accounts.iter()).find(|account| account.tenure == cycle.tenure);
            if account.is_some_and(|a| a.members < cycle.eligible || a.served < cycle.served) {
                let rule =
                    "the oracle's retained set accounts for fewer entries than the harness served";
                let tenure = cycle.tenure;
                fail(
                    &mut self.retention,
                    rule,
                    format!("tenure {}/{}", tenure.g, tenure.a),
                );
            }
        }
        let inconclusive =
            (judgment.inconclusive).then_some("the oracle judged a history inconclusive");
        let violated = judgment.other.or(judgment.retained).or(judgment.uncaptured);
        let conclusive = !judgment.inconclusive && violated.is_none();
        let mut unowned = None;
        if conclusive {
            match owned(world) {
                Verdict::Fail(rule, at) => fail(&mut self.safety, rule, at),
                Verdict::Inconclusive(why) => unowned = Some(why),
                Verdict::Pass | Verdict::Unrun(_) => {}
            }
        }
        let unjudged = (judgment.unjudged)
            .then_some("the oracle's preservation judgment did not run for a group of keys");
        let uncontained = (judgment.uncontained)
            .then_some("the oracle's uncaptured-restore rules did not run for a group of keys");
        let activations = world
            .events
            .iter()
            .filter(|event| matches!(event, Event::Activate { .. }));
        let uncut =
            (judgment.accounts.len() < activations.count()).then_some("an activation named no cut");
        let close = |failure: Failure, short: Option<&'static str>| match (failure, short) {
            (Some((rule, at)), _) => Verdict::Fail(rule, at),
            (None, Some(why)) => Verdict::Inconclusive(why),
            (None, None) => Verdict::Pass,
        };
        let cycles = self.cycles.len() as u32;
        let short = (cycles < self.config.cycles).then_some("the run ended before its last cycle");
        let undrained = (self.cycles.iter().any(|cycle| cycle.sample.is_none()))
            .then_some("a drain did not reach its boundary within its tick bound");
        let no_members = self.cycles.iter().all(|cycle| cycle.eligible == 0);
        let retention = inconclusive
            .or(unjudged)
            .or(uncut)
            .or(short)
            .or(no_members.then_some("no tenure had an eligible retained entry"));
        let limits = ledger::Limits {
            epsilon: self.config.epsilon,
            slope: 1,
            chain_cap: MAX_CHAIN as u64,
            attach_cap: MAX_ATTACHED as u64,
            band: self.config.band,
        };
        let mut samples: Vec<Option<Sample>> =
            self.cycles.iter().map(|cycle| cycle.sample).collect();
        samples.resize(self.config.cycles as usize, None);
        Report {
            identity: self.config.identity(),
            config: *self.config,
            safety: close(self.safety, inconclusive.or(unowned)),
            containment: close(self.containment, inconclusive.or(uncontained)),
            retention: close(self.retention, retention),
            progress: close(self.progress, undrained.or(short)),
            conservation: ledger::judge(&samples, &limits),
            reached: reach(&self.cycles),
            cycles: self.cycles,
            composed: self.composed,
            planted: self.planted,
            oracle: [judgment.other, judgment.retained.or(judgment.uncaptured)],
            guarded: world.guarded,
        }
    }
}

/// Runs `config`'s cycles over a fresh shard and judges them.
///
/// # Panics
///
/// When `config` asks for more than [`MAX_CYCLES`] cycles, captures no object or 100 or more, or its fill numbers
/// reach the leak control's keys or overlap its captured objects, before any cycle runs.
pub(crate) fn run(config: &Config) -> Report {
    assert!(
        config.cycles <= MAX_CYCLES,
        "a run of {} cycles is past the {MAX_CYCLES} cycles whose boot nonces and leak keys stay distinct",
        config.cycles
    );
    assert!(
        (1..100).contains(&config.objects)
            && config.objects < config.fills.0
            && config.fills.1 < 100,
        "a run captures at least one object, and its fill numbers lie past the captured objects and below the leak keys"
    );
    let mut world = World::new(config.objects, false);
    if config.reuse {
        // The owner's periodic Reports, which the reclaim step judges, run on a serving clock that moves.
        world.set_moving_clock(crate::storage::gate_fixture::Strategy::Honest {
            offset_us: 0,
            error_us: 0,
        });
        enroll_by_attach_key(&mut world);
    }
    let mut run = Run::new(config, &world);
    for _ in 0..config.cycles {
        run.at_rest(&mut world);
        let (recovery, replaced) = if config.reuse {
            run.replacement(&world)
        } else {
            (run.drawn(), None)
        };
        let (taken, class) = match run.recover(&mut world, recovery) {
            Ok(recovered) => recovered,
            Err(refusal) => {
                let at = format!("cycle {}: {refusal}", run.cycles.len());
                fail(&mut run.progress, "a slot-reuse recovery was refused", at);
                break;
            }
        };
        run.composed.recoveries[recovery as usize] += 1;
        let source = if run.planted(Plant::SwappedClass) {
            run.planted = true;
            Source::Cold
        } else {
            Source::Named
        };
        let evicting = run.planted(Plant::TotalEviction);
        crate::storage::checkpoint::PLANT.with(|plant| {
            plant.set(evicting.then_some(crate::storage::checkpoint::Plant::AllOrNothing));
        });
        let did = serve(&mut world, taken, source, |world, serving, outcome| {
            crate::storage::checkpoint::PLANT.with(|plant| plant.set(None));
            run.planted |= evicting && outcome != MetadataOutcome::Open;
            tenure(
                &mut run,
                world,
                serving,
                outcome,
                (recovery, class),
                replaced,
            )
        });
        if did.is_none() {
            break;
        }
    }
    run.report(&world)
}

/// The sites the cuts of `cycles` reached, each under the class of the recovery that followed it: `Response` when
/// the cut's owner held a GET at the drop, and `RecoveryMutation` for a second crash inside a recovery, under that
/// recovery's class. The last cycle's cut has no recovery and reaches nothing.
fn reach(cycles: &[Cycle]) -> BTreeSet<(Class, Site)> {
    let second = [
        Recovery::Interrupted,
        Recovery::Unknown,
        Recovery::AfterPreempt,
    ];
    let mut reached = BTreeSet::new();
    for (at, cycle) in cycles.iter().enumerate() {
        if second.contains(&cycle.recovery) {
            reached.insert((cycle.class, Site::RecoveryMutation));
        }
        if at
            .checked_sub(1)
            .is_some_and(|before| cycles[before].response)
        {
            reached.insert((cycle.class, Site::Response));
        }
    }
    reached
}

/// The unpowered discovery runs of `seeds` at `cycles` cycles each: every run's lines and the digest of its lines,
/// the census of the runs, the compositions they reached, the in-scope cases left unscored, and a closing line.
///
/// # Errors
///
/// The lines of the first run that does not pass, a run identity kept twice, or a refused census.
pub(crate) fn discovery(
    seeds: std::ops::RangeInclusive<u64>,
    cycles: u32,
) -> Result<Vec<String>, String> {
    let mut outputs = Outputs::default();
    let mut lines = Vec::new();
    for seed in seeds.clone() {
        let report = run(&Config::discovery(seed, cycles));
        admitted(&report)?;
        lines.extend(report.lines());
        lines.push(format!(
            "cycles: {} digest {}",
            report.identity,
            report.digest()
        ));
        (outputs.keep(report)).map_err(|identity| format!("run {identity} ran twice"))?;
    }
    let reports = outputs.reports();
    let rows = census::census(&census::REQUIRED, &reports).map_err(|r| format!("{r:?}"))?;
    let count = |status| rows.iter().filter(|(_, _, of)| *of == status).count();
    let gaps: Vec<String> = (rows.iter())
        .filter(|(_, _, status)| *status == census::Status::Gap)
        .map(|(class, site, _)| format!("{class:?}/{}", site.name()))
        .collect();
    lines.push(format!(
        "cycles: census: covered {} gap {} undecided {} not-required {}; gaps [{}]",
        count(census::Status::Covered),
        count(census::Status::Gap),
        count(census::Status::Undecided),
        count(census::Status::NotRequired),
        gaps.join(", "),
    ));
    let mut total = Composed::default();
    for report in &reports {
        let composed = &report.composed;
        for (sum, count) in total.recoveries.iter_mut().zip(composed.recoveries) {
            *sum += count;
        }
        total.fresh_hosts += composed.fresh_hosts;
        total.unauthorized += composed.unauthorized;
        total.damaged += composed.damaged;
        total.repaired += composed.repaired;
        total.landings += composed.landings;
        total.chain_full += composed.chain_full;
        total.fills += composed.fills;
        total.invalidations += composed.invalidations;
        total.captures += composed.captures;
    }
    let recoveries: Vec<String> = (Recovery::ALL.iter())
        .map(|recovery| {
            format!(
                "{} {}",
                recovery.name(),
                total.recoveries[*recovery as usize]
            )
        })
        .collect();
    lines.push(format!(
        "cycles: composed: {} fresh-hosts {} unauthorized {} damaged {} repaired {} landings {} chain-full {} \
         fills {} invalidations {} captures {}",
        recoveries.join(" "),
        total.fresh_hosts,
        total.unauthorized,
        total.damaged,
        total.repaired,
        total.landings,
        total.chain_full,
        total.fills,
        total.invalidations,
        total.captures,
    ));
    lines.push(format!("cycles: unscored: {}", UNSCORED.join("; ")));
    lines.push(format!(
        "cycles: discovery: {} seeds of {cycles} cycles, unpowered; every run passed its four verdicts and \
         its quiescent conservation, and no run is a confirmation",
        seeds.count(),
    ));
    Ok(lines)
}

/// SLOT-REUSE discovery: each seed's run of `cycles` cycles replaces the standby or the owner in every cycle, passes
/// the four verdicts and the quiescent conservation judgment, keeps at most three live attaches and admits no host
/// that returned. It returns each run's lines and digest, then one line of the replacements, the owner's drops and
/// ended-key preempts and the most live attaches over every run.
pub(crate) fn slot_reuse_discovery(
    seeds: std::ops::RangeInclusive<u64>,
    cycles: u32,
) -> Result<Vec<String>, String> {
    slot_reuse_lines(seeds.map(|seed| run(&Config::slot_reuse(seed, cycles))))
}

/// `slot_reuse_lines` produces the discovery lines for reports with a common cycle count. It validates each report
/// before requesting the next.
///
/// # Errors
///
/// The function returns the first error. If [`admitted`] returns an error, the function propagates it unchanged.
/// After admission, a failed check returns `seed {seed}: {check}: {composed:?}`, where `check` names the first
/// requirement the report fails, in this order: `config.cycles` matches the first report's cycle count; `config`
/// equals [`Config::slot_reuse`] of its seed and that count; `planted` is false; `replacements` equals the cycle
/// count; `drops` equals `replacements`; `live` is at most [`MAX_ATTACHED`]; `identity` equals
/// `config.identity()`; and `config.seed` is new across `reports`.
pub(crate) fn slot_reuse_lines<R: std::borrow::Borrow<Report>>(
    reports: impl IntoIterator<Item = R>,
) -> Result<Vec<String>, String> {
    let mut lines = Vec::new();
    let (mut replacements, mut drops, mut preempts, mut live) = (0, 0, 0, 0);
    let mut cycles = None;
    let (mut seeds, mut identities) = (BTreeSet::new(), BTreeSet::new());
    for report in reports {
        let report = report.borrow();
        admitted(report)?;
        let composed = report.composed;
        let config = report.config;
        let cycles = *cycles.get_or_insert(config.cycles);
        let checks = [
            ("cycle count", config.cycles == cycles),
            (
                "configuration",
                config == Config::slot_reuse(config.seed, cycles),
            ),
            ("plant", !report.planted),
            ("replacements", composed.replacements == cycles),
            ("drops", composed.drops == composed.replacements),
            ("live attaches", composed.live <= MAX_ATTACHED as u32),
            ("identity", report.identity == config.identity()),
            (
                "repeated seed or identity",
                seeds.insert(config.seed) && identities.insert(report.identity.clone()),
            ),
        ];
        if let Some((check, _)) = checks.iter().find(|(_, held)| !held) {
            return Err(format!("seed {}: {check}: {composed:?}", config.seed));
        }
        (replacements, drops) = (replacements + composed.replacements, drops + composed.drops);
        (preempts, live) = (preempts + composed.preempts, live.max(composed.live));
        lines.extend(report.lines());
        lines.push(format!(
            "cycles: {} digest {}",
            report.identity,
            report.digest()
        ));
    }
    let Some(cycles) = cycles else {
        return Err("no slot-reuse run".to_owned());
    };
    lines.push(format!(
        "cycles: slot-reuse: {} seeds of {cycles} cycles; replacements {replacements} drops {drops} preempts \
         {preempts} live-max {live}; every run passed its four verdicts and its quiescent conservation, and no \
         replaced host returned",
        seeds.len(),
    ));
    Ok(lines)
}

/// On discovery admission failure, the error includes the run's report lines and write-guard record.
pub(crate) fn admitted(report: &Report) -> Result<(), String> {
    if report.passed() && report.buckets().settled() && report.guard_held() {
        return Ok(());
    }
    let guarded = format!("cycles: {} guarded {:?}", report.identity, report.guarded);
    Err([report.lines(), vec![guarded]].concat().join("\n"))
}

/// The actual-volume-loss control, kept apart from every host-loss cycle: a standby takes the volume over warm and
/// serves the cut; the volume is then lost, every unit after unit 0 zeroed, and the owner restarts and attaches
/// with no warm source. Unit 0 keeps the activation record a volume of the shard's generation carries, since the
/// cold attach here stands at that generation; provisioning a next-generation replacement is the reconciler's. With
/// the loss recorded as a whole-volume damage row, the cold start is legal and the run credits no retention; with no
/// row, the same cold start is a host loss treated as a volume loss and fails retention. When the history rows pass,
/// the ownership monitor's verdict is the safety verdict. Returns the safety and retention verdicts and how many
/// objects each tenure served.
pub(crate) fn volume_loss_control(recorded: bool) -> ([Verdict; 2], [usize; 2]) {
    let (world, served) = volume_loss_world(recorded);
    (volume_loss_verdicts(&world), served)
}

/// The ownership monitor's verdict over `world`'s steps as a safety verdict: a failure names the ownership step, and
/// an inconclusive judgment reads inconclusive.
fn owned(world: &World) -> Verdict {
    match world.ownership() {
        Ok(()) => Verdict::Pass,
        Err(Judged::Violation(violation)) => {
            Verdict::Fail(violation.rule, format!("ownership step {}", violation.op.0))
        }
        Err(_) => Verdict::Inconclusive("the ownership judgment was inconclusive"),
    }
}

/// The world of the actual-volume-loss control and how many objects each tenure served.
fn volume_loss_world(recorded: bool) -> (World, [usize; 2]) {
    let mut world = World::new(6, false);
    let warm = serve_taken(&mut world, c_host(), |world, serving, _| {
        serving.read_all(world).len()
    });
    world.a.media.borrow_mut()[IO_UNIT..].fill(0);
    if recorded {
        world.events.push(Event::VolumeLost);
    }
    let restarted = restart_of(&world, c_host()).expect("the owner's restart");
    let cold = serve(&mut world, restarted, Source::Cold, |world, serving, _| {
        serving.read_all(world).len()
    });
    (world, [warm, cold])
}

/// The safety and retention verdicts of the actual-volume-loss control's world. The history rows are judged first
/// and keep their routing; when they pass, the ownership monitor's verdict is the safety verdict and retention stays
/// unrun.
/// `judged_history` returns its first failing verdict. When that verdict is a `Restart` rule, retention fails by the
/// rule and safety is a fixed `Pass`; the ownership monitor's verdict enters safety when the history rows pass.
fn volume_loss_verdicts(world: &World) -> [Verdict; 2] {
    let unrun = "an actual volume loss provisions cold and credits no retention";
    match world.judged_history() {
        Ok(_) => {
            let safety = owned(world);
            if safety.passed() {
                assert!(
                    world.guarded.clean(),
                    "a passing history records no write-guard conflict and skips no slot: {:?}",
                    world.guarded
                );
            }
            [safety, Verdict::Unrun(unrun)]
        }
        Err(verdict) => match verdict.violated() {
            Some((Obligation::Restart, rule)) => {
                [Verdict::Pass, Verdict::Fail(rule, "the history".into())]
            }
            Some((_, rule)) => [
                Verdict::Fail(rule, "the history".into()),
                Verdict::Inconclusive("the history failed before its retention rules"),
            ],
            None => {
                let why = "the oracle judged the history inconclusive";
                [Verdict::Inconclusive(why), Verdict::Inconclusive(why)]
            }
        },
    }
}
