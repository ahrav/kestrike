//! The seeded churn test drives recurring and unique-key demand, fills,
//! hits, leased reads, invalidation, expiry and maintenance over the
//! simulated disk at the fixture's occupancy; each seed must publish at
//! least three times the usable capacity.
//!
//! The test owns its oracles. After every action it reconstructs the raw
//! byte categories from the allocations it made, their charged units and
//! payloads and each slot's observed state, checks live locators disjoint
//! and their complement equal to the allocator's free runs, and checks the
//! slot partition against a per-slot census.
//! Every demand for an eligible candidate is admitted, a key's first included.
//! Budget conservation holds per dimension for each churn maintenance
//! action and each request call the churn funds through `spend`. A read
//! that completes must return exactly its key's bytes.
//!
//! Named required situations and fault members must each fire across the
//! test; an unfired one fails the run with its name. After the fault
//! phase of every seed a contention-free recovery suffix must restore
//! claimable capacity and complete another publication whose readback
//! equals its bytes within an action limit derived from the fixture. A
//! fixture flag rejects every admission, and that control must fail the
//! recovery oracle. Lifetime-word races are the policy and grace Loom
//! models' kernels. All evidence is simulated-device evidence.

use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Barrier};

use super::attempt_tests::{begin, invalidate};
use super::budget::WorkBudget;
use super::config::StorageConfig;
use super::device::sim::{Event, Fault, Unwind};
use super::device::{CommandToken, DeviceStatus, IO_UNIT, Operation};
use super::evict::Commit;
use super::extent::ExtentLocator;
use super::hit_tests::last_read;
use super::ledger::EngineBudget;
use super::lookup::LookupError;
use super::maintain::{MaintainError, MaintainStage};
use super::owner::Storage;
use super::publish_tests::{
    PAGE, RETRIES, TRIES, index_config, report, storage_config, storage_from,
};
use super::register::Registration;
use super::seeded::SplitMix64;
use super::tables::{SlotIndex, SlotState};
use super::test_platform::TestPlatform;
use super::volume::{ReadEvent, ReadOp, ReadStatus, Volume, VolumeWatermarks};
use super::volume_fixture::{
    BUFFER, DEPTH, Device, SESSION, TICK, ample_io, arena_with, bootstrap, device_with, drive,
    read_back, settle,
};
use super::{
    Admitted, AllocationId, Decision, ExtentLease, FillAttempt, FillReserveError, HeaderMismatch,
    Maintained, RetireOutcome, ReturnError, WritableFill,
};
use crate::index::{IndexConfig, Key};
use crate::oracle::{
    ActionKind, Checkpoint, Custodian, KeyId, Label, Obligation, OpId, Outcome, Recorder,
    ReportKind, ReportState, ResourceKind, Row, Verdict, check,
};
use crate::sim::round::{Act, Actor, round};

pub(crate) mod long_run;
pub(crate) mod scaled;

const READERS: usize = 16;
/// Leases a churn holds across actions; every other lease ends within the
/// action that took it.
const HELD_LEASES: usize = 6;
const READ_OPS: u32 = 4;
const MIN_FREE_SLOTS: usize = 3;
pub(super) const BODY_CAP: usize = 2 * BUFFER as usize;
pub(super) const METADATA_CAP: usize = 8;
const HOT: u8 = 24;
/// The one-unit record the recovery suffix, the stale-identity successor
/// and the stray returns use: metadata and body bytes.
const SMALL: (usize, usize) = (4, 64);
/// Seeds; one `u16` bit per seed in the witnesses' reach.
const SEEDS: u64 = 12;
const _: () = assert!(SEEDS <= u16::BITS as u64);
/// Actions before the occupancy count starts.
const WARMUP: usize = 100;
const ACTIONS: usize = 1600;

/// The churn's volume and storage shape: volume units, storage slots, the
/// record chunk length and the clean reserve `R`. Every bound the churn
/// derives (the headroom target, the occupancy ceiling, the funded call
/// limit) follows from these.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Geometry {
    pub(super) units: usize,
    pub(super) metadata_units: u64,
    pub(super) slots: usize,
    pub(super) chunk_len: usize,
    pub(super) reserve: u64,
}

impl Geometry {
    /// The original fixture: one 64-bit word of units, sixteen slots and
    /// 8 KiB chunks.
    pub(super) const ORIGINAL: Self = Self {
        units: 64,
        metadata_units: 16,
        slots: 16,
        chunk_len: 8192,
        reserve: 2,
    };

    /// Larger fixtures: unit counts past one and two machine words, more
    /// slots than the original, and the other chunk lengths. The 129-unit
    /// volume's reserve of 32 units keeps its occupancy ceiling within
    /// reach of the records the churn draws; the larger-geometry test
    /// requires the fragmentation and reserve witnesses there.
    const LARGER: [Self; 2] = [
        Self {
            units: 65,
            metadata_units: 16,
            slots: 33,
            chunk_len: 4096,
            reserve: 2,
        },
        Self {
            units: 129,
            metadata_units: 16,
            slots: 33,
            chunk_len: 16384,
            reserve: 32,
        },
    ];

    /// Units one record of `payload` bytes charges: the fixed header fields
    /// and a chunk table of one 4-byte entry per chunk plus one, then the
    /// payload, rounded up to whole units.
    pub(super) const fn charged_units(&self, payload: usize) -> usize {
        let header = 108 + 4 * (payload.div_ceil(self.chunk_len) + 1);
        (header + payload).div_ceil(IO_UNIT)
    }

    /// The largest record's units.
    pub(super) const fn largest(&self) -> u64 {
        self.charged_units(METADATA_CAP + BODY_CAP) as u64
    }

    /// The headroom target `H`: the reserve plus the largest record plus
    /// one.
    const fn low_units(&self) -> u64 {
        self.reserve + self.largest() + 1
    }

    /// The fixture occupancy's free-unit ceiling: the headroom target plus
    /// one largest record.
    const fn occupied_free(&self) -> usize {
        (self.low_units() + self.largest()) as usize
    }

    /// Extents of the largest record, each one service visit to return.
    const fn largest_extents(&self) -> usize {
        (METADATA_CAP + BODY_CAP).div_ceil(super::geometry::EXTENT_PAYLOAD as usize)
    }

    /// The funded call limit for recovery: a victim behind a retained
    /// prefix below the slot count is committed within that many calls,
    /// for each of at most that many victims; each victim's extents after
    /// its first take one more call each, since a visit returns one; plus
    /// two full stage cycles.
    const fn funded_limit(&self) -> usize {
        self.slots * (self.slots + self.largest_extents() - 1) + 2 * MaintainStage::ALL.len()
    }

    const fn raw_bytes(&self) -> usize {
        (self.units + self.metadata_units as usize) * IO_UNIT
    }

    /// Words of one bit per unit.
    const fn words(&self) -> usize {
        self.units.div_ceil(u64::BITS as usize)
    }
}

/// One live extent the census checks: its slot, first unit and length as
/// the slot's locator reports them, and the units the churn charged it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Extent {
    pub(super) slot: usize,
    pub(super) start: u64,
    pub(super) len: u64,
    pub(super) charged: u64,
}

/// What the churn derived from its own allocations for one snapshot: the
/// slot count per state (free, filling, resident, retired, quarantined),
/// the payload bytes per raw category, the waste bytes and the held units.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Derived {
    pub(super) counts: [usize; 5],
    pub(super) reserved: usize,
    pub(super) resident: usize,
    pub(super) retired: usize,
    pub(super) waste: usize,
    pub(super) held: usize,
}

/// The position of free bytes in a raw category vector.
pub(super) const RAW_FREE: usize = 0;
const RAW_RESIDENT: usize = 2;
const RAW_WASTE: usize = 4;
const RAW_METADATA: usize = 5;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Reported {
    pub(super) slots: [usize; 5],
    pub(super) raw: [usize; 6],
    pub(super) total: Option<usize>,
    pub(super) free_runs: Vec<(u64, u64)>,
}

/// The simulator's life-long accepted and delivered counts and its
/// outstanding commands at one check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DeviceCounts {
    accepted: usize,
    delivered: usize,
    outstanding: usize,
}

/// At the device boundary every accepted command had its completion
/// delivered by the driver to its caller, is still pending or posted, or is
/// the one completion the seed dropped when `lost`.
fn device_reconciles(counts: DeviceCounts, lost: bool) -> Result<(), &'static str> {
    let held = counts.delivered + counts.outstanding;
    match counts.accepted.checked_sub(held) {
        None => Err("the device delivered or holds more commands than it accepted"),
        Some(unaccounted) if unaccounted != usize::from(lost) => {
            Err("accepted commands differ from those delivered or held plus the dropped completion")
        }
        Some(_) => Ok(()),
    }
}

/// The first census rule a snapshot breaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CensusFault {
    /// The extent's length differs from the units the churn charged it.
    Charge {
        slot: usize,
    },
    PastVolume {
        slot: usize,
    },
    Overlap {
        slot: usize,
    },
    /// The ledger's slot counts per state differ from the derived states.
    SlotPartition,
    ReserveSpent,
    /// The reported raw bytes per category differ from the derived free,
    /// payload and waste bytes.
    RawCategories,
    /// The raw categories' reported total differs from the volume's bytes.
    RawTotal,
    /// The allocator's free runs differ from the maximal unoccupied runs in
    /// unit order.
    FreeRuns,
}

/// The census's scratch, sized from the geometry when the churn starts so
/// a check never grows it: each slot's word and locator, the live extents,
/// one bit per occupied unit, and the free runs those bits leave.
pub(super) struct Census {
    words: Vec<u64>,
    locators: Vec<ExtentLocator>,
    pub(super) extents: Vec<Extent>,
    occupied: Vec<u64>,
    complement: Vec<(u64, u64)>,
}

impl Census {
    pub(super) fn new(geometry: Geometry) -> Self {
        Self {
            words: Vec::with_capacity(geometry.slots),
            locators: Vec::with_capacity(geometry.slots),
            extents: Vec::with_capacity(geometry.slots),
            occupied: Vec::with_capacity(geometry.words()),
            complement: Vec::with_capacity(geometry.slots + 1),
        }
    }

    fn capacity(&self) -> [usize; 5] {
        [
            self.words.capacity(),
            self.locators.capacity(),
            self.extents.capacity(),
            self.occupied.capacity(),
            self.complement.capacity(),
        ]
    }

    /// Checks the live extents against the volume and the reported ledgers:
    /// each extent has its charged length, lies inside the volume and
    /// overlaps no other; the slot counts equal the derived states; the
    /// free bytes keep the clean reserve; the raw categories equal the
    /// derived payload, waste and free bytes and total the volume; and the
    /// maximal runs of unoccupied units, in unit order, are the allocator's
    /// free runs.
    pub(super) fn judge(
        &mut self,
        geometry: Geometry,
        derived: Derived,
        reported: &Reported,
    ) -> Result<(), CensusFault> {
        let bits = u64::BITS as u64;
        self.occupied.clear();
        self.occupied.resize(geometry.words(), 0);
        for extent in &self.extents {
            let slot = extent.slot;
            if extent.len != extent.charged {
                return Err(CensusFault::Charge { slot });
            }
            if extent.start + extent.len > geometry.units as u64 {
                return Err(CensusFault::PastVolume { slot });
            }
            for unit in extent.start..extent.start + extent.len {
                let (word, bit) = ((unit / bits) as usize, unit % bits);
                if self.occupied[word] & (1 << bit) != 0 {
                    return Err(CensusFault::Overlap { slot });
                }
                self.occupied[word] |= 1 << bit;
            }
        }
        if reported.slots != derived.counts {
            return Err(CensusFault::SlotPartition);
        }
        if reported.raw[RAW_FREE] < geometry.reserve as usize * IO_UNIT {
            return Err(CensusFault::ReserveSpent);
        }
        let expected = [
            (geometry.units - derived.held) * IO_UNIT,
            derived.reserved,
            derived.resident,
            derived.retired,
            derived.waste,
            geometry.metadata_units as usize * IO_UNIT,
        ];
        if reported.raw != expected {
            return Err(CensusFault::RawCategories);
        }
        if reported.total != Some(geometry.raw_bytes()) {
            return Err(CensusFault::RawTotal);
        }
        self.complement.clear();
        let mut run: Option<(u64, u64)> = None;
        for unit in 0..geometry.units as u64 {
            let used = self.occupied[(unit / bits) as usize] & (1 << (unit % bits)) != 0;
            run = match (run, used) {
                (Some((start, len)), false) => Some((start, len + 1)),
                (None, false) => Some((unit, 1)),
                (Some(free), true) => {
                    self.complement.push(free);
                    None
                }
                (None, true) => None,
            };
        }
        self.complement.extend(run);
        if reported.free_runs != self.complement {
            return Err(CensusFault::FreeRuns);
        }
        Ok(())
    }
}
const SECOND: u64 = 1_000_000_000;

/// Required situations; each must fire at least once across the run.
#[derive(Clone, Copy, Debug)]
enum Situation {
    OccupancySustained,
    EqualFingerprintExposesNothing,
    FirstDemandPublication,
    PublicationAndHit,
    ReserveEquality,
    ReserveOneShortRefusal,
    FragmentedNoFitAboveReserve,
    HeldReaderAcrossRetirement,
    ReadCustodyAfterCancellation,
    WriteCustodyAfterCancellation,
    HeadroomStoppedInFlight,
    ZeroBudget,
    InsufficientBudget,
    ExactBudget,
    StageFills,
    StageCertify,
    StageReclaim,
    StageExpiry,
    StageHeadroom,
    RecoveryPublicationAndReadback,
}

/// Every `Situation`, in declaration order, with its name.
const SITUATIONS: [(Situation, &str); 20] = [
    (Situation::OccupancySustained, "fixture occupancy sustained"),
    (
        Situation::EqualFingerprintExposesNothing,
        "equal fingerprint exposes no other key's bytes",
    ),
    (
        Situation::FirstDemandPublication,
        "a key's first demand publishes",
    ),
    (Situation::PublicationAndHit, "publication and hit"),
    (Situation::ReserveEquality, "reserve equality"),
    (
        Situation::ReserveOneShortRefusal,
        "reserve one-short refusal",
    ),
    (
        Situation::FragmentedNoFitAboveReserve,
        "fragmented no-fit above the reserve",
    ),
    (
        Situation::HeldReaderAcrossRetirement,
        "held old reader across retirement",
    ),
    (
        Situation::ReadCustodyAfterCancellation,
        "read custody after logical cancellation",
    ),
    (
        Situation::WriteCustodyAfterCancellation,
        "write custody after logical cancellation",
    ),
    (
        Situation::HeadroomStoppedInFlight,
        "headroom stopped with retirement in flight",
    ),
    (Situation::ZeroBudget, "zero budget"),
    (Situation::InsufficientBudget, "insufficient budget"),
    (Situation::ExactBudget, "exact budget"),
    (Situation::StageFills, "stage Fills"),
    (Situation::StageCertify, "stage Certify"),
    (Situation::StageReclaim, "stage Reclaim"),
    (Situation::StageExpiry, "stage Expiry"),
    (Situation::StageHeadroom, "stage Headroom"),
    (
        Situation::RecoveryPublicationAndReadback,
        "recovery publication and readback",
    ),
];

/// Fault-map members by family. Each needs an injection and an observed
/// affected operation. The lifetime-word race is the policy and grace Loom
/// models' kernel.
#[derive(Clone, Copy, Debug)]
enum Member {
    F1ExactBound,
    F1OneShortBound,
    F1HeaderAndPadding,
    F1Fragmentation,
    F2PinAcrossRetirement,
    F2LeaseAcrossRetirement,
    F2ForeignReturn,
    F2DroppedReturn,
    F3DelayedCompletion,
    F3ReorderedCompletions,
    F3ShortCompletion,
    F3ErrorCompletion,
    F3LostCompletion,
    F3Cancellation,
    F3Deadline,
    F4StaleIdentity,
    F4Replacement,
    F4LateMark,
    F5BusyGate,
    F5PoisonedGate,
    F5UnavailableClock,
    F5CloseDuringWork,
    F6UniqueKeyFlood,
    F6EqualFingerprint,
    F7ZeroAllowance,
    F7InsufficientAllowance,
    F7ExactAllowance,
    F7Unwind,
    F8MappingFailure,
    F8UnmapRefusal,
    F8OldDeviceBytes,
    F9BlockersRemoved,
    F9RecoveryAfterFaults,
}

/// Every `Member`, in declaration order, with its name.
const FAULTS: [(Member, &str); 33] = [
    (Member::F1ExactBound, "F1 exact bound"),
    (Member::F1OneShortBound, "F1 one-short bound"),
    (Member::F1HeaderAndPadding, "F1 header and padding"),
    (Member::F1Fragmentation, "F1 fragmentation"),
    (Member::F2PinAcrossRetirement, "F2 pin across retirement"),
    (
        Member::F2LeaseAcrossRetirement,
        "F2 lease across retirement",
    ),
    (Member::F2ForeignReturn, "F2 foreign return"),
    (Member::F2DroppedReturn, "F2 dropped return"),
    (Member::F3DelayedCompletion, "F3 delayed completion"),
    (Member::F3ReorderedCompletions, "F3 reordered completions"),
    (Member::F3ShortCompletion, "F3 short completion"),
    (Member::F3ErrorCompletion, "F3 error completion"),
    (Member::F3LostCompletion, "F3 lost completion"),
    (Member::F3Cancellation, "F3 cancellation"),
    (Member::F3Deadline, "F3 deadline"),
    (Member::F4StaleIdentity, "F4 stale identity"),
    (Member::F4Replacement, "F4 replacement"),
    (Member::F4LateMark, "F4 late mark"),
    (Member::F5BusyGate, "F5 busy gate"),
    (Member::F5PoisonedGate, "F5 poisoned gate"),
    (Member::F5UnavailableClock, "F5 unavailable clock"),
    (Member::F5CloseDuringWork, "F5 close during work"),
    (Member::F6UniqueKeyFlood, "F6 unique-key flood"),
    (Member::F6EqualFingerprint, "F6 equal fingerprint"),
    (Member::F7ZeroAllowance, "F7 zero allowance"),
    (Member::F7InsufficientAllowance, "F7 insufficient allowance"),
    (Member::F7ExactAllowance, "F7 exact allowance"),
    (Member::F7Unwind, "F7 unwind"),
    (Member::F8MappingFailure, "F8 mapping failure"),
    (Member::F8UnmapRefusal, "F8 unmap refusal"),
    (Member::F8OldDeviceBytes, "F8 old device bytes"),
    (Member::F9BlockersRemoved, "F9 blockers removed"),
    (Member::F9RecoveryAfterFaults, "F9 recovery after faults"),
];

/// An allocation the churn made: its slot's incarnation, charged units and
/// payload bytes.
#[derive(Clone, Copy, Debug)]
struct Tracked {
    incarnation: u32,
    units: usize,
    payload: usize,
    /// Observed resident: a reader may have mapped it, so its return waits
    /// for grace.
    published: bool,
}

/// A published object the churn expects to read: its slot and incarnation,
/// payload bytes and deadline.
struct Object {
    slot: usize,
    incarnation: u32,
    bytes: Vec<u8>,
    deadline: u64,
}

// Each table's row index is its enumerator's discriminant.
const _: () = {
    let mut i = 0;
    while i < SITUATIONS.len() {
        assert!(SITUATIONS[i].0 as usize == i);
        i += 1;
    }
    let mut i = 0;
    while i < FAULTS.len() {
        assert!(FAULTS[i].0 as usize == i);
        i += 1;
    }
};

/// What the run observed, by situation and fault member, with how often,
/// and which seeds reached each, one bit per seed.
struct Witnesses {
    situations: [usize; SITUATIONS.len()],
    injected: [usize; FAULTS.len()],
    affected: [usize; FAULTS.len()],
    seed: u64,
    situation_seeds: [u16; SITUATIONS.len()],
    member_seeds: [u16; FAULTS.len()],
}

impl Default for Witnesses {
    fn default() -> Self {
        Self {
            situations: [0; SITUATIONS.len()],
            injected: [0; FAULTS.len()],
            affected: [0; FAULTS.len()],
            seed: 0,
            situation_seeds: [0; SITUATIONS.len()],
            member_seeds: [0; FAULTS.len()],
        }
    }
}

impl Witnesses {
    fn saw(&mut self, situation: Situation) {
        self.situations[situation as usize] += 1;
        // The phases after the seeds record no reach.
        if self.seed < SEEDS {
            self.situation_seeds[situation as usize] |= 1 << self.seed;
        }
    }

    /// Records a fault's injection.
    fn inject(&mut self, member: Member) {
        self.injected[member as usize] += 1;
    }

    fn inject_if(&mut self, injected: bool, member: Member) {
        if injected {
            self.inject(member);
        }
    }

    /// Records an operation the injected fault affected, as the caller
    /// observed it.
    fn affect(&mut self, member: Member) {
        self.affected[member as usize] += 1;
        if self.seed < SEEDS {
            self.member_seeds[member as usize] |= 1 << self.seed;
        }
    }

    /// An injection whose affected operation the caller observed at once.
    fn fault(&mut self, member: Member) {
        self.inject(member);
        self.affect(member);
    }

    /// Adds another run's counts and reaching seeds.
    fn merge(&mut self, other: &Self) {
        for (mine, theirs) in self.situations.iter_mut().zip(other.situations) {
            *mine += theirs;
        }
        for (mine, theirs) in self.injected.iter_mut().zip(other.injected) {
            *mine += theirs;
        }
        for (mine, theirs) in self.affected.iter_mut().zip(other.affected) {
            *mine += theirs;
        }
        for (mine, theirs) in self.situation_seeds.iter_mut().zip(other.situation_seeds) {
            *mine |= theirs;
        }
        for (mine, theirs) in self.member_seeds.iter_mut().zip(other.member_seeds) {
            *mine |= theirs;
        }
    }

    /// Every situation that never fired and every fault member never both
    /// injected and affected, by name.
    fn unfired(&self) -> Vec<&'static str> {
        let situations = SITUATIONS
            .iter()
            .zip(self.situations)
            .filter(|(_, count)| *count == 0)
            .map(|((_, name), _)| *name);
        let members = FAULTS
            .iter()
            .zip(self.injected.iter().zip(self.affected))
            .filter(|(_, (injected, affected))| **injected == 0 || *affected == 0)
            .map(|((_, name), _)| *name);
        situations.chain(members).collect()
    }

    /// Fails with every unfired name, then reports the rarest witnesses.
    fn require_all(&self) {
        let missing = self.unfired();
        assert!(missing.is_empty(), "unfired witnesses: {missing:?}");
        // The seeded witnesses by how many seeds reached them.
        let situations = SITUATIONS.iter().map(|(_, name)| *name);
        let members = FAULTS.iter().map(|(_, name)| *name);
        let mut reach: Vec<_> = situations
            .zip(self.situation_seeds)
            .chain(members.zip(self.member_seeds))
            .filter(|(_, seeds)| *seeds != 0)
            .map(|(name, seeds)| (seeds.count_ones(), name))
            .collect();
        reach.sort_unstable();
        eprintln!(
            "narrowest seeded witnesses (seeds reached): {:?}",
            &reach[..8]
        );
    }
}

/// Runs `f`, asserting the thread's heap allocation counter unchanged
/// across it.
fn no_alloc<T>(what: &str, f: impl FnOnce() -> T) -> T {
    let before = crate::instrument::allocations();
    let out = f();
    assert_eq!(crate::instrument::allocations(), before, "{what} allocated");
    out
}

/// Runs `f` with `hook` installed between a removal step's selection and
/// its commit.
fn with_commit_hook<T>(hook: fn(), f: impl FnOnce() -> T) -> T {
    super::evict::INTERPOSE_BEFORE_COMMIT.with(|cell| cell.set(Some(hook)));
    let out = f();
    super::evict::INTERPOSE_BEFORE_COMMIT.with(|cell| cell.set(None));
    out
}

/// Runs `f` with `hook` installed in front of every maintenance stage.
fn with_stage_hook<T>(hook: fn(MaintainStage), f: impl FnOnce() -> T) -> T {
    super::maintain::INTERPOSE_BEFORE_STAGE.with(|cell| cell.set(Some(hook)));
    let out = f();
    super::maintain::INTERPOSE_BEFORE_STAGE.with(|cell| cell.set(None));
    out
}

fn budget() -> WorkBudget {
    WorkBudget::new(1 << 12)
}

/// Asserts every dimension of `budget` conserved against what it started
/// with: spent plus remaining.
fn conserved(budget: &WorkBudget, steps: usize, operations: usize, bytes: usize) {
    let counters = budget.counters();
    let spent = counters.comparisons
        + counters.coordination_attempts
        + counters.visits
        + counters.updates
        + counters.hashes;
    assert_eq!(spent + budget.remaining(), steps, "CPU conservation");
    assert_eq!(
        budget.operations_used() + budget.operations_remaining(),
        operations,
        "operation conservation"
    );
    assert_eq!(
        budget.bytes_used() + budget.bytes_remaining(),
        bytes,
        "byte conservation"
    );
}

/// Runs a request call with a fresh CPU allowance and checks it conserved.
fn spend<T>(f: impl FnOnce(&mut WorkBudget) -> T) -> T {
    let mut budget = budget();
    let out = f(&mut budget);
    conserved(&budget, 1 << 12, 0, 0);
    out
}

/// The churn's storage over `geometry`, hashing through a fixed seam so a
/// seed replays exactly; with `collide`, the seam fingerprints a key by
/// bits 4 to 7 of its number, so key numbers agreeing in those bits share
/// one whole fingerprint.
pub(super) fn churn_storage(geometry: Geometry, collide: bool) -> &'static Storage<TestPlatform> {
    let fills = [2usize];
    let limits = [geometry.slots];
    let index = IndexConfig {
        fills: &fills,
        ..index_config(&limits, (1, 1), 1)
    };
    let mut volume = crate::storage::test_volume_with(
        geometry.units * IO_UNIT,
        geometry.metadata_units,
        geometry.slots,
    );
    volume.reserve_units = geometry.reserve;
    volume.record.chunk_len = geometry.chunk_len as u32;
    // Room for a read held across another read, beside one a dropped
    // completion holds for the volume's lifetime.
    volume.read_ops = READ_OPS;
    volume.read_commands = READ_OPS;
    volume.maintenance = Some(VolumeWatermarks {
        low_units: geometry.low_units(),
        min_free_slots: MIN_FREE_SLOTS,
        retired_units: u64::MAX,
    });
    let config = StorageConfig {
        body_cap: BODY_CAP,
        metadata_cap: Some(METADATA_CAP),
        lease_limit: 64,
        reader_limit: READERS,
        volume,
        ..storage_config(geometry.slots)
    };
    let mut storage = storage_from(&config, &index, TestPlatform::heap(PAGE));
    let seam = if collide {
        super::publish_tests::one_fingerprint
    } else {
        distinct
    };
    super::publish_tests::install_seam(&mut storage, seam);
    storage.platform.ticks(&[Some(SECOND)]);
    Box::leak(Box::new(storage))
}

/// A four-slot storage that foreign returns are handed to.
fn small_storage() -> &'static Storage<TestPlatform> {
    let config = StorageConfig {
        volume: crate::storage::test_volume(8 * IO_UNIT, 4),
        ..storage_config(4)
    };
    Box::leak(Box::new(storage_from(
        &config,
        &index_config(&[4], (1, 1), 1),
        TestPlatform::heap(PAGE),
    )))
}

/// A seam that gives every key number its own fingerprint: the SplitMix64
/// finalizer of the number `key_of` wrote.
fn distinct(key: &Key) -> u64 {
    let mut z = u64::from(u32::from_le_bytes([key[0], key[1], key[2], key[3]]));
    z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn key_of(n: u32) -> Key {
    let mut key = [0u8; 32];
    key[..4].copy_from_slice(&n.to_le_bytes());
    key[31] = 0xC7;
    key
}

/// The state the stale-identity hook shares with the churn: the resident
/// keys by slot, the removal call's first selected victim, the successor
/// the hook published in its place, the victim's immediate commit result
/// with the successor's slot state right after it, and whether a later
/// commit of the call evicted the successor.
struct Stale {
    storage: &'static Storage<TestPlatform>,
    /// The writer generation the successor binds under: the churn's volume session.
    session: u64,
    keys: Vec<(usize, Key)>,
    selected: Option<AllocationId>,
    successor: Option<(AllocationId, Key)>,
    immediate: Option<(Commit, (SlotState, u32))>,
    successor_evicted: bool,
}

impl Stale {
    fn new(storage: &'static Storage<TestPlatform>, session: u64, keys: Vec<(usize, Key)>) -> Self {
        Self {
            storage,
            session,
            keys,
            selected: None,
            successor: None,
            immediate: None,
            successor_evicted: false,
        }
    }
}

/// Sees each removal step of a call carrying the stale-identity hook: the
/// first selection names the victim the hook replaces; once the hook
/// published a successor, the replaced victim's commit records its
/// immediate result beside the successor's slot state, and a later commit
/// whose selected victim is the successor marks it evicted.
fn observe_commit(victim: AllocationId, commit: Option<Commit>) {
    STALE.with(|cell| {
        let mut cell = cell.borrow_mut();
        let Some(stale) = cell.as_mut() else {
            return;
        };
        let Some(commit) = commit else {
            stale.selected.get_or_insert(victim);
            return;
        };
        let Some((successor, _)) = stale.successor else {
            return;
        };
        if Some(victim) == stale.selected && stale.immediate.is_none() {
            let state = stale
                .storage
                .slot_state(SlotIndex(successor.slot_index()))
                .unwrap();
            stale.immediate = Some((commit, state));
        } else if victim == successor && matches!(commit, Commit::Evicted { .. }) {
            stale.successor_evicted = true;
        }
    });
}

/// What one stale-identity call showed of its successor `B`: the replaced
/// victim's immediate commit result and `B`'s slot state right after it,
/// whether a later commit of the call evicted `B`, whether a reader held `B`,
/// `B`'s slot state after the call, and what a lookup of its key then
/// answered: `Some(Some(id))` for a lease on `id`, `Some(None)` for a miss
/// or an expiry, and `None` when no lookup ran, because `B` left residence
/// or a later commit evicted it, or when the lookup answered nothing
/// informative.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StaleObservation {
    successor: AllocationId,
    immediate: Option<(Commit, (SlotState, u32))>,
    later_evicted: bool,
    held: bool,
    after: (SlotState, u32),
    mapped: Option<Option<AllocationId>>,
}

/// How a successor fared after the stale commit, when the commit spared it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StaleLifecycle {
    /// `B` stayed resident and a lookup acquired it.
    Mapped,
    /// `B` stayed resident and the lookup answered nothing informative.
    Unobserved,
    /// A later commit of the call evicted `B` by its own identity; `B` is
    /// retired or, unheld, reclaimed at its incarnation.
    LaterRemoved,
}

/// Judges a stale commit under a completed, uncontended replacement and a
/// funded commit: the commit is `Absent` and leaves `B` resident at its
/// incarnation; afterwards `B` is resident at its incarnation and a lookup
/// acquires it or answers nothing informative, or a later commit evicted it
/// by its own identity and it is retired, or reclaimed only when no reader
/// held it.
fn classify_stale(seen: StaleObservation) -> Result<StaleLifecycle, &'static str> {
    let incarnation = seen.successor.incarnation();
    let Some((commit, right_after)) = seen.immediate else {
        return Err("the stale commit was not observed");
    };
    if commit != Commit::Absent {
        return Err("a stale commit under a completed replacement was not Absent");
    }
    if right_after != (SlotState::Resident, incarnation) {
        return Err("a stale commit unmapped its successor at its commit");
    }
    if seen.later_evicted {
        return match seen.after {
            (SlotState::Retired, at) if at == incarnation => Ok(StaleLifecycle::LaterRemoved),
            (SlotState::Free, at) if at == incarnation && !seen.held => {
                Ok(StaleLifecycle::LaterRemoved)
            }
            (SlotState::Free, at) if at == incarnation => Err("a held successor was reclaimed"),
            _ => Err("an evicted successor left an unexpected state"),
        };
    }
    if seen.after != (SlotState::Resident, incarnation) {
        return Err("a successor no later commit evicted left residence");
    }
    match seen.mapped {
        Some(Some(id)) if id == seen.successor => Ok(StaleLifecycle::Mapped),
        Some(Some(_)) => Err("a lookup acquired another identity under the successor's key"),
        Some(None) => Err("a lookup missed a resident successor"),
        None => Ok(StaleLifecycle::Unobserved),
    }
}

/// What a lookup of the successor's key says of its mapping: a lease names
/// the identity it acquired, a miss or an expiry denies any mapping, and
/// every other refusal answers nothing about it.
fn lookup_answer(lookup: Result<AllocationId, LookupError>) -> Option<Option<AllocationId>> {
    match lookup {
        Ok(id) => Some(Some(id)),
        Err(LookupError::Missing | LookupError::Expired) => Some(None),
        Err(
            LookupError::Contended
            | LookupError::LeaseLimit
            | LookupError::RetainLimit
            | LookupError::ClockUnavailable
            | LookupError::Closed,
        ) => None,
    }
}

/// A helper thread holding the pool gate until this guard drops, which
/// releases and joins it, also while a failure unwinds.
struct Holder(Arc<Barrier>, Option<std::thread::JoinHandle<()>>);

impl Drop for Holder {
    fn drop(&mut self) {
        self.0.wait();
        if let Some(thread) = self.1.take() {
            let _ = thread.join();
        }
    }
}

thread_local! {
    static STALE: RefCell<Option<Stale>> = const { RefCell::new(None) };
    static LATE: RefCell<Option<(&'static Storage<TestPlatform>, Option<Holder>)>> =
        const { RefCell::new(None) };
    static CLOSING: Cell<Option<&'static Storage<TestPlatform>>> = const { Cell::new(None) };
}

/// Runs between a removal step's selection and its commit: when the
/// selected victim is an unheld resident at its selected incarnation,
/// invalidates its key and publishes a successor under the same key, so the
/// commit carries a stale identity.
fn replace_victim() {
    STALE.with(|cell| {
        let mut cell = cell.borrow_mut();
        let stale = cell.as_mut().unwrap();
        let storage = stale.storage;
        let live = storage.live_pool().unwrap();
        let Some(selected) = stale.selected else {
            return;
        };
        let slot = selected.slot_index();
        let unheld_resident = storage.slot_state(SlotIndex(slot)).unwrap()
            == (SlotState::Resident, selected.incarnation())
            && live.refs(slot) == 1;
        if !unheld_resident {
            return;
        }
        let Some(&(_, key)) = stale.keys.iter().find(|(s, _)| *s == slot) else {
            return;
        };
        invalidate(storage, &key).unwrap();
        let mut budget = budget();
        let Ok(mut allocation) = storage.reserve(Some(SMALL.0), Some(SMALL.1), &mut budget) else {
            return;
        };
        allocation.mark_written();
        let Ok(completed) = allocation.complete_under(
            key,
            u64::MAX,
            super::tables::Naming {
                session: stale.session,
                version: 0,
            },
            &mut budget,
        ) else {
            return;
        };
        stale.successor = completed
            .publish(TRIES, &mut budget)
            .ok()
            .map(|id| (id, key));
    });
}

/// Runs before a removal commit: another thread takes the pool gate and
/// holds it until the churn releases it after the call, so the victim's
/// retirement parks and the call-end mark try finds the gate busy.
fn hold_pool_gate() {
    LATE.with(|cell| {
        let mut cell = cell.borrow_mut();
        let (storage, holder) = cell.as_mut().unwrap();
        let storage = *storage;
        let barrier = Arc::new(Barrier::new(2));
        let shared = Arc::clone(&barrier);
        let thread = std::thread::spawn(move || {
            let guard = storage.live_pool().unwrap().lock().unwrap();
            shared.wait();
            shared.wait();
            drop(guard);
        });
        barrier.wait();
        *holder = Some(Holder(barrier, Some(thread)));
    });
}

/// Closes the storage in front of the Reclaim stage.
fn close_before_reclaim(stage: MaintainStage) {
    if stage == MaintainStage::Reclaim {
        CLOSING.with(Cell::get).unwrap().close();
    }
}

/// Panics in front of the Certify stage, poisoning the root gate.
fn panic_before_certify(stage: MaintainStage) {
    if stage == MaintainStage::Certify {
        panic!("an injected panic inside maintenance");
    }
}

/// A pinned reader and the published slots it cannot protect: those
/// unmapped when it started. Only these may return while it holds.
struct Pin {
    _registration: Registration<'static, TestPlatform>,
    releasable: BTreeSet<(usize, u32)>,
}

/// How one hit's read command is driven.
#[derive(Clone, Copy)]
enum ReadFault {
    Deadline,
    Error,
    Short,
    Cancel,
    Reorder,
    Lost,
    Clean,
}

impl ReadFault {
    /// The read's deadline: a past one for the faults that wait on it.
    fn deadline(self) -> u64 {
        match self {
            Self::Deadline | Self::Lost => 10,
            _ => u64::MAX,
        }
    }
}

/// One seed's churn.
struct Churn {
    storage: &'static Storage<TestPlatform>,
    dev: Device<'static, 'static>,
    reader: Registration<'static, TestPlatform>,
    /// The action stream, apart from the draws inside each action, so an
    /// edit inside one action leaves the schedule of later actions intact.
    actions: SplitMix64,
    rng: SplitMix64,
    geometry: Geometry,
    /// Each slot's tracked allocation, one entry per slot of the geometry.
    tracked: Vec<Option<Tracked>>,
    census: Census,
    /// The objects the churn expects to read, sorted by key.
    objects: Vec<(Key, Object)>,
    held: Vec<(Key, ExtentLease<'static, TestPlatform>)>,
    pinned: Option<Pin>,
    now: u64,
    flood: u32,
    published_units: usize,
    reject_all: bool,
    collide: bool,
    /// Keys a stale-identity successor last published, without device bytes.
    unwritten: BTreeSet<Key>,
    other: &'static Storage<TestPlatform>,
    /// A read completion was dropped this seed.
    lost: bool,
    /// A busy pool gate left the last call's eviction mark pending.
    mark_late: bool,
    /// Every key the churn published; the pin looks each one up.
    published: BTreeSet<Key>,
    /// Identities of the stale-identity successors, published without
    /// device bytes.
    successors: BTreeSet<(usize, u32)>,
    /// Objects the current action may remove; `check` fails on more.
    may_drop: usize,
    /// Checks after warmup with the volume at the fixture occupancy, and
    /// all checks after warmup.
    occupied: (usize, usize),
    seed: u64,
    action: usize,
    /// The phase running, for failure diagnostics.
    phase: &'static str,
    content: Option<Vec<u8>>,
    /// Bytes of capacity the device's stores held at construction.
    built: usize,
}

impl Drop for Churn {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!(
                "churn failed: seed {} reject_all {} collide {} phase {} action {}",
                self.seed, self.reject_all, self.collide, self.phase, self.action
            );
        }
    }
}

impl Churn {
    fn new(seed: u64, reject_all: bool, collide: bool) -> Self {
        Self::over(Geometry::ORIGINAL, seed, reject_all, collide, &[])
    }

    /// A churn over `geometry` whose device starts with `image` at offset
    /// zero, written before the volume attaches.
    fn over(geometry: Geometry, seed: u64, reject_all: bool, collide: bool, image: &[u8]) -> Self {
        let storage = churn_storage(geometry, collide);
        let arena = Box::leak(Box::new(arena_with(6, 6)));
        let (disk, control) = device_with(7, BUFFER);
        control.write_device(0, image);
        let mut volume = Volume::attach(
            storage,
            arena,
            disk,
            crate::storage::portable::scripted::ScriptedClock::trusted(),
            crate::storage::ServingAuthority::fixture(),
            DEPTH,
            TICK,
            &mut EngineBudget::new(1 << 24),
        )
        .map_err(|(error, _)| error)
        .expect("attach");
        bootstrap(&mut volume, &control);
        let built = control.footprint().reserved.total();
        Self {
            storage,
            dev: Device { volume, control },
            reader: storage.register().unwrap(),
            actions: SplitMix64::new(seed ^ 0xAC71_0000),
            rng: SplitMix64::new(seed),
            geometry,
            tracked: vec![None; geometry.slots],
            census: Census::new(geometry),
            objects: Vec::new(),
            held: Vec::new(),
            pinned: None,
            now: SECOND,
            flood: 1000,
            published_units: 0,
            reject_all,
            collide,
            unwritten: BTreeSet::new(),
            other: small_storage(),
            lost: false,
            mark_late: false,
            published: BTreeSet::new(),
            successors: BTreeSet::new(),
            may_drop: 0,
            occupied: (0, 0),
            seed,
            action: 0,
            phase: "churn",
            content: None,
            built,
        }
    }

    /// Bytes of capacity the device's stores grew past their construction
    /// capacity.
    fn device_growth(&self) -> usize {
        self.dev
            .control
            .footprint()
            .reserved
            .total()
            .saturating_sub(self.built)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.rng.next_u64() % n
    }

    fn free_units(&self) -> u64 {
        (self.storage.pool_report().unwrap().ledger.unwrap().raw.free / IO_UNIT) as u64
    }

    /// Records an allocation the churn made of `payload` bytes.
    fn track(&mut self, id: AllocationId, payload: usize) {
        // A slot returned and reclaimed within one action is checked here,
        // since `check` never sees it free.
        if let Some(prior) = self.tracked[id.slot_index()] {
            self.returned(id.slot_index(), prior);
        }
        let tracked = Tracked {
            incarnation: id.incarnation(),
            units: self.geometry.charged_units(payload),
            payload,
            published: false,
        };
        self.tracked[id.slot_index()] = Some(tracked);
    }

    fn service_fills(&self) {
        let storage = self.storage;
        let _ = spend(|b| storage.service_fills(crate::index::ShardIndex(0), TRIES, b));
    }

    /// Drops objects whose incarnation is no longer resident in the slot
    /// words of the census's last snapshot, or whose word records a
    /// retirement still awaiting service: eviction, expiry, invalidation or
    /// replacement removed them; the action's own removals bound how many
    /// may go.
    fn reconcile_objects(&mut self) {
        let before = self.objects.len();
        let words = &self.census.words;
        self.objects.retain(|(_, object)| {
            let word = words[object.slot];
            (super::word::state(word), super::word::incarnation(word))
                == (SlotState::Resident, object.incarnation)
                && word & super::word::ABANDONED == 0
        });
        let dropped = before - self.objects.len();
        assert!(
            dropped <= self.may_drop,
            "{dropped} objects lost where the action removes at most {}",
            self.may_drop
        );
        self.may_drop = 0;
    }

    /// A published allocation's slot returned: a pin held since before its
    /// mapping ended must still hold it.
    fn returned(&self, slot: usize, gone: Tracked) {
        if gone.published
            && let Some(pin) = &self.pinned
        {
            assert!(
                pin.releasable.contains(&(slot, gone.incarnation)),
                "slot {slot}: a retirement under a pin returned before its certificate"
            );
        }
    }

    /// The published retirements waiting behind the held pin.
    fn pinned_retirements(&self) -> Vec<(usize, u32)> {
        let Some(pin) = &self.pinned else {
            return Vec::new();
        };
        self.tracked
            .iter()
            .enumerate()
            .filter_map(|(slot, tracked)| tracked.map(|tracked| (slot, tracked)))
            .filter(|(slot, tracked)| {
                tracked.published
                    && !pin.releasable.contains(&(*slot, tracked.incarnation))
                    && self.storage.slot_state(SlotIndex(*slot)).unwrap()
                        == (SlotState::Retired, tracked.incarnation)
            })
            .map(|(slot, tracked)| (slot, tracked.incarnation))
            .collect()
    }

    /// Every oracle, after one action. Returns the snapshot's reported
    /// ledgers and the device counts, so two checks at one stopped boundary
    /// can be compared.
    fn check(&mut self) -> (Reported, DeviceCounts) {
        let storage = self.storage;
        let live = storage.live_pool().unwrap();
        let geometry = self.geometry;
        let before = self.census.capacity();
        // Every oracle reads one snapshot, taken under one gate hold: each
        // slot's word and locator, both ledgers and the allocator's free
        // runs.
        self.census.words.clear();
        self.census.locators.clear();
        let (slots, raw, free_set) = {
            let mut access = live.lock().unwrap();
            for record in live.records().iter().take(geometry.slots) {
                self.census.words.push(record.ident.load(Ordering::Relaxed));
                self.census.locators.push(record.locator());
            }
            let mut tables = access.tables();
            let slots = tables.state.ledger;
            let extents = tables.extents();
            let (raw, free_set) = (extents.ledger(), extents.free_set());
            (slots, raw, free_set)
        };
        self.reconcile_objects();
        // One pass takes the slot census and reconstructs the raw categories
        // from the churn's own allocations; the census then checks the live
        // extents against the volume and the allocator.
        let mut derived = Derived::default();
        self.census.extents.clear();
        for slot in 0..geometry.slots {
            let word = self.census.words[slot];
            let (state, incarnation) = (super::word::state(word), super::word::incarnation(word));
            derived.counts[state as usize] += 1;
            if matches!(state, SlotState::Free | SlotState::Quarantined) {
                if let Some(gone) = self.tracked[slot].take() {
                    self.returned(slot, gone);
                }
                continue;
            }
            let tracked = self.tracked[slot]
                .as_mut()
                .unwrap_or_else(|| panic!("slot {slot}: an allocation the churn did not make"));
            assert_eq!(
                tracked.incarnation, incarnation,
                "slot {slot}'s incarnation"
            );
            tracked.published |= state == SlotState::Resident;
            match state {
                SlotState::Filling => derived.reserved += tracked.payload,
                SlotState::Resident => derived.resident += tracked.payload,
                _ => derived.retired += tracked.payload,
            }
            derived.waste += tracked.units * IO_UNIT - tracked.payload;
            derived.held += tracked.units;
            let locator = self.census.locators[slot];
            self.census.extents.push(Extent {
                slot,
                start: locator.start_unit(),
                len: u64::from(locator.len_units()),
                charged: tracked.units as u64,
            });
        }
        let reported = Reported {
            slots: [
                slots.free,
                slots.filling,
                slots.resident,
                slots.retired,
                slots.quarantined,
            ],
            raw: [
                raw.free,
                raw.reserved,
                raw.resident,
                raw.retired,
                raw.waste,
                raw.metadata,
            ],
            total: raw.total().ok(),
            free_runs: free_set,
        };
        if let Err(fault) = self.census.judge(geometry, derived, &reported) {
            panic!("census: {fault:?}");
        }
        let device = self.device_counts();
        if let Err(rule) = device_reconciles(device, self.lost) {
            panic!("{rule}: {device:?}");
        }
        assert_eq!(
            self.census.capacity(),
            before,
            "the census scratch grew during a check"
        );
        if self.action >= WARMUP {
            self.occupied.1 += 1;
            if raw.free <= geometry.occupied_free() * IO_UNIT {
                self.occupied.0 += 1;
            }
        }
        (reported, device)
    }

    /// The simulator's life-long accepted and delivered command counts and
    /// its currently pending or posted commands, read without its bounded
    /// event ring.
    fn device_counts(&self) -> DeviceCounts {
        let control = &self.dev.control;
        DeviceCounts {
            accepted: control.accepted(Operation::Read) + control.accepted(Operation::Write),
            delivered: control.delivered(Operation::Read) + control.delivered(Operation::Write),
            outstanding: control.outstanding(),
        }
    }

    /// A drawn payload size: a record at the reserve's boundary, one whose
    /// header carries it past a unit, or a uniform one.
    fn draw_sizes(&mut self) -> (usize, usize) {
        let free = self.free_units();
        if self.below(6) == 0
            && let Some(target) = (free + self.below(2)).checked_sub(self.geometry.reserve)
            && (1..=8).contains(&target)
        {
            // Equal to the free units less the reserve, or one unit more.
            return (0, target as usize * IO_UNIT - 200);
        }
        if self.below(4) == 0 {
            return (4, IO_UNIT - 8);
        }
        (
            self.below(METADATA_CAP as u64 + 1) as usize,
            1 + self.below(BODY_CAP as u64) as usize,
        )
    }

    /// Begins an attempt for `key`, servicing the fill table once when an
    /// earlier attempt's record still occupies it.
    fn begin(&self, key: &Key) -> Option<FillAttempt<'static, TestPlatform>> {
        begin(self.storage, key).ok().or_else(|| {
            self.service_fills();
            begin(self.storage, key).ok()
        })
    }

    fn decide(&self, (metadata, body): (usize, usize)) -> Option<Admitted> {
        let storage = self.storage;
        let decision = no_alloc("a decision", || {
            storage.decide_admission(Some(metadata), Some(body))
        });
        let Decision::Admit(admitted) = decision else {
            panic!("an eligible candidate decided {decision:?}");
        };
        assert_eq!(
            super::writable_tests::charge(storage, metadata, body),
            self.geometry.charged_units(metadata + body) as u64,
            "the admitted object's units"
        );
        (!self.reject_all).then_some(admitted)
    }

    /// Checks a refused reservation against the free units it saw.
    fn refused(&self, error: FillReserveError, free: u64, units: usize, w: &mut Witnesses) {
        let needed = units as u64 + self.geometry.reserve;
        match error {
            FillReserveError::CleanReserve => {
                assert!(free < needed);
                if free + 1 == needed {
                    w.saw(Situation::ReserveOneShortRefusal);
                    w.fault(Member::F1OneShortBound);
                }
            }
            FillReserveError::PayloadFull => {
                assert!(free >= needed);
                w.saw(Situation::FragmentedNoFitAboveReserve);
                w.fault(Member::F1Fragmentation);
            }
            FillReserveError::ObjectSlotsFull => {}
            // A departed fill's claim stays counted until the fill service
            // pass, so a free slot can meet a full index.
            FillReserveError::IndexFull => {
                let report = report(self.storage, 0);
                assert!(
                    report.visible + report.reserved >= self.geometry.slots,
                    "IndexFull with V = {} and P_index = {} below N = {}",
                    report.visible,
                    report.reserved,
                    self.geometry.slots
                );
            }
            other => panic!("reservation refused {other:?}"),
        }
    }

    /// Write custody after logical cancellation: an aborted fill whose
    /// write is held keeps its extent charged through service.
    fn abort_with_held_write(
        &mut self,
        mut fill: WritableFill<'static, 'static, TestPlatform>,
        bytes: &[u8],
        w: &mut Witnesses,
    ) {
        let slot = fill.id().slot_index();
        fill.receive(&mut self.dev.volume, bytes, &mut ample_io())
            .unwrap();
        let held = self.hold_writes();
        fill.abort();
        if !held.is_empty() {
            assert!(self.storage.live_pool().unwrap().refs(slot) > 0);
            let storage = self.storage;
            let _ = spend(|b| storage.service(b));
            assert_ne!(
                self.storage.slot_state(SlotIndex(slot)).unwrap().0,
                SlotState::Free,
                "an extent freed under an outstanding write"
            );
            w.saw(Situation::WriteCustodyAfterCancellation);
        }
        for token in held {
            self.dev.control.release(token);
        }
        settle(&mut self.dev.volume, &self.dev.control);
    }

    /// One demand for `key`, with the payload's sizes fixed or drawn when
    /// `None`: a decision, and for an admission a fill, publication and the
    /// object recorded.
    fn demand(&mut self, key: Key, sizes: Option<(usize, usize)>, w: &mut Witnesses) {
        let (metadata, body) = match sizes {
            Some(sizes) => sizes,
            None => self.draw_sizes(),
        };
        let Some(attempt) = self.begin(&key) else {
            return;
        };
        let Some(admitted) = self.decide((metadata, body)) else {
            attempt.abort();
            self.service_fills();
            return;
        };
        let payload = metadata + body;
        let units = self.geometry.charged_units(payload);
        let free = self.free_units();
        let reserved = no_alloc("a reservation", || {
            spend(|b| attempt.reserve_storage(admitted, Some(metadata), Some(body), TRIES, b))
        });
        let mut fill = match reserved {
            Ok(fill) => fill,
            Err(error) => {
                self.refused(error, free, units, w);
                return;
            }
        };
        if free == units as u64 + self.geometry.reserve {
            w.saw(Situation::ReserveEquality);
            w.fault(Member::F1ExactBound);
        }
        assert!(
            self.free_units() >= self.geometry.reserve,
            "a claim spent the clean reserve"
        );
        let id = fill.id();
        assert_eq!(fill.layout().units(), units, "charged units");
        self.track(id, payload);
        let seeded = super::writable_tests::bytes(payload, self.rng.next_u64());
        let bytes = match self.content.take() {
            Some(content) if content.len() == payload => content,
            _ => seeded,
        };
        if sizes.is_none() && self.below(16) == 0 {
            self.abort_with_held_write(fill, &bytes, w);
            return;
        }
        self.fill_object(&mut fill, &bytes);
        // Some deadlines fall inside a second, so expiry's whole-second
        // conversion is exercised.
        let deadline = if self.below(8) == 0 {
            self.now + (1 + self.below(3)) * SECOND + self.below(2) * (SECOND / 2)
        } else {
            u64::MAX
        };
        let replaced = self.holds(&key);
        // A publication displaces at most one object. The key's own is
        // rewritten in place below, so `check` sees no loss from it; another
        // key's object that an equal fingerprint routes to is the one loss
        // the action may show.
        self.may_drop = usize::from(!replaced);
        let volume = &mut self.dev.volume;
        no_alloc("a publication", || {
            spend(|b| fill.publish(volume, deadline, TRIES, b))
        })
        .unwrap();
        w.inject_if(replaced, Member::F4Replacement);
        if replaced {
            // The key now resolves to the new incarnation.
            let lease = super::lookup_tests::lookup(&mut self.reader, &key, 4).unwrap();
            assert_eq!(lease.id(), id, "a replaced key resolved to its old object");
            w.affect(Member::F4Replacement);
        }
        if units > payload.div_ceil(IO_UNIT) {
            // The header and padding carried the record past its payload's
            // units, and the charged units above matched.
            w.fault(Member::F1HeaderAndPadding);
        }
        self.published_units += units;
        self.published.insert(key);
        let object = Object {
            slot: id.slot_index(),
            incarnation: id.incarnation(),
            bytes,
            deadline,
        };
        match self.find(&key) {
            Ok(at) => self.objects[at].1 = object,
            Err(at) => self.objects.insert(at, (key, object)),
        }
    }

    /// Streams `bytes` into `fill` and submits every unit, with the heap
    /// counter unchanged across the receives and device ticks, then settles
    /// the writes.
    fn fill_object(
        &mut self,
        fill: &mut WritableFill<'static, 'static, TestPlatform>,
        bytes: &[u8],
    ) {
        let mut out = Vec::with_capacity(64);
        let dev = &mut self.dev;
        let mut taken = 0;
        for _ in 0..4096 {
            let submitted = no_alloc("a fill's receives", || {
                if let Ok(count) = fill.receive(&mut dev.volume, &bytes[taken..], &mut ample_io()) {
                    taken += count;
                }
                let progress = fill.progress(&dev.volume);
                taken == bytes.len() && progress.submitted_units == progress.len_units
            });
            if submitted {
                settle(&mut dev.volume, &dev.control);
                return;
            }
            // Each action counts its own heap use, so the round's bookkeeping stays outside the check.
            let mut tick = || no_alloc("a fill's receives", || dev.control.tick(64));
            let mut poll = || {
                no_alloc("a fill's receives", || {
                    let _ = dev.volume.poll_storage(0, &mut out);
                    out.clear();
                })
            };
            round(&mut [
                Act::new(Actor::Disk(0), &mut tick),
                Act::new(Actor::Volume(0), &mut poll),
            ]);
        }
        panic!("the fill never submitted its payload");
    }

    /// Holds every write the device accepted and has not completed.
    fn hold_writes(&mut self) -> Vec<CommandToken> {
        let mut submitted = Vec::new();
        for event in self.dev.control.events() {
            match event {
                Event::Submitted(token, Operation::Write) => submitted.push(token),
                Event::Executed { token, .. } | Event::Delivered(token) => {
                    submitted.retain(|t| *t != token)
                }
                _ => {}
            }
        }
        for &token in &submitted {
            self.dev.control.hold(token);
        }
        submitted
    }

    fn draw_read_fault(&mut self) -> ReadFault {
        match self.below(14) {
            0 => ReadFault::Deadline,
            1 => ReadFault::Error,
            2 => ReadFault::Short,
            3 => ReadFault::Cancel,
            4 => ReadFault::Reorder,
            6 if !self.lost => ReadFault::Lost,
            _ => ReadFault::Clean,
        }
    }

    /// One lookup of a live key and, for a hit, a read through one volume
    /// read operation that must return exactly its bytes, sometimes through a
    /// delayed, reordered, failed, short, cancelled, lost or timed-out
    /// command.
    fn hit(&mut self, w: &mut Witnesses) {
        if self.collide && self.below(3) == 0 {
            self.foreign_hit(w);
            return;
        }
        let Some(key) = self.pick_object() else {
            return;
        };
        let object = self.object(&key);
        let expired = self.now / SECOND >= (object.deadline / SECOND).min(u64::from(u32::MAX));
        let reader = &mut self.reader;
        let lease = match no_alloc("a lookup", || {
            super::lookup_tests::lookup(reader, &key, RETRIES)
        }) {
            Ok(lease) => {
                assert!(!expired, "an expired object served");
                lease
            }
            Err(LookupError::Expired) => {
                assert!(expired, "a fresh object refused as expired");
                return;
            }
            Err(error) => panic!("a live object refused {error:?}"),
        };
        let fault = self.draw_read_fault();
        self.read_with(key, lease, fault, w);
    }

    /// One read of `key`'s object under `lease`, driven through `fault`, that
    /// must return exactly its bytes when it completes; the lease is then
    /// sometimes held.
    fn read_with(
        &mut self,
        key: Key,
        lease: ExtentLease<'static, TestPlatform>,
        fault: ReadFault,
        w: &mut Witnesses,
    ) {
        let slot = lease.id().slot_index();
        let volume = &mut self.dev.volume;
        let op = no_alloc("a read submit", || {
            volume.read(lease.duplicate(), fault.deadline())
        })
        .unwrap();
        let token = last_read(&self.dev.control);
        let refs = |storage: &Storage<TestPlatform>| storage.live_pool().unwrap().refs(slot);
        // Every right on the object except this read's own.
        let base = refs(self.storage) - 1;
        match fault {
            ReadFault::Deadline => {
                // A deadline past while the command is held: the read ends
                // timed out and keeps its right until the real terminal.
                self.dev.control.hold(token);
                w.inject(Member::F3DelayedCompletion);
                w.inject(Member::F3Deadline);
                assert_eq!(self.poll_done(op, 10), ReadStatus::TimedOut);
                assert_eq!(
                    refs(self.storage),
                    base + 1,
                    "a timed-out read's right ended early"
                );
                w.affect(Member::F3Deadline);
                w.saw(Situation::ReadCustodyAfterCancellation);
                self.dev.control.release(token);
                settle(&mut self.dev.volume, &self.dev.control);
                // The real terminal returned the read's right.
                assert_eq!(refs(self.storage), base);
                w.affect(Member::F3DelayedCompletion);
            }
            ReadFault::Error => {
                let status = Fault::Status(DeviceStatus::Kernel(-5));
                self.dev.control.fault(token, status);
                let delivered = drive(&mut self.dev.volume, &self.dev.control, op);
                assert_eq!(delivered.status, ReadStatus::DeviceError);
                assert!(self.object(&key).bytes.starts_with(&delivered.bytes));
                w.fault(Member::F3ErrorCompletion);
            }
            ReadFault::Short => {
                self.dev.control.fault(token, Fault::Short { units: 1 });
                let delivered = drive(&mut self.dev.volume, &self.dev.control, op);
                let bytes = &self.object(&key).bytes;
                if self.geometry.charged_units(bytes.len()) == 1 {
                    assert_eq!(delivered.status, ReadStatus::Complete);
                    assert_eq!(&delivered.bytes, bytes, "a read returned other bytes");
                } else {
                    assert_eq!(delivered.status, ReadStatus::Short);
                    assert!(delivered.bytes.is_empty(), "a short read exposed bytes");
                    w.fault(Member::F3ShortCompletion);
                }
            }
            ReadFault::Cancel => {
                // The held command is cancelled: the read ends cancelled
                // and its right waits for the device's terminal.
                self.dev.control.hold(token);
                self.dev.volume.cancel_read(op).unwrap();
                w.inject(Member::F3Cancellation);
                assert_eq!(self.poll_done(op, 0), ReadStatus::Cancelled);
                assert_eq!(
                    refs(self.storage),
                    base + 1,
                    "a cancelled read's right ended early"
                );
                self.dev.control.release(token);
                settle(&mut self.dev.volume, &self.dev.control);
                assert_eq!(refs(self.storage), base);
                w.affect(Member::F3Cancellation);
            }
            ReadFault::Reorder => self.reorder(token, op, &key, w),
            ReadFault::Lost => {
                // A completion the device never posts: the read times out
                // and the right stays with the command for the volume's
                // lifetime, so the extent never returns under it.
                self.lost = true;
                self.dev.control.fault(token, Fault::DropCompletion);
                w.inject(Member::F3LostCompletion);
                assert_eq!(self.poll_done(op, 10), ReadStatus::TimedOut);
                drop(lease);
                assert_eq!(refs(self.storage), base, "a lost read's right ended");
                w.affect(Member::F3LostCompletion);
                return;
            }
            ReadFault::Clean => self.clean_read(op, &key, w),
        }
        if self.below(4) == 0 && self.held.len() < HELD_LEASES {
            self.held.push((key, lease));
        }
    }

    /// A second read completes ahead of the held first read, of `key`, and
    /// each returns exactly its own bytes; when the volume refuses the second
    /// read, the first is driven clean and checked.
    fn reorder(&mut self, token: CommandToken, op: ReadOp, key: &Key, w: &mut Witnesses) {
        self.dev.control.hold(token);
        // A dropped completion holds one table operation for the volume's
        // lifetime, which can refuse the second read.
        if let Some(other) = self.pick_object()
            && let Ok(second) = super::lookup_tests::lookup(&mut self.reader, &other, 4)
            && let Ok(ahead) = self.dev.volume.read(second, u64::MAX)
        {
            w.inject(Member::F3ReorderedCompletions);
            let delivered = drive(&mut self.dev.volume, &self.dev.control, ahead);
            assert_eq!(
                delivered.bytes,
                self.object(&other).bytes,
                "a reordered read returned other bytes"
            );
            self.dev.control.release(token);
            let delivered = drive(&mut self.dev.volume, &self.dev.control, op);
            assert_eq!(
                delivered.bytes,
                self.object(key).bytes,
                "a reordered read returned other bytes"
            );
            w.affect(Member::F3ReorderedCompletions);
        } else {
            self.dev.control.release(token);
            self.clean_read(op, key, w);
        }
    }

    /// A completed `op` returns exactly `key`'s bytes, witnessing a
    /// publication and hit.
    fn clean_read(&mut self, op: ReadOp, key: &Key, w: &mut Witnesses) {
        let delivered = drive(&mut self.dev.volume, &self.dev.control, op);
        assert_eq!(
            delivered.status,
            ReadStatus::Complete,
            "a clean read failed"
        );
        assert_eq!(
            delivered.bytes,
            self.object(key).bytes,
            "a read returned other bytes"
        );
        w.saw(Situation::PublicationAndHit);
    }

    /// A lookup of a key with no resident object: an equal fingerprint may
    /// route it to another key's object, whose read must expose nothing.
    fn foreign_hit(&mut self, w: &mut Witnesses) {
        let key = key_of(1 + self.below(u64::from(HOT)) as u32);
        if self.holds(&key) || self.unwritten.contains(&key) {
            return;
        }
        let Ok(lease) = super::lookup_tests::lookup(&mut self.reader, &key, 4) else {
            return;
        };
        let id = lease.id();
        let delivered = read_back(&mut self.dev.volume, &self.dev.control, &lease);
        let ReadStatus::HeaderMismatch(mismatch) = delivered.status else {
            panic!(
                "another key's object read for {key:?}: {:?}",
                delivered.status
            );
        };
        assert!(delivered.bytes.is_empty(), "another key's bytes exposed");
        // A successor published without device bytes fails on its magic;
        // every other object fails on the key.
        if self
            .successors
            .contains(&(id.slot_index(), id.incarnation()))
        {
            return;
        }
        assert_eq!(mismatch, HeaderMismatch::Key);
        w.saw(Situation::EqualFingerprintExposesNothing);
        w.fault(Member::F6EqualFingerprint);
    }

    /// `key`'s position in `objects`, or where it would go.
    fn find(&self, key: &Key) -> Result<usize, usize> {
        self.objects.binary_search_by(|(other, _)| other.cmp(key))
    }

    fn holds(&self, key: &Key) -> bool {
        self.find(key).is_ok()
    }

    fn object(&self, key: &Key) -> &Object {
        &self.objects[self.find(key).expect("a tracked object")].1
    }

    fn pick_object(&mut self) -> Option<Key> {
        if self.objects.is_empty() {
            return None;
        }
        let at = self.below(self.objects.len() as u64) as usize;
        Some(self.objects[at].0)
    }

    /// Polls at `now` until `op` ends, returning its status.
    fn poll_done(&mut self, op: ReadOp, now: u64) -> ReadStatus {
        let mut out = Vec::with_capacity(8);
        for _ in 0..16 {
            let dev = &mut self.dev;
            let mut tick = || dev.control.tick(64);
            let mut poll = || {
                let _ = dev.volume.poll_storage(now, &mut out);
            };
            round(&mut [
                Act::new(Actor::Disk(0), &mut tick),
                Act::new(Actor::Volume(0), &mut poll),
            ]);
            for event in out.drain(..) {
                if let ReadEvent::Done { op: of, status, .. } = event
                    && of == op
                {
                    return status;
                }
            }
        }
        panic!("no Done");
    }

    /// One maintenance call at a budget class, sometimes with a stale
    /// identity or a busy pool gate placed in front of its removal commit,
    /// checking conservation per dimension.
    fn maintain(&mut self, w: &mut Witnesses) {
        let storage = self.storage;
        // With no slot free or no unit claimable, every reservation refuses
        // before it reaches the volume, so the call ticks the volume first
        // and the retired slots can return.
        let blocked = storage
            .domain_report()
            .is_some_and(|domain| domain.free_slots == 0 || domain.claimable_units == 0);
        if blocked {
            settle(&mut self.dev.volume, &self.dev.control);
        }
        let minimum = storage.maintain_minimum();
        let (steps, operations, bytes) = match self.below(6) {
            0 => (0, 0, 0),
            1 => (minimum - 1, 0, 0),
            2 => (minimum, 0, 0),
            3 => (1 << 14, 4, 1 << 16),
            _ => (1 << 14, 0, 0),
        };
        let mut budget = WorkBudget::with_io(steps, operations, bytes);
        let behind_pin = self.pinned_retirements();
        let mut call = || storage.maintain(&mut budget);
        let hook = self.below(4);
        let result = match hook {
            0 => {
                let keys = self.objects.iter().map(|(key, o)| (o.slot, *key)).collect();
                let session = self.dev.volume.session();
                STALE.with(|cell| *cell.borrow_mut() = Some(Stale::new(storage, session, keys)));
                super::evict::OBSERVE_COMMIT.with(|cell| cell.set(Some(observe_commit)));
                let result = with_commit_hook(replace_victim, call);
                super::evict::OBSERVE_COMMIT.with(|cell| cell.set(None));
                result
            }
            1 => {
                LATE.with(|cell| *cell.borrow_mut() = Some((storage, None)));
                with_commit_hook(hold_pool_gate, call)
            }
            _ => call(),
        };
        // The call removes at most its victims, expired residents and the
        // stale hook's invalidated key.
        self.may_drop = usize::from(hook == 0);
        if let Ok(Maintained::Open(report)) = &result {
            self.may_drop += report.evicted + report.expired;
        }
        if hook == 0 {
            let stale = STALE.with(|cell| cell.borrow_mut().take().unwrap());
            self.stale_commit(&stale, w);
        }
        let holder = LATE
            .with(|cell| cell.borrow_mut().take())
            .and_then(|(_, holder)| holder);
        let held_gate = holder.is_some();
        drop(holder);
        // A mark the busy gate left pending applies in a later call's first
        // hold; the domain is read only after the holder released the gate.
        let pending = storage.domain_report().unwrap().pending_mark;
        if held_gate && pending {
            w.inject(Member::F4LateMark);
            self.mark_late = true;
        } else if self.mark_late && !pending {
            w.affect(Member::F4LateMark);
            self.mark_late = false;
        }
        conserved(&budget, steps, operations, bytes);
        // Maintenance issues no storage command, so a call given an I/O
        // allowance leaves it whole.
        assert_eq!(
            (budget.operations_used(), budget.bytes_used()),
            (0, 0),
            "maintenance I/O"
        );
        match result {
            Err(MaintainError::BudgetExhausted) => {
                assert!(steps < minimum);
                // A short allowance is refused with nothing debited.
                assert_eq!(budget.remaining(), steps);
                if steps == 0 {
                    w.saw(Situation::ZeroBudget);
                    w.fault(Member::F7ZeroAllowance);
                } else {
                    w.saw(Situation::InsufficientBudget);
                    w.fault(Member::F7InsufficientAllowance);
                }
            }
            Ok(Maintained::Open(report)) => {
                assert!(steps >= minimum);
                if steps == minimum {
                    w.saw(Situation::ExactBudget);
                    w.fault(Member::F7ExactAllowance);
                }
                assert_eq!((report.operations, report.transfer_bytes), (0, 0));
                // A retirement unmapped after the pin started, and retired
                // before this call, stays behind the pin through its
                // reclamation pass.
                let held = behind_pin.iter().any(|&(slot, incarnation)| {
                    storage.slot_state(SlotIndex(slot)).unwrap()
                        == (SlotState::Retired, incarnation)
                });
                if report.reclaim.ran && held {
                    w.saw(Situation::HeldReaderAcrossRetirement);
                    w.affect(Member::F2PinAcrossRetirement);
                }
                for (name, ran) in [
                    (Situation::StageFills, report.fills.ran),
                    (Situation::StageCertify, report.certify.ran),
                    (Situation::StageReclaim, report.reclaim.ran),
                    (Situation::StageExpiry, report.expiry.ran),
                    (Situation::StageHeadroom, report.headroom.ran),
                ] {
                    if ran {
                        w.saw(name);
                    }
                }
                if let Some(domain) = report.domain
                    && report.headroom.done
                    && report.evicted == 0
                    && domain.in_flight > 0
                {
                    w.saw(Situation::HeadroomStoppedInFlight);
                }
                if report.clock_unavailable {
                    w.affect(Member::F5UnavailableClock);
                }
            }
            other => panic!("maintenance {other:?}"),
        }
    }

    /// The stale-identity hook replaced the call's selected victim by
    /// publishing `successor` under its key before the victim's commit. The
    /// commit removes by exact identity, so it reports `Absent` and leaves
    /// the successor resident; a later commit of the same call may evict the
    /// successor by its own identity. The report counts that eviction, so
    /// the object-loss allowance discounts it.
    /// A pin held by the churn across the call keeps evictions retired when
    /// their retirement follows the pin's entry, the successor's among them.
    /// At the ordinary action count every seed's successors stay mapped;
    /// `later_reclaim` and its tests exercise the later-eviction branch
    /// through [`classify_stale`].
    fn stale_commit(&mut self, stale: &Stale, w: &mut Witnesses) {
        let Some((id, key)) = stale.successor else {
            return;
        };
        self.unwritten.insert(key);
        self.successors.insert((id.slot_index(), id.incarnation()));
        self.published.insert(key);
        self.track(id, SMALL.0 + SMALL.1);
        // The successor is unreadable through the device, so the churn
        // reads it only through its slot and its mapping.
        let after = self.storage.slot_state(SlotIndex(id.slot_index())).unwrap();
        let later_evicted = stale.successor_evicted;
        let mapped = if later_evicted || after != (SlotState::Resident, id.incarnation()) {
            None
        } else {
            let lookup = super::lookup_tests::lookup(&mut self.reader, &key, 4);
            lookup_answer(lookup.map(|lease| lease.id()))
        };
        let seen = StaleObservation {
            successor: id,
            immediate: stale.immediate,
            later_evicted,
            held: self.pinned.is_some(),
            after,
            mapped,
        };
        match classify_stale(seen) {
            Ok(StaleLifecycle::LaterRemoved) => self.may_drop -= 1,
            Ok(StaleLifecycle::Mapped | StaleLifecycle::Unobserved) => {}
            Err(rule) => panic!("{rule}: {seen:?}"),
        }
        w.inject(Member::F4StaleIdentity);
        // The commit found its identity absent and removed nothing.
        w.affect(Member::F4StaleIdentity);
    }

    /// Takes a pin when none is held, recording the published slots it
    /// cannot protect, or drops the held one.
    fn toggle_pin(&mut self) {
        if self.pinned.take().is_some() {
            return;
        }
        // The pin protects only what the index maps when it starts. A slot
        // can read resident with its mapping already removed and its
        // retirement parked, so mapping is decided by lookups of every key
        // the churn ever published; an expired mapping counts as mapped.
        let mut mapped = BTreeSet::new();
        let fingerprint = |key: &Key| self.storage.route(key).unwrap().fingerprint();
        for key in &self.published {
            match super::lookup_tests::lookup(&mut self.reader, key, 4) {
                Ok(lease) => {
                    mapped.insert((lease.id().slot_index(), lease.id().incarnation()));
                }
                // The expired mapping found may be any object of the key's
                // fingerprint.
                Err(LookupError::Expired) => {
                    let fp = fingerprint(key);
                    mapped.extend(
                        self.objects
                            .iter()
                            .filter(|(other, _)| fingerprint(other) == fp)
                            .map(|(_, o)| (o.slot, o.incarnation)),
                    );
                }
                Err(LookupError::Missing) => {}
                Err(error) => panic!("a pin's mapping lookup refused {error:?}"),
            }
        }
        let releasable = self
            .tracked
            .iter()
            .enumerate()
            .filter_map(|(slot, t)| t.map(|t| (slot, t.incarnation)))
            .filter(|identity| !mapped.contains(identity))
            .collect();
        let mut registration = self.storage.register().unwrap();
        std::mem::forget(registration.enter().unwrap());
        self.pinned = Some(Pin {
            _registration: registration,
            releasable,
        });
    }

    fn busy_gate(&mut self, w: &mut Witnesses) {
        let key = key_of(1 + self.below(u64::from(HOT)) as u32);
        let Ok(attempt) = begin(self.storage, &key) else {
            return;
        };
        let Some(admitted) = self.decide(SMALL) else {
            attempt.abort();
            self.service_fills();
            return;
        };
        let held = self.storage.live_pool().unwrap().lock().unwrap();
        let refused = attempt
            .reserve_storage(
                admitted,
                Some(SMALL.0),
                Some(SMALL.1),
                TRIES,
                &mut WorkBudget::new(64),
            )
            .err();
        drop(held);
        assert_eq!(refused, Some(FillReserveError::Contended));
        self.service_fills();
        w.fault(Member::F5BusyGate);
    }

    /// A dropped return, or one handed to another storage, parks on its
    /// issuer, and the issuer's service returns it.
    fn stray_return(&mut self, w: &mut Witnesses) {
        let storage = self.storage;
        let Ok(reservation) = spend(|b| storage.reserve(Some(SMALL.0), Some(SMALL.1), b)) else {
            return;
        };
        let id = reservation.id();
        self.track(id, SMALL.0 + SMALL.1);
        let pending = storage.outstanding().pending;
        let transfer = reservation.release();
        let member = if self.below(2) == 0 {
            drop(transfer);
            Member::F2DroppedReturn
        } else {
            let other = self.other;
            let elsewhere = spend(|b| other.return_allocation(transfer, b));
            assert_eq!(elsewhere, Err(ReturnError::ForeignStorage));
            assert_eq!(
                self.other.pool_report().unwrap().ledger.unwrap().raw.free,
                8 * IO_UNIT
            );
            Member::F2ForeignReturn
        };
        w.inject(member);
        assert!(
            storage.outstanding().pending > pending,
            "the return did not park on its issuer"
        );
        let _ = spend(|b| storage.service(b));
        assert_eq!(
            storage.slot_state(SlotIndex(id.slot_index())).unwrap().0,
            SlotState::Free,
            "service left the parked return"
        );
        w.affect(member);
    }

    /// A lease held across its object's invalidation reads its own bytes.
    fn lease_across_invalidation(&mut self, w: &mut Witnesses) {
        let Some(key) = self.pick_object() else {
            return;
        };
        let mut reader = self.storage.register().unwrap();
        let Ok(lease) = super::lookup_tests::lookup(&mut reader, &key, 4) else {
            return;
        };
        self.may_drop = 1;
        invalidate(self.storage, &key).unwrap();
        let delivered = read_back(&mut self.dev.volume, &self.dev.control, &lease);
        assert_eq!(
            delivered.bytes,
            self.object(&key).bytes,
            "a held lease read other bytes"
        );
        w.saw(Situation::HeldReaderAcrossRetirement);
        w.fault(Member::F2LeaseAcrossRetirement);
    }

    fn step(&mut self, w: &mut Witnesses) {
        self.action += 1;
        let storage = self.storage;
        match self.actions.next_u64() % 100 {
            0..=51 => {
                if self.below(10) < 7 {
                    let key = key_of(1 + self.below(u64::from(HOT)) as u32);
                    self.demand(key, None, w);
                } else {
                    self.flood += 1;
                    let key = key_of(self.flood);
                    w.inject(Member::F6UniqueKeyFlood);
                    self.demand(key, None, w);
                    if self.holds(&key) {
                        w.saw(Situation::FirstDemandPublication);
                        w.affect(Member::F6UniqueKeyFlood);
                    }
                }
            }
            52..=71 => self.hit(w),
            72..=76 => {
                if !self.held.is_empty() {
                    let at = self.below(self.held.len() as u64) as usize;
                    let lease = self.held.swap_remove(at);
                    no_alloc("a lease drop", || drop(lease));
                }
            }
            77 => {
                if let Some(key) = self.pick_object() {
                    let leased = self.held.iter().any(|(k, _)| *k == key);
                    self.may_drop = 1;
                    no_alloc("an invalidation", || invalidate(storage, &key)).unwrap();
                    w.inject_if(leased, Member::F2LeaseAcrossRetirement);
                    w.inject_if(self.pinned.is_some(), Member::F2PinAcrossRetirement);
                }
            }
            78..=92 => self.maintain(w),
            93..=94 => {
                self.now += (1 + self.below(2)) * SECOND + self.below(2) * (SECOND / 2);
                storage.platform.ticks(&[Some(self.now)]);
            }
            95 => self.toggle_pin(),
            96 => self.busy_gate(w),
            97 => {
                // An unavailable clock for one maintenance call.
                storage.platform.ticks(&[None, Some(self.now)]);
                w.inject(Member::F5UnavailableClock);
                self.maintain(w);
                storage.platform.ticks(&[Some(self.now)]);
            }
            98 => self.stray_return(w),
            _ => self.lease_across_invalidation(w),
        }
        self.check();
    }

    fn publish_small(&mut self, w: &mut Witnesses) -> Option<Key> {
        self.flood += 1;
        let key = key_of(self.flood);
        self.demand(key, Some(SMALL), w);
        self.check();
        self.holds(&key).then_some(key)
    }

    /// Runs funded maintenance and fill service until a largest record is
    /// claimable and a slot is free, within the headroom call bound.
    fn restore(&mut self) -> u32 {
        let storage = self.storage;
        let largest = self.geometry.largest();
        // The headroom bound: a victim behind a retained prefix of `p`
        // members, with `v` funded visits per call, is committed within
        // `ceil((p + 1) / v)` funded headroom stages. With `p` below the
        // slot count and `v` at least one, each of at most slot-count victims
        // takes at most slot-count calls, and its extents after the first
        // one call each, since a service visit returns one extent. Two full
        // stage cycles more give grace certification and reclamation room
        // after the last commit.
        let limit = self.geometry.funded_limit();
        let mut actions = 0;
        let room = |storage: &Storage<TestPlatform>| {
            let domain = storage.domain_report().unwrap();
            domain.claimable_units >= largest && domain.free_slots > 0
        };
        while !room(storage) {
            self.may_drop = usize::MAX;
            // The ticks settle the volume's metadata before maintenance returns the retired slots.
            settle(&mut self.dev.volume, &self.dev.control);
            let _ = storage.maintain(&mut WorkBudget::new(1 << 16));
            self.service_fills();
            actions += 1;
            assert!(actions <= limit, "recovery capacity past {limit} actions");
            self.check();
        }
        actions as u32
    }

    /// Records the qualified recovery interval, the recovery publication and
    /// its readback as oracle rows.
    fn judged_recovery(&mut self, w: &mut Witnesses) -> Vec<Row> {
        const K: KeyId = KeyId(0);
        const A: Label = Label(1);
        let mut rec = Recorder::new(1);
        let holders = self.held.len() as u32;
        for credit in 0..holders {
            rec.take((ResourceKind::Credit, credit, 0), Custodian::Reader, None);
        }
        self.held.clear();
        self.pinned = None;
        for credit in 0..holders {
            rec.release((ResourceKind::Credit, credit, 0), Custodian::Reader);
        }
        let credits = self
            .storage
            .lease_report()
            .map_or(ReportState::Absent, |report| {
                ReportState::Value(report.reserved as u64)
            });
        rec.report(ResourceKind::Credit, ReportKind::Ledger, credits);
        settle(&mut self.dev.volume, &self.dev.control);
        for (token, pending) in self.dev.volume.table_tokens() {
            if pending {
                let slot = u32::from(super::device::slot_of(token));
                rec.take(
                    (ResourceKind::Command, slot, token.raw()),
                    Custodian::Storage,
                    None,
                );
            }
        }
        let table = self.dev.volume.table_report();
        rec.report(
            ResourceKind::Command,
            ReportKind::Table,
            ReportState::Value(u64::from(table.pending + table.abandoned)),
        );
        let funded = self.restore();
        let limit = self.geometry.funded_limit() as u32;
        rec.checkpoint(Checkpoint::Qualified { funded, limit });
        self.content = Some(Recorder::content(K, A, SMALL.0 as u32, SMALL.1 as u64));
        // The judged window's write evidence stands on the capture and
        // token record from here, within their reserved room however long
        // the churn ran before it.
        self.dev.volume.clear_bound();
        self.dev.control.clear_capture();
        match self.publish_small(w) {
            Some(key) => {
                let object = self.object(&key);
                let (bytes, identity) = (
                    object.bytes.clone(),
                    (
                        self.dev.volume.session(),
                        AllocationId::new(SlotIndex(object.slot), object.incarnation).record_tag(),
                    ),
                );
                let written =
                    crate::net::fills_written_in(self.dev.volume.bound_tokens(), &self.dev.control)
                        .pop()
                        .expect("the small fill's write evidence");
                rec.published_written(K, A, SMALL.0 as u32, &bytes, identity, Some(written));
                let lease = super::lookup_tests::lookup(&mut self.reader, &key, 4).unwrap();
                let read = rec.lookup(K, Outcome::Hit, Some(A));
                let delivered = read_back(&mut self.dev.volume, &self.dev.control, &lease);
                assert_eq!(delivered.status, ReadStatus::Complete);
                let info = delivered.info.expect("a complete read verified its header");
                rec.delivered(
                    read,
                    (K, A),
                    (SMALL.0 as u32, SMALL.1 as u64),
                    (info.identity().session, info.identity().allocation),
                    Outcome::Complete,
                    delivered.bytes,
                );
                w.saw(Situation::RecoveryPublicationAndReadback);
            }
            None => {
                let key = key_of(self.flood);
                let missed = super::lookup_tests::lookup(&mut self.reader, &key, 4).err();
                assert_eq!(missed, Some(LookupError::Missing));
                rec.lookup(K, Outcome::Missing, None);
            }
        }
        rec.checkpoint(Checkpoint::Stopped);
        rec.rows().to_vec()
    }

    /// Releases every blocker and runs funded maintenance until a largest
    /// record is claimable, then publishes a new key's object on its first
    /// demand and reads it back, within an action limit derived from the
    /// fixture.
    fn recover(&mut self, w: &mut Witnesses) {
        self.phase = "recover";
        w.inject(Member::F9RecoveryAfterFaults);
        w.inject_if(
            !self.held.is_empty() || self.pinned.is_some(),
            Member::F9BlockersRemoved,
        );
        self.held.clear();
        self.pinned = None;
        settle(&mut self.dev.volume, &self.dev.control);
        self.restore();
        // Funded maintenance restored a largest record's claim and a free
        // slot once the blockers ended.
        w.affect(Member::F9BlockersRemoved);
        let Some(key) = self.publish_small(w) else {
            panic!("recovery publication: the first demand published nothing");
        };
        let lease = super::lookup_tests::lookup(&mut self.reader, &key, 4).unwrap();
        let delivered = read_back(&mut self.dev.volume, &self.dev.control, &lease);
        assert_eq!(
            delivered.bytes,
            self.object(&key).bytes,
            "recovery readback"
        );
        w.saw(Situation::RecoveryPublicationAndReadback);
        w.affect(Member::F9RecoveryAfterFaults);
    }

    /// The seed's terminal faults, after its recovery: a close in front of
    /// a maintenance stage with leases held, then a driver unwind under a
    /// pending read.
    fn terminal(&mut self, w: &mut Witnesses) {
        self.phase = "terminal";
        let storage = self.storage;
        let mut leases = Vec::new();
        for _ in 0..8 {
            if leases.len() == 2 {
                break;
            }
            self.restore();
            if let Some(key) = self.publish_small(w)
                && let Ok(lease) = super::lookup_tests::lookup(&mut self.reader, &key, 4)
            {
                leases.push((self.object(&key).bytes.clone(), lease));
            }
        }
        assert_eq!(leases.len(), 2, "two leases for the terminal phase");
        // A read stays outstanding at the device across the close.
        let (bytes, lease) = &leases[0];
        let outstanding = self.dev.volume.read(lease.duplicate(), u64::MAX).unwrap();
        let token = last_read(&self.dev.control);
        self.dev.control.hold(token);
        CLOSING.with(|cell| cell.set(Some(storage)));
        w.inject(Member::F5CloseDuringWork);
        self.may_drop = usize::MAX;
        let closed_in = with_stage_hook(close_before_reclaim, || {
            storage.maintain(&mut WorkBudget::new(1 << 16))
        });
        assert!(storage.is_closed(), "{closed_in:?}");
        self.check();
        assert!(
            begin(storage, &key_of(1)).is_err(),
            "a closed storage began an attempt"
        );
        assert!(matches!(
            storage.maintain(&mut WorkBudget::new(1 << 16)),
            Ok(Maintained::Closed(_))
        ));
        self.may_drop = usize::MAX;
        self.check();
        // The read outstanding across the close completes with its bytes.
        self.dev.control.release(token);
        let delivered = drive(&mut self.dev.volume, &self.dev.control, outstanding);
        assert_eq!(
            &delivered.bytes, bytes,
            "a read across the close returned other bytes"
        );
        w.affect(Member::F5CloseDuringWork);
        // A driver unwind under a pending read loses the volume; the read's
        // right stays held and later reads are refused.
        let (_, lease) = &leases[1];
        let slot = lease.id().slot_index();
        let _op = self.dev.volume.read(lease.duplicate(), u64::MAX).unwrap();
        let mut out = Vec::with_capacity(8);
        let mut unwound = None;
        let dev = &mut self.dev;
        let mut tick = || dev.control.tick(8);
        let mut poll = || {
            dev.control.unwind_next(Some(Unwind::Pick));
            w.inject(Member::F7Unwind);
            unwound = Some(catch_unwind(AssertUnwindSafe(|| {
                dev.volume.poll_storage(0, &mut out)
            })));
        };
        round(&mut [
            Act::new(Actor::Disk(0), &mut tick),
            Act::new(Actor::Volume(0), &mut poll),
        ]);
        let unwound = unwound.expect("the round polled the volume");
        assert!(unwound.is_err());
        assert!(self.dev.volume.is_lost());
        assert!(self.dev.volume.read(lease.duplicate(), u64::MAX).is_err());
        assert!(storage.live_pool().unwrap().refs(slot) >= 2);
        w.affect(Member::F7Unwind);
        drop(leases);
        self.may_drop = usize::MAX;
        self.check();
    }
}

/// A panic inside maintenance poisons the root gate: later calls are
/// refused, and every ledger still reconciles; `probe` sees the churn last.
fn poisoned_gate(w: &mut Witnesses, probe: &mut impl Probe) {
    let mut churn = Churn::new(3, false, false);
    churn.phase = "poisoned-gate";
    for _ in 0..200 {
        churn.step(w);
    }
    churn
        .storage
        .maintain
        .stage
        .store(MaintainStage::Fills as usize, Ordering::Relaxed);
    w.inject(Member::F5PoisonedGate);
    let unwound = with_stage_hook(panic_before_certify, || {
        catch_unwind(AssertUnwindSafe(|| {
            churn.storage.maintain(&mut WorkBudget::new(1 << 16))
        }))
    });
    assert!(unwound.is_err());
    assert_eq!(
        churn.storage.maintain(&mut WorkBudget::new(1 << 16)),
        Err(MaintainError::Poisoned)
    );
    churn.check();
    w.affect(Member::F5PoisonedGate);
    probe.finished(&churn);
}

/// One seed's churn, recovery and terminal faults: the units it
/// published, and its checks after warmup at the fixture occupancy out of
/// all of them.
///
/// # Errors
///
/// As [`run_on`].
fn run(
    seed: u64,
    reject_all: bool,
    collide: bool,
    actions: usize,
    w: &mut Witnesses,
) -> Result<(usize, (usize, usize)), String> {
    let mut churn = Churn::new(seed, reject_all, collide);
    run_on(&mut churn, actions, w, &mut ())
}

/// What a caller observes of the churns the storage phases drive, at the
/// points of [`run_on`], [`lifecycle_faults`] and [`poisoned_gate`] where
/// a churn's device and storage are settled between actions. Each hook
/// defaults to doing nothing.
trait Probe {
    /// After action `at` of the churn phase.
    fn stepped(&mut self, _churn: &mut Churn, _at: usize) {}

    /// Before the recovery releases the blockers.
    fn recovering(&mut self, _churn: &mut Churn) {}

    /// After the recovery published and read back its object.
    ///
    /// # Errors
    ///
    /// A check of the caller's at this point; it ends the run.
    fn recovered(&mut self, _churn: &mut Churn, _w: &mut Witnesses) -> Result<(), String> {
        Ok(())
    }

    /// After a phase finished with `churn`: the terminal faults, and each
    /// churn of the lifecycle and poisoned-gate phases.
    fn finished(&mut self, _churn: &Churn) {}
}

impl Probe for () {}

/// Runs `actions` actions of `churn`, its recovery and its terminal
/// faults, with `probe` observing each; returns the units the churn
/// published, and its checks after warmup at the fixture occupancy out of
/// all of them. A failing per-action oracle panics, and the churn reports
/// its seed, phase and action on stderr.
///
/// # Errors
///
/// A probe's refusal, or a churn that held the fixture occupancy for less
/// than two fifths of its checks after warmup.
fn run_on(
    churn: &mut Churn,
    actions: usize,
    w: &mut Witnesses,
    probe: &mut impl Probe,
) -> Result<(usize, (usize, usize)), String> {
    for at in 0..actions {
        churn.step(w);
        probe.stepped(churn, at);
    }
    probe.recovering(churn);
    churn.recover(w);
    probe.recovered(churn, w)?;
    let (occupied, checks) = churn.occupied;
    // Each seed holds the fixture occupancy for at least two fifths of its
    // checks after warmup.
    if occupied * 5 < checks * 2 {
        return Err(format!(
            "seed {} (collide {}, reject all {}): {occupied} of {checks} checks at the fixture occupancy, under two fifths",
            churn.seed, churn.collide, churn.reject_all
        ));
    }
    let published = churn.published_units;
    churn.terminal(w);
    probe.finished(churn);
    Ok((published, (occupied, checks)))
}

/// The usable capacity turnovers `published` units make over `geometry`.
///
/// # Errors
///
/// Fewer than three, which leaves the churn's turnover unmet.
fn turnovers(geometry: Geometry, published: usize) -> Result<usize, String> {
    let usable = geometry.units - geometry.reserve as usize;
    if published < 3 * usable {
        return Err(format!(
            "{published} units published, {} turnovers, under three",
            published / usable
        ));
    }
    Ok(published / usable)
}

/// Rollback retains a mapping whose unmap fails, and a storage attached
/// over another storage's device bytes serves none of its records; `probe`
/// sees each churn once it finished.
fn lifecycle_faults(w: &mut Witnesses, probe: &mut impl Probe) {
    use super::init::{Cleanup, InitPhase};
    use super::mapping::Region;
    use super::os::OsCode;
    use super::placement::PlacementConfig;
    use super::test_platform::{Fail, Op};
    let config = StorageConfig {
        volume: crate::storage::test_volume(8 * IO_UNIT, 4),
        ..storage_config(4)
    };
    let validated = config.validate().unwrap();
    let platform = TestPlatform::heap(PAGE);
    platform.fail_at(Fail {
        op: Op::Cut(InitPhase::ControlInit),
        ordinal: 0,
        code: OsCode(12),
        region: Some(Region::Control),
    });
    // The first rollback unmap targets the control mapping.
    platform.fail_at(Fail {
        op: Op::Unmap,
        ordinal: 1,
        code: OsCode(16),
        region: None,
    });
    w.inject(Member::F8MappingFailure);
    w.inject(Member::F8UnmapRefusal);
    let failure = Storage::initialize(&validated, &PlacementConfig { control_home: 0 }, platform)
        .err()
        .unwrap();
    w.affect(Member::F8MappingFailure);
    let Cleanup::Incomplete(retained) = failure.cleanup else {
        panic!("the refused unmap was not retained");
    };
    assert_eq!(
        retained.iter().map(|r| r.region).collect::<Vec<_>>(),
        [Region::Control]
    );
    w.affect(Member::F8UnmapRefusal);
    // A new storage attached over a device holding another storage's
    // records serves none of them, and its own churn over those bytes reads
    // back exactly what it wrote.
    let mut old = Churn::new(1, false, false);
    old.phase = "cold-start-old";
    for _ in 0..200 {
        old.step(w);
    }
    assert!(!old.objects.is_empty());
    let image = old
        .dev
        .control
        .device(0, Geometry::ORIGINAL.units * IO_UNIT);
    let mut fresh = Churn::over(Geometry::ORIGINAL, 2, false, false, &image);
    fresh.phase = "cold-start-fresh";
    w.inject(Member::F8OldDeviceBytes);
    for (key, _) in &old.objects {
        assert!(
            super::lookup_tests::lookup(&mut fresh.reader, key, 4).is_err(),
            "a cold start served an old record"
        );
    }
    for _ in 0..200 {
        fresh.step(w);
    }
    assert!(fresh.published_units > 0);
    w.affect(Member::F8OldDeviceBytes);
    probe.finished(&old);
    probe.finished(&fresh);
}

/// Every seed conserves every ledger after every action, reaches every
/// required situation and fault member, recovers, and turns the usable
/// capacity over several times.
#[test]
fn churn_conserves_every_ledger_and_reaches_every_situation() {
    // Each seed churns on its own thread: a churn's storage, device, hooks
    // and allocation counters are its own or thread-local, and witnesses
    // merge by summed counts and ORed seed bits. The two phases after the
    // seeds run beside them.
    let seed = |seed: u64| {
        move || {
            let mut w = Witnesses {
                seed,
                ..Witnesses::default()
            };
            // One seed in four routes keys through one-fingerprint groups.
            let ran = run(seed, false, seed % 4 == 3, ACTIONS, &mut w);
            let (published, (at, of)) = ran.unwrap_or_else(|refused| panic!("{refused}"));
            if let Err(refused) = turnovers(Geometry::ORIGINAL, published) {
                panic!("seed {seed}: {refused}");
            }
            (w, at, of)
        }
    };
    let later = |phase: fn(&mut Witnesses)| {
        move || {
            let mut w = Witnesses {
                seed: SEEDS,
                ..Witnesses::default()
            };
            phase(&mut w);
            (w, 0, 0)
        }
    };
    let mut w = Witnesses::default();
    let (mut occupied, mut checks) = (0, 0);
    std::thread::scope(|scope| {
        let mut threads = Vec::new();
        for s in 0..SEEDS {
            threads.push(spawn(scope, format!("seed {s}"), seed(s)));
        }
        threads.push(spawn(
            scope,
            "lifecycle".into(),
            later(|w| lifecycle_faults(w, &mut ())),
        ));
        threads.push(spawn(
            scope,
            "poisoned gate".into(),
            later(|w| poisoned_gate(w, &mut ())),
        ));
        for thread in threads {
            let (seen, at, of) = thread
                .join()
                .unwrap_or_else(|payload| std::panic::resume_unwind(payload));
            w.merge(&seen);
            occupied += at;
            checks += of;
        }
    });
    w.seed = SEEDS;
    // The fixture occupancy, free units at or below the headroom target
    // plus one largest record and so two thirds of the volume in use,
    // holds for two thirds of all checks after warmup.
    assert!(
        occupied * 3 >= checks * 2,
        "{occupied} of {checks} checks at the fixture occupancy"
    );
    w.saw(Situation::OccupancySustained);
    w.require_all();
}

/// Spawns `f` on a scoped thread named `name`, so a failure names its seed
/// or phase.
fn spawn<'scope, T: Send + 'scope>(
    scope: &'scope std::thread::Scope<'scope, '_>,
    name: String,
    f: impl FnOnce() -> T + Send + 'scope,
) -> std::thread::ScopedJoinHandle<'scope, T> {
    std::thread::Builder::new()
        .name(name)
        .spawn_scoped(scope, f)
        .expect("a churn thread")
}

/// Rejecting every admission keeps every safety oracle green and never
/// publishes, so the recovery oracle fails.
#[test]
#[should_panic(expected = "recovery publication")]
fn negative_control_reject_all_fails_recovery() {
    let mut w = Witnesses::default();
    let _ = run(0, true, false, ACTIONS, &mut w);
}

fn judged_run(reject_all: bool) -> (Vec<Row>, Witnesses) {
    let mut w = Witnesses::default();
    let mut churn = Churn::new(0, reject_all, false);
    // A bound the churn overflows long before its recovery, so the judged
    // window must stand on its own evidence.
    churn.dev.control.set_capture_bound(64);
    for _ in 0..ACTIONS {
        churn.step(&mut w);
    }
    let rows = churn.judged_recovery(&mut w);
    (rows, w)
}

fn recovery_lookup(rows: &[Row]) -> OpId {
    rows.iter()
        .rfind(|row| row.kind == ActionKind::Lookup)
        .expect("the recovery lookup")
        .op
}

#[test]
fn funded_recovery_hits_within_its_bound() {
    let (rows, w) = judged_run(false);
    let verdict = check(&Recorder::rebuilt(rows.clone()));
    assert!(
        verdict.satisfies(&[Obligation::Progress, Obligation::Bytes]),
        "{verdict:?}"
    );
    assert!(w.situations[Situation::RecoveryPublicationAndReadback as usize] > 0);
    assert!(w.situations[Situation::HeldReaderAcrossRetirement as usize] > 0);
    let attempt = recovery_lookup(&rows);
    let missed = rows
        .into_iter()
        .filter(|row| !(row.op == attempt && row.kind != ActionKind::Lookup))
        .map(|mut row| {
            if row.op == attempt {
                row.outcome = Some(Outcome::Missing);
                row.label = None;
                row.clock = None;
            }
            row
        });
    // A miss beside the recovered publication is legal history; the funded
    // interval's progress judgment rejects it.
    let Verdict::Violation(violation) = check(&Recorder::rebuilt(missed)) else {
        panic!("a violation");
    };
    assert_eq!(
        (violation.obligation, violation.rule, violation.op),
        (
            Obligation::Progress,
            "a qualified funded interval produced no exact hit",
            attempt
        )
    );
}

#[test]
fn always_miss_control_fails_progress_at_the_recovery_lookup() {
    let (rows, w) = judged_run(true);
    let attempt = recovery_lookup(&rows);
    let Verdict::Violation(violation) = check(&Recorder::rebuilt(rows)) else {
        panic!("a violation");
    };
    assert_eq!(
        (violation.obligation, violation.rule, violation.op),
        (
            Obligation::Progress,
            "a qualified funded interval produced no exact hit",
            attempt
        )
    );
    assert_eq!(
        w.situations[Situation::RecoveryPublicationAndReadback as usize],
        0
    );
}

/// Replays one seed of the churn for diagnosis, recovery and terminal
/// phases included: `CHURN_SEED`, `CHURN_COLLIDE=1`, `CHURN_REJECT_ALL=1`
/// and `CHURN_ACTIONS` select it, defaulting to seed 0 at the full action
/// count. The lifecycle and poisoned-gate phases run only in the full test.
#[test]
#[ignore = "diagnostic replay; run with --ignored"]
fn churn_replay() {
    let read = |name: &str| std::env::var(name).ok().and_then(|v| v.parse::<u64>().ok());
    let actions = read("CHURN_ACTIONS").map_or(ACTIONS, |n| n as usize);
    let ran = run(
        read("CHURN_SEED").unwrap_or(0),
        read("CHURN_REJECT_ALL") == Some(1),
        read("CHURN_COLLIDE") == Some(1),
        actions,
        &mut Witnesses::default(),
    );
    if let Err(refused) = ran {
        panic!("{refused}");
    }
}

fn published(churn: &mut Churn, key: Key, sizes: (usize, usize), w: &mut Witnesses) {
    churn.demand(key, Some(sizes), w);
    churn.check();
    assert!(churn.holds(&key), "the first demand published nothing");
}

#[test]
fn pins_return_their_reader_records() {
    let mut churn = Churn::new(0, false, false);
    for _ in 0..2 * READERS {
        churn.toggle_pin();
    }
    assert!(churn.storage.register().is_ok());
}

#[test]
fn a_short_fault_on_a_one_unit_read_completes_without_a_short_witness() {
    let mut w = Witnesses::default();
    let mut churn = Churn::new(0, false, false);
    let key = key_of(1);
    published(&mut churn, key, SMALL, &mut w);
    let lease = super::lookup_tests::lookup(&mut churn.reader, &key, 4).unwrap();
    churn.read_with(key, lease, ReadFault::Short, &mut w);
    assert_eq!(w.affected[Member::F3ShortCompletion as usize], 0);
}

#[test]
fn a_short_fault_on_a_multi_unit_read_ends_short_with_no_bytes() {
    let mut w = Witnesses::default();
    let mut churn = Churn::new(0, false, false);
    let key = key_of(1);
    published(&mut churn, key, (0, 2 * IO_UNIT), &mut w);
    let lease = super::lookup_tests::lookup(&mut churn.reader, &key, 4).unwrap();
    churn.read_with(key, lease, ReadFault::Short, &mut w);
    assert_eq!(w.affected[Member::F3ShortCompletion as usize], 1);
}

#[test]
#[should_panic(expected = "objects lost where the action removes at most 0")]
fn a_replacement_permits_no_other_object_loss() {
    let mut w = Witnesses::default();
    let mut churn = Churn::new(0, false, false);
    let (key, other) = (key_of(1), key_of(2));
    published(&mut churn, key, SMALL, &mut w);
    published(&mut churn, other, SMALL, &mut w);
    let identity = |churn: &Churn| {
        let object = churn.object(&key);
        (object.slot, object.incarnation)
    };
    let old = identity(&churn);
    churn.demand(key, Some(SMALL), &mut w);
    assert_ne!(identity(&churn), old, "the demand replaced nothing");
    invalidate(churn.storage, &other).unwrap();
    churn.check();
}

#[test]
#[should_panic(expected = "a clean read failed")]
fn a_reorder_without_a_second_read_checks_the_first() {
    let mut w = Witnesses::default();
    let mut churn = Churn::new(0, false, false);
    let key = key_of(1);
    published(&mut churn, key, SMALL, &mut w);
    let mut lease = || super::lookup_tests::lookup(&mut churn.reader, &key, 4).unwrap();
    let leases: Vec<_> = (0..READ_OPS).map(|_| lease()).collect();
    for lease in &leases[1..] {
        let _ = churn.dev.volume.read(lease.duplicate(), u64::MAX).unwrap();
        churn.dev.control.hold(last_read(&churn.dev.control));
    }
    let op = churn
        .dev
        .volume
        .read(leases[0].duplicate(), u64::MAX)
        .unwrap();
    let token = last_read(&churn.dev.control);
    churn
        .dev
        .control
        .fault(token, Fault::Status(DeviceStatus::Kernel(-5)));
    churn.reorder(token, op, &key, &mut w);
}

/// Runs the stale-identity hook over two removal steps of `storage`, whose
/// only resident is `key`'s, the first step's victim replaced by a
/// successor before its commit and the second evicting that successor,
/// then drains certification and reclamation; `hold` keeps a lease on the
/// successor from its selection by the second step. Returns the
/// observation for [`classify_stale`].
fn later_reclaim(hold: bool) -> StaleObservation {
    let storage: &'static Storage<TestPlatform> = Box::leak(Box::new(super::evict_tests::ready(8)));
    let key = super::lookup_tests::key(1);
    let first = super::lookup_tests::publish(storage, key, u64::MAX, &super::lookup_tests::body(1));
    STALE.with(|cell| {
        *cell.borrow_mut() = Some(Stale::new(
            storage,
            SESSION,
            vec![(first.slot_index(), key)],
        ));
    });
    super::evict::OBSERVE_COMMIT.with(|cell| cell.set(Some(observe_commit)));
    let replaced = with_commit_hook(replace_victim, || {
        storage.evict_step(&mut super::evict_tests::generous(), |_, _| true)
    })
    .unwrap();
    assert_eq!(replaced.commit, Some(Commit::Absent));
    let (successor, _) = STALE
        .with(|cell| cell.borrow().as_ref().unwrap().successor)
        .expect("the hook published a successor");
    let step = || {
        storage
            .evict_step(&mut super::evict_tests::generous(), |_, _| true)
            .unwrap()
    };
    let evicted = if hold {
        HELD.with(|cell| cell.set(Some((storage, key))));
        with_commit_hook(hold_successor, step).commit
    } else {
        step().commit
    };
    assert!(
        matches!(evicted, Some(Commit::Evicted { victim, .. }) if victim == successor),
        "the next step evicts the successor: {evicted:?}"
    );
    super::evict_tests::drain(storage);
    super::evict::OBSERVE_COMMIT.with(|cell| cell.set(None));
    let stale = STALE.with(|cell| cell.borrow_mut().take()).unwrap();
    let lease = HELD_LEASE.with(|cell| cell.borrow_mut().take());
    let seen = StaleObservation {
        successor,
        immediate: stale.immediate,
        later_evicted: stale.successor_evicted,
        held: lease.is_some(),
        after: storage
            .slot_state(SlotIndex(successor.slot_index()))
            .unwrap(),
        mapped: None,
    };
    drop(lease);
    seen
}

thread_local! {
    static HELD: Cell<Option<(&'static Storage<TestPlatform>, Key)>> = const { Cell::new(None) };
    static HELD_LEASE: RefCell<Option<ExtentLease<'static, TestPlatform>>> =
        const { RefCell::new(None) };
}

/// Runs between the successor's selection and its commit: a reader takes a
/// lease on it, so its eviction leaves it retired while the lease is held.
fn hold_successor() {
    let (storage, key) = HELD.with(Cell::take).unwrap();
    let mut reader = storage.register().unwrap();
    let lease = super::lookup_tests::lookup(&mut reader, &key, RETRIES).unwrap();
    HELD_LEASE.with(|cell| *cell.borrow_mut() = Some(lease));
}

/// A constructed minimal history of a lawful later reclaim: the stale
/// commit reports `Absent` and spares the successor, and a later removal
/// step evicts the successor by its own identity, as a later commit of one
/// maintenance call would, after which reclamation frees its slot at its
/// incarnation. The `Free` state is lawful only beside the later eviction;
/// the same state without it is an unmapping.
#[test]
fn a_successor_evicted_and_reclaimed_by_a_later_step_is_a_lawful_free() {
    let seen = later_reclaim(false);
    let (commit, right_after) = seen.immediate.unwrap();
    assert_eq!(commit, Commit::Absent);
    assert_eq!(
        right_after,
        (SlotState::Resident, seen.successor.incarnation())
    );
    assert_eq!(seen.after, (SlotState::Free, seen.successor.incarnation()));
    assert_eq!(classify_stale(seen), Ok(StaleLifecycle::LaterRemoved));
    let unrelated = StaleObservation {
        later_evicted: false,
        ..seen
    };
    assert_eq!(
        classify_stale(unrelated),
        Err("a successor no later commit evicted left residence")
    );
}

/// A reader holding the successor keeps its later eviction retired, which
/// is lawful; the same history claiming the held successor reclaimed fails.
#[test]
fn a_held_successor_stays_retired_and_its_reclaim_fails() {
    let seen = later_reclaim(true);
    assert_eq!(
        seen.after,
        (SlotState::Retired, seen.successor.incarnation())
    );
    assert_eq!(classify_stale(seen), Ok(StaleLifecycle::LaterRemoved));
    let reclaimed = StaleObservation {
        after: (SlotState::Free, seen.successor.incarnation()),
        ..seen
    };
    assert_eq!(
        classify_stale(reclaimed),
        Err("a held successor was reclaimed")
    );
}

/// A pin held across a stale-identity call blocks certification of the
/// successor's later retirement. Reclaiming the evicted successor under
/// that pin is premature; an unpinned reclaim is lawful.
#[test]
#[should_panic(expected = "a held successor was reclaimed")]
fn a_successor_reclaimed_under_the_churns_pin_fails() {
    let freed = |churn: &Churn| {
        let (state, incarnation) = churn.storage.slot_state(SlotIndex(0)).unwrap();
        assert_eq!(state, SlotState::Free);
        let mut stale = Stale::new(churn.storage, SESSION, Vec::new());
        stale.successor = Some((AllocationId::new(SlotIndex(0), incarnation), key_of(1)));
        stale.immediate = Some((Commit::Absent, (SlotState::Resident, incarnation)));
        stale.successor_evicted = true;
        stale
    };
    let mut w = Witnesses::default();
    let mut unpinned = Churn::new(0, false, false);
    let stale = freed(&unpinned);
    unpinned.may_drop = 2;
    unpinned.stale_commit(&stale, &mut w);
    assert_eq!(
        unpinned.may_drop, 1,
        "the successor's tallied eviction removes none of the churn's objects"
    );
    let mut pinned = Churn::new(0, false, false);
    pinned.toggle_pin();
    assert!(pinned.pinned.is_some());
    let stale = freed(&pinned);
    pinned.stale_commit(&stale, &mut w);
}

/// The stale commit's own result and the successor's state right after it
/// decide the commit; the lookup after the call decides the mapping, and a
/// lookup that answered nothing informative decides nothing.
#[test]
fn a_stale_commit_that_reaches_its_successor_fails() {
    let successor = AllocationId::new(SlotIndex(3), 9);
    let resident = (SlotState::Resident, 9);
    let spared = StaleObservation {
        successor,
        immediate: Some((Commit::Absent, resident)),
        later_evicted: false,
        held: false,
        after: resident,
        mapped: Some(Some(successor)),
    };
    assert_eq!(classify_stale(spared), Ok(StaleLifecycle::Mapped));
    assert_eq!(
        classify_stale(StaleObservation {
            mapped: None,
            ..spared
        }),
        Ok(StaleLifecycle::Unobserved)
    );
    let failures = [
        (
            StaleObservation {
                immediate: Some((Commit::Absent, (SlotState::Retired, 9))),
                ..spared
            },
            "a stale commit unmapped its successor at its commit",
        ),
        (
            StaleObservation {
                immediate: Some((
                    Commit::Evicted {
                        victim: successor,
                        fingerprint: 0,
                        retirement: RetireOutcome::Parked,
                    },
                    resident,
                )),
                ..spared
            },
            "a stale commit under a completed replacement was not Absent",
        ),
        (
            StaleObservation {
                mapped: Some(None),
                ..spared
            },
            "a lookup missed a resident successor",
        ),
        (
            StaleObservation {
                mapped: Some(Some(AllocationId::new(SlotIndex(3), 10))),
                ..spared
            },
            "a lookup acquired another identity under the successor's key",
        ),
        (
            StaleObservation {
                later_evicted: true,
                ..spared
            },
            "an evicted successor left an unexpected state",
        ),
        (
            StaleObservation {
                later_evicted: true,
                after: (SlotState::Free, 10),
                ..spared
            },
            "an evicted successor left an unexpected state",
        ),
        (
            StaleObservation {
                after: (SlotState::Free, 9),
                ..spared
            },
            "a successor no later commit evicted left residence",
        ),
        (
            StaleObservation {
                immediate: None,
                ..spared
            },
            "the stale commit was not observed",
        ),
    ];
    for (seen, rule) in failures {
        assert_eq!(classify_stale(seen), Err(rule), "{seen:?}");
    }
}

/// A stale commit followed by a removal step that evicts another resident
/// leaves the successor mapped: the later eviction names its own victim,
/// and a lookup of the successor's key acquires the successor.
#[test]
fn an_unrelated_later_eviction_leaves_the_successor_mapped() {
    let storage: &'static Storage<TestPlatform> = Box::leak(Box::new(super::evict_tests::ready(8)));
    let keys: Vec<(usize, Key)> = [1, 2]
        .into_iter()
        .map(|n| {
            let key = super::lookup_tests::key(n);
            let body = super::lookup_tests::body(n);
            let id = super::lookup_tests::publish(storage, key, u64::MAX, &body);
            (id.slot_index(), key)
        })
        .collect();
    STALE.with(|cell| *cell.borrow_mut() = Some(Stale::new(storage, SESSION, keys)));
    super::evict::OBSERVE_COMMIT.with(|cell| cell.set(Some(observe_commit)));
    let step = || {
        storage
            .evict_step(&mut super::evict_tests::generous(), |_, _| true)
            .unwrap()
            .commit
    };
    assert_eq!(with_commit_hook(replace_victim, step), Some(Commit::Absent));
    let other = step();
    super::evict::OBSERVE_COMMIT.with(|cell| cell.set(None));
    let stale = STALE.with(|cell| cell.borrow_mut().take()).unwrap();
    let (successor, key) = stale.successor.expect("the hook published a successor");
    assert!(
        matches!(other, Some(Commit::Evicted { victim, .. }) if victim != successor),
        "the next step evicts the other resident: {other:?}"
    );
    let mut reader = storage.register().unwrap();
    let lookup = super::lookup_tests::lookup(&mut reader, &key, RETRIES).map(|lease| lease.id());
    let seen = StaleObservation {
        successor,
        immediate: stale.immediate,
        later_evicted: stale.successor_evicted,
        held: false,
        after: storage
            .slot_state(SlotIndex(successor.slot_index()))
            .unwrap(),
        mapped: lookup_answer(lookup),
    };
    assert!(!seen.later_evicted);
    assert_eq!(classify_stale(seen), Ok(StaleLifecycle::Mapped));
}

/// A lease names the identity it acquired, a miss or an expiry denies any
/// mapping, and every refusal that proves nothing leaves the mapping
/// unobserved.
#[test]
fn a_successor_lookup_maps_only_informative_answers() {
    let successor = AllocationId::new(SlotIndex(3), 9);
    let cases = [
        (Ok(successor), Some(Some(successor))),
        (Err(LookupError::Missing), Some(None)),
        (Err(LookupError::Expired), Some(None)),
        (Err(LookupError::Contended), None),
        (Err(LookupError::LeaseLimit), None),
        (Err(LookupError::RetainLimit), None),
        (Err(LookupError::ClockUnavailable), None),
        (Err(LookupError::Closed), None),
    ];
    for (lookup, answer) in cases {
        assert_eq!(lookup_answer(lookup), answer, "{lookup:?}");
    }
}

/// Every seed churns on each larger geometry at the ordinary action count
/// with every census, budget and allocation check active after every
/// action, recovers within the geometry's funded limit, turns its usable
/// capacity over at least three times and, across seeds, holds the fixture
/// occupancy for two thirds of its checks after warmup.
#[test]
fn larger_geometries_reconcile_every_seed() {
    for geometry in Geometry::LARGER {
        let (mut occupied, mut checks) = (0, 0);
        let mut reached = Witnesses::default();
        std::thread::scope(|scope| {
            let threads: Vec<_> = (0..SEEDS)
                .map(|seed| {
                    let name = format!("{geometry:?} seed {seed}");
                    spawn(scope, name, move || {
                        let mut w = Witnesses {
                            seed,
                            ..Witnesses::default()
                        };
                        let collide = seed % 4 == 3;
                        let mut churn = Churn::over(geometry, seed, false, collide, &[]);
                        // Twice the actions reach the fragmentation and reserve witnesses on every larger geometry.
                        let ran = run_on(&mut churn, 2 * ACTIONS, &mut w, &mut ());
                        let (published, occupancy) =
                            ran.unwrap_or_else(|refused| panic!("{geometry:?} {refused}"));
                        if let Err(refused) = turnovers(geometry, published) {
                            panic!("{geometry:?} seed {seed}: {refused}");
                        }
                        (w, occupancy)
                    })
                })
                .collect();
            for thread in threads {
                let (seen, (at, of)) = thread
                    .join()
                    .unwrap_or_else(|payload| std::panic::resume_unwind(payload));
                reached.merge(&seen);
                occupied += at;
                checks += of;
            }
        });
        assert!(
            occupied * 3 >= checks * 2,
            "{geometry:?}: {occupied} of {checks} checks at the fixture occupancy"
        );
        for situation in [
            Situation::ReserveEquality,
            Situation::ReserveOneShortRefusal,
            Situation::FragmentedNoFitAboveReserve,
        ] {
            assert!(
                reached.situations[situation as usize] > 0,
                "{geometry:?}: {situation:?} never fired"
            );
        }
        for member in [
            Member::F1ExactBound,
            Member::F1OneShortBound,
            Member::F1Fragmentation,
        ] {
            assert!(
                reached.affected[member as usize] > 0,
                "{geometry:?}: {member:?} never affected an operation"
            );
        }
    }
}

/// Checks at one stopped boundary of one engine reconcile alike, also
/// across an unfunded maintenance call, which the engine refuses with
/// nothing changed.
#[test]
fn equivalent_checkpoints_on_one_engine_reconcile_alike() {
    for geometry in [Geometry::ORIGINAL, Geometry::LARGER[0], Geometry::LARGER[1]] {
        let mut churn = Churn::over(geometry, 5, false, false, &[]);
        let mut w = Witnesses::default();
        for _ in 0..300 {
            churn.step(&mut w);
        }
        let first = churn.check();
        assert_eq!(churn.check(), first, "{geometry:?}");
        let refused = churn.storage.maintain(&mut WorkBudget::with_io(0, 0, 0));
        assert!(
            matches!(refused, Err(MaintainError::BudgetExhausted)),
            "{refused:?}"
        );
        assert_eq!(churn.check(), first, "{geometry:?}");
    }
}

#[test]
#[should_panic(expected = "the census scratch grew during a check")]
fn a_census_that_outgrows_its_scratch_fails() {
    let geometry = Geometry::LARGER[0];
    let mut churn = Churn::over(geometry, 0, false, false, &[]);
    churn.census = Census::new(Geometry {
        slots: 1,
        ..geometry
    });
    churn.check();
}

/// Every geometry's storage charges a record by its own chunk length: a
/// 32,640-byte payload charges 9 units with 4 KiB chunks and 8 with 8 KiB
/// or 16 KiB chunks. A 32,645-byte payload charges 9 units with 8 KiB
/// chunks and 8 units with 16 KiB chunks.
#[test]
fn each_geometry_storage_charges_by_its_chunk_length() {
    let [wide, widest] = Geometry::LARGER;
    for (geometry, body, units) in [
        (Geometry::ORIGINAL, 32_640, 8),
        (Geometry::ORIGINAL, 32_645, 9),
        (wide, 32_640, 9),
        (widest, 32_640, 8),
        (widest, 32_645, 8),
    ] {
        let storage = churn_storage(geometry, false);
        let Decision::Admit(_) = storage.decide_admission(Some(0), Some(body)) else {
            panic!("{geometry:?}: a {body}-byte record was not admitted");
        };
        assert_eq!(
            super::writable_tests::charge(storage, 0, body),
            units as u64,
            "{geometry:?} {body}"
        );
    }
}

/// The device reconciles only when its accepted commands equal those it
/// delivered or holds plus exactly the completion a seed dropped.
#[test]
fn the_device_counters_reconcile_only_with_the_dropped_completion() {
    let counts = |accepted, delivered, outstanding| DeviceCounts {
        accepted,
        delivered,
        outstanding,
    };
    assert_eq!(device_reconciles(counts(10, 7, 3), false), Ok(()));
    assert_eq!(device_reconciles(counts(10, 6, 3), true), Ok(()));
    assert_eq!(
        device_reconciles(counts(10, 6, 3), false),
        Err("accepted commands differ from those delivered or held plus the dropped completion")
    );
    assert_eq!(
        device_reconciles(counts(10, 7, 3), true),
        Err("accepted commands differ from those delivered or held plus the dropped completion")
    );
    assert_eq!(
        device_reconciles(counts(10, 8, 3), false),
        Err("the device delivered or holds more commands than it accepted")
    );
}

/// One census input: the geometry, the live extents, what the churn
/// derived and what the ledgers and allocator reported.
struct Snapshot {
    geometry: Geometry,
    extents: Vec<Extent>,
    derived: Derived,
    reported: Reported,
}

/// A snapshot of `geometry` holding one resident record in slot 2 over the
/// `len` units from `start`, with its payload, waste and the free runs it
/// leaves reported exactly.
fn one_record(geometry: Geometry, start: u64, len: u64) -> Snapshot {
    let payload = len as usize * IO_UNIT - 300;
    let mut counts = [0; 5];
    counts[SlotState::Free as usize] = geometry.slots - 1;
    counts[SlotState::Resident as usize] = 1;
    let units = geometry.units as u64;
    let free_runs: Vec<(u64, u64)> = [(0, start), (start + len, units - start - len)]
        .into_iter()
        .filter(|&(_, run)| run > 0)
        .collect();
    let free = (geometry.units - len as usize) * IO_UNIT;
    Snapshot {
        geometry,
        extents: vec![Extent {
            slot: 2,
            start,
            len,
            charged: len,
        }],
        derived: Derived {
            counts,
            resident: payload,
            waste: 300,
            held: len as usize,
            ..Derived::default()
        },
        reported: Reported {
            slots: counts,
            raw: [
                free,
                0,
                payload,
                0,
                300,
                geometry.metadata_units as usize * IO_UNIT,
            ],
            total: Some(geometry.raw_bytes()),
            free_runs,
        },
    }
}

fn judged(snapshot: Snapshot) -> Result<(), CensusFault> {
    let mut census = Census::new(snapshot.geometry);
    let before = census.capacity();
    census.extents.extend(snapshot.extents);
    let verdict = census.judge(snapshot.geometry, snapshot.derived, &snapshot.reported);
    assert_eq!(census.capacity(), before, "the census scratch grew");
    verdict
}

/// Extents across the word boundaries of 65-unit and 129-unit volumes
/// reconcile, and each planted defect fails by its own rule: a lost or
/// omitted final unit, an overlap, a wrong free-run complement, a wrong
/// slot category, a lost charge, an extent past the volume, a spent
/// reserve, an overflowed total, the record's waste booked as resident
/// bytes, a return that credits only payload bytes, and a free run over
/// the record's units. On the 64-unit volume a 62-unit record leaves
/// exactly the two-unit reserve and reconciles, and a 63-unit record
/// spends it.
#[test]
fn the_census_reconciles_word_crossing_extents_and_fails_each_planted_defect() {
    let [wide, widest] = Geometry::LARGER;
    assert_eq!((wide.units, widest.units), (65, 129));
    let crossing = || one_record(wide, 60, 5);
    let short = || one_record(wide, 59, 5);
    assert_eq!(judged(crossing()), Ok(()));
    assert_eq!(judged(short()), Ok(()));
    assert_eq!(short().reported.free_runs, [(0, 59), (64, 1)]);
    assert_eq!(judged(one_record(widest, 126, 3)), Ok(()));
    assert_eq!(judged(one_record(widest, 60, 69)), Ok(()));
    let mut omitted = short();
    omitted.reported.free_runs = vec![(0, 59)];
    assert_eq!(judged(omitted), Err(CensusFault::FreeRuns));
    let mut uncounted = short();
    uncounted.reported.raw[RAW_FREE] -= IO_UNIT;
    assert_eq!(judged(uncounted), Err(CensusFault::RawCategories));
    let mut prefix = short();
    prefix.reported.raw[RAW_FREE] -= IO_UNIT;
    prefix.reported.raw[RAW_METADATA] += IO_UNIT;
    assert_eq!(judged(prefix), Err(CensusFault::RawCategories));
    let mut last_word = one_record(widest, 0, 3);
    last_word.reported.free_runs = vec![(3, 125)];
    assert_eq!(judged(last_word), Err(CensusFault::FreeRuns));
    let mut lost_total = crossing();
    lost_total.reported.total = Some(64 * IO_UNIT);
    assert_eq!(judged(lost_total), Err(CensusFault::RawTotal));
    let mut overlap = crossing();
    overlap.extents.push(Extent {
        slot: 3,
        start: 63,
        len: 2,
        charged: 2,
    });
    assert_eq!(judged(overlap), Err(CensusFault::Overlap { slot: 3 }));
    let mut split = crossing();
    split.reported.free_runs = vec![(0, 30), (30, 30)];
    assert_eq!(judged(split), Err(CensusFault::FreeRuns));
    let mut shifted = crossing();
    shifted.reported.free_runs = vec![(1, 60)];
    assert_eq!(judged(shifted), Err(CensusFault::FreeRuns));
    let mut category = crossing();
    category.reported.slots[SlotState::Resident as usize] = 0;
    category.reported.slots[SlotState::Retired as usize] = 1;
    assert_eq!(judged(category), Err(CensusFault::SlotPartition));
    let mut charge = crossing();
    charge.extents[0].charged = 6;
    assert_eq!(judged(charge), Err(CensusFault::Charge { slot: 2 }));
    let mut waste = crossing();
    waste.derived.waste -= 1;
    assert_eq!(judged(waste), Err(CensusFault::RawCategories));
    let mut past = crossing();
    past.extents[0].start = 61;
    assert_eq!(judged(past), Err(CensusFault::PastVolume { slot: 2 }));
    let mut spent = crossing();
    spent.reported.raw[RAW_FREE] = IO_UNIT;
    assert_eq!(judged(spent), Err(CensusFault::ReserveSpent));
    let mut overflowed = crossing();
    overflowed.reported.total = None;
    assert_eq!(judged(overflowed), Err(CensusFault::RawTotal));
    let mut booked = crossing();
    booked.reported.raw[RAW_RESIDENT] += 300;
    booked.reported.raw[RAW_WASTE] -= 300;
    assert_eq!(
        booked.reported.raw.iter().sum::<usize>(),
        wide.raw_bytes(),
        "the booked categories keep the volume's total"
    );
    assert_eq!(judged(booked), Err(CensusFault::RawCategories));
    let mut payload_only = crossing();
    payload_only.reported.raw[RAW_FREE] -= 300;
    payload_only.reported.total = Some(wide.raw_bytes() - 300);
    assert_eq!(judged(payload_only), Err(CensusFault::RawCategories));
    let mut covering = crossing();
    covering.reported.free_runs = vec![(0, 65)];
    assert_eq!(judged(covering), Err(CensusFault::FreeRuns));
    let original = Geometry::ORIGINAL;
    assert_eq!((original.units, original.reserve), (64, 2));
    assert_eq!(judged(one_record(original, 0, 62)), Ok(()));
    assert_eq!(
        judged(one_record(original, 0, 63)),
        Err(CensusFault::ReserveSpent)
    );
}

#[test]
fn each_geometry_derives_its_bounds_from_its_shape() {
    let [wide, widest] = Geometry::LARGER;
    let original = Geometry::ORIGINAL;
    assert_eq!(METADATA_CAP + BODY_CAP, 32_776);
    for (geometry, payload, units) in [
        (original, 3_980, 1),
        (original, 3_990, 2),
        (original, 32_640, 8),
        (original, 32_645, 9),
        (original, 32_776, 9),
        (wide, 32_640, 9),
        (wide, 32_776, 9),
        (widest, 32_645, 8),
        (widest, 32_776, 9),
    ] {
        assert_eq!(
            geometry.charged_units(payload),
            units,
            "{geometry:?} {payload}"
        );
    }
    let bounds = |g: Geometry| {
        (
            g.low_units(),
            g.occupied_free(),
            g.largest_extents(),
            g.funded_limit(),
            g.words(),
        )
    };
    assert_eq!(bounds(original), (12, 21, 1, 266, 1));
    assert_eq!(bounds(wide), (12, 21, 1, 1_099, 2));
    assert_eq!(bounds(widest), (42, 51, 1, 1_099, 3));
}

crate::sim::round::generated_corpus!(generated_orders_keep_every_listed_outcome:
    a_short_fault_on_a_multi_unit_read_ends_short_with_no_bytes,
    a_short_fault_on_a_one_unit_read_completes_without_a_short_witness,
    always_miss_control_fails_progress_at_the_recovery_lookup,
);
