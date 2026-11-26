//! Budgeted maintenance: one caller-scheduled call composes fill service,
//! one certification call, slot service, the expiry sweep and headroom
//! eviction under persistent cursors, and reports exact counts and flags.
//!
//! Stages, in the persistent cycle Fills, Certify, Reclaim, Expiry,
//! Headroom, one bounded unit each per call: fill service on a run of
//! shards' tables from the shard cursor, at most one certification call, slot
//! service on the volume (Reclaim), one expiry step on the volume, and one
//! headroom decision in the volume's one domain. The Fills run covers every
//! shard the allowance funds beyond the minima of the stages still to run
//! in the call, at most once around the shards, so a call funded for the
//! whole run covers every shard and a smaller allowance covers a prefix and
//! leaves the cursor on the next shard.
//! Certification precedes Reclaim, so a
//! certificate completed in a cycle makes its retired records eligible for
//! that cycle's Reclaim. Reclaim is the slot service, whose two pass
//! cursors the close service shares. A Reclaim call the allowance cut short
//! leaves work only while the service found a parked mark or a retired slot
//! pending, so a volume with neither reports none.
//! Each stage's cursor advances after
//! its unit whatever the unit found, so ordinary service, certification or
//! close-service callers sharing the underlying cursors can never make a
//! stage repeat, and a caller that keeps funding calls reaches every stage
//! and shard in turn. A busy or poisoned inner gate is counted
//! and skipped, never waited on. The call stops in front of a stage its
//! allowance cannot fund, leaving the cursor there and naming the short
//! dimension in `stopped_by`.
//!
//! `more_work == false` means consecutive clean calls have accumulated
//! coverage of every shard's fill table: each clean call adds the tables its
//! Fills run covered, a call with work left starts the count over, and a
//! storage without an index counts each clean call as covering its one empty
//! table. A Reclaim stage whose service call counted a nonzero
//! `awaiting_journal` has work left. The count holds each parked resident
//! the call's park pass retired while a volume was attached and each
//! retired slot with no right or anchor left that `reusable` refused
//! against the loaded durable prefix. A later call's retired pass returns a
//! counted slot once no right or anchor remains and `reusable` admits its
//! position: service releases an anchor once the slot's retirement era lies
//! below the certified era, and a position that names a suffix block is
//! admitted once the volume's tick stores a prefix past that block or
//! admission closes. The count reads zero once the
//! open volume's metadata halts. A stage skipped for a missing clock sample (`clock_unavailable`)
//! or a poisoned gate (`contended`, `certify_stall`) leaves the call clean,
//! and the report keeps those observations separate. A call funded
//! for the whole Fills run reports done on its own, and each done starts a
//! new run, so a volume that falls short afterwards is examined within the
//! calls whose runs cover the shards again.
//!
//! Work. Every stage is CPU work, so a stage's minimum is CPU steps and its
//! operation and byte minima are zero: reclaiming an extent returns it to
//! the allocator and coalesces it. The report's `operations` and
//! `transfer_bytes` are what the call debited from the operation and byte
//! allowances, zero for every stage, and `reclaimed_bytes` is the bytes of
//! the full charged extents (header, payload and padding) Reclaim returned
//! to the allocator in this call.
//!
//! Minimum. [`Storage::maintain_minimum`] is the root gate attempt plus the
//! largest stage minimum, derived from the configuration: fill service's
//! try and one record, certification's sighting and its minimum over the
//! registration records, Reclaim's [`Storage::service_minimum`] (which includes the
//! largest visit's return work once per service pass), and the removal minimum the expiry
//! sweep and eviction share (the selection controls and one visit) plus the
//! commit bundle, headroom adding its predicate read. A call funded at the
//! minimum therefore completes one decision in whichever stage its cursor
//! stands in. A Reclaim visit of a slot that holds an extent sequence
//! returns its last held extent; the final visit returns the last extent,
//! the block and the slot. Zero or less than the minimum refuses
//! before the root gate with nothing debited and no cursor moved.
//!
//! Headroom, in units: evict one victim in the domain when the domain has a
//! member and `placeable_units.saturating_sub(escrow_units) +
//! in_flight_units < low_units` or `free_slots + in_flight <
//! min_free_slots`. Placeable units count each maximal free run's whole
//! charges of `c` units, `c` the units of the largest admitted object's
//! first extent (63 when that object spans several extents), so a run
//! shorter than `c` counts zero. Since `placeable_units <= free_units`, the
//! volume reads short whenever its free units less the escrow, plus
//! in-flight units, fall short of `low_units`. An escrow above the
//! placeable units clamps their difference to zero, leaving the in-flight
//! units alone to count. An empty volume holds the most placeable units of
//! any allocation state, `payload_units - (payload_units mod c)`, the
//! [`placeable_ceiling`](super::ValidatedConfig::placeable_ceiling) that
//! `LowUnitsOutOfRange` enforces as the upper bound of `low_units`.
//! Held capacity never counts as headroom, promised units count as held,
//! and in-flight evictions count as headroom, so while grace is blocked
//! eviction stops once `placeable_units.saturating_sub(escrow_units) +
//! in_flight_units` reaches `low_units` and `free_slots + in_flight`
//! reaches `min_free_slots`.
//!
//! The escrow and in-flight terms count raw units. The placements of a live
//! builder's escrow lower the placeable units by at most `c - 1` more than
//! the escrow, and the return of an in-flight victim raises them by at
//! least its units less `c - 1`. While the escrow is at most the placeable
//! units, the read therefore overstates placeable space to come by at most
//! `c - 1` per live builder and `c - 1` per in-flight victim, which the
//! deployer's margin in `low_units` covers. An escrow above the placeable
//! units overstates it by the escrow less the placeable units as well,
//! until returns land and a later read counts them. The same terms can
//! understate placeable space to come: a placement shorter than `c` can
//! leave the placeable units unchanged, and each returned extent that joins
//! two free neighbours can add up to `2 * (c - 1)` units beyond its own, so
//! a victim of several extents can gain that much per extent. At most one
//! call's victim overshoots the watermark as the read that drove it counts
//! it, so the placeable units that settle after returns land can exceed the
//! watermark by more. A step at a watermark does not run. An eviction step
//! whose remaining members are all held stops without a victim. Expired
//! residents are removed whatever the watermarks, so expiry can add to in
//! flight beyond that bound. Maintenance never claims a reservation:
//! reservation outcomes are unchanged.
//!
//! Removal identities use two inline entries. The stage loop runs each
//! stage at most once; Expiry and Headroom each select at most one victim.
//! Successful commits append the copied fingerprint and allocation identity
//! in this call's execution order, starting at `started_in`. This bound covers
//! both expiry and headroom removals for every allowance and storage geometry.
//!
//! Report readings, where `claimable_units == 0` means the free units sit
//! at or below the clean reserve `R` plus the escrow `U` of units promised
//! to builders: `claimable_units == 0` with detached extents and no
//! candidate, held by leases; `more_work` with `budget_exhausted`,
//! under-funded; `claimable_units == 0` with in-flight units covering the
//! placeable shortfall,
//! `placeable_units.saturating_sub(escrow_units) + in_flight_units >= low_units`,
//! and the last certification stalled, grace blocked. The grace reading
//! and an eviction step that finds no candidate among held or detached
//! members set `blocked_by_readers_or_io`. Flags are computed from the
//! cursor and exact ledger state, except that the grace reading uses this
//! module's last certification call's outcome; the cumulative statistics
//! saturate and decide nothing. Neither `budget_exhausted` nor
//! `blocked_by_readers_or_io` is admission success.
//!
//! Close. The admission cutoff is read before each stage; a closed cutoff
//! stops the call with its report so far and `more_work`. A call on closed
//! storage delegates to [`Storage::close_service`] without taking this
//! module's gate, and the close service never takes it, so `Drained` still
//! follows only actual releases.
//!
//! Gates: this module's root gate and the close service's gate are the two
//! roots and never held together; under the root, exactly one of the pool
//! gate, a shard gate or the grace maintenance gate is held at a time, every one by a
//! single try, except that a removal's commit makes one pool-gate try under its shard gate when an in-flight pass
//! needs the member's entry or a required suffix its identity. A panic under the root gate poisons it: later calls refuse
//! `Poisoned` until admission closes, after which they delegate to the close
//! service. A panic between inner gates poisons only the root, and
//! reservation, close and drain keep working; one under the pool gate or a shard
//! gate also poisons that gate, as any holder's panic does, and one under
//! the grace maintenance gate poisons it, so the next certification closes
//! admission.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use super::allocation::AllocationId;
use super::attempt::{FILL_SERVICE_PER_RECORD, FillServiceError};
use super::budget::{BudgetDimension, WorkBudget, WorkKind};
use super::closing::{CloseError, ClosingReport};
use super::evict::{Commit, EvictError, SELECT_MIN};
use super::fill;
use super::finalize::Phase;
use super::gate::{GateError, RootGate};
use super::os::Platform;
use super::owner::Storage;
use super::prefetch::hint_read;
use super::probe::{self, Primitive};
use super::release::{ServiceError, certify_minimum};
use super::volume::VolumeWatermarks;
use crate::index::ShardIndex;

/// Steps the headroom stage pays to read its predicate under the selection
/// hold: one comparison.
const PREDICATE_READ: usize = 1;

/// Steps the certify stage pays before its call: the era, the certificate
/// and the grace gate word, one visit each.
const CERTIFY_SIGHTING: usize = 3;

/// Steps the Fills run charges a shard without a fill table: the visit that
/// reads the shard's entry in the root image.
const ABSENT_TABLE: usize = 1;

/// The stage the cursor stands in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(usize)]
pub enum MaintainStage {
    #[default]
    Fills = 0,
    Certify = 1,
    /// Slot service: abandoned and retired records' extents return.
    Reclaim = 2,
    Expiry = 3,
    Headroom = 4,
}

impl MaintainStage {
    pub(super) const ALL: [Self; 5] = [
        Self::Fills,
        Self::Certify,
        Self::Reclaim,
        Self::Expiry,
        Self::Headroom,
    ];

    fn next(self) -> Self {
        Self::ALL[(self as usize + 1) % Self::ALL.len()]
    }
}

/// The persistent stage cursors and the root gate, outside every mapping,
/// written only under that gate. A call ends its hold through the guard's
/// release alone, so the guard drops only when a stage panics, and the
/// gate's kind makes that drop poison it also in a call made by a thread
/// that was already unwinding.
pub(super) struct MaintainCursor {
    pub(super) gate: RootGate,
    pub(super) stage: AtomicUsize,
    fill_shard: AtomicUsize,
    /// Fill tables covered by the run of consecutive calls whose every unit
    /// finished with nothing left; the storage has no work only once such a
    /// run covered every shard.
    clean_cover: AtomicUsize,
    /// Whether the last certification call left the certificate below the
    /// era without advancing it: its pass still running, the certificate
    /// unmoved, or the grace gate poisoned. A busy grace gate does not
    /// count.
    certify_stalled: std::sync::atomic::AtomicBool,
    /// The run of headroom commits refused as `Poisoned` or `Corrupt` while
    /// the domain stayed short; any other commit or a domain that is not
    /// short resets it. Headroom keeps `more_work` set while the run is
    /// shorter than two passes over the domain's members.
    refused_commits: AtomicUsize,
    /// Saturating totals over every call; they decide nothing.
    pub(super) evicted: AtomicU64,
    pub(super) expired: AtomicU64,
    pub(super) short_stages: AtomicU64,
    pub(super) evicted_units: AtomicU64,
}

impl MaintainCursor {
    pub(super) fn start() -> Self {
        Self {
            gate: RootGate::open(),
            stage: AtomicUsize::new(0),
            fill_shard: AtomicUsize::new(0),
            clean_cover: AtomicUsize::new(0),
            certify_stalled: std::sync::atomic::AtomicBool::new(false),
            refused_commits: AtomicUsize::new(0),
            evicted: AtomicU64::new(0),
            expired: AtomicU64::new(0),
            short_stages: AtomicU64::new(0),
            evicted_units: AtomicU64::new(0),
        }
    }
}

/// Cumulative statistics over every call. They saturate and decide nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaintainTotals {
    pub evicted: u64,
    pub expired: u64,
    /// Headroom stages whose selection hold read the domain short, whatever
    /// the stage then committed.
    pub short_stages: u64,
    pub evicted_units: u64,
}

/// What one stage's unit did in this call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StageReport {
    /// The stage ran its unit.
    pub ran: bool,
    /// Records, slots or members the unit visited.
    pub visited: usize,
    /// The unit finished its own work without a budget stop, a busy or
    /// poisoned gate, or an unavailable clock.
    ///
    /// Reclaim's work is its pending obligations, so a slot walk cut short
    /// with no parked mark or retired slot pending is done, and one that
    /// returned an extent ahead of its slot's final return, or whose
    /// service call counted a nonzero `awaiting_journal`, is not. A done
    /// Reclaim leaves retired slots possible: the count reads zero once the
    /// open volume's metadata halts, and rights and grace still hold slots.
    pub done: bool,
}

/// Why certification did not advance the certificate in this call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertifyStall {
    /// The grace maintenance gate was busy.
    Busy,
    /// The grace maintenance gate was poisoned; admission is closed.
    Poisoned,
    /// The pass is still in progress across calls.
    InProgress,
    /// A pass completed or was not needed, and the certificate did not
    /// move: a pinned reader holds grace, or nothing retired since.
    NoProgress,
}

/// The volume domain's exact state, read under the pool gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainReport {
    /// Whole free units of the volume. The units of in-flight extents join
    /// them when their extents return.
    pub free_units: u64,
    /// Free units in whole charges of the largest admitted object's first
    /// extent (63 units when that object spans several extents), read in the
    /// hold that reads `free_units`: each maximal free run counts its largest
    /// multiple of that charge, so this is at most `free_units`, and a run
    /// shorter than the charge counts zero.
    pub placeable_units: u64,
    /// The clean reserve `R`, which every claim leaves free.
    pub reserve_units: u64,
    /// Units above the clean reserve and the escrow of units promised to
    /// builders, or zero when those cover the free units. A claim of `C`
    /// charged units passes the clean reserve check exactly when
    /// `C <= claimable_units`.
    pub claimable_units: u64,
    /// The escrow `U`: units promised to builders and not yet placed. Each
    /// placement takes its units from the free units and the escrow
    /// together, so headroom counts them as consumed.
    pub escrow_units: u64,
    /// Units of the extents evictions hold in flight.
    pub in_flight_units: u64,
    /// Slots evictions hold in flight.
    pub in_flight: usize,
    pub detached: usize,
    pub members: usize,
    pub low_units: u64,
    pub free_slots: usize,
    pub min_free_slots: usize,
    /// An eviction mark is pending.
    pub pending_mark: bool,
    /// Units of retired objects not yet returned.
    pub retired_units: u64,
    /// The retired allowance `T`.
    pub retired_limit: u64,
    /// The longest run of free units.
    pub longest_run: u64,
}

impl DomainReport {
    /// The volume is short of placeable units, counting in-flight evictions
    /// and discounting the escrow, which clamps at the placeable units. A
    /// free run shorter than the charge `c` the placeable count uses counts
    /// nothing, so a volume whose free runs are all shorter than `c` reads
    /// short while its free units cover the watermark, until its in-flight
    /// units reach it. `low_units` is at most the
    /// [`placeable_ceiling`](super::ValidatedConfig::placeable_ceiling),
    /// `payload_units - (payload_units mod c)`, so the empty volume reads
    /// not short. The escrow and
    /// in-flight terms count raw units: a builder's placements use up to
    /// `c - 1` more placeable units than its escrow, and a victim's return
    /// adds at least its units less `c - 1`. While the escrow is at most the
    /// placeable units, the read overstates placeable space to come by at
    /// most `c - 1` per builder or victim; a larger escrow overstates it by
    /// the escrow less the placeable units as well. A placement or a
    /// coalescing return can also move the placeable units the other way,
    /// so the read can understate them.
    fn units_short(&self) -> bool {
        self.placeable_units.saturating_sub(self.escrow_units) + self.in_flight_units
            < self.low_units
    }

    /// The volume is short of free slots, counting in-flight evictions.
    fn slots_short(&self) -> bool {
        self.free_slots + self.in_flight < self.min_free_slots
    }

    fn short(&self) -> bool {
        self.members > 0 && (self.units_short() || self.slots_short())
    }
}

/// Exact identity removed by one maintenance stage. The allocation names
/// its slot and incarnation; the fingerprint names its index routing key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemovedMember {
    pub fingerprint: u64,
    pub allocation: AllocationId,
}

/// What one open maintenance call did. Every count is this call's own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MaintainReport {
    pub started_in: MaintainStage,
    /// Fill service on the shards the Fills run reached: `visited` counts
    /// the records examined over every reached table, and `done` holds when
    /// every table's unit finished without a budget stop, a busy or poisoned
    /// gate, or a malformed table.
    pub fills: StageReport,
    /// The count includes each shard reached by the Fills run in this call
    /// once, regardless of its decision: a table serviced, sighted all-Free,
    /// or found busy, poisoned or malformed, or a shard whose `F` is zero.
    pub fill_tables: usize,
    pub certify: StageReport,
    pub reclaim: StageReport,
    pub expiry: StageReport,
    pub headroom: StageReport,
    /// Victims headroom eviction removed.
    pub evicted: usize,
    /// Residents the sweep removed as expired.
    pub expired: usize,
    /// Successful removals in commit order, occupying the prefix of length
    /// `evicted + expired`.
    pub removed: [Option<RemovedMember>; 2],
    /// Pending eviction marks found stale when applied.
    pub stale_marks: usize,
    /// Inner gate attempts that found the gate busy or poisoned, fill or
    /// shard tables found malformed (their gate poisoned), and commits
    /// refused `Contended`.
    pub contended: usize,
    /// Evictions and expiries the tenure's suffix refused to record: the log is full, stalled, past its bound, not yet
    /// open or closed. The stage counts them as done with no more work, so a later call after the owner's rest
    /// retries them.
    pub suffix_refused: usize,
    /// Members, or residents the sweep stopped at, retained because a lease
    /// holds them.
    pub held: usize,
    /// Commits refused because the key's replacement attempt is current and
    /// undeparted.
    pub replacing: usize,
    /// Members, or residents the sweep stopped at, retained because they
    /// are not published.
    pub unpublished: usize,
    /// Parked retirements detached on sighting.
    pub detached_seen: usize,
    /// The headroom domain this call examined, as its predicate read it.
    pub domain: Option<DomainReport>,
    pub certify_stall: Option<CertifyStall>,
    /// A stage still has work: the call stopped early, a unit stopped on its
    /// budget or met a busy gate, Reclaim returned an extent ahead of its
    /// slot's final return or counted a nonzero `awaiting_journal`, a pass
    /// is in progress, the expiry step
    /// reached a commit that removed, found its candidate already removed,
    /// was refused as replacing or met a busy shard, the examined domain is
    /// short and its run of `Poisoned` or `Corrupt` headroom commits spans
    /// fewer than two passes over its members, or the calls since the last
    /// such outcome, or since the last call that returned without it, have
    /// not yet covered every shard.
    ///
    /// Set when certification advances because covered anchors need slot
    /// service.
    pub more_work: bool,
    /// See the module's report readings: grace blocked with the volume held
    /// at its placeable watermark by evictions in flight, or no candidate
    /// among held or detached members.
    pub blocked_by_readers_or_io: bool,
    /// The allowance ended in front of a stage. Set exactly when
    /// `stopped_by` is `Some`.
    pub budget_exhausted: bool,
    /// The allowance dimension that stopped the call in front of a stage.
    pub stopped_by: Option<BudgetDimension>,
    /// Bytes of the full charged extents (header, payload and padding)
    /// Reclaim returned to the allocator in this call.
    pub reclaimed_bytes: usize,
    /// Storage commands this call debited from the operation allowance.
    pub operations: usize,
    /// Aligned transfer bytes this call debited from the byte allowance.
    pub transfer_bytes: usize,
    /// The clock gave the expiry step no sample; it skipped its stage.
    pub clock_unavailable: bool,
}

/// One removal step's retained members and mark counts, as the eviction and
/// expiry reports both carry them.
struct Retention {
    held: usize,
    unpublished: usize,
    detached_seen: usize,
    stale_marks: usize,
}

impl MaintainReport {
    /// Adds one removal step's counts and its commit: a found commit is an
    /// eviction when `evicting`, else an expiry.
    fn tally(&mut self, kept: Retention, commit: Option<Commit>, evicting: bool) {
        self.held += kept.held;
        self.unpublished += kept.unpublished;
        self.detached_seen += kept.detached_seen;
        self.stale_marks += kept.stale_marks;
        match commit {
            Some(Commit::Evicted {
                victim,
                fingerprint,
                ..
            }) => {
                self.removed[self.evicted + self.expired] = Some(RemovedMember {
                    fingerprint,
                    allocation: victim,
                });
                if evicting {
                    self.evicted += 1;
                } else {
                    self.expired += 1;
                }
            }
            Some(Commit::Replacing) => self.replacing += 1,
            Some(Commit::Contended | Commit::Poisoned | Commit::Corrupt) => self.contended += 1,
            Some(Commit::History) => self.suffix_refused += 1,
            Some(Commit::Absent) | None => {}
        }
    }
}

/// An open call's report, or the close service's once admission closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Maintained {
    Open(MaintainReport),
    Closed(ClosingReport),
}

/// Why a maintenance call did nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaintainError {
    /// The owner is finalizing or drained.
    NotLive,
    /// The storage was configured without watermarks.
    NotConfigured,
    /// Less than [`Storage::maintain_minimum`] remained; nothing debited.
    BudgetExhausted,
    /// Another call holds the root gate; the attempt is charged.
    Contended,
    /// A call that panicked poisoned the root gate; the attempt is charged.
    Poisoned,
    /// The closed-storage delegation's refusal. Its `BudgetExhausted`,
    /// `Contended` and `Poisoned` concern the close service's allowance and
    /// gate, not this module's.
    Close(CloseError),
}

#[cfg(test)]
thread_local! {
    /// Runs before each stage with the stage about to run, so a test can
    /// close admission or panic at a stage boundary.
    pub(super) static INTERPOSE_BEFORE_STAGE: std::cell::Cell<Option<fn(MaintainStage)>> =
        const { std::cell::Cell::new(None) };
    /// Runs once before headroom's selection takes the pool gate, so a test
    /// can change the volume's capacity under the stage's feet.
    pub(super) static INTERPOSE_BEFORE_HEADROOM_SELECT: std::cell::Cell<Option<fn()>> =
        const { std::cell::Cell::new(None) };
}

impl<P: Platform> Storage<P> {
    /// One budgeted maintenance call; see the module documentation.
    ///
    /// # Errors
    ///
    /// [`MaintainError`]: `NotLive`, `NotConfigured` and `BudgetExhausted`
    /// change nothing and debit nothing; `Contended` and `Poisoned` debit
    /// the root gate attempt only.
    // Forced inline, as `maintain_into` is: the open report is a local of the
    // caller's frame, the stages write it there through `&mut`, and
    // `Maintained::Open` is built from it there.
    #[inline(always)]
    pub fn maintain(&self, budget: &mut WorkBudget) -> Result<Maintained, MaintainError> {
        let mut report = MaintainReport::default();
        Ok(match self.maintain_into(budget, &mut report)? {
            None => Maintained::Open(report),
            Some(closing) => Maintained::Closed(closing),
        })
    }

    /// [`maintain`](Self::maintain) for a caller that keeps the open report
    /// in its own frame. An open call writes its counts into `report` and
    /// returns `None`. A call on closed storage returns the close service's
    /// report and leaves `report` unchanged. `report` must equal
    /// [`MaintainReport::default`] on entry; debug builds assert it.
    ///
    /// # Errors
    ///
    /// As `maintain`; `report` is then unchanged.
    // Forced inline: within `maintain`, a successful open call returns the
    // constant `Ok(None)` and a successful closed call returns `Ok(Some(_))`,
    // so the optimizer resolves that match at each return and the open path
    // builds `Maintained::Open` from the report in the frame of `maintain`'s
    // caller.
    #[inline(always)]
    pub(crate) fn maintain_into(
        &self,
        budget: &mut WorkBudget,
        report: &mut MaintainReport,
    ) -> Result<Option<ClosingReport>, MaintainError> {
        debug_assert_eq!(*report, MaintainReport::default());
        if self.phase() != Phase::Live {
            return Err(MaintainError::NotLive);
        }
        if self.is_closed() {
            return self
                .close_service(budget)
                .map(Some)
                .map_err(MaintainError::Close);
        }
        self.maintain_open(budget, report)?;
        Ok(None)
    }

    /// The open call of [`maintain`](Self::maintain) on a live storage whose
    /// admission the caller read open: takes the root gate and runs the
    /// stages, writing this call's counts into `report`, which arrives equal
    /// to [`MaintainReport::default`].
    ///
    /// # Errors
    ///
    /// `NotConfigured`, `BudgetExhausted`, `Contended` or `Poisoned`, as
    /// `maintain` documents them; `report` is then unchanged.
    fn maintain_open(
        &self,
        budget: &mut WorkBudget,
        report: &mut MaintainReport,
    ) -> Result<(), MaintainError> {
        let Some(marks) = self.pool.watermarks() else {
            return Err(MaintainError::NotConfigured);
        };
        let minima = self.stage_minima();
        budget
            .preflight(self.maintain_minimum())
            .map_err(|_| MaintainError::BudgetExhausted)?;
        budget
            .debit(WorkKind::CoordinationAttempt)
            .expect("the preflight covered the root attempt");
        let guard = self.maintain.gate.try_lock().map_err(|error| match error {
            GateError::Contended => MaintainError::Contended,
            GateError::Poisoned => MaintainError::Poisoned,
        })?;
        let cursor = &self.maintain;
        let io_before = (budget.operations_used(), budget.bytes_used());
        let mut stage = MaintainStage::ALL[cursor.stage.load(Ordering::Relaxed)];
        report.started_in = stage;
        for position in 0..MaintainStage::ALL.len() {
            #[cfg(test)]
            if let Some(interpose) = INTERPOSE_BEFORE_STAGE.with(std::cell::Cell::get) {
                interpose(stage);
            }
            // This read pairs with no second location: a stage that runs
            // past a close it did not see is one that started before the
            // close, and its own cutoff checks decide as they would then.
            // `Relaxed` spares each stage the AArch64 `SeqCst` load's wait
            // for the previous stage's gate release to drain; the cutoff
            // never clears, so a closed read stops correctly.
            if self.closed().load(Ordering::Relaxed) {
                report.more_work = true;
                break;
            }
            // A stage's operation and byte minima are zero, so only CPU can
            // leave it short.
            if budget.remaining() < minima[stage as usize] {
                report.budget_exhausted = true;
                report.stopped_by = Some(BudgetDimension::Cpu);
                report.more_work = true;
                break;
            }
            match stage {
                MaintainStage::Reclaim | MaintainStage::Expiry | MaintainStage::Headroom
                    if self.readiness.attach_unfinished() => {}
                MaintainStage::Fills => {
                    // The stages still to run in this call keep their minima,
                    // so the run funds shards from the allowance above them.
                    let reserve = (position + 1..MaintainStage::ALL.len())
                        .map(|later| minima[stage_at(report.started_in, later) as usize])
                        .sum();
                    self.fill_stage(reserve, budget, report);
                }
                MaintainStage::Certify => self.certify_stage(budget, report),
                MaintainStage::Reclaim => self.reclaim_stage(budget, report),
                MaintainStage::Expiry => self.expiry_stage(budget, report),
                MaintainStage::Headroom => self.headroom_stage(marks, budget, report),
            }
            stage = stage.next();
            cursor.stage.store(stage as usize, Ordering::Relaxed);
        }
        // A clean call adds the tables its Fills run covered, one for a
        // storage without an index, and done needs the run to cover every
        // shard; each done starts a new run.
        let clean = if report.more_work {
            0
        } else {
            cursor
                .clean_cover
                .load(Ordering::Relaxed)
                .saturating_add(report.fill_tables.max(1))
        };
        let done = clean >= self.cover();
        cursor
            .clean_cover
            .store(if done { 0 } else { clean }, Ordering::Relaxed);
        report.more_work = !done;
        saturating_add(&cursor.evicted, report.evicted);
        saturating_add(&cursor.expired, report.expired);
        report.operations = budget.operations_used() - io_before.0;
        report.transfer_bytes = budget.bytes_used() - io_before.1;
        guard.release();
        Ok(())
    }

    /// The least allowance an open call accepts: the root gate attempt plus
    /// the largest stage minimum.
    pub fn maintain_minimum(&self) -> usize {
        self.stage_minima()
            .into_iter()
            .fold(0, usize::max)
            .checked_add(1)
            .expect("validation bounds every stage minimum below usize::MAX")
    }

    /// Victims evicted, residents expired, short headroom stages and the
    /// evicted victims' units over every call, saturating.
    pub fn maintain_totals(&self) -> MaintainTotals {
        MaintainTotals {
            evicted: self.maintain.evicted.load(Ordering::Relaxed),
            expired: self.maintain.expired.load(Ordering::Relaxed),
            short_stages: self.maintain.short_stages.load(Ordering::Relaxed),
            evicted_units: self.maintain.evicted_units.load(Ordering::Relaxed),
        }
    }

    /// The exact state of the volume's domain, read under the pool gate,
    /// which this waits for like [`pool_report`](Self::pool_report); `None`
    /// for an owner that is not live, a storage configured without
    /// watermarks, or a poisoned gate.
    ///
    /// # Panics
    ///
    /// When the read finds the volume's tables malformed; the panic poisons
    /// the gate, also on a thread that was already unwinding.
    pub fn domain_report(&self) -> Option<DomainReport> {
        let live = self.live_pool()?;
        let marks = live.watermarks()?;
        // The read's return ends the hold through `release`, so its drop is a
        // panic of the read, and that drop poisons the gate also in a report
        // made by a thread that was already unwinding.
        let mut access = live.lock()?.poison_on_unwind();
        let report = self.read_domain(&mut access.tables(), marks);
        access.release();
        Some(report)
    }

    /// Fill tables a clean run must cover before the storage reports no more
    /// work: every shard's, and at least one.
    fn cover(&self) -> usize {
        self.index()
            .map_or(0, |index| index.geometry.shards().len())
            .max(1)
    }

    /// Each stage's minimum, indexed by the stage's discriminant. Every term
    /// is configuration read from no mapping, so the minimum is answered in
    /// every phase, a drained owner's included.
    pub(super) fn stage_minima(&self) -> [usize; MaintainStage::ALL.len()] {
        let removal = SELECT_MIN + self.commit_bundle();
        [
            1 + FILL_SERVICE_PER_RECORD,
            CERTIFY_SIGHTING + certify_minimum(self.root_image.registrations.len()),
            self.service_minimum(),
            removal,
            PREDICATE_READ + removal,
        ]
    }

    // Each stage is its own function, so a call that runs few stages saves
    // and spills only for those stages.
    /// The Fills run: fill service on each shard from the shard cursor, at
    /// most once around. The first shard needs only the stage's minimum and
    /// its pass may spend from the whole allowance. `reserve` covers the
    /// remaining stages in this call, and the run enters each later shard
    /// only while the allowance above `reserve` pays for that shard:
    /// [`ABSENT_TABLE`] for a shard whose `F` is zero, or the table's
    /// [`pass_bound`]. A sighting runs only when that allowance also pays for
    /// the following pass, so each later shard preserves the reserve.
    #[inline(never)]
    fn fill_stage(&self, reserve: usize, budget: &mut WorkBudget, report: &mut MaintainReport) {
        report.fills.ran = true;
        let shards = self
            .index()
            .map_or(0, |index| index.geometry.shards().len());
        if shards == 0 {
            report.fills.done = true;
            return;
        }
        let mut done = true;
        let mut at = self.maintain.fill_shard.load(Ordering::Relaxed);
        if at >= shards {
            at = 0;
        }
        let mut words = self.fill_words(ShardIndex(at));
        while report.fill_tables < shards {
            let decision = words.map_or(ABSENT_TABLE, |words| pass_bound(words.len()));
            if report.fill_tables > 0 && budget.remaining() < reserve.saturating_add(decision) {
                break;
            }
            let shard = ShardIndex(at);
            at = if at + 1 == shards { 0 } else { at + 1 };
            let table = words;
            words = self.fill_words(ShardIndex(at));
            if let Some(next) = words {
                hint_read(next.as_ptr().cast());
            }
            report.fill_tables += 1;
            let Some(table) = table else {
                probe::note(Primitive::Load);
                budget
                    .debit_n(WorkKind::Visit, ABSENT_TABLE)
                    .expect("the stage minimum or the entry check funded the absent table");
                continue;
            };
            if let Some(records) = sight_free(table, reserve, budget) {
                report.fills.visited += records;
                continue;
            }
            match self.service_fills(shard, 1, budget) {
                Ok(served) => {
                    report.fills.visited += served.examined;
                    done &= !served.budget_exhausted;
                    report.more_work |= served.budget_exhausted;
                }
                Err(FillServiceError::Corrupt(served)) => {
                    report.fills.visited += served.examined;
                    report.contended += 1;
                    done = false;
                }
                Err(error) => {
                    report.contended += 1;
                    report.more_work |= error == FillServiceError::Contended;
                    done = false;
                }
            }
        }
        self.maintain.fill_shard.store(at, Ordering::Relaxed);
        report.fills.done = done;
    }

    /// The state words of `shard`'s fill table, or `None` for a shard with
    /// `F = 0`.
    fn fill_words(&self, shard: ShardIndex) -> Option<&[AtomicU64]> {
        let table = self.fill_table(shard)?;
        // SAFETY: the storage is live under the root gate, `table` is one of
        // its root image's tables, and the run reads only the shared words.
        Some(unsafe { self.fill_view(table) }.states)
    }

    #[inline(never)]
    fn reclaim_stage(&self, budget: &mut WorkBudget, report: &mut MaintainReport) {
        report.reclaim.ran = true;
        match self.service(budget) {
            Ok(served) => {
                report.reclaim.visited = served.visited;
                // A pass cut short leaves work only while an obligation was
                // pending, and an extent returned ahead of its slot's final
                // return leaves that slot for a later visit.
                // A slot the park pass retired while a volume was attached,
                // or a retired slot with no right or anchor left that
                // `reusable` refused against the loaded durable prefix,
                // returns at a later call's retired pass once no right or
                // anchor remains and `reusable` admits its position, so
                // it leaves work; the count is zero once the open volume's
                // metadata halts.
                let unfinished = (served.budget_exhausted && served.pending)
                    || served.partial != 0
                    || served.awaiting_journal != 0;
                report.reclaim.done = !unfinished;
                report.reclaimed_bytes = served.reclaimed_bytes;
                report.more_work |= unfinished;
            }
            Err(ServiceError::Gate(error)) => {
                report.contended += 1;
                report.more_work |= error == GateError::Contended;
            }
            Err(_) => report.more_work = true,
        }
    }

    #[inline(never)]
    fn certify_stage(&self, budget: &mut WorkBudget, report: &mut MaintainReport) {
        report.certify.ran = true;
        // Read on this thread before the call, so coherence places it no
        // later than any certificate the call publishes.
        let eras = self.eras();
        let before = eras.certified.load(Ordering::Relaxed);
        // The certificate never exceeds the era and a pass begins only above
        // the certificate, so an era read at or below it has no retirement to
        // certify and no pass in progress: the stage decides from these two
        // reads and the gate word, charged as three visits whether the gate
        // word is read, and takes the grace gate only to find the poisoning
        // that closes admission. A retirement the era read misses is
        // certified by a later call.
        let gate = self.maintenance_gate();
        probe::note_n(Primitive::Load, CERTIFY_SIGHTING);
        budget
            .debit_n(WorkKind::Visit, CERTIFY_SIGHTING)
            .expect("the stage minimum covered the sighting");
        if eras.era.load(Ordering::Relaxed) <= before && !gate.is_poisoned() {
            report.certify.done = true;
            report.certify_stall = Some(CertifyStall::NoProgress);
            self.maintain
                .certify_stalled
                .store(false, Ordering::Relaxed);
            return;
        }
        let stall = match self.certify(budget) {
            Ok(certified) => {
                report.certify.visited = certified.visited;
                report.certify.done = certified.certified.is_some();
                match certified.certified {
                    None => Some(CertifyStall::InProgress),
                    Some(era) if era == before => Some(CertifyStall::NoProgress),
                    Some(_) => None,
                }
            }
            Err(ServiceError::Gate(GateError::Contended)) => {
                report.contended += 1;
                report.more_work = true;
                Some(CertifyStall::Busy)
            }
            Err(ServiceError::Gate(GateError::Poisoned)) => {
                report.contended += 1;
                Some(CertifyStall::Poisoned)
            }
            Err(_) => Some(CertifyStall::InProgress),
        };
        report.more_work |= matches!(stall, None | Some(CertifyStall::InProgress));
        report.certify_stall = stall;
        // A busy grace gate means another certifier is running, which may be
        // progress. Any other stall blocks recovery only while a retirement
        // is still uncertified: the certificate lies below the era.
        // Both loads feed only this advisory reading, so they are relaxed: a
        // stale pair can misread one call's stall, which the next call
        // corrects, while an acquire load would wait, on AArch64, for a
        // release store the call just made, such as the grace gate's, to
        // drain.
        let uncertified = eras.certified.load(Ordering::Relaxed) < eras.era.load(Ordering::Relaxed);
        self.maintain.certify_stalled.store(
            uncertified && stall.is_some() && stall != Some(CertifyStall::Busy),
            Ordering::Relaxed,
        );
    }

    #[inline(never)]
    fn expiry_stage(&self, budget: &mut WorkBudget, report: &mut MaintainReport) {
        report.expiry.ran = true;
        match self.expire_step(budget) {
            Ok(swept) => {
                report.expiry.visited = swept.visited;
                report.expiry.done = !swept.budget_exhausted
                    && !swept.clock_unavailable
                    && !matches!(
                        swept.commit,
                        Some(Commit::Contended | Commit::Poisoned | Commit::Corrupt)
                    );
                report.clock_unavailable |= swept.clock_unavailable;
                report.tally(
                    Retention {
                        held: swept.held,
                        unpublished: swept.unpublished,
                        detached_seen: swept.detached_seen,
                        stale_marks: swept.stale_marks,
                    },
                    swept.commit,
                    false,
                );
                // A removal that happened, here or by another caller, or
                // may happen soon leaves more to sweep, as the sweep stopped
                // at its candidate; a poisoned or malformed shard never will.
                let pending = matches!(
                    swept.commit,
                    Some(
                        Commit::Evicted { .. }
                            | Commit::Absent
                            | Commit::Replacing
                            | Commit::Contended
                    )
                );
                report.more_work |= swept.budget_exhausted || pending;
            }
            Err(error) => {
                report.contended += 1;
                report.more_work |= error == EvictError::Gate(GateError::Contended);
            }
        }
    }

    #[inline(never)]
    fn headroom_stage(
        &self,
        marks: VolumeWatermarks,
        budget: &mut WorkBudget,
        report: &mut MaintainReport,
    ) {
        report.headroom.ran = true;
        #[cfg(test)]
        if let Some(interpose) = INTERPOSE_BEFORE_HEADROOM_SELECT.with(std::cell::Cell::take) {
            interpose();
        }
        // The predicate is read under the selection hold, so an extent or a
        // slot freed before the hold is counted before a victim is chosen,
        // and a busy gate costs the attempt alone.
        let mut short = false;
        let evicted = match self.evict_step(budget, |tables, budget| {
            budget
                .debit(WorkKind::Comparison)
                .expect("the stage minimum covered the predicate read");
            let read = self.read_domain(tables, marks);
            short = read.short();
            report.domain = Some(read);
            short
        }) {
            Ok(evicted) => evicted,
            Err(EvictError::Gate(error)) => {
                // A poisoned pool gate stays poisoned; only a busy one may
                // free up.
                report.contended += 1;
                report.more_work |= error == GateError::Contended;
                return;
            }
            Err(EvictError::TornDown | EvictError::BudgetExhausted) => {
                unreachable!("an open call runs on a live storage and checked the stage minimum")
            }
        };
        if short {
            saturating_add(&self.maintain.short_stages, 1);
        }
        if matches!(evicted.commit, Some(Commit::Evicted { .. })) {
            saturating_add(&self.maintain.evicted_units, evicted.units);
        }
        let domain = report
            .domain
            .as_ref()
            .expect("the selection hold read the domain");
        // With no claimable unit, a volume kept at its placeable watermark
        // only by evictions still in flight, and certification not
        // advancing, only readers leaving grace can recover capacity.
        let only_in_flight =
            domain.claimable_units == 0 && domain.in_flight_units > 0 && !domain.units_short();
        if only_in_flight && self.maintain.certify_stalled.load(Ordering::Relaxed) {
            report.blocked_by_readers_or_io = true;
        }
        let members = domain.members;
        // The hold applied any pending mark before the predicate, so its
        // count is tallied whether or not a victim was chosen.
        report.headroom.visited = evicted.visited;
        report.tally(
            Retention {
                held: evicted.held,
                unpublished: evicted.unpublished,
                detached_seen: evicted.detached_seen,
                stale_marks: evicted.stale_marks,
            },
            evicted.commit,
            true,
        );
        let refused = &self.maintain.refused_commits;
        if !short {
            refused.store(0, Ordering::Relaxed);
            report.headroom.done = true;
            return;
        }
        if evicted.beyond_allowance {
            // Only returns of retired extents make room for this victim;
            // Reclaim's stage carries that work.
            refused.store(0, Ordering::Relaxed);
            report.headroom.done = true;
            report.blocked_by_readers_or_io |= evicted.blocked_by_readers_or_io;
            return;
        }
        if evicted.commit == Some(Commit::History) {
            // No removal record fits until the suffix writes, certifies, extends or hands off; a later call retries.
            refused.store(0, Ordering::Relaxed);
            report.headroom.done = true;
            return;
        }
        if matches!(evicted.commit, Some(Commit::Poisoned | Commit::Corrupt)) {
            // The hand has passed the refused member. Before SIEVE chooses an
            // evictable member of a healthy shard, it refuses each member of a
            // poisoned shard at most once per pass and clears a visited member
            // in the first of two passes, so only a run of refusals spanning
            // two passes over the members leaves no commit a funded call can
            // make.
            let run = refused.load(Ordering::Relaxed).saturating_add(1);
            refused.store(run, Ordering::Relaxed);
            report.more_work |= run < 2 * members;
            return;
        }
        if evicted.commit.is_some() {
            refused.store(0, Ordering::Relaxed);
        }
        report.headroom.done =
            !evicted.budget_exhausted && evicted.commit != Some(Commit::Contended);
        report.blocked_by_readers_or_io |= evicted.blocked_by_readers_or_io;
        // The domain was short when read; a later call decides again.
        report.more_work = true;
    }

    /// The domain's exact state under the caller's hold on the pool gate.
    #[inline(always)]
    fn read_domain(
        &self,
        tables: &mut super::tables::Tables<'_>,
        marks: VolumeWatermarks,
    ) -> DomainReport {
        let domain = *tables.domain;
        let free_units = tables.free_units();
        let placeable_units = tables.placeable_units();
        let reserve_units = self.pool.image.reserve_units;
        // One escrow sample prices both fields, so a gate-free refund
        // between two reads cannot leave them disagreeing.
        let escrow_units = self.pool.telemetry().escrow();
        DomainReport {
            free_units,
            placeable_units,
            reserve_units,
            claimable_units: super::reserve::claimable(free_units, reserve_units, escrow_units),
            escrow_units,
            in_flight_units: domain.in_flight_units,
            in_flight: domain.in_flight as usize,
            detached: domain.detached as usize,
            members: domain.members as usize,
            low_units: marks.low_units,
            free_slots: tables.state.ledger.free,
            min_free_slots: marks.min_free_slots,
            pending_mark: self.pool.pending_mark().is_pending(),
            retired_units: domain.retired_units,
            retired_limit: marks.retired_units,
            longest_run: tables.longest_free_run(),
        }
    }
}

/// The Fills run accepts an all-Free observation of a table's state words
/// as coverage of the table. The sighting needs the allowance above
/// `reserve` to fund it and a full gated pass behind it, and charges one
/// visit per word whatever it found, so a word other than Free leaves the
/// pass fully funded. The reads are relaxed: a departure after its state
/// word is read can leave the observation all-Free.
fn sight_free(words: &[AtomicU64], reserve: usize, budget: &mut WorkBudget) -> Option<usize> {
    let records = words.len();
    let funded = records
        .saturating_add(pass_bound(records))
        .saturating_add(reserve);
    if records == 0 || budget.remaining() < funded {
        return None;
    }
    budget
        .debit_n(WorkKind::Visit, records)
        .expect("the allowance covered the sighting");
    probe::note_n(Primitive::Load, records);
    let any = words
        .iter()
        .fold(fill::FREE, |any, state| any | state.load(Ordering::Relaxed));
    (any == fill::FREE).then_some(records)
}

/// The most steps one gated fill service pass can spend: one gate attempt,
/// and each record's visit and possible release.
fn pass_bound(records: usize) -> usize {
    records
        .saturating_mul(FILL_SERVICE_PER_RECORD)
        .saturating_add(1)
}

/// The stage a call that started in `first` runs at `position`, from zero.
fn stage_at(first: MaintainStage, position: usize) -> MaintainStage {
    MaintainStage::ALL[(first as usize + position) % MaintainStage::ALL.len()]
}

fn saturating_add(total: &AtomicU64, add: usize) {
    let sum = total.load(Ordering::Relaxed).saturating_add(add as u64);
    total.store(sum, Ordering::Relaxed);
}
