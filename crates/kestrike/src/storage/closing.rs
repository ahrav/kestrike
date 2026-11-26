//! Bounded close service: after admission closes, one caller-scheduled call
//! at a time advances a persistent cursor through the index, the volume and
//! the certification pass, removing the mappings that remain, servicing the
//! slots that can return and certifying grace, and reports exactly what it
//! observed.
//!
//! Stages, in cursor order:
//!
//! - Index. Every pair position of every enabled shard, bucket by bucket.
//!   Positions are read in runs under the shard's gate, one nonblocking
//!   attempt per run: a run reads consecutive positions up to the first
//!   occupied pair. That pair must name a visible object, whose identity and,
//!   through the anchor the mapping holds, fingerprint are copied under the
//!   hold; a pair that fails to resolve to a visible object is corruption,
//!   and `read_run` poisons the gate for it. Under the
//!   same hold the mapping is removed exactly, by
//!   fingerprint and identity, through the walk publication uses and
//!   removal's own commit, and the hold ends before the retirement
//!   handoff. A pair that names a restored slot of a warm attempt that has
//!   not committed is left mapped and counted as a held slot, since the
//!   storage of an ended attempt keeps the slots it installed; the attempt
//!   records its hold in the pool before its first install and clears it
//!   at its commit. A run also ends at the
//!   shard's last position and before a position the allowance cannot pay,
//!   releasing the gate. A removal that finds the pair gone is counted
//!   corruption: the sweep read the pair under the hold the removal runs
//!   under, so nothing else removed it. A busy shard gate is counted and
//!   leaves the shard and position cursor for the index stage's next visit;
//!   the call still moves on to the fills stage, so the later stages run. A
//!   poisoned shard
//!   gate is counted as a blocker and the stage moves past the shard. A
//!   shard passed without a visit is one paid step, so a call's work is
//!   bounded by its allowance and not by the shard count. The stage ends when the last enabled shard's last
//!   position is visited.
//! - Fills. Fill service runs on one shard's fill table at a time, through
//!   the same funded pass [`Storage::service_fills`] makes, until its own
//!   calls have examined, consecutively, at least as many records as the
//!   table holds; the table's cursor is shared with ordinary fill service, so
//!   a call that finds it away from where its last call left it starts its
//!   count over rather than credit records another caller examined. Departed
//!   records with no follower joined return to Free; live records, departed
//!   records a follower is still joined to, and the record custody names are
//!   counted, never revoked. A shard without a table is one paid step. A
//!   busy gate is counted and leaves the table's own cursor for the next
//!   call; a poisoned gate is counted as a blocker; either way the stage
//!   moves to the next shard. An index without any fill table passes the
//!   stage for free.
//! - Volume. Slot service runs until the stage's calls have covered,
//!   consecutively, at least as many slot positions as the volume holds in
//!   each of its two passes, retired and park; a pass may span several
//!   close-service calls when one allowance cannot pay for all of it. Each
//!   pass's cursor is shared with ordinary service calls, so a call that
//!   finds a cursor away from where the stage's last call left it starts
//!   that pass's count over from the call's coverage. A call runs only the
//!   passes whose count is below the slot count, and the pass it runs alone
//!   may spend the whole allowance.
//!   Retired slots whose anchors grace has released return their extents,
//!   one per visit, and a slot left with extents to return counts as held,
//!   abandonment marks reach the ledger, and held slots are counted. The
//!   pass ends with one read of the volume's pending-mark count, one step
//!   charged by the call that makes it; a call that completes the slots but
//!   cannot pay the read leaves it for the next call.
//!   A busy gate is counted and leaves the volume's two pass cursors for
//!   the next call; a poisoned gate is counted as a blocker; either way the stage
//!   moves on.
//! - Certification. One certification call, resumed from the engine's own
//!   pass cursor; it takes the root's maintenance gate, and a busy or
//!   poisoned maintenance gate is counted with the volume's.
//! - Status. Every registration record's claim and idle credits, one
//!   `Comparison` step each, then the engine-wide credit count, one step, so
//!   the report can
//!   name forgotten or live registrations and the credits behind leases.
//!
//! After the status stage the cursor returns to the index stage: obligations
//! that certification just made releasable return on the next pass.
//!
//! A run preflights its gate attempt and first visit together, then charges the attempt before trying the gate.
//! Each visit is charged under the taken gate before its position is read.
//! A removal charges as publication does, excluding its run's already-paid gate attempt.
//! Each call makes at most one full index sweep, one fill-service call per table, one slot-service call and one certification call.
//! An action the allowance cannot pay for does not run, and its cursor does not move.
//! A zero allowance makes no visit, gate attempt or cursor advance.
//!
//! Report. [`ClosingReport`] has fixed cardinality. Every count is a
//! decision this call made, so repeated calls never count one decision
//! twice; portions the call did not reach are unvisited, and busy, poisoned
//! and unfunded portions leave `complete` false. Blockers name what the call saw at the moment it
//! looked: claimed registrations, reserved credits, held slots, live fill
//! records, pending marks and poisoned gates. A blocker may end after its observation, and
//! the report claims only the observation. The report never claims
//! `Drained` or a clear engine; finalization is the only path that proves
//! either.
//!
//! One caller. Calls are serialized by a gate in the outer owner, whose one
//! attempt is the first charge of every call; a second concurrent call is
//! refused `Contended` without touching a cursor, and a gate a panicking
//! call poisoned refuses `Poisoned` from then on. The service refuses before
//! close, and in the `Finalizing` and `Drained` phases, before any mapping
//! is read; it never calls the blocking whole-domain inspection.

use std::ops::Range;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::AllocationId;
use super::attempt::FillServiceError;
use super::budget::{WorkBudget, WorkKind};
use super::finalize::Phase;
use super::gate::{Gate, GateError, GateGuard};
use super::lease::record_credits;
use super::os::Platform;
use super::owner::{IndexOwner, Storage};
use super::probe::{self, Primitive};
use super::release::{Passes, ServiceError};
use super::remove::RemoveError;
use super::shards::Tables;
use super::word;
use crate::index::{BucketView, CONTROL_MASK, Corrupt, Identity, PAIRS, ShardIndex, is_occupied};

/// The stage the cursor stands in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(usize)]
pub enum CloseStage {
    #[default]
    Index = 0,
    Fills = 1,
    Volume = 2,
    Certify = 3,
    Status = 4,
}

impl CloseStage {
    const fn encode(self) -> usize {
        self as usize
    }

    /// The stage a word the cursor wrote encodes; only `encode` writes it.
    const fn decode(word: usize) -> Self {
        match word {
            0 => Self::Index,
            1 => Self::Fills,
            2 => Self::Volume,
            3 => Self::Certify,
            4 => Self::Status,
            _ => unreachable!(),
        }
    }
}

/// The owner persists the close cursor, which records each stage's next action.
/// Written only under the close gate.
pub(super) struct CloseCursor {
    pub(super) gate: Gate,
    stage: AtomicUsize,
    shard: AtomicUsize,
    position: AtomicUsize,
    /// The volume's retired pass.
    slots: PassCount,
    /// The volume's park pass.
    parked: PassCount,
    /// The shard whose fill table the fills stage services next.
    fill_shard: AtomicUsize,
    /// The current table's record pass.
    fills: PassCount,
    record: AtomicUsize,
    /// Idle lease credits summed over the records the status stage visited
    /// so far.
    idle: AtomicUsize,
}

impl CloseCursor {
    pub(super) fn start() -> Self {
        Self {
            gate: Gate::open(),
            stage: AtomicUsize::new(CloseStage::Index.encode()),
            shard: AtomicUsize::new(0),
            position: AtomicUsize::new(0),
            slots: PassCount::start(),
            parked: PassCount::start(),
            fill_shard: AtomicUsize::new(0),
            fills: PassCount::start(),
            record: AtomicUsize::new(0),
            idle: AtomicUsize::new(0),
        }
    }
}

#[cfg(test)]
impl CloseCursor {
    /// The shard and the position in it the index stage decides next.
    pub(super) fn index_position(&self) -> (usize, usize) {
        (
            self.shard.load(Ordering::Relaxed),
            self.position.load(Ordering::Relaxed),
        )
    }

    /// Every cursor word: the stage, the index shard and position, the retired, park and fill pass counts, the fill shard, the status record and the idle credits summed so far.
    pub(super) fn words(&self) -> [usize; 9] {
        let load = |word: &AtomicUsize| word.load(Ordering::Relaxed);
        [
            load(&self.stage),
            load(&self.shard),
            load(&self.position),
            load(&self.slots.examined),
            load(&self.parked.examined),
            load(&self.fills.examined),
            load(&self.fill_shard),
            load(&self.record),
            load(&self.idle),
        ]
    }

    /// Plants a sweep that restarts on interference: sends the index stage back to the first shard's first position.
    pub(super) fn plant_index_restart(&self) {
        self.shard.store(0, Ordering::Relaxed);
        self.position.store(0, Ordering::Relaxed);
    }

    /// Plants credit across a foreign move: makes `at` the cursor position that resumes the retired pass's count.
    pub(super) fn plant_retired_resume(&self, at: usize) {
        self.slots.next.store(at, Ordering::Relaxed);
    }
}

/// One table's pass spread over close-service calls, whose service cursor
/// is shared with ordinary callers: how many units the pass's own calls have
/// examined consecutively, and where its next call must find the cursor for
/// its units to count.
struct PassCount {
    examined: AtomicUsize,
    next: AtomicUsize,
}

impl PassCount {
    const fn start() -> Self {
        Self {
            examined: AtomicUsize::new(0),
            next: AtomicUsize::new(0),
        }
    }

    /// Units the pass's own calls have examined so far.
    fn examined(&self) -> usize {
        self.examined.load(Ordering::Relaxed)
    }

    /// Credits one service call that covered `covered` consecutive units
    /// from `first` out of `total`, and reports whether the pass is now
    /// complete. A call that found the cursor away from where the pass's
    /// last call left it starts the count over: another caller moved it, and
    /// its units are not this pass's. An incomplete pass records where the
    /// next call must find the cursor; a complete one stays complete until
    /// [`reset`](Self::reset).
    fn credit(&self, first: usize, covered: usize, total: usize) -> bool {
        let examined = self.examined();
        if examined >= total {
            return true;
        }
        let resumed = first == self.next.load(Ordering::Relaxed);
        let examined = if examined == 0 || resumed {
            examined + covered
        } else {
            covered
        };
        self.examined.store(examined, Ordering::Relaxed);
        if examined < total {
            self.next
                .store((first + covered) % total, Ordering::Relaxed);
            return false;
        }
        true
    }

    /// Starts the next table's pass.
    fn reset(&self) {
        self.examined.store(0, Ordering::Relaxed);
    }
}

/// What still stood in the way of a clear engine when this call looked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CloseBlockers {
    /// Registration records claimed at the status stage's visit.
    pub registrations: usize,
    /// Lease credits reserved at the status stage's visit.
    pub leases: usize,
    /// Slots service found held by an owner, a right or an anchor,
    /// slots whose visit returned one extent and left the rest for a
    /// later visit, and index pairs the sweep left mapped because they name
    /// a restored slot of a warm attempt that ended before its commit.
    pub held_slots: usize,
    /// Fill records service found occupied by a live attempt, named by a
    /// shard's custody, or departed with a follower still joined.
    pub live_fills: usize,
    /// Pending marks the volume carried after service.
    pub pending_marks: usize,
    /// Shard, pool and maintenance gate attempts that found the gate
    /// poisoned, plus runs, removals and fill passes that found a table
    /// malformed and poisoned the shard's gate.
    pub poisoned_gates: usize,
}

/// What one close-service call observed. Every count is this call's own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ClosingReport {
    /// The stage the call started in.
    pub started_in: CloseStage,
    /// Index positions read under a shard gate and decided: empty, removed,
    /// held or corrupt. A position whose removal the allowance or a busy
    /// gate refused is not decided; the next call reads it again and counts
    /// it then, so the decided counts across calls add up to the positions.
    pub positions_visited: usize,
    /// Mappings removed exactly.
    pub removed: usize,
    /// Shard gate attempts that found the gate busy, by the index sweep or
    /// by fill service.
    pub shards_busy: usize,
    /// Fill service calls that took a shard gate.
    pub fill_calls: usize,
    /// Fill records the fill service calls examined.
    pub fills_visited: usize,
    /// Departed fill records returned to Free.
    pub fills_released: usize,
    /// Service calls that took the pool gate.
    pub service_calls: usize,
    /// Retired and parked slots the service calls visited, summed from
    /// [`ServiceReport::visited`](super::ServiceReport::visited).
    pub slots_visited: usize,
    /// Obligations service returned to the volume.
    pub serviced: usize,
    /// Bytes of the full charged extents (header, payload and padding)
    /// the service calls returned to the allocator.
    pub reclaimed_bytes: usize,
    /// Anchors released after grace.
    pub anchors_released: usize,
    /// Gate attempts, by service on the pool gate or by certification
    /// on the maintenance gate, that found the gate busy.
    pub gates_busy: usize,
    /// Registration records the certification call visited.
    pub records_certified: usize,
    /// The certified era after this call's certification, when it ran.
    pub certified: Option<u64>,
    /// Registration records the status stage visited.
    pub records_visited: usize,
    pub blockers: CloseBlockers,
    /// The allowance ended before the next indivisible action.
    pub budget_exhausted: bool,
    /// Every stage from the starting one through the status stage was
    /// visited to its end in this call with no busy or poisoned gate; the
    /// cursor stands at the index stage again. A busy or poisoned gate
    /// leaves this false with the stages after it still run.
    pub complete: bool,
}

/// Why a close-service call made no observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseError {
    /// Admission is open; the service runs only after close.
    Open,
    /// The owner is finalizing or drained; no mapping may be read.
    NotLive,
    /// Another close-service call holds the cursor; the attempt is charged.
    Contended,
    /// A call that panicked poisoned the cursor's gate; the attempt is
    /// charged and no later call runs.
    Poisoned,
    /// The allowance could not pay the gate attempt.
    BudgetExhausted,
}

impl From<super::budget::BudgetExhausted> for CloseError {
    fn from(_: super::budget::BudgetExhausted) -> Self {
        Self::BudgetExhausted
    }
}

/// The allowance ended before the next indivisible action.
struct Budget;

impl<P: Platform> Storage<P> {
    /// One bounded close-service call, as the module documentation
    /// describes.
    ///
    /// # Errors
    ///
    /// [`CloseError`]; nothing was visited and no cursor moved.
    pub fn close_service(&self, budget: &mut WorkBudget) -> Result<ClosingReport, CloseError> {
        if self.phase() != Phase::Live {
            return Err(CloseError::NotLive);
        }
        if !self.is_closed() {
            return Err(CloseError::Open);
        }
        budget.preflight(1)?;
        budget
            .debit(WorkKind::CoordinationAttempt)
            .expect("the preflight covered the attempt");
        // Every return below releases the hold, so its drop is a stage's
        // panic, also in a call made by a thread that was already unwinding.
        let guard = self
            .close
            .gate
            .try_lock()
            .map(GateGuard::poison_on_unwind)
            .map_err(|refused| match refused {
                GateError::Contended => CloseError::Contended,
                GateError::Poisoned => CloseError::Poisoned,
            })?;
        let mut report = ClosingReport {
            started_in: CloseStage::decode(self.close.stage.load(Ordering::Relaxed)),
            ..ClosingReport::default()
        };
        match self.advance(budget, &mut report) {
            Ok(unhindered) => report.complete = unhindered,
            Err(Budget) => report.budget_exhausted = true,
        }
        guard.release();
        Ok(report)
    }

    /// Runs the stages from the cursor until the status stage ends or the
    /// allowance ends; reports whether no gate hindered any stage.
    fn advance(&self, budget: &mut WorkBudget, report: &mut ClosingReport) -> Result<bool, Budget> {
        let mut unhindered = true;
        loop {
            let next = match CloseStage::decode(self.close.stage.load(Ordering::Relaxed)) {
                CloseStage::Index => {
                    unhindered &= self.sweep_index(budget, report)?;
                    CloseStage::Fills
                }
                CloseStage::Fills => {
                    unhindered &= self.sweep_fills(budget, report)?;
                    CloseStage::Volume
                }
                CloseStage::Volume => {
                    unhindered &= self.sweep_volume(budget, report)?;
                    CloseStage::Certify
                }
                CloseStage::Certify => {
                    unhindered &= self.certify_once(budget, report)?;
                    CloseStage::Status
                }
                CloseStage::Status => {
                    self.status(budget, report)?;
                    self.close
                        .stage
                        .store(CloseStage::Index.encode(), Ordering::Relaxed);
                    return Ok(unhindered);
                }
            };
            self.close.stage.store(next.encode(), Ordering::Relaxed);
        }
    }

    /// The index stage from its shard and position cursor: `Ok(true)` when
    /// it reached the last position, `Ok(false)` when a gate hindered it.
    fn sweep_index(
        &self,
        budget: &mut WorkBudget,
        report: &mut ClosingReport,
    ) -> Result<bool, Budget> {
        let Some(index) = self.index() else {
            return Ok(true);
        };
        let shards = index.geometry.shards();
        let mut unhindered = true;
        loop {
            let shard = self.close.shard.load(Ordering::Relaxed);
            if shard >= shards.len() {
                self.close.shard.store(0, Ordering::Relaxed);
                self.close.position.store(0, Ordering::Relaxed);
                return Ok(unhindered);
            }
            let positions = positions_of(index, ShardIndex(shard));
            let position = self.close.position.load(Ordering::Relaxed);
            if shards[shard].visible == 0 || position >= positions {
                // A shard passed without a visit, disabled or without
                // capacity, is one paid step, so a call's work stays within
                // its allowance whatever the shard count; a shard whose
                // positions were all decided was paid by their visits.
                if position == 0 {
                    budget.debit(WorkKind::Comparison).map_err(|_| Budget)?;
                }
                self.close.shard.store(shard + 1, Ordering::Relaxed);
                self.close.position.store(0, Ordering::Relaxed);
                continue;
            }
            // One gate attempt and the run's first visit, preflighted
            // together.
            budget.preflight(2).map_err(|_| Budget)?;
            budget
                .debit(WorkKind::CoordinationAttempt)
                .expect("the preflight covered the attempt");
            let run = match self.read_run(index, ShardIndex(shard), position..positions, budget) {
                Ok(run) => run,
                Err(RunError::Contended) => {
                    // The shard and position stay for the index stage's next
                    // visit; the stages after this one still run.
                    report.shards_busy += 1;
                    return Ok(false);
                }
                Err(RunError::Poisoned { visited }) => {
                    report.positions_visited += visited;
                    report.blockers.poisoned_gates += 1;
                    unhindered = false;
                    // A poisoned shard cannot be swept; the stage moves past
                    // it so the shards after it are still swept.
                    self.close.shard.store(shard + 1, Ordering::Relaxed);
                    self.close.position.store(0, Ordering::Relaxed);
                    continue;
                }
            };
            report.positions_visited += run.empty;
            self.close.position.store(run.next, Ordering::Relaxed);
            let Some(occupant) = run.occupant else {
                if run.next < positions {
                    // The allowance ended inside the run.
                    return Err(Budget);
                }
                continue;
            };
            // A restored slot of a warm attempt that has not committed keeps
            // its anchor and extent, so its pair stays mapped: the position
            // is decided as held, and the hold ends with no table write.
            if self.warm_held(occupant.id) {
                occupant.hold.release();
                report.positions_visited += 1;
                report.blockers.held_slots += 1;
                self.close.position.store(run.next + 1, Ordering::Relaxed);
                continue;
            }
            // The occupied position stays undecided, and the cursor on it,
            // until its removal is decided. The removal runs under the hold
            // that found the pair, and ends it.
            match self.remove_held(
                occupant.hold,
                ShardIndex(shard),
                occupant.fingerprint,
                occupant.id,
                budget,
            ) {
                Ok(_) => report.removed += 1,
                Err(RemoveError::BudgetExhausted) => return Err(Budget),
                Err(RemoveError::Contended) => {
                    report.shards_busy += 1;
                    return Ok(false);
                }
                Err(RemoveError::Corrupt) => {
                    // The removal poisoned the shard's gate: the position is
                    // decided, and the stage moves past the shard as it does
                    // for a gate found poisoned.
                    report.positions_visited += 1;
                    report.blockers.poisoned_gates += 1;
                    unhindered = false;
                    self.close.shard.store(shard + 1, Ordering::Relaxed);
                    self.close.position.store(0, Ordering::Relaxed);
                    continue;
                }
                Err(RemoveError::Poisoned) => {
                    report.blockers.poisoned_gates += 1;
                    unhindered = false;
                    self.close.shard.store(shard + 1, Ordering::Relaxed);
                    self.close.position.store(0, Ordering::Relaxed);
                    continue;
                }
                Err(RemoveError::Absent | RemoveError::Replacing) => {
                    unreachable!("a removal under the sweep's hold finds its pair or poisons")
                }
                Err(RemoveError::History) => {
                    unreachable!(
                        "the close's drain records no removal, so the suffix never refuses it"
                    )
                }
                Err(RemoveError::NoIndex) => return Ok(unhindered),
            }
            report.positions_visited += 1;
            self.close.position.store(run.next + 1, Ordering::Relaxed);
        }
    }

    /// The fills stage from its shard cursor: `Ok(false)` when a busy or
    /// poisoned gate prevented servicing a table.
    fn sweep_fills(
        &self,
        budget: &mut WorkBudget,
        report: &mut ClosingReport,
    ) -> Result<bool, Budget> {
        let tables = &self.root_image.fills;
        if !self.root_image.any_fills {
            return Ok(true);
        }
        let mut unhindered = true;
        loop {
            let shard = self.close.fill_shard.load(Ordering::Relaxed);
            if shard >= tables.len() {
                self.close.fill_shard.store(0, Ordering::Relaxed);
                return Ok(unhindered);
            }
            let Some(table) = &tables[shard] else {
                // A shard without a table is one paid step to pass, so a
                // call's work stays within its allowance whatever the shard
                // count.
                budget.debit(WorkKind::Comparison).map_err(|_| Budget)?;
                self.close.fill_shard.store(shard + 1, Ordering::Relaxed);
                continue;
            };
            let records = table.states.len();
            // A completed pass moves to the next shard in the call that
            // completes it, so a call always finds this pass incomplete.
            match self.service_fills(ShardIndex(shard), 1, budget) {
                Ok(service) => {
                    report.fill_calls += 1;
                    report.fills_visited += service.examined;
                    report.fills_released += service.released;
                    report.blockers.live_fills += service.retained;
                    if !self
                        .close
                        .fills
                        .credit(service.first, service.examined, records)
                    {
                        debug_assert!(service.budget_exhausted);
                        return Err(Budget);
                    }
                }
                Err(FillServiceError::BudgetExhausted) => return Err(Budget),
                Err(FillServiceError::Contended) => {
                    report.shards_busy += 1;
                    unhindered = false;
                }
                Err(FillServiceError::Corrupt(progress)) => {
                    // The pass took the gate and visited these before it
                    // poisoned the gate on the malformed word.
                    report.fill_calls += 1;
                    report.fills_visited += progress.examined;
                    report.fills_released += progress.released;
                    report.blockers.live_fills += progress.retained;
                    report.blockers.poisoned_gates += 1;
                    unhindered = false;
                }
                Err(FillServiceError::Poisoned) => {
                    report.blockers.poisoned_gates += 1;
                    unhindered = false;
                }
                Err(FillServiceError::NoIndex) => return Ok(unhindered),
            }
            self.close.fills.reset();
            self.close.fill_shard.store(shard + 1, Ordering::Relaxed);
        }
    }

    /// `Ok(false)` when a busy or poisoned gate prevents servicing the
    /// volume.
    fn sweep_volume(
        &self,
        budget: &mut WorkBudget,
        report: &mut ClosingReport,
    ) -> Result<bool, Budget> {
        let mut unhindered = true;
        let live = &self.pool;
        let slots = live.descriptor().slot_count;
        let passes = Passes {
            retired: self.close.slots.examined() < slots,
            parked: self.close.parked.examined() < slots,
        };
        let outcome = if passes.retired || passes.parked {
            self.service_passes(budget, passes).map(Some)
        } else {
            Ok(None)
        };
        match outcome {
            Ok(None) => {}
            Ok(Some(service)) => {
                report.service_calls += 1;
                report.slots_visited += service.visited;
                report.serviced += service.serviced;
                report.reclaimed_bytes += service.reclaimed_bytes;
                report.anchors_released += service.released;
                report.blockers.held_slots += service.held + service.partial;
                let retired = self
                    .close
                    .slots
                    .credit(service.first, service.covered, slots);
                let parked =
                    self.close
                        .parked
                        .credit(service.park_first, service.park_covered, slots);
                if !(retired && parked) {
                    debug_assert!(service.budget_exhausted);
                    return Err(Budget);
                }
            }
            Err(ServiceError::BudgetExhausted) => return Err(Budget),
            Err(ServiceError::Gate(GateError::Contended)) => {
                report.gates_busy += 1;
                unhindered = false;
            }
            Err(ServiceError::Gate(GateError::Poisoned)) => {
                report.blockers.poisoned_gates += 1;
                unhindered = false;
            }
            Err(ServiceError::TornDown) => {}
        }
        // The pass's one blocker observation, paid by the call that makes
        // it; a pass whose slots are done waits here for a call that can.
        budget.debit(WorkKind::Comparison).map_err(|_| Budget)?;
        probe::note(Primitive::Load);
        report.blockers.pending_marks += live.telemetry().pending_marks.load(Ordering::Acquire);
        self.close.slots.reset();
        self.close.parked.reset();
        Ok(unhindered)
    }

    /// One certification call; `Ok(false)` when its gate hindered it.
    fn certify_once(
        &self,
        budget: &mut WorkBudget,
        report: &mut ClosingReport,
    ) -> Result<bool, Budget> {
        match self.certify(budget) {
            Ok(certify) => {
                report.records_certified += certify.visited;
                report.certified = certify.certified;
                if certify.budget_exhausted {
                    return Err(Budget);
                }
                Ok(true)
            }
            Err(ServiceError::BudgetExhausted) => Err(Budget),
            Err(ServiceError::Gate(GateError::Contended)) => {
                report.gates_busy += 1;
                Ok(false)
            }
            Err(ServiceError::Gate(GateError::Poisoned)) => {
                report.blockers.poisoned_gates += 1;
                Ok(false)
            }
            Err(ServiceError::TornDown) => Ok(true),
        }
    }

    /// The status stage from its record cursor: one visit per registration
    /// record, reading its claim and its idle credits, then one read of the
    /// engine-wide credit count, which less the idle credits is the count
    /// behind leases, as `outstanding` computes it.
    fn status(&self, budget: &mut WorkBudget, report: &mut ClosingReport) -> Result<(), Budget> {
        let records = self.registrations();
        loop {
            let record = self.close.record.load(Ordering::Relaxed);
            budget.preflight(1).map_err(|_| Budget)?;
            budget
                .debit(WorkKind::Comparison)
                .expect("the preflight covered the visit");
            probe::note(Primitive::Load);
            if record >= records.len() {
                let idle = self.close.idle.load(Ordering::Relaxed);
                let taken = self.leases().reserved.load(Ordering::Acquire);
                report.blockers.leases = taken.saturating_sub(idle);
                self.close.idle.store(0, Ordering::Relaxed);
                self.close.record.store(0, Ordering::Relaxed);
                return Ok(());
            }
            report.records_visited += 1;
            report.blockers.registrations +=
                usize::from(records[record].claimed.load(Ordering::Acquire));
            let idle = record_credits(self, record, Ordering::Acquire);
            self.close.idle.fetch_add(idle, Ordering::Relaxed);
            self.close.record.store(record + 1, Ordering::Relaxed);
        }
    }
}

/// Positions of `shard`: every pair of every physical bucket.
fn positions_of(index: &IndexOwner, shard: ShardIndex) -> usize {
    let Some(image) = index.image.shard(shard) else {
        return 0;
    };
    // SAFETY: the index mapping is owned while the storage is live, which
    // the caller's phase check established.
    unsafe { image.tables(&index.mapping) }.buckets.len() * PAIRS
}

/// Why a run took no hold, or ended the one it took by poisoning it.
enum RunError {
    /// The gate was busy; nothing was read.
    Contended,
    /// The gate was poisoned before the run, with nothing read, or by the
    /// run, on a malformed table: `visited` positions were read and decided,
    /// the last of them the malformed one.
    Poisoned { visited: usize },
}

/// How one gate hold over consecutive positions ended.
struct Run<'s> {
    /// The first position the run did not decide: the occupied one, the
    /// shard's end, or the one the allowance could not pay.
    next: usize,
    /// Unoccupied pair positions the run passed.
    empty: usize,
    /// The occupied pair at `next`, when the run stopped there, with the
    /// hold still taken.
    occupant: Option<Occupant<'s>>,
}

/// An occupied pair a run stopped at: its identity and fingerprint, and the
/// gate hold under which both were read.
struct Occupant<'s> {
    id: AllocationId,
    fingerprint: u64,
    hold: GateGuard<'s>,
}

impl<P: Platform> Storage<P> {
    /// Whether a warm attempt that has not committed holds `id`'s slot: the
    /// pool records such an attempt's hold, and the slot word carries the
    /// recovered-origin marker a bootstrap's install leaves.
    fn warm_held(&self, id: AllocationId) -> bool {
        self.live_pool().is_some_and(|pool| {
            pool.warm_hold.load(Ordering::Acquire)
                && pool
                    .records()
                    .get(id.slot().0)
                    .is_some_and(|record| record.ident.load(Ordering::Acquire) & word::MARKER != 0)
        })
    }

    /// Reads consecutive positions of `shard` from `positions.start` under
    /// its gate, taken with one nonblocking attempt the caller charged,
    /// charging each visit under the gate before its read. The run ends at
    /// `positions.end` or before a position the allowance cannot pay, with
    /// the hold released, or at the first occupied position, whose
    /// fingerprint it copies, with the hold kept for its removal. The caller
    /// preflighted the first visit, so a taken gate always reads at least one
    /// position. A malformed control, or an occupied pair naming no anchored
    /// slot, poisons the gate and is reported as `Poisoned` with the
    /// positions read, as every other gate holder fails closed on one; the
    /// sweep never decides a position past it.
    fn read_run<'s>(
        &'s self,
        index: &'s IndexOwner,
        shard: ShardIndex,
        positions: Range<usize>,
        budget: &mut WorkBudget,
    ) -> Result<Run<'s>, RunError> {
        let image = index.image.shard(shard).ok_or(RunError::Contended)?;
        // SAFETY: the index mapping is owned while the storage is live, which
        // the caller's phase check established.
        let gate = unsafe { image.gate(&index.mapping) };
        // The hold ends by release or poison here, in the sweep or in
        // `remove_held`, so its drop is a panic under it, also in a call made
        // by a thread that was already unwinding.
        let guard =
            gate.try_lock()
                .map(GateGuard::poison_on_unwind)
                .map_err(|error| match error {
                    GateError::Contended => RunError::Contended,
                    GateError::Poisoned => RunError::Poisoned { visited: 0 },
                })?;
        // SAFETY: as above; the tables are read under the gate just taken.
        let tables = unsafe { image.tables(&index.mapping) };
        let mut run = Run {
            next: positions.start,
            empty: 0,
            occupant: None,
        };
        // The allowance is advanced in a local copy, which stays in
        // registers across the scan's atomic loads, and written back when
        // the scan ends.
        let mut allowance = *budget;
        // An occupied pair names a slot the index anchors, so the fingerprint
        // is there to copy; a pair naming no anchored slot is a malformed
        // table, as it is to the gate holders comparing fingerprints, and so
        // is a control word with a reserved bit set.
        let found = scan(&tables, &mut run, positions.end, &mut allowance).and_then(|found| {
            let Some(identity) = found else {
                return Ok(None);
            };
            let id = self
                .live_pool()
                .and_then(|pool| pool.resolve(identity))
                .map(|(id, _)| id)
                .ok_or(Corrupt)?;
            let fingerprint = self.visible_fingerprint(id.slot()).ok_or(Corrupt)?;
            Ok(Some((id, fingerprint)))
        });
        *budget = allowance;
        let Ok(found) = found else {
            guard.poison();
            return Err(RunError::Poisoned {
                visited: run.empty + 1,
            });
        };
        match found {
            Some((id, fingerprint)) => {
                run.occupant = Some(Occupant {
                    id,
                    fingerprint,
                    hold: guard,
                });
            }
            None => guard.release(),
        }
        Ok(run)
    }
}

/// Advances `run` over the empty positions of a shard's tables read under
/// its gate, from `run.next` towards `end`, charging each position's visit
/// before it is examined, and returns the pair at the first occupied one,
/// with `run.next` on it. `None` once `end` is reached or the allowance cannot
/// pay the next visit. `Corrupt` on a reserved control bit, with `run.next`
/// on the position that holds it. A bucket's control word is loaded once and
/// decides each of its pairs in turn.
#[inline(always)]
fn scan(
    tables: &Tables<'_>,
    run: &mut Run,
    end: usize,
    budget: &mut WorkBudget,
) -> Result<Option<Identity>, Corrupt> {
    // A one-step debit refuses only at zero, leaving the allowance unchanged.
    let mut visit = |run: &Run| run.next < end && budget.debit(WorkKind::Visit).is_ok();
    while visit(run) {
        let bucket = &tables.buckets[run.next / PAIRS];
        probe::note(Primitive::Load);
        let control = bucket.control();
        if control & !CONTROL_MASK != 0 {
            return Err(Corrupt);
        }
        let mut pair = run.next % PAIRS;
        loop {
            if is_occupied(control, pair) {
                return Ok(Some(bucket.identity(pair)));
            }
            run.empty += 1;
            run.next += 1;
            pair += 1;
            // The next bucket's word is its own load.
            if pair == PAIRS || !visit(run) {
                break;
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::PassCount;

    /// A pass counts consecutive coverage from where its last call left the
    /// cursor: a call that resumes there adds its units, a call that finds
    /// the cursor moved starts the count over, and a pass that reached the
    /// total stays complete whatever later calls cover until it is reset.
    #[test]
    fn a_pass_count_resumes_restarts_on_a_moved_cursor_and_latches_complete() {
        let pass = PassCount::start();
        assert!(!pass.credit(5, 10, 24));
        assert_eq!(pass.examined(), 10);
        // Another caller moved the cursor from 15 to 18.
        assert!(!pass.credit(18, 4, 24));
        assert_eq!(pass.examined(), 4);
        assert!(!pass.credit(22, 19, 24));
        assert_eq!(pass.examined(), 23);
        assert!(pass.credit(17, 1, 24));
        // Complete: a call from anywhere, covering anything, keeps it so.
        assert!(pass.credit(3, 2, 24));
        assert_eq!(pass.examined(), 24);
        pass.reset();
        assert_eq!(pass.examined(), 0);
        assert!(!pass.credit(9, 0, 24));
    }
}
