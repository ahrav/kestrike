//! Escrowed placement of an object of two or more extents: a builder
//! promises the object's whole charge, then places its extents in order over
//! one or more gate holds.
//!
//! The pool keeps one escrow counter `U` beside the physical ledger: the
//! units promised to builders and not yet placed. A promise, under the pool
//! gate, requires `allocatable = free - U >= C + R` for the object's charge
//! `C` and the clean reserve `R`, claims a slot and an arena block for the
//! object's sequence, and adds `C` to `U`. Every other claim of units also
//! counts `U` against the free units, so every claim leaves promised units
//! free. A placement, under the gate, reserves the next extents' `c` units
//! from the allocator, appends them to the sequence and subtracts `c` from
//! `U` and from the builder's remaining charge; a refused placement
//! preserves table and placement state, and a no-run refusal before moving
//! any units sets the builder's waiting flag. The builder is the unique
//! owner of its remaining charge, so every subtraction from `U` is bounded
//! by it: `U` is the sum of every builder's remaining charge, and the
//! gate-held read bounds it from above, so `0 <= U <= free`.
//!
//! The pool stores `U` as two counters: a gate-held term that promises,
//! placements and gate-held cancels change, and a gate-free refund term that
//! only a refund raises (see `Telemetry`). Read under the gate,
//! `promised - refunded` is at least `U` and exceeds it only by refunds
//! still in flight.
//!
//! A cancel that takes the gate subtracts the remaining charge from `U`
//! under it and, while the slot still describes the builder, returns the
//! placed extents, the block and the slot in the same hold; otherwise it
//! parks the slot for service. A cancel that finds the gate busy, and a
//! drop, refund the remaining charge with one atomic read-modify-write,
//! which works while another holder has the gate, and park the slot for
//! service, whose visits return one extent each and the block and the slot
//! with the last. Each path takes the builder's remaining charge, so the
//! refund happens once. Placed extents are prepaid.
//! A builder is complete once every extent is placed and nothing remains.
//!
//! A builder whose placement finds no free run before moving any units waits
//! for one: the refusal sets its waiting flag, repeated refusals leave it
//! set, and the first placement that makes progress clears it. A waiting
//! builder's retry reads the flag to refuse without the gate while the run
//! bound proves no run fits.

use std::sync::atomic::Ordering;

use super::allocation::{AllocationId, ExtentReservation, describes};
use super::blocks::{ArenaError, Block, BlockArena};
use super::budget::{BudgetExhausted, WorkBudget, WorkKind};
use super::extent::{ExtentLocator, ExtentRefusal, HeldPhase};
use super::held::Held;
use super::layout::{AllocationLayout, ObjectGeometry};
use super::os::Platform;
use super::owner::{Pool, Storage};
use super::release::park;
use super::reserve::{
    ReserveError, claimable_units, install_filling, restore_slot, return_extent, take_slot,
};
use super::tables::{SlotIndex, SlotState, Tables};

/// Every refusal preserves the storage's tables and the builder's placement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromiseError {
    /// The storage refused as a reservation does: teardown, a layout, the
    /// budget, the gate, closure, no free slot, allocatable units short of the
    /// charge plus the clean reserve (`CleanReserve`), or no free run for
    /// a placement (`PayloadFull`).
    Reserve(ReserveError),
    /// The object fits one extent, which [`Storage::reserve`] claims.
    OneExtent,
    /// The sequence arena holds no block for the object's extents.
    Blocks,
}

impl From<BudgetExhausted> for PromiseError {
    fn from(_: BudgetExhausted) -> Self {
        Self::Reserve(ReserveError::BudgetExhausted)
    }
}

/// The unique owner of one escrowed object: its slot, its sequence block,
/// its geometry, the extents placed so far and the units still promised.
pub struct Builder<'s, P: Platform> {
    lineage: u32,
    storage: &'s Storage<P>,
    id: AllocationId,
    block: Block,
    geometry: ObjectGeometry,
    placed: u32,
    remaining: u64,
    /// A placement that finds no free run before moving any units sets
    /// `waiting`; progress, cancel and drop clear it.
    waiting: bool,
    /// The units of the next extent, stored at each no-run refusal; a retry
    /// compares them with the pool's run bound.
    wait_units: u64,
}

impl<P: Platform> std::fmt::Debug for Builder<'_, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Builder")
            .field("id", &self.id)
            .field("placed", &self.placed)
            .field("remaining", &self.remaining)
            .field("waiting", &self.waiting)
            .finish_non_exhaustive()
    }
}

impl<P: Platform> Storage<P> {
    /// A live pool run bound below `units` proves every free run is shorter
    /// than `units` units.
    #[inline]
    pub(crate) fn proves_no_run(&self, units: u64) -> bool {
        self.live_pool()
            .is_some_and(|live| live.telemetry().run_bound() < units)
    }

    /// Promises the whole charge of an object of `metadata_len` and
    /// `body_len` bytes under one gate try, claiming its slot and its
    /// sequence block.
    ///
    /// # Errors
    ///
    /// In this order: `Reserve(TornDown)`, `Reserve(Layout)`,
    /// `Reserve(Closed)`, `OneExtent`, `Reserve(BudgetExhausted)` for the
    /// try, `Reserve(Gate)`, `Reserve(Closed)` under the gate,
    /// `Reserve(Bootstrapping)` under the gate while the attached volume's
    /// readiness is `Loading`, `Loaded` or `Replaying`, or `Detached` while
    /// its attach gate runs, `Reserve(Closed)`
    /// while it is `Withheld` or `Closed`,
    /// `Reserve(BudgetExhausted)` for the update, `Reserve(CleanReserve)`
    /// when allocatable units fall short of the charge plus the clean
    /// reserve, `Reserve(ObjectSlotsFull)` or `Reserve(BudgetExhausted)`
    /// for the slot take, then `Reserve(BudgetExhausted)` for an unfunded
    /// block allocation, which spends the rest of the budget, or `Blocks`.
    /// Both block refusals restore the taken slot.
    pub fn promise(
        &self,
        metadata_len: Option<usize>,
        body_len: Option<usize>,
        budget: &mut WorkBudget,
    ) -> Result<Builder<'_, P>, PromiseError> {
        let refused = PromiseError::Reserve;
        let (live, root) = self.live().ok_or(refused(ReserveError::TornDown))?;
        let geometry = super::layout::object_geometry(
            metadata_len,
            body_len,
            root.metadata_cap,
            root.body_cap,
            &self.record,
        )
        .map_err(|error| refused(ReserveError::Layout(error)))?;
        if self.is_closed() {
            return Err(refused(ReserveError::Closed));
        }
        let count = geometry.extents();
        if count < 2 {
            return Err(PromiseError::OneExtent);
        }
        let charge = geometry.total_units();
        // The last extent's record tail, which prices its payload.
        let tail = geometry.extent(count - 1).record_len();
        budget.debit(WorkKind::CoordinationAttempt)?;
        // Every outcome ends the hold through the `release` below, so its drop is a panic of the promise, and that drop poisons the gate also in a promise made by a thread that was already unwinding.
        let mut access = live
            .try_lock()
            .map_err(|error| refused(ReserveError::Gate(error)))?
            .poison_on_unwind();
        let lineage = self.readiness.lineage();
        let promised = if self.closed().load(Ordering::SeqCst) {
            Err(refused(ReserveError::Closed))
        } else if let Some(refusal) = self.readiness.fill_refusal() {
            Err(refused(refusal))
        } else {
            promise_locked(&mut access.tables(), live, count, charge, tail, budget)
        };
        access.release();
        let (id, block) = promised?;
        Ok(Builder {
            lineage,
            storage: self,
            id,
            block,
            geometry,
            placed: 0,
            remaining: charge,
            waiting: false,
            wait_units: 0,
        })
    }
}

/// The gate-held half of a promise of an object of `count` extents, `charge`
/// units in all and a last extent whose record is `tail` bytes: the escrow
/// check, the slot take, the block allocation and the install, then
/// `U += C`. A refusal restores the taken slot and changes nothing else.
fn promise_locked(
    tables: &mut Tables<'_>,
    live: &Pool,
    count: u32,
    charge: u64,
    tail: u64,
    budget: &mut WorkBudget,
) -> Result<(AllocationId, Block), PromiseError> {
    let refused = PromiseError::Reserve;
    budget.debit(WorkKind::Update)?;
    if super::reserve::retired_pressure(tables, live) {
        return Err(refused(ReserveError::RetiredPressure));
    }
    if charge > claimable_units(tables, live) {
        return Err(refused(ReserveError::CleanReserve));
    }
    let (slot, incarnation) = take_slot(tables, live, None, budget).map_err(refused)?;
    let id = AllocationId::new(SlotIndex(slot), incarnation);
    // The allocation and the restoring give-back together, so an
    // allocation that refuses still leaves the give-back its step.
    let allocated = if budget.preflight(BlockArena::ALLOCATE_STEPS + 1).is_ok() {
        tables.blocks().allocate(id, count, budget)
    } else {
        Err(ArenaError::Budget)
    };
    let block = match allocated {
        Ok(block) => block,
        Err(error) => {
            budget
                .debit(WorkKind::Visit)
                .expect("the take's preflight covered the give-back");
            restore_slot(tables, None, slot);
            return Err(match error {
                ArenaError::Budget => {
                    // An unfunded allocation spends the remainder, as an
                    // unfunded take does.
                    let _ = budget.debit_n(WorkKind::Visit, budget.remaining());
                    refused(ReserveError::BudgetExhausted)
                }
                _ => PromiseError::Blocks,
            });
        }
    };
    let locator = Held::Sequence { block, count }.locator();
    install_filling(tables, live, slot, incarnation, locator, tail);
    live.telemetry().promise(tables, charge);
    Ok((id, block))
}

impl<'s, P: Platform> Builder<'s, P> {
    /// The identity of the builder's slot.
    pub fn id(&self) -> AllocationId {
        self.id
    }

    /// Units promised and not yet placed.
    pub fn remaining(&self) -> u64 {
        self.remaining
    }

    /// Extents placed so far.
    pub fn placed(&self) -> u32 {
        self.placed
    }

    /// Whether the builder waits for a free run: set by a placement that
    /// refused `PayloadFull` and cleared by one that made progress.
    pub fn waiting(&self) -> bool {
        self.waiting
    }

    pub(crate) fn wait_units(&self) -> u64 {
        self.wait_units
    }

    /// The sequence block the builder lists its extents in, for a test's plant.
    #[cfg(test)]
    pub(super) fn block(&self) -> Block {
        self.block
    }

    /// Extents of the object.
    pub fn extents(&self) -> u32 {
        self.geometry.extents()
    }

    /// Whether every extent is placed and nothing remains promised, which
    /// readiness requires beside the object's index claims.
    pub fn is_complete(&self) -> bool {
        self.placed == self.geometry.extents() && self.remaining == 0
    }

    /// Work steps that fund one extent of a [`place`](Self::place) hold:
    /// the gate attempt and the pool's extent work bound, which bounds
    /// every extent's search. A budget of `place_steps()` funds one call.
    pub fn place_steps(&self) -> usize {
        1 + self.storage.pool.image.extent_bound
    }

    /// Places extents in order under one gate try and returns whether the
    /// builder is complete.
    ///
    /// Each pass reserves the full extents left that the budget funds, one per
    /// [`place_steps`](Self::place_steps), with one `ExtentAllocator::reserve_run`
    /// from the fit the first of them selects; an indexed fit takes as many as its
    /// run holds, and a first-fit fallback takes one. When the pass requests every
    /// full extent left and the budget funds the larger bound, the last extent
    /// joins the run when the run's remainder is its fit. Passes continue until
    /// every extent is placed, the budget left falls below `place_steps`, or a
    /// later pass finds no free run, which ends the hold with the extents placed
    /// before it and its search's visits debited; the next call starts with that
    /// extent. The hold appends each extent to the sequence and moves the placed
    /// units out of escrow and the remaining charge.
    ///
    /// # Errors
    ///
    /// `Reserve(TornDown)`, `Reserve(BudgetExhausted)` when the budget
    /// holds fewer than `place_steps` steps, `Reserve(Gate)`, then
    /// `Reserve(PayloadFull)` when the first pass finds no free run for
    /// its extent: the root summary's longest run is shorter than the
    /// extent, one visit debited, or the search passes its work limit,
    /// with the search's visits debited; every refusal leaves the storage's
    /// tables and the builder's
    /// placement unchanged. The promise counts free units in total, so a
    /// fragmented volume can refuse `PayloadFull` with the charge still
    /// promised; the caller retries once extents return, or cancels.
    ///
    /// # Panics
    ///
    /// If called on a complete builder, or, from corruption alone, if the
    /// extent allocator refuses for a reason other than no fit, a reserved
    /// extent passes a locator's limits, or the slot's block refuses the
    /// builder's identity; those panics run under the gate and poison it.
    pub fn place(&mut self, budget: &mut WorkBudget) -> Result<bool, PromiseError> {
        assert!(!self.is_complete(), "a complete builder places nothing");
        let refused = PromiseError::Reserve;
        let live = self
            .storage
            .live_pool()
            .ok_or(refused(ReserveError::TornDown))?;
        let steps = self.place_steps();
        budget.preflight(steps)?;
        budget.debit(WorkKind::CoordinationAttempt)?;
        // The placement's answer ends the hold through `release`, so its drop is a panic of the placement, and that drop poisons the gate also in a placement made by a thread that was already unwinding.
        let mut access = live
            .try_lock()
            .map_err(|error| refused(ReserveError::Gate(error)))?
            .poison_on_unwind();
        let mut place = || {
            let mut tables = access.tables();
            // The root summary holds the longest free run, so a first pass whose
            // extent exceeds it refuses before the sequence opens or a search
            // starts.
            let next = self.geometry.extent(self.placed).units;
            let longest = tables.extents().longest_free_run();
            if longest < next {
                budget
                    .debit(WorkKind::Visit)
                    .expect("the preflight covered the root read");
                tables.store_run_bound(longest);
                self.wait_for_run(next);
                return Err(refused(ReserveError::PayloadFull));
            }
            let count = self.geometry.extents();
            let (mut blocks, mut extents) = tables.blocks_and_extents();
            let mut sequence = match blocks.open(self.block, self.id, count) {
                Ok(sequence) => sequence,
                Err(error) => panic!("a builder's block refuses its own identity: {error:?}"),
            };
            let last = self.geometry.extent(count - 1);
            let mut moved = 0;
            loop {
                let extent = self.geometry.extent(self.placed);
                let units = extent.units as u32;
                // The `+ 1` restores the gate attempt's step, which the first
                // pass spent out of its preflighted `steps`; a later pass spends
                // no gate step, so each funded extent keeps one step of slack.
                let funded = u32::try_from((budget.remaining() + 1) / steps).unwrap_or(u32::MAX);
                let full = count - 1 - self.placed;
                let wanted = if full > 0 { full.min(funded) } else { 1 };
                let mut limit = live.run_work(u64::from(units) * u64::from(wanted));
                // The last extent joins the run when the run takes every full
                // extent left and the budget funds its lookup and its units.
                let mut tail = None;
                if full > 0 && wanted == full {
                    let span = u64::from(units) * u64::from(full) + last.units;
                    let bound = live.run_work(span) + live.image.extent_bound;
                    if bound <= budget.remaining() {
                        limit = bound;
                        tail = Some((last.units as u32, last.payload() as usize));
                    }
                }
                let payload = extent.payload() as usize;
                let run = match extents.reserve_run(units, wanted, payload, tail, limit, budget) {
                    Ok(run) => run,
                    Err(ExtentRefusal::NoFit { .. }) if moved == 0 => {
                        self.wait_for_run(extent.units);
                        return Err(refused(ReserveError::PayloadFull));
                    }
                    Err(ExtentRefusal::NoFit { .. }) => break,
                    // The preflight funds the search and validation bounds the
                    // extent, so any other refusal is corruption, and the panic
                    // poisons the gate.
                    Err(refusal) => panic!("a promised extent refused: {refusal:?}"),
                };
                for index in 0..run.taken {
                    let start = run.first.start_unit() + u64::from(index * units);
                    let Ok(located) = ExtentLocator::new(start, units) else {
                        panic!("a reserved extent passes a locator's limits");
                    };
                    if let Err(error) = sequence.push(located.ending_at(extent.record_len())) {
                        panic!("a builder's block refuses its own identity: {error:?}");
                    }
                }
                let mut charge = extent.units * u64::from(run.taken);
                self.placed += run.taken;
                if let Some(located) = run.tail {
                    if let Err(error) = sequence.push(located.ending_at(last.record_len())) {
                        panic!("a builder's block refuses its own identity: {error:?}");
                    }
                    charge += last.units;
                    self.placed += 1;
                }
                moved += charge;
                if self.placed == count || budget.remaining() < steps {
                    break;
                }
            }
            live.telemetry().settle(&mut tables, moved);
            self.remaining -= moved;
            self.stop_waiting();
            Ok(self.is_complete())
        };
        let placed = place();
        access.release();
        placed
    }

    /// A waiting builder checks the pool's run bound before it tries the
    /// gate: a bound below the units of its next extent proves no free run
    /// holds that extent, and the retry returns `Reserve(PayloadFull)` once
    /// the budget's preflight passes. Any other retry places as
    /// [`place`](Self::place) does.
    ///
    /// # Errors
    ///
    /// As for [`place`](Self::place); the proven no-run refusal comes before
    /// the gate try and its `Reserve(Gate)`.
    pub fn retry(&mut self, budget: &mut WorkBudget) -> Result<bool, PromiseError> {
        if self.waiting && self.storage.proves_no_run(self.wait_units) {
            budget.preflight(self.place_steps())?;
            return Err(PromiseError::Reserve(ReserveError::PayloadFull));
        }
        self.place(budget)
    }

    /// Refunds the remaining charge under one gate try and returns or parks
    /// the slot. When the gate is free, the hold subtracts the charge from
    /// the escrow and, while the slot still describes the builder, returns
    /// the placed extents, the block and the slot; the return's work runs
    /// unbudgeted, bounded by the slot's held work. When the gate is busy,
    /// the charge refunds without the gate. A slot the hold does not
    /// return goes to the park for service. After teardown the call does
    /// nothing. Returns false when the park found the slot word malformed
    /// or naming another incarnation, as [`park`] reports, so the slot is never returned and the caller
    /// keeps its record occupied.
    pub fn cancel(self) -> bool {
        let mut this = std::mem::ManuallyDrop::new(self);
        let Some(pool) = this.storage.live_pool() else {
            return true;
        };
        pool.prefetch_slot(this.id.slot().0);
        let Ok(access) = pool.try_lock_quiet() else {
            this.refund();
            this.stop_waiting();
            return park(pool, this.id.slot().0, this.id.incarnation());
        };
        // Both outcomes end the hold through `release`, so its drop is a
        // panic of the slot's check or of the return, and that drop poisons
        // the gate also in a cancel made by a thread that was already
        // unwinding.
        let mut access = access.poison_on_unwind();
        let mut tables = access.tables();
        pool.telemetry()
            .settle(&mut tables, std::mem::take(&mut this.remaining));
        this.stop_waiting();
        // The builder is its slot's only owner, so the slot describes it
        // while the tables are sound; a slot that does not goes to the
        // park, whose service checks the slot again.
        let described = describes(pool, SlotState::Filling, this.id);
        if described {
            return_extent(&mut tables, pool, this.id.slot().0, HeldPhase::Reserved);
        }
        access.release();
        described || park(pool, this.id.slot().0, this.id.incarnation())
    }

    /// Ends the builder as its drop does and returns the park's result:
    /// false when the slot word is malformed or names another incarnation,
    /// so the caller keeps its record occupied.
    pub(super) fn abandon(self) -> bool {
        std::mem::ManuallyDrop::new(self).end()
    }

    /// The owner of the complete object as one reservation of its slot,
    /// whose locator is the sequence's handle and whose `layout` is the first
    /// extent's record.
    ///
    /// # Panics
    ///
    /// If the builder is not complete.
    pub(crate) fn into_reservation(self, layout: AllocationLayout) -> ExtentReservation<'s, P> {
        assert!(
            self.is_complete(),
            "only a complete builder becomes a reservation"
        );
        debug_assert!(!self.waiting, "a complete builder waits for no run");
        let this = std::mem::ManuallyDrop::new(self);
        let locator = this.storage.pool().records()[this.id.slot().0].locator();
        ExtentReservation::new(this.storage, this.id, locator, layout, this.lineage)
    }

    /// Refunds the remaining charge without the gate, once. A builder that
    /// placed every extent holds no charge and leaves the escrow untouched.
    fn refund(&mut self) {
        let remaining = std::mem::take(&mut self.remaining);
        if remaining != 0
            && let Some(pool) = self.storage.live_pool()
        {
            pool.telemetry().refund(remaining);
        }
    }

    fn wait_for_run(&mut self, units: u64) {
        self.wait_units = units;
        self.waiting = true;
    }

    fn stop_waiting(&mut self) {
        self.waiting = false;
    }

    /// The drop's end: refunds, stops waiting and parks the slot, returning
    /// [`park`]'s result, or true after teardown.
    fn end(&mut self) -> bool {
        self.refund();
        self.stop_waiting();
        self.storage
            .live_pool()
            .is_none_or(|pool| park(pool, self.id.slot().0, self.id.incarnation()))
    }
}

impl<P: Platform> Drop for Builder<'_, P> {
    /// Refunds the remaining charge and parks the slot for service, which
    /// returns the placed extents, the block and the slot.
    fn drop(&mut self) {
        self.end();
    }
}
