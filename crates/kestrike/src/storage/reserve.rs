//! Reserving one metadata/body allocation and taking it back.
//!
//! Order of a reservation, and why: the layout and the close cutoff are
//! checked before any budget is spent, so a request refused there costs
//! nothing; one coordination attempt pays for the gate try; under the gate
//! the cutoff is read once more, so a close ordered before that read refuses
//! `Closed` at the cost of the attempt already spent; one update pays for the
//! indivisible claim.
//!
//! Capacity contract. The pool-gated claim is the capacity authority. Its
//! first check, before any mutation, requires the volume's actual free units
//! to cover the layout's full charged units `C` (header, payload and padding)
//! plus the clean reserve `R` and the escrow `U` of units promised to
//! builders: `free_units >= C + R + U`, equality passing.
//! A shortfall refuses `CleanReserve` with no slot, free-set, extent or
//! ledger change, so every claim leaves at least `R` units free. The units of
//! in-flight extents join `free_units` when those extents return; until
//! then they count toward maintenance's headroom target only.
//! Concurrent claims serialize on the gate, so each reads the units its
//! predecessors left. Both the direct reservation and a fill attempt's
//! reservation reach this check through the same claim.
//!
//! After the reserve check a slot is taken from the free set, its next
//! incarnation computed with checked arithmetic and a slot whose counter is
//! exhausted quarantined, then the extent allocator reserves
//! `ceil((header_bytes + metadata_len + body_len) / IO_UNIT)` units by its fit
//! rule, preflighting the largest extent's work bound plus one give-back step
//! and debiting the visits it made, and
//! only then is the next
//! incarnation installed and the identity issued. No fitting run restores
//! the slot and reports `PayloadFull`; an unfunded search restores the
//! slot, spends the remainder and reports `BudgetExhausted`; either way the
//! slot keeps its `Free` word. Only after slot and extent are both held does
//! the slot ledger move one slot from free to filling; the extent reservation
//! itself moved the raw bytes from free to reserved plus waste, so both
//! partitions sum to their totals at every observable point.
//!
//! Placement. A claim made for a key takes the lowest free slot of the
//! key's placement window (`free::window_of` the fingerprint), so the
//! records of a window's keys share its two cache lines and a lookup that
//! hints the window finds the record it validates already local; a window
//! with no free slot yields the first free slot after it, wrapping at the
//! slot count. A claim without a key takes the first free slot at or after
//! the pool's claim cursor and moves the cursor past it, so such claims
//! visit the slots in index order.
//!
//! Every slot taken from the free set debits one visit, even when it quarantines an exhausted slot, and a refused extent debits one more for the give-back that restores the slot.
//! The `TAKE_BUNDLE` preflight funds the give-back before the take. If the allowance is insufficient, the reservation refuses `BudgetExhausted` with the set as earlier quarantining takes of the call left it.
//!
//! Taking an extent back ([`return_extent`]) is the exact inverse under the
//! same gate. A transfer's return funds the return work of what the slot
//! holds ([`Pool::held_work`]) with its gate attempt, and a service visit
//! funds at most [`Pool::visit_bound`] with its return update; each caller
//! debits the visits the allocator counted; a rollback returns uncharged. The extent
//! returns to the allocator, which merges it with its free neighbours, the
//! slot rejoins the free set, and both ledgers move back. A slot that holds a
//! sequence returns each extent of its held prefix from the end, then its
//! block, then the slot, all in the one hold, so the block stays owned by the
//! slot's incarnation until its last extent's return. Service spreads that
//! return over its visits: [`return_last`] returns one extent per visit
//! while two or more are held, and the final visit's [`return_extent`]
//! returns the rest, the block and the slot. Each return call checks the
//! block against the slot's incarnation through [`BlockArena::open`] and
//! pops each extent it returns off the prefix. The slot's
//! incarnation is never reset; the claim's checked increment and the
//! quarantine of an exhausted counter bound its reuse.

use std::sync::atomic::Ordering;

use super::allocation::{AllocationId, ExtentReservation};
use super::blocks::{Block, BlockArena};
use super::budget::{BudgetExhausted, WorkBudget, WorkKind};
use super::extent::{ExtentAllocator, ExtentLocator, ExtentRefusal, HeldPhase};
use super::free::window_of;
use super::gate::GateError;
use super::held::Held;
use super::layout::{AllocationLayout, IO_UNIT, LayoutError};
use super::os::Platform;
use super::owner::{Pool, Storage};
use super::pending::unmark_parked_slot;
use super::portable::PortableExpiry;
use super::probe::{self, Primitive};
use super::tables::{
    EXTENT_REFUSED, PoolAccess, SEQUENCE_REFUSED, SlotIndex, SlotState, Tables, release_extent,
};
use super::word::{self, FLAGS, INCARNATION, MARKER, POLICY, STATE, VISITED};

/// Why a reservation produced no allocation. Every variant leaves existing
/// allocations, identities and charges untouched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReserveError {
    Withdrawn,
    /// The storage is drained.
    TornDown,
    /// The request cannot be laid out: unknown length, a cap, overflow, or
    /// a payload past one extent.
    Layout(LayoutError),
    /// Admission is closed, or the attached volume's attempt is withheld or closed. Existing allocations stay valid.
    Closed,
    /// The budget ran out before the try, the update, a slot take's bundle or the extent search.
    BudgetExhausted,
    /// The gate was busy or poisoned; the failed try is counted.
    Gate(GateError),
    /// Every slot is filling, resident, retired or quarantined.
    ObjectSlotsFull,
    /// No free run of the volume holds the layout's units.
    PayloadFull,
    /// The claim's charged units exceed the volume's free units less the
    /// clean reserve and the units promised to builders. Checked under the
    /// gate before any slot or extent mutation, with the gate attempt and
    /// the update already spent, so the refusal changes no slot, free set,
    /// extent or ledger.
    CleanReserve,
    /// The retired charge reached the volume's allowance `T`: objects
    /// retired and not yet returned hold at least that many units. Checked under the
    /// gate before the clean reserve, with the gate attempt and the update
    /// spent, so the refusal changes nothing; it lasts until service returns
    /// retired extents.
    RetiredPressure,
    /// The attached volume's gate, load or replay is unfinished.
    Bootstrapping,
}

impl From<BudgetExhausted> for ReserveError {
    fn from(_: BudgetExhausted) -> Self {
        Self::BudgetExhausted
    }
}

/// Slot and extent a reservation claimed under the gate.
pub(crate) struct Claim {
    pub slot: usize,
    pub incarnation: u32,
    pub locator: ExtentLocator,
}

impl<P: Platform> Storage<P> {
    /// Closes admission: stores `true` to the cutoff with `SeqCst` while the
    /// storage is live; dropping the [`Cache`](super::Cache) facade performs
    /// the same store. No admission succeeds after its cutoff check reads
    /// closed, though an earlier check may return another error first. The
    /// cutoff checks are registration, protected entry, scalar and batch
    /// lookup, [`reserve`](Self::reserve), publication, replacement,
    /// invalidation, [`begin_fill`](Self::begin_fill), facade issuance and
    /// volume attach.
    /// Existing owners, registrations and leases stay valid, as do exit,
    /// release, return, internal removal, certification and service. Repeating `close` changes nothing; it neither waits nor
    /// sweeps.
    ///
    /// Ordering. The cutoff is one monotonic word: every store writes
    /// `true` and nothing clears it, so any single reader sees it
    /// consistently by coherence alone. Every cutoff check that pairs with a
    /// second location uses `SeqCst`; a publication's early refusal read,
    /// the fill grant's entry check, a writable owner's receive and the
    /// maintenance call's check before each stage pair with none and read
    /// it `Relaxed`, as the `publication`, `attempt`, `writable` and
    /// `maintain` modules state. Protected entry stores its pin
    /// with `SeqCst` before checking the cutoff: if that check reads open,
    /// the pin store precedes the close in the `SeqCst` total order, and a
    /// `SeqCst` pin load ordered after the close sees the pin while the
    /// interval is active, or its clearing store after the interval's
    /// protected work has ended. The lookup checks the cutoff before its
    /// closing `SeqCst` shard-sequence load. The registration claim is
    /// `AcqRel`, so its post-claim cutoff check decides whether to give the
    /// record back and orders nothing. The consumers of the order are the
    /// terminal-band retirement that closes admission before publishing its
    /// reclaimable mark, and exclusive finalization. Reservation checks the
    /// cutoff before its gate attempt and again under the pool gate right
    /// before the slot claim commits: a close ordered before that read is
    /// refused, while a claim whose recheck read open may finish after a
    /// concurrent close. A slot retired in the terminal band is returned
    /// under the pool gate after its mark, which follows its close, so a
    /// recheck that could claim it has that close ordered before it.
    pub fn close(&self) {
        if self.is_live() {
            self.closed()
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// Whether admission is closed, read with the `SeqCst` load the deciding
    /// admission checks use; see [`close`](Self::close).
    pub fn is_closed(&self) -> bool {
        self.is_live() && self.closed().load(std::sync::atomic::Ordering::SeqCst)
    }

    /// The admission cutoff flag. Precondition: `is_live()`.
    #[inline(always)]
    pub(super) fn closed(&self) -> &std::sync::atomic::AtomicBool {
        debug_assert!(self.is_live());
        // SAFETY: the root mapping is owned and the flag was initialized
        // before the owner existed; atomics need no exclusion.
        unsafe { &self.root_image.closed.as_slice(&self.root)[0] }
    }

    /// Whether `id` names the current incarnation of a slot that an allocation
    /// owns. A stale incarnation, a free slot or a quarantined slot is
    /// rejected, so no location is ever derived from such an identity. A
    /// slot word with a reserved bit set panics under the gate and poisons
    /// it.
    ///
    /// This is a report path: it waits for the gate like
    /// [`pool_report`](Self::pool_report) and serializes with every allocator
    /// step. The allocator's own paths evaluate the same predicate under
    /// their one nonblocking try instead of calling this.
    pub fn identity_is_current(&self, id: AllocationId) -> bool {
        let Some(pool) = self.live_pool() else {
            return false;
        };
        let Some(access) = pool.lock() else {
            return false;
        };
        // The answer ends the hold through `release`, so its drop is a panic
        // of the word's check, and that drop poisons the gate also in a call
        // made by a thread that was already unwinding.
        let access = access.poison_on_unwind();
        let current = id.slot().0 < pool.records().len() && {
            let (state, incarnation) = pool.gate_state(id.slot().0);
            incarnation == id.incarnation()
                && matches!(
                    state,
                    SlotState::Filling | SlotState::Resident | SlotState::Retired
                )
        };
        access.release();
        current
    }

    /// Steps that fund a reservation of any one-extent layout the caps admit: the gate
    /// attempt, the update, the slot take with its give-back, and
    /// `alloc_search_words`, which covers the largest extent's work bound.
    /// A reservation preflights that bound, which equals every admitted
    /// extent's, and debits the visits it made, so one funded with
    /// exactly this whose first take succeeds ends with `alloc_search_words + 1 - visits` left, the
    /// give-back's step included, or refuses `PayloadFull` with
    /// `alloc_search_words - visits` left. When `alloc_search_words` equals
    /// the largest extent's bound, a reservation with one step less
    /// refuses `BudgetExhausted` with the budget spent.
    pub fn reserve_minimum(&self) -> usize {
        self.pool
            .image
            .alloc_search_words
            .checked_add(2 + TAKE_BUNDLE)
            .expect("validation bounds alloc_search_words below this sum's overflow")
    }

    /// Reserves one allocation of `metadata_len` then `body_len` bytes as an
    /// extent the volume's allocator places by its fit rule. See the module
    /// documentation for the order of checks and what each refusal leaves
    /// untouched.
    ///
    /// # Errors
    ///
    /// [`ReserveError`]. `TornDown`, `Layout` and a `Closed` read before the
    /// gate cost no budget; a `Closed` read under the gate has paid the gate
    /// attempt.
    // Forced inline: returned through memory, the owner is written here as
    // words and read back by the caller's wider moves, which then wait for
    // the store buffer to drain; inlined, it stays in registers.
    #[inline(always)]
    pub fn reserve(
        &self,
        metadata_len: Option<usize>,
        body_len: Option<usize>,
        budget: &mut WorkBudget,
    ) -> Result<ExtentReservation<'_, P>, ReserveError> {
        let (live, root) = self.live().ok_or(ReserveError::TornDown)?;
        let layout = AllocationLayout::new(
            metadata_len,
            body_len,
            root.metadata_cap,
            root.body_cap,
            &self.record,
        )
        .map_err(ReserveError::Layout)?;
        if self.is_closed() {
            return Err(ReserveError::Closed);
        }
        let reservation = self.reserve_layout(live, layout, None, budget)?;
        // The caller completes into the slot's record next, which has usually
        // stayed untouched since the previous object left; asking for its line
        // for writing now lets those stores land as local hits, so the
        // completion's and the publication's gate attempts proceed without
        // waiting on the fill.
        live.prefetch_record(reservation.id().slot().0);
        Ok(reservation)
    }

    /// Claims a slot and an extent for `layout` under one nonblocking gate try, the slot from the placement window `fingerprint` names when the pool has one, else from the claim cursor.
    ///
    /// Preconditions: `live` is this storage's volume, `layout` satisfies the root caps, and the caller read the cutoff open.
    ///
    /// # Errors
    ///
    /// `BudgetExhausted` when the budget cannot fund the gate try, the update, a slot take or the extent search; `Gate` when the try fails; `Closed` when the cutoff read under the gate observes closure; `Bootstrapping` while the readiness read under the gate is `Loading`, `Loaded` or `Replaying`, or `Detached` with an attached volume waiting at its attach gate, and `Closed` while it is `Withheld` or `Closed`; `CleanReserve` when the free units fall short of the layout's units plus the clean reserve `R` and the escrow `U` of units promised to builders; `ObjectSlotsFull` when no slot can be claimed; or `PayloadFull` when no free run fits.
    #[inline(always)]
    pub(super) fn reserve_layout(
        &self,
        live: &Pool,
        layout: AllocationLayout,
        fingerprint: Option<u64>,
        budget: &mut WorkBudget,
    ) -> Result<ExtentReservation<'_, P>, ReserveError> {
        #[cfg(test)]
        if let Ok(Some(interpose)) = INTERPOSE_AFTER_OPEN_READ.try_with(|hook| hook.take()) {
            interpose(self.closed());
        }
        budget.debit(WorkKind::CoordinationAttempt)?;
        let access = live.try_lock().map_err(ReserveError::Gate)?;
        probe::note(Primitive::GateTaken);
        // The cutoff again, under the gate and right before the claim
        // commits: a terminal-band retirement closes admission before it
        // publishes the mark that would let its slot recycle, so a claim
        // that passed the early read but reads closed here would be the one
        // that takes such a slot. A fixed administrative check, not budgeted
        // work.
        if self.closed().load(std::sync::atomic::Ordering::SeqCst) {
            return Err(ReserveError::Closed);
        }
        // Readiness after the cutoff and under the gate, so a withdrawal that passed the gate after its compare-and-swap sees every claim this hold makes (ALLOCATION-READY).
        let lineage = self.readiness.lineage();
        if let Some(refusal) = self.readiness.fill_refusal() {
            return Err(refusal);
        }
        budget.debit(WorkKind::Update)?;
        // Under the gate, so a gate exchange that waits for hints has
        // completed; the claim's record exchange, the revalidation's shard-gate
        // exchange and the bind's gate exchange then wait once for every line
        // the claim, the place claim and the bind store through, the window's
        // records and tables and the bucket's summary and both bucket lines,
        // in parallel.
        if let Some(fingerprint) = fingerprint {
            live.prefetch_claim(fingerprint);
            self.prefetch_bucket(fingerprint, true);
        }
        let window = fingerprint
            .and_then(|fingerprint| window_of(fingerprint, live.descriptor().slot_count));
        // Both outcomes of the claim end the hold through `release`, one
        // release store, so from here the hold's drop is a panic of the
        // claim, and that drop poisons the gate also in a reservation made by
        // a thread that was already unwinding.
        let mut access = access.poison_on_unwind();
        let claimed = claim(&mut access, live, &layout, window, budget);
        access.release();
        let claim = claimed?;
        let id = AllocationId::new(SlotIndex(claim.slot), claim.incarnation);
        Ok(ExtentReservation::new(
            self,
            id,
            claim.locator,
            layout,
            lineage,
        ))
    }
}

#[cfg(test)]
thread_local! {
    /// Runs once between a reservation's early open cutoff read and its gate
    /// attempt on this thread, so a test can close admission where only the
    /// recheck under the gate can catch it.
    pub(crate) static INTERPOSE_AFTER_OPEN_READ: std::cell::Cell<Option<fn(&std::sync::atomic::AtomicBool)>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(test)]
thread_local! {
    /// Visits the extent returns on this thread counted, so a test can
    /// compare a caller's debit with the allocator's count.
    pub(crate) static RETURN_VISITS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Visits the extent returns on this thread counted since the last call.
#[cfg(test)]
pub(crate) fn take_return_visits() -> usize {
    RETURN_VISITS.with(|total| total.replace(0))
}

/// Checks the clean reserve, then claims a slot, from `window` when it is
/// `Some`, then an extent for `layout`, then installs the slot's next
/// incarnation and stores the record's tail. On a refused extent the
/// slot goes back to the free set with its `Free` word unchanged,
/// so each incarnation step is one object that held the slot.
///
/// # Panics
///
/// - If the extent allocator refuses a free slot for a reason other than
///   no fit or an unfunded search.
/// - If the slot's word changed between the take and the install.
/// - If a taken slot's word carries a flag, a count or a reserved bit.
///
/// The gate is still held, so each panic poisons it instead of committing
/// a claim nothing owns.
// Out of line, over the holder's access: `reserve_layout` inlines into every
// reservation, and this call keeps the claim's search and its tables' views
// in one body they all share.
#[inline(never)]
fn claim(
    access: &mut PoolAccess<'_>,
    live: &Pool,
    layout: &AllocationLayout,
    window: Option<usize>,
    budget: &mut WorkBudget,
) -> Result<Claim, ReserveError> {
    let tables = &mut access.tables();
    // `AllocationLayout::new` holds a layout to one extent, at most 63 units:
    // `EXTENT_PAYLOAD` bytes behind a header of at most one unit.
    let units = layout.units() as u32;
    // The retired allowance, then the clean reserve, before any mutation:
    // the free units read under the gate are the actual ones, so concurrent
    // claims serialize on this check and none spends the reserve or a
    // promise.
    let pressure = retired_pressure(tables, live);
    let short = u64::from(units) > claimable_units(tables, live);
    if pressure | short {
        return Err(if pressure {
            ReserveError::RetiredPressure
        } else {
            ReserveError::CleanReserve
        });
    }
    let (slot, incarnation) = take_slot(tables, live, window, budget)?;
    let payload = layout.payload();
    // The search and the restoring give-back together, so a search that
    // finds no fit still leaves the give-back its step.
    let limit = live.image.extent_bound;
    let mut extents = tables.extents();
    let reserved = if budget.preflight(limit + 1).is_ok() {
        extents.reserve(units, payload, limit, budget)
    } else {
        Err(ExtentRefusal::BudgetExhausted)
    };
    let locator = match reserved {
        Ok(locator) => locator,
        Err(refusal) => {
            budget
                .debit(WorkKind::Visit)
                .expect("the take's preflight covered the give-back");
            restore_slot(tables, window, slot);
            return Err(match refusal {
                ExtentRefusal::NoFit { .. } => ReserveError::PayloadFull,
                ExtentRefusal::BudgetExhausted => {
                    // An unfunded search spends the remainder, as an unfunded
                    // take does.
                    let _ = budget.debit_n(WorkKind::Visit, budget.remaining());
                    ReserveError::BudgetExhausted
                }
                ExtentRefusal::Length { .. } | ExtentRefusal::Ledger => {
                    panic!("a free slot's extent claim refused for a reason validation rules out")
                }
            });
        }
    };
    // The locator records where the record ends, so a read stops at its last sector.
    let locator = locator.ending_at(layout.record().record_len());
    install_filling(
        tables,
        live,
        slot,
        incarnation,
        locator,
        layout.record().record_len(),
    );
    Ok(Claim {
        slot,
        incarnation,
        locator,
    })
}

/// Takes `units` of a returned retired extent off the retired charge.
///
/// # Panics
///
/// If the charge holds fewer units, which only a drift of its accounting
/// produces; the caller holds the gate, so the panic poisons it.
fn retire_units(tables: &mut Tables<'_>, units: u32) {
    tables.domain.retired_units = tables
        .domain
        .retired_units
        .checked_sub(u64::from(units))
        .expect("the retired charge holds every retired extent's units");
}

/// Whether the retired charge has reached the allowance `T` of a storage
/// with watermarks, so every claim refuses with pressure until returns
/// lower it.
pub(super) fn retired_pressure(tables: &mut Tables<'_>, live: &Pool) -> bool {
    tables.domain.retired_units >= live.image.retired_limit
}

/// Units a claim may spend under the gate: the free units less the clean
/// reserve and the escrow, or zero. A claim of `C >= 1` charged units
/// passes the clean reserve check exactly when `C <= claimable_units`.
/// The escrow read under the gate bounds the escrow for the rest of the
/// hold, since only a refund changes it without the gate and a refund
/// lowers it.
pub(super) fn claimable_units(tables: &mut Tables<'_>, live: &Pool) -> u64 {
    claimable(
        tables.free_units(),
        live.image.reserve_units,
        live.telemetry().escrow(),
    )
}

/// [`claimable_units`] from one reading of the free units, the clean
/// reserve and the escrow, so a report derives it from the escrow sample
/// it shows.
#[inline(always)]
pub(super) fn claimable(free: u64, reserve: u64, escrow: u64) -> u64 {
    free.saturating_sub(reserve + escrow)
}

/// Installs a taken slot's `Filling` word, its locator and its record tail
/// of `record_len`, and moves it from free to filling in the ledger.
///
/// # Panics
///
/// If the slot's word is not the `Free` value of the incarnation before
/// `incarnation`, which only corruption produces; the panic poisons the
/// gate the caller holds.
pub(super) fn install_filling(
    tables: &mut Tables<'_>,
    live: &Pool,
    slot: usize,
    incarnation: u32,
    locator: ExtentLocator,
    record_len: u64,
) {
    // Installs the next incarnation and the `Filling` state over the `Free`
    // word the take read. The
    // exchange is the release half of the pair a registered reader's
    // `Acquire` validation load completes; the gate orders it against every
    // other gate holder, and a reader accepts only the value its own
    // snapshot copied. Every write of the word is a read-modify-write, so
    // each release decrement of the previous object's count heads a release
    // sequence this exchange extends: a reader whose acquire load sees this
    // incarnation is ordered after every one of them, and the count it
    // reads beside the incarnation is this object's. The edge a reader acts
    // on is the publication's release exchange in `install`, which the
    // anchor's count carries. A previous object returned by its sole owner
    // was never mapped, so no snapshot names it and no reader compares
    // against its incarnation. Any other value here is corruption, and the
    // panic poisons the gate.
    let record = &live.records()[slot];
    if record
        .ident
        .compare_exchange(
            u64::from(incarnation - 1),
            u64::from(incarnation) | SlotState::Filling.bits(),
            Ordering::Release,
            Ordering::Relaxed,
        )
        .is_err()
    {
        panic!("a free slot's word changed under the pool gate");
    }
    record.set_locator(locator);
    // The record's tail, so every gate holder derives the payload the
    // ledger names from the slot's own tables until the return.
    tables.tails[slot] = (record_len % IO_UNIT as u64) as u16;
    tables.state.ledger.free -= 1;
    tables.state.ledger.filling += 1;
}

/// `Restored` holds the facts a warm-loaded entry carries for one binding's slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Restored {
    /// `id` names the slot and the incarnation the binding's records carry.
    pub(crate) id: AllocationId,
    /// `session` is the writer session that bound the records.
    pub(crate) session: u64,
    /// `version` is the cache version the loaded entry names for the binding.
    pub(crate) version: u64,
    pub(crate) key: [u8; 32],
    /// `fingerprint` is the key's word under this storage's hasher, which removal routes by.
    pub(crate) fingerprint: u64,
    pub(crate) expiry: PortableExpiry,
    /// `expires_at_s` is the local deadline the load gave the portable pair, in deadline seconds: its conversion, or
    /// the load sample's own whole second for a pair the load keeps expired.
    pub(crate) expires_at_s: u32,
    /// `locator` is the object's direct extent or its sequence handle; the caller installs any sequence block.
    pub(crate) locator: ExtentLocator,
    /// `tail` is the record length modulo `IO_UNIT` in bytes, as `Tables::tails` keeps it; zero means the last unit is full.
    pub(crate) tail: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RestoreRefusal {
    /// The id names a slot outside the free set, or an incarnation at or below the one the slot's `Free` word last issued.
    NotFree,
    /// The read predicate refuses the record session for the attaching writer's session.
    Session,
}

/// Steps one slot take needs affordable before it runs: the take and the give-back that restores the slot when its extent is refused.
pub(crate) const TAKE_BUNDLE: usize = 2;
/// Takes free slots from the set, the lowest free slot of `window` or the
/// first free slot after it, or the first at or after the claim cursor
/// without a window, until one can advance its incarnation, quarantining
/// each exhausted one for good, and returns the slot and the incarnation
/// the claim installs once its extent is reserved. Each inspected free
/// slot consumes one visit after [`TAKE_BUNDLE`] is preflighted, so the
/// give-back is always paid. A failed preflight returns `BudgetExhausted`
/// with the set as any earlier quarantining takes left it. A taken slot
/// remains `Free`, counted as free and with its word unwritten until its
/// extent claim succeeds. A take without a window moves the claim cursor
/// past the slot.
///
/// # Panics
///
/// If a taken slot's word carries a flag, a count or a reserved bit. The
/// `Free` word holds the slot's last incarnation and nothing else: the
/// return cleared every flag and found the count at zero, a retain needs a
/// positive count, and a park of that incarnation has no owner left to
/// issue it. The caller holds the gate, so the panic poisons it.
#[inline(always)]
pub(super) fn take_slot(
    tables: &mut Tables<'_>,
    live: &Pool,
    window: Option<usize>,
    budget: &mut WorkBudget,
) -> Result<(usize, u32), ReserveError> {
    loop {
        let cursor = tables.state.cursor_claim;
        let free = tables.free_slots();
        let found = match window {
            Some(start) => free
                .first_in_window(start)
                .or_else(|| free.next_from(start)),
            None => free.next_from(cursor),
        };
        let Some(slot) = found else {
            return Err(ReserveError::ObjectSlotsFull);
        };
        if budget.preflight(TAKE_BUNDLE).is_err() {
            let _ = budget.debit_n(WorkKind::Visit, TAKE_BUNDLE);
            return Err(ReserveError::BudgetExhausted);
        }
        budget
            .debit(WorkKind::Visit)
            .expect("the preflight covered the take");
        probe::note(Primitive::Load);
        tables.free_slots().take(slot);
        if window.is_none() {
            tables.state.cursor_claim = (slot + 1) % live.descriptor().slot_count;
        }
        let record = &live.records()[slot];
        let free = record.ident.load(Ordering::Relaxed);
        if free & !INCARNATION != 0 {
            panic!("a free slot's word carries a flag, a state, a count or a reserved bit");
        }
        match word::incarnation(free).checked_add(1) {
            Some(next) => return Ok((slot, next)),
            None => {
                record
                    .ident
                    .fetch_or(SlotState::Quarantined.bits(), Ordering::Relaxed);
                tables.state.ledger.free -= 1;
                tables.state.ledger.quarantined += 1;
            }
        }
    }
}

/// Gives a claimed `Free` slot whose extent was refused back to the free
/// set, where its claim took it; a take without a window also moves the
/// claim cursor back to the slot, so the next such claim takes it again.
#[inline(always)]
pub(super) fn restore_slot(tables: &mut Tables<'_>, window: Option<usize>, slot: usize) {
    tables.free_slots().give(slot);
    if window.is_none() {
        tables.state.cursor_claim = slot;
    }
}

/// Gives a returned `Free` slot back to the free set.
#[inline(always)]
fn release_slot(tables: &mut Tables<'_>, slot: usize) {
    tables.free_slots().give(slot);
}

/// Returns the extent slot `slot` holds and the slot itself to their free
/// structures and moves the slot's payload bytes, reserved, resident or
/// retired as `phase` names, and its waste back to free. The caller has
/// validated that the slot owns that extent and that no accessor remains.
/// Capture eligibility has ended before this first extent return.
/// One read-modify-write clears every flag, the visited bit, the state,
/// the policy bits and the recovered-origin marker of the slot's word and leaves its incarnation and its
/// count, which the caller proved zero, so the returned identity can never
/// be current again and the word is the `Free` value the next claim
/// expects. The record keeps the returned locator, or the sequence handle
/// naming the freed block, until the next claim overwrites it. Returns the units
/// returned and the visits the extent allocator and the
/// arena counted, at most [`Pool::held_work`] for what the slot holds, for
/// the caller to debit.
#[inline(always)]
pub(crate) fn return_extent(
    tables: &mut Tables<'_>,
    pool: &Pool,
    slot: usize,
    phase: HeldPhase,
) -> (u32, usize) {
    assert_eq!(
        tables.step(slot),
        0,
        "capture hook must precede extent release"
    );
    // A right or the anchor still counted here would alias the extent after
    // reuse; failing closed poisons the gate instead. Every caller proved
    // zero with acquire ordering or by consuming the only owner, so this
    // relaxed read-modify-write is a check, not the synchronization; it
    // extends every release sequence on the word to the next claim.
    let previous = pool.records()[slot].ident.fetch_and(
        !(FLAGS | VISITED | STATE | POLICY | MARKER),
        Ordering::Relaxed,
    );
    assert!(
        word::refs(previous) == 0 && word::well_formed(previous),
        "an extent returned while a right or the anchor is outstanding, or with a malformed word"
    );
    debug_assert!(
        phase != HeldPhase::Resident || previous & POLICY != 0,
        "a resident slot that did not enter through bind"
    );
    // A park that no retirement absorbed set, or is about to set, the
    // slot's parked bit.
    if previous & (word::ABANDONED | word::RETIRED) == word::ABANDONED {
        unmark_parked_slot(pool.parked_slots(), slot);
    }
    // The record's locator, fixed since the claim, names what the allocator
    // and, for a sequence, the arena take back; an extent whose units are not all held is corrupt, and the
    // panic poisons the gate the caller holds.
    let (units, visits) = return_held(tables, pool, slot, phase);
    #[cfg(test)]
    RETURN_VISITS.with(|total| total.set(total.get() + visits));
    // The extent's return ends membership: a still-linked slot leaves its
    // list and a detached or marked one leaves the counts, from the policy
    // bits the read-modify-write above cleared, so the next incarnation
    // starts clean.
    tables.queue().clear(slot, units, previous);
    tables.clear_naming(slot);
    tables.state.ledger.free += 1;
    release_slot(tables, slot);
    match phase {
        HeldPhase::Reserved => tables.state.ledger.filling -= 1,
        HeldPhase::Resident => tables.state.ledger.resident -= 1,
        HeldPhase::Retired => {
            tables.unmark_retired(slot);
            tables.state.ledger.retired -= 1;
            retire_units(tables, units);
        }
    }
    (units, visits)
}

/// Returns every extent `slot` holds, from phase `phase`, to the free set:
/// the direct extent, or each extent of the held prefix from its end, and
/// then the sequence block to the arena, so the block stays owned until its last
/// extent's return. Popped extents that adjoin one another return as one
/// run in one allocator call, whose held check covers every unit of the
/// run.
/// Returns the units returned and the visits counted, one per pop and the
/// block's steps included.
///
/// # Panics
///
/// As for [`Tables::held`], [`Pool::extent_payload`] and
/// [`release_extent`], and if the sequence block refuses the
/// slot's own incarnation; the caller holds the
/// gate, so the panic poisons it.
#[inline(always)]
fn return_held(
    tables: &mut Tables<'_>,
    pool: &Pool,
    slot: usize,
    phase: HeldPhase,
) -> (u32, usize) {
    let tail = tables.tails[slot];
    let returned = match tables.held(slot) {
        Held::Direct(locator) => {
            let payload = pool.extent_payload(locator, Some(tail));
            (
                locator.len_units(),
                release_extent(&mut tables.extents(), locator, phase, payload),
            )
        }
        Held::Sequence { block, count } => {
            let owner = tables.owner(slot);
            let (arena, extents) = tables.blocks_and_extents();
            return_sequence(arena, extents, pool, (block, count, owner), tail, phase)
        }
    };
    tables.bound_runs();
    returned
}

/// The sequence half of [`return_held`], kept out of line so the direct
/// return path stays small when callers inline `return_held`.
///
/// Each popped extent's payload must fit its own units before it joins a
/// run, so the check catches an overfull extent that spare capacity in an
/// adjoining extent of the same run would conceal.
#[cold]
#[inline(never)]
fn return_sequence(
    mut arena: BlockArena<'_>,
    mut extents: ExtentAllocator<'_>,
    pool: &Pool,
    (block, count, owner): (Block, u32, AllocationId),
    tail: u16,
    phase: HeldPhase,
) -> (u32, usize) {
    let (mut units, mut visits) = (0, 0);
    // The run of adjoining popped extents not yet returned: its first and
    // end units and its payload bytes.
    let mut run: Option<(u64, u64, usize)> = None;
    let mut prefix = arena.open(block, owner, count).expect(SEQUENCE_REFUSED);
    while let Some((index, locator)) = prefix.pop() {
        let payload = pool.extent_payload(locator, (index + 1 == count).then_some(tail));
        let (start, end) = (
            locator.start_unit(),
            locator.start_unit() + u64::from(locator.len_units()),
        );
        visits += 1;
        units += locator.len_units();
        // Each extent must satisfy the size and payload constraints before
        // coalescing can mask an invalid extent.
        assert!(
            payload <= locator.len_units() as usize * IO_UNIT,
            "{EXTENT_REFUSED}"
        );
        run = match run {
            Some((low, high, held)) if end == low => Some((start, high, held + payload)),
            Some((low, high, held)) if start == high => Some((low, end, held + payload)),
            Some(other) => {
                visits += release_run(&mut extents, other, phase);
                Some((start, end, payload))
            }
            None => Some((start, end, payload)),
        };
    }
    if let Some(last) = run {
        visits += release_run(&mut extents, last, phase);
    }
    let mut steps = WorkBudget::new(BlockArena::FREE_STEPS);
    arena
        .free(block, owner, count, &mut steps)
        .expect(SEQUENCE_REFUSED);
    (units, visits + BlockArena::FREE_STEPS - steps.remaining())
}

/// One extent of a return that service spreads over its visits: the
/// extent's index in its object, its units and the visits counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReturnedExtent {
    pub index: u32,
    pub units: u32,
    pub visits: usize,
}

/// Returns the last held extent of `slot`'s sequence, listed in `block` for
/// `count` extents as the slot's record names it, from phase `phase`, when
/// the prefix holds two or more, and `None` otherwise, when the next return
/// of the slot is its final one. The extent's charge moves to free:
/// its payload from `phase`, its padding from waste. The slot, its word,
/// its incarnation, its pending membership and its block stay as they
/// are, and a slot in flight has its in-flight units shrink by the
/// extent's. The caller holds the gate, has validated that no accessor
/// remains, and funded one pop and the extent's return. Capture eligibility has ended
/// before the first extent return.
///
/// # Panics
///
/// If capture eligibility remains, a right or the anchor is still counted, the word
/// is malformed, or the arena refuses the slot's block, and as for [`Pool::extent_payload`] and
/// [`release_extent`]; the caller holds the gate, so the panic poisons it.
pub(crate) fn return_last(
    tables: &mut Tables<'_>,
    pool: &Pool,
    slot: usize,
    (block, count): (Block, u32),
    phase: HeldPhase,
) -> Option<ReturnedExtent> {
    assert_eq!(
        tables.step(slot),
        0,
        "capture hook must precede partial extent release"
    );
    // A right or the anchor still counted here would alias the extent
    // after its reuse; failing closed poisons the gate instead.
    let current = tables.word(slot);
    assert!(
        word::refs(current) == 0 && word::well_formed(current),
        "an extent returned while a right or the anchor is outstanding, or with a malformed word"
    );
    let owner = AllocationId::new(SlotIndex(slot), word::incarnation(current));
    let tail = tables.tails[slot];
    let (mut arena, mut extents) = tables.blocks_and_extents();
    let mut prefix = arena.open(block, owner, count).expect(SEQUENCE_REFUSED);
    // A prefix of one is left for the final return.
    if prefix.len() < 2 {
        return None;
    }
    let (index, locator) = prefix
        .pop()
        .expect("a prefix of two or more holds a locator to pop");
    let payload = pool.extent_payload(locator, (index + 1 == count).then_some(tail));
    assert!(
        payload <= locator.len_units() as usize * IO_UNIT,
        "{EXTENT_REFUSED}"
    );
    let extent = ReturnedExtent {
        index,
        units: locator.len_units(),
        visits: 1 + release_extent(&mut extents, locator, phase, payload),
    };
    tables.bound_runs();
    tables.queue().returned_part(extent.units, current);
    if phase == HeldPhase::Retired {
        retire_units(tables, extent.units);
    }
    #[cfg(test)]
    RETURN_VISITS.with(|total| total.set(total.get() + extent.visits));
    Some(extent)
}

/// Returns the run `(low, high, payload)` of adjoining extents from phase
/// `phase` in one allocator call, and returns the visits it counted, at
/// most the extent work of its extents' separate returns.
///
/// # Panics
///
/// As for [`release_extent`].
#[inline(always)]
fn release_run(
    extents: &mut ExtentAllocator<'_>,
    (low, high, payload): (u64, u64, usize),
    phase: HeldPhase,
) -> usize {
    let locator = u32::try_from(high - low)
        .ok()
        .and_then(|units| ExtentLocator::new(low, units).ok())
        .expect("a run of a prefix's extents fits a locator");
    release_extent(extents, locator, phase, payload)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::super::Completed;
    use super::super::allocation::{AllocationId, ExtentReservation, Retained};
    use super::super::budget::{WorkBudget, WorkCounters};
    use super::super::config::StorageConfig;
    use super::super::extent::{ExtentLocator, RawPartition};
    use super::super::gate::GateError;
    use super::super::layout::{AllocationLayout, IO_UNIT, LayoutError};
    use super::super::ledger::SlotPartition;
    use super::super::owner::Storage;
    use super::super::placement::PlacementConfig;
    use super::super::release::ReturnOutcome;
    use super::super::seeded::SplitMix64;
    use super::super::tables::{SlotIndex, SlotState, Tables};
    use super::super::test_platform::TestPlatform;
    use super::super::word::{ABANDONED, RETIRED};
    use super::{ReserveError, TAKE_BUNDLE};

    const PAGE: usize = 4096;
    const SLOTS: usize = 4;
    const UNITS: usize = 6;
    /// The largest record: 64 bytes of metadata and a body one unit and a
    /// half long, two units.
    const BODY_CAP: usize = IO_UNIT + IO_UNIT / 2;

    fn storage_with(units: usize, slots: usize) -> Storage<TestPlatform> {
        storage_of(config_with(units, slots))
    }

    fn config_with(units: usize, slots: usize) -> StorageConfig {
        StorageConfig {
            page_size: PAGE,
            engine_budget: 1 << 24,
            body_cap: BODY_CAP,
            metadata_cap: Some(64),
            lease_limit: 1024,
            object_rights: 64,
            reader_limit: 4,
            volume: crate::storage::test_volume(units * IO_UNIT, slots),
        }
    }

    fn storage_of(config: StorageConfig) -> Storage<TestPlatform> {
        Storage::initialize(
            &config.validate().unwrap(),
            &PlacementConfig { control_home: 0 },
            TestPlatform::heap(PAGE),
        )
        .unwrap()
    }

    fn storage() -> Storage<TestPlatform> {
        storage_with(UNITS, SLOTS)
    }

    /// The extent work limit of a test volume of `UNITS` units and `slots`
    /// slots, which each reservation preflights.
    fn search(slots: usize) -> usize {
        crate::storage::test_volume(UNITS * IO_UNIT, slots).alloc_search_words
    }

    /// On a fresh five-unit volume, holds one-unit objects at units 1 and 3
    /// and frees units 0, 2 and 4: three free units in three separate runs,
    /// enough for a two-unit layout plus the one-unit reserve, so the layout
    /// clears the reserve and finds no fit. Returns the two holders and the
    /// identity of the slot the next claim takes.
    fn fragmented(
        storage: &Storage<TestPlatform>,
    ) -> (
        ExtentReservation<'_, TestPlatform>,
        ExtentReservation<'_, TestPlatform>,
        AllocationId,
    ) {
        let mut held: Vec<_> = (0..4)
            .map(|_| storage.reserve(Some(1), Some(1), &mut budget()).unwrap())
            .collect();
        let starts: Vec<_> = held.iter().map(|a| a.locator().start_unit()).collect();
        assert_eq!(starts, [0, 1, 2, 3]);
        let third = held.remove(2);
        let first = held.remove(0);
        let head = first.id();
        assert_eq!(first.cancel(), Ok(()));
        assert_eq!(third.cancel(), Ok(()));
        assert_eq!(partition(storage).0.free, 3 * IO_UNIT);
        let last = held.pop().unwrap();
        (held.pop().unwrap(), last, head)
    }

    /// Visits the first reservation of a fresh volume makes: the root
    /// summary, the one indexed run and the bitmap word of the only chunk.
    const FIRST_WORK: usize = 3;

    /// The gate try, the update, one slot take's bundle and the extent search.
    fn budget() -> WorkBudget {
        WorkBudget::new(4 + search(SLOTS))
    }

    fn partition(storage: &Storage<TestPlatform>) -> (RawPartition, SlotPartition) {
        let ledger = storage.pool_report().unwrap().ledger.unwrap();
        (ledger.raw, ledger.slots)
    }

    #[test]
    fn reservation_claims_the_layout_s_units_and_moves_exact_charges() {
        let storage = storage();
        let (raw, slots) = partition(&storage);
        assert_eq!(
            raw,
            RawPartition::new(
                crate::storage::TEST_METADATA_UNITS as usize * IO_UNIT,
                UNITS * IO_UNIT
            )
        );
        let mut spent = budget();
        let mut allocation = storage.reserve(Some(8), Some(60), &mut spent).unwrap();
        assert_eq!(
            spent.counters(),
            WorkCounters {
                coordination_attempts: 1,
                updates: 1,
                visits: 1 + FIRST_WORK,
                ..WorkCounters::default()
            }
        );
        assert_eq!(allocation.locator().len_units(), 1);
        assert_eq!(allocation.locator().start_unit(), 0);
        assert_eq!(allocation.layout().metadata_len(), 8);
        assert_eq!(allocation.layout().body_len(), 60);
        assert!(!allocation.written());
        let (after, after_slots) = partition(&storage);
        assert_eq!(
            after,
            RawPartition {
                metadata: crate::storage::TEST_METADATA_UNITS as usize * IO_UNIT,
                free: (UNITS - 1) * IO_UNIT,
                reserved: 68,
                waste: IO_UNIT - 68,
                ..RawPartition::default()
            }
        );
        assert_eq!(
            after_slots,
            SlotPartition {
                free: SLOTS - 1,
                filling: 1,
                ..SlotPartition::default()
            }
        );
        assert_eq!(slots.free, SLOTS);
        assert!(storage.identity_is_current(allocation.id()));

        // A write marks the owner and moves nothing.
        allocation.mark_written();
        assert!(allocation.written());
        assert_eq!(partition(&storage).0.reserved, 68);

        let empty = storage.reserve(Some(0), Some(0), &mut budget()).unwrap();
        assert_eq!(empty.locator().len_units(), 1);
        assert_eq!(empty.locator().start_unit(), 1);
        assert_eq!(empty.layout().record().header_bytes(), 112);
        let (after, after_slots) = partition(&storage);
        assert_eq!((after.reserved, after.waste), (68, 2 * IO_UNIT - 68));
        assert_eq!(after_slots.filling, 2);

        // Two units for a record past one unit.
        let wide = storage
            .reserve(Some(64), Some(BODY_CAP), &mut budget())
            .unwrap();
        assert_eq!(wide.locator().len_units(), 2);

        // A budget one short of the update tries the gate and changes nothing.
        let (after, after_slots) = partition(&storage);
        let mut short = WorkBudget::new(1);
        assert_eq!(
            storage.reserve(Some(8), Some(100), &mut short).err(),
            Some(ReserveError::BudgetExhausted)
        );
        assert_eq!(short.counters().coordination_attempts, 1);
        assert_eq!(partition(&storage), (after, after_slots));
        assert_eq!(
            after.total(),
            Ok((UNITS + crate::storage::TEST_METADATA_UNITS as usize) * IO_UNIT)
        );
        assert_eq!(after_slots.total(), Ok(SLOTS));
    }

    /// `reserve_minimum` funds exactly one reservation: a success and a
    /// `PayloadFull` refusal both keep the give-back's step, the refusal
    /// having read only the root summary, and one step less refuses
    /// `BudgetExhausted` whether or not a run fits, spending the remainder
    /// and leaving the ledgers as they were and the gate usable.
    #[test]
    fn the_reserve_minimum_funds_exactly_one_reservation() {
        let fresh = storage_with(5, SLOTS);
        let minimum = fresh.reserve_minimum();
        assert_eq!(minimum, 4 + search(SLOTS));
        let mut exact = WorkBudget::new(minimum);
        let first = fresh.reserve(Some(64), Some(BODY_CAP), &mut exact).unwrap();
        // The attempt, the update, the take and the search's visits.
        assert_eq!(exact.remaining(), minimum - (3 + FIRST_WORK));
        drop(first);
        let storage = storage_with(5, SLOTS);
        let (held, other, _) = fragmented(&storage);
        let before = partition(&storage);
        let mut exact = WorkBudget::new(minimum);
        assert_eq!(
            storage.reserve(Some(64), Some(BODY_CAP), &mut exact).err(),
            Some(ReserveError::PayloadFull)
        );
        assert_eq!(
            exact.counters().visits,
            3,
            "the take, the root summary and the give-back"
        );
        for body in [BODY_CAP, 1] {
            let mut short = WorkBudget::new(minimum - 1);
            assert_eq!(
                storage.reserve(Some(64), Some(body), &mut short).err(),
                Some(ReserveError::BudgetExhausted)
            );
            assert_eq!(short.remaining(), 0);
            assert_eq!(partition(&storage), before);
        }
        let fits = storage.reserve(Some(1), Some(1), &mut budget()).unwrap();
        drop((held, other, fits));
    }

    /// A work limit above the derived bound raises the reservation minimum,
    /// which funds any layout, while a reservation preflights only the
    /// largest extent's bound: a budget one step short of that refuses,
    /// and a funded reservation debits only the visits it made.
    #[test]
    fn the_reserve_minimum_follows_the_configured_work_limit() {
        let limit = search(SLOTS) + 100;
        let mut config = config_with(UNITS, SLOTS);
        config.volume.alloc_search_words = limit;
        let storage = storage_of(config);
        assert_eq!(storage.reserve_minimum(), 4 + limit);
        let own = 4 + search(SLOTS);
        let mut short = WorkBudget::new(own - 1);
        assert_eq!(
            storage.reserve(Some(1), Some(1), &mut short).err(),
            Some(ReserveError::BudgetExhausted)
        );
        let mut spent = WorkBudget::new(own);
        let allocation = storage.reserve(Some(1), Some(1), &mut spent).unwrap();
        assert_eq!(spent.counters().visits, 1 + FIRST_WORK);
        drop(allocation);
        // Service's minimum and the pool report follow the largest extent's
        // bound, and the report also carries the configured limit.
        let report = storage.pool_report().unwrap();
        assert_eq!(
            (report.alloc_search_words, report.extent_bound),
            (limit, search(SLOTS))
        );
        assert_eq!(
            storage.service_minimum(),
            super::super::release::SERVICE_MINIMUM + 2 * search(SLOTS)
        );
    }

    /// At the largest `alloc_search_words` validation admits, every budget
    /// minimum stays in range.
    #[test]
    fn every_minimum_fits_at_the_largest_work_limit() {
        let limit = super::super::config::ALLOC_SEARCH_WORDS_LIMIT;
        let mut config = config_with(UNITS, SLOTS);
        config.volume.alloc_search_words = limit;
        let storage = storage_of(config);
        assert_eq!(storage.reserve_minimum() - limit, 4);
        assert_eq!(
            storage.service_minimum(),
            super::super::release::SERVICE_MINIMUM + 2 * search(SLOTS)
        );
        assert!(storage.maintain_minimum() > storage.service_minimum());
    }

    /// An object whose geometry needs two extents refuses at reservation
    /// before any claim: the refusal is typed, no budget is spent, and no
    /// slot, extent or ledger term changes. One payload byte less fits one
    /// extent and reserves its one extent's units.
    #[test]
    fn an_object_needing_two_extents_refuses_at_reservation_and_owns_nothing() {
        use super::super::geometry::EXTENT_PAYLOAD;
        const UNITS: usize = 4096;
        let mut config = config_with(UNITS, SLOTS);
        config.body_cap = 2 * EXTENT_PAYLOAD as usize;
        let storage = storage_of(config);
        let before = storage.pool_report().unwrap().ledger;
        let states: Vec<_> = (0..SLOTS)
            .map(|slot| storage.slot_state(SlotIndex(slot)))
            .collect();
        let mut budget = WorkBudget::new(1 << 12);
        assert_eq!(
            storage
                .reserve(Some(0), Some(EXTENT_PAYLOAD as usize + 1), &mut budget)
                .err(),
            Some(ReserveError::Layout(LayoutError::MultipleExtents {
                extents: 2
            }))
        );
        assert_eq!(budget.remaining(), 1 << 12);
        assert_eq!(storage.pool_report().unwrap().ledger, before);
        let after: Vec<_> = (0..SLOTS)
            .map(|slot| storage.slot_state(SlotIndex(slot)))
            .collect();
        assert_eq!(after, states);
        let full = storage
            .reserve(Some(0), Some(EXTENT_PAYLOAD as usize), &mut budget)
            .unwrap();
        assert_eq!(full.locator().len_units(), 63);
        drop(full);
    }

    /// Every admissible extent, one unit through a full extent's, derives
    /// the extent work bound the pool report carries, so one value
    /// preflights every reservation and return. The volume's work limit,
    /// derived for a one-unit extent, admits the full extent for the same
    /// reason.
    #[test]
    fn every_admissible_extent_derives_the_reported_work_bound() {
        use super::super::geometry::EXTENT_PAYLOAD;
        const UNITS: usize = 4096;
        let mut config = config_with(UNITS, SLOTS);
        config.body_cap = EXTENT_PAYLOAD as usize - config.metadata_cap.unwrap();
        let storage = storage_of(config);
        let largest = storage.live_pool().unwrap().image.largest.units(0);
        let bound = storage.pool_report().unwrap().extent_bound;
        assert_eq!(largest, 63);
        assert_eq!(
            bound,
            crate::storage::extent::work_bound(UNITS as u64, SLOTS, largest)
        );
        for units in 1..=largest {
            assert_eq!(
                crate::storage::extent::work_bound(UNITS as u64, SLOTS, units),
                bound,
                "{units} units"
            );
        }
    }

    #[test]
    fn every_claim_refusal_leaves_the_pool_gate_open() {
        let gate_opens = |storage: &Storage<TestPlatform>| {
            storage
                .live_pool()
                .unwrap()
                .try_lock()
                .map(|access| access.release())
        };
        let mut cases = Vec::new();

        // Two free units fall one short of a two-unit layout plus the reserve.
        let short = storage_with(3, SLOTS);
        let held = short.reserve(Some(1), Some(1), &mut budget()).unwrap();
        let refusal = short.reserve(Some(64), Some(BODY_CAP), &mut budget()).err();
        cases.push((refusal, ReserveError::CleanReserve, gate_opens(&short)));
        let slots = storage_with(UNITS, 1);
        let only = slots.reserve(Some(1), Some(1), &mut budget()).unwrap();
        let refusal = slots.reserve(Some(1), Some(1), &mut budget()).err();
        cases.push((refusal, ReserveError::ObjectSlotsFull, gate_opens(&slots)));
        // Each free run contains one unit; the requested layout requires two.
        let split = storage_with(5, SLOTS);
        let (a, b, _) = fragmented(&split);
        let refusal = split.reserve(Some(64), Some(BODY_CAP), &mut budget()).err();
        cases.push((refusal, ReserveError::PayloadFull, gate_opens(&split)));
        // The attempt and update exhaust the work budget, so the slot take
        // returns `BudgetExhausted`.
        let unfunded = storage();
        let refusal = unfunded
            .reserve(Some(1), Some(1), &mut WorkBudget::new(2))
            .err();
        cases.push((
            refusal,
            ReserveError::BudgetExhausted,
            gate_opens(&unfunded),
        ));
        // The budget funds the take and its give-back, and the search's
        // preflight returns `BudgetExhausted`.
        let refusal = unfunded
            .reserve(Some(1), Some(1), &mut WorkBudget::new(2 + TAKE_BUNDLE))
            .err();
        cases.push((
            refusal,
            ReserveError::BudgetExhausted,
            gate_opens(&unfunded),
        ));

        for (refusal, expected, opens) in cases {
            assert_eq!(refusal, Some(expected));
            assert_eq!(opens, Ok(()), "{expected:?}");
        }
        drop((held, only, a, b));
    }

    /// A reservation the search cannot fund, or that finds no fitting run,
    /// restores its slot with its incarnation unchanged and leaves the free
    /// set and both ledgers as they were.
    #[test]
    fn refusals_restore_only_the_failed_attempt_and_keep_the_incumbent() {
        let storage = storage_with(5, SLOTS);
        let (mut incumbent, other, head) = fragmented(&storage);
        incumbent.mark_written();
        let incumbent_locator = incumbent.locator();
        let before = partition(&storage);
        let head_state = Some((SlotState::Free, head.incarnation()));

        // Three free units in separate runs: a two-unit layout clears the
        // reserve and finds no fit.
        assert_eq!(
            storage
                .reserve(Some(64), Some(BODY_CAP), &mut budget())
                .err(),
            Some(ReserveError::PayloadFull)
        );
        assert_eq!(partition(&storage), before);
        assert_eq!(storage.slot_state(head.slot()), head_state);

        // A budget that pays the take and its give-back but not the
        // search restores the slot and spends the remainder.
        let mut unfunded = WorkBudget::new(2 + search(SLOTS));
        assert_eq!(
            storage.reserve(Some(1), Some(1), &mut unfunded).err(),
            Some(ReserveError::BudgetExhausted)
        );
        assert_eq!(unfunded.remaining(), 0);
        assert_eq!(partition(&storage), before);
        assert_eq!(storage.slot_state(head.slot()), head_state);

        // Caps and unknown lengths refuse without spending budget.
        let mut zero = WorkBudget::new(0);
        assert_eq!(
            storage.reserve(None, Some(1), &mut zero).err(),
            Some(ReserveError::Layout(LayoutError::UnknownLength))
        );
        assert_eq!(
            storage.reserve(Some(65), Some(1), &mut zero).err(),
            Some(ReserveError::Layout(LayoutError::MetadataTooLarge {
                len: 65,
                cap: 64
            }))
        );
        assert_eq!(
            storage
                .reserve(Some(1), Some(BODY_CAP + 1), &mut zero)
                .err(),
            Some(ReserveError::Layout(LayoutError::BodyTooLarge {
                len: BODY_CAP + 1,
                cap: BODY_CAP
            }))
        );
        assert_eq!(
            storage.reserve(Some(1), Some(1), &mut zero).err(),
            Some(ReserveError::BudgetExhausted)
        );
        assert_eq!(zero.counters(), WorkCounters::default());

        // Slot shortage on a volume with room left.
        let roomy = storage_with(UNITS, 2);
        let first = roomy.reserve(Some(1), Some(1), &mut budget()).unwrap();
        let second = roomy.reserve(Some(1), Some(1), &mut budget()).unwrap();
        let full = partition(&roomy);
        assert_eq!(
            roomy.reserve(Some(1), Some(1), &mut budget()).err(),
            Some(ReserveError::ObjectSlotsFull)
        );
        assert_eq!(partition(&roomy), full);
        drop((first, second));

        // A held gate refuses without waiting.
        {
            let held = storage.live_pool().unwrap().lock().unwrap();
            let mut contended = budget();
            assert_eq!(
                storage.reserve(Some(1), Some(1), &mut contended).err(),
                Some(ReserveError::Gate(GateError::Contended))
            );
            assert_eq!(contended.remaining(), budget().remaining() - 1);
            drop(held);
        }

        // Close: new admission refused, existing owners untouched.
        storage.close();
        storage.close();
        assert!(storage.is_closed());
        assert_eq!(
            storage.reserve(Some(1), Some(1), &mut zero).err(),
            Some(ReserveError::Closed)
        );
        assert_eq!(incumbent.locator(), incumbent_locator);
        assert!(storage.identity_is_current(incumbent.id()));
        drop((incumbent, other));
        assert_eq!(partition(&storage).0.retired, 2 + 2);
    }

    #[test]
    fn exhausted_incarnation_quarantines_the_slot_and_stale_identities_are_rejected() {
        let storage = storage();
        {
            let live = storage.live_pool().unwrap();
            let _held = live.lock().unwrap();
            live.set_incarnation(0, u32::MAX);
        }
        // The exhausted slot costs one more take; a budget that covers a
        // single take's bundle refuses at the second, spends its remainder and
        // leaves the exhausted slot quarantined with nothing claimed.
        let mut single = WorkBudget::new(4);
        assert_eq!(
            storage.reserve(Some(1), Some(1), &mut single).err(),
            Some(ReserveError::BudgetExhausted)
        );
        assert_eq!(single.counters().visits, 2);
        assert_eq!(single.remaining(), 0);
        assert_eq!(
            storage.slot_state(SlotIndex(0)),
            Some((SlotState::Quarantined, u32::MAX))
        );
        assert_eq!(partition(&storage).1.filling, 0);
        let mut next = budget();
        let first = storage.reserve(Some(1), Some(1), &mut next).unwrap();
        assert_eq!(next.counters().visits, 1 + FIRST_WORK);
        assert_eq!(
            storage.slot_state(SlotIndex(1)),
            Some((SlotState::Filling, 1))
        );
        assert_eq!(
            partition(&storage).1,
            SlotPartition {
                free: 2,
                filling: 1,
                quarantined: 1,
                ..SlotPartition::default()
            }
        );
        let id = first.id();
        assert!(storage.identity_is_current(id));
        assert!(!storage.identity_is_current(AllocationId::new(SlotIndex(1), 0)));
        assert!(!storage.identity_is_current(AllocationId::new(SlotIndex(0), u32::MAX)));
        assert!(!storage.identity_is_current(AllocationId::new(SlotIndex(SLOTS), 1)));

        // Cancel gives the slot back; its identity is no longer current, the
        // next issue takes the slot at the cursor, and the returned slot
        // comes back when the cursor reaches it, with its incarnation
        // advanced again. The quarantined slot is never reissued.
        assert_eq!(first.cancel(), Ok(()));
        assert!(!storage.identity_is_current(id));
        let again = storage.reserve(Some(1), Some(1), &mut budget()).unwrap();
        assert_eq!(again.id(), AllocationId::new(SlotIndex(2), 1));
        let third = storage.reserve(Some(1), Some(1), &mut budget()).unwrap();
        let fourth = storage.reserve(Some(1), Some(1), &mut budget()).unwrap();
        assert_eq!(third.id(), AllocationId::new(SlotIndex(3), 1));
        assert_eq!(fourth.id(), AllocationId::new(SlotIndex(1), 2));
        assert_eq!(
            storage.reserve(Some(1), Some(1), &mut budget()).err(),
            Some(ReserveError::ObjectSlotsFull)
        );
    }

    /// A free slot whose word carries a count fails closed at its take. Here
    /// the take runs in a destructor that catches its panic while the thread
    /// unwinds from another: the take has already removed the slot from the
    /// free set, and the gate guard, taken during the unwind, would release
    /// open on drop. The panic leaves the word as it was and poisons the
    /// gate, so no later claim runs over it.
    #[test]
    fn a_counted_free_word_poisons_the_gate_at_its_take_during_unwinding() {
        struct ReservesOnDrop<'a>(&'a Storage<TestPlatform>, &'a std::cell::Cell<bool>);
        impl Drop for ReservesOnDrop<'_> {
            fn drop(&mut self) {
                let storage = self.0;
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    storage
                        .reserve(Some(1), Some(1), &mut budget())
                        .map(|claimed| claimed.id())
                }));
                self.1.set(outcome.is_err());
            }
        }
        let storage = storage();
        let live = storage.live_pool().unwrap();
        {
            let _held = live.lock().unwrap();
            live.set_incarnation(0, u32::MAX);
            live.set_refs(0, 1);
        }
        let counted = live.records()[0].ident.load(Ordering::Relaxed);
        let panicked = std::cell::Cell::new(false);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _reserver = ReservesOnDrop(&storage, &panicked);
            panic!("an unrelated panic with a live reserver");
        }));
        assert!(outcome.is_err());
        assert!(panicked.get(), "premise: the take panicked");
        assert_eq!(live.records()[0].ident.load(Ordering::Relaxed), counted);
        assert_eq!(
            storage.reserve(Some(1), Some(1), &mut budget()).err(),
            Some(ReserveError::Gate(GateError::Poisoned))
        );
    }

    #[test]
    fn cancel_needs_exclusive_proof_and_drop_records_abandonment() {
        let storage = storage();
        let before = partition(&storage);

        // Unwritten: immediate return; the extent coalesces back and the
        // next reservation gets the same extent.
        let first = storage.reserve(Some(8), Some(100), &mut budget()).unwrap();
        let address = first.locator();
        assert_eq!(first.cancel(), Ok(()));
        assert_eq!(partition(&storage), before);
        assert_eq!(storage.slot_state(SlotIndex(0)), Some((SlotState::Free, 1)));
        storage.live_pool().unwrap().claim_next(0);
        let second = storage.reserve(Some(8), Some(100), &mut budget()).unwrap();
        assert_eq!(second.locator(), address);
        assert_eq!(second.id(), AllocationId::new(SlotIndex(0), 2));

        // Written: cancel is refused, the owner drops, and abandonment moves
        // the payload to retired under an uncontended gate.
        let mut exposed = second;
        exposed.mark_written();
        let id = exposed.id();
        assert_eq!(exposed.cancel(), Err(Retained));
        let (raw, slots) = partition(&storage);
        assert_eq!((raw.retired, raw.reserved, raw.resident), (108, 0, 0));
        assert_eq!(raw.waste, IO_UNIT - 108);
        assert_eq!(slots.retired, 1);
        assert_eq!(
            storage.slot_state(SlotIndex(0)).map(|s| s.0),
            Some(SlotState::Retired)
        );
        assert!(storage.identity_is_current(id));
        assert_eq!(storage.pool_report().unwrap().pending_marks, 0);
        let live = storage.live_pool().unwrap();
        assert_eq!(live.flags(0), ABANDONED | RETIRED);
        // The retired extent is still charged: the next reservation takes
        // fresh units.
        let third = storage.reserve(Some(8), Some(100), &mut budget()).unwrap();
        assert_ne!(third.locator(), address);
        assert_eq!(partition(&storage).0.retired, 108);
    }

    /// Claims without a key take free slots in index order from the claim
    /// cursor, wrapping at the slot count, and a reservation refused after
    /// its claim gives its slot back and moves the cursor back to it, so
    /// the next claim takes the same slot and every incarnation is
    /// unchanged by the refusal.
    #[test]
    fn keyless_claims_follow_the_cursor_and_a_refusal_keeps_it() {
        let storage = storage();
        let reserve_all = || -> Vec<ExtentReservation<'_, TestPlatform>> {
            (0..SLOTS)
                .map(|_| storage.reserve(Some(8), Some(100), &mut budget()).unwrap())
                .collect()
        };
        let slots = |owners: &[ExtentReservation<'_, TestPlatform>]| -> Vec<(usize, u32)> {
            owners
                .iter()
                .map(|owner| (owner.id().slot_index(), owner.id().incarnation()))
                .collect()
        };
        let mut owners = reserve_all();
        assert_eq!(slots(&owners), [(0, 1), (1, 1), (2, 1), (3, 1)]);
        // Returned in the order 2, 0, 3, 1; the cursor wrapped to slot 0.
        for index in [2, 0, 3, 1] {
            let position = owners
                .iter()
                .position(|owner| owner.id().slot_index() == index)
                .unwrap();
            assert_eq!(owners.swap_remove(position).cancel(), Ok(()));
        }
        // A reservation whose extent search cannot be paid claims slot 0 and
        // gives it back with the cursor on it.
        let mut short = WorkBudget::new(storage.reserve_minimum() - 1);
        assert_eq!(
            storage.reserve(Some(8), Some(100), &mut short).err(),
            Some(ReserveError::BudgetExhausted)
        );
        let mut owners = reserve_all();
        assert_eq!(slots(&owners), [(0, 2), (1, 2), (2, 2), (3, 2)]);
        // With slots 1 and 3 free and the cursor at 0, a refused claim takes
        // slot 1 and leaves the cursor there; the next claims take 1, then 3.
        assert_eq!(owners.remove(3).cancel(), Ok(()));
        assert_eq!(owners.remove(1).cancel(), Ok(()));
        let mut short = WorkBudget::new(storage.reserve_minimum() - 1);
        assert_eq!(
            storage.reserve(Some(8), Some(100), &mut short).err(),
            Some(ReserveError::BudgetExhausted)
        );
        let later: Vec<_> = (0..2)
            .map(|_| storage.reserve(Some(8), Some(100), &mut budget()).unwrap())
            .collect();
        assert_eq!(slots(&later), [(1, 3), (3, 3)]);
        // Every slot is held; the cursor has wrapped to slot 0, and the
        // first slot returned is the next claimed.
        assert_eq!(
            storage.reserve(Some(8), Some(100), &mut budget()).err(),
            Some(ReserveError::ObjectSlotsFull)
        );
        assert_eq!(owners.remove(1).cancel(), Ok(()));
        let next = storage.reserve(Some(8), Some(100), &mut budget()).unwrap();
        assert_eq!((next.id().slot_index(), next.id().incarnation()), (2, 3));
    }

    #[test]
    fn drop_with_a_busy_gate_marks_pending_without_waiting() {
        let storage = storage();
        let allocation = storage.reserve(Some(8), Some(100), &mut budget()).unwrap();
        let live = storage.live_pool().unwrap();
        let held = live.lock().unwrap();
        drop(allocation);
        assert_eq!(live.flags(0), ABANDONED);
        assert_eq!(live.telemetry().pending_marks.load(Ordering::Acquire), 1);
        drop(held);
        // The ledger has not moved: the obligation is in the flag, waiting
        // for service.
        let report = storage.pool_report().unwrap();
        let ledger = report.ledger.unwrap();
        assert_eq!(ledger.raw.reserved, 108);
        assert_eq!(ledger.raw.retired, 0);
        assert_eq!(report.pending_marks, 1);
        // An owner's drop is mandatory work, not budgeted reservation
        // contention: a busy owner-drop try does not increment `failed_tries`.
        assert_eq!(report.failed_tries, 0);
    }

    #[test]
    fn reservation_and_drop_allocate_nothing() {
        let storage = storage();
        let before = crate::instrument::allocations();
        let mut allocation = storage.reserve(Some(8), Some(100), &mut budget()).unwrap();
        allocation.mark_written();
        drop(allocation);
        let cancelled = storage.reserve(Some(8), Some(100), &mut budget()).unwrap();
        assert_eq!(cancelled.cancel(), Ok(()));
        assert_eq!(crate::instrument::allocations(), before);
    }

    /// A reservation without a key hints the record line its completion
    /// writes, and nothing of the extent, which lives on the device.
    #[test]
    fn a_reservation_hints_only_the_completion_line() {
        use super::super::prefetch::WRITE_HINTS;
        let storage = storage();
        let before = WRITE_HINTS.with(std::cell::Cell::get);
        let allocation = storage
            .reserve(Some(64), Some(BODY_CAP), &mut budget())
            .unwrap();
        let hinted = WRITE_HINTS.with(std::cell::Cell::get) - before;
        assert_eq!(hinted, 1);
        assert_eq!(allocation.cancel(), Ok(()));
    }

    #[test]
    fn a_placed_claim_hints_the_lines_its_claim_and_bind_store_through() {
        use super::super::prefetch::WRITE_HINTS;
        use super::super::publish_tests::{index_config, storage as indexed};
        const CLAIM_HINTS: usize = 5;
        const BUCKET_HINTS: usize = 3;
        let limits = [8usize];
        let storage = indexed(16, &index_config(&limits, (1, 1), 1));
        let (live, root) = storage.live().unwrap();
        let layout = AllocationLayout::new(
            Some(4),
            Some(20),
            root.metadata_cap,
            root.body_cap,
            &storage.record,
        )
        .unwrap();
        let fingerprint = storage.route(&[0x5A; 32]).unwrap().fingerprint();
        let before = WRITE_HINTS.with(std::cell::Cell::get);
        let allocation = storage
            .reserve_layout(live, layout, Some(fingerprint), &mut budget())
            .unwrap();
        let hinted = WRITE_HINTS.with(std::cell::Cell::get) - before;
        assert_eq!(hinted, CLAIM_HINTS + BUCKET_HINTS);
        assert_eq!(allocation.cancel(), Ok(()));
    }

    /// A close before a reservation refuses `Closed` before the gate: the
    /// partitions, every slot's state and incarnation and the engine charge
    /// are exactly as before, and a zero budget is enough for the refusal.
    #[test]
    fn a_close_before_reservation_refuses_and_leaves_the_volume_untouched() {
        let storage = storage();
        let before = partition(&storage);
        let slots: Vec<_> = (0..SLOTS)
            .map(|slot| storage.slot_state(SlotIndex(slot)))
            .collect();
        let engine = storage.engine_used();
        storage.close();
        let mut zero = WorkBudget::new(0);
        assert_eq!(
            storage.reserve(Some(8), Some(100), &mut zero).err(),
            Some(ReserveError::Closed)
        );
        assert_eq!(partition(&storage), before);
        assert_eq!(
            (0..SLOTS)
                .map(|slot| storage.slot_state(SlotIndex(slot)))
                .collect::<Vec<_>>(),
            slots
        );
        assert_eq!(storage.engine_used(), engine);
        assert_eq!(storage.pool_report().unwrap().failed_tries, 0);
    }

    /// Seeded reserve, abandon, cancel, complete, return and service
    /// histories against an independent model of held units, observed after
    /// every call through the gate-held report. The model predicts each
    /// reservation: `CleanReserve` when its free units are fewer than the
    /// layout's units plus the one-unit reserve; otherwise `ObjectSlotsFull`
    /// when every slot is filling, resident
    /// or retired and unserviced; otherwise `PayloadFull` exactly when no
    /// maximal free run covers the layout's units; otherwise the extent at
    /// the start of the best-fitting indexed run, read under the gate before
    /// the call, or of the lowest maximal free run that covers them when no
    /// indexed run does. The raw
    /// partition sums to the volume's bytes, its terms and the slot counts
    /// match the model's, and the allocator's bitmap, summaries and run
    /// index agree after every step.
    #[test]
    fn seeded_histories_conserve_raw_bytes_after_every_gate_held_step() {
        const MANY_SLOTS: usize = 24;
        const MANY_UNITS: usize = 30;
        const MANY_METADATA: u64 = 2;
        let (mut slot_full, mut payload_full, mut serviced, mut returned) = (0, 0, 0, 0);
        let (mut clean_reserve, mut other_slot, mut next_incarnation) = (0, 0, 0);
        for seed in 0..8 {
            let storage = {
                let mut config = config_with(MANY_UNITS, MANY_SLOTS);
                config.volume = crate::storage::test_volume_with(
                    MANY_UNITS * IO_UNIT,
                    MANY_METADATA,
                    MANY_SLOTS,
                );
                storage_of(config)
            };
            let mut rng = SplitMix64::new(seed);
            let funded = || WorkBudget::new(1 << 12);
            let (mut reserved, mut resident, mut retired, mut waste) = (0, 0, 0, 0);
            // The ghost unit map: each held unit's owning identity, and the
            // identity that last held each unit.
            let mut used: [Option<AllocationId>; MANY_UNITS] = [None; MANY_UNITS];
            let mut last: [Option<AllocationId>; MANY_UNITS] = [None; MANY_UNITS];
            let mut live: Vec<(ExtentReservation<'_, TestPlatform>, usize, usize)> = Vec::new();
            // Resident owners with their payloads and their extents' starts and units.
            let mut completed: Vec<(Completed<'_, TestPlatform>, usize, (u64, u32))> = Vec::new();
            // Extents retired and not yet serviced, by owner, start and length.
            let mut unserviced: Vec<(AllocationId, (u64, u32))> = Vec::new();
            // A claim installs its identity on free units only; a return frees
            // only units its own identity holds.
            let mark = |used: &mut [Option<AllocationId>; MANY_UNITS],
                        (start, len): (u64, u32),
                        owner: AllocationId,
                        on: bool| {
                for unit in &mut used[start as usize..start as usize + len as usize] {
                    assert_eq!(
                        *unit,
                        (!on).then_some(owner),
                        "a unit changed owner wrongly"
                    );
                    *unit = on.then_some(owner);
                }
            };
            for _ in 0..400 {
                match rng.next_u64() % 12 {
                    0..=4 => {
                        let body = (rng.next_u64() % (BODY_CAP as u64 + 1)) as usize;
                        let payload = 1 + body;
                        let header = 108 + 4 * (payload.div_ceil(8192) + 1);
                        let units = (header + payload).div_ceil(IO_UNIT);
                        // Maximal free runs of the model.
                        let mut runs = Vec::new();
                        let mut at = 0;
                        while at < MANY_UNITS {
                            let start = at;
                            while at < MANY_UNITS && used[at].is_none() {
                                at += 1;
                            }
                            if at > start {
                                runs.push((at - start, start));
                            }
                            at += 1;
                        }
                        let fits: Vec<usize> = runs
                            .into_iter()
                            .filter(|&(len, _)| len >= units)
                            .map(|(_, start)| start)
                            .collect();
                        let indexed = {
                            let mut gate = storage.live_pool().unwrap().lock().unwrap();
                            let runs = gate.tables().extents().indexed_runs();
                            gate.release();
                            runs
                        };
                        let predicted = indexed
                            .iter()
                            .filter(|run| run.1 >= units as u64)
                            .min_by_key(|run| (run.1, run.0))
                            .map(|run| run.0 as usize)
                            .or(fits.first().copied());
                        let held = live.len() + completed.len() + unserviced.len();
                        let free = used.iter().filter(|u| u.is_none()).count();
                        let clears = free > units;
                        let result = storage.reserve(Some(1), Some(body), &mut funded());
                        match (result, fits.first()) {
                            (Err(ReserveError::CleanReserve), _) if !clears => clean_reserve += 1,
                            (Err(ReserveError::ObjectSlotsFull), _)
                                if clears && held == MANY_SLOTS =>
                            {
                                slot_full += 1
                            }
                            (Err(ReserveError::PayloadFull), None)
                                if clears && held < MANY_SLOTS =>
                            {
                                payload_full += 1
                            }
                            (Ok(allocation), Some(_)) if clears && held < MANY_SLOTS => {
                                let at = allocation.locator();
                                assert_eq!(Some(at.start_unit() as usize), predicted);
                                assert_eq!(at.len_units() as usize, units);
                                let range = at.start_unit() as usize
                                    ..(at.start_unit() + u64::from(at.len_units())) as usize;
                                let id = allocation.id();
                                for was in last[range.clone()].iter().flatten() {
                                    if was.slot_index() != id.slot_index() {
                                        other_slot += 1;
                                    } else if was.incarnation() != id.incarnation() {
                                        next_incarnation += 1;
                                    }
                                }
                                last[range].fill(Some(id));
                                mark(&mut used, (at.start_unit(), at.len_units()), id, true);
                                reserved += payload;
                                waste += units * IO_UNIT - payload;
                                live.push((allocation, payload, units));
                            }
                            (result, _) => panic!(
                                "held {held}, fits {fits:?}, got {:?}",
                                result.map(|allocation| allocation.locator())
                            ),
                        }
                    }
                    5 if !live.is_empty() => {
                        let at = (rng.next_u64() as usize) % live.len();
                        let (mut allocation, payload, _) = live.swap_remove(at);
                        allocation.mark_written();
                        let locator = allocation.locator();
                        unserviced
                            .push((allocation.id(), (locator.start_unit(), locator.len_units())));
                        drop(allocation);
                        reserved -= payload;
                        retired += payload;
                    }
                    6 if !live.is_empty() => {
                        let at = (rng.next_u64() as usize) % live.len();
                        let (allocation, payload, units) = live.swap_remove(at);
                        let (locator, id) = (allocation.locator(), allocation.id());
                        assert_eq!(allocation.cancel(), Ok(()));
                        mark(
                            &mut used,
                            (locator.start_unit(), locator.len_units()),
                            id,
                            false,
                        );
                        reserved -= payload;
                        waste -= units * IO_UNIT - payload;
                    }
                    7 | 8 if !live.is_empty() => {
                        let at = (rng.next_u64() as usize) % live.len();
                        let (allocation, payload, _) = live.swap_remove(at);
                        let locator = allocation.locator();
                        let object = allocation
                            .complete([at as u8; 32], u64::MAX, &mut funded())
                            .ok()
                            .unwrap();
                        reserved -= payload;
                        resident += payload;
                        let extent = (locator.start_unit(), locator.len_units());
                        completed.push((object, payload, extent));
                    }
                    9 if !completed.is_empty() => {
                        let at = (rng.next_u64() as usize) % completed.len();
                        let (object, payload, extent) = completed.swap_remove(at);
                        unserviced.push((object.id(), extent));
                        drop(object);
                        resident -= payload;
                        retired += payload;
                    }
                    10 if !completed.is_empty() => {
                        let at = (rng.next_u64() as usize) % completed.len();
                        let (object, payload, extent) = completed.swap_remove(at);
                        let id = object.id();
                        let transfer = object.release();
                        assert_eq!(
                            storage.return_allocation(transfer, &mut funded()),
                            Ok(ReturnOutcome::Returned)
                        );
                        mark(&mut used, extent, id, false);
                        resident -= payload;
                        waste -= extent.1 as usize * IO_UNIT - payload;
                        returned += 1;
                    }
                    _ => {
                        let report = storage.service(&mut funded()).unwrap();
                        serviced += report.serviced;
                        // Every retired record returns: no reader holds it.
                        assert_eq!(report.serviced, unserviced.len());
                        for (id, extent) in unserviced.drain(..) {
                            mark(&mut used, extent, id, false);
                        }
                        retired = 0;
                        waste = live.iter().map(|(_, p, u)| u * IO_UNIT - p).sum::<usize>()
                            + completed
                                .iter()
                                .map(|(_, p, (_, u))| *u as usize * IO_UNIT - p)
                                .sum::<usize>();
                    }
                }
                let (raw, slots) = partition(&storage);
                assert_eq!(raw.total(), Ok((MANY_UNITS + 2) * IO_UNIT));
                assert_eq!(raw.metadata, MANY_METADATA as usize * IO_UNIT);
                assert_eq!(
                    (raw.reserved, raw.resident, raw.retired, raw.waste),
                    (reserved, resident, retired, waste)
                );
                assert_eq!(
                    raw.free,
                    used.iter().filter(|u| u.is_none()).count() * IO_UNIT
                );
                {
                    // The bitmap, its summaries and the run index agree after
                    // the step, and each held identity's record names exactly
                    // the extent the unit map gives it, read under the gate
                    // like any holder.
                    let mut held = storage.live_pool().unwrap().lock().unwrap();
                    let mut tables = held.tables();
                    tables.extents().check(MANY_METADATA);
                    let owners = live
                        .iter()
                        .map(|(a, _, _)| {
                            (a.id(), (a.locator().start_unit(), a.locator().len_units()))
                        })
                        .chain(completed.iter().map(|(o, _, extent)| (o.id(), *extent)))
                        .chain(unserviced.iter().copied());
                    for (id, (start, len)) in owners {
                        let locator = tables.held_locator(id.slot_index());
                        assert_eq!((locator.start_unit(), locator.len_units()), (start, len));
                        let range = start as usize..start as usize + len as usize;
                        assert!(used[range].iter().all(|unit| *unit == Some(id)));
                    }
                    held.release();
                }
                assert_eq!(slots.total(), Ok(MANY_SLOTS));
                assert_eq!(
                    (slots.filling, slots.resident, slots.retired),
                    (live.len(), completed.len(), unserviced.len())
                );
            }
        }
        assert!(
            slot_full > 0
                && payload_full > 0
                && clean_reserve > 0
                && serviced > 0
                && returned > 0
                && other_slot > 0
                && next_incarnation > 0,
            "slot {slot_full}, payload {payload_full}, reserve {clean_reserve}, \
             serviced {serviced}, returned {returned}, \
             reowned by another slot {other_slot} and by the next incarnation {next_incarnation}"
        );
    }

    /// Same-size extents of two slots, then successors on the returned
    /// extent's units, first from another slot and then from the same slot's
    /// next incarnation: each return frees only its own record's extent, and
    /// every other owner's record keeps the units it names.
    #[test]
    fn same_size_extents_of_different_owners_return_only_their_own_units() {
        // Sixteen slots give the run index two entries, so the returned
        // one-unit run stays indexed beside the volume's tail.
        let storage = storage_with(UNITS, 16);
        let gated = |read: &dyn Fn(&mut Tables<'_>) -> Vec<(u64, u64)>| {
            let mut held = storage.live_pool().unwrap().lock().unwrap();
            let seen = read(&mut held.tables());
            held.release();
            seen
        };
        let named = |slot: usize| {
            gated(&|tables| {
                let locator = tables.held_locator(slot);
                vec![(locator.start_unit(), u64::from(locator.len_units()))]
            })[0]
        };
        let free = || gated(&|tables| tables.extents().free_set());
        let first = storage.reserve(Some(1), Some(1), &mut budget()).unwrap();
        let second = storage.reserve(Some(1), Some(1), &mut budget()).unwrap();
        let (freed, kept) = (first.locator(), second.locator());
        assert_eq!(freed.len_units(), kept.len_units());
        let previous = first.id();
        assert_eq!(first.cancel(), Ok(()));
        let span = |locator: ExtentLocator| (locator.start_unit(), u64::from(locator.len_units()));
        // A successor from another slot takes the freed units; returning it
        // frees those units and leaves the other owner's.
        let other = storage.reserve(Some(1), Some(1), &mut budget()).unwrap();
        assert_ne!(other.id().slot_index(), previous.slot_index());
        assert_eq!(other.locator(), freed);
        assert_eq!(named(other.id().slot_index()), span(freed));
        assert_eq!(named(second.id().slot_index()), span(kept));
        assert_eq!(other.cancel(), Ok(()));
        let runs = free();
        assert!(runs.contains(&span(freed)));
        assert!(
            runs.iter()
                .all(|&(at, len)| at + len <= kept.start_unit() || at > kept.start_unit())
        );
        // Claims and returns walk the cursor round to the first slot, whose
        // next incarnation takes the same units.
        for _ in 3..16 {
            let passing = storage.reserve(Some(1), Some(1), &mut budget()).unwrap();
            assert_eq!(passing.cancel(), Ok(()));
        }
        let successor = storage.reserve(Some(1), Some(1), &mut budget()).unwrap();
        assert_eq!(successor.id().slot_index(), previous.slot_index());
        assert_eq!(successor.id().incarnation(), previous.incarnation() + 1);
        assert_eq!(successor.locator(), freed);
        // Returning the other owner frees only its units: the successor's
        // stay held and its record names them.
        assert_eq!(second.cancel(), Ok(()));
        let runs = free();
        assert!(
            runs.iter()
                .all(|&(at, len)| at + len <= freed.start_unit() || at > freed.start_unit())
        );
        assert!(
            runs.iter()
                .any(|&(at, len)| at <= kept.start_unit() && kept.start_unit() < at + len)
        );
        assert_eq!(named(previous.slot_index()), span(freed));
        assert_eq!(successor.cancel(), Ok(()));
        assert_eq!(partition(&storage).0.free, UNITS * IO_UNIT);
    }

    /// Owner drop during unwinding, before and after a writable view,
    /// records abandonment exactly like an ordinary drop.
    #[test]
    fn unwinding_owners_record_abandonment_before_and_after_exposure() {
        let storage = storage();
        for expose in [false, true] {
            let before = partition(&storage);
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut allocation = storage.reserve(Some(8), Some(100), &mut budget()).unwrap();
                if expose {
                    allocation.mark_written();
                }
                panic!("unwind with a live owner");
            }));
            assert!(outcome.is_err());
            let (raw, slots) = partition(&storage);
            assert_eq!(raw.retired, before.0.retired + 108);
            assert_eq!(raw.reserved, 0);
            assert_eq!(slots.retired, before.1.retired + 1);
            assert_eq!(storage.pool_report().unwrap().pending_marks, 0);
        }
        // Unwinding against a poisoned gate leaves the obligation in the
        // flag and the pending counter.
        let allocation = storage.reserve(Some(8), Some(100), &mut budget()).unwrap();
        let slot = allocation.id().slot_index();
        std::thread::scope(|scope| {
            let handle = scope.spawn(|| {
                let _held = storage.live_pool().unwrap().lock().unwrap();
                panic!("poison the gate");
            });
            assert!(handle.join().is_err());
        });
        drop(allocation);
        let live = storage.live_pool().unwrap();
        assert_eq!(live.flags(slot), ABANDONED);
        assert_eq!(live.telemetry().pending_marks.load(Ordering::Acquire), 1);
        assert_eq!(
            storage.reserve(Some(8), Some(100), &mut budget()).err(),
            Some(ReserveError::Gate(GateError::Poisoned))
        );
    }
}
