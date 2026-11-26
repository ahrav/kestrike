//! Returning storage exactly once, servicing pending obligations within a
//! budget, and counting what is still outstanding before drain.
//!
//! A [`ReturnTransfer`] is the domain's eligibility proof for one exact
//! incarnation. It exists only by consuming the unique owner, borrows the
//! storage it came from, cannot be copied, and is consumed by the return, so
//! the same eligibility can be spent at most once by construction and never
//! against another storage; a transfer that no longer matches the slot record
//! (stale incarnation, a free or quarantined slot) returns no credit and
//! changes nothing. A return that cannot take the gate, or whose budget
//! cannot cover the try and the return work of what the slot holds
//! ([`Pool::held_work`]), parks: it moves the obligation into the slot's
//! word's pre-reserved flag and the pending counter, exactly like a dropped owner,
//! where maintenance finds it. A transfer that is dropped unspent parks the
//! obligation the same way, so releasing an owner and then losing the
//! transfer cannot lose the slot. Parking trusts the transfer's freshness,
//! which holds by construction because only a consumed owner produces one.
//! Return after close is ordinary return.
//!
//! Service visits only the pending cohort: the slots holding a retired
//! record or a parked obligation, found through the `pending` module's two
//! hierarchical sets. A call that takes the gate pays [`SERVICE_CONTROLS`]:
//! the gate attempt with its release, the cursors' restore and their save;
//! a busy or poisoned gate costs the attempt alone and leaves the cursors
//! intact. The call then runs a retired pass over the retired set from
//! `cursor_slot` and a park pass over the parked set from `cursor_park`.
//! Each pass funds every read of a summary or bitmap word, one probe of
//! [`RETIRED_PROBE`] or [`PARKED_PROBE`] steps, before it is made. A pass
//! walks each stretch of the table it covers once, handing on the members
//! of each bitmap word from the bits it read, so a stretch makes at most one
//! probe of each summary and bitmap word. Each member it finds is funded
//! [`SERVICE_PER_SLOT`] steps once the allowance also covers the largest
//! extent's work bound, plus [`SEQUENCE_VISIT`] for a member holding a
//! sequence, before any validation or update: the visit, the three
//! eligibility validations (the flag, the stamp against the certificate,
//! the count), the possible anchor update and the possible return update.
//! A member whose sighted word shows a right holding it with no anchor
//! counted and no list link to detach is held on that bundle alone; every
//! other member takes the full decision. A visit returns at most one
//! extent. For a slot that holds a sequence of two or more held extents it
//! returns the last one, moving its charge to free, and leaves the slot's
//! incarnation, pending membership and block in place for a later visit; a
//! resident still linked leaves the eviction domain at that first visit,
//! as the membership rule has it. The final visit returns the last extent,
//! the block and the slot once. A return funds the visits the extent allocator, the pop and the
//! arena counted, at most that work. Each pass funds these
//! steps from a per-pass tally of the allowance, which commits them as they
//! are funded and debits them, kind by kind, when the pass ends, by return
//! or by unwind. A pass that cannot fund its next
//! probe stops with its cursor on the position its funded probes reached;
//! one that cannot fund the member it found stops with its cursor on that
//! member, which is left untouched. While a park is counted, the
//! retired pass leaves the park pass's decision unspent, so the two passes
//! are funded separately and neither starves the other. A pass covers at
//! most every slot position once per call; its cursor advances past every
//! position covered, wraps at the end, and survives across calls, so a
//! pending obligation is revisited after finitely many calls that take the
//! gate and fund the member's return work, and one held object never keeps
//! a pass from the members after it. While admission is open, a retired
//! slot that no right or anchor holds and whose position lies outside
//! the durable prefix joins the waiting set at the visit that
//! finds it so, and the retired pass leaves the set's slots unvisited: none
//! can return while that prefix stands and admission is open. A call that
//! loads another prefix or finds admission closed clears the set before its
//! pass, so every retired slot is visited under the value that may return
//! it.
//! [`Storage::service_minimum`], the call controls and each pass's two
//! probes, slot bundle and visit bound ([`Pool::visit_bound`]), funds the
//! decision of the slot at each cursor with one extent's return and a final
//! return's cleanup; a call that cannot afford it is
//! refused before the gate attempt with nothing debited and no cursor
//! moved. Observed actions are at most what was charged and often fewer;
//! nothing is refunded. `ServiceError::BudgetExhausted` makes no progress;
//! `ServiceReport::budget_exhausted` means a pass advanced as far as its
//! funding allowed, never that nothing remains.
//!
//! The work a call does follows the cohort and the configured slot count:
//! the retired set's summary and bitmap words, the parked set's, and the
//! members themselves. A pass reads a slot's record word only behind a set
//! bit: a retired record, a parked obligation, or a stale parked bit, which
//! the park pass clears on first meeting and which each park leaves at most
//! once. At fixed slot capacity the same pending cohort therefore costs the
//! same work however many slots are occupied, plus one visit per stale bit.
//! A pass whose
//! set is empty, the ledger's retired count zero or the pending-mark counter
//! zero under the gate, reads nothing and covers every position, and a call
//! with both empty costs its controls alone. With no park counted, the
//! flagged slots are exactly the retired records: a retirement sets the
//! record's bit and flag in one hold, and the return that clears the flag
//! clears the bit; a park counts itself before it sets a flag and is
//! uncounted only once that flag is cleared or absorbed. A park sets its
//! parked bit after its flag and its summary bit after that, and the bit is
//! cleared only in the hold that absorbs or returns the park, in a park
//! pass that finds it beside a clear flag, which sets it again when a flag
//! landed meanwhile, or in a park pass that finds it beside a retired flag,
//! whose park the retirement absorbed. Every completed park's flag
//! therefore has its parked bit and summary bit set until a hold absorbs or
//! returns it, and the park pass loads a record's word only behind a set parked bit. A park that
//! happened before the call is seen by the counter load and its bits
//! through coherence. One concurrent with the call may not be sighted, as a
//! relaxed flag load may not sight it either, and a later call whose
//! counter load sees it finds it.
//!
//! A retired slot whose anchor still awaits grace is released by service
//! only when the slot's retirement era lies strictly below the certified
//! era; otherwise it is held, counted and revisited, with no waiting or
//! forced progress. The release clears the anchored flag and decrements the
//! count in one compare-exchange on the slot's word under the pool gate,
//! funded entirely by the slot's bundle, so a retry finds no
//! anchor to release and no outcome is ever half applied.
//! The exchange is the release's last access to the slot and reports the
//! count it left; the gate holder that made it is the only actor that can
//! then return or reclaim the slot, which is what licenses its own reads
//! after zero. Certification is a separate budgeted pass,
//! [`Storage::certify`], that visits every registration record ever claimed
//! once per pass, resumes from a cursor kept under the root's own gate, and
//! certifies only on completion; it prepays
//! [`CERTIFY_CONTROLS`] per call and one visit per record, and
//! [`certify_minimum`] funds an empty certification or one record's advance.
//! A pass begins only when its start era exceeds the certificate, since a
//! pass certifies at most its start era.
//! A poisoned maintenance gate found by certification closes admission: the
//! pass cursor under it cannot be trusted and no repair is attempted. A
//! poisoned pool gate found by service is reported and fails finalization;
//! it does not close admission on its own. The
//! `grace` module holds the protocol and its ordering argument.
//!
//! The pending counter is incremented before a flag is set and decremented
//! after a flag is cleared, so it never undercounts flagged, unserviced slots.
//! [`Storage::outstanding`] counts slots still owned or pending, marks still
//! unserviced, credits still reserved and slots whose reference count is
//! nonzero, and registration records still claimed, as a blocking sample;
//! finalization's exclusive inspection checks the same facts exactly and
//! blocks while any remain, so drained is never reported with an obligation
//! open, a lease alive or forgotten, an anchor unreleased or a reader
//! registered.

use std::ops::Range;
use std::sync::atomic::{AtomicU64, Ordering};

use super::allocation::AllocationId;
use super::allocation::{Owned, retire_held};
use super::blocks::BlockArena;
use super::budget::{BudgetExhausted, WorkBudget, WorkKind};
use super::extent::HeldPhase;
use super::gate::GateError;
use super::grace::{self, PassCursor, Sequential};
use super::held::Held;
use super::layout::IO_UNIT;
use super::os::Platform;
use super::owner::{Pool, Storage};
use super::pending::{
    Cohort, Funds, Levels, Parked, Published, Retired, Walked, mark_parked, parked_flag,
    unmark_parked_slot, walk,
};
use super::prefetch::hint;
use super::probe::{self, Event, Primitive};
use super::recovery::{NO_RECORD, epoch_of, reusable};
use super::reserve::{return_extent, return_last};
use super::slot::Record;
use super::tables::{SlotIndex, SlotState, Tables};
use super::word::{self, ABANDONED, ANCHORED, EVICTED, LINKED, RESERVED, RETIRED, STATE};

/// Eligibility to return one allocation, valid for exactly its incarnation
/// and only against the storage that issued it. Obtained only by consuming an
/// owner through [`ExtentReservation::release`](super::ExtentReservation::release) or
/// [`Completed::release`](super::Completed::release). Spent by
/// [`Storage::return_allocation`]; dropped unspent, it parks the obligation
/// for service exactly as dropping the owner would have.
#[must_use = "an unreturned transfer defers its slot to service; pass it to `Storage::return_allocation`"]
pub struct ReturnTransfer<'s, P: Platform> {
    storage: &'s Storage<P>,
    id: AllocationId,
}

impl<P: Platform> Drop for ReturnTransfer<'_, P> {
    fn drop(&mut self) {
        // Only an unspent transfer reaches here: `return_allocation` forgets
        // the one it consumes. The slot came from an issued identity, so it is
        // in range; a drained storage has nothing left to record.
        if let Some(pool) = self.storage.live_pool()
            && self.id.slot().0 < pool.records().len()
        {
            park(pool, self.id.slot().0, self.id.incarnation());
        }
    }
}

impl<P: Platform> std::fmt::Debug for ReturnTransfer<'_, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReturnTransfer")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl<'s, P: Platform> ReturnTransfer<'s, P> {
    pub(super) fn new(storage: &'s Storage<P>, id: AllocationId) -> Self {
        Self { storage, id }
    }

    pub fn id(&self) -> AllocationId {
        self.id
    }
}

/// What happened to a return.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReturnOutcome {
    /// Extent and slot are free again.
    Returned,
    /// Retirement keeps the slot's units owned until service finishes their return.
    Retired,
    /// The return obligation waits in pre-reserved state for service to retry.
    PendingContended,
    /// The budget cannot cover the try and the return work of what the
    /// slot holds (`Pool::held_work`); the obligation waits in
    /// pre-reserved state and nothing is debited.
    PendingBudget,
    /// The gate is poisoned; the obligation waits in pre-reserved state.
    PendingPoisoned,
}

/// A failed credit transfer. `ForeignStorage` drops the transfer, parking its
/// obligation on the issuing storage; the other errors preserve the existing
/// state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReturnError {
    /// The transfer was issued by another storage.
    ForeignStorage,
    /// The storage is drained.
    TornDown,
    /// The slot record no longer describes this transfer: the incarnation is
    /// stale, or the slot is free or quarantined.
    Rejected,
}

/// Progress of one service call: a retired pass over the retired set,
/// then a park pass over the parked set, each from its own persistent
/// cursor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ServiceReport {
    /// The retired pass's cursor as the call found it.
    pub first: usize,
    /// Slot positions the retired pass covered from `first`, wrapping at
    /// the table's end: every retired slot among them outside the waiting
    /// set was visited, and the cursor rests `covered` positions on. At
    /// most the slot count; a pass that covered every position visited
    /// each retired slot outside the waiting set once.
    pub covered: usize,
    /// The park pass's cursor as the call found it.
    pub park_first: usize,
    /// Slot positions the park pass covered from `park_first`, as
    /// `covered` counts them.
    pub park_covered: usize,
    /// Summary and bitmap words the passes examined, each one probe funded
    /// before the read. A scan of empty summary words loads them eight at a
    /// time within the funded run and charges the words up to and including
    /// the first marked one.
    pub probes: usize,
    /// Slots the passes visited, each with its whole bundle funded before
    /// the slot was touched.
    pub visited: usize,
    /// Obligations returned whole: each final return frees what the slot
    /// still holds, at most one extent and, for a sequence, its block, and
    /// the slot.
    pub serviced: usize,
    /// Extents returned ahead of their slot's final return, one per visit
    /// at most. Each leaves its slot pending for a later visit, so a call
    /// that returned one has more work.
    pub partial: usize,
    /// Bytes of the full charged extents (header, payload and padding)
    /// the returns gave back to the allocator.
    pub reclaimed_bytes: usize,
    /// Flagged slots left in place because a read right, a fill's write
    /// right or the anchor is still outstanding; they stay flagged for a
    /// later pass.
    pub held: usize,
    /// Stale entries the park pass met and cleared: a parked bit beside a
    /// clear flag or an absorbed park, or a summary bit beside a zero word.
    pub skipped: usize,
    /// Anchors released because the slot's retirement era lies below the
    /// certified era. In the same visit the slot is then serviced, returns
    /// one extent of its sequence (`partial`), or is held on its remaining
    /// rights.
    pub released: usize,
    /// A pass stopped short of covering every position because the
    /// allowance could not fund its next probe or slot; its cursor rests on
    /// the position still to examine.
    pub budget_exhausted: bool,
    /// Whether a parked mark or a retired slot awaited return when the call
    /// took the gate. A call that found neither had no obligation to return,
    /// costs its controls alone and leaves no work behind.
    pub pending: bool,
    /// Parked residents this call's park pass retired while a volume was attached, which a later retired pass returns once no right remains, and retired slots with no right left that `reusable` refused against the loaded prefix, the waiting set's unvisited slots included. The count is zero once the open volume's metadata halts, so a zero count can leave retired slots in place.
    pub awaiting_journal: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Passes {
    pub(super) retired: bool,
    pub(super) parked: bool,
}

impl Passes {
    pub(super) const BOTH: Self = Self {
        retired: true,
        parked: true,
    };
}

/// Fixed steps one [`Storage::service`] call that takes the gate pays before
/// any probe: the gate attempt with its release, the cursors' restore and
/// their save. A refused attempt pays the attempt alone.
pub const SERVICE_CONTROLS: usize = 3;

const SLOT_VISITS: usize = 1;
const SLOT_VALIDATIONS: usize = 3;
const SLOT_UPDATES: usize = 2;

/// Steps one visited slot is funded with: its visit, three eligibility
/// validations, the possible anchor update and the possible return update.
pub const SERVICE_PER_SLOT: usize = SLOT_VISITS + SLOT_VALIDATIONS + SLOT_UPDATES;

const PROBE_READS: usize = 1;
const PROBE_REPAIRS: usize = 1;

/// Steps one retired-set probe is funded with: the read of one summary or
/// bitmap word, which the gate holder alone writes.
pub(crate) const RETIRED_PROBE: usize = PROBE_READS;

/// Steps one parked-set probe is funded with: the read of one summary or
/// bitmap word and the possible repair of a stale summary bit it leads to.
pub(crate) const PARKED_PROBE: usize = PROBE_READS + PROBE_REPAIRS;

/// Steps a visit of a slot holding a sequence adds to a direct extent's
/// return: the pop of its last held extent and, at its final return, the
/// block's [`FREE_STEPS`](BlockArena::FREE_STEPS).
pub(crate) const SEQUENCE_VISIT: usize = 1 + BlockArena::FREE_STEPS;

/// The fixed part of one pass's decision: two probes reach a member in the
/// cursor's bitmap word, then its slot bundle. A pass's minimum adds the
/// largest visit's return work, so it decides the slot at its cursor, a
/// return included.
const fn pass_decision(probe: usize) -> usize {
    2 * probe + SERVICE_PER_SLOT
}

/// The fixed part of [`Storage::service_minimum`]: the call controls plus
/// each pass's decision. The minimum adds one visit bound per pass, so a
/// funded call decides at least the slot at each cursor, one extent's
/// return included, and every funded call advances the cursor of each pass
/// whose set is nonempty; with
/// fewer, a call could take the gate but decide nothing, so identical
/// retries would pay the attempt forever and free nothing.
pub(crate) const SERVICE_MINIMUM: usize =
    SERVICE_CONTROLS + pass_decision(RETIRED_PROBE) + pass_decision(PARKED_PROBE);

/// Fixed steps one [`Storage::certify`] call that takes the gate pays: the
/// gate attempt with its release, the cursor restore with the claimed-bound
/// load that ends the pass's range, the start-era read with the certificate
/// load that decides whether a pass begins, the cursor save and the possible
/// certificate publication. A refused attempt pays the attempt alone.
pub const CERTIFY_CONTROLS: usize = 5;

/// Minimum steps for [`Storage::certify`] over `records` registration
/// records: the controls plus one visit when there is a record to visit, so
/// the minimum funds an empty certification or one record's advance.
pub const fn certify_minimum(records: usize) -> usize {
    CERTIFY_CONTROLS + if records == 0 { 0 } else { 1 }
}

/// Progress of one certification call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[must_use]
pub struct CertifyReport {
    /// Registration records visited, one visit debited each.
    pub visited: usize,
    /// The era certified when this call completed a pass or found the era
    /// already certified and begun none, or `None` when the pass is still
    /// in progress. A completed pass never lowers it.
    pub certified: Option<u64>,
    /// Budget ran out before the pass completed; the cursor rests on the
    /// next record to visit and the pass resumes with the same start era.
    pub budget_exhausted: bool,
}

/// Why service did nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceError {
    /// The storage is drained.
    TornDown,
    /// Fewer steps remained than the call's minimum bundle; nothing was
    /// debited and no cursor moved.
    BudgetExhausted,
    /// The gate was busy, one attempt debited and nothing else changed, or
    /// poisoned; a poisoned maintenance gate under [`Storage::certify`] also
    /// closes admission.
    Gate(GateError),
}

impl From<BudgetExhausted> for ServiceError {
    fn from(_: BudgetExhausted) -> Self {
        Self::BudgetExhausted
    }
}

/// Everything that still blocks `Drained`. Exact under
/// an exclusive borrow; through a shared borrow the credit,
/// reference and mark counts are a sample, since leases and parking change
/// them without the gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Outstanding {
    /// Slots an owner still holds (filling or resident) with no abandonment
    /// mark.
    pub live: usize,
    /// Retired slots and unserviced abandonment marks.
    pub pending: usize,
    /// Lease credits still reserved: leases or fills alive, or forgotten.
    /// A joined publication's row retains one lease credit until fill service
    /// frees the record.
    pub leases: usize,
    /// Slots whose reference count is nonzero or whose word is malformed: a
    /// right or an anchor is still held, or the word fails its check, so the
    /// extent cannot return.
    pub anchored: usize,
    /// Whether the volume's counts cannot be trusted: a poisoned gate, or
    /// more marks than owned slots.
    pub unverifiable: bool,
    /// Registration records still claimed by a handle, alive or leaked.
    pub registrations: usize,
}

impl Outstanding {
    pub fn is_clear(&self) -> bool {
        *self == Self::default()
    }
}

impl<P: Platform> Storage<P> {
    /// Consumes `transfer` and frees its extent and slot, or parks the
    /// obligation for service when the gate cannot be taken now. While a
    /// volume is attached, or while the slot is a capture member, a published
    /// record's slot retires under the pool gate instead, and a retirement
    /// that `retire_held` leaves with the caller under capture contention is
    /// parked as `PendingContended`; service returns the retired slot's
    /// extent once no right remains and, while admission is open, the
    /// suffix block its position names, if any, lies inside the durable
    /// prefix.
    ///
    /// Before the gate the call preflights one coordination attempt and the
    /// return work of what the slot holds (`Pool::held_work`): the
    /// largest extent's work bound for a direct extent, or a sequence's
    /// whole return for a sequence handle. It debits the attempt, and after
    /// a return the visits the allocator and the arena counted.
    ///
    /// # Errors
    ///
    /// `ForeignStorage` if another storage issued it, which parks the
    /// obligation there; `TornDown` if the storage is drained; `Rejected` if
    /// the slot record mismatches the transfer. `TornDown` and `Rejected`
    /// preserve the existing state.
    ///
    /// # Panics
    ///
    /// If the retirement of a capture member panics in its entry copy, on
    /// tables the copy cannot trust, the pool gate and the capture mutex are
    /// both poisoned when the panic leaves. If the extent's return panics on
    /// tables it cannot trust, the pool gate is poisoned when the panic
    /// leaves. Both hold also on a thread that was
    /// already unwinding when the call began.
    ///
    /// If the owner check under the gate finds the slot word malformed. The
    /// pool gate is poisoned when the panic leaves, also on such a thread.
    pub fn return_allocation(
        &self,
        transfer: ReturnTransfer<'_, P>,
        budget: &mut WorkBudget,
    ) -> Result<ReturnOutcome, ReturnError> {
        if !std::ptr::eq(transfer.storage, self) {
            // Dropping it here parks the obligation on the storage that issued
            // it, so a transfer handed to the wrong storage loses nothing.
            return Err(ReturnError::ForeignStorage);
        }
        // From here the transfer is consumed whatever the outcome: a refused
        // one has nothing to park, a parked one is recorded below, a returned
        // one is spent. Its drop must not run.
        let id = transfer.id;
        std::mem::forget(transfer);
        let pool = self.live_pool().ok_or(ReturnError::TornDown)?;
        let slot = id.slot().0;
        if slot >= pool.descriptor().slot_count {
            return Err(ReturnError::Rejected);
        }
        // The record's locator is fixed from the claim to the return, as an
        // owner's `locator` reads it; a transfer that the gate then finds stale
        // has only sized this preflight.
        let work = pool.held_work(pool.records()[slot].locator());
        let access = if budget.preflight(1 + work).is_err() {
            Err(ReturnOutcome::PendingBudget)
        } else {
            budget
                .debit(WorkKind::CoordinationAttempt)
                .expect("the preflight covered the attempt");
            // Warm the records the hold will read so their cache misses are
            // taken before the gate, not while holding it.
            pool.prefetch_slot(slot);
            pool.try_lock().map_err(|error| match error {
                GateError::Contended => ReturnOutcome::PendingContended,
                GateError::Poisoned => ReturnOutcome::PendingPoisoned,
            })
        };
        // Every return below ends the hold through `release`, so its drop is
        // a panic under it: the owner check on a malformed slot word, or the
        // retirement or the extent's return on tables it cannot trust. That
        // drop poisons the gate also in a return made by a thread that was
        // already unwinding.
        let mut access = match access {
            Ok(access) => access.poison_on_unwind(),
            Err(pending) => {
                park(pool, slot, id.incarnation());
                return Ok(pending);
            }
        };
        let (state, incarnation) = pool.gate_state(slot);
        let matches = incarnation == id.incarnation();
        let Some(from) = matches.then(|| owned_from(state)).flatten() else {
            access.release();
            return Err(ReturnError::Rejected);
        };
        let mut tables = access.tables();
        if from == HeldPhase::Resident && (self.volume_attached() || tables.step(slot) != 0) {
            let retired = retire_held(pool, &mut tables, id, Owned::Resident, 0, false, None);
            if !retired {
                park(pool, slot, id.incarnation());
                access.release();
                return Ok(ReturnOutcome::PendingContended);
            }
            access.release();
            return Ok(ReturnOutcome::Retired);
        }
        let (_, visits) = return_extent(&mut tables, pool, slot, from);
        access.release();
        debug_assert!(visits <= work, "a return past its return work");
        // The preflight covered `work`, so the capped debit always succeeds.
        let _ = budget.debit_n(WorkKind::Visit, visits.min(work));
        Ok(ReturnOutcome::Returned)
    }

    /// Steps that fund one [`service`](Self::service) call's controls and
    /// one complete slot decision in each pass, one extent's return
    /// included: the call controls, each pass's two probes and slot bundle,
    /// and the largest visit's return work per pass: the largest extent's
    /// work bound, which covers any direct extent's allocator and
    /// coalescing return, plus, with a sequence arena, a sequence visit's
    /// pop and final block cleanup.
    pub fn service_minimum(&self) -> usize {
        self.pool
            .visit_bound()
            .checked_mul(2)
            .and_then(|bounds| SERVICE_MINIMUM.checked_add(bounds))
            .expect("validation bounds alloc_search_words, and so the work bound, below this sum's overflow")
    }

    /// Services pending obligations: a retired pass over the retired set, then
    /// a park pass over the parked set, each resuming from its own persistent
    /// cursor and covering at most every slot position once.
    /// [`service_minimum`](Self::service_minimum) is preflighted; every probe
    /// of a summary or bitmap word is funded before the read, and every
    /// visited slot's bundle, with its return work covered, before the slot
    /// is touched; each pass debits what it funded when it ends. A pass
    /// stops in front of the first probe or slot the allowance cannot fund,
    /// its cursor resting there. While a park is counted, the retired pass
    /// holds back the park pass's decision and visit bound, so each pass
    /// decides at least the slot at its cursor in every call the minimum
    /// funds. A visit returns at most one extent: a slot holding a sequence
    /// returns its last held extent per visit and keeps its identity,
    /// pending membership and block until the final visit returns the last
    /// extent, the block and the slot. The retired pass runs only while the ledger counts a retired
    /// slot, and the park pass only while the pending-mark counter reads
    /// nonzero under the gate; a call with neither costs its controls alone.
    /// The work follows the pending cohort and the configured slot count.
    ///
    /// # Errors
    ///
    /// `TornDown`; `BudgetExhausted` if fewer than
    /// [`service_minimum`](Self::service_minimum) steps remain (nothing is
    /// debited, no cursor moves); `Gate` if the gate was busy or poisoned
    /// (the attempt alone is debited, no cursor moves). A poisoned volume
    /// stays unverifiable and fails finalization.
    ///
    /// # Panics
    ///
    /// If the waiting set's clear meets a retired summary it cannot trust,
    /// or a pass meets a slot word, a parked record or a capture member's
    /// tables it cannot trust. The pool gate is poisoned when the panic
    /// leaves, also on a thread that was already unwinding when the call
    /// began.
    pub fn service(&self, budget: &mut WorkBudget) -> Result<ServiceReport, ServiceError> {
        self.service_passes(budget, Passes::BOTH)
    }

    /// [`service`](Self::service) restricted to `passes`. An omitted pass
    /// keeps its cursor and reports zero positions covered, and
    /// `budget_exhausted` reflects only the passes that ran. With the park
    /// pass omitted, the retired pass may spend the whole allowance.
    ///
    /// # Errors
    ///
    /// As for [`service`](Self::service).
    pub(super) fn service_passes(
        &self,
        budget: &mut WorkBudget,
        passes: Passes,
    ) -> Result<ServiceReport, ServiceError> {
        let live = self.live_pool().ok_or(ServiceError::TornDown)?;
        budget.preflight(self.service_minimum())?;
        budget.debit(WorkKind::CoordinationAttempt)?;
        // The idle return and the passes' end release the hold, so its drop is
        // a panic under it: the waiting set's clear or a pass on tables it
        // cannot trust. That drop poisons the gate also in a call made by a
        // thread that was already unwinding.
        let mut access = try_gate(live)?.poison_on_unwind();
        // The preflight covered these two; a busy gate paid the attempt only.
        budget
            .debit_n(WorkKind::Update, SERVICE_CONTROLS - 1)
            .expect("the preflight covered the call controls");
        // A zero `pending_marks` value lets the parked set be skipped: with
        // no park counted, every flagged slot is retired.
        let parked = live.telemetry().pending_marks.load(Ordering::Relaxed);
        let count = live.records().len();
        // The idle decision reads the pool state; the view of every table
        // is built once the call has pending work to walk.
        let (retired, first, park_first) = {
            let state = &*access.tables().state;
            (state.ledger.retired, state.cursor_slot, state.cursor_park)
        };
        let unwalked = |selected: bool| if selected { count } else { 0 };
        if parked == 0 && retired == 0 {
            access.release();
            return Ok(ServiceReport {
                first,
                covered: unwalked(passes.retired),
                park_first,
                park_covered: unwalked(passes.parked),
                ..ServiceReport::default()
            });
        }
        let mut tables = access.tables();
        // Acquire pairs with the tick's release store, so every suffix
        // block the value counts was persisted before any return this
        // call makes on it.
        let prefix = live.journal_words().prefix.load(Ordering::Acquire);
        let closed = self.is_closed();
        // A waiting mark holds while the durable prefix it was made under
        // stands and admission is open. Under another prefix or a close a
        // marked slot may return, so the marks go and the pass visits every
        // retired slot again.
        if closed || tables.state.waiting_under != prefix {
            tables.clear_waiting(prefix);
        }
        let waiting = tables.state.waiting;
        let mut report = ServiceReport {
            first,
            park_first,
            pending: true,
            ..ServiceReport::default()
        };
        // Each pass funds from a tally of the budget and debits what it
        // funded when the pass ends, by return or by unwind, so a panic under
        // the gate keeps every funded debit.
        let bound = self.pool.image.extent_bound;
        let mut walk = Walk {
            tables: &mut tables,
            pool: live,
            // A call that walks reads the certificate once. It only grows,
            // and every release below is judged against this value: a pass
            // raised later on another thread is seen by the next call, which
            // holds a slot one call longer and never releases one early.
            // Acquire pairs with the completing pass's publication, so every
            // pin that pass judged was loaded before any release this call
            // makes.
            certified: self.eras().certified.load(Ordering::Acquire),
            bound,
            released: 0,
            attached: self.volume_attached(),
            prefix,
            closed,
            awaiting: 0,
        };
        let held_back = if passes.parked && parked != 0 {
            pass_decision(PARKED_PROBE) + live.visit_bound()
        } else {
            0
        };
        let (cursor, covered) = if passes.retired && retired != 0 {
            walk.retired_pass(first, budget, held_back, &mut report)
        } else {
            (first, unwalked(passes.retired))
        };
        let (park_cursor, park_covered) = if passes.parked && parked != 0 {
            walk.park_pass(park_first, budget, &mut report)
        } else {
            (park_first, unwalked(passes.parked))
        };
        // Pending marks released by this call come off the counter in one
        // step at the end, still under the gate, so the call pays one
        // atomic instead of one per slot; until then the counter runs ahead
        // of the flags, the direction it may. A panic under the gate
        // poisons the volume, and nothing reads a poisoned volume's counter.
        let released = walk.released;
        // The slots the waiting set marked before the pass wait as the ones
        // the pass met do.
        report.awaiting_journal = if live.journal_words().halted.load(Ordering::Relaxed) {
            0
        } else {
            waiting + walk.awaiting
        };
        tables.state.cursor_slot = cursor;
        tables.state.cursor_park = park_cursor;
        report.covered = covered;
        report.park_covered = park_covered;
        report.budget_exhausted =
            (passes.retired && covered < count) || (passes.parked && park_covered < count);
        if released != 0 {
            live.telemetry()
                .pending_marks
                .fetch_sub(released, Ordering::Relaxed);
        }
        // Release the gate before the report goes back to the caller: the
        // report lives on the caller's side of the gate, and every store
        // still queued ahead of the release store delays it.
        access.release();
        Ok(report)
    }

    /// Runs or resumes the engine-wide grace certification pass over every
    /// registration record ever claimed: the records below the claimed
    /// bound, loaded afresh by each call. The call preflights
    /// [`certify_minimum`], debits
    /// the gate attempt, and on taking the gate debits the other four
    /// controls; then it prepays one visit per record until the pass
    /// completes or the allowance cannot fund the next visit. The pass loads
    /// its start era before its first visit, resumes from its cursor with
    /// that era across calls, and certifies only when the last record below
    /// the bound is visited; the certified era never decreases. One pass runs at a time:
    /// the cursor moves only under the maintenance gate, which the root
    /// mapping owns. When no pass is in progress and the era loaded as the start is
    /// already certified, no pass could raise the certificate, so none is
    /// begun: the call visits nothing and reports the current certificate.
    ///
    /// # Errors
    ///
    /// `TornDown` if the storage is drained; `BudgetExhausted` if the
    /// minimum bundle cannot be paid (nothing is debited, no record is
    /// visited, the cursor is untouched); `Gate` if the maintenance gate was
    /// busy (the attempt alone is debited, no cursor moves) or poisoned (the
    /// attempt is debited and admission is closed).
    pub fn certify(&self, budget: &mut WorkBudget) -> Result<CertifyReport, ServiceError> {
        if !self.is_live() {
            return Err(ServiceError::TornDown);
        }
        let records = self.registrations();
        budget.preflight(certify_minimum(records.len()))?;
        budget.debit(WorkKind::CoordinationAttempt)?;
        // Every return below releases the hold, so the guard's drop is a
        // panic of the pass, also in a call made by a thread that was
        // already unwinding.
        let access = try_maintenance_gate(self.maintenance_gate())
            .map(super::gate::GateGuard::poison_on_unwind)
            .inspect_err(|error| {
                // A poisoned maintenance gate closes admission: the pass cursor
                // under it may be half-written and no repair is attempted, so
                // nothing new is admitted against a certificate that can no
                // longer advance.
                if *error == ServiceError::Gate(GateError::Poisoned) {
                    self.close();
                }
            })?;
        // The preflight covered these four; a busy gate paid the attempt only.
        budget
            .debit_n(WorkKind::Update, CERTIFY_CONTROLS - 1)
            .expect("the preflight covered the call controls");
        let eras = self.eras();
        let holder = self.grace_cursor();
        let mut cursor = holder.load();
        if !cursor.in_progress() {
            cursor = PassCursor::begin::<_, Sequential>(&eras.era);
            probe::note(Primitive::Load);
            // A pass certifies at most its start era, so it begins only when
            // that era exceeds the certificate. The gate
            // holder is the certificate's only writer, and the gate's acquire
            // ordered the last publication before this load.
            let current = eras.certified.load(Ordering::Relaxed);
            if cursor.start_era <= current {
                access.release();
                return Ok(CertifyReport {
                    visited: 0,
                    certified: Some(current),
                    budget_exhausted: false,
                });
            }
            probe::event(Event::CertifyStart {
                era: cursor.start_era,
            });
        }
        let mut report = CertifyReport::default();
        // The visits this call funds are prepaid at once: every record left
        // in the pass, or as many as the allowance covers. The pass then
        // walks that many records with the cursor in locals, so a visit
        // waits on nothing but its own load; an exhausted allowance leaves
        // the cursor on the first unfunded record.
        // The pass covers the records below the claimed bound; a record at
        // or above it has held no pin the pass must count (the `grace`
        // module states why). The bound only grows, so a resumed pass may
        // find it higher and visits the records it gained; `SeqCst` places
        // this load after the start era's in the total order.
        let claimed = eras.claimed_bound.load(Ordering::SeqCst);
        let left = &records[cursor.next..claimed];
        let visits = left.len().min(budget.remaining());
        budget
            .debit_n(WorkKind::Visit, visits)
            .expect("the visits were bounded by the allowance");
        for record in &left[..visits] {
            let index = cursor.next;
            let pin = cursor.visit::<_, Sequential>(&record.pin);
            probe::note(Primitive::Load);
            probe::event(Event::CertifyVisit { index, pin });
        }
        report.visited = visits;
        report.budget_exhausted = visits < left.len();
        if cursor.next == claimed {
            let bound = cursor.bound();
            let certified = cursor.complete::<_, Sequential>(claimed, &eras.certified);
            probe::note(Primitive::Rmw);
            probe::event(Event::CertifyPublish { bound, certified });
            report.certified = Some(certified);
            cursor = PassCursor::IDLE;
        }
        holder.store(cursor);
        access.release();
        Ok(report)
    }

    /// Slots still owned or pending, marks still unserviced, credits still
    /// reserved, slots with a nonzero reference count and registration
    /// records still claimed. Waits for the gate like
    /// [`pool_report`](Self::pool_report), so a permanently held gate blocks
    /// the caller; finalization's inspection never waits, since `&mut self`
    /// excludes every holder and a gate word left held is reported instead.
    pub fn outstanding(&self) -> Outstanding {
        let mut total = Outstanding::default();
        if !self.is_live() {
            return total;
        }
        total.leases = self.credits_in_use();
        total.registrations = self.claimed_registrations();
        let pool = &self.pool;
        let Some(mut access) = pool.lock() else {
            total.unverifiable = true;
            return total;
        };
        let state = *access.tables().state;
        // A mark belongs to a slot still counted as filling until service
        // moves it, so it is pending, not live; more marks than owned
        // slots means the counters disagree.
        let marks = pool.telemetry().pending_marks.load(Ordering::Acquire);
        access.release();
        // Reference counts change without the gate, so the hold neither
        // orders nor fixes them; the scan runs after the release so the
        // hold stays one record copy long instead of one pass over the
        // slot table, during which every allocator try would fail.
        total.anchored = anchored_slots(pool.records());
        match (state.ledger.filling + state.ledger.resident).checked_sub(marks) {
            Some(live) => {
                total.live = live;
                total.pending = state.ledger.retired + marks;
            }
            None => total.unverifiable = true,
        }
        total
    }
}

/// One nonblocking attempt at the maintenance gate, its outcome noted for
/// the observer.
fn try_maintenance_gate(
    gate: &super::gate::Gate,
) -> Result<super::gate::GateGuard<'_>, ServiceError> {
    let attempt = gate.try_lock();
    probe::note(match &attempt {
        Ok(_) => Primitive::GateTaken,
        Err(GateError::Contended) => Primitive::GateBusy,
        Err(GateError::Poisoned) => Primitive::GatePoisoned,
    });
    attempt.map_err(ServiceError::Gate)
}

/// One nonblocking attempt at the volume's gate for a maintenance call, its
/// outcome noted for the observer.
fn try_gate(pool: &Pool) -> Result<super::tables::PoolAccess<'_>, ServiceError> {
    let attempt = pool.try_lock();
    probe::note(match &attempt {
        Ok(_) => Primitive::GateTaken,
        Err(GateError::Contended) => Primitive::GateBusy,
        Err(GateError::Poisoned) => Primitive::GatePoisoned,
    });
    attempt.map_err(ServiceError::Gate)
}

/// The set one service pass walks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pass {
    /// The retired set, from `cursor_slot`.
    Retired,
    /// The parked set, from `cursor_park`.
    Parked,
}

impl Pass {
    /// The repair updates one probe of this pass's set funds beside its
    /// read.
    const fn probe_repairs(self) -> usize {
        match self {
            Self::Retired => 0,
            Self::Parked => PROBE_REPAIRS,
        }
    }
}

/// One service call's walk under the pool gate: the tables, the
/// certificate and the extent work bound the call's passes share, and the
/// pending-mark releases they accumulate.
struct Walk<'w, 't> {
    tables: &'w mut Tables<'t>,
    pool: &'w Pool,
    /// The certificate the call loaded with acquire.
    certified: u64,
    /// The largest extent's work bound, which every visit covers
    /// before it touches its slot.
    bound: usize,
    /// Pending-mark entries the call's returns released.
    released: usize,
    /// Whether a volume is attached, so a parked resident retires under the gate.
    attached: bool,
    /// The durable prefix the call loaded with acquire.
    prefix: u64,
    /// Whether the call observed admission closed under the gate.
    closed: bool,
    /// The call's count for [`ServiceReport::awaiting_journal`].
    awaiting: usize,
}

/// One pass's funding and what the pass did. `room` is the allowance the
/// pass may still commit: the call's remaining steps past those held back
/// for a later pass, less every probe, slot bundle and return the pass
/// funded. Funding commits steps before the work they pay for; the
/// committed steps are debited from the call's allowance, kind by kind,
/// when the tally is dropped at the pass's end, by return or by unwind, so
/// the counters equal the work funded and a panic under the gate keeps
/// every funded debit. The pass's [`PassCohort`] keeps `room` and `probes`
/// in its own locals and writes them back before each [`Walk::visit`], the
/// call that fails closed on a malformed word, and at the pass's end.
struct Tally<'b> {
    budget: &'b mut WorkBudget,
    /// The room the pass began with.
    initial: usize,
    room: usize,
    /// Repair updates one probe of the pass's set funds beside its read.
    repairs: usize,
    probes: usize,
    /// Visits the extent allocator counted for the pass's returns.
    return_visits: usize,
    serviced: usize,
    /// Extents returned ahead of their slot's final return.
    partial: usize,
    reclaimed_bytes: usize,
    /// Visited slots whose parked bit was stale.
    stale: usize,
    /// Stale summary bits the pass's walks repaired.
    repaired: usize,
    /// Anchors the pass released.
    anchors: usize,
}

impl<'b> Tally<'b> {
    fn new(budget: &'b mut WorkBudget, held_back: usize, pass: Pass) -> Self {
        let room = budget.remaining().saturating_sub(held_back);
        Self {
            initial: room,
            room,
            budget,
            repairs: pass.probe_repairs(),
            probes: 0,
            return_visits: 0,
            serviced: 0,
            partial: 0,
            reclaimed_bytes: 0,
            stale: 0,
            repaired: 0,
            anchors: 0,
        }
    }

    /// Slots the pass visited: every step of room it committed beyond its
    /// probes and its returns' visits is one slot bundle.
    #[inline(always)]
    fn slots(&self) -> usize {
        let committed = self.initial - self.room;
        (committed - self.probes * (PROBE_READS + self.repairs) - self.return_visits)
            / SERVICE_PER_SLOT
    }

    /// Commits the `visits` a return counted, which the slot's funding
    /// covered up to `work`, the slot's return work.
    #[inline(always)]
    fn fund_return(&mut self, visits: usize, work: usize) {
        debug_assert!(visits <= work, "a return past its return work");
        let visits = visits.min(work);
        self.room -= visits;
        self.return_visits += visits;
    }

    /// Adds what the pass did to `report`, counting every visited slot that
    /// was neither stale nor returned, whole or in part, as held; dropping
    /// the tally then debits what it funded.
    fn finish(self, report: &mut ServiceReport) {
        let slots = self.slots();
        report.probes += self.probes;
        report.visited += slots;
        report.serviced += self.serviced;
        report.partial += self.partial;
        report.reclaimed_bytes += self.reclaimed_bytes;
        report.held += slots - self.serviced - self.partial - self.stale;
        report.skipped += self.stale + self.repaired;
        report.released += self.anchors;
    }
}

impl Drop for Tally<'_> {
    #[inline(always)]
    fn drop(&mut self) {
        let slots = self.slots();
        let budget = &mut *self.budget;
        let paid = budget
            .debit_n(
                WorkKind::Visit,
                self.probes * PROBE_READS + slots * SLOT_VISITS + self.return_visits,
            )
            .and_then(|()| budget.debit_n(WorkKind::Comparison, slots * SLOT_VALIDATIONS))
            .and_then(|()| {
                budget.debit_n(
                    WorkKind::Update,
                    self.probes * self.repairs + slots * SLOT_UPDATES,
                )
            });
        debug_assert!(paid.is_ok(), "a pass debited past the room it funded");
        probe::note_n(Primitive::Load, self.probes);
    }
}

impl Walk<'_, '_> {
    /// A parked resident requires retirement while a volume is attached or its step word is nonzero.
    #[inline(always)]
    fn records_retirement(&mut self, pass: Pass, sighted: u64, slot: usize) -> bool {
        match pass {
            Pass::Parked => {
                word::state(sighted) == SlotState::Resident
                    && (self.attached || self.tables.step(slot) != 0)
            }
            Pass::Retired => false,
        }
    }

    /// The return work a visit of `slot` in `pass` covers before it touches
    /// the slot: the walk's `bound`, which covers any one extent's return,
    /// plus [`SEQUENCE_VISIT`] for a sequence the pass returns, whose final
    /// visit also frees the block. The retired pass returns a retired slot and the park
    /// pass a filling or resident one; a slot in any other state meets the
    /// pass through a stale parked bit, which [`live_park`] clears on the
    /// slot bundle alone, and a free slot's record keeps the handle it
    /// returned until the next claim. The caller holds the pool gate, under
    /// which the state is fixed. The word is classified from its raw bits:
    /// a malformed word takes `bound` and fails closed in [`visit`](Self::visit),
    /// after the pass wrote its funded probes back.
    #[inline(always)]
    fn work(&self, pass: Pass, slot: usize) -> usize {
        let word = self.pool.records()[slot].ident.load(Ordering::Relaxed);
        let returns = word::well_formed(word)
            && match word & STATE {
                bits if bits == SlotState::Retired.bits() => pass == Pass::Retired,
                bits if bits == SlotState::Filling.bits() || bits == SlotState::Resident.bits() => {
                    pass == Pass::Parked
                }
                _ => false,
            };
        if !returns {
            return self.bound;
        }
        match Held::decode(self.tables.held_locator(slot)) {
            Some(Held::Sequence { .. }) => self.bound + SEQUENCE_VISIT,
            _ => self.bound,
        }
    }

    /// The retired pass: [`pass`](Self::pass) over the retired set, compiled
    /// on its own so the set is a constant in its loop.
    #[inline(never)]
    fn retired_pass(
        &mut self,
        first: usize,
        budget: &mut WorkBudget,
        held_back: usize,
        report: &mut ServiceReport,
    ) -> (usize, usize) {
        self.pass(Pass::Retired, first, budget, held_back, report)
    }

    /// The park pass: [`pass`](Self::pass) over the parked set, compiled on
    /// its own so the set is a constant in its loop.
    #[inline(never)]
    fn park_pass(
        &mut self,
        first: usize,
        budget: &mut WorkBudget,
        report: &mut ServiceReport,
    ) -> (usize, usize) {
        self.pass(Pass::Parked, first, budget, 0, report)
    }

    /// Walks `pass`'s set from `first` over at most every slot position
    /// once, wrapping at the table's end, spends from `budget` at most what
    /// exceeds `held_back` steps, and adds what it did to `report`. Returns
    /// the cursor to save and the positions covered. Each stretch from the
    /// cursor to the table's end, or from slot 0 back to where the pass
    /// began, is one [`walk`]. Every probe is funded before its read; a
    /// member found is visited only once its bundle and its return work
    /// ([`work`](Self::work)) are funded, and otherwise the walk stops in
    /// front of it with the slot untouched.
    #[inline(always)]
    fn pass(
        &mut self,
        pass: Pass,
        first: usize,
        budget: &mut WorkBudget,
        held_back: usize,
        report: &mut ServiceReport,
    ) -> (usize, usize) {
        let mut tally = Tally::new(budget, held_back, pass);
        let records = self.pool.records();
        let count = records.len();
        let mut cohort = PassCohort {
            room: tally.room,
            probes: tally.probes,
            cost: PROBE_READS + tally.repairs,
            walk: self,
            tally: &mut tally,
            records,
            pass,
        };
        let (mut at, mut covered) = (first, 0);
        while covered < count {
            let end = count.min(at + (count - covered));
            let (reached, stopped) = match walk(&mut cohort, at, end) {
                Walked::Clear => (end, false),
                Walked::Short(reached) | Walked::Refused(reached) => (reached, true),
            };
            covered += reached - at;
            at = reached;
            // The cursor wraps before a stop is saved, so a stop at the
            // table's end rests on slot 0.
            if at == count {
                at = 0;
            }
            if stopped {
                break;
            }
        }
        (cohort.tally.room, cohort.tally.probes) = (cohort.room, cohort.probes);
        tally.finish(report);
        (at, covered)
    }

    /// Decides one member `slot` of `records`, sighted as `sighted`, whose
    /// bundle and return work ([`work`](Self::work)) the caller funded and which
    /// [`held_in_place`] did not accept: a stale parked bit is cleared and
    /// skipped; otherwise the slot's anchor is released when grace allows.
    /// When no right or anchor remains and `reusable` admits the slot's
    /// position, the visit returns the last held extent of a sequence that
    /// holds two or more and leaves the slot pending, or else returns the
    /// slot with what it still holds. While admission is open, a slot that
    /// no right or anchor holds and whose position lies outside the durable
    /// prefix stays retired and is counted as awaiting its suffix block; in
    /// the retired pass it also joins the waiting set. Every other slot is
    /// held and counted. `ahead` is the next member in the slot's bitmap
    /// word, whose record is hinted for the store while a return runs.
    ///
    /// `sighted` is the caller's acquire load of the word. In the park pass,
    /// when that load shows a clear flag and [`live_park`] finds a park that
    /// landed meanwhile, the fresh acquire load `live_park` makes replaces
    /// it. That one word decides the whole visit: the flags, the count and
    /// the incarnation beside them. The flags change only under this gate,
    /// and the acquire pairs with the
    /// release read-modify-write of the retirement or park that set them, so
    /// the stamp read below is the value the retirement wrote. A zero count
    /// read there is final, since no retain lands on zero, and every release
    /// decrement before it heads a release sequence the load reads from, so
    /// the return orders every lease's reads before it. A park landing after
    /// the load finds its flag already set and leaves the word as the load
    /// read it.
    #[inline(never)]
    fn visit(
        &mut self,
        pass: Pass,
        slot: usize,
        records: &[Record],
        sighted: u64,
        ahead: Option<usize>,
        tally: &mut Tally<'_>,
    ) {
        let pool = self.pool;
        let mut sighted = sighted;
        // The state validation, before any bit of the word decides the
        // visit: the park pass clears a stale bit on the flags alone and the
        // retired pass releases an anchor on the flags and the count, so a
        // word whose state is malformed must fail closed here.
        word::state(sighted);
        if pass == Pass::Parked {
            let Some(live) = live_park(self.tables.parked_slots, records, slot, sighted) else {
                tally.stale += 1;
                return;
            };
            sighted = word::checked(live);
            if sighted & ANCHORED != 0 && word::refs(sighted) == 0 {
                panic!("a slot's anchored flag without its counted anchor");
            }
            if self.records_retirement(Pass::Parked, sighted, slot) {
                let id = AllocationId::new(SlotIndex(slot), word::incarnation(sighted));
                // A counted park stored its epoch before the exchange this word's acquire load read; only a retirement's park carries `ANCHORED`.
                let counted = if sighted & ANCHORED != 0 {
                    epoch_of(self.tables.journal().position(slot))
                } else {
                    None
                };
                let retired =
                    retire_held(pool, self.tables, id, Owned::Resident, 0, false, counted);
                if retired && self.attached {
                    self.awaiting += 1;
                }
                return;
            }
            if sighted & ANCHORED != 0 {
                self.tables.journal().end_parked(slot);
            }
        } else {
            debug_assert_eq!(
                pool.gate_state(slot).0,
                SlotState::Retired,
                "a retired bit on a slot whose state is not retired"
            );
        }
        // The flag validation.
        probe::note(Primitive::Load);
        let sighted = word::checked(sighted);
        // The anchored validation. The flag names a counted anchor, so a
        // zero count beside it is corruption; returning the extent on it
        // would free the extent before grace, and failing closed poisons the
        // gate instead.
        let released_to = if sighted & ANCHORED != 0 {
            if word::refs(sighted) == 0 {
                panic!("a slot's anchored flag without its counted anchor");
            }
            release_anchor(pool, slot, sighted, self.certified)
        } else {
            None
        };
        let released = released_to.is_some();
        tally.anchors += usize::from(released);
        // The count validation: the count the anchor's own compare-exchange
        // left, acquired by that exchange, or the one the sighting read. A
        // flag always describes the incarnation beside it, so a nonzero
        // count holds the owned record. Only a park of a record's current
        // incarnation, which an owner or a transfer holds, sets a flag, so a
        // flag on a free or quarantined record is corruption, and failing
        // closed poisons the gate.
        probe::note(Primitive::Load);
        let refs = released_to.unwrap_or(word::refs(sighted));
        let Some(from) = owned_from(word::state(sighted)) else {
            panic!("a slot's flag on a free or quarantined record");
        };
        // A retired slot's position is `NO_RECORD` or the suffix position its
        // retirement waits for, so its extents return once no right remains
        // and that position is durable; a parked slot waits on no block.
        let position = if pass == Pass::Retired {
            self.tables.journal().position(slot)
        } else {
            NO_RECORD
        };
        if reusable(refs as u64, position, self.prefix, self.closed) {
            let work = self.work(pass, slot);
            // The next member in this bitmap word is likely returned too,
            // so its record is requested for the store while this return
            // runs.
            if let Some(next) = ahead {
                hint(records.as_ptr().wrapping_add(next).cast());
            }
            if let Some(Held::Sequence { block, count }) =
                Held::decode(self.tables.held_locator(slot))
                && let Some(extent) = return_last(self.tables, pool, slot, (block, count), from)
            {
                // One extent per visit; the slot stays pending for the
                // next. A resident still linked leaves the eviction domain
                // at this first sighting of its parked retirement, as the
                // membership rule has it; the final return uncounts it.
                if word::state(sighted) == SlotState::Resident
                    && sighted & LINKED != 0
                    && self.tables.queue().detach(slot)
                {
                    probe::event(Event::Detached { slot });
                }
                tally.reclaimed_bytes += extent.units as usize * IO_UNIT;
                tally.fund_return(extent.visits, work);
                tally.partial += 1;
                probe::event(Event::ExtentReturn {
                    slot,
                    incarnation: word::incarnation(sighted),
                    extent: extent.index,
                    phase: from,
                });
                return;
            }
            self.tables.journal().release(slot);
            let (entries, units, visits) = service_slot(self.tables, pool, slot, sighted, from);
            self.released += entries;
            tally.reclaimed_bytes += units as usize * IO_UNIT;
            tally.fund_return(visits, work);
            tally.serviced += 1;
            return;
        }
        // A slot with no right left whose position the durable prefix does
        // not cover keeps its eviction in flight until a later call; in the
        // retired pass it joins the waiting set, since only another prefix
        // or a close can return it.
        if refs == 0 {
            self.awaiting += 1;
            if pass == Pass::Retired {
                self.tables.mark_waiting(slot);
            }
            return;
        }
        // A retired sighting whose anchor stays counted has nothing left to
        // observe: `abandon`'s hold already detached it, and the retired bit
        // changes only under this gate, so the flag decides without the slot
        // record. Once the anchor is gone, released here or by an earlier
        // visit that left the evicted bit, rights alone hold the extent as
        // soon as its journal block does not: only then is the evicted bit
        // cleared. Until then the eviction stays in flight, so the slot is
        // still counted when its last right goes and it waits for its block.
        let anchor_gone = released || sighted & (ANCHORED | EVICTED) == EVICTED;
        if sighted & RETIRED == 0 || anchor_gone {
            let rights_alone = anchor_gone && reusable(0, position, self.prefix, self.closed);
            observe_held(self.tables, sighted, slot, rights_alone);
        }
    }
}

/// One pass's [`Cohort`]: the walk under the gate, the pass's set and
/// tally, and the room and probe count in locals, which the tally takes
/// back before each [`Walk::visit`] and when the pass ends. A member
/// is visited once its slot bundle and its return work ([`Walk::work`])
/// are funded; a member [`held_in_place`] accepts costs its bundle alone,
/// and every other goes to [`Walk::visit`].
struct PassCohort<'c, 'w, 't, 'b> {
    walk: &'c mut Walk<'w, 't>,
    tally: &'c mut Tally<'b>,
    records: &'c [Record],
    pass: Pass,
    /// Steps one probe of the pass's set costs.
    cost: usize,
    room: usize,
    probes: usize,
}

impl Levels for PassCohort<'_, '_, '_, '_> {
    #[inline(always)]
    fn summary(&mut self, group: usize) -> u64 {
        let tables = &*self.walk.tables;
        match self.pass {
            Pass::Retired => tables.retired_summary[group],
            Pass::Parked => tables.parked_summary[group].load(Ordering::Relaxed),
        }
    }

    #[inline(always)]
    fn word(&mut self, word: usize) -> u64 {
        let tables = &*self.walk.tables;
        match self.pass {
            // The waiting set's slots stay unvisited; a word they fill reads
            // as empty beside its summary bit.
            Pass::Retired => tables.retired[word] & !tables.waiting[word],
            Pass::Parked => {
                let mut levels =
                    Parked::<_, Published>::new(tables.parked_slots, tables.parked_summary);
                let bits = levels.word(word);
                self.tally.repaired += levels.repaired;
                bits
            }
        }
    }

    #[inline(always)]
    fn first_marked(&mut self, groups: Range<usize>) -> Option<(usize, u64)> {
        let tables = &*self.walk.tables;
        match self.pass {
            Pass::Retired => Retired {
                bits: tables.retired,
                summary: tables.retired_summary,
            }
            .first_marked(groups),
            Pass::Parked => Parked::<_, Published>::new(tables.parked_slots, tables.parked_summary)
                .first_marked(groups),
        }
    }
}

impl Funds for PassCohort<'_, '_, '_, '_> {
    #[inline(always)]
    fn affordable(&self) -> usize {
        self.room / self.cost
    }

    #[inline(always)]
    fn spend(&mut self, probes: usize) {
        self.room -= probes * self.cost;
        self.probes += probes;
    }

    #[inline(always)]
    fn fund(&mut self) -> bool {
        if self.room < self.cost {
            return false;
        }
        self.room -= self.cost;
        self.probes += 1;
        true
    }
}

impl Cohort for PassCohort<'_, '_, '_, '_> {
    #[inline(always)]
    fn member(&mut self, slot: usize, next: Option<usize>) -> bool {
        if self.room < SERVICE_PER_SLOT + self.walk.work(self.pass, slot) {
            return false;
        }
        self.room -= SERVICE_PER_SLOT;
        // One acquire load of the word for the whole decision; `visit`
        // states what it orders.
        let sighted = self.records[slot].ident.load(Ordering::Acquire);
        if held_in_place(self.pass, sighted, slot)
            && !self.walk.records_retirement(self.pass, sighted, slot)
        {
            return true;
        }
        (self.tally.room, self.tally.probes) = (self.room, self.probes);
        self.walk
            .visit(self.pass, slot, self.records, sighted, next, self.tally);
        self.room = self.tally.room;
        true
    }
}

/// Whether `sighted`, the word of `slot` in `pass`'s set, shows a member a
/// right holds with no anchor counted and no list link to detach, so the
/// pass holds it on its funded bundle alone. The retired pass accepts a
/// retired record flagged `ABANDONED | RETIRED`, which `abandon`'s hold
/// already took off its list, unless it is still marked `EVICTED`, which
/// [`Walk::visit`] clears once the slot's journal block is durable; the park
/// pass accepts a
/// live park of a filling record, or of a resident record off its list,
/// which it reports as sighted. The masks check the reserved bits, flags
/// and state that [`Walk::visit`] validates; every other word, a malformed
/// one included, takes that full decision.
#[inline(always)]
fn held_in_place(pass: Pass, sighted: u64, slot: usize) -> bool {
    const CHECKED: u64 = RESERVED | ANCHORED | RETIRED | ABANDONED | STATE;
    if word::refs(sighted) == 0 {
        return false;
    }
    let held = match pass {
        Pass::Retired => {
            sighted & (CHECKED | EVICTED) == ABANDONED | RETIRED | SlotState::Retired.bits()
        }
        Pass::Parked => {
            let state = sighted & CHECKED;
            if state == ABANDONED | SlotState::Resident.bits() && sighted & LINKED == 0 {
                probe::event(Event::Sighted { slot });
                true
            } else {
                state == ABANDONED | SlotState::Filling.bits()
            }
        }
    };
    if held {
        // The flag and count validations.
        probe::note_n(Primitive::Load, 2);
    }
    held
}

/// The word of `slot`, whose parked bit the caller read set, when it holds a
/// park no retirement absorbed, which the park pass decides, or `None` for
/// a stale bit, which it clears. `sighted` is the slot's word the caller
/// loaded with acquire under the pool gate; a malformed one panics before
/// any bit of it decides the park. A bit beside a clear flag is
/// decided by `parked_flag`, and a park that landed meanwhile is decided
/// from a fresh acquire load. A retirement that absorbed the slot's park
/// cleared its bit and took its counter entry; a bit set after that clear
/// is stale, no later park of the retired incarnation sets one, and the
/// retired pass owns the slot, so the holder clears the bit.
#[inline(always)]
fn live_park(parked: &[AtomicU64], records: &[Record], slot: usize, sighted: u64) -> Option<u64> {
    let sighted = word::checked(sighted);
    let sighted = if sighted & ABANDONED != 0 {
        sighted
    } else if parked_flag::<_, _, Published>(parked, &records[slot].ident, slot) {
        word::checked(records[slot].ident.load(Ordering::Acquire))
    } else {
        return None;
    };
    if sighted & RETIRED != 0 {
        unmark_parked_slot(parked, slot);
        return None;
    }
    Some(sighted)
}

/// Slots of `records` whose count is nonzero or whose word is malformed.
/// Relaxed loads: nothing is read on the strength of a zero here, so no
/// acquire pairing is needed; under the exclusive borrow finalization
/// holds, every release decrement already happened before the borrow, so
/// each load returns the final count, and through a shared borrow the
/// count is a sample either way. Eight independent lanes keep the loads in
/// flight instead of chaining them through one counter.
fn anchored_slots(records: &[Record]) -> usize {
    const LANES: usize = 8;
    let held = |record: &Record| usize::from(word::held(record.ident.load(Ordering::Relaxed)));
    let (chunks, tail) = records.as_chunks::<LANES>();
    let lanes = chunks.iter().fold([0usize; LANES], |mut lanes, chunk| {
        for (lane, word) in lanes.iter_mut().zip(chunk) {
            *lane += held(word);
        }
        lanes
    });
    lanes.iter().sum::<usize>() + tail.iter().map(held).sum::<usize>()
}

/// Releases `slot`'s anchor if its retirement era lies below the certified
/// era, and returns the count the release left, or `None` when the anchor
/// is not yet releasable. `sighted` is the word the caller loaded with
/// acquire under the gate: that load pairs with the retirement's release
/// read-modify-write that set [`ANCHORED`] after storing the stamp, so the
/// relaxed stamp load here reads the value the retirement wrote.
/// `certified` is the certificate the caller loaded with acquire for this
/// pass, so every pin the completing pass judged was loaded before this
/// release.
///
/// The release is one compare-exchange that clears `ANCHORED` and takes
/// the anchor out of the count together, so the bit never names an anchor
/// already gone and never outlives it, and no concurrent write of the word
/// is overwritten. The exchange is retried against the value it found: the
/// writers without the gate are lease releases, whose number the rights
/// outstanding bound, and parks of this incarnation, which find their bits
/// set and write nothing; no retain lands once the certificate lies above
/// the stamp, since every interval that could have copied the identity has
/// ended. The exchange is acquire-release: release orders the anchor's
/// lifetime before the return that observes zero, and acquire, when it
/// leaves zero, consumes every lease's reads through the release sequences
/// their decrements head, so the caller needs no second load of the count.
///
/// `slot` is an index into the pool's word slice, so it is below `O`.
#[inline(always)]
fn release_anchor(pool: &Pool, slot: usize, sighted: u64, certified: u64) -> Option<usize> {
    // The eligibility validation: the stamp against the certificate. The
    // retirement stored it over the record's fingerprint once the mapping
    // had ended.
    probe::note(Primitive::Load);
    let retire_era = pool.records()[slot].retire_era();
    if !grace::releasable(retire_era, certified) {
        return None;
    }
    // Consuming the authority and decrementing the count are one transition
    // under the gate, funded entirely by the slot's bundle. This
    // function's exchange is its last access to the slot; the caller, still
    // holding the gate that alone can return or reclaim the slot, judges the
    // count it returns.
    debug_assert_ne!(sighted & ABANDONED, 0, "an anchor without its mark");
    probe::note(Primitive::Rmw);
    let slot_word = &pool.records()[slot].ident;
    let mut current = sighted;
    loop {
        // Only this gate's holder clears the flag, and the anchor it names
        // is counted, so any other value is corruption; failing closed
        // poisons the gate.
        if current & ANCHORED == 0 || word::refs(current) == 0 {
            panic!("a slot's anchored flag without its counted anchor");
        }
        match slot_word.compare_exchange(
            current,
            word::unanchored(current),
            Ordering::AcqRel,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(seen) => current = word::checked(seen),
        }
    }
    let previous = word::refs(current);
    probe::event(Event::AnchorRelease { slot, previous });
    Some(previous - 1)
}

/// The observer rule at service's held branch: `slot`'s flag describes its
/// current incarnation, sighted as `sighted`, and a right or the anchor
/// still holds it. A resident record there is a retirement parked without
/// the gate, so this hold is the first that can observe it and a
/// still-linked member leaves its domain; a retired record already left in
/// `abandon`'s hold. The policy bits change only under this gate, so the
/// sighting's link bit decides whether the record is still linked. With
/// `rights_alone`, the anchor is gone and the slot's journal position would
/// let it return, so only rights hold the extent: an evicted slot is no
/// longer in flight, and its `EVICTED` bit and units are cleared here,
/// once.
#[inline(always)]
fn observe_held(tables: &mut Tables<'_>, sighted: u64, slot: usize, rights_alone: bool) {
    let resident = match word::state(sighted) {
        SlotState::Resident => true,
        SlotState::Retired if rights_alone => false,
        _ => return,
    };
    if resident {
        probe::event(Event::Sighted { slot });
        if sighted & LINKED != 0 && tables.queue().detach(slot) {
            probe::event(Event::Detached { slot });
        }
    }
    if rights_alone {
        let units = tables.held_units(slot);
        tables.queue().release_evicted(slot, units);
    }
}

/// Which owned state a record is in, or `None` for a free or quarantined slot
/// that no transfer may credit.
fn owned_from(state: SlotState) -> Option<HeldPhase> {
    match state {
        SlotState::Filling => Some(HeldPhase::Reserved),
        SlotState::Resident => Some(HeldPhase::Resident),
        SlotState::Retired => Some(HeldPhase::Retired),
        SlotState::Free | SlotState::Quarantined => None,
    }
}

/// Records the obligation in pre-reserved state: the pending counter, then
/// [`ABANDONED`] in the slot's word, then the slot's parked bit and its
/// summary bit, so the
/// counter is never behind a flag a service can clear and a service that
/// reads the bit with acquire also reads the flag. The flag is set by a
/// compare-exchange that holds only while the word's low half equals
/// `incarnation`, so a park issued for an earlier incarnation changes no
/// word and sets no parked bit, and a flag always describes the
/// incarnation beside it. The exchange's release publishes every write
/// the parking thread made before it, such as a retirement's stamp, to the
/// service whose acquire sighting reads the flag. A park that finds the
/// flag already set, or changes nothing, gives its counter entry back, so
/// exactly one entry stands for each flagged slot however many parks land
/// on it. A park that finds a reserved bit set is one that changes
/// nothing: the slot is never serviced, and drain counts it held. The
/// exchange retries against the value it found until the flag is set or
/// the word refuses the park, so the obligation is always recorded. Each
/// failed exchange is another thread's completed write, so the attempts
/// are at most one more than the writes that interfere, and those are
/// finite: once the object is unmapped no new copy of its identity exists,
/// so retains come only from readers already holding a copy; a volume read's
/// record holds a right a lease or a lookup retained, so read rights come
/// from the finite retains just counted, each released once; a fill's write right
/// lives on the fill's own slot, `Filling` or, once its owner's end
/// abandoned it under the gate, `Retired`, and that end runs on the
/// volume's thread, since the owner is not `Send`, and is the slot's only
/// park, so the park and the right's install and release run in sequence;
/// the rights outstanding are at most `C + 1`, which bounds their releases; and the visited clears and every other write under the gate
/// end with the holds that make them. The bound rests on rights reaching
/// the word only through copies of the identity and a fill's own writes; a
/// new source of rights must recheck it.
///
/// Returns false when the park found a reserved bit set, or a word whose
/// low half names another incarnation: neither carries this incarnation's
/// flag, so nothing will service the slot for it, and a caller that holds a
/// record standing for the slot keeps it occupied, and finalization blocks
/// on the record as well as the slot rather than a record freeing over a
/// charged slot. A caller whose park may legitimately name an earlier
/// incarnation ignores the result.
#[inline]
pub(crate) fn park(pool: &Pool, slot: usize, incarnation: u32) -> bool {
    park_marked(pool, slot, incarnation, 0)
}

/// [`park`] with `marks`, further flag bits the same read-modify-write sets,
/// as for `abandon`, and the same result.
#[inline]
pub(crate) fn park_marked(pool: &Pool, slot: usize, incarnation: u32, marks: u64) -> bool {
    probe::event(Event::Parked { slot });
    let telemetry = pool.telemetry();
    telemetry.pending_marks.fetch_add(1, Ordering::Relaxed);
    let slot_word = &pool.records()[slot].ident;
    let mut current = slot_word.load(Ordering::Relaxed);
    let (flagged, recorded) = loop {
        let Some(next) = word::parked(current, incarnation, marks) else {
            break (
                false,
                word::well_formed(current) && current as u32 == incarnation,
            );
        };
        match slot_word.compare_exchange(current, next, Ordering::AcqRel, Ordering::Relaxed) {
            Ok(_) => break (current & ABANDONED == 0, true),
            Err(seen) => current = seen,
        }
    };
    if flagged {
        // After the flag, so a gate holder that reads this bit with acquire
        // also reads the flag. Only the park that set the flag sets the bit,
        // so one bit stands for the one counter entry kept. The summary bit
        // follows the slot's bit, as the `pending` module requires.
        mark_parked::<_, Published>(pool.parked_slots(), pool.parked_summary(), slot);
    } else {
        telemetry.pending_marks.fetch_sub(1, Ordering::Relaxed);
    }
    recorded
}

/// Discharges one flagged slot, owned in phase `from`, as a deferred
/// return, and returns how many pending-mark entries to release and the
/// units returned and the visits the return counted. The caller found the
/// word's count zero. A retired record is its own proof: only its owner's
/// drop under the gate retires it and sets the retired bit; its obligation
/// moved into the ledger when it retired, so no counter entry goes with it.
/// Any other owned record carries a park of its current incarnation, since
/// a flag always describes the incarnation beside it, and releases that
/// park's entry. The return's one read-modify-write clears every flag. The
/// caller funded the return work of what the slot holds, which bounds the
/// visits.
#[inline(always)]
fn service_slot(
    tables: &mut Tables<'_>,
    pool: &Pool,
    slot: usize,
    sighted: u64,
    from: HeldPhase,
) -> (usize, u32, usize) {
    let parked = sighted & RETIRED == 0;
    debug_assert!(parked || from == HeldPhase::Retired);
    // The return's one read-modify-write of the word.
    probe::note(Primitive::Rmw);
    let (units, visits) = return_extent(tables, pool, slot, from);
    probe::event(Event::Return { slot });
    (usize::from(parked), units, visits)
}

#[cfg(test)]
mod tests {
    //! Recorded exemptions: the tests here exercise owners without an anchor
    //! except the hold test below, so most reports show `released: 0`; pinned
    //! readers and grace certification are witnessed in `grace_tests` and
    //! `retire_tests`. An I/O owner withholds the return through its right in
    //! the slot's count, which the device fill and hit tests witness.

    use std::sync::atomic::Ordering;

    use super::super::budget::{WorkBudget, WorkCounters};
    use super::super::config::StorageConfig;
    use super::super::extent::RawPartition;
    use super::super::finalize::{Finalization, FinalizeError};
    use super::super::gate::GateError;
    use super::super::layout::IO_UNIT;
    use super::super::ledger::SlotPartition;
    use super::super::owner::Storage;
    use super::super::placement::PlacementConfig;
    use super::super::reserve::take_return_visits;
    use super::super::tables::{SlotIndex, SlotState};
    use super::super::test_platform::{Op, TestPlatform};
    use super::super::test_platform::{blocked, finalize};
    use super::super::word::{ABANDONED, ANCHORED};
    use super::{
        Outstanding, PARKED_PROBE, ReturnError, ReturnOutcome, ReturnTransfer, SERVICE_CONTROLS,
        ServiceError, ServiceReport,
    };

    const PAGE: usize = 4096;
    const SLOTS: usize = 4;

    /// One unit per slot plus the one-unit clean reserve.
    fn storage(slot_count: usize) -> Storage<TestPlatform> {
        storage_with(slot_count + 1, slot_count)
    }

    fn storage_with(units: usize, slot_count: usize) -> Storage<TestPlatform> {
        let config = StorageConfig {
            page_size: PAGE,
            engine_budget: 1 << 24,
            body_cap: 200,
            metadata_cap: Some(16),
            lease_limit: 1024,
            object_rights: 64,
            reader_limit: 4,
            volume: crate::storage::test_volume(units * IO_UNIT, slot_count),
        };
        let placement = PlacementConfig { control_home: 0 };
        Storage::initialize(
            &config.validate().unwrap(),
            &placement,
            TestPlatform::heap(PAGE),
        )
        .unwrap()
    }

    fn budget() -> WorkBudget {
        WorkBudget::new(1 << 8)
    }

    /// Enough for one whole service pass over the pool: the call controls
    /// and one funded bundle per slot.
    fn maintenance() -> WorkBudget {
        WorkBudget::new(1 << 10)
    }

    fn partition(storage: &Storage<TestPlatform>) -> (RawPartition, SlotPartition) {
        let ledger = storage.pool_report().unwrap().ledger.unwrap();
        (ledger.raw, ledger.slots)
    }

    /// The extent work bound a return of one `medium` extent preflights.
    fn return_bound(storage: &Storage<TestPlatform>) -> usize {
        storage.pool_report().unwrap().extent_bound
    }

    fn medium<'s>(
        storage: &'s Storage<TestPlatform>,
    ) -> super::super::ExtentReservation<'s, TestPlatform> {
        storage.reserve(Some(8), Some(100), &mut budget()).unwrap()
    }

    #[test]
    fn return_frees_exactly_once_and_stale_or_foreign_transfers_earn_nothing() {
        let storage = storage(SLOTS);
        let before = partition(&storage);

        let mut first = medium(&storage);
        first.mark_written();
        let address = first.locator();
        let id = first.id();
        let transfer = first.release();
        assert_eq!(transfer.id(), id);
        assert_eq!(partition(&storage).0.reserved, 108);
        let mut spent = budget();
        assert_eq!(
            storage.return_allocation(transfer, &mut spent),
            Ok(ReturnOutcome::Returned)
        );
        assert_eq!(spent.counters().coordination_attempts, 1);
        assert_eq!(partition(&storage), before);
        assert!(!storage.identity_is_current(id));
        assert_eq!(storage.slot_state(SlotIndex(0)), Some((SlotState::Free, 1)));

        // A duplicate of the consumed transfer, forged in-crate, is rejected.
        let duplicate = ReturnTransfer::new(&storage, id);
        assert_eq!(
            storage.return_allocation(duplicate, &mut budget()),
            Err(ReturnError::Rejected)
        );
        assert_eq!(partition(&storage), before);
        {
            let live = storage.live_pool().unwrap();
            assert_eq!(live.flags(0), 0);
            assert_eq!(live.telemetry().pending_marks.load(Ordering::Acquire), 0);
        }
        assert!(storage.outstanding().is_clear());

        // The second same-size reservation reuses the extent at the same
        // address with a newer incarnation; the stale transfer against it
        // changes nothing. The claim cursor moved past slot 0, so it is
        // pointed back at it.
        storage.live_pool().unwrap().claim_next(0);
        let second = medium(&storage);
        assert_eq!(second.locator(), address);
        assert_eq!(second.id().slot_index(), 0);
        let stale = ReturnTransfer::new(&storage, id);
        assert_eq!(
            storage.return_allocation(stale, &mut budget()),
            Err(ReturnError::Rejected)
        );
        assert!(storage.identity_is_current(second.id()));
        assert_eq!(partition(&storage).0.reserved, 108);
        // A transfer issued by another storage earns nothing here, even with
        // an identical configuration and identity.
        let other = self::storage(SLOTS);
        let elsewhere = medium(&other);
        // Same pool, slot and location as `second`; only the incarnation
        // history differs, and identity alone must not be trusted.
        assert_eq!(elsewhere.id().slot_index(), second.id().slot_index());
        assert_eq!(
            storage.return_allocation(elsewhere.release(), &mut budget()),
            Err(ReturnError::ForeignStorage)
        );
        assert_eq!(partition(&storage).0.reserved, 108);
        assert!(storage.identity_is_current(second.id()));
        // The issuing storage retains the obligation after a foreign return.
        assert_eq!(
            other.outstanding(),
            Outstanding {
                live: 0,
                pending: 1,
                unverifiable: false,
                ..Outstanding::default()
            }
        );
        assert_eq!(other.service(&mut maintenance()).unwrap().serviced, 1);
        assert!(other.outstanding().is_clear());

        // A transfer against a quarantined slot earns nothing.
        {
            let live = storage.live_pool().unwrap();
            let _held = live.lock().unwrap();
            live.set_incarnation(1, u32::MAX);
        }
        let quarantining = storage.reserve(Some(8), Some(100), &mut budget()).unwrap();
        assert_eq!(
            storage.slot_state(SlotIndex(1)),
            Some((SlotState::Quarantined, u32::MAX))
        );
        let against_quarantine = ReturnTransfer::new(
            &storage,
            super::super::allocation::AllocationId::new(SlotIndex(1), u32::MAX),
        );
        assert_eq!(
            storage.return_allocation(against_quarantine, &mut budget()),
            Err(ReturnError::Rejected)
        );
        drop(quarantining);

        // Return after close is ordinary return and never reduces E_used.
        let used = storage.engine_used();
        storage.close();
        assert_eq!(
            storage.return_allocation(second.release(), &mut budget()),
            Ok(ReturnOutcome::Returned)
        );
        assert_eq!(storage.engine_used(), used);
        assert_eq!(partition(&storage).0.reserved, 0);
    }

    /// A transfer that is dropped instead of returned ends its owner the same
    /// way `ExtentReservation::drop` does: the obligation waits in pre-reserved state,
    /// service discharges it, and `Drained` is refused until then.
    #[test]
    fn dropped_transfer_parks_its_obligation_for_service() {
        let mut storage = storage(SLOTS);
        let before = partition(&storage);
        let owner = medium(&storage);
        let id = owner.id();
        let held = partition(&storage);
        drop(owner.release());
        assert_eq!(partition(&storage), held);
        assert!(storage.identity_is_current(id));
        {
            let live = storage.live_pool().unwrap();
            assert_eq!(live.flags(0), ABANDONED);
            assert_eq!(live.telemetry().pending_marks.load(Ordering::Acquire), 1);
        }
        assert_eq!(
            storage.outstanding(),
            Outstanding {
                live: 0,
                pending: 1,
                unverifiable: false,
                ..Outstanding::default()
            }
        );
        assert!(!blocked(&mut storage).is_clear());
        let report = storage.service(&mut maintenance()).unwrap();
        assert_eq!(report.serviced, 1);
        assert_eq!(partition(&storage), before);
        assert!(!storage.identity_is_current(id));
        {
            let live = storage.live_pool().unwrap();
            assert_eq!(live.flags(0), 0);
            assert_eq!(live.telemetry().pending_marks.load(Ordering::Acquire), 0);
        }
        assert!(storage.outstanding().is_clear());
        assert_eq!(finalize(&mut storage), Ok(Finalization::Drained));
    }

    /// Stands in for the layer that promotes a filled object, joining its
    /// policy domain as `bind` does.
    fn promote_to_resident(storage: &Storage<TestPlatform>, slot: usize) {
        let live = storage.live_pool().unwrap();
        let mut access = live.lock().unwrap();
        let mut tables = access.tables();
        assert_eq!(live.gate_state(slot).0, SlotState::Filling);
        live.set_state(slot, SlotState::Resident);
        tables.queue().link(slot);
        let payload = live.held_charge(&mut tables, slot).0;
        tables.publish_payload(payload);
        tables.state.ledger.filling -= 1;
        tables.state.ledger.resident += 1;
    }

    #[test]
    fn resident_slots_return_directly_and_through_service() {
        let mut storage = storage(SLOTS);
        let before = partition(&storage);

        let direct = medium(&storage);
        promote_to_resident(&storage, direct.id().slot_index());
        let (payload, slots) = partition(&storage);
        assert_eq!((payload.reserved, payload.resident), (0, 108));
        assert_eq!((slots.filling, slots.resident), (0, 1));
        assert_eq!(
            storage.outstanding(),
            Outstanding {
                live: 1,
                ..Outstanding::default()
            }
        );
        assert_eq!(
            storage.return_allocation(direct.release(), &mut budget()),
            Ok(ReturnOutcome::Returned)
        );
        assert_eq!(partition(&storage), before);

        // Retire is a `Filling` transition, so a dropped resident owner
        // parks its obligation even with the gate free.
        let parked = medium(&storage);
        let slot = parked.id().slot_index();
        promote_to_resident(&storage, slot);
        drop(parked);
        {
            let live = storage.live_pool().unwrap();
            assert_eq!(live.flags(slot), ABANDONED);
            assert_eq!(live.telemetry().pending_marks.load(Ordering::Acquire), 1);
        }
        assert_eq!(
            storage.outstanding(),
            Outstanding {
                live: 0,
                pending: 1,
                unverifiable: false,
                ..Outstanding::default()
            }
        );
        assert_eq!(storage.service(&mut maintenance()).unwrap().serviced, 1);
        assert_eq!(partition(&storage), before);
        assert!(storage.outstanding().is_clear());
        assert_eq!(finalize(&mut storage), Ok(Finalization::Drained));
    }

    /// Stopping maintenance and occupying every record preserves every
    /// obligation: marks, flags and the ledger stay put until service runs.
    #[test]
    fn occupying_every_record_preserves_parked_obligations() {
        // A spare unit beyond the reserve, so slots run out before units.
        let storage = storage_with(SLOTS + 2, SLOTS);
        let live = storage.live_pool().unwrap();
        let parked_a = medium(&storage);
        let parked_b = medium(&storage);
        {
            let held = live.lock().unwrap();
            assert_eq!(
                storage.return_allocation(parked_a.release(), &mut budget()),
                Ok(ReturnOutcome::PendingContended)
            );
            drop(parked_b);
            drop(held);
        }
        // Fill the remaining two slots; the fifth request fails on slots,
        // not by stealing a parked one.
        let c = medium(&storage);
        let d = medium(&storage);
        assert_eq!(
            storage.reserve(Some(8), Some(100), &mut budget()).err(),
            Some(super::super::ReserveError::ObjectSlotsFull)
        );
        assert_eq!(live.telemetry().pending_marks.load(Ordering::Acquire), 2);
        assert_eq!(live.flags(0), ABANDONED);
        assert_eq!(live.flags(1), ABANDONED);
        let (payload, slots) = partition(&storage);
        assert_eq!(payload.reserved, 4 * 108);
        assert_eq!(slots.free, 0);
        assert_eq!(
            storage.outstanding(),
            Outstanding {
                live: 2,
                pending: 2,
                unverifiable: false,
                ..Outstanding::default()
            }
        );
        let report = storage.service(&mut maintenance()).unwrap();
        assert_eq!(report.serviced, 2);
        assert_eq!(partition(&storage).1.free, 2);
        drop((c, d));
    }

    #[test]
    fn saturation_then_return_admits_again_including_the_empty_object() {
        // Sixteen units for objects and one for the clean reserve.
        let storage = storage_with(17, 32);
        let mut owners: Vec<_> = (0..16).map(|_| medium(&storage)).collect();
        assert_eq!(
            storage.reserve(Some(8), Some(100), &mut budget()).err(),
            Some(super::super::ReserveError::CleanReserve)
        );
        let victim = owners.swap_remove(5);
        let address = victim.locator();
        assert_eq!(
            storage.return_allocation(victim.release(), &mut budget()),
            Ok(ReturnOutcome::Returned)
        );
        let again = medium(&storage);
        assert_eq!(again.locator(), address);
        owners.push(again);
        let freed = owners.pop().unwrap();
        assert_eq!(
            storage.return_allocation(freed.release(), &mut budget()),
            Ok(ReturnOutcome::Returned)
        );

        let empty = storage.reserve(Some(0), Some(0), &mut budget()).unwrap();
        let empty_address = empty.locator();
        assert_eq!(
            storage.return_allocation(empty.release(), &mut budget()),
            Ok(ReturnOutcome::Returned)
        );
        let empty = storage.reserve(Some(0), Some(0), &mut budget()).unwrap();
        assert_eq!(empty.locator(), empty_address);
        assert_eq!(partition(&storage).0.reserved, 15 * 108);
    }

    /// A return preflights one attempt and its extent's work bound before
    /// the gate: one step short parks the obligation with nothing debited,
    /// and a funded return debits the attempt and exactly the visits the
    /// extent allocator counted.
    #[test]
    fn a_return_preflights_its_work_bound_and_debits_the_counted_visits() {
        let storage = storage(SLOTS);
        let live = storage.live_pool().unwrap();
        let first = medium(&storage);
        let second = medium(&storage);
        let bound = return_bound(&storage);
        let before = partition(&storage);
        let mut short = WorkBudget::new(bound);
        assert_eq!(
            storage.return_allocation(first.release(), &mut short),
            Ok(ReturnOutcome::PendingBudget)
        );
        assert_eq!(short.counters(), WorkCounters::default());
        assert_eq!(live.flags(0), ABANDONED);
        assert_eq!(partition(&storage), before);
        take_return_visits();
        let mut funded = WorkBudget::new(1 + bound);
        assert_eq!(
            storage.return_allocation(second.release(), &mut funded),
            Ok(ReturnOutcome::Returned)
        );
        let counted = take_return_visits();
        assert!(counted > 0 && counted <= bound);
        assert_eq!(
            funded.counters(),
            WorkCounters {
                coordination_attempts: 1,
                visits: counted,
                ..WorkCounters::default()
            }
        );
        assert_eq!(storage.service(&mut maintenance()).unwrap().serviced, 1);
        assert!(storage.outstanding().is_clear());
    }

    /// The pool report counts the runs a full run index left out: four
    /// slots index one run, the reserve's unit at the volume's end, so the
    /// two returned runs separated from it are dropped, and they stay free.
    #[test]
    fn the_pool_report_counts_the_run_index_drops() {
        let storage = storage(SLOTS);
        let owners: Vec<_> = (0..SLOTS).map(|_| medium(&storage)).collect();
        let drops = || storage.pool_report().unwrap().ledger.unwrap().index_drops;
        assert_eq!(drops(), 0);
        let mut owners = owners.into_iter();
        let (a, b, c) = (
            owners.next().unwrap(),
            owners.next().unwrap(),
            owners.next().unwrap(),
        );
        for owner in [a, c] {
            assert_eq!(
                storage.return_allocation(owner.release(), &mut budget()),
                Ok(ReturnOutcome::Returned)
            );
        }
        assert_eq!(drops(), 2);
        assert_eq!(partition(&storage).0.free, 3 * IO_UNIT);
        drop((b, owners));
    }

    #[test]
    fn busy_or_unbudgeted_return_parks_the_obligation_and_service_completes_it() {
        let storage = storage(SLOTS);
        let first = medium(&storage);
        let second = medium(&storage);
        let live = storage.live_pool().unwrap();
        let before = partition(&storage);

        let held = live.lock().unwrap();
        assert_eq!(
            storage.return_allocation(first.release(), &mut budget()),
            Ok(ReturnOutcome::PendingContended)
        );
        assert_eq!(live.flags(0), ABANDONED);
        assert_eq!(live.telemetry().pending_marks.load(Ordering::Acquire), 1);
        // Zero budget: no try at all, the failed-try counter does not move.
        let tries = live.telemetry().failed_tries.load(Ordering::Relaxed);
        assert_eq!(
            storage.return_allocation(second.release(), &mut WorkBudget::new(0)),
            Ok(ReturnOutcome::PendingBudget)
        );
        assert_eq!(live.telemetry().failed_tries.load(Ordering::Relaxed), tries);
        assert_eq!(live.telemetry().pending_marks.load(Ordering::Acquire), 2);
        // Service against the held gate refuses without moving the cursor,
        // and the failed try is counted.
        assert_eq!(
            storage.service(&mut maintenance()),
            Err(ServiceError::Gate(GateError::Contended))
        );
        assert_eq!(
            live.telemetry().failed_tries.load(Ordering::Relaxed),
            tries + 1
        );
        drop(held);
        assert_eq!(partition(&storage), before);

        let mut spent = maintenance();
        take_return_visits();
        let report = storage.service(&mut spent).unwrap();
        // No retired slot, so the retired pass reads nothing. The park pass
        // probes summary word 0 and bitmap word 0 once and decides slots 0
        // and 1 from the word it read. The summary bit their returns leave
        // beside the cleared word stays for a later park pass to repair.
        assert_eq!(
            report,
            ServiceReport {
                first: 0,
                covered: SLOTS,
                park_first: 0,
                park_covered: SLOTS,
                probes: 2,
                visited: 2,
                serviced: 2,
                partial: 0,
                reclaimed_bytes: 2 * IO_UNIT,
                held: 0,
                skipped: 0,
                released: 0,
                budget_exhausted: false,
                pending: true,
                awaiting_journal: 0,
            }
        );
        // The probes, the slot visits and the visits the two returns counted.
        assert_eq!(spent.counters().visits, 2 + 2 + take_return_visits());
        assert_eq!(spent.counters().comparisons, 3 * 2);
        assert_eq!(
            spent.counters().updates,
            SERVICE_CONTROLS - 1 + 2 * (PARKED_PROBE - 1) + 2 * 2
        );
        assert_eq!(spent.counters().coordination_attempts, 1);
        let (payload, slots) = partition(&storage);
        assert_eq!(payload.reserved, 0);
        assert_eq!(slots.free, SLOTS);
        assert_eq!(live.telemetry().pending_marks.load(Ordering::Acquire), 0);
        assert_eq!(live.flags(0), 0);
        assert!(storage.outstanding().is_clear());
    }

    #[test]
    fn drained_needs_every_owner_returned_and_every_mark_serviced() {
        let platform = TestPlatform::heap(PAGE);
        let log = platform.log();
        let config = StorageConfig {
            page_size: PAGE,
            engine_budget: 1 << 24,
            body_cap: 200,
            metadata_cap: Some(16),
            lease_limit: 1024,
            object_rights: 64,
            reader_limit: 4,
            volume: crate::storage::test_volume((SLOTS + 1) * IO_UNIT, SLOTS),
        };
        let placement = PlacementConfig { control_home: 0 };
        let mut storage =
            Storage::initialize(&config.validate().unwrap(), &placement, platform).unwrap();

        let a = medium(&storage);
        let b = medium(&storage);
        let c = medium(&storage);
        assert_eq!(
            storage.outstanding(),
            Outstanding {
                live: 3,
                ..Outstanding::default()
            }
        );
        // Abandon `c` under a held gate: an unserviced mark.
        {
            let live = storage.live_pool().unwrap();
            let held = live.lock().unwrap();
            drop(c);
            drop(held);
        }
        assert_eq!(
            storage.outstanding(),
            Outstanding {
                live: 2,
                pending: 1,
                ..Outstanding::default()
            }
        );
        // While `a` and `b` exist the borrow checker forbids teardown; once
        // they are returned the ledger alone must still refuse for the mark.
        assert_eq!(
            storage.return_allocation(a.release(), &mut budget()),
            Ok(ReturnOutcome::Returned)
        );
        assert_eq!(
            storage.return_allocation(b.release(), &mut budget()),
            Ok(ReturnOutcome::Returned)
        );
        let blockers = blocked(&mut storage);
        assert_eq!(blockers.held_slots, 0, "{blockers:?}");
        assert!(blockers.pending >= 1, "{blockers:?}");
        assert!(log.calls(Op::Unmap).is_empty());
        assert_eq!(storage.service(&mut maintenance()).unwrap().serviced, 1);
        assert!(storage.outstanding().is_clear());
        assert_eq!(finalize(&mut storage), Ok(Finalization::Drained));
        assert_eq!(log.calls(Op::Unmap).len(), 2);
    }

    #[test]
    fn forgotten_owner_and_poisoned_gate_block_drained_and_keep_the_charge() {
        let mut storage = storage(SLOTS);
        let forgotten = medium(&storage);
        std::mem::forget(forgotten);
        let used = storage.engine_used();
        let blockers = blocked(&mut storage);
        assert_eq!(
            (blockers.held_slots, blockers.pending),
            (1, 0),
            "{blockers:?}"
        );
        assert_eq!(storage.engine_used(), used);
        assert_eq!(partition(&storage).0.reserved, 108);

        let mut poisoned = self::storage(SLOTS);
        std::thread::scope(|scope| {
            let handle = scope.spawn(|| {
                let _held = poisoned.live_pool().unwrap().lock().unwrap();
                panic!("poison the gate");
            });
            assert!(handle.join().is_err());
        });
        assert_eq!(finalize(&mut poisoned), Err(FinalizeError::Poisoned));
        assert_eq!(poisoned.pool_report().unwrap().ledger, None);
    }

    /// Small real-synchronization kernels: std threads and the in-mapping
    /// mutex, no substitutions. Pending return versus pool access, and the
    /// finalizer versus the last accessor.
    #[test]
    fn concurrent_returns_and_drops_conserve_the_ledger_and_never_wait() {
        let slot_count = 64;
        let mut storage = storage(slot_count);
        let live = storage.live_pool().unwrap();
        std::thread::scope(|scope| {
            for _ in 0..4u8 {
                let storage = &storage;
                scope.spawn(move || {
                    for round in 0..40 {
                        let Ok(mut allocation) = storage.reserve(Some(1), Some(1), &mut budget())
                        else {
                            continue;
                        };
                        allocation.mark_written();
                        if round % 3 == 0 {
                            drop(allocation);
                        } else {
                            let outcome =
                                storage.return_allocation(allocation.release(), &mut budget());
                            assert!(outcome.is_ok(), "{outcome:?}");
                        }
                    }
                });
            }
        });
        // Returns and drops that lost the gate parked their slots; service
        // them so a slot is free for the next reservation.
        while storage.pool_report().unwrap().ledger.unwrap().slots.free == 0 {
            storage.service(&mut WorkBudget::new(200)).unwrap();
        }
        // A drop while another thread holds the gate must finish without
        // waiting: hold the gate here and join the dropping thread while
        // holding it.
        std::thread::scope(|scope| {
            let allocation = medium(&storage);
            let held = live.lock().unwrap();
            let dropper = scope.spawn(move || drop(allocation));
            dropper.join().unwrap();
            drop(held);
        });
        // Each flagged run also funds its return's extent work bound, so a
        // round funds the whole pass and every pending return.
        let mut rounds = 0;
        while !storage.outstanding().is_clear() {
            storage.service(&mut WorkBudget::new(1 << 14)).unwrap();
            rounds += 1;
            assert!(rounds < 10, "service did not converge");
        }
        let (payload, slots) = partition(&storage);
        assert_eq!(
            payload,
            RawPartition::new(
                crate::storage::TEST_METADATA_UNITS as usize * IO_UNIT,
                (slot_count + 1) * IO_UNIT
            )
        );
        assert_eq!(slots.free, 64);
        // Finalizer versus last accessor: the last owner lives on another
        // thread; teardown can only run once it is gone.
        {
            let shared = &storage;
            std::thread::scope(|scope| {
                let allocation = medium(shared);
                scope.spawn(move || {
                    let transfer = allocation.release();
                    assert_eq!(
                        shared.return_allocation(transfer, &mut budget()),
                        Ok(ReturnOutcome::Returned)
                    );
                });
            });
        }
        assert_eq!(finalize(&mut storage), Ok(Finalization::Drained));
    }

    /// A retirement parked while the gate is held flags the current
    /// incarnation with its anchor, and service holds it while a right is
    /// outstanding: the flags and the counter entry stay, the extent stays
    /// resident, and the lease reads its bytes. Once the right is gone and a
    /// completed pass has certified past the retirement, one visit releases
    /// the anchor, reads the count at zero and services the slot.
    #[test]
    fn service_holds_a_parked_retirement_while_references_remain() {
        let storage = storage(SLOTS);
        let completed = medium(&storage)
            .complete([0x5A; 32], 7, &mut budget())
            .ok()
            .unwrap();
        let (resident, lease) = completed.handoff(&mut budget()).ok().unwrap();
        let slot = resident.id().slot_index();
        let live = storage.live_pool().unwrap();
        let access = live.lock().unwrap();
        // Missing the held gate, the drop parks the current incarnation and
        // flags the anchor as awaiting grace.
        drop(resident);
        drop(access);
        assert_eq!(live.flags(slot), ABANDONED | ANCHORED);
        assert_eq!(live.telemetry().pending_marks.load(Ordering::Acquire), 1);

        let pass = storage.service(&mut WorkBudget::new(64)).unwrap();
        assert_eq!((pass.serviced, pass.held, pass.released), (0, 1, 0));
        assert_eq!(live.flags(slot), ABANDONED | ANCHORED);
        assert_eq!(live.telemetry().pending_marks.load(Ordering::Acquire), 1);
        assert_eq!(partition(&storage).1.resident, 1);

        drop(lease);
        let _ = storage.certify(&mut WorkBudget::new(64)).unwrap();
        let pass = storage.service(&mut WorkBudget::new(64)).unwrap();
        assert_eq!((pass.serviced, pass.held, pass.released), (1, 0, 1));
        assert_eq!(partition(&storage).1.resident, 0);
        assert!(storage.outstanding().is_clear());
    }

    /// A stale transfer's park on a reissued slot changes no bit, so the
    /// resident's own parked retirement that follows it flags the word with
    /// its anchor and one counter entry, and service later releases the
    /// anchor and returns the slot.
    #[test]
    fn a_stale_park_leaves_a_parked_retirement_anchored() {
        let storage = storage(SLOTS);
        let live = storage.live_pool().unwrap();
        // Incarnation 1 of slot 0, returned: its transfers are stale.
        let old = medium(&storage);
        let stale = old.id();
        assert_eq!(
            storage.return_allocation(old.release(), &mut budget()),
            Ok(ReturnOutcome::Returned)
        );
        live.claim_next(stale.slot_index());
        // Incarnation 2 becomes resident, then the stale transfer parks.
        let completed = medium(&storage)
            .complete([0x5A; 32], 7, &mut budget())
            .ok()
            .unwrap();
        let (resident, lease) = completed.handoff(&mut budget()).ok().unwrap();
        let slot = resident.id().slot_index();
        assert_eq!(slot, stale.slot_index());
        let before = live.word(slot);
        assert_eq!(
            storage.return_allocation(
                ReturnTransfer::new(&storage, stale),
                &mut WorkBudget::new(0)
            ),
            Ok(ReturnOutcome::PendingBudget)
        );
        assert_eq!(live.word(slot), before);
        assert_eq!(live.telemetry().pending_marks.load(Ordering::Acquire), 0);

        // The resident's drop misses the held gate and parks its retirement.
        let access = live.lock().unwrap();
        drop(resident);
        drop(access);
        assert_eq!(live.flags(slot), ABANDONED | ANCHORED);
        assert_eq!(live.telemetry().pending_marks.load(Ordering::Acquire), 1);

        drop(lease);
        let _ = storage.certify(&mut WorkBudget::new(64)).unwrap();
        let pass = storage.service(&mut WorkBudget::new(64)).unwrap();
        assert_eq!((pass.serviced, pass.held, pass.released), (1, 0, 1));
        assert_eq!(live.flags(slot), 0);
        assert_eq!(live.telemetry().pending_marks.load(Ordering::Acquire), 0);
        assert!(storage.outstanding().is_clear());
    }

    /// Kernel: stale transfers parked under contention, owners dropping
    /// while service runs. A stale park on a live owner's slot leaves a mark
    /// service must not credit; if the owner then parks its own drop while
    /// service is clearing that stale mark, the drop's obligation must
    /// survive. Every obligation is eventually serviced and nothing leaks:
    /// the pool ends with every slot free and no pending mark.
    #[test]
    fn stale_parks_racing_owner_drops_and_service_lose_no_obligation() {
        const SLOTS: usize = 16;
        // Enough rounds to hit the interleavings natively; Miri runs the
        // threads slowly and checks the accesses, not the odds.
        const ROUNDS: usize = if cfg!(miri) { 12 } else { 300 };
        let storage = storage(SLOTS);
        // Old identities: incarnation 1, returned, so their transfers are
        // stale once the slots are reissued.
        let old: Vec<_> = (0..SLOTS).map(|_| medium(&storage)).collect();
        let stale: Vec<_> = old
            .into_iter()
            .map(|owner| {
                let id = owner.id();
                assert_eq!(
                    storage.return_allocation(owner.release(), &mut budget()),
                    Ok(ReturnOutcome::Returned)
                );
                id
            })
            .collect();
        let live: Vec<_> = (0..SLOTS).map(|_| medium(&storage)).collect();
        std::thread::scope(|scope| {
            let shared = &storage;
            let stale = &stale;
            scope.spawn(move || {
                for _ in 0..ROUNDS {
                    for id in stale {
                        let outcome = shared
                            .return_allocation(ReturnTransfer::new(shared, *id), &mut budget());
                        assert!(
                            matches!(
                                outcome,
                                Err(ReturnError::Rejected)
                                    | Ok(ReturnOutcome::PendingContended)
                                    | Ok(ReturnOutcome::PendingBudget)
                            ),
                            "{outcome:?}"
                        );
                    }
                }
            });
            scope.spawn(move || {
                for _ in 0..ROUNDS {
                    let _ = shared.service(&mut WorkBudget::new(usize::MAX));
                }
            });
            scope.spawn(move || {
                // Owners come and go for the whole run, so their drops keep
                // meeting stale marks and service passes on their slots.
                drop(live);
                for _ in 0..ROUNDS {
                    let owners: Vec<_> = (0..SLOTS)
                        .filter_map(|_| shared.reserve(Some(8), Some(100), &mut budget()).ok())
                        .collect();
                    std::hint::spin_loop();
                    drop(owners);
                }
            });
        });
        let mut rounds = 0;
        loop {
            let report = storage.service(&mut WorkBudget::new(usize::MAX)).unwrap();
            if report.serviced == 0 && storage.outstanding().is_clear() {
                break;
            }
            rounds += 1;
            assert!(
                rounds < 10,
                "service did not converge: {:?}",
                storage.outstanding()
            );
        }
        let (payload, slots) = partition(&storage);
        assert_eq!(payload.reserved + payload.retired, 0);
        assert_eq!(slots.free, SLOTS);
        assert_eq!(storage.pool_report().unwrap().pending_marks, 0);
    }

    /// The park pass's decision from the word it loaded: a flag that
    /// landed after the load is decided from a fresh load, a retired flag
    /// clears the bit of the park the retirement absorbed, and a bit beside
    /// a clear flag is cleared as stale.
    #[test]
    fn a_park_decision_follows_the_word_behind_its_sighting() {
        use std::sync::atomic::AtomicU64;

        use super::super::slot::Record;
        use super::super::word::REF;
        const SLOT: usize = 3;
        let cases = [
            (ABANDONED | REF, REF, Some(ABANDONED | REF), true),
            (
                ABANDONED | super::RETIRED,
                ABANDONED | super::RETIRED,
                None,
                false,
            ),
            (REF, REF, None, false),
        ];
        for (current, sighted, decided, kept) in cases {
            let records: Vec<Record> = (0..64).map(|_| Record::free()).collect();
            records[SLOT].ident.store(current, Ordering::Relaxed);
            let parked = [AtomicU64::new(1 << SLOT)];
            assert_eq!(
                super::live_park(&parked, &records, SLOT, sighted),
                decided,
                "{current:#x}"
            );
            assert_eq!(parked[0].load(Ordering::Relaxed) != 0, kept, "{current:#x}");
        }
    }

    /// The held fast pass accepts exactly the words the full decision holds
    /// with nothing to detach: a well-formed retired record with no anchor
    /// and a right in the retired pass, and in the park pass a live park of
    /// a filling record, or of a resident one off its list, with no anchor
    /// and a right.
    #[test]
    fn the_held_fast_pass_accepts_exactly_the_quiet_held_words() {
        use super::super::word::{LINKED, REF, STATE_SHIFT};
        const FILLING: u64 = 1;
        const RESIDENT: u64 = 2;
        const RETIRED_STATE: u64 = 3;
        let reserved_bit = 1 << 43;
        for state in 0..8u64 {
            for flags in 0..8u64 {
                let flag_bits = [ABANDONED, super::RETIRED, ANCHORED]
                    .iter()
                    .enumerate()
                    .filter(|(bit, _)| flags >> bit & 1 == 1)
                    .fold(0, |bits, (_, flag)| bits | flag);
                for (refs, linked, reserved) in (0..8u64).map(|i| (i & 1, i >> 1 & 1, i >> 2)) {
                    let word = (state << STATE_SHIFT)
                        | flag_bits
                        | (refs * REF)
                        | (linked * LINKED)
                        | (reserved * reserved_bit);
                    let quiet = refs == 1 && reserved == 0 && flag_bits & ANCHORED == 0;
                    let retired =
                        quiet && state == RETIRED_STATE && flag_bits == ABANDONED | super::RETIRED;
                    let parked = quiet
                        && flag_bits == ABANDONED
                        && (state == FILLING || state == RESIDENT && linked == 0);
                    assert_eq!(
                        super::held_in_place(super::Pass::Retired, word, 0),
                        retired,
                        "retired {word:#x}"
                    );
                    assert_eq!(
                        super::held_in_place(super::Pass::Parked, word, 0),
                        parked,
                        "parked {word:#x}"
                    );
                }
            }
        }
    }

    /// A certification call slices the registrations from its pass cursor
    /// under the maintenance gate, so a cursor past the claimed bound panics
    /// there, and the panic poisons the gate (`gate.rs`: "A holder that
    /// panics poisons the gate on release"), on a thread that is not
    /// unwinding and in a call made by a destructor while its thread
    /// unwinds from another panic: the guard, taken during the unwind,
    /// would release open on drop.
    #[test]
    fn a_cursor_past_the_bound_poisons_the_maintenance_gate_even_during_unwinding() {
        struct CertifiesOnDrop<'a>(&'a Storage<TestPlatform>, &'a std::cell::Cell<bool>);
        impl Drop for CertifiesOnDrop<'_> {
            fn drop(&mut self) {
                let storage = self.0;
                let certified = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    storage.certify(&mut WorkBudget::new(64))
                }));
                self.1.set(certified.is_err());
            }
        }
        for unwinding in [false, true] {
            let storage = storage(SLOTS);
            let mut cursor = storage.grace_cursor().load();
            cursor.next = usize::MAX;
            storage.grace_cursor().store(cursor);
            let panicked = std::cell::Cell::new(false);
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let certifier = CertifiesOnDrop(&storage, &panicked);
                if unwinding {
                    panic!("an unrelated panic with a live certifier");
                }
                drop(certifier);
            }));
            assert_eq!(outcome.is_err(), unwinding, "premise");
            assert!(
                panicked.get(),
                "premise: the call panicked, unwinding={unwinding}"
            );
            assert_eq!(
                storage.maintenance_gate().try_lock().err(),
                Some(GateError::Poisoned),
                "the call's panic poisons the gate, unwinding={unwinding}"
            );
        }
    }

    /// A pass that unwinds under the gate still debits every step it
    /// funded: the tally's drop runs on unwind and charges its probes, slot
    /// bundles and return visits by kind, exactly as a pass that ends does.
    #[test]
    fn a_tally_debits_what_it_funded_when_the_pass_unwinds() {
        let mut caller = WorkBudget::new(1_000);
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut tally = super::Tally::new(&mut caller, 100, super::Pass::Parked);
            // Two parked probes, one slot bundle and its return's three visits.
            (tally.room, tally.probes) = (tally.room - 2 * PARKED_PROBE, 2);
            tally.room -= super::SERVICE_PER_SLOT;
            tally.fund_return(3, 10);
            panic!("a pass unwinds under the gate");
        }));
        assert!(unwound.is_err());
        let spent = 2 * PARKED_PROBE + super::SERVICE_PER_SLOT + 3;
        assert_eq!(caller.remaining(), 1_000 - spent);
        let counters = caller.counters();
        assert_eq!(
            (counters.visits, counters.comparisons, counters.updates),
            (2 + 1 + 3, 3, 2 + 2)
        );
    }

    /// The anchored count is exact across the eight-lane body and the tail
    /// for a table whose length is not a lane multiple, with expected values
    /// computed independently of the lane layout; flags and incarnations
    /// count nothing, and a malformed word counts as held.
    #[test]
    fn anchored_slots_counts_every_nonzero_count_across_lanes_and_tail() {
        use super::super::slot::Record;
        use super::super::word::{REF, RETIRED, VISITED};
        for len in [0, 1, 7, 8, 9, 16, 19, 64] {
            let records: Vec<Record> = (0..len)
                .map(|slot| {
                    let record = Record::free();
                    record.ident.store(
                        slot as u64 | ABANDONED | RETIRED | VISITED | SlotState::Retired.bits(),
                        Ordering::Relaxed,
                    );
                    record
                })
                .collect();
            assert_eq!(super::anchored_slots(&records), 0, "len {len}");
            // Every third slot anchored, the last one in the tail when
            // there is one.
            let mut expected = 0;
            for (slot, record) in records.iter().enumerate() {
                if slot % 3 == 0 || slot + 1 == len {
                    record
                        .ident
                        .fetch_add((1 + slot as u64) * REF, Ordering::Relaxed);
                    expected += 1;
                }
            }
            assert_eq!(super::anchored_slots(&records), expected, "len {len}");
            for record in &records {
                record.ident.store(1 << 43, Ordering::Relaxed);
            }
            assert_eq!(super::anchored_slots(&records), len, "len {len}");
        }
    }

    /// The park pass's candidates, the parked set's search with each member
    /// decided by `live_park`, agree with a slot-by-slot flag scan over
    /// seeded tables whose flags come from retirements, parks, parks a
    /// retirement absorbed and stale parked bits beside clear flags: every
    /// range of a 150-slot table, and on a table of three summary groups
    /// every range whose bounds lie in the seeded regions at the group
    /// edges. Afterwards every stale bit is cleared, every unretired flagged
    /// slot keeps its parked bit, and every summary bit stands exactly for a
    /// nonzero word. Expected positions come from the words alone.
    #[test]
    fn the_park_search_matches_a_slot_by_slot_flag_scan() {
        use super::super::pending::GROUP_SLOTS;
        let whole = std::iter::once(0..150).collect::<Vec<_>>();
        check_park_search(150, 24, &whole);
        let large = 2 * GROUP_SLOTS + 150;
        let regions = [
            0..70,
            GROUP_SLOTS - 70..GROUP_SLOTS + 70,
            2 * GROUP_SLOTS - 70..2 * GROUP_SLOTS + 70,
            large - 70..large,
        ];
        check_park_search(large, 4, &regions);
    }

    /// One configuration of [`the_park_search_matches_a_slot_by_slot_flag_scan`]:
    /// `seeds` tables of `slots` slots whose `regions` carry seeded flags,
    /// swept by one walk over the whole table, then searched over every
    /// range whose bounds lie in a region or at the end.
    fn check_park_search(slots: usize, seeds: u64, regions: &[std::ops::Range<usize>]) {
        use std::sync::atomic::AtomicU64;

        use super::super::pending::{
            Counted, Every, Parked, Published, Seek, Walked, mark_parked, seek, walk,
        };
        use super::super::seeded::SplitMix64;
        use super::super::slot::Record;
        use super::super::word::{REF, VISITED};
        let words = slots.div_ceil(64);
        let seeded: Vec<usize> = regions.iter().flat_map(|region| region.clone()).collect();
        let bounds: Vec<usize> = seeded.iter().copied().chain([slots]).collect();
        for seed in 0..seeds {
            let mut rng = SplitMix64::new(seed);
            let records: Vec<Record> = (0..slots).map(|_| Record::free()).collect();
            let parked: Vec<AtomicU64> = (0..words).map(|_| AtomicU64::new(0)).collect();
            let summary: Vec<AtomicU64> =
                (0..words.div_ceil(64)).map(|_| AtomicU64::new(0)).collect();
            for &slot in &seeded {
                let (flags, park) = match rng.next_u64() % 8 {
                    0 => (ABANDONED | super::RETIRED | ANCHORED, false),
                    1 => (ABANDONED, true),
                    2 => (ABANDONED | super::RETIRED, true),
                    3 => (VISITED | (2 * REF), true),
                    _ => (VISITED, false),
                };
                records[slot].ident.store(flags, Ordering::Relaxed);
                if park {
                    mark_parked::<_, Published>(&parked, &summary, slot);
                }
            }
            let live = |slot: usize| {
                records[slot].ident.load(Ordering::Relaxed) & (ABANDONED | super::RETIRED)
                    == ABANDONED
            };
            // The park pass's decision: the slot's word loaded with acquire,
            // then `live_park` on it.
            let decide = |slot: usize| {
                let sighted = records[slot].ident.load(Ordering::Acquire);
                super::live_park(&parked, &records, slot, sighted).is_some()
            };
            let candidate = |start: usize, end: usize| {
                let mut at = start;
                loop {
                    let mut levels = Parked::<_, Published>::new(&parked, &summary);
                    match seek(&mut levels, at, end, &mut Counted::unbounded()) {
                        Seek::Member(slot) if decide(slot) => return Some(slot),
                        Seek::Member(slot) => at = slot + 1,
                        Seek::Clear => return None,
                        Seek::Short(_) => unreachable!("an unbounded search stopped short"),
                    }
                }
            };
            // One walk over every member, with each member decided by
            // `live_park` as the park pass decides it, yields exactly the
            // live parks in order and clears every stale bit it meets; the
            // searches below repair the summary bits those clears leave
            // beside zero words.
            let mut levels = Parked::<_, Published>::new(&parked, &summary);
            let mut swept = Vec::new();
            let walked = walk(
                &mut Every {
                    levels: &mut levels,
                    funds: &mut Counted::unbounded(),
                    decide: |slot| {
                        if decide(slot) {
                            swept.push(slot);
                        }
                        true
                    },
                },
                0,
                slots,
            );
            assert_eq!(walked, Walked::Clear);
            let live_slots: Vec<usize> = (0..slots).filter(|&slot| live(slot)).collect();
            assert_eq!(swept, live_slots, "seed {seed}");
            for &start in bounds.iter().filter(|&&slot| slot < slots) {
                for &end in bounds.iter().filter(|&&slot| slot > start) {
                    assert_eq!(
                        candidate(start, end),
                        (start..end).find(|&slot| live(slot)),
                        "seed {seed} range {start}..{end}"
                    );
                }
            }
            for slot in 0..slots {
                let bit = parked[slot / 64].load(Ordering::Relaxed) >> (slot % 64) & 1 == 1;
                assert_eq!(
                    bit,
                    live(slot),
                    "seed {seed} slot {slot}: a stale bit survived or a live park lost its bit"
                );
            }
            for (word, bits) in parked.iter().enumerate() {
                let summarized = summary[word / 64].load(Ordering::Relaxed) >> (word % 64) & 1 == 1;
                assert_eq!(
                    summarized,
                    bits.load(Ordering::Relaxed) != 0,
                    "seed {seed} word {word}"
                );
            }
        }
    }
}
