//! Storage phase and exclusive, resumable finalization.
//!
//! Phase. A [`Storage`] is `Live` from a completed initialization until
//! finalization attempts its first release, `Finalizing` from that attempt
//! until every release has succeeded, and `Drained` after it. Every shared
//! accessor reads the phase before it touches a mapping and refuses outside
//! `Live`, so no call through `&Storage` can reach a released or partially
//! released extent. The phase is written only under the exclusive borrow
//! finalization holds. The root mapping's ownership does not stand for
//! liveness: a `Finalizing` owner still owns its root while its index is
//! gone.
//!
//! Finalization. [`Storage::finalize`] takes `&mut self`, so it compiles
//! only where no registration, lease, completed owner or facade borrows the
//! storage; the borrow checker is the domain proof that nothing can observe
//! a mapping it releases. It runs in stages behind a cursor that lives in
//! the outer owner, outside every mapping it may release, so a call that
//! stops for its budget resumes where it stopped:
//!
//! - Inspection. Every registration record's claim, the engine-wide credit
//!   count, and under the pool gate every slot's state, count and pending
//!   flag. A claimed record is a forgotten registration; a reserved credit a
//!   forgotten lease; a retired slot or one with its abandonment flag set an
//!   unserviced obligation, counted once per slot; a slot an owner still
//!   holds, or one whose count stays positive with no obligation pending, a
//!   held slot. Then, under each shard's gate, every record of the shard's
//!   fill table and its custody record: a record whose owner has not departed
//!   is a forgotten attempt; a departed record is an unserviced obligation;
//!   a custody record naming a record is a held one. An index without any
//!   fill table passes this stage for free; a shard without a table among
//!   shards with one is one paid step.
//!   Any of these ends the call with [`Finalization::Blocked`] naming them
//!   and releases no extent; the next call inspects again from the start,
//!   since a blocker may have ended. A poisoned pool gate is
//!   [`FinalizeError::Poisoned`] and a poisoned shard gate
//!   [`FinalizeError::ShardPoisoned`], never a blocker that service could
//!   clear.
//!   Every inspection step is one prepaid `Comparison` step. A call takes the
//!   pool's or a shard's gate with one prepaid attempt and inspects
//!   consecutive slots or
//!   records under the hold, up to the last one or the last visit the
//!   allowance pays.
//! - Release. Once the inspection has completed clean, the phase becomes
//!   `Finalizing` before the first attempt, and the release positions are
//!   walked in reverse ownership order, the index first, then the volume's
//!   control, then the root. A position whose mapping is owned costs one
//!   prepaid update and one unmap; a position with no mapping to release, a
//!   zero-length mapping never acquired, costs one prepaid step, so a call's
//!   work is bounded by its allowance. A release the kernel refuses leaves that
//!   mapping retained at its original base, extent, charge and code,
//!   reported through [`Storage::retained`], and is never retried; the
//!   cursor moves on, so later extents still release exactly once. A call
//!   that reaches the last position reports [`Finalization::Drained`] only
//!   when nothing is retained; otherwise it reports
//!   [`Finalization::Closing`] with the counts, and the phase stays
//!   `Finalizing`, as does every later call.
//!
//! Every call on a `Live` owner closes admission before inspection.
//! Closed admission refuses every new registration, reservation, publication, fill attempt, lease and volume attach.
//! A volume attached before the close borrows the storage, so its bootstrap's installs end before any finalization call starts.
//! The close service may turn a held slot into a pending one, and slot service returns pending slots, but no path turns an unclaimed record, a free credit, a clean slot or a Free fill record into a blocker.
//! Calls stopped by their allowance therefore resume at the inspection cursor without missing a blocker.
//! An inspection that found nothing stays valid, and the next call starts the extent releases without inspecting again.
//!
//! Prepayment. Each inspection step, gate attempt, release position and
//! unmap is preflighted and charged
//! before it runs. An allowance that cannot pay the next action leaves that
//! action and the cursor unchanged: a call that walked no release position
//! refuses [`FinalizeError::BudgetExhausted`], one that walked at least one
//! reports [`Finalization::Closing`] with its progress. A zero allowance
//! performs no visit, gate attempt or unmap.
//!
//! Abandonment. Dropping an owner that was never finalized, or one whose
//! finalization stopped, releases its ordinary metadata through normal drop
//! glue and leaves every owned or retained mapping mapped until the process
//! exits. Once ownership has
//! transferred to a `Storage`, finalization is the only path that destroys
//! a mapping; a failed initialization releases every extent it acquired
//! before any owner exists, and reports a rejected release as its owned
//! incomplete cleanup.
//!
//! Compile-time misuse: finalizing while a registration or a lease borrows
//! the storage is rejected.
//!
//! ```compile_fail,E0502
//! # use kestrike::storage::*;
//! # fn f(mut storage: Storage<LinuxPlatform>) -> Result<(), LookupError> {
//! let mut registration = storage.register().ok().unwrap();
//! let mut budget = WorkBudget::new(64);
//! let lease = registration.lookup(&[0x5A; 32], 3, &mut budget)?;
//! let _ = storage.finalize(&mut budget);
//! drop(lease);
//! # Ok(())
//! # }
//! ```
//!
//! Stable rustdoc does not check the error code above; it records the
//! intended cause (E0502 a shared borrow alive across the exclusive call)
//! for a reader, and `cargo +nightly test --doc` verifies it.

use std::sync::atomic::Ordering;

use super::budget::{WorkBudget, WorkKind};
use super::fill::{self, Record};
use super::gate::GateError;
use super::image::{FillImage, NO_RECORD};
use super::lease::record_credits;
use super::mapping::Mapping;
use super::os::Platform;
use super::owner::Storage;
use super::probe::{self, Primitive};
use super::tables::SlotState;
use super::word::{self, ABANDONED, STATE};
use crate::index::ShardIndex;

/// Where an owner stands between initialization and the last release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Every acquired mapping is owned and every shared accessor serves.
    Live,
    /// Finalization has attempted at least one release; every shared
    /// accessor refuses, and at least one extent is still owned or retained.
    Finalizing,
    /// Every extent was released; nothing is owned or charged.
    Drained,
}

/// What still borrows or holds the engine, as the resumable inspection found
/// it; each count combines the observations of every call since inspection
/// last started from the beginning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Blockers {
    /// Registration records still claimed: handles that were forgotten.
    pub registrations: usize,
    /// Lease credits still reserved: leases or fills that were forgotten, or a
    /// joined publication's row credit that fill service has not yet returned;
    /// a forgotten fill also counts under `fills`.
    pub leases: usize,
    /// Slots with no obligation pending that an owner still holds or whose
    /// count is nonzero.
    pub held_slots: usize,
    /// Slots retired or abandoned whose obligation service has not
    /// discharged, one per slot.
    pub pending: usize,
    /// Fill records whose owner has not departed: attempts that were
    /// forgotten.
    pub fills: usize,
    /// Fill records whose owner departed and fill service has not freed.
    pub pending_fills: usize,
    /// Shards whose custody record names a fill record.
    pub custody: usize,
}

impl Blockers {
    pub fn is_clear(&self) -> bool {
        *self == Self::default()
    }
}

/// How far the release stage has come.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Progress {
    /// Extents released, over every call.
    pub released: usize,
    /// Extents the kernel refused to release; each stays owned and charged.
    pub retained: usize,
    /// Release positions the cursor has still to walk.
    pub remaining: usize,
}

/// How one finalization call ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Finalization {
    /// The inspection found what it names; no extent was released and the
    /// phase is still `Live`.
    Blocked(Blockers),
    /// The release stage ran or resumed, or had nothing left to attempt, and
    /// at least one extent is still owned or retained; the phase is
    /// `Finalizing`.
    Closing(Progress),
    /// Every extent was released; the phase is `Drained`.
    Drained,
}

/// Why a finalization call made no decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalizeError {
    /// The allowance could not pay the next inspection visit, gate attempt,
    /// pass or unmap, and this call walked no release position; that action
    /// and the release cursor are unchanged, and the inspection resumes
    /// from the visits this call paid for.
    BudgetExhausted,
    /// The pool gate is poisoned: the volume's tables cannot be inspected,
    /// so its obligations cannot be proved discharged. No extent was
    /// released.
    Poisoned,
    /// The pool gate word reads held. No Rust borrow can hold it under the
    /// exclusive borrow, so the word was left by a holder that never
    /// released it. No extent was released.
    GateHeld,
    /// A shard's gate is poisoned, or its fill table is malformed and the
    /// call poisoned the gate: its fill records cannot be inspected. No
    /// extent was released.
    ShardPoisoned { shard: ShardIndex },
    /// A shard's gate word reads held, as `GateHeld` for the volume. No extent
    /// was released.
    ShardGateHeld { shard: ShardIndex },
    /// Every extent was already released.
    Drained,
}

impl From<super::budget::BudgetExhausted> for FinalizeError {
    fn from(_: super::budget::BudgetExhausted) -> Self {
        Self::BudgetExhausted
    }
}

/// The inspection's position, resumable across calls that stop for budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Inspect {
    /// The next registration record to visit.
    Registrations {
        next: usize,
    },
    Leases,
    /// The next slot of the volume to visit.
    Slots {
        slot: usize,
    },
    /// The next fill record of `shard`'s table to visit; a fresh shard
    /// starts at zero.
    Fills {
        shard: usize,
        record: usize,
    },
    Complete,
}

/// The finalization cursor: the inspection position, the blockers it has
/// found so far, and the releases attempted once the inspection is clean.
/// Lives in the outer owner, outside every mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct FinalizeCursor {
    inspect: Inspect,
    found: Blockers,
    /// Idle lease credits summed over the records inspected so far.
    idle: usize,
    /// Extents attempted so far; the next one, in reverse ownership order,
    /// is this many past the last.
    attempted: usize,
    /// Attempted positions that held nothing to release: zero-length
    /// mappings never acquired.
    empty: usize,
    /// Refused releases so far.
    retained: usize,
}

impl FinalizeCursor {
    pub(super) const fn start() -> Self {
        Self {
            inspect: Inspect::Registrations { next: 0 },
            found: Blockers {
                registrations: 0,
                leases: 0,
                held_slots: 0,
                pending: 0,
                fills: 0,
                pending_fills: 0,
                custody: 0,
            },
            idle: 0,
            attempted: 0,
            empty: 0,
            retained: 0,
        }
    }
}

impl<P: Platform> Storage<P> {
    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// Runs or resumes finalization: the inspection, then the per-extent
    /// releases, as the module documentation describes. `&mut self` proves no
    /// registration, lease, owner or facade borrows the storage.
    ///
    /// # Errors
    ///
    /// [`FinalizeError`]; on each of them this call released nothing. On
    /// `BudgetExhausted` the inspection keeps the visits this call paid for
    /// and the next call resumes from them; the unfunded action and the
    /// release cursor are unchanged. `Poisoned`, `GateHeld`, `ShardPoisoned`
    /// and `ShardGateHeld` restart the inspection. A call that walked some
    /// release positions and then ran out reports `Closing` instead.
    pub fn finalize(&mut self, budget: &mut WorkBudget) -> Result<Finalization, FinalizeError> {
        match self.phase() {
            Phase::Drained => return Err(FinalizeError::Drained),
            Phase::Live => {
                self.close();
                if let Some(blocked) = self.inspect(budget)? {
                    return Ok(Finalization::Blocked(blocked));
                }
            }
            Phase::Finalizing => {}
        }
        self.release_extents(budget)
    }

    /// Runs the inspection from its cursor: `Ok(None)` when it completes
    /// without finding blockers, `Ok(Some(blockers))` when it finds any.
    /// Blockers reset the cursor for the next inspection. An inspection with
    /// nothing found keeps the cursor complete, so a later call starts the
    /// extent releases without paying for any inspection visit.
    fn inspect(&mut self, budget: &mut WorkBudget) -> Result<Option<Blockers>, FinalizeError> {
        loop {
            let cursor = self.finalize;
            match cursor.inspect {
                Inspect::Registrations { next } => {
                    let records = self.registrations();
                    if next >= records.len() {
                        self.finalize.inspect = Inspect::Leases;
                        continue;
                    }
                    budget.preflight(1)?;
                    budget.debit(WorkKind::Comparison)?;
                    probe::note(Primitive::Load);
                    let claimed = records[next].claimed.load(Ordering::Acquire);
                    let idle = record_credits(self, next, Ordering::Acquire);
                    self.finalize.found.registrations += usize::from(claimed);
                    self.finalize.idle += idle;
                    self.finalize.inspect = Inspect::Registrations { next: next + 1 };
                }
                Inspect::Leases => {
                    budget.preflight(1)?;
                    budget.debit(WorkKind::Comparison)?;
                    probe::note(Primitive::Load);
                    // The engine-wide count less the idle credits the record
                    // visits summed: the credits behind leases, as
                    // `outstanding` computes it.
                    let taken = self.leases().reserved.load(Ordering::Acquire);
                    self.finalize.found.leases = taken.saturating_sub(self.finalize.idle);
                    self.finalize.inspect = Inspect::Slots { slot: 0 };
                }
                Inspect::Slots { slot } => {
                    let live = &self.pool;
                    if slot >= live.descriptor().slot_count {
                        // The visits past the last slot were paid by those
                        // visits.
                        self.finalize.inspect = Inspect::Fills {
                            shard: 0,
                            record: 0,
                        };
                        continue;
                    }
                    // One gate attempt and the first slot visit, prepaid
                    // together so a taken gate always examines a slot; the
                    // hold then covers the slots after it the allowance pays.
                    budget.preflight(2)?;
                    budget.debit(WorkKind::CoordinationAttempt)?;
                    let refused = match live.try_lock_quiet() {
                        Ok(access) => {
                            probe::note(Primitive::GateTaken);
                            let mut run = Blockers::default();
                            let mut next = slot;
                            let count = live.descriptor().slot_count;
                            let records = live.records();
                            // If the allowance runs out before the slots do,
                            // `next` ends at the first unpaid slot.
                            let visits = count.saturating_sub(next).min(budget.remaining());
                            let paid = budget.debit_n(WorkKind::Comparison, visits);
                            debug_assert!(paid.is_ok(), "the allowance holds the visits");
                            probe::note_n(Primitive::Load, visits);
                            // With the visits paid, no step of the walk waits
                            // on the one before it: a group's words are
                            // loaded side by side and judged together.
                            let (groups, tail) =
                                records[next..next + visits].as_chunks::<SLOT_GROUP>();
                            for group in groups {
                                let words: [u64; SLOT_GROUP] = std::array::from_fn(|at| {
                                    group[at].ident.load(Ordering::Acquire)
                                });
                                let (mut held, mut pending) = (0, 0);
                                for word in words {
                                    let slot = inspect_slot(word);
                                    held += usize::from(slot.0);
                                    pending += usize::from(slot.1);
                                }
                                run.held_slots += held;
                                run.pending += pending;
                            }
                            for record in tail {
                                let (held, pending) =
                                    inspect_slot(record.ident.load(Ordering::Acquire));
                                run.held_slots += usize::from(held);
                                run.pending += usize::from(pending);
                            }
                            next += visits;
                            access.release();
                            Ok((run, next))
                        }
                        Err(GateError::Poisoned) => {
                            probe::note(Primitive::GatePoisoned);
                            Err(FinalizeError::Poisoned)
                        }
                        Err(GateError::Contended) => {
                            probe::note(Primitive::GateBusy);
                            Err(FinalizeError::GateHeld)
                        }
                    };
                    let (run, next) = match refused {
                        Ok(inspected) => inspected,
                        Err(error) => {
                            self.restart_inspection();
                            return Err(error);
                        }
                    };
                    self.finalize.found.held_slots += run.held_slots;
                    self.finalize.found.pending += run.pending;
                    self.finalize.inspect = Inspect::Slots { slot: next };
                }
                Inspect::Fills { shard, record } => {
                    let tables = &self.root_image.fills;
                    if shard >= tables.len() || !self.root_image.any_fills {
                        self.finalize.inspect = Inspect::Complete;
                        continue;
                    }
                    let Some(table) = &tables[shard] else {
                        // A shard without a table is one paid step to pass.
                        budget.preflight(1)?;
                        budget.debit(WorkKind::Comparison)?;
                        self.finalize.inspect = Inspect::Fills {
                            shard: shard + 1,
                            record: 0,
                        };
                        continue;
                    };
                    let count = table.states.len();
                    if record >= count {
                        self.finalize.inspect = Inspect::Fills {
                            shard: shard + 1,
                            record: 0,
                        };
                        continue;
                    }
                    // One gate attempt and the first record visit, prepaid
                    // together as for a pool.
                    budget.preflight(2)?;
                    budget.debit(WorkKind::CoordinationAttempt)?;
                    let inspected =
                        match self.inspect_fills(ShardIndex(shard), table, record, budget) {
                            Ok(inspected) => inspected,
                            Err(error) => {
                                self.restart_inspection();
                                return Err(error);
                            }
                        };
                    let (run, next) = inspected;
                    self.finalize.found.fills += run.fills;
                    self.finalize.found.pending_fills += run.pending_fills;
                    self.finalize.found.custody += run.custody;
                    self.finalize.inspect = Inspect::Fills {
                        shard,
                        record: next,
                    };
                }
                Inspect::Complete => {
                    let found = cursor.found;
                    if found.is_clear() {
                        return Ok(None);
                    }
                    self.restart_inspection();
                    return Ok(Some(found));
                }
            }
        }
    }

    /// Puts the inspection back at its start with nothing found; the
    /// release stage's progress is untouched.
    fn restart_inspection(&mut self) {
        self.finalize.inspect = Inspect::Registrations { next: 0 };
        self.finalize.found = Blockers::default();
        self.finalize.idle = 0;
    }

    /// One hold on `shard`'s gate over `table`'s records from `record`, up
    /// to the last one or the last visit the allowance pays: what it found
    /// and the next record to visit. The custody record is read with the
    /// table's first record.
    fn inspect_fills(
        &self,
        shard: ShardIndex,
        table: &FillImage,
        record: usize,
        budget: &mut WorkBudget,
    ) -> Result<(Blockers, usize), FinalizeError> {
        let index = self
            .index()
            .expect("a fill table exists only with a live index");
        let image = index
            .image
            .shard(shard)
            .expect("a fill table exists only for an enabled shard");
        // SAFETY: the index mapping is owned while the owner is live.
        let gate = unsafe { image.gate(&index.mapping) };
        let guard = match gate.try_lock() {
            Ok(guard) => {
                probe::note(Primitive::GateTaken);
                guard
            }
            Err(GateError::Poisoned) => {
                probe::note(Primitive::GatePoisoned);
                return Err(FinalizeError::ShardPoisoned { shard });
            }
            Err(GateError::Contended) => {
                probe::note(Primitive::GateBusy);
                return Err(FinalizeError::ShardGateHeld { shard });
            }
        };
        // SAFETY: the owner is live and `table` is `shard`'s table of its
        // root image; the inspection reads only the shared words.
        let view = unsafe { self.fill_view(table) };
        let next_serial = view.control.next_serial.load();
        let mut run = Blockers::default();
        if record == 0 {
            run.custody += usize::from(view.custody.record.load(Ordering::Acquire) != NO_RECORD);
        }
        let mut next = record;
        let count = view.states.len();
        // Each step debits a local copy of the allowance; `budget` takes one
        // store, when the walk ends.
        let mut allowance = *budget;
        while next < count && allowance.debit(WorkKind::Comparison).is_ok() {
            probe::note(Primitive::Load);
            let word = view.states[next].load(Ordering::Acquire);
            match fill::decode(word, next_serial) {
                Ok(Record::Free) => {}
                Ok(occupied) if occupied.is_departed() => run.pending_fills += 1,
                Ok(Record::Occupied { .. }) => run.fills += 1,
                Err(_) => {
                    *budget = allowance;
                    guard.poison();
                    return Err(FinalizeError::ShardPoisoned { shard });
                }
            }
            next += 1;
        }
        *budget = allowance;
        guard.release();
        Ok((run, next))
    }

    /// The release stage from its cursor: one prepaid unmap per extent in
    /// reverse ownership order.
    fn release_extents(&mut self, budget: &mut WorkBudget) -> Result<Finalization, FinalizeError> {
        let total = self.extent_count();
        let mut attempted_here = 0;
        while self.finalize.attempted < total {
            // The cursor moves only while the allowance can still pay a
            // release, so an allowance that cannot leaves it where it is,
            // unowned positions included.
            if budget.preflight(1).is_err() {
                if attempted_here == 0 {
                    return Err(FinalizeError::BudgetExhausted);
                }
                return Ok(Finalization::Closing(self.finalize_progress()));
            }
            let position = total - 1 - self.finalize.attempted;
            if !self.mapping_at(position).is_owned() {
                // Nothing to release: an unowned mapping ahead of the
                // cursor. The pass is one paid step, so a call's work stays
                // within its allowance.
                budget
                    .debit(WorkKind::Comparison)
                    .expect("the preflight covered the pass");
                self.finalize.attempted += 1;
                self.finalize.empty += 1;
                attempted_here += 1;
                continue;
            }
            budget
                .debit(WorkKind::Update)
                .expect("the preflight covered the release");
            // The phase turns before the first unmap, so a shared accessor
            // formed after this call returns never reaches a released extent.
            self.phase = Phase::Finalizing;
            probe::note(Primitive::Store);
            let refused = self.release_extent(position);
            self.finalize.attempted += 1;
            self.finalize.retained += usize::from(refused);
            attempted_here += 1;
        }
        if self.finalize.retained == 0 {
            self.phase = Phase::Drained;
            return Ok(Finalization::Drained);
        }
        Ok(Finalization::Closing(self.finalize_progress()))
    }

    /// How far the release stage has come: released and retained extents
    /// over every call, and the release positions the cursor has still to
    /// walk, which is every position before the first attempt. Read from
    /// the cursor's counts alone.
    pub fn finalize_progress(&self) -> Progress {
        let walked = self.finalize.attempted;
        Progress {
            released: walked - self.finalize.empty - self.finalize.retained,
            retained: self.finalize.retained,
            remaining: self.extent_count() - walked,
        }
    }

    /// Release positions in ownership order: the root, the volume's control,
    /// then the index.
    fn extent_count(&self) -> usize {
        2 + usize::from(self.index.is_some())
    }

    /// The mapping at `position` in ownership order.
    fn mapping_at(&self, position: usize) -> &Mapping {
        match position {
            0 => &self.root,
            1 => &self.pool.control,
            _ => {
                &self
                    .index
                    .as_ref()
                    .expect("an index position exists only with an index")
                    .mapping
            }
        }
    }

    /// Releases the mapping at `position` in ownership order and reports
    /// whether the kernel refused. `&mut self` proves no reference into it.
    fn release_extent(&mut self, position: usize) -> bool {
        let platform = &self.platform;
        let mapping = match position {
            0 => &mut self.root,
            1 => &mut self.pool.control,
            _ => {
                &mut self
                    .index
                    .as_mut()
                    .expect("an index position exists only with an index")
                    .mapping
            }
        };
        // SAFETY: the exclusive borrow proves no reference into the mapping
        // survives, and the phase is `Finalizing`, so no shared accessor
        // forms one afterwards.
        unsafe { mapping.release(platform) }.is_err()
    }
}

/// The slot words the slot inspection loads side by side and judges
/// together.
const SLOT_GROUP: usize = 8;

/// One slot's inspection under the pool gate, from its word's state and
/// flags: whether it is held and whether an obligation on it is
/// pending. A retired slot or one whose owner abandoned it is pending:
/// service and certification discharge it. A slot an owner still holds, or
/// one whose count a right keeps positive with no obligation pending, is
/// held: only its holder can end that. A malformed word is held, or pending
/// when its abandoned flag is set, so the inspection never reports it
/// drained; so is a state encoding past `Quarantined`.
fn inspect_slot(slot_word: u64) -> (bool, bool) {
    let state = slot_word & STATE;
    // Every term is evaluated and combined without a branch, so a run of
    // slots in mixed states costs no misprediction.
    let pending = (state == SlotState::Retired.bits()) | (slot_word & ABANDONED != 0);
    let owned = (state == SlotState::Filling.bits())
        | (state == SlotState::Resident.bits())
        | (state > SlotState::Quarantined.bits());
    let held = !pending & (owned | word::held(slot_word));
    (held, pending)
}

#[cfg(test)]
mod tests {
    use super::super::tables::SlotState;
    use super::super::word::{ABANDONED, REF};
    use super::inspect_slot;

    /// A free slot is drained only with a zero, well-formed word: a count
    /// or a reserved bit holds it, and a flag leaves it pending; a state
    /// encoding past `Quarantined` holds it too.
    #[test]
    fn a_free_slot_is_held_by_a_count_or_a_reserved_bit() {
        assert_eq!(inspect_slot(7), (false, false));
        assert_eq!(inspect_slot(7 | REF), (true, false));
        assert_eq!(inspect_slot(7 | 1 << 43), (true, false));
        assert_eq!(inspect_slot(7 | ABANDONED), (false, true));
        assert_eq!(
            inspect_slot(7 | SlotState::Quarantined.bits()),
            (false, false)
        );
        for state in 5..8 {
            assert_eq!(inspect_slot(7 | state << 36), (true, false), "{state}");
        }
        assert_eq!(inspect_slot(7 | SlotState::Filling.bits()), (true, false));
        assert_eq!(inspect_slot(7 | SlotState::Retired.bits()), (false, true));
    }
}
