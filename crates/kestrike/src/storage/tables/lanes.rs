//! Range-split installs of restored bindings: one pool-gate hold splits the slot tables into lanes of disjoint,
//! aligned slot ranges, each lane installs its bindings with no write outside its range, and the holder then folds
//! the lanes' shared effects into the tables before it releases the gate.
//!
//! Invariants owned by this module:
//!
//! - DISJOINT-LANES: lane boundaries are multiples of 64 slots, so each lane's tails, keys, portable pairs, policy
//!   links and level-0 free words are `&mut` slices no other lane holds; each lane also borrows only its own range of
//!   the records and the atomic per-slot words, and refuses a slot outside its range by panic before a write.
//! - CHECK-BEFORE-WRITE: a binding writes nothing unless the writer's session admits its record, its slot is free and
//!   its incarnation lies above the one the slot's `Free` word last issued, so a refusal leaves the tables as the
//!   lane found them.
//! - FOLD-ONCE: [`Tables::fold_lanes`] applies every effect a lane leaves pending exactly once: the summary bits of
//!   each level-0 word a lane emptied, the lane's policy sublist spliced at the domain head in lane order, the slot
//!   ledger, the capture membership count, the insertion clock at the last step a lane gave and the earliest
//!   deadline.
//!   A lane installs with the capture lock and the pool gate held by the caller, so the result equals installing the
//!   same bindings one at a time in lane order.

use std::sync::MutexGuard;
use std::sync::atomic::{AtomicU64, Ordering};

use super::super::recovery::Capture;

use super::super::held::Held;
use super::super::owner::Pool;
use super::super::policy::{POLICY_NONE, PolicySlot};
use super::super::record::{RecordIdentity, admits};
use super::super::reserve::{RestoreRefusal, Restored};
use super::super::slot::Record;
use super::super::tables::SlotState;
use super::super::word::{self, INCARNATION, LINKED, MARKER, POLICY};
use super::Tables;

/// One lane's share of the slot tables for slots `[start, end)`.
pub(crate) struct Lane<'t> {
    start: usize,
    end: usize,
    records: &'t [Record],
    tails: &'t mut [u16],
    keys: &'t mut [[u8; 32]],
    deadlines: &'t mut [u64],
    lifetimes: &'t mut [u32],
    next: &'t mut [u32],
    free: &'t mut [u64],
    generations: &'t [AtomicU64],
    versions: &'t [AtomicU64],
    steps: &'t [AtomicU64],
    /// The lane's insertion steps: the last it gave, or the clock it started from, and the last reserved for it.
    step: (u64, u64),
    folded: Folded,
}

/// What a lane leaves for [`Tables::fold_lanes`].
#[derive(Debug)]
pub(crate) struct Folded {
    pub(crate) installed: usize,
    /// The extent rows of the installed bindings.
    rows: u64,
    /// The level-0 free words the lane emptied, the first inline, so a lane of one binding allocates nothing.
    emptied: (Option<usize>, Vec<usize>),
    /// The lane's policy sublist, newest first.
    head: u32,
    tail: u32,
    earliest: u32,
    /// The last insertion step the lane gave, or the clock it started from.
    last: u64,
}

/// The lane length for `slots` slots over `lanes` lanes: a multiple of 64.
pub(crate) fn lane_len(slots: usize, lanes: usize) -> usize {
    slots.div_ceil(lanes.max(1)).div_ceil(64).max(1) * 64
}

impl<'t> Tables<'t> {
    /// Splits the slot tables into lanes of `len` slots, a value of [`lane_len`] or, for one lane, the slot count, each with `reserve[k]` insertion
    /// steps from the pool's clock reserved in lane order. The lanes borrow the capture guard, which serializes the
    /// membership words the lanes and the fold write, so the lock stays held while any lane lives.
    ///
    /// # Panics
    ///
    /// When a lane other than the last ends off a multiple of 64 slots, a lane past the
    /// slots has a nonzero reservation, or the steps pass `u64::MAX`; the caller preflights the last two.
    pub(in crate::storage) fn lanes<'l>(
        &'l mut self,
        live: &Pool,
        _capture: &'l MutexGuard<'_, Capture>,
        len: usize,
        reserve: &'l [u64],
    ) -> impl Iterator<Item = Lane<'l>> + 'l {
        let slots = self.records.len();
        let mut step = live.insert_step.load(Ordering::Relaxed);
        let leaves = slots.div_ceil(64).max(1);
        let (mut tails, mut keys, mut deadlines) =
            (&mut *self.tails, &mut *self.keys, &mut *self.deadlines);
        let (mut lifetimes, mut next) = (&mut *self.lifetimes, &mut *self.policy_next);
        let mut free = &mut self.free_slots[..leaves];
        let (records, generations, versions, steps_of) =
            (self.records, self.generations, self.versions, self.steps);
        reserve.iter().enumerate().map(move |(k, &steps)| {
            let (start, end) = (k * len, ((k + 1) * len).min(slots));
            assert!(
                start < end || steps == 0,
                "a lane past the slots: lane {k} at {start}..{end} of {slots} with {steps} steps"
            );
            let n = end.saturating_sub(start);
            let words = match end == slots {
                true => free.len(),
                false => {
                    assert!(
                        n.is_multiple_of(64),
                        "a lane boundary off the 64-slot alignment: {n} slots"
                    );
                    n / 64
                }
            };
            let last = step
                .checked_add(steps)
                .expect("the caller preflights the insertion clock");
            let shared = start.min(slots)..end;
            let lane = Lane {
                start,
                end,
                records: &records[shared.clone()],
                tails: cut(&mut tails, n),
                keys: cut(&mut keys, n),
                deadlines: cut(&mut deadlines, n),
                lifetimes: cut(&mut lifetimes, n),
                next: cut(&mut next, n),
                free: cut(&mut free, words),
                generations: &generations[shared.clone()],
                versions: &versions[shared.clone()],
                steps: &steps_of[shared],
                step: (step, last),
                folded: Folded {
                    installed: 0,
                    rows: 0,
                    emptied: (None, Vec::new()),
                    head: POLICY_NONE,
                    tail: POLICY_NONE,
                    earliest: u32::MAX,
                    last: step,
                },
            };
            step = last;
            lane
        })
    }

    /// Folds the lanes' pending effects into the tables, in lane order, consuming each, and returns whether the earliest deadline
    /// lowered, which the caller publishes.
    pub(in crate::storage) fn fold_lanes(
        &mut self,
        live: &Pool,
        _capture: &MutexGuard<'_, Capture>,
        folds: impl IntoIterator<Item = Folded>,
    ) -> bool {
        let slots = self.records.len();
        let mut free = super::super::free::FreeSlots::attach(self.free_slots, slots);
        let (mut installed, mut rows, mut earliest, mut clock) =
            (0, 0, u32::MAX, live.insert_step.load(Ordering::Relaxed));
        for fold in folds {
            for &emptied in fold.emptied.0.iter().chain(&fold.emptied.1) {
                free.emptied(emptied);
            }
            if fold.installed > 0 {
                let head = self.domain.head;
                self.policy_next[fold.tail as usize] = head;
                if head == POLICY_NONE {
                    self.domain.tail = fold.tail;
                } else {
                    self.records[head as usize].set_prev(fold.tail);
                }
                self.domain.head = fold.head;
                self.domain.members += fold.installed as u32;
            }
            installed += fold.installed;
            rows += fold.rows;
            earliest = earliest.min(fold.earliest);
            clock = clock.max(fold.last);
        }
        self.state.ledger.free -= installed;
        self.state.ledger.resident += installed;
        live.insert_step.store(clock, Ordering::Relaxed);
        live.eligible.fetch_add(installed, Ordering::Relaxed);
        live.member_rows.fetch_add(rows, Ordering::Relaxed);
        installed > 0 && self.state.note_deadline(earliest)
    }
}

/// The first `n` elements of `rest`, which keeps the others.
fn cut<'s, T>(rest: &mut &'s mut [T], n: usize) -> &'s mut [T] {
    let (first, others) = std::mem::take(rest).split_at_mut(n);
    *rest = others;
    first
}

impl Lane<'_> {
    /// Installs `restored` for writer session `writer` within this lane: the slot leaves the free set, takes the restored
    /// facts and the lane's next insertion step, joins the lane's policy sublist and becomes
    /// `incarnation | Resident | LINKED | MARKER | 1 REF`.
    ///
    /// # Errors
    ///
    /// `Session` when [`admits`] refuses the record and `NotFree` for a slot outside the free set or an incarnation at
    /// or below the last issued; each leaves the lane unchanged.
    ///
    /// # Panics
    ///
    /// When the slot lies outside the lane, a free slot's word carries a flag, a state, a count or a reserved bit, the
    /// lane's steps are spent, the slot is policy-linked, its insertion step is nonzero, or its word changes under the
    /// gate: each is an invariant violation, and the caller's hold fails closed.
    #[inline(always)]
    pub(crate) fn install(
        &mut self,
        restored: &Restored,
        writer: u64,
    ) -> Result<(), RestoreRefusal> {
        let named = RecordIdentity {
            key: restored.key,
            allocation: restored.id.record_tag(),
            session: restored.session,
            version: restored.version,
        };
        if !admits(&named, &named, writer) {
            return Err(RestoreRefusal::Session);
        }
        let id = restored.id;
        let slot = id.slot_index();
        assert!(
            (self.start..self.end).contains(&slot),
            "a restored binding outside its lane: slot {slot}, lane {}..{}",
            self.start,
            self.end
        );
        let local = slot - self.start;
        if self.free[local / 64] >> (local % 64) & 1 == 0 {
            return Err(RestoreRefusal::NotFree);
        }
        let record = &self.records[local];
        let free = record.ident.load(Ordering::Relaxed);
        assert!(
            free & !INCARNATION == 0,
            "a free slot's word carries a flag, a state, a count or a reserved bit"
        );
        if id.incarnation() <= word::incarnation(free) {
            return Err(RestoreRefusal::NotFree);
        }
        assert!(
            self.step.0 < self.step.1,
            "a lane installs within its reserved steps: step {} of last {}",
            self.step.0,
            self.step.1
        );
        assert!(
            word::checked(record.word()) & POLICY == 0
                && record.prev() == POLICY_NONE
                && self.next[local] == POLICY_NONE,
            "a resident slot linked twice or linked with stale state"
        );
        let word = &mut self.free[local / 64];
        *word &= !(1 << (local % 64));
        if *word == 0 {
            let (first, rest) = &mut self.folded.emptied;
            let emptied = self.start / 64 + local / 64;
            match first {
                None => *first = Some(emptied),
                Some(_) => rest.push(emptied),
            }
        }
        record.set_locator(restored.locator);
        record.set_fingerprint(restored.fingerprint);
        record.set_expires_at_s(restored.expires_at_s);
        self.tails[local] = restored.tail;
        self.generations[local].store(restored.session, Ordering::Relaxed);
        self.versions[local].store(restored.version, Ordering::Relaxed);
        assert_eq!(
            self.steps[local].load(Ordering::Relaxed),
            0,
            "binding requires an ineligible slot"
        );
        self.keys[local] = restored.key;
        self.deadlines[local] = restored.expiry.deadline_ns;
        self.lifetimes[local] = restored.expiry.lifetime_ms;
        self.step.0 += 1;
        self.steps[local].store(self.step.0, Ordering::Relaxed);
        let folded = &mut self.folded;
        folded.earliest = folded.earliest.min(restored.expires_at_s);
        if folded.head == POLICY_NONE {
            folded.tail = slot as u32;
        } else {
            self.records[folded.head as usize - self.start].set_prev(slot as u32);
        }
        self.next[local] = folded.head;
        folded.head = slot as u32;
        let installed =
            u64::from(id.incarnation()) | SlotState::Resident.bits() | MARKER | word::REF | LINKED;
        // The exchange is the release a reader's acquire validation of the slot pairs with, so every fact written above
        // is visible to a reader holding this incarnation's right.
        let exchanged =
            record
                .ident
                .compare_exchange(free, installed, Ordering::Release, Ordering::Relaxed);
        assert!(
            exchanged.is_ok(),
            "a free slot's word changed under the pool gate"
        );
        folded.installed += 1;
        folded.rows += match Held::decode(restored.locator) {
            Some(held) => held.extents(),
            None => panic!("a restored binding's locator names neither an extent nor a sequence"),
        };
        Ok(())
    }

    /// The lane's pending effects, for [`Tables::fold_lanes`].
    pub(crate) fn done(mut self) -> Folded {
        self.folded.last = self.step.0;
        self.folded
    }
}

#[cfg(test)]
#[path = "lanes_tests.rs"]
mod tests;
