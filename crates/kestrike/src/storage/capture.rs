//! Membership bookkeeping for checkpoint capture: the per-slot step words, the `eligible` count, the `insert_step` clock, and the `Storage` entry points a checkpoint writer drives.
//!
//! # Membership words
//!
//! Each slot's nonzero step records `insert_step` at insertion; `0` marks an ineligible slot. A capture includes members with `step <= t0`. `eligible` counts nonzero steps. Publication returns `Closed` when `insert_step == u64::MAX`, before calling `capture_insert`.
//!
//! # Locks
//!
//! The `capture` mutex serializes every membership change against capture progress and the tenure's suffix: insertion and removal paths hold it while they append the change's record (`capture_record`, while the suffix is open) and call `capture_insert`, `capture_remove` or `capture_unpublish`, and `begin_capture` reads `t0` and `eligible` under it. Every acquisition of the `capture` mutex is a nonblocking try, so the retire path (pool gate held, then the mutex) and `capture_visit` (the mutex, then the pool gate) coexist without deadlock. `capture_lock` returns `GateError::Contended` on a busy mutex; the `Storage` surface returns `CaptureError::Unavailable`. Deferred retirement leaves the object pending when capture serialization is busy.
//!
//! Publication and removal try the pool gate under their shard gate when the in-flight pass needs the departing member's entry, so the entry is copied while the member still owns its units. A required suffix also needs that try for every FILL publication and every recorded removal, to copy the record's entry or identity; a failed try refuses the change.
//!
//! A `CaptureEntry` owns copies of its extent words, so later reuse of the slot leaves previously copied entries unchanged.

use super::allocation::AllocationId;
use super::gate::GateError;
use super::held::Held;
use super::os::Platform;
use super::owner::{Pool, Storage};
use super::recovery::delta::{Cause, Change, Frame, Identity};
use super::recovery::suffix::SuffixRefusal;
use super::recovery::{Capture, CaptureEntry, CaptureError};
use super::tables::{SlotIndex, Tables};
use super::word;
use std::sync::atomic::Ordering;
use std::sync::{MutexGuard, TryLockError};

impl From<GateError> for CaptureError {
    fn from(error: GateError) -> Self {
        match error {
            GateError::Contended => Self::Unavailable,
            GateError::Poisoned => Self::Poisoned,
        }
    }
}

#[cfg(test)]
thread_local! {
    /// A wholesale replacement lands between a capture start's epoch read and its readiness read.
    pub(super) static REPLACE_AFTER_EPOCH: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Poisons capture serialization while the table walk it guards unwinds, as [`Capture::poison`] does. A mutex guard taken by a thread that was already unwinding leaves its mutex unpoisoned on drop, so the retirement, the removal, the fill publication and the warm install's fold arm this over their capture guards and disarm it once the walk returns; `capture_visit` catches its walk's panic and runs `Capture::poison` itself.
pub(in crate::storage) struct PoisonOnUnwind<'g, 'c>(
    pub(in crate::storage) &'g mut MutexGuard<'c, Capture>,
);

impl PoisonOnUnwind<'_, '_> {
    /// Disarms the guard after the guarded walk returns.
    pub(in crate::storage) fn returned(self) {
        std::mem::forget(self);
    }
}

impl Drop for PoisonOnUnwind<'_, '_> {
    fn drop(&mut self) {
        self.0.poison();
    }
}

impl Pool {
    /// Advances the capture epoch: the caller replaced the membership wholesale, by an attach, an install of restored
    /// slots or a load commit, so no pass started under an earlier epoch describes it. An attach advances it after
    /// its gate is visible in the readiness word, and a load commit before `LoadComplete`.
    pub(super) fn replaced(&self) {
        self.capture_epoch.fetch_add(1, Ordering::SeqCst);
    }
    fn epoch(&self) -> super::recovery::CaptureEpoch {
        super::recovery::CaptureEpoch(self.capture_epoch.load(Ordering::SeqCst))
    }
    /// One nonblocking try at the `capture` mutex.
    ///
    /// # Errors
    ///
    /// - `GateError::Contended` if another holder has the mutex.
    /// - `GateError::Poisoned` if a holder panicked while holding it, or a table walk under it panicked and its holder ran `Capture::poison`.
    pub(super) fn capture_lock(&self) -> Result<MutexGuard<'_, Capture>, GateError> {
        let capture = self.capture.try_lock().map_err(|e| match e {
            TryLockError::WouldBlock => GateError::Contended,
            TryLockError::Poisoned(_) => GateError::Poisoned,
        })?;
        if capture.poisoned() {
            return Err(GateError::Poisoned);
        }
        Ok(capture)
    }
    /// One nonblocking try at the `capture` mutex for a membership change. A mutex whose holder called `Capture::poison` is poisoned here as well. A poisoned mutex yields its guard with the in-flight pass abandoned and the suffix log closed, its open block dropped and its sealed blocks still draining, and stays poisoned, so captures remain terminal while publication, removal and retirement continue; a required log stays required, so its FILLs and logical removals refuse `History` while an unrequired log's FILLs and removals proceed unrecorded, as they do with no suffix.
    ///
    /// # Errors
    ///
    /// `GateError::Contended` if another holder has the mutex.
    pub(super) fn capture_membership_lock(&self) -> Result<MutexGuard<'_, Capture>, GateError> {
        if crate::sim::chaos::chaos!(CaptureBusy) {
            return Err(GateError::Contended);
        }
        let mut capture = match self.capture.try_lock() {
            Ok(capture) if !capture.poisoned() => return Ok(capture),
            Ok(capture) => capture,
            Err(TryLockError::WouldBlock) => return Err(GateError::Contended),
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
        };
        capture.abandon();
        capture.suffix.close();
        Ok(capture)
    }
    /// `slot`'s checkpoint entry, copied from the tables under the caller's pool hold.
    ///
    /// `allocation` is the record tag of the slot's current incarnation, and `extents` holds the slot's complete extent sequence: one word for a `Held::Direct` locator, the owned block prefix for a `Held::Sequence`.
    ///
    pub(super) fn capture_entry(
        &self,
        tables: &mut Tables<'_>,
        slot: usize,
    ) -> Result<CaptureEntry, CaptureError> {
        let mut entry = CaptureEntry::default();
        self.capture_entry_into(tables, slot, &mut entry)?;
        Ok(entry)
    }
    /// On success, `capture_entry_into` stores `capture_entry`'s result in `entry`, reusing `entry.extents`' allocation when its capacity suffices.
    ///
    /// # Panics
    ///
    /// The method panics before copying any entry field if [`word::state`] detects a reserved bit or a state encoding past `Quarantined` in the slot's word.
    #[inline(always)]
    pub(super) fn capture_entry_into(
        &self,
        tables: &mut Tables<'_>,
        slot: usize,
        entry: &mut CaptureEntry,
    ) -> Result<(), CaptureError> {
        let ident = self.records()[slot].ident.load(Ordering::Relaxed);
        word::state(ident);
        let id = AllocationId::new(SlotIndex(slot), word::incarnation(ident));
        let extents = &mut entry.extents;
        extents.clear();
        match tables.held(slot) {
            Held::Direct(locator) => {
                extents
                    .try_reserve_exact(1)
                    .map_err(|_| CaptureError::Allocation)?;
                extents.push(locator.bits());
            }
            Held::Sequence { block, count } => {
                let blocks = tables.blocks();
                let prefix = blocks.prefix(block, id, count).unwrap_or_else(|error| {
                    panic!("eligible slot {slot} must own its complete extent sequence: {error:?}")
                });
                extents
                    .try_reserve_exact(prefix.len())
                    .map_err(|_| CaptureError::Allocation)?;
                extents.extend_from_slice(prefix);
            }
        }
        let expiry = tables.expiry(slot);
        let Identity {
            key,
            allocation,
            session,
            version,
        } = self.capture_identity(tables, id);
        (entry.key, entry.allocation) = (key, allocation);
        (entry.session, entry.version) = (session, version);
        entry.deadline_ns = expiry.deadline_ns;
        entry.lifetime_ms = expiry.lifetime_ms;
        entry.tail = tables.tails[slot];
        Ok(())
    }
    /// The identity of `id`, a member, as its record header carries it, read under the caller's pool hold.
    #[inline(always)]
    pub(super) fn capture_identity(&self, tables: &Tables<'_>, id: AllocationId) -> Identity {
        let slot = id.slot_index();
        Identity {
            key: *tables.key(slot),
            allocation: id.record_tag(),
            session: tables.generation(slot),
            version: tables.version(slot),
        }
    }
    /// # Errors
    ///
    /// The suffix's refusal, which changes nothing.
    pub(super) fn capture_frame(
        &self,
        capture: &mut MutexGuard<'_, Capture>,
        removed: Option<(&Identity, Cause)>,
    ) -> Result<Frame, SuffixRefusal> {
        let Capture {
            scratch, suffix, ..
        } = &mut **capture;
        let inserted = Some(&*scratch);
        suffix.frame(Change { removed, inserted })
    }
    /// Appends at `now` the record of one membership change to the open suffix under the caller's `capture` guard,
    /// before the change moves any word: `removed` is the identity the change excludes with its cause. `inserted` is
    /// the frame [`capture_frame`](Self::capture_frame) returned for the same `removed`, and with it the record
    /// installs the capture's scratch entry. `removed` paired with `inserted` is a REPLACE, `inserted` alone an
    /// INSERT and `removed` alone a REMOVE. A record
    /// that removes raises `suffix_tail` to one past
    /// its last block's position, zero meaning no recorded removal, so the retirement of the slot it removes, which
    /// subtracts one, waits for that block's durability.
    ///
    /// # Errors
    ///
    /// The suffix's refusal, which changes nothing.
    pub(super) fn capture_record(
        &self,
        capture: &mut MutexGuard<'_, Capture>,
        now: u64,
        removed: Option<(&Identity, Cause)>,
        inserted: Option<Frame>,
    ) -> Result<(), SuffixRefusal> {
        let Capture {
            scratch, suffix, ..
        } = &mut **capture;
        let change = Change {
            removed,
            inserted: inserted.map(|_| &*scratch),
        };
        let frame = match inserted {
            Some(frame) => frame,
            None => suffix.frame(change)?,
        };
        let position = suffix.record(now, change, frame)?;
        if removed.is_some() {
            // The caller's capture guard serializes every writer of the word, so a load and a store raise it as
            // one step.
            let tail = self.suffix_tail.load(Ordering::Relaxed).max(position + 1);
            self.suffix_tail.store(tail, Ordering::Release);
        }
        self.suffix_wake(suffix);
        Ok(())
    }
    /// Publishes when the delta writer must next look at `log`, which the caller's `capture` guard holds.
    pub(super) fn suffix_wake(&self, log: &super::recovery::suffix::SuffixLog) {
        let due = log.due().unwrap_or(u64::MAX);
        self.suffix_due.store(due, Ordering::Relaxed);
    }
    /// The extent rows `slot` holds, from its record's locator, which a slot keeps from its claim to its return.
    pub(super) fn capture_rows(&self, slot: usize) -> u64 {
        match Held::decode(self.records()[slot].locator()) {
            Some(held) => held.extents(),
            None => panic!("a member's locator names neither an extent nor a sequence"),
        }
    }
    /// `slot`'s step word: `0` outside the membership, otherwise its insertion step.
    pub(super) fn capture_step(&self, _held: &MutexGuard<'_, Capture>, slot: usize) -> u64 {
        self.steps()[slot].load(Ordering::Relaxed)
    }
    /// Admits `slot` to the membership: assigns it the next `insert_step` and raises `eligible` and `member_rows`. A slot whose step is already nonzero is left unchanged.
    ///
    /// `_held` must be the caller's `capture` guard.
    pub(super) fn capture_insert(&self, _held: &MutexGuard<'_, Capture>, slot: usize) {
        let step = &self.steps()[slot];
        if step.load(Ordering::Relaxed) == 0 {
            let next = self.insert_step.load(Ordering::Relaxed).checked_add(1);
            let Some(next) = next else {
                panic!("membership insertion preflight must exclude exhaustion")
            };
            self.insert_step.store(next, Ordering::Relaxed);
            step.store(next, Ordering::Relaxed);
            // The caller's `capture` guard excludes every other writer of `eligible` and `member_rows`, so a load and a store raise each as one step.
            let eligible = self.eligible.load(Ordering::Relaxed);
            self.eligible
                .store(eligible.wrapping_add(1), Ordering::Relaxed);
            let rows = self.member_rows.load(Ordering::Relaxed);
            self.member_rows.store(
                rows.wrapping_add(self.capture_rows(slot)),
                Ordering::Relaxed,
            );
        }
    }
    /// Removes `slot` from the membership without saving it: clears its step word and lowers `eligible` and `member_rows` when the word was nonzero.
    ///
    /// Use this when no capture needs the slot's entry (`Capture::needs_save` is false) or when the `capture` mutex is poisoned. Every membership removal ends here, so a member of the in-flight pass's snapshot leaving the membership unrecorded in the suffix (`recorded` false) marks the pass unpublishable (`Capture::left`).
    pub(super) fn capture_unpublish(
        &self,
        held: &mut MutexGuard<'_, Capture>,
        slot: usize,
        recorded: bool,
    ) {
        // `held` excludes every other writer of the step words, `eligible` and `member_rows`, so each changes by a load and a store.
        let word = &self.steps()[slot];
        let step = word.load(Ordering::Relaxed);
        if step != 0 {
            word.store(0, Ordering::Relaxed);
            let eligible = self.eligible.load(Ordering::Relaxed);
            self.eligible
                .store(eligible.wrapping_sub(1), Ordering::Relaxed);
            let rows = self.member_rows.load(Ordering::Relaxed);
            self.member_rows.store(
                rows.wrapping_sub(self.capture_rows(slot)),
                Ordering::Relaxed,
            );
            held.left(step, recorded);
        }
    }
    /// Removes `slot` from the membership, saving its entry into `capture`'s side list first when the in-flight pass still needs it (member at `t0` and not yet visited).
    ///
    /// Call before the slot's units are released: the entry is copied from `tables` while the slot still owns its extents.
    #[inline(always)]
    pub(super) fn capture_remove(
        &self,
        tables: &mut Tables<'_>,
        capture: &mut MutexGuard<'_, Capture>,
        slot: usize,
        recorded: bool,
    ) {
        let step = tables.step(slot);
        if capture.needs_save(step, slot) {
            self.capture_save(tables, capture, slot, step);
        }
        self.capture_unpublish(capture, slot, recorded);
    }
    /// `step` is the slot's insertion step. An extent-word reservation failure abandons the pass. When side-list limits are enabled, `Capture::removed` abandons the pass if the side list already contains `pass.cap` entries or saving the entry would exceed `pass.word_cap` extent words. `capture_remove` calls `capture_save` for a member the in-flight pass still needs.
    #[cold]
    #[inline(never)]
    fn capture_save(
        &self,
        tables: &mut Tables<'_>,
        capture: &mut MutexGuard<'_, Capture>,
        slot: usize,
        step: u64,
    ) {
        match self.capture_entry(tables, slot) {
            Ok(entry) => capture.removed(step, entry),
            Err(_) => capture.abandon(),
        }
    }
}
impl<P: Platform> Storage<P> {
    /// Starts a capture pass when `policy` says one is due, returning its counter and `t0`; `Ok(None)` when the policy is not due. The start seals the suffix's open block under the `capture` mutex, so the pass's cut lies between the records before and after it.
    ///
    /// # Errors
    ///
    /// - `SlotBoundExceeded` when the pool has more slots than `policy.slot_bound()`, checked before the mutex with `policy` unchanged.
    /// - `Unavailable` for contention on the `capture` mutex or while an attached volume's gate runs or its load is unfinished, `Poisoned` for a poisoned `capture` mutex, or `Closed` during finalization.
    /// - Every `Capture::start` error: `InFlight`, `NoFreeCheckpointSlot`, `TooManyEntries` (`eligible > policy.n_max()`), `InvalidConfig`, `CounterExhausted`, `Allocation`.
    pub fn try_start_capture(
        &self,
        policy: &mut super::recovery::CapturePolicy,
        now: u64,
        planned_restart: bool,
        fill_stopped: bool,
        checkpoint_slot_free: bool,
    ) -> Result<Option<super::recovery::CaptureStarted>, CaptureError> {
        if !policy.due(now, planned_restart, fill_stopped) {
            return Ok(None);
        }
        let slots = self
            .live_pool()
            .ok_or(CaptureError::Closed)?
            .records()
            .len();
        if slots > policy.slot_bound() {
            return Err(CaptureError::SlotBoundExceeded);
        }
        let counter =
            self.begin_capture(policy.n_max(), checkpoint_slot_free, policy.side_cap())?;
        policy.started(now)?;
        Ok(Some(counter))
    }
    #[cfg(test)]
    pub(crate) fn start_capture(
        &self,
        n_max: usize,
        checkpoint_slot_free: bool,
        q_cap: usize,
    ) -> Result<u32, CaptureError> {
        let cap = super::recovery::SideCap {
            entries: q_cap,
            words: usize::MAX,
        };
        self.begin_capture(n_max, checkpoint_slot_free, cap)
            .map(|started| started.counter)
    }
    // Reads `t0` (the current `insert_step`) and `eligible` under the `capture` mutex, the same mutex every membership change holds, so the pass starts from one consistent membership. The epoch is read before the readiness word: an attach advances it after raising its gate, so a start that reads the advanced epoch also reads the gate and refuses. A load commit advances it before `LoadComplete`, so the second read refuses a start whose readiness read follows the commit and whose first epoch read precedes it.
    fn begin_capture(
        &self,
        n_max: usize,
        checkpoint_slot_free: bool,
        cap: super::recovery::SideCap,
    ) -> Result<super::recovery::CaptureStarted, CaptureError> {
        let pool = self.live_pool().ok_or(CaptureError::Closed)?;
        let mut capture = pool.capture_lock()?;
        let epoch = pool.epoch();
        #[cfg(test)]
        if REPLACE_AFTER_EPOCH.with(std::cell::Cell::get) {
            pool.replaced();
        }
        // An attached volume's unfinished bootstrap can still install restored slots at steps above any `t0` read now.
        let (state, gate) = self.readiness.state_and_attach_gate();
        if gate || state == super::readiness::State::Loading || pool.epoch() != epoch {
            return Err(CaptureError::Unavailable);
        }
        let t0 = pool.insert_step.load(Ordering::Relaxed);
        let counter = capture.start(
            (t0, epoch),
            pool.records().len(),
            pool.eligible.load(Ordering::Relaxed),
            n_max,
            checkpoint_slot_free,
            cap,
        )?;
        // The start sealed the open block, which now waits for its write.
        pool.suffix_wake(&capture.suffix);
        Ok(super::recovery::CaptureStarted { counter, t0 })
    }
    #[cfg(test)]
    pub fn capture_next(&self, counter: u32) -> Result<Option<CaptureEntry>, CaptureError> {
        let mut found = None;
        self.capture_visit(counter, 1, |entry| found = Some(entry.clone()))?;
        Ok(found)
    }
    /// `capture_visit` holds the `capture` mutex and pool gate so entry copying and cursor advancement share one membership state.
    ///
    /// `sink` runs under the `capture` mutex and pool gate, so membership changes it attempts fail their nonblocking lock acquisition.
    ///
    /// Returns the length of the walked slot range, empty slots included; `0` once the cursor has reached the slot count.
    ///
    /// # Errors
    ///
    /// A zero `max` reports `InvalidConfig`. Access reports `Unavailable`, `Poisoned` or `Closed`; pass checks report `Superseded`, `Idle` or `Abandoned`; an entry copy whose extent vector cannot be reserved reports `Allocation` and abandons the pass.
    pub fn capture_visit(
        &self,
        counter: u32,
        max: usize,
        mut sink: impl FnMut(&CaptureEntry),
    ) -> Result<usize, CaptureError> {
        let pool = self.live_pool().ok_or(CaptureError::Closed)?;
        let mut capture = pool.capture_lock()?;
        let mut access = pool.try_lock_quiet()?;
        capture.check_counter(counter)?;
        let (t0, slots) = capture.batch(max)?;
        let (end, visited) = (slots.end, slots.len());
        let mut tables = access.tables();
        let mut entry = std::mem::take(&mut capture.scratch);
        let in_sink = std::cell::Cell::new(false);
        let walked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            for (slot, step) in slots.clone().zip(&pool.steps()[slots]) {
                // The wrapping comparison accepts step values in `1..=t0`.
                if step.load(Ordering::Relaxed).wrapping_sub(1) < t0 {
                    pool.capture_entry_into(&mut tables, slot, &mut entry)?;
                    in_sink.set(true);
                    sink(&entry);
                    in_sink.set(false);
                }
            }
            Ok(())
        }));
        match walked {
            Ok(Ok(())) => {
                capture.scratch = entry;
                capture.advance(end)?;
                Ok(visited)
            }
            Ok(Err(error)) => {
                capture.abandon();
                Err(error)
            }
            // A table-walk panic poisons both locks here before it resumes, because a guard taken by a thread that was already unwinding releases unpoisoned on drop.
            Err(payload) if !in_sink.get() => {
                capture.poison();
                access.poison();
                std::panic::resume_unwind(payload)
            }
            Err(payload) => {
                // Dropping `access` and `capture` before resuming the `sink` panic preserves both locks' unpoisoned state.
                capture.abandon();
                drop((access, capture));
                std::panic::resume_unwind(payload)
            }
        }
    }
    /// `capture_side_len` returns the side-list length observed under capture serialization for pass `counter`.
    ///
    /// # Errors
    ///
    /// Contention is retryable (`Unavailable`); a poisoned mutex and finalization are terminal (`Poisoned`, `Closed`). A stale handle reports `Superseded`, an ended pass `Idle`, and an abandoned pass `Abandoned`.
    pub fn capture_side_len(&self, counter: u32) -> Result<usize, CaptureError> {
        let pool = self.live_pool().ok_or(CaptureError::Closed)?;
        let capture = pool.capture_lock()?;
        capture.check_counter(counter)?;
        capture.side_len()
    }
    /// `capture_saved` takes the side list: members at `t0` removed before the cursor reached them. A second call returns an empty list.
    ///
    /// # Errors
    ///
    /// Access can report `Unavailable`, `Poisoned` or `Closed`; pass validation can report `Superseded`, `Idle`, `Abandoned` or `Incomplete`.
    pub fn capture_saved(&self, counter: u32) -> Result<Vec<CaptureEntry>, CaptureError> {
        let pool = self.live_pool().ok_or(CaptureError::Closed)?;
        let mut capture = pool.capture_lock()?;
        capture.check_counter(counter)?;
        capture.take_saved()
    }
    /// Runs `submit` for pass `counter` while holding the `capture` mutex, so a membership change attempted during `submit` fails its nonblocking try and the unit's contents stay consistent with the pass.
    ///
    /// The callback performs a bounded, nonblocking handoff of one prepared unit. Storage reentry observes the held capture mutex.
    ///
    /// # Errors
    ///
    /// Access reports `Unavailable`, `Poisoned` or `Closed`; pass checks report `Superseded`, `Idle` or `Abandoned`.
    /// A released pass reports `Released` before `submit` runs.
    pub fn submit_capture_unit<T>(
        &self,
        counter: u32,
        submit: impl FnOnce() -> T,
    ) -> Result<T, CaptureError> {
        let pool = self.live_pool().ok_or(CaptureError::Closed)?;
        let mut capture = pool.capture_lock()?;
        capture.check_counter(counter)?;
        capture.submission_allowed()?;
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(submit)) {
            Ok(value) => Ok(value),
            Err(payload) => {
                capture.abandon();
                drop(capture);
                std::panic::resume_unwind(payload)
            }
        }
    }
    /// The proof that pass `counter`'s cut may publish as a checkpoint of `tenure`, taken under the `capture` mutex and returned with the mutex released, so the Publish's store round trip holds no membership change. `tenure` is the shard and session of the tenure this storage serves, as the caller holds them: the proof carries them, and a Publish takes the proof only for a stage of that shard and session. A returned proof requires the tenure's suffix, so every later logical membership change is recorded once the log opens and refused until then; the caller mints the proof directly before its Publish.
    ///
    /// # Errors
    ///
    /// Access reports `Unavailable`, `Poisoned` or `Closed`; pass checks report `Superseded`, then the refusals of `Capture::intact` under the current capture epoch.
    pub fn cut_intact(
        &self,
        tenure: (crate::net::ownership::Shard, u64),
        counter: u32,
    ) -> Result<super::recovery::CutIntact, CaptureError> {
        let pool = self.live_pool().ok_or(CaptureError::Closed)?;
        let mut capture = pool.capture_lock()?;
        capture.check_counter(counter)?;
        let proof = capture.intact(tenure, pool.epoch())?;
        // A published proof makes the membership recoverable from its checkpoint, so every later change to it is
        // recorded in the tenure's suffix or refused.
        capture.suffix.require();
        Ok(proof)
    }
    /// The storage's capture epoch at this read, the value a Publish's caller passes for comparison with its proof's epoch.
    pub fn capture_epoch(&self) -> super::recovery::CaptureEpoch {
        self.pool.epoch()
    }
    /// Requires the tenure's suffix before its membership is exposed, as a warm install and a minted proof do: from
    /// this call until [`open_suffix`](super::checkpoint::open_suffix) opens the log, and after a close, every logical
    /// membership change refuses `History`, so none is acknowledged unrecorded.
    ///
    /// # Errors
    ///
    /// `Unavailable` for a busy mutex, which the caller retries, `Poisoned` for a poisoned one, `Closed` during
    /// finalization.
    #[cfg(test)]
    pub(crate) fn require_suffix(&self) -> Result<(), CaptureError> {
        self.with_suffix(super::recovery::suffix::SuffixLog::require)
    }
    /// Runs `f` over the tenure's suffix log under one try of the `capture` mutex, so no membership change or capture
    /// start interleaves with it, then publishes the log's next due time to the delta writer; `f` makes no store call.
    ///
    /// # Errors
    ///
    /// `Unavailable` for a busy mutex, `Poisoned` for a poisoned one, `Closed` during finalization.
    pub(crate) fn with_suffix<T>(
        &self,
        f: impl FnOnce(&mut super::recovery::suffix::SuffixLog) -> T,
    ) -> Result<T, CaptureError> {
        let pool = self.live_pool().ok_or(CaptureError::Closed)?;
        let mut capture = pool.capture_lock()?;
        let result = f(&mut capture.suffix);
        pool.suffix_wake(&capture.suffix);
        Ok(result)
    }

    /// The tenure's suffix backlog under one try of the `capture` mutex, with the oldest pending block aged at a
    /// platform clock sample taken under that guard only while a block is pending; `None` when the pool is closed, the
    /// try finds the mutex held or poisoned, or admission is closed. The try holds the mutex for the read, so a
    /// concurrent taker's own single try can find it held and retry on its next call.
    pub(crate) fn suffix_backlog(&self) -> Option<super::recovery::suffix::SuffixBacklog> {
        let pool = self.live_pool()?;
        let capture = pool.capture_lock().ok()?;
        capture.suffix.backlog(|| self.platform.now_ticks())
    }
    /// Ends pass `counter`, abandoned or complete, then calls `policy.finished()` so its triggers can start the next pass.
    ///
    /// # Errors
    ///
    /// Access reports `Unavailable`, `Poisoned` or `Closed`; pass checks report `Superseded` or `Idle`. On every error `policy` is unchanged.
    pub fn finish_capture(
        &self,
        policy: &mut super::recovery::CapturePolicy,
        counter: u32,
    ) -> Result<(), CaptureError> {
        let pool = self.live_pool().ok_or(CaptureError::Closed)?;
        let mut capture = pool.capture_lock()?;
        capture.check_counter(counter)?;
        let saved = capture.finish();
        drop(capture);
        drop(saved);
        policy.finished();
        Ok(())
    }
}
