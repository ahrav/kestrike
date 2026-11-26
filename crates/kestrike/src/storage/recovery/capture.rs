//! One capture pass reproduces the membership as it stood at `t0`, the `insert_step` reading when the pass started, while insertions and removals continue.
//!
//! # Snapshot rule
//!
//! A slot belongs to the snapshot exactly when its step is nonzero and `step <= t0`. The pass walks slots in order with a cursor: `batch` names the next run of at most `max` slots from the cursor and `t0`, the caller emits each member of the run that meets the rule, and `advance` moves the cursor past the run. A snapshot member removed before the cursor reaches its slot is saved by `removed` into the side list, so the emitted entries plus the side list equal the `t0` membership.
//!
//! # Side-list bound
//!
//! The side list holds at most `cap.entries` entries and `cap.words` extent words. A removal that needs saving and would exceed either bound abandons the pass while retaining its saved entries, so the overflowing removal frees at most its own entry. Every later `batch`, `advance`, `take_saved` and `submission_allowed` fails `Abandoned` until `finish`, which hands the saved entries to the caller.
//!
//! # Publication
//!
//! Removing a snapshot member after `t0` unrecorded in the tenure's suffix marks the pass `Released`, including members saved in the side list or already passed by the cursor. The member's units may return to the allocator while the cut still names them, so `Released` blocks later proofs through [`Capture::intact`]. A removal the suffix recorded lies at or above the pass's cut and leaves the pass publishable: its unit may return once that record's block is durable, and the replay of the suffix from the cut excludes the entry, so the cut is a recovery cut only together with that replay. A proof covers membership at the moment it was taken. It names the shard and session its caller took it under beside its pass counter, and a Publish accepts it only for a checkpoint of that shard, session and capture number.
//!
//! # Capture epoch
//!
//! An attach, an install of restored slots and a load commit replace the membership wholesale, outside the step rule, and each advances the storage's [`CaptureEpoch`]. A pass records the epoch it started under, and its proof carries it: [`Capture::intact`] refuses `Replaced` for a pass of an earlier epoch, and a Publish refuses a proof whose epoch differs from the epoch its caller read, so a proof of a membership that a replacement superseded before that read publishes nothing. The Publish's caller keeps every replacement from running between that read and the settlement of the Publish's write, and under that serialization every published proof describes the membership its epoch names. An install of restored slots also abandons the pass in flight, so its progress calls report `Abandoned`.
//!
//! # Serialization
//!
//! The caller serializes `start`, `batch`, `advance`, `removed` and the step reads they consume under one boundary, so `t0`, the membership count and every visited or removed step describe one consistent membership.

use crate::net::ownership::Shard;

use super::super::allocation::AllocationId;

/// Whether the planted defect that drops the side-list bound is set; false outside tests.
fn uncapped_side_list() -> bool {
    #[cfg(test)]
    return NO_SIDE_CAP.with(std::cell::Cell::get);
    #[cfg(not(test))]
    false
}

#[cfg(test)]
thread_local! {
    /// A planted defect: a removal past the side list's bound is saved.
    pub(crate) static NO_SIDE_CAP: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// One checkpointed member: the slot's key, identity, expiry and owned extents, copied while the slot still owns them.
///
/// Each extent word's length is rounded up to whole I/O units; `tail` holds the record's byte remainder inside the last one.
#[derive(Debug, Default, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub struct CaptureEntry {
    /// The object key the index maps to this member.
    pub key: [u8; 32],
    /// Record tag of the member's allocation: `slot << 32 | incarnation`.
    pub allocation: u64,
    /// Volume session the member's record header carries.
    pub session: u64,
    /// Cache version the member's record header carries.
    pub version: u64,
    /// Portable expiry deadline, paired with `lifetime_ms`.
    pub deadline_ns: u64,
    /// Portable expiry lifetime, paired with `deadline_ns`.
    pub lifetime_ms: u32,
    /// Bytes of the record's last I/O unit that the record occupies; `0` means the whole unit.
    pub tail: u16,
    /// `ExtentLocator` bits of every extent the member owns, in sequence order; a loadable entry has at least one.
    pub extents: Vec<u64>,
}
impl Clone for CaptureEntry {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            extents: self.extents.clone(),
            ..*self
        }
    }

    /// When `self.extents.capacity() == source.extents.len()`, `clone_from` reuses the existing buffer to copy the words without allocating. Otherwise, `clone_from` replaces `self.extents` with `source.extents.clone()`, releasing the old buffer and any spare capacity it had.
    #[inline]
    fn clone_from(&mut self, source: &Self) {
        let Self {
            key,
            allocation,
            session,
            version,
            deadline_ns,
            lifetime_ms,
            tail,
            extents,
        } = source;
        self.key = *key;
        self.allocation = *allocation;
        self.session = *session;
        self.version = *version;
        self.deadline_ns = *deadline_ns;
        self.lifetime_ms = *lifetime_ms;
        self.tail = *tail;
        if self.extents.capacity() == extents.len() {
            self.extents.clear();
            self.extents.extend_from_slice(extents);
        } else {
            self.extents = extents.clone();
        }
    }
}
impl CaptureEntry {
    /// The slot index encoded in `allocation`.
    pub fn slot(&self) -> usize {
        AllocationId::of_record_tag(self.allocation).slot_index()
    }
}
/// Side-list capacity of one pass: at most `entries` saved removals holding at most `words` extent words in total.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SideCap {
    pub entries: usize,
    pub words: usize,
}
/// Refusals of the capture core, its policy and the `Storage` capture surface. `Unavailable` is the only retryable access refusal; `Closed` and `Poisoned` are terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureError {
    /// A pass is already in flight.
    InFlight,
    /// The caller reported no free checkpoint slot to write into: a stage holds the reservation, the layout fails its
    /// floor, or every slot is possibly named or quarantined.
    NoFreeCheckpointSlot,
    /// The membership count exceeds `n_max`.
    TooManyEntries,
    /// The next pass counter would exceed `u32::MAX`.
    CounterExhausted,
    /// A size or interval argument is zero, inconsistent, or overflows a `u64` duration.
    InvalidConfig,
    /// The pool has more slots than the policy's `slot_bound` sized its reserve for.
    SlotBoundExceeded,
    /// The pool is no longer live: storage finalization has begun.
    Closed,
    /// The `capture` mutex or the pool gate is poisoned; capture stays unavailable.
    Poisoned,
    /// The policy's worst-case capture memory exceeds the engine budget.
    Memory(super::super::ledger::EngineBudgetExceeded),
    /// The allocator refused a side-list or entry copy reservation; the pass is abandoned.
    Allocation,
    /// A nonblocking try at the `capture` mutex or the pool gate found it held, or a start found an attached volume's gate
    /// running or its load unfinished, while a bootstrap may still install restored slots; a retry may succeed.
    Unavailable,
    /// The pass overflowed its side list, in entries or extent words, or a restored install replaced the membership,
    /// and the pass was abandoned.
    Abandoned,
    /// The membership was replaced wholesale after the pass started, so its cut no longer describes the membership.
    Replaced,
    /// `visit` was given a slot other than the cursor, past the slot count, or a member whose entry names a different slot.
    Cursor,
    /// No pass is in flight.
    Idle,
    /// The counter belongs to an earlier pass.
    Superseded,
    /// The cursor has not passed every slot.
    Incomplete,
    /// A unit was submitted before its due time.
    NotDue,
    /// A member of the pass's snapshot left the membership after `t0` through a removal the suffix did not record, so
    /// its units may return to the allocator while the cut still names them: the pass cannot publish.
    Released,
}
/// The count of wholesale membership replacements a storage has made: attaches, restored installs and load commits.
/// A pass and its proof carry the epoch the pass started under.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CaptureEpoch(pub(crate) u64);

/// A started pass: the counter every later call must present, and the `insert_step` reading the snapshot is cut at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureStarted {
    pub counter: u32,
    pub t0: u64,
}
// One in-flight pass. `saved` is the side list of removed, unvisited snapshot members and holds at most `cap` entries.
#[derive(Debug)]
struct Pass {
    t0: u64,
    epoch: CaptureEpoch,
    slots: usize,
    // next slot `visit` accepts; slots below it are done
    cursor: usize,
    cap: usize,
    // `word_cap` bounds the side list's total extent words; `words` tracks that total.
    word_cap: usize,
    words: usize,
    saved: Vec<CaptureEntry>,
    // set by the removal that would exceed `cap`; cleared only by `finish`
    abandoned: bool,
    // set when a member with step `<= t0` leaves the membership unrecorded in the suffix
    released: bool,
    // the suffix LSN sealed at `t0`
    cut: u64,
}

/// Proof that pass `counter` walked every slot, is unabandoned, and that every member of its snapshot either was still
/// a member when the proof was taken or left through a removal the tenure's suffix recorded at or above the pass's
/// cut. A unit such a member's entry names may already be reused once its record's block is durable; the replay of
/// the suffix from the cut excludes that entry, so the cut is a recovery cut only together with that replay. The proof names the
/// checkpoint it publishes: the shard and session of the tenure its caller took it under, and the pass counter as the
/// capture number. It carries the epoch the pass started under, which a Publish compares with the epoch its caller
/// reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CutIntact {
    tenure: (Shard, u64),
    counter: u32,
    cut: u64,
    epoch: CaptureEpoch,
}

impl CutIntact {
    /// The shard and session of the tenure the proof was taken under.
    pub fn tenure(self) -> (Shard, u64) {
        self.tenure
    }
    /// The pass the proof names, which is the capture number of the checkpoint it publishes.
    pub fn counter(self) -> u32 {
        self.counter
    }

    /// The suffix LSN the pass sealed at its `t0`: the checkpoint's replay starts there.
    pub fn cut(self) -> u64 {
        self.cut
    }

    /// The capture epoch the pass started under.
    pub fn epoch(self) -> CaptureEpoch {
        self.epoch
    }
}
/// Pass state and the monotonic pass counter. See the module documentation for the snapshot rule.
#[derive(Debug, Default)]
pub struct Capture {
    // count of passes ever started; `start` keeps it below `1 << 32`
    counter: u64,
    pass: Option<Pass>,
    pub(crate) scratch: CaptureEntry,
    /// The tenure's mutation suffix, guarded by the same mutex as the membership so its sequence is the
    /// linearization order of membership changes and capture starts.
    pub(crate) suffix: super::suffix::SuffixLog,
    // set by `poison`, never cleared
    poisoned: bool,
}
impl Capture {
    /// Makes capture serialization terminal after a table-walk panic: the in-flight pass is abandoned, the suffix log closed, and [`poisoned`](Self::poisoned) true from here on. The retirement, the removal, the fill publication and the warm install's fold run it through `PoisonOnUnwind` as the walk's panic unwinds, and `capture_visit` runs it after catching the panic and before resuming it. Each runs it itself because a mutex guard taken by a thread that was already unwinding leaves its mutex unpoisoned on drop.
    pub(crate) fn poison(&mut self) {
        self.abandon();
        self.suffix.close();
        self.poisoned = true;
    }
    /// Whether a holder called [`poison`](Self::poison).
    pub(crate) fn poisoned(&self) -> bool {
        self.poisoned
    }
    /// The counter of the most recently started pass; `0` before the first.
    #[cfg(test)]
    pub(crate) fn counter(&self) -> u32 {
        self.counter as u32
    }
    /// Checks that `counter` names the current pass and that a pass is in flight. An abandoned pass passes this check; the next progress call reports `Abandoned`.
    ///
    /// # Errors
    ///
    /// - `Superseded` if `counter` differs from the current counter.
    /// - `Idle` if no pass is in flight.
    pub fn check_counter(&self, counter: u32) -> Result<(), CaptureError> {
        if u64::from(counter) != self.counter {
            return Err(CaptureError::Superseded);
        }
        self.pass.as_ref().ok_or(CaptureError::Idle).map(|_| ())
    }
    /// Starts a pass over `slots` slots whose snapshot is the `entries` members with step `<= t0`, with a side list bounded by `cap`, and seals the suffix's cut for it. The pass records `epoch`, the storage's capture epoch.
    ///
    /// `t0`, `entries`, and every later `visit` and `removed` step must be read under the same serialization boundary, and `epoch` no later than the readiness check that admits the start.
    ///
    /// # Errors
    ///
    /// Checked in this order:
    /// - `InFlight` if a pass is in flight.
    /// - `NoFreeCheckpointSlot` if `checkpoint_slot_free` is false.
    /// - `TooManyEntries` if `entries > n_max`.
    /// - `InvalidConfig` if `slots == 0`, either bound of `cap` is zero, or `entries > slots`.
    /// - `CounterExhausted` if the next counter would exceed `u32::MAX`; the counter is unchanged.
    /// - `Allocation` if the side-list reservation fails; the counter is unchanged.
    pub fn start(
        &mut self,
        (t0, epoch): (u64, CaptureEpoch),
        slots: usize,
        entries: usize,
        n_max: usize,
        checkpoint_slot_free: bool,
        cap: SideCap,
    ) -> Result<u32, CaptureError> {
        if self.pass.is_some() {
            return Err(CaptureError::InFlight);
        }
        if !checkpoint_slot_free {
            return Err(CaptureError::NoFreeCheckpointSlot);
        }
        if entries > n_max {
            return Err(CaptureError::TooManyEntries);
        }
        if slots == 0 || cap.entries == 0 || cap.words == 0 || entries > slots {
            return Err(CaptureError::InvalidConfig);
        }
        let counter = self
            .counter
            .checked_add(1)
            .filter(|c| *c < 1 << 32)
            .ok_or(CaptureError::CounterExhausted)?;
        let mut saved = Vec::new();
        saved
            .try_reserve_exact(cap.entries.min(entries))
            .map_err(|_| CaptureError::Allocation)?;
        self.counter = counter;
        self.pass = Some(Pass {
            t0,
            epoch,
            slots,
            cursor: 0,
            cap: cap.entries,
            word_cap: cap.words,
            words: 0,
            saved,
            abandoned: false,
            released: false,
            cut: self.suffix.seal_cut(),
        });
        Ok(counter as u32)
    }
    /// The next slot `visit` accepts.
    ///
    /// # Errors
    ///
    /// `Idle` with no pass in flight; `Abandoned` after a side-list overflow or a restored install.
    #[cfg(test)]
    pub fn cursor(&self) -> Result<usize, CaptureError> {
        Ok(self.active()?.cursor)
    }
    fn active(&self) -> Result<&Pass, CaptureError> {
        let pass = self.pass.as_ref().ok_or(CaptureError::Idle)?;
        if pass.abandoned {
            return Err(CaptureError::Abandoned);
        }
        Ok(pass)
    }
    fn active_mut(&mut self) -> Result<&mut Pass, CaptureError> {
        let pass = self.pass.as_mut().ok_or(CaptureError::Idle)?;
        if pass.abandoned {
            return Err(CaptureError::Abandoned);
        }
        Ok(pass)
    }
    /// Whether removing `slot`, whose step is `insert_step`, must first pass its entry to `removed`: true when a live, unabandoned pass has `insert_step` nonzero and `<= t0` and the cursor has not passed `slot`.
    pub fn needs_save(&self, insert_step: u64, slot: usize) -> bool {
        self.pass.as_ref().is_some_and(|p| {
            !p.abandoned && insert_step != 0 && insert_step <= p.t0 && slot >= p.cursor
        })
    }
    /// Saves `entry`, a member being removed with pre-removal step `insert_step`, into the side list when `needs_save` holds for it; every other call is a no-op.
    ///
    /// Call before the member's units are released, so `entry.extents` still describes units no other slot owns.
    ///
    /// When the side list already holds `cap.entries` entries, or `entry`'s extent words would take it past `cap.words`, the pass is abandoned instead and later progress calls fail `Abandoned`.
    pub fn removed(&mut self, insert_step: u64, entry: CaptureEntry) {
        if !self.needs_save(insert_step, entry.slot()) {
            return;
        }
        let Ok(pass) = self.active_mut() else {
            return;
        };
        let words = pass.words.saturating_add(entry.extents.len());
        if (pass.saved.len() == pass.cap || words > pass.word_cap) && !uncapped_side_list() {
            pass.abandoned = true;
        } else {
            pass.words = words;
            pass.saved.push(entry);
        }
    }
    /// Advances the cursor past `slot` and returns `member`'s entry when its step is nonzero and `<= t0`; `Ok(None)` for an empty slot or a member inserted after `t0`.
    ///
    /// `member` is `slot`'s current `(step, entry)`, read under the same boundary as `start` and `removed`.
    ///
    /// # Errors
    ///
    /// - `Idle` with no pass in flight; `Abandoned` after a side-list overflow or a restored install.
    /// - `Cursor` if `slot` is not the cursor, `slot >= slots`, or `member`'s entry names a different slot. The cursor is unchanged.
    #[cfg(test)]
    pub fn visit(
        &mut self,
        slot: usize,
        member: Option<(u64, CaptureEntry)>,
    ) -> Result<Option<CaptureEntry>, CaptureError> {
        let pass = self.active_mut()?;
        if slot != pass.cursor || slot >= pass.slots {
            return Err(CaptureError::Cursor);
        }
        if member.as_ref().is_some_and(|(_, e)| e.slot() != slot) {
            return Err(CaptureError::Cursor);
        }
        pass.cursor += 1;
        Ok(member
            .filter(|(step, _)| *step != 0 && *step <= pass.t0)
            .map(|(_, entry)| entry))
    }
    /// The returned `t0` bounds the snapshot, and the range identifies the next batch of visits: empty exactly when the cursor has reached the slot count.
    ///
    /// # Errors
    ///
    /// `InvalidConfig` if `max == 0`; `Idle` with no pass in flight; `Abandoned` after a side-list overflow or a restored install.
    pub fn batch(&self, max: usize) -> Result<(u64, std::ops::Range<usize>), CaptureError> {
        if max == 0 {
            return Err(CaptureError::InvalidConfig);
        }
        let pass = self.active()?;
        Ok((
            pass.t0,
            pass.cursor..pass.slots.min(pass.cursor.saturating_add(max)),
        ))
    }
    /// The caller must have emitted every member of the skipped slots whose step is nonzero and `<= t0`.
    ///
    /// # Errors
    ///
    /// - `Idle` with no pass in flight; `Abandoned` after a side-list overflow or a restored install.
    /// - `Cursor` if `end` lies below the cursor or past the slot count; the cursor is unchanged.
    pub fn advance(&mut self, end: usize) -> Result<(), CaptureError> {
        let pass = self.active_mut()?;
        if end < pass.cursor || end > pass.slots {
            return Err(CaptureError::Cursor);
        }
        pass.cursor = end;
        Ok(())
    }
    /// Takes the side list, leaving it empty.
    ///
    /// # Errors
    ///
    /// - `Idle` with no pass in flight; `Abandoned` after a side-list overflow or a restored install.
    /// - `Incomplete` while the cursor has not reached `slots`.
    pub fn take_saved(&mut self) -> Result<Vec<CaptureEntry>, CaptureError> {
        let pass = self.active_mut()?;
        if pass.cursor != pass.slots {
            return Err(CaptureError::Incomplete);
        }
        Ok(std::mem::take(&mut pass.saved))
    }
    /// `Ok` while the pass in flight is active and can still publish.
    ///
    /// # Errors
    ///
    /// `Idle` with no pass in flight; `Abandoned` after a side-list overflow or a restored install.
    /// `Released` after an unrecorded removal of a snapshot member.
    pub fn submission_allowed(&self) -> Result<(), CaptureError> {
        match self.active()?.released {
            true => Err(CaptureError::Released),
            false => Ok(()),
        }
    }
    /// Entries in the side list.
    ///
    /// # Errors
    ///
    /// `Idle` with no pass in flight; `Abandoned` after a side-list overflow or a restored install.
    pub fn side_len(&self) -> Result<usize, CaptureError> {
        Ok(self.active()?.saved.len())
    }
    /// Records that a member whose step was `step` left the membership, its removal `recorded` in the suffix or not:
    /// an unrecorded member of the snapshot makes the pass unpublishable. A recorded removal lies at or above the
    /// pass's cut, which every record after the start does, so a replay from the cut excludes the member and the
    /// pass stays publishable.
    pub(crate) fn left(&mut self, step: u64, recorded: bool) {
        if let Some(pass) = self.pass.as_mut()
            && !recorded
            && step != 0
            && step <= pass.t0
        {
            pass.released = true;
        }
    }
    /// Returns the in-flight pass's publication proof, which names `tenure`, the pass counter and the pass's epoch. The
    /// proof carries `tenure` unchanged; a Publish accepts it only for a stage whose checkpoint names that shard and
    /// session, and only when the epoch its caller reads equals `epoch`.
    ///
    /// # Errors
    ///
    /// `Idle` with no pass in flight, `Abandoned` after an overflow or a restored install, ahead of an epoch check,
    /// `Replaced` when the pass started under an epoch other than `epoch`, the current one, `Released` once a member
    /// of the snapshot left the membership through a removal the suffix did not record, `Incomplete`
    /// while the cursor has not reached the slot count.
    pub fn intact(
        &self,
        tenure: (Shard, u64),
        epoch: CaptureEpoch,
    ) -> Result<CutIntact, CaptureError> {
        let pass = self.active()?;
        if pass.epoch != epoch {
            return Err(CaptureError::Replaced);
        }
        if pass.released {
            return Err(CaptureError::Released);
        }
        if pass.cursor != pass.slots {
            return Err(CaptureError::Incomplete);
        }
        Ok(CutIntact {
            tenure,
            counter: self.counter as u32,
            cut: pass.cut,
            epoch,
        })
    }
    /// Records `cut` as the pass's suffix cut.
    #[cfg(test)]
    pub(crate) fn cut_at(&mut self, cut: u64) {
        if let Some(pass) = self.pass.as_mut() {
            pass.cut = cut;
        }
    }
    /// Marks the in-flight pass abandoned, as an overflow does; a no-op with no pass in flight.
    pub(crate) fn abandon(&mut self) {
        if let Some(pass) = self.pass.as_mut() {
            pass.abandoned = true;
        }
    }
    /// Ends the pass, abandoned or complete, retains the counter, and returns the side list it still held so the caller can drop it after releasing its locks.
    #[must_use]
    pub fn finish(&mut self) -> Vec<CaptureEntry> {
        self.pass.take().map_or_else(Vec::new, |pass| pass.saved)
    }
    #[cfg(test)]
    pub(crate) fn at_counter(counter: u64) -> Self {
        Self {
            counter,
            ..Self::default()
        }
    }
}
