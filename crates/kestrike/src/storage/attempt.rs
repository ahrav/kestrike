//! Bounded fill authority: at most one live attempt per full key per index
//! shard, granted from the shard's fixed fill table in the root mapping, and
//! the funded service that returns departed records to Free.
//!
//! [`Storage::begin_fill`] refuses a closed cutoff before its hash pass,
//! takes the key's shard gate within the caller's attempts, refuses again on
//! a closed cutoff read under the gate, and scans at most
//! `F[s]` records: an occupied record whose association is current and whose
//! key equals the caller's refuses `InProgress`, whether or not its owner has
//! departed, since the record is that key's attempt until service frees it; no
//! Free record refuses `FillSlotsFull`, whatever other shards hold; a shard
//! whose next serial would pass [`fill::SERIAL_MAX`] refuses `AttemptExhausted` for
//! good, before any scan, while abort, invalidation and service keep working.
//! A grant writes the key and the occupied word under the gate and advances
//! the shard's serial. The grant is metadata only: it reserves no storage,
//! writes no byte and publishes nothing, and the shard's sequence is not
//! read, so a terminal shard still grants.
//!
//! The [`FillAttempt`] owner borrows the storage and is not `Clone`; its
//! identity is the borrowed storage, the shard and the serial, never the
//! record position. Aborting or dropping it departs: one `Release`
//! compare-exchange on its record's state word, retried once at most past a
//! concurrent revocation, taken without the gate and without waiting, after
//! which the owner touches nothing. A departed record
//! stays occupied, and a same-key `begin_fill` still refuses `InProgress`,
//! until a service pass observes the departure with `Acquire`, as a load or
//! as a fence behind its run of loads, with the row's observer count at zero,
//! and releases the record.
//!
//! [`Storage::service_fills`] runs while the owner is live, open or closed:
//! paid gate attempts within the caller's tries, then at most one pass over
//! the table from its persistent cursor, each record prepaid as one visit and
//! one possible release. A live record and a record the shard's custody names
//! are skipped, never revoked; a departed record first has the index place
//! its place word names refunded and is then released with one plain
//! store, since after its owner's departure only the gate holder writes the
//! word. A record the allowance cannot pay for ends the pass with the cursor
//! on it. Every count in the report is this call's own.
//!
//! Compile-time misuse: an attempt cannot outlive the storage it borrows.
//!
//! ```compile_fail,E0597
//! # use kestrike::storage::*;
//! # fn f(storage: Storage<LinuxPlatform>) {
//! let attempt;
//! {
//!     let storage = storage;
//!     let mut budget = WorkBudget::new(64);
//!     attempt = storage.begin_fill(&[0x5A; 32], kestrike::storage::CacheVersion(0), 3, &mut budget).ok();
//! }
//! drop(attempt);
//! # }
//! ```
//!
//! An attempt cannot be cloned or copied.
//!
//! ```compile_fail,E0599
//! # use kestrike::storage::*;
//! # fn f(attempt: FillAttempt<'_, LinuxPlatform>) {
//! let _twin = attempt.clone();
//! # }
//! ```
//!
//! The positive twin of each: a borrowed attempt is used and then aborted.
//!
//! ```no_run
//! # use kestrike::storage::*;
//! # fn f(storage: &Storage<LinuxPlatform>) -> Result<(), BeginError> {
//! let mut budget = WorkBudget::new(64);
//! let attempt = storage.begin_fill(&[0x5A; 32], kestrike::storage::CacheVersion(0), 3, &mut budget)?;
//! let _serial = attempt.serial();
//! attempt.abort();
//! # Ok(())
//! # }
//! ```
//!
//! Stable rustdoc does not check the error codes above; they record the
//! intended causes for a reader, and `cargo +nightly test --doc` verifies
//! them.

use std::sync::atomic::{AtomicU64, Ordering};

use super::allocation::AllocationId;
use super::budget::{WorkBudget, WorkKind};
use super::fill::{self, FillSerial, Record};
use super::image::{FillControl, FillCustody, FillImage};
use super::lease::{Credit, release_right, return_credit};
use super::os::Platform;
use super::owner::Storage;
use super::place_claim;
use super::prefetch::RMW_WAITS_FOR_HINTS;
use super::probe::{self, Primitive};
use super::publish::{Refusal, take_gate};
use super::row::FillRow;
use crate::index::{Key, RouteError, ShardIndex};

/// Why no attempt was granted. No record, serial, mapping or sequence changed;
/// a failed gate try counts in the shard's telemetry, and `Corrupt` poisons
/// the gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BeginError {
    /// No live index: none was configured, or the owner is drained.
    NoIndex,
    /// Admission is closed.
    Closed,
    /// The budget could not pay for the hash pass, the gate try, a record
    /// visit, a key comparison or the grant.
    BudgetExhausted,
    /// Every paid gate attempt found the shard busy or poisoned, the attempt
    /// allowance was zero, or no shard is enabled.
    Contended,
    /// The key's shard holds an occupied record associated with this key,
    /// including after its owner departs.
    InProgress,
    /// The key's shard has no Free record, or no fill table.
    FillSlotsFull,
    /// The shard's serial counter has issued every serial the encoding can
    /// carry; no further attempt on this shard is ever granted.
    AttemptExhausted,
    /// The shard's fill table is malformed; the gate is poisoned.
    Corrupt,
}

impl From<RouteError> for BeginError {
    fn from(error: RouteError) -> Self {
        match error {
            RouteError::BudgetExhausted => Self::BudgetExhausted,
            RouteError::NoEnabledShard => Self::Contended,
        }
    }
}

impl From<super::budget::BudgetExhausted> for BeginError {
    fn from(_: super::budget::BudgetExhausted) -> Self {
        Self::BudgetExhausted
    }
}

impl From<Refusal> for BeginError {
    fn from(refusal: Refusal) -> Self {
        match refusal {
            Refusal::BudgetExhausted => Self::BudgetExhausted,
            Refusal::Contended | Refusal::Poisoned => Self::Contended,
            Refusal::Corrupt => Self::Corrupt,
        }
    }
}

/// The client's per-key version of the object a fill writes: the version of its source read, which the record's header carries and the index names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CacheVersion(pub u64);

/// The unique, metadata-only authority to fill one full key on one shard.
/// Holding it promises no storage and no publication; it only excludes a
/// second current attempt on the same key until an invalidation revokes it,
/// or it departs and service frees its record.
#[must_use = "an attempt that is dropped departs at once; call abort() to end it deliberately"]
pub struct FillAttempt<'s, P: Platform> {
    storage: &'s Storage<P>,
    record: AttemptRecord<'s>,
}

impl<'s, P: Platform> FillAttempt<'s, P> {
    pub fn key(&self) -> &Key {
        &self.record.key
    }

    pub fn shard(&self) -> ShardIndex {
        self.record.shard
    }

    /// The checked serial that, with the shard and the borrowed storage, is
    /// this attempt's identity.
    pub fn serial(&self) -> u64 {
        self.record.serial.get()
    }

    pub(super) fn storage(&self) -> &'s Storage<P> {
        self.storage
    }

    /// The key's fingerprint, which the reservation's slot placement and the
    /// publication route from.
    pub(super) fn fingerprint(&self) -> u64 {
        self.record.fingerprint
    }

    /// Ends the attempt: departs its record and consumes the owner. Nothing
    /// is waited for and no gate is taken; the record frees through service.
    pub fn abort(self) {
        drop(self);
    }

    /// Transfers the undeparted record without running `Drop`; the receiver
    /// owes the departure.
    pub(super) fn into_record(self) -> AttemptRecord<'s> {
        let record = self.record;
        std::mem::forget(self);
        record
    }
}

/// An attempt's record identity; whichever owner holds it last owes the
/// departure. The state word is held by reference: the grant took it from
/// the shard's table under the gate, and the storage borrow keeps the table
/// mapped, so the departure needs no lookup.
#[derive(Clone, Copy)]
pub(super) struct AttemptRecord<'s> {
    pub(super) shard: ShardIndex,
    pub(super) state: &'s AtomicU64,
    /// The record's row, held by reference for the same reason as the state
    /// word, so the owner records its outcome without a lookup.
    pub(super) row: &'s FillRow,
    pub(super) serial: FillSerial,
    pub(super) key: Key,
    pub(super) version: CacheVersion,
    /// The key's route fingerprint from the grant, so publication rederives
    /// the route without a second hash pass.
    pub(super) fingerprint: u64,
}

/// The position of `state` in `states`, the table's state words.
#[inline(always)]
fn position_of(states: &[AtomicU64], state: &AtomicU64) -> usize {
    let base = states.as_ptr() as usize;
    let word = std::ptr::from_ref(state) as usize;
    debug_assert!(word >= base && word < base + std::mem::size_of_val(states));
    (word - base) / std::mem::size_of::<AtomicU64>()
}

impl AttemptRecord<'_> {
    /// The record's position in its table, from the state word's place in
    /// `states`, the table's state words as a gate holder sees them.
    #[inline(always)]
    pub(super) fn position(&self, states: &[AtomicU64]) -> usize {
        position_of(states, self.state)
    }

    /// The owner's final record access, a `Release` read-modify-write that
    /// checks the word still carries this serial.
    #[inline]
    pub(super) fn depart(self) {
        depart_word(self.state, self.serial);
    }
}

/// [`AttemptRecord::depart`] on the state word and serial alone, for an owner whose record must not pass through memory to an out-of-line departure.
#[inline]
pub(super) fn depart_word(state: &AtomicU64, serial: FillSerial) {
    probe::note(Primitive::Cas);
    fill::depart(state, serial);
}

impl<P: Platform> Drop for FillAttempt<'_, P> {
    /// The bounded fallback for an owner that was not aborted: the same
    /// departure, with no source, shard or grace wait.
    fn drop(&mut self) {
        self.record.depart();
    }
}

/// What one service call decided over `shard`'s fill table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FillServiceReport {
    /// The record the call examined first: the table's cursor as the call
    /// found it. The records examined are `examined` consecutive ones from
    /// here, wrapping at the table's end.
    pub first: usize,
    /// Records the call examined, each prepaid as one visit and one possible
    /// release.
    pub examined: usize,
    /// Departed records returned to Free.
    pub released: usize,
    /// Occupied records left in place: live owners and the record custody
    /// names.
    pub retained: usize,
    /// The allowance ended before a record's bundle; the cursor rests on it.
    pub budget_exhausted: bool,
}

/// Why a service call ended without a complete pass. No cursor moved, and
/// no record changed except under `Corrupt`, whose report counts the
/// releases the pass made before the malformed word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FillServiceError {
    /// No live index: none was configured, or the owner is drained.
    NoIndex,
    /// The budget could not pay for the gate try. A pass that cannot pay for
    /// its first record's bundle is not an error: it reports `examined` zero
    /// with `budget_exhausted` set.
    BudgetExhausted,
    /// Every paid gate attempt found the shard busy, or the attempt allowance
    /// was zero.
    Contended,
    /// The shard's gate is poisoned; its table cannot be serviced.
    Poisoned,
    /// The shard's fill table holds a malformed word; the gate is poisoned.
    /// The report is what the pass decided before reaching it: those
    /// releases stand, the malformed record and any record loaded with it in
    /// the same run count as examined, and the cursor did not move.
    Corrupt(FillServiceReport),
}

impl From<Refusal> for FillServiceError {
    fn from(refusal: Refusal) -> Self {
        match refusal {
            Refusal::BudgetExhausted => Self::BudgetExhausted,
            Refusal::Contended => Self::Contended,
            Refusal::Poisoned => Self::Poisoned,
            Refusal::Corrupt => Self::Corrupt(FillServiceReport::default()),
        }
    }
}

/// Steps one examined record prepays: its visit and its possible release.
pub const FILL_SERVICE_PER_RECORD: usize = 2;

/// One shard's fill table's shared words: the header, the custody record,
/// the state words and the rows, atomics a departing owner and a detaching
/// follower also write.
pub(super) struct FillView<'m> {
    pub(super) control: &'m FillControl,
    pub(super) custody: &'m FillCustody,
    pub(super) states: &'m [AtomicU64],
    pub(super) rows: &'m [FillRow],
}

/// `view` borrows the storage for `'v` and may outlive the gate hold; `keys`
/// and `fingerprints` are exclusive for the gate hold `'k`.
pub(super) struct FillHold<'v, 'k> {
    pub(super) view: FillView<'v>,
    pub(super) keys: &'k mut [Key],
    pub(super) fingerprints: &'k mut [u64],
    /// Each record's place word, as the `place_claim` module encodes it.
    pub(super) places: &'k mut [u64],
}

impl<P: Platform> Storage<P> {
    /// Grants the unique current attempt on `key`, for an object of cache
    /// version `version`, if its shard has a Free
    /// record and no current association with the key, making at most
    /// `tries` gate attempts and charging the hash pass, one coordination
    /// attempt per gate try, one visit per record scanned, one comparison per
    /// key compared and one update for the grant to `budget`.
    ///
    /// The caller starts its origin read after this grant returns, the read
    /// reflects every origin change committed before it starts, and each
    /// invalidation of `key` commits after the origin change it reports. Under
    /// those conditions REVOKE closes the stale-fill race: an invalidation
    /// that returns `Ok` and commits after the grant and before the fill's
    /// publication revokes the attempt; a reservation or publication whose
    /// gate-held `check` passes its cutoff read, visit debit and record
    /// decode then refuses
    /// [`FillReserveError::Superseded`](super::writable::FillReserveError::Superseded)
    /// or
    /// [`FillPublishError::Superseded`](super::publication::FillPublishError::Superseded),
    /// any earlier refusal reports its own cause, and the fill stays
    /// unpublished either way. A receive whose check observes the
    /// revocation returns
    /// [`ReceiveError::Revoked`](super::writable::ReceiveError::Revoked).
    ///
    /// # Errors
    ///
    /// [`BeginError`]; none grants authority and none changes a record.
    pub fn begin_fill(
        &self,
        key: &Key,
        version: CacheVersion,
        tries: usize,
        budget: &mut WorkBudget,
    ) -> Result<FillAttempt<'_, P>, BeginError> {
        let index = self.index().ok_or(BeginError::NoIndex)?;
        // An early refusal only: the `SeqCst` read under the gate is the
        // open witness, so this read needs no place in the cutoff's total
        // order. `Relaxed` also spares it the AArch64 `SeqCst` load's wait
        // for this thread's earlier `Release` stores. Admission never
        // reopens, so a closed read refuses correctly.
        if self.closed().load(Ordering::Relaxed) {
            return Err(BeginError::Closed);
        }
        let route = index.hasher.route(key, &index.geometry, budget)?;
        let shard = route.shard();
        let Some(table) = self.fill_table(shard) else {
            return Err(BeginError::FillSlotsFull);
        };
        let image = index.image.shard(shard).ok_or(BeginError::Contended)?;
        // A granted attempt reserves next, claiming a slot in the key's
        // placement window and writing its record and tables; hinting those
        // lines before the gate lets the misses overlap the grant. Skipped
        // where the gate's exchange would wait for the hints.
        if !RMW_WAITS_FOR_HINTS && let Some(pool) = self.live_pool() {
            pool.prefetch_claim(route.fingerprint());
        }
        // SAFETY: the index mapping is owned and initialized while the
        // storage is live, which `&self` guarantees.
        let (gate, control) =
            unsafe { (image.gate(&index.mapping), image.control(&index.mapping)) };
        // The grant ends its hold by release or poison, so its drop is a
        // panic inside the grant, also in a call made by a thread that was
        // already unwinding.
        let guard = take_gate(gate, control, tries, budget)?.poison_on_unwind();
        probe::note(Primitive::GateTaken);
        // SAFETY: the root mapping is owned and initialized while the storage
        // is live, and the gate hold just taken makes the keys' `&mut` the
        // only reference into them; `grant` consumes the hold before the
        // gate is released, and only the state word and the row it returns,
        // atomics of the shared view, outlive it.
        let hold = unsafe { self.fill_hold(table) };
        match grant(self, hold, key, route.fingerprint(), budget) {
            Ok((state, row, serial)) => {
                guard.release();
                Ok(FillAttempt {
                    storage: self,
                    record: AttemptRecord {
                        shard,
                        state,
                        row,
                        serial,
                        key: *key,
                        version,
                        fingerprint: route.fingerprint(),
                    },
                })
            }
            Err(BeginError::Corrupt) => {
                guard.poison();
                Err(BeginError::Corrupt)
            }
            Err(error) => {
                guard.release();
                Err(error)
            }
        }
    }

    /// Services `shard`'s fill table as the module documentation describes,
    /// making at most `tries` gate attempts and charging one coordination
    /// attempt per try and, per examined record, one visit plus one update
    /// for each release; a record is examined only with its whole
    /// [`FILL_SERVICE_PER_RECORD`] bundle affordable. A shard without a fill
    /// table decides nothing and charges nothing.
    ///
    /// # Errors
    ///
    /// [`FillServiceError`]; no cursor moved, and no record changed except
    /// the releases a `Corrupt` report counts.
    pub fn service_fills(
        &self,
        shard: ShardIndex,
        tries: usize,
        budget: &mut WorkBudget,
    ) -> Result<FillServiceReport, FillServiceError> {
        let index = self.index().ok_or(FillServiceError::NoIndex)?;
        let Some(table) = self.fill_table(shard) else {
            return Ok(FillServiceReport::default());
        };
        let image = index.image.shard(shard).ok_or(FillServiceError::NoIndex)?;
        // SAFETY: as for `begin_fill`.
        let (gate, control) =
            unsafe { (image.gate(&index.mapping), image.control(&index.mapping)) };
        // The pass ends its hold by release or poison, so its drop is a
        // panic inside the pass, also in a call made by a thread that was
        // already unwinding.
        let guard = take_gate(gate, control, tries, budget)?.poison_on_unwind();
        probe::note(Primitive::GateTaken);
        // SAFETY: the storage is live, `table` is one of its root image's
        // tables, and the gate hold just taken makes the place words' `&mut`
        // the only reference into them.
        let FillHold { view, places, .. } = unsafe { self.fill_hold(table) };
        let rows = view.rows;
        // A departed record's place is refunded, and the right and credit
        // its published row retained are returned, before its release
        // store, within the release's update. A malformed row, or a place
        // the tables do not hold as pending for the row's allocation, ends
        // the pass with the record occupied. The pass resolves the shard's
        // tables only for a record that claimed a place.
        let mut refund = |position: usize| {
            let row = &rows[position];
            let retained = row.retained().map_err(|_| ())?;
            if let Some(claimed) = place_claim::Claimed::of(places[position]) {
                // SAFETY: as for the fill hold: the index mapping is live
                // and the shard gate this hold took is the only path into
                // its tables.
                let hold = unsafe { image.hold(&index.mapping) };
                let owner = AllocationId::of_record_tag(row.allocation());
                if place_claim::check(&hold, control, claimed, owner).is_none() {
                    return Err(());
                }
                place_claim::refund(&hold, control, &mut places[position]);
            }
            if let Some(tag) = retained {
                release_retained(self, AllocationId::of_record_tag(tag));
            }
            Ok(())
        };
        match pass(view, &mut refund, budget) {
            Ok(report) => {
                guard.release();
                Ok(report)
            }
            Err(progress) => {
                guard.poison();
                Err(FillServiceError::Corrupt(progress))
            }
        }
    }

    /// The fill table of `shard`, or `None` for a shard with `F = 0`, an
    /// unknown shard, no index or a drained owner.
    #[inline]
    pub(super) fn fill_table(&self, shard: ShardIndex) -> Option<&FillImage> {
        self.index()?;
        self.root_image.fills.get(shard.0)?.as_ref()
    }

    /// One record's state word, for a test's direct observation. Precondition:
    /// `is_live()` and `record` below the table's length.
    #[cfg(test)]
    pub(super) fn fill_state(&self, shard: ShardIndex, record: usize) -> &AtomicU64 {
        let table = self
            .fill_table(shard)
            .expect("a live storage whose shard has a fill table");
        // SAFETY: the root mapping is owned and initialized while the storage
        // is live; the words are atomics no holder forms a `&mut` into.
        let states = unsafe { table.states.as_slice(&self.root) };
        &states[record]
    }

    /// Always inlined, as is [`fill_hold`](Self::fill_hold), so the grant,
    /// the invalidation's search and the service pass receive the table's
    /// slices in registers, not through memory.
    ///
    /// # Safety
    ///
    /// The storage is live and `table` is one of its root image's fill
    /// tables; the words are atomics no holder forms a `&mut` into.
    #[inline(always)]
    pub(super) unsafe fn fill_view<'m>(&'m self, table: &FillImage) -> FillView<'m> {
        // SAFETY: the caller's guarantee is `as_slice`'s contract.
        unsafe {
            FillView {
                control: &table.control.as_slice(&self.root)[0],
                custody: &table.custody.as_slice(&self.root)[0],
                states: table.states.as_slice(&self.root),
                rows: table.rows.as_slice(&self.root),
            }
        }
    }

    /// # Safety
    ///
    /// As for [`fill_view`](Self::fill_view), and the caller holds `table`'s
    /// shard gate for the whole `'k`: the gate is the only path that reads
    /// or writes the keys and their fingerprints, so the `&mut`s formed here
    /// are the only references into them.
    #[inline(always)]
    pub(super) unsafe fn fill_hold<'v: 'k, 'k>(&'v self, table: &FillImage) -> FillHold<'v, 'k> {
        // SAFETY: the caller's guarantee is `fill_view`'s contract for the
        // shared words and `slice_ptr`'s for the keys and fingerprints.
        unsafe {
            FillHold {
                view: self.fill_view(table),
                keys: &mut *table.keys.slice_ptr(&self.root).as_ptr(),
                fingerprints: &mut *table.fingerprints.slice_ptr(&self.root).as_ptr(),
                places: &mut *table.places.slice_ptr(&self.root).as_ptr(),
            }
        }
    }
}

#[cfg(test)]
thread_local! {
    /// Runs once under the gate, between a grant's entry cutoff check and
    /// its cutoff read under the gate, so a test can close admission where
    /// only the read under the gate can catch it, or panic inside the hold
    /// before the grant writes.
    pub(super) static INTERPOSE_BEFORE_GRANT_CUTOFF: std::cell::Cell<
        Option<fn(&std::sync::atomic::AtomicBool)>,
    > = const { std::cell::Cell::new(None) };
}

/// What one scan of a shard's fill table found for one key.
pub(super) struct Scan {
    /// The record holding the key's current association and its serial.
    pub(super) association: Option<(usize, FillSerial)>,
    /// The first Free record.
    pub(super) free: Option<usize>,
}

/// Which current associations a [`scan`] matches.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Associations {
    /// Every current association, departed or not: the record is its key's
    /// attempt until service frees it.
    Any,
    /// The associations whose owner has not departed: the attempts that can
    /// still publish. A departed one stays occupied while service has not
    /// freed it or a follower is joined, and replaces nothing.
    Live,
}

/// Scans every record of `hold` under the gate for a current association,
/// of the kind `associations` names, whose fingerprint equals `fingerprint`
/// and, when `key` is given, whose key equals `key`, charging one visit per
/// record and one comparison per record whose association is of that
/// kind, charged before its fingerprint is compared.
/// `Corrupt` on a malformed word, which the caller answers by poisoning the
/// gate; `BudgetExhausted` when a visit or comparison cannot be paid.
///
/// The charges are settled once the loop ends, in the amounts the loop
/// found affordable in the order it would have paid them: one visit per
/// record, and the comparison right after its record's visit. An allowance
/// that covers every record's visit and comparison runs the loop with no
/// budget arithmetic at all. A smaller one runs it over the records the
/// visits alone can pay for; a paid comparison lowers that bound, and the
/// loop restarts behind the record only when the bound falls into the
/// table. The budget's state after the call, on every outcome, is what one
/// debit per step in that order leaves.
///
/// The records up to the first Free one and the records after it are two
/// loops over one body: the first ends at the Free record it finds, the
/// second ignores Free records, so neither carries a running minimum from
/// record to record.
///
/// The first loop tells an occupied, well-formed word from a Free or
/// malformed one with the one range comparison of [`fill::Issued`], and a
/// record's serial is decoded only when the record matches.
#[inline(always)]
pub(super) fn scan(
    hold: &FillHold<'_, '_>,
    fingerprint: u64,
    key: Option<&Key>,
    associations: Associations,
    budget: &mut WorkBudget,
) -> Result<Scan, Refusal> {
    let states = hold.view.states;
    let records = states.len();
    let next_serial = hold.view.control.next_serial.load();
    let mut walk = Walk {
        next_serial,
        issued: fill::Issued::before(next_serial),
        keys: &hold.keys[..records],
        fingerprints: &hold.fingerprints[..records],
        fingerprint,
        key,
        associations,
        records,
        slack: budget.remaining(),
        compared: 0,
        association: None,
    };
    let (position, free, found) = if walk.slack / 2 >= records {
        walk.run::<false>(states)
    } else {
        let outcome;
        (walk, outcome) = walk.run_bounded(states);
        outcome
    };
    budget
        .debit_n(WorkKind::Visit, position)
        .expect("the loop visited only what the allowance paid for");
    budget
        .debit_n(WorkKind::Comparison, walk.compared)
        .expect("the loop compared only what the allowance paid for");
    found.map(|()| Scan {
        association: walk.association,
        free: (free < records).then_some(free),
    })
}

/// Records the scan reads together behind the first Free one.
const FREE_RUN: usize = 4;

/// The scan's state across its occupied records.
struct Walk<'k> {
    next_serial: u64,
    /// The occupied words well formed against `next_serial`.
    issued: fill::Issued,
    keys: &'k [Key],
    fingerprints: &'k [u64],
    fingerprint: u64,
    /// The full key an association must also carry; `None` matches by
    /// fingerprint alone.
    key: Option<&'k Key>,
    associations: Associations,
    records: usize,
    /// Visits the allowance still pays for, counted from the first record:
    /// the remaining steps less the comparisons paid so far.
    slack: usize,
    compared: usize,
    /// The position and serial of the matching record, when present.
    association: Option<(usize, FillSerial)>,
}

/// What the scan does after an occupied record.
enum Step {
    Next,
    /// A paid comparison moved the visit bound into the table: the loop
    /// reruns from the next record against it.
    Rerun,
    Stop(Refusal),
}

impl Walk<'_> {
    /// The loops over `states`: the records visited, the first Free
    /// position with the table's length for none, and the outcome. With
    /// `BOUNDED` false the allowance covers every step the table can cost
    /// and the loops check nothing against it.
    #[inline(always)]
    fn run<const BOUNDED: bool>(
        &mut self,
        states: &[AtomicU64],
    ) -> (usize, usize, Result<(), Refusal>) {
        let records = self.records;
        let mut free = records;
        let mut position = 0;
        let found = 'bounded: loop {
            let end = if BOUNDED {
                records.min(self.slack)
            } else {
                records
            };
            // The slice ends at `end`, so no index below it is checked.
            let states = &states[..end];
            if free == records {
                while position < end {
                    probe::note(Primitive::Load);
                    let word = states[position].load(Ordering::Relaxed);
                    // One comparison tells an occupied, well-formed word
                    // from every other: the Free word ends this loop and a
                    // malformed one the scan.
                    if !self.issued.holds(word) {
                        position += 1;
                        if word == fill::FREE {
                            free = position - 1;
                            break;
                        }
                        break 'bounded Err(Refusal::Corrupt);
                    }
                    let step = self.formed::<BOUNDED>(word, position);
                    position += 1;
                    match step {
                        Step::Next => {}
                        Step::Rerun => continue 'bounded,
                        Step::Stop(refusal) => break 'bounded Err(refusal),
                    }
                }
            }
            // Behind the first Free record the table is mostly Free, so the
            // words are read four at a time, then singly for the remainder:
            // a run with no occupied word costs one branch, and a run with
            // one is handled from the words already read. A rerun rereads
            // the rest of its run, and a malformed word leaves the rest of
            // its run, already loaded, undecided and uncharged; the charge is
            // one visit per record handled.
            let (runs, rest) = states[position..].as_chunks::<FREE_RUN>();
            for run in runs {
                let words = run.each_ref().map(|state| {
                    probe::note(Primitive::Load);
                    state.load(Ordering::Relaxed)
                });
                if words.iter().fold(fill::FREE, |any, word| any | word) == fill::FREE {
                    position += FREE_RUN;
                    continue;
                }
                for word in words {
                    let step = if word == fill::FREE {
                        Step::Next
                    } else {
                        self.occupied::<BOUNDED>(word, position)
                    };
                    position += 1;
                    match step {
                        Step::Next => {}
                        Step::Rerun => continue 'bounded,
                        Step::Stop(refusal) => break 'bounded Err(refusal),
                    }
                }
            }
            for state in rest {
                probe::note(Primitive::Load);
                let word = state.load(Ordering::Relaxed);
                let step = if word == fill::FREE {
                    Step::Next
                } else {
                    self.occupied::<BOUNDED>(word, position)
                };
                position += 1;
                match step {
                    Step::Next => {}
                    Step::Rerun => continue 'bounded,
                    Step::Stop(refusal) => break 'bounded Err(refusal),
                }
            }
            break if end == records {
                Ok(())
            } else {
                Err(Refusal::BudgetExhausted)
            };
        };
        (position, free, found)
    }

    /// [`run`](Self::run) against the allowance, out of line: a scan that
    /// may run out of budget is the rare one, and the callers' bodies stay
    /// the size of the common loops. Passing and returning the walk by
    /// value lets the optimizer keep it in registers on the common path.
    #[inline(never)]
    fn run_bounded(mut self, states: &[AtomicU64]) -> (Self, (usize, usize, Result<(), Refusal>)) {
        let outcome = self.run::<true>(states);
        (self, outcome)
    }

    /// One occupied record at `position`: a malformed word ends the scan,
    /// and a well-formed one takes [`formed`](Self::formed).
    #[inline(always)]
    fn occupied<const BOUNDED: bool>(&mut self, word: u64, position: usize) -> Step {
        if !self.issued.holds(word) {
            return Step::Stop(Refusal::Corrupt);
        }
        self.formed::<BOUNDED>(word, position)
    }

    /// One occupied, well-formed record at `position`: for a current
    /// association of the kind the scan matches, the paid comparison.
    #[inline(always)]
    fn formed<const BOUNDED: bool>(&mut self, word: u64, position: usize) -> Step {
        if fill::revoked(word) || (self.associations == Associations::Live && fill::departed(word))
        {
            return Step::Next;
        }
        // The comparison is the step after this record's visit; counting
        // visits alone against `slack`, it fits when one step is left after
        // the `position + 1` visits so far.
        if BOUNDED && position + 1 >= self.slack {
            return Step::Stop(Refusal::BudgetExhausted);
        }
        self.compared += 1;
        // One comparison, charged once: the fingerprint decides for nearly
        // every other key. A scan with a key reads the full key only on a
        // matching fingerprint; a scan without one matches on the
        // fingerprint alone.
        if self.fingerprints[position] == self.fingerprint
            && self.key.is_none_or(|key| self.keys[position] == *key)
        {
            // Only a match names its serial, so only a match decodes.
            let Ok(Record::Occupied { serial, .. }) = fill::decode(word, self.next_serial) else {
                return Step::Stop(Refusal::Corrupt);
            };
            self.association = Some((position, serial));
        }
        if BOUNDED {
            self.slack -= 1;
            if self.slack < self.records {
                return Step::Rerun;
            }
        }
        Step::Next
    }
}

/// The grant under the gate: the cutoff, the serial, the scan, the write of
/// `key` and its `fingerprint`. Every refusal precedes the write, so a
/// refusal changes no record. Returns the granted record's state word and
/// serial.
#[inline(always)]
fn grant<'v, P: Platform>(
    storage: &Storage<P>,
    hold: FillHold<'v, '_>,
    key: &Key,
    fingerprint: u64,
    budget: &mut WorkBudget,
) -> Result<(&'v AtomicU64, &'v FillRow, FillSerial), BeginError> {
    #[cfg(test)]
    if let Ok(Some(interpose)) = INTERPOSE_BEFORE_GRANT_CUTOFF.try_with(|hook| hook.take()) {
        interpose(storage.closed());
    }
    // The open witness, read under the gate so a grant and the close it
    // could overlap are ordered by the cutoff's total order.
    if storage.closed().load(Ordering::SeqCst) {
        return Err(BeginError::Closed);
    }
    let raw = hold.view.control.next_serial.load();
    let next_serial = FillSerial::new(raw).ok_or(if raw == 0 {
        BeginError::Corrupt
    } else {
        BeginError::AttemptExhausted
    })?;
    let found = scan(&hold, fingerprint, Some(key), Associations::Any, budget)?;
    if found.association.is_some() {
        return Err(BeginError::InProgress);
    }
    let record = found.free.ok_or(BeginError::FillSlotsFull)?;
    budget.debit(WorkKind::Update)?;
    let row = &hold.view.rows[record];
    // Service frees a record only once its last follower detached, so a
    // Free record with observers is malformed, and the reset refuses it.
    row.reset().map_err(|_| BeginError::Corrupt)?;
    probe::note(Primitive::Store);
    hold.keys[record] = *key;
    hold.fingerprints[record] = fingerprint;
    let state = &hold.view.states[record];
    state.store(fill::occupied(next_serial), Ordering::Relaxed);
    hold.view.control.next_serial.advance(next_serial);
    Ok((state, row, next_serial))
}

/// Returns the right on `id` and the `Shared` credit a published row
/// retained for its followers. The caller holds the shard gate and is
/// releasing the row's departed record with no follower joined, so no
/// follower reads through the right after this call, and the record's next
/// grant resets the row before any later pass reads it. Each follower
/// counted its right before its `Release` detach, and the pass read the
/// lowered observer count with `Acquire`, so every follower's right is
/// ordered before this release on the slot's word.
#[inline]
fn release_retained<P: Platform>(storage: &Storage<P>, id: AllocationId) {
    release_right(storage, id);
    return_credit(storage, Credit::Shared);
}

#[inline(always)]
fn settle(
    record: Record,
    state: &AtomicU64,
    end: &mut impl FnMut(&AtomicU64) -> Result<bool, ()>,
    released: &mut usize,
    retained: &mut usize,
) -> Result<(), ()> {
    match record {
        Record::Free => {}
        Record::Occupied {
            departed: false, ..
        } => *retained += 1,
        Record::Occupied { departed: true, .. } => {
            if end(state)? {
                *released += 1;
            } else {
                *retained += 1;
            }
        }
    }
    Ok(())
}

#[inline(always)]
fn quiet(words: [u64; FREE_RUN], next_serial: u64) -> Option<usize> {
    let mut live = 0;
    for word in words {
        match fill::decode(word, next_serial) {
            Ok(Record::Free) => {}
            Ok(Record::Occupied {
                departed: false, ..
            }) => live += 1,
            _ => return None,
        }
    }
    Some(live)
}

/// What one walk of a fill table decided.
struct Walked {
    /// Records examined, released and retained.
    examined: usize,
    released: usize,
    retained: usize,
    /// The record the next pass examines first.
    position: usize,
    /// A malformed word or row ended the walk.
    malformed: bool,
}

/// One pass over the table from its cursor, at most one visit per record.
/// A malformed word or row ends the pass with what it decided so far; the caller
/// poisons the gate.
///
/// As for the scan, the charges are settled once the loop ends, in the
/// amounts one preflight and one or two debits per record would have left:
/// the pass runs over the records whose whole bundle the allowance pays for
/// given the releases made so far, a bound each release lowers, and it
/// reruns behind the record only when the bound falls inside the table.
/// Each run is one slice of the table, so the wrap at the table's end
/// happens between runs and no record's index is checked.
///
/// A pass funded for every record observes its words in runs of
/// [`FREE_RUN`] through [`fill::load_run`], one acquire fence per run that
/// holds an occupied word in place of the acquire load per record, which the
/// fewer than [`FREE_RUN`] records left at the end of a slice keep. A
/// malformed word inside a run ends the pass after that run's visits, all
/// of which were loaded and charged, with the run's records before it
/// settled. An under-funded pass keeps the one-record steps, since its
/// bound can fall inside a run.
///
/// [`quiet`] counts a run of Free and undeparted records in one step.
#[inline(always)]
fn pass(
    view: FillView<'_>,
    refund: &mut impl FnMut(usize) -> Result<(), ()>,
    budget: &mut WorkBudget,
) -> Result<FillServiceReport, FillServiceReport> {
    /// `bounded` walks the table when `left` covers fewer whole bundles than
    /// there are records. Each release lowers that bound.
    #[inline(never)]
    fn bounded(
        states: &[AtomicU64],
        first: usize,
        next_serial: u64,
        left: usize,
        end: &mut impl FnMut(&AtomicU64) -> Result<bool, ()>,
    ) -> Walked {
        let records = states.len();
        // The `k`th record examined has its bundle when `k`, the releases
        // before it and the bundle fit in the allowance.
        let affordable = |released: usize| {
            records.min(
                left.saturating_sub(FILL_SERVICE_PER_RECORD - 1)
                    .saturating_sub(released),
            )
        };
        let (mut examined, mut released, mut retained) = (0, 0, 0);
        let mut position = first;
        let mut malformed = false;
        'runs: loop {
            let bound = affordable(released);
            if examined >= bound {
                break;
            }
            let stop = records.min(position + (bound - examined));
            for state in &states[position..stop] {
                probe::note(Primitive::Load);
                position += 1;
                examined += 1;
                let Ok(record) = fill::observe(state, next_serial) else {
                    malformed = true;
                    break 'runs;
                };
                let before = released;
                if settle(record, state, end, &mut released, &mut retained).is_err() {
                    malformed = true;
                    break 'runs;
                }
                // The bound fell by one: rerun against it once it cuts into
                // the table.
                if released > before && affordable(released) < records {
                    continue 'runs;
                }
            }
            if position == records {
                position = 0;
            }
        }
        if position == records {
            position = 0;
        }
        Walked {
            examined,
            released,
            retained,
            position,
            malformed,
        }
    }

    let states = view.states;
    let records = states.len();
    let first = view.control.cursor.load(Ordering::Relaxed);
    let next_serial = view.control.next_serial.load();
    // The record custody names, if it names one, by identity.
    let custody = states.get(view.custody.record.load(Ordering::Relaxed));
    let left = budget.remaining();
    let mut end = |state: &AtomicU64| -> Result<bool, ()> {
        let at = position_of(states, state);
        if custody.is_some_and(|held| std::ptr::eq(held, state)) || view.rows[at].observers() != 0 {
            return Ok(false);
        }
        refund(at)?;
        probe::note(Primitive::Store);
        fill::release(state);
        Ok(true)
    };
    // With a bundle for every record the bound stays at the table's length
    // until the walk examines every record.
    let walked = if left >= records.saturating_mul(FILL_SERVICE_PER_RECORD) {
        let (before, from) = states.split_at(first);
        let (mut examined, mut released, mut retained) = (0, 0, 0);
        let mut malformed = false;
        let mut slice = from;
        let mut wrapped = false;
        'slices: loop {
            let (runs, rest) = slice.as_chunks::<FREE_RUN>();
            for (index, run) in runs.iter().enumerate() {
                probe::note_n(Primitive::Load, FREE_RUN);
                let words = fill::load_run(run);
                if words.iter().fold(fill::FREE, |any, word| any | word) == fill::FREE {
                    continue;
                }
                if let Some(live) = quiet(words, next_serial) {
                    retained += live;
                    continue;
                }
                for (state, word) in run.iter().zip(words) {
                    let settled = match fill::decode(word, next_serial) {
                        Ok(record) => settle(record, state, &mut end, &mut released, &mut retained),
                        Err(_) => Err(()),
                    };
                    if settled.is_err() {
                        examined += (index + 1) * FREE_RUN;
                        malformed = true;
                        break 'slices;
                    }
                }
            }
            for (behind, state) in rest.iter().enumerate() {
                probe::note(Primitive::Load);
                let settled = match fill::observe(state, next_serial) {
                    Ok(record) => settle(record, state, &mut end, &mut released, &mut retained),
                    Err(_) => Err(()),
                };
                if settled.is_err() {
                    examined += runs.len() * FREE_RUN + behind + 1;
                    malformed = true;
                    break 'slices;
                }
            }
            examined += slice.len();
            if wrapped {
                break;
            }
            wrapped = true;
            slice = before;
        }
        Walked {
            examined,
            released,
            retained,
            position: first,
            malformed,
        }
    } else {
        bounded(states, first, next_serial, left, &mut end)
    };
    budget
        .debit_n(WorkKind::Visit, walked.examined)
        .expect("the pass examined only records whose bundle the allowance paid for");
    budget
        .debit_n(WorkKind::Update, walked.released)
        .expect("the pass released only records whose bundle the allowance paid for");
    let report = FillServiceReport {
        first,
        examined: walked.examined,
        released: walked.released,
        retained: walked.retained,
        budget_exhausted: !walked.malformed && walked.examined < records,
    };
    if walked.malformed {
        return Err(report);
    }
    view.control
        .cursor
        .store(walked.position, Ordering::Relaxed);
    Ok(report)
}
