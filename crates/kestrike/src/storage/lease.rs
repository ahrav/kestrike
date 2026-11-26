//! Response-owned immutable leases: one engine-wide credit count, one
//! per-slot reference count with an anchor, and a fixed-work release.
//!
//! Credits: `L` bounds the credits taken from one atomic counter in the root
//! control mapping, not a mutex. A reservation on the counter is an explicit
//! bounded compare-exchange loop that debits one coordination attempt per
//! try and distinguishes `LeaseLimit` (every credit backs a live lease) from
//! `Contended` (every paid try failed its compare-exchange, to another
//! writer or spuriously); a weak compare-exchange that fails with the
//! expected value still in place is counted as spurious. Publication, and in
//! tests the handoff and the resident acquisition, reserve on the counter
//! directly. The registered lookup reserves through its registration
//! record: the record borrows a run of credits from the counter when it has
//! none idle, its leases take from the record's pool with one unconditional
//! subtract and return to the record's return line, a line of its own, on
//! whatever thread they drop, the record moves the line's credits into its
//! pool with one subtract when the pool runs out, a take that finds the pool
//! holding over two borrows gives the surplus above half a borrow back to
//! the counter, and a lookup that finds the counter at `L` takes credits
//! from another record: the lender of its last such take first, then the
//! return line of any record whose bit in the parked map, one bit per
//! record, is set, up to a borrow at once, and within each map word the
//! pools only once every flagged line there showed nothing. `LeaseLimit`
//! keeps its meaning while a reader whose leases come and go touches no
//! line another reader writes: a return reads the map and writes it only
//! when it finds its record's bit clear. A take at the limit writes the map
//! when it sweeps a word in which every record it visited showed nothing,
//! and when credits it parks or gives back land on a record whose bit is
//! clear.
//! The `credit` module holds the word-level steps and states the ordering
//! argument. The registration's drop gives its idle credits back. A right
//! that a registered lookup reserves for a volume read takes no credit
//! (`Credit::Read`): the read's operation record bounds it. Reservation
//! uses relaxed ordering: the counters carry numbers, not the
//! object's bytes, and the object is published by moving its owner. The
//! return is a separate release step after the last slot access, and the
//! report loads the engine-wide counter and every record's idle and
//! returned credits with acquire and subtracts those credits.
//!
//! References: the count in each slot's lifetime word, `refs`, counts
//! external rights plus one anchor, so `refs == rights + anchor` with
//! `anchor` in `{0, 1}`. The rights are each lease's, each in-flight volume
//! read's, and the fill's one write right on its own slot, `Filling`, or
//! `Retired` once its owner's end abandoned it; [`release_right`] ends an operation's right.
//! Publication installs the anchor and the first right together on a
//! count it has proved idle, before any other actor can see the object;
//! between that point and terminal zero every change is a read-modify-write,
//! never a plain store. An object whose every lease was dropped keeps
//! `refs == 1` and stays resident until it is retired. Clearing its mapping
//! under the shard gate, or in tests consuming the `Resident` authority by
//! `retire` or by drop, bumps the era, stamps the slot with the era it
//! retired at and records the retirement for service; the anchor stays
//! counted.
//! Copied identities in a registered reader's protected interval outlive the
//! retirement, so the retirement alone does not prove that no observer
//! remains: service releases the anchor only once a completed certification
//! pass proves every reader still pinned started after the retirement. The
//! `grace` module states that argument. Validation keeps `C + 1` at or below
//! `REFS_MAX`, so the anchor and every right fit the word's 18-bit count. Publication takes the first right
//! unconditionally; the registered lookup bounds every further right by `C`.
//! [`Volume::read`](super::Volume::read) takes over its lease's right.
//!
//! Release ordering: dropping a lease performs a release `fetch_sub` of one
//! reference on the slot's word (its last access to anything belonging to the slot), then a release
//! return of the credit, then lets its `&Storage` borrow end,
//! which is the final domain access. Nothing is freed, enqueued, scanned,
//! allocated, locked or called back: the return of the extent is discovered
//! later by service through the retirement flag, and only once service has
//! released the anchor and observes `refs == 0` with acquire ordering. A
//! lease dropped while the storage is otherwise idle therefore changes two
//! counters, or three when its `Credit::Record` return takes the record's
//! return line from zero and finds the record's bit in the parked map
//! clear.
//!
//! Moving the lease to another thread or task transfers the read right.
//! [`Volume::read`](super::Volume::read) consumes the lease and reads the
//! object's record from the
//! device under it and checks the record header's key against the lease's
//! before any byte. RAM matches an object by its key's fingerprint, so the
//! header check is the full-key check: an object of a different key with an
//! equal fingerprint ends the read `HeaderMismatch(Key)`.
//!
//! ```compile_fail,E0599
//! # use kestrike::storage::*;
//! # fn f(lease: ExtentLease<'_, LinuxPlatform>) {
//! let copy = lease.clone();
//! # }
//! ```
//!
//! ```compile_fail,E0451
//! # use kestrike::storage::*;
//! # fn f(storage: &Storage<LinuxPlatform>, real: AllocationId) {
//! let forged: ExtentLease<'_, LinuxPlatform> = ExtentLease { storage, id: real, key: [0; 32], credit: todo!() };
//! # }
//! ```
//!
//! ```compile_fail,E0599
//! # use kestrike::storage::*;
//! # fn f(storage: &Storage<LinuxPlatform>, id: AllocationId, budget: &mut WorkBudget) {
//! let lease = storage.acquire(id, budget);
//! # }
//! ```
//!
//! ```compile_fail,E0382
//! # use kestrike::storage::*;
//! # fn f<D: Disk>(
//! #     fill: WritableFill<'_, '_, LinuxPlatform>,
//! #     volume: &mut Volume<'_, '_, LinuxPlatform, D>,
//! #     budget: &mut WorkBudget,
//! # ) {
//! let lease = fill.publish(volume, 1, 3, budget);
//! let late = fill.key();
//! # }
//! ```
//!
//! ```compile_fail,E0382
//! # use kestrike::storage::*;
//! # fn f<'s, D: Disk>(
//! #     lease: ExtentLease<'s, LinuxPlatform>,
//! #     volume: &mut Volume<'s, '_, LinuxPlatform, D>,
//! # ) {
//! let first = volume.read(lease, u64::MAX);
//! let again = volume.read(lease, u64::MAX);
//! # }
//! ```
//!
//! Stable rustdoc does not check the error codes above; they record the
//! intended cause (E0599 clone and raw-identity acquisition, E0451 forged
//! lease, E0382 a consumed owner or lease reused)
//! for a reader, and `cargo +nightly test --doc` verifies them.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use super::allocation::{AllocationId, Owned, RetireOutcome, abandon};
use super::budget::{WorkBudget, WorkKind};
#[cfg(test)]
use super::completed::Completed;
use super::credit::{self, BitWord, SweepWord};
use super::grace::{self, Sequential};
use super::image::{LeaseControls, PARKED_PER_WORD, ParkedWord, RegistrationRecord, ReturnLine};
use super::os::Platform;
use super::owner::Storage;
#[cfg(test)]
use super::prefetch::hint;
use super::probe::{self, Primitive};
use super::word::{self, ANCHORED};
use crate::index::Key;

/// Why a completed object was not handed off. The owner comes back
/// unchanged; every reservation the attempt made was returned.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoffError {
    /// Every one of the `L` credits is reserved.
    LeaseLimit,
    /// Every attempt the budget paid for failed its compare-exchange, to
    /// another writer or spuriously.
    Contended,
    /// No budget for the first attempt; nothing was tried.
    BudgetExhausted,
    /// The slot's reference count was not idle, so no anchor was installed.
    /// The credit was returned.
    AnchorPresent,
}

/// Outcome of one bounded credit reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CreditError {
    LeaseLimit,
    Contended,
    BudgetExhausted,
}

#[cfg(test)]
impl From<CreditError> for HandoffError {
    fn from(error: CreditError) -> Self {
        match error {
            CreditError::LeaseLimit => Self::LeaseLimit,
            CreditError::Contended => Self::Contended,
            CreditError::BudgetExhausted => Self::BudgetExhausted,
        }
    }
}

/// Engine-wide lease figures, read without any gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseReport {
    /// Credits backing a live lease, a reserved fill or a joined publication's
    /// row right now: the
    /// engine-wide count less the credits idle in registration records,
    /// each word a sample.
    pub reserved: usize,
    /// Credit attempts that lost to another writer.
    pub cas_failed: usize,
    /// Weak credit attempts that failed with the expected value in place.
    pub cas_spurious: usize,
}

/// Why a bounded increment produced no reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IncrementError<E> {
    /// `admit` refused the value seen; the attempt was paid.
    Refused(E),
    /// Every attempt the budget paid for failed its compare-exchange.
    Contended,
    /// The budget could not pay for the first attempt; nothing was tried.
    BudgetExhausted,
}

/// A word the bounded compare-exchange loop moves: the engine's credit
/// counters and each slot's lifetime word.
pub(crate) trait Exchanged {
    type Value: Copy + PartialEq;
    fn exchange_weak(
        &self,
        current: Self::Value,
        target: Self::Value,
    ) -> Result<Self::Value, Self::Value>;
    /// Runs and clears this thread's test interposer for the word's kind,
    /// if one is set.
    #[cfg(test)]
    fn interpose(&self);
}

impl Exchanged for AtomicUsize {
    type Value = usize;

    #[inline(always)]
    fn exchange_weak(&self, current: usize, target: usize) -> Result<usize, usize> {
        self.compare_exchange_weak(current, target, Ordering::Relaxed, Ordering::Relaxed)
    }

    #[cfg(test)]
    fn interpose(&self) {
        if let Ok(Some(interpose)) = INTERPOSE_BEFORE_CAS.try_with(|hook| hook.take()) {
            interpose(self);
        }
    }
}

impl Exchanged for AtomicU64 {
    type Value = u64;

    #[inline(always)]
    fn exchange_weak(&self, current: u64, target: u64) -> Result<u64, u64> {
        self.compare_exchange_weak(current, target, Ordering::Relaxed, Ordering::Relaxed)
    }

    #[cfg(test)]
    fn interpose(&self) {
        if let Ok(Some(interpose)) = INTERPOSE_BEFORE_RETAIN.try_with(|hook| hook.take()) {
            interpose(self);
        }
    }
}

/// Moves `counter` from `current`, the value the caller last loaded, to the
/// one `next` computes from the value seen, with at most as many attempts
/// as `budget` pays for; returns the value seen by the attempt that
/// succeeded. Every attempt is one coordination step, paid before the
/// check; a compare-exchange that fails against another writer's value
/// counts in `failed`, one that fails with the expected value still in
/// place counts in `spurious`, and a refusal by `next` is paid but counted
/// nowhere. Relaxed ordering throughout: the counter carries a number, and
/// whatever it guards is published by the owner or borrow the caller
/// already holds, or, for a retain, by the caller's acquire load of
/// `current`.
///
/// Failure counts stay local until the loop exits and then land in
/// `failed` and `spurious` once, which reduces shared-counter traffic during
/// retries.
#[inline(always)]
pub(crate) fn bounded_update<A: Exchanged, E>(
    counter: &A,
    current: A::Value,
    failed: &AtomicUsize,
    spurious: &AtomicUsize,
    budget: &mut WorkBudget,
    next: impl Fn(A::Value) -> Result<A::Value, E>,
) -> Result<A::Value, IncrementError<E>> {
    update_after(counter, current, (0, 0), (failed, spurious), budget, next)
}

/// Runs the attempts of [`bounded_update`] from `current` after `lost`
/// exchanges that lost to another writer and `stalled` that failed with the
/// expected value in place, each already paid: every count adds to `failed`
/// or `spurious` once on the way out, and a budget that runs out while
/// either count is nonzero is `Contended`.
#[inline(always)]
pub(crate) fn update_after<A: Exchanged, E>(
    counter: &A,
    mut current: A::Value,
    (mut lost, mut stalled): (usize, usize),
    (failed, spurious): (&AtomicUsize, &AtomicUsize),
    budget: &mut WorkBudget,
    next: impl Fn(A::Value) -> Result<A::Value, E>,
) -> Result<A::Value, IncrementError<E>> {
    let outcome = loop {
        if budget.debit(WorkKind::CoordinationAttempt).is_err() {
            // Every earlier attempt failed its compare-exchange, or the loop
            // would have ended there; none means nothing was tried.
            break Err(if lost + stalled != 0 {
                IncrementError::Contended
            } else {
                IncrementError::BudgetExhausted
            });
        }
        let target = match next(current) {
            Ok(target) => target,
            Err(refused) => break Err(IncrementError::Refused(refused)),
        };
        #[cfg(test)]
        counter.interpose();
        probe::note(Primitive::Cas);
        if crate::sim::chaos::chaos!(ExchangeLost) {
            lost += 1 + budget.remaining();
            let _ = budget.debit_n(WorkKind::CoordinationAttempt, budget.remaining());
            break Err(IncrementError::Contended);
        }
        match counter.exchange_weak(current, target) {
            Ok(_) => break Ok(current),
            Err(seen) => {
                if seen == current {
                    stalled += 1;
                } else {
                    lost += 1;
                }
                current = seen;
            }
        }
    };
    if lost != 0 {
        failed.fetch_add(lost, Ordering::Relaxed);
    }
    if stalled != 0 {
        spurious.fetch_add(stalled, Ordering::Relaxed);
    }
    outcome
}

/// Where an acquisition's credit was taken from, and where its return goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Credit {
    /// Returning a `Shared` credit subtracts one from the engine-wide counter
    /// even when the reservation took the credit from a record's idle
    /// credits.
    Shared,
    /// The registration record at this index: the registered lookup. The
    /// credit was taken from the record's idle credits or lent to the
    /// record by the engine-wide counter, and its return adds to the
    /// record's return line.
    Record(usize),
    /// No credit: the right goes straight to a volume read, whose operation
    /// record, one of the volume's `read_ops`, bounds it in place of `L`.
    /// Reserving and returning it touch no counter, and no lease carries it.
    Read,
}

/// Credits a registration record borrows from the engine-wide counter at
/// once when it has none idle: one backs the lease being acquired and the
/// rest wait in the record for its next lookups, so a reader whose leases
/// come and go touches the shared counter once per this many net new
/// leases, not per lease. Lent credits count against `L` until the record
/// returns them, so a reader at the limit takes them back one by one.
const BORROW: usize = 32;

/// Idle credits above which a take trims its record's surplus back to the
/// engine-wide counter: two borrows, so a reader whose demand swings by a
/// borrow between rounds neither trims nor borrows on every round.
const TRIM_ABOVE: usize = 2 * BORROW;

/// Idle credits a trim leaves in the record: half a borrow.
const KEEP: usize = BORROW / 2;

/// One started sweep in [`ParkedWord::sweeps`], whose low 32 bits count
/// sweeps in progress.
const SWEEP_STARTED: u64 = 1 << 32;

/// The in-progress half of [`ParkedWord::sweeps`].
const SWEEPS_IN_PROGRESS: u64 = SWEEP_STARTED - 1;

/// Reserves one credit against `limit` for `credit`.
///
/// A `Record` reservation takes from its record's idle credits with one
/// unconditional subtract when the record shows some; a subtract that finds
/// none gives the credit back. The reservation then takes every credit the
/// record's return line shows with one more subtract, keeps one and parks
/// the rest in the record, and borrows only when that line was empty too.
/// A take that finds more than [`TRIM_ABOVE`] credits idle gives the
/// surplus above [`KEEP`] back to the engine-wide counter in the same
/// compare-exchange, where the next borrower acquires it with one
/// compare-exchange. A borrow takes up to [`BORROW`] credits, limited by
/// the remaining space below `limit`, and parks any excess as idle.
///
/// [`take_parked`] serves both `Record` and `Shared` reservations at
/// `limit`, so `LeaseLimit` means every credit backs a live lease, a
/// reserved fill, a joined publication's row or a return still in progress. A `Record` return completes at its add to the
/// return line when the record's bit in the parked map is set, else at its
/// own set of the bit. A reservation that reads the map before that is
/// refused as one that ran before the return, exactly as one racing a
/// `Shared` return's subtract is, and the next reservation at `limit` reads
/// the set bit and finds the credit. A reservation whose scan overlapped
/// another scan's clear and reload of a map word may have read a bit that
/// scan held clear over a credit, so it refuses with `Contended`.
///
/// Every step is paid before it runs. Loading the map's words costs
/// nothing; the visit to the lender of the last take at the limit costs one
/// visit for both its words, and each other visit to a flagged record's
/// return line or pool costs one; a sweep of a map word costs one update
/// per bit it clears plus three, and its take from a record it flagged
/// again pays only that take's coordination attempt; the engine-wide
/// subtract of a surplus costs an update; each subtract from a record's
/// words and each compare-exchange costs a coordination attempt. A subtract
/// that found nothing pays for its own give-back.
///
/// # Errors
///
/// `BudgetExhausted` if the first attempt cannot be paid, `LeaseLimit` if
/// every credit is reserved, `Contended` if the budget ran out after at
/// least one attempt failed or a concurrent scan may have hidden a credit.
#[inline]
pub(crate) fn reserve_credit<P: Platform>(
    storage: &Storage<P>,
    limit: usize,
    credit: Credit,
    budget: &mut WorkBudget,
) -> Result<(), CreditError> {
    let index = match credit {
        Credit::Read => return Ok(()),
        Credit::Shared => {
            return reserve_shared(storage.leases(), limit, budget, 1)
                .map(|_| ())
                .or_else(|error| match error {
                    CreditError::LeaseLimit => take_parked(storage, None, budget),
                    error => Err(error),
                });
        }
        Credit::Record(index) => index,
    };
    let pool = &storage.registrations()[index].idle;
    let seen = credit::credits(pool, Ordering::Relaxed);
    if seen > 0 && seen <= TRIM_ABOVE {
        if take_from::<credit::Sequential, _>(storage, index, pool, 1, budget)? == 1 {
            return Ok(());
        }
    } else if seen == 0 {
        // A lone returned credit is taken where it lies: the whole cycle of
        // a reader with one credit at a tight limit.
        let line = &storage.returns()[index].returned;
        if credit::credits(line, Ordering::Relaxed) == 1
            && take_from::<credit::Sequential, _>(storage, index, line, 1, budget)? == 1
        {
            return Ok(());
        }
    }
    refill(storage, limit, index, seen, budget)
}

/// The rest of a `Record` reservation once the record's own pool showed
/// nothing it could take with one subtract: the trimming take when the pool
/// showed more than [`TRIM_ABOVE`], else the return line, the engine-wide
/// counter and the other records, in that order. Out of line, so the common
/// take stays small.
#[inline(never)]
fn refill<P: Platform>(
    storage: &Storage<P>,
    limit: usize,
    index: usize,
    seen: usize,
    budget: &mut WorkBudget,
) -> Result<(), CreditError> {
    let leases = storage.leases();
    if seen > TRIM_ABOVE {
        // Trimming costs an update ahead of the take's compare-exchange, so
        // it runs only when the budget holds both steps.
        let trim = budget.preflight(2).is_ok() && budget.debit(WorkKind::Update).is_ok();
        match take_own(&storage.registrations()[index].idle, leases, budget, trim) {
            Ok(surplus) => {
                if surplus > 0 {
                    probe::note(Primitive::Rmw);
                    let previous = leases.reserved.fetch_sub(surplus, Ordering::Release);
                    debug_assert!(previous >= surplus, "surplus beyond the reservation");
                }
                return Ok(());
            }
            Err(CreditError::LeaseLimit) => {}
            Err(error) => return Err(error),
        }
    }
    // The reader collects the record's returned credits in one subtract when
    // its pool runs out, so a lease dropped on another thread costs that
    // thread's line one transfer per batch.
    let line = &storage.returns()[index].returned;
    let waiting = credit::credits(line, Ordering::Relaxed);
    if waiting > 0 {
        let returned = take_from::<credit::Sequential, _>(storage, index, line, waiting, budget)?;
        if returned > 0 {
            if returned > 1 {
                park::<credit::Sequential, _>(storage, index, returned - 1);
            }
            return Ok(());
        }
    }
    match reserve_shared(leases, limit, budget, BORROW) {
        Ok(borrowed) => {
            if borrowed > 1 {
                park::<credit::Sequential, _>(storage, index, borrowed - 1);
            }
            Ok(())
        }
        Err(CreditError::LeaseLimit) => take_parked(storage, Some(index), budget),
        Err(error) => Err(error),
    }
}

/// Takes one credit from the reader's own `idle` and, when `trim` is set and
/// the record holds more than [`TRIM_ABOVE`], the surplus above [`KEEP`]
/// with it, in one compare-exchange; returns the surplus, which the caller
/// gives back to the engine-wide counter. `LeaseLimit` here means the record
/// showed none.
#[inline(always)]
fn take_own(
    idle: &AtomicUsize,
    leases: &LeaseControls,
    budget: &mut WorkBudget,
    trim: bool,
) -> Result<usize, CreditError> {
    let surplus = |current: usize| {
        if trim && current > TRIM_ABOVE {
            current - KEEP
        } else {
            0
        }
    };
    let previous = bounded_update(
        idle,
        idle.load(Ordering::Relaxed),
        &leases.cas_failed,
        &leases.cas_spurious,
        budget,
        |current| {
            if current as isize <= 0 {
                Err(())
            } else {
                Ok(current - 1 - surplus(current))
            }
        },
    )
    .map_err(credit_error)?;
    Ok(surplus(previous))
}

/// Takes up to `share` credits from `word`, record `index`'s pool or its
/// return line, with one paid, unconditional subtract ([`credit::take`]):
/// what the word held, when fewer, with the excess given back in the same
/// paid step. Returns how many were taken; zero when the word held none.
/// The subtract never waits on another writer, so a record whose owner takes
/// while another thread returns, or while another reader takes from it,
/// costs each side one read-modify-write.
#[inline(always)]
fn take_from<S: credit::Strength, R: RecordWords>(
    records: &R,
    index: usize,
    word: &R::Credit,
    share: usize,
    budget: &mut WorkBudget,
) -> Result<usize, CreditError> {
    budget
        .debit(WorkKind::CoordinationAttempt)
        .map_err(|_| CreditError::BudgetExhausted)?;
    probe::note(Primitive::Rmw);
    let (map, bit) = map_bit(records, index);
    Ok(credit::take::<S, _, _>(word, map, bit, share))
}

/// Takes one credit from record `index`'s return line, where the record's
/// returns wait and its owner reads once per batch. A `Record` borrower
/// takes up to a borrow of them, the rest parked in its own record, so a
/// reader whose demand outgrew its record scans once per batch.
#[inline(always)]
fn take_returned<S: credit::Strength, R: RecordWords>(
    records: &R,
    index: usize,
    own: Option<usize>,
    budget: &mut WorkBudget,
) -> Result<(), CreditError> {
    let line = records.line(index);
    let waiting = credit::credits(line, Ordering::Relaxed);
    if waiting == 0 {
        return Err(CreditError::LeaseLimit);
    }
    let share = if own.is_some() {
        waiting.min(BORROW)
    } else {
        1
    };
    let taken = take_from::<S, _>(records, index, line, share, budget)?;
    if taken == 0 {
        return Err(CreditError::LeaseLimit);
    }
    if let Some(own) = own
        && taken > 1
    {
        park::<S, _>(records, own, taken - 1);
    }
    Ok(())
}

/// Takes one credit from record `index`'s pool, the word its owner takes
/// from.
#[inline(always)]
fn take_pooled<S: credit::Strength, R: RecordWords>(
    records: &R,
    index: usize,
    budget: &mut WorkBudget,
) -> Result<(), CreditError> {
    let pool = records.pool(index);
    if credit::credits(pool, Ordering::Relaxed) == 0
        || take_from::<S, _>(records, index, pool, 1, budget)? == 0
    {
        return Err(CreditError::LeaseLimit);
    }
    Ok(())
}

/// Takes one credit from record `index`: from its return line when that
/// shows some, else from its pool when that shows some.
#[inline(always)]
fn take_idle<S: credit::Strength, R: RecordWords>(
    records: &R,
    index: usize,
    own: Option<usize>,
    budget: &mut WorkBudget,
) -> Result<(), CreditError> {
    match take_returned::<S, _>(records, index, own, budget) {
        Err(CreditError::LeaseLimit) => take_pooled::<S, _>(records, index, budget),
        outcome => outcome,
    }
}

/// Both of record `index`'s words as the credits they hold.
#[inline(always)]
pub(crate) fn record_credits<R: RecordWords>(
    records: &R,
    index: usize,
    ordering: Ordering,
) -> usize {
    credit::credits(records.pool(index), ordering) + credit::credits(records.line(index), ordering)
}

#[inline]
pub(crate) fn drain_record<P: Platform>(storage: &Storage<P>, index: usize) -> usize {
    let (map, bit) = map_bit(storage, index);
    let pool = &storage.registrations()[index].idle;
    let line = &storage.returns()[index].returned;
    credit::drain::<credit::Sequential, _, _>(pool, map, bit)
        + credit::drain::<credit::Sequential, _, _>(line, map, bit)
}

/// Adds `count` credits to record `index`'s pool through [`credit::park`],
/// which sets the record's bit in the parked map when the pool held none.
#[inline(always)]
fn park<S: credit::Strength, R: RecordWords>(records: &R, index: usize, count: usize) {
    let (map, bit) = map_bit(records, index);
    credit::park::<S, _, _>(records.pool(index), map, bit, count);
}

/// Each record exposes idle credits through `pool` and returned credits
/// through `line`; map word `w` covers records `64 * w` through
/// `64 * w + 63`.
pub(crate) trait RecordWords {
    type Credit: credit::CreditWord;
    type Bits: credit::BitWord;
    fn bits(&self, word: usize) -> &Self::Bits;
    fn pool(&self, index: usize) -> &Self::Credit;
    fn line(&self, index: usize) -> &Self::Credit;
}

/// A refusal scan takes credits from registration records flagged in the
/// parked-credit map, and refuses only after checking each map word's
/// sweep counts.
pub(crate) trait ParkedCredits: RecordWords {
    type Sweeps: credit::SweepWord;
    /// Registration records.
    fn records(&self) -> usize;
    /// Words of the parked map.
    fn map_words(&self) -> usize;
    fn sweeps(&self, word: usize) -> &Self::Sweeps;
    /// Records `lender` as the record `own`'s last take at the limit came
    /// from.
    fn lent(&self, own: usize, lender: usize);
}

impl<P: Platform> RecordWords for Storage<P> {
    type Credit = AtomicUsize;
    type Bits = AtomicU64;

    #[inline(always)]
    fn bits(&self, word: usize) -> &AtomicU64 {
        &self.parked()[word].bits
    }

    #[inline(always)]
    fn pool(&self, index: usize) -> &AtomicUsize {
        &self.registrations()[index].idle
    }

    #[inline(always)]
    fn line(&self, index: usize) -> &AtomicUsize {
        &self.returns()[index].returned
    }
}

/// A refusal's scan derives each slice once here, so its loads between
/// atomic steps use the cached slices.
struct Parked<'a> {
    map: &'a [ParkedWord],
    records: &'a [RegistrationRecord],
    lines: &'a [ReturnLine],
}

impl<'a> Parked<'a> {
    #[inline(always)]
    fn of<P: Platform>(storage: &'a Storage<P>) -> Self {
        Self {
            map: storage.parked(),
            records: storage.registrations(),
            lines: storage.returns(),
        }
    }
}

impl RecordWords for Parked<'_> {
    type Credit = AtomicUsize;
    type Bits = AtomicU64;

    #[inline(always)]
    fn bits(&self, word: usize) -> &AtomicU64 {
        &self.map[word].bits
    }

    #[inline(always)]
    fn pool(&self, index: usize) -> &AtomicUsize {
        &self.records[index].idle
    }

    #[inline(always)]
    fn line(&self, index: usize) -> &AtomicUsize {
        &self.lines[index].returned
    }
}

impl ParkedCredits for Parked<'_> {
    type Sweeps = AtomicU64;

    #[inline(always)]
    fn records(&self) -> usize {
        self.records.len()
    }

    #[inline(always)]
    fn map_words(&self) -> usize {
        self.map.len()
    }

    #[inline(always)]
    fn sweeps(&self, word: usize) -> &AtomicU64 {
        &self.map[word].sweeps
    }

    #[inline(always)]
    fn lent(&self, own: usize, lender: usize) {
        self.records[own].lender.store(lender, Ordering::Relaxed);
    }
}

/// Record `index`'s map word and its bit there.
#[inline(always)]
fn map_bit<R: RecordWords>(records: &R, index: usize) -> (&R::Bits, u64) {
    (
        records.bits(index / PARKED_PER_WORD),
        1 << (index % PARKED_PER_WORD),
    )
}

/// Takes idle credits from another record. A flagged lender of the
/// borrower's last take at the limit is visited first: a reader whose
/// demand outgrew its record takes from others once per lookup, and the
/// lender that served the last one usually serves the next. Then the
/// return lines of the
/// records whose bits in the parked map are set, in index order, so every
/// reader at the limit draws on the same lowest lenders and the rest keep
/// their credits and their lines; a record flagged after the word was loaded
/// is visited by the reload that follows each pass, until a load shows
/// nothing new. After the lender, within each map word, the records' own
/// pools are visited only once every flagged return line there showed
/// nothing, so a reader whose returns wait on its line lends those first
/// and keeps the pool it is drawing on, and its line stays its own. The
/// map's `ceil(R / 64)` words are the fixed check a refusal at the limit
/// makes, loaded unpaid; the lender's two words are one paid visit, each
/// word of another record the scan visits is one, a take from it a
/// coordination step, and a sweep's take from a record it flagged again
/// only that step. A scan that finds no credit in a word's lines and pools
/// clears the bits of the records it found empty there and loads each once
/// more ([`sweep`]), so a credit that landed between the first load and the
/// clear gets its bit back and is taken. A scan clears a word's bits only
/// after every record it visited in that word showed nothing, so a return
/// finds a set bit clear only after a scan saw the record empty. A failed
/// debit spends the remainder and refuses before any credit changes hands.
///
/// Between a sweep's clear and its reset a record may hold a credit under a
/// clear bit. Every word's `sweeps` is loaded before its first bit load and
/// again after its last, all `SeqCst` with a sweep's count updates and its
/// clear, so a bit load that fell inside another sweep's window shows as a
/// sweep in progress at the first load or a started sweep by the second,
/// beyond the scan's own. Such a scan refuses with `Contended`, since it
/// cannot show that every credit backs a live lease.
#[inline]
fn take_parked<P: Platform>(
    storage: &Storage<P>,
    own: Option<usize>,
    budget: &mut WorkBudget,
) -> Result<(), CreditError> {
    let records = storage.registrations();
    if let Some(index) = own {
        let lender = records[index].lender.load(Ordering::Relaxed);
        if lender != index
            && lender < records.len()
            && let (map, bit) = map_bit(storage, lender)
            && map.load(Ordering::Relaxed) & bit != 0
        {
            budget
                .debit(WorkKind::Visit)
                .map_err(|_| CreditError::BudgetExhausted)?;
            #[cfg(test)]
            RECORDS_SCANNED.with(|scanned| scanned.set(scanned.get() + 1));
            match take_idle::<credit::Sequential, _>(storage, lender, own, budget) {
                Ok(()) => return Ok(()),
                Err(CreditError::LeaseLimit) => {}
                Err(error) => return Err(error),
            }
        }
    }
    scan_parked::<credit::Sequential, _>(&Parked::of(storage), own, budget)
}

/// The scan of [`take_parked`] after its lender. For each map word in
/// turn: its flagged return lines in index order, then the pools of the
/// records whose lines showed nothing, then the sweep of the records found
/// empty; then the refusal, `Contended` when any word's sweep counts show a
/// sweep beyond this scan's own, else `LeaseLimit`. `S` chooses the credit
/// steps' orderings and fences; the bit and sweep-count loads are `SeqCst`.
/// Production runs [`credit::Sequential`].
#[inline]
pub(crate) fn scan_parked<S: credit::Strength, R: ParkedCredits>(
    records: &R,
    own: Option<usize>,
    budget: &mut WorkBudget,
) -> Result<(), CreditError> {
    let mut hidden = false;
    for w in 0..records.map_words() {
        let counts = records.sweeps(w);
        let sweeps = counts.load(Ordering::SeqCst);
        let ours = match records.bits(w).load(Ordering::SeqCst) {
            0 => 0,
            flagged => match scan_word::<S, _>(records, w, flagged, own, budget)? {
                Some(ours) => ours,
                None => return Ok(()),
            },
        };
        hidden |= sweeps & SWEEPS_IN_PROGRESS != 0
            || counts.load(Ordering::SeqCst) != sweeps.wrapping_add(ours);
    }
    if hidden {
        Err(CreditError::Contended)
    } else {
        Err(CreditError::LeaseLimit)
    }
}

/// The part of [`scan_parked`] for map word `w`, whose first load showed
/// `flagged`: `None` once it takes a credit, else the sweep count its own
/// sweep added to the word, `SWEEP_STARTED` or zero.
#[inline(never)]
fn scan_word<S: credit::Strength, R: ParkedCredits>(
    records: &R,
    w: usize,
    flagged: u64,
    own: Option<usize>,
    budget: &mut WorkBudget,
) -> Result<Option<u64>, CreditError> {
    let base = w * PARKED_PER_WORD;
    let visitable = visitable(records.records(), w, own);
    let mut seen = 0u64;
    let mut fresh = flagged;
    loop {
        seen |= fresh;
        let mut order = fresh & visitable;
        while order != 0 {
            let index = base + order.trailing_zeros() as usize;
            order &= order - 1;
            budget
                .debit(WorkKind::Visit)
                .map_err(|_| CreditError::BudgetExhausted)?;
            #[cfg(test)]
            RECORDS_SCANNED.with(|scanned| scanned.set(scanned.get() + 1));
            match take_returned::<S, _>(records, index, own, budget) {
                Ok(()) => {
                    if let Some(own) = own {
                        records.lent(own, index);
                    }
                    return Ok(None);
                }
                Err(CreditError::LeaseLimit) => {}
                Err(error) => return Err(error),
            }
        }
        fresh = records.bits(w).load(Ordering::SeqCst) & !seen;
        if fresh == 0 {
            break;
        }
    }
    // Every flagged return line was empty: the records' own pools, which
    // their owners draw on, are visited only now. A visit that took nothing
    // leaves its record among the empty ones, so the records the sweep
    // clears are every one visited.
    let visited = seen & visitable;
    let mut order = visited;
    while order != 0 {
        let index = base + order.trailing_zeros() as usize;
        order &= order - 1;
        budget
            .debit(WorkKind::Visit)
            .map_err(|_| CreditError::BudgetExhausted)?;
        #[cfg(test)]
        RECORDS_SCANNED.with(|scanned| scanned.set(scanned.get() + 1));
        match take_pooled::<S, _>(records, index, budget) {
            Ok(()) => {
                if let Some(own) = own {
                    records.lent(own, index);
                }
                return Ok(None);
            }
            Err(CreditError::LeaseLimit) => {}
            Err(error) => return Err(error),
        }
    }
    if visited == 0 {
        return Ok(Some(0));
    }
    match sweep::<S, _>(records, w, visited, own, budget) {
        Ok(()) => Ok(None),
        Err(CreditError::LeaseLimit) => Ok(Some(SWEEP_STARTED)),
        Err(error) => Err(error),
    }
}

/// The bits of map word `w` that name a record other than `own`.
#[inline(always)]
fn visitable(records: usize, w: usize, own: Option<usize>) -> u64 {
    let present = match records.saturating_sub(w * PARKED_PER_WORD) {
        n if n >= PARKED_PER_WORD => u64::MAX,
        n => (1 << n) - 1,
    };
    match own {
        Some(own) if own / PARKED_PER_WORD == w => present & !(1 << (own % PARKED_PER_WORD)),
        _ => present,
    }
}

/// Clears the bits of `empty` in word `w` of the parked map, loads each of
/// those records once more, sets the bits of every record that gained a
/// credit back, and takes one credit from the first of them, in index
/// order, that yields one. The clears and
/// the one set are paid as updates before the first clear, so a budget that
/// cannot pay leaves the map as it was, and a budget that can leaves every
/// record with a credit flagged whatever the take's outcome. The clear is
/// `SeqCst` and so are the reload and a return's add and bit load
/// ([`park`]): whichever of the add and the clear comes first in the total
/// order, either the return sees the bit clear and sets it, or the reload
/// sees the credit. The word's `sweeps` counts this sweep as in progress
/// from before the clear until after the reset, with both updates paid in
/// the same debit, so a concurrent refusal that read a cleared bit in that
/// window sees the count ([`take_parked`]).
#[inline(never)]
fn sweep<S: credit::Strength, R: ParkedCredits>(
    records: &R,
    w: usize,
    empty: u64,
    own: Option<usize>,
    budget: &mut WorkBudget,
) -> Result<(), CreditError> {
    budget
        .debit_n(WorkKind::Update, empty.count_ones() as usize + 3)
        .map_err(|_| CreditError::BudgetExhausted)?;
    #[cfg(test)]
    let pause = PAUSE_IN_SWEEP.try_with(|hook| hook.take()).ok().flatten();
    #[cfg(test)]
    if let Some(pause) = pause {
        pause(false);
    }
    probe::note_n(Primitive::Rmw, 2);
    records
        .sweeps(w)
        .fetch_add(SWEEP_STARTED | 1, Ordering::SeqCst);
    credit::clear::<S, _>(records.bits(w), empty);
    #[cfg(test)]
    if let Some(pause) = pause {
        pause(true);
    }
    let index = |bit: u64| w * PARKED_PER_WORD + bit.trailing_zeros() as usize;
    let mut regained = 0;
    let mut again = empty;
    while again != 0 {
        let bit = again.isolate_lowest_one();
        if record_credits(records, index(bit), S::RELOAD) > 0 {
            regained |= bit;
        }
        again &= again - 1;
    }
    if regained != 0 {
        probe::note(Primitive::Rmw);
        credit::reset(records.bits(w), regained);
    }
    probe::note(Primitive::Rmw);
    records.sweeps(w).fetch_sub(1, Ordering::SeqCst);
    while regained != 0 {
        let bit = regained.isolate_lowest_one();
        regained ^= bit;
        match take_idle::<S, _>(records, index(bit), own, budget) {
            Ok(()) => return Ok(()),
            Err(CreditError::LeaseLimit) => {}
            Err(error) => return Err(error),
        }
    }
    Err(CreditError::LeaseLimit)
}

/// Adds up to `want` credits to the engine-wide counter, as many as remain
/// below `limit` and at least one; returns how many were added.
#[inline(always)]
fn reserve_shared(
    leases: &LeaseControls,
    limit: usize,
    budget: &mut WorkBudget,
    want: usize,
) -> Result<usize, CreditError> {
    let previous = bounded_update(
        &leases.reserved,
        leases.reserved.load(Ordering::Relaxed),
        &leases.cas_failed,
        &leases.cas_spurious,
        budget,
        |current| {
            if current >= limit {
                Err(())
            } else {
                Ok(current + want.min(limit - current))
            }
        },
    )
    .map_err(credit_error)?;
    Ok(want.min(limit - previous))
}

fn credit_error(error: IncrementError<()>) -> CreditError {
    match error {
        IncrementError::Refused(()) => CreditError::LeaseLimit,
        IncrementError::Contended => CreditError::Contended,
        IncrementError::BudgetExhausted => CreditError::BudgetExhausted,
    }
}

/// Returns one reserved credit after the holder's last slot access: to the
/// engine-wide counter for a `Shared` credit, to the record's return line
/// for a `Record` one. The credit remains lent until that record's lookups
/// move it into the record and use it, a reservation at the limit takes it,
/// or the registration's drop returns the record's credits to the counter.
/// A `Record` return is complete, and its credit available to other records,
/// once the record's bit in the parked map is set: at the add when the bit
/// was already set, else at the set that follows ([`credit::park`]).
#[inline(always)]
pub(crate) fn return_credit<P: Platform>(storage: &Storage<P>, credit: Credit) {
    match credit {
        Credit::Shared => return_shared(storage, 1),
        Credit::Record(index) => {
            probe::note(Primitive::Rmw);
            let (map, bit) = map_bit(storage, index);
            credit::park::<credit::Sequential, _, _>(
                &storage.returns()[index].returned,
                map,
                bit,
                1,
            );
        }
        Credit::Read => {}
    }
}

/// Returns `count` reserved `Shared` credits to the engine-wide counter
/// with one subtraction, after each holder's last slot access.
#[inline(always)]
pub(crate) fn return_shared<P: Platform>(storage: &Storage<P>, count: usize) {
    probe::note(Primitive::Rmw);
    let previous = storage
        .leases()
        .reserved
        .fetch_sub(count, Ordering::Release);
    debug_assert!(previous >= count, "credit returned without a reservation");
}

/// Reserves `count` `Shared` credits, `count` at least one, within `limit`:
/// the first exchange on the engine-wide counter grants as many as remain
/// below `limit`, and [`reserve_credit`] reserves each remaining one. The
/// charges are those of `count` calls of [`reserve_credit`] less one
/// exchange per credit the first exchange granted beyond one. A refusal returns every credit this call
/// reserved before it.
///
/// # Errors
///
/// As [`reserve_credit`].
// `#[inline]` gives the claim path, the one caller, its own copy to inline whichever codegen unit the caller is built in.
#[inline]
pub(crate) fn reserve_shared_credits<P: Platform>(
    storage: &Storage<P>,
    limit: usize,
    count: usize,
    budget: &mut WorkBudget,
) -> Result<(), CreditError> {
    let granted = match reserve_shared(storage.leases(), limit, budget, count) {
        Ok(granted) => granted,
        // The refused exchange stands for the first credit's, so that credit
        // goes straight to the parked ones, as `reserve_credit` sends it.
        Err(CreditError::LeaseLimit) => {
            take_parked(storage, None, budget)?;
            1
        }
        Err(error) => return Err(error),
    };
    for reserved in granted..count {
        if let Err(error) = reserve_credit(storage, limit, Credit::Shared, budget) {
            if reserved != 0 {
                return_shared(storage, reserved);
            }
            return Err(error);
        }
    }
    Ok(())
}

impl<P: Platform> Storage<P> {
    /// Credits backing a lease, a reserved fill or a joined publication's row
    /// right now: the engine-wide
    /// counter less every record's idle and returned credits, each word a
    /// sample.
    pub(super) fn credits_in_use(&self) -> usize {
        let records = self.registrations();
        probe::note_n(Primitive::Load, 1 + 2 * records.len());
        let taken = self.leases().reserved.load(Ordering::Acquire);
        let idle: usize = (0..records.len())
            .map(|index| record_credits(self, index, Ordering::Acquire))
            .sum();
        taken.saturating_sub(idle)
    }

    /// Engine-wide lease figures, or `None` once drained.
    pub fn lease_report(&self) -> Option<LeaseReport> {
        if !self.is_live() {
            return None;
        }
        let leases = self.leases();
        Some(LeaseReport {
            reserved: self.credits_in_use(),
            cas_failed: leases.cas_failed.load(Ordering::Relaxed),
            cas_spurious: leases.cas_spurious.load(Ordering::Relaxed),
        })
    }
}

#[cfg(test)]
impl<'s, P: Platform> Completed<'s, P> {
    /// Anchors the object and hands out the first lease: reserves one credit
    /// and one read right, installs the anchor, and returns the [`Resident`]
    /// authority over the anchored object together with the lease.
    /// Consuming the completed owner is the proof that no writer remains and
    /// that nothing else has seen the object.
    ///
    /// # Errors
    ///
    /// The owner comes back unchanged with a [`HandoffError`]; a reserved
    /// credit is returned before the error.
    pub fn handoff(
        self,
        budget: &mut WorkBudget,
    ) -> Result<(Resident<'s, P>, ExtentLease<'s, P>), (Self, HandoffError)> {
        let (storage, id) = self.parts();
        match anchor(storage, id, budget) {
            Ok(()) => {
                let key = self.key;
                let (storage, id) = self.into_parts();
                Ok((
                    Resident { storage, id, key },
                    ExtentLease::new(storage, id, key, Credit::Shared),
                ))
            }
            Err(error) => Err((self, error)),
        }
    }
}

/// The fallible part of the handoff: on success one credit is reserved and
/// `id`'s `refs` went from zero to two under the completed owner's exclusive
/// authority.
#[cfg(test)]
fn anchor<P: Platform>(
    storage: &Storage<P>,
    id: AllocationId,
    budget: &mut WorkBudget,
) -> Result<(), HandoffError> {
    let (pool, root) = storage
        .live()
        .expect("a completed owner keeps the storage live");
    // SAFETY: `id` was issued by this storage, so its slot index is below `O`.
    let slot_word = unsafe { pool.slot_word(id.slot().0) };
    // The word was last touched when the slot's extent returned or at its
    // claim, so its line is usually cold by now; fetching it while the
    // credit is reserved overlaps that miss with the credit's
    // compare-exchange.
    hint(slot_word.as_ptr().cast());
    reserve_credit(storage, root.lease_limit, Credit::Shared, budget)?;
    // Anchor plus the publisher's right, from an idle count; exposure to
    // other threads is the move of the returned values.
    if !word::install(slot_word, id.incarnation(), 2) {
        return_credit(storage, Credit::Shared);
        return Err(HandoffError::AnchorPresent);
    }
    Ok(())
}

/// The authority over one anchored resident object. Not `Clone`; no public
/// constructor. Consuming it, by [`retire`](Self::retire) or by drop, is the
/// retirement of the object: every acquisition borrowed this value, so none
/// can still be in progress once it is gone, and no writer has existed since
/// completion. The anchor itself is released later by service, after grace.
#[cfg(test)]
pub struct Resident<'s, P: Platform> {
    storage: &'s Storage<P>,
    id: AllocationId,
    /// The key the object was completed under, which its leases carry.
    key: Key,
}

#[cfg(test)]
impl<P: Platform> std::fmt::Debug for Resident<'_, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Resident")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
impl<'s, P: Platform> Resident<'s, P> {
    pub fn id(&self) -> AllocationId {
        self.id
    }

    pub(crate) fn storage(&self) -> &'s Storage<P> {
        self.storage
    }

    pub(crate) fn key(&self) -> &Key {
        &self.key
    }

    /// The deadline's whole seconds `bind` stored.
    pub(crate) fn expires_at_s(&self) -> u32 {
        self.storage.pool().records()[self.id.slot().0].expires_at_s()
    }
}

#[cfg(test)]
impl<P: Platform> Resident<'_, P> {
    /// Retires the object: bumps the era once and stamps the slot with the
    /// era returned, then records the retirement obligation for service with
    /// the flag write that marks the anchor as awaiting grace. The anchor is
    /// not released here; service releases it once a completed certification
    /// pass has certified an era above the stamp. Fixed work: one era
    /// increment, one stamp store, one nonblocking gate attempt, then a
    /// ledger move or a park, each ending in one read-modify-write on the
    /// slot's flag, and, on a bump into or inside the terminal band, the
    /// store that closes admission. Nothing waits, scans, enqueues, frees or
    /// unmaps; leases outstanding keep their bytes.
    pub fn retire(self) -> RetireOutcome {
        // `Drop` must not run after this body: a panic inside it would
        // otherwise bump the era and stamp the slot a second time.
        let this = std::mem::ManuallyDrop::new(self);
        this.record_retirement()
    }

    fn record_retirement(&self) -> RetireOutcome {
        // SAFETY: `id` was issued for its pool and this authority holds the
        // anchor, so `refs >= 1`.
        let counted = super::coverage::register(&self.storage.pool().journal_words().epochs);
        // SAFETY: as above; the registration is a plain count and no part of the anchor's proof.
        unsafe { retire_anchored(self.storage, self.id, false, counted) }
    }
}

/// Records the retirement obligation of the anchored object `id` for service:
/// bumps the era once and stamps the slot with the era returned, then moves
/// the slot to retired or parks the obligation, marking the anchor as
/// awaiting grace with the same flag write. The anchor is not released here.
/// The caller's authority over the object has ended: the resident authority
/// consumed, or the index mapping that named the object cleared under its
/// shard gate. Fixed work, nothing waits, scans, enqueues, frees or unmaps.
///
/// # Safety
///
/// `storage` is live and `id` names its current completed object, whose
/// anchor is counted (`refs >= 1`) and not marked as awaiting grace: the
/// caller holds the object's one retirement obligation, by consuming the
/// resident authority or by clearing the mapping under the shard gate. The
/// anchor's release needs the mark this call sets.
// Forced inline, as `abandon` is: this is the whole body of the resident
// authority's drop and of a retirement obligation's record.
#[inline(always)]
pub(crate) unsafe fn retire_anchored<P: Platform>(
    storage: &Storage<P>,
    id: AllocationId,
    evicted: bool,
    counted: Option<u64>,
) -> RetireOutcome {
    let pool = storage.pool();
    let slot = id.slot().0;
    // The bump follows the end of the object's visibility: the mapping's
    // removal commit, or the consumed resident authority whose leases stay
    // counted in `refs`. A reader that observed the object pinned an era no
    // greater than the stamp; the `grace` module proves the rest. Every
    // stamp in the terminal band closes admission with `SeqCst` before the
    // mark below is published, so a crossing thread paused here cannot see
    // its slot recycled into a newly admitted object: the next terminal
    // retirement closes first, and nothing admitted after the close can
    // claim a slot whose mark is still unpublished.
    let bump = grace::bump::<_, Sequential>(&storage.eras().era);
    #[cfg(test)]
    if let Ok(Some(interpose)) = INTERPOSE_BEFORE_TERMINAL_CLOSE.try_with(|hook| hook.take()) {
        interpose(bump.retire_era);
    }
    if bump.closes_admission {
        storage.close();
    }
    // The stamp is stored before the flag and carried by the release
    // read-modify-write that sets the anchored bit service reads: the one
    // `abandon` makes for the abandonment, which sets both bits at once.
    // The mapping has ended, so the record's fingerprint word takes the
    // stamp. The slot stays `Resident` until the abandonment reaches the
    // ledger, and an eviction or expiry that copies the era in that window
    // routes its removal to a chain without the pair and ends `Absent`. Every
    // retirement of a mapped object runs on the thread that cleared the
    // mapping, after the clear's release fence (behind the odd store, or
    // before a terminal shard's bare stores). A lookup that copied the pair
    // earlier and reads the era with `Acquire` is ordered after the odd or
    // terminal sequence value, and its bracket refuses the copy. In a
    // serving shard the `Release` stamp also carries the even commit.
    pool.records()[slot].stamp_era(bump.retire_era);
    // The anchor keeps `refs >= 1`, and an extent returns only at zero, so
    // the slot record still names this object: a park here means the
    // gate was unavailable, never that the slot moved on, and the stamp
    // above always lands on this object's slot.
    abandon(pool, id, Owned::Resident, ANCHORED, evicted, counted).0
}

#[cfg(test)]
impl<P: Platform> Drop for Resident<'_, P> {
    fn drop(&mut self) {
        self.record_retirement();
    }
}

#[cfg(test)]
thread_local! {
    /// Runs once between a retirement's era bump and its admission close on
    /// this thread, with the stamp the bump returned, so a test can hold a
    /// terminal-band retirement before it closes and publishes its mark.
    pub(crate) static INTERPOSE_BEFORE_TERMINAL_CLOSE: std::cell::Cell<Option<fn(u64)>> =
        const { std::cell::Cell::new(None) };
}

/// One response's read right over one resident object:
/// [`Volume::read`](super::Volume::read) reads the object's record from the
/// device under it. See the module documentation for the credit, reference
/// and release contracts.
///
/// [`Volume::read`](super::Volume::read) consumes the lease: once the read
/// is admitted, its record takes over the lease's right and the lease's
/// credit goes back to its source. A refusal before admission returns the
/// lease whole. A caller that needs the bytes again takes a new lease.
// `repr(C)` with the key first: the key's two 16-byte stores start at the
// lease's first byte, so each 16-byte move that carries a lease into its
// caller's slot loads exactly one of those stores and takes it by
// store-to-load forwarding.
#[repr(C)]
pub struct ExtentLease<'s, P: Platform> {
    /// The key the lease was taken for: the lookup's argument, the
    /// publishing fill's key, or in tests the `Resident` authority's key.
    /// The volume read checks the record header
    /// against it.
    key: Key,
    storage: &'s Storage<P>,
    id: AllocationId,
    /// Where the credit came from, so the drop returns it there.
    credit: Credit,
}

impl<'s, P: Platform> ExtentLease<'s, P> {
    /// A lease over `id`, taken for `key`, whose credit, taken as `credit`,
    /// and right are already reserved.
    pub(crate) fn new(storage: &'s Storage<P>, id: AllocationId, key: Key, credit: Credit) -> Self {
        Self {
            storage,
            id,
            key,
            credit,
        }
    }

    /// The storage whose slot this lease's right is counted on.
    pub(crate) fn storage(&self) -> &'s Storage<P> {
        self.storage
    }
}

impl<P: Platform> std::fmt::Debug for ExtentLease<'_, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtentLease")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl<P: Platform> ExtentLease<'_, P> {
    /// The identity this lease's right is counted on; no production surface
    /// takes a bare identity in exchange for a lease.
    pub(crate) fn id(&self) -> AllocationId {
        self.id
    }

    /// The key the lease was taken for.
    pub(crate) fn key(&self) -> &Key {
        &self.key
    }

    /// Ends the lease into a volume read: returns the credit to its source
    /// and yields the identity whose right stays counted. The caller owns
    /// that right and releases it with [`release_right`].
    pub(super) fn into_read_right(self) -> AllocationId {
        let lease = std::mem::ManuallyDrop::new(self);
        return_credit(lease.storage, lease.credit);
        lease.id
    }
}

#[cfg(test)]
impl<P: Platform> ExtentLease<'_, P> {
    /// The duplicate owns a separate `Shared` credit and right, allowing
    /// tests to read the object while retaining the original lease.
    ///
    /// # Panics
    ///
    /// The method panics if `reserve_lease` returns an error.
    pub(crate) fn duplicate(&self) -> Self {
        // SAFETY: the slot index was issued for its pool, and this lease's
        // right keeps the object's count positive for the whole call.
        unsafe { super::acquire::reserve_lease(self.storage, self.id, &mut WorkBudget::new(64)) }
            .expect("a duplicate lease");
        Self::new(self.storage, self.id, self.key, Credit::Shared)
    }
}

#[cfg(test)]
thread_local! {
    /// Runs between the object-right release and the credit return of a lease
    /// dropped on this thread, so a test can observe the still-charged credit
    /// without a public partial-release API.
    pub(crate) static PAUSE_BEFORE_CREDIT_RETURN: std::cell::Cell<Option<fn()>> =
        const { std::cell::Cell::new(None) };

    /// Runs once on the counter between a bounded credit update's load and
    /// its next compare-exchange on this thread, so a test can make that
    /// attempt lose deterministically.
    pub(crate) static INTERPOSE_BEFORE_CAS: std::cell::Cell<Option<fn(&AtomicUsize)>> =
        const { std::cell::Cell::new(None) };

    /// As [`INTERPOSE_BEFORE_CAS`], for a retain's compare-exchange on a
    /// slot's word.
    pub(crate) static INTERPOSE_BEFORE_RETAIN: std::cell::Cell<Option<fn(&AtomicU64)>> =
        const { std::cell::Cell::new(None) };

    /// Registration records visited by idle-credit scans on this thread.
    pub(crate) static RECORDS_SCANNED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };

    /// Lets a test complete a return just before a sweep's clear of the
    /// parked bits (`false`) and run another reader's reservation between
    /// that clear and the sweep's reload of the cleared records (`true`).
    pub(crate) static PAUSE_IN_SWEEP: std::cell::Cell<Option<fn(bool)>> =
        const { std::cell::Cell::new(None) };
}

impl<P: Platform> Drop for ExtentLease<'_, P> {
    fn drop(&mut self) {
        release(self.storage, self.id, self.credit);
    }
}

/// Returns one right on `id`, then `credit`, in the release order the
/// module documentation states. The caller owns both and makes no slot
/// access after this call.
#[inline(always)]
fn release<P: Platform>(storage: &Storage<P>, id: AllocationId, credit: Credit) {
    // SAFETY: `id` was issued for its pool, so its slot index is below `O`.
    let slot_word = unsafe { storage.pool().slot_word(id.slot().0) };
    // Final slot access: with this right live the count is positive, so
    // the subtraction leaves a well-formed count. Release publishes every
    // read made under this right to the acquire load that observes terminal
    // zero.
    probe::note(Primitive::Rmw);
    let previous = slot_word.fetch_sub(word::REF, Ordering::Release);
    debug_assert!(word::refs(previous) >= 1, "lease released without a right");
    #[cfg(test)]
    if let Ok(Some(pause)) = PAUSE_BEFORE_CREDIT_RETURN.try_with(|hook| hook.take()) {
        pause();
    }
    return_credit(storage, credit);
}

/// Returns one right on `id` that a volume operation holds, a read's or a
/// fill's write set's, with a `Release` `fetch_sub`: the operation's last
/// access to the slot, ordered before the acquire load of zero that lets
/// service return the extent. The caller gives up that right and makes no
/// access to the extent afterwards.
///
/// # Panics
///
/// If `id`'s slot is outside `storage`'s slot table.
#[inline]
pub(super) fn release_right<P: Platform>(storage: &Storage<P>, id: AllocationId) {
    let pool = storage.pool();
    let slot = id.slot().0;
    assert!(
        slot < pool.records().len(),
        "a right outside the slot table"
    );
    // SAFETY: `slot < O`, checked above.
    let slot_word = unsafe { pool.slot_word(slot) };
    let previous = slot_word.fetch_sub(word::REF, Ordering::Release);
    debug_assert!(
        word::refs(previous) >= 1,
        "an operation released without its right"
    );
}

/// One right on `id` that a registered lookup reserved under [`Credit::Read`],
/// owned until a volume read's record takes it over. Dropping the guard
/// releases the right with [`release_right`], so a read refused after its
/// lookup returns the right it reserved.
pub(super) struct ReadRight<'s, P: Platform> {
    storage: &'s Storage<P>,
    id: AllocationId,
}

impl<'s, P: Platform> ReadRight<'s, P> {
    /// Takes ownership of one right on `id`, already reserved.
    pub(super) fn new(storage: &'s Storage<P>, id: AllocationId) -> Self {
        Self { storage, id }
    }

    /// The identity the right is counted on.
    pub(super) fn id(&self) -> AllocationId {
        self.id
    }

    /// Ends the guard and yields the identity whose right stays counted, for
    /// the read record that takes the right over.
    pub(super) fn into_id(self) -> AllocationId {
        std::mem::ManuallyDrop::new(self).id
    }
}

impl<P: Platform> Drop for ReadRight<'_, P> {
    fn drop(&mut self) {
        release_right(self.storage, self.id);
    }
}

/// The right and the `Shared` credit a publication reserves for the lease it
/// returns, owned until that lease is built. Dropping it returns both as the
/// lease's drop would, so an unwind after settlement and before the lease's
/// construction leaks neither. Publication builds the lease last, after the
/// gate release and the retirement record, from the storage and identity it
/// holds.
pub(super) struct Preowned<'s, P: Platform> {
    storage: &'s Storage<P>,
    id: AllocationId,
}

impl<'s, P: Platform> Preowned<'s, P> {
    /// Takes ownership of one right on `id` and one `Shared` credit, both
    /// already reserved.
    pub(super) fn new(storage: &'s Storage<P>, id: AllocationId) -> Self {
        Self { storage, id }
    }

    /// Ends the guard without returning its claims. Call it only after
    /// building an `ExtentLease` over the same `id` with `Credit::Shared`,
    /// which then owns the right and the credit; otherwise both leak and
    /// the slot never returns.
    pub(super) fn transfer(self) {
        std::mem::forget(self);
    }
}

impl<P: Platform> Drop for Preowned<'_, P> {
    fn drop(&mut self) {
        release(self.storage, self.id, Credit::Shared);
    }
}

#[cfg(test)]
mod tests {
    //! Recorded exemptions: this crate has no facade type and no publisher.
    //! The domain root is the `&Storage` borrow, so "facade loss" has no
    //! witness and `Drained` is unreachable while any lease exists by
    //! construction (teardown needs `&mut Storage`). Completion cannot be
    //! incomplete or withheld: the layout fixes both lengths at reservation
    //! and the only completion is consuming the owner, which the compile-fail
    //! snippets cover. `Contended` needs a compare-exchange that lost to
    //! another writer; the kernel below counts every lost attempt but cannot
    //! force one, so the refusal itself is unexercised.

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Barrier, OnceLock};

    use super::super::budget::WorkBudget;
    use super::super::config::{ConfigError, StorageConfig};
    use super::super::finalize::Finalization;
    use super::super::owner::Storage;
    use super::super::placement::PlacementConfig;
    use super::super::release::Outstanding;
    use super::super::tables::{SlotIndex, SlotState};
    use super::super::test_platform::{TestPlatform, finalize};
    use super::{
        ExtentLease, HandoffError, INTERPOSE_BEFORE_CAS, IncrementError, LeaseReport,
        PAUSE_BEFORE_CREDIT_RETURN, Resident, bounded_update,
    };

    const PAGE: usize = 4096;
    const SLOTS: usize = 8;
    const KEY: [u8; 32] = [0x5A; 32];

    fn storage_with(
        slot_count: usize,
        lease_limit: usize,
        object_rights: usize,
    ) -> Storage<TestPlatform> {
        let config = StorageConfig {
            page_size: PAGE,
            engine_budget: 1 << 24,
            body_cap: 200,
            metadata_cap: Some(16),
            lease_limit,
            object_rights,
            reader_limit: 4,
            volume: crate::storage::test_volume(slot_count * crate::storage::IO_UNIT, slot_count),
        };
        let placement = PlacementConfig { control_home: 0 };

        Storage::initialize(
            &config.validate().unwrap(),
            &placement,
            TestPlatform::heap(PAGE),
        )
        .unwrap()
    }

    fn storage(slot_count: usize) -> Storage<TestPlatform> {
        storage_with(slot_count, 4, 3)
    }

    /// Room for a Miri run, where a weak compare-exchange fails spuriously
    /// most of the time; on hardware one attempt is the norm.
    fn budget() -> WorkBudget {
        WorkBudget::new(1 << 10)
    }

    /// A completed object with producer-held bytes.
    fn completed<'s>(
        storage: &'s Storage<TestPlatform>,
        metadata: &[u8],
        body: &[u8],
    ) -> super::super::Completed<'s, TestPlatform> {
        let mut allocation = storage
            .reserve(Some(metadata.len()), Some(body.len()), &mut budget())
            .unwrap();
        allocation.mark_written();
        match allocation.complete(KEY, 7, &mut budget()) {
            Ok(completed) => completed,
            Err((_, error)) => panic!("{error:?}"),
        }
    }

    fn handoff<'s>(
        storage: &'s Storage<TestPlatform>,
        metadata: &[u8],
        body: &[u8],
    ) -> (Resident<'s, TestPlatform>, ExtentLease<'s, TestPlatform>) {
        match completed(storage, metadata, body).handoff(&mut budget()) {
            Ok(pair) => pair,
            Err((_, error)) => panic!("{error:?}"),
        }
    }

    fn report(storage: &Storage<TestPlatform>) -> LeaseReport {
        storage.lease_report().unwrap()
    }

    fn refs(storage: &Storage<TestPlatform>, slot: usize) -> usize {
        storage.live_pool().unwrap().refs(slot)
    }

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn handoff_reserves_one_credit_one_right_and_the_anchor() {
        assert_send_sync::<ExtentLease<'static, TestPlatform>>();
        assert_send_sync::<Resident<'static, TestPlatform>>();
        let storage = storage(SLOTS);
        let body: Vec<u8> = (0..60u8).map(|b| b ^ 0x33).collect();
        let owner = completed(&storage, &[4; 8], &body);
        let slot = owner.id().slot_index();
        let resident_before = storage.pool_report().unwrap();
        assert_eq!(refs(&storage, slot), 0);
        let allocations = crate::instrument::allocations();

        let mut spent = budget();
        let (resident, lease) = owner.handoff(&mut spent).ok().unwrap();
        // One attempt on hardware, where a single thread cannot provoke a
        // weak failure; under Miri, which injects spurious failures, one
        // attempt per injected failure more.
        let spurious = report(&storage).cas_spurious;
        if cfg!(miri) {
            assert_eq!(spent.counters().coordination_attempts, 1 + spurious);
        } else {
            assert_eq!((spent.counters().coordination_attempts, spurious), (1, 0));
        }
        assert_eq!(
            report(&storage),
            LeaseReport {
                reserved: 1,
                cas_failed: 0,
                cas_spurious: spurious,
            }
        );
        assert_eq!(refs(&storage, slot), 2);
        assert_eq!(resident.id().slot_index(), slot);
        assert_eq!(resident.key(), &KEY);
        assert_eq!(crate::instrument::allocations(), allocations);

        assert_eq!(refs(&storage, slot), 2);
        assert_eq!(report(&storage).reserved, 1);
        assert_eq!(crate::instrument::allocations(), allocations);
        // The ledger is unchanged by the handoff: one resident object.
        assert_eq!(storage.pool_report().unwrap(), resident_before);

        // Dropping the lease releases the right and the credit; the anchor
        // stays and the object stays resident and readable.
        drop(lease);
        assert_eq!(crate::instrument::allocations(), allocations);
        assert_eq!(refs(&storage, slot), 1);
        assert_eq!(report(&storage).reserved, 0);
        assert_eq!(
            storage.slot_state(SlotIndex(slot)),
            Some((SlotState::Resident, 1))
        );
        assert_eq!(storage.pool_report().unwrap(), resident_before);
        drop(resident);
    }

    /// Generated handoff, drop and move histories over several objects
    /// against an independent per-operation ledger of credits, rights and
    /// anchors at every prefix.
    #[test]
    fn credit_right_and_anchor_ledgers_agree_at_every_prefix() {
        const WIDE: usize = 64;
        let slot_count = WIDE;
        let storage = storage_with(slot_count, 3, 2);
        let mut seed = 0x9E37_79B9u32;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed
        };
        // Independent model: per slot (rights, anchor) and the credit total.
        let mut model_rights = [0usize; WIDE];
        let mut model_anchor = [0usize; WIDE];
        let mut model_credits = 0usize;
        let mut residents: Vec<Resident<'_, TestPlatform>> = Vec::new();
        let mut leases: Vec<ExtentLease<'_, TestPlatform>> = Vec::new();
        let mut handoffs = 0;
        let mut limit_hits = 0;
        for step in 0..300 {
            match next() % 4 {
                0 | 1 if residents.len() < 40 => {
                    let owner = completed(&storage, &[step as u8; 2], &[step as u8; 30]);
                    let slot = owner.id().slot_index();
                    match owner.handoff(&mut budget()) {
                        Ok((resident, lease)) => {
                            assert!(model_credits < 3);
                            model_credits += 1;
                            model_rights[slot] += 1;
                            model_anchor[slot] = 1;
                            residents.push(resident);
                            leases.push(lease);
                            handoffs += 1;
                        }
                        Err((owner, HandoffError::LeaseLimit)) => {
                            assert_eq!(model_credits, 3);
                            limit_hits += 1;
                            // The refused owner is unchanged and returns.
                            assert_eq!(refs(&storage, slot), 0);
                            assert_eq!(
                                storage.return_allocation(owner.release(), &mut budget()),
                                Ok(super::super::ReturnOutcome::Returned)
                            );
                        }
                        Err((_, error)) => panic!("{error:?}"),
                    }
                }
                2 if !leases.is_empty() => {
                    let index = next() as usize % leases.len();
                    let lease = leases.swap_remove(index);
                    let slot = lease.id.slot_index();
                    // Moving the lease adds nothing.
                    let moved =
                        std::thread::scope(|scope| scope.spawn(move || lease).join()).unwrap();
                    assert_eq!(model_credits, report(&storage).reserved);
                    drop(moved);
                    model_credits -= 1;
                    model_rights[slot] -= 1;
                }
                _ => {}
            }
            assert_eq!(report(&storage).reserved, model_credits, "{step}");
            assert!(model_credits <= 3);
            for slot in 0..WIDE {
                assert!(model_rights[slot] <= 1);
                assert_eq!(
                    refs(&storage, slot),
                    model_rights[slot] + model_anchor[slot],
                    "{step} {slot}"
                );
            }
        }
        assert!(handoffs >= 10, "{handoffs}");
        assert!(limit_hits >= 1, "{limit_hits}");
        // Every exposed object whose lease is gone keeps its anchor.
        drop(leases);
        for resident in &residents {
            assert_eq!(refs(&storage, resident.id().slot_index()), 1);
        }
        assert_eq!(report(&storage).reserved, 0);
        drop(residents);
    }

    #[test]
    fn refusals_return_the_owner_and_refund_once() {
        let storage = storage_with(SLOTS, 1, 2);
        let body = [9u8; 20];
        let (first_resident, first_lease) = handoff(&storage, &[1], &body);
        assert_eq!(report(&storage).reserved, 1);

        // Zero budget: no attempt, no counter moves, no allocation.
        let owner = completed(&storage, &[2], &body);
        let slot = owner.id().slot_index();
        let before = report(&storage);
        let allocations = crate::instrument::allocations();
        let (owner, error) = owner.handoff(&mut WorkBudget::new(0)).err().unwrap();
        assert_eq!(error, HandoffError::BudgetExhausted);
        assert_eq!(report(&storage), before);
        assert_eq!(refs(&storage, slot), 0);

        // At the limit: one attempt paid, refused, nothing reserved.
        let mut one = WorkBudget::new(1);
        let (owner, error) = owner.handoff(&mut one).err().unwrap();
        assert_eq!(error, HandoffError::LeaseLimit);
        assert_eq!(one.counters().coordination_attempts, 1);
        assert_eq!(report(&storage), before);
        assert_eq!(refs(&storage, slot), 0);
        assert!(storage.identity_is_current(owner.id()));

        // Free the credit; a stale nonzero count refuses the anchor and the
        // credit reserved for the attempt is refunded exactly once.
        drop(first_lease);
        assert_eq!(report(&storage).reserved, 0);
        storage.live_pool().unwrap().set_refs(slot, 5);
        let (owner, error) = owner.handoff(&mut budget()).err().unwrap();
        assert_eq!(error, HandoffError::AnchorPresent);
        assert_eq!(report(&storage).reserved, 0);
        assert_eq!(refs(&storage, slot), 5);
        assert_eq!(crate::instrument::allocations(), allocations);
        storage.live_pool().unwrap().set_refs(slot, 0);
        // A reserved bit beside the idle count refuses the anchor too.
        storage
            .live_pool()
            .unwrap()
            .edit_word(slot, |word| word | 1 << 43);
        let (owner, error) = owner.handoff(&mut budget()).err().unwrap();
        assert_eq!(error, HandoffError::AnchorPresent);
        assert_eq!(report(&storage).reserved, 0);
        storage
            .live_pool()
            .unwrap()
            .edit_word(slot, |word| word & !(1 << 43));

        // Now it succeeds and the earlier resident is untouched.
        let (resident, lease) = owner.handoff(&mut budget()).ok().unwrap();
        assert_eq!(refs(&storage, slot), 2);
        assert_eq!(report(&storage).reserved, 1);
        assert_eq!(refs(&storage, first_resident.id().slot_index()), 1);
        drop((lease, resident, first_resident));
    }

    /// One attempt made to lose deterministically: the lost attempt is
    /// counted, a budget of one refuses `Contended` with nothing reserved and
    /// the owner intact, and a budget of two succeeds on the retry.
    #[test]
    fn a_lost_credit_attempt_is_charged_and_refunded() {
        fn steal(counter: &AtomicUsize) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
        let storage = storage(SLOTS);
        let owner = completed(&storage, &[6; 4], &[6; 40]);
        let slot = owner.id().slot_index();
        let allocations = crate::instrument::allocations();

        INTERPOSE_BEFORE_CAS.with(|hook| hook.set(Some(steal)));
        let mut one = WorkBudget::new(1);
        let (owner, error) = owner.handoff(&mut one).err().unwrap();
        assert_eq!(error, HandoffError::Contended);
        assert_eq!(one.counters().coordination_attempts, 1);
        let after = report(&storage);
        assert_eq!((after.reserved, after.cas_failed), (1, 1));
        assert_eq!(refs(&storage, slot), 0);
        assert_eq!(crate::instrument::allocations(), allocations);
        // Undo the stolen credit; the interposer ran exactly once.
        assert!(INTERPOSE_BEFORE_CAS.with(|hook| hook.get().is_none()));
        storage.leases().reserved.fetch_sub(1, Ordering::Relaxed);

        INTERPOSE_BEFORE_CAS.with(|hook| hook.set(Some(steal)));
        let (resident, lease) = owner.handoff(&mut budget()).ok().unwrap();
        let after = report(&storage);
        assert_eq!((after.reserved, after.cas_failed), (2, 2));
        assert_eq!(refs(&storage, slot), 2);
        drop(lease);
        storage.leases().reserved.fetch_sub(1, Ordering::Relaxed);
        assert_eq!(report(&storage).reserved, 0);
        drop(resident);
    }

    /// When `ExchangeLost` fires, `update_after` counts every exchange the
    /// budget covers as lost to another writer, spends the budget and
    /// returns `Contended` with the word unchanged. The point asks the
    /// chooser only once the budget paid for an attempt and `next` accepted
    /// the value. When `ExchangeLost` fires during `handoff`, `handoff`
    /// returns `HandoffError::Contended` with nothing reserved and the owner
    /// intact.
    #[test]
    fn a_fired_exchange_lost_point_spends_the_budget_and_leaves_the_word() {
        use crate::sim::chaos::{acting, arm, sites};
        use std::{cell::RefCell, rc::Rc};
        // Each fed zero lets the armed point fire once.
        let chooser = Rc::new(RefCell::new(crate::sim::choice::Chooser::fed(
            &sites(1),
            vec![0, 0, 1, 0],
        )));
        let incarnation = chooser.borrow_mut().launch(1);
        let (failed, spurious) = (AtomicUsize::new(0), AtomicUsize::new(0));
        let word = AtomicUsize::new(5);
        let update = |budget: &mut WorkBudget, admit: bool| {
            acting(|| {
                bounded_update(&word, 5, &failed, &spurious, budget, |value| {
                    if admit { Ok(value + 1) } else { Err(()) }
                })
            })
        };
        let armed = arm(&chooser, (1, incarnation), [0, 0, 1]);
        let mut five = WorkBudget::new(5);
        assert_eq!(update(&mut five, true), Err(IncrementError::Contended));
        assert_eq!(word.load(Ordering::Relaxed), 5);
        assert_eq!(
            (
                failed.load(Ordering::Relaxed),
                spurious.load(Ordering::Relaxed)
            ),
            (5, 0)
        );
        assert_eq!(
            (five.remaining(), five.counters().coordination_attempts),
            (0, 5)
        );
        assert_eq!(chooser.borrow().decisions(), 1);
        let mut refused = WorkBudget::new(5);
        assert_eq!(
            update(&mut refused, false),
            Err(IncrementError::Refused(()))
        );
        assert_eq!(refused.remaining(), 4);
        let mut unpaid = WorkBudget::new(0);
        assert_eq!(
            update(&mut unpaid, true),
            Err(IncrementError::BudgetExhausted)
        );
        assert_eq!(chooser.borrow().decisions(), 1, "no exchange was due");

        let storage = storage(SLOTS);
        let owner = completed(&storage, &[6; 4], &[6; 40]);
        let slot = owner.id().slot_index();
        let mut eight = WorkBudget::new(8);
        let (owner, error) = acting(|| owner.handoff(&mut eight)).err().unwrap();
        assert_eq!(error, HandoffError::Contended);
        assert_eq!(eight.remaining(), 0);
        let after = report(&storage);
        assert_eq!((after.reserved, after.cas_spurious), (0, 0));
        assert_eq!(after.cas_failed, eight.counters().coordination_attempts);
        assert_eq!(refs(&storage, slot), 0);
        assert_eq!(chooser.borrow().decisions(), 2);
        assert_eq!(armed.disarm(), None);
        let (resident, lease) = acting(|| owner.handoff(&mut budget())).ok().unwrap();
        assert_eq!(report(&storage).reserved, 1);
        assert_eq!(chooser.borrow().decisions(), 2);
        drop((lease, resident));

        // A fire after an exchange another writer won adds to that loss.
        fn steal(counter: &AtomicUsize) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
        failed.store(0, Ordering::Relaxed);
        let armed = arm(&chooser, (1, incarnation), [0, 0, 4]);
        INTERPOSE_BEFORE_CAS.with(|hook| hook.set(Some(steal)));
        let mut five = WorkBudget::new(5);
        assert_eq!(update(&mut five, true), Err(IncrementError::Contended));
        assert_eq!(word.load(Ordering::Relaxed), 6);
        assert_eq!(failed.load(Ordering::Relaxed), 5);
        assert_eq!(
            (five.remaining(), five.counters().coordination_attempts),
            (0, 5)
        );
        assert_eq!(chooser.borrow().decisions(), 4);
        assert_eq!(armed.disarm(), None);
    }

    /// A writer changes the credit word between 0 and 1 before every
    /// exchange. With a lease limit of 2 both counts admit another attempt,
    /// so `handoff` returns `Contended` with the budget spent and every paid
    /// attempt counted as failed. With a limit of 1 the second attempt
    /// returns `LeaseLimit` after one failed exchange.
    #[test]
    fn writers_win_every_paid_exchange_only_from_a_lease_limit_of_two() {
        fn alternate(counter: &AtomicUsize) {
            counter.fetch_xor(1, Ordering::Relaxed);
            INTERPOSE_BEFORE_CAS.with(|hook| hook.set(Some(alternate)));
        }
        assert_eq!(crate::sim::chaos::EXCHANGE_LOST_LEASE_LIMIT, 2);
        for limit in [1, 2] {
            let storage = storage_with(SLOTS, limit, 3);
            let owner = completed(&storage, &[6; 4], &[6; 40]);
            INTERPOSE_BEFORE_CAS.with(|hook| hook.set(Some(alternate)));
            let mut five = WorkBudget::new(5);
            let (owner, error) = owner.handoff(&mut five).err().unwrap();
            INTERPOSE_BEFORE_CAS.with(|hook| hook.set(None));
            let (failed, paid) = (
                report(&storage).cas_failed,
                five.counters().coordination_attempts,
            );
            if limit == 1 {
                assert_eq!((error, failed), (HandoffError::LeaseLimit, 1));
                assert!(paid >= 2, "the refused attempt was paid: {paid}");
            } else {
                assert_eq!((error, failed), (HandoffError::Contended, 5));
                assert_eq!((five.remaining(), paid), (0, 5));
            }
            storage.leases().reserved.store(0, Ordering::Relaxed);
            drop(owner);
        }
    }

    /// The release ordering: right, then credit, then root. Observed from
    /// another thread while the dropping thread is paused between the two
    /// decrements; the slot's flag, state and record are untouched.
    #[test]
    fn final_drop_on_another_thread_releases_right_then_credit_then_root() {
        static PAUSE: OnceLock<Barrier> = OnceLock::new();
        static RESUME: OnceLock<Barrier> = OnceLock::new();
        fn pause() {
            PAUSE.get().unwrap().wait();
            RESUME.get().unwrap().wait();
        }
        PAUSE.get_or_init(|| Barrier::new(2));
        RESUME.get_or_init(|| Barrier::new(2));

        let storage = storage(SLOTS);
        let body: Vec<u8> = (100..160u8).collect();
        let (resident, lease) = handoff(&storage, &[8; 8], &body);
        let slot = resident.id().slot_index();
        let live = storage.live_pool().unwrap();
        let flag_before = live.flags(slot);
        let shared = &storage;
        std::thread::scope(|scope| {
            scope.spawn(move || {
                PAUSE_BEFORE_CREDIT_RETURN.with(|hook| hook.set(Some(pause)));
                drop(lease);
            });
            PAUSE.get().unwrap().wait();
            // Right released, credit still charged, root still retained.
            assert_eq!(refs(shared, slot), 1);
            assert_eq!(report(shared).reserved, 1);
            assert_eq!(live.flags(slot), flag_before);
            assert_eq!(
                shared.slot_state(SlotIndex(slot)),
                Some((SlotState::Resident, 1))
            );
            RESUME.get().unwrap().wait();
        });
        assert_eq!(report(&storage).reserved, 0);
        assert_eq!(refs(&storage, slot), 1);
        assert_eq!(live.flags(slot), flag_before);
        assert!(PAUSE_BEFORE_CREDIT_RETURN.with(|hook| hook.get().is_none()));
        drop(resident);

        // The earlier resident's slot has no right left; its anchor waits
        // for grace.
        let earlier = slot;
        assert_eq!(refs(&storage, earlier), 1);

        // A delayed final drop after the authority is gone: the slot is
        // retired and flagged with the anchor awaiting grace, the lease still
        // reads its bytes, and service holds the slot while the right remains.
        let (resident, lease) = handoff(&storage, &[8; 8], &body);
        let slot = resident.id().slot_index();
        drop(resident);
        assert_eq!(
            storage.slot_state(SlotIndex(slot)),
            Some((SlotState::Retired, 1))
        );
        assert_eq!(refs(&storage, slot), 2);
        // One certified pass covers both retirements: the earlier slot
        // returns; this one is held by the lease's right.
        let _ = storage.certify(&mut WorkBudget::new(64)).unwrap();
        let pass = storage.service(&mut WorkBudget::new(64)).unwrap();
        assert_eq!((pass.serviced, pass.held, pass.released), (1, 1, 2));
        assert_eq!(refs(&storage, earlier), 0);
        assert_eq!(refs(&storage, slot), 1);
        let delayed = std::thread::scope(|scope| scope.spawn(move || lease).join()).unwrap();
        assert_eq!(report(&storage).reserved, 1);
        drop(delayed);
        assert_eq!(report(&storage).reserved, 0);
        assert_eq!(refs(&storage, slot), 0);
        assert_eq!(
            storage.outstanding(),
            Outstanding {
                pending: 1,
                ..Outstanding::default()
            }
        );
        let pass = storage.service(&mut WorkBudget::new(64)).unwrap();
        assert_eq!((pass.serviced, pass.held), (1, 0));
        assert!(storage.outstanding().is_clear());
    }

    /// Several threads hand off distinct objects against one credit counter
    /// and release them; every attempt is charged, the lost and spurious
    /// attempts are counted, and the counter ends where the model says.
    #[test]
    fn concurrent_handoffs_charge_every_attempt_and_conserve_credits() {
        let slot_count = 64;
        let mut storage = storage_with(slot_count, 6, 2);
        let attempts = std::sync::atomic::AtomicUsize::new(0);
        let successes = std::sync::atomic::AtomicUsize::new(0);
        let limit_hits = std::sync::atomic::AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for worker in 0..4u8 {
                let storage = &storage;
                let attempts = &attempts;
                let successes = &successes;
                let limit_hits = &limit_hits;
                scope.spawn(move || {
                    for round in 0..40u8 {
                        let Ok(mut allocation) = storage.reserve(Some(1), Some(1), &mut budget())
                        else {
                            continue;
                        };
                        allocation.mark_written();
                        let Ok(owner) = allocation.complete([worker; 32], 1, &mut budget()) else {
                            continue;
                        };
                        let mut spent = WorkBudget::new(4);
                        let outcome = owner.handoff(&mut spent);
                        attempts
                            .fetch_add(spent.counters().coordination_attempts, Ordering::Relaxed);
                        match outcome {
                            Ok((resident, lease)) => {
                                successes.fetch_add(1, Ordering::Relaxed);
                                if round % 2 == 0 {
                                    drop(lease);
                                    drop(resident);
                                } else {
                                    drop(resident);
                                    drop(lease);
                                }
                            }
                            Err((owner, HandoffError::LeaseLimit)) => {
                                limit_hits.fetch_add(1, Ordering::Relaxed);
                                drop(owner);
                            }
                            Err((owner, HandoffError::Contended)) => drop(owner),
                            Err((_, error)) => panic!("{error:?}"),
                        }
                    }
                });
            }
        });
        let report = report(&storage);
        assert_eq!(report.reserved, 0);
        let attempts = attempts.load(Ordering::Relaxed);
        let successes = successes.load(Ordering::Relaxed);
        let limit_hits = limit_hits.load(Ordering::Relaxed);
        assert!(successes >= 4, "{successes}");
        // Every attempt ended in success, a limit refusal, a lost or a
        // spurious compare-exchange.
        assert_eq!(
            attempts,
            successes + limit_hits + report.cas_failed + report.cas_spurious
        );
        // Every dropped authority stamped its retirement and every lease
        // released its right, so one certified pass then service returns
        // every slot and teardown drains.
        let _ = storage.certify(&mut WorkBudget::new(400)).unwrap();
        loop {
            let pass = storage.service(&mut WorkBudget::new(400)).unwrap();
            if pass.serviced == 0 && !pass.budget_exhausted {
                assert_eq!(pass.held, 0);
                break;
            }
        }
        assert!(storage.outstanding().is_clear());
        assert_eq!(finalize(&mut storage), Ok(Finalization::Drained));
    }

    #[test]
    fn a_park_for_an_earlier_incarnation_changes_no_bit() {
        let storage = storage(SLOTS);
        let body = [3u8; 64];
        let (resident, lease) = handoff(&storage, &[], &body);
        let id = resident.id();
        let slot = id.slot_index();
        assert_eq!(refs(&storage, slot), 2);
        {
            let live = storage.live_pool().unwrap();
            let before = live.word(slot);
            for stale in [id.incarnation() - 1, id.incarnation() + 1] {
                super::super::release::park(live, slot, stale);
                assert_eq!(live.word(slot), before);
                assert_eq!(live.telemetry().pending_marks.load(Ordering::Acquire), 0);
            }
        }

        let pass = storage.service(&mut WorkBudget::new(64)).unwrap();
        assert_eq!((pass.serviced, pass.held), (0, 0));
        let live = storage.live_pool().unwrap();
        assert_eq!(live.flags(slot), 0);
        assert_eq!(live.telemetry().pending_marks.load(Ordering::Acquire), 0);
        assert_eq!(
            storage.slot_state(SlotIndex(slot)),
            Some((SlotState::Resident, id.incarnation()))
        );
        assert_eq!(refs(&storage, slot), 2);
        drop((lease, resident));
    }

    #[test]
    fn object_rights_must_leave_room_for_the_anchor() {
        let config = StorageConfig {
            page_size: PAGE,
            engine_budget: 1 << 24,
            body_cap: 200,
            metadata_cap: Some(16),
            lease_limit: 4,
            object_rights: usize::MAX,
            reader_limit: 4,
            volume: crate::storage::test_volume(SLOTS * crate::storage::IO_UNIT, SLOTS),
        };
        assert_eq!(
            config.validate().err(),
            Some(ConfigError::InvalidObjectRights {
                object_rights: usize::MAX
            })
        );
        let full = super::super::word::REFS_MAX;
        assert_eq!(
            StorageConfig {
                object_rights: full,
                ..config
            }
            .validate()
            .err(),
            Some(ConfigError::InvalidObjectRights {
                object_rights: full
            })
        );
        assert_eq!(
            StorageConfig {
                object_rights: 0,
                ..config
            }
            .validate()
            .err(),
            Some(ConfigError::InvalidObjectRights { object_rights: 0 })
        );
        let validated = StorageConfig {
            object_rights: full - 1,
            ..config
        }
        .validate()
        .unwrap();
        assert_eq!(validated.object_rights(), full - 1);
        assert_eq!(validated.lease_limit(), 4);
        let storage = storage(SLOTS);
        let root = storage.root_descriptor().unwrap();
        assert_eq!((root.lease_limit, root.object_rights), (4, 3));
    }
}
