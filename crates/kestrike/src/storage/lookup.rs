//! Registered lookup: one complete key to one lease, through the reader's
//! pinned interval, a coherent snapshot, protected identity validation,
//! fingerprint equality, the shared reservation step and a final live witness;
//! or exactly one refusal with every reservation refunded and the pin ended.
//! `Registration::lookup_right` runs the same call for a volume read: it
//! reserves the right alone, under `Credit::Read`, and returns it as a
//! `ReadRight` for the read's record to take over.
//!
//! Order of one call. The admission cutoff is read first, as the fixed
//! administrative check every public call makes after close, so a closed
//! cache refuses without touching the reader's record. The key is routed
//! next, unpaid and with its search's first lines hinted, when the budget
//! could pay the pass and the call has no supplied route. The interval is
//! then pinned before any bucket load, and the entry reads the cutoff once
//! more after its pin store, the read that orders the pin against the
//! close. The route is charged and the key
//! is copied through the snapshot's [`Observation`], every pair whose tag
//! matches the key's. For every copied candidate, in order: the slot is
//! checked against the volume's slot count; the slot's record line is
//! hinted for writing; the slot's lifetime word is
//! loaded once, its incarnation's low 16 bits must equal the copied ones,
//! and that incarnation is the identity the lease names; the word must be
//! well formed and its reference count positive. Only then is the record's
//! fingerprint loaded, with `Acquire`, and compared with the key's. Tags only
//! filter; a mismatching fingerprint moves on to the next candidate, so a tag
//! shared by two keys of one bucket costs one record read and no device read.
//! The fingerprint, beside the validated incarnation, is the object's
//! identity, so a lookup whose key shares its fingerprint with another
//! key's object returns a lease on that object. The lease carries the
//! requested key, and the volume read checks it against the record's header
//! before any byte, so that read ends `HeaderMismatch(Key)`. A candidate
//! that fails a check before the fingerprint is a malformed table or a stale
//! copy that protection excludes, and the call fails closed as `Contended`
//! after reading only the lifetime word, before any other record field is
//! read. A stable, complete, exhausted search with no equal fingerprint is
//! `Missing` only through its own bracket: the cutoff read, then the
//! sequence load that must still show the copy's value. A moved sequence
//! consumes the attempt, so a search that completed over a copy a mutation
//! then overtook is repeated, not reported; an unchanged sequence with
//! admission closed is `Closed`. Nothing else is `Missing`.
//!
//! A retirement overwrites the fingerprint with its era once the mapping has
//! ended. The thread that cleared the mapping stores the stamp after the
//! clear's release fence: the fence behind the bracket's odd store or, in a
//! terminal shard, the fence the hold issues before its bare stores. In a
//! serving shard the even commit also precedes the stamp, and the stamp's
//! `Release` carries it. A candidate whose `Acquire` fingerprint load reads
//! the era synchronizes with that fence, so every later sequence load of
//! this call reads the odd or terminal value or a later one, never the
//! copy's. An era that differs from the key's fingerprint skips the
//! candidate; an era equal to it is reserved like a match. Either way
//! reading an era never yields `Missing` or a hit: the bracket that ends
//! the search, the final bracket of a match or the absence bracket, finds
//! the sequence moved and spends the attempt, and only those brackets
//! return `Missing`, `Expired` or a hit, so every earlier exit returns
//! another error.
//!
//! On the first equal fingerprint the credit and the right are reserved
//! through the counters the validation resolved ([`LeaseCounters`]), the retain
//! expecting the word the validation read, so a retain that meets a moved
//! incarnation fails; the retain sets the word's visited bit in the same
//! exchange, which is the hit's SIEVE record, and a retain the final
//! bracket then refuses leaves it set. Then the final bracket: one fresh sample and the cutoff read,
//! followed by the sequence load that must still show the copy's value. The
//! deadline is compared only against that sample, after the reservation, so
//! an expired object costs its lookup the reservation and its refund, and
//! one sample serves both the hit and the expiry verdict, so a hit reads the
//! clock once. A refused limit takes
//! the same sample: below the deadline seconds the refusal stands; at or
//! past them, and when `now_ticks` returns `None`, the bracket runs with
//! zero reservations and its verdict, `Moved`, `Closed`, `ClockUnavailable`
//! or `Expired`, replaces the limit. A moved
//! sequence refunds right then credit and consumes the attempt, whatever
//! the sample said: a candidate observed at second 9 and replaced before its
//! deadline of second 10 is never `Expired` at second 10. An unchanged sequence with
//! admission closed refunds and returns `Closed`; a failed sample refunds
//! and returns `ClockUnavailable`; a sample at or past the deadline refunds
//! and returns `Expired`; otherwise the reservations move into the hit, the
//! pin ends, and the lookup then builds the returned lease from them. The
//! reservation is held by a guard until that move into the lease, so an
//! unwind before it refunds it as well.
//!
//! The Hit witness is the instant of that sample. The conjuncts it
//! establishes are: the exact incarnation was visible in the shard's stable
//! state throughout, because the sequence read the copy's value after the
//! sample and equal even values exclude any intervening mutation; the object
//! was retained, because the right was reserved before the bracket against a
//! counter the mapping's anchor kept positive; the object was unexpired, by
//! the sample's whole seconds below the deadline seconds; and admission was open, by the
//! cutoff read inside the same bracket and before the sequence load. The two
//! sequence loads, the scan's identity loads and the cutoff load are all
//! `SeqCst`, so they sit in one total order with the shard's commits and the
//! close. The word load is `Acquire`: the incarnation and the count come
//! from one load, and a positive count beside the copied incarnation is
//! this object's anchor or right. The grace argument keeps the copied incarnation current for
//! the interval; the count check fails closed on a table protection
//! excludes. Removal or replacement before the final sequence load
//! invalidates the candidate even with the right already counted; existing
//! leases are never revalidated.
//!
//! The sample is one `CLOCK_MONOTONIC` read through the platform: elapsed
//! time as the host reports it, frequency-adjusted and not counting suspend,
//! at the resolution recorded in the root descriptor. A deadline is kept in
//! whole seconds of that timeline, rounded down, and the sample's whole
//! seconds are compared against it, so an object whose deadline lies within
//! `u32::MAX` seconds expires up to one second early, and every object
//! expires no later than its deadline. The sample is never restarted or
//! cached; a caller converting freshness into a deadline owns the conversion, and one that must expire
//! across suspend gates or invalidates on resume. The platform's sample runs
//! inside the pinned interval; the platform contract makes it one clock read
//! and nothing else.
//!
//! Work. Every step is paid before it runs, and no charge is ever returned
//! to the budget; the refunds below are of reservations, never of steps.
//! The administrative cutoff read every public call makes after close and
//! the unpaid route derivation before the pin are outside the inventory.
//! The inventory, in call order:
//!
//! - The guard bundle, [`GUARD_STEPS`] units, before the pin: the era
//!   check, the leaked-interval check and the final cutoff check as
//!   comparisons, the pin store, the clearing store and the record's
//!   statistics as updates. It is preflighted whole, so an allowance short
//!   of it pins nothing, hashes nothing and is left as it was; a leaked
//!   interval or a terminal era then refuses for the bundle alone.
//! - The hash pass, [`HASH_CHARGE`](crate::index::HASH_CHARGE), once,
//!   before the first attempt.
//! - Per attempt, the whole scan bound before the first sequence load:
//!   `1 + D` visits and `14 (1 + D) + 2` comparisons, the two being the
//!   sequence validations that bracket the scan. The bound is preflighted
//!   whole; a short allowance is left as it was and the attempt is refused
//!   before any bucket load, so a copy torn or moved at the scan's closing
//!   validation costs exactly its bound.
//! - Per candidate, one comparison for the identity checks; a candidate
//!   that passes them pays one more for the fingerprint.
//! - On the first equal fingerprint, the acquisition's fixed steps,
//!   [`ACQUISITION`] units, prepaid whole before the reservation: one
//!   comparison for the deadline and the payload's lengths, two updates for the refunds a
//!   failed acquisition may owe, and three comparisons for the final
//!   bracket's sample, cutoff read and sequence load. A short allowance is
//!   left as it was and nothing is reserved. Then one coordination attempt
//!   per iteration of the credit's and the right's bounded compare-exchange
//!   loops as the lease module charges them, a refused limit, a lost
//!   attempt and a spurious failure each included. A refused limit takes
//!   the bracket's sample, and at or past the deadline runs the bracket
//!   with nothing reserved, on the charge already made; a refusal of any
//!   kind leaves that charge spent.
//! - With no equal fingerprint, two comparisons for the bracket that
//!   confirms absence.
//!
//! `retries` counts observation attempts including the first; zero makes
//! none. A torn copy, a moved sequence at any bracket and a busy or terminal
//! shard each consume one. A budget that runs out anywhere refuses
//! `Contended` after returning whatever it had reserved; exhaustion is never
//! `Missing`. No step here takes a gate, waits, calls back, allocates, copies
//! a body or touches the backing.
//!
//! Compile-time misuse: a forged identity and an acquisition by identity
//! alone are rejected. Protected entry is private, so callers can cause only
//! the intervals a lookup pins and ends itself; the `register` module
//! carries that rejection.
//!
//! ```compile_fail,E0624
//! # use kestrike::storage::*;
//! let forged = AllocationId::new(SlotIndex(0), 1);
//! ```
//!
//! ```compile_fail,E0599
//! # use kestrike::storage::*;
//! # fn f(storage: &Storage<LinuxPlatform>, id: AllocationId, budget: &mut WorkBudget) {
//! let lease = storage.lookup(id, budget);
//! # }
//! ```
//!
//! Positive use: a registered caller, one key, a lease that outlives the
//! interval.
//!
//! ```no_run
//! # use kestrike::storage::*;
//! # fn f(storage: &Storage<LinuxPlatform>) -> Result<(), LookupError> {
//! let mut registration = storage.register().ok().unwrap();
//! let mut budget = WorkBudget::new(64);
//! let lease = registration.lookup(&[0x5A; 32], 3, &mut budget)?;
//! let _lease: ExtentLease<'_, LinuxPlatform> = lease;
//! # Ok(())
//! # }
//! ```
//!
//! Stable rustdoc does not check the error codes above; they record the
//! intended cause (E0624 a forged identity, E0599 acquisition by identity)
//! for a reader, and `cargo +nightly test --doc` verifies them.

use std::sync::atomic::Ordering;

use super::acquire::{Hit, LeaseCounters, LeaseRefusal};
use super::allocation::AllocationId;
use super::budget::{WorkBudget, WorkKind};
use super::image::RootDescriptor;
use super::lease::{Credit, ExtentLease, ReadRight};
use super::os::Platform;
use super::owner::Storage;
use super::probe::{self, Primitive};
use super::register::{PinError, Protected, Registration};
use super::slot::{Record, expired};
use super::snapshot::{Observation, SnapshotError, Stable};
use super::tables::RetainCounters;
use super::word;
use crate::index::{HASH_CHARGE, Identity, Key, KeyRoute};

/// Why no lease was acquired. Every reservation the call made was refunded
/// and its protected interval ended before the error was returned. Mappings,
/// counts and sequences are as before; a retain that succeeded before the
/// refusal leaves the object's visited bit set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupError {
    /// A stable, complete search of the key's chain found no object with the
    /// key's fingerprint.
    Missing,
    /// The key's object is at or past its deadline, witnessed under an
    /// unchanged mapping with admission open.
    Expired,
    /// No lease and no proof of absence: every attempt found the shard
    /// sequence moved or busy, the credit or right compare-exchange lost
    /// every paid try, the budget ran out, the attempt allowance was
    /// zero, the shard or the era is terminal, an earlier interval on this
    /// registration was leaked, indexing or every shard is disabled, the
    /// candidate is a recovered-origin slot while the readiness word differs
    /// from `Live`, or a copied candidate failed a check that protection
    /// excludes and the call failed closed before reading its fingerprint.
    Contended,
    /// Every one of the `L` credits is reserved.
    LeaseLimit,
    /// The object already holds `C` external rights.
    RetainLimit,
    /// The platform's clock gave no sample, or its conversion overflowed.
    ClockUnavailable,
    /// Admission was closed before the witness.
    Closed,
}

impl From<PinError> for LookupError {
    fn from(refused: PinError) -> Self {
        match refused {
            PinError::Contended | PinError::Leaked => Self::Contended,
            PinError::Closed => Self::Closed,
        }
    }
}

impl From<super::budget::BudgetExhausted> for LookupError {
    fn from(_: super::budget::BudgetExhausted) -> Self {
        Self::Contended
    }
}

impl From<LeaseRefusal> for LookupError {
    fn from(refusal: LeaseRefusal) -> Self {
        match refusal {
            LeaseRefusal::LeaseLimit => Self::LeaseLimit,
            LeaseRefusal::RetainLimit => Self::RetainLimit,
            LeaseRefusal::Contended | LeaseRefusal::BudgetExhausted => Self::Contended,
            // READ-READY requires `Live` readiness before granting access to a
            // recovered-origin slot.
            LeaseRefusal::NotLive => Self::Contended,
            // The word read positive at the copied incarnation under
            // protection moments ago; a zero count, a moved incarnation or
            // a reserved bit at the retain is a table protection excludes.
            LeaseRefusal::Retired => reject_before_access(),
        }
    }
}

/// The snapshot's refusals as the lookup reports them: a malformed chain is
/// a pre-access rejection, everything else is `Contended`.
fn refuse(error: SnapshotError) -> LookupError {
    match error {
        SnapshotError::Corrupt => reject_before_access(),
        SnapshotError::NoIndex | SnapshotError::BudgetExhausted | SnapshotError::NoEnabledShard => {
            LookupError::Contended
        }
    }
}

/// A candidate refused before its fingerprint was read. Test builds count
/// it so a test can tell this refusal from an ordinary contended one.
#[cold]
fn reject_before_access() -> LookupError {
    #[cfg(test)]
    REJECTED_BEFORE_ACCESS.with(|count| count.set(count.get() + 1));
    LookupError::Contended
}

/// Where a test may pause one lookup on this thread: before a batch element
/// begins, before the pin, before the first sequence load, before the
/// reservation, before the final bracket, or before the bracket that
/// confirms absence.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Pause {
    Element,
    Pin,
    Snapshot,
    Retain,
    FinalBracket,
    /// Before the final bracket of a search that found no equal fingerprint.
    Missing,
}

/// A test's pause: where to stop, and what to run there.
#[cfg(test)]
pub(crate) type PauseHook = (Pause, Box<dyn FnOnce()>);

#[cfg(test)]
thread_local! {
    /// Runs once at the named pause of the next lookup on this thread, so a
    /// test can mutate, close or expire the candidate from another thread
    /// while the lookup waits.
    pub(crate) static INTERPOSE: std::cell::Cell<Option<PauseHook>> =
        const { std::cell::Cell::new(None) };

    /// Candidates refused before any fingerprint read on this thread.
    pub(crate) static REJECTED_BEFORE_ACCESS: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(super) fn interpose(at: Pause) {
    if let Ok(Some((pause, hook))) = INTERPOSE.try_with(std::cell::Cell::take) {
        if pause == at {
            hook();
        } else {
            INTERPOSE.with(|cell| cell.set(Some((pause, hook))));
        }
    }
}

/// How examining one stable copy ended.
enum Examined<'s, P: Platform> {
    /// The reservations on the object whose retain recorded the hit, and
    /// its identity, which the caller moves into a lease.
    Lease(Reserved<'s, P>, AllocationId),
    /// Every candidate was compared, none carried the key's fingerprint, and
    /// the sequence still read the copy's value with admission open.
    Missing,
    /// The shard moved under the copy; the attempt is spent.
    Moved,
    /// Admission closed before the final check, under an unchanged copy.
    Closed,
}

/// Steps the guard bundle prepays before entering the protected interval:
/// the era check, the leaked-interval check, the pin store, the final
/// cutoff check, the clearing store and the record's statistics update.
pub(super) const GUARD_STEPS: usize = GUARD_CHECKS + GUARD_UPDATES;
/// The guard bundle's comparisons: the era check, the leaked-interval check
/// and the final cutoff check.
const GUARD_CHECKS: usize = 3;
/// The guard bundle's updates: the pin store, the clearing store and the
/// statistics.
const GUARD_UPDATES: usize = 3;

/// The acquisition's fixed steps, prepaid whole before the reservation: the
/// record read, the refund reserve and the final bracket.
pub(super) const ACQUISITION: usize = RECORD + REFUND_RESERVE + BRACKET;
/// One comparison for the matched record's deadline and payload lengths.
const RECORD: usize = 1;
/// The two updates a refund of the right and the credit may need.
const REFUND_RESERVE: usize = 2;
/// The final bracket's comparisons: the sample, the cutoff read and the
/// sequence load.
const BRACKET: usize = 3;

impl<'s, P: Platform> Registration<'s, P> {
    /// Acquires one lease on the object visible under `key`, making at most
    /// `retries` observation attempts and charging `budget` as the module
    /// documentation describes. The interval this call pins ends before it
    /// returns, whatever the outcome.
    ///
    /// # Errors
    ///
    /// [`LookupError`]; every reservation the call made is refunded first.
    pub fn lookup(
        &mut self,
        key: &Key,
        retries: usize,
        budget: &mut WorkBudget,
    ) -> Result<ExtentLease<'s, P>, LookupError> {
        self.lookup_routed(key, None, retries, budget)
    }

    /// [`lookup`](Self::lookup) with `key`'s route supplied when `route` is
    /// `Some`. The route must be `key`'s against this storage's index, from
    /// [`KeyHasher::route_unpaid`](crate::index::KeyHasher::route_unpaid);
    /// the hash charge and every other step land where the unrouted call
    /// puts them. The caller that supplies the route hints the search's
    /// summary line, then its bucket and window lines for a tag the summary
    /// admits; this call's validation hints each candidate's record line.
    /// Always inlined, so a batch keeps each element's route in registers.
    #[inline(always)]
    pub(super) fn lookup_routed(
        &mut self,
        key: &Key,
        route: Option<KeyRoute>,
        retries: usize,
        budget: &mut WorkBudget,
    ) -> Result<ExtentLease<'s, P>, LookupError> {
        let storage = self.storage();
        let credit = Credit::Record(self.index().0);
        let (reserved, id) = self.reserve(key, route, credit, retries, budget)?;
        // The lease is built here, after the pin ends, so the key is copied
        // once, from the caller's argument straight into the returned lease.
        Ok(reserved.into_lease(storage, id, key))
    }

    /// The lookup a volume read makes: [`lookup_routed`](Self::lookup_routed)'s
    /// order, charges and refusals, `route` under the same precondition, with only the right
    /// reserved, under [`Credit::Read`], and returned as a [`ReadRight`] for
    /// the read's record to take over. The interval this call pins ends
    /// before it returns.
    ///
    /// # Errors
    ///
    /// [`LookupError`], with any reserved right released first.
    /// `LeaseLimit` refuses lease-credit reservations, and this call
    /// reserves only the right.
    #[inline]
    pub(super) fn lookup_right(
        &mut self,
        key: &Key,
        route: Option<KeyRoute>,
        retries: usize,
        budget: &mut WorkBudget,
    ) -> Result<ReadRight<'s, P>, LookupError> {
        let storage = self.storage();
        let (reserved, id) = self.reserve(key, route, Credit::Read, retries, budget)?;
        Ok(reserved.into_right(storage, id))
    }

    /// The steps [`lookup_routed`](Self::lookup_routed) and
    /// [`lookup_right`](Self::lookup_right) share: the cutoff, the guard
    /// bundle, the route, the pin and the attempts. A hit reserves its right
    /// and a credit from `credit`, and the pin ends before this returns.
    #[inline(always)]
    fn reserve(
        &mut self,
        key: &Key,
        route: Option<KeyRoute>,
        credit: Credit,
        retries: usize,
        budget: &mut WorkBudget,
    ) -> Result<(Reserved<'s, P>, AllocationId), LookupError> {
        if self.storage().is_closed() {
            return Err(LookupError::Closed);
        }
        // The guard bundle: prepaid whole, so a zero or short allowance pins
        // nothing and hashes nothing. The preflight decides here; the
        // bookkeeping of the debit, which cannot fail behind it, runs after
        // the pin's ordered operations rather than ahead of them.
        budget.preflight(GUARD_STEPS)?;
        #[cfg(test)]
        interpose(Pause::Pin);
        // A key with at least `GUARD_STEPS + HASH_CHARGE` remaining derives
        // its route before the pin through `route_unpaid`, so the route
        // derivation and prefetch latency overlap the pin's atomic
        // operations.
        // A `match` arm keeps the derivation in this body: passed to
        // `Option::or_else` as a closure, it compiled to a separate call.
        let route = match route {
            Some(route) => Some(route),
            None => 'derive: {
                let storage = self.storage();
                let Some(index) = storage.index() else {
                    break 'derive None;
                };
                if budget.remaining() < GUARD_STEPS + HASH_CHARGE {
                    break 'derive None;
                }
                storage.route_hinted(index, key)
            }
        };
        let entered = self.enter();
        let paid = budget
            .debit_n(WorkKind::Comparison, GUARD_CHECKS)
            .and_then(|()| budget.debit_n(WorkKind::Update, GUARD_UPDATES));
        debug_assert!(paid.is_ok(), "the preflight covered the guard bundle");
        entered?.lookup(key, route, credit, retries, budget)
    }
}

impl<'s, P: Platform> Protected<'_, 's, P> {
    /// The attempts of one lookup inside this pinned interval, returning a
    /// hit's reservations and identity. The guard is consumed: it drops,
    /// ending the pin, before the outcome escapes.
    #[inline(always)]
    fn lookup(
        mut self,
        key: &Key,
        route: Option<KeyRoute>,
        credit: Credit,
        retries: usize,
        budget: &mut WorkBudget,
    ) -> Result<(Reserved<'s, P>, AllocationId), LookupError> {
        let storage: &'s Storage<P> = self.registration().storage();
        #[cfg(test)]
        interpose(Pause::Snapshot);
        let mut observation =
            Observation::routed(&mut self, key, route, credit, budget).map_err(refuse)?;
        for _ in 0..retries {
            let Some(stable) = observation.attempt(budget).map_err(refuse)? else {
                continue;
            };
            match examine(storage, &observation, stable, budget)? {
                Examined::Lease(reserved, id) => return Ok((reserved, id)),
                Examined::Missing => return Err(LookupError::Missing),
                Examined::Closed => return Err(LookupError::Closed),
                Examined::Moved => {}
            }
        }
        Err(LookupError::Contended)
    }
}

/// Validates every candidate of `stable` in order and acquires the first one
/// whose fingerprint equals the observation's.
#[inline(always)]
fn examine<'s, P: Platform>(
    storage: &'s Storage<P>,
    observation: &Observation<'_>,
    stable: Stable,
    budget: &mut WorkBudget,
) -> Result<Examined<'s, P>, LookupError> {
    for candidate in observation.candidates(stable) {
        budget.debit(WorkKind::Comparison)?;
        let validated = validate(storage, *candidate).ok_or_else(reject_before_access)?;
        // The validation's slot words for one decision, recorded as it
        // happens, so a refusal of the next step leaves it on the record.
        probe::note(Primitive::Load);
        budget.debit(WorkKind::Comparison)?;
        probe::note(Primitive::Load);
        // The pinned interval keeps the object's anchor counted, so the word
        // holds the fingerprint `bind` stored or, once the mapping has ended,
        // the retirement era; the module documentation states why reading
        // the era never ends the call as `Missing` or a hit.
        if validated.record.fingerprint() != observation.fingerprint() {
            continue;
        }
        return acquire(storage, observation, stable, validated, budget);
    }
    // Absence needs the same bracket a hit does: the cutoff read, then the
    // sequence still at the copy's value, so a completed search over a copy
    // that a mutation then overtook is retried, not reported, and a search
    // completed after the close is `Closed`.
    #[cfg(test)]
    interpose(Pause::Missing);
    budget.debit_n(WorkKind::Comparison, 2)?;
    probe::note_n(Primitive::Load, 2);
    let closed = storage.closed().load(Ordering::SeqCst);
    if !observation.still(stable) {
        return Ok(Examined::Moved);
    }
    Ok(if closed {
        Examined::Closed
    } else {
        Examined::Missing
    })
}

/// The matched candidate's acquisition: the reservation and the final
/// bracket, or the refusal that ends the call. A refused reservation whose
/// sample is at or past the deadline, or missing, runs the same bracket
/// with zero reservations, so its verdict comes from the bracket.
#[inline(always)]
fn acquire<'s, P: Platform>(
    storage: &'s Storage<P>,
    observation: &Observation<'_>,
    stable: Stable,
    validated: Validated<'s, P>,
    budget: &mut WorkBudget,
) -> Result<Examined<'s, P>, LookupError> {
    // The acquisition's fixed steps, prepaid whole before the reservation:
    // one comparison for the deadline and payload read, two updates for the
    // refunds a failed acquisition may owe, and the final bracket's three
    // comparisons. A short allowance is left as it was and nothing is
    // reserved; a refused limit runs the bracket on the charge already made.
    budget.preflight(ACQUISITION)?;
    let paid = budget
        .debit_n(WorkKind::Comparison, RECORD + BRACKET)
        .and_then(|()| budget.debit_n(WorkKind::Update, REFUND_RESERVE));
    debug_assert!(paid.is_ok(), "the preflight covered the acquisition");
    probe::note(Primitive::Load);
    let bracket = Bracket {
        storage,
        observation,
        stable,
        id: validated.id,
        record: validated.record,
    };
    #[cfg(test)]
    interpose(Pause::Retain);
    match Reserved::take(
        validated,
        observation.credit(),
        observation.retains(),
        budget,
    ) {
        Ok(reserved) => {
            #[cfg(test)]
            interpose(Pause::FinalBracket);
            // The final bracket: the sample and the cutoff read, then the
            // sequence load that must still show the copy's value.
            probe::note_n(Primitive::Load, BRACKET);
            let now = storage.platform.now_ticks();
            bracket.conclude(now, Some(reserved))
        }
        Err(refusal @ (LeaseRefusal::LeaseLimit | LeaseRefusal::RetainLimit)) => {
            // The sample decides whether the refused object had expired:
            // before the deadline the refusal stands, at or past it the
            // bracket runs with nothing reserved.
            probe::note(Primitive::Load);
            let now = storage.platform.now_ticks();
            if matches!(now, Some(now) if !expired(now, bracket.deadline())) {
                return Err(refusal.into());
            }
            probe::note_n(Primitive::Load, BRACKET - 1);
            bracket.conclude(now, None)
        }
        Err(refusal) => Err(refusal.into()),
    }
}

/// The final bracket's inputs: the cutoff read, then the sequence load that
/// must still show the copy's value, then the verdict on the sample.
struct Bracket<'a, 's, P: Platform> {
    storage: &'s Storage<P>,
    observation: &'a Observation<'a>,
    stable: Stable,
    id: AllocationId,
    record: &'a Record,
}

impl<'s, P: Platform> Bracket<'_, 's, P> {
    /// The deadline's whole seconds.
    #[inline(always)]
    fn deadline(&self) -> u32 {
        self.record.expires_at_s()
    }

    /// The verdict on `now`, with `reserved` moved into the hit or refunded
    /// by its drop. `reserved` is `None` only for a sample at or past the
    /// deadline, or no sample. The caller has paid the bracket's steps.
    #[inline(always)]
    fn conclude(
        self,
        now: Option<u64>,
        reserved: Option<Reserved<'s, P>>,
    ) -> Result<Examined<'s, P>, LookupError> {
        let closed = self.storage.closed().load(Ordering::SeqCst);
        if !self.observation.still(self.stable) {
            return Ok(Examined::Moved);
        }
        if closed {
            return Err(LookupError::Closed);
        }
        let Some(now) = now else {
            return Err(LookupError::ClockUnavailable);
        };
        if !expired(now, self.deadline())
            && let Some(reserved) = reserved
        {
            return Ok(Examined::Lease(reserved, self.id));
        }
        Err(LookupError::Expired)
    }
}

/// One credit and one right held for the rest of the acquisition: refunded
/// when dropped, so every refusal and an unwind between the reservation and
/// the lease give them back exactly once, or moved into the lease. The
/// resolved counters and the credit's source, so the value travels in
/// registers.
struct Reserved<'s, P: Platform> {
    counters: LeaseCounters<'s, P>,
    credit: Credit,
}

impl<'s, P: Platform> Reserved<'s, P> {
    /// Reserves the credit, from `credit`, and the right on `validated`'s
    /// object, whose anchor the pinned interval keeps counted, the retain
    /// expecting the word the validation read.
    #[inline(always)]
    fn take(
        validated: Validated<'s, P>,
        credit: Credit,
        retains: &RetainCounters,
        budget: &mut WorkBudget,
    ) -> Result<Self, LeaseRefusal> {
        let incarnation = validated.id.incarnation();
        validated.counters.reserve(
            validated.root,
            credit,
            retains,
            incarnation,
            validated.word,
            Hit::WithRight,
            budget,
        )?;
        Ok(Self {
            counters: validated.counters,
            credit,
        })
    }

    /// The lease over `id`, the identity `validated` resolved, taken for
    /// `key` and carrying the reservations.
    #[inline(always)]
    fn into_lease(
        self,
        storage: &'s Storage<P>,
        id: AllocationId,
        key: &Key,
    ) -> ExtentLease<'s, P> {
        let credit = self.credit;
        std::mem::forget(self);
        ExtentLease::new(storage, id, *key, credit)
    }

    /// The right on `id`, reserved under [`Credit::Read`], for the volume
    /// read that takes it over.
    #[inline(always)]
    fn into_right(self, storage: &'s Storage<P>, id: AllocationId) -> ReadRight<'s, P> {
        debug_assert_eq!(
            self.credit,
            Credit::Read,
            "a read's right carries no credit"
        );
        std::mem::forget(self);
        ReadRight::new(storage, id)
    }
}

impl<P: Platform> Drop for Reserved<'_, P> {
    fn drop(&mut self) {
        self.counters.refund(self.credit);
    }
}

/// What the checks before the fingerprint read established about one
/// candidate: the counters its reservation moves, the limits they are held
/// to, and the record whose fingerprint the caller compares, under the
/// protection that keeps it this object's.
struct Validated<'s, P: Platform> {
    /// The allocation the candidate names, at the slot's full incarnation.
    id: AllocationId,
    /// The slot's word as the validation loaded it: the retain's expected
    /// value.
    word: u64,
    counters: LeaseCounters<'s, P>,
    root: &'s RootDescriptor,
    record: &'s Record,
}

/// The checks before the fingerprint read: a live pool, a slot inside it,
/// and the slot's word, from one load, carrying the copied low bits, no
/// reserved bit and a positive reference count.
#[inline(always)]
fn validate<'s, P: Platform>(
    storage: &'s Storage<P>,
    candidate: Identity,
) -> Option<Validated<'s, P>> {
    let (pool, root) = storage.live()?;
    let slot = candidate.slot as usize;
    if slot >= pool.descriptor().slot_count {
        return None;
    }
    // A write hint for the record's line ahead of its first load requests
    // the line exclusive in one transfer, for the word load and the
    // retain's exchange that follows. When the record lies in the key's
    // placement window, the window's hint requested the same line earlier;
    // a reader on another core that retains this object or its line
    // neighbour takes the line back in between.
    pool.prefetch_record(slot);
    // The resolution's word load is `Acquire`. Every write of the word is a
    // read-modify-write, so each release decrement of an earlier object's
    // count, and the anchor's release install, heads a release sequence
    // that every later write extends, the claim's exchange of this
    // incarnation among them. A reader whose load returns this incarnation
    // therefore synchronizes with all of them, and the count beside it is
    // this incarnation's: a positive value is this object's anchor or a
    // right on it, never the count of the object that held the slot before,
    // and the record writes the anchor's install published are visible. The
    // grace argument keeps a copied incarnation current for the interval.
    // The copy carries only the incarnation's low 16 bits. That the full value it resolves to names the copied object
    // rests on grace: a pinned reader's copied mapping keeps the object's
    // anchor counted, so service never returns the slot and no claim reuses
    // it during the interval. The 16-bit fragment, which rejects a stale or
    // malformed pair, the retain's compare against the whole word, and the
    // volume read's check of the header's incarnation are defense in depth
    // behind that guarantee.
    let (id, current) = pool.resolve(candidate)?;
    if word::refs(current) == 0 || !word::well_formed(current) {
        return None;
    }
    // SAFETY: `slot < O` was checked against the pool's slot count, and the
    // pinned interval keeps the object's anchor counted while the value is
    // in use.
    let counters = unsafe { LeaseCounters::new(storage, pool, slot) };
    Some(Validated {
        id,
        word: current,
        counters,
        root,
        // SAFETY: `slot < O`, as above; a record holds only atomics.
        record: unsafe { pool.record(slot) },
    })
}
