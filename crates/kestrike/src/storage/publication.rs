//! Every outcome consumes the fill. Before binding the record or taking the shard gate, publication refuses in this order: `ForeignVolume` for another storage's volume, `Lost` for a lost volume, `Closed` when the volume's serving token is absent or of another lineage than the fill's, or refuses fills at the owner's latest deadline sample, and `Incomplete` for a record not ready on the volume, with a write outstanding, failed or never submitted. A lost volume therefore returns `Lost` for a ready record and for an unready one. These four refusals leave the index unchanged; consuming the fill then disposes of its extent, which can try the pool gate. A serving window or cutoff that closes after the precheck refuses `Closed` inside the visibility bracket, under the shard gate. Completion binds the block's resident record, separating allocator residency from index visibility.
//! Publication spends the claims its reservation took: the index place its record's place word names and the two `Shared` lease credits the fill transfers, the publisher's and its terminal read right's.
//! The observer count of the record's row, read under the shard hold that joins also take, decides whether the row retains a right: with a follower joined, the anchor's install counts the row's right beside the publisher's and the terminal credit stays with the row; with none, the terminal credit returns once custody names the claims.
//! Every outcome except an expiry or a supersession records the producer's terminal in the row before the record departs: the published deadline and whether the right was retained, or the typed failure a refusal names; those two leave the upload-granted terminal, which followers report as missing.
//! The custody record names the attempt, candidate and phase before the first step under the gate, and the incumbent once the preparation finds it, all before the candidate's destructor is suppressed, so an unwind leaves the claims named in a fixed record that service skips and finalization counts as a blocker, not an abandoned resident object.
//! An unwind after the even store and before settlement makes the shard terminal, since the mapping is coherent but the claims are not.
//! Success clears the place word and the first lease takes the publisher's credit. A refusal under the hold on intact tables refunds the place there and returns the credits; a refusal before custody names the credits returns them through a drop guard, and the service pass that releases the departed record refunds its place.
//!
//! After storing the odd sequence, the publisher checks serving authority and classifies `Closed` before `ClockUnavailable` and `Expired`. It takes one object-expiry sample and one serving-clock sample.
//! Visibility of the slot record rests on the even store and the anchor's release sequence, never on a sample; the object's bytes are on the device, and a reader reaches them only through a lease.

use std::mem::ManuallyDrop;
use std::sync::atomic::{AtomicU64, Ordering};

use super::allocation::AllocationId;
use super::attempt::AttemptRecord;
use super::budget::{BudgetExhausted, WorkBudget};
use super::capture::PoisonOnUnwind;
use super::completed::{CompleteError, Completed};
use super::device::Disk;
use super::fill;
use super::gate::GateGuard;
use super::image::{FillCustody, NO_RECORD};
use super::lease::{Credit, ExtentLease, Preowned};
use super::os::Platform;
use super::owner::Storage;
use super::place_claim::{self, Claimed, FILL_CREDITS, return_credits, return_fill_credits};
use super::probe::{self, Event, Primitive};
use super::publish::{
    Mode, PublishError, Refusal, Retirement, Tables, attempts, commit, fail_closed, prepare, store,
    take_gate,
};
use super::recovery::delta::{Cause, Identity};
use super::row::FillFailure;
use super::slot::expired;
use super::tables::Naming;
use super::volume::Volume;
use super::word;
use super::writable::{FillReserveError, WritableFill, check};
use crate::index::{Busy, RouteError, terminate};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FillPublishError {
    /// The volume belongs to another storage; no record was bound and no shard gate taken.
    ForeignVolume,
    /// The volume is lost; no record was bound and no shard gate taken.
    Lost,
    /// A write of the record is outstanding or failed, or the record was never wholly submitted; no record was bound and no shard gate taken.
    Incomplete,
    /// The in-bracket sample was at or past the deadline.
    Expired,
    /// The platform gave no sample inside the bracket.
    ClockUnavailable,
    /// The attempt was revoked, its record, pool or shard no longer describes it, or the candidate's count was not idle.
    Superseded,
    /// The shard is terminal or about to exhaust its sequence; the reservation's place is refunded.
    IndexFull,
    /// The capture mutex stayed busy through `tries` attempts, the pool or shard gate was poisoned or stayed busy through `tries` attempts, or a bounded compare-exchange loop ran out of attempts.
    Contended,
    /// The budget could not pay for the completion, the hash pass, a gate try, the walk or a record visit.
    BudgetExhausted,
    /// Closure or a stale serving token refuses admission before publication,
    /// or the serving window or cutoff closes inside the visibility bracket.
    Closed,
    /// The shard's tables are malformed; the gate is poisoned.
    Corrupt,
    /// The tenure's suffix refused the publication's record, its log full, stalled, past its certified bound, at its
    /// reserved end, not yet open or closed, or the record's entry could not be built, or the suffix's bound on the
    /// set a replay could rebuild after the publication lies past the layout's entry cap
    /// (`SuffixLog::past_entry_cap`); nothing was recorded or published.
    History,
}

impl From<CompleteError> for FillPublishError {
    fn from(error: CompleteError) -> Self {
        match error {
            CompleteError::TornDown | CompleteError::Rejected => Self::Superseded,
            CompleteError::BudgetExhausted => Self::BudgetExhausted,
            CompleteError::Gate(_) => Self::Contended,
        }
    }
}

impl From<PublishError> for FillPublishError {
    fn from(error: PublishError) -> Self {
        match error {
            PublishError::NoIndex | PublishError::AnchorPresent | PublishError::Present => {
                Self::Superseded
            }
            PublishError::Closed => Self::Closed,
            PublishError::BudgetExhausted => Self::BudgetExhausted,
            PublishError::Contended => Self::Contended,
            PublishError::IndexFull => Self::IndexFull,
            PublishError::Corrupt => Self::Corrupt,
        }
    }
}

impl From<Refusal> for FillPublishError {
    fn from(refusal: Refusal) -> Self {
        match refusal {
            Refusal::BudgetExhausted => Self::BudgetExhausted,
            Refusal::Contended | Refusal::Poisoned => Self::Contended,
            Refusal::Corrupt => Self::Corrupt,
        }
    }
}

impl From<RouteError> for FillPublishError {
    fn from(error: RouteError) -> Self {
        match error {
            RouteError::BudgetExhausted => Self::BudgetExhausted,
            RouteError::NoEnabledShard => Self::Superseded,
        }
    }
}

impl From<BudgetExhausted> for FillPublishError {
    fn from(_: BudgetExhausted) -> Self {
        Self::BudgetExhausted
    }
}

impl From<FillReserveError> for FillPublishError {
    fn from(error: FillReserveError) -> Self {
        match error {
            FillReserveError::Closed | FillReserveError::Withdrawn => Self::Closed,
            FillReserveError::BudgetExhausted => Self::BudgetExhausted,
            FillReserveError::Contended | FillReserveError::Bootstrapping => Self::Contended,
            FillReserveError::Corrupt => Self::Corrupt,
            FillReserveError::IndexFull => Self::IndexFull,
            FillReserveError::TornDown
            | FillReserveError::Layout(_)
            | FillReserveError::ObjectSlotsFull
            | FillReserveError::PayloadFull
            | FillReserveError::CleanReserve
            | FillReserveError::RetiredPressure
            | FillReserveError::LeaseLimit
            | FillReserveError::Superseded => Self::Superseded,
        }
    }
}

pub(crate) mod phase {
    pub(crate) const NONE: u64 = 0;
    pub(crate) const PREPARED: u64 = 1;
    pub(crate) const INHIBITED: u64 = 2;
    pub(crate) const STORED: u64 = 3;
    pub(crate) const COMMITTED: u64 = 4;
    pub(crate) const REFUSED: u64 = 5;
}

/// The shard's custody record and the sequence it terminalizes when settlement is uncertain.
struct Custody<'c> {
    record: &'c FillCustody,
    sequence: &'c AtomicU64,
}

// Each method is `#[inline]`: `install` is instantiated in the caller's crate, and a non-generic method may otherwise stay a call.
impl Custody<'_> {
    /// Names `attempt`'s record, at `position` in the shard's fill table, and candidate `id` in the `PREPARED` phase.
    /// Every store is `Relaxed`: service and finalization read custody only under the shard gate, whose release orders these stores for them.
    /// On AArch64 a `Release` store here would hold the stable sequence's `SeqCst` load that follows until the store drains.
    #[inline]
    fn take(&self, attempt: &AttemptRecord<'_>, position: usize, id: AllocationId) {
        self.record.record.store(position, Ordering::Relaxed);
        self.record
            .serial
            .store(attempt.serial.get(), Ordering::Relaxed);
        self.record.candidate.store(id.slot().0, Ordering::Relaxed);
        self.record.phase.store(phase::PREPARED, Ordering::Relaxed);
    }

    #[inline]
    fn incumbent(&self, incumbent: Option<AllocationId>) {
        let slot = incumbent.map_or(NO_RECORD, |id| id.slot().0);
        self.record.incumbent.store(slot, Ordering::Relaxed);
    }

    #[inline]
    fn advance(&self, to: u64) {
        self.record.phase.store(to, Ordering::Relaxed);
    }

    /// Settles: every claim has an owner again.
    #[inline]
    fn release(self) {
        let this = ManuallyDrop::new(self);
        this.record.phase.store(phase::NONE, Ordering::Relaxed);
        this.record.incumbent.store(NO_RECORD, Ordering::Relaxed);
        this.record.candidate.store(NO_RECORD, Ordering::Relaxed);
        this.record.serial.store(0, Ordering::Relaxed);
        this.record.record.store(NO_RECORD, Ordering::Release);
    }
}

impl Drop for Custody<'_> {
    /// An unwind after the even store and before settlement leaves the shard terminal: the mapping is coherent but the claims are not, so no later publication or lookup trusts it and every claim stays retained.
    fn drop(&mut self) {
        let phase = self.record.phase.load(Ordering::Relaxed);
        if phase == phase::COMMITTED || phase == phase::REFUSED {
            terminate(self.sequence);
        }
    }
}

/// A point at which a test may make the publication unwind.
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub(super) enum Cut {
    BeforeGate,
    HeldPreCustody,
    DisarmedPreInhibition,
    AfterOdd,
    MidStores,
    AfterEvenPreSettle,
    SettledPreRelease,
    ReleasedPreRetirement,
}

#[cfg(test)]
thread_local! {
    pub(super) static CUT: std::cell::Cell<Option<Cut>> = const { std::cell::Cell::new(None) };
}

#[inline(always)]
fn cut(_at: Cut) {
    #[cfg(test)]
    if CUT.with(|cut| cut.get() == Some(_at)) {
        CUT.with(|cut| cut.set(None));
        panic!("publication cut at {_at:?}");
    }
}

/// The completed block with its attempt, owned until custody names them: dropping it disposes of the block and then departs the record, in that order, and leaves the record occupied when the disposal's park found the slot word malformed or naming another incarnation.
/// Both are held by reference, where `publish` keeps them, so suppressing the candidate's destructor and re-arming it move two words and never the completed owner or the key.
struct Candidate<'c, 's, P: Platform> {
    completed: &'c mut ManuallyDrop<Completed<'s, P>>,
    record: &'c AttemptRecord<'s>,
}

impl<P: Platform> Drop for Candidate<'_, '_, P> {
    fn drop(&mut self) {
        // The candidate is the completed owner's only disposer: the owner stays in its `ManuallyDrop`, so the abandonment in place is its one disposal.
        if self.completed.abandon_in_place() {
            self.record.depart();
        }
    }
}

#[cfg(test)]
thread_local! {
    /// Runs once in a refused publication after its hold and before its
    /// departure, so a test can observe the record in that window.
    pub(super) static REFUSAL_WINDOW: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
thread_local! {
    /// Runs once in a successful publication after its shard hold released and before the displaced incumbent's retirement records.
    pub(super) static AFTER_RELEASE: std::cell::Cell<Option<fn()>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
thread_local! {
    /// Plants the membership's member count in place of its extent rows as the entry-cap guard's bound, the control
    /// of the guard's row count.
    pub(crate) static MEMBER_COUNT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
thread_local! {
    pub(super) static AFTER_BIND: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
thread_local! {
    pub(super) static INTERPOSE_BEFORE_INHIBITION: std::cell::Cell<Option<fn(&std::sync::atomic::AtomicBool)>> =
        const { std::cell::Cell::new(None) };
}

impl<'s, 'a, P: Platform> WritableFill<'s, 'a, P> {
    /// Publication stores the fill under its key with deadline `expires_at_ticks` and returns the object's first lease. The lease holds the right installed beside the anchor and the publisher's `Shared` credit taken by the reservation. Shard gate, capture mutex and pool gate acquisition each allow at most `tries` attempts; capture mutex and pool gate acquisition follow the walk.
    /// With a follower joined the row retains a second right and the terminal credit until service frees it after its last follower; with none the terminal credit returns.
    /// A visible object with the key's fingerprint is the incumbent this publication replaces, whichever key it was published under.
    /// Success makes the mapping and the first lease visible to this process under the fill's authority; every refusal consumes the fill and leaves the incumbent's pair stored.
    /// An `IndexFull` refusal whose commit would have exhausted the shard's sequence also makes the shard terminal, where every lookup refuses `Contended`, so that incumbent stays stored and stops being readable.
    /// Publication visibility is scoped to the live process; a new storage starts with an empty index.
    ///
    /// The record must be ready on `volume`: every unit reached a successful terminal and none failed ([`is_ready`](Self::is_ready)).
    /// The last write terminal released the write set's right before readiness, so a right still counted refuses at the anchor's install.
    ///
    /// # Errors
    ///
    /// [`FillPublishError`]; every variant consumes the fill and returns or parks its extent for service, which can try the pool gate. Four refusals come before the record is bound and the shard gate taken, and leave the index unchanged: `ForeignVolume`, checked first; `Lost`, checked next; `Closed` when the volume's serving token is absent or of another lineage than the fill's, or refuses fills at the owner's latest deadline sample; and `Incomplete`, checked last of the four. A serving window or cutoff that closes after that precheck refuses `Closed` inside the visibility bracket, under the shard gate.
    pub fn publish<D: Disk>(
        self,
        volume: &mut Volume<'s, 'a, P, D>,
        expires_at_ticks: u64,
        tries: usize,
        budget: &mut WorkBudget,
    ) -> Result<ExtentLease<'s, P>, FillPublishError> {
        // The bind stores the slot's record, policy link, naming and deadline lines under the pool gate. The record's writes and their terminals ran since the claim hinted those lines, so they are requested again before the first check and arrive while the checks, the expiry's clock samples and the routing run. A refusal below leaves the hints without effect: only addresses are formed.
        if let Some((pool, _)) = self.storage().live() {
            let slot = self.id().slot().0;
            pool.prefetch_retirement(slot);
            pool.prefetch_slot(slot);
        }
        if !volume.serves(self.storage()) {
            return Err(self.refuse(FillPublishError::ForeignVolume));
        }
        // A lost volume admits no receive, so it publishes no record either: a write that ended in success after the loss leaves the fill ready.
        if volume.is_lost() {
            return Err(self.refuse(FillPublishError::Lost));
        }
        if !self.authority_current(volume) {
            return Err(self.refuse(FillPublishError::Closed));
        }
        if !self.is_ready(volume) {
            return Err(self.refuse(FillPublishError::Incomplete));
        }
        let authority = volume.serving_token();
        let storage = self.storage();
        let expiry = volume.portable_expiry(expires_at_ticks);
        let (reservation, record) = self.into_parts(volume);
        // The reservation's credits: returned by any refusal before custody
        // names them, an unwind included.
        let owed = Owed { storage };
        let completed = match reservation.complete_routed(
            record.key,
            record.fingerprint,
            expires_at_ticks,
            expiry,
            Naming {
                session: volume.session(),
                version: record.version.0,
            },
            budget,
        ) {
            Ok(completed) => completed,
            Err((reservation, error)) => {
                let disposed = reservation.abandon();
                let error = refused(&record, error.into());
                // An abandonment whose park found the slot word malformed or naming another incarnation left the slot to no one, so the record stays occupied.
                if disposed {
                    record.depart();
                }
                drop(owed);
                return Err(error);
            }
        };
        let mut completed = ManuallyDrop::new(completed);
        #[cfg(test)]
        if let Some(hook) = AFTER_BIND.with(|h| h.borrow_mut().take()) {
            hook();
        }
        let candidate = Candidate {
            completed: &mut completed,
            record: &record,
        };
        install(storage, candidate, owed, tries, budget, || {
            volume
                .admit_authority(crate::failover::serving::Operation::Fill, authority)
                .is_ok()
        })
    }
}

// Forced inline into `publish`, its one caller: across a call the candidate
// travels through memory, and the wide reload of the record's key at entry
// waits on the store buffer.
#[inline(always)]
fn install<'s, P: Platform>(
    storage: &'s Storage<P>,
    candidate: Candidate<'_, 's, P>,
    owed: Owed<'s, P>,
    tries: usize,
    budget: &mut WorkBudget,
    authorized: impl Fn() -> bool,
) -> Result<ExtentLease<'s, P>, FillPublishError> {
    let record = candidate.record;
    let id = candidate.completed.id();
    // Every refusal records its terminal before the candidate's drop departs the record.
    let refuse = |error| refused(record, error);
    let Some(index) = storage.index() else {
        return Err(refuse(FillPublishError::Superseded));
    };
    // An early refusal only: the cutoff that decides is the `SeqCst` read under the gate and the one inside the bracket. `closed` never clears, so a `true` here is final and a stale `false` leaves the decision to those reads. On AArch64 a `Relaxed` load does not wait for the completion's pool gate release to drain.
    if storage.closed().load(Ordering::Relaxed) {
        return Err(refuse(FillPublishError::Closed));
    }
    let route = index
        .hasher
        .reroute_prefetching(
            record.fingerprint,
            &index.geometry,
            budget,
            index.prefetch(true),
        )
        .map_err(|error| refuse(error.into()))?;
    // The grant routed this fingerprint over the same enabled shards.
    debug_assert_eq!(route.shard(), record.shard);
    let Some(shard) = index.image.shard(record.shard) else {
        return Err(refuse(FillPublishError::Superseded));
    };
    let Some(table) = storage.fill_table(record.shard) else {
        return Err(refuse(FillPublishError::Superseded));
    };
    let Some((pool, _)) = storage.live() else {
        return Err(refuse(FillPublishError::Superseded));
    };
    // SAFETY: `id` was issued for its pool, so its slot index is below `O`.
    let slot_word = unsafe { pool.slot_word(id.slot().0) };
    // SAFETY: the index mapping is owned and initialized while the storage is live, which the `storage` borrow guarantees.
    let (gate, control) = unsafe { (shard.gate(&index.mapping), shard.control(&index.mapping)) };
    cut(Cut::BeforeGate);
    // Every completed or refused hold below ends the guard through `release` or `poison`, so only a panic inside the hold drops it. That drop poisons the gate even when a destructor of a thread that already unwinds made the take, with the custody record still naming the claims.
    let guard = take_gate(gate, control, tries, budget)
        .map_err(|error| refuse(error.into()))?
        .poison_on_unwind();
    probe::note(Primitive::GateTaken);
    // Hinting the word's line once the gate is held overlaps its fetch with the revalidation and the walk that precede the anchor's install.
    // On AMD Zen 4 a locked instruction waits for older software prefetches, so the hint comes after the gate exchange.
    super::prefetch::hint(slot_word.as_ptr().cast());
    // SAFETY: the index mapping is owned and initialized while the storage is live; `guard` holds the shard gate, which excludes every other access to the fill keys and the stack for as long as `fills` and `hold` live.
    let (fills, hold) = unsafe { (storage.fill_hold(table), shard.hold(&index.mapping)) };
    match check(storage, &fills, record, budget) {
        Ok(()) => {}
        Err(FillReserveError::Corrupt) => return Err(refuse(fail_closed(guard).into())),
        Err(error) => return Err(refuse(released(guard, error.into()))),
    }
    cut(Cut::HeldPreCustody);
    let position = record.position(fills.view.states);
    // The reservation's claims, which the revalidated record still names.
    let Some(claimed) = Claimed::of(fills.places[position]) else {
        return Err(refuse(fail_closed(guard).into()));
    };
    // Joins take this gate, so the count cannot rise during the hold: a
    // follower joined before it finds the row's right attached, and one that
    // joins after it finds the published terminal, a recorded failure, or an
    // upload-granted terminal it reports as missing at the departure. A
    // detach runs lock-free and may lower the count after this read. If
    // every follower detaches after the read, the row retains an unused
    // right, which the next service pass returns with its credit.
    let retained = fills.view.rows[position].observers() != 0;
    let mode = Mode::Lease { retained };
    // Custody names the candidate before the first step under the gate, so an unwind at any later cut leaves the claims discoverable rather than guessed.
    let custody = Custody {
        record: fills.view.custody,
        sequence: &control.sequence,
    };
    custody.take(record, position, id);
    // From here the refusal paths below return the credits explicitly, and
    // success hands them to the lease and the row. With no follower joined
    // the terminal read right's credit is unused and returns now, so no
    // later cut holds it.
    std::mem::forget(owed);
    // The publisher's credit, and the row's when a follower is joined.
    let held = 1 + usize::from(retained);
    return_credits(storage, FILL_CREDITS - held);
    let mut tables = Tables {
        shard,
        hold,
        control,
    };
    let placement = match prepare(
        storage,
        &mut tables,
        mode,
        &route,
        id,
        Some(claimed),
        budget,
    ) {
        Ok(prepared) => prepared,
        Err(error) => {
            custody.release();
            // The credits are engine-wide, so they return even from a shard
            // whose malformed tables keep the place.
            return_credits(storage, held);
            if error == PublishError::Corrupt {
                return Err(refuse(fail_closed(guard).into()));
            }
            place_claim::refund(&tables.hold, control, &mut fills.places[position]);
            return Err(refuse(released(guard, error.into())));
        }
    };
    custody.incumbent(placement.incumbent);
    // Custody names every claim from here, so the candidate's destructor is suppressed: on success its block is the mapping's and the owner is never dropped; a refusal re-arms it before custody settles and drops it after the gate release.
    let candidate = ManuallyDrop::new(candidate);
    cut(Cut::DisarmedPreInhibition);
    #[cfg(test)]
    if let Ok(Some(interpose)) = INTERPOSE_BEFORE_INHIBITION.try_with(|hook| hook.take()) {
        interpose(storage.closed());
    }
    // Membership changes serialize against capture start and progress on this mutex. The hold starts after the index walk and lasts through the commit, so a pass cuts at one publication step while the walk leaves the pool-wide mutex free. The mutex and the pool gate get the same `tries` paid attempts as the shard gate.
    let mut capture_membership = || {
        let capture = attempts(|| pool.capture_membership_lock(), tries, budget)
            .0
            .map_err(FillPublishError::from)?;
        if pool.insert_step.load(Ordering::Relaxed) == u64::MAX {
            return Err(FillPublishError::Closed);
        }
        // Gate contention refuses publication when capture.needs_save selects the incumbent for snapshot capture, or a required suffix needs the publication's record.
        let incumbent = placement.incumbent;
        let saving = (incumbent.map(|id| id.slot_index()))
            .filter(|&slot| capture.needs_save(pool.capture_step(&capture, slot), slot));
        let recording = capture.suffix.required();
        if saving.is_none() && !recording {
            return Ok((capture, None, None));
        }
        // A recorded publication adds the candidate's extent rows and removes its incumbent's when the incumbent
        // is a member. When the record is this tenure's alone, a replay of it keeps only entries that were
        // members and the tenure's next checkpoint places a row for each extent of every member, so the
        // membership's rows bound both: the entry cap counts rows at the placement and entries, at most one per
        // row, at the load. A set past the cap fits no checkpoint slot and no warm load admits it, so a
        // publication whose bound lies past the cap is refused before any change (REFUSE-BEFORE-ACK).
        let member = |id: AllocationId| pool.capture_step(&capture, id.slot_index()) != 0;
        let rows = || {
            let leaving = incumbent
                .filter(|&old| member(old))
                .map_or(0, |old| pool.capture_rows(old.slot_index()));
            #[cfg(test)]
            if MEMBER_COUNT.with(std::cell::Cell::get) {
                return (pool.eligible.load(Ordering::Relaxed) + usize::from(leaving == 0)) as u64;
            }
            let joined =
                pool.member_rows.load(Ordering::Relaxed) + pool.capture_rows(id.slot_index());
            joined.saturating_sub(leaving)
        };
        let slots = pool.descriptor().slot_count;
        if recording && capture.suffix.past_entry_cap(rows(), slots) {
            return Err(FillPublishError::History);
        }
        // The copies and the record's refusal end the pool hold through `release`, so its drop is a panic of either copy. That drop poisons the gate, and the walk guard the capture, also when a thread that was already unwinding took them.
        let mut access = attempts(|| pool.try_lock_quiet(), tries, budget)
            .0
            .map_err(FillPublishError::from)?
            .poison_on_unwind();
        let mut capture = capture;
        let walk = PoisonOnUnwind(&mut capture);
        // The saved entry and the record each take a short-lived view of the tables under the one pool hold.
        let saved = saving.map(|slot| {
            let entry = pool.capture_entry(&mut access.tables(), slot);
            (pool.capture_step(walk.0, slot), entry)
        });
        // The record's halves, read under the pool hold: the candidate's entry into the capture's scratch entry,
        // and the identity of an incumbent the publication replaces.
        let replaced = if recording {
            let mut tables = access.tables();
            let copied = pool.capture_entry_into(&mut tables, id.slot_index(), &mut walk.0.scratch);
            copied.map(|()| Some(incumbent.map(|old| pool.capture_identity(&tables, old))))
        } else {
            Ok(None)
        };
        walk.returned();
        access.release();
        let replaced = replaced.map_err(|_| FillPublishError::History)?;
        let change = match replaced {
            Some(replaced) => {
                let frame = (pool.capture_frame(&mut capture, evicting(&replaced)))
                    .map_err(|_| FillPublishError::History)?;
                Some((replaced, frame))
            }
            None => None,
        };
        Ok((capture, saved, change))
    };
    let membership = capture_membership();
    let busy = Busy::begin(&control.sequence, placement.stable);
    custody.advance(phase::INHIBITED);
    probe::event(Event::Inhibit {
        sequence: placement.stable + 1,
    });
    cut(Cut::AfterOdd);
    let sample = storage.platform.now_ticks_after_stores();
    probe::event(Event::Sampled { ticks: sample });
    let closed = storage.closed().load(Ordering::SeqCst) || !authorized();
    probe::event(Event::Cutoff { closed });
    // The deadline is read after the walk, where the completion left the record hot, and the sample's whole seconds are compared, as lookup's are.
    let expires_at_s = candidate.completed.expires_at_s();
    let verdict = if closed {
        Err(FillPublishError::Closed)
    } else {
        match sample {
            None => Err(FillPublishError::ClockUnavailable),
            Some(ticks) if expired(ticks, expires_at_s) => Err(FillPublishError::Expired),
            Some(_) => Ok(()),
        }
    };
    // `check` revalidated the record under this hold, so the owner is the word's only writer until the gate is released.
    fill::revoke_held(record.state, record.serial);
    probe::event(Event::Revoked {
        serial: record.serial.get(),
    });
    // The record is appended after every other check passed and before any membership word moves, so a refused append, like every refusal here, publishes nothing (REFUSE-BEFORE-ACK); `sample` is the in-bracket sample `verdict` accepted.
    let admitted = verdict
        .and(membership)
        .and_then(|(mut capture, saved, change)| {
            let recorded = change.is_some();
            if let Some((replaced, frame)) = change {
                let now = sample.ok_or(FillPublishError::ClockUnavailable)?;
                (pool.capture_record(&mut capture, now, evicting(&replaced), Some(frame)))
                    .map_err(|_| FillPublishError::History)?;
            }
            Ok((capture, saved, recorded))
        });
    match admitted {
        Ok((mut capture, saved, recorded)) => {
            match saved {
                Some((step, Ok(entry))) => capture.removed(step, entry),
                Some((_, Err(_))) => capture.abandon(),
                None => {}
            }
            if let Some(incumbent) = placement.incumbent {
                pool.capture_unpublish(&mut capture, incumbent.slot_index(), recorded);
            }
            pool.capture_insert(&capture, id.slot_index());
            store(&tables.hold, &route, id, &placement);
            custody.advance(phase::STORED);
            cut(Cut::MidStores);
            let sequence = commit(control, busy, &placement);
            drop(capture);
            custody.advance(phase::COMMITTED);
            probe::event(Event::Committed { sequence });
            cut(Cut::AfterEvenPreSettle);
            let retirement = placement
                .incumbent
                .map(|incumbent| Retirement::new(storage, incumbent));
            let preowned = Preowned::new(storage, id);
            probe::note(Primitive::Store);
            // The commit spent the place and the publisher's credit backs the lease.
            fills.places[position] = 0;
            // Followers read the allocation the reservation's hold stored.
            debug_assert_eq!(fills.view.rows[position].allocation(), id.record_tag());
            // The terminal precedes the departure, whose `Release` and this hold's release carry it to every follower.
            record.row.publish(expires_at_s, retained);
            fill::depart_held(record.state, record.serial);
            custody.release();
            cut(Cut::SettledPreRelease);
            guard.release();
            cut(Cut::ReleasedPreRetirement);
            #[cfg(test)]
            if let Some(hook) = AFTER_RELEASE.with(std::cell::Cell::take) {
                hook();
            }
            if let Some(retirement) = retirement {
                retirement.record();
            }
            let lease = ExtentLease::new(storage, id, record.key, Credit::Shared);
            preowned.transfer();
            Ok(lease)
        }
        Err(error) => {
            let sequence = busy.commit();
            custody.advance(phase::REFUSED);
            probe::event(Event::Committed { sequence });
            cut(Cut::AfterEvenPreSettle);
            slot_word.fetch_sub(mode.rights() as u64 * word::REF, Ordering::Release);
            place_claim::refund(&tables.hold, control, &mut fills.places[position]);
            return_credits(storage, held);
            let error = refuse(error);
            let candidate = ManuallyDrop::into_inner(candidate);
            custody.release();
            cut(Cut::SettledPreRelease);
            guard.release();
            cut(Cut::ReleasedPreRetirement);
            #[cfg(test)]
            if let Some(observe) = REFUSAL_WINDOW.with(|hook| hook.borrow_mut().take()) {
                observe();
            }
            drop(candidate);
            Err(error)
        }
    }
}

/// The two `Shared` credits a publication holds before custody names them, which its drop returns.
struct Owed<'s, P: Platform> {
    storage: &'s Storage<P>,
}

impl<P: Platform> Drop for Owed<'_, P> {
    fn drop(&mut self) {
        return_fill_credits(self.storage);
    }
}

fn evicting(replaced: &Option<Identity>) -> Option<(&Identity, Cause)> {
    replaced.as_ref().map(|old| (old, Cause::Evict))
}

/// The terminal a refused publication leaves its followers: none, so they report the key missing, for an expiry or a supersession, and otherwise the failure the refusal names.
fn failure(error: FillPublishError) -> Option<FillFailure> {
    match error {
        FillPublishError::Expired | FillPublishError::Superseded => None,
        FillPublishError::Closed => Some(FillFailure::Closed),
        FillPublishError::ClockUnavailable => Some(FillFailure::ClockUnavailable),
        FillPublishError::Incomplete => Some(FillFailure::DeviceError),
        FillPublishError::IndexFull | FillPublishError::History => {
            Some(FillFailure::ObjectPressure)
        }
        FillPublishError::Contended | FillPublishError::BudgetExhausted => {
            Some(FillFailure::Contended)
        }
        FillPublishError::ForeignVolume | FillPublishError::Lost | FillPublishError::Corrupt => {
            Some(FillFailure::OwnerUnavailable)
        }
    }
}

/// Records `error`'s terminal on `record`, which the caller departs next, and returns `error`.
fn refused(record: &AttemptRecord<'_>, error: FillPublishError) -> FillPublishError {
    if let Some(failure) = failure(error) {
        record.row.record_failure(failure);
    }
    error
}

impl<P: Platform> WritableFill<'_, '_, P> {
    /// Refuses the publication before the record is bound and the shard gate taken: records `error`'s terminal, then ends the fill as its drop does, which can try the pool gate.
    fn refuse(self, error: FillPublishError) -> FillPublishError {
        let error = refused(self.record(), error);
        drop(self);
        error
    }
}

fn released(guard: GateGuard<'_>, error: FillPublishError) -> FillPublishError {
    guard.release();
    error
}
