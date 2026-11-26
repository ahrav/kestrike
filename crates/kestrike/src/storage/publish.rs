//! Publishing one complete immutable object: the index insert for a vacant
//! fingerprint, or the replacement of the incumbent with the equal
//! fingerprint, under the shard gate
//! with every claim refunded on refusal. The gate hold, the chain walk and
//! the fail-closed poisoning are shared with the `remove` module, which
//! walks the chain through [`find`].
//!
//! The publisher is the [`Completed`] owner. Nothing else has seen the
//! object, so consuming the owner on a successful commit is the proof that
//! no writer remains, exactly as a handoff's is; the anchor the commit
//! installs (`refs` from zero to one, or to two when the publisher keeps its
//! own right) is then held by the index mapping, and
//! the object becomes reachable through the pair that names it. On every
//! refusal of the test-only `Completed::publish` the owner comes back
//! unchanged and only this call's claims are
//! refunded: the anchor is uninstalled, a popped overflow bucket is pushed
//! back, the additional-key claim is released; the incarnation, record
//! and payload charges belong to the owner and are untouched. The
//! production `WritableFill::publish` consumes its fill on every outcome.
//!
//! Order under the gate: the sequence must be stable and not about to
//! exhaust; one additional-key claim against `V + P_index <= N`; the walk,
//! charging every visit and every tag comparison and comparing the
//! fingerprint of every tag match, which refuses an existing equal one;
//! the place; the anchor. That is [`prepare`]; only then does [`commit`]
//! take the sequence busy, and it has no error path: every store between the
//! odd and even values is infallible by its signature. Exhausted gate
//! attempts refuse `Contended`. A commit that would land the sequence on its
//! terminal value makes the shard terminal instead, records the capacity lost
//! and refuses. A malformed link or control word poisons the gate and
//! refuses `Corrupt`, so the shard admits nothing further.
//!
//! `WritableFill::publish` arrives with its place and additional-key claim
//! already taken, at reservation under an earlier hold of the same gate,
//! through the `place_claim` module. Its preparation takes neither again:
//! with no incumbent the place is the claimed pending pair, which the
//! commit activates, and with an incumbent the commit stores over the
//! incumbent's pair and cancels the pending one. The commit releases the
//! reservation's additional-key claim either way, and a refusal of the
//! preparation leaves the reservation's claims for the caller to refund.
//! After its odd store `WritableFill::publish` can still refuse `Closed`,
//! `ClockUnavailable` or `Expired`; it then makes no index store and closes
//! the bracket with an empty `busy.commit()` before the refund.
//!
//! The walk covers the base bucket and at most `D` links, and the place is
//! the first free pair, or one overflow bucket popped from the shard's free
//! stack when the chain has no free pair and room for a link; a chain full
//! at its depth bound, an empty stack or the `N` limit refuse `IndexFull`
//! whatever other shards hold. The insertion stores the pair word, then
//! the pair's control lane, its occupancy bit and three tag filter bits,
//! then the chain summary, and for a popped bucket the tail's link, inside
//! one bracket; nothing moves and nothing is swept.
//!
//! Replacement finds the incumbent with the equal fingerprint and takes its
//! pair as the place; the new identity is stored over that pair inside one
//! bracket and the incumbent's retirement obligation is recorded once the
//! gate is released, through the same path a resident authority's
//! retirement takes, carried across the release by a guard so an unwind
//! cannot lose it. The test-only `Completed::publish` walks first and claims
//! after, so its replacement of an incumbent takes no additional-key claim
//! and leaves `V` and `P_index` unchanged even at `V = N`; a lease
//! publication's reservation took its additional-key claim and its pending
//! pair before the upload, so at `V = N`, or on a chain full at its depth
//! bound, that replacement refuses `IndexFull` at reservation. Without an
//! incumbent the replacement is an insert: `Completed::publish` claims and
//! places it and may refuse `IndexFull`, and a lease publication activates
//! the pair its reservation claimed. Every refusal leaves the incumbent's
//! mapping, bytes and charges untouched. A replacement overwrites an occupied
//! pair, so a reader copying it concurrently is rejected by the sequence
//! bracket alone: the occupancy bit never clears. Replacement therefore keeps
//! refusing in a terminal shard, where the bracket is gone, while removal
//! proceeds there with its own argument.
//!
//! The fingerprint is the object's identity in RAM, so a chain holds at most
//! one visible object per fingerprint: two keys whose fingerprints are equal
//! displace each other, and the displaced object is retired like any
//! replaced incumbent. The full key lives in the record's header on the
//! device, and a read checks it against the key it was started for before
//! any byte, so a lookup of the displaced key finds the displacing object
//! and its read ends `HeaderMismatch(Key)`.
//!
//! Time samples against the sequence. The test-only `Completed` publisher
//! takes no clock sample. `WritableFill::publish` samples once inside its
//! bracket, after the odd store and before the cutoff read, and needs one
//! relation to make that sample a witness against readers: a reader whose
//! second sequence load reads the even value before the odd store in the
//! sequence's total order took its own sample no later than the publisher's.
//! The sequence and the platform clock establish that relation together;
//! the memory model supplies only the first half. `publication_model`
//! checks it with the clock as a `SeqCst` word and each hardware edge as a
//! fence the model can drop.
//!
//! Language half. The odd store is `SeqCst`, so it sits in the total order
//! of the sequence's `SeqCst` loads and stores. A reader's final load that
//! returns the even `v` reads from the store of `v` or from nothing later,
//! so it precedes the odd `v + 1` in that order. That is a from-read edge:
//! it constrains the order and creates no happens-before edge, so the model
//! never joins the reader's chain, sample then loads, to the publisher's,
//! odd store then sample. Each clock read is sequenced only within its own
//! thread, and the model says nothing about what a counter read observes.
//! The conclusion below rests on coherence of the one word and on the
//! clock's serialization; the `SeqCst` store states the same order at the
//! language level.
//!
//! The `os` helpers place a barrier before and after the publisher's
//! `clock_gettime` call and one after a reader's, on x86-64 where `lfence`
//! is dispatch serializing and on AArch64.
//! Publisher side: the odd store is performed, visible to every CPU, before
//! the publisher's counter read; the barriers before the call wrap the
//! whole call, vDSO or system call. Reader side: the reader's counter read
//! completes before its cutoff and sequence loads start; on x86-64 the
//! trailing barrier orders that. On AArch64 the trailing `isb` orders later
//! instruction fetch, and the counter read's order before later loads rests
//! on the vDSO's dependency and read barrier or the system call's exception
//! return, an assumption the `os` module records. The reader's final load
//! returned `v`, so it was performed before the odd store became visible:
//! both architectures are multi-copy atomic, so a store becomes visible to
//! every other CPU at once, and coherence of the one word forbids a later
//! load returning `v`. The reader's sample therefore precedes that load,
//! which precedes the odd store's visibility, which precedes the
//! publisher's sample, all in real time. A monotonic clock that is
//! comparable across CPUs then gives the reader's sample no later than the
//! publisher's.
//!
//! Cross-CPU comparability of the two samples is an assumption beside the
//! barriers: one boot, one time namespace, and a clocksource whose
//! cross-CPU and conversion guarantees hold, which selecting a clocksource
//! does not by itself prove. Within one boot and time namespace
//! `CLOCK_MONOTONIC` is one clock whose consecutive reads in a thread never
//! decrease, may repeat, are frequency-adjusted and exclude suspend. Under
//! Miri and on other targets the serialization is empty and the relation is
//! unargued.
//!
//! The reader-side edge is also the premise of the `lookup` module's own
//! witness: its Hit and Expired outcomes take the sample as performed before
//! the cutoff and sequence loads that follow it, and the reader side above
//! supplies that order. Missing needs no sample; Closed is justified by the
//! cutoff alone even where a sample was taken; invalidation takes no sample.
//!
//! Every producer write reaches a reader's byte access without a sample:
//! the snapshot's first `SeqCst` sequence load reads from the publication's
//! even store, or from a later commit that inherits it through the gate's
//! release and acquire handoffs, and the record and payload writes
//! happen before that even store through the publisher's own sequencing or
//! the synchronized transfer of the owner it consumed. The `Release`
//! compare-exchange that installs the anchor over an idle count heads a
//! release sequence the reader's `Acquire` count load reads, a second
//! publication edge.
//!
//! Clock call contract: the successful vDSO fast path allocates nothing and
//! makes no system call, and validates under the kernel's timekeeping
//! seqcount with no fixed retry bound; the vDSO entry can instead invoke the
//! system call, which requests no timer wait but writes its result through a
//! user page that can fault. `clock_gettime` is async-signal-safe with valid
//! output storage. The `os` module's clock test records the environment a
//! run had.

use std::marker::PhantomData;
use std::sync::atomic::{AtomicU64, Ordering};

use super::allocation::RetireOutcome;
use super::budget::{BudgetExhausted, WorkBudget, WorkKind};
#[cfg(test)]
use super::completed::Completed;
use super::gate::{GateError, GateGuard};
use super::lease::retire_anchored;
use super::os::Platform;
use super::owner::Storage;
use super::place_claim::{self, Claimed};
use super::reserve::Restored;
use super::shards::{Hold, ShardControl, ShardImage};
use super::word;
use crate::index::{
    Bucket, BucketView, Busy, CONTROL_MASK, Identity, KeyRoute, OverflowLink, RouteError, Unstable,
    candidate_lanes, first_free, lane_pairs, occupied, occupied_pairs, read_stable, summary_bits,
    terminate, would_exhaust,
};
use crate::storage::AllocationId;

/// Why the object was not published. The owner comes back unchanged and
/// every claim this call made was returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishError {
    /// No index was configured.
    NoIndex,
    /// Admission is closed.
    Closed,
    /// The budget could not pay for the hash pass, the gate try, a visit or
    /// a comparison.
    BudgetExhausted,
    /// Every paid gate attempt found the shard busy, an attempt found its
    /// gate poisoned, or the attempt allowance was zero; a restored
    /// publication reports a poisoned gate `Corrupt` instead.
    Contended,
    /// The key's chain is full at its depth bound, the shard's overflow stack
    /// is empty, the shard's `N` is reached, the shard is terminal, or no
    /// shard is enabled. Other shards may still have room.
    IndexFull,
    /// An equal fingerprint is already visible (publication only; replacement
    /// takes its place).
    Present,
    /// The object's reference count was not idle, so no anchor could be
    /// installed.
    AnchorPresent,
    /// The shard's tables are malformed: a link or control word in the
    /// chain, a pair naming no slot, the free stack, or an odd sequence under
    /// an open gate. The shard gate is poisoned and the shard admits nothing
    /// further. A restored publication also reports a gate it found poisoned.
    Corrupt,
}

impl From<RouteError> for PublishError {
    fn from(error: RouteError) -> Self {
        match error {
            RouteError::BudgetExhausted => Self::BudgetExhausted,
            RouteError::NoEnabledShard => Self::IndexFull,
        }
    }
}

impl From<BudgetExhausted> for PublishError {
    fn from(_: BudgetExhausted) -> Self {
        Self::BudgetExhausted
    }
}

/// Where a walk found a pair, or would put one.
#[derive(Clone, Copy)]
pub(super) struct Place {
    /// The bucket's index in the shard's bucket array.
    pub(super) bucket: usize,
    /// The pair's position within `bucket`.
    pub(super) pair: usize,
    /// `bucket`'s control word as loaded under the gate. A publish stores
    /// it back with `pair`'s lane set and a removal with it cleared;
    /// a removal from an overflow bucket also tests it for `pair` as the last
    /// held pair, which returns the bucket to the free stack.
    pub(super) control: u64,
    /// The bucket linking to `bucket`; `None` for the base bucket.
    pub(super) prev: Option<usize>,
}

/// Where a new pair goes on a chain: its first free pair, or else the tail
/// a popped overflow bucket links from. [`place`] reads it.
pub(super) struct ChainEnd {
    /// The first free pair along the chain; `None` when every visited
    /// bucket is full.
    pub(super) free: Option<Place>,
    /// The last bucket visited: the chain's tail when `free` is `None`.
    tail: usize,
    /// Links followed to reach `tail`, at most the hold's depth bound.
    followed: usize,
}

/// What a completed walk found: no matching pair, and where one would go.
pub(super) struct Walk {
    end: ChainEnd,
    /// The summary bits of every occupied pair the walk passed: the chain's
    /// exact summary before the insert.
    summary: u64,
}

/// The matching pair [`walk`] or [`find`] stopped on.
#[derive(Clone, Copy)]
pub(super) struct Found {
    pub(super) place: Place,
    /// The identity the pair names.
    pub(super) id: AllocationId,
    /// The links the walk followed from the base bucket to the pair's
    /// bucket, at most `D`.
    pub(super) followed: usize,
}

/// How a chain walk ended.
pub(super) enum Walked {
    Found(Found),
    End(Walk),
}

/// Refusals the gate take and the chain walk share with every mutation; the
/// ending mutations also fold their routing refusals into it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Refusal {
    /// The budget could not pay for a hash pass, an attempt, a visit or a
    /// comparison.
    BudgetExhausted,
    /// Every paid gate attempt found the gate busy, the allowance was zero,
    /// or no shard is enabled.
    Contended,
    /// A paid gate attempt found the gate poisoned.
    Poisoned,
    /// The shard's tables are malformed.
    Corrupt,
}

impl From<BudgetExhausted> for Refusal {
    fn from(_: BudgetExhausted) -> Self {
        Self::BudgetExhausted
    }
}

impl From<GateError> for Refusal {
    fn from(error: GateError) -> Self {
        match error {
            GateError::Contended => Self::Contended,
            GateError::Poisoned => Self::Poisoned,
        }
    }
}

impl From<Refusal> for PublishError {
    fn from(refusal: Refusal) -> Self {
        match refusal {
            Refusal::BudgetExhausted => Self::BudgetExhausted,
            Refusal::Contended | Refusal::Poisoned => Self::Contended,
            Refusal::Corrupt => Self::Corrupt,
        }
    }
}

/// An overflow bucket popped from the free stack for this commit.
#[derive(Clone, Copy)]
pub(super) struct Popped {
    /// Its position on the stack, for the push back on refusal.
    top: usize,
    /// Its shard-local overflow index.
    overflow: usize,
    /// The chain's last bucket, which stores `link` to it.
    pub(super) tail: usize,
    pub(super) link: OverflowLink,
}

/// A prepared commit: every fallible step is done and every claim is held.
pub(super) struct Placement {
    /// Where the pair goes.
    place: Place,
    /// The bucket popped for the pair, which the tail links.
    popped: Option<Popped>,
    /// The incumbent whose pair is taken; its retirement follows the commit.
    pub(super) incumbent: Option<AllocationId>,
    /// The chain summary an insert stores: the walked chain's bits with the
    /// new pair's. `None` for a replacement, whose tag the chain already
    /// summarizes.
    summary: Option<u64>,
    /// The stable sequence the commit moves from.
    pub(super) stable: u64,
    /// `V` and `P_index` as read under the gate; the commit publishes
    /// `visible + 1` for an insert and releases the additional-key claim,
    /// this call's or the reservation's, from `reserved`.
    visible: usize,
    reserved: usize,
    /// The reservation's claims the commit spends: its pending pair is the
    /// place an insert activates, and a replacement frees it; its
    /// additional-key claim is released either way.
    claimed: Option<Claimed>,
}

/// Which publication is being prepared.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Mode {
    /// A vacant fingerprint: an equal one refuses `Present`.
    #[cfg(test)]
    Insert,
    /// An equal fingerprint is the place; otherwise an insert.
    #[cfg(test)]
    Replace,
    /// `Replace`, with the publisher's first right installed beside the
    /// anchor and, when `retained`, the right a joined fill's row retains for
    /// its followers.
    Lease { retained: bool },
    /// A vacant fingerprint for a restored binding, whose restored install already counted its anchor: an equal one refuses `Present`, and the store installs no right.
    Restored,
}

impl Mode {
    /// The anchor store installs one right for the anchor, plus the publisher's right for `Lease` and the row's right when `retained` is true. `Restored` returns zero because the restored install already counted the anchor.
    pub(super) fn rights(self) -> usize {
        match self {
            Self::Lease { retained } => 2 + usize::from(retained),
            Self::Restored => 0,
            #[cfg(test)]
            Self::Insert | Self::Replace => 1,
        }
    }

    /// Whether an equal fingerprint is the place rather than a `Present` refusal.
    fn replaces(self) -> bool {
        match self {
            #[cfg(test)]
            Self::Insert => false,
            Self::Restored => false,
            _ => true,
        }
    }
}

/// What a replacement did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Replacement {
    /// The published identity.
    pub id: AllocationId,
    /// The incumbent whose mapping ended, with its retirement record's
    /// outcome; `None` when the key was vacant and this was an insert.
    pub replaced: Option<(AllocationId, RetireOutcome)>,
}

/// The retirement obligation of an identity whose mapping ended, carried
/// from the commit to the record so an unwind in between cannot lose it:
/// dropping it records the retirement, as consuming it does. It is recorded
/// or dropped on the thread that committed the clear, because the era
/// stamp's ordering rests on that thread's release fence; the marker removes
/// `Send` and `Sync`.
pub(super) struct Retirement<'s, P: Platform> {
    storage: &'s Storage<P>,
    id: AllocationId,
    /// The coverage epoch this retirement registered under, `None` when admission was closed.
    counted: Option<u64>,
    thread_bound: PhantomData<*const ()>,
}

impl<'s, P: Platform> Retirement<'s, P> {
    /// Takes the obligation for `id`, whose pair the gate holder has cleared
    /// or overwritten; its anchor is now this obligation's. Called in the
    /// shard hold that ended the mapping, it registers the retirement under
    /// the current epoch, and the registration ends in the pool-gate hold
    /// that retires its slot or, when a park reaches service unretired, in
    /// the gate hold that converts the park.
    // Forced inline into the hold that ends the mapping: an outlined call
    // saves the hold's live registers around the registration's exchange and
    // returns the obligation through memory.
    #[inline(always)]
    pub(super) fn new(storage: &'s Storage<P>, id: AllocationId) -> Self {
        let counted = super::coverage::register(&storage.pool().journal_words().epochs);
        Self {
            storage,
            id,
            counted,
            thread_bound: PhantomData,
        }
    }

    pub(super) fn id(&self) -> AllocationId {
        self.id
    }

    /// Records the retirement.
    pub(super) fn record(self) -> RetireOutcome {
        self.record_as(false)
    }

    pub(super) fn record_evicted(self) -> RetireOutcome {
        self.record_as(true)
    }

    #[inline(always)]
    fn record_as(self, evicted: bool) -> RetireOutcome {
        // `Drop` must not run after this body: a panic inside it would
        // otherwise bump the era and stamp the slot a second time.
        let this = std::mem::ManuallyDrop::new(self);
        let counted = this.counted;
        // SAFETY: `id` was issued for its pool; the anchor the pair held is
        // this obligation's, and only this call marks it as awaiting grace.
        unsafe { retire_anchored(this.storage, this.id, evicted, counted) }
    }
}

impl<P: Platform> Drop for Retirement<'_, P> {
    fn drop(&mut self) {
        // SAFETY: as for `record`.
        unsafe { retire_anchored(self.storage, self.id, false, self.counted) };
    }
}

#[cfg(test)]
impl<'s, P: Platform> Completed<'s, P> {
    /// Publishes this object under its key's fingerprint if no equal
    /// fingerprint is visible, making at most `tries` gate attempts and
    /// charging the hash passes, one coordination attempt per gate try, one
    /// visit per bucket and one comparison per tag or fingerprint comparison
    /// to `budget`. The additional-key claim precedes the walk, so at `V = N` a
    /// present key is refused `IndexFull`, not `Present`.
    ///
    /// # Errors
    ///
    /// The owner comes back unchanged with a [`PublishError`]; see the module
    /// documentation for what each refusal leaves in place. Dropping the
    /// returned owner abandons the object to service.
    #[must_use = "a refusal hands the owner back; dropping it abandons the object to service"]
    pub(crate) fn publish(
        self,
        tries: usize,
        budget: &mut WorkBudget,
    ) -> Result<AllocationId, (Self, PublishError)> {
        match publish(&self, Mode::Insert, tries, budget) {
            Ok(_) => {
                let (_, id) = self.into_parts();
                Ok(id)
            }
            Err(error) => Err((self, error)),
        }
    }

    /// Publishes this object under its key's fingerprint in place of the
    /// incumbent with the equal fingerprint, or as an insert when none is
    /// visible, with the same attempts and charges as [`publish`](Self::publish).
    /// An incumbent's pair is taken without an additional-key claim, so `V`
    /// and `P_index` are unchanged even at `V = N`, and its retirement
    /// obligation is recorded once the commit is visible.
    ///
    /// # Errors
    ///
    /// The owner comes back unchanged with a [`PublishError`], never
    /// `Present`; the incumbent's mapping, bytes and charges are untouched.
    #[must_use = "a refusal hands the owner back; dropping it abandons the object to service"]
    pub(crate) fn replace(
        self,
        tries: usize,
        budget: &mut WorkBudget,
    ) -> Result<Replacement, (Self, PublishError)> {
        match publish(&self, Mode::Replace, tries, budget) {
            Ok(retirement) => {
                // The owner ends before the incumbent's record, so an unwind
                // in the record cannot abandon a published object.
                let (_, id) = self.into_parts();
                let replaced = retirement.map(|retirement| (retirement.id(), retirement.record()));
                Ok(Replacement { id, replaced })
            }
            Err(error) => Err((self, error)),
        }
    }
}

/// The publication against `&Completed`, so a refusal leaves the owner in
/// the caller's hands. Returns the incumbent's retirement obligation, if a
/// pair was taken over.
#[cfg(test)]
fn publish<'s, P: Platform>(
    owner: &Completed<'s, P>,
    mode: Mode,
    tries: usize,
    budget: &mut WorkBudget,
) -> Result<Option<Retirement<'s, P>>, PublishError> {
    let (storage, id) = owner.parts();
    let index = storage.index().ok_or(PublishError::NoIndex)?;
    if storage.is_closed() {
        return Err(PublishError::Closed);
    }
    // The walk reads the base bucket first and the commit usually stores
    // into it, and no load of it can complete before the gate's acquire: the
    // derivation prefetches both of its lines for writing as soon as its
    // passes finish, ahead of the acquire.
    let route = index.hasher.route_prefetching(
        &owner.key,
        &index.geometry,
        budget,
        index.prefetch(true),
    )?;
    let shard = index
        .image
        .shard(route.shard())
        .ok_or(PublishError::IndexFull)?;
    // SAFETY: the index mapping is owned and initialized while the storage is
    // live, which the owner's borrow guarantees.
    let (gate, control) = unsafe { (shard.gate(&index.mapping), shard.control(&index.mapping)) };
    let guard = take_gate(gate, control, tries, budget)?;
    // SAFETY: as above; the gate hold makes the stack reference the only
    // one, and it ends with the hold.
    let hold = unsafe { shard.hold(&index.mapping) };
    let mut tables = Tables {
        shard,
        hold,
        control,
    };
    let pool = storage.pool();
    let gate_error = |error| PublishError::from(Refusal::from(error));
    let mut capture = pool.capture_membership_lock().map_err(gate_error)?;
    if pool.insert_step.load(Ordering::Relaxed) == u64::MAX {
        return Err(PublishError::Closed);
    }
    assert!(
        !capture.suffix.required(),
        "the test-only publication records nothing: suffix tests publish through fills"
    );
    let mut membership = if capture.side_len().is_ok() {
        Some(pool.try_lock_quiet().map_err(gate_error)?)
    } else {
        None
    };
    match prepare(storage, &mut tables, mode, &route, id, None, budget) {
        Ok(placement) => {
            let incumbent = placement.incumbent;
            if let Some(incumbent) = incumbent {
                let slot = incumbent.slot_index();
                if capture.needs_save(pool.capture_step(&capture, slot), slot) {
                    let Some(access) = &mut membership else {
                        unreachable!("active capture preflight owns the pool hold")
                    };
                    pool.capture_remove(&mut access.tables(), &mut capture, slot, false);
                } else {
                    pool.capture_unpublish(&mut capture, slot, false);
                }
            }
            pool.capture_insert(&capture, id.slot_index());
            let busy = Busy::begin(&control.sequence, placement.stable);
            store(&tables.hold, &route, id, &placement);
            commit(control, busy, &placement);
            // The incumbent's authority ended with the commit; the obligation
            // outlives the hold and is recorded after it, past the sequence
            // step a reader may have observed the object under.
            let retirement = incumbent.map(|incumbent| Retirement::new(storage, incumbent));
            drop(membership);
            drop(capture);
            guard.release();
            Ok(retirement)
        }
        Err(PublishError::Corrupt) => Err(fail_closed(guard)),
        Err(error) => {
            guard.release();
            Err(error)
        }
    }
}

/// [`publish_restored`] hints buckets this many bindings ahead, to overlap their prefetching with the publications between.
const HINTED_AHEAD: usize = 16;

/// [`publish_restored`] publishes at most this many bindings of one shard under one hold of its gate.
const GATE_RUN: usize = 64;

/// What a restored publication reads of a binding: the fingerprint its key routes by and the identity its pair names.
pub(crate) trait Binding {
    fn fingerprint(&self) -> u64;
    fn id(&self) -> AllocationId;
}

impl Binding for Restored {
    fn fingerprint(&self) -> u64 {
        self.fingerprint
    }

    fn id(&self) -> AllocationId {
        self.id
    }
}

/// A restored entry's index pair as a warm publication reads it: the fingerprint its key routes by and the record
/// tag of the identity the pair names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Pair {
    pub(crate) fingerprint: u64,
    pub(crate) tag: u64,
}

impl Binding for Pair {
    fn fingerprint(&self) -> u64 {
        self.fingerprint
    }

    fn id(&self) -> AllocationId {
        AllocationId::of_record_tag(self.tag)
    }
}

/// `publish_restored` routes each restored binding by its fingerprint, so restoration and publication share one fingerprint computation per binding, and publishes consecutive bindings of one shard under one gate hold.
///
/// # Errors
///
/// `publish_restored` returns the first refusal with the count of leading bindings it published, which stay published; `Contended` names a shard gate another holder had, which one try-lock attempt per hold leaves to the caller's next call, and `Corrupt` a poisoned shard gate.
pub(crate) fn publish_restored<P: Platform, B: Binding>(
    storage: &Storage<P>,
    restored: &[B],
    budget: &mut WorkBudget,
) -> Result<(), (usize, PublishError)> {
    let mut published = 0;
    publish_from(storage, restored, budget, &mut published).map_err(|error| (published, error))
}

fn publish_from<P: Platform, B: Binding>(
    storage: &Storage<P>,
    restored: &[B],
    budget: &mut WorkBudget,
    at: &mut usize,
) -> Result<(), PublishError> {
    let index = storage.index().ok_or(PublishError::NoIndex)?;
    if storage.is_closed() {
        return Err(PublishError::Closed);
    }
    // The derivation prefetches each base bucket's lines for writing, ahead of the walk's loads and the commit's stores.
    let route_of = |binding: &B, budget: &mut WorkBudget| {
        let prefetch = index.prefetch(true);
        (index.hasher).reroute_prefetching(binding.fingerprint(), &index.geometry, budget, prefetch)
    };
    let mut next = match restored.first() {
        Some(first) => Some(route_of(first, budget)?),
        None => None,
    };
    while let Some(mut route) = next.take() {
        let shard = index
            .image
            .shard(route.shard())
            .ok_or(PublishError::IndexFull)?;
        // SAFETY: the index mapping is owned and initialized while the storage is
        // live, which the caller's borrow of the storage guarantees.
        let (gate, control) =
            unsafe { (shard.gate(&index.mapping), shard.control(&index.mapping)) };
        // A poisoned gate never reopens, so the restored publication ends on it.
        let guard = gate.try_lock().map_err(|error| match error {
            GateError::Contended => PublishError::Contended,
            GateError::Poisoned => PublishError::Corrupt,
        })?;
        // SAFETY: as above; the gate hold makes the stack reference the only
        // one, and it ends with the hold.
        let hold = unsafe { shard.hold(&index.mapping) };
        let mut tables = Tables {
            shard,
            hold,
            control,
        };
        let end = (*at + GATE_RUN).min(restored.len());
        loop {
            if let Some(ahead) = restored.get(*at + HINTED_AHEAD) {
                let prefetch = index.prefetch(true);
                (index.hasher).hint_route(ahead.fingerprint(), &index.geometry, prefetch);
            }
            let id = restored[*at].id();
            match prepare(
                storage,
                &mut tables,
                Mode::Restored,
                &route,
                id,
                None,
                budget,
            ) {
                Ok(placement) => {
                    debug_assert!(
                        placement.incumbent.is_none(),
                        "an insert takes no incumbent"
                    );
                    let busy = Busy::begin(&control.sequence, placement.stable);
                    store(&tables.hold, &route, id, &placement);
                    commit(control, busy, &placement);
                }
                Err(PublishError::Corrupt) => return Err(fail_closed(guard)),
                Err(error) => {
                    guard.release();
                    return Err(error);
                }
            }
            *at += 1;
            let Some(binding) = restored.get(*at) else {
                break;
            };
            let following = match route_of(binding, budget) {
                Ok(following) => following,
                Err(error) => {
                    guard.release();
                    return Err(error.into());
                }
            };
            if *at == end || following.shard() != route.shard() {
                next = Some(following);
                break;
            }
            route = following;
        }
        guard.release();
    }
    Ok(())
}

/// The shard's tables as the gate holder sees them.
pub(super) struct Tables<'t> {
    pub(super) shard: &'t ShardImage,
    pub(super) hold: Hold<'t>,
    pub(super) control: &'t ShardControl,
}

/// Takes the shard gate within `tries` paid attempts, charging one
/// coordination attempt per try and counting each failed try on the shard.
///
/// Inlined into each hold that calls it: the uncontended path is one load
/// and one compare-exchange, and a call boundary around it costs the
/// publication and the removal more than the loop does.
#[inline(always)]
pub(super) fn take_gate<'g>(
    gate: &'g super::gate::Gate,
    control: &ShardControl,
    tries: usize,
    budget: &mut WorkBudget,
) -> Result<GateGuard<'g>, Refusal> {
    let (outcome, failed) = attempts(|| gate.try_lock(), tries, budget);
    if failed != 0 {
        // One load and one `fetch_max`: the count never decreases and
        // `usize::MAX` stays put, in bounded work. Two callers that load the
        // same value lose one increment; the count is a diagnostic and
        // authorizes nothing.
        let count = control.failed_tries.load(Ordering::Relaxed);
        control
            .failed_tries
            .fetch_max(count.saturating_add(failed), Ordering::Relaxed);
    }
    outcome
}

/// Runs `try_lock`, a nonblocking acquisition, up to `tries` times, charging
/// one coordination attempt per try and spinning once between busy tries;
/// returns the outcome and the number of tries that found the lock busy or
/// poisoned. A poisoned lock ends the attempts at once.
#[inline(always)]
pub(super) fn attempts<T>(
    mut try_lock: impl FnMut() -> Result<T, GateError>,
    tries: usize,
    budget: &mut WorkBudget,
) -> (Result<T, Refusal>, usize) {
    let mut failed = 0;
    let outcome = loop {
        if failed == tries {
            break Err(Refusal::Contended);
        }
        if budget.debit(WorkKind::CoordinationAttempt).is_err() {
            break Err(Refusal::BudgetExhausted);
        }
        match try_lock() {
            Ok(held) => break Ok(held),
            Err(GateError::Contended) => {
                failed += 1;
                if failed < tries {
                    std::hint::spin_loop();
                }
            }
            Err(GateError::Poisoned) => {
                failed += 1;
                break Err(Refusal::Poisoned);
            }
        }
    };
    (outcome, failed)
}

/// Moves the shard to the terminal state if a commit from `stable` would
/// land the sequence on its reserved value, recording the admissions it can
/// no longer grant as `N - visible`. Returns whether it did.
#[inline]
pub(super) fn terminate_if_exhausting(
    control: &ShardControl,
    shard: &ShardImage,
    stable: u64,
    visible: usize,
) -> bool {
    if !would_exhaust(stable) {
        return false;
    }
    control
        .lost_capacity
        .store(shard.geometry.visible - visible, Ordering::Relaxed);
    terminate(&control.sequence);
    true
}

/// Whether the visible object `candidate` names carries `fingerprint`,
/// charged as one comparison. The caller holds the shard gate and read
/// `candidate` from an occupied pair.
#[inline]
pub(super) fn fingerprint_matches<P: Platform>(
    storage: &Storage<P>,
    candidate: AllocationId,
    fingerprint: u64,
    budget: &mut WorkBudget,
) -> Result<bool, Refusal> {
    budget.debit(WorkKind::Comparison)?;
    let visible = storage
        .visible_fingerprint(candidate.slot())
        .ok_or(Refusal::Corrupt)?;
    Ok(visible == fingerprint)
}

/// The stable sequence, `V` and `P_index` under the gate, with the shard
/// made terminal when a commit from that sequence would exhaust it.
///
/// # Errors
///
/// `IndexFull` for a terminal or exhausting shard; `Corrupt` for a busy
/// sequence under an open gate, which only an unwinding holder leaves and
/// it poisons the gate on the way out.
#[inline(always)]
pub(super) fn counted(
    shard: &ShardImage,
    control: &ShardControl,
) -> Result<(u64, usize, usize), PublishError> {
    let stable = match read_stable(&control.sequence) {
        Ok(stable) => stable,
        Err(Unstable::Terminal) => return Err(PublishError::IndexFull),
        Err(Unstable::Busy) => return Err(PublishError::Corrupt),
    };
    let visible = control.visible.load(Ordering::Relaxed);
    if terminate_if_exhausting(control, shard, stable, visible) {
        return Err(PublishError::IndexFull);
    }
    Ok((stable, visible, control.reserved.load(Ordering::Relaxed)))
}

/// Every fallible step of the publication under the gate, from the stable
/// sequence to the anchor. On `Ok` every claim the commit needs is held and
/// the tables are left for the commit; on `Err` every claim this call made
/// is back, and `Corrupt` asks the caller to poison the gate. With
/// `claimed`, the reservation's place and additional-key claim, the call
/// takes no claim and no place of its own, and `claimed` stays held on
/// `Err`. Every `Err` except `Corrupt` comes after the tables agreed with
/// `claimed`, so the caller's refund of it cannot fail and never acts on a
/// bucket whose control word has a reserved bit set.
///
/// Inlined into its callers so the tables stay in registers, and the tables
/// are borrowed rather than passed and returned: moved through memory, this
/// function's wide loads of them straddle the caller's narrower stores and
/// wait for the store buffer to drain, and the placement would come back
/// beside a copy of the hold.
#[inline(always)]
pub(super) fn prepare<P: Platform>(
    storage: &Storage<P>,
    tables: &mut Tables<'_>,
    mode: Mode,
    route: &KeyRoute,
    id: AllocationId,
    claimed: Option<Claimed>,
    budget: &mut WorkBudget,
) -> Result<Placement, PublishError> {
    let shard = tables.shard;
    let control = tables.control;
    let hold = &mut tables.hold;
    // The reservation's place is checked before the sequence is read: a
    // caller refunds it on every refusal except `Corrupt`, a terminal or
    // exhausting sequence's `IndexFull` among them.
    if let Some(claimed) = claimed
        && !place_claim::check(hold, control, claimed, id)
            .is_some_and(|pending| pending.tag == route.tag())
    {
        return Err(PublishError::Corrupt);
    }
    let (stable, visible, reserved) = counted(shard, control)?;
    let claim = || {
        if visible + reserved >= shard.geometry.visible {
            return Err(PublishError::IndexFull);
        }
        control.reserved.store(reserved + 1, Ordering::Relaxed);
        Ok(())
    };
    // Restores the value read under this hold, so it is a no-op on a path
    // that never claimed: nothing else writes `reserved` while the gate is
    // held, and a claim is taken at most once per call.
    let refund = || control.reserved.store(reserved, Ordering::Relaxed);
    // An insert claims before it walks; a replacement walks first, since an
    // incumbent's place needs no claim.
    if !mode.replaces() {
        claim()?;
    }
    let walked = walk(storage, shard, hold, route, budget, |candidate, budget| {
        fingerprint_matches(storage, candidate, route.fingerprint(), budget)
    });
    let walked = match walked {
        Ok(walked) => walked,
        Err(refusal) => {
            refund();
            return Err(refusal.into());
        }
    };
    // The place: the incumbent's pair, a free pair the walk passed, or a
    // popped overflow bucket the tail will link to.
    let (place, popped, incumbent, summary) = match walked {
        Walked::Found(_) if !mode.replaces() => {
            refund();
            return Err(PublishError::Present);
        }
        Walked::Found(found) => {
            // Prefetching the incumbent's slot lets cache-line fetches for its membership removal, retirement, and slot return overlap the anchor and the commit.
            storage.pool().prefetch_slot(found.id.slot().0);
            storage.pool().prefetch_retirement(found.id.slot().0);
            (found.place, None, Some(found.id), None)
        }
        Walked::End(walk) => {
            let summary = walk.summary | summary_bits(route.tag());
            if let Some(claimed) = claimed {
                // The reservation's pending pair is the place.
                let place = Place {
                    bucket: claimed.bucket,
                    pair: claimed.pair,
                    control: 0,
                    prev: None,
                };
                (place, None, None, Some(summary))
            } else {
                if mode.replaces() {
                    claim()?;
                }
                match place(shard, hold, control, &walk.end) {
                    Ok((place, popped)) => (place, popped, None, Some(summary)),
                    Err(error) => {
                        refund();
                        return Err(error);
                    }
                }
            }
        }
    };
    // The anchor, and for a lease publication the publisher's own right,
    // from an idle count, before the sequence goes busy, so a reader that
    // copies the identity after the commit retains against a count the
    // index already holds. Every right is reserved against a positive count
    // and nothing else raises the count, so a nonzero one is refused.
    if mode.rights() != 0 {
        // SAFETY: a mode that installs rights publishes an `id` this pool's reservation issued, so its slot index is
        // below `O`; a restored binding installs none and forms no slot reference.
        let slot_word = unsafe { storage.pool().slot_word(id.slot().0) };
        if !word::install(slot_word, id.incarnation(), mode.rights()) {
            if let Some(popped) = popped {
                hold.stack[popped.top] = popped.overflow;
                control.free_top.store(popped.top + 1, Ordering::Relaxed);
            }
            refund();
            return Err(PublishError::AnchorPresent);
        }
    }
    Ok(Placement {
        place,
        popped,
        incumbent,
        summary,
        stable,
        visible,
        reserved,
        claimed,
    })
}

/// The free pair `end` names, or, with none, one overflow bucket popped
/// from the stack for `end`'s tail to link. Returns `IndexFull` when the
/// chain is at its depth bound or the stack is empty, and `Corrupt` on a
/// malformed free stack or popped bucket.
///
/// Inlining lets callers pass the chain end in registers.
#[inline(always)]
pub(super) fn place(
    shard: &ShardImage,
    hold: &mut Hold<'_>,
    control: &ShardControl,
    end: &ChainEnd,
) -> Result<(Place, Option<Popped>), PublishError> {
    if let Some(place) = end.free {
        return Ok((place, None));
    }
    let top = control.free_top.load(Ordering::Relaxed);
    let top = if end.followed < hold.depth {
        top.checked_sub(1)
    } else {
        None
    }
    .ok_or(PublishError::IndexFull)?;
    // A top past the stack or an entry past the overflow count is a
    // malformed control word.
    let overflow = *hold.stack.get(top).ok_or(PublishError::Corrupt)?;
    let link = if overflow < shard.geometry.overflow {
        OverflowLink::encode(overflow).ok()
    } else {
        None
    }
    .ok_or(PublishError::Corrupt)?;
    let bucket = shard.geometry.base + overflow;
    // An intact free-stack bucket has zero control and next words.
    let record = hold.buckets.get(bucket).ok_or(PublishError::Corrupt)?;
    if record.control() != 0 || record.next() != 0 {
        return Err(PublishError::Corrupt);
    }
    control.free_top.store(top, Ordering::Relaxed);
    let popped = Popped {
        top,
        overflow,
        tail: end.tail,
        link,
    };
    // A popped bucket is empty, so its control word is zero.
    let place = Place {
        bucket: shard.geometry.base + overflow,
        pair: 0,
        control: 0,
        prev: Some(end.tail),
    };
    Ok((place, Some(popped)))
}

/// The stores of a commit, `Relaxed` behind the bracket's release fence: the
/// pair, for an insert the chain's summary, and for a popped bucket the
/// tail's link. A claimed insert activates its pending pair; a claimed
/// replacement stores over the incumbent's pair and cancels the pending
/// one. Nothing here can fail.
///
/// Inlined into its callers so the hold arrives in registers: across a
/// call its address would be taken and it would travel through memory.
#[inline(always)]
pub(super) fn store(hold: &Hold<'_>, route: &KeyRoute, id: AllocationId, placement: &Placement) {
    let place = placement.place;
    match placement.claimed {
        Some(_) if placement.incumbent.is_none() => {
            // The reservation reserved the pair under this tag for this
            // identity, so its activation publishes them.
            let activated = hold.buckets[place.bucket].activate_pair(place.pair);
            debug_assert_eq!(activated, Some(route.tag()), "a claimed pair is pending");
        }
        Some(claimed) => {
            hold.buckets[place.bucket].publish_pair(place.pair, place.control, route.tag(), id);
            let freed = hold.buckets[claimed.bucket].cancel_pair(claimed.pair);
            debug_assert!(freed, "a claimed pair is pending");
        }
        None => hold.buckets[place.bucket].publish_pair(place.pair, place.control, route.tag(), id),
    }
    if let Some(summary) = placement.summary {
        hold.summaries[route.bucket()].store(summary, Ordering::Relaxed);
    }
    if let Some(popped) = placement.popped {
        hold.buckets[popped.tail].link(popped.link);
    }
}

/// The sequence commits and the counters move. Counters are sampled without
/// the gate and read under it; their stores follow the commit. The claim is
/// released before the key is counted, so a reader under the gate sees
/// `V + P_index` at most `N`; the gate-free `Relaxed` report loads can
/// briefly see the sum above `N`. Returns the even value committed.
#[inline(always)]
pub(super) fn commit(
    control: &ShardControl,
    busy: Busy<'_, AtomicU64>,
    placement: &Placement,
) -> u64 {
    let sequence = busy.commit();
    let inserted = usize::from(placement.incumbent.is_none());
    let spent = usize::from(placement.claimed.is_some());
    control
        .reserved
        .store(placement.reserved - spent, Ordering::Relaxed);
    control
        .visible
        .store(placement.visible + inserted, Ordering::Relaxed);
    sequence
}

/// Walks `route`'s chain under the gate: the base bucket, then at most `D`
/// links. Charges one visit per bucket and one comparison per occupied
/// pair, loads every occupied pair's word, resolves every pair whose tag
/// matches the route's to the allocation it names, and calls `matches` with
/// it until one answers `true`; that pair is [`Walked::Found`]. A chain that
/// ends first is [`Walked::End`] with the first free pair, the tail, the
/// links followed and the summary of every pair passed.
///
/// # Errors
///
/// - `Corrupt` on a malformed control word, on a link out of range or past
///   the `D`th, or on a tag-matching pair that resolves to no allocation: an
///   occupied pair's anchor keeps its slot at the incarnation it names, so
///   a slot past the count or other incarnation bits is a malformed table.
/// - `BudgetExhausted` when a visit or a comparison cannot be paid.
/// - Every refusal `matches` returns, unchanged.
///
/// Inlined into each hold that calls it, so the result stays in registers:
/// returned through memory, the caller's wide loads of it straddled the
/// callee's narrower stores and waited for the store buffer to drain up to
/// them.
#[inline(always)]
pub(super) fn walk<P: Platform>(
    storage: &Storage<P>,
    shard: &ShardImage,
    hold: &Hold<'_>,
    route: &KeyRoute,
    budget: &mut WorkBudget,
    mut matches: impl FnMut(AllocationId, &mut WorkBudget) -> Result<bool, Refusal>,
) -> Result<Walked, Refusal> {
    let mut bucket = route.bucket();
    let mut prev = None;
    let mut free = None;
    let mut summary = 0;
    for followed in 0..=hold.depth {
        let (record, control) = visit(hold, bucket, budget)?;
        if let Some(pair) = first_free(control) {
            free.get_or_insert(Place {
                bucket,
                pair,
                control,
                prev,
            });
        }
        // Every occupied pair's word is loaded, in pair order: each tag joins
        // the chain's summary, and each pair carrying the route's tag is
        // resolved, the first whose object carries the fingerprint being the
        // place.
        for pair in occupied(control) {
            let identity = record.identity(pair);
            summary |= summary_bits(identity.tag);
            if identity.tag != route.tag() {
                continue;
            }
            let id = resolve(storage, identity)?;
            if matches(id, budget)? {
                return Ok(Walked::Found(Found {
                    place: Place {
                        bucket,
                        pair,
                        control,
                        prev,
                    },
                    id,
                    followed,
                }));
            }
        }
        match follow(shard, hold, record, followed)? {
            None => {
                return Ok(Walked::End(Walk {
                    end: ChainEnd {
                        free,
                        tail: bucket,
                        followed,
                    },
                    summary,
                }));
            }
            Some(next) => {
                prev = Some(bucket);
                bucket = next;
            }
        }
    }
    unreachable!("the walk returns from its last permitted bucket")
}

/// Walks `route`'s chain under the gate to a reservation's place, from the
/// base bucket through at most `D` links. The walk reads each bucket's
/// control and link words and stops at the first bucket with a free pair or
/// at the tail, charging one visit per bucket read.
///
/// # Errors
///
/// - `Corrupt` on a malformed control word, or on a link out of range or
///   past the `D`th.
/// - `BudgetExhausted` when a visit cannot be paid.
///
/// Inlined for the reason [`walk`] is.
#[inline(always)]
pub(super) fn walk_to_free(
    shard: &ShardImage,
    hold: &Hold<'_>,
    route: &KeyRoute,
    budget: &mut WorkBudget,
) -> Result<ChainEnd, Refusal> {
    let mut bucket = route.bucket();
    let mut prev = None;
    for followed in 0..=hold.depth {
        budget.debit(WorkKind::Visit)?;
        let record = hold.buckets.get(bucket).ok_or(Refusal::Corrupt)?;
        let control = record.control();
        if control & !CONTROL_MASK != 0 {
            return Err(Refusal::Corrupt);
        }
        if let Some(pair) = first_free(control) {
            return Ok(ChainEnd {
                free: Some(Place {
                    bucket,
                    pair,
                    control,
                    prev,
                }),
                tail: bucket,
                followed,
            });
        }
        match follow(shard, hold, record, followed)? {
            None => {
                return Ok(ChainEnd {
                    free: None,
                    tail: bucket,
                    followed,
                });
            }
            Some(next) => {
                prev = Some(bucket);
                bucket = next;
            }
        }
    }
    unreachable!("the walk returns from its last permitted bucket")
}

/// Finds the pair a removal clears along `route`'s chain, with [`walk`]'s
/// visits and charges. Each bucket loads only the words of the occupied
/// pairs whose lane filter matches the route's tag ([`candidate_lanes`]),
/// the pairs the reader's scan loads, and passes each whose full tag
/// matches to `matches` in pair order. Each occupied lane carries its
/// pair's tag filter as publication writes it, so the selected pairs are
/// every pair that can carry the tag and the pair found is the one [`walk`]
/// stops on. Returns `None` when the chain ends with no pair `matches`
/// accepts.
///
/// # Errors
///
/// As for [`walk`]: `Corrupt` on a bucket index past the bucket array, a
/// malformed control word, a link out of range or past the `D`th, or a
/// selected tag-matching pair that resolves to no allocation;
/// `BudgetExhausted` when a visit or a comparison cannot be paid; and every
/// refusal `matches` returns.
#[inline(always)]
pub(super) fn find<P: Platform>(
    storage: &Storage<P>,
    shard: &ShardImage,
    hold: &Hold<'_>,
    route: &KeyRoute,
    budget: &mut WorkBudget,
    mut matches: impl FnMut(AllocationId, &mut WorkBudget) -> Result<bool, Refusal>,
) -> Result<Option<Found>, Refusal> {
    let mut bucket = route.bucket();
    let mut prev = None;
    for followed in 0..=hold.depth {
        let (record, control) = visit(hold, bucket, budget)?;
        for pair in lane_pairs(candidate_lanes(control, route.tag())) {
            let identity = record.identity(pair);
            if identity.tag != route.tag() {
                continue;
            }
            let id = resolve(storage, identity)?;
            if matches(id, budget)? {
                return Ok(Some(Found {
                    place: Place {
                        bucket,
                        pair,
                        control,
                        prev,
                    },
                    id,
                    followed,
                }));
            }
        }
        match follow(shard, hold, record, followed)? {
            None => return Ok(None),
            Some(next) => {
                prev = Some(bucket);
                bucket = next;
            }
        }
    }
    unreachable!("the find returns from its last permitted bucket")
}

/// Visits chain bucket `bucket` and returns it with its control word.
/// Charges the visit, then one comparison per occupied pair, debited at once
/// before any pair word is loaded; only the caller's `matches` debits
/// further. An index past the bucket array or a reserved control bit is
/// `Corrupt`.
#[inline(always)]
fn visit<'h>(
    hold: &Hold<'h>,
    bucket: usize,
    budget: &mut WorkBudget,
) -> Result<(&'h Bucket, u64), Refusal> {
    budget.debit(WorkKind::Visit)?;
    let record = hold.buckets.get(bucket).ok_or(Refusal::Corrupt)?;
    let control = record.control();
    if control & !CONTROL_MASK != 0 {
        return Err(Refusal::Corrupt);
    }
    budget.debit_n(WorkKind::Comparison, occupied_pairs(control))?;
    Ok((record, control))
}

/// The allocation a tag-matching pair names, or `Corrupt` when it names none.
#[inline(always)]
fn resolve<P: Platform>(storage: &Storage<P>, identity: Identity) -> Result<AllocationId, Refusal> {
    storage
        .live_pool()
        .and_then(|pool| pool.resolve(identity))
        .map(|(id, _)| id)
        .ok_or(Refusal::Corrupt)
}

/// The index of the bucket `record` links to, reached after `followed + 1`
/// links, or `None` at the chain's end. A link out of range, or a link from
/// a bucket already `hold.depth` links deep, is `Corrupt`.
#[inline(always)]
fn follow(
    shard: &ShardImage,
    hold: &Hold<'_>,
    record: &Bucket,
    followed: usize,
) -> Result<Option<usize>, Refusal> {
    match OverflowLink::decode(record.next()) {
        None => Ok(None),
        Some(overflow) if overflow < shard.geometry.overflow && followed < hold.depth => {
            Ok(Some(shard.geometry.base + overflow))
        }
        Some(_) => Err(Refusal::Corrupt),
    }
}

/// Poisons the shard gate on a malformed table so the shard admits nothing
/// further, and names the refusal.
#[inline]
pub(super) fn fail_closed(guard: GateGuard<'_>) -> PublishError {
    guard.poison();
    PublishError::Corrupt
}
