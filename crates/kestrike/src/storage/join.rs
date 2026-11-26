//! Followers of an accepted fill: a reader whose object lookup missed joins
//! the fill record that holds the key's upload, observes its producer's
//! terminal and reads the exact version that terminal names, or ends with
//! the outcome the producer recorded.
//!
//! Safety invariant: a follower reads only the allocation its row names, the
//! exact `(slot, incarnation)` the fill reserved, and the row stays occupied
//! while any follower is joined, so a follower never observes a successor's
//! terminal and never reads a successor's bytes.
//!
//! [`Registration::lookup_or_join`] serves a reader incumbent first: the
//! registered lookup runs, and only a stable, complete search that proves
//! the key missing joins the key's fill, so a visible object always wins
//! over a fill in progress. A refused lookup returns its refusal and joins
//! nothing.
//!
//! A follower's successful acquisition takes its right through the bounded
//! retain every lease takes, checked against the version's full 32-bit
//! incarnation, and sets the visited bit of that exact slot word once its
//! cutoff read grants the lease: the one policy hit of a successful joined
//! read, on the incarnation the follower reads. A follower whose
//! acquisition ends without a lease (missing, failed, expired or refused)
//! or that detaches first keeps no right and sets no bit.
//!
//! [`Storage::join_fill`] routes the key, takes its shard gate within the
//! caller's tries and scans the shard's fill table: one paid visit per record
//! and one paid comparison per occupied record whose fingerprint equals the
//! key's, the full key compared only then. A record of the full key is joinable when it
//! is upload-granted, undeparted and unrevoked, or when it departed with its
//! own publication's terminal, is not yet freed, and its object is still the
//! key's visible mapping, which one paid walk of the key's chain checks
//! under the same hold. Among joinable records the one with the highest
//! serial, the most recent attempt, is joined, and its observer count rises
//! by one under the hold, within the caller's per-fill follower limit. No
//! other record qualifies: an attempt not yet upload-granted has no object,
//! an invalidation's revocation ended the fill, a publication whose mapping
//! since ended was replaced or removed, and a departed record with any
//! other terminal has nothing to read. A key's publications happen in serial
//! order, since an attempt begins only once every earlier one is revoked or
//! freed, so the newest publication is the only one that can still be the
//! key's mapping.
//!
//! [`FillFollower::observe`] reads the record's state word outside the
//! gate, with the `fill` module's `Acquire` load checked against the
//! follower's own serial, so the terminal the producer stored before its
//! `Release` departure is visible. The follower's interest keeps the record
//! occupied with its serial, since service frees a record only after its
//! last follower detached. A word naming another attempt is malformed; the
//! observation then repeats under the gate, and a word still malformed there
//! poisons the gate. A poisoned gate leaves the observation and acquisition
//! of a well-formed record unchanged: a departed terminal is final, so a
//! poisoned shard still reports the outcome the departure fixed. An undeparted
//! record is pending, revoked or not: a revoked producer still departs, and
//! a publication refused inside its odd-even bracket revokes its record
//! before the departure that follows its hold. A departed record reports its terminal, which is final
//! from the departure on: the published version, the recorded failure, or
//! missing for an upload-granted terminal, which an ordinary abort, a
//! revocation, a supersession or an expiry leaves. A producer that sees an
//! invalidation's revocation before it fails records no failure, so its
//! followers report missing; a failure recorded before the revocation, or a
//! publication refused before its revalidation saw it, keeps its cause.
//! Every follower of one record reads the one terminal its departure fixed.
//!
//! [`FillFollower::acquire`] observes the record once more, as
//! [`FillFollower::observe`] does,
//! and turns the published version it finds into a lease, or returns the
//! pending or other ended observation with the follower: the object's
//! deadline is checked against one fresh sample, then one engine credit
//! within `L` and one right on the version's exact incarnation within `C`
//! are reserved through the lease counters, whose exchange refuses another
//! incarnation and a zero count. A publication that found a follower joined
//! installed one more right on the object and moved the fill's terminal
//! credit to the row, so the object stays held through any eviction,
//! replacement or expiry until service frees the row; a follower that joined
//! after the publication reads the version only while the object still
//! holds a right, and otherwise reports it missing. The incarnation-checked
//! exchange decides whether the right is taken. The admission cutoff is
//! read with `SeqCst` before the reservation, so a follower that finds it
//! closed refuses `Closed` having taken no right. It is read with `SeqCst`
//! again after the reservation, so a close that lands during the
//! reservation also rejects admission with `Closed`: the lease's drop
//! returns the right and then the credit. The follower's retain leaves the
//! visited bit as it found it, so neither refusal sets it. An open cutoff
//! sets the bit, under the right just counted, and detaches the follower.
//!
//! Detaching, by [`FillFollower::detach`] or drop, lowers the observer count
//! with one `Release` subtraction outside the gate, sequenced after every
//! read the follower made of its row or record and every right it took.
//! Service reads the count with an `Acquire` load under the gate, and only
//! read-modify-writes change the count, so a pass that reads a count a
//! detach lowered synchronizes with that detach and every earlier one: each
//! follower's accesses happen before the pass frees the record, returns the
//! row's right and credit, and a later grant resets the row, so every
//! follower read precedes a successor's writes. Two `Release`-`Acquire`
//! pairs order the threads outside the gate: the departure with the
//! observation, and the detach with the count.

use std::mem::ManuallyDrop;
use std::sync::atomic::{AtomicU64, Ordering};

use super::acquire::{LeaseCounters, LeaseRefusal, reserve_incarnation};
use super::allocation::AllocationId;
use super::attempt::FillHold;
use super::budget::{BudgetExhausted, WorkBudget, WorkKind};
use super::fill::{self, FillSerial, Record};
use super::gate::GateGuard;
use super::lease::{Credit, ExtentLease, ReadRight};
use super::lookup::LookupError;
use super::os::Platform;
use super::owner::{IndexOwner, Storage};
use super::prepare::{AHEAD, PreparedLookup};
use super::probe::{self, Primitive};
use super::publish::{Refusal, find, take_gate};
use super::register::Registration;
use super::row::{FillFailure, FillRow, Terminal};
use super::shards::ShardImage;
use super::slot::expired;
use crate::index::{Key, KeyRoute, RouteError, ShardIndex};

/// What [`Registration::lookup_or_join`] found for a key: the hit is a
/// lease, or `H`, the right a volume read takes over.
#[derive(Debug)]
pub enum Sought<'s, P: Platform, H = ExtentLease<'s, P>> {
    /// The key's visible object, leased or with its right reserved.
    Hit(H),
    /// The key had no visible object; this follower joined its fill.
    Joined(FillFollower<'s, P>),
}

/// Why [`Registration::lookup_or_join`] returned neither a lease nor a
/// follower.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoughtError {
    /// The key has no visible object and no joinable fill.
    Missing,
    /// The lookup refused, with this cause other than `Missing`.
    Lookup(LookupError),
    /// The lookup proved the key missing and the join refused, with this
    /// cause other than `NoFill`.
    Join(JoinError),
}

impl<'s, P: Platform> Registration<'s, P> {
    /// Looks `key` up and, only when the lookup proves it missing, joins its
    /// most recent joinable fill within `max_observers`. With admission open
    /// and `budget` covering the guard bundle and the hash charge, the key is
    /// hashed once, before the lookup's guard preflight, and the lookup pays
    /// the one hash charge; a call short of either refuses at the lookup
    /// with the key unhashed. The join cuts its route again from that hash's
    /// fingerprint.
    /// `retries` bounds the lookup's attempts and `tries` the join's gate
    /// attempts; `budget` pays both. An expired object is the lookup's
    /// `Expired`, which joins nothing. `Missing` holds as of the lookup's
    /// bracket and the join's hold: a fill that published and was freed
    /// between them leaves its object visible to the next lookup.
    ///
    /// # Errors
    ///
    /// [`SoughtError`]; a refused lookup joins nothing, and every
    /// reservation either step made is returned.
    pub fn lookup_or_join(
        &mut self,
        key: &Key,
        max_observers: u64,
        retries: usize,
        tries: usize,
        budget: &mut WorkBudget,
    ) -> Result<Sought<'s, P>, SoughtError> {
        let route = seek_route(self.storage(), key, budget);
        let limits = (max_observers, retries, tries);
        self.seek(key, route, limits, budget, Self::lookup_routed)
    }

    /// [`lookup_or_join`](Self::lookup_or_join) of `prepared`'s key with the
    /// hit's right alone reserved, under `Credit::Read`, as
    /// [`lookup_right`](Self::lookup_right) reserves it for a volume read.
    /// The search starts from the prepared route when `prepared` is this
    /// storage's.
    pub(super) fn lookup_right_or_join(
        &mut self,
        prepared: &PreparedLookup<'s, P>,
        max_observers: u64,
        retries: usize,
        tries: usize,
        budget: &mut WorkBudget,
    ) -> Result<Sought<'s, P, ReadRight<'s, P>>, SoughtError> {
        let storage = self.storage();
        let route = prepared
            .route_for(storage)
            .or_else(|| seek_route(storage, prepared.key(), budget));
        let limits = (max_observers, retries, tries);
        self.seek(prepared.key(), route, limits, budget, Self::lookup_right)
    }

    /// The search both forms share: `lookup` of `key` along `route`, then,
    /// on a proved miss, the join along the same route; `limits` are the
    /// join's follower limit, the lookup's retries and the join's gate tries.
    #[inline(always)]
    fn seek<H>(
        &mut self,
        key: &Key,
        route: Option<KeyRoute>,
        (max_observers, retries, tries): (u64, usize, usize),
        budget: &mut WorkBudget,
        lookup: impl FnOnce(
            &mut Self,
            &Key,
            Option<KeyRoute>,
            usize,
            &mut WorkBudget,
        ) -> Result<H, LookupError>,
    ) -> Result<Sought<'s, P, H>, SoughtError> {
        let storage = self.storage();
        // Only the fingerprint stays live across the lookup; the join cuts
        // its route again from it.
        let fingerprint = route.map(|route| route.fingerprint());
        match lookup(self, key, route, retries, budget) {
            Ok(hit) => Ok(Sought::Hit(hit)),
            Err(LookupError::Missing) => {
                // A storage with no route refuses its lookup before it can
                // prove the key missing, so this arm is reached with a
                // fingerprint, and cutting it again gives the lookup's route.
                let route = storage
                    .index()
                    .zip(fingerprint)
                    .and_then(|(index, fingerprint)| {
                        index.hasher.reroute_unpaid(fingerprint, &index.geometry)
                    });
                let Some(route) = route else {
                    return Err(SoughtError::Join(JoinError::NoIndex));
                };
                match storage.join_routed(key, &route, max_observers, tries, budget) {
                    Ok(follower) => Ok(Sought::Joined(follower)),
                    Err(JoinError::NoFill) => Err(SoughtError::Missing),
                    Err(error) => Err(SoughtError::Join(error)),
                }
            }
            Err(error) => Err(SoughtError::Lookup(error)),
        }
    }
}

/// `key`'s route with the lookup's line hints, derived as the lookup derives
/// an unrouted key's: only with admission open and `budget` covering the
/// guard bundle and the hash charge, so a closed storage or a shorter
/// budget hashes nothing and the lookup refuses it.
fn seek_route<P: Platform>(
    storage: &Storage<P>,
    key: &Key,
    budget: &WorkBudget,
) -> Option<KeyRoute> {
    if storage.is_closed() || budget.remaining() < AHEAD {
        return None;
    }
    storage
        .index()
        .and_then(|index| storage.route_hinted(index, key))
}

/// Why no follower joined. No record or count changed; a failed gate try
/// counts in the shard's telemetry, and `Corrupt` poisons the gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinError {
    /// No live index: none was configured, or the owner is drained.
    NoIndex,
    /// The budget could not pay for the hash pass, a gate try, a record
    /// visit, a comparison, the mapping walk or the observer count's update.
    BudgetExhausted,
    /// Every paid gate attempt found the shard busy, the attempt allowance
    /// was zero, or no shard is enabled.
    Contended,
    /// The key's shard holds no joinable fill for the key, or its gate is
    /// poisoned.
    NoFill,
    /// The joinable fill already has the caller's limit of followers.
    FollowerLimit,
    /// The shard's fill table or the key's chain is malformed; the gate is
    /// poisoned.
    Corrupt,
}

impl From<Refusal> for JoinError {
    fn from(refusal: Refusal) -> Self {
        match ObserveError::from(refusal) {
            ObserveError::BudgetExhausted => Self::BudgetExhausted,
            ObserveError::Contended => Self::Contended,
            ObserveError::Corrupt => Self::Corrupt,
        }
    }
}

impl From<BudgetExhausted> for JoinError {
    fn from(_: BudgetExhausted) -> Self {
        Self::BudgetExhausted
    }
}

/// Why an observation decided nothing. The follower stays joined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObserveError {
    /// The budget could not pay for the record's visit, or for a gate try of
    /// a malformed record's second observation.
    BudgetExhausted,
    /// A malformed record's second observation found the gate busy on every
    /// paid attempt, or `tries` was zero.
    Contended,
    /// The record or its row no longer describes the joined fill, and the
    /// gate is poisoned. A follower's borrow keeps the storage live, so the
    /// shard's index and table it was joined under always resolve.
    Corrupt,
}

impl From<Refusal> for ObserveError {
    fn from(refusal: Refusal) -> Self {
        match refusal {
            Refusal::BudgetExhausted => Self::BudgetExhausted,
            Refusal::Contended | Refusal::Poisoned => Self::Contended,
            Refusal::Corrupt => Self::Corrupt,
        }
    }
}

/// What one observation found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observed {
    /// The producer has not ended.
    Pending,
    /// The producer ended with this outcome.
    Ended(FillEnd),
}

/// A producer's outcome as its followers report it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FillEnd {
    /// The fill published this version.
    Published(JoinedVersion),
    /// The fill ended without publishing and recorded no failure: an ordinary
    /// abort, a revocation, a supersession or an expiry.
    Missing,
    /// The fill ended with this recorded failure.
    Failed(FillFailure),
}

/// The version a fill published, as its row retains it: the exact
/// allocation, the key, both lengths and the deadline's whole seconds. It
/// describes the version and grants no access: only
/// [`FillFollower::acquire`] leases it.
///
/// `repr(C)` keeps the declared order: the allocation as one record-tag
/// word, then the key at byte offset 8, so the version carries no padding
/// ahead of its lengths.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct JoinedVersion {
    tag: u64,
    key: Key,
    metadata_len: u32,
    body_len: u32,
    expires_at_s: u32,
}

const _: () = assert!(std::mem::offset_of!(JoinedVersion, key) == 8);

impl std::fmt::Debug for JoinedVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JoinedVersion")
            .field("id", &self.id())
            .field("key", &self.key)
            .field("metadata_len", &self.metadata_len)
            .field("body_len", &self.body_len)
            .field("expires_at_s", &self.expires_at_s)
            .finish()
    }
}

impl JoinedVersion {
    /// The published allocation's exact identity.
    pub fn id(&self) -> AllocationId {
        AllocationId::of_record_tag(self.tag)
    }

    pub fn key(&self) -> &Key {
        &self.key
    }

    pub fn metadata_len(&self) -> u32 {
        self.metadata_len
    }

    pub fn body_len(&self) -> u32 {
        self.body_len
    }

    /// The object's deadline in whole seconds of the engine's timeline.
    pub fn expires_at_s(&self) -> u32 {
        self.expires_at_s
    }
}

/// Why no lease was acquired on a joined version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinedReadError {
    /// The sample is at or past the object's deadline.
    Expired,
    /// The platform gave no sample.
    ClockUnavailable,
    /// Every one of the `L` credits is reserved.
    LeaseLimit,
    /// The object already holds `C` rights.
    RetainLimit,
    /// Every paid gate attempt or exchange failed.
    Contended,
    /// The budget could not pay for a gate try, the record's visit or a
    /// reservation.
    BudgetExhausted,
    /// The version is gone: the producer ended without publishing and
    /// recorded no failure, or, for a follower that joined after an
    /// unretained publication, the object no longer holds a right.
    Missing,
    /// The producer ended with this recorded failure.
    Failed(FillFailure),
    /// The producer has not ended.
    Pending,
    /// The record or its row no longer describes the joined fill; the gate
    /// is poisoned.
    Corrupt,
    /// The `SeqCst` cutoff read after the credit and right were reserved
    /// found admission closed; both were returned.
    Closed,
}

impl From<ObserveError> for JoinedReadError {
    fn from(error: ObserveError) -> Self {
        match error {
            ObserveError::BudgetExhausted => Self::BudgetExhausted,
            ObserveError::Contended => Self::Contended,
            ObserveError::Corrupt => Self::Corrupt,
        }
    }
}

impl From<LeaseRefusal> for JoinedReadError {
    fn from(refusal: LeaseRefusal) -> Self {
        match refusal {
            LeaseRefusal::LeaseLimit => Self::LeaseLimit,
            LeaseRefusal::RetainLimit => Self::RetainLimit,
            LeaseRefusal::Contended => Self::Contended,
            LeaseRefusal::BudgetExhausted => Self::BudgetExhausted,
            LeaseRefusal::Retired => Self::Missing,
            LeaseRefusal::NotLive => Self::Contended,
        }
    }
}

/// One follower's interest in one fill record: the storage it borrows, the
/// shard and the attempt's serial, and the record's state word and row,
/// which its interest keeps occupied. Not `Clone`: each follower detaches
/// once. A follower that is forgotten instead keeps its record occupied and
/// any right its row retains counted, so service never frees them and
/// finalization blocks on the record.
#[must_use = "a dropped follower detaches at once"]
pub struct FillFollower<'s, P: Platform> {
    storage: &'s Storage<P>,
    shard: ShardIndex,
    serial: FillSerial,
    key: Key,
    state: &'s AtomicU64,
    row: &'s FillRow,
}

impl<P: Platform> std::fmt::Debug for FillFollower<'_, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FillFollower")
            .field("shard", &self.shard)
            .field("serial", &self.serial.get())
            .finish_non_exhaustive()
    }
}

impl<P: Platform> Storage<P> {
    /// Joins the most recent joinable fill of `key`, as the module
    /// documentation describes, unless it already has `max_observers`
    /// followers, making at most `tries` gate attempts. `budget` is charged
    /// the hash pass, one coordination attempt per gate try, one visit per
    /// record scanned, one comparison per fingerprint match, the mapping
    /// walk's visits and comparisons when a departed publication is newer
    /// than every live upload, and one update for the join.
    ///
    /// # Errors
    ///
    /// [`JoinError`]; none joins and none changes a record.
    pub fn join_fill(
        &self,
        key: &Key,
        max_observers: u64,
        tries: usize,
        budget: &mut WorkBudget,
    ) -> Result<FillFollower<'_, P>, JoinError> {
        let index = self.index().ok_or(JoinError::NoIndex)?;
        let route =
            index
                .hasher
                .route(key, &index.geometry, budget)
                .map_err(|error| match error {
                    RouteError::BudgetExhausted => JoinError::BudgetExhausted,
                    RouteError::NoEnabledShard => JoinError::Contended,
                })?;
        self.join_routed(key, &route, max_observers, tries, budget)
    }

    /// [`join_fill`](Self::join_fill) along `route`, `key`'s route under this
    /// storage's index, with no hash pass. Always inlined into
    /// [`join_fill`](Self::join_fill) and [`Registration::lookup_or_join`].
    #[inline(always)]
    pub(super) fn join_routed(
        &self,
        key: &Key,
        route: &KeyRoute,
        max_observers: u64,
        tries: usize,
        budget: &mut WorkBudget,
    ) -> Result<FillFollower<'_, P>, JoinError> {
        let index = self.index().ok_or(JoinError::NoIndex)?;
        let shard = route.shard();
        let table = self.fill_table(shard).ok_or(JoinError::NoFill)?;
        let image = index.image.shard(shard).ok_or(JoinError::Contended)?;
        // SAFETY: the index mapping is owned and initialized while the
        // storage is live, which `&self` guarantees.
        let (gate, control) =
            unsafe { (image.gate(&index.mapping), image.control(&index.mapping)) };
        // The join explicitly releases or poisons the gate. Dropping a
        // still-held guard signals a panic inside the join, even if the
        // thread was already unwinding when it entered.
        let guard = take_gate(gate, control, tries, budget)
            .map_err(|refusal| match refusal {
                Refusal::Poisoned => JoinError::NoFill,
                refusal => JoinError::from(refusal),
            })?
            .poison_on_unwind();
        probe::note(Primitive::GateTaken);
        // SAFETY: the storage is live, `table` is one of its tables, and the
        // gate hold just taken makes the keys' `&mut` the only reference
        // into them until the hold ends below.
        let hold = unsafe { self.fill_hold(table) };
        let joined = self.joined(&hold, image, index, route, key, max_observers, budget);
        match joined {
            Ok((position, serial)) => {
                guard.release();
                Ok(FillFollower {
                    storage: self,
                    shard,
                    serial,
                    key: *key,
                    state: &hold.view.states[position],
                    row: &hold.view.rows[position],
                })
            }
            Err(JoinError::Corrupt) => {
                guard.poison();
                Err(JoinError::Corrupt)
            }
            Err(error) => {
                guard.release();
                Err(error)
            }
        }
    }

    /// The join under `hold`: the chosen record's position and serial, its
    /// observer count raised by one. The caller builds the follower from
    /// them after the gate is released.
    #[inline(always)]
    #[expect(clippy::too_many_arguments, reason = "the hold's resolved parts")]
    fn joined(
        &self,
        hold: &FillHold<'_, '_>,
        image: &ShardImage,
        index: &IndexOwner,
        route: &KeyRoute,
        key: &Key,
        max_observers: u64,
        budget: &mut WorkBudget,
    ) -> Result<(usize, FillSerial), JoinError> {
        let (live, published) = candidates(hold, route, key, budget)?;
        // A departed publication newer than every live upload is joined
        // only while its object is the key's mapping.
        let newer = published.filter(|newer| live.is_none_or(|live| newer.1 > live.1));
        let chosen = match newer {
            Some(newer) => {
                let tag = hold.view.rows[newer.0].allocation();
                // SAFETY: the index mapping is live and this call holds
                // the shard's gate, the only path into its tables.
                let tables = unsafe { image.hold(&index.mapping) };
                let mapped = find(self, image, &tables, route, budget, |found, _| {
                    Ok(found.record_tag() == tag)
                })?;
                if mapped.is_some() { Some(newer) } else { live }
            }
            None => live,
        };
        let (position, serial) = chosen.ok_or(JoinError::NoFill)?;
        let row = &hold.view.rows[position];
        if row.observers() >= max_observers {
            return Err(JoinError::FollowerLimit);
        }
        budget.debit(WorkKind::Update)?;
        probe::note(Primitive::Rmw);
        // Under the gate: every other writer of the count is a detach,
        // whose subtraction follows an earlier join's addition.
        row.join();
        #[cfg(test)]
        if let Ok(Some(interpose)) = INTERPOSE_AFTER_JOIN.try_with(|hook| hook.take()) {
            interpose();
        }
        Ok((position, serial))
    }
}

/// A joinable record's position and serial.
type Candidate = Option<(usize, FillSerial)>;

/// Records the scan loads together. The Free word is zero, so a run whose
/// words OR to zero is all Free and takes one branch.
const RUN: usize = 4;

/// The most recent live upload of `key` and its most recent departed
/// publication in `hold`'s table, each as its position and serial, with
/// one paid visit per record and one paid comparison per occupied record of
/// the key's fingerprint.
///
/// When the allowance covers a visit and a comparison for every record, no
/// step of the scan can exhaust it, so the scan counts its steps and debits
/// them after the loop; the counters equal those of a debit before each
/// step. It reads the state words [`RUN`] at a time and decides record by
/// record only a run that holds a malformed word or an occupied record of
/// the key's fingerprint; every record of another run is Free, or occupied
/// and well formed under another fingerprint, and incurs only its visit. A
/// malformed word ends the scan, and the later records of its run stay
/// loaded, undecided and uncharged. A smaller allowance debits each step
/// before it, out of line.
#[inline(always)]
fn candidates(
    hold: &FillHold<'_, '_>,
    route: &KeyRoute,
    key: &Key,
    budget: &mut WorkBudget,
) -> Result<(Candidate, Candidate), JoinError> {
    let states = hold.view.states;
    let mut search = Search::new(hold, route, key);
    if budget.remaining() / 2 < states.len() {
        return bounded(search, states, budget);
    }
    let (visited, searched) = search.run(states, budget);
    budget.debit_n(WorkKind::Visit, visited)?;
    budget.debit_n(WorkKind::Comparison, search.compared)?;
    searched?;
    Ok((search.live, search.published))
}

/// [`candidates`] with each visit and comparison debited before it.
/// Passing the search by value lets the optimizer keep it in registers on
/// the common path.
#[inline(never)]
fn bounded(
    mut search: Search<'_>,
    states: &[AtomicU64],
    budget: &mut WorkBudget,
) -> Result<(Candidate, Candidate), JoinError> {
    let prints = search.fingerprints;
    for (position, (state, &print)) in states.iter().zip(prints).enumerate() {
        budget.debit(WorkKind::Visit)?;
        probe::note(Primitive::Load);
        search.record::<true>(state.load(Ordering::Relaxed), print, position, budget)?;
    }
    Ok((search.live, search.published))
}

/// One scan of a fill table for a key: the table's slices under the hold,
/// the comparisons counted for the debit after the loop, and the newest
/// live and published records found.
struct Search<'h> {
    next_serial: u64,
    /// The occupied words well formed against `next_serial`.
    issued: fill::Issued,
    fingerprint: u64,
    key: &'h Key,
    fingerprints: &'h [u64],
    keys: &'h [Key],
    rows: &'h [FillRow],
    compared: usize,
    live: Candidate,
    published: Candidate,
}

impl<'h> Search<'h> {
    #[inline(always)]
    fn new(hold: &'h FillHold<'_, '_>, route: &KeyRoute, key: &'h Key) -> Self {
        let records = hold.view.states.len();
        let next_serial = hold.view.control.next_serial.load();
        Self {
            next_serial,
            issued: fill::Issued::before(next_serial),
            fingerprint: route.fingerprint(),
            key,
            fingerprints: &hold.fingerprints[..records],
            keys: &hold.keys[..records],
            rows: &hold.view.rows[..records],
            compared: 0,
            live: None,
            published: None,
        }
    }

    #[inline(always)]
    fn run(
        &mut self,
        states: &[AtomicU64],
        budget: &mut WorkBudget,
    ) -> (usize, Result<(), JoinError>) {
        let (runs, rest) = states.as_chunks::<RUN>();
        let (prints, rest_prints) = self.fingerprints.as_chunks::<RUN>();
        let mut next = 0;
        while let Some((at, words)) = self.notable(&runs[next..], &prints[next..]) {
            let run = next + at;
            probe::note_n(Primitive::Load, at * RUN);
            for (offset, (word, &print)) in words.into_iter().zip(&prints[run]).enumerate() {
                let position = run * RUN + offset;
                probe::note(Primitive::Load);
                let found = self.record::<false>(word, print, position, budget);
                if found.is_err() {
                    return (position + 1, found);
                }
            }
            next = run + 1;
        }
        probe::note_n(Primitive::Load, (runs.len() - next) * RUN);
        let mut position = runs.len() * RUN;
        for (state, &print) in rest.iter().zip(rest_prints) {
            probe::note(Primitive::Load);
            let found =
                self.record::<false>(state.load(Ordering::Relaxed), print, position, budget);
            position += 1;
            if found.is_err() {
                return (position, found);
            }
        }
        (position, Ok(()))
    }

    /// The first of `runs` holding a malformed word or an occupied record of
    /// the key's fingerprint, as its offset and its words; every run before
    /// it decides nothing and costs only its visits, which the scan counts
    /// by position.
    #[inline(always)]
    fn notable(
        &self,
        runs: &[[AtomicU64; RUN]],
        prints: &[[u64; RUN]],
    ) -> Option<(usize, [u64; RUN])> {
        for (at, (run, prints)) in runs.iter().zip(prints).enumerate() {
            let words = run.each_ref().map(|state| state.load(Ordering::Relaxed));
            if words.iter().fold(fill::FREE, |any, word| any | word) == fill::FREE {
                continue;
            }
            for (&word, &print) in words.iter().zip(prints) {
                if word != fill::FREE && (print == self.fingerprint || !self.issued.holds(word)) {
                    return Some((at, words));
                }
            }
        }
        None
    }

    #[inline(always)]
    fn record<const BOUNDED: bool>(
        &mut self,
        word: u64,
        print: u64,
        position: usize,
        budget: &mut WorkBudget,
    ) -> Result<(), JoinError> {
        let record = fill::decode(word, self.next_serial).map_err(|_| JoinError::Corrupt)?;
        let Record::Occupied {
            serial,
            departed,
            revoked,
        } = record
        else {
            return Ok(());
        };
        if print != self.fingerprint {
            return Ok(());
        }
        if BOUNDED {
            budget.debit(WorkKind::Comparison)?;
        } else {
            self.compared += 1;
        }
        match matched(self.keys, self.rows, self.key, position, departed, revoked)? {
            Some(Joinable::Live) => newest(&mut self.live, position, serial),
            Some(Joinable::Published) => newest(&mut self.published, position, serial),
            None => {}
        }
        Ok(())
    }
}

/// Which joinable record a fingerprint match is.
enum Joinable {
    Live,
    Published,
}

/// The record at `position` of the key's fingerprint, occupied with the
/// flags `departed` and `revoked`: joinable when its key is `key` and it is
/// an undeparted, unrevoked upload or a departed publication. Out of line,
/// so the inlined per-record step keeps only the decode and the fingerprint
/// test; the key comparison and the terminal read run only for a
/// fingerprint match.
#[inline(never)]
fn matched(
    keys: &[Key],
    rows: &[FillRow],
    key: &Key,
    position: usize,
    departed: bool,
    revoked: bool,
) -> Result<Option<Joinable>, JoinError> {
    if !joins_key(&keys[position], key) {
        return Ok(None);
    }
    let terminal = rows[position].terminal().map_err(|_| JoinError::Corrupt)?;
    Ok(match terminal {
        Terminal::Ready if !departed && !revoked => Some(Joinable::Live),
        Terminal::Published { .. } if departed => Some(Joinable::Published),
        _ => None,
    })
}

/// Keeps in `best` the record of the higher serial.
#[inline(always)]
fn newest(best: &mut Candidate, position: usize, serial: FillSerial) {
    if best.is_none_or(|(_, newest)| serial > newest) {
        *best = Some((position, serial));
    }
}

/// Whether a record's key is `key`, all 32 bytes compared.
#[inline(always)]
fn joins_key(stored: &Key, key: &Key) -> bool {
    #[cfg(test)]
    if PLANT.with(std::cell::Cell::get) == Some(Plant::FingerprintJoin) {
        return true;
    }
    stored == key
}

impl<'s, P: Platform> FillFollower<'s, P> {
    /// The storage the follower's fill belongs to.
    pub(super) fn storage(&self) -> &'s Storage<P> {
        self.storage
    }

    /// The fill's observer count, for a test's view of the follower caps.
    #[cfg(test)]
    pub(crate) fn observers(&self) -> u64 {
        self.row.observers()
    }

    pub fn key(&self) -> &Key {
        &self.key
    }

    pub fn shard(&self) -> ShardIndex {
        self.shard
    }

    /// The joined attempt's serial.
    pub fn serial(&self) -> u64 {
        self.serial.get()
    }

    /// Observes the joined record outside the gate, charging one visit to
    /// `budget`. A malformed word is observed again under the gate, taken
    /// within `tries` attempts that each charge one coordination attempt,
    /// and a word still malformed there poisons the gate.
    ///
    /// # Errors
    ///
    /// [`ObserveError`]; the follower stays joined.
    pub fn observe(&self, tries: usize, budget: &mut WorkBudget) -> Result<Observed, ObserveError> {
        budget
            .debit(WorkKind::Visit)
            .map_err(|_| ObserveError::BudgetExhausted)?;
        match self.decide() {
            Err(ObserveError::Corrupt) => self.observe_held(tries, budget),
            observed => observed,
        }
    }

    #[cold]
    fn observe_held(
        &self,
        tries: usize,
        budget: &mut WorkBudget,
    ) -> Result<Observed, ObserveError> {
        let guard = self.hold(tries, budget)?;
        let observed = self.decide();
        match observed {
            Ok(_) => guard.release(),
            Err(_) => guard.poison(),
        }
        observed
    }

    #[inline(always)]
    fn decide(&self) -> Result<Observed, ObserveError> {
        probe::note(Primitive::Load);
        let record =
            fill::observe(self.state, self.serial.get() + 1).map_err(|_| ObserveError::Corrupt)?;
        let Record::Occupied {
            serial, departed, ..
        } = record
        else {
            return Err(ObserveError::Corrupt);
        };
        if serial != self.serial {
            return Err(ObserveError::Corrupt);
        }
        if !departed {
            return Ok(Observed::Pending);
        }
        let terminal = self.row.terminal().map_err(|_| ObserveError::Corrupt)?;
        let end = match terminal {
            Terminal::Published { expires_at_s, .. } => {
                FillEnd::Published(self.version(expires_at_s))
            }
            Terminal::Failed(failure) => FillEnd::Failed(failure),
            Terminal::Ready => FillEnd::Missing,
            Terminal::Granted => return Err(ObserveError::Corrupt),
        };
        #[cfg(test)]
        if PLANT.with(std::cell::Cell::get) == Some(Plant::FailedAsPublished)
            && let FillEnd::Failed(_) = end
        {
            return Ok(Observed::Ended(FillEnd::Published(self.version(u32::MAX))));
        }
        Ok(Observed::Ended(end))
    }

    /// The version the row names, with deadline `expires_at_s`.
    fn version(&self, expires_at_s: u32) -> JoinedVersion {
        let (metadata_len, body_len) = self.row.lengths();
        JoinedVersion {
            tag: self.row.allocation(),
            key: self.key,
            metadata_len,
            body_len,
            expires_at_s,
        }
    }

    /// Takes a lease on the version the record published and detaches the
    /// follower once the lease's right is counted. `budget` is charged the
    /// record's visit, for a malformed record the second observation's gate
    /// tries, and the credit's and the right's reservations.
    ///
    /// # Errors
    ///
    /// The follower, still joined, with the [`JoinedReadError`], which
    /// carries the observation when the record has not published; every
    /// reservation the attempt made was returned.
    pub fn acquire(
        self,
        tries: usize,
        budget: &mut WorkBudget,
    ) -> Result<ExtentLease<'s, P>, (Self, JoinedReadError)> {
        self.acquired(Credit::Shared, tries, budget, |storage, version| {
            ExtentLease::new(storage, version.id(), version.key, Credit::Shared)
        })
    }

    /// [`acquire`](Self::acquire) with the right alone reserved, under
    /// `Credit::Read`, for the volume read that takes it over: no credit
    /// within `L`, so the acquisition never refuses `LeaseLimit`.
    ///
    /// # Errors
    ///
    /// As [`acquire`](Self::acquire).
    pub(super) fn acquire_right(
        self,
        tries: usize,
        budget: &mut WorkBudget,
    ) -> Result<ReadRight<'s, P>, (Self, JoinedReadError)> {
        self.acquired(Credit::Read, tries, budget, |storage, version| {
            ReadRight::new(storage, version.id())
        })
    }

    /// The follower remains joined until `hold` returns and the cutoff reads
    /// open with `SeqCst`.
    fn acquired<H>(
        self,
        credit: Credit,
        tries: usize,
        budget: &mut WorkBudget,
        hold: impl FnOnce(&'s Storage<P>, &JoinedVersion) -> H,
    ) -> Result<H, (Self, JoinedReadError)> {
        let version = match self.observe(tries, budget) {
            Ok(Observed::Ended(FillEnd::Published(version))) => version,
            Ok(Observed::Ended(FillEnd::Missing)) => return Err((self, JoinedReadError::Missing)),
            Ok(Observed::Ended(FillEnd::Failed(failure))) => {
                return Err((self, JoinedReadError::Failed(failure)));
            }
            Ok(Observed::Pending) => return Err((self, JoinedReadError::Pending)),
            Err(error) => return Err((self, error.into())),
        };
        // A cutoff already closed refuses before any reservation.
        if self.storage.is_closed() {
            return Err((self, JoinedReadError::Closed));
        }
        let counters = match self.reserve(&version, credit, budget) {
            Ok(counters) => counters,
            Err(error) => return Err((self, error)),
        };
        let held = hold(self.storage, &version);
        if self.storage.closed().load(Ordering::SeqCst) {
            drop(held);
            return Err((self, JoinedReadError::Closed));
        }
        // The lease is granted, so the read earns its hit; `held` owns the
        // right that keeps the word on the version's incarnation.
        counters.visit();
        // The right is counted, so the follower's interest ends here.
        let follower = ManuallyDrop::new(self);
        probe::note(Primitive::Rmw);
        follower.row.detach();
        Ok(held)
    }

    /// The deadline check, then the credit from `credit`'s source and the
    /// right on `version`'s exact incarnation, with no visited bit set.
    fn reserve(
        &self,
        version: &JoinedVersion,
        credit: Credit,
        budget: &mut WorkBudget,
    ) -> Result<LeaseCounters<'s, P>, JoinedReadError> {
        let ticks = self
            .storage
            .platform
            .now_ticks()
            .ok_or(JoinedReadError::ClockUnavailable)?;
        if expired(ticks, version.expires_at_s) {
            return Err(JoinedReadError::Expired);
        }
        let (pool, root) = self.storage.live().ok_or(JoinedReadError::Missing)?;
        let slot = version.id().slot().0;
        if slot >= pool.records().len() {
            return Err(JoinedReadError::Missing);
        }
        // SAFETY: `slot < O`, checked above.
        unsafe {
            reserve_incarnation(
                self.storage,
                pool,
                slot,
                root,
                version.id().incarnation(),
                credit,
                budget,
            )
        }
        .map_err(JoinedReadError::from)
    }

    /// Ends the follower's interest; its drop does the same.
    pub fn detach(self) {
        drop(self);
    }

    fn hold(&self, tries: usize, budget: &mut WorkBudget) -> Result<GateGuard<'s>, ObserveError> {
        let index = self.storage.index().ok_or(ObserveError::Corrupt)?;
        let image = index.image.shard(self.shard).ok_or(ObserveError::Corrupt)?;
        // SAFETY: the index mapping is owned and initialized while the
        // storage is live, which the follower's borrow guarantees, and every
        // word read here is an atomic.
        let (gate, control) =
            unsafe { (image.gate(&index.mapping), image.control(&index.mapping)) };
        // Gate poisoning confirms corruption after an unlocked read finds a malformed record.
        let guard = take_gate(gate, control, tries, budget).map_err(|refusal| match refusal {
            Refusal::Poisoned => ObserveError::Corrupt,
            refusal => ObserveError::from(refusal),
        })?;
        probe::note(Primitive::GateTaken);
        Ok(guard)
    }
}

impl<P: Platform> Drop for FillFollower<'_, P> {
    /// The follower detaches with one `Release` subtraction, paired with
    /// service's `Acquire` read of the count to order the follower's reads
    /// before its record is freed.
    fn drop(&mut self) {
        probe::note(Primitive::Rmw);
        let previous = self.row.detach();
        debug_assert!(previous >= 1, "a follower detached without its interest");
    }
}

/// A planted defect for a negative control.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Plant {
    /// A join matches a record by its fingerprint alone.
    FingerprintJoin,
    /// An observation reports a recorded failure as a publication.
    FailedAsPublished,
}

#[cfg(test)]
thread_local! {
    pub(super) static PLANT: std::cell::Cell<Option<Plant>> = const { std::cell::Cell::new(None) };

    pub(super) static INTERPOSE_AFTER_JOIN: std::cell::Cell<Option<fn()>> =
        const { std::cell::Cell::new(None) };
}

/// One fill record and its row as a test observes them.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RowView {
    pub(crate) record: Record,
    pub(crate) observers: u64,
    pub(crate) terminal: Terminal,
    /// The row's allocation: the retained incarnation once published.
    pub(crate) allocation: AllocationId,
}

#[cfg(test)]
impl<P: Platform> Storage<P> {
    /// Record `record` of `shard`'s fill table and its row. Precondition:
    /// the storage is live and the record is below the table's length.
    pub(crate) fn fill_row(&self, shard: ShardIndex, record: usize) -> RowView {
        let table = self
            .fill_table(shard)
            .expect("a live shard with a fill table");
        // SAFETY: the storage is live and only atomics are read.
        let view = unsafe { self.fill_view(table) };
        let next = view.control.next_serial.load();
        let row = &view.rows[record];
        RowView {
            record: fill::decode(view.states[record].load(Ordering::Acquire), next)
                .expect("a well-formed record"),
            observers: row.observers(),
            terminal: row.terminal().expect("a well-formed row"),
            allocation: AllocationId::of_record_tag(row.allocation()),
        }
    }
}
