//! SIEVE eviction in the volume's one domain: select one feasible victim
//! under the pool gate, commit it by exact identity under the shard gate,
//! and mark its slot in flight, as one budgeted internal step.
//!
//! Selection (Zhang et al., *SIEVE is Simpler than LRU*, NSDI 2024,
//! Algorithm 1, with retention). The hand examines members from the tail
//! toward the head, wrapping. One visit decides from one load of the
//! member's lifetime word, in this order:
//!
//! 1. a set abandonment flag is a retirement of the member's current
//!    incarnation parked without the gate, since a flag always describes the
//!    incarnation beside it: the observer rule detaches the member and the
//!    hand moves on;
//! 2. a count of zero is an unpublished resident, retained;
//! 3. a count above one is a leased object, retained;
//! 4. a set visited bit is cleared with one `fetch_and`, which changes no
//!    other bit of the word, and the hand moves on;
//! 5. otherwise the member is unflagged and `refs == 1`, the
//!    index's anchor alone: the candidate. Its fingerprint word is copied
//!    from its record; `bind` wrote it before the slot became resident. A
//!    retirement may already have stamped its era over the fingerprint, and
//!    a removal routed from the era ends `Absent`. Its `AllocationId` is
//!    built from the slot and the word's incarnation, and the hand rests on
//!    its head-side neighbour.
//!
//! Retained members keep their visited bit and their place. A word with a
//! reserved bit set panics under the gate and poisons it. A pass is the
//! domain's member count once the pending mark is applied, in visits. A
//! second pass runs only if the first cleared a visited bit, since
//! a pass that cleared nothing cannot yield a candidate from the same state;
//! after the passes the call reports `blocked_by_readers_or_io`, as it does
//! when the domain has no member, the volume's free units sit at or below
//! the clean reserve `R` plus the escrow `U` of units promised to builders,
//! and some detached extent waits for readers.
//!
//! Commit. After the pool gate is released, exact removal of the copied
//! identity under the shard gate, routed from the copied fingerprint without
//! a hash pass, refusing a victim whose fingerprint has a current,
//! undeparted replacement attempt (`Replacing`, attempt intact, incumbent
//! visible). A stale identity is `Absent`; a busy shard gate is `Contended`
//! and a poisoned one `Poisoned`, the candidate staying linked with the
//! hand past it;
//! `Corrupt` poisons the shard gate.
//! A found commit records the retirement through the ordinary path with
//! `record_evicted`. When that path takes the pool gate, the same hold
//! calls `mark_evicted_with`, which detaches the member;
//! when `record_evicted` returns `RetireOutcome::Parked`, the commit leaves
//! one pending mark `(slot, incarnation)` in the volume's record.
//! Under the selection hold, `prefetch_after_selection` issues write hints for the victim's catalog entries that `return_extent` clears.
//! Before the selection hold ends, the lines the commit and the retirement
//! touch after the shard gate, the victim's base bucket among them, and
//! those the next selection reads first at the hand, are requested from the
//! cache. Where a locked instruction waits for earlier hints, the shard
//! gate's exchange then waits once for all of them, instead of each later
//! locked instruction waiting for its own miss. After its last gate
//! exchange the step requests the record of the member past the hand, from
//! the `prev` link of the hand's record, hinted under the selection hold: a
//! selection that passes the hand's member reads that record next. From the
//! same record's fingerprint it also requests the chain summary and base
//! bucket of the hand's member, which the next step's commit walks first
//! when that member is its victim, so their misses overlap the work between
//! the two steps.
//!
//! Mark. The first pool-gate hold the next eviction takes applies a pending
//! mark before any selection, and the call ends with one try to apply it
//! itself; a busy gate leaves it pending. The mark applies only while the
//! slot still holds the victim's incarnation and is resident or retired
//! (the incarnation advances at claim, so a returned and reused slot never
//! matches): a still-linked slot detaches, and while the anchor is still
//! counted the slot is marked evicted and the domain's `in_flight` counts
//! it and `in_flight_units` its extents' length, which shrinks as service
//! returns them one per visit; once service released the
//! anchor with rights remaining and the slot's journal block is durable or
//! not needed, the extents are held by those rights, not in flight, and the
//! mark only detaches, while a slot whose anchor service released and whose
//! journal block is still unwritten, or which no right holds, is marked
//! evicted as an anchored one is. A mismatch writes nothing and counts a stale mark, so
//! `in_flight` and `in_flight_units` may under-count but never over-count.
//!
//! Budget. Selection spends only what the call's allowance leaves above
//! [`Storage::commit_bundle`], which prepays the commit (hash, gate tries,
//! the chain walk's bound, the fill-table scan) and the final mark try, so a
//! chosen commit is never refused for budget. [`SELECT_MIN`] plus that
//! bundle is the least allowance that makes one decision; less does nothing
//! beyond the refusal.
//!
//! Gate topology: selection releases the pool gate before the commit takes
//! the shard gate, and the commit makes one nonblocking pool-gate try under
//! the shard gate only when an in-flight pass needs the member's entry or a
//! required suffix its identity, a failed try refusing the commit; every
//! acquisition is one nonblocking try, and nothing waits under the pool gate.

use std::sync::atomic::Ordering;

use super::allocation::{AllocationId, RetireOutcome};
use super::budget::{BudgetExhausted, WorkBudget, WorkKind};
use super::gate::GateError;
use super::os::Platform;
use super::owner::{Pool, Storage};
use super::policy::{MARK_NONE, POLICY_NONE, PendingMark, PolicySlot, Queue};
use super::prefetch::{hint, hint_read};
use super::probe::{self, Event, Primitive};
use super::recovery::reusable;
use super::remove::RemoveError;
use super::slot::Record;
use super::tables::{SlotIndex, SlotState, Tables};
use super::word::{self, ABANDONED, ANCHORED, RESERVED, STATE, VISITED};
use crate::index::HASH_CHARGE;

/// Shard-gate attempts one commit makes.
pub(crate) const COMMIT_TRIES: usize = 2;

/// The selection hold's controls: the pool-gate attempt, the pending mark's
/// application and the hand's write-back.
pub(crate) const SELECT_CONTROLS: usize = 3;

const VISIT_VISITS: usize = 1;
const VISIT_VALIDATIONS: usize = 3;
const VISIT_UPDATES: usize = 1;

/// One visit: the visit, three validations (flag, count, visited bit) and
/// one possible update (a detach or a visited clear).
pub(crate) const SELECT_PER_VISIT: usize = VISIT_VISITS + VISIT_VALIDATIONS + VISIT_UPDATES;

/// The selection part of the least allowance that makes one decision.
pub(crate) const SELECT_MIN: usize = SELECT_CONTROLS + SELECT_PER_VISIT;

/// The final mark try: one gate attempt and one update.
const MARK_TRY: usize = 2;

/// Why an eviction step did nothing at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EvictError {
    /// The storage is drained.
    TornDown,
    /// Fewer than [`SELECT_MIN`] plus the commit bundle remain; nothing was
    /// debited.
    BudgetExhausted,
    /// The pool gate was busy or poisoned; the attempt alone was debited
    /// and any pending mark stays pending.
    Gate(GateError),
}

impl From<BudgetExhausted> for EvictError {
    fn from(_: BudgetExhausted) -> Self {
        Self::BudgetExhausted
    }
}

/// What a chosen candidate's commit did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Commit {
    /// The pair was cleared and the retirement recorded.
    Evicted {
        victim: AllocationId,
        fingerprint: u64,
        retirement: RetireOutcome,
    },
    /// A current, undeparted attempt is associated with a key of the
    /// victim's fingerprint; nothing changed.
    Replacing,
    /// No pair names the identity: invalidated, replaced or reused before
    /// the commit, or never published into an index.
    Absent,
    /// Every shard-gate attempt found it busy; the candidate stays linked.
    Contended,
    /// The shard's gate is poisoned; the candidate stays linked and no later
    /// commit in that shard can succeed.
    Poisoned,
    /// The shard's tables are malformed; its gate is poisoned.
    Corrupt,
    /// The tenure's suffix refused the removal's record, its log full, stalled, past its bound, not yet open or
    /// closed; the candidate stays linked and a later call retries it.
    History,
}

/// What the shared step frame reports.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Framed {
    pub commit: Option<Commit>,
    pub stale_marks: usize,
    pub mark_pending: bool,
}

/// One nonblocking pool-gate attempt, noted for the observer.
fn try_pool(live: &Pool) -> Result<super::tables::PoolAccess<'_>, GateError> {
    let attempt = live.try_lock();
    probe::note(match &attempt {
        Ok(_) => Primitive::GateTaken,
        Err(GateError::Contended) => Primitive::GateBusy,
        Err(GateError::Poisoned) => Primitive::GatePoisoned,
    });
    attempt
}

/// One eviction step's exact counts, for this call only.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct EvictReport {
    pub visited: usize,
    /// Visited bits cleared.
    pub cleared: usize,
    /// Members retained because their count is above one, the anchor plus
    /// at least one right.
    pub held: usize,
    pub unpublished: usize,
    /// Members detached on sighting their current retirement.
    pub detached_seen: usize,
    /// The chosen candidate's commit, `None` when selection chose none.
    pub commit: Option<Commit>,
    /// Pending marks found stale when applied.
    pub stale_marks: usize,
    /// Whether a mark is still pending when the call returns.
    pub mark_pending: bool,
    pub blocked_by_readers_or_io: bool,
    /// Selection stopped because its allowance ended.
    pub budget_exhausted: bool,
    /// The chosen candidate's charge would take the retired charge past the
    /// allowance `T`, so the step committed nothing.
    pub beyond_allowance: bool,
    /// Units the chosen candidate's extents hold, read under the selection
    /// hold; zero when selection chose none.
    pub units: usize,
}

/// What one visit decided.
enum Visit {
    Kept(Kept),
    Clear,
    /// The candidate, at the incarnation its word carries.
    Candidate(u32),
}

/// A visit decided before the policy's own test: the member detaches or is
/// retained.
pub(super) enum Kept {
    Detach,
    Retain(Retained),
}

pub(super) enum Retained {
    Held,
    Unpublished,
}

impl<P: Platform> Storage<P> {
    /// Steps a commit prepays: one hash pass, [`COMMIT_TRIES`] gate
    /// attempts, the chain walk's bound (every bucket it may visit, one
    /// comparison per pair it may examine and one more per identity
    /// comparison), a scan of the largest fill table (one
    /// visit and one comparison per record), and the final mark try.
    pub(crate) fn commit_bundle(&self) -> usize {
        // The geometry is owned outside every mapping, so the bundle is the
        // same in every phase.
        let walk = self.index.as_ref().map_or(0, |index| {
            let geometry = &index.geometry;
            1 + geometry.depth() + 2 * geometry.chain_pairs() + 2 * geometry.fill_max()
        });
        HASH_CHARGE + COMMIT_TRIES + walk + MARK_TRY
    }

    /// One eviction step in the volume's domain: selection under the
    /// pool gate, the commit of a candidate after the gate is released, and
    /// the pending mark's application. See the module documentation.
    /// `admit` runs under the selection hold before any visit and may debit
    /// its own steps, which the visits are counted after. `framed_step`
    /// applies the pending mark before `admit` runs, so a `false` leaves the
    /// domain with that mark applied and nothing selected. `admit` reads the
    /// tables under the selection hold and pays only after the gate opened.
    ///
    /// Precondition: at most one eviction or expiry step runs at a time, and
    /// successive steps are ordered by happens-before: the volume's pending
    /// mark is two words with one writer. The caller serializes these steps;
    /// `maintain` does so under its root gate, and
    /// [`PendingMark::take`]'s relaxed store relies on that order.
    ///
    /// # Errors
    ///
    /// [`EvictError`]; only the pool-gate attempt is debited on `Gate`.
    pub(crate) fn evict_step(
        &self,
        budget: &mut WorkBudget,
        admit: impl FnOnce(&mut Tables<'_>, &mut WorkBudget) -> bool,
    ) -> Result<EvictReport, EvictError> {
        let live = self.live_pool().ok_or(EvictError::TornDown)?;
        let reserve = self.commit_bundle();
        budget.preflight(SELECT_MIN + reserve)?;
        let mut report = EvictReport::default();
        let mut ahead = POLICY_NONE;
        let refuse_replacing = true;
        let framed = self.framed_step(live, refuse_replacing, budget, |tables, budget| {
            if !admit(tables, budget) {
                return None;
            }
            let visits = funded_visits(budget, reserve);
            let chosen = select(tables, live, visits, &mut report, &mut ahead);
            pay_visits(budget, report.visited);
            // A discretionary victim's whole charge must fit the retired
            // allowance beside the charge already retired; a victim that
            // does not, a member when selected, takes the hand, so the next
            // step examines it first.
            chosen.filter(|victim| {
                report.units = tables.held_units(victim.id.slot().0) as usize;
                let fits = fits_allowance(tables, live, report.units as u64);
                if !fits {
                    report.beyond_allowance = true;
                    let slot = victim.id.slot().0 as u32;
                    tables.queue().set_hand(slot);
                    ahead = slot;
                }
                fits
            })
        })?;
        self.prefetch_past_hand(live, ahead);
        report.commit = framed.commit;
        report.stale_marks = framed.stale_marks;
        report.mark_pending = framed.mark_pending;
        Ok(report)
    }

    /// The frame one removal step shares: the pool-gate try and the
    /// selection controls, the pending mark applied first, `choose` run under
    /// the hold with the visits the allowance funds above the commit bundle,
    /// the gate released, the chosen candidate committed (refusing replacing
    /// keys when `refuse_replacing`), and the call-end mark try. The caller
    /// preflighted [`SELECT_MIN`] plus the commit bundle.
    ///
    /// # Errors
    ///
    /// `Gate` when the pool gate was busy or poisoned; the attempt alone is
    /// debited.
    pub(super) fn framed_step(
        &self,
        live: &Pool,
        refuse_replacing: bool,
        budget: &mut WorkBudget,
        choose: impl FnOnce(&mut Tables<'_>, &mut WorkBudget) -> Option<Victim>,
    ) -> Result<Framed, EvictError> {
        let mut framed = Framed::default();
        budget.debit(WorkKind::CoordinationAttempt)?;
        let access = try_pool(live).map_err(EvictError::Gate)?;
        budget
            .debit_n(WorkKind::Update, SELECT_CONTROLS - 1)
            .expect("the preflight covered the selection controls");
        // The selection's return ends the hold through `release`, so its drop
        // is a panic of the mark or the selection, and that drop poisons the
        // gate also in a step made by a thread that was already unwinding.
        let mut access = access.poison_on_unwind();
        let mut tables = access.tables();
        framed.stale_marks += usize::from(apply_mark(&mut tables, live));
        let candidate = choose(&mut tables, budget);
        if let Some(victim) = &candidate {
            // The commit's walk reads the victim's base bucket first, after
            // the shard gate's exchange; hinted here, from the fingerprint
            // the selection copied, the bucket's lines are in flight across
            // the gate release, the route derivation and the shard gate
            // tries.
            self.prefetch_bucket(victim.fingerprint, true);
        }
        access.release();
        if let Some(victim) = candidate {
            #[cfg(test)]
            if let Some(observe) = OBSERVE_COMMIT.with(std::cell::Cell::get) {
                observe(victim.id, None);
            }
            #[cfg(test)]
            if let Some(interpose) = INTERPOSE_BEFORE_COMMIT.with(std::cell::Cell::take) {
                interpose();
            }
            let commit = self.commit(live, &victim, refuse_replacing, budget);
            #[cfg(test)]
            if let Some(observe) = OBSERVE_COMMIT.with(std::cell::Cell::get) {
                observe(victim.id, Some(commit));
            }
            framed.commit = Some(commit);
        }
        if live.pending_mark().is_pending() {
            budget
                .debit(WorkKind::CoordinationAttempt)
                .expect("the commit bundle covered the mark try");
            if let Ok(access) = try_pool(live) {
                budget
                    .debit(WorkKind::Update)
                    .expect("the commit bundle covered the mark try");
                // The mark's panic poisons the gate, as the selection hold
                // above does.
                let mut access = access.poison_on_unwind();
                framed.stale_marks += usize::from(apply_mark(&mut access.tables(), live));
                access.release();
            }
        }
        framed.mark_pending = live.pending_mark().is_pending();
        Ok(framed)
    }

    /// Hints the chain summary and both lines of the base bucket
    /// `fingerprint` routes to, for a caller that will store to the bucket
    /// (`for_write`) or only read it, as [`IndexOwner::prefetch`] does. Only
    /// addresses are formed.
    ///
    /// [`IndexOwner::prefetch`]: super::owner::IndexOwner::prefetch
    #[inline(always)]
    pub(super) fn prefetch_bucket(&self, fingerprint: u64, for_write: bool) {
        if let Some(index) = self.index() {
            index
                .hasher
                .hint_route(fingerprint, &index.geometry, index.prefetch(for_write));
        }
    }

    /// Commits `victim` under the shard gate its fingerprint routes to,
    /// refusing a replacing attempt when `refuse_replacing`, and leaves its
    /// mark pending on a found commit.
    ///
    /// Always inlined into its one caller, so the outcome stays in
    /// registers: returned through memory, the caller's wide loads of it
    /// straddle this function's narrower stores and stall on store
    /// forwarding.
    #[inline(always)]
    fn commit(
        &self,
        live: &Pool,
        victim: &Victim,
        refuse_replacing: bool,
        budget: &mut WorkBudget,
    ) -> Commit {
        let Victim {
            id: victim,
            fingerprint,
        } = *victim;
        match self.remove_exact(fingerprint, victim, refuse_replacing, COMMIT_TRIES, budget) {
            Ok(retirement) => {
                let retirement = retirement.record_evicted();
                if retirement == RetireOutcome::Parked {
                    live.pending_mark()
                        .set(victim.slot().0, victim.incarnation());
                }
                Commit::Evicted {
                    victim,
                    fingerprint,
                    retirement,
                }
            }
            Err(RemoveError::Absent | RemoveError::NoIndex) => {
                probe::event(Event::Absent {
                    slot: victim.slot().0,
                });
                Commit::Absent
            }
            Err(RemoveError::Replacing) => Commit::Replacing,
            Err(RemoveError::Contended) => Commit::Contended,
            Err(RemoveError::Poisoned) => Commit::Poisoned,
            Err(RemoveError::Corrupt) => Commit::Corrupt,
            Err(RemoveError::History) => Commit::History,
            Err(RemoveError::BudgetExhausted) => {
                unreachable!("the commit bundle covers every step a commit takes")
            }
        }
    }
}

#[cfg(test)]
thread_local! {
    /// Runs once between the selection hold's release and the commit, so a
    /// test can move the candidate or hold a gate where only the commit or
    /// the mark can meet it.
    pub(super) static INTERPOSE_BEFORE_COMMIT: std::cell::Cell<Option<fn()>> =
        const { std::cell::Cell::new(None) };

    /// Sees every removal step's selected victim twice while installed:
    /// with `None` once the selection hold is released, before the commit
    /// and any interposed hook, and with the commit's immediate result
    /// after it.
    pub(super) static OBSERVE_COMMIT: std::cell::Cell<Option<CommitObserver>> =
        const { std::cell::Cell::new(None) };
}

/// A test observer of one removal step's victim and, after the commit, its
/// immediate result.
#[cfg(test)]
pub(super) type CommitObserver = fn(AllocationId, Option<Commit>);

impl PendingMark {
    /// Records the committed victim `(slot, incarnation)`. The call's first
    /// hold took any earlier mark, so none is pending here.
    #[inline]
    pub(crate) fn set(&self, slot: usize, incarnation: u32) {
        debug_assert!(!self.is_pending(), "a second victim before the mark");
        self.incarnation.store(incarnation, Ordering::Relaxed);
        self.slot.store(slot as u64, Ordering::Release);
    }

    /// The caller serializes eviction and expiry steps, so the words have one
    /// writer and `take` clears the mark with a relaxed store; concurrent
    /// steps could take the same mark.
    #[inline]
    pub(crate) fn take(&self) -> Option<(usize, u32)> {
        let slot = self.slot.load(Ordering::Acquire);
        if slot == MARK_NONE {
            return None;
        }
        self.slot.store(MARK_NONE, Ordering::Relaxed);
        Some((slot as usize, self.incarnation.load(Ordering::Relaxed)))
    }

    #[inline]
    pub(crate) fn is_pending(&self) -> bool {
        self.slot.load(Ordering::Relaxed) != MARK_NONE
    }
}

/// A removal candidate chosen under the pool gate: its identity and the
/// fingerprint word copied under the pool gate in the same hold. The commit
/// routes from the fingerprint word and checks a replacing attempt against
/// it.
#[derive(Debug, Clone, Copy)]
pub(super) struct Victim {
    pub(super) id: AllocationId,
    pub(super) fingerprint: u64,
}

impl Victim {
    /// Copies resident `slot`'s fingerprint for its current `incarnation`,
    /// under the pool gate the caller holds.
    #[inline(always)]
    pub(super) fn read(live: &Pool, slot: usize, incarnation: u32) -> Self {
        Self {
            id: AllocationId::new(SlotIndex(slot), incarnation),
            fingerprint: live.records()[slot].fingerprint(),
        }
    }
}

/// If the hand's candidate tests fail, [`walk`] starts with the queue hand
/// present on entry to `select`, and its counts add to the report values
/// present then. A choice sets `ahead` to the member the hand then names.
#[inline(always)]
fn select(
    tables: &mut Tables<'_>,
    live: &Pool,
    visits: usize,
    report: &mut EvictReport,
    ahead: &mut u32,
) -> Option<Victim> {
    let at = tables.queue().start();
    if at != POLICY_NONE && visits != 0 {
        let records = live.records();
        let slot = at as usize;
        let record = &records[slot];
        let current = record.ident.load(Ordering::Relaxed);
        let newer = record.prev();
        if candidate(current) {
            let victim = Victim::read(live, slot, word::incarnation(current));
            *ahead = newer;
            tables.queue().set_hand(newer);
            prefetch_after_selection(tables, live, slot, newer);
            report.visited += 1;
            return Some(victim);
        }
        if candidate(current & !VISITED) && visits >= 2 && tables.queue().members_len() >= 2 {
            let next = match newer {
                POLICY_NONE => tables.domain.tail,
                newer => newer,
            } as usize;
            let following = &records[next];
            let after = following.ident.load(Ordering::Relaxed);
            if candidate(after) {
                record.ident.fetch_and(!VISITED, Ordering::Relaxed);
                let rest = following.prev();
                let victim = Victim::read(live, next, word::incarnation(after));
                *ahead = rest;
                tables.queue().set_hand(rest);
                prefetch_after_selection(tables, live, next, rest);
                report.visited += 2;
                report.cleared += 1;
                return Some(victim);
            }
        }
    }
    let walked = walk(tables.queue(), live.records(), visits);
    let kept = walked.held + walked.unpublished + walked.detached_seen;
    report.visited += walked.visited;
    report.cleared += walked.visited - kept - usize::from(walked.found.is_some());
    report.held += walked.held;
    report.unpublished += walked.unpublished;
    report.detached_seen += walked.detached_seen;
    report.budget_exhausted |= walked.budget_exhausted;
    report.blocked_by_readers_or_io |= walked.passes_spent;
    if let Some((slot, incarnation, newer)) = walked.found {
        let victim = Victim::read(live, slot, incarnation);
        *ahead = newer;
        prefetch_after_selection(tables, live, slot, newer);
        return Some(victim);
    }
    // No member, or every member detached on sighting: nothing to select.
    if tables.queue().members_len() == 0 {
        let claimable = super::reserve::claimable_units(tables, live);
        report.blocked_by_readers_or_io |= claimable == 0 && tables.domain.detached > 0;
    }
    None
}

/// Whether a victim holding `units` units fits the retired allowance `T`
/// beside the units already retired, under the pool gate the caller holds;
/// a storage configured without watermarks has `retired_limit` `u64::MAX`,
/// which every victim fits.
fn fits_allowance(tables: &Tables<'_>, live: &Pool, units: u64) -> bool {
    tables.domain.retired_units + units <= live.image.retired_limit
}

/// What one walk did: the candidate's slot, incarnation and the hand's new
/// position, if it found one, and its counts and flags, which [`select`]
/// merges into the step's report.
#[derive(Default)]
struct Walked {
    found: Option<(usize, u32, u32)>,
    visited: usize,
    held: usize,
    unpublished: usize,
    detached_seen: usize,
    budget_exhausted: bool,
    passes_spent: bool,
}

/// The SIEVE walk over the domain for at most `visits` visits, the
/// number the allowance funds; the caller debits the visits made as one
/// total when the walk ends.
#[inline(never)]
fn walk(mut queue: Queue<'_>, records: &[Record], visits: usize) -> Walked {
    let pass = queue.members_len();
    let mut at = queue.start();
    let mut walked = Walked::default();
    // Each visit retains or detaches its member, a `Kept` outcome counted by
    // `kept`, clears its visited bit, or chooses it and ends the walk. So a
    // full pass cleared a bit exactly when fewer than `pass` of its visits
    // were `Kept`, and the walk's clears are its visits less its `Kept`
    // visits and its candidate.
    let kept = |walked: &Walked| walked.held + walked.unpublished + walked.detached_seen;
    let (mut pass_end, mut pass_kept, mut second) = (pass, 0, false);
    let mut visited = 0;
    while at != POLICY_NONE {
        if visited == visits {
            walked.budget_exhausted = true;
            break;
        }
        visited += 1;
        let slot = at as usize;
        let record = &records[slot];
        let current = record.ident.load(Ordering::Relaxed);
        let newer = record.prev();
        let next = match newer {
            POLICY_NONE => queue.tail(),
            newer => newer,
        };
        match visit(current) {
            Visit::Kept(Kept::Detach) => {
                queue.detach(slot);
                probe::event(Event::Detached { slot });
                walked.detached_seen += 1;
                at = if queue.members_len() == 0 {
                    POLICY_NONE
                } else {
                    next
                };
            }
            Visit::Kept(Kept::Retain(Retained::Unpublished)) => {
                walked.unpublished += 1;
                at = next;
            }
            Visit::Kept(Kept::Retain(Retained::Held)) => {
                at = next;
                let stop = visits.min(pass_end);
                let mut held = 1;
                while visited < stop {
                    let record = &records[at as usize];
                    let current = record.ident.load(Ordering::Relaxed);
                    if current & (ABANDONED | RESERVED | STATE) != SlotState::Resident.bits()
                        || word::refs(current) < 2
                    {
                        break;
                    }
                    let newer = record.prev();
                    visited += 1;
                    held += 1;
                    at = match newer {
                        POLICY_NONE => queue.tail(),
                        newer => newer,
                    };
                }
                walked.held += held;
            }
            Visit::Clear => {
                record.ident.fetch_and(!VISITED, Ordering::Relaxed);
                at = next;
                let stop = visits.min(pass_end);
                while visited < stop {
                    let record = &records[at as usize];
                    let current = record.ident.load(Ordering::Relaxed);
                    if !clearable(current) {
                        break;
                    }
                    let newer = record.prev();
                    visited += 1;
                    record.ident.fetch_and(!VISITED, Ordering::Relaxed);
                    at = match newer {
                        POLICY_NONE => queue.tail(),
                        newer => newer,
                    };
                }
            }
            Visit::Candidate(incarnation) => {
                queue.set_hand(newer);
                walked.found = Some((slot, incarnation, newer));
                walked.visited = visited;
                return walked;
            }
        }
        if visited == pass_end {
            let kept_now = kept(&walked);
            if second || kept_now - pass_kept == pass {
                walked.passes_spent = true;
                break;
            }
            (pass_end, pass_kept, second) = (pass_end + pass, kept_now, true);
        }
    }
    queue.set_hand(at);
    walked.visited = visited;
    walked
}

/// The prefetches prepare cache lines for work after the selection hold: `victim`'s record for its retirement stamp, its retired-bitmap word, metadata hinted by [`Pool::prefetch_retirement`], and, when `victim` has a tail-side neighbour, that neighbour's record for the unlink's `prev` update. When `next != POLICY_NONE`, they also prepare `next`'s record for the next selection and its policy `next` link, which the unlink updates when `next` is `victim`'s head-side neighbour. Reading `tables.policy_next[victim]` under the selection hold identifies the tail-side neighbour; the remaining prefetches only form addresses.
///
/// The hints sit between two gate exchanges. On a core whose locked instructions wait for older software prefetches, such as AMD Zen 4, the shard gate's exchange waits for them. Each line would otherwise miss after that exchange, behind a later locked instruction of the commit, the retirement, the slot's return or the next selection; requested here, the one wait covers them together with the bucket the commit's walk reads first.
#[inline(always)]
fn prefetch_after_selection(tables: &Tables<'_>, live: &Pool, victim: usize, next: u32) {
    prefetch_retirement_lines(tables, live, victim);
    live.prefetch_retirement(victim);
    let older = tables.policy_next[victim];
    if older != POLICY_NONE {
        hint(std::ptr::from_ref(&live.records()[older as usize]).cast());
    }
    if next == POLICY_NONE {
        return;
    }
    let next = next as usize;
    hint(std::ptr::from_ref(&tables.policy_next[next]).cast());
    hint_read(std::ptr::from_ref(&live.records()[next]).cast());
}

impl<P: Platform> Storage<P> {
    /// Asks the cache for the record of the member after `ahead`, the member
    /// the hand names, which the next selection reads when it passes `ahead`,
    /// as it does when `ahead` keeps a hit; and for the base bucket of
    /// `ahead` itself, which the next commit walks first when `ahead` is the
    /// next victim.
    ///
    /// `ahead`'s record was hinted under the selection hold, so by the end of
    /// the step its line is usually cached. Its `prev` link and its
    /// fingerprint are read here, without the gate, only to form addresses:
    /// a link a concurrent hold has since moved names another line to hint,
    /// and a fingerprint a retirement has since stamped routes to another
    /// bucket, never a decision. The hints are issued after the step's last
    /// gate exchange.
    #[inline(always)]
    pub(super) fn prefetch_past_hand(&self, live: &Pool, ahead: u32) {
        let records = live.records();
        if let Some(record) = records.get(ahead as usize) {
            let after = record.prev();
            if after != POLICY_NONE {
                hint_read(records.as_ptr().wrapping_add(after as usize).cast());
            }
            self.prefetch_bucket(record.fingerprint_hint(), false);
        }
    }
}

/// Asks the cache for the lines `victim`'s retirement touches after the
/// shard gate: its record, whose fingerprint takes the stamp and whose word
/// and locator the retirement reads, and its retired-bitmap word. Only
/// addresses are formed; nothing is read. Shared by eviction's selection and
/// the expiry sweep, each hinting its own further lines.
#[inline(always)]
pub(super) fn prefetch_retirement_lines(tables: &Tables<'_>, live: &Pool, victim: usize) {
    hint(std::ptr::from_ref(&live.records()[victim]).cast());
    hint(std::ptr::from_ref(&tables.retired[victim / 64]).cast());
}

/// The visits `budget` funds while keeping `reserve` for the commit. The
/// caller ensures `reserve <= budget.remaining()` and calls this after its
/// own debits, since a debit after the call would spend into `reserve`.
pub(super) fn funded_visits(budget: &WorkBudget, reserve: usize) -> usize {
    (budget.remaining() - reserve) / SELECT_PER_VISIT
}

/// Debits `visits` visit bundles; the caller bounded its visits by the
/// allowance, so every debit succeeds. Each visit is observed as one load.
pub(super) fn pay_visits(budget: &mut WorkBudget, visits: usize) {
    let paid = budget
        .debit_n(WorkKind::Visit, VISIT_VISITS * visits)
        .and_then(|()| budget.debit_n(WorkKind::Comparison, VISIT_VALIDATIONS * visits))
        .and_then(|()| budget.debit_n(WorkKind::Update, VISIT_UPDATES * visits));
    debug_assert!(paid.is_ok(), "visits were bounded by the allowance");
    probe::note_n(Primitive::Load, visits);
}

#[inline(always)]
fn visit(current: u64) -> Visit {
    if current & (ABANDONED | RESERVED | STATE) == SlotState::Resident.bits() {
        return match word::refs(current) {
            0 => Visit::Kept(Kept::Retain(Retained::Unpublished)),
            1 if current & VISITED != 0 => Visit::Clear,
            1 => Visit::Candidate(word::incarnation(current)),
            _ => Visit::Kept(Kept::Retain(Retained::Held)),
        };
    }
    // Decoded in every build, so a malformed word or an unknown state
    // panics under the gate the caller holds and poisons it.
    let state = word::state(current);
    debug_assert_eq!(state, SlotState::Resident, "a linked slot not resident");
    if let Some(kept) = retention(current) {
        return Visit::Kept(kept);
    }
    if current & VISITED != 0 {
        Visit::Clear
    } else {
        Visit::Candidate(word::incarnation(current))
    }
}

#[inline(always)]
fn clearable(current: u64) -> bool {
    let set = SlotState::Resident.bits() | VISITED;
    current & (ABANDONED | VISITED | RESERVED | STATE) == set && word::refs(current) == 1
}

#[inline(always)]
fn candidate(current: u64) -> bool {
    current & (ABANDONED | VISITED | RESERVED | STATE) == SlotState::Resident.bits()
        && word::refs(current) == 1
}

/// The first three steps of a visit to a resident whose word is `current`,
/// shared with the expiry sweep: a parked retirement of the current
/// incarnation detaches, and a zero count or a lease retains; `None` leaves
/// the decision to the caller's own test.
#[inline(always)]
pub(super) fn retention(current: u64) -> Option<Kept> {
    if current & ABANDONED != 0 {
        return Some(Kept::Detach);
    }
    match word::refs(current) {
        0 => Some(Kept::Retain(Retained::Unpublished)),
        1 => None,
        _ => Some(Kept::Retain(Retained::Held)),
    }
}

/// Applies the volume's pending mark, if any, under the gate the caller holds,
/// and returns whether it was stale.
#[inline(always)]
fn apply_mark(tables: &mut Tables<'_>, live: &Pool) -> bool {
    let Some((slot, incarnation)) = live.pending_mark().take() else {
        return false;
    };
    let slot_word = live.records()[slot].ident.load(Ordering::Relaxed);
    let current = word::incarnation(word::checked(slot_word)) == incarnation
        && matches!(
            word::state(slot_word),
            SlotState::Resident | SlotState::Retired
        );
    if !current {
        probe::event(Event::StaleMark { slot });
        return true;
    }
    // The victim's own retirement set the anchored bit before the mark was
    // recorded, and only a holder of this gate clears it. Once service
    // released the anchor while rights remain and the journal block does
    // not hold the slot, the extent is held by those rights, not in flight:
    // the mark only detaches. Released with no right left, the slot is held
    // only for its journal block, and its eviction is in flight as the
    // gate-recorded one is; a zero count is final, since no retain lands on
    // zero. Released with its block still unwritten, the slot is in flight
    // too, as service leaves a gate-recorded one, so it is still counted
    // when its last right goes. A closed storage's next service call
    // returns or uncounts it.
    let in_flight = slot_word & ANCHORED != 0
        || word::refs(slot_word) == 0
        || !reusable(
            0,
            tables.journal().position(slot),
            live.journal_words().prefix.load(Ordering::Acquire),
            false,
        );
    let units = tables.held_units(slot);
    let mut queue = tables.queue();
    let detached = if in_flight {
        queue.mark_evicted(slot, units)
    } else {
        queue.detach(slot)
    };
    if detached {
        probe::event(Event::Detached { slot });
    }
    false
}
