//! The expiry sweep: one budgeted step that advances a persistent
//! cursor over runs of slots and removes the first unretained resident whose
//! deadline seconds the call's sample has reached, by exact identity, through
//! the eviction step's frame.
//!
//! Sample rule. The monotonic clock is sampled once per call, before the
//! pool gate is taken and before any slot is examined; never per slot and
//! never inside a gate hold. A resident is expired when the sample's whole
//! seconds are at or past its record's deadline seconds, the rule lookup and
//! publication apply ([`expired`]), so the sweep never removes an object a
//! lookup could still serve. Rounding the deadline down lets removal precede
//! a deadline within `u32::MAX` seconds by less than one second on this
//! thread's timeline, never
//! follow it by more than the delay of how often a funded caller runs the
//! sweep. A `None` sample
//! skips the stage: nothing is examined, the cursor stays and the report
//! says `clock_unavailable`. The sweep decides no validity: lookup refuses
//! an expired resident as `Expired` whether or not the sweep has reached it.
//! The deadline is the caller's absolute tick value, kept in whole seconds.
//! That the sweep removes only objects a lookup on another CPU also refuses
//! as `Expired` assumes the monotonic clock is one domain across CPUs within
//! one boot and time namespace; this is assumed, not proven.
//!
//! Visit. The cursor walks slot indices, not a list. A slot that is not
//! resident costs its visit and nothing more. A resident takes the eviction
//! visit's first three steps on one load of its lifetime word: a parked
//! retirement of its current incarnation is detached (the observer rule),
//! and an unpublished resident or a lease retains it and is counted, so an
//! expired object a reader holds stays indexed, its bytes readable through
//! the held lease, until the lease is released and the sweep revisits it.
//! Otherwise the resident is a candidate when the sample has reached its
//! deadline. The walk reads the state and the deadline from the slot's one
//! record, where `bind` stored the deadline in the hold that set `Resident`,
//! and copies a candidate's fingerprint from the same record.
//!
//! Removal. The candidate is removed by exact identity after the gate is
//! released, routed from its stored fingerprint, without the eviction
//! commit's association check: an expired
//! incumbent can never be served, so a current replacement attempt stays
//! intact and its later publication is a vacant insert. The removal records
//! the retirement, and its pending mark counts the extent in flight as
//! eviction's does. The cursor rests past the candidate, wraps at the end of
//! the table, and persists across calls, so a stopped sweep resumes where it
//! stopped and a funded loop revisits every slot.
//!
//! Bound. The volume keeps the least deadline, in whole seconds, among its
//! residents as a lower
//! bound: `bind` and the restored installs fold the deadline they make resident into the bound and
//! into the running least of the current pass, and the visit that wraps
//! the cursor publishes that running least as the bound and starts the next
//! pass at `u32::MAX`. Every resident at a wrap was either visited in the
//! pass that ended or bound during it, so the published value is at or
//! below every resident's deadline; a removal never raises it before the
//! next wrap. The holder that changes the bound also publishes it in the
//! pool's atomic copy, which the step reads before its sample and its gate
//! attempt: a sample whose whole seconds lie below the bound visits nothing
//! and takes no gate, since no resident can be expired; the cursor and the
//! pending mark stay, and the call reports zero visits and the stage done. A
//! bind that lowers the bound after the copy was read delays that resident's
//! removal to the next call, which is the sweep's one error. Removal still
//! follows the whole-second rule, and a funded loop still reaches every
//! expired resident: once a sample reaches any resident's deadline it is at
//! or past the bound, and the sweep runs.

use std::sync::atomic::Ordering;

use super::budget::WorkBudget;
use super::evict::{
    Commit, EvictError, Kept, Retained, SELECT_MIN, Victim, funded_visits, pay_visits,
    prefetch_retirement_lines, retention,
};
use super::os::Platform;
use super::owner::{Pool, Storage};
use super::policy::{POLICY_NONE, PolicySlot};
use super::prefetch::hint;
use super::probe::{self, Event};
use super::slot::{Record, expired};
use super::tables::{SlotState, Tables};
use super::word::{self, ABANDONED, RESERVED, STATE};

/// One expiry step's exact counts, for this call only.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ExpiryReport {
    /// Slots the cursor passed over.
    pub visited: usize,
    /// Residents retained because a lease holds them.
    pub held: usize,
    /// Residents retained because they are not published.
    pub unpublished: usize,
    /// Residents detached on sighting their current retirement.
    pub detached_seen: usize,
    /// The expired candidate's removal, `None` when the run found none.
    pub commit: Option<Commit>,
    /// Pending marks found stale when applied.
    pub stale_marks: usize,
    /// The mark is still pending at call end, on every `Ok` return, a
    /// missing clock included.
    pub mark_pending: bool,
    /// The cursor passed the end of the slot table and restarted.
    pub wrapped: bool,
    /// The run stopped because its allowance ended.
    pub budget_exhausted: bool,
    /// The clock gave no sample; the stage was skipped.
    pub clock_unavailable: bool,
}

impl<P: Platform> Storage<P> {
    /// One expiry step over the volume's slots from its expiry cursor. See
    /// the module documentation.
    ///
    /// Precondition: at most one eviction or expiry step runs at a time,
    /// ordered by happens-before, because both write the volume's two-word
    /// pending mark.
    ///
    /// # Errors
    ///
    /// `TornDown`; `BudgetExhausted` below the eviction step's minimum,
    /// before the sample, with nothing debited; `Gate` when the pool gate was
    /// busy or poisoned, with the attempt alone debited and the cursor
    /// unmoved.
    pub(crate) fn expire_step(&self, budget: &mut WorkBudget) -> Result<ExpiryReport, EvictError> {
        let live = self.live_pool().ok_or(EvictError::TornDown)?;
        let reserve = self.commit_bundle();
        budget.preflight(SELECT_MIN + reserve)?;
        let mut report = ExpiryReport::default();
        // The published bound, in whole seconds, read without the gate: a
        // sample whose seconds lie below it can reach no resident's deadline,
        // so the call leaves the cursor, the mark and the gate untouched. A
        // bound of `u32::MAX` is both the value for no resident and a
        // clamped deadline's seconds, so the sample decides there too, and a
        // sweep at that second removes the clamped objects lookup refuses. A
        // bound lowered by a bind this read did not see delays that
        // resident's removal to the next call, the sweep's one error.
        let bound = live.deadline_bound.load(Ordering::Relaxed);
        // Every early return reports the mark as it stands; a funded run
        // reports the mark at its end instead.
        report.mark_pending = live.pending_mark().is_pending();
        let Some(sample) = self.platform.now_ticks() else {
            report.clock_unavailable = true;
            return Ok(report);
        };
        if !expired(sample, bound) {
            return Ok(report);
        }
        // An expired incumbent can never be served: no replacement check.
        let refuse_replacing = false;
        let mut next = None;
        let framed = self.framed_step(live, refuse_replacing, budget, |tables, budget| {
            let visits = funded_visits(budget, reserve);
            let chosen = sweep(tables, live, sample, visits, &mut report, &mut next);
            pay_visits(budget, report.visited);
            chosen
        })?;
        // The next step's removal starts its walk at this bucket when the
        // slot at the cursor is its candidate, as it is in a wave of expiry.
        if let Some(fingerprint) = next {
            self.prefetch_bucket(fingerprint, true);
        }
        report.commit = framed.commit;
        report.stale_marks = framed.stale_marks;
        report.mark_pending = framed.mark_pending;
        Ok(report)
    }
}

/// The run from the expiry cursor: at most `visits` visits, the number the
/// allowance funds, and one pass over the table, stopping at the first
/// expired candidate, whose fingerprint is copied and whose
/// identity is built from its slot and current incarnation; the caller debits the
/// visits made as one total when the run ends, as a bounded run may. The
/// cursor is written back past the last slot visited. A sample below the
/// volume's deadline bound visits nothing; otherwise every resident passed or
/// stopped at folds its deadline into the pass's running least, which the
/// wrap publishes as the bound.
///
/// Passes non-resident slots and only unflagged, anchored-only, unexpired
/// residents. `retention` decides every stopped
/// resident, as for eviction, so the scan filters never choose a removal.
///
/// A run that chose a candidate also tests the slot the cursor rests on:
/// when it holds an expired resident the scan would stop at, its
/// fingerprint goes to `next`, so the caller can hint the bucket the next
/// step's removal walks first. The test decides nothing: the next step
/// visits that slot again under its own hold.
///
/// Inlined into its one caller; no out-of-line call holds the report.
#[inline(always)]
pub(super) fn sweep(
    tables: &mut Tables<'_>,
    live: &Pool,
    sample: u64,
    visits: usize,
    report: &mut ExpiryReport,
    next: &mut Option<u64>,
) -> Option<Victim> {
    if !expired(sample, tables.state.earliest_deadline) {
        return None;
    }
    let records = live.records();
    let count = records.len();
    let run = visits.min(count);
    let start = tables.state.cursor_expiry;
    let (mut cursor, mut left) = (start, run);
    let resident = tables.state.ledger.resident;
    let predictable = resident >= count - count / DENSE_SLACK || resident <= count / SPARSE_SLACK;
    let mut candidate = None;
    let mut pass_earliest = tables.state.pass_earliest;
    while left > 0 {
        let stretch = &records[cursor..count.min(cursor + left)];
        let len = stretch.len();
        // The stretch's first slot is tested here: a wave of expiry stops
        // every call there, and needs no out-of-line scan.
        let first = stop_bit(&stretch[0], sample) != 0;
        let stop = if first {
            Some(0)
        } else {
            first_stop(&stretch[1..len], predictable, sample).map(|at| at + 1)
        };
        let passed = stop.map_or(len, |at| at + 1);
        // The records just scanned are in cache; the fold over them is what
        // the bound costs the walk.
        for record in &stretch[..passed] {
            if is_resident(record.ident.load(Ordering::Relaxed)) {
                pass_earliest = pass_earliest.min(record.expires_at_s());
            }
        }
        left -= passed;
        let slot = cursor + passed - 1;
        cursor = if slot + 1 == count {
            tables.state.earliest_deadline = std::mem::replace(&mut pass_earliest, u32::MAX);
            live.publish_deadline_bound(tables.state.earliest_deadline);
            0
        } else {
            slot + 1
        };
        if stop.is_none() {
            continue;
        }
        // Relaxed, as eviction's visit: the decision changes only gate-owned
        // state. The scan stops only at a resident or at a malformed word,
        // and only this gate's holder moves the state, so the word read here
        // is resident or panics.
        let current = records[slot].ident.load(Ordering::Relaxed);
        if word::state(current) != SlotState::Resident {
            unreachable!("the expiry scan stopped at a slot that is not resident");
        }
        match retention(current) {
            Some(Kept::Detach) => report.detached_seen += usize::from(detach(tables, slot)),
            Some(Kept::Retain(Retained::Held)) => report.held += 1,
            Some(Kept::Retain(Retained::Unpublished)) => report.unpublished += 1,
            None if !expired(sample, records[slot].expires_at_s()) => {}
            None => {
                candidate = Some(Victim::read(live, slot, word::incarnation(current)));
                prefetch_after_choice(tables, live, slot);
                break;
            }
        }
    }
    let visited = run - left;
    if candidate.is_some()
        && let Some(after) = records.get(cursor)
        && stop_bit(after, sample) != 0
        && expired(sample, after.expires_at_s())
    {
        *next = Some(after.fingerprint());
    }
    tables.state.cursor_expiry = cursor;
    tables.state.pass_earliest = pass_earliest;
    report.visited = visited;
    // The run passed the table's last slot exactly when it visited one and
    // began within `visited` slots of the end.
    report.wrapped = visited > 0 && start + visited >= count;
    report.budget_exhausted = candidate.is_none() && visited < count;
    candidate
}

/// Asks the cache for the lines the removal of `slot` touches after the
/// pool gate is released: the candidate's record, which takes the
/// retirement's stamp, its bitmap word, its policy `next` link, and the
/// lines of its two list neighbours that the retirement's unlink writes:
/// the head-side neighbour's `next` link and the tail-side neighbour's
/// record, which holds its `prev`. The neighbours' indices are read from
/// the candidate's links under the gate; every other line is only
/// addressed. The next slots' records are read in slot order, which the
/// hardware prefetches, and the step hints the next removal's bucket from
/// the fingerprint the sweep names.
///
/// The hints are issued before the selection hold ends, so they sit between
/// the pool gate's exchange and the shard gate's exchange. On a core whose
/// locked instructions wait for older software prefetches, such as AMD Zen
/// 4, the shard gate's exchange waits for them, and each of
/// these lines would otherwise miss behind a later locked instruction, in
/// the retirement's hold, one wait apiece; requested here, the one wait
/// covers them together with the bucket the commit's walk reads first.
#[inline(always)]
fn prefetch_after_choice(tables: &Tables<'_>, live: &Pool, slot: usize) {
    prefetch_retirement_lines(tables, live, slot);
    let (prev, next) = (live.records()[slot].prev(), tables.policy_next[slot]);
    hint(std::ptr::from_ref(&tables.policy_next[slot]).cast());
    if prev != POLICY_NONE {
        hint(std::ptr::from_ref(&tables.policy_next[prev as usize]).cast());
    }
    if next != POLICY_NONE {
        hint(std::ptr::from_ref(&live.records()[next as usize]).cast());
    }
}

/// Whether `current`'s state is `Resident`.
#[inline(always)]
fn is_resident(current: u64) -> bool {
    current & STATE == SlotState::Resident.bits()
}

/// 1 when the scan stops at `record`, else 0: a resident whose word is
/// flagged, malformed or not anchored only, or whose deadline `sample` has
/// reached; or a word whose state encoding is past `Quarantined`, which the
/// stop then fails closed on. Every term is evaluated, so the decision has
/// no branch.
#[inline(always)]
fn stop_bit(record: &Record, sample: u64) -> u32 {
    let current = record.ident.load(Ordering::Relaxed);
    let other = (current & (ABANDONED | RESERVED) != 0)
        | (word::refs(current) != 1)
        | expired(sample, record.expires_at_s());
    let malformed = current & STATE > SlotState::Quarantined.bits();
    u32::from((is_resident(current) & other) | malformed)
}

/// Slots one scan block decides together.
const BLOCK: usize = 8;

/// The walk tests slots one at a time while at most `1 / DENSE_SLACK` of
/// them are not resident.
const DENSE_SLACK: usize = 32;

/// The walk also tests slots one at a time while at most `1 / SPARSE_SLACK`
/// of them are resident.
const SPARSE_SLACK: usize = 16;

#[inline(never)]
fn first_stop(records: &[Record], predictable: bool, sample: u64) -> Option<usize> {
    if predictable {
        records
            .iter()
            .position(|record| stop_bit(record, sample) != 0)
    } else {
        blocks_stop(records, sample)
    }
}

/// The first of the stretch's slots the scan cannot pass: a resident that is flagged, not anchored only or expired. Each
/// block of [`BLOCK`] slots is decided into one mask with every term
/// evaluated, so the scan branches once per block however states
/// interleave. A malformed word stops the scan too, so the step's decode of
/// that slot panics.
#[inline(always)]
fn blocks_stop(records: &[Record], sample: u64) -> Option<usize> {
    let stops = |record: &Record| stop_bit(record, sample);
    let (blocks, tail) = records.as_chunks::<BLOCK>();
    for (at, block) in blocks.iter().enumerate() {
        let mut mask = 0u32;
        for (j, record) in block.iter().enumerate() {
            mask |= stops(record) << j;
        }
        if mask != 0 {
            return Some(at * BLOCK + mask.trailing_zeros() as usize);
        }
    }
    let mask = tail
        .iter()
        .enumerate()
        .fold(0u32, |mask, (j, record)| mask | stops(record) << j);
    (mask != 0).then(|| blocks.len() * BLOCK + mask.trailing_zeros() as usize)
}

/// Detaches the parked retirement `retention` sighted on `slot`, and
/// returns whether this sighting detached it: the walk meets it again on
/// every pass, and only the first sighting detaches.
#[cold]
#[inline(never)]
fn detach(tables: &mut Tables<'_>, slot: usize) -> bool {
    let detached = tables.queue().detach(slot);
    if detached {
        probe::event(Event::Detached { slot });
    }
    detached
}
