//! Ending a mapping's visibility under the shard gate: exact removal of one
//! identity, and invalidation of a key's fingerprint, with overflow bucket
//! recycling and the retirement obligation each ended mapping produces.
//!
//! Removal clears exactly the pair naming the identity found in the bounded
//! chain. A bucket's held pairs are its occupied and pending pairs. When
//! the cleared pair was the last held one of an overflow bucket, the bucket
//! is unlinked by the predecessor the same walk recorded and pushed to the
//! shard's free stack; a bucket that still holds a pending pair stays
//! linked. A cancel that frees an overflow bucket's last held pair leaves
//! the bucket linked and empty, and publications into the chain fill its
//! free pairs as they fill any linked bucket's. Every other pair, bucket
//! and chain keeps its contents and position. Removal restores the entry
//! credit only: `V` falls by one and the object's payload, record and slot
//! charges stay until the return path discharges them.
//!
//! In a terminal shard the stores happen without a sequence bracket, behind
//! a release fence of their own, and a shard whose next commit would exhaust
//! the sequence becomes terminal first. The store that moves the sequence to
//! its terminal value plays the fenced odd store's role: it is `SeqCst`,
//! every bare `Relaxed` store follows it, the terminal value is final and never
//! repeats, and a reader anchors only on a non-terminal even value, so a
//! reader still scanning when the shard turns terminal either copied nothing
//! a bare store wrote and holds a coherent pre-transition state, or acquired
//! a bare store's value, after which its second sequence load reads the
//! terminal value and rejects the copy. The sequence module states the
//! argument.
//!
//! Every ended mapping yields one retirement obligation, carried out of the
//! gate hold by a guard so an unwind cannot lose it and recorded once the
//! gate is released, through the same path a resident authority's retirement
//! takes: the era is bumped once and stamped on the slot, then the slot
//! moves to retired or the obligation is parked on its pre-reserved record,
//! with the anchor marked as awaiting grace. Removal never releases the anchor,
//! retires storage or refunds payload itself. Of the reuse invariant's
//! conjuncts, removal supplies invisibility only: no snapshot taken after the
//! commit copies the identity. That the last reader who copied it has left
//! its pinned interval is grace certification's conjunct, and that the block
//! returns only afterwards is the return path's.
//!
//! Invalidation is the public form, and it is joint: under one gate hold it
//! walks the chain for the resident whose fingerprint equals the key's and
//! scans the shard's fill table for the key's current attempt, then, in a
//! serving shard, commits one sequence step either way. The odd store is
//! the inhibition; the admission cutoff is read once inside it, and only
//! then are the pair cleared, the bucket recycled, the attempt's claimed
//! index place refunded and its association revoked, all before the even
//! store. The committed value is
//! the revocation ordering point, totally ordered against the shard's
//! publications by the gate. A resident alone is
//! removed, an attempt alone is revoked, both together are ended atomically,
//! and neither, or a repeat with no intervening work, reports both absent,
//! still commits its own ordering point, and records no second retirement.
//! Revocation clears the
//! association and refunds the attempt's index place: the attempt's owner
//! stays charged with its record and its lease credit until it departs and
//! service frees the record, and a same-key attempt begun after the
//! revocation takes another record. Existing leases are untouched.
//!
//! The fingerprint is the object's identity in RAM. Publication keeps at
//! most one visible object per fingerprint in a chain, displacing an equal
//! one, so the one match the walk removes is every match: an invalidation
//! leaves no visible object with the key's fingerprint. That object may have
//! been published under a different key with an equal fingerprint, and the
//! invalidation removes it all the same. The fill-table search compares the
//! full key, so it revokes only the key's own attempt.
//!
//! In a terminal shard the value is the terminal one, a shared bound greater
//! than every publication the shard ever committed, and the cutoff is read
//! under the hold after the terminal store; a shard whose commit would
//! exhaust the sequence becomes terminal first, so a near-terminal
//! invalidation writes the terminal value before it reads the cutoff.
//! Exhausted gate attempts and an exhausted budget refuse before the
//! inhibition: no mapping, sequence, association or count changes, only the
//! budget and the failed-try telemetry, and the refusal is never an
//! acknowledgement. A cutoff read closed inside the inhibition is the late
//! `Closed`: the mapping and the association stay, a serving shard still
//! commits the fresh even, and nothing is acknowledged. A found pair's suffix
//! record, appended after the cutoff read and before any store, is the other
//! late decision: its refusal is `History`, with the same effects as the late
//! `Closed`. Exact removal stays
//! permitted after close, as the cleanup it is, and reads no cutoff.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering, fence};

use super::allocation::RetireOutcome;
use super::attempt::{Associations, scan};
use super::budget::{WorkBudget, WorkKind};
use super::capture::PoisonOnUnwind;
use super::fill::{self, FillSerial};
use super::gate::GateGuard;
use super::os::Platform;
use super::owner::{Pool, Storage};
use super::place_claim::{self, Claimed};
use super::probe::{self, Event};
use super::publish::{
    Found, Place, Refusal, Retirement, Tables, fail_closed, find, fingerprint_matches, take_gate,
    terminate_if_exhausting,
};
use super::recovery::delta::Cause;
use super::shards::{Hold, ShardImage};
use crate::index::{
    BucketView, Busy, Key, KeyRoute, OverflowLink, Prefetch, RouteError, ShardIndex, TERMINAL,
    Unstable, control_without, held_pairs, read_stable,
};
use crate::storage::AllocationId;

/// Why an identity was not removed. No mapping or count changed, and only
/// `History` moves the sequence, by one empty step in a serving shard; a
/// failed gate try counts in the telemetry, and `Corrupt` poisons the gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RemoveError {
    /// No live index: none was configured, or the owner is drained.
    NoIndex,
    /// The budget could not pay for the hash pass, the gate try, a visit or
    /// a comparison.
    BudgetExhausted,
    /// Every paid gate attempt found the shard busy, the attempt allowance
    /// was zero, or no shard is enabled.
    Contended,
    /// A gate attempt found the shard's gate poisoned; no later attempt can
    /// take it.
    Poisoned,
    /// No tag-matching pair in the key's chain names the identity.
    /// Only the exact removal that takes the gate itself reports it; one
    /// under a caller's hold poisons the gate instead.
    Absent,
    /// The shard's fill table associates a current, undeparted attempt with
    /// a key of the pair's fingerprint: the incumbent's replacement can
    /// still publish, so the removal that refuses replacing keys changed
    /// nothing, the attempt included.
    Replacing,
    /// The shard's tables are malformed; the gate is poisoned.
    Corrupt,
    /// The tenure's suffix refused the removal's record: its log is full, stalled, past its certified bound, at
    /// its reserved end or closed, or no clock sample was available. No mapping ended and a serving shard committed
    /// an empty step; the entry stays live until the suffix advances.
    History,
}

/// Why a key was not invalidated. No mapping, association or count
/// changed; a failed gate try counts in the telemetry, `Corrupt` poisons the
/// gate, only the late `Closed` and `History` move the sequence, each by one
/// empty step in a serving shard, and the call is not an acknowledgement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidateError {
    Withdrawn,
    /// No live index: none was configured, or the owner is drained.
    NoIndex,
    /// Admission is closed. Read before the gate, nothing changed; read
    /// inside the inhibition, a serving shard committed a fresh even value,
    /// a terminal shard kept the terminal one, and no mapping and no
    /// association ended.
    Closed,
    /// The budget could not pay for the hash pass, the gate try, a visit or
    /// a comparison.
    BudgetExhausted,
    /// Every paid gate attempt found the shard busy or poisoned, the attempt
    /// allowance was zero, or no shard is enabled; the owner's
    /// `invalidate_interval` also refuses `Contended` while its held pairs are
    /// full, or while readiness reads `Detached` or `Loading` and a bootstrap
    /// may still restore the key.
    Contended,
    /// The shard's tables are malformed; the gate is poisoned.
    Corrupt,
    /// The tenure's suffix refused the invalidation's record, or no clock sample was available. No mapping or
    /// association ended and nothing is acknowledged; a serving shard committed an empty step.
    History,
}

/// An acknowledged invalidation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Invalidation {
    /// The shard sequence value the invalidation committed: the revocation
    /// ordering point. A publication of the key committed later carries a
    /// greater value. In a terminal shard the terminal value, greater than
    /// every publication the shard ever committed and shared by every
    /// invalidation there.
    pub sequence: u64,
    /// The identity whose mapping ended, with its retirement record's
    /// outcome; `None` for an absent key.
    pub removed: Option<(AllocationId, RetireOutcome)>,
    /// The serial of the attempt whose association was revoked; `None` when
    /// the shard associated no record with the key. The record stays
    /// occupied until its owner departs and service frees it.
    pub revoked: Option<u64>,
}

/// How one gate hold ended without ending a mapping: the shared refusals,
/// no index at all, or the invalidation's cutoff read closed inside its
/// inhibition, after which the sequence moved in a serving shard and
/// nothing else did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ending {
    NoIndex,
    Refused(Refusal),
    Closed,
    /// An exact removal that refuses replacing keys found a current,
    /// undeparted attempt of the pair's fingerprint associated: nothing
    /// changed.
    Replacing,
    /// The suffix refused the removal's record: like `Closed`, the bracket committed with nothing else stored.
    History,
}

impl From<Refusal> for Ending {
    fn from(refusal: Refusal) -> Self {
        Self::Refused(refusal)
    }
}

impl From<RouteError> for Ending {
    fn from(error: RouteError) -> Self {
        match error {
            RouteError::BudgetExhausted => Self::Refused(Refusal::BudgetExhausted),
            // No enabled shard: no key is visible, so nothing can be found.
            RouteError::NoEnabledShard => Self::Refused(Refusal::Contended),
        }
    }
}

impl From<Ending> for RemoveError {
    fn from(ending: Ending) -> Self {
        match ending {
            Ending::NoIndex => Self::NoIndex,
            Ending::Refused(Refusal::BudgetExhausted) => Self::BudgetExhausted,
            Ending::Refused(Refusal::Contended) => Self::Contended,
            Ending::Refused(Refusal::Poisoned) => Self::Poisoned,
            Ending::Refused(Refusal::Corrupt) => Self::Corrupt,
            // Exact removal reads no cutoff; only an invalidation's hold ends
            // this way.
            Ending::Closed => unreachable!("exact removal reads no cutoff"),
            Ending::Replacing => Self::Replacing,
            Ending::History => Self::History,
        }
    }
}

impl From<Ending> for InvalidateError {
    fn from(ending: Ending) -> Self {
        match ending {
            Ending::NoIndex => Self::NoIndex,
            Ending::Refused(Refusal::BudgetExhausted) => Self::BudgetExhausted,
            Ending::Refused(Refusal::Contended | Refusal::Poisoned) => Self::Contended,
            Ending::Refused(Refusal::Corrupt) => Self::Corrupt,
            Ending::Closed => Self::Closed,
            Ending::Replacing => unreachable!("an invalidation never refuses replacing keys"),
            Ending::History => Self::History,
        }
    }
}

/// Whether a hold that found no pair still commits a sequence step, and
/// whether it also searches the fill table and reads the cutoff.
#[derive(Clone, Copy)]
enum Step<'k> {
    /// Only an ended mapping moves the sequence. With `refuse`, a found
    /// pair whose fingerprint the shard's fill table associates with a
    /// current, undeparted attempt is left in place and the hold ends with
    /// [`Ending::Replacing`]; the table is only read.
    OnlyIfFound { refuse: bool },
    /// The step commits either way: the ordering point of an invalidation
    /// of `key`, whose current attempt the hold also revokes.
    Always { key: &'k Key },
    /// The pair must be found: the caller read it under this same hold, so
    /// a walk that misses it found a malformed table, and the hold fails
    /// closed.
    Required,
}

impl Step<'_> {
    /// The cause the suffix records for a removal under this step: an invalidation's, an eviction's (which refuses
    /// a replacing key), an expiry's (whose incumbent can never serve, so it refuses none); `None` for the close's
    /// drain, which ends a mapping without excluding its entry from the recoverable set.
    fn cause(self) -> Option<Cause> {
        match self {
            Self::Always { .. } => Some(Cause::Invalidate),
            Self::OnlyIfFound { refuse: true } => Some(Cause::Evict),
            Self::OnlyIfFound { refuse: false } => Some(Cause::Expire),
            Self::Required => None,
        }
    }
}

/// What one gate hold ended.
struct Ended<'s, P: Platform> {
    /// The committed sequence value, or the terminal one.
    sequence: u64,
    /// The obligation of the identity whose mapping ended, if one was found.
    retirement: Option<Retirement<'s, P>>,
    /// The serial of the attempt whose association was revoked.
    revoked: Option<FillSerial>,
}

impl<P: Platform> Storage<P> {
    /// Removes the exact mapping to `id` if a tag-matching pair in the chain
    /// `fingerprint` routes to resolves to it, slot and full
    /// incarnation, making at
    /// most `tries` gate attempts and charging as publication does. On
    /// success the caller receives the identity's retirement obligation and
    /// records it; service releases the anchor after
    /// grace. `id` may be stale or unmatched: only equality with the
    /// allocation an occupied pair resolves to establishes that it is
    /// anchored, so a stale or reused identity is `Absent`, one whose
    /// incarnation shares the pair's low 16 bits included. Permitted after
    /// close and in a terminal shard. The close service removes under the
    /// hold that found the pair, through [`remove_held`](Self::remove_held);
    /// this form takes the gate itself; eviction and expiry use it, with the
    /// fingerprint word copied under the pool gate for `id`, so the key is
    /// not hashed again.
    ///
    /// With `refuse_replacing`, the hold that found the pair first scans the
    /// shard's fill table, read-only, and a current attempt whose key has
    /// `fingerprint` and whose owner has not departed refuses the removal as
    /// `Replacing`: an incumbent is never removed while its replacement's
    /// attempt can still publish. The attempt is
    /// never revoked either way; only an invalidation revokes.
    ///
    /// # Errors
    ///
    /// [`RemoveError`]; no mapping changes on any of them, and a refusal
    /// mid-walk leaves the pair in place.
    pub(super) fn remove_exact(
        &self,
        fingerprint: u64,
        id: AllocationId,
        refuse_replacing: bool,
        tries: usize,
        budget: &mut WorkBudget,
    ) -> Result<Retirement<'_, P>, RemoveError> {
        let index = self.index().ok_or(Ending::NoIndex)?;
        // The walk reads the base bucket first and a found pair's clearing
        // stores into its bucket; the derivation prefetches both of its
        // lines for writing, as publication does.
        let route = index
            .hasher
            .reroute_prefetching(fingerprint, &index.geometry, budget, index.prefetch(true))
            .map_err(Ending::from)?;
        let ended = self.end_mapping(
            &route,
            tries,
            budget,
            Step::OnlyIfFound {
                refuse: refuse_replacing,
            },
            |candidate, budget| {
                budget.debit(WorkKind::Comparison)?;
                Ok(candidate == id)
            },
        );
        // Matched in place rather than moved through `?`: see `settle`.
        match ended {
            Ok(Ended {
                retirement: Some(retirement),
                ..
            }) => Ok(retirement),
            Ok(Ended {
                retirement: None, ..
            }) => Err(RemoveError::Absent),
            Err(ending) => Err(ending.into()),
        }
    }

    /// [`remove_exact`](Self::remove_exact) with no fill-table check, routed
    /// from `key`'s own fingerprint, for tests that drive exact removal
    /// alone.
    #[cfg(test)]
    pub(crate) fn remove(
        &self,
        key: &Key,
        id: AllocationId,
        tries: usize,
        budget: &mut WorkBudget,
    ) -> Result<RetireOutcome, RemoveError> {
        let fingerprint = self.route(key).map_or(0, |route| route.fingerprint());
        self.remove_exact(fingerprint, id, false, tries, budget)
            .map(Retirement::record)
    }

    /// [`remove_exact`](Self::remove_exact) without the fill-table check,
    /// under `guard`, the caller's hold on `shard`'s gate, which the route
    /// of `fingerprint`, the pair's own word copied under this hold, must
    /// name: the hash charge, the visits and the comparisons are charged as
    /// there and the gate attempt was the caller's. The caller read the pair
    /// `id` names under this hold, so the walk must find it again: a route
    /// naming another shard
    /// or a walk that misses the pair found a malformed table, and the gate
    /// is poisoned. The hold ends inside this call, before the retirement is
    /// recorded, whatever the outcome.
    ///
    /// # Errors
    ///
    /// [`RemoveError`]; no mapping changes on any of them. `Absent` is
    /// never returned.
    pub(crate) fn remove_held(
        &self,
        guard: GateGuard<'_>,
        shard: ShardIndex,
        fingerprint: u64,
        id: AllocationId,
        budget: &mut WorkBudget,
    ) -> Result<RetireOutcome, RemoveError> {
        let Some(index) = self.index() else {
            guard.release();
            return Err(RemoveError::NoIndex);
        };
        let route = match index.hasher.reroute_prefetching(
            fingerprint,
            &index.geometry,
            budget,
            Prefetch::NONE,
        ) {
            Ok(route) => route,
            Err(error) => {
                guard.release();
                return Err(Ending::from(error).into());
            }
        };
        let Some(image) = index.image.shard(shard).filter(|_| route.shard() == shard) else {
            fail_closed(guard);
            return Err(RemoveError::Corrupt);
        };
        // SAFETY: the index mapping is owned and initialized while the
        // storage is live, which `&self` guarantees; the caller's hold on
        // this shard's gate makes the stack reference the only one, and it
        // ends when `end_held` returns, before `settle` releases the gate.
        let (control, hold) =
            unsafe { (image.control(&index.mapping), image.hold(&index.mapping)) };
        let tables = Tables {
            shard: image,
            hold,
            control,
        };
        let ended = self.end_held(
            tables,
            &route,
            budget,
            Step::Required,
            |candidate, budget| {
                budget.debit(WorkKind::Comparison)?;
                Ok(candidate == id)
            },
        );
        settle(guard, &ended);
        match ended {
            Ok(Ended {
                retirement: Some(retirement),
                ..
            }) => Ok(retirement.record()),
            Ok(Ended {
                retirement: None, ..
            }) => unreachable!("a required step ends only with the pair found"),
            Err(ending) => Err(ending.into()),
        }
    }

    /// Removes the visibility of the object whose fingerprint equals `key`'s,
    /// if one is present, and revokes `key`'s current attempt, and in a
    /// serving shard commits one sequence step either way, making at most
    /// `tries` gate attempts and charging as publication does. The removed
    /// object may have been published under a different key with an equal
    /// fingerprint. The committed sequence value is the revocation ordering
    /// point. Permitted in a terminal shard, where the value is the terminal
    /// one.
    ///
    /// An [`Invalidation`] acknowledges RAM state of this process: one shard
    /// gate hold ended the fingerprint's mapping and revoked the key's current
    /// attempt. `removed: None` shows only that the current RAM mapping held
    /// no object with the fingerprint. The sequence value orders commits
    /// within this shard of this process; values from other shards or other
    /// storages are incomparable with it. In a terminal shard every
    /// invalidation returns the shared terminal value, which places them all
    /// after every publication the shard committed and leaves their mutual
    /// order unstated. A lease acquired before the
    /// invalidation keeps reading its version to its last terminal, and a new
    /// lookup obeys the current mapping. A volume read returns
    /// `HeaderMismatch::Key` when the record header's full key differs from
    /// the reader's, so an object found under an equal fingerprint exposes
    /// bytes only to its own key's readers (IDENTITY-BEFORE-BYTES).
    ///
    /// # Errors
    ///
    /// [`InvalidateError`]; no mapping changes on any of them, and none is an
    /// acknowledgement.
    pub fn invalidate(
        &self,
        key: &Key,
        tries: usize,
        budget: &mut WorkBudget,
    ) -> Result<Invalidation, InvalidateError> {
        if self.is_closed() {
            return Err(InvalidateError::Closed);
        }
        if self.readiness.authority_withdrawn() {
            return Err(InvalidateError::Withdrawn);
        }
        let index = self.index().ok_or(Ending::NoIndex)?;
        // As for `remove_exact`, from the key's own pass.
        let route = index
            .hasher
            .route_prefetching(key, &index.geometry, budget, index.prefetch(true))
            .map_err(Ending::from)?;
        // The key's placement window, hinted beside the bucket: the walk
        // compares the fingerprint of the resident's record, which lies in
        // the window unless the window was full at its claim, and the
        // retirement then stamps that record, so its miss overlaps the
        // bucket's instead of following it.
        if let Some(pool) = self.live_pool() {
            pool.prefetch_window(route.fingerprint());
        }
        let ended = self.end_mapping(
            &route,
            tries,
            budget,
            Step::Always { key },
            |candidate, budget| fingerprint_matches(self, candidate, route.fingerprint(), budget),
        );
        match ended {
            Ok(Ended {
                sequence,
                retirement,
                revoked,
                ..
            }) => Ok(Invalidation {
                sequence,
                removed: retirement.map(|retirement| (retirement.id(), retirement.record())),
                revoked: revoked.map(FillSerial::get),
            }),
            Err(ending) => Err(ending.into()),
        }
    }

    /// One gate hold over `route`'s shard: walks the chain for the pair
    /// `matches` accepts, clears it, recycles its bucket if emptied, and in a
    /// serving shard commits a sequence step as `step` says; a terminal shard
    /// has no bracket and reports the terminal value.
    fn end_mapping(
        &self,
        route: &KeyRoute,
        tries: usize,
        budget: &mut WorkBudget,
        step: Step<'_>,
        matches: impl FnMut(AllocationId, &mut WorkBudget) -> Result<bool, Refusal>,
    ) -> Result<Ended<'_, P>, Ending> {
        let index = self.index().ok_or(Ending::NoIndex)?;
        let shard = index.image.shard(route.shard()).ok_or(Refusal::Contended)?;
        // SAFETY: the index mapping is owned and initialized while the
        // storage is live, which `&self` guarantees.
        let (gate, control) =
            unsafe { (shard.gate(&index.mapping), shard.control(&index.mapping)) };
        // `settle` ends every hold that returns, so the guard's drop is a
        // panic of `end_held`, also in a removal made by a thread that was
        // already unwinding.
        let guard = take_gate(gate, control, tries, budget)?.poison_on_unwind();
        // SAFETY: as above; the gate hold makes the stack reference the only
        // one, and it ends when `end_held` returns, before `settle` releases
        // the gate.
        let hold = unsafe { shard.hold(&index.mapping) };
        let tables = Tables {
            shard,
            hold,
            control,
        };
        let ended = self.end_held(tables, route, budget, step, matches);
        settle(guard, &ended);
        ended
    }

    /// The body of [`end_mapping`](Self::end_mapping) under the caller's
    /// hold on the gate of `tables`' shard, which `route` names. The caller
    /// ends the hold through [`settle`] after this returns, so the gate
    /// guards `tables`' references for the whole call.
    ///
    /// Always inlined: the `matches` closure's type gives each instance one
    /// caller, so nothing is duplicated, and the result stays in registers.
    /// Returned through memory, the caller's wide loads of it straddle this
    /// function's narrower stores and stall on store forwarding.
    #[inline(always)]
    fn end_held(
        &self,
        tables: Tables<'_>,
        route: &KeyRoute,
        budget: &mut WorkBudget,
        step: Step<'_>,
        matches: impl FnMut(AllocationId, &mut WorkBudget) -> Result<bool, Refusal>,
    ) -> Result<Ended<'_, P>, Ending> {
        let found =
            find(self, tables.shard, &tables.hold, route, budget, matches).and_then(|found| {
                match found {
                    None if matches!(step, Step::Required) => Err(Refusal::Corrupt),
                    found => Ok(found),
                }
            });
        if let Ok(Some(found)) = &found {
            // Prefetching the slot lets cache-line fetches for membership removal, retirement, and slot return overlap the commit.
            self.pool().prefetch_slot(found.id.slot().0);
            self.pool().prefetch_retirement(found.id.slot().0);
        }
        let ended = match found {
            Ok(found) => {
                // An invalidation also finds the key's attempt to revoke; a
                // pair found for a removal that refuses replacing keys is
                // cleared only when no current, undeparted attempt is
                // associated with its fingerprint.
                let joint = match (step, &found) {
                    // SAFETY: the caller holds `route.shard()`'s gate for
                    // this whole call.
                    (Step::Always { key }, _) => unsafe { self.joint(route, key, budget) }
                        .map(Some)
                        .map_err(Ending::from),
                    (Step::OnlyIfFound { refuse: true }, Some(_)) => {
                        // SAFETY: as above.
                        match unsafe { self.associated(route, budget) } {
                            Ok(true) => Err(Ending::Replacing),
                            Ok(false) => Ok(None),
                            Err(refusal) => Err(Ending::from(refusal)),
                        }
                    }
                    _ => Ok(None),
                };
                match joint {
                    Ok(joint) => clear_member(
                        (self.pool(), || self.platform.now_ticks()),
                        tables,
                        found,
                        step,
                        joint,
                        budget,
                    ),
                    Err(ending) => Err(ending),
                }
            }
            Err(refusal) => Err(Ending::from(refusal)),
        };
        match ended {
            Ok(cleared) => Ok(Ended {
                sequence: cleared.sequence,
                retirement: cleared.removed.map(|id| Retirement::new(self, id)),
                revoked: cleared.revoked,
            }),
            Err(ending) => Err(ending),
        }
    }

    /// The invalidation's second search under the hold: the record holding
    /// `key`'s current attempt, compared by `route`'s fingerprint and then
    /// the full key, if the shard has a fill table and one is
    /// associated, and the cutoff the commit reads inside its inhibition.
    /// Always inlined into its one caller, so the result stays in registers.
    ///
    /// # Safety
    ///
    /// The caller holds `route.shard()`'s gate for the whole call: the scan
    /// forms the keys' and the fingerprints' `&mut`, which the gate makes
    /// the only references into them.
    #[inline(always)]
    unsafe fn joint(
        &self,
        route: &KeyRoute,
        key: &Key,
        budget: &mut WorkBudget,
    ) -> Result<Joint<'_>, Refusal> {
        let association = match self.fill_table(route.shard()) {
            Some(table) => {
                // SAFETY: the storage is live, `fill_table` gave one of its
                // tables, and the caller's gate hold is `fill_hold`'s.
                let hold = unsafe { self.fill_hold(table) };
                scan(
                    &hold,
                    route.fingerprint(),
                    Some(key),
                    Associations::Any,
                    budget,
                )?
                .association
                .map(|(record, serial)| {
                    let owner = AllocationId::of_record_tag(hold.view.rows[record].allocation());
                    (
                        &hold.view.states[record],
                        serial,
                        &mut hold.places[record],
                        owner,
                    )
                })
            }
            None => None,
        };
        Ok(Joint {
            association,
            cutoff: self.closed(),
        })
    }

    /// Whether `route.shard()`'s fill table associates a current attempt
    /// whose owner has not departed with a key of `route`'s fingerprint: one
    /// charged scan of the table, which reads and changes nothing else. A
    /// departed attempt can no longer publish, so a record that service has
    /// not yet freed, or that a follower keeps occupied, refuses nothing.
    /// The match is by fingerprint alone: a current attempt of a different
    /// key with an equal fingerprint also refuses the eviction as
    /// `Replacing`, and the victim stays resident until that attempt
    /// departs or is revoked.
    ///
    /// # Safety
    ///
    /// As for [`joint`](Self::joint).
    #[inline(always)]
    unsafe fn associated(
        &self,
        route: &KeyRoute,
        budget: &mut WorkBudget,
    ) -> Result<bool, Refusal> {
        let Some(table) = self.fill_table(route.shard()) else {
            return Ok(false);
        };
        // SAFETY: as for `joint`.
        let hold = unsafe { self.fill_hold(table) };
        Ok(
            scan(&hold, route.fingerprint(), None, Associations::Live, budget)?
                .association
                .is_some(),
        )
    }
}

#[cfg(test)]
thread_local! {
    /// Runs once inside an invalidation's inhibition, before its cutoff
    /// read, so a test can close admission where only that read can catch
    /// it.
    pub(super) static INTERPOSE_BEFORE_CUTOFF: std::cell::Cell<Option<fn(&AtomicBool)>> =
        const { std::cell::Cell::new(None) };
}

/// What an invalidation prepared before its inhibition.
struct Joint<'s> {
    /// The state word of the key's current attempt, its serial, and its
    /// place word, whose place the revocation refunds.
    /// The fourth field is the allocation the attempt reserved.
    association: Option<(&'s AtomicU64, FillSerial, &'s mut u64, AllocationId)>,
    /// The admission cutoff, read once inside the inhibition.
    cutoff: &'s AtomicBool,
}

/// What one commit did.
struct Cleared {
    /// The committed or terminal sequence value.
    sequence: u64,
    removed: Option<AllocationId>,
    revoked: Option<FillSerial>,
}

/// Ends the gate hold an [`end_held`](Storage::end_held) call ran under,
/// once that call has returned: a malformed table poisons the gate, and
/// every other outcome releases it. The hold's references, the `Tables`
/// argument `end_held` received, end with that call, before the release
/// lets the next holder form its own. The outcome is borrowed, and the
/// callers match it in place: moved by value, through this function or
/// through `?`, it was copied through memory with loads that straddled the
/// narrower stores that wrote it and waited for them to retire.
#[inline(always)]
fn settle<P: Platform>(guard: GateGuard<'_>, ended: &Result<Ended<'_, P>, Ending>) {
    match ended {
        Err(Ending::Refused(Refusal::Corrupt)) => {
            fail_closed(guard);
        }
        _ => guard.release(),
    }
}

/// Runs [`clear`] under capture serialization when `found` names a member. The caller holds the shard gate while `clear_member` tries the pool gate if capture needs the member's entry or a required suffix its identity; a hold taken for the identity alone ends before the clear. With the suffix required, the removal's REMOVE record is appended at a sample of `now` inside the bracket, after every check and before any store, so a refused append, `History`, removes nothing (REFUSE-BEFORE-ACK).
#[inline(always)]
fn clear_member(
    (pool, now): (&Pool, impl FnOnce() -> Option<u64>),
    tables: Tables<'_>,
    found: Option<Found>,
    step: Step<'_>,
    joint: Option<Joint<'_>>,
    budget: &mut WorkBudget,
) -> Result<Cleared, Ending> {
    let Some(id) = found.as_ref().map(|f| f.id) else {
        return clear(tables, found, step, joint, budget, || Ok(()));
    };
    let slot = id.slot_index();
    let mut capture = pool.capture_membership_lock().map_err(Refusal::from)?;
    let saving = capture.needs_save(pool.capture_step(&capture, slot), slot);
    let cause = step.cause().filter(|_| capture.suffix.required());
    let mut access = ((saving || cause.is_some())
        .then(|| pool.try_lock_quiet())
        .transpose())
    .map_err(Refusal::from)?;
    let removal = cause
        .zip(access.as_mut())
        .map(|(cause, access)| (pool.capture_identity(&access.tables(), id), cause));
    // The mapping names the member under the shard gate, so its identity stays fixed after the pool hold ends.
    if !saving {
        access = None;
    }
    let recorded = removal.is_some();
    let cleared = clear(tables, found, step, joint, budget, || {
        let Some((identity, cause)) = &removal else {
            return Ok(());
        };
        let Some(now) = now() else {
            return Err(Ending::History);
        };
        (pool.capture_record(&mut capture, now, Some((identity, *cause)), None))
            .map_err(|_| Ending::History)
    })?;
    if let Some(id) = cleared.removed {
        match access {
            Some(access) => {
                // A panic in the entry copy leaves the mapping ended and the member's step word set. The copy's return ends the pool hold through `release`, so from here the hold's drop is that panic: it poisons the gate, and the walk guard the capture, also when a thread that was already unwinding took them.
                let mut access = access.poison_on_unwind();
                let walk = PoisonOnUnwind(&mut capture);
                pool.capture_remove(&mut access.tables(), walk.0, id.slot_index(), recorded);
                walk.returned();
                access.release();
            }
            None => pool.capture_unpublish(&mut capture, id.slot_index(), recorded),
        }
    }
    Ok(cleared)
}

/// Whether the chain behind emptied overflow bucket `overflow`, from its
/// link `carried`, may pass to the predecessor. The walk reached `overflow`
/// after `followed` links and stopped at the found pair, so this is the only
/// check of the rest: it must end within the `hold.depth - followed` links
/// the depth bound leaves, each below the overflow count and none naming
/// `overflow`. The unlink shortens the chain by one link, so a chain one
/// link past the bound would become one every reader accepts; a chain that
/// returned to the emptied bucket would link it from the predecessor once it
/// is on the free stack.
/// Each bucket read debits one visit from `budget` first.
#[inline(always)]
fn carried_chain_holds(
    shard: &ShardImage,
    hold: &Hold<'_>,
    (overflow, followed): (usize, usize),
    carried: usize,
    budget: &mut WorkBudget,
) -> Result<bool, Refusal> {
    let mut link = carried;
    for _ in 0..hold.depth.saturating_sub(followed) {
        match OverflowLink::decode(link) {
            None => return Ok(true),
            Some(next) if next < shard.geometry.overflow && next != overflow => {
                budget.debit(WorkKind::Visit)?;
                match hold.buckets.get(shard.geometry.base + next) {
                    Some(record) => link = record.next(),
                    None => return Ok(false),
                }
            }
            Some(_) => return Ok(false),
        }
    }
    Ok(OverflowLink::decode(link).is_none())
}

/// The commit of one ended mapping, or of an empty step: clears the found
/// pair, unlinks and recycles its overflow bucket when it emptied, lowers
/// `V`, revokes the attempt `joint` names, and moves the sequence. In a
/// terminal shard the stores happen without a bracket. Without a found pair
/// and with `Step::OnlyIfFound` nothing changes; `Step::Required` never
/// arrives without one. Every check precedes the bracket except two late
/// decisions inside it: the invalidation's cutoff read, and then, for a found
/// pair, `append`, the suffix record, before any mapping or revocation store.
/// A closed cutoff ends the hold with [`Ending::Closed`], a refused append
/// with its error, [`Ending::History`] for a suffix refusal; either commits
/// the bracket with nothing else stored. Otherwise returns the committed or
/// terminal sequence value and what ended.
///
/// `lost_capacity` is `N - V` for the `V` a shard keeps at its terminal
/// transition. Both late refusals keep the found resident, so a transition
/// made in the same call is recorded with the resident counted.
///
/// Inlined into the one hold that calls it, so the result stays in
/// registers: returned through memory, the caller copied the tagged result
/// with loads that straddled the callee's narrower stores and waited for
/// them to retire.
#[inline(always)]
fn clear(
    tables: Tables<'_>,
    found: Option<Found>,
    step: Step<'_>,
    joint: Option<Joint<'_>>,
    budget: &mut WorkBudget,
    append: impl FnOnce() -> Result<(), Ending>,
) -> Result<Cleared, Ending> {
    let Tables {
        shard,
        hold,
        control,
    } = tables;
    let visible = control.visible.load(Ordering::Relaxed);
    let stable = match read_stable(&control.sequence) {
        // A busy value under an open gate is corruption.
        Err(Unstable::Busy) => return Err(Refusal::Corrupt.into()),
        Err(Unstable::Terminal) => None,
        Ok(stable) => Some(stable),
    };
    // What the found pair's removal does to its bucket and the counters,
    // decided and checked before the sequence moves.
    let top = control.free_top.load(Ordering::Relaxed);
    let (after, recycle) = match found {
        Some(found) => {
            let after = visible.checked_sub(1).ok_or(Refusal::Corrupt)?;
            let recycle = match found.place {
                Place {
                    bucket,
                    pair,
                    control: word,
                    prev: Some(prev),
                } if held_pairs(control_without(word, pair)) == 0 => {
                    // The chain the predecessor takes over was not followed
                    // by the walk, so it is checked here.
                    let overflow = bucket - shard.geometry.base;
                    let carried = hold.buckets[bucket].next();
                    if !carried_chain_holds(
                        shard,
                        &hold,
                        (overflow, found.followed),
                        carried,
                        budget,
                    )? || top >= hold.stack.len()
                    {
                        return Err(Refusal::Corrupt.into());
                    }
                    Some((prev, overflow, carried))
                }
                _ => None,
            };
            (after, recycle)
        }
        None => (visible, None),
    };
    // The revoked attempt's place, checked here so its refund inside the
    // bracket cannot fail.
    if let Some(Joint {
        association: Some((_, _, place, owner)),
        ..
    }) = &joint
        && let Some(claimed) = Claimed::of(**place)
        && place_claim::check(&hold, control, claimed, *owner).is_none()
    {
        return Err(Refusal::Corrupt.into());
    }
    let nothing = Cleared {
        sequence: 0,
        removed: None,
        revoked: None,
    };
    let sequence = match stable {
        None => None,
        Some(stable) if found.is_none() && !matches!(step, Step::Always { .. }) => {
            return Ok(Cleared {
                sequence: stable,
                ..nothing
            });
        }
        Some(stable) => (!terminate_if_exhausting(control, shard, stable, after)).then_some(stable),
    };
    let busy = sequence.map(|stable| Busy::begin(&control.sequence, stable));
    if busy.is_none() {
        // A terminal shard's bare stores get the fence a bracket issues after
        // its odd store: the terminal store fenced in its own hold, and a
        // reader that acquires one of these stores needs a fence in this
        // thread to be ordered after that store. The sequence module states
        // the argument.
        fence(Ordering::Release);
    }
    if joint.is_some() {
        probe::event(Event::Inhibit {
            sequence: sequence.map_or(TERMINAL, |stable| stable + 1),
        });
    }
    // The invalidation's open witness: read after the odd or terminal store,
    // so a close ordered before this read leaves the mapping and the
    // association in place, and an open read places the inhibition before
    // the close; the admitted removal may still finish after a concurrent
    // close returns, as every admitted mutation may.
    #[cfg(test)]
    if let Some(joint) = &joint
        && let Ok(Some(interpose)) = INTERPOSE_BEFORE_CUTOFF.try_with(|hook| hook.take())
    {
        interpose(joint.cutoff);
    }
    // A hold that ends with nothing stored keeps the found resident, so a transition made in this call counts it.
    let keep = |busy: Option<Busy<_>>| {
        if stable.is_some() && sequence.is_none() {
            control
                .lost_capacity
                .store(shard.geometry.visible - visible, Ordering::Relaxed);
        }
        let sequence = busy.map_or(TERMINAL, Busy::commit);
        probe::event(Event::Committed { sequence });
    };
    if let Some(joint) = &joint {
        let closed = joint.cutoff.load(Ordering::SeqCst);
        probe::event(Event::Cutoff { closed });
        if closed {
            keep(busy);
            return Err(Ending::Closed);
        }
    }
    // The suffix's record of the removal, appended once nothing can refuse the stores below.
    if found.is_some()
        && let Err(refused) = append()
    {
        keep(busy);
        return Err(refused);
    }
    if let Some(found) = found {
        let record = &hold.buckets[found.place.bucket];
        record.clear_pair(found.place.pair, found.place.control);
        if let Some((prev, overflow, carried)) = recycle {
            // The emptied overflow bucket: the predecessor takes its link, it
            // forgets its own, and it returns to the stack.
            hold.buckets[prev].link(OverflowLink::from_raw(carried));
            record.link(OverflowLink::NONE);
            hold.stack[top] = overflow;
            control.free_top.store(top + 1, Ordering::Relaxed);
        }
        control.visible.store(after, Ordering::Relaxed);
        probe::event(Event::Cleared {
            slot: found.id.slot_index(),
        });
    }
    let revoked = joint.and_then(|joint| {
        let (state, serial, place, _) = joint.association?;
        // Revocation makes the attempt's publication refuse, so its place is
        // refunded here; its owner keeps the credit until its end.
        place_claim::refund(&hold, control, place);
        fill::revoke(state);
        probe::event(Event::Revoked {
            serial: serial.get(),
        });
        Some(serial)
    });
    let sequence = busy.map_or(TERMINAL, Busy::commit);
    probe::event(Event::Committed { sequence });
    Ok(Cleared {
        sequence,
        removed: found.map(|found| found.id),
        revoked,
    })
}
