//! Snapshot read of one key's candidates: every tag-matching identity
//! copied into the reader's scratch under one stable shard sequence, or
//! `Ok(None)` when that sequence changed, was busy or was terminal.
//!
//! An attempt loads a stable even sequence, loads the base bucket's chain
//! summary and, unless the summary excludes the key's tag, scans the chain
//! into the registration's scratch, then requires the same sequence. A
//! summary that excludes the tag under an unchanged sequence is the stable,
//! complete copy of nothing: the summary holds a superset of the chain's
//! tags at every stable sequence, so the chain had no pair of the tag, and
//! no bucket line is read. A changed, busy
//! or terminal sequence consumes one attempt from `retries` and the next
//! attempt starts over; when the allowance is spent the result is
//! `Contended`. The snapshot is taken through the reader's pinned interval,
//! so the pin precedes the copy: a reader that copies an identity pinned an
//! era no greater than the era its later retirement is stamped with, which
//! is what the grace argument needs to hold the anchor for that reader. A
//! stable copy is coherent by the sequence module's argument; a stable,
//! complete scan that copied nothing proves the key absent at the identity
//! level, and so does a summary that excludes the tag under a stable
//! sequence. The reader validates the chains it scans: a scanned chain
//! that reads malformed under an unchanged sequence fails closed as
//! `Corrupt` before any identity is used, for exactly its prepaid scan
//! bound. A summary exclusion loads no bucket, so a malformed chain is
//! caught by the publisher's or remover's walk, which poisons the gate.
//! Read across a recycle, the links of two states
//! can exceed the depth bound, and that attempt is retried like any other
//! torn copy. Every attempt preflights the scan's whole bound before its
//! first sequence load and debits it after that load: one visit per bucket
//! the chain may visit, one comparison
//! per pair it may compare, and the two sequence validations, with no
//! refund when the scan finishes early or the attempt is torn; the scan
//! never performs more than the bound. Routing is paid first: a zero
//! budget hashes nothing and reads nothing, a zero retry allowance pays the
//! hash pass and then reads nothing, and an allowance short of one bound
//! reads nothing after the hash.
//!
//! The copied identities grant no access to an object: they are storage
//! identities whose validity a caller re-establishes, inside the same pinned
//! interval, before acting on one. Publication anchors an object for as long
//! as the index names it, and an ended mapping's anchor is released only
//! after every interval pinned at or below its retirement era has ended.
//!
//! [`Observation`] is the attempt itself, built once per call from the route
//! and the registration's scratch, and only from a pinned interval, so the
//! pin precedes every copy by construction. The snapshot loops over it; the
//! lookup loops over it too and, between attempts, validates and retains a
//! candidate, then asks the same observation whether the sequence it copied
//! under is still in place.

use std::sync::atomic::Ordering;

use super::budget::{WorkBudget, WorkKind};
use super::lease::Credit;
use super::os::Platform;
use super::owner::Storage;
use super::probe::{self, Primitive};
use super::register::Protected;
use super::shards::{ShardControl, Tables};
use super::tables::RetainCounters;
use crate::index::{
    Corrupt, HASH_CHARGE, Identity, Key, KeyRoute, PAIRS, RouteError, ScanWork, Unstable, excludes,
    read_stable, scan_chain, still,
};

/// Each attempt prepays bucket visits, pair comparisons and two sequence
/// validations: it preflights them before its first sequence load and
/// debits them after that load. The validations count as comparisons.
struct ScanBound {
    visits: usize,
    comparisons: usize,
}

impl ScanBound {
    /// Debits the whole bound from `budget`, which a preflight of the same
    /// bound has already covered.
    #[inline(always)]
    fn debit(&self, budget: &mut WorkBudget) {
        let paid = budget
            .debit_n(WorkKind::Visit, self.visits)
            .and_then(|()| budget.debit_n(WorkKind::Comparison, self.comparisons));
        debug_assert!(paid.is_ok(), "the preflight covered the scan bound");
    }
}

/// Why no snapshot was taken. The scratch contents are unspecified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SnapshotError {
    /// No index was configured.
    NoIndex,
    /// The budget could not pay for the hash pass or for one attempt's
    /// whole scan bound.
    BudgetExhausted,
    /// No shard is enabled, so no key has a home.
    NoEnabledShard,
    /// The chain is malformed. Nothing was copied for use.
    Corrupt,
}

impl From<RouteError> for SnapshotError {
    fn from(error: RouteError) -> Self {
        match error {
            RouteError::BudgetExhausted => Self::BudgetExhausted,
            RouteError::NoEnabledShard => Self::NoEnabledShard,
        }
    }
}

impl From<super::budget::BudgetExhausted> for SnapshotError {
    fn from(_: super::budget::BudgetExhausted) -> Self {
        Self::BudgetExhausted
    }
}

impl From<Corrupt> for SnapshotError {
    fn from(_: Corrupt) -> Self {
        Self::Corrupt
    }
}

/// One stable copy: the even sequence it was taken under and how many
/// identities it wrote to the front of the scratch. Opaque, so the only way
/// to ask whether the copy still stands is [`Observation::still`].
#[derive(Clone, Copy)]
pub(super) struct Stable {
    sequence: u64,
    copied: usize,
}

/// One key's route into its shard, with the shard's tables and the reader's
/// scratch: everything an attempt reads or writes, resolved and paid once.
/// `'p` is the pinned interval's exclusive borrow, which the storage borrow
/// outlives.
pub(super) struct Observation<'p> {
    control: &'p ShardControl,
    tables: Tables<'p>,
    scratch: &'p mut [Identity],
    /// The route's base bucket.
    bucket: usize,
    tag: u16,
    /// The key's fingerprint, which a candidate's record must carry.
    fingerprint: u64,
    /// The source of the credit an acquisition under this observation
    /// reserves: the reader's record for a lease, none for a volume read.
    credit: Credit,
    /// The pinned reader's record's counters of failed right reservations.
    retains: &'p RetainCounters,
}

impl<'p> Observation<'p> {
    /// Routes `key`, charging the hash pass, and resolves its shard and
    /// the pinned registration's scratch. The scratch lives in the mapping
    /// the registration borrows; the exclusive borrow of the interval makes
    /// its run ours alone for `'p`. When `route` is `Some` it must be `key`'s
    /// from [`KeyHasher::route_unpaid`](crate::index::KeyHasher::route_unpaid)
    /// against this index, and this method debits [`HASH_CHARGE`]; when it is
    /// `None`, [`KeyHasher::route`](crate::index::KeyHasher::route) checks
    /// for an enabled shard and otherwise debits the same charge before
    /// deriving the route, so the budget sees one derivation either way.
    /// An acquisition under the observation reserves its credit from
    /// `credit`.
    ///
    /// # Errors
    ///
    /// `NoIndex`, `BudgetExhausted` from the hash pass, or
    /// `NoEnabledShard`.
    #[inline(always)]
    pub(super) fn routed<'s, P: Platform>(
        protected: &'p mut Protected<'_, 's, P>,
        key: &Key,
        route: Option<KeyRoute>,
        credit: Credit,
        budget: &mut WorkBudget,
    ) -> Result<Self, SnapshotError> {
        let reader = protected.registration();
        let storage: &'s Storage<P> = reader.storage();
        let index = storage.index().ok_or(SnapshotError::NoIndex)?;
        let route = match route {
            Some(route) => {
                budget.debit_n(WorkKind::Hash, HASH_CHARGE)?;
                route
            }
            // The derivation prefetches the chain summary's line and the
            // base bucket's lines, shared, as soon as its passes finish; the
            // summary load and the scan's loads then find them on the way.
            None => {
                let route = index.hasher.route_prefetching(
                    key,
                    &index.geometry,
                    budget,
                    index.prefetch(false),
                )?;
                if let Some(pool) = storage.live_pool() {
                    pool.prefetch_window(route.fingerprint());
                }
                route
            }
        };
        // The run table lists the enabled shards in route order, so the
        // route's position names the run; a route over an enabled shard
        // always has one.
        let run = index
            .image
            .runs()
            .get(route.position())
            .ok_or(SnapshotError::NoEnabledShard)?;
        // SAFETY: the run is this image's and the index mapping is owned and
        // initialized while the storage is live, which the registration's
        // borrow guarantees; every shared field is an atomic.
        let (control, tables) = unsafe { index.image.reader_tables(&index.mapping, run) };
        // SAFETY: `reader.index()` is a position in the root image's
        // registration records, sized from the same `reader_limit` as the
        // scratch, so the run lies inside the field; the exclusive borrow of
        // the interval, and through it of the registration, makes that run
        // ours alone, so the `&mut` formed here is the only reference into
        // it for `'p`.
        let scratch = unsafe { &mut *index.image.scratch(&index.mapping, reader.index()).as_ptr() };
        Ok(Self {
            control,
            tables,
            scratch,
            bucket: route.bucket(),
            tag: route.tag(),
            fingerprint: route.fingerprint(),
            credit,
            retains: &reader.record().retains,
        })
    }

    /// The key's fingerprint: the identity a candidate's record must carry.
    #[inline(always)]
    pub(super) fn fingerprint(&self) -> u64 {
        self.fingerprint
    }

    #[inline(always)]
    pub(super) fn credit(&self) -> Credit {
        self.credit
    }

    /// Where an acquisition under this observation counts a failed right
    /// reservation: the pinned reader's record.
    #[inline(always)]
    pub(super) fn retains(&self) -> &'p RetainCounters {
        self.retains
    }

    /// The scan's upper bound, prepaid before every attempt: every bucket
    /// the scan may visit and every pair it may compare, plus the two
    /// sequence validations that bracket it.
    #[inline(always)]
    fn bound(&self) -> ScanBound {
        let depth = self.tables.depth;
        ScanBound {
            visits: 1 + depth,
            comparisons: PAIRS * (1 + depth) + 2,
        }
    }

    /// One attempt: the whole scan bound prepaid, a stable sequence, the
    /// chain summary and, unless it excludes the tag, the scan into the
    /// scratch, and the same sequence again. `Ok(None)` is a torn, busy or
    /// terminal attempt, consumed with its charge; the caller decides whether
    /// another follows. The bound is charged whole whether or not the summary
    /// spared the scan.
    ///
    /// # Errors
    ///
    /// `BudgetExhausted` if the bound cannot be paid before the first
    /// sequence load, with no sequence or bucket read; `Corrupt` for
    /// a chain malformed under an unchanged sequence, when the attempt scans it.
    #[inline(always)]
    pub(super) fn attempt(
        &mut self,
        budget: &mut WorkBudget,
    ) -> Result<Option<Stable>, SnapshotError> {
        // The bound is decided before the first sequence load and cannot
        // fail after it; the bookkeeping of the debit runs once the loads
        // it covers are in flight, off the path the scan's loads wait on.
        let bound = self.bound();
        budget.preflight(bound.visits + bound.comparisons)?;
        probe::note(Primitive::Load);
        let sequence = match read_stable(&self.control.sequence) {
            Ok(sequence) => sequence,
            Err(Unstable::Busy) => {
                // A writer is inside its bracket; a reload without a pause
                // lands inside the same bracket.
                std::hint::spin_loop();
                bound.debit(budget);
                return Ok(None);
            }
            Err(Unstable::Terminal) => {
                bound.debit(budget);
                return Ok(None);
            }
        };
        // The summary belongs to the same stable state as the pairs: it is
        // stored inside the insert's bracket and read here with the same
        // `SeqCst` load as every bucket field, so the second sequence load
        // vouches for it as it does for a copy.
        probe::note(Primitive::Load);
        let summary = self.tables.summaries[self.bucket].load(Ordering::SeqCst);
        if excludes(summary, self.tag) {
            bound.debit(budget);
            probe::note(Primitive::Load);
            return Ok(still(&self.control.sequence, sequence).then_some(Stable {
                sequence,
                copied: 0,
            }));
        }
        let mut work = ScanWork::default();
        let scanned = scan_chain(
            self.tables.buckets,
            self.tables.base,
            self.bucket,
            self.tables.depth,
            self.tag,
            self.scratch,
            &mut work,
        );
        bound.debit(budget);
        let copied = match scanned {
            Ok(copied) => copied,
            // A chain that reads malformed under an unchanged sequence is
            // malformed; under a changed one the links were read across a
            // recycle, and the attempt is retried like any other torn copy.
            // Either way the attempt cost exactly its prepaid bound, which
            // the scan's work cannot exceed, so a short allowance can neither
            // mask the fault nor let the retries run past the budget.
            Err(Corrupt) => {
                debug_assert!(
                    work.visits <= bound.visits && work.comparisons + 2 <= bound.comparisons,
                    "a scan did more than its prepaid bound"
                );
                // The malformed link ends the walk; its reads are recorded at
                // the bound, an upper bound on what it did.
                probe::note_n(Primitive::Load, 1 + bound.visits);
                if still(&self.control.sequence, sequence) {
                    return Err(SnapshotError::Corrupt);
                }
                return Ok(None);
            }
        };
        debug_assert!(
            work.visits <= bound.visits && work.comparisons + 2 <= bound.comparisons,
            "a scan did more than its prepaid bound"
        );
        // One load per bucket read, and the closing sequence load.
        probe::note_n(Primitive::Load, work.visits + 1);
        Ok(still(&self.control.sequence, sequence).then_some(Stable { sequence, copied }))
    }

    /// The identities `stable` copied.
    #[inline(always)]
    pub(super) fn candidates(&self, stable: Stable) -> &[Identity] {
        &self.scratch[..stable.copied]
    }

    /// Whether the shard sequence still reads `stable`'s value: no mutation
    /// has committed in the shard since the copy, so every mapping the copy
    /// saw is in place and none was added.
    #[inline(always)]
    pub(super) fn still(&self, stable: Stable) -> bool {
        still(&self.control.sequence, stable.sequence)
    }

    /// The identities `stable` copied, for the rest of the borrow: the
    /// snapshot hands its caller a slice that outlives this value, which
    /// `candidates` cannot.
    #[cfg(test)]
    fn into_candidates(self, stable: Stable) -> &'p [Identity] {
        &self.scratch[..stable.copied]
    }
}

impl<'s, P: Platform> Protected<'_, 's, P> {
    /// Test probe: copies every candidate identity for `key` into the
    /// registration's scratch under one stable shard sequence, making at
    /// most `retries` attempts. Returns `Some` candidates, an empty slice
    /// under a stable sequence proving the key absent at the identity level,
    /// or `None` when every paid attempt found the sequence changed, busy or
    /// terminal or the allowance was zero, as [`Observation::attempt`]
    /// reports it. The copy is taken inside this pinned interval, so the era
    /// pinned is at most the retirement era of any object it names: the
    /// order the grace argument needs.
    ///
    /// # Errors
    ///
    /// [`SnapshotError`]; no bucket or shard control word changes on any of
    /// them, and the scratch contents are unspecified.
    #[cfg(test)]
    pub(crate) fn snapshot<'p>(
        &'p mut self,
        key: &Key,
        retries: usize,
        budget: &mut WorkBudget,
    ) -> Result<Option<&'p [Identity]>, SnapshotError> {
        let credit = Credit::Record(self.registration().index().0);
        let mut observation = Observation::routed(self, key, None, credit, budget)?;
        for _ in 0..retries {
            if let Some(stable) = observation.attempt(budget)? {
                return Ok(Some(observation.into_candidates(stable)));
            }
        }
        Ok(None)
    }
}
