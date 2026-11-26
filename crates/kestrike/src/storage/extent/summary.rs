//! A node's summary after a join or split, computed from its old summary and the run bounds alone.
//!
//! A summary of the units `n0..n1` is `(start, max, end)`: the free run at `n0`, the longest free run and the free run ending at `n1`, where units past the volume count as taken.
//!
//! The verifier checks the contracts under its `verus_keep_ghost` cfg; an ordinary build compiles the function bodies alone.

#[cfg(verus_keep_ghost)]
use crate::model::{joins, splits, summarizes};
#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

/// One node's free runs: the run at its start, its longest run and the run at its end, in units.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Summary {
    pub(super) start: u64,
    pub(super) max: u64,
    pub(super) end: u64,
}

/// Precondition: `low..high` is the maximal free run the join formed, every other unit keeps its state, and the run overlaps the node over units `n0..n1`, whose summary before the join is `old`.
///
/// The join merges every run it touches into `low..high`, so the node's longest run is the larger of its old one and the join's part.
#[cfg_attr(verus_keep_ghost, verus_spec(sum =>
    requires
        n0 < n1,
        low < high,
        low < n1,
        n0 < high,
    ensures
        forall|was: spec_fn(int) -> bool, now: spec_fn(int) -> bool|
            #[trigger] joins(was, now, low as int, high as int)
                && summarizes(old, was, n0 as int, n1 as int)
                ==> summarizes(sum, now, n0 as int, n1 as int),
))]
pub(super) fn joined(low: u64, high: u64, old: Summary, n0: u64, n1: u64) -> Summary {
    #[cfg(verus_keep_ghost)]
    proof! { crate::proof::joined_runs(low as int, high as int, n0 as int, n1 as int); }
    Summary {
        start: if low <= n0 {
            high.min(n1) - n0
        } else {
            old.start
        },
        max: old.max.max(high.min(n1) - low.max(n0)),
        end: if high >= n1 {
            n1 - low.max(n0)
        } else {
            old.end
        },
    }
}

/// The node's summary after `start..end` left the run `low..high`, or `None` when the run's part inside the node was at least `old.max` units and covered only part of the node, which leaves the recomputation from the node's words or children to the caller.
///
/// `range` holds `[low, start, end, high]` with `low <= start < end <= high`, where `low..high` was the maximal free run before the split; the node spans units `n0..n1` and holds a unit of `start..end`, and `old` is its summary before the split.
/// The split shortens one run, so the node keeps its longest run when the split run's part inside the node was shorter, and when that run covered the node only its two remainders are left.
#[cfg_attr(verus_keep_ghost, verus_spec(sum =>
    requires
        n0 < n1,
        range[0] <= range[1],
        range[1] < range[2],
        range[2] <= range[3],
        range[1] < n1,
        n0 < range[2],
    ensures
        forall|was: spec_fn(int) -> bool, now: spec_fn(int) -> bool|
            #[trigger] splits(was, now, range[0] as int, range[1] as int, range[2] as int, range[3] as int)
                && summarizes(old, was, n0 as int, n1 as int)
                ==> (sum matches Some(s) ==> summarizes(s, now, n0 as int, n1 as int)),
        sum is None ==> vstd::math::min(range[3] as int, n1 as int) - vstd::math::max(range[0] as int, n0 as int) >= old.max,
        range[0] <= n0 && n1 <= range[3] ==> sum is Some,
))]
pub(super) fn split(range: [u64; 4], old: Summary, n0: u64, n1: u64) -> Option<Summary> {
    #[cfg(verus_keep_ghost)]
    proof! { crate::proof::split_runs(range[0] as int, range[1] as int, range[2] as int, range[3] as int, n0 as int, n1 as int); }
    // Indexed reads keep this body inside the verifier's supported Rust subset.
    let (low, start, end, high) = (range[0], range[1], range[2], range[3]);
    let head = if low <= n0 {
        start.saturating_sub(n0)
    } else {
        old.start
    };
    let tail = if high >= n1 {
        n1.saturating_sub(end)
    } else {
        old.end
    };
    let max = if high.min(n1) - low.max(n0) < old.max {
        old.max
    } else if low <= n0 && high >= n1 {
        head.max(tail)
    } else {
        return None;
    };
    Some(Summary {
        start: head,
        max,
        end: tail,
    })
}
