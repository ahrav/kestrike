//! The `campaign sweep` table classifies each coverage counter as required
//! or excused separately for `cluster-swarm`, `cluster-broad`, and
//! `cluster-pressure`.
//!
//! A row names each counter of [`COVERAGE`](crate::protocol::COVERAGE) once,
//! as required or as excused. `unreached` lists each required counter with
//! zero reaching passes once a non-control profile has at least
//! [`REQUIRED_PASSES`] covered passes. The status's `zero` list, built from
//! `COVERAGE`, names every counter with zero reaching passes, excused ones
//! included, while the profile has a covered pass.
//! Each row records a sweep at `counts: {}` with at least 2,000 covered
//! passes, and at least one in eight of them reached each required counter.
//! An excused counter's reason identifies the workload step, fault, or
//! setting the counter requires. A counter moves from required to excused
//! only with the owner's approval.

use super::Totals;

/// Covered-pass floor for reporting a missing event.
pub(super) const REQUIRED_PASSES: u64 = 64;

/// Each row records the profile, its covered pass count, how many passes
/// reached each required counter, and the reason for each excused counter.
type MeasuredRow = (
    &'static str,
    u64,
    &'static [(&'static str, u64)],
    &'static [(&'static str, &'static str)],
);

pub(super) const REQUIRED: &[MeasuredRow] = &[
    (
        "cluster-swarm",
        10673,
        &[
            ("published", 10655),
            ("hits", 9211),
            ("misses", 10503),
            ("refused", 9438),
            ("invalidated", 5836),
            ("cancelled", 5598),
            ("cross", 5874),
            ("reused", 10346),
            ("healthy", 10673),
            ("faults", 9620),
        ],
        &[],
    ),
    (
        "cluster-broad",
        72459,
        &[
            ("published", 72459),
            ("hits", 72459),
            ("misses", 72443),
            ("refused", 72459),
            ("invalidated", 72459),
            ("cancelled", 72459),
            ("cross", 38587),
            ("reused", 72459),
            ("healthy", 72459),
            ("faults", 72459),
        ],
        &[],
    ),
    (
        "cluster-pressure",
        33676,
        &[
            ("published", 33676),
            ("hits", 33676),
            ("misses", 33676),
            ("refused", 8719),
            ("cross", 33676),
            ("reused", 33676),
            ("healthy", 33676),
            ("faults", 33676),
        ],
        &[
            (
                "invalidated",
                "the shape runs no invalidation: with `invalidate` off its workload \
                 proposes no INVALIDATE, the one action that raises the counter",
            ),
            (
                "cancelled",
                "the shape runs no cancel: with `cancel` off its workload proposes \
                 no CANCEL, the one action that raises the counter",
            ),
        ],
    ),
];

/// The required events of `events` with zero reaching passes, for a
/// non-control profile with at least [`REQUIRED_PASSES`] covered passes;
/// empty for any other profile.
pub(super) fn unreached(totals: &Totals, events: &[(&'static str, u64)]) -> Vec<&'static str> {
    if totals.control || totals.covered < REQUIRED_PASSES {
        return Vec::new();
    }
    events
        .iter()
        .map(|&(name, _)| name)
        .filter(|name| totals.never_reached(name))
        .collect()
}
