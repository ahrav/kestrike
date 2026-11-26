//! A verdict satisfies a gate only as `Pass` with every declared obligation
//! activated; `Violation` keeps the first broken rule and `Inconclusive`
//! names why judgment stopped.

use super::evidence::Decision;
use super::ids::{OpId, Tenure};
use super::obligation::Obligation;
use super::row::{Field, ReportKind};

/// Each obligation's activation count and three scope counts a verdict
/// reports beside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Activations {
    counts: [u32; Obligation::ALL.len()],
    /// The pending effects whose target tenure went unrecorded, each judged
    /// in every segment at or above its floor.
    pub(crate) unrecorded_targets: u32,
    /// The lookups and removals whose deadline lies in another tenure's
    /// clock domain, each left unjudged against that deadline.
    pub(crate) cross_tenure_deadlines: u32,
    /// `judge_rows` sets this count to the number of cross-timeline pairs
    /// ordered by the recorded interleaving when a per-client verdict is
    /// `Verdict::Pass`.
    pub(crate) cross_timeline_orders: u32,
}

impl Activations {
    pub(crate) fn activate(&mut self, obligation: Obligation) {
        self.counts[obligation as usize] += 1;
    }

    pub(crate) const fn count(&self, obligation: Obligation) -> u32 {
        self.counts[obligation as usize]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Violation {
    pub(crate) obligation: Obligation,
    pub(crate) op: OpId,
    pub(crate) rule: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Inconclusive {
    HistoryBound {
        limit: usize,
        rows: usize,
    },
    SearchBound {
        limit: u32,
    },
    DomainBound {
        dimension: &'static str,
        limit: usize,
        observed: usize,
    },
    Truncated,
    Malformed {
        op: OpId,
        field: Field,
    },
    Unresolved {
        op: OpId,
        decision: Decision,
    },
    PoisonedReport {
        op: OpId,
        report: ReportKind,
    },
    AbsentReport {
        op: OpId,
        report: ReportKind,
    },
    /// The continuation reached `limit` in `dimension` and stopped before
    /// dropping any state it carries.
    ContinuationBound {
        dimension: &'static str,
        limit: usize,
    },
    /// A completed response's tenure tag or a client's recorded high-water
    /// names no tenure the activation log activated at or before its
    /// response, or a request's recorded target names none activated at or
    /// before its invocation: a harness failure. Under per-client ordinals
    /// a client row's tag, high-water or target need only name an
    /// activated tenure.
    UnloggedTenure {
        op: OpId,
        tenure: Tenure,
    },
    /// Under per-client ordinals, the lenient reading finds no failure and
    /// the strict reading fails at `op`, so the verdict depends on how rows
    /// of two timelines are ordered.
    CrossClientOrder {
        op: OpId,
    },
    /// The verdict depends on a landing the history does not record: a
    /// key's search fails with each expiry end judged against the samples
    /// known to precede it, and passes once an effect with an unrecorded
    /// target may land in that end's clock domain and bound its sample.
    /// `op` names the failing step of the first search.
    UnplacedSample {
        op: OpId,
    },
    /// Under per-client ordinals, `op` is a row only a shared ordinal lets
    /// the checker judge, as `tenure::per_client_scope` defines.
    PerClientScope {
        op: OpId,
    },
    /// `op` is a captured entry that leaves an activation's retained set
    /// only through a cancelled or timed-out publication, replacement or
    /// invalidation, so whether the successor had to serve it is unknown.
    UnknownExclusion {
        op: OpId,
    },
    /// The geometry fails [`Geometry::defines_windows`](super::content::Geometry::defines_windows):
    /// its chunk is zero or its header is longer than its chunk, and the
    /// oracle judges bytes only against chunk windows.
    Geometry {
        chunk: usize,
        header: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    Pass(Activations),
    Violation(Violation),
    Inconclusive(Inconclusive),
}

impl Verdict {
    pub(crate) fn satisfies(&self, declared: &[Obligation]) -> bool {
        match self {
            Self::Pass(activations) => {
                !declared.is_empty() && declared.iter().all(|&o| activations.count(o) > 0)
            }
            Self::Violation(_) | Self::Inconclusive(_) => false,
        }
    }

    pub(crate) const fn violated(&self) -> Option<(Obligation, &'static str)> {
        match self {
            Self::Violation(violation) => Some((violation.obligation, violation.rule)),
            Self::Pass(_) | Self::Inconclusive(_) => None,
        }
    }
}
