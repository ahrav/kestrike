//! Permanent invalidation coverage of one key. Coverage records the version
//! intervals and labels each linearized invalidation adds and only grows, so
//! a covered version stays ineligible for every later lookup and recorded
//! restore in every tenure. A version outside every interval and label
//! stays eligible.

use std::collections::HashSet;

use super::action::ActionKind;
use super::ids::{Label, OpId};
use super::row::Row;
use super::rules::{Rule, holds};

/// The versions one invalidation names: an inclusive interval, or every
/// version of the key. While [`Rule::AbsentCoverage`] holds, an interval
/// also covers versions the key has not published yet, and `All` covers
/// every publication of its key, versioned or not, at any later point. An
/// interval covers versioned publications only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Cover {
    Range { lo: u64, hi: u64 },
    All,
}

impl Cover {
    pub(crate) fn contains(self, version: Option<u64>) -> bool {
        match self {
            Self::Range { lo, hi } => version.is_some_and(|v| lo <= v && v <= hi),
            Self::All => true,
        }
    }
}

/// One key's coverage: whether an every-version invalidation linearized,
/// the covered intervals, and the covered labels. Sorting and deduplication
/// make equality and hashing independent of insertion order.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub(crate) struct Coverage {
    all: bool,
    intervals: Vec<(u64, u64)>,
    labels: Vec<Label>,
}

impl Coverage {
    /// Adds one invalidation at its linearization point. `present` lists
    /// each label the key has published there, with its version. An
    /// unversioned invalidation covers every present label; a fill still in
    /// flight is revoked by the key model and leaves its label uncovered.
    pub(crate) fn add(
        &mut self,
        cover: Option<Cover>,
        present: impl Iterator<Item = (Label, Option<u64>)>,
    ) {
        match cover {
            None => self.labels.extend(present.map(|(label, _)| label)),
            Some(cover) if !holds(Rule::AbsentCoverage) => self.labels.extend(
                present.filter_map(|(label, version)| cover.contains(version).then_some(label)),
            ),
            Some(Cover::All) => self.all = true,
            Some(Cover::Range { lo, hi }) => self.intervals.push((lo, hi)),
        }
        self.intervals.sort_unstable();
        self.intervals.dedup();
        self.labels.sort_unstable_by_key(|label| label.0);
        self.labels.dedup();
    }

    /// Whether an invalidation already covered `label` at `version`.
    pub(crate) fn covers(&self, label: Label, version: Option<u64>) -> bool {
        self.all
            || self.labels.contains(&label)
            || self
                .intervals
                .iter()
                .any(|&(lo, hi)| Cover::Range { lo, hi }.contains(version))
    }
}

/// The first unversioned publication on a key some invalidation names by
/// interval. An interval covers versioned publications only.
pub(crate) fn unversioned_under_range(rows: &[Row]) -> Option<OpId> {
    let ranged: HashSet<_> = rows
        .iter()
        .filter(|row| {
            row.kind == ActionKind::Invalidate && matches!(row.covers, Some(Cover::Range { .. }))
        })
        .map(Row::key)
        .collect();
    rows.iter()
        .find(|row| {
            matches!(row.kind, ActionKind::Publish | ActionKind::Replace)
                && row.version.is_none()
                && ranged.contains(&row.key())
        })
        .map(|row| row.op)
}
