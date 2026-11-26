//! A history is judged only after `admit` accepts it: within the history
//! bound, sealed, with every row well formed, every ordinal unique, every
//! decision resolved, every sampled report accepted, each upload attempt
//! holding at most one resolved result and resolving an `Unknown` result
//! only as `Published` or `Failed`, each upload begin declaring `Pending`
//! exactly when its attempt has no result, and each abandoned attempt
//! holding an `Unknown` result, and each publication on a key an
//! invalidation names by interval carrying a version. Ordering across rows is
//! the checkers' judgment, not an admission rule.

use std::collections::HashSet;

use super::attempt::{contradictory_result, misstated_cut};
use super::bounds::HISTORY_BOUND;
use super::coverage::unversioned_under_range;
use super::ids::Ordinal;
use super::row::{Field, Row};
use super::tenure::Ordinals;
use super::verdict::{Inconclusive, Verdict};

/// A recorded history. [`History::tick`] draws every ordinal from one
/// counter, so a history declares a shared ordinal unless its rows came
/// from separate per-client clocks and it declares [`Ordinals::PerClient`].
/// Under either declaration every ordinal is distinct across the whole
/// history: a recorder merging per-client clocks assigns each row a
/// distinct value that keeps each timeline's own order, and the strict
/// reading takes that merge as one recorded interleaving.
#[derive(Debug, Clone, Default)]
pub(crate) struct History {
    rows: Vec<Row>,
    sealed: bool,
    next: u32,
    ordinals: Ordinals,
}

impl History {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn tick(&mut self) -> Ordinal {
        let ordinal = Ordinal(self.next);
        self.next += 1;
        ordinal
    }

    pub(crate) fn push(&mut self, row: Row) {
        self.rows.push(row);
        self.sealed = false;
    }

    pub(crate) fn seal(&mut self) {
        self.sealed = true;
    }

    pub(crate) fn rows(&self) -> &[Row] {
        &self.rows
    }

    pub(crate) fn ordered_by(&mut self, ordinals: Ordinals) {
        self.ordinals = ordinals;
    }
}

/// Proof that `admit` accepted the history; `admit` is its only constructor.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Admitted<'h> {
    history: &'h History,
}

impl<'h> Admitted<'h> {
    pub(crate) fn rows(&self) -> &'h [Row] {
        &self.history.rows
    }

    pub(crate) fn ordinals(&self) -> Ordinals {
        self.history.ordinals
    }

    pub(crate) fn live(&self) -> impl Iterator<Item = &'h Row> {
        self.history
            .rows
            .iter()
            .filter(|row| !row.evidence.is_recovery())
    }
}

pub(crate) fn admit(history: &History) -> Result<Admitted<'_>, Inconclusive> {
    if history.rows.len() > HISTORY_BOUND {
        return Err(Inconclusive::HistoryBound {
            limit: HISTORY_BOUND,
            rows: history.rows.len(),
        });
    }
    admit_unbounded(history)
}

/// Every admission rule but the history bound, the seal included.
pub(crate) fn admit_unbounded(history: &History) -> Result<Admitted<'_>, Inconclusive> {
    if !history.sealed {
        return Err(Inconclusive::Truncated);
    }
    admit_rows(&history.rows)?;
    Ok(Admitted { history })
}

/// Every admission rule but the history bound and the seal, over `rows`.
pub(crate) fn admit_rows(rows: &[Row]) -> Result<(), Inconclusive> {
    let mut seen = HashSet::new();
    for row in rows {
        if let Some(field) = row.malformed_field() {
            return Err(Inconclusive::Malformed { op: row.op, field });
        }
        if let Some((field, _)) = row.ordinals().find(|&(_, ordinal)| !seen.insert(ordinal)) {
            return Err(Inconclusive::Malformed { op: row.op, field });
        }
        if let Some(decision) = row.unresolved {
            return Err(Inconclusive::Unresolved {
                op: row.op,
                decision,
            });
        }
        if row.outcome.is_none()
            && let Some(reason) = row.report.and_then(|report| report.rejection(row.op))
        {
            return Err(reason);
        }
    }
    if let Some(op) = contradictory_result(rows) {
        return Err(Inconclusive::Malformed {
            op,
            field: Field::Outcome,
        });
    }
    if let Some(op) = misstated_cut(rows) {
        return Err(Inconclusive::Malformed {
            op,
            field: Field::Open,
        });
    }
    if let Some(op) = unversioned_under_range(rows) {
        return Err(Inconclusive::Malformed {
            op,
            field: Field::Version,
        });
    }
    Ok(())
}

pub(crate) fn judge(history: &History, check: impl FnOnce(Admitted<'_>) -> Verdict) -> Verdict {
    match admit(history) {
        Ok(admitted) => check(admitted),
        Err(reason) => Verdict::Inconclusive(reason),
    }
}
