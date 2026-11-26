//! `check` runs every per-key and recovery judgment on one admitted history
//! and returns the first violation it finds.

use super::attempts::judge_attempts;
use super::bounds::SearchBudget;
use super::candidates::{
    ConstraintsOf, cross_tenure_deadlines, cross_timeline_orders, judge_candidates,
};
use super::clients::judge_clients;
use super::content::Geometry;
use super::custody::{ended_visibility, judge_custody};
use super::delivery::{Catalog, judge_deliveries};
use super::domain::{domain, domain_across_keys};
use super::history::{Admitted, History, admit_unbounded, judge};
use super::ids::{KeyId, ResourceId};
use super::ledger::judge_ledger;
use super::retention::judge_retention;
use super::row::Row;
use super::search::linearize;
use super::tenure::{ActivationLog, Ordinals, Place, Reading, per_client_scope};
use super::verdict::{Activations, Inconclusive, Verdict, Violation};

pub(crate) fn check(history: &History) -> Verdict {
    check_within(history, Geometry::GOLDEN, &mut SearchBudget::per_key())
}

/// Judges `history` under `geometry` within `budget`. When `geometry` fails
/// [`Geometry::defines_windows`], the verdict is `Inconclusive::Geometry` and
/// no row is judged.
pub(crate) fn check_within(
    history: &History,
    geometry: Geometry,
    budget: &mut SearchBudget,
) -> Verdict {
    if !geometry.defines_windows() {
        return Verdict::Inconclusive(Inconclusive::Geometry {
            chunk: geometry.chunk,
            header: geometry.header,
        });
    }
    judge(history, |admitted| {
        judge_admitted(admitted, geometry, budget)
    })
}

fn judge_admitted(
    admitted: Admitted<'_>,
    geometry: Geometry,
    budget: &mut SearchBudget,
) -> Verdict {
    let all: Vec<&Row> = admitted.rows().iter().collect();
    judge_rows(
        &all,
        geometry,
        admitted.ordinals(),
        |_, ops, constrain| {
            budget.start_key();
            linearize(ops, &constrain(ops), budget)
        },
        |_, _| true,
    )
}

/// Judges the client acceptances of `history` alone, across any number of
/// keys. The client high-water rule spans every key of one shard, while
/// [`check`] admits at most `MAX_KEYS` keys a history, so a harness that
/// judges a wider history key by key judges its clients here once. Every
/// admission rule of `check` applies except the bounds on the history's rows
/// and keys: the domain rules judge the whole history, a label under two
/// keys and the holder bound included, and refuse before the activation
/// log does. Per-client ordinals are read as `check` reads them.
pub(crate) fn check_clients(history: &History) -> Result<(), Verdict> {
    let admitted = admit_unbounded(history).map_err(Verdict::Inconclusive)?;
    let all: Vec<&Row> = admitted.rows().iter().collect();
    let log = ActivationLog::of(&all);
    domain_across_keys(&all, log.as_ref().ok(), admitted.ordinals())
        .map_err(Verdict::Inconclusive)?;
    let log = log.map_err(Verdict::Inconclusive)?;
    let log = match admitted.ordinals() {
        Ordinals::Shared => log,
        Ordinals::PerClient => {
            if let Some(op) = per_client_scope(&all) {
                return Err(Verdict::Inconclusive(Inconclusive::PerClientScope { op }));
            }
            log.read(Reading::Lenient)
        }
    };
    log.reconcile(&all).map_err(Verdict::Inconclusive)?;
    judge_clients(&all, &log).map_err(Verdict::Violation)
}

pub(crate) fn implied_ends(live: &[&Row]) -> Vec<Row> {
    live.iter()
        .filter_map(|row| ended_visibility(row))
        .collect()
}

/// Judges `all` in order: the domain, the activation log and its tags, the
/// client acceptances of every evidence class, the recorded restores, the
/// upload attempts, each key's legal order through `search`, the
/// deliveries, custody, the recovery ledger and the retained sets, which
/// read the visibility ends slot releases imply beside the recorded rows;
/// the first failure is the verdict. An inconclusive per-key judgment
/// leaves the later judgments run, and their failure is the verdict before
/// that reason. Under
/// per-client `ordinals`, a row outside the per-client scope is
/// `PerClientScope`; otherwise the lenient reading's failure is the verdict,
/// and when the lenient reading finds none, the strict reading's failure is
/// `CrossClientOrder` and its pass is the verdict. A failure holds in every
/// order between timelines. A per-client pass holds under per-timeline
/// precedence and the recorded interleaving, and counts in
/// `cross_timeline_orders` the pairs that interleaving orders across
/// timelines.
pub(crate) fn judge_rows(
    all: &[&Row],
    geometry: Geometry,
    ordinals: Ordinals,
    mut search: impl FnMut(
        KeyId,
        &[&Row],
        ConstraintsOf<'_>,
    ) -> Result<Result<(), Violation>, Inconclusive>,
    ends: impl Fn(&Row, ResourceId) -> bool,
) -> Verdict {
    let log = ActivationLog::of(all);
    if let Err(reason) = domain(all, log.as_ref().ok(), ordinals) {
        return Verdict::Inconclusive(reason);
    }
    let log = match log {
        Ok(log) => log,
        Err(reason) => return Verdict::Inconclusive(reason),
    };
    let log = match ordinals {
        Ordinals::Shared => log,
        Ordinals::PerClient => {
            if let Some(op) = per_client_scope(all) {
                return Verdict::Inconclusive(Inconclusive::PerClientScope { op });
            }
            log.read(Reading::Lenient)
        }
    };
    if let Err(reason) = log.reconcile(all) {
        return Verdict::Inconclusive(reason);
    }
    let verdict = judge_in(all, geometry, &log, &mut search, &ends);
    if ordinals == Ordinals::Shared || !matches!(verdict, Verdict::Pass(_)) {
        return verdict;
    }
    match judge_in(
        all,
        geometry,
        &log.read(Reading::Strict),
        &mut search,
        &ends,
    ) {
        Verdict::Violation(violation) => {
            Verdict::Inconclusive(Inconclusive::CrossClientOrder { op: violation.op })
        }
        Verdict::Pass(mut activations) => {
            activations.cross_timeline_orders = cross_timeline_orders(all, &log);
            Verdict::Pass(activations)
        }
        judged => judged,
    }
}

fn judge_in(
    all: &[&Row],
    geometry: Geometry,
    log: &ActivationLog,
    search: &mut impl FnMut(
        KeyId,
        &[&Row],
        ConstraintsOf<'_>,
    ) -> Result<Result<(), Violation>, Inconclusive>,
    ends: &impl Fn(&Row, ResourceId) -> bool,
) -> Verdict {
    let live: Vec<&Row> = all
        .iter()
        .copied()
        .filter(|row| !row.evidence.is_recovery())
        .collect();
    let mut activations = Activations::default();
    activations.unrecorded_targets = live
        .iter()
        .filter(|row| matches!(log.place(row), Place::AtLeast(_)))
        .count() as u32;
    let ended = implied_ends(&live);
    let searched: Vec<&Row> = live.iter().copied().chain(ended.iter()).collect();
    activations.cross_tenure_deadlines = cross_tenure_deadlines(&searched, log);
    let judged = judge_clients(all, log)
        .and_then(|()| log.judge_restores(&live))
        .and_then(|()| judge_attempts(&live, &mut activations));
    if let Err(failure) = judged {
        return Verdict::Violation(failure);
    }
    let catalog = match Catalog::build(&live) {
        Ok(catalog) => catalog,
        Err(reason) => return Verdict::Inconclusive(reason),
    };
    let uncertain = match judge_candidates(&searched, log, &mut activations, &mut *search) {
        Err(reason) => Some(reason),
        Ok(Err(failure)) => return Verdict::Violation(failure),
        Ok(Ok(())) => None,
    };
    let retained: Vec<&Row> = all.iter().copied().chain(ended.iter()).collect();
    let judged = judge_deliveries(&live, &catalog, geometry, &mut activations)
        .and_then(|()| judge_custody(&live, &mut activations, ends))
        .and_then(|()| judge_ledger(all, &mut activations))
        .and_then(|()| judge_retention(&retained, log, &mut activations));
    match (judged, uncertain) {
        (Err(failure), _) => Verdict::Violation(failure),
        (Ok(()), Some(reason)) => Verdict::Inconclusive(reason),
        (Ok(()), None) => Verdict::Pass(activations),
    }
}
