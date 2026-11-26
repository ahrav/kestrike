//! The profile-by-run matrix and the snapshot totals. A matrix row holds one
//! (campaign, profile, build, variant) population; each cell shows the
//! highest-priority outcome among that population's jobs in one run.

use std::collections::{BTreeMap, BTreeSet};

use crate::outcome::{Domain, Outcome};
use crate::parallel;
use crate::signals::JOBS_PER_THREAD;
use crate::snapshot::{JobState, Snapshot};

/// The window `Totals::finished_last_hour` counts back from `observed_ms`.
const HOUR_MS: u64 = 3_600_000;

#[derive(Debug, Clone)]
pub struct Cell {
    pub outcome: Outcome,
}

/// One (campaign, profile, build, variant) population. `cells` maps each
/// run to its highest-priority outcome. `rank` is the lowest
/// [`Outcome::rank`] among the cells. `mixed` is true when the cells that
/// pass or carry a domain show more than one label.
#[derive(Debug, Clone)]
pub struct MatrixRow {
    pub campaign: String,
    pub profile: String,
    pub build: String,
    pub variant: String,
    pub cells: BTreeMap<u64, Cell>,
    pub rank: u8,
    pub mixed: bool,
}

impl MatrixRow {
    /// True when any cell has a domain: a service or simulator fault, a
    /// campaign or host outcome, an inconclusive stop or a chaos
    /// interruption.
    pub fn failing(&self) -> bool {
        self.rank < Outcome::UNRANKED
    }
}

#[derive(Debug, Clone, Default)]
pub struct Matrix {
    pub runs: Vec<u64>,
    pub rows: Vec<MatrixRow>,
}

pub fn matrix(snapshot: &Snapshot) -> Matrix {
    type Population<'a> = (&'a str, &'a str, &'a str, &'a str);
    let parts = parallel::runs(&snapshot.jobs, JOBS_PER_THREAD, |jobs| {
        let mut runs = BTreeSet::new();
        let mut rows: BTreeMap<Population, BTreeMap<u64, Cell>> = BTreeMap::new();
        for job in jobs.iter().filter(|job| job.held.is_none()) {
            let Some(run) = job.run else {
                continue;
            };
            runs.insert(run);
            let key = (
                job.campaign.as_str(),
                job.profile.as_str(),
                job.build.as_str(),
                job.variant.as_str(),
            );
            keep(rows.entry(key).or_default(), run, Outcome::of_job(job));
        }
        (runs, rows)
    });
    let mut runs = BTreeSet::new();
    let mut rows: BTreeMap<Population, BTreeMap<u64, Cell>> = BTreeMap::new();
    for (part_runs, part_rows) in parts {
        runs.extend(part_runs);
        for (key, cells) in part_rows {
            let held = rows.entry(key).or_default();
            for (run, cell) in cells {
                keep(held, run, cell.outcome);
            }
        }
    }
    let mut rows: Vec<MatrixRow> = rows
        .into_iter()
        .map(|((campaign, profile, build, variant), cells)| {
            let labels: BTreeSet<&str> = cells
                .values()
                .filter(|cell| cell.outcome.domain.is_some() || cell.outcome.is_pass())
                .map(|cell| cell.outcome.label.as_str())
                .collect();
            let rank = cells
                .values()
                .map(|cell| cell.outcome.rank())
                .min()
                .unwrap_or(Outcome::UNRANKED);
            let mixed = labels.len() > 1;
            MatrixRow {
                campaign: campaign.to_owned(),
                profile: profile.to_owned(),
                build: build.to_owned(),
                variant: variant.to_owned(),
                cells,
                rank,
                mixed,
            }
        })
        .collect();
    rows.sort_by(|a, b| {
        (
            a.rank,
            !a.mixed,
            &a.profile,
            &a.campaign,
            &a.build,
            &a.variant,
        )
            .cmp(&(
                b.rank,
                !b.mixed,
                &b.profile,
                &b.campaign,
                &b.build,
                &b.variant,
            ))
    });
    Matrix {
        runs: runs.into_iter().collect(),
        rows,
    }
}

/// Places `outcome` in the cell for `run`, keeping the cell when it holds
/// a more urgent outcome; of equally urgent outcomes the later one stays,
/// so merging runs of jobs in order keeps what one pass in job order keeps.
fn keep(cells: &mut BTreeMap<u64, Cell>, run: u64, outcome: Outcome) {
    if cells
        .get(&run)
        .is_some_and(|cell| cell.outcome.rank() < outcome.rank())
    {
        return;
    }
    cells.insert(run, Cell { outcome });
}

pub fn glyph(outcome: &Outcome) -> char {
    match (outcome.label.as_str(), outcome.domain) {
        _ if outcome.is_pass() => '✓',
        ("queued", _) => '·',
        ("running", _) => '▶',
        ("settling" | "waiting", None) => '…',
        (_, Some(Domain::Service)) if outcome.is_violation() => '✗',
        (_, Some(Domain::Service)) => '~',
        (_, Some(_)) if outcome.is_inconclusive() => '?',
        (_, Some(Domain::Chaos)) => 'k',
        (_, Some(_)) => '!',
        (_, None) => ' ',
    }
}

/// Counts over one snapshot. `by_state` counts every job; `by_domain` and
/// `by_label` count settled jobs by outcome. `attempts` counts attempt
/// rows with a finish time, and `finished_last_hour` those finished at or
/// after `observed_ms.saturating_sub(HOUR_MS)`. The wall quantiles take
/// the zero-based index `ceil((n - 1) * q / 100)` of the sorted wall times
/// of rows whose finish follows their intent.
#[derive(Debug, Clone, Default)]
pub struct Totals {
    pub by_state: BTreeMap<JobState, u64>,
    pub by_domain: BTreeMap<Option<Domain>, u64>,
    pub by_label: BTreeMap<String, u64>,
    pub attempts: u64,
    pub finished_last_hour: u64,
    pub wall_p50_ms: Option<u64>,
    pub wall_p95_ms: Option<u64>,
    pub wall_max_ms: Option<u64>,
}

pub fn totals(snapshot: &Snapshot) -> Totals {
    let hour_ago = snapshot.observed_ms.saturating_sub(HOUR_MS);
    let parts = parallel::runs(&snapshot.jobs, JOBS_PER_THREAD, |jobs| {
        let mut totals = Totals::default();
        let mut walls = Vec::new();
        for job in jobs {
            *totals.by_state.entry(job.state).or_default() += 1;
            if job.state == JobState::Settled {
                let outcome = Outcome::of_job(job);
                *totals.by_domain.entry(outcome.domain).or_default() += 1;
                *totals.by_label.entry(outcome.label).or_default() += 1;
            }
            for row in &job.attempts {
                let Some(finished) = row.finished_ms else {
                    continue;
                };
                totals.attempts += 1;
                if finished >= hour_ago {
                    totals.finished_last_hour += 1;
                }
                walls.extend(row.wall_ms());
            }
        }
        (totals, walls)
    });
    let mut totals = Totals::default();
    let mut walls = Vec::new();
    for (part, part_walls) in parts {
        for (state, count) in part.by_state {
            *totals.by_state.entry(state).or_default() += count;
        }
        for (domain, count) in part.by_domain {
            *totals.by_domain.entry(domain).or_default() += count;
        }
        for (label, count) in part.by_label {
            *totals.by_label.entry(label).or_default() += count;
        }
        totals.attempts += part.attempts;
        totals.finished_last_hour += part.finished_last_hour;
        walls.extend(part_walls);
    }
    walls.sort_unstable();
    let quantile =
        |q: usize| (!walls.is_empty()).then(|| walls[((walls.len() - 1) * q).div_ceil(100)]);
    totals.wall_p50_ms = quantile(50);
    totals.wall_p95_ms = quantile(95);
    totals.wall_max_ms = walls.last().copied();
    totals
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn job(id: &str, profile: &str, run: u64, class: &str, wall: u64) -> serde_json::Value {
        json!({
            "id": id, "profile": profile, "campaign": "c", "run": run, "variant": "v",
            "state": "settled", "result": {"attempt": 1, "class": class},
            "attempts": [{"number": 1, "intent_ms": 0, "finished_ms": wall,
                          "finished": {"class": class, "binding": "matching"}}],
        })
    }

    fn snapshot(jobs: Vec<serde_json::Value>) -> Snapshot {
        serde_json::from_value(json!({
            "format": 1, "observed_ms": 3_000_000, "state": "/s", "config": null,
            "probes": 0, "held_probes": [], "jobs": jobs, "findings": [],
            "failure_groups": [], "space": {"free_bytes": 1, "free_inodes": 1},
        }))
        .unwrap()
    }

    #[test]
    fn matrix_rows_with_failures_sort_first_and_mixed_outcomes_are_marked() {
        let shown = snapshot(vec![
            job("a", "alpha", 0, "pass", 1),
            job("b", "alpha", 1, "pass", 1),
            job("c", "beta", 0, "pass", 1),
            job("d", "beta", 1, "violation", 1),
            json!({"id": "e", "profile": "gamma", "campaign": "c", "run": 2, "variant": "v",
                   "state": "queued"}),
        ]);
        let built = matrix(&shown);
        assert_eq!(built.runs, vec![0, 1, 2]);
        let order: Vec<_> = built.rows.iter().map(|row| row.profile.as_str()).collect();
        assert_eq!(order, ["beta", "alpha", "gamma"]);
        assert!(built.rows[0].failing() && built.rows[0].mixed);
        assert!(!built.rows[1].failing() && !built.rows[1].mixed);
        let cell = &built.rows[0].cells[&1];
        assert_eq!(glyph(&cell.outcome), '✗');
        assert_eq!(glyph(&built.rows[2].cells[&2].outcome), '·');
    }

    #[test]
    fn a_cell_keeps_the_last_of_its_most_urgent_outcomes_across_thread_runs() {
        let classes = ["violation", "unsuccessful", "pass", "oom"];
        let jobs = (0..4 * JOBS_PER_THREAD)
            .map(|n| job(&n.to_string(), "p", 0, classes[n * 7 % 5 % 4], 1))
            .collect();
        let shown = snapshot(jobs);
        let last = (0..4 * JOBS_PER_THREAD)
            .rev()
            .map(|n| classes[n * 7 % 5 % 4])
            .find(|class| matches!(*class, "violation" | "unsuccessful"))
            .unwrap();
        let built = matrix(&shown);
        assert_eq!(built.rows.len(), 1);
        assert_eq!(built.rows[0].cells[&0].outcome.label, last);
        let counted = totals(&shown);
        assert_eq!(counted.attempts, 4 * JOBS_PER_THREAD as u64);
        assert_eq!(
            counted.by_state[&JobState::Settled],
            4 * JOBS_PER_THREAD as u64
        );
    }

    #[test]
    fn jobs_of_one_profile_on_two_builds_form_two_matrix_rows() {
        let mut old = job("a", "p", 0, "violation", 1);
        old["build"] = json!("b1");
        let mut fixed = job("b", "p", 0, "pass", 1);
        fixed["build"] = json!("b2");
        let built = matrix(&snapshot(vec![old, fixed]));
        assert_eq!(built.rows.len(), 2);
        assert!(built.rows.iter().all(|row| !row.mixed));
        assert_eq!(built.rows[1].cells[&0].outcome.label, "pass");
    }

    #[test]
    fn totals_count_settled_outcomes_and_rank_attempt_wall_times() {
        let jobs = (1..=20)
            .map(|n| job(&n.to_string(), "p", n, "pass", n * 1000))
            .collect();
        let mut shown = snapshot(jobs);
        shown.observed_ms = HOUR_MS + 10_000;
        let counted = totals(&shown);
        assert_eq!(counted.by_label["pass"], 20);
        assert_eq!(counted.by_domain[&None], 20);
        assert_eq!(counted.attempts, 20);
        assert_eq!(counted.finished_last_hour, 11);
        assert_eq!(counted.wall_p50_ms, Some(11_000));
        assert_eq!(counted.wall_p95_ms, Some(20_000));
        assert_eq!(counted.wall_max_ms, Some(20_000));
    }
}
