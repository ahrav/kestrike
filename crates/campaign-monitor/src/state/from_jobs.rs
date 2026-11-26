//! The values derived from a snapshot's job rows alone: the matrix with
//! its Profiles summary and row texts, the totals, the outcomes, the id
//! index, the populations and the display ranking within one flag. Each reads
//! `snapshot.jobs` and `snapshot.observed_ms` and nothing else, so the
//! values of fetched job rows equal those of sanitized ones whenever
//! sanitizing changes no job string.

use std::collections::BTreeSet;

use super::ids::IdIndex;
use super::populations::Populations;
use crate::model::{Matrix, MatrixRow, Totals, matrix, totals};
use crate::outcome::Outcome;
use crate::parallel;
use crate::snapshot::{Job, JobState, Snapshot};
use crate::tui::text;

/// Per-snapshot totals of the Profiles matrix that its renderer reads on
/// every frame.
#[derive(Debug, Default)]
pub(crate) struct ProfileSummary {
    /// The campaign of every row when all rows share one campaign.
    pub(crate) campaign: Option<String>,
    pub(crate) campaign_width: u16,
    pub(crate) profile_width: u16,
    pub(crate) failing: usize,
    pub(crate) service: usize,
    /// Per matrix row: cells with a failure domain, and the
    /// `label count · ...` outcome summary.
    pub(crate) failed: Vec<usize>,
    pub(crate) counts: Vec<String>,
}

pub(super) struct FromJobs {
    pub(super) matrix: Matrix,
    pub(super) profile_summary: ProfileSummary,
    /// The identity of each matrix row.
    pub(super) profile_keys: Vec<String>,
    /// The lowercase search text of each matrix row.
    pub(super) profile_texts: Vec<String>,
    pub(super) totals: Totals,
    /// Index-aligned with `snapshot.jobs`.
    pub(super) outcomes: Vec<Outcome>,
    pub(super) ids: IdIndex,
    pub(super) populations: Populations,
    /// Every job index ordered by [`rank_order`].
    pub(super) ranked: Vec<u32>,
}

impl FromJobs {
    /// Derives the values of `snapshot`'s job rows. The matrix with its
    /// summary and row texts, the totals and the outcomes each derive on
    /// their own thread while the calling thread builds the id index and
    /// the populations, then ranks the jobs once the outcomes arrive.
    pub(super) fn new(snapshot: &Snapshot) -> Self {
        let matrix_work = || {
            let matrix = matrix(snapshot);
            let summary = profile_summary(&matrix);
            let key = |row: &MatrixRow| {
                format!(
                    "{}\n{}\n{}\n{}",
                    row.campaign, row.profile, row.build, row.variant
                )
            };
            let text = |row: &MatrixRow| {
                format!(
                    "{} {} {} {}",
                    row.profile, row.campaign, row.build, row.variant
                )
                .to_lowercase()
            };
            let keys = matrix.rows.iter().map(key).collect::<Vec<_>>();
            let texts = matrix.rows.iter().map(text).collect::<Vec<_>>();
            (matrix, summary, keys, texts)
        };
        let totals_work = || totals(snapshot);
        let outcomes_work = || {
            snapshot
                .jobs
                .iter()
                .map(Outcome::of_job)
                .collect::<Vec<_>>()
        };
        std::thread::scope(|scope| {
            let by_matrix = parallel::start(scope, &matrix_work);
            let totals = parallel::start(scope, &totals_work);
            let outcomes = parallel::start(scope, &outcomes_work);
            let ids = IdIndex::new(&snapshot.jobs);
            let populations = Populations::new(&snapshot.jobs);
            let outcomes = outcomes.finish();
            let ranked = rank_order(&snapshot.jobs, &outcomes, &populations);
            let (matrix, profile_summary, profile_keys, profile_texts) = by_matrix.finish();
            Self {
                matrix,
                profile_summary,
                profile_keys,
                profile_texts,
                totals: totals.finish(),
                outcomes,
                ids,
                populations,
                ranked,
            }
        })
    }
}

/// Every index of `jobs` ordered by running jobs first, then outcome rank,
/// profile, campaign, run and index: the display order of jobs that share
/// a flag. The leading three keys pack into one integer whose order is
/// theirs: not running in bit 40, the outcome rank in bits 32 to 39 and the
/// (profile, campaign) rank in bits 0 to 31. Job indices fit in `u32`, as
/// [`IdIndex::new`] states.
fn rank_order(jobs: &[Job], outcomes: &[Outcome], populations: &Populations) -> Vec<u32> {
    let mut keyed: Vec<(u64, Option<u64>, u32)> = jobs
        .iter()
        .enumerate()
        .map(|(index, job)| {
            let lead = u64::from(job.state != JobState::Running) << 40
                | u64::from(outcomes[index].rank()) << 32
                | u64::from(populations.rank(index));
            let index = u32::try_from(index).expect("job indices fit in u32");
            (lead, job.run, index)
        })
        .collect();
    keyed.sort_unstable();
    keyed.iter().map(|&(_, _, index)| index).collect()
}

/// Matrix rows per thread when the Profiles summary counts cells.
const ROWS_PER_THREAD: usize = 16;

/// A matrix row's cells with a failure domain, and its `label count · ...`
/// outcome summary in label order.
fn row_counts(row: &MatrixRow) -> (usize, String) {
    let mut failed = 0;
    let mut counts: Vec<(&str, u64)> = Vec::new();
    for cell in row.cells.values() {
        failed += usize::from(cell.outcome.domain.is_some());
        let label = cell.outcome.label.as_str();
        match counts.iter_mut().find(|(seen, _)| *seen == label) {
            Some((_, count)) => *count += 1,
            None => counts.push((label, 1)),
        }
    }
    counts.sort_unstable();
    let counts = counts
        .iter()
        .map(|(label, n)| format!("{label} {n}"))
        .collect::<Vec<_>>()
        .join(" · ");
    (failed, counts)
}

fn profile_summary(matrix: &Matrix) -> ProfileSummary {
    let campaigns: BTreeSet<&str> = matrix
        .rows
        .iter()
        .map(|row| row.campaign.as_str())
        .collect();
    let (failed, counts) = parallel::runs(&matrix.rows, ROWS_PER_THREAD, |rows| {
        rows.iter().map(row_counts).collect::<Vec<_>>()
    })
    .into_iter()
    .flatten()
    .unzip();
    let width = |longest: Option<usize>, low: usize, high: usize| {
        u16::try_from(longest.unwrap_or(low).clamp(low, high)).unwrap_or(u16::MAX)
    };
    ProfileSummary {
        campaign: campaigns
            .first()
            .filter(|_| campaigns.len() == 1)
            .map(|name| (*name).to_owned()),
        campaign_width: width(campaigns.iter().map(|name| text::width(name)).max(), 8, 16),
        profile_width: width(
            matrix
                .rows
                .iter()
                .map(|row| text::width(&row.profile))
                .max(),
            7,
            28,
        ),
        failing: matrix.rows.iter().filter(|row| row.failing()).count(),
        service: matrix.rows.iter().filter(|row| row.rank == 0).count(),
        failed,
        counts,
    }
}
