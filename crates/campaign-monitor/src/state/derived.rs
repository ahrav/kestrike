//! Every value the monitor derives from one snapshot, built together off
//! the input thread, so all of them describe the same snapshot.

use std::collections::{BTreeMap, BTreeSet};

use super::Tab;
use super::from_jobs::{FromJobs, ProfileSummary};
use super::ids::IdIndex;
use super::naming::{job_of, naming, signal_jobs};
use super::populations::Populations;
use super::sanitize::{sanitize, unclean_jobs};
use crate::history::{History, Sample};
use crate::model::{Matrix, Totals};
use crate::outcome::Outcome;
use crate::parallel;
use crate::signals::{Severity, Signal, detect};
use crate::snapshot::{FailureGroup, Snapshot};

/// Columns of a failure group's run summary in the Findings table.
pub(crate) const RUNS_WIDTH: usize = 16;

/// Per-snapshot facts of one failure group that its renderer reads on
/// every frame.
#[derive(Debug)]
pub(crate) struct GroupSummary {
    /// The index in `findings` of the first unresolved finding, or of the
    /// first finding when all are resolved.
    pub(crate) target: Option<usize>,
    pub(crate) runs: String,
    pub(crate) profiles: String,
}

/// `outcomes` and `flags` are index-aligned with
/// `snapshot.jobs`; `flags` holds the worst severity among the signals that
/// name each job.
/// `order` holds every `snapshot.jobs` index in display order. `named`
/// holds, per signal, the jobs `signal_jobs` finds it names. `keys`,
/// `texts` and `drillable` hold, per row of Signals, Profiles and Findings
/// in [`Tab::index`] order, the row's identity, its lowercase search text
/// and whether Enter resolves it to jobs. `attempts` holds each history
/// sample's finished-attempt count, oldest first, after this snapshot's
/// sample was recorded.
///
/// Every string in `snapshot` and `signals` is display text: it passed
/// [`crate::tui::text::sanitize`], so it holds no control character.
/// `altered` holds the display form of each string that sanitizing changed,
/// so a view can tell that such a string is not the value a command needs.
pub struct Derived {
    pub(crate) snapshot: Snapshot,
    pub(crate) outcomes: Vec<Outcome>,
    pub(crate) flags: Vec<Option<Severity>>,
    pub(crate) signals: Vec<Signal>,
    pub(crate) matrix: Matrix,
    pub(crate) totals: Totals,
    pub(crate) critical: usize,
    pub(crate) warnings: usize,
    pub(crate) profile_summary: ProfileSummary,
    pub(crate) group_summaries: Vec<GroupSummary>,
    pub(crate) drillable: [Vec<bool>; Tab::ALL.len()],
    /// Settled outcome labels and counts, most frequent first, and the
    /// worst severity each detector raised.
    pub(crate) labels: Vec<(String, u64)>,
    pub(crate) worst: BTreeMap<&'static str, Severity>,
    pub(crate) named: Vec<Vec<usize>>,
    pub(crate) finding_rows: BTreeMap<String, usize>,
    pub(crate) ids: IdIndex,
    pub(crate) populations: Populations,
    pub(crate) order: Vec<u32>,
    pub(crate) keys: [Vec<String>; Tab::ALL.len()],
    pub(crate) texts: [Vec<String>; Tab::ALL.len()],
    pub(crate) attempts: Vec<u64>,
    /// Why recording this snapshot's history sample failed.
    pub(crate) history_error: Option<String>,
    pub(crate) altered: BTreeSet<String>,
}

impl Derived {
    /// Records the snapshot's sample (a file write for a file-backed
    /// history, which can wait for another writer's lock and reloads what
    /// another monitor wrote), detects signals in `snapshot` against the
    /// samples `history` then holds, sanitizes the snapshot and signal
    /// text, and derives the rest from the sanitized text. Detection and the
    /// sample read the text as fetched; both history-reading detectors skip
    /// samples at or after the snapshot's own time, so the sample recorded
    /// first leaves detection as it was.
    ///
    /// While the record and detection run, the `FromJobs` values and a scan
    /// for the jobs whose text sanitizing changes each derive from the
    /// fetched text on their own thread. With no such job the sanitized job
    /// rows equal the fetched ones, so those values stand; otherwise they
    /// derive again from the sanitized rows.
    pub fn observe(mut snapshot: Snapshot, history: &mut History) -> Self {
        let from_jobs_work = || FromJobs::new(&snapshot);
        let unclean_work = || unclean_jobs(&snapshot.jobs);
        let (mut signals, history_error, from_jobs, unclean) = std::thread::scope(|scope| {
            let from_jobs = parallel::start(scope, &from_jobs_work);
            let unclean = parallel::start(scope, &unclean_work);
            let history_error = history
                .record(Sample::of(&snapshot))
                .err()
                .map(|error| format!("history not recorded: {error}"));
            let signals = detect(&snapshot, history.samples());
            (signals, history_error, from_jobs.finish(), unclean.finish())
        });
        let attempts = history
            .samples()
            .iter()
            .map(|sample| sample.attempts)
            .collect();
        let altered = sanitize(&mut snapshot, &mut signals, &unclean);
        let from_jobs = if unclean.is_empty() {
            from_jobs
        } else {
            FromJobs::new(&snapshot)
        };
        let mut derived = Self::build(snapshot, signals, from_jobs, attempts, history_error);
        derived.altered = altered;
        derived
    }

    /// Derives the rest from the sanitized `snapshot` and `signals` and the
    /// [`FromJobs`] values of its job rows: the jobs each signal names, the
    /// job flags and display order, and the per-row facts of each tab.
    fn build(
        snapshot: Snapshot,
        signals: Vec<Signal>,
        from_jobs: FromJobs,
        attempts: Vec<u64>,
        history_error: Option<String>,
    ) -> Self {
        let FromJobs {
            matrix,
            profile_summary,
            profile_keys,
            profile_texts,
            totals,
            outcomes,
            ids,
            populations,
            ranked,
        } = from_jobs;
        let jobs = &snapshot.jobs;
        let named: Vec<Vec<usize>> = signals
            .iter()
            .map(|signal| signal_jobs(signal, &populations, jobs, &ids))
            .collect();
        let mut flags: Vec<Option<Severity>> = vec![None; jobs.len()];
        for (named, signal) in named.iter().zip(&signals) {
            for &index in named {
                let flag = &mut flags[index];
                *flag = Some(flag.map_or(signal.severity, |worst| worst.min(signal.severity)));
            }
        }
        let order = display_order(&ranked, &flags);
        let mut finding_rows = BTreeMap::new();
        for (index, row) in snapshot.findings.iter().enumerate() {
            finding_rows.entry(row.id.clone()).or_insert(index);
        }
        let count = |severity| {
            signals
                .iter()
                .filter(|signal| signal.severity == severity)
                .count()
        };
        let (critical, warnings) = (count(Severity::Critical), count(Severity::Warning));
        let group_summaries = snapshot
            .failure_groups
            .iter()
            .map(|group| GroupSummary {
                target: group
                    .findings
                    .iter()
                    .position(|id| {
                        finding_rows
                            .get(id)
                            .and_then(|&index| snapshot.findings.get(index))
                            .is_some_and(|row| !row.resolved)
                    })
                    .or_else(|| (!group.findings.is_empty()).then_some(0)),
                runs: runs_summary(&group.runs, RUNS_WIDTH),
                profiles: group.profiles.join(","),
            })
            .collect();
        let mut keys: [Vec<String>; Tab::ALL.len()] = Default::default();
        let mut texts: [Vec<String>; Tab::ALL.len()] = Default::default();
        keys[Tab::Signals.index()] = signals.iter().map(Signal::key).collect();
        texts[Tab::Signals.index()] = signals
            .iter()
            .map(|signal| {
                format!(
                    "{} {} {} {}",
                    signal.title,
                    signal.detail,
                    signal.domain.name(),
                    signal.detector
                )
                .to_lowercase()
            })
            .collect();
        keys[Tab::Profiles.index()] = profile_keys;
        texts[Tab::Profiles.index()] = profile_texts;
        keys[Tab::Findings.index()] = snapshot
            .failure_groups
            .iter()
            .map(FailureGroup::key)
            .collect();
        texts[Tab::Findings.index()] = snapshot
            .failure_groups
            .iter()
            .map(|group| {
                format!(
                    "{} {} {} {} {}",
                    group.kind,
                    group.identity.as_deref().unwrap_or(""),
                    group.cause.as_deref().unwrap_or(""),
                    group.profiles.join(" "),
                    group.findings.join(" ")
                )
                .to_lowercase()
            })
            .collect();
        let mut drillable: [Vec<bool>; Tab::ALL.len()] = Default::default();
        drillable[Tab::Signals.index()] = named.iter().map(|jobs| !jobs.is_empty()).collect();
        drillable[Tab::Findings.index()] = snapshot
            .failure_groups
            .iter()
            .map(|group| {
                group
                    .findings
                    .iter()
                    .any(|id| job_of(id, &snapshot.jobs, &ids).is_some())
            })
            .collect();
        let mut labels: Vec<(String, u64)> = totals
            .by_label
            .iter()
            .map(|(label, count)| (label.clone(), *count))
            .collect();
        labels.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        let mut worst = BTreeMap::new();
        for signal in &signals {
            let entry = worst.entry(signal.detector).or_insert(signal.severity);
            *entry = (*entry).min(signal.severity);
        }
        Self {
            snapshot,
            outcomes,
            flags,
            signals,
            matrix,
            totals,
            critical,
            warnings,
            profile_summary,
            group_summaries,
            drillable,
            labels,
            worst,
            named,
            finding_rows,
            ids,
            populations,
            order,
            keys,
            texts,
            attempts,
            history_error,
            altered: BTreeSet::new(),
        }
    }

    /// The index in `snapshot.jobs` of the first job with `id`.
    fn job(&self, id: &str) -> Option<usize> {
        self.ids.find(&self.snapshot.jobs, id).next()
    }

    /// The signals that name the job `id`, in signal order.
    pub fn naming(&self, id: &str) -> impl Iterator<Item = &Signal> {
        self.job(id)
            .into_iter()
            .flat_map(|job| naming(&self.named, job))
            .map(|index| &self.signals[index])
    }

    /// The worst severity among the signals that name the job `id`.
    pub fn flag(&self, id: &str) -> Option<Severity> {
        self.flags[self.job(id)?]
    }

    /// Whether the signal at `signal` names the job `id`.
    pub(crate) fn names(&self, signal: usize, id: &str) -> bool {
        self.job(id)
            .is_some_and(|job| self.named[signal].binary_search(&job).is_ok())
    }

    /// A mask over `snapshot.jobs`: true at each job whose id is in `ids`.
    pub(crate) fn job_mask<'a>(&self, ids: impl IntoIterator<Item = &'a String>) -> Vec<bool> {
        let jobs = &self.snapshot.jobs;
        let mut mask = vec![false; jobs.len()];
        for id in ids {
            for index in self.ids.find(jobs, id) {
                mask[index] = true;
            }
        }
        mask
    }

    /// The jobs a failure group's findings name.
    pub(crate) fn group_jobs(&self, group: &FailureGroup) -> BTreeSet<String> {
        group
            .findings
            .iter()
            .filter_map(|id| job_of(id, &self.snapshot.jobs, &self.ids))
            .map(str::to_owned)
            .collect()
    }
}

/// Every job index in display order: flagged jobs first, the worst flag
/// first, then unflagged jobs, each group in `ranked` order. A flag takes
/// its severity's declaration position, so a stable partition of `ranked`
/// by flag sorts by (flag, then `ranked`'s keys).
fn display_order(ranked: &[u32], flags: &[Option<Severity>]) -> Vec<u32> {
    let group = |index: u32| flags[index as usize].map_or(3, |severity| severity as u8);
    let mut order = Vec::with_capacity(ranked.len());
    for wanted in 0..=3 {
        order.extend(
            ranked
                .iter()
                .copied()
                .filter(|&index| group(index) == wanted),
        );
    }
    order
}

/// The runs of a failure group in `width` columns: the sorted distinct runs
/// when they fit, otherwise their count and range.
fn runs_summary(runs: &[u64], width: usize) -> String {
    let runs: BTreeSet<u64> = runs.iter().copied().collect();
    if runs.len() * 2 <= width + 1 {
        let joined = runs
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(",");
        if joined.len() <= width {
            return joined;
        }
    }
    match (runs.first(), runs.last()) {
        (Some(first), Some(last)) => format!("{} runs {first}-{last}", runs.len()),
        _ => String::new(),
    }
}
