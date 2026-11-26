//! Which jobs each signal and failure group names. Subjects name jobs by
//! id, record path, attempt or finding id, or, for a seed-sensitive signal,
//! by workload; names are matched in their sanitized display form.

use super::ids::IdIndex;
use super::populations::Populations;
use crate::parallel;
use crate::signals::Signal;
use crate::snapshot::Job;
use crate::tui::text::clean;

/// Subjects per thread when a signal's subjects are looked up in parallel.
const SUBJECTS_PER_THREAD: usize = 512;

/// The job id a signal subject names, and the stem tried when no job has
/// that id. A subject is `jobs/<id>`, `attempts/<id>`, a bare job id, or an
/// attempt or finding id `<id>-<suffix>`, `<id>.<suffix>` or
/// `<id>/<suffix>`, and a held-record subject adds ` (<reason>)`.
fn subject_names(subject: &str) -> (&str, &str) {
    let subject = subject
        .strip_prefix("jobs/")
        .or_else(|| subject.strip_prefix("attempts/"))
        .unwrap_or(subject);
    let reason = subject.as_bytes().windows(2).position(|pair| pair == b" (");
    let subject = reason.map_or(subject, |at| &subject[..at]);
    let suffix = subject
        .bytes()
        .position(|byte| matches!(byte, b'-' | b'.' | b'/'));
    (subject, suffix.map_or(subject, |at| &subject[..at]))
}

/// The id of the job a signal subject names, among `jobs` indexed by
/// `ids`, as [`subject_names`] reads it.
pub(crate) fn job_of<'a>(subject: &str, jobs: &'a [Job], ids: &IdIndex) -> Option<&'a str> {
    let (name, stem) = subject_names(subject);
    ids.get(jobs, name).or_else(|| ids.get(jobs, stem))
}

/// Appends to `named` the indices of every job with the id [`job_of`]
/// finds for `subject`.
fn push_subject_jobs(subject: &str, jobs: &[Job], ids: &IdIndex, named: &mut Vec<usize>) {
    let (name, stem) = subject_names(subject);
    let before = named.len();
    named.extend(ids.find(jobs, name));
    if named.len() == before {
        named.extend(ids.find(jobs, stem));
    }
}

/// The indices in `jobs`, ascending and distinct, of the jobs `signal`
/// names. A `seed-sensitive` subject names a workload as a JSON array of
/// campaign, profile, build and variant and names the workload's jobs;
/// other subjects name jobs through [`job_of`]. A job is named when its id
/// is, so jobs that share an id are named together.
pub(crate) fn signal_jobs(
    signal: &Signal,
    populations: &Populations,
    jobs: &[Job],
    ids: &IdIndex,
) -> Vec<usize> {
    let mut named = Vec::new();
    if signal.detector != "seed-sensitive" {
        named = parallel::runs(&signal.subjects, SUBJECTS_PER_THREAD, |subjects| {
            let mut named = Vec::new();
            for subject in subjects {
                push_subject_jobs(subject, jobs, ids, &mut named);
            }
            named
        })
        .concat();
    } else {
        for mut names in signal
            .subjects
            .iter()
            .filter_map(|subject| serde_json::from_str::<[String; 4]>(subject).ok())
        {
            for name in &mut names {
                clean(name);
            }
            let [campaign, profile, build, variant] = names;
            let workload = populations.jobs(jobs, |job| {
                job.campaign == campaign
                    && job.profile == profile
                    && job.build == build
                    && job.variant == variant
            });
            for index in workload {
                named.extend(ids.find(jobs, &jobs[index].id));
            }
        }
    }
    named.sort_unstable();
    named.dedup();
    named
}

/// The indices of the signals that name the job at `job`, in signal order,
/// given each signal's [`signal_jobs`] in `named`.
pub(crate) fn naming(named: &[Vec<usize>], job: usize) -> impl Iterator<Item = usize> + '_ {
    named
        .iter()
        .enumerate()
        .filter(move |(_, jobs)| jobs.binary_search(&job).is_ok())
        .map(|(index, _)| index)
}
