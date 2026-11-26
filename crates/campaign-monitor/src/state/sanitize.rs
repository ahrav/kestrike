//! Display text for one snapshot: every string the views can show is made
//! display text once, and each string that changed is recorded, so a view
//! can tell that its display form is not the value a command needs. Job
//! rows are first scanned read-only on up to [`parallel::THREADS`] threads;
//! the jobs the scan finds holding a control character are rewritten with
//! `text::sanitize`. `job_texts` is the one list of a job's display strings
//! that both the scan and the rewrite visit.

use std::collections::BTreeSet;

use serde_json::Value;

use crate::parallel;
use crate::signals::{JOBS_PER_THREAD, Signal};
use crate::snapshot::{AttemptRow, Finish, Job, Settled, Sim, Snapshot};
use crate::tui::text::{clean, is_clean};

/// Calls `$visit` on every string of `$job` the views can show. `$job` is a
/// `&Job` or a `&mut Job`, and `$visit` takes a `&String` or a
/// `&mut String` to match.
macro_rules! job_texts {
    ($job:expr, $visit:expr) => {{
        let Job {
            id,
            held,
            profile,
            campaign,
            build,
            class,
            variant,
            result,
            attempts,
            ..
        } = $job;
        let mut visit = $visit;
        for text in [id, profile, campaign, build, variant] {
            visit(text);
        }
        for text in [held, class].into_iter().flatten() {
            visit(text);
        }
        if let Some(Settled { class, held, .. }) = result {
            for text in [class, held].into_iter().flatten() {
                visit(text);
            }
        }
        for AttemptRow {
            entry,
            attempt,
            finding,
            held,
            finished,
            sim,
            ..
        } in attempts
        {
            for text in [entry, attempt, finding, held].into_iter().flatten() {
                visit(text);
            }
            if let Some(Finish { class, binding, .. }) = finished {
                visit(class);
                visit(binding);
            }
            if let Some(Sim {
                class,
                command,
                reason,
                terminal,
                cause,
                identity,
                ledger,
                unsuccessful,
                held,
                ..
            }) = sim
            {
                for text in [
                    class,
                    command,
                    reason,
                    terminal,
                    cause,
                    identity,
                    ledger,
                    unsuccessful,
                    held,
                ]
                .into_iter()
                .flatten()
                {
                    visit(text);
                }
            }
        }
    }};
}

/// The indices, ascending, of the jobs holding a display string that
/// sanitizing would change; read on up to [`parallel::THREADS`] threads.
pub(super) fn unclean_jobs(jobs: &[Job]) -> Vec<usize> {
    let runs = parallel::runs(jobs, JOBS_PER_THREAD, |run| {
        let unclean: Vec<usize> = run
            .iter()
            .enumerate()
            .filter(|(_, job)| {
                let mut unclean = false;
                job_texts!(*job, |text: &String| unclean |= !is_clean(text));
                unclean
            })
            .map(|(index, _)| index)
            .collect();
        (run.len(), unclean)
    });
    let mut offset = 0;
    let mut unclean = Vec::new();
    for (len, run) in runs {
        unclean.extend(run.into_iter().map(|index| offset + index));
        offset += len;
    }
    unclean
}

/// Sanitizes every string the views can show in `snapshot` and `signals`
/// and returns the display forms that differ from the text as fetched.
/// `unclean` holds the [`unclean_jobs`] of `snapshot.jobs`; every other
/// job's strings already are display text.
pub(super) fn sanitize(
    snapshot: &mut Snapshot,
    signals: &mut [Signal],
    unclean: &[usize],
) -> BTreeSet<String> {
    let mut altered = BTreeSet::new();
    for &index in unclean {
        job_texts!(&mut snapshot.jobs[index], |text: &mut String| note(
            text,
            &mut altered
        ));
    }
    sanitize_snapshot(snapshot, &mut altered);
    for signal in signals {
        for text in [&mut signal.title, &mut signal.detail]
            .into_iter()
            .chain(&mut signal.subjects)
        {
            note(text, &mut altered);
        }
    }
    altered
}

/// Sanitizes `text` in place, adding its display form to `altered` when
/// sanitizing changed it.
fn note(text: &mut String, altered: &mut BTreeSet<String>) {
    if clean(text) {
        altered.insert(text.clone());
    }
}

fn note_all<'a>(texts: impl IntoIterator<Item = &'a mut String>, altered: &mut BTreeSet<String>) {
    for text in texts {
        note(text, altered);
    }
}

/// Every string the views can show from `snapshot` outside its job rows,
/// made display text.
fn sanitize_snapshot(snapshot: &mut Snapshot, altered: &mut BTreeSet<String>) {
    note(&mut snapshot.state, altered);
    if let Some(held) = snapshot.config.as_mut().and_then(|row| row.held.as_mut()) {
        note(held, altered);
    }
    let variants = std::mem::take(&mut snapshot.variants);
    snapshot.variants = variants
        .into_iter()
        .map(|(mut name, counts)| {
            note(&mut name, altered);
            let counts = counts
                .into_iter()
                .map(|(mut key, value)| {
                    note(&mut key, altered);
                    (key, value)
                })
                .collect();
            (name, counts)
        })
        .collect();
    for row in &mut snapshot.findings {
        note(&mut row.id, altered);
        note_all(row.held.as_mut(), altered);
        for value in row
            .verified
            .iter_mut()
            .chain(row.triage.iter_mut())
            .chain(row.dispositions.iter_mut())
        {
            sanitize_value(value, altered);
        }
    }
    note_all(&mut snapshot.release_blockers, altered);
    if let Some(lock) = &mut snapshot.lock {
        note_all(lock.unknown.as_mut(), altered);
        for holder in lock.holders.iter_mut().flatten() {
            note(&mut holder.mode, altered);
            note_all(holder.command.as_mut(), altered);
        }
    }
    for group in &mut snapshot.failure_groups {
        note(&mut group.kind, altered);
        note_all(group.identity.as_mut(), altered);
        note_all(group.cause.as_mut(), altered);
        note_all(&mut group.findings, altered);
        note_all(&mut group.profiles, altered);
    }
}

fn sanitize_value(value: &mut Value, altered: &mut BTreeSet<String>) {
    match value {
        Value::String(text) => note(text, altered),
        Value::Array(items) => {
            for item in items {
                sanitize_value(item, altered);
            }
        }
        Value::Object(fields) => {
            for item in fields.values_mut() {
                sanitize_value(item, altered);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// A job with a value in every display string, each one clean.
    fn full_job() -> serde_json::Value {
        json!({
            "id": "j", "held": "h", "profile": "p", "campaign": "c", "build": "b", "class": "k",
            "variant": "v", "state": "settled",
            "result": {"attempt": 1, "class": "pass", "held": "rh"},
            "attempts": [{
                "number": 1, "entry": "e", "attempt": "a", "finding": "f", "held": "ah",
                "finished": {"class": "fc", "binding": "fb"},
                "sim": {"class": "sc", "command": "sm", "reason": "sr", "terminal": "st",
                        "cause": "sx", "identity": "si", "ledger": "sl", "unsuccessful": "su",
                        "held": "sh"},
            }],
        })
    }

    /// Every display string of a job, one at a time, makes the scan flag
    /// that job and only it, and sanitizing the flagged job leaves each of
    /// its strings clean, with the rewritten form recorded as altered.
    #[test]
    fn the_scan_flags_a_control_character_in_every_display_string_of_a_job() {
        let paths: [&[&str]; 24] = [
            &["id"],
            &["held"],
            &["profile"],
            &["campaign"],
            &["build"],
            &["class"],
            &["variant"],
            &["result", "class"],
            &["result", "held"],
            &["attempts", "0", "entry"],
            &["attempts", "0", "attempt"],
            &["attempts", "0", "finding"],
            &["attempts", "0", "held"],
            &["attempts", "0", "finished", "class"],
            &["attempts", "0", "finished", "binding"],
            &["attempts", "0", "sim", "class"],
            &["attempts", "0", "sim", "command"],
            &["attempts", "0", "sim", "reason"],
            &["attempts", "0", "sim", "terminal"],
            &["attempts", "0", "sim", "cause"],
            &["attempts", "0", "sim", "identity"],
            &["attempts", "0", "sim", "ledger"],
            &["attempts", "0", "sim", "unsuccessful"],
            &["attempts", "0", "sim", "held"],
        ];
        for path in paths {
            let mut dirty = full_job();
            let mut field = &mut dirty;
            for step in path {
                field = match step.parse::<usize>() {
                    Ok(index) => &mut field[index],
                    Err(_) => &mut field[*step],
                };
            }
            *field = json!("x\ty\u{1b}");
            let jobs: Vec<Job> = [full_job(), dirty, full_job()]
                .into_iter()
                .map(|job| serde_json::from_value(job).unwrap())
                .collect();
            assert_eq!(unclean_jobs(&jobs), [1], "{path:?}");
            let mut snapshot = crate::state::tests::parsed(json!({ "jobs": [] }));
            snapshot.jobs = jobs;
            let altered = sanitize(&mut snapshot, &mut [], &[1]);
            assert_eq!(
                altered.into_iter().collect::<Vec<_>>(),
                ["x       y\\u{1b}"],
                "{path:?}"
            );
            assert!(unclean_jobs(&snapshot.jobs).is_empty(), "{path:?}");
        }
    }

    /// Indices count from the start of the whole job array across the runs
    /// the scan reads on separate threads.
    #[test]
    fn the_scan_returns_indices_into_the_whole_array_across_its_runs() {
        let count = 5 * JOBS_PER_THREAD + 3;
        let dirty = [0, JOBS_PER_THREAD + 1, 3 * JOBS_PER_THREAD - 1, count - 1];
        let jobs: Vec<Job> = (0..count)
            .map(|index| Job {
                id: format!("{index}"),
                profile: if dirty.contains(&index) {
                    "a\u{7}".into()
                } else {
                    "a".into()
                },
                ..Job::default()
            })
            .collect();
        assert_eq!(unclean_jobs(&jobs), dirty);
    }
}
