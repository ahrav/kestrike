//! A locked snapshot projects bound coverage, held records and selected-attempt resources.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde_json::{Value, json};

use super::coverage::{Coverage, Declaration, metric};
use super::measurement::{MeasuredAttempt, totals};
use super::{Error, held, name};
use crate::protocol::{Listing, Summary};
use crate::record::{
    Admission, Artifact, Class, Configuration, Digest, JobResult, Pin, Purpose, ResourceBounds,
    Started, Text,
};
use crate::store::{Dir, View};

/// The diagnostic for a state-root entry outside the declared record kinds.
pub(in crate::campaign) const UNDECLARED: &str = "record kind is undeclared";

/// Reports a lock-only snapshot. Busy returns exit 3; overflowing totals return exit 4.
pub fn report(path: &Path) -> Result<Value, Error> {
    let view = View::snapshot(path)?;
    project(&view)
}

pub(in crate::campaign) fn project(view: &View) -> Result<Value, Error> {
    snapshot(view).map(|snapshot| snapshot.projection)
}

pub(in crate::campaign) struct Snapshot {
    pub(in crate::campaign) projection: Value,
    pub(in crate::campaign) hardware: Option<View>,
    pub(in crate::campaign) histories: BTreeMap<String, VerifiedHistory>,
}

pub(in crate::campaign) struct VerifiedHistory {
    pub(in crate::campaign) purpose: Purpose,
    pub(in crate::campaign) targeted: bool,
    /// Entry `i` describes attempt number `i + 1`.
    pub(in crate::campaign) attempts: Vec<VerifiedAttempt>,
}

#[derive(Clone, Copy)]
pub(in crate::campaign) struct VerifiedAttempt {
    pub(in crate::campaign) directory: (u64, u64),
    /// Unfinished attempts, finding completions and named captures keep their evidence.
    pub(in crate::campaign) rooted: bool,
}

pub(in crate::campaign) fn snapshot(view: &View) -> Result<Snapshot, Error> {
    view.require_state_marker()?;
    let mut held_rows = Vec::new();
    for entry in super::super::projection::entries(view, view.root(), "state", &mut held_rows)? {
        if ![
            "jobs",
            "attempts",
            "probes",
            "findings",
            "triage",
            "calibrations",
            "capacity",
            "corpus",
            "hardware",
            "config.json",
        ]
        .contains(&entry.as_str())
        {
            held(
                &mut held_rows,
                entry.as_str(),
                Error::Held(UNDECLARED.into()),
            )?;
        }
    }
    let (hardware_view, hardware) = match crate::hardware::rows(view, &mut held_rows) {
        Ok(rows) => rows,
        Err(error @ Error::Store(crate::store::Error::Busy)) => return Err(error),
        Err(error) => {
            held(&mut held_rows, "hardware", error)?;
            (None, Vec::new())
        }
    };
    let mut listings = probes(view, &mut held_rows)?;
    let mut findings = finding_rows(view, &mut held_rows)?;
    let (triage, candidates) = super::super::triage::project(view, &mut held_rows)?;
    let config = match view.read_record::<Configuration>(view.root(), &name("config.json")) {
        Ok(Some(config)) => match view.barrier(config.read()) {
            Ok(()) => Some(config.record().clone()),
            Err(error) => {
                held(&mut held_rows, "config.json", error.into())?;
                None
            }
        },
        Ok(None) => None,
        Err(error) => {
            held(&mut held_rows, "config.json", error.into())?;
            None
        }
    };
    let super::calibrations::Calibrations {
        rows: calibrations,
        qualified: capacities,
        refused,
    } = super::calibrations::project(view, config.as_ref(), &mut held_rows)?;
    let corpus = super::super::corpus::project(view, &mut held_rows)?;
    if let Some(row) = held_rows.iter().find(|row| row["path"] == "corpus") {
        findings.rows.push(json!({"id": "corpus", "held": row["reason"], "held_code": row["held_code"], "blocker": true}));
        findings.blockers.push("corpus".into());
    }
    let mut profiles = BTreeMap::new();
    let mut jobs = Vec::new();
    let mut targeted = Vec::new();
    let mut job_ids = BTreeSet::new();
    let mut measurements = Vec::new();
    let mut histories = BTreeMap::new();
    {
        let mut ids = BTreeSet::new();
        super::each_shard(view, crate::layout::JOBS, &mut held_rows, |shard, rows| {
            let path = &shard.path;
            for entry in super::super::projection::entries(view, &shard.dir, path, rows)? {
                let id = super::super::admission::job_id(entry.as_str());
                match id.filter(|id| shard.holds(id)) {
                    Some(id) if Digest::parse(id).is_some() => {
                        ids.insert(id.to_owned());
                    }
                    _ => held(
                        rows,
                        &format!("{path}/{}", entry.as_str()),
                        Error::Held("job entry has an invalid identity or suffix".into()),
                    )?,
                }
            }
            Ok(())
        })?;
        // Verified histories hold records and stream text, no descriptors,
        // so the pass over every job stays within one job's descriptors.
        let mut verified = BTreeMap::new();
        for id in &ids {
            let checked = (|| -> Result<_, Error> {
                let root = &crate::layout::jobs(view, id)?
                    .ok_or_else(|| Error::Held("job shard vanished".into()))?;
                let admission = super::super::show::verified_job(view, root, id)?;
                let build =
                    Digest::parse(admission.record().job().experiment().pins.build.as_str())
                        .ok_or_else(|| Error::Held("invalid build digest".into()))?;
                let job = admission.record();
                let attempts =
                    verify_history(view, job, root, id, &findings).and_then(|mut attempts| {
                        if let Some(own) = attempts.listing.take() {
                            check_version(&own, job)?;
                            match listings.get(&build) {
                                None => {
                                    listings.insert(build, own);
                                }
                                Some(cached) if cached != &own => attempts.listing = Some(own),
                                Some(_) => {}
                            }
                        }
                        let listing =
                            governing(job, attempts.listing.as_ref(), listings.get(&build))?;
                        if let (Some(selected), Some(listing)) = (&mut attempts.selected, listing) {
                            selected.summarize(listing);
                        }
                        Ok(attempts)
                    });
                Ok((admission.record().clone(), build, attempts))
            })();
            verified.insert(id.clone(), checked);
        }
        for (id, mut checked) in verified {
            job_ids.insert(id.clone());
            let history = match &mut checked {
                Ok((job, _, Ok(attempts))) => Some(VerifiedHistory {
                    targeted: job.target().is_some(),
                    purpose: job.purpose(),
                    attempts: std::mem::take(&mut attempts.verified),
                }),
                _ => None,
            };
            let published = match &checked {
                Ok((_, _, Ok(attempts))) => attempts.result.is_some(),
                _ => match crate::layout::jobs(view, &id)
                    .map_err(Error::from)
                    .and_then(|root| {
                        let root = root.ok_or_else(|| Error::Held("job shard vanished".into()))?;
                        Ok(view.identity(&root, &name(&format!("{id}{}", JobResult::SUFFIX)))?)
                    }) {
                    Ok(result) => result.is_some(),
                    Err(error) => {
                        held(
                            &mut held_rows,
                            &crate::layout::job_file(&id, &format!("{id}{}", JobResult::SUFFIX))
                                .display()
                                .to_string(),
                            error,
                        )?;
                        true
                    }
                },
            };
            let checked = (|| -> Result<Value, Error> {
                let (job, build, mut attempts) = checked?;
                let job = &job;
                let experiment = job.job().experiment();
                let own = attempts.as_mut().ok().and_then(|a| a.listing.take());
                let cached = listings.get(&build);
                let history = attempts.and_then(|attempts| {
                    let listing = governing(job, own.as_ref(), cached)?;
                    project_history(job, &id, attempts, listing, &findings)
                });
                let listing = cached.filter(|listing| check_version(listing, job).is_ok());
                let support = listing
                    .and_then(|l| l.profile(experiment.profile.as_str()))
                    .map_or("unknown".to_owned(), |p| p.support.clone());
                if let Some(target) = &experiment.target {
                    let history = history?;
                    if let Some(measured) = history.measured {
                        measurements.push(Some(measured));
                    }
                    targeted.push(json!({"id": id, "target": target, "corpus_version": job.corpus_version(), "credited": history.credit, "judgment": history.row["targeted"].clone()}));
                    return Ok(history.row);
                }
                let declaration = Declaration {
                    build,
                    class: experiment.class.clone(),
                    counts: Some(experiment.counts.clone()),
                    generator: experiment.generator.clone(),
                    minima: experiment.minima.clone(),
                    profile: experiment.profile.clone(),
                    support,
                    declared: listing
                        .and_then(|listing| listing.profile(experiment.profile.as_str()))
                        .is_some(),
                    unsupported_dimensions: unavailable(
                        listing.and_then(|l| l.cluster(experiment.profile.as_str())),
                    ),
                };
                let coverage = match profiles.entry(declaration.clone()) {
                    std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        entry.insert(Coverage::new(declaration)?)
                    }
                };
                coverage.jobs.push(id.clone());
                match history {
                    Ok(history) => {
                        coverage.ran |= history.ran;
                        if history.credit {
                            coverage.credit(
                                id.clone(),
                                history
                                    .measured
                                    .as_ref()
                                    .expect("credited job has a published operand")
                                    .attempt,
                                history.summary.as_ref(),
                            );
                        }
                        if let Some(measured) = history.measured {
                            measurements.push(Some(measured));
                        }
                        Ok(history.row)
                    }
                    Err(error) => {
                        coverage.ran = true;
                        Err(error)
                    }
                }
            })();
            match checked {
                Ok(row) => {
                    jobs.push(row);
                    if let Some(history) = history {
                        histories.insert(id, history);
                    }
                }
                Err(error) => {
                    if published {
                        measurements.push(None);
                    }
                    held(&mut held_rows, &format!("jobs/{id}"), error)?;
                    jobs.push(json!({"id": id, "state": "held"}));
                }
            }
        }
    }
    super::each_shard(
        view,
        crate::layout::ATTEMPTS,
        &mut held_rows,
        |shard, rows| {
            let path = &shard.path;
            for entry in super::super::projection::entries(view, &shard.dir, path, rows)? {
                if !job_ids.contains(entry.as_str()) || !shard.holds(entry.as_str()) {
                    held(
                        rows,
                        &format!("{path}/{}", entry.as_str()),
                        Error::Held("attempt history lacks an admission".into()),
                    )?;
                }
            }
            Ok(())
        },
    )?;
    seed_profiles(&listings, &mut profiles, &mut held_rows)?;
    qualify_profiles(&mut profiles, &capacities, &refused);
    let profiles: Vec<_> = profiles
        .into_values()
        .map(Coverage::row)
        .collect::<Result<_, _>>()?;
    let unqualified: Vec<_> = profiles
        .iter()
        .filter(|row| row["qualified"] == false)
        .cloned()
        .collect();
    let metrics = totals(&measurements)?;
    if let Some(hardware_view) = &hardware_view
        && !hardware_view.current().map_err(crate::store::Error::from)?
    {
        return Err(crate::store::Error::Replaced.into());
    }
    if !view.current().map_err(crate::store::Error::from)? {
        return Err(Error::Store(crate::store::Error::Replaced));
    }
    Ok(Snapshot {
        projection: json!({"profiles": profiles, "unqualified": unqualified, "jobs": jobs,
        "totals": {"population": "each published job selected attempt", "population_completeness": if held_rows.iter().any(|row| row["path"].as_str().is_some_and(|path| path == "state" || path == "jobs" || path.starts_with("jobs/") || path == "attempts" || path.starts_with("attempts/"))) { "unknown" } else { "complete" }, "metrics": metrics},
        "config": config, "held": held_rows, "findings": findings.rows, "release_blockers": findings.blockers,
        "triage": triage, "regression_candidates": candidates, "targeted": targeted, "calibrations": calibrations, "corpus": corpus, "hardware": hardware}),
        hardware: hardware_view,
        histories,
    })
}

struct JobHistory {
    row: Value,
    measured: Option<MeasuredAttempt>,
    credit: bool,
    summary: Option<Summary>,
    ran: bool,
}

/// The listing-independent facts of one job's history: every attempt is
/// verified once, and the selected completion, result, pin and resources
/// are bound to that verification. The facts are records and text, so a
/// history keeps no descriptor open after verification.
struct Attempts {
    rows: Vec<Value>,
    selected: Option<Selected>,
    result: Option<JobResult>,
    pin: Option<Pin>,
    resources: Option<ResourceBounds>,
    uncaptured: bool,
    ran: bool,
    /// The capability listing the selected completion's bound evidence declares.
    listing: Option<Listing>,
    verified: Vec<VerifiedAttempt>,
}

/// The selected completion of a job's history, with its bound `inspect`
/// stream read and digest-checked once.
struct Selected {
    finished: crate::record::Finished,
    artifact: Option<Artifact>,
    inspect: Option<String>,
    summary: Option<Summary>,
    targeted: Option<Value>,
}

impl Selected {
    fn summarize(&mut self, listing: &Listing) {
        if let Some(text) = self.inspect.take() {
            self.summary = Summary::parse(&text, listing).ok();
        }
    }
}

fn verify_history(
    view: &View,
    job: &Admission,
    jobs: &Dir,
    id: &str,
    findings: &FindingHistory,
) -> Result<Attempts, Error> {
    let mut rows = Vec::new();
    let mut outcomes = Vec::new();
    let mut selected = None;
    let mut first_failure = None;
    let mut uncaptured = false;
    let mut ran = false;
    let mut verified = Vec::new();
    if let Some((root, maximum)) = crate::attempt::history(view, job)? {
        for number in 1..=maximum {
            let (directory, record) = crate::attempt::read_attempt(view, job, &root, number)?;
            view.barrier(record.read())?;
            if view
                .read_record::<crate::record::Finished>(&directory, &name("finished"))?
                .is_none()
            {
                ran |= crate::attempt::pending_started(view, &directory, record.record())?;
                rows.push(json!({"number": number, "state": "inconclusive", "reason": "attempt is unfinished", "attempt": record.record()}));
                verified.push(VerifiedAttempt {
                    directory: directory.identity(),
                    rooted: true,
                });
                continue;
            }
            ran |= view
                .read_record::<Started>(&directory, &name("started"))?
                .is_some();
            let found =
                crate::attempt::read_completed(view, &directory, record.record(), job.command())?;
            let captured = crate::attempt::capture_recorded(view, &directory, found.finished())?;
            if findings
                .finished
                .get(found.finished().record().attempt.as_str())
                .is_some_and(|finish| finish != found.finished().record())
            {
                return Err(Error::Held(
                    "finding differs from verified attempt finish".into(),
                ));
            }
            let class = found.finished().record().class;
            let finding = found.has_finding();
            verified.push(VerifiedAttempt {
                directory: directory.identity(),
                rooted: finding || captured == Some(true),
            });
            uncaptured |= finding
                && (captured.is_none()
                    || !findings
                        .recorded
                        .contains(found.finished().record().attempt.as_str()));
            uncaptured |= found
                .bound()
                .and_then(|bound| bound.targeted())
                .is_some_and(|judged| {
                    judged.children.iter().any(|child| {
                        !findings.recorded.contains(
                            child
                                .finding_id(&found.finished().record().attempt)
                                .as_str(),
                        )
                    })
                });
            rows.push(json!({"number": number, "finished": found.finished().record(), "artifact": found.bound().map(|b| b.artifact())}));
            outcomes.push((number, class));
            if first_failure.is_none() {
                if crate::attempt::pins(class) {
                    first_failure = Some(number);
                }
                selected = Some((number, directory, found));
            }
        }
    }
    let result =
        view.read_record::<JobResult>(jobs, &name(&format!("{id}{}", JobResult::SUFFIX)))?;
    let pin = view.read_record::<Pin>(jobs, &name(&format!("{id}{}", Pin::SUFFIX)))?;
    let failed = crate::attempt::selected_failure(outcomes.iter().copied())?;
    let expected = selected.as_ref().map(|(number, _, done)| JobResult {
        attempt: *number,
        finished: done.finished().record().clone(),
        job: job.job().id().digest(),
        manifest: job.job().manifest_sha256(),
    });
    if let Some(pin) = &pin {
        view.barrier(pin.read())?;
        if failed.is_none() || Some(&pin.record().result) != expected.as_ref() {
            return Err(Error::Held(
                "pin differs from verified failure history".into(),
            ));
        }
    }
    if let Some(bound) = selected.as_ref().and_then(|(_, _, done)| done.bound())
        && bound.artifact().archive != Digest::parse(job.job().experiment().pins.build.as_str())
    {
        return Err(Error::Held("artifact build differs from job".into()));
    }
    let listing = selected
        .as_ref()
        .map(|(_, directory, done)| capabilities(view, directory, done))
        .transpose()?
        .flatten();
    let mut resources = None;
    if let Some(result) = &result {
        view.barrier(result.read())?;
        if Some(result.record()) != expected.as_ref()
            || rows.len() != outcomes.len()
            || failed.is_some() && pin.is_none()
        {
            return Err(Error::Held(
                "result differs from verified selected outcome".into(),
            ));
        }
        let (_, directory, done) = selected.as_ref().expect("result selected a completion");
        resources = Some(
            if let Some(record) =
                view.read_record::<ResourceBounds>(directory, &name("resources"))?
            {
                view.barrier(record.read())?;
                if super::super::calibration::measured(done, record.record().wall_us)
                    != *record.record()
                {
                    return Err(Error::Held("selected resource binding differs".into()));
                }
                record.record().clone()
            } else {
                super::super::calibration::measured(done, None)
            },
        );
    }
    let selected = selected
        .map(|(_, directory, done)| -> Result<Selected, Error> {
            Ok(Selected {
                finished: done.finished().record().clone(),
                artifact: done.bound().map(|bound| bound.artifact().clone()),
                inspect: stream(view, &directory, &done, "inspect")?,
                summary: None,
                targeted: done.bound().and_then(|bound| bound.targeted()).map(|judged| json!({"printed": judged.printed, "credited": judged.credited, "leaves": judged.leaves.map(|(printed, counting)| json!({"printed": printed, "counting": counting})), "failed": judged.children})),
            })
        })
        .transpose()?;
    Ok(Attempts {
        rows,
        selected,
        result: result.map(|result| result.record().clone()),
        pin: pin.map(|pin| pin.record().clone()),
        resources,
        uncaptured,
        ran,
        listing,
        verified,
    })
}

fn check_version(listing: &Listing, job: &Admission) -> Result<(), Error> {
    if job.job().experiment().capabilities.as_str() == listing.capabilities.to_string() {
        Ok(())
    } else {
        Err(Error::Held(
            "capability version differs from frozen job".into(),
        ))
    }
}

fn governing<'a>(
    job: &Admission,
    own: Option<&'a Listing>,
    cached: Option<&'a Listing>,
) -> Result<Option<&'a Listing>, Error> {
    let listing = own.or(cached);
    if let Some(listing) = listing {
        check_version(listing, job)?;
    }
    Ok(listing)
}

/// `project_history` parses a deferred inspection with the build listing supplied by another job.
fn project_history(
    job: &Admission,
    id: &str,
    attempts: Attempts,
    listing: Option<&Listing>,
    findings: &FindingHistory,
) -> Result<JobHistory, Error> {
    let Attempts {
        rows,
        mut selected,
        result,
        pin,
        resources,
        uncaptured,
        ran,
        listing: _,
        verified: _,
    } = attempts;
    let selected_summary = match (&mut selected, listing) {
        (Some(selected), Some(listing)) => {
            selected.summarize(listing);
            selected.summary.take()
        }
        _ => None,
    };
    let mut measured = None;
    let mut credit = false;
    let listing_available = listing
        .and_then(|listing| listing.profile(job.job().experiment().profile.as_str()))
        .is_some_and(|profile| profile.support == "implemented");
    let inspection_reason = selected
        .as_ref()
        .and_then(|selected| selected.artifact.as_ref())
        .and_then(|artifact| {
            if artifact
                .workers
                .keys()
                .any(|phase| phase.as_str() == "inspect")
            {
                match selected_summary.as_ref() {
                    None => Some("bound inspection facts are unavailable"),
                    Some(summary)
                        if summary.profile.as_deref()
                            != Some(job.job().experiment().profile.as_str()) =>
                    {
                        Some("bound inspection names another profile")
                    }
                    Some(summary)
                        if artifact.summary.as_ref().is_none_or(|copied| {
                            copied.digest != summary.digest
                                || copied.decisions != summary.decisions
                                || copied.counts != summary.counts
                                || copied.terminal.as_str() != summary.terminal.to_string()
                                || copied.identity.as_ref().map(Text::as_str)
                                    != summary.identity.as_ref().map(|identity| identity.as_str())
                                || copied.cause.as_ref().map(Text::as_str)
                                    != summary.cause.as_deref()
                                || copied.ledger.as_ref().map(Text::as_str)
                                    != summary.ledger.as_ref().map(|ledger| ledger.verdict())
                        }) =>
                    {
                        Some("bound inspection differs from recorded summary")
                    }
                    Some(_) => None,
                }
            } else {
                None
            }
        });
    let mut reason = "job is unpublished";
    if let (Some(result), Some(resources)) = (&result, resources) {
        let done = selected.as_ref().expect("result selected a completion");
        // Summary metrics come from the inspection the row attributes;
        // kernel resources are measured independently of it.
        let trusted = selected_summary
            .as_ref()
            .filter(|_| inspection_reason.is_none());
        measured = Some(MeasuredAttempt {
            job: job.job().id().digest(),
            attempt: result.attempt,
            resources,
            virtual_us: trusted.and_then(|s| metric(s, "virtual_us")),
            skipped_us: trusted.and_then(|s| metric(s, "skipped_us")),
        });
        let distrusted = findings.incomplete
            || findings
                .invalidated
                .get(&job.job().id().digest())
                .is_some_and(|numbers| numbers.iter().any(|number| *number <= result.attempt));
        credit = inspection_reason.is_none()
            && listing_available
            && super::coverage::supports_credit(job.job().experiment().class.as_ref())
            && done.finished.class == Class::Pass
            && done.artifact.is_some()
            && !findings.incomplete
            && !distrusted
            && !uncaptured;
        reason = if let Some(reason) = inspection_reason {
            reason
        } else if !listing_available {
            "capability declaration is unavailable"
        } else if findings.incomplete {
            "finding census is incomplete"
        } else if distrusted {
            "finding history withholds credit"
        } else if uncaptured {
            "failure capture is incomplete"
        } else if credit {
            "bound passing outcome"
        } else {
            "bound outcome provides no pass credit"
        };
    }
    Ok(JobHistory {
        row: json!({"id": id, "state": if measured.is_some() && listing_available && inspection_reason.is_none() { "measured" } else { "inconclusive" }, "admission": job, "attempts": rows, "result": result, "pin": pin, "targeted": selected.as_ref().and_then(|selected| selected.targeted.as_ref()), "credited": credit, "reason": reason}),
        measured,
        credit,
        summary: selected_summary,
        ran,
    })
}

/// Reads and digest-checks the bound `{phase}.stdout` stream of `completed`.
/// Returns `None` when the completion is unbound, its artifact records no
/// such phase, the attempt has no artifacts directory, or the stream bytes
/// are not UTF-8.
pub(super) fn stream(
    view: &View,
    directory: &Dir,
    completed: &crate::attempt::Completed,
    phase: &str,
) -> Result<Option<String>, Error> {
    let Some(bound) = completed.bound() else {
        return Ok(None);
    };
    let Some(worker) = bound
        .artifact()
        .workers
        .iter()
        .find(|(key, _)| key.as_str() == phase)
        .map(|(_, worker)| worker)
    else {
        return Ok(None);
    };
    let Some(artifacts) = view.open_dir(directory, &name("artifacts"))? else {
        return Ok(None);
    };
    let directory = view
        .open_dir(&artifacts, &name(bound.artifact().run_id.as_str()))?
        .ok_or_else(|| Error::Held("bound artifact directory missing".into()))?;
    let read = view
        .read(
            &directory,
            &name(&format!("{phase}.stdout")),
            crate::sim::OUTPUT as u64,
        )?
        .ok_or_else(|| Error::Held("bound summary stream missing".into()))?;
    view.barrier(&read)?;
    if worker.stdout != Digest::of(read.bytes()) {
        return Err(Error::Held("summary stream digest differs".into()));
    }
    Ok(String::from_utf8(read.bytes().to_vec()).ok())
}

/// A capability listing requires a bound artifact with at least two worker entries
/// and a `capabilities` worker that exited with code 0 and no signal.
fn capabilities(
    view: &View,
    directory: &Dir,
    completed: &crate::attempt::Completed,
) -> Result<Option<Listing>, Error> {
    let passed_closing_checks = completed.bound().is_some_and(|bound| {
        bound.artifact().workers.len() > 1
            && bound
                .artifact()
                .workers
                .iter()
                .find(|(phase, _)| phase.as_str() == "capabilities")
                .is_some_and(|(_, worker)| {
                    worker.ended.as_str() == "exited"
                        && worker.exit == Some(0)
                        && worker.signal.is_none()
                })
    });
    if !passed_closing_checks {
        return Ok(None);
    }
    let stdout = stream(view, directory, completed, "capabilities")?
        .ok_or_else(|| Error::Held("bound capabilities stdout is missing or not UTF-8".into()))?;
    Listing::parse(&stdout)
        .map(Some)
        .map_err(|e| Error::Held(format!("bound capabilities listing refused: {e:?}")))
}

fn probes(view: &View, held_rows: &mut Vec<Value>) -> Result<BTreeMap<Digest, Listing>, Error> {
    let mut listings = BTreeMap::new();
    let Some(root) = super::root(view, "probes", held_rows)? else {
        return Ok(listings);
    };
    for entry in super::super::projection::entries(view, &root, "probes", held_rows)? {
        if crate::campaign::corpus::is_probe(entry.as_str()) {
            continue;
        }
        let checked = (|| -> Result<(Digest, Listing), Error> {
            let directory = view
                .open_dir(&root, &entry)?
                .ok_or_else(|| Error::Held("probe missing".into()))?;
            super::super::probe::build_listing(
                view,
                &directory,
                &super::super::text(entry.as_str())?,
            )
        })();
        match checked {
            Ok((build, listing)) => {
                listings.insert(build, listing);
            }
            Err(error) => held(held_rows, &format!("probes/{}", entry.as_str()), error)?,
        }
    }
    Ok(listings)
}

struct FindingHistory {
    rows: Vec<Value>,
    blockers: Vec<String>,
    recorded: BTreeSet<String>,
    invalidated: BTreeMap<Digest, Vec<u64>>,
    incomplete: bool,
    finished: BTreeMap<String, crate::record::Finished>,
}

fn finding_rows(view: &View, held_rows: &mut Vec<Value>) -> Result<FindingHistory, Error> {
    let mut history = FindingHistory {
        rows: Vec::new(),
        blockers: Vec::new(),
        recorded: BTreeSet::new(),
        invalidated: BTreeMap::new(),
        incomplete: false,
        finished: BTreeMap::new(),
    };
    if let Some(root) = super::root(view, "findings", held_rows)? {
        let parents = super::super::lineage::Parents::default();
        for entry in super::super::projection::entries(view, &root, "findings", held_rows)? {
            let id = entry.as_str();
            history.recorded.insert(id.to_owned());
            match super::super::findings::row(view, &root, &entry, &parents) {
                Ok(mut row) => {
                    if !row.targeted {
                        row.data
                            .as_object_mut()
                            .expect("finding row is an object")
                            .remove("triage");
                    }
                    if row.invalidates && row.ordinary_attempt {
                        history
                            .invalidated
                            .entry(row.job)
                            .or_default()
                            .push(row.attempt);
                    }
                    history.finished.insert(id.to_owned(), row.finished);
                    if row.blocker {
                        history.blockers.push(id.to_owned());
                    }
                    history.rows.push(row.data);
                }
                Err(error) => {
                    let reason = error.to_string();
                    held(held_rows, &format!("findings/{id}"), error)?;
                    if let Some((job, number)) = parent_attempt(id) {
                        history.invalidated.entry(job).or_default().push(number);
                    }
                    history.blockers.push(id.to_owned());
                    history
                        .rows
                        .push(json!({"id": id, "held": reason, "blocker": true}));
                }
            }
        }
    }
    history.incomplete |= held_rows.iter().any(|row| row["path"] == "findings");
    if let Err(error) = super::super::findings::uncaptured(
        view,
        super::super::findings::Known::default(),
        &history.recorded,
        &mut history.rows,
        &mut history.blockers,
    ) {
        let id = "findings/pending-capture";
        history.incomplete = true;
        history
            .rows
            .push(json!({"id": id, "held": error.to_string(), "blocker": true}));
        history.blockers.push(id.into());
        held(held_rows, id, error)?;
    }
    Ok(history)
}

fn unavailable(cluster: Option<&crate::protocol::Declared>) -> BTreeSet<String> {
    cluster
        .and_then(|cluster| cluster.field("unavailable"))
        .into_iter()
        .flat_map(|names| names.split(','))
        .map(str::to_owned)
        .collect()
}

fn seed_profiles(
    listings: &BTreeMap<Digest, Listing>,
    profiles: &mut BTreeMap<Declaration, Coverage>,
    held_rows: &mut Vec<Value>,
) -> Result<(), Error> {
    for (build, listing) in listings {
        for profile in &listing.profiles {
            if profiles
                .keys()
                .any(|row| row.build == *build && row.profile.as_str() == profile.name)
            {
                continue;
            }
            let checked = (|| -> Result<Coverage, Error> {
                let cluster = listing.cluster(&profile.name);
                let field = |key| {
                    cluster
                        .map(|cluster| {
                            cluster
                                .field(key)
                                .ok_or_else(|| {
                                    Error::Held(format!("cluster declaration requires {key}"))
                                })
                                .and_then(super::super::text)
                        })
                        .transpose()
                };
                let declaration = Declaration {
                    build: *build,
                    class: Text::new(profile.class.name()),
                    counts: None,
                    generator: field("generator")?,
                    minima: field("minima")?,
                    profile: Text::new(&profile.name).ok_or_else(|| {
                        Error::Held("listed profile requires printable ASCII".into())
                    })?,
                    support: profile.support.clone(),
                    declared: true,
                    unsupported_dimensions: unavailable(cluster),
                };
                Coverage::new(declaration)
            })();
            match checked {
                Ok(row) => {
                    profiles.insert(row.declaration.clone(), row);
                }
                Err(error) => held(
                    held_rows,
                    &format!("probes/{build}/{}", profile.name),
                    error,
                )?,
            }
        }
    }
    Ok(())
}

/// Qualifies each declared profile whose contract a capacity in `capacities`
/// serves; a profile whose contract appears in `refused` takes that reason.
pub(super) fn qualify_profiles(
    profiles: &mut BTreeMap<Declaration, Coverage>,
    capacities: &[crate::record::Capacity],
    refused: &BTreeMap<Digest, &'static str>,
) {
    for coverage in profiles.values_mut() {
        if !coverage.declaration.declared {
            coverage.qualified = false;
            coverage.qualification = "capability declaration is unavailable".into();
            continue;
        }
        if let Some(counts) = &coverage.declaration.counts {
            let contract = crate::record::CalibrationContract {
                build: coverage.declaration.build,
                counts: counts.clone(),
                profile: coverage.declaration.profile.clone(),
            };
            if capacities
                .iter()
                .any(|capacity| capacity.contract() == &contract)
            {
                coverage.qualified = true;
                coverage.qualification =
                    "calibrated capacity matches build, profile and frozen counts".into();
            } else if let Some(reason) = refused.get(&contract.key()) {
                coverage.qualification = (*reason).into();
            }
        } else {
            coverage.qualification = "capacity qualification requires frozen counts".into();
        }
    }
}

fn parent_attempt(id: &str) -> Option<(Digest, u64)> {
    let (job, tail) = id.split_once('-')?;
    Some((
        Digest::parse(job)?,
        super::super::findings::attempt_number(&crate::store::Name::new(tail.split('-').next()?)?)
            .ok()?,
    ))
}

#[cfg(test)]
mod lineage_tests {
    #[test]
    fn held_child_ids_attribute_the_actual_job_and_attempt() {
        let job = crate::record::Digest::of(b"job");
        for suffix in ["0001", "0001-c0-0", "0001-n2", "0001-l3"] {
            assert_eq!(
                super::parent_attempt(&format!("{job}-{suffix}")),
                Some((job, 1))
            );
        }
        assert_eq!(
            super::parent_attempt(&format!("{job}-calibration-replay-0001")),
            None
        );
        for suffix in ["0", "1", "+001", "00001"] {
            assert_eq!(super::parent_attempt(&format!("{job}-{suffix}-c0-0")), None);
        }
    }
}
