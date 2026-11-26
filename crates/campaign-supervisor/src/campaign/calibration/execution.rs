//! A calibration plan fixes job inputs and custody limits for its numbered attempts.

use super::{Error, contract, controls, directory, name, replay, text, verdict};
use crate::attempt::{self, Attempt, Completed, Launch};
use crate::custody::{Custody, Timing};
use crate::protocol::{Class as ProfileClass, Expected, Listing, Run, Summary};
use crate::record::{
    Admission, Calibration, CalibrationEvidence, CalibrationPlan, CalibrationVerdict, Capacity,
    Class, Configuration, Digest, Purpose, ResourceBounds, Verified,
};
use crate::store::{Dir, ReadStore, Store};
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

pub(super) fn wait(
    custody: &mut Custody,
    running: crate::custody::Running,
) -> Result<(crate::custody::Stopped, Option<crate::custody::Error>), Error> {
    match custody.wait_any(vec![running]) {
        Ok(waited) => Ok((waited.stopped, None)),
        Err(error) => {
            let mut retained = custody.take_retained();
            match retained.pop() {
                Some(running) => Ok((custody.stop(running)?, Some(error))),
                None => Err(error.into()),
            }
        }
    }
}

fn job(store: &impl ReadStore, admission: &Admission) -> Result<Verified<Admission>, Error> {
    let jobs = crate::layout::jobs(store, &admission.job().id().to_string())?
        .ok_or_else(|| Error::Held("calibration jobs missing".into()))?;
    let found = store
        .read_record::<Admission>(&jobs, &name(&format!("{}.json", admission.job().id())))?
        .ok_or_else(|| Error::Held("calibration admission missing".into()))?;
    if found.record() != admission {
        return Err(Error::Held("calibration admission differs".into()));
    }
    store.barrier(found.read())?;
    Ok(found)
}

fn attempt_directory(store: &Store, admission: &Admission, number: u64) -> Result<Dir, Error> {
    let root = crate::layout::attempts(store, &admission.job().id().to_string())?
        .ok_or_else(|| Error::Held("attempt root missing".into()))?;
    store
        .open_dir(&root, &name(&format!("{number:04}")))?
        .ok_or_else(|| Error::Held("calibration attempt missing".into()))
}

pub(in crate::campaign) fn measured(completed: &Completed, elapsed: Option<u64>) -> ResourceBounds {
    let kernel = &completed.finished().record().kernel;
    let counter = |map: &BTreeMap<crate::record::Text, u64>, key| {
        map.get(&text(key).expect("counter name is ASCII")).copied()
    };
    ResourceBounds {
        cpu_us: counter(&kernel.cpu, "usage_usec"),
        memory_bytes: counter(&kernel.memory, "peak"),
        pids: counter(&kernel.pids, "peak"),
        wall_us: elapsed,
    }
}

pub(super) fn evidence(
    store: &Store,
    directory: &Dir,
    completed: &Completed,
    job: Digest,
    elapsed: Option<u64>,
) -> Result<CalibrationEvidence, Error> {
    let resources = match store.read_record::<ResourceBounds>(directory, &name("resources"))? {
        Some(found) => {
            store.barrier(found.read())?;
            found.record().clone()
        }
        None => {
            let resources = measured(completed, elapsed);
            super::super::once(store, directory, "resources", &resources)?;
            resources
        }
    };
    let mut outcome = snapshot(completed, job);
    outcome.resources = resources;
    Ok(outcome)
}

pub(super) fn snapshot(completed: &Completed, job: Digest) -> CalibrationEvidence {
    CalibrationEvidence {
        artifact: completed.bound().map(|bound| bound.artifact().clone()),
        finished: completed.finished().record().clone(),
        job,
        product: attempt::finding_kind(completed.finished().record(), completed.bound())
            .filter(|kind| kind.release_blocker()),
        resources: measured(completed, None),
    }
}

pub(super) fn retained_product(
    store: &impl ReadStore,
    finished: &crate::record::Finished,
) -> Result<bool, Error> {
    let Some(findings) = store.open_dir(store.root(), &name("findings"))? else {
        return Ok(false);
    };
    let Some(directory) = store.open_dir(&findings, &name(finished.attempt.as_str()))? else {
        return Ok(false);
    };
    let finding = store
        .read_record::<crate::record::Finding>(&directory, &name("finding.json"))?
        .ok_or_else(|| Error::Held("retained calibration finding missing".into()))?;
    store.barrier(finding.read())?;
    if finding.record().finished != *finished {
        return Err(Error::Held("retained calibration finish differs".into()));
    }
    Ok(finding.record().kind.release_blocker())
}

pub(super) fn control_disagreed(
    store: &impl ReadStore,
    admission: &Admission,
) -> Result<bool, Error> {
    let Some(root) = crate::layout::attempts(store, &admission.job().id().to_string())? else {
        return Ok(false);
    };
    for entry in store.list(&root, crate::scan_bound())? {
        let directory = store
            .open_dir(&root, &entry)?
            .ok_or_else(|| Error::Held("control attempt missing".into()))?;
        if let Some(finished) =
            store.read_record::<crate::record::Finished>(&directory, &name("finished"))?
        {
            store.barrier(finished.read())?;
            if finished.record().class == Class::Disagreement
                || !verdict::product_class(finished.record().class)
                    && retained_product(store, finished.record())?
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

pub(in crate::campaign) fn partial_defect(
    store: &impl ReadStore,
    plan: &CalibrationPlan,
) -> Result<bool, Error> {
    let directory = directory(store, plan.healthy.job().id().digest())?;
    if let Some(lost) = store.read_record::<crate::record::Finished>(&directory, &name("lost"))? {
        store.barrier(lost.read())?;
        if verdict::product_class(lost.record().class) || retained_product(store, lost.record())? {
            return Ok(true);
        }
    }
    let mut original = None;
    if let Some(completed) = latest(store, &plan.healthy)? {
        let healthy = snapshot(&completed, plan.healthy.job().id().digest());
        if verdict::product_class(completed.finished().record().class)
            || healthy.product.is_some()
            || verdict::null_original(&healthy)
        {
            return Ok(true);
        }
        original = completed
            .bound()
            .and_then(|bound| bound.artifact().summary.clone());
        if healthy.finished.class == Class::Pass
            && plan.healthy.job().experiment().minima.is_some()
            && let Some(listing) = raw(store, &healthy, "capabilities.stdout")?
                .and_then(|raw| Listing::parse(&raw).ok())
            && let Some(summary) = inspect(store, &listing, &healthy)?
            && reached(plan, Some(&summary))?
                .iter()
                .any(|(_, required, reached)| reached.is_some_and(|reached| reached < *required))
        {
            return Ok(true);
        }
    }
    for control in controls::declared(plan.healthy.job().experiment().profile.as_str()) {
        let Some(admission) = plan.controls.get(&text(control.profile)?) else {
            continue;
        };
        if control_disagreed(store, admission)? {
            return Ok(true);
        }
        let Some(completed) = latest(store, admission)? else {
            continue;
        };
        let evidence = snapshot(&completed, admission.job().id().digest());
        if evidence.finished.class == Class::Pass || evidence.finished.class == Class::Disagreement
        {
            return Ok(true);
        }
        if !verdict::product_class(evidence.finished.class) && evidence.product.is_none() {
            continue;
        }
        let listing =
            raw(store, &evidence, "capabilities.stdout")?.and_then(|raw| Listing::parse(&raw).ok());
        let Some(listing) = listing else {
            return Ok(true);
        };
        if !detected(store, &listing, control, &evidence)? {
            return Ok(true);
        }
    }
    for evidence in replay::partial(store, plan)? {
        if verdict::replay_defect(original.as_ref(), &evidence) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn launch(config: &Configuration, executable: &Path) -> Launch {
    Launch {
        gate: executable.into(),
        launcher: executable.into(),
        environment: BTreeMap::new(),
        limits: super::super::configuration::limits(config),
    }
}

fn capture(
    store: &Store,
    admission: &Admission,
    completed: &Completed,
    directory: &Dir,
    root: Digest,
) -> Result<(), Error> {
    let attempt = store
        .read_record::<crate::record::Attempt>(directory, &name("attempt"))?
        .ok_or_else(|| Error::Held("calibration attempt missing".into()))?;
    crate::attempt::capture(store, admission, completed, directory, &attempt, Some(root))?;
    Ok(())
}

fn retry(outcome: &CalibrationEvidence, settled: bool, number: u64, limit: u64) -> bool {
    outcome.finished.class != Class::Disagreement
        && outcome.product.is_none()
        && !settled
        && number < limit
}

fn run_job(
    store: &Store,
    custody: &mut Custody,
    admission: &Admission,
    config: &Configuration,
    executable: &Path,
    root: Digest,
) -> Result<CalibrationEvidence, Error> {
    loop {
        let current = Attempt::current(store, job(store, admission)?)?;
        if let Some(current) = current {
            let number = current.number();
            let completed = current.reconcile(store, custody, attempt::EVIDENCE_BOUND)?;
            let directory = attempt_directory(store, admission, number)?;
            capture(store, admission, &completed, &directory, root)?;
            let outcome = evidence(
                store,
                &directory,
                &completed,
                admission.job().id().digest(),
                None,
            )?;
            let settled = attempt::settle(store, job(store, admission)?, completed)?.is_some();
            if !retry(
                &outcome,
                settled,
                number,
                admission.job().experiment().attempts,
            ) {
                return Ok(outcome);
            }
        }
        custody.check_release()?;
        capacity(store, custody, config)?;
        let (running_attempt, running) = attempt::start_calibration(
            store,
            custody,
            job(store, admission)?,
            launch(config, executable),
        )?;
        let number = running_attempt.number();
        let (stopped, wait_error) = wait(custody, running)?;
        let elapsed = stopped
            .elapsed_ms()
            .and_then(|value| value.checked_mul(1000));
        let completed = running_attempt.finish(store, stopped, attempt::EVIDENCE_BOUND)?;
        let directory = attempt_directory(store, admission, number)?;
        capture(store, admission, &completed, &directory, root)?;
        let outcome = evidence(
            store,
            &directory,
            &completed,
            admission.job().id().digest(),
            elapsed,
        )?;
        let settled = attempt::settle(store, job(store, admission)?, completed)?.is_some();
        if let Some(error) = wait_error {
            return Err(error.into());
        }
        if !retry(
            &outcome,
            settled,
            number,
            admission.job().experiment().attempts,
        ) {
            return Ok(outcome);
        }
    }
}

fn raw(
    store: &impl ReadStore,
    evidence: &CalibrationEvidence,
    entry: &str,
) -> Result<Option<String>, Error> {
    if evidence.finished.binding != crate::record::Binding::Matching || evidence.artifact.is_none()
    {
        return Ok(None);
    }
    let number = evidence
        .finished
        .attempt
        .as_str()
        .rsplit_once('-')
        .and_then(|(_, n)| n.parse::<u64>().ok())
        .ok_or_else(|| Error::Held("calibration evidence identity malformed".into()))?;
    let job = crate::layout::attempts(store, &evidence.job.to_string())?
        .ok_or_else(|| Error::Held("calibration job evidence missing".into()))?;
    let attempt = store
        .open_dir(&job, &name(&format!("{number:04}")))?
        .ok_or_else(|| Error::Held("calibration attempt evidence missing".into()))?;
    let Some(artifacts) = store.open_dir(&attempt, &name("artifacts"))? else {
        return Ok(None);
    };
    let Some(directory) = store.open_dir(&artifacts, &name(evidence.finished.attempt.as_str()))?
    else {
        return Ok(None);
    };
    store
        .read(&directory, &name(entry), crate::sim::OUTPUT as u64)?
        .map(|read| {
            let phase = entry.strip_suffix(".stdout").unwrap_or(entry);
            let expected = evidence
                .artifact
                .as_ref()
                .and_then(|artifact| {
                    artifact
                        .workers
                        .iter()
                        .find(|(name, _)| name.as_str() == phase)
                })
                .map(|(_, worker)| worker.stdout)
                .ok_or_else(|| Error::Held("calibration stream digest missing".into()))?;
            if Digest::of(read.bytes()) != expected {
                return Err(Error::Held("calibration stream digest differs".into()));
            }
            store.barrier(&read)?;
            Ok(String::from_utf8(read.bytes().to_vec()).ok())
        })
        .transpose()
        .map(Option::flatten)
}

fn inspect(
    store: &impl ReadStore,
    listing: &Listing,
    evidence: &CalibrationEvidence,
) -> Result<Option<Summary>, Error> {
    Ok(raw(store, evidence, "inspect.stdout")?
        .and_then(|output| Summary::parse(&output, listing).ok()))
}

fn reached(
    plan: &CalibrationPlan,
    summary: Option<&Summary>,
) -> Result<Vec<(crate::record::Text, u64, Option<u64>)>, Error> {
    let Some(minima) = plan.healthy.job().experiment().minima.as_ref() else {
        return Ok(Vec::new());
    };
    super::super::minima::parse(minima)?
        .into_iter()
        .map(|(key, count)| {
            let reached = summary
                .and_then(|summary| summary.cluster.as_ref())
                .and_then(|cluster| cluster.drawn.as_ref())
                .and_then(|drawn| {
                    crate::protocol::COVERAGE
                        .iter()
                        .position(|name| *name == key.as_str())
                        .map(|index| u64::from(drawn.coverage[index]))
                });
            Ok((key, count, reached))
        })
        .collect()
}

fn detected(
    store: &impl ReadStore,
    listing: &Listing,
    control: &controls::Control,
    evidence: &CalibrationEvidence,
) -> Result<bool, Error> {
    let summary = inspect(store, listing, evidence)?;
    let panic =
        raw(store, evidence, "run.stdout")?.and_then(|raw| match Run::parse(&raw, listing) {
            Ok(Run::Panicked(identity)) => Some(identity),
            _ => None,
        });
    Ok(controls::detected(
        control,
        evidence,
        summary.as_ref(),
        panic.as_deref(),
    ))
}

fn minima(
    record: &mut Calibration,
    plan: &CalibrationPlan,
    summary: Option<&Summary>,
) -> Result<(), Error> {
    if record.healthy.finished.class != Class::Pass {
        return Ok(());
    }
    for (key, count, reached) in reached(plan, summary)? {
        if reached.is_none_or(|reached| reached < count) {
            let reason = text(&format!(
                "healthy control does not reach frozen minimum {}={count}",
                key.as_str()
            ))?;
            if reached.is_some_and(|reached| reached < count) {
                record.defects.push(reason.clone());
            }
            record.reasons.push(reason);
        }
    }
    Ok(())
}

/// Admits one calibration start against the ancestor limits, the backlog
/// and the storage pauses.
///
/// # Errors
///
/// The ancestor fit's error; the backlog hold, or a backlog count error,
/// when failure pins without a resolved disposition reach `backlog`;
/// [`Error::Bound`], [`Error::Census`] or [`Error::Store`] when the
/// charged census holds; and
/// [`Error::Rejected`] naming the storage dimensions that pause it.
pub(super) fn capacity(
    store: &Store,
    custody: &Custody,
    config: &Configuration,
) -> Result<(), Error> {
    capacity_counted(store, custody, config, &mut None)
}

fn capacity_counted(
    store: &Store,
    custody: &Custody,
    config: &Configuration,
    census: &mut Option<crate::campaign::census::Census>,
) -> Result<(), Error> {
    super::super::dispatch::ancestor_fit(
        custody,
        super::super::configuration::limits(config),
        config,
    )?;
    super::super::dispatch::backlog_hold(config, super::super::dispatch::backlog(store)?)?;
    let pauses = super::super::dispatch::storage_pauses(
        config,
        crate::campaign::census::Census::cached(census, store)?.usage(store, config)?,
        0,
        config.value("reserve_slots"),
    );
    if pauses.is_empty() {
        Ok(())
    } else {
        Err(Error::Rejected(format!("calibration paused: {pauses:?}")))
    }
}

pub(super) fn control_scope(
    contract: &crate::record::CalibrationContract,
    config: &Configuration,
) -> Digest {
    #[derive(serde::Serialize)]
    struct Scope<'a> {
        contract: &'a crate::record::CalibrationContract,
        limits: &'a BTreeMap<crate::record::Text, u64>,
    }
    Digest::of(
        &serde_json::to_vec(&Scope {
            contract,
            limits: config.config(),
        })
        .expect("control scope encodes"),
    )
}

fn admit_profile(
    store: &Store,
    probed: &super::super::probe::Probed,
    request: &super::super::Request,
    profile: crate::record::Text,
    scope: Option<Digest>,
) -> Result<super::super::Outcome, Error> {
    let frozen = super::super::Request {
        profile,
        campaign: text("calibration")?,
        run: request.run,
        attempts: 2,
        counts: request.counts.clone(),
    };
    let archive = text(
        probed
            .archive
            .to_str()
            .ok_or_else(|| Error::Rejected("archive path must be ASCII".into()))?,
    )?;
    match scope {
        Some(scope) => super::super::admission::admit_control(
            store,
            &probed.listing,
            probed.pins.clone(),
            archive,
            &frozen,
            scope,
        ),
        None => super::super::admit(
            store,
            &probed.listing,
            probed.pins.clone(),
            archive,
            &frozen,
            Purpose::Calibration,
        ),
    }
}

fn lost_check(
    store: &Store,
    custody: &mut Custody,
    directory: &Dir,
    plan: &CalibrationPlan,
    executable: &Path,
) -> Result<crate::record::Finished, Error> {
    if let Some(found) = store.read_record::<crate::record::Finished>(directory, &name("lost"))? {
        store.barrier(found.read())?;
        return Ok(found.record().clone());
    }
    let current = Attempt::current(store, job(store, &plan.healthy)?)?;
    let attempt = match current {
        Some(current) if current.number() == 1 => current,
        Some(_) => {
            return Err(Error::Held(
                "lost check missing before later healthy attempt".into(),
            ));
        }
        None => {
            capacity(store, custody, &plan.config)?;
            let (attempt, running) = attempt::start_calibration(
                store,
                custody,
                job(store, &plan.healthy)?,
                launch(&plan.config, executable),
            )?;
            if let Err(error) = custody.stop_for_reconcile(running) {
                if let Some(running) = custody.take_retained().pop() {
                    let stopped = custody.stop(running)?;
                    let completed = attempt.finish(store, stopped, attempt::EVIDENCE_BOUND)?;
                    capture(
                        store,
                        &plan.healthy,
                        &completed,
                        &attempt_directory(store, &plan.healthy, 1)?,
                        plan.healthy.job().id().digest(),
                    )?;
                    super::super::once(store, directory, "lost", completed.finished().record())?;
                }
                return Err(error.into());
            }
            attempt
        }
    };
    let completed = attempt.reconcile(store, custody, attempt::EVIDENCE_BOUND)?;
    capture(
        store,
        &plan.healthy,
        &completed,
        &attempt_directory(store, &plan.healthy, 1)?,
        plan.healthy.job().id().digest(),
    )?;
    let lost = completed.finished().record().clone();
    super::super::once(store, directory, "lost", &lost)?;
    Ok(lost)
}

pub(in crate::campaign) fn execute(
    store: &Store,
    archive: &Path,
    root: &Path,
    request: &super::super::Request,
    watchdog: Duration,
) -> Result<Calibration, Error> {
    let config = store
        .read_record::<Configuration>(store.root(), &name("config.json"))?
        .ok_or_else(|| Error::Rejected("calibration needs a configuration".into()))?;
    store.barrier(config.read())?;
    let config = config.record();
    let timing = Timing {
        poll: Duration::from_millis(10),
        kill_wait: Duration::from_secs(5),
        watchdog: Duration::from_secs(config.value("wall")),
    };
    let mut custody = Custody::open(root, timing)?;
    super::super::probe::reconcile_records(store, &mut custody)?;
    let mut census = None;
    super::super::triage::reconcile_counted(store, &mut custody, &mut census)?;
    super::super::dispatch::recover_counted(store, &mut custody, &mut census)?;
    custody.check_release()?;
    capacity_counted(store, &custody, config, &mut census)?;
    drop(custody);
    let probed = super::super::probe::probe(store, archive, root, watchdog)?;
    let listing = &probed.listing;
    let profile = listing
        .profile(request.profile.as_str())
        .ok_or_else(|| Error::Rejected("profile is not listed".into()))?;
    if matches!(
        profile.class,
        ProfileClass::Control | ProfileClass::Recovery
    ) || profile
        .expected
        .is_some_and(|expected| expected != Expected::Pass)
    {
        return Err(Error::Rejected(
            "calibration requires a healthy non-recovery profile".into(),
        ));
    }
    let first = admit_profile(store, &probed, request, request.profile.clone(), None)?;
    let second = admit_profile(store, &probed, request, request.profile.clone(), None)?;
    let mut plan = CalibrationPlan {
        config: config.clone(),
        controls: BTreeMap::new(),
        deduplicated: first.record == second.record && second.existing,
        healthy: first.record,
        missing: Vec::new(),
    };
    let declared = controls::declared(request.profile.as_str());
    if declared.is_empty() {
        plan.missing
            .push(text("no fault controls declared for this profile")?)
    }
    if request.profile.as_str() == "cluster-pressure" {
        plan.missing
            .push(text("early slot reuse has no declared control")?)
    }
    for control in declared {
        if listing.profile(control.profile).is_none() {
            plan.missing
                .push(text(&format!("missing fault control {}", control.profile))?);
            continue;
        }
        let admitted = admit_profile(
            store,
            &probed,
            request,
            text(control.profile)?,
            Some(control_scope(&contract(&plan)?, config)),
        )?;
        plan.controls
            .insert(text(control.profile)?, admitted.record);
    }
    let id = plan.healthy.job().id().digest();
    let directory = retain_root(store, id)?;
    if let Some(found) = store.read_record::<Calibration>(&directory, &name("result"))? {
        if found.record().contract != contract(&plan)? || found.record().root != id {
            return Err(Error::Held("sealed calibration contract differs".into()));
        }
        let frozen = store
            .read_record::<CalibrationPlan>(&directory, &name("plan"))?
            .ok_or_else(|| Error::Held("sealed calibration plan missing".into()))?;
        store.barrier(frozen.read())?;
        if frozen.record().config != plan.config {
            return Err(Error::Rejected(
                "sealed calibration limits differ; use a fresh run".into(),
            ));
        }
        store.barrier(found.read())?;
        publish_capacity(store, found.record())?;
        return Ok(found.record().clone());
    }
    super::super::once(store, &directory, "plan", &plan)?;
    let executable = crate::store::canonical_host(Path::new("/proc/self/exe"))
        .map_err(|error| Error::Held(error.to_string()))?;
    let mut custody = Custody::open(root, timing)?;
    custody
        .validate_limits(super::super::configuration::limits(config), 1)
        .map_err(|error| match error {
            crate::store::cgroup::FitError::Io(error) => {
                Error::Store(crate::store::Error::Io(error))
            }
            error => Error::Rejected(format!("calibration ancestor capacity: {error:?}")),
        })?;
    let lost = lost_check(store, &mut custody, &directory, &plan, &executable)?;
    let lost_product = retained_product(store, &lost)?;
    let healthy = run_job(store, &mut custody, &plan.healthy, config, &executable, id)?;
    let mut record = Calibration {
        contract: contract(&plan)?,
        controls: BTreeMap::new(),
        defects: if lost_product {
            vec![text("lost attempt recorded a bound product failure")?]
        } else {
            Vec::new()
        },
        detected: Vec::new(),
        healthy,
        lost,
        missing: plan.missing.clone(),
        reasons: Vec::new(),
        replays: Vec::new(),
        root: id,
        verdict: CalibrationVerdict::Uncalibrated,
    };
    if !plan.deduplicated {
        record
            .reasons
            .push(text("duplicate admission created two jobs")?)
    }
    let summary = inspect(store, listing, &record.healthy)?;
    minima(&mut record, &plan, summary.as_ref())?;
    for control in declared {
        let Some(admission) = plan.controls.get(&text(control.profile)?) else {
            continue;
        };
        let evidence = run_job(store, &mut custody, admission, config, &executable, id)?;
        if detected(store, listing, control, &evidence)? {
            record.detected.push(text(control.profile)?);
        } else {
            record.reasons.push(text(&format!(
                "fault control {} failed otherwise or passed: {}",
                control.profile,
                evidence.finished.class.name()
            ))?);
        }
        if control_disagreed(store, admission)? {
            record.defects.push(text(&format!(
                "fault control {} recorded a disagreement",
                control.profile
            ))?);
        }
        record.controls.insert(text(control.profile)?, evidence);
        resolve_controls(store, &record)?;
    }
    if record.healthy.finished.class == Class::Pass
        && record
            .healthy
            .artifact
            .as_ref()
            .is_some_and(|artifact| artifact.bundle.is_some())
    {
        for number in 1..=2 {
            record.replays.push(replay::execute(
                store,
                &mut custody,
                &plan,
                &record.healthy,
                number,
                &executable,
            )?);
        }
    }
    if !record.healthy.resources.fits(config, 1) {
        record.missing.push(text(
            "complete resource measurements within the custody limits are missing",
        )?)
    }
    record.detected.sort();
    verdict::finish(&mut record)?;
    super::super::once(store, &directory, "result", &record)?;
    publish_capacity(store, &record)?;
    Ok(record)
}

fn publish_capacity(store: &Store, record: &Calibration) -> Result<(), Error> {
    let root = directory(store, record.root)?;
    let plan = store
        .read_record::<CalibrationPlan>(&root, &name("plan"))?
        .ok_or_else(|| Error::Held("capacity calibration plan missing".into()))?;
    store.barrier(plan.read())?;
    let config = &plan.record().config;
    resolve_controls(store, record)?;
    if !verdict::complete(record) {
        return Ok(());
    }
    let bounds = &record.healthy.resources;
    let cores = bounds
        .cpu_us
        .zip(bounds.wall_us)
        .filter(|(_, wall)| *wall > 0)
        .map(|(cpu, wall)| cpu.div_ceil(wall))
        .filter(|cores| *cores > 0);
    let Some(cores) = cores else { return Ok(()) };
    let shares = config
        .value("cores")
        .checked_div(cores)
        .unwrap_or(0)
        .min(config.value("memory") / config.value("tree_memory"));
    let slots = shares.saturating_sub(config.value("reserve_slots"));
    if slots == 0 || !bounds.fits(config, slots) {
        return Ok(());
    }
    let resources = serde_json::to_vec(record).expect("calibration encodes");
    let capacity = Capacity::new(
        record.contract.clone(),
        Digest::of(&resources),
        bounds.clone(),
        record.root,
        slots,
        config.clone(),
    )
    .map_err(|error| Error::Held(error.to_string()))?;
    store.mkdir(store.root(), &name("capacity"))?;
    let directory = store
        .open_dir(store.root(), &name("capacity"))?
        .expect("capacity directory is present");
    let key = record.contract.key().to_string();
    store.mkdir(&directory, &name(&key))?;
    let scoped = store
        .open_dir(&directory, &name(&key))?
        .ok_or_else(|| Error::Held("capacity contract directory missing".into()))?;
    super::super::once(store, &scoped, &record.root.to_string(), &capacity)?;
    Ok(())
}

/// The retention bound holds new roots; an existing root opens at any count,
/// since resuming or rereading it preserves the entry count.
fn retain_root(store: &Store, id: Digest) -> Result<Dir, Error> {
    store.mkdir(store.root(), &name("calibrations"))?;
    let roots = store
        .open_dir(store.root(), &name("calibrations"))?
        .expect("created calibration roots");
    let entry = name(&id.to_string());
    if store.open_dir(&roots, &entry)?.is_none()
        && store.list(&roots, crate::scan_bound())?.len() >= crate::scan_bound()
    {
        return Err(Error::Held(Error::authority_full("calibration")));
    }
    store.mkdir(&roots, &entry)?;
    directory(store, id)
}

pub(super) fn resolve_controls(store: &Store, record: &Calibration) -> Result<(), Error> {
    let view = crate::store::View::open(store.path())?;
    for profile in &record.detected {
        let control = record
            .controls
            .get(profile)
            .ok_or_else(|| Error::Held("detected control evidence missing".into()))?;
        if !matches!(
            control.finished.class,
            Class::Violation | Class::EngineFailure
        ) {
            continue;
        }
        let id = control.finished.attempt.as_str();
        let directory = super::super::findings::directory(&view, id)?;
        let finding = super::super::findings::load(&view, &directory, id)?;
        if super::super::findings::latest(&view, &directory, id, finding.record())?.is_some() {
            continue;
        }
        let evidence = text(&format!(
            "calibration {}: control {} failed its declared check",
            record.root,
            profile.as_str()
        ))?;
        super::super::findings::append(
            store,
            &view,
            control.finished.attempt.clone(),
            crate::record::Decision::Resolved,
            evidence,
        )?;
    }
    Ok(())
}

fn latest(store: &impl ReadStore, admission: &Admission) -> Result<Option<Completed>, Error> {
    let verified = job(store, admission)?;
    let Some((root, maximum)) = crate::attempt::history(store, verified.record())? else {
        return Ok(None);
    };
    if maximum == 0 {
        return Ok(None);
    }
    let (_, _, completed) = crate::attempt::completed_at(store, admission, &root, maximum)?;
    Ok(Some(completed))
}

#[cfg(test)]
#[path = "execution_tests.rs"]
mod tests;
