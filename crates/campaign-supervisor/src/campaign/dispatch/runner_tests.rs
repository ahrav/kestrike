use super::*;

#[cfg(test)]
pub(in crate::campaign) fn ordinary_admission_during_triage(
    store: &Store,
    custody: &mut Custody,
    options: &Options,
    step: triage::Step,
    running: Running,
) -> Result<(), Error> {
    let mut report = Report::default();
    let mut jobs = Jobs::load(store, &mut report)?.expect("the fixture admits ordinary jobs");
    let finding = step.finding_id().to_owned();
    jobs.settled.insert(
        finding
            .rsplit_once('-')
            .expect("finding token has an attempt")
            .0
            .to_owned(),
    );
    let config = store
        .read_record::<Configuration>(store.root(), &name("config.json"))?
        .unwrap()
        .record()
        .clone();
    let build = crate::archive::Archive::load(&options.archive)
        .unwrap()
        .id();
    let mut dispatcher = Dispatcher {
        store,
        custody,
        options,
        limits: crate::campaign::configuration::limits(&config),
        config,
        build,
        jobs,
        attempts: BTreeMap::new(),
        running: vec![running],
        steps: [(finding.clone(), step)].into(),
        unchanged: BTreeSet::new(),
        pending: Vec::new(),
        backlog: None,
        backlog_hold: None,
        census: None,
        collected: None,
        budget: PASS_DELETIONS,
        report,
    };
    dispatcher.admit_ordinary()?;
    assert_eq!(dispatcher.report.started, 1);
    assert_eq!(dispatcher.running.len(), 2);
    assert_eq!(dispatcher.attempts.len(), 1);
    let (id, attempt) = dispatcher.attempts.pop_first().unwrap();
    let ordinary = dispatcher.running.pop().unwrap();
    let stopped = dispatcher.custody.stop(ordinary)?;
    let completed = attempt.finish(store, stopped, attempt::EVIDENCE_BOUND);
    dispatcher.conclude(id.clone(), completed);
    assert_eq!(dispatcher.pending.len(), 1);
    assert!(dispatcher.report.completed.is_empty());
    let job = crate::layout::attempts(store, &id)?.unwrap();
    let directory = store.open_dir(&job, &name("0001"))?.unwrap();
    assert!(
        store
            .read_record::<crate::record::Captured>(&directory, &name("captured"))?
            .is_none()
    );
    assert!(!dispatcher.running.is_empty());
    let running = dispatcher.running.pop().unwrap();
    let step = dispatcher.steps.remove(&finding).unwrap();
    let stopped = dispatcher.custody.stop(running)?;
    dispatcher.report.triage(step.finish(store, stopped)?);
    dispatcher.settle_pending();
    assert!(
        dispatcher.report.refusals.is_empty(),
        "{:?}",
        dispatcher.report
    );
    assert!(
        store
            .read_record::<crate::record::Captured>(&directory, &name("captured"))?
            .is_some()
    );
    Ok(())
}

#[cfg(test)]
pub(in crate::campaign) fn triage_admission_waits_for_pending_capture(
    store: &Store,
    custody: &mut Custody,
    options: &Options,
    step: triage::Step,
    running: Running,
    settled: &[String],
    ordinary_job: &str,
) -> Result<(), Error> {
    let mut report = Report::default();
    let mut jobs = Jobs::load(store, &mut report)?.expect("the fixture admits ordinary jobs");
    let finding = step.finding_id().to_owned();
    jobs.settled.insert(
        finding
            .rsplit_once('-')
            .expect("finding token has an attempt")
            .0
            .to_owned(),
    );
    jobs.settled.extend(settled.iter().cloned());
    let config = store
        .read_record::<Configuration>(store.root(), &name("config.json"))?
        .unwrap()
        .record()
        .clone();
    assert_eq!(config.value("reserve_slots"), 2);
    let build = crate::archive::Archive::load(&options.archive)
        .unwrap()
        .id();
    let mut dispatcher = Dispatcher {
        store,
        custody,
        options,
        limits: crate::campaign::configuration::limits(&config),
        config,
        build,
        jobs,
        attempts: BTreeMap::new(),
        running: vec![running],
        steps: [(finding.clone(), step)].into(),
        unchanged: BTreeSet::new(),
        pending: Vec::new(),
        backlog: None,
        backlog_hold: None,
        census: None,
        collected: None,
        budget: PASS_DELETIONS,
        report,
    };
    dispatcher.admit_ordinary()?;
    assert_eq!(dispatcher.report.started, 1);
    let (id, attempt) = dispatcher.attempts.pop_first().unwrap();
    assert_eq!(id, ordinary_job);
    let ordinary = dispatcher.running.pop().unwrap();
    let stopped = dispatcher.custody.wait_any(vec![ordinary])?.stopped;
    let completed = attempt.finish(store, stopped, attempt::EVIDENCE_BOUND)?;
    assert!(
        completed.has_finding(),
        "{:?}",
        completed.finished().record()
    );
    dispatcher.conclude(id, Ok(completed));
    dispatcher.settle_pending();
    assert_eq!(dispatcher.pending.len(), 1, "{:?}", dispatcher.report);
    assert_eq!(dispatcher.running.len(), 1);
    dispatcher.admit_triage()?;
    assert_eq!(
        dispatcher.report.triage_started, 0,
        "a waiting capture pauses triage admission: {:?}",
        dispatcher.report
    );
    assert_eq!(dispatcher.steps.len(), 1);
    let running = dispatcher.running.pop().unwrap();
    let step = dispatcher.steps.remove(&finding).unwrap();
    let stopped = dispatcher.custody.stop(running)?;
    dispatcher.report.triage(step.finish(store, stopped)?);
    dispatcher.settle_pending();
    assert!(dispatcher.pending.is_empty(), "{:?}", dispatcher.report);
    assert!(
        dispatcher.report.refusals.is_empty(),
        "{:?}",
        dispatcher.report
    );
    dispatcher.admit_triage()?;
    assert!(
        dispatcher.report.triage_started > 0,
        "{:?}",
        dispatcher.report
    );
    while let Some(running) = dispatcher.running.pop() {
        let identity = running.started().record().attempt.clone();
        let (_, step) = dispatcher
            .steps
            .iter()
            .find(|(_, step)| *step.identity() == identity)
            .map(|(id, _)| id.clone())
            .and_then(|id| dispatcher.steps.remove_entry(&id))
            .expect("every running process is a minted step");
        let stopped = dispatcher.custody.stop(running)?;
        step.finish(store, stopped)?;
    }
    Ok(())
}

/// Runs a session that resumes the settlement of `completed`. With
/// `backlog` set, the session starts from that backlog and from a census
/// counted before the settlement, and returns the census it ended with.
#[cfg(test)]
pub(in crate::campaign) fn resume_pending_capture(
    store: &Store,
    custody: &mut Custody,
    options: &Options,
    id: String,
    completed: Completed,
    fault: bool,
    backlog: Option<u64>,
) -> Result<(Report, Option<crate::campaign::census::Census>), Error> {
    let mut report = Report {
        started: 1,
        ..Report::default()
    };
    let mut jobs = Jobs::load(store, &mut report)?.expect("the fixture admits ordinary jobs");
    jobs.counts.insert(id.clone(), 1);
    let config = store
        .read_record::<Configuration>(store.root(), &name("config.json"))?
        .unwrap()
        .record()
        .clone();
    let build = crate::archive::Archive::load(&options.archive)
        .unwrap()
        .id();
    let census = backlog
        .is_some()
        .then(|| crate::campaign::census::Census::count(store))
        .transpose()?;
    crate::step::install(Some(crate::step::Script {
        nth: fault.then_some((
            crate::step::Step::List,
            0,
            crate::step::Outcome::Errno(libc::EIO),
        )),
        ..crate::step::Script::default()
    }));
    Dispatcher {
        store,
        custody,
        options,
        limits: crate::campaign::configuration::limits(&config),
        config,
        build,
        jobs,
        attempts: BTreeMap::new(),
        running: Vec::new(),
        steps: BTreeMap::new(),
        unchanged: BTreeSet::new(),
        pending: vec![(id, completed, true)],
        census,
        collected: None,
        budget: PASS_DELETIONS,
        backlog,
        backlog_hold: None,
        report,
    }
    .run()
}

pub(in crate::campaign) fn run_with_settled(
    store: &Store,
    custody: &mut Custody,
    options: &Options,
    settled: &[String],
) -> Result<Report, Error> {
    let mut report = Report::default();
    let mut jobs = Jobs::load(store, &mut report)?.expect("fixture admits ordinary jobs");
    jobs.settled.extend(settled.iter().cloned());
    let config = store
        .read_record::<Configuration>(store.root(), &name("config.json"))?
        .unwrap()
        .record()
        .clone();
    let mut report = Dispatcher {
        store,
        custody,
        options,
        limits: crate::campaign::configuration::limits(&config),
        config,
        build: crate::archive::Archive::load(&options.archive)
            .unwrap()
            .id(),
        jobs,
        attempts: BTreeMap::new(),
        running: Vec::new(),
        steps: BTreeMap::new(),
        unchanged: BTreeSet::new(),
        pending: Vec::new(),
        backlog: None,
        backlog_hold: None,
        census: None,
        collected: None,
        budget: PASS_DELETIONS,
        report,
    }
    .run()?
    .0;
    report.finish(store);
    Ok(report)
}

#[test]
fn artifact_exhaustion_requires_an_empty_finished_pass() {
    for dimensions in [
        vec!["disk"],
        vec!["disk_inodes"],
        vec!["artifact_bytes"],
        vec!["artifact_inodes"],
        vec!["artifact_bytes", "artifact_inodes", "disk"],
    ] {
        let paused: BTreeSet<_> = dimensions.iter().map(|value| (*value).to_owned()).collect();
        let operator = dimensions
            .iter()
            .any(|value| value.starts_with("artifact_"));
        assert!(exhausted(None, &paused, true).is_ok());
        for (deletions, finished) in [(0, false), (1, false), (1, true), (0, true)] {
            let pass = Collected {
                changed: deletions > 0,
                finished,
                held: None,
            };
            assert!(exhausted(Some(&pass), &paused, false).is_ok());
            let result = exhausted(Some(&pass), &paused, true);
            assert_eq!(
                result.is_err(),
                operator && deletions == 0 && finished,
                "{dimensions:?} {deletions} {finished}"
            );
            if let Err(error) = result {
                let names = dimensions
                    .iter()
                    .filter(|value| value.starts_with("artifact_"))
                    .copied()
                    .collect::<Vec<_>>()
                    .join(" and ");
                assert_eq!(
                    error.to_string(),
                    format!(
                        "{names} exhausted and collect reclaims nothing; raise it with configure"
                    )
                );
            }
        }
    }
    let pass = Collected {
        changed: false,
        finished: true,
        held: Some("probes/probe-kept: unlisted entry".to_owned()),
    };
    let error = exhausted(Some(&pass), &["artifact_inodes".to_owned()].into(), true).unwrap_err();
    assert!(error.to_string().ends_with(
        "; collection kept probes/probe-kept: unlisted entry; inspect the held evidence"
    ));
    for dimension in ["artifact_bytes", "artifact_inodes", "disk", "disk_inodes"] {
        assert!(storage(dimension));
    }
    for dimension in ["slots", "triage reserve slots", "archive", "backlog"] {
        assert!(!storage(dimension));
    }
}

#[test]
fn collection_stops_on_a_signal_read_fault_or_expired_deadline() {
    let mut fault = None;
    assert!(!collecting_stops(Ok(None), None, &mut fault));
    assert!(collecting_stops(Ok(Some(libc::SIGTERM)), None, &mut fault));
    assert!(collecting_stops(
        Err(crate::custody::Error::Io(
            std::io::Error::from_raw_os_error(libc::EIO)
        )),
        None,
        &mut fault,
    ));
    assert!(!collecting_stops(Ok(None), None, &mut fault));
    let mut report = Report::default();
    report.error(fault.take().unwrap().into());
    assert_eq!(report.exit(), crate::exit::Supervisor::Held);
    assert_eq!(report.refusals.len(), 1);
    assert!(report.refusals[0].contains("Input/output error"));
    assert!(collecting_stops(Ok(None), Some(Instant::now()), &mut fault));
    assert!(!collecting_stops(
        Ok(None),
        Some(Instant::now() + std::time::Duration::from_secs(60)),
        &mut fault,
    ));
}
