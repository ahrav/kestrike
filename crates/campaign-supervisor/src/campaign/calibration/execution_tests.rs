use super::*;

#[test]
fn calibration_streams_require_the_bound_worker_digest() {
    let case = crate::store::fixture::Case::new();
    let store = Store::open(&case.state).unwrap();
    let job = Digest::of(b"stream-job");
    let id = format!("{job}-0001");
    let mut directory =
        crate::layout::make_shard(&store, crate::layout::ATTEMPTS, &job.to_string()).unwrap();
    for component in [
        job.to_string(),
        "0001".to_owned(),
        "artifacts".to_owned(),
        id.clone(),
    ] {
        store.mkdir(&directory, &name(&component)).unwrap();
        directory = store
            .open_dir(&directory, &name(&component))
            .unwrap()
            .unwrap();
    }
    let mut evidence = super::super::tests::record().healthy;
    evidence.job = job;
    evidence.finished.attempt = text(&id).unwrap();
    for phase in ["capabilities", "inspect", "run"] {
        let entry = format!("{phase}.stdout");
        store
            .replace(&directory, &name(&entry), b"bound-output")
            .unwrap();
        evidence.artifact.as_mut().unwrap().workers.insert(
            text(phase).unwrap(),
            crate::record::Worker {
                ended: text("exited").unwrap(),
                exit: Some(0),
                signal: None,
                stderr: Digest::of(b""),
                stdout: Digest::of(b"bound-output"),
            },
        );
        assert_eq!(
            raw(&store, &evidence, &entry).unwrap().as_deref(),
            Some("bound-output")
        );
        store
            .replace(&directory, &name(&entry), b"changed-output")
            .unwrap();
        assert!(matches!(
            raw(&store, &evidence, &entry),
            Err(Error::Held(_))
        ));
        store
            .replace(&directory, &name(&entry), b"bound-output")
            .unwrap();
        evidence
            .artifact
            .as_mut()
            .unwrap()
            .workers
            .remove(&text(phase).unwrap());
        assert!(matches!(
            raw(&store, &evidence, &entry),
            Err(Error::Held(_))
        ));
    }
}
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn failed_wait_preserves_observed_exit_and_watchdog() {
    let _processes = crate::store::fixture::processes();
    for watchdog in [false, true] {
        let host = crate::custody::run_tests::Hosted::new(25000 + usize::from(watchdog));
        let store = Store::open(&host.case.state).unwrap();
        let mut custody = host.custody(Duration::from_secs(1));
        let mut launch = host.launch();
        launch.launcher = if watchdog { "/bin/sleep" } else { "/bin/false" }.into();
        launch.args = if watchdog { vec!["20".into()] } else { vec![] };
        crate::custody::charge(&store, store.root(), &launch.attempt).unwrap();
        let running = custody.launch(&store, store.root(), launch).unwrap();
        crate::step::install(Some(crate::step::Script {
            nth: Some((
                crate::step::Step::Kill,
                0,
                crate::step::Outcome::Errno(libc::EIO),
            )),
            ..crate::step::Script::default()
        }));
        let result = wait(&mut custody, running);
        let script = crate::step::install(None).unwrap();
        assert!(script.nth.is_none());
        let (stopped, error) = result.unwrap();
        assert!(error.is_some());
        let finished = stopped
            .finished(Class::Infrastructure, crate::record::Binding::Missing, None)
            .unwrap();
        assert_eq!(finished.watchdog, watchdog);
        if !watchdog {
            assert_eq!(finished.exit, Some(1));
        }
        assert!(stopped.elapsed_ms().is_some());
        assert!(custody.take_retained().is_empty());
        stopped.remove_group().unwrap();
    }
    let host = crate::custody::run_tests::Hosted::new(25002);
    let store = Store::open(&host.case.state).unwrap();
    let custody = host.custody(Duration::from_secs(1));
    let mut values = super::super::tests::config().config().clone();
    values.insert(text("backlog").unwrap(), 1);
    let config = Configuration::new(values).unwrap();
    let job = Digest::of(b"pinned-control");
    let mut finished = super::super::tests::record().healthy.finished;
    finished.attempt = text(&format!("{job}-0001")).unwrap();
    finished.binding = crate::record::Binding::Missing;
    finished.bound = None;
    finished.class = Class::Violation;
    let pin = crate::record::Pin {
        result: crate::record::JobResult {
            job,
            manifest: Digest::of(b"manifest"),
            attempt: 1,
            finished,
        },
    };
    let jobs = crate::layout::make_shard(&store, crate::layout::JOBS, &job.to_string()).unwrap();
    store
        .create_record(&jobs, &name(&format!("{job}.pin")), &pin)
        .unwrap();
    assert_eq!(super::super::super::dispatch::backlog(&store).unwrap(), 1);
    for free_space in [None, Some((0, 0))] {
        crate::step::install(Some(crate::step::Script {
            free_space,
            ..Default::default()
        }));
        let error = capacity(&store, &custody, &config).unwrap_err();
        crate::step::install(None);
        assert_eq!(error.exit(), crate::exit::Supervisor::Held);
        assert_eq!(
            error.to_string(),
            "backlog holds 1 failure pins without a resolved disposition at limit 1; dispose findings or raise backlog"
        );
    }
}

#[test]
fn later_control_success_preserves_an_earlier_disagreement() {
    let case = crate::store::fixture::Case::new();
    let store = Store::open(&case.state).unwrap();
    store
        .create_once(
            store.root(),
            &name("admission"),
            include_bytes!("../../../testdata/admission.json"),
        )
        .unwrap();
    let admission = store
        .read_record::<Admission>(store.root(), &name("admission"))
        .unwrap()
        .unwrap();
    let id = admission.record().job().id().to_string();
    let attempts = crate::layout::make_shard(&store, crate::layout::ATTEMPTS, &id).unwrap();
    store.mkdir(&attempts, &name(&id)).unwrap();
    let root = store.open_dir(&attempts, &name(&id)).unwrap().unwrap();
    for (number, class) in [(1, Class::Disagreement), (2, Class::Pass)] {
        let name_value = name(&format!("{number:04}"));
        store.mkdir(&root, &name_value).unwrap();
        let directory = store.open_dir(&root, &name_value).unwrap().unwrap();
        let mut finished = super::super::tests::record().healthy.finished;
        finished.attempt = text(&format!("{id}-{number:04}")).unwrap();
        finished.class = class;
        store
            .create_record(&directory, &name("finished"), &finished)
            .unwrap();
        assert!(control_disagreed(&store, admission.record()).unwrap());
    }
}

#[test]
fn frozen_minima_separate_missing_checks_from_product_shortfalls() {
    let case = crate::store::fixture::Case::new();
    let store = Store::open(&case.state).unwrap();
    store
        .create_once(
            store.root(),
            &name("admission"),
            include_bytes!("../../../testdata/admission.json"),
        )
        .unwrap();
    let admission = store
        .read_record::<Admission>(store.root(), &name("admission"))
        .unwrap()
        .unwrap();
    let listing = Listing::parse(include_str!("../../../testdata/admission-listing.txt")).unwrap();
    let keys = listing
        .keys
        .iter()
        .map(|key| key.name.as_str())
        .collect::<Vec<_>>();
    let mut experiment = admission.record().job().experiment().clone();
    experiment.campaign = text("calibration").unwrap();
    experiment.minima = Some(text(&format!("{}:2", crate::protocol::COVERAGE[0])).unwrap());
    let (job, _) = crate::record::Job::derive(experiment, &keys).unwrap();
    let plan = CalibrationPlan {
        config: super::super::tests::config(),
        controls: BTreeMap::new(),
        deduplicated: true,
        healthy: Admission::new(
            admission.record().archive().clone(),
            job,
            Purpose::Calibration,
        )
        .unwrap(),
        missing: Vec::new(),
    };
    let mut summary =
        Summary::parse(include_str!("../../../testdata/counting.summary"), &listing).unwrap();
    summary.cluster = Some(crate::protocol::Cluster {
        drawn: Some(crate::protocol::Drawn {
            topology: crate::protocol::Topology {
                owners: 1,
                keys: 1,
                hot: 0,
            },
            coverage: [0; crate::protocol::COVERAGE.len()],
        }),
        unavailable: String::new(),
    });
    for count in [0, 2] {
        summary
            .cluster
            .as_mut()
            .unwrap()
            .drawn
            .as_mut()
            .unwrap()
            .coverage[0] = count;
        let mut value = super::super::tests::record();
        minima(&mut value, &plan, Some(&summary)).unwrap();
        verdict::finish(&mut value).unwrap();
        assert_eq!(value.defects.is_empty(), count == 2);
        assert_eq!(value.verdict == CalibrationVerdict::Calibrated, count == 2);
    }
    let mut missing = super::super::tests::record();
    minima(&mut missing, &plan, None).unwrap();
    verdict::finish(&mut missing).unwrap();
    assert!(missing.defects.is_empty());
    assert_ne!(missing.verdict, CalibrationVerdict::Calibrated);
}

#[test]
fn calibration_retry_policy_preserves_disagreements_and_bound_product_failures() {
    let mut outcome = super::super::tests::record().healthy;
    outcome.finished.class = Class::Incomplete;
    assert!(retry(&outcome, false, 1, 2));
    outcome.finished.class = Class::Disagreement;
    assert!(!retry(&outcome, false, 1, 2));
    let mut root = super::super::tests::record();
    root.controls
        .insert(text("long-planted").unwrap(), outcome.clone());
    verdict::finish(&mut root).unwrap();
    assert_eq!(root.verdict, CalibrationVerdict::Refused);
    assert!(!root.defects.is_empty());
    outcome.finished.class = Class::Oom;
    outcome.product = Some(crate::record::FindingKind::Panic);
    assert!(!retry(&outcome, false, 1, 2));
}

#[test]
fn retained_lost_product_survives_an_unsealed_root() {
    let case = crate::store::fixture::Case::new();
    let store = Store::open(&case.state).unwrap();
    store
        .create_once(
            store.root(),
            &name("admission"),
            include_bytes!("../../../testdata/admission.json"),
        )
        .unwrap();
    let admission = store
        .read_record::<Admission>(store.root(), &name("admission"))
        .unwrap()
        .unwrap()
        .record()
        .clone();
    let id = admission.job().id().digest();
    let mut lost = super::super::tests::record().lost;
    lost.attempt = text(&format!("{id}-0001")).unwrap();
    lost.class = Class::Oom;
    store.mkdir(store.root(), &name("findings")).unwrap();
    let findings = store
        .open_dir(store.root(), &name("findings"))
        .unwrap()
        .unwrap();
    store
        .mkdir(&findings, &name(lost.attempt.as_str()))
        .unwrap();
    let finding = store
        .open_dir(&findings, &name(lost.attempt.as_str()))
        .unwrap()
        .unwrap();
    store
        .create_record(
            &finding,
            &name("finding.json"),
            &crate::record::Finding {
                child: None,
                parent_attempt: None,
                admission: admission.clone(),
                artifact: None,
                attempt: crate::record::Attempt {
                    attempt: lost.attempt.clone(),
                    file_bytes: 1,
                    job: id,
                    manifest: admission.job().manifest_sha256(),
                    number: 1,
                },
                calibration_root: Some(id),
                finished: lost.clone(),
                kind: crate::record::FindingKind::Panic,
            },
        )
        .unwrap();
    assert!(retained_product(&store, &lost).unwrap());
    store.mkdir(store.root(), &name("calibrations")).unwrap();
    let roots = store
        .open_dir(store.root(), &name("calibrations"))
        .unwrap()
        .unwrap();
    store.mkdir(&roots, &name(&id.to_string())).unwrap();
    let root = store
        .open_dir(&roots, &name(&id.to_string()))
        .unwrap()
        .unwrap();
    store.create_record(&root, &name("lost"), &lost).unwrap();
    let plan = CalibrationPlan {
        config: super::super::tests::config(),
        controls: BTreeMap::new(),
        deduplicated: true,
        healthy: admission,
        missing: Vec::new(),
    };
    assert!(partial_defect(&store, &plan).unwrap());
}

#[test]
fn a_full_calibrations_directory_resumes_an_existing_root_and_holds_a_new_one() {
    // Resuming an unsealed root or rereading a sealed one keeps the entry count,
    // so the retention bound holds only a fresh root.
    let case = crate::store::fixture::Case::new();
    let store = Store::open(&case.state).unwrap();
    let existing = Digest::of(b"existing calibration root");
    let fresh = Digest::of(b"fresh calibration root");
    let roots = case.state.join("calibrations");
    std::fs::create_dir(&roots).unwrap();
    std::fs::create_dir(roots.join(existing.to_string())).unwrap();
    for index in 1..crate::SCAN_BOUND {
        std::fs::write(roots.join(format!("retained-{index}")), b"").unwrap();
    }
    assert_eq!(
        std::fs::read_dir(&roots).unwrap().count(),
        crate::SCAN_BOUND
    );
    retain_root(&store, existing).unwrap();
    assert_eq!(
        std::fs::read_dir(&roots).unwrap().count(),
        crate::SCAN_BOUND
    );
    assert!(matches!(retain_root(&store, fresh), Err(Error::Held(_))));
    assert!(!roots.join(fresh.to_string()).exists());
}

#[test]
fn control_dispositions_use_a_constant_descriptor_budget() {
    let _processes = crate::store::fixture::processes();
    if std::env::var_os("CAMPAIGN_CONTROL_DESCRIPTOR_CHILD").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "campaign::calibration::execution::tests::control_dispositions_use_a_constant_descriptor_budget", "--nocapture"])
            .env("CAMPAIGN_CONTROL_DESCRIPTOR_CHILD", "1").output().unwrap();
        assert!(
            output.status.success()
                && String::from_utf8_lossy(&output.stdout).contains("test result: ok. 1 passed;"),
            "{output:?}"
        );
        return;
    }
    let fixture = crate::attempt::tests::settlement::Fixture::new(&[Class::Violation]);
    fixture.settle().unwrap().unwrap();
    let id = text(&format!("{}-0001", fixture.job.job().id())).unwrap();
    let mut calibration = super::super::tests::record();
    let directory = super::super::super::findings::directory(&fixture.store, id.as_str()).unwrap();
    let finding =
        super::super::super::findings::load(&fixture.store, &directory, id.as_str()).unwrap();
    let profile = text("control").unwrap();
    let mut control = calibration.healthy.clone();
    control.finished = finding.record().finished.clone();
    calibration.detected = vec![profile.clone()];
    calibration.controls.insert(profile, control);
    drop(finding);
    drop(directory);
    drop(fixture.store);
    for n in 0..48 {
        let decision = if n == 47 {
            crate::record::Decision::Resolved
        } else {
            crate::record::Decision::ReleaseBlocker
        };
        crate::campaign::dispose(
            &fixture.case.state,
            id.clone(),
            decision,
            text("evidence").unwrap(),
        )
        .unwrap();
    }
    let before = crate::store::fixture::snapshot(&fixture.case.state);
    let open = std::fs::read_dir("/proc/self/fd").unwrap().count() as u64;
    crate::sys::restrict_descriptor_limit(open + 24).unwrap();
    let store = Store::open(&fixture.case.state).unwrap();
    resolve_controls(&store, &calibration).unwrap();
    assert_eq!(crate::store::fixture::snapshot(&fixture.case.state), before);
}

/// Calibration reserves one start and the configured triage reserve against
/// the charged census, refusing equality and admitting one unit of headroom.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn capacity_checks_each_charged_threshold_before_writes() {
    let _processes = crate::store::fixture::processes();
    let host = crate::custody::run_tests::Hosted::new(25004);
    let store = Store::open(&host.case.state).unwrap();
    let custody = host.custody(Duration::from_secs(1));
    crate::campaign::state_fixture::probe(&store, "probe-budget", 0);
    let mut values = super::super::tests::config().config().clone();
    values.insert(text("slots").unwrap(), 1);
    let config = Configuration::new(values).unwrap();
    let usage = crate::campaign::census::census(&store, &config).unwrap();
    let charge = config.charge();
    for (dimension, threshold) in [
        ("artifact_bytes", u128::from(usage.bytes) + 2 * charge.bytes),
        (
            "artifact_inodes",
            u128::from(usage.inodes) + 2 * charge.inodes,
        ),
    ] {
        for headroom in [0, 1] {
            let mut values = config.config().clone();
            values.insert(text(dimension).unwrap(), threshold as u64 + headroom);
            let config = Configuration::new(values).unwrap();
            let before = crate::store::fixture::snapshot(&host.case.state);
            let result = capacity(&store, &custody, &config);
            assert_eq!(crate::store::fixture::snapshot(&host.case.state), before);
            if headroom == 0 {
                assert!(
                    matches!(result, Err(Error::Rejected(ref reason))
                    if reason == &format!("calibration paused: {{\"{dimension}\"}}")),
                    "{result:?}"
                );
            } else {
                result.unwrap();
            }
        }
    }
}
