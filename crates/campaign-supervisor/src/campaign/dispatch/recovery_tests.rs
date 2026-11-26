use super::*;

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_missing_or_unreadable_charge_before_cgroup_creation_stays_held_on_every_restart() {
    let _processes = processes();
    for missing in [true, false] {
        let host = Host::new("intent-charge-hold");
        let store = Store::open(&host.case.state).unwrap();
        host.config(&store, &[("slots", 1)]);
        let job = host.job(&store, 0, "upload", Purpose::Campaign, 1);
        let mut custody = host.custody();
        step::install(Some(Script {
            nth: Some((Step::Intent, 0, Outcome::Kill)),
            ..Script::default()
        }));
        let killed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            dispatch(&store, &mut custody, &host.options())
        }));
        step::install(None);
        assert!(
            killed
                .as_ref()
                .err()
                .is_some_and(|error| error.is::<step::Killed>())
        );
        let path = attempt_path(&host, &job);
        let group = host.root.join(format!("{}-0001", job.job().id()));
        assert!(path.join("intent").exists());
        assert!(path.join("reservation").exists());
        assert!(!group.exists());
        if missing {
            fs::remove_file(path.join("reservation")).unwrap();
        } else {
            fs::write(path.join("reservation"), b"damaged").unwrap();
        }
        drop(custody);
        drop(store);
        for _ in 0..2 {
            let store = Store::open(&host.case.state).unwrap();
            let mut custody = host.custody();
            let report = dispatch(&store, &mut custody, &host.options()).unwrap();
            assert_eq!(report.exit(), crate::exit::Supervisor::Held, "{report:?}");
            assert_eq!(report.started, 0);
            if missing {
                assert!(
                    report
                        .refusals
                        .iter()
                        .any(|reason| reason.contains("stopped attempt lacks reservation")),
                    "{report:?}"
                );
            }
            assert!(report.completed.is_empty());
            assert!(!path.join("finished").exists());
            assert!(!group.exists());
            assert_eq!(
                fs::read(path.join("reservation")).ok(),
                if missing {
                    None
                } else {
                    Some(b"damaged".to_vec())
                }
            );
        }
    }
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn invalid_launch_input_reports_rejection_and_mints_no_attempt() {
    let _processes = processes();
    let host = Host::new("rejected-launch");
    let store = Store::open(&host.case.state).unwrap();
    host.config(&store, &[("slots", 1)]);
    let job = host.job(&store, 0, "upload", Purpose::Campaign, 1);
    let mut custody = host.custody();
    let mut options = host.options();
    options.launcher = PathBuf::new();
    let report = dispatch(&store, &mut custody, &options).unwrap();
    assert_eq!(
        report.exit(),
        crate::exit::Supervisor::Rejected,
        "{report:?}"
    );
    assert_eq!(report.started, 0);
    assert!(report.refusals.is_empty());
    assert_eq!(
        report.rejections,
        ["custody rejected: invalid custody command"]
    );
    assert!(!attempt_path(&host, &job).exists());
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_held_wait_failure_reconciles_the_other_running_attempt() {
    let _processes = processes();
    let host = Host::new("held-sibling");
    let store = Store::open(&host.case.state).unwrap();
    host.config(&store, &[("wall", 60)]);
    host.capacity(&store, "upload", 2);
    let jobs = [
        host.job(&store, 0, "upload", Purpose::Campaign, 1),
        host.job(&store, 1, "upload", Purpose::Campaign, 1),
    ];
    let fast = jobs
        .iter()
        .map(|job| job.job().id().to_string())
        .min()
        .unwrap();
    let held_group = host.root.join(format!("{fast}-0001"));
    let options = host.options();
    fs::write(&options.launcher, format!("#!/bin/sh\nwhile [ $# -gt 0 ]; do\nif [ \"$1\" = --run-id ]; then shift; id=$1; fi\nshift\ndone\nif [ \"$id\" = {fast}-0001 ]; then sleep 0.08; else sleep 10; fi\n")).unwrap();
    let mut custody = Custody::open(
        &host.root,
        Timing {
            poll: Duration::from_millis(1),
            kill_wait: Duration::from_millis(50),
            watchdog: Duration::from_secs(60),
        },
    )
    .unwrap();
    let mut late = std::process::Command::new("/bin/sleep")
        .arg("10")
        .spawn()
        .unwrap();
    let pid = late.id();
    let observed = held_group.clone();
    let mut killed = false;
    let mut joined = false;
    step::install(Some(Script {
        observe: Some(Box::new(move |at| {
            if at == Step::Kill {
                killed = true;
            }
            if killed && !joined && at == Step::Read {
                fs::write(observed.join("cgroup.procs"), pid.to_string()).unwrap();
                joined = true;
            }
        })),
        ..Script::default()
    }));
    let report = dispatch(&store, &mut custody, &options).unwrap();
    step::install(None);
    assert_eq!(report.exit(), crate::exit::Supervisor::Held);
    assert_eq!(report.started, 2);
    assert!(populated(&held_group));
    let held = jobs
        .iter()
        .find(|job| job.job().id().to_string() == fast)
        .unwrap();
    assert!(attempt_path(&host, held).join("reservation").exists());
    let sibling = jobs
        .iter()
        .find(|job| job.job().id().to_string() != fast)
        .unwrap();
    let path = attempt_path(&host, sibling);
    assert!(path.join("finished").exists());
    assert!(!path.join("reservation").exists());
    assert!(
        !host
            .root
            .join(format!("{}-0001", sibling.job().id()))
            .exists()
    );
    assert!(
        report
            .completed
            .iter()
            .any(|finished| finished.attempt.as_str() == format!("{}-0001", sibling.job().id()))
    );
    fs::write(held_group.join("cgroup.kill"), "1").unwrap();
    assert!(!late.wait().unwrap().success());
}

fn pending(host: &Host) -> Admission {
    let store = Store::open(&host.case.state).unwrap();
    host.config(&store, &[("slots", 1)]);
    let job = host.job(&store, 0, "upload", Purpose::Campaign, 1);
    let mut custody = host.custody();
    step::install(Some(Script {
        nth: Some((Step::Reservation, 0, Outcome::Kill)),
        ..Script::default()
    }));
    let killed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        dispatch(&store, &mut custody, &host.options())
    }));
    step::install(None);
    assert!(
        killed
            .as_ref()
            .err()
            .is_some_and(|error| error.is::<step::Killed>())
    );
    assert!(attempt_path(host, &job).join("reservation").exists());
    assert!(!attempt_path(host, &job).join("intent").exists());
    job
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn reservation_only_recovery_converges_after_a_crash_at_every_recovery_sync() {
    let _processes = processes();
    let baseline = Host::new("pending-baseline");
    let job = pending(&baseline);
    let store = Store::open(&baseline.case.state).unwrap();
    let mut custody = baseline.custody();
    let mut options = baseline.options();
    options.max_attempts = Some(0);
    step::install(Some(Script::default()));
    let report = dispatch(&store, &mut custody, &options).unwrap();
    let trace = step::install(None).unwrap();
    assert_eq!(report.exit(), crate::exit::Supervisor::Success);
    assert_eq!(report.completed.len(), 1);
    assert_eq!(report.counts[report.completed[0].class.name()], 1);
    let path = attempt_path(&baseline, &job);
    assert!(path.join("finished").exists());
    assert!(!path.join("reservation").exists());
    let syncs = trace.reached.iter().filter(|at| **at == Step::Sync).count();
    assert!(syncs > 0);
    drop(custody);
    drop(store);
    drop(baseline);
    for index in 0..syncs {
        let host = Host::new(&format!("pending-{index}"));
        let job = pending(&host);
        let store = Store::open(&host.case.state).unwrap();
        let mut custody = host.custody();
        let mut options = host.options();
        options.max_attempts = Some(0);
        step::install(Some(Script {
            nth: Some((Step::Sync, index, Outcome::Kill)),
            ..Script::default()
        }));
        let killed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            dispatch(&store, &mut custody, &options)
        }));
        let fired = step::install(None).unwrap();
        assert!(
            killed
                .as_ref()
                .err()
                .is_some_and(|error| error.is::<step::Killed>())
        );
        assert_eq!(
            fired.reached.iter().filter(|at| **at == Step::Sync).count(),
            index + 1
        );
        drop(custody);
        drop(store);
        let store = Store::open(&host.case.state).unwrap();
        let mut custody = host.custody();
        let report = dispatch(&store, &mut custody, &options).unwrap();
        assert_eq!(
            report.exit(),
            crate::exit::Supervisor::Success,
            "sync {index}: {report:?}"
        );
        let path = attempt_path(&host, &job);
        let finished = fs::read(path.join("finished")).unwrap();
        assert!(!path.join("reservation").exists());
        let again = dispatch(&store, &mut custody, &options).unwrap();
        assert_eq!(again.exit(), crate::exit::Supervisor::Success);
        assert_eq!(again.started, 0);
        assert!(again.completed.is_empty());
        assert_eq!(fs::read(path.join("finished")).unwrap(), finished);
    }
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_crash_after_attempt_publication_and_before_charge_stays_held() {
    let _processes = processes();
    let baseline = Host::new("pre-charge-baseline");
    let store = Store::open(&baseline.case.state).unwrap();
    baseline.config(&store, &[("slots", 1)]);
    let job = baseline.job(&store, 0, "upload", Purpose::Campaign, 1);
    let path = attempt_path(&baseline, &job);
    let seen = std::rc::Rc::new(std::cell::Cell::new(None));
    let witness = seen.clone();
    let mut ordinal = 0;
    step::install(Some(Script {
        observe: Some(Box::new(move |at| {
            if at == Step::Sync {
                if path.join("attempt").exists()
                    && !path.join("reservation").exists()
                    && witness.get().is_none()
                {
                    witness.set(Some(ordinal));
                }
                ordinal += 1;
            }
        })),
        ..Script::default()
    }));
    let mut custody = baseline.custody();
    dispatch(&store, &mut custody, &baseline.options()).unwrap();
    step::install(None);
    let index = seen.get().expect("attempt-before-charge witness");
    drop(custody);
    drop(store);
    drop(baseline);
    let host = Host::new("pre-charge");
    let store = Store::open(&host.case.state).unwrap();
    host.config(&store, &[("slots", 1)]);
    let job = host.job(&store, 0, "upload", Purpose::Campaign, 1);
    let mut custody = host.custody();
    step::install(Some(Script {
        nth: Some((Step::Sync, index, Outcome::Kill)),
        ..Script::default()
    }));
    let killed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        dispatch(&store, &mut custody, &host.options())
    }));
    step::install(None);
    assert!(
        killed
            .as_ref()
            .err()
            .is_some_and(|error| error.is::<step::Killed>())
    );
    drop(custody);
    drop(store);
    let store = Store::open(&host.case.state).unwrap();
    let mut custody = host.custody();
    let report = dispatch(&store, &mut custody, &host.options()).unwrap();
    assert_eq!(report.exit(), crate::exit::Supervisor::Held);
    assert_eq!(report.started, 0);
    assert!(attempt_path(&host, &job).join("attempt").exists());
    assert!(!attempt_path(&host, &job).join("reservation").exists());
    assert!(!attempt_path(&host, &job).join("finished").exists());
}

#[test]
fn settled_jobs_load_by_name_across_shards_past_the_total_bound() {
    let case = crate::store::fixture::Case::new();
    let store = Store::open(&case.state).unwrap();
    let jobs: Vec<_> = (0..12)
        .map(|run| crate::campaign::state_fixture::job(&store, run))
        .collect();
    let settled: BTreeSet<_> = jobs[..6]
        .iter()
        .map(|job| job.job().id().to_string())
        .collect();
    for id in &settled {
        let shard = crate::layout::jobs(&store, id).unwrap().unwrap();
        store
            .create_once(&shard, &name(&format!("{id}.result.json")), b"settled")
            .unwrap();
        store
            .replace(&shard, &name(&format!("{id}.json")), b"damaged")
            .unwrap();
    }
    // A settled job's attempt history passes the orphan check by the job's
    // result name alone.
    for job in &jobs[..6] {
        crate::campaign::state_fixture::attempt(&store, job, 1, 0);
    }
    let total: usize = fs::read_dir(case.state.join("jobs"))
        .unwrap()
        .map(|shard| fs::read_dir(shard.unwrap().path()).unwrap().count())
        .sum();
    let bound = 16;
    assert!(total > bound, "{total}");
    step::install(Some(Script {
        scan_bound: Some(bound),
        ..Script::default()
    }));
    let mut report = Report::default();
    let loaded = super::super::recovery::Jobs::load(&store, &mut report);
    step::install(None);
    let loaded = loaded.unwrap().unwrap();
    assert!(report.refusals.is_empty(), "{report:?}");
    assert!(loaded.settled.is_empty(), "{:?}", loaded.settled);
    let unsettled: BTreeSet<_> = jobs[6..]
        .iter()
        .map(|job| job.job().id().to_string())
        .collect();
    assert_eq!(
        loaded.records.keys().cloned().collect::<BTreeSet<_>>(),
        unsettled
    );
}

/// A job entry or attempt history listed in a shard other than its job id's
/// is refused by dispatch and held by `show` and `status`, so a stray result
/// record settles no job and the job's own record still loads.
#[test]
fn entries_outside_their_job_shard_are_refused_and_held() {
    let case = crate::store::fixture::Case::new();
    let store = Store::open(&case.state).unwrap();
    let job = crate::campaign::state_fixture::job(&store, 0);
    let id = job.job().id().to_string();
    let other = "ff";
    assert!(crate::layout::shard(&id).as_str() < other, "{id}");
    fs::create_dir_all(case.state.join("jobs").join(other)).unwrap();
    fs::write(
        case.state
            .join("jobs")
            .join(other)
            .join(format!("{id}.result.json")),
        b"stray",
    )
    .unwrap();
    fs::create_dir_all(case.state.join("attempts").join(other).join(&id)).unwrap();
    let mut report = Report::default();
    let loaded = super::super::recovery::Jobs::load(&store, &mut report)
        .unwrap()
        .unwrap();
    assert!(loaded.records.contains_key(&id), "{report:?}");
    assert_eq!(
        report.refusals,
        [
            format!("job entry jobs/{other}/{id}.result.json outside its shard"),
            format!("attempts without readable job {id}"),
        ]
    );
    let held = |rows: &serde_json::Value, path: &str| {
        rows.as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == path && row["held"] == "entry outside its job's shard")
    };
    let result = format!("jobs/{other}/{id}.result.json");
    let shown = crate::campaign::show(&case.state).unwrap();
    assert!(held(&shown["jobs"], &result), "{shown}");
    let status = crate::campaign::status_tests::status(&case.state).unwrap();
    assert!(held(&status["jobs"], &result), "{:?}", status["jobs"]);
    assert!(
        held(&status["jobs"], &format!("attempts/{other}/{id}")),
        "{:?}",
        status["jobs"]
    );
}

/// A two-hex root entry that does not open as a directory is one refused
/// entry of dispatch and one held row of `show` and `status`, whether it
/// stands alone in `jobs/` or beside its jobs in `attempts/`, so the jobs of
/// every readable shard still load.
#[test]
fn root_entries_that_do_not_open_as_shards_are_refused_and_held() {
    let case = crate::store::fixture::Case::new();
    let store = Store::open(&case.state).unwrap();
    let job = crate::campaign::state_fixture::job(&store, 0);
    let id = job.job().id().to_string();
    let own = crate::layout::shard(&id);
    let file = "ff";
    assert_ne!(own.as_str(), file, "{id}");
    fs::write(case.state.join("jobs").join(file), b"stray").unwrap();
    fs::create_dir_all(case.state.join("attempts")).unwrap();
    std::os::unix::fs::symlink(&case.state, case.state.join("attempts").join(own.as_str()))
        .unwrap();
    let mut report = Report::default();
    let loaded = super::super::recovery::Jobs::load(&store, &mut report)
        .unwrap()
        .unwrap();
    assert!(loaded.records.contains_key(&id), "{report:?}");
    let link = format!("attempts/{}", own.as_str());
    assert_eq!(
        report.refusals,
        [
            format!("unknown job entry jobs/{file}"),
            format!("attempts without readable job {link}"),
        ]
    );
    let held = |rows: &serde_json::Value, path: &str| {
        rows.as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == path && row["held"] == "root entry is not a shard")
    };
    let shown = crate::campaign::show(&case.state).unwrap();
    assert!(held(&shown["jobs"], &format!("jobs/{file}")), "{shown}");
    assert!(
        shown["jobs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == id),
        "{shown}"
    );
    let status = crate::campaign::status_tests::status(&case.state).unwrap();
    for path in [format!("jobs/{file}"), link] {
        assert!(held(&status["jobs"], &path), "{:?}", status["jobs"]);
    }
    let rows = status["jobs"].as_array().unwrap();
    let row = rows.iter().find(|row| row["id"] == id).unwrap();
    assert_eq!(row["state"], "held", "{row}");
    assert!(row["attempts_held"].is_object(), "{row}");
}

/// A `jobs/` shard that does not open as a directory leaves the attempt
/// histories of its jobs without a job record: dispatch refuses the shard
/// and each history, and `status` holds both in one snapshot.
#[test]
fn a_jobs_shard_that_does_not_open_holds_its_attempt_histories() {
    let case = crate::store::fixture::Case::new();
    let store = Store::open(&case.state).unwrap();
    let job = crate::campaign::state_fixture::job(&store, 0);
    let id = job.job().id().to_string();
    let own = crate::layout::shard(&id);
    let shard = case.state.join("jobs").join(own.as_str());
    fs::create_dir_all(case.state.join(crate::layout::attempt_path(&id, 1))).unwrap();
    fs::rename(&shard, case.root.join("moved")).unwrap();
    fs::write(&shard, b"stray").unwrap();
    let mut report = Report::default();
    let loaded = super::super::recovery::Jobs::load(&store, &mut report)
        .unwrap()
        .unwrap();
    assert!(loaded.records.is_empty());
    assert_eq!(
        report.refusals,
        [
            format!("unknown job entry jobs/{}", own.as_str()),
            format!("attempts without readable job {id}"),
        ]
    );
    let status = crate::campaign::status_tests::status(&case.state).unwrap();
    let held = |path: &str, reason: &str| {
        status["jobs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == path && row["held"] == reason)
    };
    assert!(
        held(
            &format!("jobs/{}", own.as_str()),
            "root entry is not a shard"
        ),
        "{:?}",
        status["jobs"]
    );
    assert!(
        held(&id, "attempt history without job record"),
        "{:?}",
        status["jobs"]
    );
}

/// Fairness ranks profiles by the attempts of unsettled jobs: the attempts
/// of a job settled during the session leave its profile's rank unchanged,
/// as they do after a restart, where loading leaves settled jobs out.
#[test]
fn fairness_ranks_profiles_by_unsettled_attempts() {
    let case = crate::store::fixture::Case::new();
    let store = Store::open(&case.state).unwrap();
    let request = |profile: &str, run| crate::campaign::Request {
        profile: text(profile),
        campaign: text("fairness"),
        run,
        attempts: 3,
        counts: BTreeMap::new(),
    };
    let listing =
        crate::protocol::Listing::parse(include_str!("../../../testdata/admission-listing.txt"))
            .unwrap();
    let pins = crate::record::Pins {
        build: text(&"b".repeat(64)),
        executable: text(&"e".repeat(64)),
        platform: text("x86_64-linux"),
        toolchain: text("rustc 1.99.0"),
    };
    let admit = |profile, run| {
        crate::campaign::admission::admit(
            &store,
            &listing,
            pins.clone(),
            text("/archive"),
            &request(profile, run),
            Purpose::Campaign,
        )
        .unwrap()
        .record
    };
    let upload = admit("upload", 0);
    let broad = admit("cluster-broad", 0);
    let settled = admit("upload", 1);
    let id = |job: &Admission| job.job().id().to_string();
    let jobs = super::super::recovery::Jobs {
        records: [
            (id(&upload), upload.clone()),
            (id(&broad), broad.clone()),
            (id(&settled), settled.clone()),
        ]
        .into(),
        counts: [(id(&upload), 0), (id(&broad), 1), (id(&settled), 50)].into(),
        settled: [id(&settled)].into(),
        excluded: BTreeSet::new(),
    };
    let build = Digest::parse(&"b".repeat(64)).unwrap();
    assert_eq!(jobs.next(&BTreeMap::new(), build), Some(id(&upload)));
}

/// A settled job whose attempt bulk is gone still loads, and dispatch
/// starts the next queued job.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_settled_job_without_its_attempt_bulk_loads_and_the_queue_continues() {
    let _processes = processes();
    let host = Host::new("settled-without-bulk");
    let store = Store::open(&host.case.state).unwrap();
    host.config(&store, &[]);
    host.capacity(&store, "upload", 1);
    let first = host.job(&store, 0, "upload", Purpose::Campaign, 1);
    let mut options = host.options();
    options.environment.insert(
        "ARTIFACT_TEMPLATE".into(),
        crate::attempt::tests::write_bundle_template(&store, &first).into_os_string(),
    );
    fs::write(
        &options.launcher,
        crate::attempt::tests::bundle_launcher(false),
    )
    .unwrap();
    let report = dispatch(&store, &mut host.custody(), &options).unwrap();
    assert_eq!(
        report.completed[0].binding,
        crate::record::Binding::Matching
    );
    assert!(report.completed[0].bound.as_ref().unwrap().bundle.is_some());
    assert_eq!(report.started, 1, "{report:?}");
    assert!(report.refusals.is_empty(), "{report:?}");
    assert!(
        crate::campaign::state_fixture::result_path(&host.case.state, first.job().id()).exists()
    );
    let attempt = attempt_path(&host, &first);
    let bundle = attempt
        .join("artifacts")
        .join(report.completed[0].attempt.as_str())
        .join("bundle");
    assert!(bundle.is_file());
    for entry in fs::read_dir(&attempt).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().into_string().unwrap();
        if !crate::store::ATTEMPT_RECORDS.contains(&name.as_str()) {
            if entry.file_type().unwrap().is_dir() {
                fs::remove_dir_all(entry.path()).unwrap();
            } else {
                fs::remove_file(entry.path()).unwrap();
            }
        }
    }
    assert!(!bundle.exists());
    let queued = host.job(&store, 1, "upload", Purpose::Campaign, 1);
    let report = dispatch(&store, &mut host.custody(), &host.options()).unwrap();
    assert!(report.refusals.is_empty(), "{report:?}");
    assert_eq!(report.started, 1, "{report:?}");
    assert!(attempt_path(&host, &queued).exists());
}

/// After collect reclaims a settled job's attempt, the dispatch start's job
/// load settles the job by name and reads none of its bulk, damaged bytes
/// under a bulk name included, and refuses nothing.
#[test]
fn a_reclaimed_settled_job_loads_by_name_and_reads_no_bulk() {
    let fixture = crate::campaign::report::tests::Fixture::new();
    fixture.probe();
    let job = fixture.admit(0);
    let id = job.job().id().to_string();
    let directory = fixture.finish(&job, Some(7));
    for output in crate::custody::LAUNCHER_OUTPUTS {
        fixture
            .store
            .create_once(&directory, &name(output), b"launcher log")
            .unwrap();
    }
    let path = fixture.case.state.clone();
    drop(fixture.store);
    let collected = crate::campaign::collect::collect(&path, false).unwrap();
    let attempt = crate::layout::attempt_path(&id, 1);
    assert_eq!(
        collected["reclaimed"],
        serde_json::json!([attempt.to_str().unwrap()]),
        "{collected}"
    );
    fs::write(
        path.join(&attempt)
            .join("artifacts")
            .join(format!("{id}-0001"))
            .join("bundle"),
        b"damaged",
    )
    .unwrap();
    let store = Store::open(&path).unwrap();
    let mut report = Report::default();
    let loaded = super::super::recovery::Jobs::load(&store, &mut report)
        .unwrap()
        .unwrap();
    assert!(report.refusals.is_empty(), "{report:?}");
    assert!(!loaded.records.contains_key(&id));
}

#[test]
fn a_non_digest_result_name_refuses_its_job_and_history() {
    let case = crate::store::fixture::Case::new();
    let store = Store::open(&case.state).unwrap();
    let shard = crate::layout::make_shard(&store, crate::layout::JOBS, "abinvalid").unwrap();
    store
        .create_once(&shard, &name("abinvalid.result.json"), b"settled")
        .unwrap();
    fs::create_dir_all(case.state.join("attempts/ab/abinvalid")).unwrap();
    let mut report = Report::default();
    let loaded = super::super::recovery::Jobs::load(&store, &mut report)
        .unwrap()
        .unwrap();
    assert!(loaded.records.is_empty());
    assert_eq!(
        report.refusals,
        [
            "job abinvalid: invalid job identity filename",
            "attempts without readable job abinvalid"
        ]
    );
}

#[test]
fn readers_accept_empty_job_and_attempt_shards() {
    for roots in [vec!["jobs"], vec!["attempts"], vec!["jobs", "attempts"]] {
        let case = crate::store::fixture::Case::new();
        let store = Store::open(&case.state).unwrap();
        for root in &roots {
            crate::layout::make_shard(&store, root, "e9").unwrap();
        }
        let mut report = Report::default();
        let loaded = super::super::recovery::Jobs::load(&store, &mut report).unwrap();
        assert_eq!(loaded.is_some(), roots.contains(&"jobs"));
        assert!(report.refusals.is_empty(), "{report:?}");
        let config = crate::campaign::state_fixture::config(1 << 20, 100);
        let usage = crate::campaign::census::census(&store, &config).unwrap();
        assert_eq!((usage.inodes, usage.bytes), (0, 0));
        assert!(
            crate::campaign::show(&case.state).unwrap()["jobs"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(
            crate::campaign::status_tests::status(&case.state).unwrap()["jobs"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(
            crate::campaign::findings(&case.state).unwrap()["release_blockers"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        drop(store);
        let projected = crate::campaign::report(&case.state).unwrap();
        assert!(
            !projected["held"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row.to_string().contains("e9")),
            "{projected}"
        );
    }
}

#[test]
fn report_and_findings_check_each_shard_placement_and_bound() {
    for root in ["jobs", "attempts"] {
        for placement in ["0", "ff"] {
            let case = crate::store::fixture::Case::new();
            let store = Store::open(&case.state).unwrap();
            let job = crate::campaign::state_fixture::job(&store, 0);
            let id = job.job().id().to_string();
            assert_ne!(crate::layout::shard(&id).as_str(), "ff");
            let foreign = placement != "ff";
            let path = if foreign {
                format!("{root}/{placement}")
            } else if root == "jobs" {
                format!("jobs/ff/{id}.result.json")
            } else {
                format!("attempts/ff/{id}")
            };
            if foreign {
                for entry in ["0", "zz"] {
                    fs::create_dir_all(case.state.join(root).join(entry)).unwrap();
                }
            } else if root == "jobs" {
                fs::create_dir_all(case.state.join("jobs/ff")).unwrap();
                fs::write(case.state.join(&path), b"stray").unwrap();
            } else {
                fs::create_dir_all(case.state.join(&path)).unwrap();
            }
            drop(store);
            let error = crate::campaign::findings(&case.state).unwrap_err();
            assert!(error.to_string().contains(&path), "{error}");
            let projected = crate::campaign::report(&case.state).unwrap();
            assert!(
                projected["jobs"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|row| row["id"] == id),
                "{projected}"
            );
            let held_paths = if foreign {
                vec![path, format!("{root}/zz")]
            } else {
                vec![path]
            };
            for path in held_paths {
                assert!(
                    projected["held"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|row| row.to_string().contains(&path)),
                    "{projected}"
                );
            }
        }
    }
    for kind in ["jobs", "attempts", "history"] {
        let case = crate::store::fixture::Case::new();
        let store = Store::open(&case.state).unwrap();
        let job = crate::campaign::state_fixture::job(&store, 0);
        let id = job.job().id().to_string();
        let path = match kind {
            "jobs" => format!("jobs/{}", crate::layout::shard(&id).as_str()),
            "attempts" => format!("attempts/{}", crate::layout::shard(&id).as_str()),
            _ => crate::campaign::state_fixture::attempts_dir(&id)
                .display()
                .to_string(),
        };
        fs::create_dir_all(case.state.join(&path)).unwrap();
        for number in 1..=33 {
            let entry = case.state.join(&path).join(format!("{number:04}"));
            if kind == "jobs" {
                fs::write(entry, b"").unwrap();
            } else {
                fs::create_dir(entry).unwrap();
            }
        }
        drop(store);
        let (findings, _) =
            crate::store::fixture::bounded(32, || crate::campaign::findings(&case.state));
        assert!(findings.unwrap_err().at_scan_bound());
        let (projected, _) =
            crate::store::fixture::bounded(32, || crate::campaign::report(&case.state));
        assert!(projected.unwrap_err().at_scan_bound());
    }
}

#[test]
fn unknown_job_files_do_not_mint_findings_at_a_derived_shard() {
    let case = crate::store::fixture::Case::new();
    let store = Store::open(&case.state).unwrap();
    let shard = crate::layout::make_shard(&store, crate::layout::JOBS, "ab").unwrap();
    store
        .create_once(&shard, &name("notes.txt"), b"notes")
        .unwrap();
    let found = crate::campaign::findings(&case.state).unwrap();
    assert!(found["findings"].as_array().unwrap().is_empty(), "{found}");
    assert!(
        found["release_blockers"].as_array().unwrap().is_empty(),
        "{found}"
    );
}

/// A command that reports its refusals as one error keeps the first 16
/// causes and names how many the sample leaves out.
#[test]
fn a_held_reason_counts_the_refusals_its_sample_omits() {
    let case = crate::store::fixture::Case::new();
    let store = Store::open(&case.state).unwrap();
    for index in 0..17 {
        fs::create_dir_all(case.state.join(format!("jobs/stray-{index:02}"))).unwrap();
    }
    let mut report = crate::campaign::dispatch::Report::default();
    crate::campaign::dispatch::recovery::Jobs::load(&store, &mut report).unwrap();
    let reason = report.held_reason();
    assert_eq!(reason.matches("unknown job entry").count(), 16, "{reason}");
    assert!(reason.ends_with("; omitted refusals: 1"), "{reason}");
    assert!(
        reason.contains(sim_host::runner::OMITTED_REFUSALS),
        "the host runner finds the omission in {reason:?}"
    );
}

#[test]
fn foreign_root_entries_hold_per_item_and_preserve_storage() {
    let case = crate::store::fixture::Case::new();
    let store = Store::open(&case.state).unwrap();
    let job = crate::campaign::state_fixture::job(&store, 0);
    let id = job.job().id().to_string();
    for root in ["jobs", "attempts"] {
        for entry in ["0", "zz"] {
            fs::create_dir_all(case.state.join(root).join(entry)).unwrap();
        }
    }
    let mut report = Report::default();
    let loaded = super::super::recovery::Jobs::load(&store, &mut report)
        .unwrap()
        .unwrap();
    assert!(loaded.records.contains_key(&id));
    assert_eq!(
        report.refusals,
        [
            "unknown job entry jobs/0",
            "unknown job entry jobs/zz",
            "attempts without readable job attempts/0",
            "attempts without readable job attempts/zz"
        ]
    );
    let refused = report.refusals.clone();
    report.finish(&store);
    assert_eq!(report.refusals, refused);
    assert!(report.storage.is_some());
    let shown = crate::campaign::status_tests::status(&case.state).unwrap();
    assert!(
        shown["jobs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == id && row["state"] == "queued"),
        "{shown}"
    );
    for path in ["jobs/0", "jobs/zz", "attempts/0", "attempts/zz"] {
        assert!(
            shown["jobs"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["id"] == path && row["held"] == "root entry is not a shard"),
            "{shown}"
        );
    }
    let config = crate::campaign::state_fixture::config(1 << 20, 100);
    for root in ["jobs", "attempts"] {
        for entry in ["0", "zz"] {
            let path = format!("{root}/{entry}");
            let error = crate::campaign::census::census(&store, &config).unwrap_err();
            assert!(matches!(error, Error::Census { .. }));
            assert!(error.to_string().contains(&path), "{error}");
            fs::remove_dir(case.state.join(&path)).unwrap();
        }
    }
}
