use super::super::{policy, recovery::Jobs};
use super::*;
use crate::campaign::state_fixture::Sharded;

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn ancestor_above_the_delegated_root_and_cpu_equality_refuse_admission() {
    let _processes = processes();
    let host = Host::new("ancestor-parent");
    let store = Store::open(&host.case.state).unwrap();
    host.config(&store, &[]);
    let job = host.job(&store, 0, "upload", Purpose::Campaign, 1);
    fs::write(
        host.root.join("cgroup.subtree_control"),
        "+cpu +memory +pids",
    )
    .unwrap();
    let child = host.root.join("child");
    fs::create_dir(&child).unwrap();
    fs::write(host.root.join("cpu.max"), "100000 100000").unwrap();
    let mut custody = Custody::open(
        &child,
        Timing {
            poll: Duration::from_millis(1),
            kill_wait: Duration::from_secs(1),
            watchdog: Duration::from_secs(2),
        },
    )
    .unwrap();
    let report = dispatch(&store, &mut custody, &host.options()).unwrap();
    assert_eq!(report.exit(), crate::exit::Supervisor::Rejected);
    assert_eq!(report.state, super::super::State::Rejected);
    assert_eq!(report.started, 0);
    assert!(
        report
            .rejections
            .iter()
            .any(|reason| reason.contains("cpu") && reason.ends_with(host.root.to_str().unwrap())),
        "{report:?}"
    );
    assert!(!attempt_path(&host, &job).exists());
    let base = crate::custody::Limits {
        cpu_quota_us: 1000,
        memory_bytes: 100,
        pids: 10,
        file_bytes: 100,
        cpu_seconds: 1,
        output_bytes: 100,
        output_inodes: 10,
    };
    let aggregate = policy::aggregate(
        base,
        [crate::attempt::scaled(base, 3).unwrap(), base].into_iter(),
        0,
        2,
    )
    .unwrap();
    fs::write(host.root.join("cpu.max"), "max 100000").unwrap();
    fs::write(host.root.join("pids.max"), "22").unwrap();
    assert!(custody.validate_limits(base, 1).is_ok());
    assert!(matches!(
        custody.validate_limits(aggregate, 1),
        Err(crate::store::cgroup::FitError::Limit {
            resource: "aggregate pids",
            ..
        })
    ));
    drop(custody);
    fs::write(
        host.delegation.join("controller/cgroup.procs"),
        std::process::id().to_string(),
    )
    .unwrap();
    fs::remove_dir(child.join("controller")).unwrap();
    fs::remove_dir(child).unwrap();
}

/// Fills the `jobs/` shard `shard` with result records of settled ids in
/// its shard up to `entries` entries; dispatch settles them by name and
/// reads none.
fn settled_names(shard: &Path, entries: usize) {
    let prefix = shard.file_name().unwrap().to_str().unwrap();
    let mut index = 0;
    while fs::read_dir(shard).unwrap().count() < entries {
        fs::write(
            shard.join(format!("{prefix}{index:062x}.result.json")),
            b"settled",
        )
        .unwrap();
        index += 1;
    }
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_settlement_that_fills_jobs_holds_the_next_start() {
    let _processes = processes();
    for max_attempts in [None, Some(1)] {
        let host = Host::new("census-bound");
        let store = Store::open(&host.case.state).unwrap();
        host.config(&store, &[("wall", 60), ("slots", 1)]);
        host.capacity(&store, "upload", 1);
        let first = (0..2)
            .map(|run| host.job(&store, run, "upload", Purpose::Campaign, 1))
            .map(|job| job.job().id().to_string())
            .min()
            .unwrap();
        // The first job's shard is filled with settled names to one entry
        // below the bound, so its result record reaches the bound.
        let bound = 16;
        let shard = host
            .case
            .state
            .join("jobs")
            .join(crate::layout::shard(&first).as_str());
        settled_names(&shard, bound - 1);
        step::install(Some(Script {
            scan_bound: Some(bound),
            ..Script::default()
        }));
        let mut custody = host.custody();
        let mut options = host.options();
        options.max_attempts = max_attempts;
        let report = dispatch(&store, &mut custody, &options).unwrap();
        step::install(None);
        assert_eq!(report.exit(), crate::exit::Supervisor::Held, "{report:?}");
        assert_eq!(report.state, super::super::State::Held);
        assert_eq!(
            report.refusals,
            [format!(
                "jobs/{} holds {bound} entries at bound {bound}; collect or shard",
                crate::layout::shard(&first).as_str()
            )]
        );
        assert_eq!(report.started, 1);
        assert_eq!(report.completed.len(), 1);
        assert_eq!(report.completed[0].exit, Some(0));
        let (id, number) = report.completed[0]
            .attempt
            .as_str()
            .rsplit_once('-')
            .unwrap();
        assert!(
            host.case
                .state
                .join(crate::campaign::state_fixture::attempts_dir(id))
                .join(number)
                .join("worker-ran")
                .exists()
        );
        assert_eq!(
            report.paused,
            if max_attempts.is_none() {
                ["slots".to_owned()].into()
            } else {
                Default::default()
            },
            "{report:?}"
        );
        assert_eq!(fs::read_dir(&shard).unwrap().count(), bound);
        assert_eq!(
            fs::read_dir(&host.root)
                .unwrap()
                .flatten()
                .filter(|entry| entry.file_type().unwrap().is_dir()
                    && entry.file_name() != "controller")
                .count(),
            0
        );
    }
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn jobs_at_the_scan_bound_hold_dispatch_before_any_start() {
    let _processes = processes();
    let host = Host::new("jobs-bound");
    let store = Store::open(&host.case.state).unwrap();
    host.config(&store, &[]);
    host.capacity(&store, "upload", 2);
    let jobs: Vec<_> = (0..2)
        .map(|run| host.job(&store, run, "upload", Purpose::Campaign, 1))
        .collect();
    let id = jobs[0].job().id().to_string();
    let entries = 16;
    let shard = host
        .case
        .state
        .join("jobs")
        .join(crate::layout::shard(&id).as_str());
    settled_names(&shard, entries);
    let mut custody = host.custody();
    let (report, _) = crate::store::fixture::bounded(entries, || {
        dispatch(&store, &mut custody, &host.options()).unwrap()
    });
    assert_eq!(report.exit(), crate::exit::Supervisor::Held, "{report:?}");
    assert_eq!(report.state, super::super::State::Held);
    assert_eq!(
        report.refusals,
        [format!(
            "jobs/{} holds {entries} entries at bound {entries}; collect or shard",
            crate::layout::shard(&id).as_str()
        )]
    );
    assert_eq!(report.started, 0);
    assert!(report.paused.is_empty(), "{report:?}");
    assert!(jobs.iter().all(|job| !attempt_path(&host, job).exists()));
    assert_eq!(
        report.storage.as_ref().unwrap().roots["jobs"],
        crate::campaign::Root {
            entries,
            bound: entries
        }
    );
    drop(custody);
    drop(store);
    for root in [
        "jobs",
        "triage",
        "findings",
        "calibrations",
        "calibration-jobs",
        "triage-steps",
    ] {
        let host = Host::new(&format!("startup-{root}"));
        let store = Store::open(&host.case.state).unwrap();
        host.config(&store, &[]);
        host.job(&store, 0, "upload", Purpose::Campaign, 1);
        let measured = match root {
            "calibration-jobs" => "jobs",
            "triage-steps" => "triage/retained/steps",
            root => root,
        };
        if root == "calibration-jobs" {
            fs::create_dir_all(host.case.state.join("calibrations/missing-plan")).unwrap();
        }
        let path = host.case.state.join(measured);
        fs::create_dir_all(&path).unwrap();
        for n in 0..33 {
            fs::create_dir(path.join(format!("retained-{n}"))).unwrap();
        }
        step::install(Some(Script {
            scan_bound: Some(32),
            ..Default::default()
        }));
        let report = dispatch(&store, &mut host.custody(), &host.options()).unwrap();
        step::install(None);
        let expected = if root == "calibrations" {
            "a listing exceeds its scan bound".to_owned()
        } else {
            format!("{measured} holds more than 32 entries at bound 32; collect or shard")
        };
        assert_eq!(report.refusals, [expected], "{root}: {report:?}");
        assert_eq!(report.state, super::super::State::Held, "{root}");
        // The charged census lists `jobs/`, `attempts/` and `probes/` only,
        // so a full `findings/` holds at the first listing of it, triage
        // selection after the first conclusion.
        assert_eq!(
            report.started,
            u64::from(root == "findings"),
            "{root}: {report:?}"
        );
        assert_eq!(
            report.storage.is_none(),
            !matches!(root, "calibrations" | "triage-steps"),
            "{root}"
        );
    }
    let host = Host::new("startup-custody-fault");
    let store = Store::open(&host.case.state).unwrap();
    let mut custody = host.custody();
    step::install(Some(Script {
        nth: Some((Step::List, 0, Outcome::Errno(libc::EIO))),
        ..Default::default()
    }));
    let report = dispatch(&store, &mut custody, &host.options()).unwrap();
    let script = step::install(None).unwrap();
    assert!(script.nth.is_none());
    assert_eq!(report.refusals.len(), 1, "{report:?}");
    assert!(
        report.refusals[0].contains("Input/output error"),
        "{report:?}"
    );
    assert_eq!(report.state, super::super::State::Held);
    assert_eq!(report.started, 0);
    assert!(report.storage.is_some());
    drop(custody);
    drop(store);
    let host = Host::new("startup-compound-hold");
    let store = Store::open(&host.case.state).unwrap();
    fs::create_dir(host.case.state.join("probes")).unwrap();
    for n in 0..32 {
        fs::create_dir(host.case.state.join(format!("probes/probe-{n}"))).unwrap();
    }
    fs::create_dir(host.case.state.join("jobs")).unwrap();
    fs::write(host.case.state.join("jobs/.foreign-job"), b"").unwrap();
    let mut custody = host.custody();
    step::install(Some(Script {
        scan_bound: Some(32),
        ..Default::default()
    }));
    let report = dispatch(&store, &mut custody, &host.options()).unwrap();
    step::install(None);
    assert_eq!(
        report.refusals,
        [
            "probes holds 32 entries at bound 32; collect or shard",
            "a listing holds the foreign entry \".foreign-job\"",
        ]
    );
    assert_eq!(report.state, super::super::State::Held);
    assert_eq!(report.started, 0);
    assert!(report.storage.is_none());
    fs::write(host.case.state.join("probes/.foreign-probe"), b"").unwrap();
    let error = super::super::recover(&store, &mut custody).unwrap_err();
    assert_eq!(
        error.to_string(),
        "a listing holds the foreign entry \".foreign-probe\"; a listing holds the foreign entry \".foreign-job\""
    );
    step::install(Some(Script {
        nth: Some((Step::List, 4, Outcome::Errno(libc::EIO))),
        ..Default::default()
    }));
    let error = super::super::recover(&store, &mut custody).unwrap_err();
    let script = step::install(None).unwrap();
    assert!(script.nth.is_none());
    let reason = error.to_string();
    assert!(reason.starts_with("a listing holds the foreign entry \".foreign-probe\"; a listing holds the foreign entry \".foreign-job\"; "), "{reason}");
    assert!(reason.contains("Input/output error"), "{reason}");
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn ancestor_io_invalid_input_remains_an_io_failure() {
    let _processes = processes();
    let host = Host::new("ancestor-io");
    let custody = host.custody();
    let limits = crate::custody::Limits {
        cpu_quota_us: 100_000,
        memory_bytes: 1 << 30,
        pids: 64,
        file_bytes: 1 << 20,
        cpu_seconds: 300,
        output_bytes: u64::MAX,
        output_inodes: 4094,
    };
    step::install(Some(Script {
        nth: Some((Step::Open, 0, Outcome::Errno(libc::EINVAL))),
        ..Script::default()
    }));
    let result = custody.validate_limits(limits, 3);
    step::install(None);
    assert!(
        matches!(result, Err(crate::store::cgroup::FitError::Io(error)) if error.raw_os_error() == Some(libc::EINVAL))
    );
}

#[test]
fn retained_build_order_prefers_the_running_build_then_the_queue_order() {
    let mut host = Fixture::new();
    let store = Store::open(&host.case.state).unwrap();
    let a = host.job(&store, 0, "upload", Purpose::Campaign, 1);
    let selected = Digest::parse(host.pins.build.as_str()).unwrap();
    host.pins.build = text(&"c".repeat(64));
    let b = host.job(&store, 1, "upload", Purpose::Campaign, 1);
    let queue = [&b, &a, &b];
    assert_eq!(
        policy::builds(&queue, false, selected, 1),
        (vec!["retained_builds", "archive"], false)
    );
    assert_eq!(
        policy::builds(&queue, true, selected, 1),
        (vec!["retained_builds"], true)
    );
    assert_eq!(
        policy::builds(&queue, false, selected, 2),
        (vec!["archive"], true)
    );
}

#[test]
fn ordering_counts_published_profiles_then_job_attempts_then_identity() {
    let host = Fixture::new();
    let store = Store::open(&host.case.state).unwrap();
    let a = host.job(&store, 0, "upload", Purpose::Campaign, 5);
    let b = host.job(&store, 1, "upload", Purpose::Campaign, 5);
    let c = host.job(&store, 2, "cluster-broad", Purpose::Campaign, 5);
    let d = host.job(&store, 3, "cluster-broad", Purpose::Campaign, 5);
    let id = |job: &Admission| job.job().id().to_string();
    let mut report = Report::default();
    let mut jobs = Jobs::load(&store, &mut report).unwrap().unwrap();
    jobs.counts = [(id(&a), 3), (id(&b), 0), (id(&c), 1), (id(&d), 0)].into();
    jobs.settled.insert(id(&c));
    let build = Digest::parse(host.pins.build.as_str()).unwrap();
    assert_eq!(jobs.next(&BTreeMap::new(), build), Some(id(&d)));
    jobs.counts = [(id(&a), 3), (id(&b), 1), (id(&c), 50), (id(&d), 2)].into();
    assert_eq!(jobs.next(&BTreeMap::new(), build), Some(id(&d)));
    jobs.settled.insert(id(&d));
    let (low, high) = if id(&a) < id(&b) {
        (id(&a), id(&b))
    } else {
        (id(&b), id(&a))
    };
    jobs.counts = [(low, 3), (high.clone(), 1), (id(&c), 50), (id(&d), 9)].into();
    assert_eq!(jobs.next(&BTreeMap::new(), build), Some(high));
    jobs.counts.insert(id(&a), 0);
    jobs.counts.insert(id(&b), 0);
    assert_eq!(jobs.next(&BTreeMap::new(), build), Some(id(&a).min(id(&b))));
}

#[test]
fn each_pause_boundary_reserves_triage_and_allows_one_unit_of_headroom() {
    let host = Fixture::new();
    let store = Store::open(&host.case.state).unwrap();
    for reserve in [1, 2] {
        let config = host.config(&store, &[("reserve_slots", reserve)]);
        let charge = config.charge();
        let bytes = charge.bytes as u64;
        let inodes = charge.inodes as u64;
        let disk = charge.disk(std::num::NonZeroU64::new(4096).unwrap()) as u64;
        for dimension in ["disk", "disk_inodes", "artifact_bytes", "artifact_inodes"] {
            let mut usage = Usage {
                bytes: 0,
                inodes: 0,
                free_bytes: u64::MAX,
                free_inodes: u64::MAX,
                fragment_bytes: std::num::NonZeroU64::new(4096).unwrap(),
            };
            match dimension {
                "disk" => usage.free_bytes = (2 + reserve) * disk,
                "disk_inodes" => usage.free_inodes = (2 + reserve) * inodes,
                "artifact_bytes" => {
                    usage.bytes = config.value("artifact_bytes") - (2 + reserve) * bytes
                }
                "artifact_inodes" => {
                    usage.inodes = config.value("artifact_inodes") - (2 + reserve) * inodes
                }
                _ => unreachable!(),
            }
            assert!(
                policy::storage_pauses(&config, usage, 1, config.value("reserve_slots"))
                    .contains(dimension)
            );
            match dimension {
                "disk" => usage.free_bytes += 1,
                "disk_inodes" => usage.free_inodes += 1,
                "artifact_bytes" => usage.bytes -= 1,
                "artifact_inodes" => usage.inodes -= 1,
                _ => unreachable!(),
            }
            assert!(
                !policy::storage_pauses(&config, usage, 1, config.value("reserve_slots"))
                    .contains(dimension)
            );
        }
        let backlog = config.value("backlog");
        assert!(policy::backlog_hold(&config, backlog - 1).is_ok());
        let held = policy::backlog_hold(&config, backlog)
            .unwrap_err()
            .to_string();
        assert_eq!(
            held,
            format!(
                "backlog holds {backlog} failure pins without a resolved disposition at limit {backlog}; dispose findings or raise backlog"
            )
        );
        assert!(
            sim_host::runner::is_backlog_hold(&held),
            "the host runner reads {held:?} as the backlog hold"
        );
    }
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_single_slot_configuration_starts_one_tree_at_a_time() {
    let _processes = processes();
    let host = Host::new("single-slot");
    let store = Store::open(&host.case.state).unwrap();
    host.config(&store, &[("slots", 1)]);
    for run in 0..2 {
        host.job(&store, run, "upload", Purpose::Campaign, 1);
    }
    let mut custody = host.custody();
    let root = host.root.clone();
    let seen = std::rc::Rc::new(std::cell::Cell::new(0));
    let witness = seen.clone();
    step::install(Some(Script {
        observe: Some(Box::new(move |at| {
            if at == Step::Go {
                assert_eq!(
                    fs::read_dir(&root)
                        .unwrap()
                        .flatten()
                        .filter(|entry| entry.file_type().unwrap().is_dir()
                            && entry.file_name() != "controller")
                        .count(),
                    1
                );
                witness.set(witness.get() + 1);
            }
        })),
        ..Script::default()
    }));
    let report = dispatch(&store, &mut custody, &host.options()).unwrap();
    step::install(None);
    assert_eq!(report.exit(), crate::exit::Supervisor::Success);
    assert_eq!(report.started, 2);
    assert_eq!(seen.get(), 2);
}

/// A first configuration, a raise of its slots and a return to the first
/// each install, and the stored record is the last one installed.
#[test]
fn a_first_a_raised_and_a_lowered_configuration_each_install() {
    let host = Fixture::new();
    let store = Store::open(&host.case.state).unwrap();
    let first = host.config(&store, &[]);
    host.job(&store, 0, "upload", Purpose::Campaign, 1);
    fs::remove_file(host.case.state.join("config.json")).unwrap();
    assert_eq!(
        crate::campaign::configure(&store, first.clone()).unwrap(),
        first
    );
    let mut values = first.config().clone();
    values.insert(text("slots"), 3);
    let raised = Configuration::new(values).unwrap();
    assert_eq!(
        crate::campaign::configure(&store, raised.clone()).unwrap(),
        raised
    );
    assert_eq!(
        crate::campaign::configure(&store, first.clone()).unwrap(),
        first
    );
    let saved = store
        .read_record::<Configuration>(store.root(), &name("config.json"))
        .unwrap()
        .unwrap();
    assert_eq!(saved.record(), &first);
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn archive_and_retained_build_filters_leave_foreign_jobs_queued() {
    let _processes = processes();
    for retained in [1, 2] {
        let mut host = Host::new(&format!("build-filter-{retained}"));
        let store = Store::open(&host.case.state).unwrap();
        host.config(&store, &[("retained_builds", retained)]);
        let local = host.job(&store, 0, "upload", Purpose::Campaign, 1);
        let build = Digest::parse(host.pins.build.as_str()).unwrap();
        host.pins.build = text(&Digest::of(b"foreign-build").to_string());
        let mut foreign = Vec::new();
        for run in 0..100 {
            let job = host.job(&store, run, "upload", Purpose::Campaign, 1);
            let earlier = job.job().id().to_string() < local.job().id().to_string();
            foreign.push(job);
            if earlier {
                break;
            }
        }
        assert!(
            foreign
                .iter()
                .any(|job| job.job().id().to_string() < local.job().id().to_string())
        );
        let mut loaded_report = Report::default();
        let jobs = Jobs::load(&store, &mut loaded_report).unwrap().unwrap();
        assert_eq!(
            jobs.next(&BTreeMap::new(), build),
            Some(local.job().id().to_string())
        );
        let report = dispatch(&store, &mut host.custody(), &host.options()).unwrap();
        assert_eq!(report.started, retained - 1, "{report:?}");
        assert!(report.paused.contains("archive"));
        assert_eq!(report.pauses["archive"], 1);
        assert_eq!(
            report.pauses.get("retained_builds"),
            if retained == 1 { Some(&1) } else { None }
        );
        assert_eq!((report.collect_passes, report.collect_finished), (0, None));
        assert_eq!(report.paused.contains("retained_builds"), retained == 1);
        // Only foreign-build jobs remain queued, so the build filter ends
        // the window.
        assert_eq!(report.state, super::super::State::Paused, "{report:?}");
        for job in foreign {
            assert!(!attempt_path(&host, &job).exists());
        }
    }
}

#[test]
fn empty_files_keep_a_fragment_cushion_in_the_disk_charge() {
    let host = Fixture::new();
    let store = Store::open(&host.case.state).unwrap();
    let config = host.config(&store, &[("slots", 1)]);
    let before = store.usage(crate::SCAN_BOUND).unwrap();
    for n in 0..4 {
        fs::write(host.case.state.join(format!("empty-{n}")), b"").unwrap();
    }
    let mut usage = store.usage(crate::SCAN_BOUND).unwrap();
    assert_eq!(usage.bytes, before.bytes);
    assert_eq!(usage.inodes, before.inodes + 4);
    let charge = config.charge();
    assert_eq!(
        charge.disk(usage.fragment_bytes) - charge.bytes,
        charge.inodes * u128::from(usage.fragment_bytes.get())
    );
    usage.free_bytes = (2 * charge.bytes + 1) as u64;
    assert!(
        policy::storage_pauses(&config, usage, 0, config.value("reserve_slots")).contains("disk")
    );
    usage.free_bytes = (2 * charge.disk(usage.fragment_bytes) + 1) as u64;
    assert!(
        !policy::storage_pauses(&config, usage, 0, config.value("reserve_slots")).contains("disk")
    );
}

#[test]
fn aggregate_charges_installed_pids_and_only_unoccupied_triage_reserve() {
    let base = crate::custody::Limits {
        cpu_quota_us: 1000,
        memory_bytes: 100,
        pids: 10,
        file_bytes: 100,
        cpu_seconds: 1,
        output_bytes: 100,
        output_inodes: 10,
    };
    let targeted = crate::attempt::scaled(base, 3).unwrap();
    let aggregate = policy::aggregate(base, [targeted, base].into_iter(), 0, 2).unwrap();
    assert_eq!(
        (
            aggregate.cpu_quota_us,
            aggregate.memory_bytes,
            aggregate.pids
        ),
        (4000, 400, 22)
    );
    let reserve = policy::aggregate(base, [targeted].into_iter(), 1, 2).unwrap();
    assert_eq!(
        (reserve.cpu_quota_us, reserve.memory_bytes, reserve.pids),
        (4000, 400, 22)
    );
}

#[test]
fn targeted_frozen_input_hold_requires_empty_history_and_absent_settlement() {
    use crate::campaign::report::tests::Fixture as ReportFixture;
    for state in [
        "absent",
        "empty",
        "minted",
        "pin",
        "result",
        "damaged-result",
    ] {
        let fixture = ReportFixture::new();
        let healthy = fixture.admit(0);
        let queued = fixture.admit(2);
        fixture.finish(&healthy, Some(7));
        let target = fixture.targeted(1);
        let id = target.job().id().to_string();
        let store = &fixture.store;
        let jobs = store.shard_jobs(healthy.job().id()).unwrap().unwrap();
        let target_jobs = store.shard_jobs(&id).unwrap().unwrap();
        if matches!(state, "empty" | "minted") {
            let attempts = crate::layout::make_shard(store, crate::layout::ATTEMPTS, &id).unwrap();
            store.mkdir(&attempts, &name(&id)).unwrap();
            if state == "minted" {
                let root = store.open_dir(&attempts, &name(&id)).unwrap().unwrap();
                store.mkdir(&root, &name("0001")).unwrap();
            }
        }
        if matches!(state, "pin" | "result") {
            let mut result = store
                .read_record::<crate::record::JobResult>(
                    &jobs,
                    &name(&format!(
                        "{}{}",
                        healthy.job().id(),
                        crate::record::JobResult::SUFFIX
                    )),
                )
                .unwrap()
                .unwrap()
                .record()
                .clone();
            result.job = target.job().id().digest();
            result.manifest = target.job().manifest_sha256();
            result.finished.attempt = text(&format!("{id}-0001"));
            if state == "pin" {
                store
                    .create_record(
                        &target_jobs,
                        &name(&format!("{id}{}", crate::record::Pin::SUFFIX)),
                        &crate::record::Pin { result },
                    )
                    .unwrap();
            } else {
                store
                    .create_record(
                        &target_jobs,
                        &name(&format!("{id}{}", crate::record::JobResult::SUFFIX)),
                        &result,
                    )
                    .unwrap();
            }
        }
        if state == "damaged-result" {
            store
                .create_once(
                    &target_jobs,
                    &name(&format!("{id}{}", crate::record::JobResult::SUFFIX)),
                    b"damaged",
                )
                .unwrap();
        }
        store
            .replace(
                &target_jobs,
                &name(&format!("{id}.bundle")),
                b"damaged frozen input",
            )
            .unwrap();
        let mut report = Report::default();
        let loaded = Jobs::load(store, &mut report).unwrap().unwrap();
        let healthy_id = healthy.job().id().to_string();
        assert!(
            !report
                .refusals
                .iter()
                .any(|refusal| refusal.contains(&healthy_id)),
            "{report:?}"
        );
        assert!(!loaded.records.contains_key(&id));
        assert!(loaded.records.contains_key(&queued.job().id().to_string()));
        assert!(loaded.settled.is_empty());
        let local = matches!(state, "absent" | "empty");
        // A result record settles the job by its name, so dispatch reads none
        // of its records and its damaged input waits for the findings scan.
        let settled = matches!(state, "result" | "damaged-result");
        assert_eq!(loaded.excluded.contains(&id), local, "{state}");
        assert_eq!(report.unfit.contains_key(&id), local, "{state}");
        assert_eq!(
            report.exit(),
            if local || settled {
                crate::exit::Supervisor::Success
            } else {
                crate::exit::Supervisor::Held
            },
            "{state}"
        );
        assert_eq!(report.started, 0);
        let path = fixture.case.state.clone();
        drop(fixture.store);
        let findings = crate::campaign::findings(&path).unwrap();
        assert!(
            findings["release_blockers"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| *row
                    == crate::layout::job_file(&id, &format!("{id}.json"))
                        .to_str()
                        .unwrap()),
            "{findings}"
        );
    }
}

#[test]
fn targeted_frozen_input_read_fault_stays_a_global_refusal() {
    let fixture = crate::campaign::report::tests::Fixture::new();
    let target = fixture.targeted(1);
    let id = target.job().id().to_string();
    let (_, trace) =
        crate::store::fixture::scripted([], || Jobs::load(&fixture.store, &mut Report::default()));
    let index = trace
        .iter()
        .rposition(|point| *point == Step::Read)
        .unwrap();
    let mut report = Report::default();
    let (result, trace) =
        crate::store::fixture::scripted([(index, Outcome::Errno(libc::EIO))], || {
            Jobs::load(&fixture.store, &mut report)
        });
    let loaded = result.unwrap().unwrap().unwrap();
    assert_eq!(trace[index], Step::Read);
    assert!(!loaded.records.contains_key(&id));
    assert!(!loaded.excluded.contains(&id));
    assert!(!report.unfit.contains_key(&id));
    assert_eq!(report.exit(), crate::exit::Supervisor::Held);
    assert!(report.stopping());
    assert_eq!(report.started, 0);
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn probes_at_the_scan_bound_hold_admission_before_a_probe_exists() {
    let _processes = processes();
    let host = Host::new("probes-bound");
    let store = Store::open(&host.case.state).unwrap();
    host.config(&store, &[]);
    store.mkdir(store.root(), &name("probes")).unwrap();
    let probes = store
        .open_dir(store.root(), &name("probes"))
        .unwrap()
        .unwrap();
    for index in 0..4 {
        store
            .mkdir(&probes, &name(&format!("probe-{index}")))
            .unwrap();
    }
    let before = crate::store::fixture::snapshot(&host.case.state);
    let request = crate::campaign::Request {
        profile: text("upload"),
        campaign: text("dispatch"),
        run: 0,
        attempts: 1,
        counts: BTreeMap::new(),
    };
    let bounded = |bound| {
        step::install(Some(Script {
            scan_bound: Some(bound),
            ..Default::default()
        }));
        let result = crate::campaign::admit_campaign(
            &store,
            &host.archive,
            &host.root,
            Duration::from_secs(5),
            &request,
        );
        step::install(None);
        result
    };
    let held = bounded(4);
    let Err(error) = held else {
        panic!("admission ran past the probe bound");
    };
    assert_eq!(error.exit(), crate::exit::Supervisor::Held);
    assert_eq!(
        error.to_string(),
        "probes holds 4 entries at bound 4; collect or shard"
    );
    assert_eq!(crate::store::fixture::snapshot(&host.case.state), before);
    // Below the probe count, probe reconciliation's listing refuses and
    // names the root.
    let listed = bounded(3);
    let Err(error) = listed else {
        panic!("admission ran past the probe listing bound");
    };
    assert_eq!(
        error.to_string(),
        "probes holds more than 3 entries at bound 3; collect or shard"
    );
    assert_eq!(crate::store::fixture::snapshot(&host.case.state), before);
    assert_eq!(
        fs::read_dir(&host.root)
            .unwrap()
            .flatten()
            .filter(|entry| entry.file_name() != "controller"
                && entry.file_type().unwrap().is_dir())
            .count(),
        0
    );
}

#[test]
fn storage_counts_each_root_and_the_fullest_job_shard() {
    let host = Fixture::new();
    let store = Store::open(&host.case.state).unwrap();
    let config = host.config(&store, &[]);
    let first = host.job(&store, 0, "upload", Purpose::Campaign, 1);
    for run in 1..3 {
        host.job(&store, run, "upload", Purpose::Campaign, 1);
    }
    // One job shard and one attempts shard hold more entries than the others,
    // so only the fullest shard matches the count.
    crate::campaign::state_fixture::bundle(&store, &first.job().id().to_string(), 1);
    store
        .create_once(
            &store.shard_jobs(first.job().id()).unwrap().unwrap(),
            &name("retained"),
            b"",
        )
        .unwrap();
    for root in ["attempts", "findings", "probes", "triage"] {
        fs::create_dir(host.case.state.join(root)).unwrap();
    }
    for index in 0..5 {
        fs::create_dir(host.case.state.join(format!("probes/probe-{index}"))).unwrap();
    }
    for index in 0..2 {
        fs::create_dir(host.case.state.join(format!("attempts/a{index}"))).unwrap();
    }
    fs::create_dir(host.case.state.join("attempts/a1/a1")).unwrap();
    for index in 0..3 {
        fs::create_dir(host.case.state.join(format!("triage/t{index}"))).unwrap();
    }
    fs::create_dir(host.case.state.join("findings/a")).unwrap();
    // Distinct scripted free space tells the two measured fields apart.
    step::install(Some(Script {
        free_space: Some((7, 11)),
        ..Script::default()
    }));
    let storage = crate::campaign::storage::measure(&store).unwrap();
    let shown = crate::campaign::show(&host.case.state).unwrap();
    step::install(None);
    assert_eq!(storage.roots["jobs"].entries, 4);
    assert_ne!(
        storage.roots["jobs"].entries,
        fs::read_dir(host.case.state.join("jobs")).unwrap().count()
    );
    assert_eq!(storage.roots["attempts"].entries, 1);
    let independent = |root: &str| {
        let entries = fs::read_dir(host.case.state.join(root)).unwrap();
        if ["jobs", "attempts"].contains(&root) {
            entries
                .map(|shard| fs::read_dir(shard.unwrap().path()).unwrap().count())
                .max()
                .unwrap_or(0)
        } else {
            entries.count()
        }
    };
    assert_eq!(
        storage.roots.keys().map(String::as_str).collect::<Vec<_>>(),
        ["attempts", "findings", "jobs", "probes", "triage"]
    );
    for (root, found) in &storage.roots {
        assert_eq!(found.entries, independent(root), "{root}");
        assert_eq!(found.bound, crate::SCAN_BOUND);
        assert_eq!(
            shown["storage"]["roots"][root]["entries"],
            independent(root),
            "{root}"
        );
        assert_eq!(
            shown["storage"]["roots"][root]["bound"],
            crate::SCAN_BOUND,
            "{root}"
        );
    }
    assert_eq!(
        shown["storage"]["roots"].as_object().unwrap().len(),
        storage.roots.len()
    );
    assert_eq!((storage.free_bytes, storage.free_inodes), (7, 11));
    assert_eq!(shown["storage"]["free_bytes"], 7);
    assert_eq!(shown["storage"]["free_inodes"], 11);
    // The census holds at the fullest job shard, and a bound above every
    // counted listing counts.
    let shard = format!(
        "jobs/{}",
        crate::layout::shard(&first.job().id().to_string()).as_str()
    );
    let jobs = independent("jobs");
    let census = |bound| crate::campaign::state_fixture::counted_at(&store, bound);
    assert_eq!(
        census(jobs).unwrap_err().to_string(),
        format!("{shard} holds {jobs} entries at bound {jobs}; collect or shard")
    );
    let usage = crate::store::fixture::bounded(independent("probes") + 1, || {
        crate::campaign::census::census(&store, &config)
    })
    .0
    .unwrap();
    let files = crate::campaign::state_fixture::job_file_lengths(&host.case.state);
    assert_eq!(
        usage.inodes,
        files.len() as u64 + 5 * crate::campaign::probe::OUTPUT_INODES
    );
    assert_eq!(
        usage.bytes,
        files.iter().sum::<u64>() + 5 * crate::campaign::probe::OUTPUT_BYTES
    );
}

/// Job and attempt listings name their roots through admission, recovery
/// and each read-only projection.
#[test]
fn a_listing_past_the_bound_names_its_root() {
    let host = Fixture::new();
    let store = Store::open(&host.case.state).unwrap();
    host.config(&store, &[]);
    let id = host
        .job(&store, 0, "upload", Purpose::Campaign, 1)
        .job()
        .id()
        .to_string();
    let shard = format!("jobs/{}", crate::layout::shard(&id).as_str());
    for index in 0..3 {
        fs::create_dir_all(host.case.state.join(format!("attempts/aa/aa{index}"))).unwrap();
    }
    let bounded = |bound: usize, run: &dyn Fn() -> Result<(), Error>| {
        crate::store::fixture::bounded(bound, run)
            .0
            .unwrap_err()
            .to_string()
    };
    let held = |root: &str, bound: usize| {
        format!("{root} holds more than {bound} entries at bound {bound}; collect or shard")
    };
    let load = || Jobs::load(&store, &mut super::super::Report::default()).map(drop);
    assert_eq!(bounded(1, &load), held(&shard, 1));
    assert_eq!(bounded(2, &load), held("attempts/aa", 2));
    assert_eq!(
        bounded(1, &|| policy::backlog(&store).map(drop)),
        held(&shard, 1)
    );
    assert_eq!(
        bounded(2, &|| crate::campaign::storage::measure(&store).map(drop)),
        held("attempts/aa", 2)
    );
    let listing =
        crate::protocol::Listing::parse(include_str!("../../../testdata/admission-listing.txt"))
            .unwrap();
    let request = Request {
        profile: text("upload"),
        campaign: text("dispatch"),
        run: 0,
        attempts: 1,
        counts: BTreeMap::new(),
    };
    let before = crate::store::fixture::snapshot(&host.case.state);
    let admit = || {
        admission::admit(
            &store,
            &listing,
            host.pins.clone(),
            text(host.archive.to_str().unwrap()),
            &request,
            Purpose::Campaign,
        )
        .map(drop)
    };
    assert_eq!(bounded(1, &admit), held(&shard, 1));
    assert_eq!(crate::store::fixture::snapshot(&host.case.state), before);
    drop(store);
    for (attempts, command) in [
        (
            false,
            crate::campaign::show as fn(&Path) -> Result<serde_json::Value, Error>,
        ),
        (true, |path| {
            crate::campaign::status(path).map(|_| serde_json::Value::Null)
        }),
    ] {
        assert_eq!(
            bounded(1, &|| command(&host.case.state).map(drop)),
            held(&shard, 1)
        );
        if attempts {
            assert_eq!(
                bounded(2, &|| command(&host.case.state).map(drop)),
                held("attempts/aa", 2)
            );
        }
    }
}

/// A directory nested 64 levels deep stops the census with the depth
/// error, which names nesting, and the entry-count hold stays for counts.
#[test]
fn a_census_names_a_64_level_nesting_as_depth() {
    let host = Fixture::new();
    let store = Store::open(&host.case.state).unwrap();
    host.config(&store, &[]);
    let mut deep = host.case.state.join("triage");
    for _ in 0..64 {
        deep.push("d");
    }
    fs::create_dir_all(&deep).unwrap();
    let error = Error::from(store.usage(crate::SCAN_BOUND).unwrap_err());
    assert!(
        matches!(error, Error::Store(crate::store::Error::DepthBound)),
        "{error:?}"
    );
    assert_eq!(
        error.to_string(),
        "a census found a directory nested 64 levels deep"
    );
    assert_eq!(error.exit(), crate::exit::Supervisor::Held);
}

/// The report's `state` serializes to the snake-case names `dispatch`
/// prints.
#[test]
fn report_states_serialize_to_their_printed_names() {
    use super::super::State;
    let names: Vec<_> = [
        State::QueueEmpty,
        State::Paused,
        State::Held,
        State::Deadline,
        State::MaxAttempts,
        State::Interrupted,
        State::Rejected,
    ]
    .iter()
    .map(|state| serde_json::to_value(state).unwrap())
    .collect();
    assert_eq!(
        names,
        [
            "queue_empty",
            "paused",
            "held",
            "deadline",
            "max_attempts",
            "interrupted",
            "rejected"
        ]
    );
}

/// After a window of starts, conclusions and settlements, the census the
/// session maintained in process equals a fresh census of the tree.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_session_census_matches_a_fresh_census_after_starts_and_settlements() {
    let _processes = processes();
    let host = Host::new("session-census");
    let store = Store::open(&host.case.state).unwrap();
    let config = host.config(&store, &[("attempt_output", 32 << 20)]);
    host.capacity(&store, "upload", 2);
    for run in 0..3 {
        host.job(&store, run, "upload", Purpose::Campaign, 2);
    }
    let options = host.options();
    fs::write(&options.launcher, "#!/bin/sh\nhead -c 32505856 /dev/zero > bulk\ni=0; while [ $i -lt 90 ]; do : > file-$i; i=$((i+1)); done\n").unwrap();
    let mut custody = host.custody();
    let (report, census) = super::super::runner::session(&store, &mut custody, &options).unwrap();
    assert!(report.refusals.is_empty(), "{report:?}");
    assert!(report.started >= 3, "{report:?}");
    assert_eq!(
        census.unwrap(),
        crate::campaign::census::Census::count(&store).unwrap()
    );
    // The declared charge covers what the concluded attempts hold, their
    // job history directories included; the shard directories above them
    // fall to the measured `disk_inodes` dimension.
    let mut measured = crate::store::Usage {
        bytes: 0,
        inodes: 0,
        free_bytes: 0,
        free_inodes: 0,
        fragment_bytes: std::num::NonZeroU64::new(1).unwrap(),
    };
    for shard in crate::layout::shards(&store, crate::layout::ATTEMPTS).unwrap() {
        let shard = shard.unwrap().dir.usage(crate::SCAN_BOUND).unwrap();
        measured.bytes += shard.bytes;
        measured.inodes += shard.inodes;
    }
    let retained = config.retained_charge();
    let concluded = u128::from(report.started);
    assert!(
        u128::from(measured.bytes) <= concluded * retained.bytes,
        "{measured:?}"
    );
    assert!(
        u128::from(measured.bytes) > concluded * (retained.bytes - u128::from(config.file_bytes())),
        "{measured:?}"
    );
    assert!(
        u128::from(measured.inodes)
            > concluded * (retained.inodes - u128::from(config.value("attempt_inodes"))),
        "{measured:?}"
    );
    assert!(
        u128::from(measured.inodes) <= concluded * retained.inodes,
        "{measured:?}"
    );
}

/// The session counts its census once: a probe directory planted after the
/// first start reaches a fresh census and leaves the session's census and
/// its later starts unchanged.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn later_starts_reuse_the_session_census() {
    let _processes = processes();
    let host = Host::new("session-census-cached");
    let store = Store::open(&host.case.state).unwrap();
    let config = host.config(&store, &[]);
    host.capacity(&store, "upload", 2);
    for run in 0..3 {
        host.job(&store, run, "upload", Purpose::Campaign, 2);
    }
    let late = host.case.state.join("probes/probe-late");
    let mut planted = false;
    step::install(Some(Script {
        observe: Some(Box::new(move |at| {
            if at == Step::Go && !planted {
                planted = true;
                fs::create_dir_all(&late).unwrap();
            }
        })),
        ..Script::default()
    }));
    let mut custody = host.custody();
    let session = super::super::runner::session(&store, &mut custody, &host.options());
    step::install(None);
    let (report, census) = session.unwrap();
    assert!(report.refusals.is_empty(), "{report:?}");
    assert!(report.started >= 2, "{report:?}");
    let session = census.unwrap().usage(&store, &config).unwrap();
    let fresh = crate::campaign::census::census(&store, &config).unwrap();
    assert_eq!(fresh.bytes, session.bytes + 8 * crate::record::BOUND);
    assert_eq!(fresh.inodes, session.inodes + 16);
}

/// Targeted conclusions enter the session census at the job's fork shares,
/// and the retained charge covers output that exceeds a one-share budget.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn targeted_conclusions_preserve_the_session_census() {
    let _processes = processes();
    let host = Host::new("target-census");
    let store = Store::open(&host.case.state).unwrap();
    let config = host.config(&store, &[("attempt_output", 32 << 20)]);
    host.capacity(&store, "upload", 2);
    let ordinary = host.job(&store, 0, "upload", Purpose::Campaign, 1);
    let target = crate::campaign::state_fixture::target_admission(&ordinary, 2);
    crate::campaign::state_fixture::retarget(&store, &ordinary, &target, &[0; 48]);
    let options = host.options();
    fs::write(&options.launcher, "#!/bin/sh\nfor i in 1 2 3; do head -c 31457280 /dev/zero > bulk-$i; done\ni=0; while [ $i -lt 200 ]; do : > file-$i; i=$((i+1)); done\n").unwrap();
    let mut custody = host.custody();
    let (report, census) = super::super::runner::session(&store, &mut custody, &options).unwrap();
    assert!(report.refusals.is_empty(), "{report:?}");
    assert_eq!(report.started, 1, "{report:?}");
    assert_eq!(
        census.unwrap(),
        crate::campaign::census::Census::count(&store).unwrap()
    );
    let attempts = store
        .open_dir(store.root(), &name("attempts"))
        .unwrap()
        .unwrap();
    let measured = attempts.usage(crate::SCAN_BOUND).unwrap();
    let retained = config.retained_charge();
    let shares = u128::from(target.shares());
    assert!(u128::from(measured.bytes) > retained.bytes, "{measured:?}");
    assert!(
        u128::from(measured.bytes) <= shares * retained.bytes,
        "{measured:?}"
    );
    assert!(
        u128::from(measured.inodes) > retained.inodes,
        "{measured:?}"
    );
    assert!(
        u128::from(measured.inodes) <= shares * retained.inodes,
        "{measured:?}"
    );
}

/// The most entries any directory under `path` lists, `path` included.
fn widest(path: &Path) -> usize {
    let entries: Vec<_> = fs::read_dir(path).unwrap().flatten().collect();
    entries
        .iter()
        .filter(|entry| entry.file_type().unwrap().is_dir())
        .map(|entry| widest(&entry.path()))
        .fold(entries.len(), usize::max)
}

/// A session holds as soon as a retry fills its attempt history to the
/// listing bound and drains that attempt before returning.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_session_holds_when_a_retry_reaches_the_attempt_bound() {
    let _processes = processes();
    for failed_start in [false, true] {
        let host = Host::new(if failed_start {
            "failed-retry-bound"
        } else {
            "retry-bound"
        });
        let store = Store::open(&host.case.state).unwrap();
        host.config(&store, &[]);
        host.capacity(&store, "upload", 2);
        let job = host.job(&store, 0, "upload", Purpose::Campaign, 100);
        let bound = widest(&host.case.state) + 1;
        assert!(bound < 100, "bound {bound}");
        let mut options = host.options();
        options.max_attempts = None;
        let mut custody = host.custody();
        if failed_start {
            options.max_attempts = Some(bound as u64 - 1);
            let (report, _) =
                super::super::runner::session(&store, &mut custody, &options).unwrap();
            assert_eq!(report.started, bound as u64 - 1, "{report:?}");
            options.max_attempts = None;
            options.deadline = Some(Instant::now() + Duration::from_secs(1));
        }
        let deadline = options.deadline;
        step::install(Some(Script {
            scan_bound: Some(bound),
            observe: Some(Box::new(move |at| {
                if at == Step::Intent
                    && let Some(deadline) = deadline
                {
                    std::thread::sleep(
                        deadline.saturating_duration_since(Instant::now())
                            + Duration::from_millis(10),
                    );
                }
            })),
            ..Script::default()
        }));
        let result = super::super::runner::session(&store, &mut custody, &options);
        step::install(None);
        let (report, _) = result.unwrap();
        assert_eq!(
            report.started,
            if failed_start { 0 } else { bound as u64 },
            "{report:?}"
        );
        assert_eq!(report.exit(), crate::exit::Supervisor::Held, "{report:?}");
        assert!(
            report.refusals.contains(&format!(
                "{} holds {bound} entries at bound {bound}; collect or shard",
                crate::campaign::state_fixture::attempts_dir(job.job().id().to_string()).display()
            )),
            "{report:?}"
        );
        let last = host
            .case
            .state
            .join(crate::campaign::state_fixture::attempts_dir(
                job.job().id().to_string(),
            ))
            .join(format!("{bound:04}"));
        assert!(last.join("finished").exists(), "{report:?}");
        assert!(!last.join("reservation").exists(), "{report:?}");
        if !failed_start {
            assert!(
                report
                    .completed
                    .iter()
                    .any(|finished| finished.attempt.as_str()
                        == format!("{}-{bound:04}", job.job().id())),
                "{report:?}"
            );
        }
        assert!(
            !host
                .case
                .state
                .join(crate::campaign::state_fixture::attempts_dir(
                    job.job().id().to_string()
                ))
                .join(format!("{:04}", bound + 1))
                .exists()
        );
    }
}

/// Failed retry starts charge a newly minted attempt once and preserve
/// the previous charge when launcher validation fails before minting.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn failed_retry_starts_preserve_the_session_census() {
    let _processes = processes();
    for minted in [false, true] {
        let host = Host::new(if minted {
            "failed-minted"
        } else {
            "failed-unminted"
        });
        let store = Store::open(&host.case.state).unwrap();
        host.config(&store, &[]);
        host.capacity(&store, "upload", 2);
        let job = host.job(&store, 0, "upload", Purpose::Campaign, 3);
        let mut custody = host.custody();
        let mut options = host.options();
        options.max_attempts = Some(1);
        let (report, _) = super::super::runner::session(&store, &mut custody, &options).unwrap();
        assert_eq!(report.started, 1, "{report:?}");
        options.max_attempts = None;
        options.deadline = minted.then(|| Instant::now() + Duration::from_secs(1));
        let deadline = options.deadline;
        let launcher = options.launcher.clone();
        let point = if minted { Step::Intent } else { Step::Census };
        let mut triggered = false;
        step::install(Some(Script {
            observe: Some(Box::new(move |at| {
                if at == point && !triggered {
                    triggered = true;
                    if minted {
                        std::thread::sleep(
                            deadline.unwrap().saturating_duration_since(Instant::now())
                                + Duration::from_millis(10),
                        );
                    } else {
                        fs::remove_file(&launcher).unwrap();
                    }
                }
            })),
            ..Script::default()
        }));
        let result = super::super::runner::session(&store, &mut custody, &options);
        let trace = step::install(None).unwrap();
        let (report, census) = result.unwrap();
        assert!(trace.reached.contains(&point), "{report:?}");
        assert_eq!(report.started, 0, "{report:?}");
        assert_eq!(
            census.unwrap(),
            crate::campaign::census::Census::count(&store).unwrap(),
            "{report:?}"
        );
        let path = host
            .case
            .state
            .join(crate::campaign::state_fixture::attempts_dir(
                job.job().id().to_string(),
            ))
            .join("0002");
        assert_eq!(path.exists(), minted, "{report:?}");
    }
}

#[test]
fn finding_and_probe_root_listings_name_their_bounds() {
    for root in ["findings", "probes"] {
        let host = Fixture::new();
        let store = Store::open(&host.case.state).unwrap();
        host.config(&store, &[]);
        fs::create_dir(host.case.state.join(root)).unwrap();
        for index in 0..33 {
            fs::create_dir(host.case.state.join(root).join(format!("entry-{index}"))).unwrap();
        }
        for (probes, command) in [
            (
                false,
                crate::campaign::findings as fn(&Path) -> Result<serde_json::Value, Error>,
            ),
            (true, |path| {
                crate::campaign::status(path).map(|_| serde_json::Value::Null)
            }),
        ] {
            if root == "probes" && !probes {
                continue;
            }
            step::install(Some(Script {
                scan_bound: Some(32),
                ..Default::default()
            }));
            let error = command(&host.case.state).unwrap_err();
            step::install(None);
            assert_eq!(
                error.to_string(),
                format!("{root} holds more than 32 entries at bound 32; collect or shard")
            );
        }
        if root == "findings" {
            step::install(Some(Script {
                scan_bound: Some(32),
                ..Default::default()
            }));
            let error = crate::campaign::triage::select(
                &store,
                Digest::parse(host.pins.build.as_str()).unwrap(),
                &host.config(&store, &[]),
                &Default::default(),
            )
            .err()
            .unwrap();
            step::install(None);
            assert_eq!(
                error.to_string(),
                "findings holds more than 32 entries at bound 32; collect or shard"
            );
        }
    }
}

#[test]
fn report_root_listing_hold_names_the_root() {
    let host = Fixture::new();
    let store = Store::open(&host.case.state).unwrap();
    host.config(&store, &[]);
    fs::create_dir(host.case.state.join("jobs")).unwrap();
    for n in 0..33 {
        fs::write(host.case.state.join(format!("jobs/entry-{n}")), []).unwrap();
    }
    drop(store);
    step::install(Some(Script {
        scan_bound: Some(32),
        ..Default::default()
    }));
    let error = crate::campaign::report(&host.case.state).unwrap_err();
    step::install(None);
    assert_eq!(
        error.to_string(),
        "jobs holds more than 32 entries at bound 32; collect or shard"
    );
}

/// A report keeps the last [`super::super::RECENT`] completions of each
/// kind within [`super::super::RECENT_BYTES`] beside per-class counts, so a
/// window of 10,000 completions stays under 1 MiB and its counts sum to the
/// completions.
#[test]
fn a_report_of_ten_thousand_completions_stays_bounded() {
    let mut report = super::super::Report::default();
    let classes = [
        crate::record::Class::Pass,
        crate::record::Class::Interrupted,
        crate::record::Class::Violation,
    ];
    let finished = |index: u64| crate::record::Finished {
        attempt: text(&format!("{}-{:05}", "a".repeat(64), index)),
        binding: crate::record::Binding::Matching,
        bound: Some(crate::record::BoundEvidence {
            artifact: Digest::of(b"artifact"),
            attempt: text(&format!("{}-{:05}", "a".repeat(64), index)),
            bundle: Some(Digest::of(b"bundle")),
        }),
        class: classes[index as usize % classes.len()],
        exit: Some(0),
        interruption: (classes[index as usize % classes.len()]
            == crate::record::Class::Interrupted)
            .then_some(libc::SIGTERM as u64),
        kernel: crate::record::Kernel {
            cpu: [
                (text("usage_usec"), u64::MAX),
                (text("user_usec"), u64::MAX),
                (text("system_usec"), u64::MAX),
                (text("nr_throttled"), u64::MAX),
            ]
            .into(),
            memory: [
                (text("peak"), u64::MAX),
                (text("oom"), u64::MAX),
                (text("oom_kill"), u64::MAX),
            ]
            .into(),
            pids: [(text("peak"), u64::MAX), (text("max"), u64::MAX)].into(),
        },
        residual_members: false,
        signal: None,
        watchdog: false,
    };
    for index in 0..10_000u64 {
        report.complete(finished(index));
        report.pause(["artifact_inodes".to_owned()]);
    }
    for index in 0..500u64 {
        let mut stopped = finished(index);
        stopped.class = crate::record::Class::Pass;
        stopped.interruption = None;
        let result = crate::record::TriageResult {
            comparison: Some(crate::record::Comparison {
                candidate: Some(Digest::of(b"candidate")),
                divergence: None,
                failure_identity: Some(text(&"a".repeat(128))),
                failure_kind: Some(text("violation")),
                observed: None,
                original: None,
                output: Some(text(&format!(
                    "/{}",
                    "a".repeat(libc::PATH_MAX as usize - 2)
                ))),
                status: text("reproduced"),
            }),
            elapsed_ms: Some(u64::MAX),
            file_limited: false,
            finding: text(&format!("{}-0001", "a".repeat(64))),
            finished: stopped,
            number: index + 1,
            output_limited: false,
            state: crate::record::StepState::Complete,
            status: Some(crate::record::ReplayStatus::Reproduced),
        };
        let encoded = serde_json::to_vec(&result).unwrap();
        assert!(encoded.len() < crate::record::BOUND as usize);
        assert_eq!(
            serde_json::from_slice::<crate::record::TriageResult>(&encoded).unwrap(),
            result
        );
        report.triage(result);
    }
    for index in 0..10_000 {
        for rows in [
            &mut report.unfit,
            &mut report.calibration_held,
            &mut report.triage_skipped,
        ] {
            rows.insert(
                format!("{index:064x}"),
                format!("held path /{}", "a".repeat(libc::PATH_MAX as usize - 2)),
            );
        }
        report.trim_diagnostics();
    }
    for field in ["unfit", "calibration_held", "triage_skipped"] {
        assert_eq!(
            report.diagnostics_omitted[field],
            10_000 - super::super::DIAGNOSTICS as u64
        );
    }
    assert_eq!(report.triage_skipped.len(), super::super::DIAGNOSTICS);
    assert_eq!(
        report.triage_skipped.keys().cloned().collect::<Vec<_>>(),
        (10_000 - super::super::DIAGNOSTICS..10_000)
            .map(|index| format!("{index:064x}"))
            .collect::<Vec<_>>()
    );
    let encoded = serde_json::to_vec(&report).unwrap();
    assert!(encoded.len() < 1 << 20, "{}", encoded.len());
    // Each list keeps its newest entries, oldest first.
    let kept: Vec<_> = report
        .completed
        .iter()
        .map(|finished| finished.attempt.clone())
        .collect();
    assert_eq!(
        kept,
        (10_000 - super::super::RECENT as u64..10_000)
            .map(|index| finished(index).attempt)
            .collect::<Vec<_>>()
    );
    assert_eq!(report.triage_completed.len(), super::super::RECENT);
    assert_eq!(
        report.triage_completed[0].number,
        500 - super::super::RECENT as u64 + 1
    );
    assert_eq!(report.counts.values().sum::<u64>(), 10_500);
    assert_eq!(
        report.counts,
        [
            ("pass".to_owned(), 3_334),
            ("interrupted".to_owned(), 3_333),
            ("violation".to_owned(), 3_333),
            ("triage".to_owned(), 500)
        ]
        .into()
    );
    assert_eq!(report.pauses["artifact_inodes"], 10_000);
    // Results whose two summaries carry a cause at the launcher's reason
    // limit, of quotes that JSON escapes to twice their length, reach the
    // byte budget before the entry count. The list keeps the longest newest
    // run within the budget, and the report stays under 1 MiB.
    let summarized = || crate::record::Summarized {
        cause: Some(text(&"\"".repeat(crate::sim::REASON))),
        counts: false,
        decisions: Some(u64::MAX),
        digest: Digest::of(b"semantic"),
        first_failure: None,
        identity: None,
        ledger: None,
        terminal: text("infrastructure:truncated"),
        unsuccessful: None,
    };
    let mut result = report.triage_completed[0].clone();
    let comparison = result.comparison.as_mut().unwrap();
    comparison.observed = Some(summarized());
    comparison.original = Some(summarized());
    for number in 501..=1_000 {
        result.number = number;
        report.triage(result.clone());
    }
    let kept: Vec<_> = report
        .triage_completed
        .iter()
        .map(|result| result.number)
        .collect();
    let size = serde_json::to_vec(&result).unwrap().len();
    assert_eq!(kept.len(), super::super::RECENT_BYTES / size);
    assert_eq!(
        kept,
        (1_000 - kept.len() as u64 + 1..=1_000).collect::<Vec<_>>()
    );
    assert_eq!(report.counts["triage"], 1_000);
    let encoded = serde_json::to_vec(&report).unwrap();
    assert!(encoded.len() < 1 << 20, "{}", encoded.len());
}

/// Writes `count` released admission probes of one build, all but the
/// last of which collect may sweep, and returns the census they leave.
fn released_probes(store: &Store, config: &Configuration, count: usize) -> Usage {
    for index in 0..count {
        crate::campaign::state_fixture::released_probe(
            store,
            &format!("probe-{index:04}"),
            "/sys/fs/cgroup/campaign-released-probe",
        );
    }
    crate::campaign::census::census(store, config).unwrap()
}

/// The `artifact_inodes` limit that pauses a first start over `usage` by
/// `over` inodes, under `config`.
fn inode_limit(config: &Configuration, usage: Usage, over: u64) -> u64 {
    let charge = config.charge().inodes as u64;
    usage.inodes + (1 + config.value("reserve_slots")) * charge - over
}

/// At the artifact-inode threshold, dispatch runs one collect pass, which
/// sweeps the released probes, counts its census again and starts; with
/// nothing to reclaim, it holds and names the remedy, and a measured
/// dimension pauses.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_full_artifact_dimension_runs_one_pass_then_starts_or_holds_naming_the_remedy() {
    let _processes = processes();
    for probes in [3, 0] {
        let host = Host::new(&format!("collect-pass-{probes}"));
        let store = Store::open(&host.case.state).unwrap();
        let config = host.config(&store, &[("slots", 1)]);
        host.capacity(&store, "upload", 1);
        host.job(&store, 0, "upload", Purpose::Campaign, 1);
        let usage = released_probes(&store, &config, probes);
        let limit = inode_limit(&config, usage, 0);
        host.config(&store, &[("slots", 1), ("artifact_inodes", limit)]);
        let report = dispatch(&store, &mut host.custody(), &host.options()).unwrap();
        if probes > 0 {
            assert!(report.refusals.is_empty(), "{report:?}");
            assert_eq!(report.started, 1, "{report:?}");
            assert_eq!(
                (report.collect_passes, report.collect_deletions),
                (1, (probes - 1) as u64)
            );
            assert_eq!(
                report.counts.values().sum::<u64>(),
                report.completed.len() as u64
            );
            assert_eq!(report.pauses.get("artifact_inodes"), None, "{report:?}");
            assert_eq!(
                fs::read_dir(host.case.state.join("probes"))
                    .unwrap()
                    .count(),
                1
            );
        } else {
            assert_eq!(report.started, 0, "{report:?}");
            assert_eq!(
                (report.collect_passes, report.collect_finished),
                (1, Some(true))
            );
            assert_eq!(
                report.refusals,
                ["artifact_inodes exhausted and collect reclaims nothing; raise it with configure"]
            );
        }
    }
    let host = Host::new("collect-pass-disk");
    let store = Store::open(&host.case.state).unwrap();
    let config = host.config(&store, &[]);
    host.capacity(&store, "upload", 1);
    host.job(&store, 0, "upload", Purpose::Campaign, 1);
    let disk = config
        .charge()
        .disk(std::num::NonZeroU64::new(4096).unwrap()) as u64;
    step::install(Some(Script {
        free_space: Some((disk, u64::MAX)),
        ..Script::default()
    }));
    let report = dispatch(&store, &mut host.custody(), &host.options());
    step::install(None);
    let report = report.unwrap();
    assert!(report.refusals.is_empty(), "{report:?}");
    assert_eq!(report.started, 0, "{report:?}");
    assert_eq!(report.state, super::super::State::Paused);
    assert!(report.paused.contains("disk"), "{report:?}");
    assert_eq!(
        (
            report.collect_passes,
            report.collect_deletions,
            report.collect_finished
        ),
        (1, 0, Some(true))
    );
}

/// With more to reclaim than one pass deletes and nothing running,
/// dispatch runs successive passes, one per loop iteration, until the
/// start fits; the window does not end paused.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn successive_passes_reclaim_past_one_pass_until_a_start() {
    let _processes = processes();
    let host = Host::new("collect-passes");
    let store = Store::open(&host.case.state).unwrap();
    let config = host.config(&store, &[("slots", 1)]);
    host.capacity(&store, "upload", 1);
    host.job(&store, 0, "upload", Purpose::Campaign, 1);
    let probes = super::super::runner::PASS_DELETIONS + 44;
    let usage = released_probes(&store, &config, probes);
    let per_probe = crate::campaign::probe::OUTPUT_INODES;
    let limit = inode_limit(
        &config,
        usage,
        (super::super::runner::PASS_DELETIONS as u64 + 4) * per_probe,
    );
    host.config(&store, &[("slots", 1), ("artifact_inodes", limit)]);
    let report = dispatch(&store, &mut host.custody(), &host.options()).unwrap();
    assert!(report.refusals.is_empty(), "{report:?}");
    assert_eq!(report.started, 1, "{report:?}");
    assert_eq!(report.pauses["artifact_inodes"], 1, "{report:?}");
    assert_eq!(report.collect_finished, Some(true));
    assert_eq!(
        (report.collect_passes, report.collect_deletions),
        (2, (probes - 1) as u64)
    );
    assert_eq!(
        fs::read_dir(host.case.state.join("probes"))
            .unwrap()
            .count(),
        1
    );
}

/// Each consecutive pass that leaves the start paused doubles the deletion
/// budget. The start needs more than three base budgets deleted. The first
/// two passes delete one and two base budgets and leave the start paused.
/// The third pass deletes the remainder, so the window takes three passes.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn consecutive_passes_double_the_deletion_budget() {
    let _processes = processes();
    let host = Host::new("collect-budget");
    let store = Store::open(&host.case.state).unwrap();
    let config = host.config(&store, &[("slots", 1)]);
    host.capacity(&store, "upload", 1);
    host.job(&store, 0, "upload", Purpose::Campaign, 1);
    let cap = super::super::runner::PASS_DELETIONS;
    let probes = 3 * cap + 44;
    let usage = released_probes(&store, &config, probes);
    let limit = inode_limit(
        &config,
        usage,
        (3 * cap as u64 + 4) * crate::campaign::probe::OUTPUT_INODES,
    );
    // The byte limit stays clear of the probes' charge, so the inode
    // dimension alone decides each pause.
    host.config(
        &store,
        &[
            ("slots", 1),
            ("artifact_inodes", limit),
            ("artifact_bytes", 1 << 40),
        ],
    );
    let report = dispatch(&store, &mut host.custody(), &host.options()).unwrap();
    assert!(report.refusals.is_empty(), "{report:?}");
    assert_eq!(report.started, 1, "{report:?}");
    assert_eq!(
        (
            report.collect_passes,
            report.collect_deletions,
            report.collect_finished
        ),
        (3, (probes - 1) as u64, Some(true)),
        "{report:?}"
    );
    assert_eq!(
        report.pauses,
        [("artifact_inodes".to_owned(), 2)].into(),
        "{report:?}"
    );
    assert_eq!(
        fs::read_dir(host.case.state.join("probes"))
            .unwrap()
            .count(),
        1
    );
}

/// Successive passes that delete less than the start needs stop once a
/// pass deletes nothing: dispatch then holds and names the remedy for the
/// operator dimension alone.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn passes_that_run_out_of_reclaim_hold_naming_the_operator_dimension() {
    let _processes = processes();
    let host = Host::new("collect-passes-exhausted");
    let store = Store::open(&host.case.state).unwrap();
    let config = host.config(&store, &[("slots", 1)]);
    host.capacity(&store, "upload", 1);
    host.job(&store, 0, "upload", Purpose::Campaign, 1);
    let usage = released_probes(&store, &config, 4);
    let limit = inode_limit(&config, usage, 8 * crate::campaign::probe::OUTPUT_INODES);
    host.config(&store, &[("slots", 1), ("artifact_inodes", limit)]);
    let disk = config
        .charge()
        .disk(std::num::NonZeroU64::new(4096).unwrap()) as u64;
    step::install(Some(Script {
        free_space: Some((disk, u64::MAX)),
        ..Script::default()
    }));
    let report = dispatch(&store, &mut host.custody(), &host.options());
    step::install(None);
    let report = report.unwrap();
    assert_eq!(report.started, 0, "{report:?}");
    assert_eq!(report.pauses["artifact_inodes"], 1, "{report:?}");
    assert_eq!(
        report.refusals,
        ["artifact_inodes exhausted and collect reclaims nothing; raise it with configure"]
    );
    assert_eq!(
        fs::read_dir(host.case.state.join("probes"))
            .unwrap()
            .count(),
        1
    );
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_busy_hardware_snapshot_pauses_collect_until_the_lock_is_released() {
    let _processes = processes();
    let host = Host::new("collect-busy");
    let store = Store::open(&host.case.state).unwrap();
    let config = host.config(&store, &[("slots", 1)]);
    host.capacity(&store, "upload", 1);
    host.job(&store, 0, "upload", Purpose::Campaign, 1);
    let usage = released_probes(&store, &config, 3);
    host.config(
        &store,
        &[
            ("slots", 1),
            ("artifact_inodes", inode_limit(&config, usage, 0)),
        ],
    );
    crate::store::create_dir(&host.case.state.join("hardware")).unwrap();
    let hardware = Store::open(&host.case.state.join("hardware")).unwrap();
    let mut custody = host.custody();
    let report = dispatch(&store, &mut custody, &host.options()).unwrap();
    assert_eq!(report.state, super::super::State::Paused, "{report:?}");
    assert!(report.refusals.is_empty(), "{report:?}");
    assert_eq!(report.collect_deletions, 0);
    assert_eq!(report.collect_finished, Some(false));
    assert_eq!(report.collect_passes, 1);
    drop(hardware);
    let report = dispatch(&store, &mut custody, &host.options()).unwrap();
    assert_eq!(report.started, 1, "{report:?}");
    assert!(report.refusals.is_empty(), "{report:?}");
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_signal_or_deadline_during_collection_stops_before_the_next_probe() {
    let _processes = processes();
    for signal in [true, false] {
        let host = Host::new(&format!("collect-stop-{signal}"));
        let store = Store::open(&host.case.state).unwrap();
        let config = host.config(&store, &[]);
        host.capacity(&store, "upload", 1);
        let job = host.job(&store, 0, "upload", Purpose::Campaign, 1);
        let usage = released_probes(&store, &config, 4);
        host.config(
            &store,
            &[("artifact_inodes", inode_limit(&config, usage, 0))],
        );
        let fired = std::rc::Rc::new(std::cell::Cell::new(false));
        let witness = fired.clone();
        let recounts = std::rc::Rc::new(std::cell::Cell::new(0));
        let recounted = recounts.clone();
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut options = host.options();
        if !signal {
            options.deadline = Some(deadline);
        }
        let mut custody = host.custody();
        step::install(Some(Script {
            observe: Some(Box::new(move |point| {
                if point == Step::Census && witness.get() {
                    recounted.set(recounted.get() + 1);
                }
                if point == Step::Unlink && !witness.replace(true) {
                    if signal {
                        crate::sys::interrupt(libc::SIGTERM).unwrap();
                    } else {
                        std::thread::sleep(
                            deadline.saturating_duration_since(Instant::now())
                                + Duration::from_millis(10),
                        );
                    }
                }
            })),
            ..Script::default()
        }));
        let report = dispatch(&store, &mut custody, &options);
        step::install(None);
        let report = report.unwrap();
        assert!(fired.get());
        // The stopped pass ends the storage decision, so the only free-space
        // read after the stop is the report's storage measurement.
        assert_eq!(recounts.get(), 1);
        assert!(report.refusals.is_empty(), "{report:?}");
        assert_eq!(report.started, 0, "{report:?}");
        assert!(!attempt_path(&host, &job).exists());
        assert_eq!(report.collect_deletions, 1, "{report:?}");
        assert_eq!(report.collect_finished, Some(false));
        assert_eq!(
            report.state,
            if signal {
                super::super::State::Interrupted
            } else {
                super::super::State::Deadline
            }
        );
        assert_eq!(
            fs::read_dir(host.case.state.join("probes"))
                .unwrap()
                .count(),
            3
        );
    }
}

#[test]
fn diagnostic_lists_preserve_the_first_cause_and_count_omitted_visits() {
    let mut report = super::super::Report::default();
    for index in 0..100 {
        report.refuse(format!("cause-{index:02}"));
        report.error(Error::Rejected(format!("reject-{index:02}")));
    }
    let cap = super::super::DIAGNOSTICS;
    assert_eq!(
        report.refusals,
        (0..cap)
            .map(|index| format!("cause-{index:02}"))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        report.rejections,
        (0..cap)
            .map(|index| format!("reject-{index:02}"))
            .collect::<Vec<_>>()
    );
    assert_eq!(report.diagnostics_omitted["refusals"], (100 - cap) as u64);
    assert_eq!(report.diagnostics_omitted["rejections"], (100 - cap) as u64);
    assert!(report.stopping());
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn an_empty_pass_honors_a_signal_or_deadline_before_the_exhaustion_decision() {
    let _processes = processes();
    for signal in [true, false] {
        let host = Host::new(&format!("empty-pass-stop-{signal}"));
        let store = Store::open(&host.case.state).unwrap();
        let config = host.config(&store, &[("slots", 1)]);
        host.capacity(&store, "upload", 1);
        let job = host.job(&store, 0, "upload", Purpose::Campaign, 1);
        let usage = crate::campaign::census::census(&store, &config).unwrap();
        host.config(
            &store,
            &[
                ("slots", 1),
                ("artifact_inodes", inode_limit(&config, usage, 0)),
            ],
        );
        let mut options = host.options();
        let deadline = Instant::now() + Duration::from_secs(2);
        if !signal {
            options.deadline = Some(deadline);
        }
        let fired = std::rc::Rc::new(std::cell::Cell::new(false));
        let witness = fired.clone();
        let mut counted = false;
        let mut custody = host.custody();
        step::install(Some(Script {
            observe: Some(Box::new(move |point| {
                if point == Step::Census {
                    counted = true;
                }
                if counted && point == Step::List && !witness.replace(true) {
                    if signal {
                        crate::sys::interrupt(libc::SIGTERM).unwrap();
                    } else {
                        std::thread::sleep(
                            deadline.saturating_duration_since(Instant::now())
                                + Duration::from_millis(10),
                        );
                    }
                }
            })),
            ..Script::default()
        }));
        let result = dispatch(&store, &mut custody, &options);
        step::install(None);
        let report = result.unwrap();
        assert!(fired.get());
        assert!(report.refusals.is_empty(), "{report:?}");
        assert_eq!(
            (
                report.collect_passes,
                report.collect_deletions,
                report.collect_finished
            ),
            (1, 0, Some(true))
        );
        assert_eq!(
            report.state,
            if signal {
                super::super::State::Interrupted
            } else {
                super::super::State::Deadline
            }
        );
        assert!(!attempt_path(&host, &job).exists());
    }
}

fn counting_evidence(store: &Store, job: &Admission, directory: &crate::store::Dir) {
    let record = store
        .read_record::<crate::record::Attempt>(directory, &name("attempt"))
        .unwrap()
        .unwrap();
    let mut artifact =
        crate::attempt::tests::artifact(record.record().attempt.as_str(), record.record().manifest);
    artifact.archive = Digest::parse(job.job().experiment().pins.build.as_str());
    let stdout = include_bytes!("../../../testdata/counting.summary");
    artifact.summary.as_mut().unwrap().digest =
        Digest::parse("f524dec13f9c0f31be2de651057fad6650d068a55d69e55f62e58b6df1875dfa").unwrap();
    artifact.summary.as_mut().unwrap().decisions = Some(61);
    artifact.workers.get_mut(&text("inspect")).unwrap().stdout = Digest::of(stdout);
    let evidence = crate::attempt::tests::stage(store, directory, record.record(), &artifact);
    let jobs = store.shard_jobs(job.job().id()).unwrap().unwrap();
    let manifest = store
        .read(
            &jobs,
            &name(&format!("{}.manifest", job.job().id())),
            crate::record::BOUND,
        )
        .unwrap()
        .unwrap();
    store
        .replace(&evidence, &name("manifest"), manifest.bytes())
        .unwrap();
    store
        .replace(&evidence, &name("inspect.stdout"), stdout)
        .unwrap();
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_dispatch_window_reclaims_the_first_attempt_bulk_before_its_second_start() {
    let _processes = processes();
    let host = Host::new("bulk-window");
    let store = std::rc::Rc::new(Store::open(&host.case.state).unwrap());
    let config = host.config(&store, &[("slots", 1)]);
    host.capacity(&store, "upload", 1);
    let jobs: Vec<_> = (0..2)
        .map(|run| host.job(&store, run, "upload", Purpose::Campaign, 1))
        .collect();
    crate::campaign::state_fixture::finished_probe(
        &store,
        "probe-source",
        "/sys/fs/cgroup/campaign-released-probe",
        Digest::parse(host.pins.build.as_str()).unwrap(),
        crate::record::ProbeOutcome::Complete,
    );
    let usage = crate::campaign::census::census(&*store, &config).unwrap();
    let limit = usage.inodes
        + (1 + config.value("reserve_slots")) * config.charge().inodes as u64
        + config.reclaimed_charge().inodes as u64
        + 2;
    host.config(&store, &[("slots", 1), ("artifact_inodes", limit)]);
    let options = host.options();
    fs::write(&options.launcher, "#!/bin/sh\nexit 0\n").unwrap();
    let writer = store.clone();
    let admitted = jobs.clone();
    step::install(Some(Script {
        observe: Some(Box::new(move |point| {
            if point != Step::Go {
                return;
            }
            for job in &admitted {
                let Some(root) =
                    crate::layout::attempts(&*writer, &job.job().id().to_string()).unwrap()
                else {
                    continue;
                };
                let Some(directory) = writer.open_dir(&root, &name("0001")).unwrap() else {
                    continue;
                };
                if writer
                    .open_dir(&directory, &name("artifacts"))
                    .unwrap()
                    .is_none()
                {
                    counting_evidence(&writer, job, &directory);
                }
            }
        })),
        ..Script::default()
    }));
    let result = dispatch(&store, &mut host.custody(), &options);
    step::install(None);
    let report = result.unwrap();
    assert_eq!(report.started, 2, "{report:?}");
    assert_eq!(report.counts, [("pass".to_owned(), 2)].into());
    assert!(report.refusals.is_empty(), "{report:?}");
    assert_eq!(
        (
            report.collect_passes,
            report.collect_deletions,
            report.collect_finished
        ),
        (1, 6, Some(true))
    );
    let id = report.completed[0]
        .attempt
        .as_str()
        .strip_suffix("-0001")
        .unwrap();
    let directory = host.case.state.join(crate::layout::attempt_path(id, 1));
    assert!(directory.join("reclaimed").exists());
    assert!(!directory.join("launcher.stdout").exists());
    assert!(
        !directory
            .join("artifacts")
            .join(format!("{id}-0001"))
            .join("bundle")
            .exists()
    );
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_marker_only_pass_recounts_before_starting_the_queued_job() {
    let _processes = processes();
    let host = Host::new("marker-only");
    let store = Store::open(&host.case.state).unwrap();
    let config = host.config(&store, &[("slots", 1)]);
    let old = host.job(&store, 0, "upload", Purpose::Campaign, 1);
    let queued = host.job(&store, 1, "upload", Purpose::Campaign, 1);
    let mut custody = host.custody();
    let mut options = host.options();
    options.environment.insert("DELAY".into(), "30".into());
    let limits = crate::campaign::configuration::limits(&config);
    let verified = store
        .read_record::<Admission>(
            &store.shard_jobs(old.job().id()).unwrap().unwrap(),
            &name(&format!("{}.json", old.job().id())),
        )
        .unwrap()
        .unwrap();
    let (attempt, running) = crate::attempt::start(
        &store,
        &mut custody,
        verified,
        crate::attempt::Launch {
            gate: options.gate.clone(),
            launcher: options.launcher.clone(),
            environment: options.environment.clone(),
            limits,
        },
    )
    .unwrap();
    let root = crate::layout::attempts(&store, &old.job().id().to_string())
        .unwrap()
        .unwrap();
    let directory = store.open_dir(&root, &name("0001")).unwrap().unwrap();
    store.mkdir(&directory, &name("artifacts")).unwrap();
    let artifacts = store
        .open_dir(&directory, &name("artifacts"))
        .unwrap()
        .unwrap();
    let identity = format!("{}-0001", old.job().id());
    store.mkdir(&artifacts, &name(&identity)).unwrap();
    let evidence = store
        .open_dir(&artifacts, &name(&identity))
        .unwrap()
        .unwrap();
    let mut artifact = crate::attempt::tests::artifact(&identity, old.job().manifest_sha256());
    artifact.archive = Digest::parse(old.job().experiment().pins.build.as_str());
    artifact.bundle = None;
    artifact.workers.clear();
    artifact.summary = None;
    store
        .create_record(&evidence, &name("artifact"), &artifact)
        .unwrap();
    let jobs = store.shard_jobs(old.job().id()).unwrap().unwrap();
    let manifest = store
        .read(
            &jobs,
            &name(&format!("{}.manifest", old.job().id())),
            crate::record::BOUND,
        )
        .unwrap()
        .unwrap();
    store
        .create_once(&evidence, &name("manifest"), manifest.bytes())
        .unwrap();
    let completed = attempt
        .finish(
            &store,
            custody.stop(running).unwrap(),
            crate::attempt::EVIDENCE_BOUND,
        )
        .unwrap();
    assert_eq!(
        completed.finished().record().class,
        crate::record::Class::Interrupted
    );
    assert_eq!(
        completed.finished().record().binding,
        crate::record::Binding::Matching
    );
    let verified = store
        .read_record::<Admission>(&jobs, &name(&format!("{}.json", old.job().id())))
        .unwrap()
        .unwrap();
    crate::attempt::settle(&store, verified, completed).unwrap();
    for file in crate::custody::LAUNCHER_OUTPUTS {
        store.delete(&directory, &name(file)).unwrap();
    }
    let usage = crate::campaign::census::census(&store, &config).unwrap();
    let limit = inode_limit(&config, usage, 0);
    host.config(&store, &[("slots", 1), ("artifact_inodes", limit)]);
    options.environment.insert("DELAY".into(), "0".into());
    fs::write(
        &options.launcher,
        "#!/bin/sh
exit 0
",
    )
    .unwrap();
    let report = dispatch(&store, &mut custody, &options).unwrap();
    assert_eq!(report.started, 1, "{report:?}");
    assert!(report.refusals.is_empty(), "{report:?}");
    assert_eq!(
        (
            report.collect_passes,
            report.collect_deletions,
            report.collect_finished
        ),
        (1, 0, Some(true))
    );
    assert!(
        host.case
            .state
            .join(crate::layout::attempt_path(&old.job().id().to_string(), 1))
            .join("reclaimed")
            .exists()
    );
    assert_eq!(
        report.completed[0].attempt.as_str(),
        format!("{}-0001", queued.job().id())
    );
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_second_pass_fault_clears_the_previous_completion_flag_and_starts_nothing() {
    let _processes = processes();
    let host = Host::new("second-pass-fault");
    let store = Store::open(&host.case.state).unwrap();
    let config = host.config(&store, &[("slots", 1)]);
    host.capacity(&store, "upload", 1);
    let job = host.job(&store, 0, "upload", Purpose::Campaign, 1);
    let cap = super::super::runner::PASS_DELETIONS;
    let probes = cap + 44;
    let usage = released_probes(&store, &config, probes);
    host.config(
        &store,
        &[
            ("slots", 1),
            (
                "artifact_inodes",
                inode_limit(
                    &config,
                    usage,
                    (cap as u64 + 4) * crate::campaign::probe::OUTPUT_INODES,
                ),
            ),
        ],
    );
    let path = host.case.state.clone();
    let moved = host.case.root.join("moved-state");
    let restore = moved.clone();
    let fired = std::rc::Rc::new(std::cell::Cell::new(false));
    let witness = fired.clone();
    let mut censuses = 0;
    step::install(Some(Script {
        observe: Some(Box::new(move |point| {
            if point == Step::Census {
                censuses += 1;
            }
            if censuses >= 3 && point == Step::List && !witness.replace(true) {
                fs::rename(&path, &moved).unwrap();
            }
        })),
        ..Script::default()
    }));
    let result = dispatch(&store, &mut host.custody(), &host.options());
    step::install(None);
    fs::rename(&restore, &host.case.state).unwrap();
    let report = result.unwrap();
    assert!(fired.get());
    assert_eq!(
        (
            report.collect_passes,
            report.collect_deletions,
            report.collect_finished
        ),
        (2, cap as u64, None)
    );
    assert_eq!(report.state, super::super::State::Held, "{report:?}");
    assert_eq!(report.started, 0);
    assert!(!attempt_path(&host, &job).exists());
    assert!(!report.refusals.is_empty());
    assert_eq!(
        fs::read_dir(host.case.state.join("probes"))
            .unwrap()
            .count(),
        probes - cap
    );
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn an_exhausted_dispatch_names_the_kept_probe_on_one_line() {
    let _processes = processes();
    let host = Host::new("kept-probe-hold");
    let store = Store::open(&host.case.state).unwrap();
    let config = host.config(&store, &[("slots", 1)]);
    host.capacity(&store, "upload", 1);
    let job = host.job(&store, 0, "upload", Purpose::Campaign, 1);
    crate::campaign::state_fixture::finished_probe(
        &store,
        "probe-extra",
        "/sys/fs/cgroup/campaign-released-probe",
        Digest::parse(host.pins.build.as_str()).unwrap(),
        crate::record::ProbeOutcome::Complete,
    );
    fs::write(
        host.case.state.join("probes/probe-extra/bad\nname"),
        b"keep",
    )
    .unwrap();
    let usage = crate::campaign::census::census(&store, &config).unwrap();
    host.config(
        &store,
        &[
            ("slots", 1),
            ("artifact_inodes", inode_limit(&config, usage, 0)),
        ],
    );
    let report = dispatch(&store, &mut host.custody(), &host.options()).unwrap();
    assert_eq!(
        report.refusals,
        [
            "artifact_inodes exhausted and collect reclaims nothing; raise it with configure; collection kept probes/probe-extra: probe holds unlisted entry bad\\nname; inspect the held evidence"
        ]
    );
    assert_eq!(report.refusals[0].lines().count(), 1);
    assert_eq!(
        (report.collect_passes, report.collect_finished),
        (1, Some(true))
    );
    assert!(!attempt_path(&host, &job).exists());
}

#[test]
fn loading_unfit_jobs_records_every_recovery_exclusion_before_sampling() {
    let fixture = crate::campaign::report::tests::Fixture::new();
    let mut ids = BTreeSet::new();
    for run in 0..33 {
        let job = fixture.targeted(run);
        let id = job.job().id().to_string();
        fs::write(
            fixture
                .case
                .state
                .join(crate::layout::job_file(&id, &format!("{id}.bundle"))),
            b"damaged frozen input",
        )
        .unwrap();
        ids.insert(id);
    }
    let mut report = Report::default();
    let jobs = Jobs::load(&fixture.store, &mut report).unwrap().unwrap();
    assert_eq!(report.unfit.len(), ids.len());
    report.trim_diagnostics();
    assert_eq!(report.unfit.len(), super::super::DIAGNOSTICS);
    assert_eq!(jobs.excluded, ids);
    assert_eq!(
        jobs.next(&BTreeMap::new(), Digest::parse(&"b".repeat(64)).unwrap()),
        None
    );
    assert!(report.refusals.is_empty());
}
