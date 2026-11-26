use crate::campaign::state_fixture::Sharded;
#[path = "policy_tests.rs"]
mod policy_checks;
#[path = "recovery_tests.rs"]
mod recovery_checks;

use super::*;
use crate::campaign::{Request, admission};
use crate::custody::{Custody, Timing};
use crate::record::{Admission, Build, Configuration, Digest, Native, Pins, Provenance, Purpose};
use crate::step::{self, Outcome, Script, Step};
use crate::store::fixture::{Case, processes};
use crate::store::{Store, Usage};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

fn text(value: &str) -> crate::record::Text {
    crate::record::Text::new(value).unwrap()
}

/// A state directory with an archive of one build and no cgroup, for tests
/// of records and policy that start no attempt.
struct Fixture {
    case: Case,
    archive: PathBuf,
    pins: Pins,
}
/// A [`Fixture`] with the delegated cgroup root `dispatch` and custody need.
struct Host {
    fixture: Fixture,
    root: PathBuf,
    delegation: PathBuf,
}
impl std::ops::Deref for Host {
    type Target = Fixture;
    fn deref(&self) -> &Fixture {
        &self.fixture
    }
}
impl std::ops::DerefMut for Host {
    fn deref_mut(&mut self) -> &mut Fixture {
        &mut self.fixture
    }
}
impl Host {
    fn new(label: &str) -> Self {
        let fixture = Fixture::new();
        let delegation = PathBuf::from(std::env::var_os("CAMPAIGN_CGROUP_ROOT").unwrap());
        fs::create_dir_all(delegation.join("controller")).unwrap();
        let root = delegation.join(format!("dispatch-{}-{label}", std::process::id()));
        fs::create_dir(&root).unwrap();
        Self {
            fixture,
            root,
            delegation,
        }
    }
    fn custody(&self) -> Custody {
        Custody::open(
            &self.root,
            Timing {
                poll: Duration::from_millis(1),
                kill_wait: Duration::from_secs(1),
                watchdog: Duration::from_secs(2),
            },
        )
        .unwrap()
    }
}
impl Fixture {
    fn new() -> Self {
        let case = Case::new();
        let archive = case.root.join("archive");
        fs::create_dir(&archive).unwrap();
        fs::set_permissions(&archive, fs::Permissions::from_mode(0o700)).unwrap();
        let archived = Store::open(&archive).unwrap();
        let digest = Digest::of(b"fixture");
        let build = Build {
            executable: digest,
            libraries: BTreeMap::new(),
            loader: None,
            lock: digest,
            machine: text("x86_64"),
            provenance: Provenance {
                cargo: text("cargo"),
                command: text("build"),
                dirty: false,
                environment: BTreeMap::new(),
                native: Native {
                    install_record: text("native"),
                    install_record_sha256: digest,
                    link_plan_sha256: digest,
                    package: text("worker"),
                },
                revision: text(&"a".repeat(40)),
                target: text("x86_64-unknown-linux-gnu"),
                toolchain: text("rustc 1.99.0"),
                untracked: 0,
            },
        };
        archived
            .create_record(archived.root(), &name("build"), &build)
            .unwrap();
        drop(archived);
        let pins = crate::archive::Archive::load(&archive).unwrap().pins();
        Self {
            case,
            archive,
            pins,
        }
    }
    fn options(&self) -> Options {
        let gate = self.case.root.join("gate");
        fs::write(
            &gate,
            "#!/bin/sh\nIFS= read -r go\n[ \"$go\" = G ] || exit 125\nshift\nshift\nexec \"$@\"\n",
        )
        .unwrap();
        fs::set_permissions(&gate, fs::Permissions::from_mode(0o700)).unwrap();
        let launcher = self.case.root.join("launcher");
        fs::write(
            &launcher,
            "#!/bin/sh\nif [ -n \"${WAIT_FOR:-}\" ]; then\nwhile [ ! -f \"$WAIT_FOR\" ]; do sleep 0.001; done\nfi\nif [ \"${STRAGGLER:-}\" = yes ]; then sleep 30 & fi\nsleep \"$DELAY\"\nprintf ran > worker-ran\nexit 0\n",
        )
        .unwrap();
        fs::set_permissions(&launcher, fs::Permissions::from_mode(0o700)).unwrap();
        Options {
            archive: self.archive.clone(),
            gate,
            launcher,
            environment: [("DELAY".into(), "0.08".into())].into(),
            deadline: None,
            max_attempts: Some(10),
        }
    }
    fn job(
        &self,
        store: &Store,
        run: u64,
        profile: &str,
        purpose: Purpose,
        attempts: u64,
    ) -> Admission {
        let listing = crate::protocol::Listing::parse(include_str!(
            "../../../testdata/admission-listing.txt"
        ))
        .unwrap();
        let request = Request {
            profile: text(profile),
            campaign: text(if purpose == Purpose::Calibration {
                "calibration"
            } else {
                "dispatch"
            }),
            run,
            attempts,
            counts: BTreeMap::new(),
        };
        admission::admit(
            store,
            &listing,
            self.pins.clone(),
            text(self.archive.to_str().unwrap()),
            &request,
            purpose,
        )
        .unwrap()
        .record
    }
    fn config(&self, store: &Store, overrides: &[(&str, u64)]) -> Configuration {
        let mut values: BTreeMap<_, _> = [
            ("slots", 2),
            ("reserve_slots", 1),
            ("cores", 4),
            ("memory", 4 << 30),
            ("cpu", 60),
            ("tree_memory", 1 << 30),
            ("attempt_output", 1 << 20),
            ("attempt_inodes", 100),
            ("wall", 2),
            ("processes", 64),
            ("artifact_bytes", 1 << 30),
            ("artifact_inodes", 10000),
            ("backlog", 10),
            ("retained_builds", 1),
        ]
        .into_iter()
        .map(|(k, v)| (text(k), v))
        .collect();
        for (key, value) in overrides {
            values.insert(text(key), *value);
        }
        let config = Configuration::new(values).unwrap();
        store
            .replace_record(store.root(), &name("config.json"), &config)
            .unwrap();
        config
    }
    fn capacity(&self, store: &Store, profile: &str, slots: u64) {
        store.mkdir(store.root(), &name("capacity")).unwrap();
        let directory = store
            .open_dir(store.root(), &name("capacity"))
            .unwrap()
            .unwrap();
        let build = Digest::parse(self.pins.build.as_str()).unwrap();
        let profile = text(profile);
        let listing = crate::protocol::Listing::parse(include_str!(
            "../../../testdata/admission-listing.txt"
        ))
        .unwrap();
        let request = Request {
            profile: profile.clone(),
            campaign: text("calibration"),
            run: 0,
            attempts: 2,
            counts: BTreeMap::new(),
        };
        let job = crate::campaign::freeze::freeze(&listing, self.pins.clone(), &request)
            .unwrap()
            .0;
        let contract = crate::record::CalibrationContract {
            build,
            profile,
            counts: job.experiment().counts.clone(),
        };
        let config = store
            .read_record::<Configuration>(store.root(), &name("config.json"))
            .unwrap()
            .unwrap()
            .record()
            .clone();
        let admission = Admission::new(
            text(self.archive.to_str().unwrap()),
            job,
            Purpose::Calibration,
        )
        .unwrap();
        let value =
            crate::campaign::calibration::tests::stored_capacity(store, admission, config, slots);
        store
            .mkdir(&directory, &name(&contract.key().to_string()))
            .unwrap();
        let directory = store
            .open_dir(&directory, &name(&contract.key().to_string()))
            .unwrap()
            .unwrap();
        store
            .create_record(&directory, &name(&value.root().to_string()), &value)
            .unwrap();
    }
}
impl Drop for Host {
    fn drop(&mut self) {
        step::install(None);
        fs::write(
            self.delegation.join("controller/cgroup.procs"),
            std::process::id().to_string(),
        )
        .unwrap();
        let _ = fs::write(self.root.join("cgroup.kill"), "1");
        let deadline = Instant::now() + Duration::from_secs(2);
        while populated(&self.root) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        for entry in fs::read_dir(&self.root).unwrap().flatten() {
            if entry.file_type().unwrap().is_dir()
                && let Err(error) = fs::remove_dir(entry.path())
            {
                eprintln!("cgroup teardown: {error}");
            }
        }
        if let Err(error) = fs::remove_dir(&self.root) {
            eprintln!("cgroup teardown: {error}");
        }
    }
}
fn attempt_path(host: &Host, job: &Admission) -> PathBuf {
    host.case
        .state
        .join(crate::campaign::state_fixture::attempts_dir(
            job.job().id().to_string(),
        ))
        .join("0001")
}
fn populated(path: &Path) -> bool {
    fs::read_to_string(path.join("cgroup.events"))
        .unwrap()
        .contains("populated 1")
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn ancestor_limits_bound_maximum_exploration_and_triage_reservations() {
    let _processes = processes();
    for (label, memory, pids, cpu, expected) in [
        (
            "mem2",
            Some(2u64 << 30),
            None,
            None,
            Some("aggregate memory"),
        ),
        (
            "mem3",
            Some(3u64 << 30),
            None,
            None,
            Some("aggregate memory"),
        ),
        ("mem4", Some(4u64 << 30), None, None, None),
        (
            "reserve-mem4",
            Some(4u64 << 30),
            None,
            None,
            Some("aggregate memory"),
        ),
        ("reserve-mem5", Some(5u64 << 30), None, None, None),
        ("pids193", None, Some(193), None, Some("aggregate pids")),
        ("pids194", None, Some(194), None, None),
        ("cpu", None, None, Some("50000 100000"), Some("cpu")),
        ("cpu-leaf", None, None, Some("150000 100000"), Some("cpu")),
        ("cpu-equal", None, None, Some("300000 100000"), Some("cpu")),
        ("cpu-fits", None, None, Some("400000 100000"), None),
        ("cpu-period-fits", None, None, Some("160000 40000"), None),
        (
            "cpu-period-equal",
            None,
            None,
            Some("120000 40000"),
            Some("cpu"),
        ),
    ] {
        let host = Host::new(label);
        let store = Store::open(&host.case.state).unwrap();
        host.config(
            &store,
            if label.starts_with("reserve-") {
                &[("reserve_slots", 2)]
            } else {
                &[]
            },
        );
        let job = host.job(&store, 0, "upload", Purpose::Campaign, 1);
        if let Some(memory) = memory {
            fs::write(host.root.join("memory.max"), memory.to_string()).unwrap();
        }
        if let Some(pids) = pids {
            fs::write(host.root.join("pids.max"), pids.to_string()).unwrap();
        }
        if let Some(cpu) = cpu {
            fs::write(host.root.join("cpu.max"), cpu).unwrap();
        }
        let mut custody = host.custody();
        let mut options = host.options();
        options.max_attempts = Some(1);
        let report = dispatch(&store, &mut custody, &options).unwrap();
        if let Some(expected) = expected {
            assert_eq!(report.exit(), crate::exit::Supervisor::Rejected);
            assert_eq!(report.started, 0);
            assert!(
                report
                    .rejections
                    .iter()
                    .any(|reason| reason.contains(expected)
                        && reason.contains(host.root.to_str().unwrap())),
                "{report:?}"
            );
            assert!(!attempt_path(&host, &job).exists());
        } else {
            assert_eq!(
                report.exit(),
                crate::exit::Supervisor::Success,
                "{report:?}"
            );
            assert_eq!(report.started, 1);
        }
    }
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn ancestor_limit_lowered_after_go_refuses_new_starts_and_drains_the_running_tree() {
    let _processes = processes();
    let host = Host::new("lowered");
    let store = Store::open(&host.case.state).unwrap();
    host.config(&store, &[("wall", 60)]);
    host.capacity(&store, "upload", 2);
    let jobs = [
        host.job(&store, 0, "upload", Purpose::Campaign, 1),
        host.job(&store, 1, "upload", Purpose::Campaign, 1),
    ];
    fs::write(host.root.join("memory.max"), (4u64 << 30).to_string()).unwrap();
    let mut custody = host.custody();
    let root = host.root.clone();
    let witnessed = std::rc::Rc::new(std::cell::Cell::new(false));
    let observed = witnessed.clone();
    step::install(Some(Script {
        observe: Some(Box::new(move |at| {
            if at == Step::Go {
                assert!(
                    !observed.replace(true),
                    "new start followed the lowered ancestor ceiling"
                );
                fs::write(root.join("memory.max"), (3u64 << 30).to_string()).unwrap();
            }
        })),
        ..Script::default()
    }));
    let mut options = host.options();
    options.environment.insert(
        "WAIT_FOR".into(),
        host.case.root.join("never-release").into_os_string(),
    );
    let report = dispatch(&store, &mut custody, &options).unwrap();
    step::install(None);
    assert!(witnessed.get());
    assert_eq!(
        report.exit(),
        crate::exit::Supervisor::Rejected,
        "{report:?}"
    );
    assert_eq!(report.started, 1);
    assert_eq!(report.completed.len(), 1);
    assert_eq!(report.completed[0].class, crate::record::Class::Interrupted);
    assert!(
        report
            .rejections
            .iter()
            .any(|reason| reason.contains("aggregate memory")
                && reason.contains(host.root.to_str().unwrap()))
    );
    assert_eq!(
        jobs.iter()
            .filter(|job| attempt_path(&host, job).join("started").exists())
            .count(),
        1
    );
    assert!(
        jobs.iter()
            .map(|job| attempt_path(&host, job))
            .all(|path| !path.join("reservation").exists())
    );
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn deadline_drains_a_running_worker_that_waits_for_release_and_leaves_a_runnable_job() {
    let _processes = processes();
    let host = Host::new("running-deadline");
    let store = Store::open(&host.case.state).unwrap();
    host.config(&store, &[("slots", 1), ("wall", 10)]);
    let jobs = [
        host.job(&store, 0, "upload", Purpose::Campaign, 1),
        host.job(&store, 1, "upload", Purpose::Campaign, 1),
    ];
    let mut custody = host.custody();
    let mut options = host.options();
    options.environment.insert(
        "WAIT_FOR".into(),
        host.case.root.join("never-release").into_os_string(),
    );
    let began = Instant::now();
    options.deadline = Some(began + Duration::from_secs(2));
    let report = dispatch(&store, &mut custody, &options).unwrap();
    assert_eq!(
        report.exit(),
        crate::exit::Supervisor::Success,
        "{report:?}"
    );
    assert_eq!(report.started, 1);
    assert_eq!(report.completed.len(), 1);
    assert_eq!(report.completed[0].class, crate::record::Class::Interrupted);
    assert!(began.elapsed() < Duration::from_secs(8));
    assert_eq!(
        jobs.iter()
            .filter(|job| attempt_path(&host, job).exists())
            .count(),
        1
    );
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn calibration_jobs_are_excluded_from_dispatch_with_free_slots() {
    let _processes = processes();
    let host = Host::new("calibration-excluded");
    let store = Store::open(&host.case.state).unwrap();
    let config = host.config(&store, &[]);
    let campaign = host.job(&store, 0, "upload", Purpose::Campaign, 1);
    let calibration = host.job(&store, 1, "upload", Purpose::Calibration, 1);
    let other = host.job(&store, 2, "upload", Purpose::Campaign, 1);
    let mut custody = host.custody();
    let mut options = host.options();
    let jobs = store.shard_jobs(campaign.job().id()).unwrap().unwrap();
    let verified = store
        .read_record::<Admission>(&jobs, &name(&format!("{}.json", campaign.job().id())))
        .unwrap()
        .unwrap();
    assert!(matches!(
        crate::attempt::start_calibration(
            &store,
            &mut custody,
            verified,
            crate::attempt::Launch {
                gate: options.gate.clone(),
                launcher: options.launcher.clone(),
                environment: options.environment.clone(),
                limits: crate::campaign::configuration::limits(&config)
            }
        ),
        Err(crate::custody::Error::Rejected(
            "only calibration jobs start calibration attempts"
        ))
    ));
    assert!(!host.case.state.join("attempts").exists());

    store.mkdir(store.root(), &name("calibrations")).unwrap();
    let roots = store
        .open_dir(store.root(), &name("calibrations"))
        .unwrap()
        .unwrap();
    store
        .mkdir(&roots, &name(&Digest::of(b"unlaunched root").to_string()))
        .unwrap();
    let seen = std::rc::Rc::new(std::cell::Cell::new(0));
    let counted = seen.clone();
    let root = host.root.clone();
    step::install(Some(Script {
        observe: Some(Box::new(move |at| {
            if at == Step::Go {
                let groups: Vec<_> = fs::read_dir(&root)
                    .unwrap()
                    .flatten()
                    .filter(|e| e.file_type().unwrap().is_dir() && e.file_name() != "controller")
                    .collect();
                assert!(groups.iter().any(|group| populated(&group.path())));
                counted.set(counted.get() + 1);
            }
        })),
        ..Script::default()
    }));
    let report = dispatch(&store, &mut custody, &options).unwrap();
    step::install(None);
    assert!(report.refusals.is_empty(), "{:?}", report.refusals);
    assert_eq!(report.started, 2);
    assert_eq!(seen.get(), 2);
    assert!(!attempt_path(&host, &calibration).exists());
    assert!(attempt_path(&host, &campaign).join("started").exists());
    assert!(attempt_path(&host, &other).join("started").exists());
    host.job(&store, 3, "upload", Purpose::Campaign, 1);
    host.capacity(&store, "upload", 2);
    options.max_attempts = Some(10);
    let report = dispatch(&store, &mut custody, &options).unwrap();
    assert_eq!(report.started, 1);
    assert_eq!(report.completed.len(), 1);
    assert_eq!(report.exit(), crate::exit::Supervisor::Success);
    assert_eq!(
        report.counts.values().sum::<u64>(),
        (report.completed.len() + report.triage_completed.len()) as u64
    );
    assert!(!attempt_path(&host, &calibration).exists());
    let again = dispatch(&store, &mut custody, &options).unwrap();
    assert_eq!(again.started, 0);
    assert!(again.completed.is_empty());
    assert_eq!(again.exit(), crate::exit::Supervisor::Success);
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn fifteen_lifecycle_crashes_reconcile_before_any_new_start() {
    let _processes = processes();
    for (index, cut) in [
        Step::Reservation,
        Step::Intent,
        Step::Created,
        Step::Spawned,
        Step::Moved,
        Step::Started,
        Step::Go,
        Step::ReleasedGate,
        Step::Exited,
        Step::Kill,
        Step::Killed,
        Step::Drained,
        Step::Finished,
        Step::Removed,
        Step::Released,
    ]
    .into_iter()
    .enumerate()
    {
        let host = Host::new(&format!("cut-{index}"));
        let store = Store::open(&host.case.state).unwrap();
        host.config(&store, &[("slots", 1)]);
        let jobs = [
            host.job(&store, 0, "upload", Purpose::Campaign, 2),
            host.job(&store, 1, "upload", Purpose::Campaign, 2),
        ];
        let mut options = host.options();
        options.environment.insert("STRAGGLER".into(), "yes".into());
        let mut custody = host.custody();
        let released_paths: Vec<_> = jobs.iter().map(|job| attempt_path(&host, job)).collect();
        step::install(Some(Script {
            nth: Some((cut, 0, Outcome::Kill)),
            observe: Some(Box::new(move |at| {
                if cut == Step::ReleasedGate && at == Step::ReleasedGate {
                    let deadline = Instant::now() + Duration::from_secs(2);
                    while !released_paths
                        .iter()
                        .any(|path| path.join("worker-ran").exists())
                    {
                        assert!(Instant::now() < deadline);
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
            })),
            ..Script::default()
        }));
        let crash = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            dispatch(&store, &mut custody, &options)
        }));
        let trace = step::install(None).unwrap();
        assert!(
            crash
                .as_ref()
                .err()
                .is_some_and(|error| error.is::<step::Killed>()),
            "cut {cut:?} did not fire"
        );
        assert!(trace.reached.contains(&cut));
        let crashed = jobs
            .iter()
            .map(|job| attempt_path(&host, job))
            .find(|path| path.exists())
            .unwrap();
        assert_eq!(
            crashed.join("reservation").exists(),
            cut != Step::Released,
            "{cut:?}"
        );
        if let Some(intent) = trace.reached.iter().position(|step| *step == Step::Intent) {
            assert!(
                trace
                    .reached
                    .iter()
                    .position(|step| *step == Step::Reservation)
                    .unwrap()
                    < intent
            );
        }
        let mut groups = Vec::new();
        for job in &jobs {
            let path = attempt_path(&host, job);
            if let Ok(bytes) = fs::read(path.join("intent")) {
                assert!(!bytes.is_empty());
                let group = host.root.join(format!("{}-0001", job.job().id()));
                if group.exists() {
                    assert!(
                        path.join("reservation").exists(),
                        "{cut:?} released with cgroup present"
                    );
                    groups.push(group);
                }
            }
        }
        let was_populated = groups.iter().any(|group| populated(group));
        if matches!(
            cut,
            Step::Drained | Step::Finished | Step::Removed | Step::Released
        ) {
            assert!(!was_populated, "{cut:?} retained population after drain");
        }
        if matches!(cut, Step::Exited | Step::Kill | Step::ReleasedGate) {
            assert!(was_populated, "{cut:?} did not retain its real straggler");
        }
        drop(custody);
        drop(store);
        let restarted = Store::open(&host.case.state).unwrap();
        let mut custody = host.custody();
        let root = host.root.clone();
        let original_groups = groups.clone();
        let original_attempt = crashed.clone();
        step::install(Some(Script {
            observe: Some(Box::new(move |at| {
                if at == Step::Reservation {
                    assert!(original_attempt.join("finished").exists());
                    assert!(!original_attempt.join("reservation").exists());
                    assert!(
                        original_groups.iter().all(|group| !group.exists()),
                        "new start preceded old cgroup removal"
                    );
                    assert!(
                        fs::read_dir(&root)
                            .unwrap()
                            .flatten()
                            .filter(|entry| entry.file_type().unwrap().is_dir()
                                && entry.file_name() != "controller")
                            .all(|entry| !populated(&entry.path())),
                        "new reservation beside populated tree"
                    );
                }
            })),
            ..Script::default()
        }));
        options.max_attempts = Some(1);
        let report = dispatch(&restarted, &mut custody, &options).unwrap();
        let restarted_trace = step::install(None).unwrap().reached;
        if report.started > 0 {
            let reservation = restarted_trace
                .iter()
                .position(|at| *at == Step::Reservation)
                .unwrap();
            let intent = restarted_trace
                .iter()
                .position(|at| *at == Step::Intent)
                .unwrap();
            assert!(reservation < intent);
        }
        let expected_held = matches!(cut, Step::Created | Step::Spawned | Step::Moved);
        assert_eq!(
            !report.refusals.is_empty(),
            expected_held,
            "{cut:?}: {report:?}"
        );
        assert!(report.rejections.is_empty(), "{cut:?}: {report:?}");
        if !report.refusals.is_empty() {
            assert_eq!(report.started, 0);
            assert!(!crashed.join("finished").exists());
            assert!(!groups.is_empty());
            assert!(groups.iter().all(|group| group.exists()));
            assert!(crashed.join("reservation").exists());
            for group in &groups {
                let identity = group.file_name().unwrap().to_str().unwrap();
                let id = identity.strip_suffix("-0001").unwrap();
                assert!(
                    host.case
                        .state
                        .join(crate::campaign::state_fixture::attempts_dir(id))
                        .join("0001/reservation")
                        .exists()
                );
            }
        } else {
            assert_eq!(report.started, 1, "{cut:?}");
            assert!(crashed.join("finished").exists());
            assert!(!crashed.join("reservation").exists());
            if cut != Step::Released {
                let identity = format!(
                    "{}-0001",
                    crashed
                        .parent()
                        .unwrap()
                        .file_name()
                        .unwrap()
                        .to_str()
                        .unwrap()
                );
                assert!(
                    report
                        .completed
                        .iter()
                        .any(|finished| finished.attempt.as_str() == identity)
                );
            }
            assert!(groups.iter().all(|group| !group.exists()));
        }
        eprintln!(
            "dispatch crash cut={cut:?} populated_at_crash={was_populated} new_starts={} held={}",
            report.started,
            !report.refusals.is_empty()
        );
    }
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn pause_dimensions_keep_a_live_witness_and_a_runnable_queue() {
    let _processes = processes();
    // An artifact dimension pauses at its threshold and starts the second
    // attempt beside the first one unit above it.
    for (dimension, headroom) in [
        ("disk", 0),
        ("disk_inodes", 0),
        ("artifact_bytes", 0),
        ("artifact_bytes", 1),
        ("artifact_inodes", 0),
        ("artifact_inodes", 1),
        ("unreadable", 0),
        ("missing", 0),
    ] {
        let host = Host::new(&format!("{dimension}-{headroom}"));
        let store = Store::open(&host.case.state).unwrap();
        // A concluded attempt and its result record must charge less than a
        // running one, so the output budget exceeds the record bound.
        let output = ("attempt_output", 4 << 20);
        let config = host.config(&store, &[output]);
        let charge = config.charge();
        host.capacity(&store, "upload", 2);
        let jobs = [
            host.job(&store, 0, "upload", Purpose::Campaign, 1),
            host.job(&store, 1, "upload", Purpose::Campaign, 1),
        ];
        for index in 0..3 {
            crate::campaign::state_fixture::released_probe(
                &store,
                &format!("probe-live-{index}"),
                "/sys/fs/cgroup/campaign-released-probe",
            );
        }
        let calibrated = crate::campaign::census::census(&store, &config).unwrap();
        let fragment = calibrated.fragment_bytes;
        let overrides: Vec<_> = match dimension {
            "artifact_bytes" => vec![(
                "artifact_bytes",
                calibrated.bytes + (3 * charge.bytes) as u64 + headroom,
            )],
            "artifact_inodes" => vec![(
                "artifact_inodes",
                calibrated.inodes + (3 * charge.inodes) as u64 + headroom,
            )],
            _ => Vec::new(),
        };
        host.config(&store, &[overrides, vec![output]].concat());
        let witness = std::rc::Rc::new(std::cell::Cell::new(false));
        let observed = witness.clone();
        let root = host.root.clone();
        let release = host.case.root.join("release");
        let worker_release = release.clone();
        let paths: Vec<_> = jobs.iter().map(|job| attempt_path(&host, job)).collect();
        let free_space = match dimension {
            "disk" => Some(((3 * charge.disk(fragment)) as u64, u64::MAX)),
            "disk_inodes" => Some((u64::MAX, (3 * charge.inodes) as u64)),
            _ => None,
        };
        let initial = store.usage(crate::SCAN_BOUND).unwrap();
        let mut custody = host.custody();
        step::install(Some(Script {
            free_space,
            observe: Some(Box::new(move |at| {
                if at == Step::Census && observed.get() {
                    fs::write(&release, b"release").unwrap();
                }
                if at != Step::Go {
                    return;
                }
                if observed.get() {
                    assert_eq!(
                        paths.iter().any(|path| path.join("finished").exists()),
                        headroom == 0,
                        "a paused start ran before the running attempt finished, or an \
                         admitted start waited for it"
                    );
                    return;
                }
                let started = paths
                    .iter()
                    .find(|path| path.join("started").exists())
                    .unwrap();
                let queued = paths
                    .iter()
                    .find(|path| !path.join("started").exists())
                    .unwrap();
                assert!(!queued.exists(), "queued job already has an attempt");
                let identity = started
                    .parent()
                    .unwrap()
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap();
                assert!(populated(&root.join(format!("{identity}-0001"))));
                observed.set(true);
                match dimension {
                    "unreadable" => {
                        fs::remove_file(started.join("reservation")).unwrap();
                        fs::create_dir(started.join("reservation")).unwrap();
                    }
                    "missing" => fs::remove_file(started.join("reservation")).unwrap(),
                    _ => {}
                }
            })),
            ..Script::default()
        }));
        let mut options = host.options();
        options
            .environment
            .insert("WAIT_FOR".into(), worker_release.into_os_string());
        let report = dispatch(&store, &mut custody, &options).unwrap();
        step::install(None);
        assert!(
            witness.get(),
            "{dimension} never reached a running Campaign and queued witness"
        );
        assert_eq!(
            report.started,
            if ["unreadable", "missing"].contains(&dimension) {
                1
            } else {
                2
            },
            "{dimension}: {report:?}"
        );
        if ["unreadable", "missing"].contains(&dimension) {
            assert!(!report.refusals.is_empty());
            if dimension == "missing" {
                assert!(
                    report
                        .refusals
                        .iter()
                        .any(|reason| reason.contains("running attempt lacks reservation"))
                );
            }
            assert!(
                jobs.iter()
                    .map(|job| attempt_path(&host, job))
                    .any(|path| path.join("finished").exists())
            );
            let groups: Vec<_> = fs::read_dir(&host.root)
                .unwrap()
                .flatten()
                .filter(|entry| {
                    entry.file_type().unwrap().is_dir() && entry.file_name() != "controller"
                })
                .map(|entry| entry.path())
                .collect();
            assert_eq!(groups.len(), 1);
            assert!(!populated(&groups[0]));
            drop(custody);
            drop(store);
            let restarted = Store::open(&host.case.state).unwrap();
            let mut custody = host.custody();
            let report = dispatch(&restarted, &mut custody, &options).unwrap();
            assert_eq!(
                report.exit(),
                crate::exit::Supervisor::Held,
                "{dimension}: {report:?}"
            );
            assert_eq!(report.started, 0);
            assert!(groups[0].exists());
            assert!(!populated(&groups[0]));
        } else {
            assert!(report.refusals.is_empty(), "{dimension}: {report:?}");
            assert_eq!(report.collect_passes, 0, "{dimension}: {report:?}");
            for index in 0..3 {
                assert!(
                    host.case
                        .state
                        .join(format!("probes/probe-live-{index}"))
                        .exists()
                );
            }
            assert_eq!(
                report.paused.contains(dimension),
                headroom == 0,
                "{dimension} {headroom}: {report:?}"
            );
            assert_eq!(report.completed.len() as u64, report.started);
            for finished in &report.completed {
                assert_eq!(finished.exit, Some(0));
                assert_eq!(finished.interruption, None);
                assert!(!finished.watchdog);
                let (id, number) = finished.attempt.as_str().rsplit_once('-').unwrap();
                assert!(
                    host.case
                        .state
                        .join(crate::campaign::state_fixture::attempts_dir(id))
                        .join(number)
                        .join("worker-ran")
                        .exists()
                );
            }
        }
        assert!(initial.inodes > 0);
        assert_eq!(
            fs::read_dir(&host.root)
                .unwrap()
                .flatten()
                .filter(|entry| entry.file_type().unwrap().is_dir()
                    && entry.file_name() != "controller")
                .count(),
            if ["unreadable", "missing"].contains(&dimension) {
                1
            } else {
                0
            }
        );
    }
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn report_state_names_the_branch_that_ended_the_window() {
    let _processes = processes();
    for (label, expected) in [
        ("queue", State::QueueEmpty),
        ("maximum", State::MaxAttempts),
        ("deadline", State::Deadline),
        ("disk", State::Paused),
    ] {
        let host = Host::new(&format!("state-{label}"));
        let store = Store::open(&host.case.state).unwrap();
        host.config(&store, &[]);
        host.capacity(&store, "upload", 2);
        for run in 0..2 {
            host.job(&store, run, "upload", Purpose::Campaign, 1);
        }
        let mut options = host.options();
        match expected {
            State::MaxAttempts => options.max_attempts = Some(1),
            State::Deadline => options.deadline = Some(Instant::now()),
            _ => {}
        }
        step::install(Some(Script {
            free_space: (expected == State::Paused).then_some((0, u64::MAX)),
            ..Script::default()
        }));
        let report = dispatch(&store, &mut host.custody(), &options).unwrap();
        step::install(None);
        assert_eq!(report.state, expected, "{label}: {report:?}");
        assert_eq!(
            report.exit(),
            crate::exit::Supervisor::Success,
            "{report:?}"
        );
        let started = match expected {
            State::QueueEmpty => 2,
            State::MaxAttempts => 1,
            _ => 0,
        };
        assert_eq!(report.started, started, "{label}: {report:?}");
        assert_eq!(report.paused.contains("disk"), expected == State::Paused);
        if expected == State::Paused {
            assert_eq!(
                (
                    report.collect_passes,
                    report.collect_deletions,
                    report.collect_finished
                ),
                (1, 0, Some(true))
            );
        }
        let storage = report.storage.unwrap();
        assert!(storage.roots.contains_key("jobs"), "{label}: {storage:?}");
        for (root, found) in &storage.roots {
            let entries = fs::read_dir(host.case.state.join(root)).unwrap();
            let independent = if ["jobs", "attempts"].contains(&root.as_str()) {
                entries
                    .map(|shard| fs::read_dir(shard.unwrap().path()).unwrap().count())
                    .max()
                    .unwrap_or(0)
            } else {
                entries.count()
            };
            assert_eq!(found.entries, independent, "{label}: {root}");
        }
        if expected == State::Paused {
            assert_eq!((storage.free_bytes, storage.free_inodes), (0, u64::MAX));
        } else {
            assert_ne!(storage.free_bytes, 0);
        }
    }
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn sigterm_drains_every_running_attempt_and_leaves_the_queue_unstarted() {
    let _processes = processes();
    let host = Host::new("signal");
    let store = Store::open(&host.case.state).unwrap();
    host.config(&store, &[("wall", 60)]);
    host.capacity(&store, "upload", 2);
    let jobs: Vec<_> = (0..3)
        .map(|run| host.job(&store, run, "upload", Purpose::Campaign, 1))
        .collect();
    let mut custody = host.custody();
    let sent = std::rc::Rc::new(std::cell::Cell::new(false));
    let signal = sent.clone();
    step::install(Some(Script {
        observe: Some(Box::new(move |at| {
            if at == Step::Poll && !signal.replace(true) {
                crate::sys::interrupt(libc::SIGTERM).unwrap();
            }
        })),
        ..Script::default()
    }));
    let mut options = host.options();
    options.environment.insert(
        "WAIT_FOR".into(),
        host.case.root.join("signal-release").into_os_string(),
    );
    let report = dispatch(&store, &mut custody, &options).unwrap();
    step::install(None);
    assert!(sent.get());
    assert_eq!(report.started, 2);
    assert_eq!(report.completed.len(), 2);
    assert!(report.refusals.is_empty(), "{report:?}");
    assert_eq!(report.state, State::Interrupted);
    assert!(
        report
            .completed
            .iter()
            .all(|finished| finished.class == crate::record::Class::Interrupted)
    );
    assert_eq!(
        jobs.iter()
            .filter(|job| attempt_path(&host, job).join("started").exists())
            .count(),
        2
    );
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn deadline_reached_during_preparation_stops_before_the_go_byte() {
    let _processes = processes();
    let host = Host::new("preparation");
    let store = Store::open(&host.case.state).unwrap();
    host.config(&store, &[]);
    let job = host.job(&store, 0, "upload", Purpose::Campaign, 1);
    let mut custody = host.custody();
    let mut options = host.options();
    let deadline = Instant::now() + Duration::from_secs(1);
    options.deadline = Some(deadline);
    step::install(Some(Script {
        observe: Some(Box::new(move |at| {
            if at == Step::Started {
                std::thread::sleep(
                    deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(2),
                );
            }
        })),
        ..Script::default()
    }));
    let report = dispatch(&store, &mut custody, &options).unwrap();
    let trace = step::install(None).unwrap();
    assert!(trace.reached.contains(&Step::Started));
    assert!(!trace.reached.contains(&Step::Go));
    assert_eq!(report.started, 0);
    assert!(report.refusals.is_empty(), "{report:?}");
    assert!(attempt_path(&host, &job).join("finished").exists());
    assert!(!attempt_path(&host, &job).join("worker-ran").exists());
    assert!(!attempt_path(&host, &job).join("reservation").exists());
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn populated_past_kill_wait_retains_its_charge_and_stops_dispatch() {
    let _processes = processes();
    let host = Host::new("populated");
    let store = Store::open(&host.case.state).unwrap();
    host.config(&store, &[("slots", 1)]);
    let jobs = [
        host.job(&store, 0, "upload", Purpose::Campaign, 1),
        host.job(&store, 1, "upload", Purpose::Campaign, 1),
    ];
    let mut custody = Custody::open(
        &host.root,
        Timing {
            poll: Duration::from_millis(1),
            kill_wait: Duration::from_millis(50),
            watchdog: Duration::from_secs(2),
        },
    )
    .unwrap();
    let mut member = std::process::Command::new("/bin/sleep")
        .arg("10")
        .spawn()
        .unwrap();
    let pid = member.id();
    let root = host.root.clone();
    let group = std::rc::Rc::new(std::cell::RefCell::new(None::<PathBuf>));
    let chosen = group.clone();
    let mut killed = false;
    let mut joined = false;
    step::install(Some(Script {
        observe: Some(Box::new(move |at| {
            if at == Step::Go {
                let path = fs::read_dir(&root)
                    .unwrap()
                    .flatten()
                    .find(|entry| {
                        entry.file_type().unwrap().is_dir() && entry.file_name() != "controller"
                    })
                    .unwrap()
                    .path();
                *chosen.borrow_mut() = Some(path);
            }
            if at == Step::Kill {
                killed = true;
            }
            if killed && !joined && at == Step::Read {
                fs::write(
                    chosen.borrow().as_ref().unwrap().join("cgroup.procs"),
                    pid.to_string(),
                )
                .unwrap();
                joined = true;
            }
        })),
        ..Script::default()
    }));
    let report = dispatch(&store, &mut custody, &host.options()).unwrap();
    step::install(None);
    assert_eq!(report.started, 1);
    assert!(!report.refusals.is_empty());
    let group = group.borrow().as_ref().unwrap().clone();
    assert!(populated(&group));
    let active = jobs
        .iter()
        .map(|job| attempt_path(&host, job))
        .find(|path| path.join("started").exists())
        .unwrap();
    assert!(active.join("reservation").exists());
    assert!(!active.join("finished").exists());
    fs::write(group.join("cgroup.kill"), "1").unwrap();
    assert!(!member.wait().unwrap().success());
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn nested_empty_child_holds_release_until_the_next_reconcile() {
    let _processes = processes();
    let host = Host::new("nested");
    let store = Store::open(&host.case.state).unwrap();
    host.config(&store, &[("slots", 1)]);
    let jobs = [
        host.job(&store, 0, "upload", Purpose::Campaign, 1),
        host.job(&store, 1, "upload", Purpose::Campaign, 1),
    ];
    let mut custody = host.custody();
    let root = host.root.clone();
    let nested = std::rc::Rc::new(std::cell::RefCell::new(None::<PathBuf>));
    let observed = nested.clone();
    step::install(Some(Script {
        observe: Some(Box::new(move |at| {
            if at == Step::Drained && observed.borrow().is_none() {
                let group = fs::read_dir(&root)
                    .unwrap()
                    .flatten()
                    .find(|entry| {
                        entry.file_type().unwrap().is_dir() && entry.file_name() != "controller"
                    })
                    .unwrap()
                    .path();
                let child = group.join("nested");
                fs::create_dir(&child).unwrap();
                *observed.borrow_mut() = Some(child);
            }
        })),
        ..Script::default()
    }));
    let report = dispatch(&store, &mut custody, &host.options()).unwrap();
    step::install(None);
    assert_eq!(report.started, 1);
    assert!(!report.refusals.is_empty());
    let active = jobs
        .iter()
        .map(|job| attempt_path(&host, job))
        .find(|path| path.join("finished").exists())
        .unwrap();
    assert!(active.join("reservation").exists());
    let nested = nested.borrow().as_ref().unwrap().clone();
    let held_group = nested.parent().unwrap().to_owned();
    assert!(held_group.exists());
    fs::remove_dir(nested).unwrap();
    drop(custody);
    drop(store);
    let store = Store::open(&host.case.state).unwrap();
    let mut custody = host.custody();
    let mut options = host.options();
    options.max_attempts = Some(1);
    let report = dispatch(&store, &mut custody, &options).unwrap();
    assert!(report.refusals.is_empty(), "{report:?}");
    assert_eq!(report.started, 1);
    assert!(!active.join("reservation").exists());
    assert!(!held_group.exists());
    let recovered = active
        .parent()
        .unwrap()
        .file_name()
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        report
            .completed
            .iter()
            .any(|finished| finished.attempt.as_str() == format!("{recovered}-0001"))
    );
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn calibrated_slots_overlap_real_processes_and_record_elapsed_time() {
    let _processes = processes();
    let host = Host::new("timing");
    let store = Store::open(&host.case.state).unwrap();
    let config = host.config(&store, &[("wall", 60)]);
    host.capacity(&store, "upload", config.value("slots"));
    let calibration_attempts = crate::store::fixture::snapshot(&host.case.state.join("attempts"));
    for run in 0..3 {
        host.job(&store, run, "upload", Purpose::Campaign, 1);
    }
    let mut custody = host.custody();
    let observed = std::rc::Rc::new(std::cell::Cell::new(false));
    let witness = observed.clone();
    let root = host.root.clone();
    let release = host.case.root.join("timing-release");
    let worker_release = release.clone();
    step::install(Some(Script {
        observe: Some(Box::new(move |at| {
            if at == Step::Go {
                let live = fs::read_dir(&root)
                    .unwrap()
                    .flatten()
                    .filter(|e| e.file_type().unwrap().is_dir() && e.file_name() != "controller")
                    .filter(|e| populated(&e.path()))
                    .count();
                if live == 2 {
                    witness.set(true);
                    fs::write(&release, b"release").unwrap();
                }
            }
        })),
        ..Script::default()
    }));
    let mut options = host.options();
    options
        .environment
        .insert("WAIT_FOR".into(), worker_release.into_os_string());
    let began = Instant::now();
    let report = dispatch(&store, &mut custody, &options).unwrap();
    let elapsed = began.elapsed();
    step::install(None);
    assert_eq!(report.started, 3);
    assert!(report.refusals.is_empty(), "{:?}", report.refusals);
    assert!(observed.get(), "two real populated trees overlapped");
    for job in crate::layout::shards(&store, crate::layout::JOBS)
        .unwrap()
        .flat_map(|shard| store.list(&shard.unwrap().dir, crate::SCAN_BOUND).unwrap())
    {
        if let Some(id) = job.as_str().strip_suffix(".manifest") {
            let jobs = store.shard_jobs(id).unwrap().unwrap();
            let admission = store
                .read_record::<Admission>(&jobs, &name(&format!("{id}.json")))
                .unwrap()
                .unwrap();
            if admission.record().purpose() == Purpose::Calibration {
                let prefix = crate::campaign::state_fixture::attempts_dir(id)
                    .strip_prefix("attempts")
                    .unwrap()
                    .to_path_buf();
                let within = |snapshot: &crate::store::fixture::Snapshot| {
                    snapshot
                        .keys()
                        .filter(|path| path.starts_with(&prefix))
                        .cloned()
                        .collect::<Vec<_>>()
                };
                assert_eq!(
                    within(&crate::store::fixture::snapshot(
                        &host.case.state.join("attempts")
                    )),
                    within(&calibration_attempts),
                    "dispatch starts no calibration attempt"
                );
                continue;
            }
            assert!(
                host.case
                    .state
                    .join(crate::campaign::state_fixture::attempts_dir(id))
                    .join("0001/worker-ran")
                    .exists()
            );
        }
    }
    assert_eq!(report.completed.len(), 3);
    eprintln!(
        "dispatch timing: attempts={} worker_delay_s={} slots={} total_dispatch_elapsed_ms={}",
        report.started,
        options
            .environment
            .get(std::ffi::OsStr::new("DELAY"))
            .unwrap()
            .to_string_lossy(),
        config.value("slots"),
        elapsed.as_millis()
    );
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn configured_cpu_bytes_and_inodes_stop_over_budget_trees() {
    let _processes = processes();
    for (label, body, overrides, expected) in [
        (
            "budget-cpu",
            "while :; do :; done",
            vec![("cpu", 1), ("wall", 10)],
            crate::record::Class::CpuLimit,
        ),
        (
            "budget-bytes",
            "dd if=/dev/zero of=a bs=12000 count=1 2>/dev/null; dd if=/dev/zero of=b bs=12000 count=1 2>/dev/null; sleep 30",
            vec![("attempt_output", 16384), ("wall", 10)],
            crate::record::Class::OutputLimit,
        ),
        (
            "budget-byte-exact",
            "dd if=/dev/zero of=a bs=16354 count=1 2>/dev/null; exit 0",
            vec![("attempt_output", 16384), ("wall", 10)],
            crate::record::Class::Incomplete,
        ),
        (
            "budget-byte-over",
            "dd if=/dev/zero of=a bs=16355 count=1 2>/dev/null; exit 0",
            vec![("attempt_output", 16384), ("wall", 10)],
            crate::record::Class::OutputLimit,
        ),
        (
            "budget-inodes",
            "i=0; while [ $i -lt 30 ]; do : > file$i; i=$((i+1)); done; sleep 30",
            vec![("attempt_inodes", 12), ("wall", 10)],
            crate::record::Class::OutputLimit,
        ),
    ] {
        let host = Host::new(label);
        let store = Store::open(&host.case.state).unwrap();
        host.config(&store, &overrides);
        let job = host.job(&store, 0, "upload", Purpose::Campaign, 1);
        let options = host.options();
        fs::write(
            &options.launcher,
            format!("#!/bin/sh\nprintf captured-stdout\nprintf captured-stderr >&2\n{body}\n"),
        )
        .unwrap();
        let now = Instant::now();
        let report = dispatch(&store, &mut host.custody(), &options).unwrap();
        assert_eq!(report.started, 1, "{label}: {report:?}");
        assert_eq!(report.completed.len(), 1, "{label}: {report:?}");
        assert_eq!(report.completed[0].class, expected, "{label}: {report:?}");
        assert!(!report.completed[0].watchdog);
        assert!(now.elapsed() < Duration::from_secs(5), "{label}");
        assert_eq!(
            fs::read(attempt_path(&host, &job).join("launcher.stdout")).unwrap(),
            b"captured-stdout"
        );
        assert_eq!(
            fs::read(attempt_path(&host, &job).join("launcher.stderr")).unwrap(),
            b"captured-stderr"
        );
        assert!(!attempt_path(&host, &job).join("reservation").exists());
        assert!(!host.root.join(format!("{}-0001", job.job().id())).exists());
    }
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn live_capture_census_fault_stops_admission_before_the_next_job() {
    let _processes = processes();
    for fault in [false, true] {
        let host = Host::new("live-capture-census");
        let store = Store::open(&host.case.state).unwrap();
        // An incomplete settlement leaves the session's backlog of zero
        // below the limit of one, so the second job still starts.
        let config = host.config(&store, &[("slots", 1), ("backlog", 1)]);
        let mut jobs = [
            host.job(&store, 0, "upload", Purpose::Campaign, 1),
            host.job(&store, 1, "upload", Purpose::Campaign, 1),
        ];
        jobs.sort_by_key(|job| job.job().id().to_string());
        let first = attempt_path(&host, &jobs[0]);
        let options = host.options();
        let mut custody = host.custody();
        custody.set_watchdog(config.value("wall")).unwrap();
        let directory = store.shard_jobs(jobs[0].job().id()).unwrap().unwrap();
        let admission = store
            .read_record::<Admission>(&directory, &name(&format!("{}.json", jobs[0].job().id())))
            .unwrap()
            .unwrap();
        let launch = crate::attempt::Launch {
            gate: options.gate.clone(),
            launcher: options.launcher.clone(),
            environment: options.environment.clone(),
            limits: crate::campaign::configuration::limits(&config),
        };
        let (attempt, running) =
            crate::attempt::start(&store, &mut custody, admission, launch).unwrap();
        let stopped = custody.wait_any(vec![running]).unwrap().stopped;
        let completed = attempt
            .finish(&store, stopped, crate::attempt::EVIDENCE_BOUND)
            .unwrap();
        assert!(first.join("finished").exists());
        assert!(!first.join("reservation").exists());
        assert!(!first.join("captured").exists());
        let report = resume_pending_capture(
            &store,
            &mut custody,
            &options,
            jobs[0].job().id().to_string(),
            completed,
            fault,
            Some(0),
        )
        .unwrap()
        .0;
        let trace = step::install(None).unwrap();
        if fault {
            assert!(trace.nth.is_none());
            assert_eq!(report.exit(), crate::exit::Supervisor::Held, "{report:?}");
            assert_eq!(report.started, 1, "{report:?}");
            assert_eq!(report.completed.len(), 1);
            assert_eq!(report.counts[report.completed[0].class.name()], 1);
            assert!(!first.join("captured").exists());
            assert!(!attempt_path(&host, &jobs[1]).exists());
        } else {
            assert_eq!(report.started, 2, "{report:?}");
            assert!(report.refusals.is_empty(), "{report:?}");
            assert!(first.join("captured").exists());
        }
    }
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn remaining_cgroup_defers_live_capture_and_refuses_more_admission() {
    let _processes = processes();
    let host = Host::new("live-capture-leftover");
    let store = Store::open(&host.case.state).unwrap();
    host.config(&store, &[("slots", 1)]);
    let job = host.job(&store, 0, "upload", Purpose::Campaign, 1);
    host.job(&store, 1, "upload", Purpose::Campaign, 1);
    let orphan = host.root.join("orphan");
    let injected = orphan.clone();
    step::install(Some(Script {
        observe: Some(Box::new(move |at| {
            if at == Step::Finished {
                fs::create_dir(&injected).unwrap();
            }
        })),
        ..Script::default()
    }));
    let report = dispatch(&store, &mut host.custody(), &host.options()).unwrap();
    step::install(None);
    assert_eq!(report.exit(), crate::exit::Supervisor::Held, "{report:?}");
    assert_eq!(report.started, 1);
    assert!(!attempt_path(&host, &job).join("captured").exists());
    fs::remove_dir(&orphan).unwrap();
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn restart_captures_a_healthy_finish_beside_an_unrelated_reconcile_hold() {
    let _processes = processes();
    let host = Host::new("restart-capture-unrelated");
    let store = Store::open(&host.case.state).unwrap();
    host.config(&store, &[]);
    let healthy = host.job(&store, 0, "upload", Purpose::Campaign, 1);
    let first = dispatch(&store, &mut host.custody(), &host.options()).unwrap();
    assert_eq!(first.started, 1);
    let path = attempt_path(&host, &healthy);
    let result = crate::campaign::state_fixture::result_path(&host.case.state, healthy.job().id());
    fs::remove_file(path.join("captured")).unwrap();
    let settled = dispatch(&store, &mut host.custody(), &host.options()).unwrap();
    assert_eq!(settled.started, 0, "{settled:?}");
    assert!(!path.join("captured").exists());
    assert!(result.exists());
    fs::remove_file(&result).unwrap();
    let held = host.job(&store, 1, "upload", Purpose::Campaign, 1);
    fs::write(
        host.case
            .state
            .join(crate::campaign::state_fixture::job_file(format!(
                "{}{}",
                held.job().id(),
                crate::record::Pin::SUFFIX
            ))),
        b"damaged pin",
    )
    .unwrap();
    let report = dispatch(&store, &mut host.custody(), &host.options()).unwrap();
    assert_eq!(report.exit(), crate::exit::Supervisor::Held, "{report:?}");
    assert_eq!(report.started, 0);
    assert!(path.join("captured").exists());
    assert!(result.exists());
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_long_poll_wakes_at_the_dispatch_deadline() {
    let _processes = processes();
    let host = Host::new("deadline-poll");
    let store = Store::open(&host.case.state).unwrap();
    host.config(&store, &[("wall", 10)]);
    host.job(&store, 0, "upload", Purpose::Campaign, 1);
    let mut options = host.options();
    options.environment.insert("DELAY".into(), "30".into());
    let mut custody = Custody::open(
        &host.root,
        Timing {
            poll: Duration::from_secs(5),
            kill_wait: Duration::from_secs(1),
            watchdog: Duration::from_secs(20),
        },
    )
    .unwrap();
    options.deadline = Some(Instant::now() + Duration::from_secs(1));
    let now = Instant::now();
    let report = dispatch(&store, &mut custody, &options).unwrap();
    assert_eq!(report.started, 1, "{report:?}");
    assert_eq!(
        report.completed[0].interruption,
        Some(crate::sys::KILL_SIGNAL)
    );
    assert!(!report.completed[0].watchdog);
    assert!(now.elapsed() < Duration::from_secs(3));
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn completed_siblings_keep_their_exit_when_settlement_crosses_deadline() {
    let _processes = processes();
    let host = Host::new("completed-deadline");
    let store = Store::open(&host.case.state).unwrap();
    host.config(&store, &[("wall", 10)]);
    host.capacity(&store, "upload", 2);
    for run in 0..2 {
        host.job(&store, run, "upload", Purpose::Campaign, 1);
    }
    let mut options = host.options();
    options.environment.insert("DELAY".into(), "0.01".into());
    let mut custody = host.custody();
    let deadline = Instant::now() + Duration::from_secs(2);
    options.deadline = Some(deadline);
    let mut slept = false;
    step::install(Some(Script {
        observe: Some(Box::new(move |at| {
            if at == Step::Finished && !slept {
                slept = true;
                std::thread::sleep(
                    deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(50),
                );
            }
        })),
        ..Script::default()
    }));
    let report = dispatch(&store, &mut custody, &options).unwrap();
    step::install(None);
    assert_eq!(report.started, 2, "{report:?}");
    assert_eq!(report.completed.len(), 2);
    for finished in report.completed {
        assert_eq!(finished.exit, Some(0));
        assert_eq!(finished.interruption, None);
        assert!(!finished.watchdog);
    }
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn setup_errors_preserve_reconciled_completion_rows_and_reject_orphan_pins() {
    let _processes = processes();
    for problem in [
        "config-missing",
        "config-damaged",
        "archive",
        "pin",
        "result",
        "stray",
    ] {
        let host = Host::new(problem);
        let store = Store::open(&host.case.state).unwrap();
        host.config(&store, &[]);
        let job = host.job(&store, 0, "upload", Purpose::Campaign, 1);
        let mut options = host.options();
        let mut expected = if problem == "result" {
            // A result record settles the job by its name; dispatch reads
            // none of its records.
            crate::exit::Supervisor::Success
        } else {
            crate::exit::Supervisor::Held
        };
        if problem == "archive" {
            options.archive = host.case.root.join("missing-archive");
            expected = crate::exit::Supervisor::Rejected;
        }
        if problem == "config-missing" {
            fs::remove_file(host.case.state.join("config.json")).unwrap();
        }
        if problem == "config-damaged" {
            fs::write(host.case.state.join("config.json"), b"bad").unwrap();
        }
        if problem == "pin" {
            fs::write(
                host.case
                    .state
                    .join(crate::campaign::state_fixture::job_file(format!(
                        "{}.pin",
                        job.job().id()
                    ))),
                b"bad",
            )
            .unwrap();
        }
        if problem == "result" {
            fs::write(
                crate::campaign::state_fixture::result_path(&host.case.state, job.job().id()),
                b"bad",
            )
            .unwrap();
        }
        if problem == "stray" {
            fs::create_dir_all(host.case.state.join("jobs/ab")).unwrap();
            fs::write(host.case.state.join("jobs/ab/stray"), b"held").unwrap();
        }
        let report = dispatch(&store, &mut host.custody(), &options).unwrap();
        assert_eq!(report.exit(), expected, "{problem}: {report:?}");
        if problem == "stray" {
            assert!(
                report
                    .refusals
                    .iter()
                    .any(|reason| reason == "unknown job entry stray")
            );
        }
        assert_eq!(report.started, 0);
        assert!(!attempt_path(&host, &job).exists());
    }
    let host = Host::new("setup-recovered");
    let store = Store::open(&host.case.state).unwrap();
    host.config(&store, &[]);
    host.job(&store, 0, "upload", Purpose::Campaign, 1);
    let options = host.options();
    let mut custody = host.custody();
    step::install(Some(Script {
        nth: Some((Step::Finished, 0, Outcome::Kill)),
        ..Script::default()
    }));
    let crash = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        dispatch(&store, &mut custody, &options)
    }));
    assert!(crash.err().is_some_and(|error| error.is::<step::Killed>()));
    step::install(None);
    fs::remove_file(host.case.state.join("config.json")).unwrap();
    drop(custody);
    drop(store);
    let store = Store::open(&host.case.state).unwrap();
    let report = dispatch(&store, &mut host.custody(), &options).unwrap();
    assert_eq!(report.exit(), crate::exit::Supervisor::Held);
    assert_eq!(report.started, 0);
    assert_eq!(report.completed.len(), 1, "{report:?}");
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn configuration_wall_replaces_the_initial_watchdog() {
    let _processes = processes();
    let host = Host::new("wall-budget");
    let store = Store::open(&host.case.state).unwrap();
    host.config(&store, &[("wall", 1)]);
    host.job(&store, 0, "upload", Purpose::Campaign, 1);
    let mut options = host.options();
    options.environment.insert("DELAY".into(), "30".into());
    let mut custody = Custody::open(
        &host.root,
        Timing {
            poll: Duration::from_millis(5),
            kill_wait: Duration::from_secs(1),
            watchdog: Duration::from_secs(20),
        },
    )
    .unwrap();
    let now = Instant::now();
    let report = dispatch(&store, &mut custody, &options).unwrap();
    assert_eq!(report.completed.len(), 1);
    assert!(report.completed[0].watchdog);
    assert_eq!(report.completed[0].class, crate::record::Class::Watchdog);
    assert!(now.elapsed() < Duration::from_secs(3));
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn settled_failure_pins_fill_backlog_in_the_same_controller_and_after_restart() {
    let _processes = processes();
    let host = Host::new("backlog-producer");
    let store = Store::open(&host.case.state).unwrap();
    // The session starts from one counted pin at limit 2, so its own pin
    // must add to that count to reach the limit.
    let config = host.config(&store, &[("backlog", 2)]);
    let failed = host.job(&store, 0, "upload", Purpose::Campaign, 1);
    let queued = host.job(&store, 1, "upload", Purpose::Campaign, 1);
    let options = host.options();
    fs::write(&options.launcher, "#!/bin/sh\nsleep 0.02\nexit 1\n").unwrap();
    let jobs = store.shard_jobs(failed.job().id()).unwrap().unwrap();
    let verified = store
        .read_record::<Admission>(&jobs, &name(&format!("{}.json", failed.job().id())))
        .unwrap()
        .unwrap();
    let mut custody = host.custody();
    let (attempt, running) = crate::attempt::start(
        &store,
        &mut custody,
        verified,
        crate::attempt::Launch {
            gate: options.gate.clone(),
            launcher: options.launcher.clone(),
            environment: options.environment.clone(),
            limits: crate::custody::Limits {
                cpu_quota_us: crate::store::cgroup::CPU_PERIOD_US,
                memory_bytes: config.value("tree_memory"),
                pids: config.value("processes"),
                file_bytes: config.file_bytes(),
                cpu_seconds: config.value("cpu"),
                output_bytes: config.file_bytes(),
                output_inodes: config.value("attempt_inodes"),
            },
        },
    )
    .unwrap();
    let directory = crate::layout::attempts(&store, &failed.job().id().to_string())
        .unwrap()
        .unwrap();
    let directory = store.open_dir(&directory, &name("0001")).unwrap().unwrap();
    let record = store
        .read_record::<crate::record::Attempt>(&directory, &name("attempt"))
        .unwrap()
        .unwrap();
    let mut artifact =
        crate::attempt::tests::artifact(record.record().attempt.as_str(), record.record().manifest);
    artifact.archive = Digest::parse(failed.job().experiment().pins.build.as_str());
    artifact.class = text("complete");
    artifact.summary.as_mut().unwrap().terminal = text("complete violation fired=03 required=03");
    let evidence = crate::attempt::tests::stage(&store, &directory, record.record(), &artifact);
    let manifest = fs::read(
        host.case
            .state
            .join(crate::campaign::state_fixture::job_file(format!(
                "{}.manifest",
                failed.job().id()
            ))),
    )
    .unwrap();
    store
        .replace(&evidence, &name("manifest"), &manifest)
        .unwrap();
    let waited = custody.wait_any(vec![running]).unwrap();
    let completed = attempt
        .finish(&store, waited.stopped, crate::attempt::EVIDENCE_BOUND)
        .unwrap();
    assert_eq!(
        completed.finished().record().class,
        crate::record::Class::Violation
    );
    assert_eq!(policy::backlog(&store).unwrap(), 0);
    let (report, census) = resume_pending_capture(
        &store,
        &mut custody,
        &options,
        failed.job().id().to_string(),
        completed,
        false,
        Some(1),
    )
    .unwrap();
    step::install(None);
    assert_eq!(
        census.unwrap(),
        crate::campaign::census::Census::count(&store).unwrap(),
        "the session charges the pin and result it published"
    );
    assert_eq!(policy::backlog(&store).unwrap(), 1);
    assert_eq!(report.completed.len(), 1);
    assert_eq!(report.completed[0].class, crate::record::Class::Violation);
    assert_eq!(
        report.refusals,
        [
            "backlog holds 2 failure pins without a resolved disposition at limit 2; dispose findings or raise backlog"
        ]
    );
    host.config(&store, &[("backlog", 1)]);
    let held = "backlog holds 1 failure pins without a resolved disposition at limit 1; dispose findings or raise backlog";
    assert!(!attempt_path(&host, &queued).exists());
    drop(custody);
    drop(store);
    let store = Store::open(&host.case.state).unwrap();
    let report = dispatch(&store, &mut host.custody(), &options).unwrap();
    assert_eq!(report.exit(), crate::exit::Supervisor::Held);
    assert_eq!(report.state, super::State::Held);
    assert_eq!(report.started, 0);
    assert!(report.completed.is_empty());
    assert_eq!(report.refusals, [held]);
    assert!(report.paused.is_empty(), "{report:?}");
    assert!(!attempt_path(&host, &queued).exists());
    let finding = format!("{}-0001", failed.job().id());
    crate::campaign::findings::append(
        &store,
        &crate::store::View::open(&host.case.state).unwrap(),
        text(&finding),
        crate::record::Decision::Resolved,
        text("fixed"),
    )
    .unwrap();
    assert_eq!(policy::backlog(&store).unwrap(), 0);
    let report = dispatch(&store, &mut host.custody(), &options).unwrap();
    assert_eq!(
        report.exit(),
        crate::exit::Supervisor::Success,
        "{report:?}"
    );
    assert_eq!(report.started, 1);
    assert!(attempt_path(&host, &queued).exists());
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_failed_second_start_lets_the_running_attempt_conclude() {
    let _processes = processes();
    let host = Host::new("start-refusal-drain");
    let store = Store::open(&host.case.state).unwrap();
    host.config(&store, &[]);
    host.capacity(&store, "upload", 2);
    for run in 0..2 {
        host.job(&store, run, "upload", Purpose::Campaign, 1);
    }
    let options = host.options();
    fs::write(
        &options.launcher,
        "#!/bin/sh\nprintf ready > worker-ready\nsleep 0.1\nprintf ran > worker-ran\nexit 0\n",
    )
    .unwrap();
    let state = host.case.state.clone();
    let gate = options.gate.clone();
    let mut launched = false;
    let mut removed = false;
    step::install(Some(Script {
        observe: Some(Box::new(move |at| {
            if at == Step::Go {
                launched = true;
            }
            if at == Step::Census && launched && !removed {
                let deadline = Instant::now() + Duration::from_secs(2);
                loop {
                    let ready = fs::read_dir(state.join("attempts"))
                        .unwrap()
                        .flatten()
                        .flat_map(|shard| fs::read_dir(shard.path()).unwrap().flatten())
                        .any(|job| job.path().join("0001/worker-ready").exists());
                    if ready {
                        break;
                    }
                    assert!(Instant::now() < deadline);
                    std::thread::sleep(Duration::from_millis(1));
                }
                fs::remove_file(&gate).unwrap();
                removed = true;
            }
        })),
        ..Script::default()
    }));
    let report = dispatch(&store, &mut host.custody(), &options).unwrap();
    step::install(None);
    assert_eq!(
        report.exit(),
        crate::exit::Supervisor::Rejected,
        "{report:?}"
    );
    assert_eq!(report.started, 1);
    assert_eq!(report.completed.len(), 1);
    assert_eq!(report.completed[0].exit, Some(0));
    assert_eq!(report.completed[0].interruption, None);
    assert!(!report.completed[0].watchdog);
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn dispatch_recovers_probe_records_before_campaign_starts_and_holds_damaged_charge() {
    let _processes = processes();
    for damaged in [false, true] {
        let host = Host::new(if damaged {
            "probe-charge-held"
        } else {
            "probe-recovered"
        });
        let store = Store::open(&host.case.state).unwrap();
        let config = host.config(&store, &[]);
        let job = host.job(&store, 0, "upload", Purpose::Campaign, 1);
        store.mkdir(store.root(), &name("probes")).unwrap();
        let probes = store
            .open_dir(store.root(), &name("probes"))
            .unwrap()
            .unwrap();
        store.mkdir(&probes, &name("probe-recovery")).unwrap();
        let directory = store
            .open_dir(&probes, &name("probe-recovery"))
            .unwrap()
            .unwrap();
        crate::custody::charge(&store, &directory, &text("probe-recovery")).unwrap();
        let options = host.options();
        let mut custody = host.custody();
        let running = custody
            .launch(
                &store,
                &directory,
                crate::custody::Launch {
                    attempt: text("probe-recovery"),
                    name: name("probe-recovery"),
                    gate: options.gate.clone(),
                    launcher: options.launcher.clone(),
                    args: Vec::new(),
                    directory: host.case.state.join("probes/probe-recovery"),
                    environment: options.environment.clone(),
                    limits: crate::custody::Limits {
                        cpu_quota_us: crate::store::cgroup::CPU_PERIOD_US,
                        memory_bytes: config.value("tree_memory"),
                        pids: config.value("processes"),
                        file_bytes: config.file_bytes(),
                        cpu_seconds: config.value("cpu"),
                        output_bytes: config.file_bytes(),
                        output_inodes: config.value("attempt_inodes"),
                    },
                },
            )
            .unwrap();
        drop(running);
        if damaged {
            fs::write(
                host.case.state.join("probes/probe-recovery/reservation"),
                b"bad",
            )
            .unwrap();
        }
        let report = dispatch(&store, &mut custody, &options).unwrap();
        if damaged {
            assert_eq!(report.exit(), crate::exit::Supervisor::Held);
            assert_eq!(report.started, 0);
            assert!(!attempt_path(&host, &job).exists());
            assert!(!populated(&host.root.join("probe-recovery")));
        } else {
            assert_eq!(
                report.exit(),
                crate::exit::Supervisor::Success,
                "{report:?}"
            );
            assert_eq!(report.started, 1);
            assert!(!host.root.join("probe-recovery").exists());
            assert!(
                !host
                    .case
                    .state
                    .join("probes/probe-recovery/reservation")
                    .exists()
            );
            assert!(
                host.case
                    .state
                    .join("probes/probe-recovery/finished")
                    .exists()
            );
        }
    }
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn tree_cpu_budget_keeps_priority_when_output_also_exceeds_its_budget() {
    let _processes = processes();
    let host = Host::new("tree-budget-priority");
    let store = Store::open(&host.case.state).unwrap();
    host.config(
        &store,
        &[("cpu", 1), ("wall", 10), ("attempt_output", 16384)],
    );
    let job = host.job(&store, 0, "upload", Purpose::Campaign, 1);
    let options = host.options();
    fs::write(&options.launcher, "#!/bin/sh\ndd if=/dev/zero of=a bs=12000 count=1 2>/dev/null\ndd if=/dev/zero of=b bs=12000 count=1 2>/dev/null\n(while :; do :; done) &\n(while :; do :; done) &\nwait\n").unwrap();
    let group = host.root.join(format!("{}-0001", job.job().id()));
    let mut released = false;
    let mut sampled = false;
    step::install(Some(Script {
        observe: Some(Box::new(move |at| {
            if at == Step::ReleasedGate {
                released = true;
            }
            if released && !sampled && at == Step::Read {
                sampled = true;
                let deadline = Instant::now() + Duration::from_secs(5);
                loop {
                    let stats = fs::read_to_string(group.join("cpu.stat")).unwrap();
                    let used = stats
                        .lines()
                        .find_map(|line| line.strip_prefix("usage_usec "))
                        .unwrap()
                        .parse::<u64>()
                        .unwrap();
                    if used >= 1_100_000 {
                        break;
                    }
                    assert!(Instant::now() < deadline);
                    std::thread::sleep(Duration::from_millis(2));
                }
            }
        })),
        ..Script::default()
    }));
    let report = dispatch(&store, &mut host.custody(), &options).unwrap();
    step::install(None);
    assert_eq!(report.completed.len(), 1, "{report:?}");
    assert_eq!(report.completed[0].class, crate::record::Class::CpuLimit);
    assert_eq!(
        report.completed[0].interruption,
        Some(crate::sys::CPU_SIGNAL as u64)
    );
    assert!(report.completed[0].kernel.cpu[&text("usage_usec")] >= 1_000_000);
    assert_eq!(
        fs::metadata(attempt_path(&host, &job).join("a"))
            .unwrap()
            .len()
            + fs::metadata(attempt_path(&host, &job).join("b"))
                .unwrap()
                .len(),
        24000
    );
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn an_output_read_fault_holds_one_attempt_while_healthy_siblings_conclude() {
    let _processes = processes();
    let host = Host::new("local-census-fault");
    let store = Store::open(&host.case.state).unwrap();
    host.config(&store, &[]);
    host.capacity(&store, "upload", 2);
    let mut jobs: Vec<_> = (0..3)
        .map(|run| host.job(&store, run, "upload", Purpose::Campaign, 1))
        .collect();
    jobs.sort_by_key(|job| job.job().id().to_string());
    let failed = attempt_path(&host, &jobs[0]);
    let release = host.case.root.join("release");
    let mut options = host.options();
    options
        .environment
        .insert("WAIT_FOR".into(), release.clone().into_os_string());
    let fault_path = failed.clone();
    let mut starts = 0;
    let mut faulted = false;
    step::install(Some(Script {
        observe: Some(Box::new(move |at| {
            if at == Step::ReleasedGate {
                starts += 1;
            }
            if starts == 2 && !faulted && at == Step::Reap {
                faulted = true;
                fs::set_permissions(&fault_path, fs::Permissions::from_mode(0o0)).unwrap();
                fs::write(&release, b"go").unwrap();
            }
        })),
        ..Script::default()
    }));
    let report = dispatch(&store, &mut host.custody(), &options).unwrap();
    step::install(None);
    fs::set_permissions(&failed, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(report.exit(), crate::exit::Supervisor::Held, "{report:?}");
    assert_eq!(report.started, 2);
    assert_eq!(report.completed.len(), 1);
    assert_eq!(report.completed[0].exit, Some(0));
    assert_eq!(report.completed[0].interruption, None);
    assert!(failed.join("reservation").exists());
    assert!(!failed.join("finished").exists());
    let group = host.root.join(format!("{}-0001", jobs[0].job().id()));
    assert!(group.exists());
    assert!(!populated(&group));
    assert!(attempt_path(&host, &jobs[1]).join("worker-ran").exists());
    assert!(!attempt_path(&host, &jobs[2]).exists());
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn probe_prefix_and_read_fault_recovery_preserve_charges_and_drain_missing_charges() {
    let _processes = processes();
    for state in ["pending", "missing", "damaged", "read-fault"] {
        let host = Host::new(state);
        let store = Store::open(&host.case.state).unwrap();
        let config = host.config(&store, &[]);
        host.job(&store, 0, "upload", Purpose::Campaign, 1);
        store.mkdir(store.root(), &name("probes")).unwrap();
        let probes = store
            .open_dir(store.root(), &name("probes"))
            .unwrap()
            .unwrap();
        store.mkdir(&probes, &name("probe-prefix")).unwrap();
        let directory = store
            .open_dir(&probes, &name("probe-prefix"))
            .unwrap()
            .unwrap();
        crate::custody::charge(&store, &directory, &text("probe-prefix")).unwrap();
        let mut options = host.options();
        let mut custody = host.custody();
        if state != "pending" {
            let mut environment = options.environment.clone();
            environment.insert("DELAY".into(), "30".into());
            let running = custody
                .launch(
                    &store,
                    &directory,
                    crate::custody::Launch {
                        attempt: text("probe-prefix"),
                        name: name("probe-prefix"),
                        gate: options.gate.clone(),
                        launcher: options.launcher.clone(),
                        args: Vec::new(),
                        directory: host.case.state.join("probes/probe-prefix"),
                        environment,
                        limits: crate::custody::Limits {
                            cpu_quota_us: crate::store::cgroup::CPU_PERIOD_US,
                            memory_bytes: config.value("tree_memory"),
                            pids: config.value("processes"),
                            file_bytes: config.file_bytes(),
                            cpu_seconds: config.value("cpu"),
                            output_bytes: config.file_bytes(),
                            output_inodes: config.value("attempt_inodes"),
                        },
                    },
                )
                .unwrap();
            drop(running);
            assert!(populated(&host.root.join("probe-prefix")));
        }
        let path = host.case.state.join("probes/probe-prefix");
        if state == "missing" {
            fs::remove_file(path.join("reservation")).unwrap();
        }
        if state == "damaged" {
            fs::write(path.join("reservation"), b"bad").unwrap();
        }
        let before = fs::read(path.join("reservation")).ok();
        if state == "read-fault" {
            step::install(Some(Script {
                nth: Some((Step::Read, 0, Outcome::Errno(libc::EIO))),
                ..Script::default()
            }));
        }
        let report = dispatch(&store, &mut custody, &options).unwrap();
        step::install(None);
        if state == "pending" {
            assert_eq!(report.started, 1, "{report:?}");
            assert!(path.join("finished").exists());
            assert!(!path.join("reservation").exists());
        } else {
            assert_eq!(
                report.exit(),
                crate::exit::Supervisor::Held,
                "{state}: {report:?}"
            );
            assert_eq!(report.started, 0);
            assert!(!populated(&host.root.join("probe-prefix")));
            assert!(host.root.join("probe-prefix").exists());
            assert_eq!(fs::read(path.join("reservation")).ok(), before);
            assert!(!path.join("finished").exists());
            drop(custody);
            drop(store);
            let store = Store::open(&host.case.state).unwrap();
            let mut custody = host.custody();
            options.environment.insert("DELAY".into(), "0.01".into());
            let again = dispatch(&store, &mut custody, &options).unwrap();
            if state == "read-fault" {
                assert_eq!(again.started, 1);
                assert!(!path.join("reservation").exists());
            } else {
                assert_eq!(again.started, 0);
                assert_eq!(again.exit(), crate::exit::Supervisor::Held);
                assert_eq!(fs::read(path.join("reservation")).ok(), before);
                assert!(!path.join("finished").exists());
            }
        }
    }
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn verified_orphan_settlement_entries_hold_all_entry_points_before_minting() {
    let _processes = processes();
    for pin in [false, true] {
        let host = Host::new(if pin {
            "valid-orphan-pin"
        } else {
            "valid-orphan-result"
        });
        let store = Store::open(&host.case.state).unwrap();
        let config = host.config(&store, &[]);
        let job = host.job(&store, 0, "upload", Purpose::Campaign, 2);
        let id = job.job().id().to_string();
        let jobs = store.shard_jobs(&id).unwrap().unwrap();
        let result = crate::record::JobResult {
            attempt: 1,
            job: job.job().id().digest(),
            manifest: job.job().manifest_sha256(),
            finished: crate::record::Finished {
                attempt: text(&format!("{id}-0001")),
                binding: crate::record::Binding::Missing,
                bound: None,
                class: crate::record::Class::Interrupted,
                exit: None,
                interruption: Some(15),
                kernel: crate::record::Kernel::default(),
                residual_members: false,
                signal: None,
                watchdog: false,
            },
        };
        let file = if pin {
            format!("{id}.pin")
        } else {
            format!("{id}.result.json")
        };
        if pin {
            store
                .create_record(&jobs, &name(&file), &crate::record::Pin { result })
                .unwrap();
        } else {
            store.create_record(&jobs, &name(&file), &result).unwrap();
        }
        let before = fs::read(
            host.case
                .state
                .join(crate::campaign::state_fixture::job_file(&file)),
        )
        .unwrap();
        let report = dispatch(&store, &mut host.custody(), &host.options()).unwrap();
        assert_eq!(report.started, 0);
        if pin {
            assert_eq!(report.exit(), crate::exit::Supervisor::Held);
            assert!(
                report
                    .refusals
                    .iter()
                    .any(|message| message.contains("settlement entry has no attempt history"))
            );
        } else {
            // A result record settles the job by its name, so dispatch reads
            // none of its records; attempt start still refuses it.
            assert_eq!(
                report.exit(),
                crate::exit::Supervisor::Success,
                "{report:?}"
            );
        }
        let options = host.options();
        let verified = store
            .read_record::<Admission>(&jobs, &name(&format!("{id}.json")))
            .unwrap()
            .unwrap();
        let started = crate::attempt::start(
            &store,
            &mut host.custody(),
            verified,
            crate::attempt::Launch {
                gate: options.gate,
                launcher: options.launcher,
                environment: options.environment,
                limits: crate::custody::Limits {
                    cpu_quota_us: crate::store::cgroup::CPU_PERIOD_US,
                    memory_bytes: config.value("tree_memory"),
                    pids: config.value("processes"),
                    file_bytes: config.file_bytes(),
                    cpu_seconds: config.value("cpu"),
                    output_bytes: config.file_bytes(),
                    output_inodes: config.value("attempt_inodes"),
                },
            },
        );
        assert!(matches!(
            started,
            Err(crate::custody::Error::Held(
                "settlement entry has no attempt history"
            ))
        ));
        assert!(!attempt_path(&host, &job).exists());
        assert_eq!(
            fs::read(
                host.case
                    .state
                    .join(crate::campaign::state_fixture::job_file(&file))
            )
            .unwrap(),
            before
        );
    }
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_deadline_crossed_during_census_mints_no_numbered_attempt() {
    let _processes = processes();
    let host = Host::new("pre-mint-deadline");
    let store = Store::open(&host.case.state).unwrap();
    host.config(&store, &[]);
    let job = host.job(&store, 0, "upload", Purpose::Campaign, 1);
    let mut custody = host.custody();
    let mut options = host.options();
    let deadline = Instant::now() + Duration::from_secs(1);
    options.deadline = Some(deadline);
    let mut delayed = false;
    step::install(Some(Script {
        observe: Some(Box::new(move |at| {
            if at == Step::Census && !delayed {
                delayed = true;
                std::thread::sleep(
                    deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(10),
                );
            }
        })),
        ..Script::default()
    }));
    let report = dispatch(&store, &mut custody, &options).unwrap();
    let trace = step::install(None).unwrap();
    assert!(trace.reached.contains(&Step::Census));
    assert!(!trace.reached.contains(&Step::Reservation));
    assert_eq!(report.started, 0);
    assert!(report.completed.is_empty());
    assert!(!attempt_path(&host, &job).exists());
    assert!(
        !crate::campaign::state_fixture::result_path(&host.case.state, job.job().id()).exists()
    );
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn stray_cgroups_and_attempts_without_readable_jobs_hold_dispatch_startup() {
    let _processes = processes();
    for jobs_present in [false, true] {
        let host = Host::new(if jobs_present {
            "stray-with-job"
        } else {
            "stray-no-job"
        });
        let store = Store::open(&host.case.state).unwrap();
        host.config(&store, &[]);
        if jobs_present {
            host.job(&store, 0, "upload", Purpose::Campaign, 1);
        }
        let stray = host.root.join("stray");
        fs::create_dir(&stray).unwrap();
        let report = dispatch(&store, &mut host.custody(), &host.options()).unwrap();
        assert_eq!(report.exit(), crate::exit::Supervisor::Held);
        assert_eq!(report.started, 0);
        assert!(stray.exists());
        assert!(!host.case.state.join("attempts").exists());
    }
    let host = Host::new("unreadable-attempt-job");
    let store = Store::open(&host.case.state).unwrap();
    host.config(&store, &[]);
    let job = host.job(&store, 0, "upload", Purpose::Campaign, 1);
    fs::create_dir_all(attempt_path(&host, &job)).unwrap();
    fs::write(
        host.case
            .state
            .join(crate::campaign::state_fixture::job_file(format!(
                "{}.json",
                job.job().id()
            ))),
        b"damaged",
    )
    .unwrap();
    let report = dispatch(&store, &mut host.custody(), &host.options()).unwrap();
    assert_eq!(report.exit(), crate::exit::Supervisor::Held);
    assert_eq!(report.started, 0);
    assert!(
        report
            .refusals
            .iter()
            .any(|reason| reason.contains("attempts without readable job"))
    );
    assert_eq!(fs::read_dir(attempt_path(&host, &job)).unwrap().count(), 0);
    let host = Host::new("attempts-without-jobs-directory");
    let store = Store::open(&host.case.state).unwrap();
    host.config(&store, &[]);
    let job = host.job(&store, 0, "upload", Purpose::Campaign, 1);
    fs::create_dir_all(attempt_path(&host, &job)).unwrap();
    fs::remove_dir_all(host.case.state.join("jobs")).unwrap();
    let report = dispatch(&store, &mut host.custody(), &host.options()).unwrap();
    assert_eq!(report.exit(), crate::exit::Supervisor::Held, "{report:?}");
    assert_eq!(report.started, 0);
    assert!(
        report
            .refusals
            .iter()
            .any(|reason| reason.contains("attempts without readable job"))
    );
    assert!(attempt_path(&host, &job).exists());
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_transient_inner_charge_read_holds_after_drain_and_retries_uncredited_on_restart() {
    let _processes = processes();
    let host = Host::new("inner-charge-read");
    let store = Store::open(&host.case.state).unwrap();
    let config = host.config(&store, &[]);
    let job = host.job(&store, 0, "upload", Purpose::Campaign, 1);
    let jobs = store.shard_jobs(job.job().id()).unwrap().unwrap();
    let verified = store
        .read_record::<Admission>(&jobs, &name(&format!("{}.json", job.job().id())))
        .unwrap()
        .unwrap();
    let mut options = host.options();
    options.environment.insert("DELAY".into(), "30".into());
    let mut custody = host.custody();
    let (active, running) = crate::attempt::start(
        &store,
        &mut custody,
        verified,
        crate::attempt::Launch {
            gate: options.gate.clone(),
            launcher: options.launcher.clone(),
            environment: options.environment.clone(),
            limits: crate::custody::Limits {
                cpu_quota_us: crate::store::cgroup::CPU_PERIOD_US,
                memory_bytes: config.value("tree_memory"),
                pids: config.value("processes"),
                file_bytes: config.file_bytes(),
                cpu_seconds: config.value("cpu"),
                output_bytes: config.file_bytes(),
                output_inodes: config.value("attempt_inodes"),
            },
        },
    )
    .unwrap();
    drop(running);
    assert!(active.reservation(&store).unwrap());
    step::install(Some(Script {
        nth: Some((Step::Read, 0, Outcome::Errno(libc::EIO))),
        ..Script::default()
    }));
    let result = active.reconcile(&store, &mut custody, crate::attempt::EVIDENCE_BOUND);
    step::install(None);
    assert!(result.is_err());
    let path = attempt_path(&host, &job);
    assert!(path.join("reservation").exists());
    assert!(!path.join("finished").exists());
    assert!(!populated(
        &host.root.join(format!("{}-0001", job.job().id()))
    ));
    drop(custody);
    drop(store);
    let store = Store::open(&host.case.state).unwrap();
    let report = dispatch(&store, &mut host.custody(), &options).unwrap();
    assert_eq!(report.started, 0);
    assert_eq!(report.completed.len(), 1);
    assert_eq!(report.completed[0].class, crate::record::Class::Interrupted);
    assert_eq!(report.completed[0].exit, None);
    assert!(!path.join("reservation").exists());
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn wait_error_keeps_a_resource_faulted_siblings_charge_for_uncredited_restart() {
    let _processes = processes();
    let host = Host::new("wait-error-resource");
    let store = Store::open(&host.case.state).unwrap();
    host.config(&store, &[]);
    host.capacity(&store, "upload", 2);
    let mut jobs: Vec<_> = (0..2)
        .map(|run| host.job(&store, run, "upload", Purpose::Campaign, 1))
        .collect();
    jobs.sort_by_key(|job| job.job().id().to_string());
    let failed = attempt_path(&host, &jobs[0]);
    let fault_path = failed.clone();
    let release = host.case.root.join("release");
    let mut options = host.options();
    options
        .environment
        .insert("WAIT_FOR".into(), release.clone().into_os_string());
    let mut starts = 0;
    let mut faulted = false;
    let mut restored = false;
    step::install(Some(Script {
        nth: Some((Step::Poll, 0, Outcome::Errno(libc::EIO))),
        observe: Some(Box::new(move |at| {
            if at == Step::ReleasedGate {
                starts += 1;
            }
            if starts == 2 && !faulted && at == Step::Reap {
                faulted = true;
                fs::set_permissions(&fault_path, fs::Permissions::from_mode(0o0)).unwrap();
            }
            if faulted && !restored && at == Step::Killed {
                restored = true;
                fs::set_permissions(&fault_path, fs::Permissions::from_mode(0o700)).unwrap();
            }
        })),
        ..Script::default()
    }));
    let mut custody = host.custody();
    let report = dispatch(&store, &mut custody, &options).unwrap();
    let trace = step::install(None).unwrap();
    assert!(trace.reached.contains(&Step::Poll));
    assert_eq!(report.exit(), crate::exit::Supervisor::Held);
    assert!(custody.resource_faulted(&text(&format!("{}-0001", jobs[0].job().id()))));
    assert!(failed.join("reservation").exists());
    assert!(!failed.join("finished").exists());
    drop(custody);
    drop(store);
    let store = Store::open(&host.case.state).unwrap();
    options.environment.remove(std::ffi::OsStr::new("WAIT_FOR"));
    let again = dispatch(&store, &mut host.custody(), &options).unwrap();
    let recovered = again
        .completed
        .iter()
        .find(|row| row.attempt.as_str() == format!("{}-0001", jobs[0].job().id()))
        .unwrap();
    assert_eq!(recovered.class, crate::record::Class::Interrupted);
    assert_eq!(recovered.exit, None);
    assert!(!failed.join("reservation").exists());
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_pending_finding_waits_for_the_sibling_watchdog_before_capture() {
    let _processes = processes();
    let host = Host::new("capture-batch");
    let store = Store::open(&host.case.state).unwrap();
    host.config(&store, &[("wall", 1)]);
    host.capacity(&store, "upload", 2);
    let mut jobs = [
        host.job(&store, 0, "upload", Purpose::Campaign, 1),
        host.job(&store, 1, "upload", Purpose::Campaign, 1),
        host.job(&store, 2, "upload", Purpose::Campaign, 1),
    ];
    jobs.sort_by_key(|job| job.job().id().to_string());
    let fast = jobs[0].clone();
    let fast_path = attempt_path(&host, &jobs[0]);
    let slow_path = attempt_path(&host, &jobs[1]);
    let manifest = fs::read(
        host.case
            .state
            .join(crate::campaign::state_fixture::job_file(format!(
                "{}.manifest",
                fast.job().id()
            ))),
    )
    .unwrap();
    let finding = host
        .case
        .state
        .join("findings")
        .join(format!("{}-0001", fast.job().id()));
    let deferred = std::rc::Rc::new(std::cell::Cell::new(false));
    let saw_deferred = deferred.clone();
    let slow = slow_path.clone();
    let quick = fast_path.clone();
    let mut staged = false;
    let mut launches = 0;
    step::install(Some(Script {
        observe: Some(Box::new(move |at| {
            if at == Step::Go {
                launches += 1;
                if launches == 3 {
                    assert!(quick.join("finished").exists());
                    assert!(slow.join("finished").exists());
                }
            }
            if at == Step::Go && !staged {
                staged = true;
                let id = format!("{}-0001", fast.job().id());
                let mut artifact =
                    crate::attempt::tests::artifact(&id, fast.job().manifest_sha256());
                artifact.archive = Digest::parse(fast.job().experiment().pins.build.as_str());
                artifact.class = text("complete");
                artifact.summary.as_mut().unwrap().terminal =
                    text("complete violation fired=03 required=03");
                let dir = quick.join("artifacts").join(&id);
                fs::create_dir_all(&dir).unwrap();
                fs::write(dir.join("manifest"), &manifest).unwrap();
                fs::write(dir.join("bundle"), b"bundle").unwrap();
                for phase in ["run", "inspect"] {
                    fs::write(dir.join(format!("{phase}.stdout")), b"stdout").unwrap();
                    fs::write(dir.join(format!("{phase}.stderr")), b"stderr").unwrap();
                }
                let mut envelope =
                    serde_json::json!({"format": 1, "kind": "artifact", "record": artifact});
                let digest = Digest::of(&serde_json::to_vec(&envelope).unwrap());
                envelope["sha256"] = serde_json::to_value(digest).unwrap();
                fs::write(dir.join("artifact"), serde_json::to_vec(&envelope).unwrap()).unwrap();
            }
            if at == Step::Poll
                && quick.join("finished").exists()
                && !slow.join("finished").exists()
            {
                assert!(!finding.exists());
                saw_deferred.set(true);
            }
            if finding.exists() {
                assert!(slow.join("finished").exists());
            }
        })),
        ..Script::default()
    }));
    let mut custody = host.custody();
    let options = host.options();
    fs::write(
        &options.launcher,
        format!(
            "#!/bin/sh\ncase \"$*\" in *{}-0001*) exit 0;; esac\nsleep 30\n",
            jobs[0].job().id()
        ),
    )
    .unwrap();
    let started = Instant::now();
    let report = dispatch(&store, &mut custody, &options).unwrap();
    step::install(None);
    assert_eq!(report.started, 3);
    assert!(deferred.get());
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "watchdog waited for retention work"
    );
    assert!(
        report
            .completed
            .iter()
            .any(|finish| finish.class == crate::record::Class::Violation)
    );
    assert!(
        report
            .completed
            .iter()
            .any(|finish| finish.class == crate::record::Class::Watchdog)
    );
    assert_eq!(
        report.exit(),
        crate::exit::Supervisor::Success,
        "{report:?}"
    );
    assert!(fast_path.join("captured").exists());
    assert!(slow_path.join("captured").exists());
    let id = format!("{}-0001", jobs[0].job().id());
    assert!(
        host.case
            .state
            .join("findings")
            .join(&id)
            .join("finding.json")
            .exists()
    );
    assert_eq!(
        crate::campaign::findings(&host.case.state).unwrap()["release_blockers"],
        serde_json::json!([id])
    );
    let once = crate::store::fixture::snapshot(&host.case.state);
    let report = dispatch(&store, &mut custody, &options).unwrap();
    assert_eq!(report.started, 0);
    assert_eq!(crate::store::fixture::snapshot(&host.case.state), once);
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_slot_freed_without_a_finding_refills_while_a_sibling_runs() {
    let _processes = processes();
    let host = Host::new("refill");
    let store = Store::open(&host.case.state).unwrap();
    host.config(&store, &[]);
    host.capacity(&store, "upload", 2);
    let mut jobs: Vec<_> = (0..3)
        .map(|run| host.job(&store, run, "upload", Purpose::Campaign, 1))
        .collect();
    jobs.sort_by_key(|job| job.job().id().to_string());
    let third = attempt_path(&host, &jobs[2]);
    let options = host.options();
    fs::write(
        &options.launcher,
        format!(
            "#!/bin/sh\ncase \"$PWD\" in\n*{}*) while [ ! -d \"{}\" ]; do sleep 0.001; done ;;\nesac\nexit 0\n",
            jobs[1].job().id(),
            third.display()
        ),
    )
    .unwrap();
    let report = dispatch(&store, &mut host.custody(), &options).unwrap();
    assert!(report.refusals.is_empty(), "{report:?}");
    assert_eq!(report.started, 3);
    let slow = format!("{}-0001", jobs[1].job().id());
    let slow = report
        .completed
        .iter()
        .find(|row| row.attempt.as_str() == slow)
        .unwrap_or_else(|| panic!("{slow} has no completion row in {report:?}"));
    assert!(!slow.watchdog, "{slow:?}");
    assert_eq!(slow.exit, Some(0), "{slow:?}");
    for job in &jobs {
        assert!(attempt_path(&host, job).join("captured").exists());
    }
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn restart_drains_every_recorded_tree_before_capturing_a_finding() {
    let _processes = processes();
    let host = Host::new("capture-restart");
    let store = Store::open(&host.case.state).unwrap();
    host.config(&store, &[]);
    let mut jobs = [
        host.job(&store, 0, "upload", Purpose::Campaign, 1),
        host.job(&store, 1, "upload", Purpose::Campaign, 1),
    ];
    jobs.sort_by_key(|job| job.job().id().to_string());
    let mut custody = host.custody();
    let mut options = host.options();
    options.environment.insert("DELAY".into(), "30".into());
    let limits = crate::custody::Limits {
        cpu_quota_us: 100_000,
        memory_bytes: 1 << 30,
        pids: 64,
        file_bytes: 1 << 20,
        cpu_seconds: 60,
        output_bytes: 1 << 20,
        output_inodes: 100,
    };
    let mut live = Vec::new();
    for job in &jobs {
        let (attempt, running) = crate::attempt::start(
            &store,
            &mut custody,
            store
                .read_record::<Admission>(
                    &store.shard_jobs(job.job().id()).unwrap().unwrap(),
                    &name(&format!("{}.json", job.job().id())),
                )
                .unwrap()
                .unwrap(),
            crate::attempt::Launch {
                gate: options.gate.clone(),
                launcher: options.launcher.clone(),
                environment: options.environment.clone(),
                limits,
            },
        )
        .unwrap();
        live.push((attempt, running));
    }
    let path = attempt_path(&host, &jobs[0]);
    let job = crate::layout::attempts(&store, &jobs[0].job().id().to_string())
        .unwrap()
        .unwrap();
    let directory = store.open_dir(&job, &name("0001")).unwrap().unwrap();
    let record = store
        .read_record::<crate::record::Attempt>(&directory, &name("attempt"))
        .unwrap()
        .unwrap();
    let mut artifact =
        crate::attempt::tests::artifact(record.record().attempt.as_str(), record.record().manifest);
    artifact.archive = Digest::parse(jobs[0].job().experiment().pins.build.as_str());
    artifact.class = text("complete");
    artifact.summary.as_mut().unwrap().terminal = text("complete violation fired=03 required=03");
    let evidence = crate::attempt::tests::stage(&store, &directory, record.record(), &artifact);
    let manifest = fs::read(
        host.case
            .state
            .join(crate::campaign::state_fixture::job_file(format!(
                "{}.manifest",
                jobs[0].job().id()
            ))),
    )
    .unwrap();
    store
        .replace(&evidence, &name("manifest"), &manifest)
        .unwrap();
    let state = host.case.state.clone();
    let paths = [path, attempt_path(&host, &jobs[1])];
    let groups: Vec<_> = jobs
        .iter()
        .map(|job| host.root.join(format!("{}-0001", job.job().id())))
        .collect();
    let captured = std::rc::Rc::new(std::cell::Cell::new(false));
    let observed = captured.clone();
    step::install(Some(Script {
        observe: Some(Box::new(move |_| {
            if state.join("findings").exists() {
                observed.set(true);
                assert!(paths.iter().all(|path| path.join("finished").exists()));
                assert!(groups.iter().all(|group| !group.exists()));
            }
        })),
        ..Script::default()
    }));
    let report = dispatch(&store, &mut custody, &options).unwrap();
    step::install(None);
    assert_eq!(
        report.exit(),
        crate::exit::Supervisor::Success,
        "{report:?}"
    );
    assert_eq!(report.started, 0);
    assert_eq!(report.completed.len(), 2);
    assert!(captured.get());
    drop(live);
    let once = crate::store::fixture::snapshot(&host.case.state);
    let report = dispatch(&store, &mut custody, &options).unwrap();
    assert_eq!(report.started, 0);
    assert_eq!(crate::store::fixture::snapshot(&host.case.state), once);
    let broken = host.job(&store, 9, "upload", Purpose::Campaign, 1);
    fs::write(
        host.case
            .state
            .join(crate::campaign::state_fixture::job_file(format!(
                "{}.json",
                broken.job().id()
            ))),
        b"damaged tree-less job",
    )
    .unwrap();
    let id = format!("{}-0001", jobs[0].job().id());
    let result = crate::campaign::state_fixture::result_path(&host.case.state, jobs[0].job().id());
    fs::remove_dir_all(host.case.state.join("findings").join(&id)).unwrap();
    fs::remove_file(attempt_path(&host, &jobs[0]).join("captured")).unwrap();
    let settled = dispatch(&store, &mut custody, &options).unwrap();
    assert_eq!(settled.exit(), crate::exit::Supervisor::Held, "{settled:?}");
    assert_eq!(settled.started, 0, "{settled:?}");
    assert!(!attempt_path(&host, &jobs[0]).join("captured").exists());
    assert!(
        !host
            .case
            .state
            .join("findings")
            .join(&id)
            .join("finding.json")
            .exists()
    );
    assert!(result.exists());
    fs::remove_file(&result).unwrap();
    let report = dispatch(&store, &mut custody, &options).unwrap();
    assert_eq!(report.exit(), crate::exit::Supervisor::Held);
    assert_eq!(report.started, 0);
    assert!(result.exists());
    assert!(
        host.case
            .state
            .join("findings")
            .join(&id)
            .join("finding.json")
            .exists()
    );
    assert!(attempt_path(&host, &jobs[0]).join("captured").exists());
    let listed = crate::campaign::findings(&host.case.state).unwrap();
    assert!(
        listed["release_blockers"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!(id)),
        "{listed}"
    );
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn wait_error_keeps_an_exited_siblings_status_and_interrupts_only_the_running_one() {
    let _processes = processes();
    let host = Host::new("wait-error-exited");
    let store = Store::open(&host.case.state).unwrap();
    host.config(&store, &[]);
    host.capacity(&store, "upload", 2);
    let mut jobs: Vec<_> = (0..2)
        .map(|run| host.job(&store, run, "upload", Purpose::Campaign, 1))
        .collect();
    jobs.sort_by_key(|job| job.job().id().to_string());
    let exits = attempt_path(&host, &jobs[0]);
    let waits = attempt_path(&host, &jobs[1]);
    let release = host.case.root.join("release");
    let options = host.options();
    fs::write(
        &options.launcher,
        format!(
            "#!/bin/sh\ncase \"$PWD\" in\n*{}*) exit 0 ;;\nesac\nwhile [ ! -f \"{}\" ]; do sleep 0.001; done\nexit 0\n",
            jobs[0].job().id(),
            release.display()
        ),
    )
    .unwrap();
    step::install(Some(Script {
        nth: Some((Step::Killed, 0, Outcome::Errno(libc::EIO))),
        ..Script::default()
    }));
    let report = dispatch(&store, &mut host.custody(), &options).unwrap();
    let trace = step::install(None).unwrap();
    assert!(trace.reached.contains(&Step::Killed), "{:?}", trace.reached);
    assert_eq!(report.exit(), crate::exit::Supervisor::Held, "{report:?}");
    assert_eq!(report.started, 2);
    assert_eq!(report.completed.len(), 2, "{report:?}");
    let row = |job: &Admission| {
        let attempt = format!("{}-0001", job.job().id());
        report
            .completed
            .iter()
            .find(|row| row.attempt.as_str() == attempt)
            .unwrap_or_else(|| panic!("{attempt} has no completion row in {report:?}"))
    };
    let exited = row(&jobs[0]);
    assert_eq!(exited.exit, Some(0), "{exited:?}");
    assert_eq!(exited.interruption, None);
    assert!(!exited.residual_members);
    let interrupted = row(&jobs[1]);
    assert_eq!(interrupted.class, crate::record::Class::Interrupted);
    assert_eq!(interrupted.exit, None);
    assert!(!exits.join("reservation").exists());
    assert!(!waits.join("reservation").exists());
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn wait_error_keeps_the_watchdog_of_an_attempt_stopped_before_its_reap() {
    let _processes = processes();
    let host = Host::new("wait-error-watchdog");
    let store = Store::open(&host.case.state).unwrap();
    host.config(&store, &[("wall", 1)]);
    host.capacity(&store, "upload", 2);
    let mut jobs: Vec<_> = (0..2)
        .map(|run| host.job(&store, run, "upload", Purpose::Campaign, 1))
        .collect();
    jobs.sort_by_key(|job| job.job().id().to_string());
    let release = host.case.root.join("release");
    let mut options = host.options();
    options.deadline = Some(Instant::now() + Duration::from_secs(20));
    fs::write(
        &options.launcher,
        format!(
            "#!/bin/sh\ncase \"$PWD\" in\n*{}*) sleep 30 ;;\nesac\nwhile [ ! -f \"{}\" ]; do sleep 0.001; done\nexit 0\n",
            jobs[0].job().id(),
            release.display()
        ),
    )
    .unwrap();
    step::install(Some(Script {
        nth: Some((Step::Killed, 0, Outcome::Errno(libc::EIO))),
        ..Script::default()
    }));
    let report = dispatch(&store, &mut host.custody(), &options).unwrap();
    let trace = step::install(None).unwrap();
    assert!(trace.reached.contains(&Step::Killed), "{:?}", trace.reached);
    assert_eq!(report.exit(), crate::exit::Supervisor::Held, "{report:?}");
    assert_eq!(report.started, 2);
    assert_eq!(report.completed.len(), 2, "{report:?}");
    let row = |job: &Admission| {
        let attempt = format!("{}-0001", job.job().id());
        report
            .completed
            .iter()
            .find(|row| row.attempt.as_str() == attempt)
            .unwrap_or_else(|| panic!("{attempt} has no completion row in {report:?}"))
    };
    let expired = row(&jobs[0]);
    assert!(expired.watchdog, "{expired:?}");
    assert_eq!(expired.class, crate::record::Class::Watchdog);
    assert_eq!(expired.exit, None);
    assert_eq!(expired.interruption, None);
    let interrupted = row(&jobs[1]);
    assert_eq!(interrupted.class, crate::record::Class::Interrupted);
    assert!(!interrupted.watchdog);
}
