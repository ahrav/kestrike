use super::*;
use campaign_supervisor::attempt::{self, Attempt};
use campaign_supervisor::record::{
    Admission, Artifact, Class, Experiment, Job, Pins, Purpose, Summarized, Worker,
};
use campaign_supervisor::store::{View, create_dir};

fn admitted(store: &Store) -> Admission {
    admitted_as(store, Purpose::Campaign)
}

fn admitted_as(store: &Store, purpose: Purpose) -> Admission {
    let experiment = Experiment {
        target: None,
        calibration_scope: None,
        attempts: 3,
        campaign: text(if purpose == Purpose::Calibration {
            "calibration"
        } else {
            "campaign"
        }),
        capabilities: text("1"),
        class: None,
        counts: [(text("turns"), 7)].into(),
        format: 1,
        generator: None,
        manifest_version: text("1"),
        minima: None,
        pins: Pins {
            build: text(&"b".repeat(64)),
            executable: text(&"e".repeat(64)),
            platform: text("x86_64-linux"),
            toolchain: text("rustc"),
        },
        profile: text("upload"),
        run: 1,
    };
    let (job, manifest) = Job::derive(
        experiment,
        &[
            "version",
            "profile",
            "root",
            "executable",
            "toolchain",
            "build",
            "platform",
            "cpu",
            "scenario",
            "turns",
        ],
    )
    .unwrap();
    let admission = Admission::new(text("/archive"), job, purpose).unwrap();
    let jobs = crate::sharded::jobs(store, admission.job().id());
    store
        .create_record(
            &jobs,
            &name(&format!("{}.json", admission.job().id())),
            &admission,
        )
        .unwrap();
    store
        .create_once(
            &jobs,
            &name(&format!("{}.manifest", admission.job().id())),
            manifest.as_bytes(),
        )
        .unwrap();
    admission
}

fn verified(store: &Store, job: &Admission) -> campaign_supervisor::record::Verified<Admission> {
    let jobs = crate::sharded::jobs(store, job.job().id());
    store
        .read_record(&jobs, &name(&format!("{}.json", job.job().id())))
        .unwrap()
        .unwrap()
}

fn launch(case: &Case, mode: &str) -> attempt::Launch {
    attempt::Launch {
        gate: PathBuf::from(env!("CARGO_BIN_EXE_campaign")),
        launcher: std::env::current_exe().unwrap(),
        environment: [
            (
                "CAMPAIGN_ATTEMPT_LAUNCHER".into(),
                case.path.clone().into_os_string(),
            ),
            ("CAMPAIGN_ATTEMPT_MODE".into(), mode.into()),
        ]
        .into(),
        limits: Limits {
            cpu_quota_us: if mode == "cpu" { 1000 } else { 1_000_000 },
            memory_bytes: if mode.starts_with("oom") {
                64 << 20
            } else {
                1 << 30
            },
            pids: if mode == "pids" { 8 } else { 64 },
            file_bytes: 16 << 20,
            cpu_seconds: 300,
            output_bytes: u64::MAX,
            output_inodes: 4094,
        },
    }
}

fn directory(case: &Case, job: &Admission, number: u64) -> PathBuf {
    case.path
        .join("state")
        .join(crate::sharded::attempts_dir(job.job().id().to_string()))
        .join(format!("{number:04}"))
}

pub(super) fn numbered_outcomes_and_binding() {
    misbound_directory_and_inode_stop_proofs_keep_attempts_started_and_charged();
    stale_history_at_finish_and_recovery_keeps_the_original_reservation();
    finished_outcome_guards_and_foreign_stopped_proofs_hold();
    recovered_kernel_hits_keep_their_deltas_and_classes();
    finished_charged_recovery_keeps_missing_and_mismatched_witnesses_held();
    purpose_and_frozen_manifest_refusals_mint_nothing();
    invalid_execution_mints_and_charges_nothing();
    real_launcher_failure_artifacts();
    for (mode, expected) in [
        ("pass", Class::Pass),
        ("prewritten", Class::Disagreement),
        ("wrong-id", Class::MisboundEvidence),
        ("oom", Class::Oom),
        ("oom-misbound", Class::Oom),
        ("pids", Class::PidLimit),
        ("cpu", Class::Pass),
    ] {
        let case = Case::new("numbered");
        let store = case.store();
        let job = admitted(&store);
        let mut custody = case.custody();
        let (attempt, running) = attempt::start(
            &store,
            &mut custody,
            verified(&store, &job),
            launch(&case, mode),
        )
        .unwrap();
        assert_eq!(attempt.number(), 1);
        assert!(!directory(&case, &job, 1).join("finished").exists());
        let stopped = custody.wait_any(vec![running]).unwrap().stopped;
        assert!(
            case.path.join("numbered-started").exists(),
            "same-run Campaign-started witness"
        );
        assert!(Path::new(stopped.started().unwrap().record().cgroup.as_str()).exists());
        let completed = attempt
            .finish(&store, stopped, attempt::EVIDENCE_BOUND)
            .unwrap();
        assert_eq!(completed.finished().record().class, expected, "mode {mode}");
        let finished = completed.finished().record();
        assert_eq!(
            finished.binding,
            if mode == "wrong-id" || mode == "oom-misbound" {
                campaign_supervisor::record::Binding::Misbound
            } else {
                campaign_supervisor::record::Binding::Matching
            }
        );

        match expected {
            Class::Oom => assert!(finished.kernel.memory[&text("oom_kill")] > 0),
            Class::PidLimit => {
                assert!(finished.kernel.pids[&text("max")] > 0);
                assert_eq!(fs::read(case.path.join("pids-hit")).unwrap(), b"max");
            }

            _ => {}
        }
        if mode == "cpu" {
            assert!(finished.kernel.cpu[&text("nr_throttled")] > 0);
            assert_eq!(finished.class, Class::Pass);
        }
        assert!(!directory(&case, &job, 1).join("reservation").exists());
        assert!(!case.root.join(format!("{}-0001", job.job().id())).exists());
        let current = Attempt::current(&store, verified(&store, &job))
            .unwrap()
            .unwrap();
        assert_eq!(
            current
                .read_finished(&store)
                .unwrap()
                .finished()
                .record()
                .class,
            expected
        );
        if expected == Class::Pass {
            let artifact_path = directory(&case, &job, 1)
                .join("artifacts")
                .join(format!("{}-0001", job.job().id()));
            let artifact_store = Store::open(&artifact_path).unwrap();
            let artifact = artifact_store
                .read_record::<Artifact>(artifact_store.root(), &name("artifact"))
                .unwrap()
                .unwrap();
            let mut copied = artifact.record().clone();
            copied.run_id = text("another-run");
            artifact_store
                .replace_record(artifact_store.root(), &name("artifact"), &copied)
                .unwrap();
            assert!(
                matches!(
                    current.read_finished(&store),
                    Err(Error::Held("stored outcome differs from bound evidence"))
                ),
                "re-signed copied artifact holds stored pass"
            );
        }
        if mode == "prewritten" {
            assert_eq!(completed.finished().record().exit, Some(4));
            let (_, bound) = completed.into_parts();
            assert_eq!(bound.unwrap().artifact().class, text("counts"));
        }
    }
}

pub(super) fn held_history_and_overflow_with_started_campaign() {
    let case = Case::new("admission");
    let admission_output = admission_command(&case).output().unwrap();
    assert_eq!(
        admission_output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&admission_output.stderr)
    );
    let store = Store::open(&case.path.join("state")).unwrap();
    let shards = store
        .open_dir(store.root(), &name("jobs"))
        .unwrap()
        .unwrap();
    let shard = store.list(&shards, 16).unwrap().remove(0);
    let jobs = store.open_dir(&shards, &shard).unwrap().unwrap();
    let entry = store
        .list(&jobs, 16)
        .unwrap()
        .into_iter()
        .find(|name| name.as_str().ends_with(".json"))
        .unwrap();
    let job = store
        .read_record::<Admission>(&jobs, &entry)
        .unwrap()
        .unwrap()
        .record()
        .clone();
    let mut custody = case.custody();
    let (attempt, running) = attempt::start(
        &store,
        &mut custody,
        verified(&store, &job),
        launch(&case, "pass"),
    )
    .unwrap();
    let stopped = custody.wait_any(vec![running]).unwrap().stopped;
    assert!(case.path.join("numbered-started").exists());
    assert_eq!(
        attempt
            .finish(&store, stopped, attempt::EVIDENCE_BOUND)
            .unwrap()
            .finished()
            .record()
            .class,
        Class::Pass
    );
    let gap = directory(&case, &job, 3);
    fs::create_dir(&gap).unwrap();
    assert!(matches!(
        attempt::start(
            &store,
            &mut custody,
            verified(&store, &job),
            launch(&case, "pass")
        ),
        Err(Error::Held("attempt history has gaps or duplicates"))
    ));
    assert!(!directory(&case, &job, 2).exists());
    assert!(!gap.join("intent").exists());
    assert!(!gap.join("finished").exists());
    fs::remove_dir(gap).unwrap();
    fs::write(directory(&case, &job, 1).join("attempt"), b"{}").unwrap();
    assert!(matches!(
        Attempt::current(&store, verified(&store, &job)),
        Err(Error::Record(
            campaign_supervisor::record::Held::UnknownFormat
        ))
    ));
    assert!(matches!(
        attempt::start(
            &store,
            &mut custody,
            verified(&store, &job),
            launch(&case, "pass")
        ),
        Err(Error::Record(
            campaign_supervisor::record::Held::UnknownFormat
        ))
    ));
    assert!(!directory(&case, &job, 2).exists());
    let jobs = crate::sharded::jobs(&store, job.job().id());
    let job_name = name(&format!("{}.json", job.job().id()));
    fs::write(
        case.path
            .join("state")
            .join(crate::sharded::job_file(job_name.as_str())),
        b"{}",
    )
    .unwrap();
    assert!(matches!(
        store.read_record::<Admission>(&jobs, &job_name),
        Err(campaign_supervisor::record::Held::UnknownFormat)
    ));
    assert_eq!(
        store.create_record(&jobs, &job_name, &job).unwrap(),
        campaign_supervisor::store::Creation::Existing
    );
    assert_eq!(
        fs::read(
            case.path
                .join("state")
                .join(crate::sharded::job_file(job_name.as_str()))
        )
        .unwrap(),
        b"{}"
    );

    drop(custody);
    drop(store);
    let readmitted = admission_command(&case).output().unwrap();
    assert_eq!(readmitted.status.code(), Some(4));
    assert!(readmitted.stdout.is_empty());
    assert_eq!(
        fs::read(
            case.path
                .join("state")
                .join(crate::sharded::job_file(job_name.as_str()))
        )
        .unwrap(),
        b"{}"
    );
    assert!(!directory(&case, &job, 2).exists());
    drop(case);

    let case = Case::new("numbered");
    let store = case.store();
    let job = admitted(&store);
    let mut custody = case.custody();
    let (attempt, running) = attempt::start(
        &store,
        &mut custody,
        verified(&store, &job),
        launch(&case, "pass"),
    )
    .unwrap();
    let stopped = custody.wait_any(vec![running]).unwrap().stopped;
    assert!(case.path.join("numbered-started").exists());
    let path = directory(&case, &job, 1);
    assert!(matches!(
        attempt.finish(&store, stopped, 3),
        Err(Error::Store(campaign_supervisor::store::Error::ScanBound))
    ));
    assert!(matches!(
        store.create_once(store.root(), &name("later"), b"later"),
        Err(campaign_supervisor::store::Error::Poisoned)
    ));
    assert!(path.join("started").exists());
    let reservation: serde_json::Value =
        serde_json::from_slice(&fs::read(path.join("reservation")).unwrap()).unwrap();
    assert_eq!(reservation["kind"], "reservation");
    assert_eq!(
        reservation["record"]["attempt"],
        format!("{}-0001", job.job().id())
    );
    assert!(!path.join("finished").exists());
    assert!(case.root.join(format!("{}-0001", job.job().id())).exists());
}

pub(super) fn straggler_pass_is_fenced_by_stopped_membership() {
    let case = Case::new("numbered");
    let store = case.store();
    let job = admitted(&store);
    let mut custody = case.custody();
    let (attempt, running) = attempt::start(
        &store,
        &mut custody,
        verified(&store, &job),
        launch(&case, "straggler"),
    )
    .unwrap();
    let stopped = custody.wait_any(vec![running]).unwrap().stopped;
    assert!(
        case.path.join("straggler-ready").exists(),
        "descendant reached its delayed-write branch"
    );
    assert!(!case.path.join("straggler-wrote").exists());
    let result = attempt
        .finish(&store, stopped, attempt::EVIDENCE_BOUND)
        .unwrap();
    assert_eq!(result.finished().record().class, Class::Incomplete);
    assert_eq!(result.finished().record().exit, Some(0));
    assert!(result.finished().record().residual_members);
    assert!(!case.path.join("straggler-wrote").exists());
    let control = case.path.join("control");
    create_dir(&control).unwrap();
    let id = format!("{}-0001", job.job().id());
    let manifest = case
        .path
        .join("state")
        .join(crate::sharded::job_file(format!(
            "{}.manifest",
            job.job().id()
        )));
    let status = Command::new(std::env::current_exe().unwrap())
        .args(["sim", "run", "--manifest"])
        .arg(&manifest)
        .arg("--artifacts")
        .arg(&control)
        .args(["--run-id", &id])
        .env("CAMPAIGN_ATTEMPT_LAUNCHER", &case.path)
        .env("CAMPAIGN_ATTEMPT_MODE", "straggler-control")
        .status()
        .unwrap();
    assert!(status.success());
    let deadline = Instant::now() + Duration::from_secs(3);
    while !case.path.join("straggler-wrote").exists() {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(5));
    }
    let view = View::open(&control.join(&id)).unwrap();
    let artifact = view
        .read_record::<Artifact>(view.root(), &name("artifact"))
        .unwrap()
        .unwrap();
    assert_eq!(artifact.record().run_id.as_str(), id);
    assert_eq!(
        artifact.record().manifest,
        Some(job.job().manifest_sha256())
    );
    assert_eq!(artifact.record().bundle, Some(Digest::of(b"bundle")));
    assert_eq!(artifact.record().class.as_str(), "counts");
    assert!(
        !directory(&case, &job, 1)
            .join("artifacts")
            .join(&id)
            .join("artifact")
            .exists()
    );
}

pub(super) fn launcher(plan: &Path) -> std::process::ExitCode {
    let mode = std::env::var("CAMPAIGN_ATTEMPT_MODE").unwrap();
    if mode.starts_with("real-") {
        if std::env::args().any(|arg| arg == "--capabilities") {
            print!("{}", include_str!("../../testdata/admission-listing.txt"));
            return std::process::ExitCode::SUCCESS;
        }
        if mode == "real-abort" || mode == "real-unreadable" {
            let args: Vec<_> = std::env::args().collect();
            let bundle = &args[args.iter().position(|arg| arg == "--bundle").unwrap() + 1];
            if mode == "real-unreadable" {
                assert!(
                    Command::new("mkfifo")
                        .arg(bundle)
                        .status()
                        .unwrap()
                        .success()
                );
            } else {
                fs::write(bundle, b"partial-bundle").unwrap();
            }
            std::process::abort();
        }
        if mode == "real-panic" {
            println!("run: the run panicked at src/fake.rs:1:2: planned panic");
            return std::process::ExitCode::from(3);
        }
        return std::process::ExitCode::from(2);
    }
    let args: Vec<_> = std::env::args().collect();
    let value = |key| args.windows(2).find(|words| words[0] == key).unwrap()[1].clone();
    let id = value("--run-id");
    let manifest_path = PathBuf::from(value("--manifest"));
    let artifacts = PathBuf::from(value("--artifacts"));
    let mode = std::env::var("CAMPAIGN_ATTEMPT_MODE").unwrap();
    if !mode.ends_with("control") {
        let (job, number) = id.rsplit_once('-').unwrap();
        let state = View::open(&plan.join("state")).unwrap();
        let attempts = crate::sharded::open_shard(&state, "attempts", job);
        let job = state.open_dir(&attempts, &name(job)).unwrap().unwrap();
        let dir = state.open_dir(&job, &name(number)).unwrap().unwrap();
        let started = state
            .read_record::<Started>(&dir, &name("started"))
            .unwrap()
            .unwrap();
        assert_eq!(started.record().attempt.as_str(), id);
        assert_eq!(
            fs::read_to_string("/proc/self/cgroup")
                .unwrap()
                .trim()
                .strip_prefix("0::")
                .map(|path| format!("/sys/fs/cgroup{path}")),
            Some(started.record().cgroup.as_str().to_owned())
        );
        fs::write(plan.join("numbered-started"), &id).unwrap();
    }
    if mode.starts_with("straggler") {
        let mut child = Command::new("/usr/bin/setsid");
        child.arg("--fork").arg(std::env::current_exe().unwrap());
        child
            .args(&args[1..])
            .env_remove("CAMPAIGN_ATTEMPT_LAUNCHER")
            .env("CAMPAIGN_ATTEMPT_STRAGGLER", plan)
            .env("CAMPAIGN_ATTEMPT_PARENT", std::process::id().to_string());
        if mode.ends_with("control") {
            child.env("CAMPAIGN_ATTEMPT_MODE", "write-control");
        } else {
            child.env("CAMPAIGN_ATTEMPT_MODE", "write");
        }
        let child = child
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(child.success());
        let deadline = Instant::now() + Duration::from_secs(2);
        while !plan.join("straggler-ready").exists() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        return std::process::ExitCode::SUCCESS;
    }
    write_artifact(
        &artifacts,
        &id,
        &manifest_path,
        mode == "wrong-id" || mode == "oom-misbound",
    );
    if mode == "prewritten" {
        let artifact_store = Store::open(&artifacts.join(&id)).unwrap();
        let artifact = artifact_store
            .read_record::<Artifact>(artifact_store.root(), &name("artifact"))
            .unwrap()
            .unwrap();
        assert_eq!(
            artifact_store
                .create_record(artifact_store.root(), &name("artifact"), artifact.record())
                .unwrap(),
            campaign_supervisor::store::Creation::Existing
        );
        return std::process::ExitCode::from(4);
    }
    if mode == "copy" {
        let (job, number) = id.rsplit_once('-').unwrap();
        let prior = number.parse::<u64>().unwrap() - 1;
        let source = artifacts
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join(format!("{prior:04}"))
            .join("artifacts")
            .join(format!("{job}-{prior:04}"))
            .join("artifact");
        fs::copy(source, artifacts.join(&id).join("artifact")).unwrap();
    }
    match mode.as_str() {
        "oom" | "oom-misbound" => {
            let mut memory = vec![0u8; 256 << 20];
            for byte in memory.iter_mut().step_by(4096) {
                *byte = 1;
            }
            std::hint::black_box(memory);
        }
        "stall" => std::thread::sleep(Duration::from_secs(20)),
        "pids" => {
            let mut children = Vec::new();
            while let Ok(child) = Command::new("/bin/sleep").arg("20").spawn() {
                children.push(child);
            }
            assert!(!children.is_empty());
            fs::write(plan.join("pids-hit"), b"max").unwrap();
        }
        "cpu" => {
            let until = Instant::now() + Duration::from_millis(300);
            while Instant::now() < until {
                std::hint::black_box(7u64.wrapping_mul(17));
            }
        }
        _ => {}
    }
    std::process::ExitCode::SUCCESS
}

fn write_artifact(artifacts: &Path, id: &str, manifest_path: &Path, wrong_id: bool) {
    fs::create_dir_all(artifacts).unwrap();
    create_dir(&artifacts.join(id)).unwrap();
    let store = Store::open(&artifacts.join(id)).unwrap();
    let manifest = fs::read(manifest_path).unwrap();
    store
        .create_once(store.root(), &name("bundle"), b"bundle")
        .unwrap();
    store
        .create_once(store.root(), &name("manifest"), &manifest)
        .unwrap();
    let artifact = Artifact {
        archive: std::str::from_utf8(&manifest)
            .unwrap()
            .lines()
            .find_map(|line| line.strip_prefix("build = ").and_then(Digest::parse)),
        archive_path: None,
        bundle: Some(Digest::of(b"bundle")),
        class: text("counts"),
        command: text("run"),
        comparison: None,
        manifest: Some(Digest::of(&manifest)),
        output: None,
        reason: text("counts"),
        run_id: text(if wrong_id { "copied-run" } else { id }),
        session: None,
        session_original: None,
        summary: Some(Summarized {
            cause: None,
            counts: true,
            decisions: Some(1),
            digest: Digest::of(b"semantic"),
            first_failure: None,
            identity: None,
            ledger: None,
            terminal: text("complete pass fired=03 required=03"),
            unsuccessful: None,
        }),
        workers: ["run", "inspect"]
            .into_iter()
            .map(|phase| {
                (
                    text(phase),
                    Worker {
                        ended: text("exited"),
                        exit: Some(0),
                        signal: None,
                        stdout: Digest::of(b"stdout"),
                        stderr: Digest::of(b"stderr"),
                    },
                )
            })
            .collect(),
    };
    for phase in ["run", "inspect"] {
        store
            .create_once(store.root(), &name(&format!("{phase}.stdout")), b"stdout")
            .unwrap();
        store
            .create_once(store.root(), &name(&format!("{phase}.stderr")), b"stderr")
            .unwrap();
    }
    store
        .create_record(store.root(), &name("artifact"), &artifact)
        .unwrap();
}

pub(super) fn straggler(plan: &Path) -> std::process::ExitCode {
    fs::write(plan.join("straggler-ready"), b"ready").unwrap();
    let args: Vec<_> = std::env::args().collect();
    let value = |key| args.windows(2).find(|words| words[0] == key).unwrap()[1].clone();
    if std::env::var("CAMPAIGN_ATTEMPT_MODE").unwrap() == "write" {
        loop {
            std::thread::sleep(Duration::from_secs(60));
        }
    }
    let parent = std::env::var("CAMPAIGN_ATTEMPT_PARENT").unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Path::new("/proc").join(&parent).exists() {
        assert!(
            Instant::now() < deadline,
            "parent reaped before artifact write"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(
        !Path::new("/proc").join(&parent).exists(),
        "parent exit precedes delayed passing artifact"
    );
    write_artifact(
        Path::new(&value("--artifacts")),
        &value("--run-id"),
        Path::new(&value("--manifest")),
        false,
    );
    fs::write(plan.join("straggler-wrote"), b"after-parent-exit").unwrap();
    std::process::ExitCode::SUCCESS
}

pub(super) fn numbered_retry_limits_and_finished_reconciliation() {
    let case = Case::new("numbered");
    let store = case.store();
    let job = admitted(&store);
    let mut custody = case.custody();
    for number in 1..=3 {
        let (attempt, running) = attempt::start(
            &store,
            &mut custody,
            verified(&store, &job),
            launch(&case, if number == 2 { "copy" } else { "pass" }),
        )
        .unwrap();
        assert_eq!(attempt.number(), number);
        assert_eq!(
            running.started().record().attempt.as_str(),
            format!("{}-{number:04}", job.job().id())
        );
        let stopped = custody.wait_any(vec![running]).unwrap().stopped;
        let path = directory(&case, &job, number);
        if number == 1 {
            let artifact_path = path
                .join("artifacts")
                .join(format!("{}-0001", job.job().id()));
            let artifact_store = Store::open(&artifact_path).unwrap();
            let original = artifact_store
                .read_record::<Artifact>(artifact_store.root(), &name("artifact"))
                .unwrap()
                .unwrap();
            let mut retryable = original.record().clone();
            retryable.summary.as_mut().unwrap().counts = false;
            artifact_store
                .replace_record(artifact_store.root(), &name("artifact"), &retryable)
                .unwrap();
            drop(artifact_store);
            let group = case.root.join(format!("{}-0001", job.job().id()));
            fs::create_dir(group.join("nested")).unwrap();
            assert!(
                matches!(attempt.finish(&store, stopped, attempt::EVIDENCE_BOUND), Err(Error::Io(error)) if error.raw_os_error() == Some(libc::EBUSY))
            );
            let finished = fs::read(path.join("finished")).unwrap();
            assert!(path.join("reservation").exists());
            assert!(group.exists());
            assert!(matches!(
                Attempt::current(&store, verified(&store, &job))
                    .unwrap()
                    .unwrap()
                    .read_finished(&store),
                Err(Error::Held("finished tree remains present"))
            ));
            fs::remove_dir(group.join("nested")).unwrap();
            let artifact_path = path
                .join("artifacts")
                .join(format!("{}-0001", job.job().id()));
            let artifact_store = Store::open(&artifact_path).unwrap();
            let original = artifact_store
                .read_record::<Artifact>(artifact_store.root(), &name("artifact"))
                .unwrap()
                .unwrap();
            let mut changed = original.record().clone();
            changed.run_id = text("another-run");
            artifact_store
                .replace_record(artifact_store.root(), &name("artifact"), &changed)
                .unwrap();
            assert!(matches!(
                Attempt::current(&store, verified(&store, &job))
                    .unwrap()
                    .unwrap()
                    .reconcile(&store, &mut custody, attempt::EVIDENCE_BOUND),
                Err(Error::Held("stored outcome differs from bound evidence"))
            ));
            assert!(path.join("reservation").exists());
            assert!(group.exists());
            assert_eq!(fs::read(path.join("finished")).unwrap(), finished);
            artifact_store
                .replace_record(artifact_store.root(), &name("artifact"), original.record())
                .unwrap();
            drop(artifact_store);
            fs::remove_dir(&group).unwrap();
            assert!(matches!(
                Attempt::current(&store, verified(&store, &job))
                    .unwrap()
                    .unwrap()
                    .read_finished(&store),
                Err(Error::Held("finished attempt remains charged"))
            ));
            assert!(matches!(
                attempt::start(
                    &store,
                    &mut custody,
                    verified(&store, &job),
                    launch(&case, "pass")
                ),
                Err(Error::Held("finished attempt remains charged"))
            ));
            assert!(!directory(&case, &job, 2).exists());
            let completed = Attempt::current(&store, verified(&store, &job))
                .unwrap()
                .unwrap()
                .reconcile(&store, &mut custody, attempt::EVIDENCE_BOUND)
                .unwrap();
            assert_eq!(completed.finished().record().class, Class::Incomplete);
            assert_eq!(fs::read(path.join("finished")).unwrap(), finished);
        } else {
            let completed = attempt
                .finish(&store, stopped, attempt::EVIDENCE_BOUND)
                .unwrap();
            assert_eq!(
                completed.finished().record().class,
                if number == 2 {
                    Class::MisboundEvidence
                } else {
                    Class::Pass
                }
            );
        }
        assert!(!path.join("reservation").exists());
    }
    assert!(matches!(
        attempt::start(
            &store,
            &mut custody,
            verified(&store, &job),
            launch(&case, "pass")
        ),
        Err(Error::Rejected("frozen attempt limit exhausted"))
    ));
    assert!(!directory(&case, &job, 4).exists());
    fs::remove_dir_all(directory(&case, &job, 1)).unwrap();
    assert!(matches!(
        Attempt::current(&store, verified(&store, &job)),
        Err(Error::Held("attempt history has gaps or duplicates"))
    ));
    assert!(matches!(
        attempt::start(
            &store,
            &mut custody,
            verified(&store, &job),
            launch(&case, "pass")
        ),
        Err(Error::Held("attempt history has gaps or duplicates"))
    ));
    assert!(!directory(&case, &job, 4).exists());
}

pub(super) fn started_attempt_reconciles_membership_after_owner_drop() {
    let case = Case::new("numbered");
    let store = case.store();
    let job = admitted(&store);
    let mut custody = case.custody();
    let (attempt, running) = attempt::start(
        &store,
        &mut custody,
        verified(&store, &job),
        launch(&case, "stall"),
    )
    .unwrap();
    let path = directory(&case, &job, 1);
    let id = format!("{}-0001", job.job().id());
    let deadline = Instant::now() + Duration::from_secs(5);
    while !path.join("artifacts").join(&id).join("artifact").exists() {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(1));
    }
    drop(attempt);
    drop(running);
    drop(custody);
    drop(store);
    assert!(
        fs::read_to_string(case.root.join(&id).join("cgroup.events"))
            .unwrap()
            .contains("populated 1")
    );
    let store = Store::open(&case.path.join("state")).unwrap();
    let mut custody = case.custody();
    let completed = Attempt::current(&store, verified(&store, &job))
        .unwrap()
        .unwrap()
        .reconcile(&store, &mut custody, attempt::EVIDENCE_BOUND)
        .unwrap();
    assert_eq!(completed.finished().record().class, Class::Interrupted);
    assert_eq!(completed.finished().record().exit, None);
    assert_eq!(
        completed.finished().record().binding,
        campaign_supervisor::record::Binding::Matching
    );
    assert!(!case.root.join(&id).exists());
    assert!(!path.join("reservation").exists());
    assert_eq!(
        Attempt::current(&store, verified(&store, &job))
            .unwrap()
            .unwrap()
            .read_finished(&store)
            .unwrap()
            .finished()
            .record()
            .class,
        Class::Interrupted
    );
}

fn real_launcher_failure_artifacts() {
    for (mode, expected) in [
        ("real-panic", Some(Class::EngineFailure)),
        ("real-refuse", Some(Class::Rejected)),
        ("real-abort", Some(Class::EngineFailure)),
        ("real-unreadable", None),
    ] {
        let case = Case::new("real-attempt");
        let store = case.store();
        let mut archive = Archive::load(super::archive()).unwrap();
        let _ = archive.verify().unwrap();
        let listing = campaign_supervisor::protocol::Listing::parse(include_str!(
            "../../testdata/admission-listing.txt"
        ))
        .unwrap();
        let keys: Vec<_> = listing.keys.iter().map(|key| key.name.as_str()).collect();
        let mut counts: BTreeMap<Text, u64> = listing
            .keys
            .iter()
            .filter_map(|key| match key.form {
                campaign_supervisor::protocol::Form::Count { min, .. } if key.name != "root" => {
                    Some((text(&key.name), min.max(1)))
                }
                _ => None,
            })
            .collect();
        counts.insert(text("records"), 1024);
        counts.insert(text("bytes"), 49_152);
        let (job, manifest) = Job::derive(
            Experiment {
                target: None,
                calibration_scope: None,
                attempts: 1,
                campaign: text("real"),
                capabilities: text("1"),
                class: None,
                counts,
                format: 1,
                generator: None,
                manifest_version: text("2"),
                minima: None,
                pins: archive.pins(),
                profile: text("upload"),
                run: 0,
            },
            &keys,
        )
        .unwrap();
        let job = Admission::new(
            text(super::archive().to_str().unwrap()),
            job,
            Purpose::Campaign,
        )
        .unwrap();
        let jobs = crate::sharded::jobs(&store, job.job().id());
        store
            .create_record(&jobs, &name(&format!("{}.json", job.job().id())), &job)
            .unwrap();
        store
            .create_once(
                &jobs,
                &name(&format!("{}.manifest", job.job().id())),
                manifest.as_bytes(),
            )
            .unwrap();
        let mut custody = case.custody();
        let mut launcher = launch(&case, mode);
        launcher.launcher = PathBuf::from(env!("CARGO_BIN_EXE_campaign"));
        let (attempt, running) =
            attempt::start(&store, &mut custody, verified(&store, &job), launcher).unwrap();
        let stopped = custody.wait_any(vec![running]).unwrap().stopped;
        if mode == "real-unreadable" {
            let path = directory(&case, &job, 1);
            let artifact_dir = path
                .join("artifacts")
                .join(format!("{}-0001", job.job().id()));
            let view = View::open(&artifact_dir).unwrap();
            let artifact = view
                .read_record::<Artifact>(view.root(), &name("artifact"))
                .unwrap()
                .unwrap();
            assert_eq!(artifact.record().class, text("incomplete"));
            assert_eq!(artifact.record().bundle, None);
            assert_eq!(
                artifact.record().workers[&text("run")].signal,
                Some(libc::SIGABRT as u64)
            );
            assert!(matches!(
                attempt.finish(&store, stopped, attempt::EVIDENCE_BOUND),
                Err(Error::Store(campaign_supervisor::store::Error::Unreadable(
                    campaign_supervisor::store::Unreadable::NotRegular
                )))
            ));
            assert!(path.join("started").exists());
            assert!(path.join("reservation").exists());
            assert!(!path.join("finished").exists());
            continue;
        }
        let expected = expected.unwrap();
        let completed = attempt
            .finish(&store, stopped, attempt::EVIDENCE_BOUND)
            .unwrap();
        assert_eq!(completed.finished().record().class, expected, "{mode}");
        assert_eq!(
            completed.finished().record().binding,
            campaign_supervisor::record::Binding::Matching
        );
        let expected_finish = completed.finished().record().clone();
        let (finished, bound) = completed.into_parts();
        assert_eq!(finished.record(), &expected_finish);
        let bound = bound.unwrap();
        let bundle = (mode == "real-abort").then(|| Digest::of(b"partial-bundle"));
        assert_eq!(bound.artifact().bundle, bundle);
        assert_eq!(bound.binding().bundle, bundle);
        if mode == "real-abort" {
            assert_eq!(
                bound.artifact().workers[&text("run")].signal,
                Some(libc::SIGABRT as u64)
            );
        }
        assert_eq!(bound.artifact().run_id, bound.binding().attempt);
        let current = Attempt::current(&store, verified(&store, &job))
            .unwrap()
            .unwrap();
        assert_eq!(
            current
                .read_finished(&store)
                .unwrap()
                .finished()
                .record()
                .class,
            expected
        );
    }
}

fn invalid_execution_mints_and_charges_nothing() {
    for field in [
        "gate",
        "launcher",
        "missing-launcher",
        "environment",
        "cpu",
        "memory",
        "pids",
        "file",
    ] {
        let case = Case::new("invalid-attempt");
        let store = case.store();
        let job = admitted(&store);
        let mut custody = case.custody();
        let mut execution = launch(&case, "pass");
        match field {
            "gate" => execution.gate = case.path.join("missing-gate"),
            "launcher" => execution.launcher = PathBuf::new(),
            "missing-launcher" => execution.launcher = case.path.join("missing-launcher"),
            "environment" => {
                execution
                    .environment
                    .insert("bad=key".into(), "value".into());
            }
            "cpu" => execution.limits.cpu_quota_us = 0,
            "memory" => execution.limits.memory_bytes = 0,
            "pids" => execution.limits.pids = 0,
            "file" => execution.limits.file_bytes = 0,
            _ => unreachable!(),
        }
        let reason = match field {
            "gate" => "invalid custody launch paths",
            "launcher" | "environment" => "invalid custody command",
            "missing-launcher" => "invalid attempt launcher",
            _ => "invalid custody limits",
        };
        assert!(
            matches!(
                attempt::start(&store, &mut custody, verified(&store, &job), execution),
                Err(Error::Rejected(found)) if found == reason
            ),
            "{field}"
        );
        assert!(!case.path.join("state/attempts").exists(), "{field}");
        assert!(
            !case.root.join(format!("{}-0001", job.job().id())).exists(),
            "{field}"
        );
        assert!(
            Attempt::current(&store, verified(&store, &job))
                .unwrap()
                .is_none()
        );
    }
}

fn finished_charged_recovery_keeps_missing_and_mismatched_witnesses_held() {
    for field in ["missing", "attempt", "boot", "cgroup"] {
        let case = Case::new("charged-finished");
        let store = case.store();
        let job = admitted(&store);
        let mut custody = case.custody();
        let (active, running) = attempt::start(
            &store,
            &mut custody,
            verified(&store, &job),
            launch(&case, "pass"),
        )
        .unwrap();
        let root = crate::sharded::attempts(&store, job.job().id());
        let root = store
            .open_dir(&root, &name(&job.job().id().to_string()))
            .unwrap()
            .unwrap();
        let dir = store.open_dir(&root, &name("0001")).unwrap().unwrap();
        let charge = store
            .read(
                &dir,
                &name("reservation"),
                campaign_supervisor::record::BOUND,
            )
            .unwrap()
            .unwrap()
            .bytes()
            .to_vec();
        let stopped = custody.wait_any(vec![running]).unwrap().stopped;
        let completed = active
            .finish(&store, stopped, attempt::EVIDENCE_BOUND)
            .unwrap();
        assert_eq!(completed.finished().record().class, Class::Pass);
        store
            .create_once(&dir, &name("reservation"), &charge)
            .unwrap();
        let witness = store
            .read_record::<Started>(&dir, &name("started"))
            .unwrap()
            .unwrap();
        let mut witness = witness.record().clone();
        match field {
            "missing" => {
                store.delete(&dir, &name("started")).unwrap();
            }
            "attempt" => {
                witness.attempt = text("another-attempt");
                store
                    .replace_record(&dir, &name("started"), &witness)
                    .unwrap();
            }
            "boot" => {
                witness.boot = text("another-boot");
                store
                    .replace_record(&dir, &name("started"), &witness)
                    .unwrap();
            }
            "cgroup" => {
                witness.cgroup = text("/sys/fs/cgroup/another-group");
                store
                    .replace_record(&dir, &name("started"), &witness)
                    .unwrap();
            }
            _ => unreachable!(),
        }
        let prior = fs::read(directory(&case, &job, 1).join("finished")).unwrap();
        let active = Attempt::current(&store, verified(&store, &job))
            .unwrap()
            .unwrap();
        let expected = if field == "missing" {
            "pass lacks started witness"
        } else {
            "started differs from intent"
        };
        assert!(
            matches!(active.reconcile(&store, &mut custody, attempt::EVIDENCE_BOUND), Err(Error::Held(found)) if found == expected),
            "{field}"
        );
        assert_eq!(
            fs::read(directory(&case, &job, 1).join("reservation")).unwrap(),
            charge
        );
        assert_eq!(
            fs::read(directory(&case, &job, 1).join("finished")).unwrap(),
            prior
        );
    }
}

fn recovered_kernel_hits_keep_their_deltas_and_classes() {
    for (mode, class) in [
        ("oom", Class::Oom),
        ("pids", Class::PidLimit),
        ("cpu", Class::Interrupted),
    ] {
        let case = Case::new("recovered-limit");
        let store = case.store();
        let job = admitted(&store);
        let mut custody = case.custody();
        let (active, running) = attempt::start(
            &store,
            &mut custody,
            verified(&store, &job),
            launch(&case, mode),
        )
        .unwrap();
        let stopped = custody.wait_any(vec![running]).unwrap().stopped;
        let deltas = stopped.kernel().unwrap();
        drop(stopped);
        let completed = active
            .reconcile(&store, &mut custody, attempt::EVIDENCE_BOUND)
            .unwrap();
        assert_eq!(completed.finished().record().class, class, "{mode}");
        let observed = &completed.finished().record().kernel;
        for (prior, observed) in [
            (&deltas.cpu, &observed.cpu),
            (&deltas.memory, &observed.memory),
            (&deltas.pids, &observed.pids),
        ] {
            assert_eq!(
                prior.keys().collect::<Vec<_>>(),
                observed.keys().collect::<Vec<_>>(),
                "{mode}"
            );
            for (key, value) in prior {
                assert!(observed[key] >= *value, "{mode}: {key:?}");
            }
        }
        let active = Attempt::current(&store, verified(&store, &job))
            .unwrap()
            .unwrap();
        assert_eq!(
            active
                .read_finished(&store)
                .unwrap()
                .finished()
                .record()
                .class,
            class
        );
    }
}

fn finished_outcome_guards_and_foreign_stopped_proofs_hold() {
    for field in [
        "attempt",
        "binding",
        "bound",
        "class",
        "residual",
        "stored-bound",
    ] {
        let case = Case::new("finished-guard");
        let store = case.store();
        let job = admitted(&store);
        let mut custody = case.custody();
        let (active, running) = attempt::start(
            &store,
            &mut custody,
            verified(&store, &job),
            launch(&case, "pass"),
        )
        .unwrap();
        let stopped = custody.wait_any(vec![running]).unwrap().stopped;
        let completed = active
            .finish(&store, stopped, attempt::EVIDENCE_BOUND)
            .unwrap();
        assert_eq!(completed.finished().record().class, Class::Pass);
        let mut record = completed.finished().record().clone();
        let root = crate::sharded::attempts(&store, job.job().id());
        let root = store
            .open_dir(&root, &name(&job.job().id().to_string()))
            .unwrap()
            .unwrap();
        let dir = store.open_dir(&root, &name("0001")).unwrap().unwrap();
        match field {
            "attempt" => record.attempt = text("foreign-attempt"),
            "binding" => record.binding = campaign_supervisor::record::Binding::Missing,
            "bound" => record.bound.as_mut().unwrap().artifact = Digest::of(b"wrong"),
            "class" => record.class = Class::Oom,
            "residual" => record.residual_members = true,
            "stored-bound" => {
                let mut bound = record.bound.as_ref().unwrap().clone();
                bound.artifact = Digest::of(b"wrong");
                store.replace_record(&dir, &name("bound"), &bound).unwrap();
            }
            _ => unreachable!(),
        }
        store
            .replace_record(&dir, &name("finished"), &record)
            .unwrap();
        let active = Attempt::current(&store, verified(&store, &job))
            .unwrap()
            .unwrap();
        let expected = match field {
            "attempt" => "finished names another attempt",
            "stored-bound" => "stored binding differs",
            _ => "stored outcome differs from bound evidence",
        };
        assert!(
            matches!(active.read_finished(&store), Err(Error::Held(reason)) if reason == expected),
            "{field}"
        );
        assert!(!directory(&case, &job, 1).join("reservation").exists());
    }
    let first = Case::new("foreign-stopped-first");
    let first_store = first.store();
    let first_job = admitted(&first_store);
    let mut first_custody = first.custody();
    let (active, running) = attempt::start(
        &first_store,
        &mut first_custody,
        verified(&first_store, &first_job),
        launch(&first, "pass"),
    )
    .unwrap();
    let first_stopped = first_custody.wait_any(vec![running]).unwrap().stopped;
    drop(first_custody);
    let second = Case::new("foreign-stopped-second");
    let second_store = second.store();
    let second_job = admitted(&second_store);
    let mut second_custody = second.custody();
    let (_, running) = attempt::start(
        &second_store,
        &mut second_custody,
        verified(&second_store, &second_job),
        launch(&second, "pass"),
    )
    .unwrap();
    let foreign = second_custody.wait_any(vec![running]).unwrap().stopped;
    assert_eq!(first_stopped.identity(), foreign.identity());
    assert!(matches!(
        active.finish(&first_store, foreign, attempt::EVIDENCE_BOUND),
        Err(Error::Held("started record differs from stopped proof"))
    ));
    assert!(
        directory(&first, &first_job, 1)
            .join("reservation")
            .exists()
    );
    assert!(
        directory(&second, &second_job, 1)
            .join("reservation")
            .exists()
    );
    let active = Attempt::current(&first_store, verified(&first_store, &first_job))
        .unwrap()
        .unwrap();
    active
        .finish(&first_store, first_stopped, attempt::EVIDENCE_BOUND)
        .unwrap();
    let active = Attempt::current(&second_store, verified(&second_store, &second_job))
        .unwrap()
        .unwrap();
    active
        .reconcile(&second_store, &mut second_custody, attempt::EVIDENCE_BOUND)
        .unwrap();
}

fn purpose_and_frozen_manifest_refusals_mint_nothing() {
    let case = Case::new("calibration-start");
    let store = case.store();
    let job = admitted_as(&store, Purpose::Calibration);
    let mut custody = case.custody();
    assert!(matches!(
        attempt::start(
            &store,
            &mut custody,
            verified(&store, &job),
            launch(&case, "pass")
        ),
        Err(Error::Rejected(
            "only campaign jobs start numbered attempts"
        ))
    ));
    assert!(!case.path.join("state/attempts").exists());
    drop(custody);
    for (control, expected) in [
        ("missing", "frozen manifest vanished"),
        ("changed", "frozen manifest digest differs"),
        ("oversize", "frozen manifest unreadable"),
    ] {
        let case = Case::new("manifest-start");
        let store = case.store();
        let job = admitted(&store);
        let jobs = crate::sharded::jobs(&store, job.job().id());
        let manifest = name(&format!("{}.manifest", job.job().id()));
        match control {
            "missing" => {
                store.delete(&jobs, &manifest).unwrap();
            }
            "changed" => {
                store.replace(&jobs, &manifest, b"changed").unwrap();
            }
            "oversize" => {
                store
                    .replace(
                        &jobs,
                        &manifest,
                        &vec![b'x'; campaign_supervisor::record::BOUND as usize + 1],
                    )
                    .unwrap();
            }
            _ => unreachable!(),
        }
        let mut custody = case.custody();
        assert!(
            matches!(attempt::start(&store, &mut custody, verified(&store, &job), launch(&case, "pass")), Err(Error::Held(reason)) if reason == expected),
            "{control}"
        );
        assert!(!case.path.join("state/attempts").exists());
        assert!(!case.root.join(format!("{}-0001", job.job().id())).exists());
    }
}

fn stale_history_at_finish_and_recovery_keeps_the_original_reservation() {
    for recovery in [false, true] {
        let case = Case::new("stale-finish");
        let store = case.store();
        let job = admitted(&store);
        let mut custody = case.custody();
        let (active, running) = attempt::start(
            &store,
            &mut custody,
            verified(&store, &job),
            launch(&case, "pass"),
        )
        .unwrap();
        let stopped = custody.wait_any(vec![running]).unwrap().stopped;
        let next = directory(&case, &job, 2);
        fs::create_dir(&next).unwrap();
        let outcome = if recovery {
            drop(stopped);
            active.reconcile(&store, &mut custody, attempt::EVIDENCE_BOUND)
        } else {
            active.finish(&store, stopped, attempt::EVIDENCE_BOUND)
        };
        assert!(matches!(
            outcome,
            Err(Error::Held("attempt is not the current publish token"))
        ));
        let current = directory(&case, &job, 1);
        assert!(current.join("reservation").exists());
        assert!(!current.join("finished").exists());
        assert!(!next.join("intent").exists());
        fs::remove_dir(next).unwrap();
        Attempt::current(&store, verified(&store, &job))
            .unwrap()
            .unwrap()
            .reconcile(&store, &mut custody, attempt::EVIDENCE_BOUND)
            .unwrap();
    }
}

fn misbound_directory_and_inode_stop_proofs_keep_attempts_started_and_charged() {
    for control in [
        "directory",
        "reconcile-directory",
        "inode",
        "baseline",
        "missing-intent",
        "intent",
    ] {
        let case = Case::new("misbound-stop");
        let store = case.store();
        let job = admitted(&store);
        let mut custody = case.custody();
        let (_, running) = attempt::start(
            &store,
            &mut custody,
            verified(&store, &job),
            launch(&case, "pass"),
        )
        .unwrap();
        let stopped = custody.wait_any(vec![running]).unwrap().stopped;
        let root = crate::sharded::attempts(&store, job.job().id());
        let root = store
            .open_dir(&root, &name(&job.job().id().to_string()))
            .unwrap()
            .unwrap();
        let actual = store.open_dir(&root, &name("0001")).unwrap().unwrap();
        let intent = store
            .read_record::<Intent>(&actual, &name("intent"))
            .unwrap()
            .unwrap();
        let started = store
            .read_record::<Started>(&actual, &name("started"))
            .unwrap()
            .unwrap();
        let original = started.record().clone();
        if matches!(control, "directory" | "reconcile-directory") {
            store
                .mkdir(store.root(), &name("replayed-directory"))
                .unwrap();
            let replay = store
                .open_dir(store.root(), &name("replayed-directory"))
                .unwrap()
                .unwrap();
            store
                .create_record(&replay, &name("intent"), intent.record())
                .unwrap();
            store
                .create_record(&replay, &name("started"), started.record())
                .unwrap();
            let reservation = store
                .read(
                    &actual,
                    &name("reservation"),
                    campaign_supervisor::record::BOUND,
                )
                .unwrap()
                .unwrap();
            store
                .create_once(&replay, &name("reservation"), reservation.bytes())
                .unwrap();
            if control == "directory" {
                assert!(matches!(
                    stopped.evidence(&store, &replay, attempt::EVIDENCE_BOUND),
                    Err(Error::Held("misbound stop proof: directory"))
                ));
            } else {
                let replayed = store
                    .read_record::<Started>(&replay, &name("started"))
                    .unwrap()
                    .unwrap();
                assert!(matches!(
                    custody.reconcile(&store, &intent, Some(&replayed)),
                    Err(Error::Held("misbound stop proof: directory"))
                ));
                drop(stopped);
            }
            assert!(!case.path.join("state/replayed-directory/finished").exists());
            assert!(case.path.join("state/replayed-directory/started").exists());
            assert!(
                case.path
                    .join("state/replayed-directory/reservation")
                    .exists()
            );
        } else if matches!(control, "missing-intent" | "intent") {
            let reason = if control == "missing-intent" {
                store.delete(&actual, &name("intent")).unwrap();
                "evidence lacks intent"
            } else {
                let mut changed = intent.record().clone();
                changed.boot = text("other-boot");
                store
                    .replace_record(&actual, &name("intent"), &changed)
                    .unwrap();
                "misbound stop proof: intent"
            };
            assert!(
                matches!(stopped.evidence(&store, &actual, attempt::EVIDENCE_BOUND), Err(Error::Held(found)) if found == reason)
            );
            store
                .replace_record(&actual, &name("intent"), intent.record())
                .unwrap();
        } else {
            let mut changed = original.clone();
            if control == "inode" {
                changed.cgroup_inode = changed.cgroup_inode.checked_add(1).unwrap();
            } else {
                changed.baseline.cpu.insert(text("proof-counter"), 1);
            }
            store
                .replace_record(&actual, &name("started"), &changed)
                .unwrap();
            assert!(matches!(
                stopped.evidence(&store, &actual, attempt::EVIDENCE_BOUND),
                Err(Error::Held("misbound stop proof: started"))
            ));
            store
                .replace_record(&actual, &name("started"), &original)
                .unwrap();
        }
        let path = directory(&case, &job, 1);
        assert!(path.join("started").exists());
        assert!(path.join("reservation").exists());
        assert!(!path.join("finished").exists());
        assert!(case.root.join(format!("{}-0001", job.job().id())).exists());
        Attempt::current(&store, verified(&store, &job))
            .unwrap()
            .unwrap()
            .reconcile(&store, &mut custody, attempt::EVIDENCE_BOUND)
            .unwrap();
    }
}
