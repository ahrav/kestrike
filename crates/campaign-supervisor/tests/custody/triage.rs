use super::sim_worker::{COUNTING, PLAN};
use campaign_supervisor::archive::{Built, publish};
use campaign_supervisor::record::{Configuration, Native, Provenance, Text};
use campaign_supervisor::store::{Name, Store, View, open_host};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};

fn text(value: &str) -> Text {
    Text::new(value).unwrap()
}
fn name(value: &str) -> Name {
    Name::new(value).unwrap()
}

struct Triage {
    path: PathBuf,
    state: PathBuf,
    root: PathBuf,
    archive: PathBuf,
    id: String,
}
impl Triage {
    fn new(label: &str) -> Self {
        let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("triage-{label}-{}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        let root = PathBuf::from(std::env::var_os("CAMPAIGN_CGROUP_ROOT").unwrap())
            .join(format!("triage-{label}-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let executable = std::env::current_exe().unwrap();
        let digest = campaign_supervisor::record::Digest::of(b"test");
        let built = Built {
            identity: open_host(&executable).unwrap().identity(),
            executable,
            lock: b"version = 4\n".to_vec(),
            provenance: Provenance {
                cargo: text("cargo"),
                command: text("test"),
                dirty: false,
                environment: BTreeMap::new(),
                native: Native {
                    install_record: text("native"),
                    install_record_sha256: digest,
                    link_plan_sha256: digest,
                    package: text("worker"),
                },
                revision: text(&"0".repeat(40)),
                target: text("x86_64-unknown-linux-gnu"),
                toolchain: text("rustc 1.0.0 (fake)"),
                untracked: 0,
            },
        };
        let archive = path.join("archive");
        publish(&archive, &built).unwrap();
        let state = path.join("state");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(path.join("alias-parent")).unwrap();
        let state = path.join("alias-parent/../state");
        fs::write(
            path.join("capabilities.out"),
            include_str!("../../testdata/admission-listing.txt"),
        )
        .unwrap();
        let failure = COUNTING
            .replace("counts: true", "counts: false")
            .replace(
                "terminal: complete pass fired=03 required=03",
                "terminal: complete violation fired=03 required=03",
            )
            .replace(
                "replay: passes",
                "replay: does not count, violation, broken invariant",
            );
        let failure = format!(
            "{}cause: violation, violating Bytes\nidentity: {}\n",
            failure,
            "ab".repeat(44)
        );
        for phase in [
            "bundle",
            "run",
            "inspect",
            "inspect-original",
            "inspect-replay",
            "inspect-baseline",
            "inspect-candidate",
            "inspect-candidate-replay",
        ] {
            fs::write(path.join(format!("{phase}.out")), &failure).unwrap();
            fs::write(
                path.join(format!("{phase}.exit")),
                if ["bundle", "run"].contains(&phase) {
                    "1"
                } else {
                    "0"
                },
            )
            .unwrap();
        }
        fs::write(path.join("triage"), "yes").unwrap();
        let mut case = Self {
            path,
            state,
            root,
            archive,
            id: String::new(),
        };
        let admission = case.command(
            "admit",
            &[
                "--profile",
                "upload",
                "--campaign",
                "triage",
                "--attempts",
                "1",
                "--archive",
                case.archive.to_str().unwrap(),
            ],
        );
        case.require(&admission, 0);
        let admitted: serde_json::Value = serde_json::from_slice(&admission.stdout).unwrap();
        case.id = format!("{}-0001", admitted["id"].as_str().unwrap());
        let manifest = fs::read_to_string(case.state.join(crate::sharded::job_file(format!(
            "{}.manifest",
            admitted["id"].as_str().unwrap()
        ))))
        .unwrap();
        fs::write(case.path.join("manifest"), &manifest).unwrap();
        let canonical: String = manifest
            .lines()
            .filter(|line| !line.starts_with("cpu = "))
            .map(|line| format!("{line}\n"))
            .collect();
        let mut bundle = super::sim_worker::bundle(&canonical, 2);
        let mut violation = [0; 48];
        violation[0] = 7;
        violation[4] = 1;
        bundle.extend_from_slice(&violation);
        fs::write(case.path.join("bundle.bundle"), bundle).unwrap();
        let store = Store::open(&case.state).unwrap();
        let config = Configuration::new(
            [
                ("slots", 1),
                ("reserve_slots", 1),
                ("cores", 2),
                ("memory", 512 << 20),
                ("cpu", 60),
                ("tree_memory", 128 << 20),
                ("attempt_output", 4 << 20),
                ("attempt_inodes", 200),
                ("wall", 120),
                ("processes", 64),
                ("artifact_bytes", 256 << 20),
                ("artifact_inodes", 10000),
                ("backlog", 2),
                ("retained_builds", 1),
            ]
            .into_iter()
            .map(|(key, value)| (text(key), value))
            .collect(),
        )
        .unwrap();
        store
            .create_record(store.root(), &name("config.json"), &config)
            .unwrap();
        drop(store);
        if matches!(label, "pause" | "full" | "drain") {
            let store = Store::open(&case.state).unwrap();
            let id = case.id.rsplit_once('-').unwrap().0;
            let jobs = crate::sharded::jobs(&store, id);
            let job = store
                .read_record::<campaign_supervisor::record::Admission>(
                    &jobs,
                    &name(&format!("{id}.json")),
                )
                .unwrap()
                .unwrap();
            let config = store
                .read_record::<Configuration>(store.root(), &name("config.json"))
                .unwrap()
                .unwrap();
            let config = config.record();
            let mut custody = campaign_supervisor::custody::Custody::open(
                &case.root,
                campaign_supervisor::custody::Timing {
                    poll: std::time::Duration::from_millis(1),
                    kill_wait: std::time::Duration::from_secs(1),
                    watchdog: std::time::Duration::from_secs(120),
                },
            )
            .unwrap();
            let executable = PathBuf::from(env!("CARGO_BIN_EXE_campaign"));
            let (attempt, running) = campaign_supervisor::attempt::start(
                &store,
                &mut custody,
                job,
                campaign_supervisor::attempt::Launch {
                    gate: executable.clone(),
                    launcher: executable,
                    environment: [(PLAN.into(), case.path.as_os_str().to_owned())].into(),
                    limits: campaign_supervisor::custody::Limits {
                        cpu_quota_us: 100_000,
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
            let completed = attempt
                .finish(
                    &store,
                    custody.wait_any(vec![running]).unwrap().stopped,
                    campaign_supervisor::attempt::EVIDENCE_BOUND,
                )
                .unwrap();
            let job = store
                .read_record::<campaign_supervisor::record::Admission>(
                    &jobs,
                    &name(&format!("{id}.json")),
                )
                .unwrap()
                .unwrap();
            campaign_supervisor::attempt::settle(&store, job, completed).unwrap();
            drop(custody);
            drop(store);
        } else {
            let dispatch = case.command(
                "dispatch",
                &[
                    "--archive",
                    case.archive.to_str().unwrap(),
                    "--max-attempts",
                    "1",
                ],
            );
            case.require(&dispatch, 0);
        }
        let view = View::open(&case.state).unwrap();
        let findings = view
            .open_dir(view.root(), &name("findings"))
            .unwrap()
            .unwrap_or_else(|| panic!("bootstrap retained no finding"));
        let directory = view.open_dir(&findings, &name(&case.id)).unwrap().unwrap();
        assert_eq!(
            view.read_record::<campaign_supervisor::record::Finding>(
                &directory,
                &name("finding.json")
            )
            .unwrap()
            .unwrap()
            .record()
            .kind,
            campaign_supervisor::record::FindingKind::Violation,
            "bootstrap must retain a violation"
        );
        case
    }
    fn command(&self, command: &str, extra: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_campaign"))
            .arg(command)
            .arg("--state")
            .arg(&self.state)
            .arg("--cgroup-root")
            .arg(&self.root)
            .args(extra)
            .env(PLAN, &self.path)
            .output()
            .unwrap()
    }
    fn require(&self, output: &Output, code: i32) {
        assert_eq!(
            output.status.code(),
            Some(code),
            "{} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    fn result(&self, output: &Output) -> campaign_supervisor::record::TriageResult {
        self.require(output, 0);
        serde_json::from_slice(&output.stdout).unwrap()
    }
    fn calls(&self) -> Vec<String> {
        fs::read_to_string(self.path.join("calls"))
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }
}
impl Drop for Triage {
    fn drop(&mut self) {
        let delegation = PathBuf::from(std::env::var_os("CAMPAIGN_CGROUP_ROOT").unwrap());
        fs::write(
            delegation.join("controller/cgroup.procs"),
            std::process::id().to_string(),
        )
        .unwrap();
        let _ = fs::write(self.root.join("cgroup.kill"), "1");
        let _ = fs::remove_dir(&self.root);
        if !std::thread::panicking() {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(crate) fn retained_run_replays_in_fresh_processes_and_drift_starts_nothing() {
    let case = Triage::new("fresh");
    use campaign_supervisor::record::ReplayStatus;
    for _ in 0..2 {
        let before = case.calls().len();
        let output = case.command("triage", &["--from-run", &case.id, "--step", "replay"]);
        let result = case.result(&output);
        assert_eq!(result.status, Some(ReplayStatus::Reproduced));
        assert!(case.calls().len() > before);
        assert_eq!(
            result.comparison.as_ref().unwrap().original,
            result.comparison.as_ref().unwrap().observed
        );
    }
    fs::set_permissions(
        case.archive.join("Cargo.lock"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fs::write(case.archive.join("Cargo.lock"), b"drift").unwrap();
    let before = case.calls();
    let output = case.command("triage", &["--from-run", &case.id, "--step", "replay"]);
    case.require(&output, 2);
    assert_eq!(case.calls(), before);
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(crate) fn retained_rerun_and_reduction_keep_full_identity() {
    let case = Triage::new("identity");
    let initial = campaign_supervisor::campaign::report(&case.state).unwrap();
    let initial_steps = initial["triage"].as_array().unwrap().len();
    let initial_candidates = initial["regression_candidates"].as_array().unwrap().len();
    use campaign_supervisor::record::ReplayStatus;
    fs::write(case.path.join("bundle.out"), COUNTING).unwrap();
    fs::write(case.path.join("bundle.exit"), "0").unwrap();
    fs::write(case.path.join("inspect.out"), COUNTING).unwrap();
    fs::write(case.path.join("inspect.exit"), "0").unwrap();
    let result = case.result(&case.command("triage", &["--from-run", &case.id, "--step", "rerun"]));
    assert_eq!(result.status, Some(ReplayStatus::Unreproduced));
    let summary = fs::read_to_string(case.path.join("inspect-original.out")).unwrap();
    let different = summary.replace(&"ab".repeat(44), &"cd".repeat(44));
    for phase in ["bundle", "inspect"] {
        fs::write(case.path.join(format!("{phase}.out")), &different).unwrap();
        fs::write(
            case.path.join(format!("{phase}.exit")),
            if phase == "bundle" { "1" } else { "0" },
        )
        .unwrap();
    }
    let result = case.result(&case.command("triage", &["--from-run", &case.id, "--step", "rerun"]));
    assert_eq!(result.status, Some(ReplayStatus::Diverged));
    let manifest = fs::read_to_string(case.path.join("manifest")).unwrap();
    fs::write(
        case.path.join("reduce.manifest"),
        manifest.replace("cpu = unrecorded", "cpu = candidate"),
    )
    .unwrap();
    let result =
        case.result(&case.command("triage", &["--from-run", &case.id, "--step", "reduce"]));
    assert_eq!(result.status, Some(ReplayStatus::Reduced));
    assert_eq!(
        result
            .comparison
            .as_ref()
            .unwrap()
            .failure_identity
            .as_ref()
            .unwrap()
            .as_str(),
        &"ab".repeat(44)
    );
    let directory = case
        .state
        .join("triage")
        .join(&case.id)
        .join("steps")
        .join(format!("{:04}", result.number));
    let view = View::open(&directory).unwrap();
    let candidate = view
        .read_record::<campaign_supervisor::record::RegressionCandidate>(
            view.root(),
            &name("candidate"),
        )
        .unwrap()
        .unwrap();
    let candidate = candidate.record();
    assert_ne!(
        candidate.manifest,
        campaign_supervisor::record::Digest::of(manifest.as_bytes())
    );
    let source = View::open(std::path::Path::new(candidate.input.as_str())).unwrap();
    assert_eq!(
        source
            .read_record::<campaign_supervisor::record::Artifact>(source.root(), &name("artifact"))
            .unwrap()
            .unwrap()
            .record()
            .manifest,
        Some(candidate.manifest)
    );
    let mut command = Command::new(candidate.command[0].as_str());
    command
        .args(candidate.command.iter().skip(1).map(Text::as_str))
        .env(PLAN, &case.path);
    let output = command.output().unwrap();
    case.require(&output, candidate.expected_exit.unwrap() as i32);
    let output: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let replay = View::open(std::path::Path::new(output["artifact"].as_str().unwrap())).unwrap();
    let artifact = replay
        .read_record::<campaign_supervisor::record::Artifact>(replay.root(), &name("artifact"))
        .unwrap()
        .unwrap();
    assert_eq!(artifact.record().manifest, Some(candidate.manifest));
    assert_eq!(
        artifact
            .record()
            .comparison
            .as_ref()
            .unwrap()
            .status
            .as_str(),
        "reproduced"
    );
    let artifacts = replay.path().parent().unwrap().to_owned();
    drop(replay);
    fs::remove_dir_all(artifacts).unwrap();
    let first = fs::read(directory.join("result")).unwrap();
    let repeated =
        case.result(&case.command("triage", &["--from-run", &case.id, "--step", "reduce"]));
    assert_eq!(repeated.status, Some(ReplayStatus::Reduced));
    assert_eq!(repeated.number, result.number + 1);
    assert_eq!(fs::read(directory.join("result")).unwrap(), first);
    let next = case
        .state
        .join("triage")
        .join(&case.id)
        .join("steps")
        .join(format!("{:04}", repeated.number));
    assert!(next.join("candidate").exists());
    let report = case.command(
        "dispatch",
        &[
            "--archive",
            case.archive.to_str().unwrap(),
            "--max-attempts",
            "0",
        ],
    );
    case.require(&report, 0);
    let report: serde_json::Value = serde_json::from_slice(&report.stdout).unwrap();
    assert_eq!(report["triage_started"], 0);
    let projection = campaign_supervisor::campaign::report(&case.state).unwrap();
    assert_eq!(
        projection["triage"].as_array().unwrap().len(),
        initial_steps + 4,
        "{projection}"
    );
    assert_eq!(
        projection["triage"][initial_steps]["result"]["status"],
        "unreproduced"
    );
    assert_eq!(
        projection["triage"][initial_steps + 1]["result"]["status"],
        "diverged"
    );
    assert_eq!(
        projection["triage"][initial_steps + 2]["result"]["status"],
        "reduced"
    );
    assert_eq!(
        projection["regression_candidates"]
            .as_array()
            .unwrap()
            .len(),
        initial_candidates + 2
    );
    assert!(
        projection["release_blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|id| id == &case.id)
    );
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(crate) fn retained_step_owner_loss_at_worker_seam_is_interrupted_and_exclusive() {
    let case = Triage::new("lost");
    let steps = case.state.join("triage").join(&case.id).join("steps");
    let number = fs::read_dir(&steps).unwrap().count() as u64 + 1;
    let step = steps.join(format!("{number:04}"));
    let _ = fs::remove_file(case.path.join("replay.seen"));
    fs::write(case.path.join("replay.action"), "hang").unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_campaign"))
        .args(["triage", "--state"])
        .arg(&case.state)
        .args(["--from-run", &case.id, "--step", "replay", "--cgroup-root"])
        .arg(&case.root)
        .env(PLAN, &case.path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
    while !case.path.join("replay.seen").exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "replay worker seam was not reached"
        );
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    let view = View::open(&step).unwrap();
    let started = view
        .read_record::<campaign_supervisor::record::Started>(view.root(), &name("started"))
        .unwrap()
        .unwrap();
    let dependencies = view
        .read_record::<campaign_supervisor::record::ReplayDependencies>(
            view.root(),
            &name("dependencies"),
        )
        .unwrap()
        .unwrap();
    assert!(
        fs::read_to_string(
            std::path::Path::new(started.record().cgroup.as_str()).join("cgroup.events")
        )
        .unwrap()
        .contains("populated 1")
    );
    let refused = case.command("triage", &["--from-run", &case.id, "--step", "replay"]);
    case.require(&refused, 3);
    assert_eq!(fs::read_dir(&steps).unwrap().count() as u64, number);
    child.kill().unwrap();
    let lost = child.wait_with_output().unwrap();
    assert!(!lost.status.success());
    fs::remove_file(case.path.join("replay.action")).unwrap();
    case.result(&case.command("triage", &["--from-run", &case.id, "--step", "rerun"]));
    let result = view
        .read_record::<campaign_supervisor::record::TriageResult>(view.root(), &name("result"))
        .unwrap()
        .unwrap();
    assert_eq!(
        result.record().state,
        campaign_supervisor::record::StepState::Interrupted
    );
    assert_eq!(result.record().status, None);
    assert_eq!(result.record().comparison, None);
    assert_eq!(
        view.read_record::<campaign_supervisor::record::ReplayDependencies>(
            view.root(),
            &name("dependencies")
        )
        .unwrap()
        .unwrap()
        .record(),
        dependencies.record()
    );
    assert!(!std::path::Path::new(started.record().cgroup.as_str()).exists());
    let before_collect = campaign_supervisor::campaign::report(&case.state).unwrap();
    let collection = Command::new(env!("CARGO_BIN_EXE_campaign"))
        .arg("collect")
        .arg("--state")
        .arg(&case.state)
        .output()
        .unwrap();
    case.require(&collection, 0);
    let collection: serde_json::Value = serde_json::from_slice(&collection.stdout).unwrap();
    assert_eq!(collection["held"], serde_json::json!([]), "{collection}");
    let bundle = fs::read(
        case.state
            .join("findings")
            .join(dependencies.record().finding.as_str())
            .join("bundle"),
    )
    .unwrap();
    assert_eq!(
        Some(campaign_supervisor::record::Digest::of(&bundle)),
        dependencies.record().bundle
    );
    assert_eq!(
        view.read_record::<campaign_supervisor::record::ReplayDependencies>(
            view.root(),
            &name("dependencies")
        )
        .unwrap()
        .unwrap()
        .record(),
        dependencies.record()
    );
    let projection = campaign_supervisor::campaign::report(&case.state).unwrap();
    assert_eq!(projection, before_collect);
    let interrupted = projection["triage"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["number"] == number)
        .unwrap();
    assert_eq!(
        interrupted["result"]["state"], "interrupted",
        "{projection}"
    );
    assert_eq!(interrupted["result"]["status"], serde_json::Value::Null);
    assert_eq!(interrupted["result"]["elapsed_ms"], serde_json::Value::Null);
    let disposition = Command::new(env!("CARGO_BIN_EXE_campaign"))
        .arg("dispose")
        .arg("--state")
        .arg(&case.state)
        .args([
            "--finding",
            &case.id,
            "--disposition",
            "harness",
            "--evidence",
            "infrastructure triage evidence",
        ])
        .output()
        .unwrap();
    case.require(&disposition, 0);
    let findings = campaign_supervisor::campaign::findings(&case.state).unwrap();
    assert!(
        findings["release_blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|id| id == &case.id)
    );
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(crate) fn storage_pause_is_successful_dispatch_and_explicit_refusal_without_mutation() {
    let case = Triage::new("pause");
    let store = Store::open(&case.state).unwrap();
    let mut values = store
        .read_record::<Configuration>(store.root(), &name("config.json"))
        .unwrap()
        .unwrap()
        .record()
        .config()
        .clone();
    values.insert(text("artifact_bytes"), 64 << 20);
    let config = Configuration::new(values).unwrap();
    store
        .replace_record(store.root(), &name("config.json"), &config)
        .unwrap();
    drop(store);
    // Eight admission probe directories charge 64 MiB, the whole budget.
    // Each holds an unlisted entry, so the dispatch-owned collect pass
    // keeps them.
    for index in 0..8 {
        let probe = case.state.join(format!("probes/probe-fill-{index}"));
        std::os::unix::fs::DirBuilderExt::mode(&mut fs::DirBuilder::new(), 0o700)
            .recursive(true)
            .create(&probe)
            .unwrap();
        fs::write(probe.join("unlisted"), b"").unwrap();
    }
    let calls = case.calls();
    let steps = case.state.join("triage").join(&case.id).join("steps");
    let before = if steps.exists() {
        fs::read_dir(&steps).unwrap().count()
    } else {
        0
    };
    let dispatch = case.command(
        "dispatch",
        &[
            "--archive",
            case.archive.to_str().unwrap(),
            "--max-attempts",
            "0",
        ],
    );
    case.require(&dispatch, 0);
    let report: serde_json::Value = serde_json::from_slice(&dispatch.stdout).unwrap();
    assert!(
        report["paused"]
            .as_array()
            .unwrap()
            .iter()
            .any(|reason| reason == "artifact_bytes")
    );
    assert_eq!(report["pauses"]["artifact_bytes"], 1);
    let output = case.command("triage", &["--from-run", &case.id, "--step", "replay"]);
    case.require(&output, 2);
    assert!(String::from_utf8_lossy(&output.stderr).contains("artifact_bytes"));
    assert_eq!(case.calls(), calls);
    assert_eq!(
        if steps.exists() {
            fs::read_dir(&steps).unwrap().count()
        } else {
            0
        },
        before
    );
    let help = Command::new(env!("CARGO_BIN_EXE_campaign"))
        .args(["triage", "--help"])
        .output()
        .unwrap();
    case.require(&help, 0);
    assert!(String::from_utf8_lossy(&help.stdout).contains("explicit reduce may repeat"));
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(crate) fn triage_runs_on_reserve_while_the_ordinary_slot_is_full() {
    let case = Triage::new("full");
    let admitted = case.command(
        "admit",
        &[
            "--profile",
            "upload",
            "--campaign",
            "triage",
            "--run",
            "2",
            "--attempts",
            "1",
            "--archive",
            case.archive.to_str().unwrap(),
        ],
    );
    case.require(&admitted, 0);
    fs::write(case.path.join("bundle.action"), "wait-for-release").unwrap();
    let _ = fs::remove_file(case.path.join("bundle.seen"));
    let _ = fs::remove_file(case.path.join("replay.seen"));
    let child = Command::new(env!("CARGO_BIN_EXE_campaign"))
        .args(["dispatch", "--state"])
        .arg(&case.state)
        .args(["--archive"])
        .arg(&case.archive)
        .args(["--cgroup-root"])
        .arg(&case.root)
        .args(["--max-attempts", "1"])
        .env(PLAN, &case.path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
    while !case.path.join("bundle.seen").exists() || !case.path.join("replay.seen").exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "ordinary and replay worker seams were not reached"
        );
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    let live = fs::read_dir(&case.root)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry.file_name() != "controller" && entry.file_type().is_ok_and(|kind| kind.is_dir())
        })
        .filter(|entry| {
            fs::read_to_string(entry.path().join("cgroup.events"))
                .is_ok_and(|events| events.contains("populated 1"))
        })
        .count();
    assert_eq!(live, 2, "ordinary and reserved trees run together");
    fs::write(case.path.join("release"), b"1").unwrap();
    let output = child.wait_with_output().unwrap();
    case.require(&output, 0);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["started"], 1);
    assert!(report["triage_started"].as_u64().unwrap() >= 1);
    assert_eq!(
        report["counts"]["triage"].as_u64().unwrap(),
        report["triage_completed"].as_array().unwrap().len() as u64
    );
    assert!(
        report["completed"]
            .as_array()
            .unwrap()
            .iter()
            .all(|finish| finish["interruption"].is_null()
                && finish["signal"].is_null()
                && finish["watchdog"] == false)
    );
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(crate) fn cli_signal_drain_smoke_preserves_minted_results() {
    let case = Triage::new("drain");
    let spawn = || {
        Command::new(env!("CARGO_BIN_EXE_campaign"))
            .args(["triage", "--state"])
            .arg(&case.state)
            .args(["--from-run", &case.id, "--step", "replay", "--cgroup-root"])
            .arg(&case.root)
            .env(PLAN, &case.path)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap()
    };
    let first = spawn();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let status = fs::read_to_string(format!("/proc/{}/status", first.id())).unwrap();
        let ready = status
            .lines()
            .find(|line| line.starts_with("SigBlk:"))
            .is_some_and(|line| !line.ends_with("0000000000000000"));
        if ready {
            break;
        }
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    assert!(
        !case.state.join("triage").exists(),
        "signal seam precedes the mint"
    );
    assert!(
        Command::new("/bin/kill")
            .args(["-TERM", &first.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    let output = first.wait_with_output().unwrap();
    case.require(&output, 0);
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["state"], "drained");
    assert_eq!(value["started"], false);
    assert!(!case.state.join("triage").exists());
    fs::write(case.path.join("replay.action"), "wait-for-release").unwrap();
    let second = spawn();
    let step = case.state.join("triage").join(&case.id).join("steps/0001");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while !step.join("started").exists() {
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    let view = View::open(&step).unwrap();
    assert!(
        view.read_record::<campaign_supervisor::record::Started>(view.root(), &name("started"))
            .unwrap()
            .is_some()
    );
    assert!(
        Command::new("/bin/kill")
            .args(["-TERM", &second.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    let output = second.wait_with_output().unwrap();
    case.require(&output, 0);
    let result: campaign_supervisor::record::TriageResult =
        serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        result.state,
        campaign_supervisor::record::StepState::Interrupted
    );
    assert_eq!(result.status, None);
    assert!(
        view.read_record::<campaign_supervisor::record::ReplayDependencies>(
            view.root(),
            &name("dependencies")
        )
        .unwrap()
        .is_some()
    );
}
