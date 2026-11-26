use super::sim_worker::{COUNTING, PLAN};
use campaign_supervisor::record::{
    Calibration, CalibrationPlan, CalibrationReplay, CalibrationVerdict, Capacity, Class,
    Configuration, Digest, Finished, Text,
};
use campaign_supervisor::store::{Name, Store, View};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Output};

fn text(value: &str) -> Text {
    Text::new(value).unwrap()
}
fn name(value: &str) -> Name {
    Name::new(value).unwrap()
}

pub(crate) fn worker(path: &Path) -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let value = |flag| {
        args.iter()
            .position(|arg| arg == flag)
            .and_then(|index| args.get(index + 1))
    };
    let manifest = value("--manifest").map(|path| fs::read_to_string(path).unwrap());
    let fault = manifest.as_ref().is_some_and(|manifest| {
        manifest
            .lines()
            .any(|line| line == "profile = long-planted")
    });
    let dir = path.join(if fault { "fault" } else { "healthy" });
    if let Some(output) = value("--bundle")
        && fault
    {
        let manifest = manifest.as_ref().unwrap();
        let canonical: String = manifest
            .lines()
            .filter(|line| !line.starts_with("cpu = "))
            .map(|line| format!("{line}\n"))
            .collect();
        let mut bytes = super::sim_worker::bundle(&canonical, 2);
        let mut violation = [0; 48];
        violation[0] = 7;
        violation[4] = 1;
        bytes.extend_from_slice(&violation);
        fs::write(dir.join("bundle.bundle"), bytes).unwrap();
        assert!(!output.is_empty());
    }
    if value("--replay").is_some() {
        let count = fs::read_to_string(path.join("replay-count"))
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0)
            + 1;
        fs::write(path.join("replay-count"), count.to_string()).unwrap();
        if path.join("replay-panic").exists() {
            eprintln!("thread 'worker' panicked at replay failure");
            return ExitCode::from(101);
        }
        let mut pids = fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(path.join("replay-pids"))
            .unwrap();
        writeln!(pids, "{}", std::process::id()).unwrap();
        if path.join("pause-replay").is_file() && count == 1
            || path.join("pause-second-replay").is_file() && count == 2
        {
            fs::write(path.join("replay-entered"), std::process::id().to_string()).unwrap();
            loop {
                std::thread::park();
            }
        }
        if path.join("second-drift").exists() && count == 2
            || path.join("first-drift").exists() && count == 1
            || path.join("two-wrong").exists()
        {
            let original = COUNTING.replace("profile: upload", "profile: long");
            let digest = original
                .lines()
                .find_map(|line| line.strip_prefix("digest: "))
                .unwrap();
            fs::write(
                dir.join("inspect-replay.out"),
                original.replace(digest, &Digest::of(b"wrong").to_string()),
            )
            .unwrap();
        }
    }
    super::sim_worker::worker(&dir)
}

struct Case {
    path: PathBuf,
    state: PathBuf,
    root: PathBuf,
}
impl Case {
    fn new(label: &str) -> Self {
        let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("calibration-{label}-{}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        let state = path.join("state");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let root = PathBuf::from(std::env::var_os("CAMPAIGN_CGROUP_ROOT").unwrap())
            .join(format!("calibration-{label}-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        fs::write(path.join("calibration"), "yes").unwrap();
        let listing = format!(
            "{}profile: long class=live support=implemented campaign=unqualified held=bytes=1,every=1,pending=1,records=1,ring=1,turns=1\nprofile: long-planted class=control support=implemented campaign=unqualified held=bytes=1,every=1,pending=1,records=1,ring=1,turns=1\n",
            include_str!("../../testdata/admission-listing.txt")
        );
        for mode in ["healthy", "fault"] {
            let dir = path.join(mode);
            fs::create_dir(&dir).unwrap();
            fs::write(dir.join("triage"), "yes").unwrap();
            fs::write(dir.join("capabilities.out"), &listing).unwrap();
            let mut output = COUNTING.replace(
                "profile: upload",
                &format!(
                    "profile: {}",
                    if mode == "fault" {
                        "long-planted"
                    } else {
                        "long"
                    }
                ),
            );
            if mode == "fault" {
                output = output
                    .replace("counts: true", "counts: false")
                    .replace(
                        "terminal: complete pass fired=03 required=03",
                        "terminal: complete violation fired=03 required=03",
                    )
                    .replace(
                        "replay: passes",
                        "replay: does not count, violation, broken invariant",
                    );
                output.push_str(&format!(
                    "cause: violation, violating Bytes\nidentity: 020101{}\n",
                    "00".repeat(41)
                ));
            }
            for phase in [
                "bundle",
                "run",
                "inspect",
                "inspect-original",
                "inspect-replay",
            ] {
                fs::write(dir.join(format!("{phase}.out")), &output).unwrap();
                fs::write(
                    dir.join(format!("{phase}.exit")),
                    if mode == "fault" && matches!(phase, "bundle" | "run") {
                        "1"
                    } else {
                        "0"
                    },
                )
                .unwrap();
            }
            fs::write(
                dir.join("replay.out"),
                "replay: reproduced, complete pass fired=03 required=03\n",
            )
            .unwrap();
            fs::write(dir.join("replay.exit"), "0").unwrap();
        }
        let config = Configuration::new(
            [
                ("slots", 1),
                ("reserve_slots", 1),
                ("cores", 4),
                ("memory", 512 << 20),
                ("cpu", 60),
                ("tree_memory", 128 << 20),
                ("attempt_output", 4 << 20),
                ("attempt_inodes", 200),
                ("wall", 120),
                ("processes", 64),
                ("artifact_bytes", 256 << 20),
                ("artifact_inodes", 10000),
                ("backlog", 20),
                ("retained_builds", 1),
            ]
            .map(|(key, value)| (text(key), value))
            .into(),
        )
        .unwrap();
        let store = Store::open(&state).unwrap();
        store
            .create_record(store.root(), &name("config.json"), &config)
            .unwrap();
        Self { path, state, root }
    }
    fn command(&self, command: &str, extra: &[&str]) -> Output {
        let mut process = Command::new(env!("CARGO_BIN_EXE_campaign"));
        process.arg(command).arg("--state").arg(&self.state);
        if matches!(command, "admit" | "calibrate" | "dispatch") {
            process
                .arg("--cgroup-root")
                .arg(&self.root)
                .arg("--archive")
                .arg(super::cases::archive());
        }
        process.args(extra).env(PLAN, &self.path).output().unwrap()
    }
    fn configure(&self, slots: u64) -> Output {
        let view = View::open(&self.state).unwrap();
        let config = view
            .read_record::<Configuration>(view.root(), &name("config.json"))
            .unwrap()
            .unwrap();
        let mut values = config.record().config().clone();
        values.insert(text("slots"), slots);
        let arguments: Vec<String> = values
            .iter()
            .flat_map(|(key, value)| ["--set".to_owned(), format!("{}={value}", key.as_str())])
            .collect();
        let args: Vec<_> = arguments.iter().map(String::as_str).collect();
        self.command("configure", &args)
    }
    fn require(&self, output: &Output, code: i32) {
        assert_eq!(
            output.status.code(),
            Some(code),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    fn calibrate(&self) -> Calibration {
        let output = self.command("calibrate", &["--profile", "long", "--run", "1"]);
        self.require(&output, 0);
        serde_json::from_slice(&output.stdout).unwrap()
    }
    fn queued(&self, run: &str, counts: Option<&str>) -> String {
        let mut args = vec![
            "--profile",
            "long",
            "--campaign",
            "coverage",
            "--attempts",
            "1",
            "--run",
            run,
        ];
        if let Some(counts) = counts {
            args.extend(["--set", counts]);
        }
        let output = self.command("admit", &args);
        self.require(&output, 0);
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned()
    }
}
impl Drop for Case {
    fn drop(&mut self) {
        let delegation = PathBuf::from(std::env::var_os("CAMPAIGN_CGROUP_ROOT").unwrap());
        fs::write(
            delegation.join("controller/cgroup.procs"),
            std::process::id().to_string(),
        )
        .unwrap();
        assert_eq!(
            fs::read_dir(&self.root)
                .unwrap()
                .flatten()
                .filter(|entry| entry.file_type().unwrap().is_dir()
                    && entry.file_name() != "controller")
                .count(),
            0
        );
        fs::remove_dir(self.root.join("controller")).unwrap();
        fs::remove_dir(&self.root).unwrap();
        fs::remove_dir_all(&self.path).unwrap();
    }
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(crate) fn calibrated_controls_lost_attempt_and_two_fresh_replays_grant_scoped_capacity() {
    let case = Case::new("positive");
    let queued = case.queued("1", None);
    let record = case.calibrate();
    assert_eq!(record.verdict, CalibrationVerdict::Calibrated, "{record:?}");
    assert_eq!(record.lost.class, Class::Interrupted);
    assert_eq!(record.healthy.finished.class, Class::Pass);
    assert_eq!(
        record.controls[&text("long-planted")].finished.class,
        Class::Violation
    );
    assert_eq!(record.replays.len(), 2);
    let pids = fs::read_to_string(case.path.join("replay-pids"))
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    assert_eq!(pids.len(), 2);
    assert_ne!(pids[0], pids[1]);
    assert!(
        record
            .healthy
            .resources
            .memory_bytes
            .is_some_and(|value| value > 0)
    );
    assert!(record.healthy.resources.pids.is_some_and(|value| value > 0));
    let root = case
        .state
        .join("calibrations")
        .join(record.root.to_string());
    let view = View::open(&root).unwrap();
    let plan = view
        .read_record::<CalibrationPlan>(view.root(), &name("plan"))
        .unwrap()
        .unwrap();
    assert_eq!(
        plan.record().healthy.job().experiment().counts,
        record.contract.counts
    );
    assert_eq!(plan.record().controls.len(), 1);
    for number in 1..=2 {
        let replay = View::open(&root.join("replays").join(format!("{number:04}"))).unwrap();
        let dependency = replay
            .read_record::<CalibrationReplay>(replay.root(), &name("replay"))
            .unwrap()
            .unwrap();
        assert!(
            Path::new(dependency.record().source.as_str())
                .join("bundle")
                .exists()
        );
        assert_eq!(
            dependency.record().attempt.manifest,
            plan.record().healthy.job().manifest_sha256()
        );
        assert_eq!(
            replay
                .read_record::<Finished>(replay.root(), &name("finished"))
                .unwrap()
                .unwrap()
                .record()
                .exit,
            Some(0)
        );
        assert!(
            !root
                .join("replays")
                .join(format!("{number:04}"))
                .join("reservation")
                .exists()
        );
    }
    let capacities = View::open(
        &case
            .state
            .join("capacity")
            .join(record.contract.key().to_string()),
    )
    .unwrap();
    let capacity = capacities
        .read_record::<Capacity>(capacities.root(), &name(&record.root.to_string()))
        .unwrap()
        .unwrap();
    assert!(capacity.record().slots() >= 2);
    assert_eq!(capacity.record().root(), record.root);
    let config = case.configure(2);
    case.require(&config, 0);
    case.require(&case.configure(1), 0);
    let changed = case.queued("2", Some("turns=20001"));
    let dispatch = case.command("dispatch", &["--max-attempts", "2"]);
    case.require(&dispatch, 0);
    let report: serde_json::Value = serde_json::from_slice(&dispatch.stdout).unwrap();
    assert_eq!(report["started"], 2);
    assert!(
        case.state
            .join(crate::sharded::attempts_dir(&queued))
            .join("0001/started")
            .exists()
    );
    assert!(
        case.state
            .join(crate::sharded::attempts_dir(&changed))
            .join("0001/started")
            .exists()
    );
    assert!(
        !case
            .state
            .join(crate::sharded::attempts_dir(record.root.to_string()))
            .join("0003")
            .exists()
    );
    let projection = case.command("report", &[]);
    case.require(&projection, 0);
    let projection: serde_json::Value = serde_json::from_slice(&projection.stdout).unwrap();
    let profiles = projection["profiles"].as_array().unwrap();
    let matching = profiles
        .iter()
        .find(|row| {
            row["declaration"]["profile"] == "long"
                && row["declaration"]["counts"] == serde_json::json!(record.contract.counts)
        })
        .unwrap();
    assert_eq!(matching["qualified"], true, "{projection}");
    assert_eq!(matching["state"], "credited");
    assert!(
        matching["credited"]
            .as_array()
            .unwrap()
            .iter()
            .any(|id| id == &queued)
    );
    let published = projection["jobs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == queued)
        .unwrap();
    assert_eq!(published["credited"], true);
    let other = profiles
        .iter()
        .find(|row| {
            row["declaration"]["profile"] == "long"
                && row["jobs"]
                    .as_array()
                    .is_some_and(|jobs| jobs.iter().any(|id| id == &changed))
        })
        .unwrap();
    assert_eq!(other["qualified"], false);
    assert!(
        projection["calibrations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["qualified"] == true)
    );
    assert_eq!(
        projection["totals"]["metrics"]["wall_us"]["measurement"],
        "unmeasured"
    );
    assert!(
        projection["held"].as_array().unwrap().is_empty(),
        "{projection}"
    );
    let before = fs::read(root.join("result")).unwrap();
    assert_eq!(case.calibrate(), record);
    assert_eq!(fs::read(root.join("result")).unwrap(), before);
    assert_eq!(
        fs::read_to_string(case.path.join("replay-count")).unwrap(),
        "2"
    );
    let control = &record.controls[&text("long-planted")];
    let finding_path = case
        .state
        .join("findings")
        .join(control.finished.attempt.as_str());
    let finding = View::open(&finding_path).unwrap();
    let disposition = finding
        .read_record::<campaign_supervisor::record::Disposition>(
            finding.root(),
            &name("0001.disposition.json"),
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        disposition.record().decision(),
        campaign_supervisor::record::Decision::Resolved
    );
    assert_eq!(
        fs::read_dir(&finding_path)
            .unwrap()
            .flatten()
            .filter(|entry| entry
                .file_name()
                .to_string_lossy()
                .ends_with(".disposition.json"))
            .count(),
        1
    );
    let healthy_artifacts = case
        .state
        .join(crate::sharded::attempts_dir(record.root.to_string()))
        .join("0002/artifacts")
        .join(record.healthy.finished.attempt.as_str());
    let bundle_path = healthy_artifacts.join("bundle");
    let bundle = fs::read(&bundle_path).unwrap();
    fs::write(&bundle_path, b"changed bound calibration evidence").unwrap();
    let before = tree_bytes(&case.state);
    let damaged = case.command("report", &[]);
    case.require(&damaged, 0);
    let damaged: serde_json::Value = serde_json::from_slice(&damaged.stdout).unwrap();
    assert!(
        damaged["profiles"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["declaration"]["profile"] == "long")
            .all(|row| row["qualified"] == false)
    );
    assert!(
        damaged["calibrations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == record.root.to_string() && row["verdict"] == "held")
    );
    assert_eq!(tree_bytes(&case.state), before);
    fs::write(&bundle_path, bundle).unwrap();
    let control = &record.controls[&text("long-planted")];
    let control_bundle_path = case
        .state
        .join(crate::sharded::attempts_dir(control.job.to_string()))
        .join("0001/artifacts")
        .join(control.finished.attempt.as_str())
        .join("bundle");
    let control_bundle = fs::read(&control_bundle_path).unwrap();
    fs::write(&control_bundle_path, b"changed bound control evidence").unwrap();
    let before = tree_bytes(&case.state);
    let damaged = case.command("report", &[]);
    case.require(&damaged, 0);
    let damaged: serde_json::Value = serde_json::from_slice(&damaged.stdout).unwrap();
    assert!(
        damaged["calibrations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == record.root.to_string() && row["verdict"] == "held")
    );
    assert!(
        damaged["profiles"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["declaration"]["profile"] == "long")
            .all(|row| row["qualified"] == false)
    );
    assert_eq!(tree_bytes(&case.state), before);
    fs::write(&control_bundle_path, control_bundle).unwrap();
    let capacity_path = case
        .state
        .join("capacity")
        .join(record.contract.key().to_string())
        .join(record.root.to_string());
    let wrong_capacity_path = capacity_path.with_file_name("a".repeat(64));
    fs::rename(&capacity_path, &wrong_capacity_path).unwrap();
    let before = tree_bytes(&case.state);
    let damaged = case.command("report", &[]);
    case.require(&damaged, 0);
    let damaged: serde_json::Value = serde_json::from_slice(&damaged.stdout).unwrap();
    assert!(
        damaged["held"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["reason"] == "capacity filename binding differs")
    );
    assert!(
        damaged["profiles"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["declaration"]["profile"] == "long")
            .all(|row| row["qualified"] == false)
    );
    assert_eq!(tree_bytes(&case.state), before);
    fs::rename(&wrong_capacity_path, &capacity_path).unwrap();
    let store = Store::open(&case.state).unwrap();
    for id in [&queued, &changed] {
        let jobs = crate::sharded::jobs(&store, id);
        let attempts = crate::sharded::attempts(&store, id);
        let root = store.open_dir(&attempts, &name(id)).unwrap().unwrap();
        let directory = store.open_dir(&root, &name("0001")).unwrap().unwrap();
        let found = store
            .read_record::<Finished>(&directory, &name("finished"))
            .unwrap()
            .unwrap();
        let mut finished = found.record().clone();
        finished.kernel.cpu.insert(text("usage_usec"), u64::MAX);
        store
            .replace_record(&directory, &name("finished"), &finished)
            .unwrap();
        let verified = store
            .read_record::<Finished>(&directory, &name("finished"))
            .unwrap()
            .unwrap();
        let mut captured = store
            .read_record::<campaign_supervisor::record::Captured>(&directory, &name("captured"))
            .unwrap()
            .unwrap()
            .record()
            .clone();
        captured.finished = Digest::of(verified.read().bytes());
        store
            .replace_record(&directory, &name("captured"), &captured)
            .unwrap();
        let entry = name(&format!("{id}.result.json"));
        let found = store
            .read_record::<campaign_supervisor::record::JobResult>(&jobs, &entry)
            .unwrap()
            .unwrap();
        let mut result = found.record().clone();
        result.finished = finished;
        store.replace_record(&jobs, &entry, &result).unwrap();
    }
    drop(store);
    let before = tree_bytes(&case.state);
    let overflow = case.command("report", &[]);
    case.require(&overflow, 4);
    assert!(overflow.stdout.is_empty());
    let error = String::from_utf8(overflow.stderr).unwrap();
    assert!(error.contains("total cpu_us overflows u64"), "{error}");
    assert!(error.contains("operands"), "{error}");
    assert_eq!(tree_bytes(&case.state), before);
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(crate) fn missing_controls_and_disagreeing_fresh_replays_preserve_explicit_verdicts() {
    for mutation in [
        "missing-control",
        "second-drift",
        "two-wrong",
        "wrong-control",
        "garbled-control",
        "non-utf8-control",
    ] {
        let case = Case::new(mutation);
        match mutation {
            "missing-control" => {
                for mode in ["healthy", "fault"] {
                    let path = case.path.join(mode).join("capabilities.out");
                    let listing = fs::read_to_string(&path).unwrap();
                    fs::write(
                        path,
                        listing
                            .lines()
                            .filter(|line| !line.starts_with("profile: long-planted "))
                            .map(|line| format!("{line}\n"))
                            .collect::<String>(),
                    )
                    .unwrap();
                }
            }
            "garbled-control" => {
                fs::write(case.path.join("fault/inspect.out"), "garbled summary\n").unwrap()
            }
            "non-utf8-control" => {
                fs::write(case.path.join("fault/inspect.action"), "non-utf8").unwrap()
            }
            "wrong-control" => {
                for phase in ["run", "inspect"] {
                    let path = case.path.join("fault").join(format!("{phase}.out"));
                    let output = fs::read_to_string(&path)
                        .unwrap()
                        .replace("identity: 020101", "identity: 020102");
                    fs::write(path, output).unwrap();
                }
            }
            _ => fs::write(case.path.join(mutation), "yes").unwrap(),
        }
        let record = case.calibrate();
        assert_eq!(
            record.verdict,
            if mutation == "missing-control" {
                CalibrationVerdict::Uncalibrated
            } else {
                CalibrationVerdict::Refused
            },
            "{mutation}: {record:?}"
        );
        assert_eq!(record.healthy.finished.class, Class::Pass);
        assert_eq!(record.replays.len(), 2);
        assert!(!case.state.join("capacity").exists());
        match mutation {
            "missing-control" => assert_eq!(
                record.missing,
                vec![text("missing fault control long-planted")]
            ),
            "second-drift" => assert_eq!(
                record.reasons,
                vec![text(
                    "fresh replay 2 disagrees with the original or was refused"
                )]
            ),
            "two-wrong" => assert_eq!(
                record.reasons,
                vec![
                    text("fresh replay 1 disagrees with the original or was refused"),
                    text("fresh replay 2 disagrees with the original or was refused")
                ]
            ),
            _ => assert!(record.reasons.iter().any(|reason| {
                reason
                    .as_str()
                    .starts_with("fault control long-planted failed otherwise or passed:")
            })),
        }
    }
    for (label, class, expected) in [
        ("refuse-control", "control", ""),
        ("refuse-recovery", "recovery", ""),
        ("refuse-expected-failure", "history", " expected=violation"),
    ] {
        let case = Case::new(label);
        let path = case.path.join("healthy/capabilities.out");
        let listing = fs::read_to_string(&path).unwrap().replace(
            "profile: long class=live ",
            &format!("profile: long class={class}{expected} "),
        );
        fs::write(path, listing).unwrap();
        let output = case.command("calibrate", &["--profile", "long", "--run", "1"]);
        case.require(&output, 2);
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("calibration requires a healthy non-recovery profile")
        );
        assert!(!case.state.join("jobs").exists());
        assert!(!case.state.join("attempts").exists());
        assert!(!case.state.join("calibrations").exists());
    }
    for (label, terminal, class) in [
        ("healthy-missing-witness", "pass", Class::Inconclusive),
        ("healthy-unsuccessful", "unsuccessful", Class::Unsuccessful),
    ] {
        let case = Case::new(label);
        for phase in [
            "bundle",
            "run",
            "inspect",
            "inspect-original",
            "inspect-replay",
        ] {
            let path = case.path.join("healthy").join(format!("{phase}.out"));
            let output = fs::read_to_string(&path)
                .unwrap()
                .replace("counts: true", "counts: false")
                .replace("fired=03 required=03", "fired=01 required=03")
                .replace("complete pass ", &format!("complete {terminal} "));
            fs::write(
                path,
                format!("{output}cause: unsuccessful\nunsuccessful: required witness missing\n"),
            )
            .unwrap();
            if matches!(phase, "bundle" | "run") {
                fs::write(case.path.join("healthy").join(format!("{phase}.exit")), "1").unwrap();
            }
        }
        let record = case.calibrate();
        assert_eq!(record.healthy.finished.class, class, "{record:?}");
        assert_eq!(record.verdict, CalibrationVerdict::Refused, "{record:?}");
        assert!(record.replays.is_empty());
        assert!(!case.state.join("capacity").exists());
    }
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(crate) fn lost_calibration_replay_reconciles_under_dispatch_and_preserves_dependencies() {
    let case = Case::new("replay-loss");
    fs::write(case.path.join("pause-replay"), "yes").unwrap();
    let mut controller = Command::new(env!("CARGO_BIN_EXE_campaign"))
        .args(["calibrate", "--profile", "long", "--run", "1", "--state"])
        .arg(&case.state)
        .arg("--archive")
        .arg(super::cases::archive())
        .arg("--cgroup-root")
        .arg(&case.root)
        .env(PLAN, &case.path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    while !case.path.join("replay-entered").exists() {
        assert!(
            controller.try_wait().unwrap().is_none(),
            "controller must reach the replay seam"
        );
        assert!(
            std::time::Instant::now() < deadline,
            "replay seam must be reached"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    controller.kill().unwrap();
    let status = controller.wait().unwrap();
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(status.signal(), Some(libc::SIGKILL));
    fs::remove_file(case.path.join("pause-replay")).unwrap();
    let roots = case.state.join("calibrations");
    let root = fs::read_dir(&roots)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let replay_path = root.join("replays/0001");
    assert!(replay_path.join("started").exists());
    assert!(replay_path.join("reservation").exists());
    assert!(!replay_path.join("finished").exists());
    let dispatch = case.command("dispatch", &["--for", "0.001", "--max-attempts", "0"]);
    case.require(&dispatch, 0);
    let report: serde_json::Value = serde_json::from_slice(&dispatch.stdout).unwrap();
    assert_eq!(report["started"], 0);
    let replay = View::open(&replay_path).unwrap();
    let finished = replay
        .read_record::<Finished>(replay.root(), &name("finished"))
        .unwrap()
        .unwrap();
    assert_eq!(finished.record().class, Class::Interrupted);
    assert_eq!(finished.record().exit, None);
    assert!(!replay_path.join("reservation").exists());
    let dependency = replay
        .read_record::<CalibrationReplay>(replay.root(), &name("replay"))
        .unwrap()
        .unwrap();
    assert!(
        Path::new(dependency.record().source.as_str())
            .join("bundle")
            .exists()
    );
    assert!(!root.join("replays/0002").exists());
    assert_eq!(
        fs::read_to_string(case.path.join("replay-count")).unwrap(),
        "1"
    );
    // A replay record sealed while the state directory was named through
    // `..` retains that spelling when calibration resumes, with the
    // directory the `..` was spelled beneath gone.
    fs::create_dir(case.path.join("alias")).unwrap();
    let legacy = text(&dependency.record().source.as_str().replacen(
        case.state.to_str().unwrap(),
        &format!("{}/alias/../state", case.path.to_str().unwrap()),
        1,
    ));
    assert_ne!(legacy, dependency.record().source);
    {
        let store = Store::open(&case.state).unwrap();
        let roots = store
            .open_dir(store.root(), &name("calibrations"))
            .unwrap()
            .unwrap();
        let root = store
            .open_dir(&roots, &name(root.file_name().unwrap().to_str().unwrap()))
            .unwrap()
            .unwrap();
        let replays = store.open_dir(&root, &name("replays")).unwrap().unwrap();
        let first = store.open_dir(&replays, &name("0001")).unwrap().unwrap();
        let mut rewritten = dependency.record().clone();
        rewritten.source = legacy.clone();
        store
            .replace_record(&first, &name("replay"), &rewritten)
            .unwrap();
    }
    fs::remove_dir(case.path.join("alias")).unwrap();
    let result = case.calibrate();
    let replay = View::open(&replay_path).unwrap();
    assert_eq!(
        replay
            .read_record::<CalibrationReplay>(replay.root(), &name("replay"))
            .unwrap()
            .unwrap()
            .record()
            .source,
        legacy
    );
    assert_eq!(result.verdict, CalibrationVerdict::Refused);
    assert_eq!(result.replays.len(), 2);
    assert_eq!(result.replays[0].finished.class, Class::Interrupted);
    assert_eq!(result.replays[1].finished.class, Class::Pass);
    assert!(!case.state.join("capacity").exists());
    assert_eq!(
        fs::read_to_string(case.path.join("replay-count")).unwrap(),
        "2"
    );
    assert!(result.defects.is_empty());
    case.queued("3", None);
    let next = case.command("calibrate", &["--profile", "long", "--run", "2"]);
    case.require(&next, 0);
    let next: Calibration = serde_json::from_slice(&next.stdout).unwrap();
    assert_eq!(next.verdict, CalibrationVerdict::Calibrated);
    assert_ne!(next.root, result.root);
    assert_eq!(next.contract, result.contract);
    let capacity = View::open(
        &case
            .state
            .join("capacity")
            .join(next.contract.key().to_string()),
    )
    .unwrap();
    let capacity = capacity
        .read_record::<Capacity>(capacity.root(), &name(&next.root.to_string()))
        .unwrap()
        .unwrap();
    assert_eq!(capacity.record().root(), next.root);
    case.require(&case.configure(2), 0);
    let shown = case.command("show", &[]);
    case.require(&shown, 0);
    let shown: serde_json::Value = serde_json::from_slice(&shown.stdout).unwrap();
    let roots = shown["calibrations"].as_array().unwrap();
    assert_eq!(roots.len(), 2);
    assert!(
        roots
            .iter()
            .any(|root| root["id"] == result.root.to_string() && root["verdict"] == "refused")
    );
    assert!(
        roots
            .iter()
            .any(|root| root["id"] == next.root.to_string() && root["verdict"] == "calibrated")
    );
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(crate) fn unsealed_replay_disagreement_blocks_every_later_capacity_root() {
    let case = Case::new("partial-defect");
    fs::write(case.path.join("first-drift"), "yes").unwrap();
    fs::write(case.path.join("pause-second-replay"), "yes").unwrap();
    let mut controller = Command::new(env!("CARGO_BIN_EXE_campaign"))
        .args(["calibrate", "--profile", "long", "--run", "1", "--state"])
        .arg(&case.state)
        .arg("--archive")
        .arg(super::cases::archive())
        .arg("--cgroup-root")
        .arg(&case.root)
        .env(PLAN, &case.path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    while !case.path.join("replay-entered").exists() {
        assert!(controller.try_wait().unwrap().is_none());
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    controller.kill().unwrap();
    controller.wait().unwrap();
    let original = fs::read_dir(case.state.join("calibrations"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    assert!(!original.join("result").exists());
    let first = View::open(&original.join("replays/0001")).unwrap();
    let first = first
        .read_record::<Finished>(first.root(), &name("finished"))
        .unwrap()
        .unwrap();
    assert_eq!(first.record().exit, Some(1));
    fs::remove_file(case.path.join("first-drift")).unwrap();
    fs::remove_file(case.path.join("pause-second-replay")).unwrap();
    fs::write(
        case.path.join("healthy/inspect-replay.out"),
        COUNTING.replace("profile: upload", "profile: long"),
    )
    .unwrap();
    case.require(
        &case.command("dispatch", &["--for", "0.001", "--max-attempts", "0"]),
        0,
    );
    case.queued("3", None);
    let later = case.command("calibrate", &["--profile", "long", "--run", "2"]);
    case.require(&later, 0);
    let later: Calibration = serde_json::from_slice(&later.stdout).unwrap();
    assert_eq!(later.verdict, CalibrationVerdict::Calibrated);
    assert!(!original.join("result").exists());
    let shown = case.command("show", &[]);
    case.require(&shown, 0);
    let shown: serde_json::Value = serde_json::from_slice(&shown.stdout).unwrap();
    assert!(
        shown["calibrations"]
            .as_array()
            .unwrap()
            .iter()
            .any(
                |root| root["id"] == original.file_name().unwrap().to_str().unwrap()
                    && root["verdict"] == "unsealed"
            )
    );
}

pub(super) fn tree_bytes(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    fn walk(root: &Path, path: &Path, rows: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
        rows.insert(path.strip_prefix(root).unwrap().to_owned(), None);
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if entry.file_type().unwrap().is_dir() {
                walk(root, &path, rows);
            } else {
                rows.insert(
                    path.strip_prefix(root).unwrap().to_owned(),
                    Some(fs::read(&path).unwrap()),
                );
            }
        }
    }
    let mut rows = BTreeMap::new();
    walk(root, root, &mut rows);
    rows
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(crate) fn calibration_replay_panic_is_a_release_blocker_with_root_provenance() {
    let case = Case::new("replay-product-failure");
    {
        let store = Store::open(&case.state).unwrap();
        store.mkdir(store.root(), &name("calibrations")).unwrap();
        let roots = store
            .open_dir(store.root(), &name("calibrations"))
            .unwrap()
            .unwrap();
        for id in ["00".repeat(32), "01".repeat(32)] {
            store.mkdir(&roots, &name(&id)).unwrap();
            if id.starts_with("01") {
                let root = store.open_dir(&roots, &name(&id)).unwrap().unwrap();
                store.create_once(&root, &name("plan"), b"damaged").unwrap();
            }
        }
    }
    fs::write(case.path.join("replay-panic"), "yes").unwrap();
    let record = case.calibrate();
    assert_eq!(record.verdict, CalibrationVerdict::Refused);
    assert!(!record.defects.is_empty());
    assert_eq!(record.replays.len(), 2);
    for command in ["findings", "report"] {
        let output = case.command(command, &[]);
        case.require(&output, 0);
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        for number in 1..=2 {
            let id = format!("{}-calibration-replay-{number:04}", record.root);
            assert!(
                report["release_blockers"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|entry| entry == &id)
            );
            let row = report["findings"]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["id"] == id)
                .unwrap();
            assert_eq!(row["verified"]["kind"], "panic");
            assert_eq!(row["verified"]["calibration_root"], record.root.to_string());
            assert_eq!(row["blocker"], true);
            assert!(row.get("held").is_none());
        }
    }
    let id = format!("{}-calibration-replay-0001", record.root);
    for damage in ["harness", "held"] {
        {
            let store = Store::open(&case.state).unwrap();
            let findings = store
                .open_dir(store.root(), &name("findings"))
                .unwrap()
                .unwrap();
            let finding = store.open_dir(&findings, &name(&id)).unwrap().unwrap();
            if damage == "harness" {
                let disposition = campaign_supervisor::record::Disposition::new(
                    text(&id),
                    1,
                    campaign_supervisor::record::Decision::Harness,
                    text("replay harness evidence"),
                )
                .unwrap();
                store
                    .create_record(&finding, &name("0001.disposition.json"), &disposition)
                    .unwrap();
            } else {
                store
                    .replace(&finding, &name("finding.json"), b"damaged")
                    .unwrap();
            }
        }
        let output = case.command("report", &[]);
        case.require(&output, 0);
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let healthy = report["jobs"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["id"] == record.root.to_string())
            .unwrap();
        assert_eq!(healthy["credited"], true, "{damage}: {report}");
        assert!(
            report["release_blockers"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row == &id)
        );
    }
    let id = format!("{}-calibration-replay-0001", record.root);
    let replay = case
        .state
        .join("calibrations")
        .join(record.root.to_string())
        .join("replays/0001");
    fs::remove_dir_all(case.state.join("findings").join(&id)).unwrap();
    fs::remove_file(replay.join("captured")).unwrap();
    let control_id = record.controls[&text("long-planted")]
        .finished
        .attempt
        .as_str();
    fs::remove_dir_all(case.state.join("findings").join(control_id)).unwrap();
    fs::remove_file(
        case.state
            .join(crate::sharded::attempts_dir(
                record.controls[&text("long-planted")].job.to_string(),
            ))
            .join("0001/captured"),
    )
    .unwrap();
    let output = case.command("findings", &[]);
    case.require(&output, 0);
    let pending: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        pending["release_blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry == &id)
    );
    case.require(&case.command("dispatch", &[]), 0);
    let output = case.command("findings", &[]);
    case.require(&output, 0);
    let recovered: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let row = recovered["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == *id)
        .unwrap();
    assert_eq!(row["verified"]["calibration_root"], record.root.to_string());
    assert!(row.get("held").is_none());
    // The settled control job is settled by its result's name, so dispatch
    // leaves its lost capture to the findings scan, which keeps it a blocker.
    assert!(
        recovered["release_blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry == control_id)
    );
    assert!(
        case.state
            .join("findings")
            .join(&id)
            .join("input")
            .is_file()
    );
    let pending = recovered["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == control_id)
        .unwrap();
    assert_eq!(pending["held_code"], "capture-missing", "{recovered}");
    assert!(
        !case
            .state
            .join("findings")
            .join(control_id)
            .join("finding.json")
            .exists()
    );
    let control_job = control_id.rsplit_once('-').unwrap().0;
    let control_result = case.state.join(crate::sharded::job_file(format!(
        "{control_job}.result.json"
    )));
    fs::remove_file(&control_result).unwrap();
    case.require(&case.command("dispatch", &[]), 0);
    let output = case.command("findings", &[]);
    case.require(&output, 0);
    let recovered: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let control = recovered["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == control_id)
        .unwrap();
    assert!(control.get("verified").is_some(), "{recovered}");
    assert!(control.get("held").is_none(), "{recovered}");
    assert_eq!(
        control["verified"]["calibration_root"],
        record.root.to_string(),
        "{recovered}"
    );
    assert!(control_result.is_file());
    assert!(
        case.state
            .join("findings")
            .join(control_id)
            .join("finding.json")
            .is_file()
    );
    let path = case.state.join("findings").join(&id).join("finding.json");
    {
        let store = Store::open(&case.state).unwrap();
        let findings = store
            .open_dir(store.root(), &name("findings"))
            .unwrap()
            .unwrap();
        let directory = store.open_dir(&findings, &name(&id)).unwrap().unwrap();
        let mut legacy = store
            .read_record::<campaign_supervisor::record::Finding>(&directory, &name("finding.json"))
            .unwrap()
            .unwrap()
            .record()
            .clone();
        legacy.calibration_root = None;
        store
            .replace_record(&directory, &name("finding.json"), &legacy)
            .unwrap();
    }
    fs::remove_file(replay.join("captured")).unwrap();
    let legacy_bytes = fs::read(&path).unwrap();
    case.require(&case.command("dispatch", &[]), 0);
    assert_eq!(fs::read(&path).unwrap(), legacy_bytes);
    {
        let store = Store::open(&case.state).unwrap();
        let findings = store
            .open_dir(store.root(), &name("findings"))
            .unwrap()
            .unwrap();
        let directory = store.open_dir(&findings, &name(&id)).unwrap().unwrap();
        let mut changed = store
            .read_record::<campaign_supervisor::record::Finding>(&directory, &name("finding.json"))
            .unwrap()
            .unwrap()
            .record()
            .clone();
        changed.kind = campaign_supervisor::record::FindingKind::Harness;
        store
            .replace_record(&directory, &name("finding.json"), &changed)
            .unwrap();
    }
    fs::remove_file(replay.join("captured")).unwrap();
    let changed_bytes = fs::read(&path).unwrap();
    let output = case.command("dispatch", &[]);
    case.require(&output, 0);
    let held: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        held["calibration_held"]
            .get(record.root.to_string())
            .is_some()
    );
    assert_eq!(fs::read(&path).unwrap(), changed_bytes);
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(crate) fn undetected_control_preserves_its_release_blocker() {
    let case = Case::new("undetected-control");
    for phase in ["bundle", "run", "inspect"] {
        let path = case.path.join("fault").join(format!("{phase}.out"));
        let output = fs::read_to_string(&path)
            .unwrap()
            .replace("identity: 020101", "identity: 020102");
        fs::write(path, output).unwrap();
    }
    let record = case.calibrate();
    assert_eq!(record.verdict, CalibrationVerdict::Refused);
    assert!(!record.defects.is_empty());
    assert!(record.detected.is_empty());
    let id = record.controls[&text("long-planted")]
        .finished
        .attempt
        .as_str();
    let output = case.command("findings", &[]);
    case.require(&output, 0);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["release_blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry == id)
    );
    let row = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == id)
        .unwrap();
    assert_eq!(row["verified"]["kind"], "violation");
    assert_eq!(row["blocker"], true);
    assert!(row["dispositions"].as_array().unwrap().is_empty());
}
