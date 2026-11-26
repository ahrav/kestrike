use super::{Case, archive, name, text};
use crate::sim_worker::{COUNTING, PLAN, bundle};
use campaign_supervisor::archive::Archive;
use campaign_supervisor::record::{
    Configuration, CorpusProbe, Digest, Intent, ProbeFinished, ProbeOutcome, Reservation, Started,
};
use campaign_supervisor::store::{Store, View};
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{Duration, Instant};

struct Corpus {
    case: Case,
    bundle: PathBuf,
    config: Configuration,
}

impl Corpus {
    fn new() -> Self {
        Self::with_cores(2)
    }
    fn with_cores(cores: u64) -> Self {
        let case = Case::new("unused");
        let config = Configuration::new(
            [
                ("slots", 1),
                ("reserve_slots", 1),
                ("cores", cores),
                ("memory", 512 << 20),
                ("cpu", 60),
                ("tree_memory", 128 << 20),
                ("attempt_output", 16 << 20),
                ("attempt_inodes", 200),
                ("wall", 120),
                ("processes", 64),
                ("artifact_bytes", 1 << 30),
                ("artifact_inodes", 10000),
                ("backlog", 2),
                ("retained_builds", 1),
                ("corpus_count", 4),
                ("corpus_bytes", 32 << 20),
            ]
            .into_iter()
            .map(|(key, value)| (text(key), value))
            .collect(),
        )
        .unwrap();
        fs::write(
            case.path.join("capabilities.out"),
            include_str!("../../testdata/admission-listing.txt"),
        )
        .unwrap();
        fs::write(case.path.join("inspect.out"), COUNTING).unwrap();
        let bundle = case.path.join("offered");
        let fixture = Self {
            case,
            bundle,
            config,
        };
        fixture.configure(fixture.config.clone());
        fixture.input(1, 0);
        fixture
    }
    fn configure(&self, config: Configuration) {
        let store = Store::open(&self.case.path.join("state")).unwrap();
        campaign_supervisor::campaign::configure(&store, config).unwrap();
    }
    fn limits(&self, key: &str, value: u64) {
        let mut settings = self.config.config().clone();
        settings.insert(text(key), value);
        self.configure(Configuration::new(settings).unwrap());
    }
    fn input(&self, root: u64, trajectory: u8) {
        self.input_records(root, trajectory, 2);
    }
    fn input_records(&self, root: u64, trajectory: u8, body: usize) {
        let pins = Archive::load(archive()).unwrap().pins();
        let records = body.saturating_add(1000).max(10000);
        let budget = (records * 48).max(1 << 20);
        let manifest = format!(
            "version = 2\nprofile = upload\nroot = {root}\nexecutable = {}\ntoolchain = {}\nbuild = {}\nplatform = {}\nbytes = {budget}\nevery = 1\npending = 1\nrecords = {records}\nring = 1\nturns = 1\n",
            pins.executable.as_str(),
            pins.toolchain.as_str(),
            pins.build.as_str(),
            pins.platform.as_str()
        );
        let mut bytes = bundle(&manifest, body);
        let turn = bytes.len() - 96;
        bytes[turn + 5] = trajectory;
        let semantic = bytes.len() / 48 - 1;
        let prefix = Digest::of(&bytes[..bytes.len() - 48]);
        let child = Digest::of(b"child");
        fs::write(&self.bundle, &bytes).unwrap();
        fs::write(self.case.path.join("branch.out"), format!("milestone: pending-put boundary=13 semantic={semantic} decisions=1 prefix={prefix}\nwitness: pending-put holds=true boundary=13 upload=attempt:1,grant:3,held:2,outcome:0 armed=false\nparent: reproduced\nchild: suffix=0 sibling=0 class=success digest={child} terminal=complete pass fired=03 required=03\nbranch: 1 children, 1 credited, 0 problems\n")).unwrap();
    }
    fn command(&self, command: &str) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_campaign"));
        cmd.arg(command).env(PLAN, &self.case.path);
        cmd
    }
    fn add_command(&self) -> Command {
        let mut cmd = self.command("corpus");
        cmd.args(["add", "--state"])
            .arg(self.case.path.join("state"))
            .arg("--archive")
            .arg(archive())
            .arg("--bundle")
            .arg(&self.bundle)
            .args(["--milestone", "pending-put", "--cgroup-root"])
            .arg(&self.case.root);
        cmd
    }
    fn add(&self) -> Output {
        self.add_command().output().unwrap()
    }
    fn remove(&self, id: &str) -> Output {
        self.command("corpus")
            .args(["remove", "--state"])
            .arg(self.case.path.join("state"))
            .args(["--asset", id])
            .output()
            .unwrap()
    }
    fn report(&self) -> serde_json::Value {
        let output = self
            .command("report")
            .arg("--state")
            .arg(self.case.path.join("state"))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }
    fn probes(&self) -> Vec<PathBuf> {
        let path = self.case.path.join("state/probes");
        if !path.exists() {
            return vec![];
        }
        let mut paths: Vec<_> = fs::read_dir(path)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        paths.sort();
        paths
    }
    fn started(&self, path: &std::path::Path) {
        let view = View::open(&self.case.path.join("state")).unwrap();
        let probes = view
            .open_dir(view.root(), &name("probes"))
            .unwrap()
            .unwrap();
        let dir = view
            .open_dir(&probes, &name(path.file_name().unwrap().to_str().unwrap()))
            .unwrap()
            .unwrap();
        let started = view
            .read_record::<Started>(&dir, &name("started"))
            .unwrap()
            .unwrap();
        let intent = view
            .read_record::<Intent>(&dir, &name("intent"))
            .unwrap()
            .unwrap();
        assert_eq!(started.record().attempt, intent.record().attempt);
        assert_eq!(started.record().boot, intent.record().boot);
        assert_eq!(started.record().cgroup, intent.record().cgroup);
        assert!(
            view.read_record::<CorpusProbe>(&dir, &name("corpus-probe"))
                .unwrap()
                .is_some()
        );
    }
    fn recover_version(&self, number: u64) {
        let version = self
            .case
            .path
            .join("state/corpus/versions")
            .join(number.to_string());
        let original = fs::read(&version).unwrap();
        fs::remove_file(&version).unwrap();
        let report = self.report();
        assert_eq!(report["corpus"]["version"], number - 1);
        assert_eq!(report["corpus"]["assets"][0]["eligible"], false);
        if number == 1 {
            assert!(report["corpus"]["assets"][0]["version"].is_null());
        }
        assert!(!version.exists());
        let output = self.remove(&Digest::of(b"unknown asset").to_string());
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains("unknown corpus asset"));
        assert_eq!(fs::read(version).unwrap(), original);
    }
    fn admitted(&self) -> String {
        let before: std::collections::BTreeSet<_> = self.probes().into_iter().collect();
        let output = self.add();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["version"], 1);
        assert_eq!(result["state"], "registered");
        let mut bytes = 0;
        let mut inodes = 1;
        let mut pending: Vec<_> = self
            .probes()
            .into_iter()
            .filter(|path| !before.contains(path))
            .collect();
        assert_eq!(pending.len(), 1);
        let state = View::open(&self.case.path.join("state")).unwrap();
        let installed = state
            .read_record::<Configuration>(state.root(), &name("config.json"))
            .unwrap()
            .unwrap();
        let installed = installed.record();
        while let Some(path) = pending.pop() {
            for entry in fs::read_dir(path).unwrap() {
                let entry = entry.unwrap();
                let metadata = entry.metadata().unwrap();
                inodes += 1;
                if metadata.is_dir() {
                    pending.push(entry.path());
                } else {
                    bytes += metadata.len();
                }
            }
        }
        // Corpus probes include the staged bundle as well as worker output.
        assert!(
            bytes <= 2 * installed.value("attempt_output") + (15 << 20),
            "{bytes} bytes"
        );
        assert!(
            inodes <= 2 * installed.value("attempt_inodes") + 17,
            "{inodes} inodes"
        );
        assert!(bytes >= fs::metadata(&self.bundle).unwrap().len());
        if fs::metadata(&self.bundle).unwrap().len() > (8 << 20) {
            assert!(bytes > (8 << 20), "{bytes} bytes");
        }
        result["asset"].as_str().unwrap().to_owned()
    }
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(crate) fn corpus_registration_retirement_and_report_keep_frozen_roots() {
    let large = Corpus::new();
    large.limits("attempt_output", 32 << 20);
    large.input_records(1, 0, 200_000);
    large.admitted();
    let boundary = Corpus::new();
    boundary.admitted();
    for (index, dimension) in ["artifact_bytes", "artifact_inodes"]
        .into_iter()
        .enumerate()
    {
        boundary.input(index as u64 + 2, index as u8 + 1);
        let rate = if dimension == "artifact_bytes" {
            2 * boundary.config.value("attempt_output") + (15 << 20)
        } else {
            2 * boundary.config.value("attempt_inodes") + 17
        };
        let threshold = (boundary.probes().len() as u64 + 2) * rate;
        boundary.limits(dimension, threshold);
        let before = crate::calibration::tree_bytes(&boundary.case.path.join("state"));
        let refused = boundary.add();
        assert_eq!(refused.status.code(), Some(2));
        assert!(
            String::from_utf8_lossy(&refused.stderr)
                .contains(&format!("corpus probe capacity: {dimension}"))
        );
        assert_eq!(
            crate::calibration::tree_bytes(&boundary.case.path.join("state")),
            before
        );
        boundary.limits(dimension, threshold + 1);
        let admitted = boundary.add();
        assert!(
            admitted.status.success(),
            "{}",
            String::from_utf8_lossy(&admitted.stderr)
        );
    }

    let fixture = Corpus::new();
    let add = fixture.add_command();
    let refused = Command::new("bash")
        .args([
            "-c",
            "ulimit -S -f 512; ulimit -H -f 512; exec \"$@\"",
            "bash",
        ])
        .arg(add.get_program())
        .args(add.get_args())
        .env(PLAN, &fixture.case.path)
        .output()
        .unwrap();
    assert_eq!(
        refused.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    assert!(
        String::from_utf8_lossy(&refused.stderr)
            .contains("corpus controller RLIMIT_FSIZE cannot hold records")
    );
    assert!(fixture.probes().is_empty());
    assert!(!fixture.case.path.join("calls").exists());
    let fixture = Corpus::new();
    fixture.input_records(1, 0, 32);
    assert!(fs::metadata(&fixture.bundle).unwrap().len() > 1024);
    let add = fixture.add_command();
    let output = Command::new("bash")
        .args(["-c", "ulimit -S -f 1; exec \"$@\"", "bash"])
        .arg(add.get_program())
        .args(add.get_args())
        .env(PLAN, &fixture.case.path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let admitted: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let low_limit_id = admitted["asset"].as_str().unwrap();
    assert!(fixture.remove(low_limit_id).status.success());
    let fixture = Corpus::new();
    let help = fixture.command("corpus").arg("--help").output().unwrap();
    assert!(help.status.success());
    let help = String::from_utf8(help.stdout).unwrap();
    assert!(help.starts_with("usage: campaign corpus add"));
    assert!(help.contains("corpus_bytes"));
    assert!(help.contains("frees one corpus_count slot"));
    assert!(help.contains("four 1 MiB stream bounds"));
    for form in ["add", "remove"] {
        let help_output = fixture
            .command("corpus")
            .args([form, "--help"])
            .output()
            .unwrap();
        assert!(help_output.status.success());
        assert_eq!(String::from_utf8(help_output.stdout).unwrap(), help);
    }

    let id = fixture.admitted();
    let probe = fixture.probes().pop().unwrap();
    fixture.started(&probe);
    assert!(!probe.join("reservation").exists());
    let original_bundle = fs::read(probe.join("bundle")).unwrap();
    let original_manifest = fs::read(probe.join("manifest")).unwrap();
    let asset_path = fixture
        .case
        .path
        .join("state/corpus/assets")
        .join(&id)
        .join("asset");
    let original_asset = fs::read(&asset_path).unwrap();
    fixture.recover_version(1);
    let report = fixture.report();
    assert_eq!(report["corpus"]["assets"][0]["state"], "registered");
    assert_eq!(report["corpus"]["assets"][0]["eligible"], true);
    assert_eq!(report["corpus"]["probes"][0]["state"], "verified");
    assert!(report["held"].as_array().unwrap().is_empty(), "{report}");
    let removed = fixture.remove(&id);
    assert!(
        removed.status.success(),
        "{}",
        String::from_utf8_lossy(&removed.stderr)
    );
    let removed: serde_json::Value = serde_json::from_slice(&removed.stdout).unwrap();
    assert_eq!(removed["version"], 2);
    fixture.recover_version(2);
    assert_eq!(fs::read(probe.join("bundle")).unwrap(), original_bundle);
    assert_eq!(fs::read(probe.join("manifest")).unwrap(), original_manifest);
    assert_eq!(fs::read(&asset_path).unwrap(), original_asset);
    let report = fixture.report();
    assert_eq!(report["corpus"]["assets"][0]["state"], "retired");
    assert_eq!(report["corpus"]["assets"][0]["eligible"], false);
    assert_eq!(report["corpus"]["version"], 2);
    let bundle_path = report["corpus"]["assets"][0]["bundle"].as_str().unwrap();
    assert_eq!(
        fs::read(fixture.case.path.join("state").join(bundle_path)).unwrap(),
        original_bundle
    );
    assert_eq!(fixture.remove(&id).status.code(), Some(0));
    assert_eq!(fixture.report()["corpus"]["version"], 2);
    fs::write(&asset_path, b"broken").unwrap();
    let report = fixture.report();
    assert!(report["corpus"]["assets"].as_array().unwrap().is_empty());
    assert!(
        report["held"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["path"] == "corpus")
    );
    fs::write(fixture.case.path.join("action"), "admission-pass").unwrap();
    let ordinary = super::admission_command(&fixture.case)
        .args(["--attempts", "1"])
        .output()
        .unwrap();
    assert!(
        ordinary.status.success(),
        "{}",
        String::from_utf8_lossy(&ordinary.stderr)
    );
    let ordinary: serde_json::Value = serde_json::from_slice(&ordinary.stdout).unwrap();
    let job = ordinary["id"].as_str().unwrap();
    fs::write(fixture.case.path.join("action"), "campaign-pass").unwrap();
    let dispatch = || {
        Command::new(env!("CARGO_BIN_EXE_campaign"))
            .args(["dispatch", "--state"])
            .arg(fixture.case.path.join("state"))
            .arg("--archive")
            .arg(archive())
            .arg("--cgroup-root")
            .arg(&fixture.case.root)
            .args(["--poll", "0.001", "--kill-wait", "2", "--max-attempts", "1"])
            .env("CAMPAIGN_CUSTODY_WORKER", &fixture.case.path)
            .output()
            .unwrap()
    };
    fs::write(probe.join("reservation"), b"damaged").unwrap();
    let held = dispatch();
    assert_eq!(
        held.status.code(),
        Some(4),
        "{}",
        String::from_utf8_lossy(&held.stderr)
    );
    assert!(
        !fixture
            .case
            .path
            .join("state")
            .join(crate::sharded::attempts_dir(job))
            .exists()
    );
    fs::remove_file(probe.join("reservation")).unwrap();
    let ran = dispatch();
    assert!(
        ran.status.success(),
        "{}",
        String::from_utf8_lossy(&ran.stderr)
    );
    assert!(
        fixture
            .case
            .path
            .join("state")
            .join(crate::sharded::attempts_dir(job))
            .join("0001/started")
            .exists()
    );
    assert_eq!(fs::read(&asset_path).unwrap(), b"broken");
    let findings = fixture
        .command("findings")
        .arg("--state")
        .arg(fixture.case.path.join("state"))
        .output()
        .unwrap();
    assert!(findings.status.success());
    let findings: serde_json::Value = serde_json::from_slice(&findings.stdout).unwrap();
    assert!(
        findings["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == "corpus" && row["blocker"] == true)
    );
    assert!(
        findings["release_blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|id| id == "corpus")
    );
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(crate) fn corpus_duplicate_semantics_and_caps_refuse_at_reached_guards() {
    let reserve = Corpus::new();
    let share = 2 * reserve.config.file_bytes()
        + 8 * campaign_supervisor::record::BOUND
        + campaign_supervisor::record::Kind::Captured.bound()
        + campaign_supervisor::record::Kind::Finding.bound()
        + campaign_supervisor::record::Kind::Reclaimed.bound();
    let mut settings = reserve.config.config().clone();
    settings.insert(text("corpus_bytes"), 1 << 20);
    settings.insert(text("artifact_bytes"), 2 * share + (1 << 20) + 1);
    let config = Configuration::new(settings).unwrap();
    reserve.configure(config.clone());
    let fitting = Corpus::new();
    fitting.configure(config);
    let admitted = fitting.add();
    assert!(
        admitted.status.success(),
        "{}",
        String::from_utf8_lossy(&admitted.stderr)
    );
    let retained = reserve.case.path.join("state/probes/corpus-probe-retained");
    fs::create_dir_all(&retained).unwrap();
    fs::write(retained.join("bundle"), vec![0; 2 << 20]).unwrap();
    let before = reserve.probes().len();
    let output = reserve.add();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("artifact_bytes"));
    assert_eq!(reserve.probes().len(), before);
    assert!(!reserve.case.path.join("calls").exists());
    let fixture = Corpus::new();
    let id = fixture.admitted();
    fixture.input(2, 0);
    let output = fixture.add();
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("semantic state"));
    assert_eq!(fixture.probes().len(), 2);
    for probe in fixture.probes() {
        fixture.started(&probe);
        assert!(!probe.join("reservation").exists());
    }
    assert_eq!(
        fixture.report()["corpus"]["assets"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(fixture.report()["corpus"]["version"], 1);
    assert!(fixture.remove(&id).status.success());
    let output = fixture.add();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("semantic state"));
    assert_eq!(fixture.report()["corpus"]["version"], 2);
    fixture.input(3, 7);
    fixture.limits("corpus_bytes", 1);
    let before = fixture.probes().len();
    let output = fixture.add();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("byte limit"));
    assert_eq!(fixture.probes().len(), before);
    fixture.limits("corpus_count", 1);
    let output = fixture.add();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    fixture.input(4, 8);
    let before = fixture.probes().len();
    let output = fixture.add();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("count limit"));
    assert_eq!(fixture.probes().len(), before);
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(crate) fn corpus_failed_prefix_and_interruption_keep_history_without_admission() {
    for replacement in [
        "upload=none",
        "upload=attempt:1,grant:3,held:0,outcome:0",
        "upload=attempt:1,grant:3,held:2,outcome:1",
    ] {
        let fixture = Corpus::new();
        let output = fs::read_to_string(fixture.case.path.join("branch.out")).unwrap();
        fs::write(
            fixture.case.path.join("branch.out"),
            output.replace("upload=attempt:1,grant:3,held:2,outcome:0", replacement),
        )
        .unwrap();
        let refused = fixture.add();
        assert_eq!(
            refused.status.code(),
            Some(2),
            "{}",
            String::from_utf8_lossy(&refused.stderr)
        );
        assert!(
            String::from_utf8_lossy(&refused.stderr)
                .contains("corpus witness facts do not satisfy the milestone")
        );
        let probe = fixture.probes().pop().unwrap();
        assert!(probe.join("finished").exists());
        assert!(!probe.join("reservation").exists());
        assert_eq!(fixture.report()["corpus"]["version"], 0);
        assert!(
            fixture.report()["corpus"]["assets"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }
    let fixture = Corpus::new();
    let branch = fs::read_to_string(fixture.case.path.join("branch.out")).unwrap();
    let prefix = branch
        .split("prefix=")
        .nth(1)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap();
    fs::write(
        fixture.case.path.join("branch.out"),
        branch.replace(prefix, &Digest::of(b"wrong").to_string()),
    )
    .unwrap();
    let failed = fixture.add();
    assert_eq!(
        failed.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&failed.stderr)
    );
    assert!(
        String::from_utf8_lossy(&failed.stderr)
            .contains("corpus prefix differs from the frozen bundle")
    );
    let probe = fixture.probes().pop().unwrap();
    fixture.started(&probe);
    assert!(probe.join("finished").exists());
    assert!(!probe.join("reservation").exists());
    assert_eq!(fixture.report()["corpus"]["version"], 0);
    assert!(
        fixture.report()["corpus"]["assets"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    fixture.input(1, 0);
    fs::write(fixture.case.path.join("branch.action"), "wait-for-release").unwrap();
    let mut child = fixture.add_command().spawn().unwrap();
    let began = Instant::now();
    loop {
        let calls = fs::read_to_string(fixture.case.path.join("calls")).unwrap_or_default();
        if calls.lines().filter(|line| *line == "branch").count() == 2 {
            break;
        }
        assert!(began.elapsed() < Duration::from_secs(60));
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(child.wait().unwrap().code(), Some(4));
    assert_eq!(fixture.probes().len(), 2);
    for probe in fixture.probes() {
        fixture.started(&probe);
        assert!(probe.join("finished").exists());
        assert!(!probe.join("reservation").exists());
    }
    let report = fixture.report();
    assert_eq!(report["corpus"]["version"], 0);
    assert!(report["corpus"]["assets"].as_array().unwrap().is_empty());
    assert_eq!(report["corpus"]["probes"].as_array().unwrap().len(), 2);
    assert!(
        report["corpus"]["probes"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["state"] == "held")
    );
    fs::remove_file(fixture.case.path.join("branch.action")).unwrap();
    fixture.input(1, 0);
    let printed = fs::read_to_string(fixture.case.path.join("branch.out"))
        .unwrap()
        .lines()
        .map(|line| {
            if line.starts_with("child:") {
                "child: suffix=0 sibling=0 class=failed"
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        .replace("1 children, 1 credited", "1 children, 0 credited")
        + "\n";
    fs::write(fixture.case.path.join("branch.out"), printed).unwrap();
    fs::write(fixture.case.path.join("branch.exit"), "1").unwrap();
    fixture.admitted();
    assert_eq!(fixture.probes().len(), 3);
    assert_eq!(
        fixture.report()["corpus"]["probes"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["state"] == "verified")
            .count(),
        1
    );
    for (exit, expected, reason) in [
        ("2", 2, "corpus probe refused"),
        ("3", 4, "corpus probe incomplete"),
    ] {
        fixture.input(2, 7);
        fs::write(fixture.case.path.join("branch.out"), "").unwrap();
        fs::write(fixture.case.path.join("branch.exit"), exit).unwrap();
        let before = fixture.probes();
        let output = fixture.add();
        assert_eq!(output.status.code(), Some(expected));
        assert!(String::from_utf8_lossy(&output.stderr).contains(reason));
        let probe = fixture
            .probes()
            .into_iter()
            .find(|probe| !before.contains(probe))
            .unwrap();
        fixture.started(&probe);
        assert!(probe.join("finished").exists());
        assert!(!probe.join("reservation").exists());
        assert_eq!(fixture.report()["corpus"]["version"], 1);
    }
    fixture.input(3, 8);
    fs::write(fixture.case.path.join("branch.exit"), "0").unwrap();
    fs::write(fixture.case.path.join("branch.action"), "hang").unwrap();
    fixture.limits("wall", 30);
    let calls = fs::read_to_string(fixture.case.path.join("calls"))
        .unwrap()
        .lines()
        .filter(|line| *line == "branch")
        .count();
    let before = fixture.probes();
    let output = fixture.add();
    assert_eq!(output.status.code(), Some(4));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("corpus probe interrupted or timed out")
    );
    assert_eq!(
        fs::read_to_string(fixture.case.path.join("calls"))
            .unwrap()
            .lines()
            .filter(|line| *line == "branch")
            .count(),
        calls + 1
    );
    let probe = fixture
        .probes()
        .into_iter()
        .find(|probe| !before.contains(probe))
        .unwrap();
    fixture.started(&probe);
    assert!(probe.join("finished").exists());
    assert!(!probe.join("reservation").exists());
    assert_eq!(fixture.report()["corpus"]["version"], 1);
    fs::remove_file(fixture.case.path.join("branch.action")).unwrap();
    fixture.limits("wall", 120);
    let output = fixture.add();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fixture.report()["corpus"]["version"], 2);

    let limited = Corpus::new();
    fs::write(
        limited.case.path.join("branch.action"),
        "corpus-output-limit",
    )
    .unwrap();
    let output = limited.add();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains(
        "corpus probe output-limit exceeds configured attempt_output or attempt_inodes limit"
    ));
    let probe = limited.probes().pop().unwrap();
    limited.started(&probe);
    assert_eq!(
        super::probe_record::<ProbeFinished>(&probe, "finished").outcome,
        ProbeOutcome::OutputLimit
    );
    assert!(!probe.join("reservation").exists());
    assert!(!limited.case.path.join("state/corpus/assets").exists());
    let report = limited.report();
    assert_eq!(report["corpus"]["version"], 0);
    assert!(report["corpus"]["assets"].as_array().unwrap().is_empty());
    assert_eq!(report["corpus"]["probes"][0]["state"], "output-limit");
    assert_eq!(report["corpus"]["probes"][0]["charged"], false);
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(crate) fn corpus_lost_probe_reservation_reconciles_before_new_registration() {
    let fixture = Corpus::new();
    fs::write(fixture.case.path.join("branch.action"), "wait-for-release").unwrap();
    let mut child = fixture.add_command().spawn().unwrap();
    let began = Instant::now();
    loop {
        if fs::read_to_string(fixture.case.path.join("calls"))
            .unwrap_or_default()
            .lines()
            .any(|line| line == "branch")
        {
            break;
        }
        assert!(began.elapsed() < Duration::from_secs(60));
        std::thread::sleep(Duration::from_millis(10));
    }
    child.kill().unwrap();
    assert_eq!(child.wait().unwrap().signal(), Some(libc::SIGKILL));
    let lost = fixture.probes().pop().unwrap();
    fixture.started(&lost);
    assert!(lost.join("reservation").exists());
    assert!(!lost.join("finished").exists());
    assert!(!fixture.case.path.join("state/corpus/assets").exists());
    let report = fixture.report();
    assert_eq!(report["corpus"]["probes"][0]["charged"], true);
    assert_eq!(report["corpus"]["probes"][0]["state"], "unfinished");
    assert_eq!(report["corpus"]["version"], 0);
    assert!(report["corpus"]["assets"].as_array().unwrap().is_empty());
    fs::remove_file(fixture.case.path.join("branch.action")).unwrap();
    fixture.admitted();
    assert_eq!(fixture.probes().len(), 2);
    assert!(!lost.join("reservation").exists());
    let view = View::open(&fixture.case.path.join("state")).unwrap();
    let probes = view
        .open_dir(view.root(), &name("probes"))
        .unwrap()
        .unwrap();
    let dir = view
        .open_dir(&probes, &name(lost.file_name().unwrap().to_str().unwrap()))
        .unwrap()
        .unwrap();
    assert_eq!(
        view.read_record::<ProbeFinished>(&dir, &name("finished"))
            .unwrap()
            .unwrap()
            .record()
            .outcome,
        ProbeOutcome::Held
    );
    assert!(
        view.read_record::<Reservation>(&dir, &name("reservation"))
            .unwrap()
            .is_none()
    );
    let report = fixture.report();
    assert_eq!(report["corpus"]["assets"].as_array().unwrap().len(), 1);
    assert_eq!(report["corpus"]["version"], 1);
    assert_eq!(report["corpus"]["probes"].as_array().unwrap().len(), 2);
}

use std::os::unix::process::ExitStatusExt;

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(crate) fn corpus_duplicate_bundles_preserve_version_and_skip_workers() {
    let fixture = Corpus::new();
    let id = fixture.admitted();
    for retired in [false, true] {
        if retired {
            assert!(fixture.remove(&id).status.success());
        }
        let before = fs::read_to_string(fixture.case.path.join("calls")).unwrap();
        let output = fixture.add();
        assert_eq!(output.status.code(), Some(2));
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("duplicate corpus bundle and milestone")
        );
        assert_eq!(
            fs::read_to_string(fixture.case.path.join("calls")).unwrap(),
            before
        );
        let report = fixture.report();
        assert_eq!(report["corpus"]["version"], if retired { 2 } else { 1 });
        assert_eq!(report["corpus"]["assets"].as_array().unwrap().len(), 1);
        let unfinished: Vec<_> = report["corpus"]["probes"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["state"] == "unfinished")
            .collect();
        assert_eq!(unfinished.len(), if retired { 2 } else { 1 });
        for row in unfinished {
            assert_eq!(row["charged"], false);
            assert!(row["record"].is_null());
        }
    }
    let boundary = Corpus::new();
    let bundle_bytes = fs::metadata(&boundary.bundle).unwrap().len();
    let bytes_at_bound = 2 * bundle_bytes + 4 * (1 << 20) + 7 * campaign_supervisor::record::BOUND;
    let inodes_at_bound = 2 + 12 + 12;
    for (bytes, inodes) in [
        (bytes_at_bound - 1, inodes_at_bound),
        (bytes_at_bound, inodes_at_bound - 1),
    ] {
        let mut settings = boundary.config.config().clone();
        settings.insert(text("attempt_output"), bytes);
        settings.insert(text("attempt_inodes"), inodes);
        boundary.configure(Configuration::new(settings).unwrap());
        let output = boundary.add();
        assert_eq!(output.status.code(), Some(2));
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("corpus probe attempt_output or attempt_inodes cannot hold")
        );
        assert!(!boundary.case.path.join("calls").exists());
        assert!(boundary.probes().iter().all(|probe| {
            !probe.join("intent").exists() && !probe.join("reservation").exists()
        }));
        assert_eq!(boundary.report()["corpus"]["version"], 0);
    }
    let mut settings = boundary.config.config().clone();
    settings.insert(text("attempt_output"), bytes_at_bound);
    settings.insert(text("attempt_inodes"), inodes_at_bound);
    boundary.configure(Configuration::new(settings).unwrap());
    boundary.admitted();
    assert_eq!(boundary.report()["corpus"]["version"], 1);
    assert_eq!(
        boundary.report()["corpus"]["assets"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    let retry = Corpus::new();
    retry.limits("corpus_bytes", 20000);
    let mut offered = fs::read(&retry.bundle).unwrap();
    for _ in 0..600 {
        let mut record = [0; 48];
        record[0] = 4;
        offered.extend_from_slice(&record);
    }
    fs::write(&retry.bundle, offered).unwrap();
    let output = retry.add();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("corpus bundle or manifest exceeds its bound")
    );
    assert_eq!(retry.probes().len(), 1);
    assert!(!retry.case.path.join("calls").exists());
    assert_eq!(retry.report()["corpus"]["version"], 0);
    retry.input(1, 0);
    retry.admitted();
    assert_eq!(retry.probes().len(), 2);
    assert_eq!(
        retry.report()["corpus"]["assets"].as_array().unwrap().len(),
        1
    );
}

impl Corpus {
    fn target(&self, asset: &str, run: u64, suffixes: u64) -> Output {
        self.command("admit")
            .args(["--state"])
            .arg(self.case.path.join("state"))
            .arg("--archive")
            .arg(archive())
            .args([
                "--target",
                asset,
                "--campaign",
                "targeted",
                "--run",
                &run.to_string(),
                "--suffixes",
                &suffixes.to_string(),
                "--siblings",
                "1",
                "--cgroup-root",
            ])
            .arg(&self.case.root)
            .output()
            .unwrap()
    }
    fn dispatch(&self) -> serde_json::Value {
        let output = self
            .command("dispatch")
            .arg("--state")
            .arg(self.case.path.join("state"))
            .arg("--archive")
            .arg(archive())
            .arg("--cgroup-root")
            .arg(&self.case.root)
            .args(["--max-attempts", "1", "--for", "30", "--poll", "0.01"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(crate) fn targeted_admission_freezes_versions_retirement_and_dispatch_roots() {
    let f = Corpus::with_cores(3);
    let help = f.command("admit").arg("--help").output().unwrap();
    assert!(help.status.success());
    let help = String::from_utf8(help.stdout).unwrap();
    assert!(help.contains("--target ASSET"));
    assert!(help.contains("--watchdog SECONDS"));
    assert!(help.contains("corpus version current at admission"));
    let asset = f.admitted();
    let branch = fs::read(f.case.path.join("branch.out")).unwrap();
    for (extra, said) in [
        (
            vec!["--target", asset.as_str(), "--explore", "--suffixes", "1"],
            "explore takes tree bounds from its asset",
        ),
        (vec!["--suffixes", "1"], "fork bounds require --target"),
        (
            vec!["--target", asset.as_str(), "--suffixes", "1"],
            "target profile comes from the asset",
        ),
        (
            vec!["--target", asset.as_str()],
            "targeted branch requires --suffixes or --explore",
        ),
    ] {
        let before = f.probes();
        let output = f
            .command("admit")
            .arg("--state")
            .arg(f.case.path.join("state"))
            .arg("--archive")
            .arg(archive())
            .args([
                "--campaign",
                "targeted",
                "--profile",
                "upload",
                "--cgroup-root",
            ])
            .arg(&f.case.root)
            .args(extra)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(said),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(f.probes(), before);
    }
    let first = f.target(&asset, 0, 1);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let admitted: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    let id = admitted["id"].as_str().unwrap();
    assert_eq!(admitted["seed"], 1);
    let root = f
        .case
        .path
        .join("state")
        .join(crate::sharded::job_file(id).parent().unwrap());
    let record = fs::read(root.join(format!("{id}.json"))).unwrap();
    let bundle = fs::read(root.join(format!("{id}.bundle"))).unwrap();
    let frozen_path = root.join(format!("{id}.bundle"));
    for corruption in [Some(b"changed target".as_slice()), None] {
        if let Some(bytes) = corruption {
            fs::write(&frozen_path, bytes).unwrap();
        } else {
            fs::remove_file(&frozen_path).unwrap();
        }
        let rejected = f.target(&asset, 0, 1);
        assert_eq!(rejected.status.code(), Some(4));
        assert!(String::from_utf8_lossy(&rejected.stderr).contains("frozen target bundle differs"));
        let dispatch = f
            .command("dispatch")
            .arg("--state")
            .arg(f.case.path.join("state"))
            .arg("--archive")
            .arg(archive())
            .arg("--cgroup-root")
            .arg(&f.case.root)
            .output()
            .unwrap();
        assert_eq!(dispatch.status.code(), Some(0));
        let report: serde_json::Value = serde_json::from_slice(&dispatch.stdout).unwrap();
        assert_eq!(report["started"], 0);
        assert!(
            report["unfit"][id]
                .as_str()
                .is_some_and(|reason| reason.contains("frozen target bundle differs"))
        );
        assert!(
            !f.case
                .path
                .join("state")
                .join(crate::sharded::attempts_dir(id))
                .exists()
        );
        fs::write(&frozen_path, &bundle).unwrap();
    }
    f.input(2, 1);
    let second_asset = f.add();
    assert!(
        second_asset.status.success(),
        "{}",
        String::from_utf8_lossy(&second_asset.stderr)
    );
    let second = f.target(&asset, 0, 1);
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    let second: serde_json::Value = serde_json::from_slice(&second.stdout).unwrap();
    assert_eq!(second["id"], admitted["id"]);
    assert_eq!(second["state"], "existing");
    assert_eq!(fs::read(root.join(format!("{id}.json"))).unwrap(), record);
    let changed = f.target(&asset, 0, 2);
    assert!(
        changed.status.success(),
        "{}",
        String::from_utf8_lossy(&changed.stderr)
    );
    let changed: serde_json::Value = serde_json::from_slice(&changed.stdout).unwrap();
    assert_ne!(changed["id"], admitted["id"]);
    assert!(f.remove(&asset).status.success());
    let probes = f.probes();
    let jobs = fs::read_dir(&root).unwrap().count();
    let rejected = f.target(&asset, 7, 1);
    assert_eq!(rejected.status.code(), Some(2));
    assert!(rejected.stdout.is_empty());
    assert_eq!(f.probes(), probes);
    assert_eq!(fs::read_dir(&root).unwrap().count(), jobs);
    let before_collect = f.report();
    let collection = f
        .command("collect")
        .arg("--state")
        .arg(f.case.path.join("state"))
        .output()
        .unwrap();
    assert!(
        collection.status.success(),
        "{}",
        String::from_utf8_lossy(&collection.stderr)
    );
    let collection: serde_json::Value = serde_json::from_slice(&collection.stdout).unwrap();
    assert_eq!(collection["held"], serde_json::json!([]), "{collection}");
    assert_eq!(f.report(), before_collect);
    assert_eq!(fs::read(root.join(format!("{id}.bundle"))).unwrap(), bundle);
    fs::write(f.case.path.join("branch.out"), &branch).unwrap();
    let dispatched = f.dispatch();
    assert_eq!(dispatched["started"], 1, "{dispatched}");
    assert_eq!(dispatched["completed"][0]["class"], "pass", "{dispatched}");
    let seen = fs::read_to_string(f.case.path.join("branch.seen")).unwrap();
    let args: Vec<String> = serde_json::from_str(
        seen.lines()
            .find_map(|line| line.strip_prefix("args="))
            .unwrap(),
    )
    .unwrap();
    let at = args.iter().position(|arg| arg == "--branch").unwrap();
    let staged = fs::read(&args[at + 1]).unwrap();
    assert_eq!(staged, bundle);
    assert!(
        args.windows(2)
            .any(|pair| pair == ["--milestone", "pending-put"])
    );
    assert!(args.windows(2).any(|pair| pair == ["--suffixes", "1"]));
    assert!(args.windows(2).any(|pair| pair == ["--siblings", "1"]));
    let launcher: Vec<String> = serde_json::from_str(
        seen.lines()
            .find_map(|line| line.strip_prefix("launcher_args="))
            .unwrap(),
    )
    .unwrap();
    let at = launcher.iter().position(|arg| arg == "branch").unwrap();
    assert_eq!(
        std::path::Path::new(&launcher[at + 1]),
        root.join(format!("{id}.bundle"))
    );
    assert_eq!(fs::read(root.join(format!("{id}.bundle"))).unwrap(), bundle);
    assert_eq!(fs::read(root.join(format!("{id}.json"))).unwrap(), record);
    let report = f.report();
    let row = report["targeted"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == id)
        .unwrap();
    assert_eq!(row["corpus_version"], 1);
    assert_eq!(row["credited"], true, "{report}");
    assert_eq!(row["judgment"]["printed"], 1);
    assert_eq!(row["judgment"]["credited"], 1);
    let status = campaign_supervisor::campaign::status(&f.case.path.join("state")).unwrap();
    let mut status_bytes = Vec::new();
    status.write(&mut status_bytes).unwrap();
    let status: serde_json::Value = serde_json::from_slice(&status_bytes).unwrap();
    assert!(
        !status["jobs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == id && row.get("held").is_some()),
        "{status}"
    );
    let unfit = f.dispatch();
    assert_eq!(unfit["started"], 0);
    assert!(
        unfit["unfit"]
            .get(changed["id"].as_str().unwrap())
            .is_some()
    );
    drop(f);
    let f = Corpus::with_cores(3);
    let asset = f.admitted();
    let targeted = f.target(&asset, 0, 1);
    assert!(targeted.status.success());
    let targeted: serde_json::Value = serde_json::from_slice(&targeted.stdout).unwrap();
    let targeted_id = targeted["id"].as_str().unwrap();
    let path = f
        .case
        .path
        .join("state")
        .join(crate::sharded::job_file(format!("{targeted_id}.bundle")));
    let mut bytes = fs::read(&path).unwrap();
    let end = bytes.len() - 1;
    bytes[end] ^= 1;
    fs::write(&path, &bytes).unwrap();
    let healthy = f
        .command("admit")
        .arg("--state")
        .arg(f.case.path.join("state"))
        .arg("--archive")
        .arg(archive())
        .arg("--cgroup-root")
        .arg(&f.case.root)
        .args([
            "--profile",
            "upload",
            "--campaign",
            "healthy-control",
            "--attempts",
            "1",
            "--run",
            "5",
        ])
        .output()
        .unwrap();
    assert!(
        healthy.status.success(),
        "{}",
        String::from_utf8_lossy(&healthy.stderr)
    );
    let healthy: serde_json::Value = serde_json::from_slice(&healthy.stdout).unwrap();
    let healthy_id = healthy["id"].as_str().unwrap();
    fs::write(f.case.path.join("bundle.out"), COUNTING).unwrap();
    fs::write(f.case.path.join("run.out"), COUNTING).unwrap();
    let dispatched = f.dispatch();
    assert_eq!(dispatched["started"], 1, "{dispatched}");
    assert_eq!(dispatched["completed"][0]["class"], "pass", "{dispatched}");
    assert!(
        f.case
            .path
            .join("state")
            .join(crate::sharded::attempts_dir(healthy_id))
            .join("0001/started")
            .is_file()
    );
    assert!(
        !f.case
            .path
            .join("state")
            .join(crate::sharded::attempts_dir(targeted_id))
            .exists()
    );
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert!(
        dispatched["unfit"].get(targeted_id).is_some(),
        "{dispatched}"
    );
    let show = campaign_supervisor::campaign::show(&f.case.path.join("state")).unwrap();
    assert!(
        show["jobs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == targeted_id && row.get("held").is_some())
    );
    let findings = campaign_supervisor::campaign::findings(&f.case.path.join("state")).unwrap();
    assert!(findings["findings"].as_array().unwrap().iter().any(|row| {
        row["id"]
            == crate::sharded::job_file(format!("{targeted_id}.json"))
                .to_str()
                .unwrap()
            && row.get("held").is_some()
    }));
    assert!(
        f.report()["jobs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == targeted_id && row["state"] == "held")
    );
    let mut restored = bytes.clone();
    restored[end] ^= 1;
    fs::write(&path, &restored).unwrap();
    let resumed = f.dispatch();
    assert_eq!(resumed["started"], 1, "{resumed}");
    assert!(
        f.case
            .path
            .join("state")
            .join(crate::sharded::attempts_dir(targeted_id))
            .join("0001/started")
            .is_file()
    );
    let queued = f
        .command("admit")
        .arg("--state")
        .arg(f.case.path.join("state"))
        .arg("--archive")
        .arg(archive())
        .arg("--cgroup-root")
        .arg(&f.case.root)
        .args([
            "--profile",
            "upload",
            "--campaign",
            "healthy-control",
            "--attempts",
            "1",
            "--run",
            "6",
        ])
        .output()
        .unwrap();
    assert!(queued.status.success());
    let queued: serde_json::Value = serde_json::from_slice(&queued.stdout).unwrap();
    let queued_id = queued["id"].as_str().unwrap();
    fs::write(&path, &bytes).unwrap();
    let result_path = f
        .case
        .path
        .join("state")
        .join(crate::sharded::job_file(format!(
            "{targeted_id}.result.json"
        )));
    let result_bytes = fs::read(&result_path).unwrap();
    fs::remove_file(&result_path).unwrap();
    let dispatch_once = || {
        f.command("dispatch")
            .arg("--state")
            .arg(f.case.path.join("state"))
            .arg("--archive")
            .arg(archive())
            .arg("--cgroup-root")
            .arg(&f.case.root)
            .args(["--max-attempts", "1"])
            .output()
            .unwrap()
    };
    let unsettled = dispatch_once();
    assert_eq!(unsettled.status.code(), Some(4));
    let unsettled: serde_json::Value = serde_json::from_slice(&unsettled.stdout).unwrap();
    assert_eq!(unsettled["started"], 0, "{unsettled}");
    assert!(
        !unsettled["refusals"].as_array().unwrap().is_empty(),
        "{unsettled}"
    );
    fs::write(&result_path, result_bytes).unwrap();
    let held = dispatch_once();
    // The targeted job has settled, so dispatch settles it by its result's
    // name and reads none of its frozen inputs; the queued job starts.
    assert_eq!(
        held.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&held.stderr)
    );
    assert!(
        f.case
            .path
            .join("state")
            .join(crate::sharded::attempts_dir(queued_id))
            .exists()
    );
    let slow = Corpus::with_cores(4);
    let asset = slow.admitted();
    let admitted = slow.target(&asset, 0, 1);
    assert!(admitted.status.success());
    let admitted: serde_json::Value = serde_json::from_slice(&admitted.stdout).unwrap();
    let slow_id = admitted["id"].as_str().unwrap();
    let mut config = slow.config.config().clone();
    config.insert(
        text("attempt_inodes"),
        campaign_supervisor::store::EVIDENCE_BOUND as u64 - 2,
    );
    config.insert(text("artifact_inodes"), 1 << 20);
    slow.configure(Configuration::new(config).unwrap());
    let unfit = slow.dispatch();
    assert_eq!(unfit["started"], 0);
    assert!(unfit["unfit"].get(slow_id).is_some());
    assert!(
        !slow
            .case
            .path
            .join("state")
            .join(crate::sharded::attempts_dir(slow_id))
            .exists()
    );
    slow.configure(slow.config.clone());
    fs::write(slow.case.root.join("cpu.max"), "300000 100000").unwrap();
    let unfit = slow.dispatch();
    assert_eq!(unfit["started"], 0, "{unfit}");
    assert!(unfit["unfit"].get(slow_id).is_some(), "{unfit}");
    assert!(
        !slow
            .case
            .path
            .join("state")
            .join(crate::sharded::attempts_dir(slow_id))
            .exists()
    );
    fs::write(slow.case.root.join("cpu.max"), "max 100000").unwrap();
    slow.limits("wall", 1);
    fs::write(slow.case.path.join("branch.action"), "hang").unwrap();
    let before = Instant::now();
    let stopped = slow.dispatch();
    assert_eq!(stopped["started"], 1, "{stopped}");
    assert_eq!(stopped["completed"][0]["watchdog"], true, "{stopped}");
    assert_eq!(stopped["completed"][0]["class"], "watchdog", "{stopped}");
    assert!(
        before.elapsed() < Duration::from_secs(3),
        "{:?}",
        before.elapsed()
    );
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(crate) fn targeted_child_capture_binds_actual_parent_and_retains_independent_bundle() {
    let f = Corpus::with_cores(3);
    let asset = f.admitted();
    let admitted = f.target(&asset, 0, 1);
    assert!(
        admitted.status.success(),
        "{}",
        String::from_utf8_lossy(&admitted.stderr)
    );
    let admitted: serde_json::Value = serde_json::from_slice(&admitted.stdout).unwrap();
    let id = admitted["id"].as_str().unwrap();
    let digest = COUNTING
        .lines()
        .find_map(|line| line.strip_prefix("digest: "))
        .unwrap();
    let output = fs::read_to_string(f.case.path.join("branch.out"))
        .unwrap()
        .replace(
            "complete pass fired=03 required=03",
            "complete violation fired=03 required=03",
        )
        .replace(&Digest::of(b"child").to_string(), digest);
    fs::write(f.case.path.join("branch.out"), output).unwrap();
    fs::write(f.case.path.join("branch.exit"), "1").unwrap();
    let tree = f.case.path.join("child-tree");
    fs::create_dir(&tree).unwrap();
    let mut child = fs::read(&f.bundle).unwrap();
    let last = child.len() - 1;
    child[last] ^= 1;
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
    fs::write(
        f.case.path.join("inspect.out"),
        format!(
            "{failure}cause: violation, violating Bytes\nidentity: {}\n",
            "ab".repeat(44)
        ),
    )
    .unwrap();
    fs::write(
        f.case.path.join("replay.out"),
        "replay: reproduced, complete violation fired=03 required=03, violating Bytes\n",
    )
    .unwrap();
    fs::write(tree.join("suffix-0-0.bundle"), &child).unwrap();
    fs::write(f.case.path.join("branch.tree"), tree.to_str().unwrap()).unwrap();
    let dispatched = f.dispatch();
    assert_eq!(
        dispatched["completed"][0]["class"], "violation",
        "{dispatched}"
    );
    let parent = format!("{id}-0001");
    let child_id = format!("{parent}-c0-0");
    let retained = f.case.path.join("state/findings").join(&child_id);
    assert_eq!(fs::read(retained.join("bundle")).unwrap(), child);
    assert_eq!(
        fs::read(
            f.case
                .path
                .join("state/findings")
                .join(&parent)
                .join("bundle")
        )
        .unwrap(),
        child
    );
    let store = Store::open(&f.case.path.join("state")).unwrap();
    let root = store
        .open_dir(store.root(), &name("findings"))
        .unwrap()
        .unwrap();
    let dir = store.open_dir(&root, &name(&child_id)).unwrap().unwrap();
    let finding = store
        .read_record::<campaign_supervisor::record::Finding>(&dir, &name("finding.json"))
        .unwrap()
        .unwrap()
        .record()
        .clone();
    assert_eq!(finding.parent_attempt.as_ref().unwrap().as_str(), parent);
    assert_eq!(finding.attempt.attempt.as_str(), parent);
    assert_eq!(
        finding.child.as_ref().unwrap().bundle,
        Some(Digest::of(&child))
    );
    assert_ne!(finding.bundle(), finding.artifact.as_ref().unwrap().bundle);
    drop(store);
    let rerun = f
        .command("triage")
        .arg("--state")
        .arg(f.case.path.join("state"))
        .args(["--from-run", &child_id, "--step", "rerun", "--cgroup-root"])
        .arg(&f.case.root)
        .output()
        .unwrap();
    assert_eq!(rerun.status.code(), Some(2));
    assert!(rerun.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&rerun.stderr)
            .contains("targeted findings replay their retained bundle")
    );
    let before_collect = f.report();
    let collection = f
        .command("collect")
        .arg("--state")
        .arg(f.case.path.join("state"))
        .output()
        .unwrap();
    assert!(
        collection.status.success(),
        "{}",
        String::from_utf8_lossy(&collection.stderr)
    );
    let collection: serde_json::Value = serde_json::from_slice(&collection.stdout).unwrap();
    assert_eq!(collection["held"], serde_json::json!([]), "{collection}");
    assert_eq!(f.report(), before_collect);
    let replay = f
        .command("triage")
        .arg("--state")
        .arg(f.case.path.join("state"))
        .args(["--from-run", &child_id, "--step", "replay", "--cgroup-root"])
        .arg(&f.case.root)
        .output()
        .unwrap();
    assert!(
        replay.status.success(),
        "{}",
        String::from_utf8_lossy(&replay.stderr)
    );
    let replay: serde_json::Value = serde_json::from_slice(&replay.stdout).unwrap();
    assert_eq!(replay["status"], "reproduced", "{replay}");
    let seen = fs::read_to_string(f.case.path.join("replay.seen")).unwrap();
    let launcher: Vec<String> = serde_json::from_str(
        seen.lines()
            .find_map(|line| line.strip_prefix("launcher_args="))
            .unwrap(),
    )
    .unwrap();
    assert!(
        launcher
            .iter()
            .any(|arg| arg.ends_with(&format!("/{child_id}/bundle"))),
        "{launcher:?}"
    );
    assert!(!launcher.iter().any(|arg| arg == "--from-run"));
    let report = f.report();
    assert!(report["held"].as_array().unwrap().is_empty(), "{report}");
    assert!(
        report["regression_candidates"]
            .as_array()
            .unwrap()
            .iter()
            .any(|candidate| candidate["finding"] == child_id),
        "{report}"
    );
    for candidate in report["regression_candidates"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|candidate| candidate["finding"] == child_id || candidate["finding"] == parent)
    {
        let args: Vec<_> = candidate["command"]
            .as_array()
            .unwrap()
            .iter()
            .map(|arg| arg.as_str().unwrap())
            .collect();
        assert!(!args.contains(&"--from-run"));
        assert!(args.iter().any(|arg| arg.ends_with(&format!(
            "/{}/bundle",
            candidate["finding"].as_str().unwrap()
        ))));
        let output = Command::new(args[0])
            .args(&args[1..])
            .env(PLAN, &f.case.path)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(candidate["expected_exit"].as_i64().unwrap() as i32),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let child_path = f.case.path.join("state/findings").join(&child_id);
    let saved = f.case.path.join("saved-child");
    fs::rename(&child_path, &saved).unwrap();
    let missing = f.report();
    assert!(
        missing["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["held"]
                .as_str()
                .is_some_and(|reason| reason.contains("finding child capture missing"))),
        "{missing}"
    );
    fs::rename(&saved, &child_path).unwrap();
    let marker = f
        .case
        .path
        .join("state")
        .join(crate::sharded::attempts_dir(id))
        .join("0001/captured");
    let marker_bytes = fs::read(&marker).unwrap();
    fs::remove_file(&marker).unwrap();
    let pending = f.report();
    assert!(
        pending["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["held"].as_str().is_some_and(
                |reason| reason.contains("finding capture marker missing or mismatched")
            )),
        "{pending}"
    );
    fs::write(&marker, marker_bytes).unwrap();
    assert!(
        report["release_blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|id| id == &child_id)
    );
    let store = Store::open(&f.case.path.join("state")).unwrap();
    let root = store
        .open_dir(store.root(), &name("findings"))
        .unwrap()
        .unwrap();
    let dir = store.open_dir(&root, &name(&child_id)).unwrap().unwrap();
    let parent_path = f
        .case
        .path
        .join("state")
        .join(crate::sharded::attempts_dir(id))
        .join("0001");
    let saved_parent = f.case.path.join("saved-parent");
    drop(dir);
    drop(root);
    drop(store);
    fs::rename(&parent_path, &saved_parent).unwrap();
    let missing = f.report();
    assert!(
        missing["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == child_id && row.get("held").is_some()),
        "{missing}"
    );
    fs::rename(&saved_parent, &parent_path).unwrap();
    let live_job = f
        .case
        .path
        .join("state")
        .join(crate::sharded::job_file(format!("{id}.json")));
    let saved_job = fs::read(&live_job).unwrap();
    fs::write(&live_job, b"damaged live parent job").unwrap();
    let damaged = f.report();
    assert!(
        damaged["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == child_id && row.get("held").is_some()),
        "{damaged}"
    );
    fs::write(&live_job, saved_job).unwrap();
    let store = Store::open(&f.case.path.join("state")).unwrap();
    let root = store
        .open_dir(store.root(), &name("findings"))
        .unwrap()
        .unwrap();
    let dir = store.open_dir(&root, &name(&child_id)).unwrap().unwrap();
    let mut relabeled = finding.clone();
    relabeled.child.as_mut().unwrap().label = text("unreported");
    let relabeled_id = relabeled.id().as_str().to_owned();
    store.mkdir(&root, &name(&relabeled_id)).unwrap();
    let relabeled_dir = store
        .open_dir(&root, &name(&relabeled_id))
        .unwrap()
        .unwrap();
    store
        .create_record(&relabeled_dir, &name("finding.json"), &relabeled)
        .unwrap();
    for entry in fs::read_dir(&retained).unwrap() {
        let entry = entry.unwrap();
        if entry.file_name() != "finding.json" && entry.file_type().unwrap().is_file() {
            fs::copy(
                entry.path(),
                f.case
                    .path
                    .join("state/findings")
                    .join(&relabeled_id)
                    .join(entry.file_name()),
            )
            .unwrap();
        }
    }
    let mut copied = finding;
    copied.artifact.as_mut().unwrap().reason =
        text("another attempt's artifact with the same label and bundle");
    store
        .replace_record(&dir, &name("finding.json"), &copied)
        .unwrap();
    drop(store);
    let report = f.report();
    assert!(
        report["held"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["path"] == format!("findings/{child_id}")
                && row["reason"].as_str().is_some_and(
                    |reason| reason.contains("child differs from its bound parent evidence")
                )),
        "{report}"
    );
    assert!(
        report["held"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["path"] == format!("findings/{relabeled_id}")
                && row["reason"] == "child differs from its bound parent evidence"),
        "{report}"
    );
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(crate) fn targeted_exploration_freezes_manifest_bounds_and_rejudges_retired_inputs() {
    let f = Corpus::with_cores(3);
    let listing = fs::read_to_string(f.case.path.join("capabilities.out")).unwrap();
    let keys: String = [
        "suffix_depth",
        "suffix_children",
        "suffix_faults",
        "suffix_advances",
    ]
    .iter()
    .map(|key| format!("key: {key} count min=1 max=128\n"))
    .collect();
    fs::write(
        f.case.path.join("capabilities.out"),
        listing.replacen(
            "constraint: min(records",
            &format!("{keys}constraint: min(records"),
            1,
        ),
    )
    .unwrap();
    let pins = Archive::load(archive()).unwrap().pins();
    let manifest = format!(
        "version = 2\nprofile = upload\nroot = 1\nexecutable = {}\ntoolchain = {}\nbuild = {}\nplatform = {}\nbytes = 1048576\nevery = 1\npending = 1\nrecords = 10000\nring = 1\nturns = 1\nsuffix_depth = 1\nsuffix_children = 1\nsuffix_faults = 1\nsuffix_advances = 1\n",
        pins.executable.as_str(),
        pins.toolchain.as_str(),
        pins.build.as_str(),
        pins.platform.as_str()
    );
    let bytes = bundle(&manifest, 2);
    let semantic = bytes.len() / 48 - 1;
    let prefix = Digest::of(&bytes[..bytes.len() - 48]);
    let header = format!(
        "milestone: pending-put boundary=13 semantic={semantic} decisions=1 prefix={prefix}\nwitness: pending-put holds=true boundary=13 upload=attempt:1,grant:3,held:2,outcome:0 armed=false\nparent: reproduced\n"
    );
    fs::write(&f.bundle, &bytes).unwrap();
    fs::write(f.case.path.join("branch.out"), format!("{header}child: suffix=0 sibling=0 class=success digest={} terminal=complete pass fired=03 required=03\nbranch: 1 children, 1 credited, 0 problems\n", Digest::of(b"child"))).unwrap();
    let asset = f.admitted();
    let output = f
        .command("admit")
        .arg("--state")
        .arg(f.case.path.join("state"))
        .arg("--archive")
        .arg(archive())
        .args([
            "--target",
            &asset,
            "--campaign",
            "explore",
            "--explore",
            "--cgroup-root",
        ])
        .arg(&f.case.root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let admitted: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let id = admitted["id"].as_str().unwrap();
    assert!(f.remove(&asset).status.success());
    fs::write(f.case.path.join("explore.out"), format!("label: composed-bounded\n{header}limits: depth=1 children=1 faults=1 advances=1\nnode: path=0 class=success wall_us=1 cpu_us=1 max_rss_kib=1\nleaf: path=0 digest={} unexplored=0 counts=true verdict=complete pass fired=03 required=03\nfrontier: nodes=1 credited=1 explored=1 failing=0 unexplored=0\nexplore: composed-bounded, 0 problems\n", Digest::of(b"leaf"))).unwrap();
    let dispatched = f.dispatch();
    assert_eq!(dispatched["started"], 1, "{dispatched}");
    assert_eq!(dispatched["completed"][0]["class"], "pass", "{dispatched}");
    let report = f.report();
    let row = report["targeted"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == id)
        .unwrap();
    assert_eq!(row["credited"], true, "{report}");
    assert_eq!(row["target"]["form"]["depth"], 1);
    assert_eq!(row["target"]["form"]["children"], 1);
    let job_path = f
        .case
        .path
        .join("state")
        .join(crate::sharded::attempts_dir(id))
        .join("0001/artifacts")
        .join(format!("{id}-0001"));
    let original = fs::read(job_path.join("explore.stdout")).unwrap();
    fs::write(
        job_path.join("explore.stdout"),
        b"copied unbound exploration stdout",
    )
    .unwrap();
    let report = f.report();
    assert!(
        report["held"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["path"] == format!("jobs/{id}")),
        "{report}"
    );
    assert!(
        !report["targeted"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == id && row["credited"] == true)
    );
    fs::write(job_path.join("explore.stdout"), original).unwrap();
    assert_eq!(f.report()["targeted"][0]["credited"], true);
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(crate) fn targeted_explore_nodes_and_leaves_keep_separate_findings_and_waiting_nodes() {
    let f = Corpus::with_cores(4);
    let listing = fs::read_to_string(f.case.path.join("capabilities.out")).unwrap();
    let keys: String = [
        "suffix_depth",
        "suffix_children",
        "suffix_faults",
        "suffix_advances",
    ]
    .iter()
    .map(|key| format!("key: {key} count min=1 max=128\n"))
    .collect();
    fs::write(
        f.case.path.join("capabilities.out"),
        listing.replacen(
            "constraint: min(records",
            &format!("{keys}constraint: min(records"),
            1,
        ),
    )
    .unwrap();
    let pins = Archive::load(archive()).unwrap().pins();
    let manifest = format!(
        "version = 2\nprofile = upload\nroot = 1\nexecutable = {}\ntoolchain = {}\nbuild = {}\nplatform = {}\nbytes = 1048576\nevery = 1\npending = 1\nrecords = 10000\nring = 1\nturns = 1\nsuffix_depth = 1\nsuffix_children = 2\nsuffix_faults = 1\nsuffix_advances = 1\n",
        pins.executable.as_str(),
        pins.toolchain.as_str(),
        pins.build.as_str(),
        pins.platform.as_str()
    );
    let bytes = bundle(&manifest, 2);
    let semantic = bytes.len() / 48 - 1;
    let prefix = Digest::of(&bytes[..bytes.len() - 48]);
    let header = format!(
        "milestone: pending-put boundary=13 semantic={semantic} decisions=1 prefix={prefix}\nwitness: pending-put holds=true boundary=13 upload=attempt:1,grant:3,held:2,outcome:0 armed=false\nparent: reproduced\n"
    );
    fs::write(&f.bundle, &bytes).unwrap();
    fs::write(f.case.path.join("branch.out"), format!("{header}child: suffix=0 sibling=0 class=success digest={} terminal=complete pass fired=03 required=03\nbranch: 1 children, 1 credited, 0 problems\n", Digest::of(b"child"))).unwrap();
    let asset = f.admitted();
    let output = f
        .command("admit")
        .arg("--state")
        .arg(f.case.path.join("state"))
        .arg("--archive")
        .arg(archive())
        .args([
            "--target",
            &asset,
            "--campaign",
            "explore",
            "--explore",
            "--cgroup-root",
        ])
        .arg(&f.case.root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let admitted: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let id = admitted["id"].as_str().unwrap();
    let tree = f.case.path.join("explore-tree");
    fs::create_dir(&tree).unwrap();
    fs::write(tree.join("leaf-0.bundle"), &bytes).unwrap();
    fs::write(f.case.path.join("explore.tree"), tree.to_str().unwrap()).unwrap();
    let digest = COUNTING
        .lines()
        .find_map(|line| line.strip_prefix("digest: "))
        .unwrap();
    fs::write(f.case.path.join("explore.out"), format!("label: composed-bounded\n{header}limits: depth=1 children=2 faults=1 advances=1\nnode: path=0 class=success wall_us=1 cpu_us=1 max_rss_kib=1\nnode: path=1 class=failed wall_us=0 cpu_us=0 max_rss_kib=0\nleaf: path=0 digest={digest} unexplored=0 counts=false verdict=complete violation fired=03 required=03\nfrontier: nodes=2 credited=1 explored=1 failing=1 unexplored=0\nexplore: composed-bounded, 0 problems\n")).unwrap();
    fs::write(f.case.path.join("explore.exit"), "1").unwrap();
    let dispatched = f.dispatch();
    assert_eq!(
        dispatched["completed"][0]["class"], "violation",
        "{dispatched}"
    );
    let node = format!("{id}-0001-n1");
    let leaf = format!("{id}-0001-l0");
    let report = f.report();
    let rows = report["findings"].as_array().unwrap();
    let node_row = rows.iter().find(|row| row["id"] == node).unwrap();
    assert_eq!(node_row["triage"]["state"], "waiting");
    assert_eq!(node_row["triage"]["reason"], "no retained child bundle");
    let leaf_row = rows.iter().find(|row| row["id"] == leaf).unwrap();
    assert_eq!(leaf_row["verified"]["parent_attempt"], format!("{id}-0001"));
    assert_eq!(
        leaf_row["verified"]["child"]["bundle"],
        Digest::of(&bytes).to_string()
    );
    assert_eq!(
        fs::read(
            f.case
                .path
                .join("state/findings")
                .join(&leaf)
                .join("bundle")
        )
        .unwrap(),
        bytes
    );
    assert_eq!(leaf_row["verified"]["child"]["digest"], digest);
    assert!(!f.case.path.join("state/triage").join(&node).exists());
    let refused = f
        .command("triage")
        .arg("--state")
        .arg(f.case.path.join("state"))
        .args(["--from-run", &node, "--step", "replay", "--cgroup-root"])
        .arg(&f.case.root)
        .output()
        .unwrap();
    assert_eq!(refused.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("no retained child bundle"));
    assert!(!f.case.path.join("state/triage").join(&node).exists());
    let findings = f
        .command("findings")
        .arg("--state")
        .arg(f.case.path.join("state"))
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&findings.stdout).contains("no retained child bundle"));
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(crate) fn targeted_missing_facts_settle_one_replay_and_explicit_steps_can_repeat() {
    let f = Corpus::with_cores(3);
    let asset = f.admitted();
    let output = f.target(&asset, 0, 1);
    assert!(output.status.success());
    let admitted: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let id = admitted["id"].as_str().unwrap();
    let branch = fs::read_to_string(f.case.path.join("branch.out"))
        .unwrap()
        .replace("parent: reproduced", "parent: changed");
    fs::write(f.case.path.join("branch.out"), branch).unwrap();
    fs::write(f.case.path.join("branch.exit"), "1").unwrap();
    fs::write(
        f.case.path.join("replay.out"),
        "replay: reproduced, complete pass fired=03 required=03\n",
    )
    .unwrap();
    let output = f
        .command("dispatch")
        .arg("--state")
        .arg(f.case.path.join("state"))
        .arg("--archive")
        .arg(archive())
        .arg("--cgroup-root")
        .arg(&f.case.root)
        .args(["--max-attempts", "1", "--for", "90"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let dispatch: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(dispatch["triage_started"], 1, "{dispatch}");
    let finding = format!("{id}-0001");
    let report = f.report();
    let row = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == finding)
        .unwrap();
    assert_eq!(row["triage"]["state"], "waiting");
    assert_eq!(
        row["triage"]["reason"],
        "stored replay digest or terminal is absent"
    );
    assert_eq!(row["triage"]["latest"]["status"], "insufficient-evidence");
    let output = f
        .command("triage")
        .arg("--state")
        .arg(f.case.path.join("state"))
        .args(["--from-run", &finding, "--step", "replay", "--cgroup-root"])
        .arg(&f.case.root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["status"], "insufficient-evidence");
    assert_eq!(result["number"], 2);
    let output = f
        .command("triage")
        .arg("--state")
        .arg(f.case.path.join("state"))
        .args(["--from-run", &finding, "--step", "replay", "--cgroup-root"])
        .arg(&f.case.root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["status"], "insufficient-evidence");
    assert_eq!(result["number"], 3);
    let store = Store::open(&f.case.path.join("state")).unwrap();
    let triage = store
        .open_dir(store.root(), &name("triage"))
        .unwrap()
        .unwrap();
    let retained = store.open_dir(&triage, &name(&finding)).unwrap().unwrap();
    let steps = store.open_dir(&retained, &name("steps")).unwrap().unwrap();
    for number in [2u64, 3] {
        let dir = store
            .open_dir(&steps, &name(&format!("{number:04}")))
            .unwrap()
            .unwrap();
        let mut done = store
            .read_record::<campaign_supervisor::record::Finished>(&dir, &name("finished"))
            .unwrap()
            .unwrap()
            .record()
            .clone();
        done.class = campaign_supervisor::record::Class::Interrupted;
        done.interruption = Some(15);
        let mut result = store
            .read_record::<campaign_supervisor::record::TriageResult>(&dir, &name("result"))
            .unwrap()
            .unwrap()
            .record()
            .clone();
        result.finished = done.clone();
        result.state = campaign_supervisor::record::StepState::Interrupted;
        result.status = None;
        result.comparison = None;
        store
            .replace_record(&dir, &name("finished"), &done)
            .unwrap();
        store
            .replace_record(&dir, &name("result"), &result)
            .unwrap();
    }
    drop(store);
    let report = f.report();
    let row = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == finding)
        .unwrap();
    assert_eq!(row["triage"]["state"], "waiting", "{report}");
    assert_eq!(row["triage"]["latest"]["number"], 3);
    assert!(row["triage"]["latest"]["status"].is_null());
}
