use super::*;
use campaign_supervisor::record::{Admission, Configuration, Finished};

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(crate) fn dispatch_cli_runs_and_reports_held_reservations() {
    let case = Case::new("admission-pass");
    for extra in [
        vec!["--for", "-1"],
        vec!["--for", "bad"],
        vec!["--max-attempts", "-1"],
        vec!["--max-attempts", "bad"],
        vec!["--poll", "0"],
        vec!["--set", "slots=2"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_campaign"))
            .args(["dispatch", "--state"])
            .arg(case.path.join("rejected-state"))
            .arg("--archive")
            .arg(archive())
            .arg("--cgroup-root")
            .arg(&case.root)
            .args(extra)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(!case.path.join("rejected-state/attempts").exists());
    }
    let invalid_state = case.path.join("invalid-root-state");
    let invalid = Command::new(env!("CARGO_BIN_EXE_campaign"))
        .arg("dispatch")
        .arg("--state")
        .arg(&invalid_state)
        .arg("--archive")
        .arg(archive())
        .arg("--cgroup-root")
        .arg("relative-root")
        .output()
        .unwrap();
    assert_eq!(invalid.status.code(), Some(2));
    assert!(invalid.stdout.is_empty());
    assert!(!invalid_state.exists());
    let admitted = admission_command(&case)
        .args(["--attempts", "1", "--set", "bytes=18446744073709551615"])
        .output()
        .unwrap();
    assert!(
        admitted.status.success(),
        "{}",
        String::from_utf8_lossy(&admitted.stderr)
    );
    let row: serde_json::Value = serde_json::from_slice(&admitted.stdout).unwrap();
    let id = row["id"].as_str().unwrap();
    let store = Store::open(&case.path.join("state")).unwrap();
    let values = [
        ("slots", 1),
        ("reserve_slots", 1),
        ("cores", 4),
        ("memory", 1 << 30),
        ("cpu", 60),
        ("tree_memory", 256 << 20),
        ("attempt_output", 16 << 20),
        ("attempt_inodes", 100),
        ("wall", 30),
        ("processes", 64),
        ("artifact_bytes", 256 << 20),
        ("artifact_inodes", 4096),
        ("backlog", 10),
        ("retained_builds", 1),
    ]
    .into_iter()
    .map(|(key, value)| (text(key), value))
    .collect();
    store
        .create_record(
            store.root(),
            &name("config.json"),
            &Configuration::new(values).unwrap(),
        )
        .unwrap();
    let jobs = crate::sharded::jobs(&store, id);
    assert_eq!(
        store
            .read_record::<Admission>(&jobs, &name(&format!("{id}.json")))
            .unwrap()
            .unwrap()
            .record()
            .purpose(),
        campaign_supervisor::record::Purpose::Campaign
    );
    drop(store);
    fs::write(case.path.join("action"), "campaign-pass").unwrap();
    let invoke_with = |extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_campaign"))
            .arg("dispatch")
            .arg("--state")
            .arg(case.path.join("state"))
            .arg("--archive")
            .arg(archive())
            .arg("--cgroup-root")
            .arg(&case.root)
            .args(["--poll", "0.001", "--kill-wait", "2", "--max-attempts", "1"])
            .args(extra)
            .env("CAMPAIGN_CUSTODY_WORKER", &case.path)
            .env("CAMPAIGN_CUSTODY_STALL_SECONDS", "2")
            .output()
            .unwrap()
    };
    let invoke = || invoke_with(&[]);
    let dispatched = invoke();
    assert_eq!(
        dispatched.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&dispatched.stderr)
    );
    assert_eq!(
        dispatched
            .stdout
            .iter()
            .filter(|byte| **byte == b'\n')
            .count(),
        1
    );
    let report: serde_json::Value = serde_json::from_slice(&dispatched.stdout).unwrap();
    assert_eq!(report["started"], 1);
    assert_eq!(report["completed"].as_array().unwrap().len(), 1);
    assert_eq!(report["counts"], serde_json::json!({"pass": 1}));
    let path = case
        .path
        .join("state")
        .join(crate::sharded::attempts_dir(id))
        .join("0001");
    assert!(path.join("started").exists());
    let captured: serde_json::Value =
        serde_json::from_slice(&fs::read(path.join("launcher.stdout")).unwrap()).unwrap();
    assert!(captured.is_object());
    assert!(case.path.join("seen").exists());
    let store = Store::open(&case.path.join("state")).unwrap();
    let jobs = crate::sharded::jobs(&store, id);
    let result = store
        .read_record::<campaign_supervisor::record::JobResult>(
            &jobs,
            &name(&format!("{id}.result.json")),
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        result.record().finished.class,
        campaign_supervisor::record::Class::Pass
    );
    assert_eq!(
        result.record().finished.binding,
        campaign_supervisor::record::Binding::Matching
    );
    assert!(result.record().finished.bound.is_some());
    let artifact_view =
        campaign_supervisor::store::View::open(&path.join("artifacts").join(format!("{id}-0001")))
            .unwrap();
    let artifact = artifact_view
        .read_record::<campaign_supervisor::record::Artifact>(
            artifact_view.root(),
            &name("artifact"),
        )
        .unwrap()
        .unwrap();
    for phase in ["run", "inspect"] {
        assert_eq!(artifact.record().workers[&text(phase)].exit, Some(0));
        assert_eq!(artifact.record().workers[&text(phase)].signal, None);
    }
    drop(store);
    assert!(path.join("launcher.stderr").is_file());
    assert!(!case.path.join("launcher.stdout").exists());
    assert!(path.join("finished").exists());
    assert!(!path.join("reservation").exists());
    assert!(!case.root.join(format!("{id}-0001")).exists());
    let view = campaign_supervisor::store::View::open(&path).unwrap();
    assert!(
        view.read_record::<Finished>(view.root(), &name("finished"))
            .unwrap()
            .is_some()
    );
    drop(view);
    let readers_before = campaign_supervisor::campaign::report(&case.path.join("state")).unwrap();
    let collect = |flags: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_campaign"))
            .arg("collect")
            .arg("--state")
            .arg(case.path.join("state"))
            .args(flags)
            .output()
            .unwrap()
    };
    let dry = collect(&["--dry-run"]);
    assert_eq!(
        dry.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&dry.stderr)
    );
    let dry: serde_json::Value = serde_json::from_slice(&dry.stdout).unwrap();
    assert_eq!(dry["dry_run"], true);
    assert_eq!(dry["held"], serde_json::json!([]), "{dry}");
    // The settled attempt's launcher logs and its reclaimed bulk.
    let planned = dry["entries"].as_array().unwrap();
    let mut expected = std::collections::BTreeSet::from([
        path.join("launcher.stdout"),
        path.join("launcher.stderr"),
        path.join("artifacts").join(format!("{id}-0001/bundle")),
    ]);
    for phase in artifact.record().workers.keys() {
        for stream in ["stdout", "stderr"] {
            if stream == "stdout" && matches!(phase.as_str(), "inspect" | "capabilities") {
                continue;
            }
            expected.insert(
                path.join("artifacts")
                    .join(format!("{id}-0001/{}.{stream}", phase.as_str())),
            );
        }
    }
    let listed: std::collections::BTreeSet<_> = planned
        .iter()
        .map(|row| case.path.join("state").join(row["path"].as_str().unwrap()))
        .collect();
    assert_eq!(listed, expected);
    assert_eq!(dry["projected_inodes"], expected.len());
    assert_eq!(dry["reclaimed"].as_array().unwrap().len(), 1, "{dry}");

    assert!(path.join("launcher.stdout").is_file());
    assert!(path.join("launcher.stderr").is_file());
    assert_eq!(collect(&["--dry-run", "--dry-run"]).status.code(), Some(2));
    assert!(path.join("launcher.stdout").is_file());
    let collected = collect(&[]);
    assert_eq!(
        collected.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&collected.stderr)
    );
    let collected: serde_json::Value = serde_json::from_slice(&collected.stdout).unwrap();
    assert_eq!(collected["held"], serde_json::json!([]));
    assert_eq!(collected["entries"], dry["entries"]);
    assert_eq!(collected["freed_inodes"], dry["projected_inodes"]);
    assert!(path.join("reclaimed").is_file());
    assert!(!path.join("launcher.stdout").exists());
    assert!(!path.join("launcher.stderr").exists());
    for entry in &expected {
        assert!(!entry.exists(), "{}", entry.display());
    }
    assert!(
        path.join("artifacts")
            .join(format!("{id}-0001/inspect.stdout"))
            .is_file()
    );
    assert_eq!(
        campaign_supervisor::campaign::report(&case.path.join("state")).unwrap(),
        readers_before
    );
    // The job has settled, so dispatch settles it by its result's name and
    // reconciles none of its attempts: a damaged charge there holds nothing.
    fs::write(path.join("reservation"), b"damaged").unwrap();
    let settled = invoke();
    assert_eq!(
        settled.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&settled.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&settled.stdout).unwrap();
    assert_eq!(report["started"], 0);
    assert!(report["refusals"].as_array().unwrap().is_empty());
    assert_eq!(fs::read(path.join("reservation")).unwrap(), b"damaged");
    let result_path = case
        .path
        .join("state")
        .join(crate::sharded::job_file(format!("{id}.result.json")));
    let result_bytes = fs::read(&result_path).unwrap();
    fs::remove_file(&result_path).unwrap();
    for extra in [vec![], vec!["--for", "0"]] {
        let held = invoke_with(&extra);
        assert_eq!(
            held.status.code(),
            Some(4),
            "{}",
            String::from_utf8_lossy(&held.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&held.stdout).unwrap();
        assert_eq!(report["started"], 0);
        assert!(!report["refusals"].as_array().unwrap().is_empty());
        assert_eq!(fs::read(path.join("reservation")).unwrap(), b"damaged");
    }
    fs::write(&result_path, result_bytes).unwrap();
    fs::remove_file(path.join("reservation")).unwrap();
    fs::write(case.path.join("action"), "admission-pass").unwrap();
    let queued = admission_command(&case)
        .args(["--run", "1", "--attempts", "1"])
        .output()
        .unwrap();
    assert!(
        queued.status.success(),
        "{}",
        String::from_utf8_lossy(&queued.stderr)
    );
    let queued: serde_json::Value = serde_json::from_slice(&queued.stdout).unwrap();
    fs::write(case.path.join("action"), "campaign-pass").unwrap();
    let window = invoke_with(&["--for", "0"]);
    assert_eq!(
        window.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&window.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&window.stdout).unwrap();
    assert_eq!(report["started"], 0);
    assert!(report["completed"].as_array().unwrap().is_empty());
    assert!(report["refusals"].as_array().unwrap().is_empty());
    assert!(
        !case
            .path
            .join("state")
            .join(crate::sharded::attempts_dir(queued["id"].as_str().unwrap()))
            .exists()
    );
    let memory_max = fs::read(case.root.join("memory.max")).unwrap();
    fs::write(case.root.join("memory.max"), (512u64 << 20).to_string()).unwrap();
    let rejected = invoke();
    assert_eq!(
        rejected.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&rejected.stderr)
    );
    assert_eq!(
        rejected
            .stdout
            .iter()
            .filter(|byte| **byte == b'\n')
            .count(),
        1
    );
    let report: serde_json::Value = serde_json::from_slice(&rejected.stdout).unwrap();
    assert_eq!(report["started"], 0);
    assert!(report["completed"].as_array().unwrap().is_empty());
    assert!(
        report["rejections"]
            .as_array()
            .unwrap()
            .iter()
            .any(|reason| reason.as_str().unwrap().contains("aggregate memory"))
    );
    assert!(
        !case
            .path
            .join("state")
            .join(crate::sharded::attempts_dir(queued["id"].as_str().unwrap()))
            .exists()
    );
    fs::write(case.root.join("memory.max"), memory_max).unwrap();
    let started = invoke();
    assert_eq!(
        started.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&started.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&started.stdout).unwrap();
    assert_eq!(report["started"], 1);
    assert!(report["refusals"].as_array().unwrap().is_empty());
    assert!(
        case.path
            .join("state")
            .join(crate::sharded::attempts_dir(queued["id"].as_str().unwrap()))
            .join("0001/finished")
            .is_file()
    );
    assert!(path.join("reclaimed").is_file());
}
