#![cfg(all(target_os = "linux", target_pointer_width = "64"))]

use campaign_supervisor::record::{
    Admission, Artifact, Attempt, Binding, BoundEvidence, Class, Decision, Digest, Finding,
    FindingKind, Finished, Kernel, Summarized, Text, Worker,
};
use campaign_supervisor::store::{Name, Store};
use std::{fs, process::Command};

fn text(value: &str) -> Text {
    Text::new(value).unwrap()
}
fn name(value: &str) -> Name {
    Name::new(value).unwrap()
}
fn run(state: &std::path::Path, command: &str, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_campaign"))
        .arg(command)
        .arg("--state")
        .arg(state)
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn binary_findings_lists_every_kind_and_dispose_preserves_history() {
    let root = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("findings-cli")
        .join(std::process::id().to_string());
    fs::create_dir_all(&root).unwrap();
    let state = root.join("state");
    fs::create_dir(&state).unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    let value: serde_json::Value =
        serde_json::from_slice(include_bytes!("../testdata/admission.json")).unwrap();
    let admission: Admission = serde_json::from_value(value["record"].clone()).unwrap();
    let keys = [
        "version",
        "profile",
        "root",
        "executable",
        "toolchain",
        "build",
        "platform",
        "cpu",
        "scenario",
        "bytes",
        "every",
        "pending",
        "records",
        "ring",
        "turns",
    ];
    let manifest = admission.job().manifest(&keys).unwrap();
    assert_eq!(
        Digest::of(manifest.as_bytes()),
        admission.job().manifest_sha256()
    );
    let store = Store::open(&state).unwrap();
    store.mkdir(store.root(), &name("findings")).unwrap();
    let findings = store
        .open_dir(store.root(), &name("findings"))
        .unwrap()
        .unwrap();
    let mut ids = Vec::new();
    for (index, kind) in [
        FindingKind::Violation,
        FindingKind::Panic,
        FindingKind::Abort,
        FindingKind::Truncated,
        FindingKind::Watchdog,
        FindingKind::Harness,
        FindingKind::Violation,
        FindingKind::Violation,
        FindingKind::Violation,
    ]
    .into_iter()
    .enumerate()
    {
        let mut experiment = admission.job().experiment().clone();
        experiment.run = index as u64;
        let (job, manifest) = campaign_supervisor::record::Job::derive(experiment, &keys).unwrap();
        let admission =
            Admission::new(admission.archive().clone(), job, admission.purpose()).unwrap();
        let id = format!("{}-0001", admission.job().id());
        ids.push(id.clone());
        let manifest_digest = admission.job().manifest_sha256();
        let stdout: &[u8] = if kind == FindingKind::Panic {
            b"run: the run panicked at engine.rs:1:1\n"
        } else {
            b"stdout"
        };
        let terminal = match kind {
            FindingKind::Violation => "complete violation fired=03 required=03",
            FindingKind::Harness => "infrastructure defect",
            FindingKind::Truncated => "infrastructure truncated",
            _ => "complete pass fired=03 required=03",
        };
        let artifact = Artifact {
            archive: Digest::parse(admission.job().experiment().pins.build.as_str()),
            archive_path: None,
            bundle: Some(Digest::of(b"bundle")),
            class: text("incomplete"),
            command: text("run"),
            comparison: None,
            manifest: Some(manifest_digest),
            output: None,
            reason: text("failure"),
            run_id: text(&id),
            session: None,
            session_original: None,
            summary: Some(Summarized {
                cause: None,
                counts: false,
                decisions: Some(1),
                digest: Digest::of(b"semantic"),
                first_failure: None,
                identity: (index >= 6).then(|| {
                    text(&format!(
                        "020101{}",
                        if index == 8 { "b" } else { "a" }.repeat(82)
                    ))
                }),
                ledger: None,
                terminal: text(terminal),
                unsuccessful: None,
            }),
            workers: [(
                text("run"),
                Worker {
                    ended: text(if kind == FindingKind::Truncated {
                        "oversized"
                    } else if kind == FindingKind::Abort {
                        "signaled"
                    } else {
                        "exited"
                    }),
                    exit: if matches!(kind, FindingKind::Abort | FindingKind::Truncated) {
                        None
                    } else {
                        Some(0)
                    },
                    signal: (kind == FindingKind::Abort).then_some(libc::SIGABRT as u64),
                    stdout: Digest::of(stdout),
                    stderr: Digest::of(b"stderr"),
                },
            )]
            .into(),
        };
        let attempt = Attempt {
            attempt: text(&id),
            file_bytes: 1024,
            job: admission.job().id().digest(),
            manifest: manifest_digest,
            number: 1,
        };
        let mut envelope =
            serde_json::json!({"format": 1, "kind": "artifact", "record": &artifact});
        envelope["sha256"] =
            serde_json::to_value(Digest::of(&serde_json::to_vec(&envelope).unwrap())).unwrap();
        let artifact_digest = Digest::of(&serde_json::to_vec(&envelope).unwrap());
        let finished = Finished {
            attempt: text(&id),
            binding: Binding::Matching,
            bound: Some(BoundEvidence {
                artifact: artifact_digest,
                attempt: text(&id),
                bundle: artifact.bundle,
            }),
            class: match kind {
                FindingKind::Violation => Class::Violation,
                FindingKind::Panic | FindingKind::Abort | FindingKind::Harness => {
                    Class::EngineFailure
                }
                FindingKind::Watchdog => Class::Watchdog,
                _ => Class::Incomplete,
            },
            exit: Some(4),
            interruption: None,
            kernel: Kernel::default(),
            residual_members: false,
            signal: None,
            watchdog: kind == FindingKind::Watchdog,
        };
        store.mkdir(&findings, &name(&id)).unwrap();
        let directory = store.open_dir(&findings, &name(&id)).unwrap().unwrap();
        store
            .create_once(&directory, &name("manifest"), manifest.as_bytes())
            .unwrap();
        store
            .create_once(&directory, &name("bundle"), b"bundle")
            .unwrap();
        store
            .create_once(&directory, &name("run.stdout"), stdout)
            .unwrap();
        store
            .create_once(&directory, &name("run.stderr"), b"stderr")
            .unwrap();
        store
            .create_record(
                &directory,
                &name("finding.json"),
                &Finding {
                    child: None,
                    parent_attempt: None,
                    calibration_root: None,
                    admission,
                    artifact: Some(artifact),
                    attempt,
                    finished,
                    kind,
                },
            )
            .unwrap();
    }
    drop(store);
    let first = run(&state, "findings", &[]);
    assert_eq!(first.status.code(), Some(0));
    let listed: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    let shown = run(&state, "status", &[]);
    assert_eq!(shown.status.code(), Some(0));
    let shown: serde_json::Value = serde_json::from_slice(&shown.stdout).unwrap();
    assert_eq!(shown["format"], 1);
    assert_eq!(shown["findings"], listed["findings"]);
    assert_eq!(shown["release_blockers"], listed["release_blockers"]);
    let grouped: usize = shown["failure_groups"]
        .as_array()
        .unwrap()
        .iter()
        .map(|group| group["findings"].as_array().unwrap().len())
        .sum();
    assert_eq!(grouped, 9);
    assert_eq!(run(&state, "status", &["--bogus"]).status.code(), Some(2));
    assert_eq!(listed["findings"].as_array().unwrap().len(), 9);
    let labels: std::collections::BTreeSet<_> = listed["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["verified"]["kind"].as_str().unwrap())
        .collect();
    assert_eq!(
        labels,
        [
            "violation",
            "panic",
            "abort",
            "truncated",
            "watchdog",
            "harness"
        ]
        .into()
    );
    let blockers: Vec<_> = listed["release_blockers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|id| id.as_str().unwrap())
        .collect();
    assert_eq!(blockers.len(), 6);
    for id in &ids[..3] {
        assert!(blockers.contains(&id.as_str()));
    }
    let identity = |id: &str| {
        listed["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["id"] == id)
            .unwrap()["verified"]["artifact"]["summary"]["identity"]
            .clone()
    };
    assert_eq!(
        identity(&ids[6]),
        serde_json::json!(format!("020101{}", "a".repeat(82)))
    );
    assert_eq!(identity(&ids[6]), identity(&ids[7]));
    assert_ne!(identity(&ids[6]), identity(&ids[8]));
    for id in &ids[6..] {
        assert!(blockers.contains(&id.as_str()));
    }
    let id = &ids[0];
    let directory = state.join("findings").join(id);
    for evidence in ["", "  "] {
        assert_eq!(
            run(
                &state,
                "dispose",
                &[
                    "--finding",
                    id,
                    "--disposition",
                    "resolved",
                    "--evidence",
                    evidence
                ]
            )
            .status
            .code(),
            Some(2)
        );
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 5);
    }
    let collection = run(&state, "collect", &[]);
    assert_eq!(
        collection.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&collection.stderr)
    );
    assert_eq!(run(&state, "findings", &[]).stdout, first.stdout);
    for decision in [Decision::Harness, Decision::Resolved, Decision::Harness] {
        assert_eq!(
            run(
                &state,
                "dispose",
                &[
                    "--finding",
                    id,
                    "--disposition",
                    decision.name(),
                    "--evidence",
                    "fix and replay evidence"
                ]
            )
            .status
            .code(),
            Some(0)
        );
        let listed: serde_json::Value =
            serde_json::from_slice(&run(&state, "findings", &[]).stdout).unwrap();
        let blockers = listed["release_blockers"].as_array().unwrap();
        assert_eq!(
            blockers.iter().any(|entry| entry == id),
            decision != Decision::Resolved
        );
    }
    let first_disposition = fs::read(directory.join("0001.disposition.json")).unwrap();
    assert_eq!(
        run(
            &state,
            "dispose",
            &[
                "--finding",
                id,
                "--disposition",
                "resolved",
                "--evidence",
                "new evidence"
            ]
        )
        .status
        .code(),
        Some(0)
    );
    assert_eq!(
        fs::read(directory.join("0001.disposition.json")).unwrap(),
        first_disposition
    );
    fs::remove_dir_all(root).unwrap();
}
