use super::{Fixture, name, text};
use crate::exit::Supervisor;
use crate::record::{Artifact, Class, Digest, Finding, FindingKind, Finished};
use crate::store::Store;
use crate::store::fixture::snapshot;
use std::fs;

fn fixture(kind: FindingKind) -> Fixture {
    let class = match kind {
        FindingKind::Engine => Class::EngineFailure,
        FindingKind::Unsuccessful => Class::Unsuccessful,
        FindingKind::Inconclusive => Class::Inconclusive,
        FindingKind::Incomplete => Class::Incomplete,
        FindingKind::Violation => Class::Violation,
        FindingKind::Panic | FindingKind::Abort | FindingKind::Harness => Class::EngineFailure,
        FindingKind::Truncated => Class::Incomplete,
        FindingKind::Watchdog => Class::Watchdog,
    };
    let f = Fixture::new(&[class]);
    let directory = f.artifact_directory(1);
    let mut artifact = f
        .store
        .read_record::<Artifact>(&directory, &name("artifact"))
        .unwrap()
        .unwrap()
        .record()
        .clone();
    artifact.archive = Digest::parse(f.job.job().experiment().pins.build.as_str());
    if kind == FindingKind::Violation {
        artifact.summary.as_mut().unwrap().identity = Some(text("failure identity v1"));
    }
    if matches!(kind, FindingKind::Panic | FindingKind::Abort) {
        artifact.summary.as_mut().unwrap().terminal = text("complete pass fired=03 required=03");
        if kind == FindingKind::Panic {
            let output = b"run: the run panicked at engine.rs:1:1\n";
            f.store
                .replace(&directory, &name("run.stdout"), output)
                .unwrap();
            artifact.workers.get_mut(&text("run")).unwrap().stdout = Digest::of(output);
        } else {
            let worker = artifact.workers.get_mut(&text("run")).unwrap();
            worker.signal = Some(libc::SIGABRT as u64);
            worker.exit = None;
            worker.ended = text("signaled");
            f.store
                .create_once(
                    &directory,
                    &name("foreign.log"),
                    b"thread 'main' panicked at unrelated",
                )
                .unwrap();
        }
    }
    if kind == FindingKind::Truncated {
        artifact.workers.get_mut(&text("run")).unwrap().ended = text("oversized");
        artifact.workers.get_mut(&text("run")).unwrap().exit = None;
    }
    f.store
        .replace_record(&directory, &name("artifact"), &artifact)
        .unwrap();
    rebind(&f, class);
    f
}

#[test]
fn every_bound_failure_kind_retains_identity_and_replay_after_attempt_removal() {
    for (kind, label, blocker) in [
        (FindingKind::Violation, "violation", true),
        (FindingKind::Panic, "panic", true),
        (FindingKind::Abort, "abort", true),
        (FindingKind::Truncated, "truncated", false),
        (FindingKind::Watchdog, "watchdog", false),
        (FindingKind::Harness, "harness", false),
    ] {
        let f = fixture(kind);
        f.settle().unwrap();
        let id = format!("{}-0001", f.job.job().id());
        let root = f.case.state.join("findings").join(&id);
        let bytes = fs::read(root.join("finding.json")).unwrap();
        f.settle().unwrap();
        assert_eq!(fs::read(root.join("finding.json")).unwrap(), bytes);
        let findings = f
            .store
            .open_dir(f.store.root(), &name("findings"))
            .unwrap()
            .unwrap();
        let retained = f.store.open_dir(&findings, &name(&id)).unwrap().unwrap();
        let record = f
            .store
            .read_record::<Finding>(&retained, &name("finding.json"))
            .unwrap()
            .unwrap();
        assert_eq!(record.record().kind, kind);
        assert_eq!(record.record().admission, f.job);
        assert_eq!(
            Digest::of(&fs::read(root.join("bundle")).unwrap()),
            record.record().artifact.as_ref().unwrap().bundle.unwrap()
        );
        if kind == FindingKind::Violation {
            assert_eq!(
                record
                    .record()
                    .artifact
                    .as_ref()
                    .unwrap()
                    .summary
                    .as_ref()
                    .unwrap()
                    .identity,
                Some(text("failure identity v1"))
            );
        }
        if kind == FindingKind::Panic {
            assert_eq!(
                fs::read(root.join("run.stdout")).unwrap(),
                b"run: the run panicked at engine.rs:1:1\n"
            );
        }
        fs::remove_dir_all(f.case.state.join("attempts")).unwrap();
        let before = snapshot(&f.case.state);
        let listed = crate::campaign::findings(&f.case.state).unwrap();
        assert_eq!(listed["findings"][0]["verified"]["kind"], label);
        assert_eq!(listed["findings"][0]["blocker"], blocker);
        assert_eq!(
            listed["release_blockers"].as_array().unwrap().len(),
            usize::from(blocker)
        );
        assert_eq!(snapshot(&f.case.state), before);
        drop(f.store);
        assert_eq!(
            crate::campaign::run(
                "findings",
                &["--state".into(), f.case.state.as_os_str().to_owned()]
            ),
            Supervisor::Success
        );
    }
}

#[test]
fn status_reports_a_retained_violation_through_verified_job_and_group_rows() {
    let f = fixture(FindingKind::Violation);
    f.settle().unwrap();
    let id = format!("{}-0001", f.job.job().id());
    drop(f.store);
    let before = snapshot(&f.case.state);
    let shown = crate::campaign::status_tests::status(&f.case.state).unwrap();
    let listed = crate::campaign::findings(&f.case.state).unwrap();
    assert_eq!(snapshot(&f.case.state), before);
    assert_eq!(shown["findings"], listed["findings"]);
    assert_eq!(shown["release_blockers"], serde_json::json!([id]));
    let job = &shown["jobs"][0];
    assert_eq!(job["state"], "settled", "{job}");
    assert_eq!(job["result"]["class"], "violation");
    assert_eq!(job["pin"]["class"], "violation");
    let attempt = &job["attempts"][0];
    assert_eq!(attempt["number"], 1, "{attempt}");
    assert_eq!(attempt["captured"], true);
    assert_eq!(attempt["finding"], id);
    assert_eq!(attempt["sim"]["identity"], "failure identity v1");
    let groups = shown["failure_groups"].as_array().unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0]["kind"], "violation");
    assert_eq!(groups[0]["identity"], "failure identity v1");
    assert_eq!(groups[0]["findings"], serde_json::json!([id]));
    assert_eq!(groups[0]["profiles"], serde_json::json!(["upload"]));
    assert_eq!(groups[0]["runs"], serde_json::json!([0]));
    assert_eq!(groups[0]["unresolved"], 1);
}

#[test]
fn status_codes_held_triage_and_ends_with_a_host_fault_on_finding_reads() {
    let f = fixture(FindingKind::Violation);
    f.settle().unwrap();
    let id = format!("{}-0001", f.job.job().id());
    f.store.mkdir(f.store.root(), &name("triage")).unwrap();
    let triage = f
        .store
        .open_dir(f.store.root(), &name("triage"))
        .unwrap()
        .unwrap();
    f.store.mkdir(&triage, &name(&id)).unwrap();
    let history = f.store.open_dir(&triage, &name(&id)).unwrap().unwrap();
    f.store.mkdir(&history, &name("steps")).unwrap();
    let steps = f.store.open_dir(&history, &name("steps")).unwrap().unwrap();
    f.store.mkdir(&steps, &name("0001")).unwrap();
    drop((steps, history, triage));
    drop(f.store);
    assert_eq!(
        dispose(&f.case.state, &id, "harness", "harness evidence"),
        Supervisor::Success
    );
    let before = snapshot(&f.case.state);
    let listed = crate::campaign::findings(&f.case.state).unwrap();
    let (clean, reached) = crate::store::fixture::scripted([], || {
        crate::campaign::status_tests::status(&f.case.state)
    });
    let shown = clean.unwrap().unwrap();
    let held = &listed["findings"][0]["triage"];
    assert_eq!(held["held"], "minted triage step lacks record", "{held}");
    assert!(held.get("held_code").is_none());
    let mut coded = held.clone();
    coded["held_code"] = "binding".into();
    assert_eq!(shown["findings"][0]["triage"], coded);
    assert_eq!(
        shown["findings"][0]["dispositions"][0]["decision"],
        "harness"
    );
    for (index, at) in reached.iter().enumerate() {
        let (result, _) = crate::store::fixture::scripted(
            [(index, crate::step::Outcome::Errno(libc::EIO))],
            || crate::campaign::status_tests::status(&f.case.state),
        );
        let error = result.unwrap().expect_err("a host fault ends the snapshot");
        assert!(error.host_fault(), "{index} {at:?}: {error}");
        assert_eq!(snapshot(&f.case.state), before);
    }
}

#[test]
fn status_reports_a_resolved_finding_without_a_sync() {
    let f = fixture(FindingKind::Violation);
    f.settle().unwrap();
    let id = format!("{}-0001", f.job.job().id());
    drop(f.store);
    assert_eq!(
        dispose(&f.case.state, &id, "resolved", "verified fix"),
        Supervisor::Success
    );
    let before = snapshot(&f.case.state);
    let (shown, reached) = crate::store::fixture::scripted([], || {
        crate::campaign::status_tests::status(&f.case.state)
    });
    let shown = shown.unwrap().unwrap();
    assert_eq!(snapshot(&f.case.state), before);
    assert!(
        !reached.contains(&crate::step::Step::Sync),
        "status issued an fsync: {reached:?}"
    );
    assert_eq!(shown["findings"][0]["resolved"], true);
    assert_eq!(shown["release_blockers"], serde_json::json!([]));
    assert_eq!(shown["failure_groups"][0]["unresolved"], 0);
    let (listed, reached) =
        crate::store::fixture::scripted([], || crate::campaign::findings(&f.case.state));
    assert!(
        reached.contains(&crate::step::Step::Sync),
        "findings makes the records it lists durable"
    );
    assert_eq!(listed.unwrap().unwrap()["findings"], shown["findings"]);
}

fn dispose(path: &std::path::Path, id: &str, decision: &str, evidence: &str) -> Supervisor {
    crate::campaign::run(
        "dispose",
        &[
            "--state".into(),
            path.as_os_str().to_owned(),
            "--finding".into(),
            id.into(),
            "--disposition".into(),
            decision.into(),
            "--evidence".into(),
            evidence.into(),
        ],
    )
}

#[test]
fn cli_dispositions_append_preserve_prior_bytes_and_only_latest_resolved_clears() {
    for kind in [
        FindingKind::Violation,
        FindingKind::Panic,
        FindingKind::Abort,
    ] {
        let f = fixture(kind);
        f.settle().unwrap();
        let id = format!("{}-0001", f.job.job().id());
        let root = f.case.state.join("findings").join(&id);
        drop(f.store);
        for evidence in ["", "   "] {
            let before = snapshot(&f.case.state);
            assert_eq!(
                dispose(&f.case.state, &id, "resolved", evidence),
                Supervisor::Rejected
            );
            assert_eq!(snapshot(&f.case.state), before);
        }
        for (finding, decision) in [
            (&id[..], "infrastructure"),
            ("unknown-0001", "resolved"),
            ("invalid/id", "resolved"),
        ] {
            let before = snapshot(&f.case.state);
            assert_eq!(
                dispose(&f.case.state, finding, decision, "evidence"),
                Supervisor::Rejected
            );
            assert_eq!(snapshot(&f.case.state), before);
            assert_eq!(
                crate::campaign::findings(&f.case.state).unwrap()["release_blockers"],
                serde_json::json!([id])
            );
        }
        let before = snapshot(&f.case.state);
        assert!(matches!(
            crate::campaign::dispose(
                &f.case.state,
                text(&id),
                crate::record::Decision::Resolved,
                text("")
            ),
            Err(crate::campaign::Error::Rejected(_))
        ));
        assert_eq!(snapshot(&f.case.state), before);
        let mut previous = Vec::new();
        for (index, (decision, blocker)) in [
            ("harness", true),
            ("resolved", false),
            ("harness", true),
            ("release-blocker", true),
            ("resolved", false),
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(
                dispose(&f.case.state, &id, decision, "replay and fix evidence"),
                Supervisor::Success
            );
            for (entry, bytes) in &previous {
                assert_eq!(&fs::read(root.join(entry)).unwrap(), bytes);
            }
            let entry = format!("{:04}.disposition.json", index + 1);
            previous.push((entry.clone(), fs::read(root.join(entry)).unwrap()));
            let before = snapshot(&f.case.state);
            let listed = crate::campaign::findings(&f.case.state).unwrap();
            assert_eq!(listed["findings"][0]["blocker"], blocker);
            assert_eq!(
                listed["findings"][0]["dispositions"]
                    .as_array()
                    .unwrap()
                    .len(),
                index + 1
            );
            assert_eq!(
                listed["release_blockers"].as_array().unwrap().len(),
                usize::from(blocker)
            );
            assert_eq!(snapshot(&f.case.state), before);
        }
    }
}

#[test]
fn held_findings_histories_and_dependencies_remain_blockers_and_refuse_dispose() {
    for fault in [
        "finding",
        "corrupt",
        "gap",
        "short-number",
        "malformed-number",
        "wrong-finding",
        "bundle",
        "symlink",
        "orphan",
        "number",
        "non-directory",
    ] {
        let f = fixture(FindingKind::Violation);
        f.settle().unwrap();
        let id = format!("{}-0001", f.job.job().id());
        let root = f.case.state.join("findings").join(&id);
        drop(f.store);
        assert_eq!(
            dispose(&f.case.state, &id, "resolved", "verified fix"),
            Supervisor::Success
        );
        match fault {
            "finding" => fs::write(root.join("finding.json"), b"corrupt").unwrap(),
            "corrupt" => fs::write(root.join("0001.disposition.json"), b"corrupt").unwrap(),
            "gap" => {
                let store = Store::open(&f.case.state).unwrap();
                let findings = store
                    .open_dir(store.root(), &name("findings"))
                    .unwrap()
                    .unwrap();
                let dir = store.open_dir(&findings, &name(&id)).unwrap().unwrap();
                let record = crate::record::Disposition::new(
                    text(&id),
                    2,
                    crate::record::Decision::Resolved,
                    text("evidence"),
                )
                .unwrap();
                store
                    .create_record(&dir, &name("0002.disposition.json"), &record)
                    .unwrap();
                store.delete(&dir, &name("0001.disposition.json")).unwrap();
            }
            "short-number" => fs::rename(
                root.join("0001.disposition.json"),
                root.join("1.disposition.json"),
            )
            .unwrap(),
            "malformed-number" => fs::rename(
                root.join("0001.disposition.json"),
                root.join("x.disposition.json"),
            )
            .unwrap(),
            "wrong-finding" | "number" => {
                let store = Store::open(&f.case.state).unwrap();
                let findings = store
                    .open_dir(store.root(), &name("findings"))
                    .unwrap()
                    .unwrap();
                let dir = store.open_dir(&findings, &name(&id)).unwrap().unwrap();
                let record = crate::record::Disposition::new(
                    text(if fault == "wrong-finding" {
                        "another"
                    } else {
                        &id
                    }),
                    if fault == "number" { 2 } else { 1 },
                    crate::record::Decision::Resolved,
                    text("evidence"),
                )
                .unwrap();
                store
                    .replace_record(&dir, &name("0001.disposition.json"), &record)
                    .unwrap();
            }
            "bundle" => fs::write(root.join("bundle"), b"changed").unwrap(),
            "symlink" => {
                fs::remove_file(root.join("0001.disposition.json")).unwrap();
                std::os::unix::fs::symlink("finding.json", root.join("0001.disposition.json"))
                    .unwrap();
            }
            "orphan" => fs::remove_file(root.join("finding.json")).unwrap(),
            "non-directory" => {
                fs::remove_dir_all(&root).unwrap();
                fs::write(&root, b"not a directory").unwrap();
            }
            _ => unreachable!(),
        }
        let before = snapshot(&f.case.state);
        let listed = crate::campaign::findings(&f.case.state).unwrap();
        assert!(listed["findings"][0].get("held").is_some(), "{fault}");
        if let Some(reason) = match fault {
            "gap" => Some("disposition history has gaps"),
            "short-number" => Some("noncanonical disposition number"),
            "malformed-number" => Some("invalid disposition number"),
            "number" | "wrong-finding" => Some("disposition binding differs"),
            _ => None,
        } {
            assert_eq!(listed["findings"][0]["held"], reason);
        }
        assert_eq!(listed["release_blockers"], serde_json::json!([id]));
        assert_eq!(
            dispose(&f.case.state, &id, "resolved", "more evidence"),
            Supervisor::Held,
            "{fault}"
        );
        assert_eq!(snapshot(&f.case.state), before, "{fault}");
    }
}

#[test]
fn explicit_blocker_dispositions_keep_nonrelease_kinds_blocked_until_latest_resolved() {
    let f = fixture(FindingKind::Watchdog);
    f.settle().unwrap();
    let id = format!("{}-0001", f.job.job().id());
    drop(f.store);
    for (decision, blocker) in [
        ("harness", false),
        ("release-blocker", true),
        ("harness", true),
        ("resolved", false),
        ("harness", true),
    ] {
        assert_eq!(
            dispose(&f.case.state, &id, decision, "evidence"),
            Supervisor::Success
        );
        assert_eq!(
            crate::campaign::findings(&f.case.state).unwrap()["findings"][0]["blocker"],
            blocker
        );
    }
}

#[test]
fn dispose_refuses_unmarked_state_and_symlinked_ancestors_before_writing() {
    let case = crate::store::fixture::Case::new();
    let before = snapshot(&case.state);
    assert_eq!(
        dispose(&case.state, "finding", "resolved", "evidence"),
        Supervisor::Held
    );
    assert_eq!(snapshot(&case.state), before);
    let f = fixture(FindingKind::Violation);
    f.settle().unwrap();
    let id = format!("{}-0001", f.job.job().id());
    drop(f.store);
    let alias = f.case.root.join("alias");
    std::os::unix::fs::symlink(&f.case.root, &alias).unwrap();
    let before = snapshot(&f.case.state);
    assert_eq!(
        dispose(&alias.join("state"), &id, "resolved", "evidence"),
        Supervisor::Rejected
    );
    assert_eq!(snapshot(&f.case.state), before);
}

#[test]
fn abnormal_exit_is_abort_and_panic_evidence_wins_over_a_crash_signal() {
    for (kind, exit, signal) in [
        (FindingKind::Abort, Some(134), None),
        (FindingKind::Panic, None, Some(libc::SIGABRT as u64)),
    ] {
        let f = fixture(kind);
        let dir = f.artifact_directory(1);
        let mut artifact = f
            .store
            .read_record::<Artifact>(&dir, &name("artifact"))
            .unwrap()
            .unwrap()
            .record()
            .clone();
        let worker = artifact.workers.get_mut(&text("run")).unwrap();
        worker.exit = exit;
        worker.signal = signal;
        worker.ended = text(if signal.is_some() {
            "signaled"
        } else {
            "exited"
        });
        f.store
            .replace_record(&dir, &name("artifact"), &artifact)
            .unwrap();
        rebind(&f, Class::EngineFailure);
        f.settle().unwrap();
        assert_eq!(
            crate::campaign::findings(&f.case.state).unwrap()["findings"][0]["verified"]["kind"],
            match kind {
                FindingKind::Abort => "abort",
                FindingKind::Panic => "panic",
                _ => unreachable!(),
            }
        );
    }
}

#[test]
fn passing_retry_preserves_the_first_truncated_finding() {
    let f = fixture(FindingKind::Truncated);
    assert!(f.settle().unwrap().is_none());
    let id = format!("{}-0001", f.job.job().id());
    let bytes = fs::read(f.case.state.join("findings").join(&id).join("finding.json")).unwrap();
    f.add(2, Class::Pass);
    assert_eq!(
        f.settle().unwrap().unwrap().record().finished.class,
        Class::Pass
    );
    assert_eq!(
        fs::read(f.case.state.join("findings").join(&id).join("finding.json")).unwrap(),
        bytes
    );
    let listed = crate::campaign::findings(&f.case.state).unwrap();
    assert_eq!(listed["findings"].as_array().unwrap().len(), 1);
    assert_eq!(listed["findings"][0]["verified"]["kind"], "truncated");
    assert_eq!(listed["release_blockers"], serde_json::json!([]));
}

#[test]
fn verified_watchdog_without_bound_artifact_is_retained_and_can_be_promoted() {
    let f = Fixture::new(&[Class::Watchdog]);
    let directory = f.directory(1);
    fs::remove_dir_all(f.attempt_path(1).join("artifacts")).unwrap();
    let mut finished = f
        .store
        .read_record::<Finished>(&directory, &name("finished"))
        .unwrap()
        .unwrap()
        .record()
        .clone();
    finished.binding = crate::record::Binding::Missing;
    finished.bound = None;
    f.store
        .replace_record(&directory, &name("finished"), &finished)
        .unwrap();
    f.store
        .create_once(
            &directory,
            &name("unbound.log"),
            b"thread 'main' panicked at unrelated",
        )
        .unwrap();
    assert!(f.settle().unwrap().is_none());
    let id = format!("{}-0001", f.job.job().id());
    let path = f.case.state.join("findings").join(&id);
    let bytes = fs::read(path.join("finding.json")).unwrap();
    f.settle().unwrap();
    assert_eq!(fs::read(path.join("finding.json")).unwrap(), bytes);
    fs::remove_dir_all(f.case.state.join("attempts")).unwrap();
    fs::remove_dir_all(f.case.state.join("jobs")).unwrap();
    let before = snapshot(&f.case.state);
    let listed = crate::campaign::findings(&f.case.state).unwrap();
    let row = &listed["findings"][0];
    assert!(row.get("held").is_none());
    assert_eq!(row["verified"]["kind"], "watchdog");
    assert_eq!(row["verified"]["artifact"], serde_json::Value::Null);
    assert_eq!(
        row["verified"]["finished"],
        serde_json::to_value(&finished).unwrap()
    );
    assert_eq!(row["blocker"], false);
    assert_eq!(listed["release_blockers"], serde_json::json!([]));
    assert_eq!(snapshot(&f.case.state), before);
    drop(f.store);
    for (decision, blocker) in [
        ("release-blocker", true),
        ("harness", true),
        ("resolved", false),
        ("harness", true),
    ] {
        assert_eq!(
            dispose(&f.case.state, &id, decision, "evidence"),
            Supervisor::Success
        );
        assert_eq!(
            crate::campaign::findings(&f.case.state).unwrap()["findings"][0]["blocker"],
            blocker
        );
    }
}

#[test]
fn unbound_signal_and_interrupted_attempts_grant_no_worker_finding() {
    for class in [Class::Signal, Class::Interrupted] {
        let f = Fixture::new(&[class]);
        let directory = f.directory(1);
        fs::remove_dir_all(f.attempt_path(1).join("artifacts")).unwrap();
        let mut finished = f
            .store
            .read_record::<Finished>(&directory, &name("finished"))
            .unwrap()
            .unwrap()
            .record()
            .clone();
        finished.binding = crate::record::Binding::Missing;
        finished.bound = None;
        f.store
            .replace_record(&directory, &name("finished"), &finished)
            .unwrap();
        assert!(f.settle().unwrap().is_none());
        assert!(!f.case.state.join("findings").exists());
    }
}

#[test]
fn bound_truncated_terminal_yields_truncated_finding() {
    let f = fixture(FindingKind::Truncated);
    let dir = f.artifact_directory(1);
    let mut artifact = f
        .store
        .read_record::<Artifact>(&dir, &name("artifact"))
        .unwrap()
        .unwrap()
        .record()
        .clone();
    artifact.workers.get_mut(&text("run")).unwrap().ended = text("exited");
    artifact.workers.get_mut(&text("run")).unwrap().exit = Some(3);
    artifact.summary.as_mut().unwrap().terminal = text("infrastructure truncated");
    artifact.summary.as_mut().unwrap().counts = false;
    f.store
        .replace_record(&dir, &name("artifact"), &artifact)
        .unwrap();
    rebind(&f, Class::Incomplete);
    f.settle().unwrap();
    let listed = crate::campaign::findings(&f.case.state).unwrap();
    assert_eq!(listed["findings"][0]["verified"]["kind"], "truncated");
    assert_eq!(listed["release_blockers"], serde_json::json!([]));
}

#[test]
fn settlement_holds_damaged_retained_copies_and_preserves_existing_bytes() {
    for fault in ["bundle", "stream", "record"] {
        let f = fixture(FindingKind::Violation);
        f.settle().unwrap();
        let id = format!("{}-0001", f.job.job().id());
        let path = f.case.state.join("findings").join(&id);
        match fault {
            "bundle" => fs::write(path.join("bundle"), b"changed").unwrap(),
            "stream" => fs::remove_file(path.join("run.stderr")).unwrap(),
            "record" => {
                let root = f
                    .store
                    .open_dir(f.store.root(), &name("findings"))
                    .unwrap()
                    .unwrap();
                let dir = f.store.open_dir(&root, &name(&id)).unwrap().unwrap();
                let mut record = f
                    .store
                    .read_record::<Finding>(&dir, &name("finding.json"))
                    .unwrap()
                    .unwrap()
                    .record()
                    .clone();
                record.kind = FindingKind::Panic;
                f.store
                    .replace_record(&dir, &name("finding.json"), &record)
                    .unwrap();
            }
            _ => unreachable!(),
        }
        let before = snapshot(&f.case.state);
        assert!(
            matches!(f.settle(), Err(crate::attempt::Error::Held(reason)) if reason == if fault == "record" { "retained finding differs" } else { "retained finding dependency differs" })
        );
        assert_eq!(snapshot(&f.case.state), before);
    }
}

#[test]
fn disposition_syncs_verified_prerequisites_before_its_write() {
    let f = fixture(FindingKind::Violation);
    f.settle().unwrap();
    let id = format!("{}-0001", f.job.job().id());
    drop(f.store);
    for number in 1..=3 {
        let (result, steps) = crate::store::fixture::scripted([], || {
            crate::campaign::dispose(
                &f.case.state,
                text(&id),
                crate::record::Decision::Harness,
                text("evidence"),
            )
        });
        assert!(result.unwrap().is_ok());
        let write = steps
            .iter()
            .position(|step| *step == crate::step::Step::Write)
            .unwrap();
        assert_eq!(
            steps[..write]
                .iter()
                .filter(|step| **step == crate::step::Step::Sync)
                .count(),
            3 + 2 * number
        );
        assert_eq!(
            steps
                .iter()
                .filter(|step| **step == crate::step::Step::Sync)
                .count(),
            3 + 2 * number + 4
        );
    }
}

#[test]
fn disposition_rejects_a_state_replacement_between_preflight_and_lock() {
    let f = fixture(FindingKind::Violation);
    f.settle().unwrap();
    let id = format!("{}-0001", f.job.job().id());
    drop(f.store);
    let before = snapshot(&f.case.state);
    let (result, steps) = crate::store::fixture::scripted([], || {
        crate::store::given_ancestors(&f.case.state).unwrap();
        crate::store::View::open(&f.case.state)
            .unwrap()
            .require_state_marker()
            .unwrap();
    });
    assert!(result.is_some());
    let reads = steps
        .iter()
        .filter(|step| **step == crate::step::Step::Read)
        .count();
    assert!(reads > 0);
    let moved = f.case.root.join("moved");
    let state = f.case.state.clone();
    let target = moved.clone();
    let changed = std::rc::Rc::new(std::cell::Cell::new(false));
    let witness = changed.clone();
    let mut seen = 0;
    let result = crate::store::fixture::observed(
        move |step| {
            if step == crate::step::Step::Read {
                seen += 1;
                if seen == reads {
                    crate::store::fixture::replace(&state, &target);
                    changed.set(true);
                }
            }
        },
        || {
            crate::campaign::dispose(
                &f.case.state,
                text(&id),
                crate::record::Decision::Resolved,
                text("evidence"),
            )
        },
    );
    assert!(witness.get());
    assert!(
        matches!(result, Err(crate::campaign::Error::Held(reason)) if reason == "state changed before disposition")
    );
    assert_eq!(snapshot(&moved), before);
    assert!(!f.case.state.join("findings").exists());
}

#[test]
fn findings_holds_a_replaced_state_and_preserves_the_read_tree() {
    let f = fixture(FindingKind::Violation);
    f.settle().unwrap();
    drop(f.store);
    let before = snapshot(&f.case.state);
    let (_, steps) = crate::store::fixture::scripted([], || {
        crate::store::View::open(&f.case.state)
            .unwrap()
            .require_state_marker()
            .unwrap()
    });
    let reads = steps
        .iter()
        .filter(|step| **step == crate::step::Step::Read)
        .count();
    assert!(reads > 0);
    let moved = f.case.root.join("moved");
    let target = moved.clone();
    let state = f.case.state.clone();
    let changed = std::rc::Rc::new(std::cell::Cell::new(false));
    let witness = changed.clone();
    let mut seen = 0;
    let result = crate::store::fixture::observed(
        move |step| {
            if step == crate::step::Step::Read {
                seen += 1;
                if seen == reads + 1 {
                    crate::store::fixture::replace(&state, &target);
                    changed.set(true);
                }
            }
        },
        || crate::campaign::findings(&f.case.state),
    );
    assert!(witness.get());
    assert!(
        matches!(result, Err(crate::campaign::Error::Held(reason)) if reason == "state moved during findings")
    );
    assert_eq!(snapshot(&moved), before);
    assert_eq!(snapshot(&f.case.state).len(), 0);
}

#[test]
fn descriptor_exhaustion_holds_append_with_named_limit_and_preserves_history() {
    let baseline = fixture(FindingKind::Violation);
    baseline.settle().unwrap();
    let id = format!("{}-0001", baseline.job.job().id());
    drop(baseline.store);
    assert_eq!(
        dispose(&baseline.case.state, &id, "harness", "evidence"),
        Supervisor::Success
    );
    let (result, steps) = crate::store::fixture::scripted([], || {
        crate::campaign::dispose(
            &baseline.case.state,
            text(&id),
            crate::record::Decision::Resolved,
            text("evidence"),
        )
    });
    assert!(result.unwrap().is_ok());
    let write = steps
        .iter()
        .position(|step| *step == crate::step::Step::Write)
        .unwrap();
    let cut = steps[..write]
        .iter()
        .rposition(|step| *step == crate::step::Step::Open)
        .unwrap();
    let f = fixture(FindingKind::Violation);
    f.settle().unwrap();
    drop(f.store);
    assert_eq!(
        dispose(&f.case.state, &id, "harness", "evidence"),
        Supervisor::Success
    );
    let before = snapshot(&f.case.state);
    let (result, _) =
        crate::store::fixture::scripted([(cut, crate::step::Outcome::Errno(libc::EMFILE))], || {
            crate::campaign::dispose(
                &f.case.state,
                text(&id),
                crate::record::Decision::Resolved,
                text("evidence"),
            )
        });
    let error = result.unwrap().unwrap_err();
    assert!(
        error
            .to_string()
            .contains("descriptor limit reached (RLIMIT_NOFILE)")
    );
    assert_eq!(snapshot(&f.case.state), before);
    let (result, _) =
        crate::store::fixture::scripted([(cut, crate::step::Outcome::Errno(libc::EMFILE))], || {
            dispose(&f.case.state, &id, "resolved", "evidence")
        });
    assert_eq!(result.unwrap(), Supervisor::Held);
    assert_eq!(crate::exit::Exit::Supervisor(Supervisor::Held).code(), 4);
    assert_eq!(snapshot(&f.case.state), before);
    assert_eq!(
        crate::campaign::findings(&f.case.state).unwrap()["release_blockers"],
        serde_json::json!([id])
    );
}

fn rebind(f: &Fixture, class: Class) {
    let directory = f.directory(1);
    let attempt = f
        .store
        .read_record::<crate::record::Attempt>(&directory, &name("attempt"))
        .unwrap()
        .unwrap();
    let evidence = crate::attempt::binding::read(&f.store, &directory, attempt.record()).unwrap();
    let mut finished = f
        .store
        .read_record::<Finished>(&directory, &name("finished"))
        .unwrap()
        .unwrap()
        .record()
        .clone();
    finished.bound = evidence.binding().cloned();
    finished.class = class;
    assert_eq!(
        crate::attempt::classify::classify(&finished, &evidence),
        class
    );
    f.store
        .replace_record(&directory, &name("bound"), finished.bound.as_ref().unwrap())
        .unwrap();
    f.store
        .replace_record(&directory, &name("finished"), &finished)
        .unwrap();
}

#[test]
fn bound_product_kinds_survive_each_resource_limit_and_noncrash_signal() {
    for kind in [
        FindingKind::Violation,
        FindingKind::Panic,
        FindingKind::Abort,
        FindingKind::Truncated,
    ] {
        for class in [
            Class::Oom,
            Class::PidLimit,
            Class::CpuLimit,
            Class::MixedLimits,
            Class::OutputLimit,
        ] {
            let f = fixture(kind);
            let dir = f.directory(1);
            let mut finish = f
                .store
                .read_record::<Finished>(&dir, &name("finished"))
                .unwrap()
                .unwrap()
                .record()
                .clone();
            finish.class = class;
            match class {
                Class::Oom => {
                    finish.kernel.memory.insert(text("oom"), 1);
                }
                Class::PidLimit => {
                    finish.kernel.pids.insert(text("max"), 1);
                }
                Class::CpuLimit => finish.signal = Some(libc::SIGXCPU as u64),
                Class::MixedLimits => {
                    finish.kernel.memory.insert(text("oom"), 1);
                    finish.kernel.pids.insert(text("max"), 1);
                }
                Class::OutputLimit => finish.signal = Some(libc::SIGXFSZ as u64),
                _ => unreachable!(),
            }
            if class == Class::OutputLimit {
                finish.class = match kind {
                    FindingKind::Engine => Class::EngineFailure,
                    FindingKind::Unsuccessful => Class::Unsuccessful,
                    FindingKind::Inconclusive => Class::Inconclusive,
                    FindingKind::Incomplete => Class::Incomplete,
                    FindingKind::Violation => Class::Violation,
                    FindingKind::Panic | FindingKind::Abort => Class::EngineFailure,
                    _ => Class::OutputLimit,
                };
            }
            f.store
                .replace_record(&dir, &name("finished"), &finish)
                .unwrap();
            f.settle().unwrap();
            let listed = crate::campaign::findings(&f.case.state).unwrap();
            assert_eq!(listed["findings"][0]["verified"]["kind"], kind.name());
            assert_eq!(
                listed["findings"][0]["blocker"],
                kind != FindingKind::Truncated
            );
        }
    }
    for signal in [libc::SIGTERM, libc::SIGKILL, libc::SIGHUP, libc::SIGQUIT] {
        let f = fixture(FindingKind::Abort);
        let dir = f.artifact_directory(1);
        let mut artifact = f
            .store
            .read_record::<Artifact>(&dir, &name("artifact"))
            .unwrap()
            .unwrap()
            .record()
            .clone();
        artifact.workers.get_mut(&text("run")).unwrap().signal = Some(signal as u64);
        f.store
            .replace_record(&dir, &name("artifact"), &artifact)
            .unwrap();
        rebind(&f, Class::Signal);
        f.settle().unwrap();
        assert_eq!(
            crate::campaign::findings(&f.case.state).unwrap()["findings"][0]["verified"]["kind"],
            "abort"
        );
    }
}

#[test]
fn capture_markers_skip_old_evidence_backfill_and_refuse_digest_mismatches() {
    let f = fixture(FindingKind::Violation);
    let directory = f.directory(1);
    let mut finish = f
        .store
        .read_record::<Finished>(&directory, &name("finished"))
        .unwrap()
        .unwrap()
        .record()
        .clone();
    finish.class = Class::Oom;
    finish.kernel.memory.insert(text("oom"), 1);
    f.store
        .replace_record(&directory, &name("finished"), &finish)
        .unwrap();
    assert!(f.settle().unwrap().is_none());
    let marker = f
        .store
        .read_record::<crate::record::Captured>(&directory, &name("captured"))
        .unwrap()
        .unwrap();
    assert_eq!(
        marker.record().finished,
        Digest::of(
            f.store
                .read_record::<Finished>(&directory, &name("finished"))
                .unwrap()
                .unwrap()
                .read()
                .bytes()
        )
    );
    assert_eq!(
        marker.record().finding.as_ref().unwrap().as_str(),
        finish.attempt.as_str()
    );
    fs::remove_dir_all(f.attempt_path(1).join("artifacts")).unwrap();
    f.add(2, Class::Pass);
    assert_eq!(f.settle().unwrap().unwrap().record().attempt, 2);
    let listed = crate::campaign::findings(&f.case.state).unwrap();
    assert_eq!(
        listed["release_blockers"],
        serde_json::json!([finish.attempt.as_str()])
    );
    let mut changed = marker.record().clone();
    changed.finished = Digest::of(b"foreign finish");
    f.store
        .replace_record(&directory, &name("captured"), &changed)
        .unwrap();
    let before = snapshot(&f.case.state);
    assert!(matches!(
        f.settle(),
        Err(crate::attempt::Error::Held(
            "capture marker binding differs"
        ))
    ));
    assert_eq!(snapshot(&f.case.state), before);

    let f = fixture(FindingKind::Truncated);
    f.settle().unwrap();
    let before = snapshot(&f.case.state);
    fs::remove_file(f.attempt_path(1).join("captured")).unwrap();
    f.settle().unwrap();
    assert_eq!(snapshot(&f.case.state), before);
    let f = f.reopen();
    f.settle().unwrap();
    assert_eq!(snapshot(&f.case.state), before);
}

#[test]
fn current_failure_is_retained_before_a_damaged_prior_attempt_holds_settlement() {
    let f = fixture(FindingKind::Truncated);
    f.settle().unwrap();
    f.add(2, Class::Violation);
    fs::write(f.attempt_path(1).join("finished"), b"damaged").unwrap();
    assert!(f.settle().is_err());
    let root = f
        .case
        .state
        .join("findings")
        .join(format!("{}-0002", f.job.job().id()));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&fs::read(root.join("finding.json")).unwrap())
            .unwrap()["record"]["kind"],
        "violation"
    );
    assert!(!f.path("pin").exists());
    assert!(!f.path("result").exists());
}

#[test]
fn listing_holds_uncaptured_finishes_and_unknown_history_preserves_prior_bytes() {
    let f = fixture(FindingKind::Violation);
    let id = format!("{}-0001", f.job.job().id());
    assert_eq!(
        crate::campaign::findings(&f.case.state).unwrap()["release_blockers"],
        serde_json::json!([id])
    );
    f.settle().unwrap();
    drop(f.store);
    let first = crate::campaign::dispose(
        &f.case.state,
        text(&id),
        crate::record::Decision::Resolved,
        text("replay verified"),
    )
    .unwrap();
    assert_eq!(first["disposition"]["decision"], "resolved");
    assert_eq!(first["disposition"]["evidence"], "replay verified");
    crate::campaign::dispose(
        &f.case.state,
        text(&id),
        crate::record::Decision::ReleaseBlocker,
        text("new evidence"),
    )
    .unwrap();
    let dir = f.case.state.join("findings").join(&id);
    fs::rename(
        dir.join("0002.disposition.json"),
        dir.join("0002.disposition.jsom"),
    )
    .unwrap();
    let before = snapshot(&f.case.state);
    let listed = crate::campaign::findings(&f.case.state).unwrap();
    assert_eq!(listed["release_blockers"], serde_json::json!([id]));
    assert!(
        listed["findings"][0]["held"]
            .as_str()
            .unwrap()
            .contains("unknown finding entry")
    );
    assert!(
        crate::campaign::dispose(
            &f.case.state,
            text(&id),
            crate::record::Decision::Resolved,
            text("evidence")
        )
        .is_err()
    );
    assert_eq!(snapshot(&f.case.state), before);
}

#[test]
fn bundleless_abort_retains_a_blocker_after_a_harness_disposition() {
    let f = fixture(FindingKind::Abort);
    let dir = f.artifact_directory(1);
    let mut artifact = f
        .store
        .read_record::<Artifact>(&dir, &name("artifact"))
        .unwrap()
        .unwrap()
        .record()
        .clone();
    artifact.bundle = None;
    fs::remove_file(
        f.attempt_path(1)
            .join("artifacts")
            .join(format!("{}-0001", f.job.job().id()))
            .join("bundle"),
    )
    .unwrap();
    f.store
        .replace_record(&dir, &name("artifact"), &artifact)
        .unwrap();
    rebind(&f, Class::EngineFailure);
    f.settle().unwrap();
    let listed = crate::campaign::findings(&f.case.state).unwrap();
    let id = format!("{}-0001", f.job.job().id());
    assert_eq!(listed["findings"][0]["verified"]["kind"], "abort");
    assert_eq!(listed["release_blockers"], serde_json::json!([id]));
    drop(f.store);
    assert!(
        crate::campaign::dispose(
            &f.case.state,
            text(&id),
            crate::record::Decision::Harness,
            text("evidence")
        )
        .is_ok()
    );
}

#[test]
fn successful_verdicts_have_no_finding_and_empty_evidence_leaves_a_missing_state_absent() {
    for class in [Class::Pass, Class::Unsuccessful, Class::Inconclusive] {
        let f = Fixture::new(&[class]);
        f.settle().unwrap();
        assert!(!f.case.state.join("findings").exists());
    }
    let f = fixture(FindingKind::Violation);
    let absent = f.case.root.join("absent");
    assert!(matches!(
        crate::campaign::dispose(
            &absent,
            text("finding"),
            crate::record::Decision::Resolved,
            text(" ")
        ),
        Err(crate::campaign::Error::Rejected(_))
    ));
    assert!(!absent.exists());
}

#[test]
fn listing_holds_damaged_retained_manifest_and_stream() {
    for file in ["manifest", "run.stdout", "run.stderr"] {
        let f = fixture(FindingKind::Violation);
        f.settle().unwrap();
        let id = format!("{}-0001", f.job.job().id());
        fs::write(
            f.case.state.join("findings").join(&id).join(file),
            b"changed",
        )
        .unwrap();
        let before = snapshot(&f.case.state);
        let listed = crate::campaign::findings(&f.case.state).unwrap();
        assert_eq!(listed["release_blockers"], serde_json::json!([id]));
        assert!(listed["findings"][0].get("held_code").is_some());
        assert_eq!(snapshot(&f.case.state), before);
    }
}

#[test]
fn existing_result_backfills_a_missing_finding_and_marker() {
    let f = fixture(FindingKind::Violation);
    f.settle().unwrap();
    let before = snapshot(&f.case.state);
    fs::remove_dir_all(f.case.state.join("findings")).unwrap();
    fs::remove_file(f.attempt_path(1).join("captured")).unwrap();
    f.settle().unwrap();
    assert_eq!(snapshot(&f.case.state), before);
}

#[test]
fn disposition_crash_cuts_and_barrier_faults_preserve_prior_bytes_and_safe_recovery() {
    let create = || {
        let f = fixture(FindingKind::Violation);
        f.settle().unwrap();
        let id = format!("{}-0001", f.job.job().id());
        drop(f.store);
        crate::campaign::dispose(
            &f.case.state,
            text(&id),
            crate::record::Decision::Harness,
            text("original evidence"),
        )
        .unwrap();
        (f.case, id)
    };
    let append = |case: &crate::store::fixture::Case, id: &str| {
        crate::campaign::dispose(
            &case.state,
            text(id),
            crate::record::Decision::Resolved,
            text("verified replay"),
        )
    };
    let (base, id) = create();
    let (result, steps) = crate::store::fixture::scripted([], || append(&base, &id));
    assert!(result.unwrap().is_ok());
    let expected = fs::read(
        base.state
            .join("findings")
            .join(&id)
            .join("0002.disposition.json"),
    )
    .unwrap();
    for (index, step) in steps.iter().enumerate() {
        let (case, id) = create();
        let path = case.state.join("findings").join(&id);
        let before = fs::read(path.join("0001.disposition.json")).unwrap();
        let (result, reached) =
            crate::store::fixture::scripted([(index, crate::step::Outcome::Kill)], || {
                append(&case, &id)
            });
        assert!(result.is_none(), "{index} {step:?}");
        assert_eq!(reached.last(), Some(step));
        assert_eq!(
            fs::read(path.join("0001.disposition.json")).unwrap(),
            before
        );
        let second = fs::read(path.join("0002.disposition.json")).ok();
        if let Some(bytes) = &second {
            assert_eq!(bytes, &expected);
        }
        append(&case, &id).unwrap();
        assert_eq!(
            fs::read(path.join("0001.disposition.json")).unwrap(),
            before
        );
        assert_eq!(
            fs::read(path.join("0002.disposition.json")).unwrap(),
            expected
        );
        if second.is_some() {
            assert!(path.join("0003.disposition.json").exists());
        }
        assert_eq!(
            crate::campaign::findings(&case.state).unwrap()["release_blockers"],
            serde_json::json!([])
        );
        if *step == crate::step::Step::Sync {
            let (case, id) = create();
            let path = case.state.join("findings").join(&id);
            let before = fs::read(path.join("0001.disposition.json")).unwrap();
            let (result, reached) = crate::store::fixture::scripted(
                [(index, crate::step::Outcome::Errno(libc::EIO))],
                || append(&case, &id),
            );
            assert!(result.unwrap().is_err());
            assert_eq!(reached[index], *step);
            assert!(!reached[index + 1..].contains(&crate::step::Step::Rename));
            assert_eq!(
                fs::read(path.join("0001.disposition.json")).unwrap(),
                before
            );
        }
    }
}

#[test]
fn verified_controller_stops_keep_noncrash_signals_out_of_abort_findings() {
    for (signal, class, watchdog, expected) in [
        (
            libc::SIGKILL,
            Class::Watchdog,
            true,
            Some(FindingKind::Watchdog),
        ),
        (
            libc::SIGSEGV,
            Class::EngineFailure,
            true,
            Some(FindingKind::Abort),
        ),
        (
            libc::SIGTERM,
            Class::Signal,
            false,
            Some(FindingKind::Abort),
        ),
        (libc::SIGXCPU, Class::CpuLimit, false, None),
    ] {
        let f = fixture(FindingKind::Abort);
        let directory = f.artifact_directory(1);
        let mut artifact = f
            .store
            .read_record::<Artifact>(&directory, &name("artifact"))
            .unwrap()
            .unwrap()
            .record()
            .clone();
        artifact.workers.get_mut(&text("run")).unwrap().signal = Some(signal as u64);
        f.store
            .replace_record(&directory, &name("artifact"), &artifact)
            .unwrap();
        let directory = f.directory(1);
        let attempt = f
            .store
            .read_record::<crate::record::Attempt>(&directory, &name("attempt"))
            .unwrap()
            .unwrap();
        let evidence =
            crate::attempt::binding::read(&f.store, &directory, attempt.record()).unwrap();
        let mut finish = f
            .store
            .read_record::<Finished>(&directory, &name("finished"))
            .unwrap()
            .unwrap()
            .record()
            .clone();
        finish.bound = evidence.binding().cloned();
        finish.class = class;
        finish.watchdog = watchdog;
        finish.interruption = (class == Class::CpuLimit).then_some(libc::SIGXCPU as u64);
        assert_eq!(
            crate::attempt::classify::finding_kind(&finish, evidence.into_bound().as_deref()),
            expected
        );
        {
            f.store
                .replace_record(&directory, &name("bound"), finish.bound.as_ref().unwrap())
                .unwrap();
            f.store
                .replace_record(&directory, &name("finished"), &finish)
                .unwrap();
            f.settle().unwrap();
            let listed = crate::campaign::findings(&f.case.state).unwrap();
            assert_eq!(
                !listed["release_blockers"].as_array().unwrap().is_empty(),
                expected.is_some_and(FindingKind::release_blocker)
            );
            if let Some(kind) = expected {
                assert_eq!(listed["findings"][0]["verified"]["kind"], kind.name());
            } else {
                assert!(listed["findings"].as_array().unwrap().is_empty());
            }
        }
    }
}

#[test]
fn renamed_finding_identity_and_legacy_archive_metadata_are_held() {
    let f = fixture(FindingKind::Violation);
    f.settle().unwrap();
    let id = format!("{}-0001", f.job.job().id());
    let path = f.case.state.join("findings");
    fs::rename(path.join(&id), path.join("renamed")).unwrap();
    let listed = crate::campaign::findings(&f.case.state).unwrap();
    assert!(listed["findings"].as_array().unwrap().iter().any(|row| {
        row["id"] == "renamed"
            && row["held"]
                .as_str()
                .unwrap()
                .contains("finding binding differs")
    }));
    fs::rename(path.join("renamed"), path.join(&id)).unwrap();
    let root = f
        .store
        .open_dir(f.store.root(), &name("findings"))
        .unwrap()
        .unwrap();
    let directory = f.store.open_dir(&root, &name(&id)).unwrap().unwrap();
    let mut record = f
        .store
        .read_record::<Finding>(&directory, &name("finding.json"))
        .unwrap()
        .unwrap()
        .record()
        .clone();
    record.artifact.as_mut().unwrap().archive = None;
    f.store
        .replace_record(&directory, &name("finding.json"), &record)
        .unwrap();
    let listed = crate::campaign::findings(&f.case.state).unwrap();
    assert_eq!(listed["release_blockers"], serde_json::json!([id]));
    assert!(
        listed["findings"][0]["held"]
            .as_str()
            .unwrap()
            .contains("finding artifact binding differs")
    );
    let artifact = record.artifact.as_mut().unwrap();
    artifact.archive = Digest::parse(f.job.job().experiment().pins.build.as_str());
    artifact.command = text("replay");
    f.store
        .replace_record(&directory, &name("finding.json"), &record)
        .unwrap();
    let listed = crate::campaign::findings(&f.case.state).unwrap();
    assert!(
        listed["findings"][0]["held"]
            .as_str()
            .unwrap()
            .contains("finding artifact binding differs")
    );
    let shown = crate::campaign::status_tests::status(&f.case.state).unwrap();
    assert_eq!(shown["failure_groups"], serde_json::json!([]));
}

#[test]
fn retained_snapshot_listing_ignores_damage_in_its_original_attempt_records() {
    let f = fixture(FindingKind::Violation);
    f.settle().unwrap();
    let id = format!("{}-0001", f.job.job().id());
    fs::write(f.attempt_path(1).join("finished"), b"damaged original").unwrap();
    fs::write(
        f.attempt_path(1).join("captured"),
        b"damaged original marker",
    )
    .unwrap();
    let listed = crate::campaign::findings(&f.case.state).unwrap();
    assert_eq!(listed["findings"].as_array().unwrap().len(), 1);
    assert!(listed["findings"][0].get("held").is_none());
    assert_eq!(listed["findings"][0]["verified"]["kind"], "violation");
    assert_eq!(listed["release_blockers"], serde_json::json!([id]));
}

#[test]
fn a_missing_retained_finding_keeps_its_capture_marker_as_a_blocker() {
    let f = fixture(FindingKind::Violation);
    let directory = f.directory(1);
    let mut finish = f
        .store
        .read_record::<Finished>(&directory, &name("finished"))
        .unwrap()
        .unwrap()
        .record()
        .clone();
    finish.class = Class::Oom;
    finish.kernel.memory.insert(text("oom"), 1);
    f.store
        .replace_record(&directory, &name("finished"), &finish)
        .unwrap();
    f.settle().unwrap();
    fs::remove_dir_all(f.case.state.join("findings")).unwrap();
    let listed = crate::campaign::findings(&f.case.state).unwrap();
    assert_eq!(
        listed["release_blockers"],
        serde_json::json!([finish.attempt.as_str()])
    );
    assert_eq!(listed["findings"][0]["held_code"], "capture-missing");
}

#[test]
fn output_limit_preserves_bound_violations_and_suppresses_only_stop_signal_findings() {
    for (kind, expected) in [
        (FindingKind::Violation, Some("violation")),
        (FindingKind::Abort, None),
    ] {
        let f = fixture(kind);
        if kind == FindingKind::Abort {
            let directory = f.artifact_directory(1);
            let mut artifact = f
                .store
                .read_record::<Artifact>(&directory, &name("artifact"))
                .unwrap()
                .unwrap()
                .record()
                .clone();
            artifact.workers.get_mut(&text("run")).unwrap().signal = Some(libc::SIGKILL as u64);
            f.store
                .replace_record(&directory, &name("artifact"), &artifact)
                .unwrap();
        }
        let directory = f.directory(1);
        let attempt = f
            .store
            .read_record::<crate::record::Attempt>(&directory, &name("attempt"))
            .unwrap()
            .unwrap();
        let evidence =
            crate::attempt::binding::read(&f.store, &directory, attempt.record()).unwrap();
        let mut finish = f
            .store
            .read_record::<Finished>(&directory, &name("finished"))
            .unwrap()
            .unwrap()
            .record()
            .clone();
        finish.class = Class::OutputLimit;
        finish.interruption = Some(crate::sys::OUTPUT_SIGNAL as u64);
        finish.bound = evidence.binding().cloned();
        let projected =
            crate::attempt::classify::finding_kind(&finish, evidence.into_bound().as_deref());
        assert_eq!(projected.map(FindingKind::name), expected);
        if kind == FindingKind::Violation {
            finish.class = Class::Violation;
        }

        f.store
            .replace_record(&directory, &name("bound"), finish.bound.as_ref().unwrap())
            .unwrap();
        f.store
            .replace_record(&directory, &name("finished"), &finish)
            .unwrap();
        let result = f.settle().unwrap();
        assert_eq!(result.is_some(), kind == FindingKind::Violation);
        let listed = crate::campaign::findings(&f.case.state).unwrap();
        if let Some(kind) = expected {
            assert_eq!(listed["findings"][0]["verified"]["kind"], kind);
            assert_eq!(
                listed["release_blockers"],
                serde_json::json!([finish.attempt.as_str()])
            );
        } else {
            assert_eq!(listed["findings"], serde_json::json!([]));
            assert_eq!(listed["release_blockers"], serde_json::json!([]));
        }
    }
}

#[test]
fn controller_record_paths_raise_soft_limits_and_hold_small_hard_limits() {
    const CHILD: &str = "CAMPAIGN_RECORD_LIMIT_CASE";
    if let Ok(mode) = std::env::var(CHILD) {
        let f = if mode == "marker" || mode == "marker-hard" {
            Fixture::new(&[Class::Pass])
        } else {
            fixture(FindingKind::Violation)
        };
        if mode.starts_with("dispose") {
            f.settle().unwrap();
        }
        let hard = if mode.ends_with("-hard") { 128 } else { 65536 };
        crate::sys::restrict_file_limit(1, hard).unwrap();
        if mode.starts_with("dispose") {
            drop(f.store);
            let result = crate::campaign::dispose(
                &f.case.state,
                text(&format!("{}-0001", f.job.job().id())),
                crate::record::Decision::Resolved,
                text("inspected retained evidence"),
            );
            if mode.ends_with("-hard") {
                assert!(result.unwrap_err().to_string().contains("RLIMIT_FSIZE"));
                assert!(
                    !f.case
                        .state
                        .join("findings")
                        .join(format!("{}-0001", f.job.job().id()))
                        .join("0001.disposition.json")
                        .exists()
                );
            } else {
                result.unwrap();
            }
        } else {
            let result = f.settle();
            if mode.ends_with("-hard") {
                assert!(result.unwrap_err().to_string().contains("RLIMIT_FSIZE"));
                assert!(!f.attempt_path(1).join("captured").exists());
            } else {
                result.unwrap();
                assert!(f.attempt_path(1).join("captured").exists());
            }
        }
        return;
    }
    let _processes = crate::store::fixture::processes();
    use std::os::unix::process::CommandExt;
    for mode in [
        "marker",
        "dispose",
        "finding-hard",
        "marker-hard",
        "dispose-hard",
    ] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "attempt::tests::settlement::findings::controller_record_paths_raise_soft_limits_and_hold_small_hard_limits"])
            .process_group(0)
            .env(CHILD, mode)
            .output().unwrap();
        assert!(
            output.status.success(),
            "{mode}: {:?}\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains("test result: ok. 1 passed; 0 failed; 0 ignored;"),
            "{mode}: the child must complete exactly one test\n{}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}

#[test]
fn wrong_type_attempt_beside_a_resolved_finding_stays_held() {
    let f = fixture(FindingKind::Violation);
    f.settle().unwrap();
    let id = format!("{}-0001", f.job.job().id());
    let path = f.attempt_path(1);
    drop(f.store);
    crate::campaign::dispose(
        &f.case.state,
        text(&id),
        crate::record::Decision::Resolved,
        text("inspected retained evidence"),
    )
    .unwrap();
    assert_eq!(
        crate::campaign::findings(&f.case.state).unwrap()["release_blockers"],
        serde_json::json!([])
    );
    fs::remove_dir_all(&path).unwrap();
    fs::write(&path, b"wrong type").unwrap();
    let listed = crate::campaign::findings(&f.case.state).unwrap();
    assert_eq!(listed["release_blockers"], serde_json::json!([id]));
    let rows = listed["findings"].as_array().unwrap();
    assert!(
        rows.iter()
            .any(|row| row["verified"]["kind"] == "violation")
    );
    assert!(
        rows.iter()
            .any(|row| row["id"] == id && row["held"].is_string() && row["blocker"] == true)
    );
}

#[test]
fn exact_rust_panic_headers_reject_a_denial_and_accept_both_thread_formats() {
    for (line, panic) in [
        ("thread 'main' has not panicked at engine.rs:1:1\n", false),
        ("thread 'main' panicked at engine.rs:1:1\n", true),
        ("thread 'main' (123) panicked at engine.rs:1:1\n", true),
        ("thread 'worker's task' panicked at engine.rs:1:1\n", true),
        (
            "thread 'worker's task' (123) panicked at engine.rs:1:1\n",
            true,
        ),
        ("thread 'main' () panicked at engine.rs:1:1\n", false),
        ("thread 'main' (12x) panicked at engine.rs:1:1\n", false),
        ("thread 'main' (-1) panicked at engine.rs:1:1\n", false),
        ("thread 'main' (123 panicked at engine.rs:1:1\n", false),
    ] {
        let f = Fixture::new(&[Class::Pass]);
        let directory = f.artifact_directory(1);
        f.store
            .replace(&directory, &name("run.stderr"), line.as_bytes())
            .unwrap();
        let mut artifact = f
            .store
            .read_record::<Artifact>(&directory, &name("artifact"))
            .unwrap()
            .unwrap()
            .record()
            .clone();
        artifact.workers.get_mut(&text("run")).unwrap().stderr = Digest::of(line.as_bytes());
        f.store
            .replace_record(&directory, &name("artifact"), &artifact)
            .unwrap();
        rebind(
            &f,
            if panic {
                Class::EngineFailure
            } else {
                Class::Pass
            },
        );
        f.settle().unwrap();
        let listed = crate::campaign::findings(&f.case.state).unwrap();
        assert_eq!(
            !listed["release_blockers"].as_array().unwrap().is_empty(),
            panic
        );
        if panic {
            assert_eq!(listed["findings"][0]["verified"]["kind"], "panic");
        } else {
            assert_eq!(listed["findings"], serde_json::json!([]));
        }
    }
}

#[test]
fn causal_stop_witnesses_distinguish_pid_oom_and_residual_members() {
    for (class, signal, memory, residual, interruption, launcher_signal, watchdog, abort) in [
        (
            Class::PidLimit,
            libc::SIGTERM,
            None,
            false,
            None,
            None,
            false,
            true,
        ),
        (
            Class::Oom,
            libc::SIGTERM,
            Some("oom_kill"),
            false,
            None,
            None,
            false,
            true,
        ),
        (
            Class::Oom,
            libc::SIGKILL,
            Some("oom_kill"),
            false,
            None,
            None,
            false,
            false,
        ),
        (
            Class::Oom,
            libc::SIGKILL,
            Some("oom"),
            false,
            None,
            None,
            false,
            true,
        ),
        (
            Class::Signal,
            libc::SIGTERM,
            None,
            true,
            None,
            None,
            false,
            true,
        ),
        (
            Class::MixedLimits,
            libc::SIGXCPU,
            None,
            false,
            None,
            None,
            false,
            false,
        ),
        (
            Class::PidLimit,
            libc::SIGXFSZ,
            None,
            false,
            None,
            None,
            false,
            false,
        ),
        (
            Class::CpuLimit,
            libc::SIGXFSZ,
            None,
            false,
            Some(libc::SIGXCPU),
            None,
            false,
            false,
        ),
        (
            Class::CpuLimit,
            libc::SIGKILL,
            None,
            false,
            None,
            None,
            false,
            false,
        ),
        (
            Class::OutputLimit,
            libc::SIGKILL,
            None,
            false,
            None,
            None,
            false,
            false,
        ),
        (
            Class::Signal,
            libc::SIGKILL,
            None,
            false,
            None,
            Some(libc::SIGXFSZ),
            false,
            false,
        ),
        (
            Class::OutputLimit,
            libc::SIGXFSZ,
            None,
            false,
            None,
            None,
            false,
            false,
        ),
        (
            Class::Interrupted,
            libc::SIGKILL,
            None,
            false,
            None,
            None,
            false,
            false,
        ),
        (
            Class::Interrupted,
            libc::SIGTERM,
            None,
            false,
            Some(libc::SIGKILL),
            None,
            false,
            true,
        ),
        (
            Class::Interrupted,
            libc::SIGTERM,
            None,
            false,
            Some(libc::SIGTERM),
            None,
            false,
            false,
        ),
        (
            Class::Watchdog,
            libc::SIGTERM,
            None,
            false,
            None,
            None,
            true,
            true,
        ),
        (
            Class::PidLimit,
            libc::SIGKILL,
            None,
            false,
            None,
            None,
            false,
            true,
        ),
        (
            Class::Signal,
            libc::SIGKILL,
            None,
            true,
            None,
            None,
            false,
            true,
        ),
    ] {
        let f = fixture(FindingKind::Abort);
        let directory = f.artifact_directory(1);
        let mut artifact = f
            .store
            .read_record::<Artifact>(&directory, &name("artifact"))
            .unwrap()
            .unwrap()
            .record()
            .clone();
        artifact.workers.get_mut(&text("run")).unwrap().signal = Some(signal as u64);
        f.store
            .replace_record(&directory, &name("artifact"), &artifact)
            .unwrap();
        let directory = f.directory(1);
        let attempt = f
            .store
            .read_record::<crate::record::Attempt>(&directory, &name("attempt"))
            .unwrap()
            .unwrap();
        let evidence =
            crate::attempt::binding::read(&f.store, &directory, attempt.record()).unwrap();
        let mut finished = f
            .store
            .read_record::<Finished>(&directory, &name("finished"))
            .unwrap()
            .unwrap()
            .record()
            .clone();
        finished.class = class;
        finished.residual_members = residual;
        finished.interruption = interruption.map(|signal| signal as u64);
        finished.signal = launcher_signal.map(|signal| signal as u64);
        finished.watchdog = watchdog;
        if let Some(counter) = memory {
            finished.kernel.memory.insert(text(counter), 1);
        }
        if matches!(class, Class::PidLimit | Class::MixedLimits) {
            finished.kernel.pids.insert(text("max"), 1);
        }
        finished.bound = evidence.binding().cloned();
        f.store
            .replace_record(&directory, &name("bound"), finished.bound.as_ref().unwrap())
            .unwrap();
        let bound = match &evidence {
            crate::attempt::binding::Evidence::Bound(bound) => bound,
            _ => panic!("fixture evidence is bound"),
        };
        assert_eq!(
            crate::attempt::classify::finding_kind(&finished, Some(bound)),
            abort.then_some(FindingKind::Abort),
            "{class:?} worker={signal} interruption={interruption:?}"
        );
        if class == Class::CpuLimit && signal == libc::SIGKILL {
            finished.interruption = Some(libc::SIGXCPU as u64);
        }
        if class == Class::OutputLimit && signal == libc::SIGKILL {
            finished.signal = Some(libc::SIGXFSZ as u64);
        }
        if class == Class::Interrupted && interruption.is_none() {
            finished.exit = None;
        }
        finished.class = crate::attempt::classify::classify(&finished, &evidence);
        f.store
            .replace_record(&directory, &name("finished"), &finished)
            .unwrap();
        f.settle().unwrap();
        let listed = crate::campaign::findings(&f.case.state).unwrap();
        assert_eq!(
            !listed["release_blockers"].as_array().unwrap().is_empty(),
            abort
        );
        if abort {
            assert_eq!(listed["findings"][0]["verified"]["kind"], "abort");
        } else {
            assert_eq!(listed["findings"], serde_json::json!([]));
            assert!(!f.case.state.join("findings").exists());
        }
    }
}

#[test]
fn a_wrong_frozen_archive_is_misbound_for_pass_and_violation() {
    for kind in [None, Some(FindingKind::Violation)] {
        let f = kind.map_or_else(|| Fixture::new(&[Class::Pass]), fixture);
        let directory = f.artifact_directory(1);
        let mut artifact = f
            .store
            .read_record::<Artifact>(&directory, &name("artifact"))
            .unwrap()
            .unwrap()
            .record()
            .clone();
        artifact.archive = Some(Digest::of(b"foreign archive"));
        f.store
            .replace_record(&directory, &name("artifact"), &artifact)
            .unwrap();
        let directory = f.directory(1);
        let attempt = f
            .store
            .read_record::<crate::record::Attempt>(&directory, &name("attempt"))
            .unwrap()
            .unwrap();
        let evidence =
            crate::attempt::binding::read(&f.store, &directory, attempt.record()).unwrap();
        assert_eq!(evidence.state(), crate::record::Binding::Misbound);
        let mut finished = f
            .store
            .read_record::<Finished>(&directory, &name("finished"))
            .unwrap()
            .unwrap()
            .record()
            .clone();
        finished.class = Class::MisboundEvidence;
        finished.binding = crate::record::Binding::Misbound;
        finished.bound = None;
        f.store
            .replace_record(&directory, &name("finished"), &finished)
            .unwrap();
        assert!(f.settle().unwrap().is_none());
        assert!(!f.case.state.join("findings").exists());
    }
}

#[test]
fn pending_held_entries_preserve_intact_findings_and_unbound_watchdogs_are_visible() {
    let f = fixture(FindingKind::Violation);
    f.settle().unwrap();
    fs::write(f.path("pin"), b"damaged pin").unwrap();
    let listed = crate::campaign::findings(&f.case.state).unwrap();
    assert!(
        listed["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["verified"]["kind"] == "violation")
    );
    assert!(
        listed["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["held_code"] == "malformed")
    );
    let f = Fixture::new(&[Class::Watchdog]);
    fs::remove_dir_all(f.attempt_path(1).join("artifacts")).unwrap();
    let directory = f.directory(1);
    let mut finished = f
        .store
        .read_record::<Finished>(&directory, &name("finished"))
        .unwrap()
        .unwrap()
        .record()
        .clone();
    finished.binding = crate::record::Binding::Missing;
    finished.bound = None;
    f.store
        .replace_record(&directory, &name("finished"), &finished)
        .unwrap();
    let listed = crate::campaign::findings(&f.case.state).unwrap();
    assert_eq!(
        listed["release_blockers"],
        serde_json::json!([finished.attempt.as_str()])
    );
}
