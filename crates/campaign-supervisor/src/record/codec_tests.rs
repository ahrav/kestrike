//! The envelope codec: every kind round-trips byte-identically, and each
//! read fault yields its own held code and no record.

use std::collections::{BTreeMap, BTreeSet};
use std::mem::discriminant;

use super::codec::{decode, encode};
use super::identity_tests::{NAMED, PINNED_KEYS, cluster_broad, pinned, text};
use super::{
    Admission, Artifact, Attempt, Binding, BoundEvidence, Build, Class, Comparison, Configuration,
    Difference, Event, Finished, Held, Intent, Job, JobResult, Kernel, Kind, Loader, ManifestError,
    Native, Pin, ProbeFinished, ProbeOutcome, Provenance, Purpose, Record, Reservation,
    SessionEvidence, Started, Summarized, Worker,
};
use super::{Digest, FORMAT};

#[test]
fn admission_configuration_and_probe_wire_bytes_are_pinned() {
    assert_eq!(
        encode(&admissions()[0]),
        include_bytes!("../../testdata/admission.json")
    );
    assert_eq!(
        encode(&configurations()[0]),
        include_bytes!("../../testdata/configuration.json")
    );
    assert_eq!(
        encode(&Reservation {
            attempt: text("probe-1")
        }),
        include_bytes!("../../testdata/reservation.json")
    );
    assert_eq!(
        encode(&ProbeFinished {
            attempt: text("probe-1"),
            outcome: ProbeOutcome::Complete
        }),
        include_bytes!("../../testdata/probe_finished.json")
    );
}

#[test]
fn universal_configuration_limit_violations_are_held_on_read() {
    for bytes in [
        include_bytes!("../../testdata/configuration-cpu-over-cap.json").as_slice(),
        include_bytes!("../../testdata/configuration-output-over-cap.json").as_slice(),
    ] {
        assert!(matches!(
            decode::<Configuration>(bytes),
            Err(Held::Mismatch)
        ));
        let case = crate::store::fixture::Case::new();
        let store = crate::store::Store::open(&case.state).unwrap();
        let name = crate::store::Name::new("config.json").unwrap();
        store.create_once(store.root(), &name, bytes).unwrap();
        assert!(matches!(
            store.read_record::<Configuration>(store.root(), &name),
            Err(Held::Mismatch)
        ));
    }
}

#[test]
fn unknown_probe_outcomes_are_held() {
    let record = ProbeFinished {
        attempt: text("probe-1"),
        outcome: ProbeOutcome::Complete,
    };
    let bytes = changed_record(&record, |value| {
        value["outcome"] = serde_json::json!("passed")
    });
    assert!(matches!(
        decode::<ProbeFinished>(&bytes),
        Err(Held::Mismatch)
    ));
}

#[test]
fn hardware_disposition_wire_requires_nonempty_evidence_and_a_run() {
    let record = super::HardwareDisposition::new(1, text("operator containment log")).unwrap();
    for bytes in [
        changed_record(&record, |value| value["evidence"] = serde_json::json!(" ")),
        changed_record(&record, |value| value["run"] = serde_json::json!(0)),
    ] {
        assert!(matches!(
            decode::<super::HardwareDisposition>(&bytes),
            Err(Held::Mismatch)
        ));
    }
}

fn hardware() -> super::Hardware {
    super::Hardware {
        argv: vec![text("python3"), text("lane.py"), text("sweep")],
        class: Some(super::HardwareClass::Completed),
        custody_directory: Some(text("/custody")),
        directory: text("/evidence"),
        exit: Some(0),
        kind: super::HardwareKind::Sweep,
        number: 1,
        phase: super::HardwarePhase::Finished,
        platform: text("supported"),
        profile: text("profile"),
        reason: text("controller exited 0"),
        signal: None,
        stopped: false,
    }
}

fn corpus_asset() -> super::CorpusAsset {
    super::CorpusAsset {
        boundary: 1,
        decisions: 2,
        prefix: Digest::of(b"prefix"),
        probe: super::CorpusProbe {
            archive: Digest::of(b"archive"),
            archive_path: text("/archive"),
            attempt: text("probe-1"),
            bundle: Digest::of(b"bundle"),
            bytes: 48,
            manifest: Digest::of(b"manifest"),
            milestone: text("pending-put"),
        },
        profile: text("cluster"),
        root: 1,
        semantic: 3,
        state: Digest::of(b"state"),
    }
}

fn corpus_version() -> super::CorpusVersion {
    super::CorpusVersion {
        asset: corpus_asset().id(),
        number: 1,
        retired: false,
    }
}

fn finding() -> super::Finding {
    super::Finding {
        child: None,
        parent_attempt: None,
        calibration_root: None,
        admission: admissions()[0].clone(),
        artifact: Some(artifacts()[0].clone()),
        attempt: attempt(),
        finished: finished(),
        kind: super::FindingKind::Violation,
    }
}
fn disposition() -> super::Disposition {
    super::Disposition::new(
        text("finding-1"),
        1,
        super::Decision::Resolved,
        text("fixed with replay evidence"),
    )
    .unwrap()
}

#[test]
fn finding_kinds_and_dispositions_refuse_unknown_labels_and_empty_evidence() {
    for kind in [
        super::FindingKind::Violation,
        super::FindingKind::Panic,
        super::FindingKind::Abort,
        super::FindingKind::Truncated,
        super::FindingKind::Watchdog,
        super::FindingKind::Harness,
    ] {
        let mut record = finding();
        record.kind = kind;
        round_trip(&record);
    }
    for decision in [
        super::Decision::Resolved,
        super::Decision::Harness,
        super::Decision::ReleaseBlocker,
    ] {
        round_trip(
            &super::Disposition::new(text("finding-1"), 1, decision, text("evidence")).unwrap(),
        );
    }
    let bytes = changed_record(&finding(), |record| {
        record["kind"] = serde_json::json!("unknown")
    });
    assert!(matches!(
        decode::<super::Finding>(&bytes),
        Err(Held::Mismatch)
    ));
    for (field, value) in [
        ("decision", serde_json::json!("unknown")),
        ("evidence", serde_json::json!("  ")),
        ("evidence", serde_json::json!("")),
        ("number", serde_json::json!(0)),
    ] {
        let bytes = changed_record(&disposition(), |record| record[field] = value);
        assert!(matches!(
            decode::<super::Disposition>(&bytes),
            Err(Held::Mismatch)
        ));
    }
}

fn admissions() -> [Admission; 3] {
    let campaign = Admission::new(text("/archive"), jobs()[0].clone(), Purpose::Campaign).unwrap();
    let mut experiment = pinned();
    experiment.campaign = text("calibration");
    let calibration = Admission::new(
        text("/archive"),
        Job::derive(experiment, &PINNED_KEYS).unwrap().0,
        Purpose::Calibration,
    )
    .unwrap();
    let mut experiment = pinned();
    experiment.counts.clear();
    let empty = Admission::new(
        text("/archive"),
        Job::derive(experiment, &PINNED_KEYS[..NAMED]).unwrap().0,
        Purpose::Campaign,
    )
    .unwrap();
    [campaign, calibration, empty]
}

fn capacity() -> super::Capacity {
    super::Capacity::new(
        super::CalibrationContract {
            build: Digest::of(b"build"),
            counts: BTreeMap::new(),
            profile: text("profile"),
        },
        Digest::of(b"evidence"),
        resources(),
        Digest::of(b"root"),
        2,
        configurations()[0].clone(),
    )
    .unwrap()
}

#[test]
fn capacity_requires_positive_slots_and_a_named_profile() {
    for (key, value) in [
        ("slots", serde_json::json!(0)),
        (
            "contract",
            serde_json::json!({"build":Digest::of(b"build"),"counts":{},"profile":""}),
        ),
    ] {
        let bytes = changed_record(&capacity(), |v| v[key] = value);
        assert!(matches!(
            decode::<super::Capacity>(&bytes),
            Err(Held::Mismatch)
        ));
    }
}

fn resources() -> super::ResourceBounds {
    super::ResourceBounds {
        cpu_us: Some(100),
        memory_bytes: Some(128),
        pids: Some(2),
        wall_us: Some(1000),
    }
}
fn calibration_plan() -> super::CalibrationPlan {
    super::CalibrationPlan {
        config: configurations()[0].clone(),
        controls: BTreeMap::new(),
        deduplicated: true,
        healthy: admissions()[1].clone(),
        missing: Vec::new(),
    }
}
fn calibration_replay() -> super::CalibrationReplay {
    super::CalibrationReplay {
        attempt: attempt(),
        original: Digest::of(b"artifact"),
        source: text("/source"),
    }
}
fn calibration() -> super::Calibration {
    let evidence = super::CalibrationEvidence {
        artifact: Some(artifacts()[0].clone()),
        finished: finished(),
        job: Digest::of(b"job"),
        product: None,
        resources: resources(),
    };
    super::Calibration {
        contract: capacity().contract().clone(),
        controls: BTreeMap::new(),
        defects: Vec::new(),
        detected: Vec::new(),
        healthy: evidence.clone(),
        lost: finished(),
        missing: vec![],
        reasons: vec![],
        replays: vec![evidence.clone(), evidence],
        root: Digest::of(b"root"),
        verdict: super::CalibrationVerdict::Uncalibrated,
    }
}

fn configurations() -> [Configuration; 2] {
    let values: BTreeMap<_, _> = [
        ("slots", 1),
        ("reserve_slots", 1),
        ("cores", 4),
        ("memory", 1024),
        ("cpu", 60),
        ("tree_memory", 128),
        ("attempt_output", 100),
        ("attempt_inodes", 10),
        ("wall", 60),
        ("processes", 64),
        ("artifact_bytes", 50_000_000),
        ("artifact_inodes", 100),
        ("backlog", 10),
        ("retained_builds", 1),
    ]
    .into_iter()
    .map(|(k, v)| (text(k), v))
    .collect();
    let basic = Configuration::new(values.clone()).unwrap();
    let mut extra = values;
    extra.insert(text("memory"), u64::MAX);
    extra.insert(text("corpus_count"), 1);
    extra.insert(text("corpus_bytes"), 100);
    [basic, Configuration::new(extra).unwrap()]
}

fn changed_record<R: Record>(record: &R, change: impl FnOnce(&mut serde_json::Value)) -> Vec<u8> {
    let mut value = serde_json::to_value(record).unwrap();
    change(&mut value);
    let mut envelope =
        serde_json::json!({"format": FORMAT, "kind": R::KIND.name(), "record": value});
    let digest = Digest::of(&serde_json::to_vec(&envelope).unwrap());
    envelope["sha256"] = serde_json::to_value(digest).unwrap();
    serde_json::to_vec(&envelope).unwrap()
}

#[test]
fn configuration_static_rules_and_empty_maps_read_as_mismatch() {
    let config = configurations()[0].clone();
    let faults: [fn(&mut serde_json::Value); 12] = [
        |v| {
            v["config"].as_object_mut().unwrap().clear();
        },
        |v| {
            v["config"].as_object_mut().unwrap().remove("cpu");
        },
        |v| {
            v["config"]["other"] = 1.into();
        },
        |v| {
            v["config"]["backlog"] = 0.into();
        },
        |v| {
            v["config"]["corpus_count"] = 1.into();
        },
        |v| {
            v["config"]["cores"] = 1.into();
        },
        |v| {
            v["config"]["memory"] = 255.into();
        },
        |v| {
            v["config"]["artifact_bytes"] = 200.into();
        },
        |v| {
            v["config"]["artifact_inodes"] = 20.into();
        },
        |v| {
            v["config"]["corpus_count"] = 1.into();
            v["config"]["corpus_bytes"] = 50_000_000.into();
        },
        |v| {
            v["format"] = 2.into();
        },
        |v| {
            v["enforcement"] = "other".into();
        },
    ];
    for (index, fault) in faults.into_iter().enumerate() {
        let bytes = changed_record(&config, fault);
        assert!(
            matches!(decode::<Configuration>(&bytes), Err(Held::Mismatch)),
            "static rule {index}"
        );
    }
}

#[test]
fn admission_purpose_mismatches_read_as_mismatch() {
    for (record, other) in [
        (admissions()[0].clone(), "calibration"),
        (admissions()[1].clone(), "campaign"),
    ] {
        let bytes = changed_record(&record, |v| v["purpose"] = other.into());
        assert!(matches!(decode::<Admission>(&bytes), Err(Held::Mismatch)));
    }
    assert!(Admission::new(text("/archive"), jobs()[0].clone(), Purpose::Calibration).is_err());
}

fn intent() -> Intent {
    Intent {
        attempt: text("job-1"),
        boot: text("boot"),
        cgroup: text("/sys/fs/cgroup/user.slice/attempt-1"),
    }
}

fn started() -> Started {
    let intent = intent();
    Started {
        baseline: Kernel::default(),
        attempt: intent.attempt,
        boot: intent.boot,
        cgroup: intent.cgroup,
        cgroup_inode: u64::MAX,
        launcher_pid: u64::MAX,
    }
}

/// The pinned job, with no cluster entry and six counts; one with every
/// option set; and one with integers above 2^53.
fn jobs() -> [Job; 3] {
    let (bare, _) = Job::derive(pinned(), &PINNED_KEYS).expect("the keys fit the experiment");
    let full = cluster_broad();
    let counts: Vec<String> = full
        .counts
        .keys()
        .map(|key| key.as_str().to_owned())
        .collect();
    let mut keys: Vec<&str> = PINNED_KEYS[..NAMED].to_vec();
    keys.extend(counts.iter().map(String::as_str));
    let (full, _) = Job::derive(full, &keys).expect("the keys fit the experiment");
    let mut big = pinned();
    big.run = u64::MAX;
    big.counts.insert(text("records"), (1 << 53) + 1);
    let (big, _) = Job::derive(big, &PINNED_KEYS).expect("the keys fit the experiment");
    [bare, full, big]
}

/// A dynamically linked build with two libraries, one named with `+`,
/// and a static build with no loader and an empty library map.
fn builds() -> [Build; 2] {
    let digest = |byte: char| Digest::parse(&byte.to_string().repeat(64)).expect("hex digits");
    let dynamic = Build {
        executable: digest('e'),
        libraries: BTreeMap::from([
            (text("libc.so.6"), digest('c')),
            (text("libstdc++.so.6"), digest('d')),
        ]),
        loader: Some(Loader {
            path: text("/lib64/ld-linux-x86-64.so.2"),
            sha256: digest('a'),
        }),
        lock: digest('b'),
        machine: text("x86_64"),
        provenance: Provenance {
            cargo: text("cargo 1.99.0 (5f94df478 2026-08-27)"),
            command: text("test -p kestrike --test sim_worker --no-run --locked"),
            dirty: true,
            environment: BTreeMap::from([(text("CARGO_ENCODED_RUSTFLAGS"), text(r"--cfg\u{1f}x"))]),
            native: Native {
                install_record: text("x86_64-unknown-linux-gnu-native"),
                install_record_sha256: digest('1'),
                link_plan_sha256: digest('2'),
                package: text("path+file:///src/crates/spdk-sys#0.1.0"),
            },
            revision: text(&"f".repeat(40)),
            target: text("x86_64-unknown-linux-gnu"),
            toolchain: text("rustc 1.99.0 (b940084d7 2026-09-28)"),
            untracked: u64::MAX,
        },
    };
    let mut fixed = dynamic.clone();
    fixed.libraries = BTreeMap::new();
    fixed.loader = None;
    fixed.provenance.dirty = false;
    fixed.provenance.untracked = 0;
    fixed.provenance.environment = BTreeMap::new();
    [dynamic, fixed]
}

/// A run artifact with summaries, comparison evidence and three worker exits,
/// a refused artifact with empty evidence, and a session artifact with verified windows.
fn artifacts() -> [Artifact; 3] {
    let digest = |byte: char| Digest::parse(&byte.to_string().repeat(64)).expect("hex digits");
    let worker = |exit| Worker {
        ended: text("exited"),
        exit: Some(exit),
        signal: None,
        stderr: digest('e'),
        stdout: digest('f'),
    };
    let mut counting = Artifact {
        archive: Some(digest('a')),
        archive_path: Some(text("/archives/worker")),
        bundle: Some(digest('b')),
        class: text("counts"),
        command: text("run"),
        comparison: Some(Comparison {
            candidate: Some(digest('c')),
            output: Some(text("/outputs/regression.bundle")),
            divergence: Some(Difference {
                committed: Some(Event {
                    node: Some(u64::MAX),
                    operation: Some(text("PUT")),
                    record: text("07"),
                    semantic_record: u64::MAX,
                    virtual_us: Some(u64::MAX),
                }),
                replayed: None,
            }),
            failure_identity: Some(text(&"a".repeat(88))),
            failure_kind: Some(text("violation")),
            original: None,
            observed: None,
            status: text("diverged"),
        }),
        manifest: Some(digest('c')),
        reason: text("complete pass fired=03 required=03, 61 decisions"),
        run_id: text("local-1-2"),
        output: None,
        session: None,
        session_original: None,
        summary: Some(Summarized {
            cause: Some(text("violating Bytes")),
            identity: Some(text(&"a".repeat(88))),
            first_failure: Some(Event {
                node: None,
                operation: None,
                record: text("07"),
                semantic_record: 12,
                virtual_us: None,
            }),
            counts: true,
            decisions: Some(u64::MAX),
            digest: digest('d'),
            ledger: Some(text("credited")),
            terminal: text("complete pass fired=03 required=03"),
            unsuccessful: Some(text("fewer exact reads than the profile requir")),
        }),
        workers: BTreeMap::from([
            (text("capabilities"), worker(0)),
            (text("inspect"), worker(0)),
            (text("run"), worker(0)),
        ]),
    };
    let comparison = counting.comparison.as_mut().expect("comparison");
    comparison.original = counting.summary.clone();
    comparison.observed = counting.summary.clone();
    comparison.divergence.as_mut().expect("divergence").replayed = comparison
        .divergence
        .as_ref()
        .expect("divergence")
        .committed
        .clone();
    let refused = Artifact {
        archive: None,
        archive_path: None,
        bundle: None,
        class: text("rejected"),
        command: text("inspect"),
        comparison: None,
        manifest: None,
        reason: text(r#"the bundle "b" \ pins no build"#),
        run_id: text("attempt-1"),
        output: None,
        session: None,
        session_original: None,
        summary: None,
        workers: BTreeMap::new(),
    };
    let mut session = counting.clone();
    session.command = text("session");
    session.session = Some(SessionEvidence {
        bytes: u64::MAX,
        chain: digest('a'),
        complete: false,
        counts: false,
        digests: vec![digest('b')],
        end: None,
        index: text("window 0"),
        output: text("/outputs/session"),
        records: u64::MAX,
        tail: None,
        verification_error: Some(text("end is missing")),
        verified_windows: 1,
    });
    session.session_original = session.session.clone();
    [counting, refused, session]
}

/// A job whose counts map is empty and whose options are all absent.
fn empty_counts() -> Job {
    let mut experiment = pinned();
    experiment.counts = BTreeMap::new();
    experiment.class = None;
    Job::derive(experiment, &PINNED_KEYS[..NAMED])
        .expect("the keys fit the experiment")
        .0
}

fn triage_step() -> super::TriageStep {
    super::TriageStep {
        attempt: attempt(),
        finding: text("finding"),
        kind: super::StepKind::Replay,
        launcher: text("/campaign"),
        limits: BTreeMap::new(),
    }
}
fn replay_dependencies() -> super::ReplayDependencies {
    super::ReplayDependencies {
        archive: Digest::of(b"archive"),
        archive_path: text("/archive"),
        bundle: None,
        finding: text("finding"),
        manifest: Digest::of(b"manifest"),
    }
}
fn triage_result() -> super::TriageResult {
    super::TriageResult {
        comparison: None,
        elapsed_ms: None,
        file_limited: false,
        finding: text("finding"),
        finished: {
            let mut stopped = finished();
            stopped.exit = None;
            stopped.class = Class::Interrupted;
            stopped
        },
        number: 1,
        output_limited: false,
        state: super::StepState::Interrupted,
        status: None,
    }
}
fn reclaimed() -> super::Reclaimed {
    super::Reclaimed {
        attempt: 1,
        finished: Digest::of(b"finished"),
        names: vec![text("launcher.stdout"), text("artifacts/job-0001/bundle")],
    }
}

fn regression_candidate() -> super::RegressionCandidate {
    super::RegressionCandidate {
        archive: Digest::of(b"archive"),
        bundle: None,
        bytes: None,
        command: vec![],
        expected_exit: None,
        failure_identity: None,
        failure_kind: super::FindingKind::Violation,
        finding: text("finding"),
        number: 1,
        input: text("/input"),
        manifest: Digest::of(b"manifest"),
        step_ms: None,
        tier: text("pinned-corpus"),
    }
}

/// Encodes and decodes the record and checks its generic value form.
fn round_trip<R: Record + PartialEq + std::fmt::Debug>(record: &R) -> Vec<u8> {
    let bytes = encode(record);
    let decoded: R = decode(&bytes).expect("an encoded record verifies");
    assert_eq!(&decoded, record);
    assert_eq!(
        super::codec::canonical::<R>(&bytes).as_ref(),
        Some(record),
        "the one-pass check accepts canonical bytes"
    );
    let generic: serde_json::Value =
        serde_json::from_slice(&bytes).expect("the bytes parse as generic JSON");
    assert_eq!(
        serde_json::to_vec(&generic).expect("the generic value encodes"),
        bytes
    );
    assert_eq!(
        serde_json::to_vec(&serde_json::to_value(record).expect("the record has a generic form"))
            .expect("the generic value encodes"),
        serde_json::to_vec(record).expect("the record encodes")
    );
    bytes
}

/// Every kind in the registry encodes, decodes and re-encodes to the same
/// bytes, absent options, an empty map, empty text and escaped quotes and
/// backslashes included, and its encoding
/// equals the encoding through the generic value form, whose objects sort
/// their keys; so every record type declares its fields in byte order.
#[test]
fn every_kind_round_trips_through_its_canonical_bytes() {
    assert_eq!(
        serde_json::to_string(&serde_json::json!({"b": 1, "a": 2})).expect("the value encodes"),
        r#"{"a":2,"b":1}"#,
        "the generic value form sorts object keys"
    );
    for &kind in Kind::ALL {
        match kind {
            Kind::Hardware => {
                for &phase in super::HardwarePhase::ALL {
                    let mut record = hardware();
                    record.phase = phase;
                    round_trip(&record);
                }
                let mut record = hardware();
                record.argv.clear();
                record.custody_directory = None;
                record.exit = None;
                record.class = None;
                round_trip(&record);
                record.signal = Some(15);
                round_trip(&record);
                for class in super::HardwareClass::ALL {
                    record.class = Some(*class);
                    round_trip(&record);
                }
                for kind in super::HardwareKind::ALL {
                    record.kind = *kind;
                    round_trip(&record);
                }
            }
            Kind::HardwareDisposition => {
                round_trip(
                    &super::HardwareDisposition::new(1, text("contained: evidence/receipt"))
                        .unwrap(),
                );
            }
            Kind::CorpusProbe => {
                round_trip(&corpus_asset().probe);
            }
            Kind::CorpusAsset => {
                round_trip(&corpus_asset());
            }
            Kind::CorpusVersion => {
                round_trip(&corpus_version());
            }
            Kind::CorpusRetirement => {
                round_trip(&super::CorpusRetirement {
                    asset: corpus_asset().id(),
                });
            }
            Kind::Captured => {
                for finding in [None, Some(super::Text::new("attempt").unwrap())] {
                    round_trip(&super::Captured {
                        attempt: super::Text::new("attempt").unwrap(),
                        finding,
                        finished: super::Digest::of(b"finished"),
                    });
                }
            }
            Kind::Finding => {
                for artifact in artifacts().into_iter().map(Some).chain([None]) {
                    let mut record = finding();
                    record.artifact = artifact;
                    round_trip(&record);
                }
            }
            Kind::Disposition => {
                round_trip(&disposition());
            }
            Kind::TriageStep => {
                round_trip(&triage_step());
            }
            Kind::ReplayDependencies => {
                round_trip(&replay_dependencies());
            }
            Kind::TriageResult => {
                round_trip(&triage_result());
            }
            Kind::RegressionCandidate => {
                round_trip(&regression_candidate());
            }
            Kind::Reclaimed => {
                round_trip(&reclaimed());
            }

            Kind::Job => {
                for job in jobs() {
                    let bytes = round_trip(&job);
                    assert!(bytes.starts_with(br#"{"format":1,"kind":"job","record":{"#));
                }
                let bytes = round_trip(&empty_counts());
                assert!(bytes.starts_with(br#"{"format":1,"kind":"job","record":{"#));
                let text = String::from_utf8(bytes).expect("the bytes are ASCII");
                assert!(text.contains(r#""counts":{}"#), "{text}");
                for absent in ["class", "generator", "minima"] {
                    assert!(text.contains(&format!(r#""{absent}":null"#)), "{text}");
                }
                let mut escaped = pinned();
                escaped.campaign = super::Text::new(r#"a "q" \ p/~"#).expect("the text is ASCII");
                escaped.class = Some(super::Text::new("").expect("the text is ASCII"));
                escaped
                    .counts
                    .insert(super::identity_tests::text(r#"q"k\"#), 1);
                let keys = [&PINNED_KEYS[..], &[r#"q"k\"#]].concat();
                let (escaped, _) =
                    Job::derive(escaped, &keys).expect("the keys fit the experiment");
                let text = String::from_utf8(round_trip(&escaped)).expect("the bytes are ASCII");
                for written in [
                    r#""campaign":"a \"q\" \\ p/~""#,
                    r#""class":"""#,
                    r#""q\"k\\":1"#,
                ] {
                    assert!(text.contains(written), "{written} is in {text}");
                }
            }
            Kind::Build => {
                let [dynamic, fixed] = builds();
                let text = String::from_utf8(round_trip(&dynamic)).expect("the bytes are ASCII");
                assert!(text.starts_with(r#"{"format":1,"kind":"build","record":{"#));
                assert!(text.contains(r#""libstdc++.so.6":"#), "{text}");
                assert!(
                    text.contains(r#""untracked":18446744073709551615"#),
                    "{text}"
                );
                let text = String::from_utf8(round_trip(&fixed)).expect("the bytes are ASCII");
                for written in [
                    r#""environment":{}"#,
                    r#""libraries":{}"#,
                    r#""loader":null"#,
                ] {
                    assert!(text.contains(written), "{written} is in {text}");
                }
            }
            Kind::Admission => {
                for record in admissions() {
                    round_trip(&record);
                }
            }
            Kind::Configuration => {
                for record in configurations() {
                    round_trip(&record);
                }
            }
            Kind::Capacity => {
                round_trip(&capacity());
            }
            Kind::CalibrationPlan => {
                round_trip(&calibration_plan());
            }
            Kind::CalibrationReplay => {
                round_trip(&calibration_replay());
            }
            Kind::ResourceBounds => {
                round_trip(&resources());
                round_trip(&super::ResourceBounds {
                    cpu_us: None,
                    memory_bytes: None,
                    pids: None,
                    wall_us: None,
                });
            }
            Kind::Calibration => {
                round_trip(&calibration());
                let mut absent = calibration();
                absent.healthy.artifact = None;
                absent.controls.clear();
                absent.replays.clear();
                round_trip(&absent);
            }
            Kind::Intent => {
                round_trip(&intent());
            }
            Kind::Started => {
                round_trip(&started());
            }
            Kind::Attempt => {
                round_trip(&attempt());
            }
            Kind::Bound => {
                round_trip(&bound());
                let mut absent = bound();
                absent.bundle = None;
                let bytes = round_trip(&absent);
                assert!(
                    std::str::from_utf8(&bytes)
                        .unwrap()
                        .contains(r#""bundle":null"#)
                );
            }
            Kind::Pin => {
                round_trip(&Pin {
                    result: job_result(),
                });
            }
            Kind::JobResult => {
                round_trip(&job_result());
                let mut result = job_result();
                result.finished.bound = Some(bound());
                result.finished.exit = Some(u64::MAX);
                result
                    .finished
                    .kernel
                    .cpu
                    .insert(text("usage_usec"), u64::MAX);
                round_trip(&result);
                result.finished.bound.as_mut().unwrap().bundle = None;
                result.finished.residual_members = true;
                let bytes = round_trip(&result);
                assert!(
                    std::str::from_utf8(&bytes)
                        .unwrap()
                        .contains(r#""bundle":null"#)
                );
                round_trip(&Pin { result });
            }
            Kind::Finished => {
                for &class in Class::ALL {
                    let mut record = finished();
                    record.class = class;
                    for &binding in Binding::ALL {
                        record.binding = binding;
                        round_trip(&record);
                    }
                    record.bound = Some(bound());
                    record.exit = Some(u64::MAX);
                    record.signal = Some(9);
                    record.interruption = Some(15);
                    record.watchdog = true;
                    record.residual_members = true;
                    record.kernel.cpu.insert(text("nr_throttled"), u64::MAX);
                    round_trip(&record);
                }
            }
            Kind::Reservation => {
                round_trip(&Reservation {
                    attempt: text("probe-1"),
                });
            }
            Kind::ProbeFinished => {
                for outcome in [
                    ProbeOutcome::Complete,
                    ProbeOutcome::Held,
                    ProbeOutcome::OutputLimit,
                    ProbeOutcome::Oom,
                    ProbeOutcome::PidLimit,
                    ProbeOutcome::CpuLimit,
                    ProbeOutcome::MixedLimits,
                ] {
                    round_trip(&ProbeFinished {
                        attempt: text("probe-1"),
                        outcome,
                    });
                }
            }
            Kind::Artifact => {
                let [counting, refused, session] = artifacts();
                let text = String::from_utf8(round_trip(&counting)).expect("the bytes are ASCII");
                assert!(text.starts_with(r#"{"format":1,"kind":"artifact","record":{"#));
                assert!(
                    text.contains(r#""decisions":18446744073709551615"#),
                    "{text}"
                );
                let text = String::from_utf8(round_trip(&refused)).expect("the bytes are ASCII");
                for written in [r#""archive":null"#, r#""summary":null"#, r#""workers":{}"#] {
                    assert!(text.contains(written), "{written} is in {text}");
                }
                assert!(!text.contains(r#""session""#), "{text}");
                assert!(!text.contains(r#""session_original""#), "{text}");
                let text = String::from_utf8(round_trip(&session)).expect("ASCII session");
                assert!(text.contains(r#""verified_windows":1"#));
                assert!(text.contains(r#""end":null"#));
                assert!(text.contains(r#""tail":null"#));
            }
        }
    }
}

/// The canonical artifact encoding represents `None` for `archive_path`,
/// `comparison` and the summary's `cause`, `first_failure`, `identity` and
/// `unsuccessful` by omitting the key, so an artifact file without those keys verifies.
/// An explicit `null` gives the same value a second encoding and is held
/// as non-canonical.
#[test]
fn an_artifact_without_its_omitted_options_decodes_to_its_stored_bytes() {
    let hex = |byte: char| byte.to_string().repeat(64);
    let terminal = "complete pass fired=03 required=03";
    let summary = format!(
        r#"{{"counts":true,"decisions":61,"digest":"{}","ledger":null,"terminal":"{terminal}"}}"#,
        hex('d')
    );
    let worker = format!(
        r#"{{"ended":"exited","exit":0,"signal":null,"stderr":"{}","stdout":"{}"}}"#,
        hex('e'),
        hex('f')
    );
    let omitted = resealed(
        format!(
            r#"{{"format":1,"kind":"artifact","record":{{"archive":"{}","bundle":"{}","class":"counts","command":"run","manifest":"{}","reason":"{terminal}, 61 decisions","run_id":"local-1-2","summary":{summary},"workers":{{"run":{worker}}}}},"sha256":"{}"}}"#,
            hex('a'),
            hex('b'),
            hex('c'),
            hex('0'),
        )
        .as_bytes(),
    );
    let decoded = decode::<Artifact>(&omitted).expect("the artifact verifies");
    assert_eq!((&decoded.archive_path, &decoded.comparison), (&None, &None));
    let summarized = decoded.summary.as_ref().expect("the summary decodes");
    assert_eq!(
        (
            &summarized.cause,
            &summarized.first_failure,
            &summarized.identity,
            &summarized.unsuccessful
        ),
        (&None, &None, &None, &None)
    );
    assert_eq!(summarized.decisions, Some(61));
    assert_eq!(encode(&decoded), omitted);
    for (from, to) in [
        (r#""bundle":"#, r#""archive_path":null,"bundle":"#),
        (r#""manifest":"#, r#""comparison":null,"manifest":"#),
        (r#"{"counts":true"#, r#"{"cause":null,"counts":true"#),
        (r#""ledger":null"#, r#""first_failure":null,"ledger":null"#),
        (r#""ledger":null"#, r#""identity":null,"ledger":null"#),
        (r#"required=03"}"#, r#"required=03","unsuccessful":null}"#),
    ] {
        let spelled = resealed(&planted(&omitted, from, to));
        let held = decode::<Artifact>(&spelled).expect_err("an explicit null is held");
        assert!(matches!(held, Held::NonCanonical), "{to}: {held:?}");
    }
}

/// `bytes` with the first `from` replaced by `to`.
fn planted(bytes: &[u8], from: &str, to: &str) -> Vec<u8> {
    let text = String::from_utf8(bytes.to_vec()).expect("the bytes are ASCII");
    assert!(text.contains(from), "{from} is in {text}");
    text.replacen(from, to, 1).into_bytes()
}

/// The six read faults planted in `bytes`, each at the envelope, with the
/// code each must yield: non-canonical bytes, a duplicate key, an unknown
/// field, an unknown format, a bad checksum and non-ASCII text.
fn envelope_faults(bytes: &[u8]) -> [(Vec<u8>, Held); 6] {
    let sha256 = String::from_utf8(bytes[bytes.len() - 66..bytes.len() - 2].to_vec())
        .expect("the checksum is ASCII");
    let flipped = format!(
        "{}{}",
        if sha256.starts_with('0') { '1' } else { '0' },
        &sha256[1..]
    );
    [
        (
            planted(bytes, r#"{"format""#, r#"{ "format""#),
            Held::NonCanonical,
        ),
        (
            planted(bytes, r#"{"format":1,"#, r#"{"format":1,"format":1,"#),
            Held::DuplicateKey,
        ),
        (
            planted(bytes, r#"{"format":1,"#, r#"{"extra":0,"format":1,"#),
            Held::UnknownField,
        ),
        (
            planted(bytes, r#"{"format":1,"#, r#"{"format":2,"#),
            Held::UnknownFormat,
        ),
        (planted(bytes, &sha256, &flipped), Held::Checksum),
        (
            planted(bytes, r#""kind":""#, r#""kind":"\u00e9"#),
            Held::NonAscii,
        ),
    ]
}

/// A decode of one kind, with the record dropped.
type Decode = fn(&[u8]) -> Result<(), Held>;

/// For every kind, non-canonical bytes, a duplicate key, an unknown field,
/// an unknown format, a bad checksum and non-ASCII text each yield their
/// own code and no record, and an unknown field inside the record is held
/// as one; for a job, duplicate keys, unknown fields and non-ASCII text
/// planted in its nested objects yield their codes.
#[test]
fn six_read_faults_yield_six_distinct_codes() {
    for &kind in Kind::ALL {
        let (bytes, decode): (Vec<u8>, Decode) = match kind {
            Kind::Hardware => (encode(&hardware()), |bytes| {
                decode::<super::Hardware>(bytes).map(drop)
            }),
            Kind::HardwareDisposition => (
                encode(&super::HardwareDisposition::new(1, text("evidence")).unwrap()),
                |bytes| decode::<super::HardwareDisposition>(bytes).map(drop),
            ),
            Kind::CorpusProbe => (encode(&corpus_asset().probe), |bytes| {
                decode::<super::CorpusProbe>(bytes).map(drop)
            }),
            Kind::CorpusAsset => (encode(&corpus_asset()), |bytes| {
                decode::<super::CorpusAsset>(bytes).map(drop)
            }),
            Kind::CorpusVersion => (encode(&corpus_version()), |bytes| {
                decode::<super::CorpusVersion>(bytes).map(drop)
            }),
            Kind::CorpusRetirement => (
                encode(&super::CorpusRetirement {
                    asset: corpus_asset().id(),
                }),
                |bytes| decode::<super::CorpusRetirement>(bytes).map(drop),
            ),
            Kind::Captured => (
                encode(&super::Captured {
                    attempt: super::Text::new("attempt").unwrap(),
                    finding: None,
                    finished: super::Digest::of(b"finished"),
                }),
                |bytes| decode::<super::Captured>(bytes).map(drop),
            ),
            Kind::Finding => (encode(&finding()), |bytes| {
                decode::<super::Finding>(bytes).map(drop)
            }),
            Kind::Disposition => (encode(&disposition()), |bytes| {
                decode::<super::Disposition>(bytes).map(drop)
            }),
            Kind::TriageStep => (encode(&triage_step()), |bytes| {
                decode::<super::TriageStep>(bytes).map(drop)
            }),
            Kind::ReplayDependencies => (encode(&replay_dependencies()), |bytes| {
                decode::<super::ReplayDependencies>(bytes).map(drop)
            }),
            Kind::TriageResult => (encode(&triage_result()), |bytes| {
                decode::<super::TriageResult>(bytes).map(drop)
            }),
            Kind::RegressionCandidate => (encode(&regression_candidate()), |bytes| {
                decode::<super::RegressionCandidate>(bytes).map(drop)
            }),
            Kind::Reclaimed => (encode(&reclaimed()), |bytes| {
                decode::<super::Reclaimed>(bytes).map(drop)
            }),

            Kind::Job => (encode(&jobs()[0]), |bytes| decode::<Job>(bytes).map(drop)),
            Kind::Build => (encode(&builds()[0]), |bytes| {
                decode::<Build>(bytes).map(drop)
            }),
            Kind::Admission => (encode(&admissions()[0]), |bytes| {
                decode::<Admission>(bytes).map(drop)
            }),
            Kind::Configuration => (encode(&configurations()[0]), |bytes| {
                decode::<Configuration>(bytes).map(drop)
            }),
            Kind::Capacity => (encode(&capacity()), |bytes| {
                decode::<super::Capacity>(bytes).map(drop)
            }),
            Kind::CalibrationPlan => (encode(&calibration_plan()), |bytes| {
                decode::<super::CalibrationPlan>(bytes).map(drop)
            }),
            Kind::CalibrationReplay => (encode(&calibration_replay()), |bytes| {
                decode::<super::CalibrationReplay>(bytes).map(drop)
            }),
            Kind::ResourceBounds => (encode(&resources()), |bytes| {
                decode::<super::ResourceBounds>(bytes).map(drop)
            }),
            Kind::Calibration => (encode(&calibration()), |bytes| {
                decode::<super::Calibration>(bytes).map(drop)
            }),
            Kind::Intent => (encode(&intent()), |bytes| decode::<Intent>(bytes).map(drop)),
            Kind::Started => (encode(&started()), |bytes| {
                decode::<Started>(bytes).map(drop)
            }),
            Kind::Attempt => (encode(&attempt()), |bytes| {
                decode::<Attempt>(bytes).map(drop)
            }),
            Kind::Bound => (encode(&bound()), |bytes| {
                decode::<BoundEvidence>(bytes).map(drop)
            }),
            Kind::Pin => (
                encode(&Pin {
                    result: job_result(),
                }),
                |bytes| decode::<Pin>(bytes).map(drop),
            ),
            Kind::JobResult => (encode(&job_result()), |bytes| {
                decode::<JobResult>(bytes).map(drop)
            }),
            Kind::Finished => (encode(&finished()), |bytes| {
                decode::<Finished>(bytes).map(drop)
            }),
            Kind::Reservation => (
                encode(&Reservation {
                    attempt: text("probe-1"),
                }),
                |bytes| decode::<Reservation>(bytes).map(drop),
            ),
            Kind::ProbeFinished => (
                encode(&ProbeFinished {
                    attempt: text("probe-1"),
                    outcome: ProbeOutcome::Complete,
                }),
                |bytes| decode::<ProbeFinished>(bytes).map(drop),
            ),
            Kind::Artifact => (encode(&artifacts()[0]), |bytes| {
                decode::<Artifact>(bytes).map(drop)
            }),
        };
        let mut codes = BTreeSet::new();
        for (fault, expected) in envelope_faults(&bytes) {
            let held = decode(&fault).expect_err("a faulty record is held");
            assert_eq!(
                discriminant(&held),
                discriminant(&expected),
                "{held:?}, expected {expected:?}: {}",
                String::from_utf8_lossy(&fault)
            );
            codes.insert(held.code());
        }
        assert_eq!(codes.len(), 6, "{kind:?}");
        let foreign = planted(
            &bytes,
            &format!(r#""kind":"{}""#, kind.name()),
            r#""kind":"foreign""#,
        );
        assert!(matches!(decode(&foreign), Err(Held::WrongKind)), "{kind:?}");
        let inner = planted(&bytes, r#""record":{"#, r#""record":{"!":0,"#);
        assert!(
            matches!(decode(&inner), Err(Held::UnknownField)),
            "{kind:?}"
        );
    }
    let names: BTreeSet<&str> = Kind::ALL.iter().map(|kind| kind.name()).collect();
    assert_eq!(names.len(), Kind::ALL.len());
    let bytes = encode(&jobs()[0]);
    for (fault, expected) in [
        (
            planted(&bytes, r#""ring":2,"#, r#""ring":2,"ring":2,"#),
            Held::DuplicateKey,
        ),
        (
            planted(&bytes, r#""profile":"#, r#""note":"planted","profile":"#),
            Held::UnknownField,
        ),
        (
            planted(&bytes, r#""pins":{"#, r#""pins":{"aaa":"x","#),
            Held::UnknownField,
        ),
        (
            planted(&bytes, r#""ring":2,"#, r#""ring":2,"r\u00e9":2,"#),
            Held::NonAscii,
        ),
        (
            planted(&bytes, r#""id":"#, r#""extra":0,"id":"#),
            Held::UnknownField,
        ),
        (
            planted(&bytes, r#""campaign":"c1""#, r#""campaign":"c\u00e9""#),
            Held::NonAscii,
        ),
    ] {
        let held = decode::<Job>(&fault).expect_err("a faulty record is held");
        assert_eq!(
            discriminant(&held),
            discriminant(&expected),
            "{held:?}, expected {expected:?}: {}",
            String::from_utf8_lossy(&fault)
        );
    }
}

/// Faults planted in a build record's nested objects and values yield
/// their codes: an unknown field in its provenance and its native
/// identity, a repeated library, a non-ASCII library name, a digest that
/// is no 64 lowercase hex digits, and a loader with no digest.
#[test]
fn build_faults_in_nested_values_are_held() {
    let bytes = encode(&builds()[0]);
    let digest = "c".repeat(64);
    for (fault, expected) in [
        (
            planted(&bytes, r#""provenance":{"#, r#""provenance":{"x":0,"#),
            Held::UnknownField,
        ),
        (
            planted(&bytes, r#""native":{"#, r#""native":{"x":0,"#),
            Held::UnknownField,
        ),
        (
            planted(
                &bytes,
                r#""libraries":{"#,
                &format!(r#""libraries":{{"libc.so.6":"{digest}","#),
            ),
            Held::DuplicateKey,
        ),
        (
            planted(&bytes, r#""libc.so.6""#, r#""libc.so.é""#),
            Held::NonAscii,
        ),
        (
            resealed(&planted(
                &bytes,
                &format!(r#""libc.so.6":"{digest}""#),
                &format!(r#""libc.so.6":"{}""#, "C".repeat(64)),
            )),
            Held::Mismatch,
        ),
        (
            resealed(&planted(
                &bytes,
                &format!(r#","sha256":"{}""#, "a".repeat(64)),
                "",
            )),
            Held::Mismatch,
        ),
    ] {
        let held = decode::<Build>(&fault).expect_err("a faulty build record is held");
        assert_eq!(
            discriminant(&held),
            discriminant(&expected),
            "{held:?}, expected {expected:?}: {}",
            String::from_utf8_lossy(&fault)
        );
    }
}

/// The checksum covers the format and the kind: a job's envelope is the
/// golden byte string whose `sha256` is the SHA-256 of the same envelope
/// without it.
#[test]
fn the_checksum_covers_the_format_and_the_kind() {
    const RECORD: &str = concat!(
        r#"{"experiment":{"attempts":3,"campaign":"c1","capabilities":"1","class":"live","#,
        r#""counts":{"bytes":9600,"every":5,"pending":3,"records":80,"ring":2,"turns":7},"#,
        r#""format":1,"generator":null,"manifest_version":"2","minima":null,"#,
        r#""pins":{"build":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","#,
        r#""executable":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","#,
        r#""platform":"x86_64-linux","toolchain":"rustc 1.99.0"},"profile":"upload","run":0},"#,
        r#""id":"dede8442617896e012b3588170f0d42d2f5811b975f42335d570713f2a93aeaf","#,
        r#""manifest_sha256":"4fef012cc0a78ee550432b648aebe856fffb54ef9631cb6db28b89dcdc804e7e","#,
        r#""seed":15296928082430272672}"#,
    );
    const SHA256: &str = "e313fd06a1fff642b51738f9767d93ae7c438fbc4fe24c788cf779a96a77362a";
    let unsealed = format!(r#"{{"format":{FORMAT},"kind":"job","record":{RECORD}}}"#);
    assert_eq!(Digest::of(unsealed.as_bytes()).to_string(), SHA256);
    let sealed = format!(r#"{{"format":1,"kind":"job","record":{RECORD},"sha256":"{SHA256}"}}"#);
    assert_eq!(
        String::from_utf8(encode(&jobs()[0])).expect("the bytes are ASCII"),
        sealed
    );
}

/// `bytes`, a record envelope, with its checksum recomputed over its format,
/// kind and record as they stand.
fn resealed(bytes: &[u8]) -> Vec<u8> {
    let text = String::from_utf8(bytes.to_vec()).expect("the bytes are ASCII");
    let (unsealed, _) = text
        .rsplit_once(r#","sha256":""#)
        .expect("the envelope ends in its checksum");
    let sha256 = Digest::of(format!("{unsealed}}}").as_bytes());
    format!(r#"{unsealed},"sha256":"{sha256}"}}"#).into_bytes()
}

/// A canonical, checksummed job whose identity or seed is not the one its
/// experiment derives is held, and so is a job whose frozen fields changed
/// under its stored identity and seed, whether or not it was resealed. A
/// job keeps the manifest digest its writer stored, and its manifest
/// refuses keys whose bytes hash to another digest.
#[test]
fn a_job_whose_identity_or_seed_does_not_derive_is_held() {
    let [job, ..] = jobs();
    let mut value = serde_json::to_value(&job).expect("the job has a generic form");
    value["seed"] = (job.seed() + 1).into();
    assert!(serde_json::from_value::<Job>(value.clone()).is_err());
    value["seed"] = job.seed().into();
    value["id"] = "0".repeat(64).into();
    assert!(serde_json::from_value::<Job>(value).is_err());
    let reseeded = resealed(&planted(
        &encode(&job),
        &format!(r#""seed":{}}}"#, job.seed()),
        &format!(r#""seed":{}}}"#, job.seed() + 1),
    ));
    let held = decode::<Job>(&reseeded).expect_err("an underived job is held");
    assert!(matches!(held, Held::Mismatch), "{held:?}");
    let reidentified = resealed(&planted(
        &encode(&job),
        &format!(r#""id":"{}""#, job.id()),
        &format!(r#""id":"{}""#, "0".repeat(64)),
    ));
    let held = decode::<Job>(&reidentified).expect_err("an underived job is held");
    assert!(matches!(held, Held::Mismatch), "{held:?}");
    let other = "0".repeat(64);
    let foreign = resealed(&planted(
        &encode(&job),
        &format!(r#""manifest_sha256":"{}""#, job.manifest_sha256()),
        &format!(r#""manifest_sha256":"{other}""#),
    ));
    let kept = decode::<Job>(&foreign).expect("a job keeps the digest its writer stored");
    assert_eq!(kept.manifest_sha256().to_string(), other);
    assert_eq!(kept.manifest(&PINNED_KEYS), Err(ManifestError::Digest));
    let bytes = encode(&job);
    for (from, to) in [
        (r#""ring":2,"#, r#""ring":3,"#),
        (r#""attempts":3,"#, r#""attempts":4,"#),
        (r#""profile":"upload""#, r#""profile":"cluster-broad""#),
    ] {
        let edited = planted(&bytes, from, to);
        for edited in [resealed(&edited), edited] {
            let held = decode::<Job>(&edited).expect_err("an edited job is held");
            assert!(matches!(held, Held::Mismatch), "{to}: {held:?}");
        }
    }
}

/// Bytes outside the record domain, invalid UTF-8, raw non-ASCII text,
/// faults inside an array, a record of another kind, an envelope or record
/// of another shape, a format of another type, reordered keys, a trailing
/// newline and escaped ASCII are each held with their own code. A file
/// with two faults is held with the earlier step's code: the scan precedes
/// the format check, and the kind check precedes the typed decode.
#[test]
fn malformed_foreign_and_misshapen_records_are_held() {
    let [job, ..] = jobs();
    let bytes = encode(&job);
    let deep = format!("{}{}", "[".repeat(100_000), "]".repeat(100_000));
    let mut invalid = bytes.clone();
    let campaign = String::from_utf8(bytes.clone())
        .expect("the bytes are ASCII")
        .find(r#""campaign":"c1""#)
        .expect("the job names its campaign");
    invalid[campaign + r#""campaign":"c"#.len()] = 0xff;
    let sha256 = String::from_utf8(bytes[bytes.len() - 66..bytes.len() - 2].to_vec())
        .expect("the checksum is ASCII");
    let mut trailing = bytes.clone();
    trailing.push(b'\n');
    let cases = [
        (invalid, Held::Malformed),
        (trailing, Held::NonCanonical),
        (
            planted(
                &bytes,
                r#"{"format":1,"kind":"job","#,
                r#"{"kind":"job","format":1,"#,
            ),
            Held::NonCanonical,
        ),
        (
            resealed(&planted(
                &bytes,
                r#""bytes":9600,"every":5,"#,
                r#""every":5,"bytes":9600,"#,
            )),
            Held::NonCanonical,
        ),
        (b"{".to_vec(), Held::Malformed),
        (bytes[..bytes.len() - 1].to_vec(), Held::Malformed),
        (deep.into_bytes(), Held::Malformed),
        (
            planted(&bytes, r#""format":1,"#, r#""format":1.0,"#),
            Held::Malformed,
        ),
        (
            planted(
                &bytes,
                r#""format":1,"generator""#,
                r#""format":1.0,"generator""#,
            ),
            Held::Malformed,
        ),
        (
            planted(&bytes, r#"{"format":1,"#, r#"{"x":["\u00e9"],"format":1,"#),
            Held::NonAscii,
        ),
        (
            planted(
                &bytes,
                r#"{"format":1,"#,
                r#"{"x":[{"a":0,"a":0}],"format":1,"#,
            ),
            Held::DuplicateKey,
        ),
        (
            planted(&bytes, r#""run":0}"#, r#""run":-1}"#),
            Held::Malformed,
        ),
        (
            planted(&bytes, r#""run":0}"#, r#""run":18446744073709551616}"#),
            Held::Malformed,
        ),
        (
            planted(&bytes, r#""campaign":"c1""#, "\"campaign\":\"c\u{e9}\""),
            Held::NonAscii,
        ),
        (
            planted(&bytes, r#""kind":"job""#, r#""kind":"attempt""#),
            Held::WrongKind,
        ),
        (
            planted(&bytes, r#""ring":2,"#, r#""ring":"2","#),
            Held::Mismatch,
        ),
        (planted(&bytes, r#","run":0}"#, "}"), Held::Mismatch),
        (
            planted(&bytes, r#""run":0}"#, r#""run":"0"}"#),
            Held::Mismatch,
        ),
        (
            planted(&bytes, r#""platform":"x86_64-linux","#, ""),
            Held::Mismatch,
        ),
        (
            planted(&bytes, r#""kind":"job""#, r#""kind":7"#),
            Held::Mismatch,
        ),
        (
            planted(&bytes, r#""sha256":""#, r#""sha256":"A"#),
            Held::Mismatch,
        ),
        (
            planted(
                &bytes,
                r#""format":1,"generator""#,
                r#""format":true,"generator""#,
            ),
            Held::Mismatch,
        ),
        (
            planted(&bytes, r#""class":"live""#, r#""class":[]"#),
            Held::Mismatch,
        ),
        (
            planted(&bytes, r#"{"format":1,"#, r#"{"extra":0,"format":2,"#),
            Held::UnknownFormat,
        ),
        (
            planted(&bytes, r#"{"format":1,"#, r#"{"format":"1","#),
            Held::UnknownFormat,
        ),
        (
            planted(&bytes, r#"{"format":1,"#, r#"{"format":true,"#),
            Held::UnknownFormat,
        ),
        (
            planted(&bytes, r#"{"format":1,"#, r#"{"extra":0,"#),
            Held::UnknownFormat,
        ),
        (b"[]".to_vec(), Held::UnknownFormat),
        (b"1".to_vec(), Held::UnknownFormat),
        (b"null".to_vec(), Held::UnknownFormat),
        (planted(&bytes, r#""kind":"job","#, ""), Held::Mismatch),
        (
            planted(&bytes, &format!(r#","sha256":"{sha256}""#), ""),
            Held::Mismatch,
        ),
        (
            format!(r#"{{"format":1,"kind":"job","sha256":"{sha256}"}}"#).into_bytes(),
            Held::Mismatch,
        ),
        (
            planted(&bytes, r#"{"format":1,"#, r#"{"format":2,"x":"\u00e9","#),
            Held::NonAscii,
        ),
        (
            planted(
                &planted(&bytes, r#""kind":"job""#, r#""kind":"attempt""#),
                r#""run":0}"#,
                r#""run":"0"}"#,
            ),
            Held::WrongKind,
        ),
        (
            planted(&bytes, r#""generator":null,"#, ""),
            Held::NonCanonical,
        ),
        (
            resealed(&planted(&bytes, r#""generator":null,"#, "")),
            Held::NonCanonical,
        ),
        (
            planted(&bytes, r#""campaign":"c1""#, r#""campaign":"\u00631""#),
            Held::NonCanonical,
        ),
    ];
    for (bytes, expected) in cases {
        let held = decode::<Job>(&bytes).expect_err("a faulty record is held");
        assert_eq!(
            discriminant(&held),
            discriminant(&expected),
            "{held:?}, expected {expected:?}: {}",
            String::from_utf8_lossy(&bytes)
        );
    }
}

/// A struct given as an array is held as a mismatch, under its original
/// checksum and under a recomputed one, rather than decoded by position.
#[test]
fn a_struct_given_as_an_array_is_held() {
    let [job, ..] = jobs();
    let text = String::from_utf8(encode(&job)).expect("the bytes are ASCII");
    let record = serde_json::to_value(&job).expect("the job has a generic form");
    let values = |value: &serde_json::Value| {
        let object = value.as_object().expect("the value is an object");
        serde_json::to_string(&object.values().collect::<Vec<_>>()).expect("the values encode")
    };
    let experiment = &record["experiment"];
    for (value, field) in [
        (&experiment["pins"], "pins"),
        (experiment, "experiment"),
        (&record, "record"),
    ] {
        let object = serde_json::to_string(value).expect("the value encodes");
        let from = format!(r#""{field}":{object}"#);
        let to = format!(r#""{field}":{}"#, values(value));
        let arrayed = planted(text.as_bytes(), &from, &to);
        for arrayed in [resealed(&arrayed), arrayed] {
            let held = decode::<Job>(&arrayed).expect_err("an arrayed struct is held");
            assert!(matches!(held, Held::Mismatch), "{field}: {held:?}");
        }
    }
}

#[test]
fn artifact_comparison_faults_are_held() {
    let mut fork = artifacts()[0].clone();
    fork.output = Some(text("/outputs/children"));
    round_trip(&fork);
    let bytes = encode(&artifacts()[0]);
    for (fault, expected) in [
        (
            planted(
                &bytes,
                r#""archive_path":"/archives/worker""#,
                r#""archive_path":"\u00e9""#,
            ),
            Held::NonAscii,
        ),
        (
            planted(&bytes, r#""comparison":{"#, r#""comparison":{"extra":0,"#),
            Held::UnknownField,
        ),
        (
            planted(&bytes, r#""divergence":{"#, r#""divergence":{"extra":0,"#),
            Held::UnknownField,
        ),
        (
            planted(&bytes, r#""committed":{"#, r#""committed":{"extra":0,"#),
            Held::UnknownField,
        ),
        (
            planted(&bytes, r#""summary":{"#, r#""summary":{"extra":0,"#),
            Held::UnknownField,
        ),
        (
            planted(
                &bytes,
                r#""first_failure":{"#,
                r#""first_failure":{"extra":0,"#,
            ),
            Held::UnknownField,
        ),
        (
            planted(
                &bytes,
                r#""status":"diverged""#,
                r#""status":"diverged","status":"reduced""#,
            ),
            Held::DuplicateKey,
        ),
    ] {
        let held = decode::<Artifact>(&fault).expect_err("a faulty artifact is held");
        assert_eq!(discriminant(&held), discriminant(&expected), "{held:?}");
    }
}

#[test]
fn session_optionals_are_canonical_and_nested_faults_are_held() {
    let absent = encode(&artifacts()[0]);
    assert!(decode::<Artifact>(&absent).is_ok());
    for field in ["session", "session_original"] {
        let spelled = resealed(&planted(
            &absent,
            r#""summary":"#,
            &format!("\"{field}\":null,\"summary\":"),
        ));
        assert!(matches!(
            decode::<Artifact>(&spelled),
            Err(Held::NonCanonical)
        ));
    }
    let null_output = resealed(&planted(
        &absent,
        r#""reason":"#,
        r#""output":null,"reason":"#,
    ));
    assert!(matches!(
        decode::<Artifact>(&null_output),
        Err(Held::NonCanonical)
    ));
    let present = encode(&artifacts()[2]);
    for (fault, expected) in [
        (
            planted(&present, r#""session":{"#, r#""session":{"extra":0,"#),
            Held::UnknownField,
        ),
        (
            planted(
                &present,
                r#""session_original":{"#,
                r#""session_original":{"extra":0,"#,
            ),
            Held::UnknownField,
        ),
        (
            planted(&present, r#""complete":false"#, r#""complete":"false""#),
            Held::Mismatch,
        ),
        (
            planted(&present, r#""index":"window 0""#, r#""index":"\u00e9""#),
            Held::NonAscii,
        ),
    ] {
        let held = decode::<Artifact>(&resealed(&fault)).unwrap_err();
        assert_eq!(discriminant(&held), discriminant(&expected));
    }
}

#[test]
fn maximum_session_texts_and_digests_fit_the_artifact_bound() {
    let mut artifact = artifacts()[0].clone();
    artifact.command = text("replay-session");
    artifact.comparison = None;
    artifact.summary = None;
    artifact.archive_path = Some(text(&"\"".repeat(4096)));
    artifact.reason = text(&"\\u{1f}".repeat(4096));
    let mut evidence = artifacts()[2].session.clone().unwrap();
    evidence.bytes = u64::MAX;
    evidence.records = u64::MAX;
    evidence.verified_windows = 1024;
    evidence.index = text(&"x".repeat((1 << 18) + 2048));
    evidence.end = Some(text(&"\\u{1f}".repeat(1 << 14)));
    evidence.digests = vec![Digest::of(b"window"); 1024];
    evidence.verification_error = Some(text(&"\\u{1f}".repeat(4096)));
    evidence.output = text(&"\\u{fffd}".repeat(4096));
    artifact.session_original = Some(evidence.clone());
    evidence.output = text(&"\"".repeat(4096));
    artifact.session = Some(evidence);
    let encoded = round_trip(&artifact);
    assert!((encoded.len() as u64) < super::BOUND, "{}", encoded.len());
}

#[test]
fn started_inode_is_an_exact_unsigned_integer_and_bad_types_are_held() {
    let bytes = encode(&started());
    let text = String::from_utf8(bytes.clone()).unwrap();
    assert!(text.contains("\"cgroup_inode\":18446744073709551615"));
    for (replacement, expected) in [
        ("-1", Held::Malformed),
        ("\"1\"", Held::Mismatch),
        ("null", Held::Mismatch),
        ("1.0", Held::Malformed),
    ] {
        let fault = resealed(&planted(
            &bytes,
            "\"cgroup_inode\":18446744073709551615",
            &format!("\"cgroup_inode\":{replacement}"),
        ));
        let held = decode::<Started>(&fault).unwrap_err();
        assert_eq!(
            discriminant(&held),
            discriminant(&expected),
            "{replacement}: {held:?}"
        );
    }
}

fn attempt() -> Attempt {
    Attempt {
        attempt: text("job-0001"),
        file_bytes: u64::MAX,
        job: Digest::of(b"job"),
        manifest: Digest::of(b"manifest"),
        number: 1,
    }
}
fn bound() -> BoundEvidence {
    BoundEvidence {
        artifact: Digest::of(b"artifact"),
        attempt: text("job-0001"),
        bundle: Some(Digest::of(b"bundle")),
    }
}
fn finished() -> Finished {
    Finished {
        attempt: text("job-0001"),
        binding: Binding::Missing,
        bound: None,
        class: Class::Interrupted,
        exit: None,
        signal: None,
        interruption: None,
        kernel: Kernel::default(),
        residual_members: false,
        watchdog: false,
    }
}

fn job_result() -> JobResult {
    JobResult {
        attempt: 1,
        finished: finished(),
        job: Digest::of(b"job"),
        manifest: Digest::of(b"manifest"),
    }
}

#[test]
fn settlement_records_hold_nested_unknown_fields_and_invalid_classes() {
    let result = job_result();
    let pin = Pin {
        result: result.clone(),
    };
    let cases = [
        changed_record(&result, |v| {
            v["finished"]["extra"] = true.into();
        }),
        changed_record(&result, |v| {
            v["finished"]["class"] = "unknown".into();
        }),
    ];
    assert!(matches!(
        decode::<JobResult>(&cases[0]),
        Err(Held::UnknownField)
    ));
    assert!(matches!(
        decode::<JobResult>(&cases[1]),
        Err(Held::Mismatch)
    ));
    let cases = [
        changed_record(&pin, |v| {
            v["result"]["extra"] = true.into();
        }),
        changed_record(&pin, |v| {
            v["result"]["finished"]["class"] = "unknown".into();
        }),
    ];
    assert!(matches!(decode::<Pin>(&cases[0]), Err(Held::UnknownField)));
    assert!(matches!(decode::<Pin>(&cases[1]), Err(Held::Mismatch)));
}

#[test]
fn attempt_labels_and_terminal_flags_hold_invalid_values() {
    for field in ["class", "binding", "residual_members"] {
        let bytes = changed_record(&finished(), |value| {
            value[field] = serde_json::json!("unknown");
        });
        assert!(
            matches!(decode::<Finished>(&bytes), Err(Held::Mismatch)),
            "{field}"
        );
    }
    let old_started = changed_record(&started(), |value| {
        value.as_object_mut().unwrap().remove("baseline");
    });
    assert!(matches!(
        decode::<Started>(&old_started),
        Err(Held::Mismatch)
    ));
    let bytes = changed_record(&bound(), |value| {
        value["bundle"] = serde_json::json!("not-a-digest");
    });
    assert!(matches!(
        decode::<BoundEvidence>(&bytes),
        Err(Held::Mismatch)
    ));
}

#[test]
fn attempt_kinds_have_fixed_envelope_bytes() {
    assert_eq!(
        String::from_utf8(encode(&attempt())).unwrap(),
        r#"{"format":1,"kind":"attempt","record":{"attempt":"job-0001","file_bytes":18446744073709551615,"job":"5e8c9902207afaeb7120430c585a445f21e92932081d64bc99f80e4925bcb002","manifest":"05b3abf2579a5eb66403cd78be557fd860633a1fe2103c7642030defe32c657f","number":1},"sha256":"07a229f0e2c4a26b89be72767e42b58405e816252f0f462c8ef38d7dc96ce3e7"}"#
    );
    assert_eq!(
        String::from_utf8(encode(&bound())).unwrap(),
        r#"{"format":1,"kind":"bound","record":{"artifact":"c7c5c1d70c5dec4416ab6158afd0b223ef40c29b1dc1f97ed9428b94d4cadb1c","attempt":"job-0001","bundle":"1e6ed65d77d6364eeaed5a745ba5c4985ae2b700dd85d7cf7f027bdf294a33fc"},"sha256":"4bedb19f20997ee0715161824f8647ab82a947e21f9a9145327f7ad85f57d167"}"#
    );
    assert_eq!(
        String::from_utf8(encode(&finished())).unwrap(),
        r#"{"format":1,"kind":"finished","record":{"attempt":"job-0001","binding":"missing","bound":null,"class":"interrupted","exit":null,"interruption":null,"kernel":{"cpu":{},"memory":{},"pids":{}},"residual_members":false,"signal":null,"watchdog":false},"sha256":"2067abacc6001cf1a593db9ed073a7b2a1abada35a70794550a2e5d37473a820"}"#
    );
}

#[test]
fn interrupted_triage_records_refuse_replay_status_and_complete_without_status() {
    let mut record = triage_result();
    record.status = Some(super::ReplayStatus::Reproduced);
    assert!(matches!(
        decode::<super::TriageResult>(&encode(&record)),
        Err(Held::Mismatch)
    ));
    record.status = None;
    record.state = super::StepState::Complete;
    assert!(matches!(
        decode::<super::TriageResult>(&encode(&record)),
        Err(Held::Mismatch)
    ));
    record.finished = finished();
    record.finished.exit = Some(0);
    record.finished.class = Class::Pass;
    assert!(matches!(
        decode::<super::TriageResult>(&encode(&record)),
        Err(Held::Mismatch)
    ));
    record.status = Some(super::ReplayStatus::Reproduced);
    round_trip(&record);
}

#[test]
fn finding_bound_and_one_extra_byte_use_the_kind_specific_cap() {
    let sized = |size: usize| {
        let mut record = finding();
        record.artifact.as_mut().unwrap().reason = text("");
        let base = record.encoded_len();
        record.artifact.as_mut().unwrap().reason = text(&"x".repeat(size - base));
        assert_eq!(record.encoded_len(), size);
        record
    };
    let case = crate::store::fixture::Case::new();
    let store = crate::store::Store::open(&case.state).unwrap();
    let bound = <super::Finding as Record>::BOUND as usize;
    assert_eq!(bound, 5 * super::BOUND as usize);
    let record = sized(bound);
    let name = crate::store::Name::new("at-bound").unwrap();
    store.create_record(store.root(), &name, &record).unwrap();
    assert_eq!(
        store
            .read_record::<super::Finding>(store.root(), &name)
            .unwrap()
            .unwrap()
            .record(),
        &record
    );
    let over = crate::store::Name::new("over-bound").unwrap();
    assert!(matches!(
        store.create_record(store.root(), &over, &sized(bound + 1)),
        Err(crate::store::Error::Oversize)
    ));
    store
        .create_once(store.root(), &over, &encode(&sized(bound + 1)))
        .unwrap();
    assert!(matches!(
        store.read_record::<super::Finding>(store.root(), &over),
        Err(Held::Unreadable(crate::store::Unreadable::Oversize))
    ));
}

#[test]
fn finding_disposition_and_capture_marker_envelope_bytes_are_pinned() {
    let admission = admissions()[0].clone();
    let id = text(&format!("{}-0001", admission.job().id()));
    let attempt = Attempt {
        attempt: id.clone(),
        file_bytes: 1024,
        job: admission.job().id().digest(),
        manifest: admission.job().manifest_sha256(),
        number: 1,
    };
    let finished = Finished {
        attempt: id.clone(),
        class: Class::Watchdog,
        exit: Some(6),
        watchdog: true,
        ..finished()
    };
    let captured = super::Captured {
        attempt: id.clone(),
        finding: Some(id),
        finished: Digest::of(&encode(&finished)),
    };
    let finding = super::Finding {
        child: None,
        parent_attempt: None,
        calibration_root: None,
        admission,
        artifact: None,
        attempt,
        finished,
        kind: super::FindingKind::Watchdog,
    };
    assert_eq!(
        encode(&finding),
        include_bytes!("../../testdata/finding.json")
    );
    assert_eq!(
        encode(&disposition()),
        include_bytes!("../../testdata/disposition.json")
    );
    assert_eq!(
        encode(&captured),
        include_bytes!("../../testdata/captured.json")
    );
}

#[test]
fn controller_and_retention_allowances_are_charged_in_both_capacity_dimensions() {
    let charge = super::resource_charge(100, 10);
    assert_eq!((charge.bytes, charge.inodes), (15 * 1_048_576 + 200, 37));
    let mut values = configurations()[0].config().clone();
    values.insert(text("artifact_bytes"), 31_457_680);
    assert!(matches!(
        Configuration::new(values.clone()),
        Err(super::ConfigurationError::Capacity)
    ));
    values.insert(text("artifact_bytes"), 31_457_681);
    values.insert(text("artifact_inodes"), 74);
    assert!(matches!(
        Configuration::new(values.clone()),
        Err(super::ConfigurationError::Capacity)
    ));
    values.insert(text("artifact_inodes"), 75);
    assert!(Configuration::new(values.clone()).is_ok());
    values.insert(text("artifact_inodes"), 100_000);
    values.insert(text("attempt_inodes"), 4094);
    assert!(Configuration::new(values.clone()).is_ok());
    values.insert(text("attempt_inodes"), 4095);
    assert!(matches!(
        Configuration::new(values),
        Err(super::ConfigurationError::InodeLimit)
    ));
}

#[test]
fn overflowing_retention_capacity_is_rejected_before_multiplication() {
    let mut values = configurations()[0].config().clone();
    for (key, value) in [
        ("slots", u64::MAX - 1),
        ("reserve_slots", 1),
        ("cores", u64::MAX),
        ("memory", u64::MAX),
        ("tree_memory", 1),
        ("attempt_output", crate::sys::LIMIT_MAX),
        ("artifact_bytes", u64::MAX),
    ] {
        values.insert(text(key), value);
    }
    assert!(matches!(
        Configuration::new(values),
        Err(super::ConfigurationError::Capacity)
    ));
}

#[test]
fn candidate_null_measurement_roundtrips_distinctly_from_zero() {
    let mut record = regression_candidate();
    record.step_ms = None;
    record.tier = text("pinned-corpus");
    let absent = round_trip(&record);
    record.step_ms = Some(0);
    let measured = round_trip(&record);
    assert_ne!(absent, measured);
}

#[test]
fn signal_aborts_complete_and_output_limits_interrupt_triage() {
    let mut record = triage_result();
    record.finished.class = Class::Signal;
    record.finished.exit = Some(1);
    record.finished.signal = None;
    record.state = super::StepState::Complete;
    record.status = Some(super::ReplayStatus::Reproduced);
    round_trip(&record);
    record.finished.class = Class::OutputLimit;
    assert!(matches!(
        decode::<super::TriageResult>(&encode(&record)),
        Err(Held::Mismatch)
    ));
    record.state = super::StepState::Interrupted;
    record.status = None;
    record.comparison = None;
    round_trip(&record);
    record.comparison = Some(super::Comparison {
        candidate: None,
        divergence: None,
        failure_identity: None,
        failure_kind: None,
        observed: None,
        original: None,
        output: None,
        status: text("reproduced"),
    });
    assert!(matches!(
        decode::<super::TriageResult>(&encode(&record)),
        Err(Held::Mismatch)
    ));
    record.comparison = None;
    record.finished.class = Class::Pass;
    record.finished.exit = Some(0);
    record.finished.signal = None;
    record.status = Some(super::ReplayStatus::Reproduced);
    assert!(matches!(
        decode::<super::TriageResult>(&encode(&record)),
        Err(Held::Mismatch)
    ));
}

#[test]
fn output_limit_witness_roundtrips_absent_false_and_true() {
    let mut record = triage_result();
    let absent = round_trip(&record);
    let mut fields = serde_json::to_value(&record).unwrap();
    assert!(fields.get("output_limited").is_none());
    assert_eq!(
        serde_json::from_value::<super::TriageResult>(fields.clone()).unwrap(),
        record
    );
    fields["output_limited"] = false.into();
    assert_eq!(
        serde_json::from_value::<super::TriageResult>(fields).unwrap(),
        record
    );
    record.output_limited = true;
    let present = round_trip(&record);
    assert_ne!(present, absent);
    record.finished.class = Class::Incomplete;
    record.finished.exit = Some(4);
    round_trip(&record);
}

#[test]
fn file_limit_witness_roundtrips_absent_false_and_true() {
    let mut record = triage_result();
    let absent = round_trip(&record);
    let mut fields = serde_json::to_value(&record).unwrap();
    assert!(fields.get("file_limited").is_none());
    fields["file_limited"] = false.into();
    assert_eq!(
        serde_json::from_value::<super::TriageResult>(fields).unwrap(),
        record
    );
    record.file_limited = true;
    assert_ne!(round_trip(&record), absent);
}

fn target() -> super::Target {
    let asset = corpus_asset();
    super::Target {
        asset: asset.id(),
        boundary: asset.boundary,
        build: asset.probe.archive,
        bundle: asset.probe.bundle,
        bytes: asset.probe.bytes,
        decisions: asset.decisions,
        form: super::ForkForm::Branch {
            siblings: 1,
            suffixes: 1,
        },
        manifest: asset.probe.manifest,
        milestone: asset.probe.milestone,
        prefix: asset.prefix,
        root: asset.root,
        semantic: asset.semantic,
    }
}

#[test]
fn targeted_variants_and_child_options_round_trip_with_semantic_identity() {
    for form in [
        super::ForkForm::Branch {
            siblings: 2,
            suffixes: 3,
        },
        super::ForkForm::Explore {
            advances: 4,
            children: 2,
            depth: 2,
            faults: 3,
        },
    ] {
        let mut target = target();
        target.form = form;
        let mut experiment = super::identity_tests::pinned();
        experiment.format = 2;
        experiment.pins.build = super::Text::new(&target.build.to_string()).unwrap();
        experiment.target = Some(target.clone());
        let job = super::Job::targeted(experiment.clone()).unwrap();
        assert!(
            super::Admission::new(
                super::Text::new("/archive").unwrap(),
                job.clone(),
                super::Purpose::Campaign
            )
            .is_err()
        );
        assert!(matches!(
            super::Job::derive(experiment.clone(), &[]),
            Err(super::ManifestError::TargetedInputs)
        ));
        round_trip(&job);
        let first =
            super::Admission::targeted(super::Text::new("/archive").unwrap(), job.clone(), 1)
                .unwrap();
        let second =
            super::Admission::targeted(super::Text::new("/archive").unwrap(), job.clone(), 2)
                .unwrap();
        round_trip(&first);
        round_trip(&second);
        assert_eq!(first.job().id(), second.job().id());
        assert_ne!(first, second);
        let id = job.id();
        assert_eq!(job.seed(), target.root);
        assert_eq!(
            id.to_string(),
            match target.form {
                super::ForkForm::Branch { .. } =>
                    "c955b6512939bb955686c4502a742d04ffc54a882dbad2999e95ee59b946e1ed",
                super::ForkForm::Explore { .. } =>
                    "8b2301d67300d366a7818f856526e6618dd860ac4a0e73c5832d4ee3333d129a",
            }
        );
        for mutate in 0..4 {
            let mut changed = experiment.clone();
            let target = changed.target.as_mut().unwrap();
            match mutate {
                0 => target.asset = super::Digest::of(b"another asset"),
                1 => target.prefix = super::Digest::of(b"another prefix"),
                2 => {
                    target.build = super::Digest::of(b"another build");
                    changed.pins.build = super::Text::new(&target.build.to_string()).unwrap();
                }
                _ => {
                    target.form = super::ForkForm::Branch {
                        siblings: 4,
                        suffixes: 16,
                    }
                }
            }
            assert_ne!(id, super::Job::targeted(changed).unwrap().id());
        }
        let mut finding = finding();
        finding.admission = first;
        finding.child = Some(super::ChildEvidence {
            bundle: None,
            digest: None,
            terminal: None,
            class: super::Class::Violation,
            kind: super::FindingKind::Violation,
            file: None,
            label: super::Text::new("c0-0").unwrap(),
        });
        finding.parent_attempt = Some(finding.attempt.attempt.clone());
        round_trip(&finding);
        finding.child.as_mut().unwrap().digest = Some(super::Digest::of(b"semantic child"));
        finding.child.as_mut().unwrap().terminal =
            Some(super::Text::new("complete violation fired=03 required=03").unwrap());
        finding.child.as_mut().unwrap().bundle = Some(super::Digest::of(b"child"));
        finding.child.as_mut().unwrap().file = Some(super::Text::new("suffix-0-0.bundle").unwrap());
        round_trip(&finding);
    }
}

#[test]
fn targeted_static_rules_and_nested_fields_are_held_on_read() {
    let target = target();
    let mut experiment = super::identity_tests::pinned();
    experiment.format = 2;
    experiment.pins.build = text(&target.build.to_string());
    experiment.target = Some(target);
    let job = super::Job::targeted(experiment).unwrap();
    let admission = super::Admission::targeted(text("/archive"), job.clone(), 1).unwrap();
    for mutate in 0..4 {
        let bytes = changed_record(&admission, |value| match mutate {
            0 => {
                value.as_object_mut().unwrap().remove("corpus_version");
            }
            1 => value["corpus_version"] = 0.into(),
            2 => value["purpose"] = "calibration".into(),
            _ => value["job"]["experiment"]["target"]["form"]["siblings"] = 0.into(),
        });
        assert!(
            matches!(decode::<super::Admission>(&bytes), Err(Held::Mismatch)),
            "{mutate}"
        );
    }
    let bytes = changed_record(&admission, |value| {
        value["job"]["experiment"]["target"]["extra"] = true.into()
    });
    assert!(matches!(
        decode::<super::Admission>(&bytes),
        Err(Held::UnknownField)
    ));
    let bytes = changed_record(&admission, |value| {
        value["job"]["experiment"]["target"]["prefix"] =
            Digest::of(b"tampered target").to_string().into()
    });
    assert!(matches!(
        decode::<super::Admission>(&bytes),
        Err(Held::Mismatch)
    ));
    let bytes = changed_record(&job, |value| {
        value["experiment"]["target"]["root"] = 0.into();
        value["id"] = Digest::of(&serde_json::to_vec(&value["experiment"]).unwrap())
            .to_string()
            .into();
        value["seed"] = 0.into();
    });
    assert!(matches!(decode::<super::Job>(&bytes), Err(Held::Mismatch)));
    let bytes = changed_record(&job, |value| {
        value["manifest_sha256"] = Digest::of(b"wrong manifest").to_string().into()
    });
    assert!(matches!(decode::<super::Job>(&bytes), Err(Held::Mismatch)));
    let bytes = changed_record(&admissions()[0], |value| value["corpus_version"] = 1.into());
    assert!(matches!(
        decode::<super::Admission>(&bytes),
        Err(Held::Mismatch)
    ));
}

#[test]
fn ordinary_and_targeted_experiment_formats_are_paired_on_write_and_read() {
    for format in [0, 2, 3] {
        let mut experiment = super::identity_tests::pinned();
        experiment.format = format;
        assert!(Job::derive(experiment, &PINNED_KEYS).is_err());
    }
    let ordinary = admissions()[0].job().clone();
    for format in [0, 2, 3] {
        let bytes = changed_record(&ordinary, |value| {
            value["experiment"]["format"] = format.into();
            let experiment: super::Experiment =
                serde_json::from_value(value["experiment"].clone()).unwrap();
            let id = experiment.id();
            value["id"] = id.to_string().into();
            value["seed"] = super::identity::seed(&id).into();
        });
        assert!(matches!(decode::<Job>(&bytes), Err(Held::Mismatch)));
    }
}

#[test]
fn finding_lineage_decode_refuses_orphan_parents_and_mismatched_kinds() {
    let original = finding();
    let bytes = changed_record(&original, |value| {
        value["parent_attempt"] = value["attempt"]["attempt"].clone()
    });
    assert!(matches!(
        decode::<super::Finding>(&bytes),
        Err(Held::Mismatch)
    ));
    let mut child = original;
    child.child = Some(super::ChildEvidence {
        bundle: None,
        class: Class::Violation,
        digest: None,
        file: None,
        kind: super::FindingKind::Violation,
        label: text("c0-0"),
        terminal: None,
    });
    child.parent_attempt = Some(child.attempt.attempt.clone());
    round_trip(&child);
    let bytes = changed_record(&child, |value| value["child"]["kind"] = "incomplete".into());
    assert!(matches!(
        decode::<super::Finding>(&bytes),
        Err(Held::Mismatch)
    ));
}

#[test]
fn targeted_reader_checks_format_and_build_after_semantic_identity() {
    let target = target();
    let mut experiment = super::identity_tests::pinned();
    experiment.format = 2;
    experiment.pins.build = text(&target.build.to_string());
    experiment.target = Some(target);
    let job = super::Job::targeted(experiment).unwrap();
    for mutation in ["format", "build"] {
        let bytes = changed_record(&job, |value| {
            if mutation == "format" {
                value["experiment"]["format"] = 1.into();
            } else {
                value["experiment"]["pins"]["build"] =
                    Digest::of(b"other build").to_string().into();
            }
            let experiment: super::Experiment =
                serde_json::from_value(value["experiment"].clone()).unwrap();
            value["id"] = experiment.id().to_string().into();
        });
        assert!(
            matches!(decode::<Job>(&bytes), Err(Held::Mismatch)),
            "{mutation}"
        );
    }
}
