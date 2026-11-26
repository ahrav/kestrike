use super::name;
use crate::campaign::state_fixture::Sharded;
use crate::protocol::Listing;
use crate::record::{
    Admission, Attempt, BOUND, Binding, BoundEvidence, Class, Digest, Finished, Intent, Kernel,
    Pins, Purpose, Started, Text,
};
use crate::step::{Outcome, Step};
use crate::store::fixture::{Case, scripted, snapshot};
use crate::store::{Dir, Store};
use serde_json::{Value, json};
use std::collections::BTreeMap;

fn report(path: &std::path::Path) -> Result<Value, crate::campaign::Error> {
    let view = crate::store::View::open(path)?;
    super::projection::project(&view)
}

fn text(value: &str) -> Text {
    Text::new(value).unwrap()
}

pub(in crate::campaign) struct Fixture {
    pub(in crate::campaign) case: Case,
    pub(in crate::campaign) store: Store,
    listing: Listing,
}
impl Fixture {
    pub(in crate::campaign) fn new() -> Self {
        let case = Case::new();
        let store = Store::open(&case.state).unwrap();
        let listing =
            Listing::parse(include_str!("../../../testdata/admission-listing.txt")).unwrap();
        Self {
            case,
            store,
            listing,
        }
    }
    pub(in crate::campaign) fn admit(&self, run: u64) -> Admission {
        self.admit_n(run, 3)
    }
    pub(in crate::campaign) fn admit_n(&self, run: u64, attempts: u64) -> Admission {
        self.admission(run, attempts, Purpose::Campaign)
    }
    pub(in crate::campaign) fn admit_purpose(&self, run: u64, purpose: Purpose) -> Admission {
        self.admission(run, 3, purpose)
    }
    fn admission(&self, run: u64, attempts: u64, purpose: Purpose) -> Admission {
        self.admit_profile("upload", run, attempts, purpose)
    }
    fn admit_profile(&self, profile: &str, run: u64, attempts: u64, purpose: Purpose) -> Admission {
        crate::campaign::admit(
            &self.store,
            &self.listing,
            Pins {
                build: text(&"b".repeat(64)),
                executable: text(&"e".repeat(64)),
                platform: text("x86_64-linux"),
                toolchain: text("rustc"),
            },
            text("/archive"),
            &crate::campaign::Request {
                profile: text(profile),
                campaign: text(if purpose == Purpose::Calibration {
                    "calibration"
                } else {
                    "c1"
                }),
                run,
                attempts,
                counts: BTreeMap::new(),
            },
            purpose,
        )
        .unwrap()
        .record
    }
    pub(in crate::campaign) fn targeted(&self, run: u64) -> Admission {
        let original = self.admit(run);
        let bundle = vec![0u8; 96];
        let mut experiment = original.job().experiment().clone();
        experiment.format = 2;
        experiment.target = Some(crate::record::Target {
            asset: Digest::of(b"asset"),
            boundary: 1,
            build: Digest::parse(experiment.pins.build.as_str()).unwrap(),
            bundle: Digest::of(&bundle),
            bytes: bundle.len() as u64,
            decisions: 1,
            form: crate::record::ForkForm::Branch {
                siblings: 1,
                suffixes: 1,
            },
            manifest: original.job().manifest_sha256(),
            milestone: text("upload"),
            prefix: Digest::of(b"prefix"),
            root: original.job().seed(),
            semantic: 1,
        });
        let job = crate::record::Job::targeted(experiment).unwrap();
        let admission = Admission::targeted(text("/archive"), job, 1).unwrap();
        crate::campaign::state_fixture::retarget(&self.store, &original, &admission, &bundle);
        admission
    }

    pub(in crate::campaign) fn finish(&self, job: &Admission, cpu: Option<u64>) -> Dir {
        self.finish_at(job, 1, cpu, Class::Pass)
    }
    pub(in crate::campaign) fn finish_at(
        &self,
        job: &Admission,
        number: u64,
        cpu: Option<u64>,
        class: Class,
    ) -> Dir {
        self.finish_at_with_listing(job, number, cpu, class, None)
    }
    pub(in crate::campaign) fn finish_at_with_listing(
        &self,
        job: &Admission,
        number: u64,
        cpu: Option<u64>,
        class: Class,
        listing: Option<&[u8]>,
    ) -> Dir {
        let (directory, verified, completed) =
            self.finish_unsettled_with_listing(job, number, cpu, class, listing);
        crate::attempt::settle(&self.store, verified, completed).unwrap();
        directory
    }
    pub(in crate::campaign) fn finish_unsettled(
        &self,
        job: &Admission,
        number: u64,
        cpu: Option<u64>,
        class: Class,
    ) -> (
        Dir,
        crate::record::Verified<Admission>,
        crate::attempt::Completed,
    ) {
        self.finish_unsettled_with_listing(job, number, cpu, class, None)
    }
    fn finish_unsettled_with_listing(
        &self,
        job: &Admission,
        number: u64,
        cpu: Option<u64>,
        class: Class,
        listing: Option<&[u8]>,
    ) -> (
        Dir,
        crate::record::Verified<Admission>,
        crate::attempt::Completed,
    ) {
        let store = &self.store;
        let id = job.job().id();
        let attempts =
            crate::layout::make_shard(store, crate::layout::ATTEMPTS, &id.to_string()).unwrap();
        store.mkdir(&attempts, &name(&id.to_string())).unwrap();
        let root = store
            .open_dir(&attempts, &name(&id.to_string()))
            .unwrap()
            .unwrap();
        store.mkdir(&root, &name(&format!("{number:04}"))).unwrap();
        let directory = store
            .open_dir(&root, &name(&format!("{number:04}")))
            .unwrap()
            .unwrap();
        let attempt = Attempt {
            attempt: text(&format!("{id}-{number:04}")),
            file_bytes: BOUND,
            job: id.digest(),
            manifest: job.job().manifest_sha256(),
            number,
        };
        store
            .create_record(&directory, &name("attempt"), &attempt)
            .unwrap();
        let intent = Intent {
            attempt: attempt.attempt.clone(),
            boot: text("boot"),
            cgroup: text(self.case.state.join("gone").to_str().unwrap()),
        };
        store
            .create_record(&directory, &name("intent"), &intent)
            .unwrap();
        let started = Started {
            attempt: intent.attempt.clone(),
            baseline: Kernel::default(),
            boot: intent.boot.clone(),
            cgroup: intent.cgroup.clone(),
            cgroup_inode: 1,
            launcher_pid: 1,
        };
        store
            .create_record(&directory, &name("started"), &started)
            .unwrap();
        let mut artifact =
            crate::attempt::tests::artifact(attempt.attempt.as_str(), attempt.manifest);
        artifact.archive = Digest::parse(&"b".repeat(64));
        let stdout = if class == Class::Violation {
            include_str!("../../../testdata/counting.summary")
                .replace("complete pass", "complete violation")
                .replace("counts: true", "counts: false")
                .into_bytes()
        } else {
            include_bytes!("../../../testdata/counting.summary").to_vec()
        };
        let summary = artifact.summary.as_mut().unwrap();
        summary.digest =
            Digest::parse("f524dec13f9c0f31be2de651057fad6650d068a55d69e55f62e58b6df1875dfa")
                .unwrap();
        summary.decisions = Some(61);
        if class == Class::Violation {
            summary.counts = false;
            summary.terminal = text("complete violation fired=03 required=03");
            artifact.class = text("complete");
            artifact.workers.get_mut(&text("run")).unwrap().exit = Some(1);
        }
        artifact.workers.get_mut(&text("inspect")).unwrap().stdout = Digest::of(&stdout);
        if let Some(listing) = listing {
            let mut worker = artifact.workers[&text("inspect")].clone();
            worker.stdout = Digest::of(listing);
            artifact.workers.insert(text("capabilities"), worker);
        }
        if class == Class::Incomplete {
            artifact
                .workers
                .retain(|name, _| name.as_str() == "capabilities");
            artifact.summary = None;
            artifact.bundle = None;
            artifact.class = text("incomplete");
            artifact.reason = text("the archive no longer verifies after capabilities");
        }
        let artifacts = crate::attempt::tests::stage(store, &directory, &attempt, &artifact);
        let jobs = store.shard_jobs(id).unwrap().unwrap();
        let manifest = store
            .read(&jobs, &name(&format!("{id}.manifest")), BOUND)
            .unwrap()
            .unwrap();
        store
            .replace(&artifacts, &name("manifest"), manifest.bytes())
            .unwrap();
        store
            .replace(&artifacts, &name("inspect.stdout"), &stdout)
            .unwrap();
        if let Some(listing) = listing {
            store
                .replace(&artifacts, &name("capabilities.stdout"), listing)
                .unwrap();
            store
                .replace(&artifacts, &name("capabilities.stderr"), b"stderr")
                .unwrap();
        }
        if class == Class::Incomplete {
            for file in [
                "bundle",
                "run.stdout",
                "run.stderr",
                "inspect.stdout",
                "inspect.stderr",
            ] {
                store.delete(&artifacts, &name(file)).unwrap();
            }
        }
        let artifact_read = store
            .read_record::<crate::record::Artifact>(&artifacts, &name("artifact"))
            .unwrap()
            .unwrap();
        let bound = BoundEvidence {
            artifact: Digest::of(artifact_read.read().bytes()),
            attempt: attempt.attempt.clone(),
            bundle: artifact.bundle,
        };
        store
            .create_record(&directory, &name("bound"), &bound)
            .unwrap();
        let finished = Finished {
            attempt: attempt.attempt.clone(),
            binding: Binding::Matching,
            bound: Some(bound),
            class,
            exit: Some(match class {
                Class::Violation => 1,
                Class::Infrastructure => 42,
                Class::Incomplete => 4,
                _ => 0,
            }),
            interruption: (class == Class::Interrupted).then_some(libc::SIGTERM as u64),
            kernel: Kernel {
                cpu: cpu
                    .map(|value| (text("usage_usec"), value))
                    .into_iter()
                    .collect(),
                memory: [(text("peak"), 0)].into(),
                pids: [(text("peak"), 2)].into(),
            },
            residual_members: false,
            signal: None,
            watchdog: class == Class::Watchdog,
        };
        store
            .create_record(&directory, &name("finished"), &finished)
            .unwrap();
        let verified = store
            .read_record::<Admission>(&jobs, &name(&format!("{id}.json")))
            .unwrap()
            .unwrap();
        let (_, _, completed) = crate::attempt::completed_at(store, job, &root, number).unwrap();
        assert_eq!(completed.finished().record().class, class);
        (directory, verified, completed)
    }
    pub(in crate::campaign) fn probe(&self) {
        self.probe_listing(include_bytes!("../../../testdata/admission-listing.txt"));
    }
    fn probe_listing(&self, listing: &[u8]) {
        let store = &self.store;
        store.mkdir(store.root(), &name("probes")).unwrap();
        let root = store
            .open_dir(store.root(), &name("probes"))
            .unwrap()
            .unwrap();
        store.mkdir(&root, &name("probe-fixture")).unwrap();
        let directory = store
            .open_dir(&root, &name("probe-fixture"))
            .unwrap()
            .unwrap();
        let intent = Intent {
            attempt: text("probe-fixture"),
            boot: text("boot"),
            cgroup: text(self.case.state.join("gone").to_str().unwrap()),
        };
        store
            .create_record(&directory, &name("intent"), &intent)
            .unwrap();
        store
            .create_record(
                &directory,
                &name("started"),
                &Started {
                    attempt: intent.attempt.clone(),
                    baseline: Kernel::default(),
                    boot: intent.boot.clone(),
                    cgroup: intent.cgroup.clone(),
                    cgroup_inode: 1,
                    launcher_pid: 1,
                },
            )
            .unwrap();
        store
            .create_record(
                &directory,
                &name("finished"),
                &crate::record::ProbeFinished {
                    attempt: intent.attempt,
                    outcome: crate::record::ProbeOutcome::Complete,
                },
            )
            .unwrap();
        for output in crate::custody::LAUNCHER_OUTPUTS {
            store.create_once(&directory, &name(output), b"").unwrap();
        }
        store.mkdir(&directory, &name("artifacts")).unwrap();
        let artifacts = store
            .open_dir(&directory, &name("artifacts"))
            .unwrap()
            .unwrap();
        store.mkdir(&artifacts, &name("probe")).unwrap();
        let evidence =
            Store::open(&self.case.state.join("probes/probe-fixture/artifacts/probe")).unwrap();
        let directory = evidence.root();
        let mut artifact = crate::attempt::tests::artifact("probe", Digest::of(b"manifest"));
        artifact.archive = Digest::parse(&"b".repeat(64));
        artifact.bundle = None;
        artifact.manifest = None;
        artifact.command = text("capabilities");
        artifact.summary = None;
        let mut worker = artifact.workers.remove(&text("run")).unwrap();
        worker.stdout = Digest::of(listing);
        worker.stderr = Digest::of(b"");
        artifact.workers = [(text("capabilities"), worker)].into();
        evidence
            .create_record(directory, &name("artifact"), &artifact)
            .unwrap();
        evidence
            .create_once(directory, &name("capabilities.stdout"), listing)
            .unwrap();
        evidence
            .create_once(directory, &name("capabilities.stderr"), b"")
            .unwrap();
    }
}

fn profile<'a>(report: &'a Value, name: &str) -> &'a Value {
    report["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| {
            row["declaration"]["profile"] == name && row["declaration"]["counts"].is_object()
        })
        .unwrap()
}

#[test]
fn declared_unrun_and_unsupported_profiles_remain_visible() {
    let fixture = Fixture::new();
    fixture.admit(0);
    fixture.probe();
    let report = report(&fixture.case.state).unwrap();
    assert_eq!(profile(&report, "upload")["state"], "unrun");
    let expected_work: std::collections::BTreeSet<_> = [
        "decisions",
        "turns",
        "progress",
        "boundaries_checked",
        "operations",
        "witnesses",
        "faults_delivered",
        "owners",
        "clients",
        "incarnations",
        "retained_depth",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    assert_eq!(
        profile(&report, "upload")["dimensions"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>(),
        expected_work
    );
    let mut expected_cluster = expected_work;
    expected_cluster.extend(
        [
            "published",
            "hits",
            "misses",
            "refused",
            "invalidated",
            "cancelled",
            "cross",
            "reused",
            "healthy",
            "faults",
        ]
        .map(|key| format!("reached.{key}")),
    );
    expected_cluster.extend(["node-lifecycle".into(), "membership".into()]);
    let cluster = report["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["declaration"]["profile"] == "cluster-broad")
        .unwrap();
    assert_eq!(
        cluster["dimensions"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>(),
        expected_cluster
    );
    assert!(
        profile(&report, "upload")["dimensions"]
            .as_object()
            .unwrap()
            .iter()
            .all(|(key, row)| row["state"]
                == if ["incarnations", "retained_depth"].contains(&key.as_str()) {
                    "unsupported"
                } else {
                    "unrun"
                })
    );
    for declared in &fixture.listing.profiles {
        let row = report["profiles"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["declaration"]["profile"] == declared.name)
            .unwrap();
        assert_eq!(
            row["state"],
            if matches!(
                declared.class,
                crate::protocol::Class::Control | crate::protocol::Class::Recovery
            ) {
                "unsupported"
            } else {
                "unrun"
            }
        );
    }
}

#[test]
fn report_and_settle_agree_and_missing_operands_propagate_null() {
    let fixture = Fixture::new();
    fixture.probe();
    let first = fixture.admit(0);
    fixture.finish(&first, Some(0));
    let second = fixture.admit(1);
    fixture.finish(&second, None);
    let report = report(&fixture.case.state).unwrap();
    assert_eq!(profile(&report, "upload")["state"], "credited");
    assert_eq!(
        profile(&report, "upload")["credited"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        profile(&report, "upload")["dimensions"]["incarnations"]["state"],
        "unsupported"
    );
    assert_eq!(
        report["totals"]["metrics"]["cpu_us"],
        json!({"value": null, "measurement": "unmeasured", "reason": "an operand is absent"})
    );
    assert_eq!(report["totals"]["metrics"]["memory_bytes"]["value"], 0);
    assert_eq!(
        report["totals"]["metrics"]["memory_bytes"]["measurement"],
        "measured"
    );
    assert_eq!(report["totals"]["metrics"]["pids"]["value"], 2);
    assert_eq!(report["totals"]["metrics"]["pids"]["source"]["attempt"], 1);
    assert!(
        [first.job().id().to_string(), second.job().id().to_string()]
            .iter()
            .any(|id| report["totals"]["metrics"]["pids"]["source"]["job"] == *id)
    );
    assert_eq!(report["totals"]["metrics"]["virtual_us"]["value"], 1200);
    assert_eq!(
        report["totals"]["metrics"]["wall_us"]["measurement"],
        "unmeasured"
    );
    assert_eq!(profile(&report, "upload")["qualified"], false);
    for (key, expected) in [("owners", 1), ("clients", 2)] {
        assert_eq!(
            profile(&report, "upload")["dimensions"][key]["measurement"]["aggregation"],
            "maximum"
        );
        assert_eq!(
            profile(&report, "upload")["dimensions"][key]["measurement"]["value"],
            expected
        );
        assert_eq!(
            profile(&report, "upload")["dimensions"][key]["measurement"]["sources"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }
}

#[test]
fn changed_bound_evidence_holds_stored_pass_and_grants_no_credit() {
    let fixture = Fixture::new();
    fixture.probe();
    let job = fixture.admit(0);
    let directory = fixture.finish(&job, Some(3));
    let artifacts = fixture
        .store
        .open_dir(&directory, &name("artifacts"))
        .unwrap()
        .unwrap();
    let artifact = fixture
        .store
        .open_dir(&artifacts, &name(&format!("{}-0001", job.job().id())))
        .unwrap()
        .unwrap();
    fixture
        .store
        .replace(&artifact, &name("bundle"), b"changed")
        .unwrap();
    let before = snapshot(&fixture.case.state);
    let report = report(&fixture.case.state).unwrap();
    assert_eq!(profile(&report, "upload")["state"], "inconclusive");
    assert!(
        profile(&report, "upload")["credited"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        report["held"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["reason"].as_str().unwrap().contains("bound evidence"))
    );
    assert_eq!(report["totals"]["metrics"]["cpu_us"]["value"], Value::Null);
    assert_eq!(snapshot(&fixture.case.state), before);
}

#[test]
fn report_preserves_store_bytes_tree_hash_metadata_and_orphan_staging() {
    use std::os::unix::fs::MetadataExt;
    let fixture = Fixture::new();
    fixture.probe();
    let job = fixture.admit(0);
    fixture.finish(&job, Some(0));
    let orphan = fixture.case.state.join(".staging").join("orphan");
    std::fs::write(orphan, b"orphan").unwrap();
    let before = snapshot(&fixture.case.state);
    let hash =
        |snapshot: &crate::store::fixture::Snapshot| Digest::of(format!("{snapshot:?}").as_bytes());
    let metadata = |snapshot: &crate::store::fixture::Snapshot| {
        snapshot
            .keys()
            .map(|path| {
                let metadata = std::fs::symlink_metadata(fixture.case.state.join(path)).unwrap();
                (
                    path.clone(),
                    (
                        metadata.ino(),
                        metadata.len(),
                        metadata.mtime(),
                        metadata.mtime_nsec(),
                        metadata.ctime(),
                        metadata.ctime_nsec(),
                    ),
                )
            })
            .collect::<BTreeMap<_, _>>()
    };
    let metadata_before = metadata(&before);
    report(&fixture.case.state).unwrap();
    let after = snapshot(&fixture.case.state);
    assert_eq!(hash(&after), hash(&before));
    assert_eq!(after, before);
    assert_eq!(metadata(&after), metadata_before);
}

#[test]
fn view_barrier_failure_holds_record_and_preserves_tree() {
    let fixture = Fixture::new();
    let mut ids = [fixture.admit(0), fixture.admit(1)].map(|job| job.job().id().to_string());
    ids.sort();
    let [failed, healthy] = ids;
    let before = snapshot(&fixture.case.state);
    let view = crate::store::View::open(&fixture.case.state).unwrap();
    let (_, reached) = scripted([], || super::projection::project(&view).unwrap());
    let sync = reached.iter().position(|step| *step == Step::Sync).unwrap();
    let (result, _) = scripted([(sync, Outcome::Errno(libc::EIO))], || {
        super::projection::project(&view)
    });
    let report = result.unwrap().unwrap();
    let held = report["held"].as_array().unwrap();
    assert_eq!(held.len(), 1, "{held:?}");
    assert!(held.iter().any(|row| {
        row["path"] == format!("jobs/{failed}")
            && row["held_code"] == "store"
            && row["reason"]
                .as_str()
                .unwrap()
                .contains("Input/output error")
    }));
    assert!(
        report["release_blockers"]
            .as_array()
            .unwrap()
            .contains(&json!(
                crate::layout::job_file(&failed, &format!("{failed}.json"))
                    .to_str()
                    .unwrap()
            ))
    );
    assert!(
        report["jobs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == healthy && row["state"] != "held")
    );
    let jobs = view.shard_jobs(&failed).unwrap().unwrap();
    let failed = view
        .read(&jobs, &name(&format!("{failed}.json")), BOUND)
        .unwrap()
        .unwrap();
    let healthy = view
        .read(
            &view.shard_jobs(&healthy).unwrap().unwrap(),
            &name(&format!("{healthy}.json")),
            BOUND,
        )
        .unwrap()
        .unwrap();
    let (_, repeated) = scripted([], || {
        assert!(view.barrier(&failed).is_err());
        view.barrier(&healthy).unwrap();
    });
    assert_eq!(
        repeated.iter().filter(|step| **step == Step::Sync).count(),
        2
    );
    assert_eq!(snapshot(&fixture.case.state), before);
}

#[test]
fn missing_marker_refuses_without_creating_state_and_totals_preserve_zero() {
    let fixture = Fixture::new();
    let missing = fixture.case.state.join("missing");
    assert!(report(&missing).is_err());
    assert!(!missing.exists());
    assert_eq!(
        super::coverage::total("fixture", &[Some(0), Some(0)]).unwrap(),
        json!({"value": 0, "measurement": "measured", "reason": null})
    );
    assert_eq!(
        super::coverage::total("fixture", &[Some(3), None]).unwrap(),
        json!({"value": null, "measurement": "unmeasured", "reason": "an operand is absent"})
    );
    assert!(super::coverage::total("fixture", &[Some(u64::MAX), Some(1)]).is_err());
    assert_eq!(
        super::coverage::total("fixture", &[]).unwrap()["measurement"],
        "unmeasured"
    );
    std::fs::remove_file(fixture.case.state.join(".state")).unwrap();
    let before = snapshot(&fixture.case.state);
    assert!(report(&fixture.case.state).is_err());
    assert_eq!(snapshot(&fixture.case.state), before);
}

#[test]
fn missing_minimum_witness_is_inconclusive_and_declared_exclusions_are_unsupported() {
    use super::coverage::{Coverage, Declaration};
    let fixture = Fixture::new();
    let job = fixture.admit(0);
    let mut row = Coverage::new(Declaration {
        build: Digest::of(b"build"),
        class: Some(text("live")),
        counts: Some(BTreeMap::new()),
        generator: Some(text("1")),
        minima: Some(text("published:4,faults:2,cross:0")),
        profile: text("cluster-broad"),
        support: "implemented".into(),
        declared: true,
        unsupported_dimensions: ["membership".into()].into(),
    })
    .unwrap();
    let unrun = Coverage::new(row.declaration.clone())
        .unwrap()
        .row()
        .unwrap();
    assert_eq!(unrun["dimensions"]["reached.cross"]["state"], "unrun");
    let mut absent = Coverage::new(row.declaration.clone()).unwrap();
    absent.ran = true;
    absent.credit(job.job().id().to_string(), 1, None);
    let absent = absent.row().unwrap();
    assert_eq!(
        absent["dimensions"]["reached.cross"]["state"],
        "inconclusive"
    );
    assert_eq!(
        absent["dimensions"]["reached.cross"]["measurement"]["value"],
        Value::Null
    );
    row.ran = true;
    let mut summary = crate::protocol::Summary::parse(
        include_str!("../../../testdata/counting.summary"),
        &fixture.listing,
    )
    .unwrap();
    summary.cluster = Some(crate::protocol::Cluster {
        unavailable: "membership".into(),
        drawn: Some(crate::protocol::Drawn {
            topology: crate::protocol::Topology {
                owners: 2,
                keys: 3,
                hot: 0,
            },
            coverage: [4, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        }),
    });
    row.credit(job.job().id().to_string(), 1, Some(&summary));
    let row = row.row().unwrap();
    assert_eq!(row["dimensions"]["reached.published"]["state"], "credited");
    assert_eq!(row["dimensions"]["reached.faults"]["state"], "inconclusive");
    assert_eq!(row["dimensions"]["reached.cross"]["state"], "credited");
    assert_eq!(row["dimensions"]["reached.cross"]["required"], 0);
    assert_eq!(
        row["dimensions"]["reached.cross"]["measurement"]["value"],
        0
    );
    assert_eq!(row["dimensions"]["membership"]["state"], "unsupported");
    assert_eq!(
        row["dimensions"]["membership"]["measurement"]["value"],
        Value::Null
    );
    assert!(
        row["dimensions"]
            .as_object()
            .unwrap()
            .values()
            .all(
                |dimension| ["credited", "unsupported", "unrun", "inconclusive"]
                    .contains(&dimension["state"].as_str().unwrap())
            )
    );
    fixture.probe();
    let report = report(&fixture.case.state).unwrap();
    let cluster = report["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["declaration"]["profile"] == "cluster-broad")
        .unwrap();
    assert_eq!(cluster["state"], "unrun");
    assert_eq!(cluster["dimensions"]["membership"]["state"], "unsupported");
    assert_eq!(
        cluster["dimensions"]["node-lifecycle"]["state"],
        "unsupported"
    );
}

#[test]
fn damaged_publication_makes_its_operands_missing_beside_a_measured_job() {
    let fixture = Fixture::new();
    fixture.probe();
    let first = fixture.admit(0);
    fixture.finish(&first, Some(7));
    let second = fixture.admit(1);
    fixture.finish(&second, Some(11));
    let jobs = fixture
        .store
        .shard_jobs(second.job().id())
        .unwrap()
        .unwrap();
    fixture
        .store
        .replace(
            &jobs,
            &name(&format!("{}.result.json", second.job().id())),
            b"damaged",
        )
        .unwrap();
    let before = snapshot(&fixture.case.state);
    let report = report(&fixture.case.state).unwrap();
    assert_eq!(report["held"].as_array().unwrap().len(), 1);
    assert_eq!(
        profile(&report, "upload")["credited"].as_array().unwrap(),
        &vec![json!(first.job().id().to_string())]
    );
    for key in super::coverage::TOTALS {
        assert_eq!(report["totals"]["metrics"][key]["value"], Value::Null);
        assert_eq!(
            report["totals"]["metrics"][key]["measurement"],
            "unmeasured"
        );
    }
    assert_eq!(snapshot(&fixture.case.state), before);
}

#[test]
fn damaged_roots_records_and_orphan_histories_stay_held() {
    let fixture = Fixture::new();
    fixture.admit(0);
    fixture
        .store
        .create_once(fixture.store.root(), &name("capacity"), b"damaged")
        .unwrap();
    fixture
        .store
        .create_once(fixture.store.root(), &name("config.json"), b"damaged")
        .unwrap();
    fixture
        .store
        .create_once(fixture.store.root(), &name("unknown"), b"damaged")
        .unwrap();
    let attempts =
        crate::layout::make_shard(&fixture.store, crate::layout::ATTEMPTS, &"a".repeat(64))
            .unwrap();
    fixture
        .store
        .mkdir(&attempts, &name(&"a".repeat(64)))
        .unwrap();
    fixture
        .store
        .mkdir(fixture.store.root(), &name("findings"))
        .unwrap();
    let findings = fixture
        .store
        .open_dir(fixture.store.root(), &name("findings"))
        .unwrap()
        .unwrap();
    fixture.store.mkdir(&findings, &name("damaged")).unwrap();
    let finding = fixture
        .store
        .open_dir(&findings, &name("damaged"))
        .unwrap()
        .unwrap();
    fixture
        .store
        .create_once(&finding, &name("finding.json"), b"damaged")
        .unwrap();
    let before = snapshot(&fixture.case.state);
    let report = report(&fixture.case.state).unwrap();
    let held = report["held"].as_array().unwrap();
    assert_eq!(held.len(), 5, "{report}");
    for path in ["capacity", "config.json", "unknown", "findings/damaged"] {
        assert!(held.iter().any(|row| row["path"] == path));
    }
    assert!(
        held.iter()
            .all(|row| !row["reason"].as_str().unwrap().is_empty())
    );
    assert_eq!(report["release_blockers"], json!(["damaged"]));
    assert_eq!(snapshot(&fixture.case.state), before);
}

#[test]
fn calibrated_pass_fields_without_bound_attempts_remain_explicitly_unqualified() {
    let fixture = Fixture::new();
    let job = fixture.admit(0);
    let config = crate::campaign::calibration::tests::config();
    let capacity = crate::campaign::calibration::tests::stored_capacity(
        &fixture.store,
        job.clone(),
        config,
        1,
    );
    fixture
        .store
        .mkdir(fixture.store.root(), &name("capacity"))
        .unwrap();
    let root = fixture
        .store
        .open_dir(fixture.store.root(), &name("capacity"))
        .unwrap()
        .unwrap();
    fixture
        .store
        .mkdir(&root, &name(&capacity.contract().key().to_string()))
        .unwrap();
    let root = fixture
        .store
        .open_dir(&root, &name(&capacity.contract().key().to_string()))
        .unwrap()
        .unwrap();
    fixture
        .store
        .create_record(&root, &name(&capacity.root().to_string()), &capacity)
        .unwrap();
    assert!(crate::campaign::calibration::matches_capacity(
        &capacity,
        &crate::campaign::calibration::eligible(&fixture.store, capacity.contract()).unwrap()
    ));
    std::fs::remove_dir_all(
        fixture
            .case
            .state
            .join(crate::campaign::state_fixture::attempts_dir(
                job.job().id().to_string(),
            )),
    )
    .unwrap();
    assert!(
        !crate::campaign::calibration::eligible(&fixture.store, capacity.contract())
            .is_ok_and(|roots| crate::campaign::calibration::matches_capacity(&capacity, &roots)),
        "the eligibility reader must hold the calibration the report holds"
    );
    let before = snapshot(&fixture.case.state);
    let report = report(&fixture.case.state).unwrap();
    assert_eq!(profile(&report, "upload")["qualified"], false);
    assert!(report["unqualified"].as_array().unwrap().iter().any(|row| {
        row["jobs"]
            .as_array()
            .unwrap()
            .contains(&json!(job.job().id().to_string()))
    }));
    assert_eq!(report["calibrations"][0]["verdict"], "held");
    let held = report["held"].as_array().unwrap();
    assert!(
        held.iter()
            .any(|row| row["path"] == format!("calibrations/{}", capacity.root()))
    );
    assert!(
        held.iter().any(|row| row["path"]
            == format!("capacity/{}/{}", capacity.contract().key(), capacity.root()))
    );
    assert_eq!(snapshot(&fixture.case.state), before);
}

#[test]
fn malformed_probe_declarations_hold_their_rows_and_preserve_other_profiles() {
    for listing in [
        include_str!("../../../testdata/admission-listing.txt")
            .replace("minima=published:4", "minima=bad"),
        include_str!("../../../testdata/admission-listing.txt")
            .replace("profile: upload", "profile: futureé"),
    ] {
        let fixture = Fixture::new();
        fixture.probe_listing(listing.as_bytes());
        let before = snapshot(&fixture.case.state);
        let report = report(&fixture.case.state).unwrap();
        assert_eq!(report["held"].as_array().unwrap().len(), 1, "{report}");
        assert!(!report["profiles"].as_array().unwrap().is_empty());
        assert_eq!(snapshot(&fixture.case.state), before);
    }
}

#[test]
fn started_unfinished_attempt_is_inconclusive_and_intent_only_is_unrun() {
    for started in [false, true] {
        let fixture = Fixture::new();
        fixture.probe();
        let job = fixture.admit(0);
        let directory = fixture.finish(&job, Some(1));
        for entry in ["finished", "bound"] {
            fixture.store.delete(&directory, &name(entry)).unwrap();
        }
        if !started {
            fixture.store.delete(&directory, &name("started")).unwrap();
        }
        fixture
            .store
            .create_record(
                &directory,
                &name("reservation"),
                &crate::record::Reservation {
                    attempt: text(&format!("{}-0001", job.job().id())),
                },
            )
            .unwrap();
        let jobs = fixture.store.shard_jobs(job.job().id()).unwrap().unwrap();
        fixture
            .store
            .delete(&jobs, &name(&format!("{}.result.json", job.job().id())))
            .unwrap();
        let before = snapshot(&fixture.case.state);
        let report = report(&fixture.case.state).unwrap();
        assert_eq!(
            profile(&report, "upload")["state"],
            if started { "inconclusive" } else { "unrun" }
        );
        assert_eq!(report["jobs"][0]["attempts"][0]["state"], "inconclusive");
        assert_eq!(report["jobs"][0]["state"], "inconclusive", "{report}");
        assert_eq!(report["jobs"][0]["reason"], "job is unpublished");
        assert_eq!(snapshot(&fixture.case.state), before);
    }
}

#[test]
fn uncaptured_held_and_harness_disposed_findings_withhold_passing_retry_credit() {
    for damage in ["captured", "uncaptured", "held", "harness"] {
        let fixture = Fixture::new();
        fixture.probe();
        let job = fixture.admit(0);
        fixture.finish_at(&job, 1, Some(1), Class::Watchdog);
        fixture.finish_at(&job, 2, Some(2), Class::Pass);
        let id = format!("{}-0001", job.job().id());
        let root = fixture
            .store
            .open_dir(fixture.store.root(), &name("findings"))
            .unwrap()
            .unwrap();
        let directory = fixture.store.open_dir(&root, &name(&id)).unwrap().unwrap();
        match damage {
            "captured" => {}
            "uncaptured" => {
                std::fs::remove_dir_all(fixture.case.state.join("findings").join(&id)).unwrap();
            }
            "held" => {
                fixture
                    .store
                    .replace(&directory, &name("finding.json"), b"damaged")
                    .unwrap();
            }
            "harness" => {
                fixture
                    .store
                    .create_record(
                        &directory,
                        &name("0001.disposition.json"),
                        &crate::record::Disposition::new(
                            text(&id),
                            1,
                            crate::record::Decision::Harness,
                            text("harness evidence"),
                        )
                        .unwrap(),
                    )
                    .unwrap();
            }
            _ => unreachable!(),
        }
        let before = snapshot(&fixture.case.state);
        let report = report(&fixture.case.state).unwrap();
        if damage == "captured" {
            assert_eq!(
                profile(&report, "upload")["credited"],
                json!([job.job().id().to_string()])
            );
            assert_eq!(report["jobs"][0]["reason"], "bound passing outcome");
        } else {
            assert!(
                profile(&report, "upload")["credited"]
                    .as_array()
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(
                report["jobs"][0]["reason"],
                if damage == "uncaptured" {
                    "failure capture is incomplete"
                } else {
                    "finding history withholds credit"
                }
            );
        }
        if damage == "uncaptured" {
            assert!(
                report["release_blockers"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|row| row == &id)
            );
        }
        if damage == "held" {
            assert!(!report["held"].as_array().unwrap().is_empty());
        } else {
            assert!(report["held"].as_array().unwrap().is_empty(), "{report}");
        }
        if damage == "harness" {
            assert_eq!(
                report["findings"][0]["dispositions"][0]["decision"],
                "harness"
            );
        }
        assert_eq!(snapshot(&fixture.case.state), before);
    }
}

#[test]
fn every_view_barrier_failure_holds_its_evidence_and_preserves_the_tree() {
    let fixture = Fixture::new();
    fixture.probe();
    let job = fixture.admit(0);
    fixture.finish_at(&job, 1, Some(1), Class::Watchdog);
    fixture.finish_at(&job, 2, Some(2), Class::Pass);
    let before = snapshot(&fixture.case.state);
    let (baseline, reached) = scripted([], || report(&fixture.case.state).unwrap());
    assert!(baseline.unwrap()["held"].as_array().unwrap().is_empty());
    let syncs: Vec<_> = reached
        .iter()
        .enumerate()
        .filter_map(|(index, step)| (*step == Step::Sync).then_some(index))
        .collect();
    assert!(syncs.len() > 10);
    for index in &syncs {
        let (result, reached) = scripted([(*index, Outcome::Errno(libc::EIO))], || {
            report(&fixture.case.state)
        });
        assert_eq!(reached[*index], Step::Sync);
        let report = result.unwrap().unwrap();
        assert!(
            !report["held"].as_array().unwrap().is_empty(),
            "barrier {index}"
        );
        if report["held"].as_array().unwrap().iter().any(|row| {
            row["path"]
                .as_str()
                .is_some_and(|path| path.starts_with("jobs/"))
        }) {
            assert!(
                report["profiles"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|row| { row["declaration"]["profile"] == "upload" })
                    .all(|row| row["credited"].as_array().unwrap().is_empty()),
                "barrier {index}"
            );
        }
        assert_eq!(snapshot(&fixture.case.state), before, "barrier {index}");
    }
    println!(
        "report durability witness: {} fsync indices injected",
        syncs.len()
    );
}

#[test]
fn resource_marks_choose_one_peak_source_and_missing_operands_preserve_null() {
    use super::measurement::{MeasuredAttempt, totals};
    let sample = |job: &[u8], attempt, memory, pids| {
        Some(MeasuredAttempt {
            job: Digest::of(job),
            attempt,
            virtual_us: Some(0),
            skipped_us: Some(0),
            resources: crate::record::ResourceBounds {
                cpu_us: Some(0),
                wall_us: Some(0),
                memory_bytes: memory,
                pids,
            },
        })
    };
    let samples = [
        sample(b"first", 1, Some(600), Some(2)),
        sample(b"second", 2, Some(600), Some(3)),
    ];
    let measured = totals(&samples).unwrap();
    assert_eq!(measured["memory_bytes"]["value"], 600);
    assert_eq!(
        measured["memory_bytes"]["source"],
        json!({"job": Digest::of(b"first"), "attempt": 1})
    );
    let reversed = totals(&[
        sample(b"first", 1, Some(600), Some(3)),
        sample(b"second", 2, Some(500), Some(2)),
    ])
    .unwrap();
    assert_eq!(reversed["pids"]["value"], 3);
    assert_eq!(
        reversed["pids"]["source"],
        json!({"job": Digest::of(b"first"), "attempt": 1})
    );
    assert_eq!(measured["pids"]["value"], 3);
    assert_eq!(
        measured["pids"]["source"],
        json!({"job": Digest::of(b"second"), "attempt": 2})
    );
    let partial = totals(&[
        sample(b"first", 1, Some(600), Some(2)),
        sample(b"second", 2, None, None),
    ])
    .unwrap();
    for key in ["memory_bytes", "pids"] {
        assert_eq!(partial[key]["value"], Value::Null);
        assert_eq!(partial[key]["measurement"], "unmeasured");
        assert_eq!(partial[key]["source"], Value::Null);
    }
    assert_eq!(partial["cpu_us"]["value"], 0);
}

#[test]
fn declared_control_and_planned_profiles_are_explicitly_unsupported() {
    let fixture = Fixture::new();
    let listing = format!(
        "{}profile: control class=control support=implemented campaign=unqualified held=bytes=1,every=1,pending=1,records=1,ring=1,turns=1\nprofile: planned class=live support=planned campaign=unqualified held=bytes=1,every=1,pending=1,records=1,ring=1,turns=1\n",
        include_str!("../../../testdata/admission-listing.txt")
    );
    fixture.probe_listing(listing.as_bytes());
    let report = report(&fixture.case.state).unwrap();
    for name in ["control", "planned"] {
        let row = report["profiles"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["declaration"]["profile"] == name)
            .unwrap();
        assert_eq!(row["state"], "unsupported");
        assert!(!row["dimensions"].as_object().unwrap().is_empty());
        assert!(
            row["dimensions"]
                .as_object()
                .unwrap()
                .values()
                .all(|dim| dim["state"] == "unsupported"
                    && !dim["reason"].as_str().unwrap().is_empty())
        );
    }
}

#[test]
fn locked_report_preserves_tree_and_lexical_state_paths_share_the_canonical_form() {
    let fixture = Fixture::new();
    fixture.probe();
    let job = fixture.admit(0);
    fixture.finish(&job, Some(3));
    assert!(matches!(
        super::report(&fixture.case.state),
        Err(crate::campaign::Error::Store(crate::store::Error::Busy))
    ));
    let Fixture { case, store, .. } = fixture;
    drop(store);
    let reader = crate::store::View::snapshot(&case.state).unwrap();
    assert_eq!(
        profile(&super::report(&case.state).unwrap(), "upload")["state"],
        "credited",
        "a second report runs beside a held snapshot"
    );
    assert!(matches!(
        Store::open(&case.state),
        Err(crate::store::Error::Busy)
    ));
    drop(reader);
    std::fs::create_dir(case.root.join("alias-parent")).unwrap();
    let lexical = case.root.join("alias-parent/../state");
    let store = Store::open(&lexical).unwrap();
    assert_eq!(store.path(), case.state.canonicalize().unwrap());
    drop(store);
    std::fs::write(case.state.join(".staging/orphan"), b"orphan").unwrap();
    let before = snapshot(&case.state);
    let hash = Digest::of(format!("{before:?}").as_bytes());
    let projection = super::report(&lexical).unwrap();
    assert_eq!(profile(&projection, "upload")["state"], "credited");
    let after = snapshot(&case.state);
    assert_eq!(Digest::of(format!("{after:?}").as_bytes()), hash);
    assert_eq!(after, before);
}

#[test]
fn empty_population_is_unmeasured_and_an_unpublished_retry_adds_no_operand() {
    let fixture = Fixture::new();
    fixture.probe();
    let job = fixture.admit(0);
    let empty = report(&fixture.case.state).unwrap();
    assert_eq!(empty["totals"]["metrics"]["cpu_us"]["value"], Value::Null);
    assert_eq!(
        empty["totals"]["metrics"]["cpu_us"]["reason"],
        "no published attempts"
    );
    fixture.finish_at(&job, 1, None, Class::Watchdog);
    fixture.finish_at(&job, 2, Some(5), Class::Pass);
    let measured = report(&fixture.case.state).unwrap();
    assert_eq!(
        measured["totals"]["population"],
        "each published job selected attempt"
    );
    assert_eq!(measured["totals"]["metrics"]["cpu_us"]["value"], 5);
    assert_eq!(
        measured["totals"]["metrics"]["cpu_us"]["measurement"],
        "measured"
    );
    assert_eq!(measured["jobs"][0]["result"]["attempt"], 2);
    fixture
        .store
        .mkdir(fixture.store.root(), &name("calibrations"))
        .unwrap();
    let root = fixture
        .store
        .open_dir(fixture.store.root(), &name("calibrations"))
        .unwrap()
        .unwrap();
    fixture.store.mkdir(&root, &name(&"a".repeat(64))).unwrap();
    let projection = report(&fixture.case.state).unwrap();
    assert_eq!(
        projection["calibrations"],
        json!([{"id": "a".repeat(64), "qualified": false, "verdict": "uncalibrated", "reason": "calibration plan is missing"}])
    );
    assert!(projection["held"].as_array().unwrap().is_empty());
}

#[test]
fn foreign_and_oversized_job_names_are_held_without_panicking() {
    let fixture = Fixture::new();
    fixture.probe();
    fixture
        .store
        .mkdir(fixture.store.root(), &name("jobs"))
        .unwrap();
    let oversized = format!("aa{}", "x".repeat(118));
    let jobs = fixture.store.shard_jobs(&oversized).unwrap().unwrap();
    for entry in [format!("{oversized}.json"), "aaunexpected".into()] {
        fixture
            .store
            .create_once(&jobs, &name(&entry), b"damaged")
            .unwrap();
        let report = report(&fixture.case.state).unwrap();
        assert!(
            report["held"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["path"] == format!("jobs/aa/{entry}"))
        );
        assert_eq!(report["totals"]["population_completeness"], "unknown");
    }
}

#[test]
fn selected_resource_wall_time_is_measured_and_changed_kernel_counters_are_held() {
    let fixture = Fixture::new();
    fixture.probe();
    let job = fixture.admit(0);
    let directory = fixture.finish(&job, Some(7));
    let resources = crate::record::ResourceBounds {
        cpu_us: Some(7),
        memory_bytes: Some(0),
        pids: Some(2),
        wall_us: Some(19),
    };
    fixture
        .store
        .create_record(&directory, &name("resources"), &resources)
        .unwrap();
    let measured = report(&fixture.case.state).unwrap();
    assert_eq!(measured["totals"]["metrics"]["wall_us"]["value"], 19);
    let mut changed = resources;
    changed.cpu_us = Some(8);
    fixture
        .store
        .replace_record(&directory, &name("resources"), &changed)
        .unwrap();
    let held = report(&fixture.case.state).unwrap();
    assert_eq!(held["jobs"][0]["state"], "held");
    assert!(held["totals"]["metrics"]["wall_us"]["value"].is_null());
}

#[test]
fn summary_stream_digest_is_checked_at_use() {
    let fixture = Fixture::new();
    let job = fixture.admit(0);
    let directory = fixture.finish(&job, Some(1));
    let record = fixture
        .store
        .read_record::<Attempt>(&directory, &name("attempt"))
        .unwrap()
        .unwrap();
    let completed =
        crate::attempt::read_completed(&fixture.store, &directory, record.record(), "run").unwrap();
    let artifacts = fixture
        .store
        .open_dir(&directory, &name("artifacts"))
        .unwrap()
        .unwrap();
    let artifacts = fixture
        .store
        .open_dir(&artifacts, &name(record.record().attempt.as_str()))
        .unwrap()
        .unwrap();
    fixture
        .store
        .replace(&artifacts, &name("inspect.stdout"), b"changed")
        .unwrap();
    let view = crate::store::View::open(&fixture.case.state).unwrap();
    assert!(super::projection::stream(&view, &directory, &completed, "inspect").is_err());
}

#[test]
fn barrier_failure_remains_held_when_the_same_inode_is_read_again() {
    for failed_sync in [0, 1] {
        let fixture = Fixture::new();
        fixture
            .store
            .create_once(fixture.store.root(), &name("record"), b"evidence")
            .unwrap();
        let view = crate::store::View::open(&fixture.case.state).unwrap();
        let read = view
            .read(view.root(), &name("record"), BOUND)
            .unwrap()
            .unwrap();
        let (_, steps) = scripted([], || view.barrier(&read));
        let index = steps
            .iter()
            .enumerate()
            .filter(|(_, step)| **step == Step::Sync)
            .nth(failed_sync)
            .unwrap()
            .0;
        let (failed, _) = scripted([(index, Outcome::Errno(libc::EIO))], || view.barrier(&read));
        assert!(failed.unwrap().is_err());
        let reread = view
            .read(view.root(), &name("record"), BOUND)
            .unwrap()
            .unwrap();
        assert!(view.barrier(&reread).is_err());
    }
}

#[test]
fn missing_capability_declaration_is_inconclusive_and_withholds_qualification() {
    let fixture = Fixture::new();
    let job = fixture.admit(0);
    fixture.finish(&job, Some(1));
    let report = report(&fixture.case.state).unwrap();
    assert_eq!(report["jobs"][0]["state"], "inconclusive");
    assert_eq!(profile(&report, "upload")["state"], "inconclusive");
    assert_eq!(
        profile(&report, "upload")["declaration"]["support"],
        "unknown"
    );
    assert_eq!(profile(&report, "upload")["qualified"], false);
    assert!(
        profile(&report, "upload")["credited"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn held_population_keeps_profile_attribution_unknown_and_listed_profiles_unrun() {
    for corrupt_root in [false, true] {
        let fixture = Fixture::new();
        fixture.probe();
        let job = fixture.admit(0);
        let jobs = fixture.store.shard_jobs(job.job().id()).unwrap().unwrap();
        if corrupt_root {
            std::fs::remove_dir_all(fixture.case.state.join("jobs")).unwrap();
            fixture
                .store
                .create_once(fixture.store.root(), &name("jobs"), b"damaged")
                .unwrap();
        } else {
            fixture
                .store
                .replace(
                    &jobs,
                    &name(&format!("{}.json", job.job().id())),
                    b"damaged",
                )
                .unwrap();
        }
        let report = report(&fixture.case.state).unwrap();
        assert_eq!(report["totals"]["population_completeness"], "unknown");
        let listed = report["profiles"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["declaration"]["profile"] == "upload")
            .unwrap();
        assert_eq!(listed["state"], "unrun");
        assert!(!report["held"].as_array().unwrap().is_empty());
    }
}

#[test]
fn negative_history_profile_is_listed_as_unrun_when_its_support_is_implemented() {
    let fixture = Fixture::new();
    fixture.probe_listing(include_bytes!("../../../testdata/listing.txt"));
    let report = report(&fixture.case.state).unwrap();
    let listed = report["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["declaration"]["profile"] == "h1-get-unheld")
        .unwrap();
    assert_eq!(listed["state"], "unrun");
    for key in ["operations", "witnesses"] {
        assert_eq!(listed["dimensions"][key]["state"], "unsupported");
    }
}

#[test]
fn long_retry_history_reports_under_a_small_descriptor_limit() {
    const CHILD: &str = "KESTRIKE_REPORT_FD_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let _processes = crate::store::fixture::processes();
        let output = std::process::Command::new("bash").args(["-c", "ulimit -n 80 && exec \"$@\"", "bash"])
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", "campaign::report::tests::long_retry_history_reports_under_a_small_descriptor_limit", "--nocapture"])
            .env(CHILD, "1").env("RUST_TEST_THREADS", "1").output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains("test result: ok. 1 passed;"), "{stdout}");
        return;
    }
    let fixture = Fixture::new();
    fixture.probe();
    let job = fixture.admit_n(0, 41);
    for number in 1..=40 {
        fixture.finish_at(&job, number, Some(1), Class::Watchdog);
    }
    fixture.finish_at(&job, 41, Some(2), Class::Pass);
    let report = report(&fixture.case.state).unwrap();
    assert_eq!(report["jobs"][0]["attempts"].as_array().unwrap().len(), 41);
    assert_eq!(profile(&report, "upload")["state"], "credited");
    assert!(report["held"].as_array().unwrap().is_empty(), "{report}");
}

#[test]
fn plan_only_roots_remain_visible_and_damaged_replays_hold_them() {
    let fixture = Fixture::new();
    let job = fixture.admit(0);
    let id = job.job().id().to_string();
    fixture
        .store
        .mkdir(fixture.store.root(), &name("calibrations"))
        .unwrap();
    let roots = fixture
        .store
        .open_dir(fixture.store.root(), &name("calibrations"))
        .unwrap()
        .unwrap();
    fixture.store.mkdir(&roots, &name(&id)).unwrap();
    let root = fixture.store.open_dir(&roots, &name(&id)).unwrap().unwrap();
    let plan = crate::record::CalibrationPlan {
        config: crate::campaign::calibration::tests::config(),
        controls: BTreeMap::new(),
        deduplicated: true,
        healthy: job,
        missing: Vec::new(),
    };
    fixture
        .store
        .create_record(&root, &name("plan"), &plan)
        .unwrap();
    let projected = report(&fixture.case.state).unwrap();
    let view = crate::store::View::open(&fixture.case.state).unwrap();
    let status = crate::campaign::calibration::status(&view).unwrap();
    assert_eq!(
        projected["calibrations"][0]["verdict"],
        status[0]["verdict"]
    );
    assert_eq!(projected["calibrations"][0]["verdict"], "unsealed");
    assert_eq!(projected["calibrations"][0]["qualified"], false);
    fixture.store.mkdir(&root, &name("replays")).unwrap();
    let replays = fixture
        .store
        .open_dir(&root, &name("replays"))
        .unwrap()
        .unwrap();
    fixture.store.mkdir(&replays, &name("0001")).unwrap();
    let replay = fixture
        .store
        .open_dir(&replays, &name("0001"))
        .unwrap()
        .unwrap();
    fixture
        .store
        .create_once(&replay, &name("replay"), b"damaged")
        .unwrap();
    let before = snapshot(&fixture.case.state);
    let projected = report(&fixture.case.state).unwrap();
    assert_eq!(projected["calibrations"][0]["verdict"], "held");
    assert!(
        projected["held"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["path"] == format!("calibrations/{id}"))
    );
    assert_eq!(snapshot(&fixture.case.state), before);
}

#[test]
fn retained_planless_and_unopenable_calibration_roots_are_held() {
    let fixture = Fixture::new();
    fixture.admit(0);
    fixture
        .store
        .mkdir(fixture.store.root(), &name("calibrations"))
        .unwrap();
    let roots = fixture
        .store
        .open_dir(fixture.store.root(), &name("calibrations"))
        .unwrap()
        .unwrap();
    let retained = Digest::of(b"retained planless root").to_string();
    fixture.store.mkdir(&roots, &name(&retained)).unwrap();
    let root = fixture
        .store
        .open_dir(&roots, &name(&retained))
        .unwrap()
        .unwrap();
    fixture
        .store
        .create_once(&root, &name("result"), b"retained")
        .unwrap();
    let unopenable = Digest::of(b"unopenable root").to_string();
    fixture
        .store
        .create_once(&roots, &name(&unopenable), b"damaged")
        .unwrap();
    let before = snapshot(&fixture.case.state);
    let projected = report(&fixture.case.state).unwrap();
    let view = crate::store::View::open(&fixture.case.state).unwrap();
    let status = crate::campaign::calibration::status(&view).unwrap();
    for id in [&retained, &unopenable] {
        let row = projected["calibrations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["id"] == *id)
            .unwrap();
        let shown = status.iter().find(|row| row["id"] == *id).unwrap();
        assert_eq!(row["verdict"], shown["verdict"]);
        assert_eq!(row["verdict"], "held");
        assert_eq!(row["qualified"], false);
        assert!(
            projected["held"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| { row["path"] == format!("calibrations/{id}") })
        );
    }
    let findings = crate::campaign::findings::findings(&fixture.case.state).unwrap();
    let path = format!("calibrations/{unopenable}");
    assert!(
        findings["release_blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|id| id == &path)
    );
    assert!(
        findings["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| { row["id"] == path && row["blocker"] == true && row["held"].is_string() })
    );
    assert_eq!(snapshot(&fixture.case.state), before);
}

#[test]
fn damaged_unfinished_intent_and_reservation_are_held() {
    for entry in ["intent", "reservation"] {
        let fixture = Fixture::new();
        fixture.probe();
        let job = fixture.admit(0);
        let directory = fixture.finish(&job, Some(1));
        for remove in ["finished", "bound", "started"] {
            fixture.store.delete(&directory, &name(remove)).unwrap();
        }
        fixture
            .store
            .replace(&directory, &name(entry), b"damaged")
            .unwrap();
        let projected = report(&fixture.case.state).unwrap();
        assert_eq!(projected["jobs"][0]["state"], "held");
        assert_eq!(projected["totals"]["population_completeness"], "unknown");
    }
}

#[test]
fn damaged_capture_marker_holds_published_credit() {
    let fixture = Fixture::new();
    fixture.probe();
    let job = fixture.admit(0);
    let directory = fixture.finish(&job, Some(1));
    fixture
        .store
        .replace(&directory, &name("captured"), b"damaged")
        .unwrap();
    let projected = report(&fixture.case.state).unwrap();
    assert_eq!(projected["jobs"][0]["state"], "held");
    assert!(
        profile(&projected, "upload")["credited"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn mismatched_pin_and_result_hold_selected_attempt_measurements() {
    for entry in [crate::record::JobResult::SUFFIX, crate::record::Pin::SUFFIX] {
        let fixture = Fixture::new();
        fixture.probe();
        let job = fixture.admit(0);
        let directory = fixture.finish(&job, Some(1));
        let finished = fixture
            .store
            .read_record::<Finished>(&directory, &name("finished"))
            .unwrap()
            .unwrap();
        let jobs = fixture.store.shard_jobs(job.job().id()).unwrap().unwrap();
        let mut result = crate::record::JobResult {
            attempt: 1,
            finished: finished.record().clone(),
            job: job.job().id().digest(),
            manifest: job.job().manifest_sha256(),
        };
        result.finished.kernel.cpu.insert(text("usage_usec"), 99);
        if entry == crate::record::JobResult::SUFFIX {
            fixture
                .store
                .replace_record(&jobs, &name(&format!("{}{entry}", job.job().id())), &result)
                .unwrap();
        } else {
            fixture
                .store
                .create_record(
                    &jobs,
                    &name(&format!("{}{entry}", job.job().id())),
                    &crate::record::Pin { result },
                )
                .unwrap();
        }
        let projected = report(&fixture.case.state).unwrap();
        assert_eq!(projected["jobs"][0]["state"], "held");
        assert!(projected["totals"]["metrics"]["cpu_us"]["value"].is_null());
        assert!(
            profile(&projected, "upload")["credited"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }
}

#[test]
fn published_nonpass_outcomes_measure_resources_and_withhold_credit() {
    let fixture = Fixture::new();
    fixture.probe();
    let job = fixture.admit_n(0, 1);
    fixture.finish_at(&job, 1, Some(7), Class::Watchdog);
    let projected = report(&fixture.case.state).unwrap();
    assert_eq!(
        projected["jobs"][0]["result"]["finished"]["class"],
        "watchdog"
    );
    assert_eq!(projected["totals"]["metrics"]["cpu_us"]["value"], 7);
    assert_eq!(projected["totals"]["metrics"]["pids"]["value"], 2);
    assert_eq!(profile(&projected, "upload")["state"], "inconclusive");
}

#[test]
fn zero_work_measurements_and_malformed_frozen_minima_withhold_dimension_credit() {
    let fixture = Fixture::new();
    fixture.probe();
    let job = fixture.admit(0);
    fixture.finish(&job, Some(1));
    let projected = report(&fixture.case.state).unwrap();
    let declaration: super::coverage::Declaration = super::coverage::Declaration {
        build: Digest::parse(&"b".repeat(64)).unwrap(),
        class: Some(text("live")),
        counts: Some(BTreeMap::new()),
        generator: None,
        minima: None,
        profile: text("upload"),
        support: "implemented".into(),
        declared: true,
        unsupported_dimensions: Default::default(),
    };
    let mut summary = crate::protocol::Summary::parse(
        include_str!("../../../testdata/counting.summary"),
        &fixture.listing,
    )
    .unwrap();
    summary.turns = Some(0);
    let mut coverage = super::coverage::Coverage::new(declaration.clone()).unwrap();
    coverage.credit(job.job().id().to_string(), 1, Some(&summary));
    let row = coverage.row().unwrap();
    assert_eq!(row["dimensions"]["turns"]["state"], "inconclusive");
    assert_eq!(row["dimensions"]["turns"]["measurement"]["value"], 0);
    assert_eq!(profile(&projected, "upload")["state"], "credited");
    for frozen in [
        "",
        "bad",
        "owners:no",
        "unknown:1",
        "published:1,published:2",
        "published:1,",
    ] {
        let mut declaration = declaration.clone();
        declaration.minima = Some(text(frozen));
        assert!(
            super::coverage::Coverage::new(declaration).is_err(),
            "{frozen}"
        );
        assert!(
            super::super::minima::parse(&text(frozen)).is_err(),
            "{frozen}"
        );
    }
}

#[test]
fn calibration_scope_mismatch_withholds_capacity_eligibility() {
    let fixture = Fixture::new();
    let job = fixture.admit(0);
    let config = crate::campaign::calibration::tests::config();
    let capacity = crate::campaign::calibration::tests::stored_capacity(
        &fixture.store,
        job,
        config.clone(),
        1,
    );
    assert!(
        !crate::campaign::calibration::eligible(&fixture.store, capacity.contract())
            .unwrap()
            .is_empty()
    );
    record_capacity(&fixture, &capacity);
    fixture
        .store
        .create_record(fixture.store.root(), &name("config.json"), &config)
        .unwrap();
    // The report is the reader production runs: it qualifies the
    // capacity's calibration row.
    let reported = || {
        let report = report(&fixture.case.state).unwrap();
        report["calibrations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == capacity.root().to_string() && row["qualified"] == true)
    };
    assert!(reported());
    let roots = fixture
        .store
        .open_dir(fixture.store.root(), &name("calibrations"))
        .unwrap()
        .unwrap();
    let root = fixture
        .store
        .open_dir(&roots, &name(&capacity.root().to_string()))
        .unwrap()
        .unwrap();
    let mut plan = fixture
        .store
        .read_record::<crate::record::CalibrationPlan>(&root, &name("plan"))
        .unwrap()
        .unwrap()
        .record()
        .clone();
    let control = plan.controls.values_mut().next().unwrap();
    let mut experiment = control.job().experiment().clone();
    experiment.calibration_scope = Some(Digest::of(b"different scope"));
    let keys = fixture
        .listing
        .keys
        .iter()
        .map(|key| key.name.as_str())
        .collect::<Vec<_>>();
    let (job, _) = crate::record::Job::derive(experiment, &keys).unwrap();
    *control = Admission::new(control.archive().clone(), job, Purpose::Calibration).unwrap();
    fixture
        .store
        .replace_record(&root, &name("plan"), &plan)
        .unwrap();
    assert!(matches!(
        crate::campaign::calibration::eligible(&fixture.store, capacity.contract()),
        Err(crate::campaign::Error::Held(_))
    ));
    assert!(!reported());
}

#[test]
fn foreign_root_entries_are_held_while_other_rows_remain_visible() {
    let fixture = Fixture::new();
    fixture.probe();
    let job = fixture.admit(0);
    fixture.finish(&job, Some(1));
    for kind in ["calibrations", "findings", "triage"] {
        fixture
            .store
            .mkdir(fixture.store.root(), &name(kind))
            .unwrap();
        std::fs::write(
            fixture.case.state.join(kind).join("foreign name"),
            b"damaged",
        )
        .unwrap();
        let projected = report(&fixture.case.state).unwrap();
        assert!(
            projected["held"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["path"] == kind)
        );
        assert!(!projected["profiles"].as_array().unwrap().is_empty());
        if kind == "findings" {
            assert_eq!(projected["jobs"][0]["credited"], false);
            assert!(
                profile(&projected, "upload")["credited"]
                    .as_array()
                    .unwrap()
                    .is_empty()
            );
        }
    }
}

#[test]
fn bound_capabilities_restore_declarations_when_a_probe_is_missing_or_held() {
    for damaged_probe in [false, true] {
        let fixture = Fixture::new();
        if damaged_probe {
            fixture.probe();
            let probes = fixture
                .store
                .open_dir(fixture.store.root(), &name("probes"))
                .unwrap()
                .unwrap();
            let probe = fixture
                .store
                .open_dir(&probes, &name("probe-fixture"))
                .unwrap()
                .unwrap();
            fixture
                .store
                .replace(&probe, &name("finished"), b"damaged")
                .unwrap();
        }
        let job = fixture.admit(0);
        fixture.finish_at_with_listing(
            &job,
            1,
            Some(1),
            Class::Pass,
            Some(include_bytes!("../../../testdata/admission-listing.txt")),
        );
        let projected = report(&fixture.case.state).unwrap();
        assert_eq!(profile(&projected, "upload")["state"], "credited");
        let other = projected["profiles"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["declaration"]["profile"] == "cluster-broad")
            .unwrap();
        assert_eq!(other["state"], "unrun");
        assert_eq!(
            profile(&projected, "upload")["declaration"]["support"],
            "implemented"
        );
        assert_eq!(projected["jobs"][0]["credited"], true);
        assert_eq!(
            !projected["held"].as_array().unwrap().is_empty(),
            damaged_probe
        );
    }
}

#[test]
fn violation_finished_before_capture_remains_a_release_blocker() {
    let fixture = Fixture::new();
    fixture.probe();
    let job = fixture.admit(0);
    let directory = fixture.finish_at(&job, 1, Some(1), Class::Violation);
    let id = format!("{}-0001", job.job().id());
    fixture.store.delete(&directory, &name("captured")).unwrap();
    std::fs::remove_dir_all(fixture.case.state.join("findings").join(&id)).unwrap();
    let jobs = fixture.store.shard_jobs(job.job().id()).unwrap().unwrap();
    for suffix in [crate::record::JobResult::SUFFIX, crate::record::Pin::SUFFIX] {
        fixture
            .store
            .delete(&jobs, &name(&format!("{}{suffix}", job.job().id())))
            .unwrap();
    }
    let projected = report(&fixture.case.state).unwrap();
    assert!(
        projected["release_blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row == &id)
    );
    assert!(
        projected["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == id && row["blocker"] == true)
    );
    assert!(
        profile(&projected, "upload")["credited"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn store_ancestor_refusal_preserves_the_unopened_state_directory() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    let ancestor = fixture.case.root.join("shared");
    let state = ancestor.join("state");
    std::fs::create_dir_all(&state).unwrap();
    std::fs::set_permissions(&ancestor, std::fs::Permissions::from_mode(0o777)).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    let before = snapshot(&state);
    assert!(matches!(
        Store::open(&state),
        Err(crate::store::Error::Refused(_))
    ));
    assert_eq!(snapshot(&state), before);
}

fn revise_artifact(
    fixture: &Fixture,
    directory: &Dir,
    class: Class,
    change: impl FnOnce(&Dir, &mut crate::record::Artifact),
) {
    let attempt = fixture
        .store
        .read_record::<Attempt>(directory, &name("attempt"))
        .unwrap()
        .unwrap();
    let artifacts = fixture
        .store
        .open_dir(directory, &name("artifacts"))
        .unwrap()
        .unwrap();
    let artifact_dir = fixture
        .store
        .open_dir(&artifacts, &name(attempt.record().attempt.as_str()))
        .unwrap()
        .unwrap();
    let mut artifact = fixture
        .store
        .read_record::<crate::record::Artifact>(&artifact_dir, &name("artifact"))
        .unwrap()
        .unwrap()
        .record()
        .clone();
    change(&artifact_dir, &mut artifact);
    fixture
        .store
        .replace_record(&artifact_dir, &name("artifact"), &artifact)
        .unwrap();
    let artifact = fixture
        .store
        .read_record::<crate::record::Artifact>(&artifact_dir, &name("artifact"))
        .unwrap()
        .unwrap();
    let mut bound = fixture
        .store
        .read_record::<BoundEvidence>(directory, &name("bound"))
        .unwrap()
        .unwrap()
        .record()
        .clone();
    bound.artifact = Digest::of(artifact.read().bytes());
    fixture
        .store
        .replace_record(directory, &name("bound"), &bound)
        .unwrap();
    let mut finished = fixture
        .store
        .read_record::<Finished>(directory, &name("finished"))
        .unwrap()
        .unwrap()
        .record()
        .clone();
    finished.bound = Some(bound);
    finished.class = class;
    fixture
        .store
        .replace_record(directory, &name("finished"), &finished)
        .unwrap();
    let verified = fixture
        .store
        .read_record::<Finished>(directory, &name("finished"))
        .unwrap()
        .unwrap();
    let mut captured = fixture
        .store
        .read_record::<crate::record::Captured>(directory, &name("captured"))
        .unwrap()
        .unwrap()
        .record()
        .clone();
    captured.finished = Digest::of(verified.read().bytes());
    fixture
        .store
        .replace_record(directory, &name("captured"), &captured)
        .unwrap();
    let jobs = fixture
        .store
        .shard_jobs(attempt.record().job)
        .unwrap()
        .unwrap();
    let entry = name(&format!(
        "{}{}",
        attempt.record().job,
        crate::record::JobResult::SUFFIX
    ));
    let mut result = fixture
        .store
        .read_record::<crate::record::JobResult>(&jobs, &entry)
        .unwrap()
        .unwrap()
        .record()
        .clone();
    result.finished = finished;
    fixture
        .store
        .replace_record(&jobs, &entry, &result)
        .unwrap();
}

#[test]
fn a_listing_for_other_profiles_withholds_the_frozen_jobs_credit() {
    let fixture = Fixture::new();
    let listing = include_str!("../../../testdata/admission-listing.txt")
        .replace("profile: upload ", "profile: other ");
    fixture.probe_listing(listing.as_bytes());
    let job = fixture.admit(0);
    fixture.finish(&job, Some(1));
    let projected = report(&fixture.case.state).unwrap();
    assert_eq!(projected["jobs"][0]["state"], "inconclusive");
    assert_eq!(projected["jobs"][0]["credited"], false);
    assert_eq!(
        profile(&projected, "upload")["declaration"]["declared"],
        false
    );
    assert!(
        profile(&projected, "upload")["credited"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn a_bound_inspection_for_another_profile_is_inconclusive() {
    let fixture = Fixture::new();
    let listing = include_str!("../../../testdata/admission-listing.txt");
    let line = listing
        .lines()
        .find(|line| line.starts_with("profile: upload "))
        .unwrap();
    let listing = format!(
        "{listing}{}\n",
        line.replace("profile: upload ", "profile: other ")
    );
    fixture.probe_listing(listing.as_bytes());
    let job = fixture.admit(0);
    let directory = fixture.finish(&job, Some(1));
    revise_artifact(
        &fixture,
        &directory,
        Class::Pass,
        |artifact_dir, artifact| {
            let stdout = include_str!("../../../testdata/counting.summary")
                .replace("profile: upload", "profile: other");
            fixture
                .store
                .replace(artifact_dir, &name("inspect.stdout"), stdout.as_bytes())
                .unwrap();
            artifact.workers.get_mut(&text("inspect")).unwrap().stdout =
                Digest::of(stdout.as_bytes());
        },
    );
    let projected = report(&fixture.case.state).unwrap();
    assert_eq!(projected["jobs"][0]["state"], "inconclusive");
    assert_eq!(
        projected["jobs"][0]["reason"],
        "bound inspection names another profile"
    );
    assert_eq!(projected["jobs"][0]["credited"], false);
    assert!(
        profile(&projected, "upload")["credited"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    for metric in ["virtual_us", "skipped_us"] {
        assert_eq!(
            projected["totals"]["metrics"][metric],
            json!({"value": null, "measurement": "unmeasured", "reason": "an operand is absent"}),
            "{metric} comes from the inspection the row distrusts: {projected}"
        );
    }
    assert_eq!(projected["totals"]["metrics"]["cpu_us"]["value"], 1);
}

#[test]
fn a_rejected_capability_phase_cannot_select_a_recovery_inspections_grammar() {
    let mut fixture = Fixture::new();
    let current = include_str!("../../../testdata/admission-listing.txt")
        .replace("capabilities: 1", "capabilities: 5")
        .replace(
            "profile: upload class=live",
            "profile: recovery-512 class=recovery",
        );
    let old = current.replace("capabilities: 5", "capabilities: 4");
    fixture.listing = Listing::parse(&current).unwrap();
    let mut jobs =
        [0, 1].map(|run| fixture.admit_profile("recovery-512", run, 3, Purpose::Campaign));
    jobs.sort_by_key(|job| job.job().id().to_string());
    fixture.finish_unsettled_with_listing(
        &jobs[0],
        1,
        Some(1),
        Class::Incomplete,
        Some(old.as_bytes()),
    );
    let failed = report(&fixture.case.state).unwrap();
    assert_eq!(failed["held"], json!([]));
    assert_eq!(
        profile(&failed, "recovery-512")["declaration"]["declared"],
        false
    );

    let dir =
        fixture.finish_at_with_listing(&jobs[1], 1, Some(1), Class::Pass, Some(current.as_bytes()));
    revise_artifact(&fixture, &dir, Class::Pass, |dir, artifact| {
        let stdout = include_str!("../../../testdata/counting.summary")
            .replace("profile: upload", "profile: recovery-512")
            .replace("skipped_us: 0", "skipped_us: 42")
            + "ledger: credited
stages: planned=1 reached=1 activated=1 recovered=1 checked=1 skipped=0
limits: cold relaunch
windows: a=1
";
        fixture
            .store
            .replace(dir, &name("inspect.stdout"), stdout.as_bytes())
            .unwrap();
        artifact.workers.get_mut(&text("inspect")).unwrap().stdout = Digest::of(stdout.as_bytes());
        artifact.summary.as_mut().unwrap().ledger = Some(text("credited"));
    });
    let projected = report(&fixture.case.state).unwrap();
    assert_eq!(projected["held"], json!([]));
    assert_eq!(
        projected["jobs"][1]["state"], "measured",
        "{}",
        projected["jobs"]
    );
    assert_eq!(projected["totals"]["metrics"]["virtual_us"]["value"], 600);
    assert_eq!(projected["totals"]["metrics"]["skipped_us"]["value"], 42);
    fixture.probe_listing(current.as_bytes());
    revise_artifact(&fixture, &dir, Class::Pass, |dir, artifact| {
        let refused = b"invalid listing\n";
        fixture
            .store
            .replace(dir, &name("capabilities.stdout"), refused)
            .unwrap();
        artifact
            .workers
            .get_mut(&text("capabilities"))
            .unwrap()
            .stdout = Digest::of(refused);
    });
    let projected = report(&fixture.case.state).unwrap();
    assert_eq!(projected["jobs"][1]["state"], "held");
    assert!(
        projected["held"][0]["reason"]
            .as_str()
            .unwrap()
            .contains("bound capabilities listing refused")
    );
    assert!(projected["totals"]["metrics"]["virtual_us"]["value"].is_null());
    assert!(projected["totals"]["metrics"]["skipped_us"]["value"].is_null());
}

#[test]
fn a_late_fallback_of_another_version_holds_the_earlier_job_in_coverage() {
    let mut fixture = Fixture::new();
    let v1 = include_str!("../../../testdata/admission-listing.txt");
    let v4 = v1.replace("capabilities: 1", "capabilities: 4");
    let first = fixture.admit(0);
    fixture.listing = Listing::parse(&v4).unwrap();
    let second = fixture.admit(1);
    let mut jobs = [(first, v1), (second, v4.as_str())];
    jobs.sort_by_key(|(job, _)| job.job().id().to_string());
    fixture.finish(&jobs[0].0, Some(1));
    fixture.finish_at_with_listing(
        &jobs[1].0,
        1,
        Some(1),
        Class::Pass,
        Some(jobs[1].1.as_bytes()),
    );
    let projected = report(&fixture.case.state).unwrap();
    assert_eq!(projected["jobs"][0]["state"], "held");
    assert_eq!(projected["jobs"][1]["state"], "measured");
    let row = projected["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["jobs"] == json!([jobs[0].0.job().id().to_string()]))
        .unwrap();
    assert_eq!(row["state"], "inconclusive");
    assert_eq!(row["credited"], json!([]));
}

#[test]
fn a_probe_of_another_capability_version_holds_the_frozen_job() {
    let fixture = Fixture::new();
    let listing = include_str!("../../../testdata/admission-listing.txt")
        .replace("capabilities: 1", "capabilities: 4");
    fixture.probe_listing(listing.as_bytes());
    let job = fixture.admit(0);
    fixture.finish(&job, Some(1));
    let projected = report(&fixture.case.state).unwrap();
    assert_eq!(projected["jobs"][0]["state"], "held");
    assert!(
        projected["held"][0]["reason"]
            .as_str()
            .unwrap()
            .contains("capability version differs")
    );
    let row = profile(&projected, "upload");
    assert_eq!(row["jobs"], json!([job.job().id().to_string()]));
    assert_eq!(row["state"], "inconclusive");
    assert_eq!(row["credited"], json!([]));
}

#[test]
fn a_wrong_version_bound_listing_holds_only_its_job() {
    let fixture = Fixture::new();
    let mut jobs = [fixture.admit(0), fixture.admit(1)];
    jobs.sort_by_key(|job| job.job().id().to_string());
    let listing = include_str!("../../../testdata/admission-listing.txt")
        .replace("capabilities: 1", "capabilities: 4");
    fixture.finish_at_with_listing(&jobs[0], 1, Some(1), Class::Pass, Some(listing.as_bytes()));
    fixture.finish(&jobs[1], Some(1));
    let projected = report(&fixture.case.state).unwrap();
    assert_eq!(projected["held"].as_array().unwrap().len(), 1);
    assert_eq!(
        projected["held"][0]["path"],
        format!("jobs/{}", jobs[0].job().id())
    );
    assert!(
        projected["held"][0]["reason"]
            .as_str()
            .unwrap()
            .contains("capability version differs")
    );
    assert_eq!(projected["jobs"][1]["state"], "inconclusive");
    let row = profile(&projected, "upload");
    assert_eq!(
        row["jobs"],
        json!(jobs.map(|job| job.job().id().to_string()))
    );
    assert_eq!(row["credited"], json!([]));
}

#[test]
fn refused_bound_capabilities_hold_a_passing_job_even_with_a_valid_probe() {
    for (bad, reason) in [
        (
            b"bad listing\n".as_slice(),
            "bound capabilities listing refused",
        ),
        (
            &[0xff][..],
            "bound capabilities stdout is missing or not UTF-8",
        ),
    ] {
        let fixture = Fixture::new();
        fixture.probe();
        let job = fixture.admit(0);
        fixture.finish_at_with_listing(&job, 1, Some(1), Class::Pass, Some(bad));
        let projected = report(&fixture.case.state).unwrap();
        assert_eq!(projected["jobs"][0]["state"], "held");
        assert_eq!(
            projected["held"][0]["path"],
            format!("jobs/{}", job.job().id())
        );
        assert!(
            projected["held"][0]["reason"]
                .as_str()
                .unwrap()
                .contains(reason)
        );
        assert_eq!(profile(&projected, "upload")["credited"], json!([]));
        assert!(projected["totals"]["metrics"]["virtual_us"]["value"].is_null());
    }
}

#[test]
fn failed_capabilities_phase_supplies_no_fallback_declaration() {
    let fixture = Fixture::new();
    let job = fixture.admit(0);
    let directory = fixture.finish_at_with_listing(
        &job,
        1,
        Some(1),
        Class::Pass,
        Some(include_bytes!("../../../testdata/admission-listing.txt")),
    );
    revise_artifact(&fixture, &directory, Class::Disagreement, |_, artifact| {
        artifact
            .workers
            .get_mut(&text("capabilities"))
            .unwrap()
            .exit = Some(1)
    });
    let projected = report(&fixture.case.state).unwrap();
    assert_eq!(
        projected["jobs"][0]["credited"], false,
        "{:?}",
        projected["held"]
    );
    assert_eq!(
        profile(&projected, "upload")["declaration"]["declared"],
        false
    );
}

#[test]
fn a_failed_bundle_barrier_fences_digest_credit_in_the_same_snapshot() {
    for entry in ["bundle", "artifact", "manifest", "inspect.stdout"] {
        let fixture = Fixture::new();
        fixture.probe();
        let job = fixture.admit(0);
        let directory = fixture.finish(&job, Some(1));
        let artifacts = fixture
            .store
            .open_dir(&directory, &name("artifacts"))
            .unwrap()
            .unwrap();
        let artifacts = fixture
            .store
            .open_dir(&artifacts, &name(&format!("{}-0001", job.job().id())))
            .unwrap()
            .unwrap();
        let view = crate::store::View::open(&fixture.case.state).unwrap();
        let file = view.open_file(&artifacts, &name(entry)).unwrap().unwrap();
        let (_, steps) = scripted([], || view.sync_file(&artifacts, &file));
        let index = steps.iter().position(|step| *step == Step::Sync).unwrap();
        let (result, _) = scripted([(index, Outcome::Errno(libc::EIO))], || {
            view.sync_file(&artifacts, &file)
        });
        assert!(result.unwrap().is_err());
        assert!(
            crate::store::ReadStore::evidence_digest(&view, &artifacts, &name(entry), BOUND)
                .is_err()
        );
        let projected = super::projection::project(&view).unwrap();
        assert_eq!(projected["jobs"][0]["state"], "held");
        assert!(
            profile(&projected, "upload")["credited"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }
}

#[test]
fn fault_shortfalls_stay_measured_and_are_excluded_from_credited_delivery_totals() {
    let declaration = super::coverage::Declaration {
        build: Digest::of(b"build"),
        class: Some(text("live")),
        counts: Some(Default::default()),
        generator: None,
        minima: Some(text("faults:2")),
        profile: text("upload"),
        support: "implemented".into(),
        declared: true,
        unsupported_dimensions: Default::default(),
    };
    let listing = Listing::parse(include_str!("../../../testdata/admission-listing.txt")).unwrap();
    let mut summary = crate::protocol::Summary::parse(
        include_str!("../../../testdata/counting.summary"),
        &listing,
    )
    .unwrap();
    summary.faults_delivered = Some(1);
    let mut coverage = super::coverage::Coverage::new(declaration.clone()).unwrap();
    coverage.credit("job".into(), 7, Some(&summary));
    let row = coverage.row().unwrap();
    let dimension = &row["dimensions"]["faults_delivered"];
    assert_eq!(dimension["state"], "inconclusive");
    assert_eq!(dimension["measurement"]["value"], 1);
    assert!(dimension["measurement"]["credited_total"]["value"].is_null());
    assert_eq!(
        dimension["measurement"]["credited_total"]["measurement"],
        "unmeasured"
    );
    assert_eq!(
        dimension["measurement"]["shortfalls"],
        json!([{"job": "job", "attempt": 7, "requested": 2, "delivered": 1}])
    );
    let mut joined = super::coverage::Coverage::new(declaration.clone()).unwrap();
    joined.credit("shortfall".into(), 7, Some(&summary));
    summary.faults_delivered = Some(2);
    joined.credit("meets".into(), 8, Some(&summary));
    let row = joined.row().unwrap();
    assert_eq!(
        row["dimensions"]["faults_delivered"]["measurement"]["value"],
        3
    );
    assert_eq!(
        row["dimensions"]["faults_delivered"]["measurement"]["credited_total"]["value"],
        2
    );
    let mut missing = super::coverage::Coverage::new(declaration.clone()).unwrap();
    missing.credit("meets".into(), 8, Some(&summary));
    summary.faults_delivered = None;
    missing.credit("missing".into(), 9, Some(&summary));
    let row = missing.row().unwrap();
    assert!(
        row["dimensions"]["faults_delivered"]["measurement"]["credited_total"]["value"].is_null()
    );
    assert_eq!(
        row["dimensions"]["faults_delivered"]["measurement"]["credited_total"]["measurement"],
        "unmeasured"
    );
    assert_eq!(
        row["dimensions"]["faults_delivered"]["measurement"]["credited_total"]["reason"],
        "an operand is absent"
    );
    summary.faults_delivered = Some(1);
    let mut no_minimum = declaration;
    no_minimum.minima = None;
    let mut coverage = super::coverage::Coverage::new(no_minimum).unwrap();
    coverage.credit("job".into(), 7, Some(&summary));
    let row = coverage.row().unwrap();
    assert_eq!(
        row["dimensions"]["faults_delivered"]["measurement"]["value"],
        1
    );
}

#[test]
fn admission_refuses_minima_that_the_report_and_calibration_cannot_measure() {
    let fixture = Fixture::new();
    for frozen in [
        "",
        "bad",
        "owners:no",
        "unknown:1",
        "published:1,published:2",
        "published:1,",
    ] {
        let mut listing = fixture.listing.clone();
        let cluster = listing
            .clusters
            .iter_mut()
            .find(|cluster| cluster.name == "cluster-broad")
            .unwrap();
        cluster
            .fields
            .iter_mut()
            .find(|(key, _)| key == "minima")
            .unwrap()
            .1 = frozen.into();
        let outcome = crate::campaign::admit(
            &fixture.store,
            &listing,
            Pins {
                build: text(&"b".repeat(64)),
                executable: text(&"e".repeat(64)),
                platform: text("x86_64-linux"),
                toolchain: text("rustc"),
            },
            text("/archive"),
            &crate::campaign::Request {
                profile: text("cluster-broad"),
                campaign: text("c1"),
                run: 0,
                attempts: 1,
                counts: Default::default(),
            },
            Purpose::Campaign,
        );
        assert!(
            matches!(outcome, Err(crate::campaign::Error::Rejected(_))),
            "{frozen}"
        );
    }
}

#[test]
fn finding_finish_mismatch_holds_the_job_before_measurement_credit() {
    let fixture = Fixture::new();
    fixture.probe();
    let job = fixture.admit(0);
    fixture.finish_at(&job, 1, Some(1), Class::Watchdog);
    fixture.finish_at(&job, 2, Some(2), Class::Pass);
    let findings = fixture
        .store
        .open_dir(fixture.store.root(), &name("findings"))
        .unwrap()
        .unwrap();
    let directory = fixture
        .store
        .open_dir(&findings, &name(&format!("{}-0001", job.job().id())))
        .unwrap()
        .unwrap();
    let mut finding = fixture
        .store
        .read_record::<crate::record::Finding>(&directory, &name("finding.json"))
        .unwrap()
        .unwrap()
        .record()
        .clone();
    finding.finished.kernel.cpu.insert(text("usage_usec"), 99);
    fixture
        .store
        .replace_record(&directory, &name("finding.json"), &finding)
        .unwrap();
    let projected = report(&fixture.case.state).unwrap();
    assert_eq!(projected["jobs"][0]["state"], "held");
    assert!(projected["held"].as_array().unwrap().iter().any(|row| {
        row["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("finding differs from verified attempt finish"))
    }));
}

#[test]
fn incomplete_declarations_withhold_qualification_even_with_matching_capacity() {
    let fixture = Fixture::new();
    let job = fixture.admit(0);
    let capacity = crate::campaign::calibration::tests::stored_capacity(
        &fixture.store,
        job.clone(),
        crate::campaign::calibration::tests::config(),
        1,
    );
    for declared in [false, true] {
        let declaration = super::coverage::Declaration {
            build: capacity.contract().build,
            class: Some(text("live")),
            counts: Some(capacity.contract().counts.clone()),
            generator: None,
            minima: None,
            profile: capacity.contract().profile.clone(),
            support: if declared { "implemented" } else { "unknown" }.into(),
            declared,
            unsupported_dimensions: Default::default(),
        };
        let mut profiles = [(
            declaration.clone(),
            super::coverage::Coverage::new(declaration).unwrap(),
        )]
        .into();
        super::projection::qualify_profiles(
            &mut profiles,
            std::slice::from_ref(&capacity),
            &BTreeMap::new(),
        );
        assert_eq!(profiles.values().next().unwrap().qualified, declared);
    }
}

#[test]
fn inspection_uses_its_own_listing_when_the_probe_differs() {
    let fixture = Fixture::new();
    fixture.probe();
    let job = fixture.admit(0);
    let fallback = include_str!("../../../testdata/admission-listing.txt")
        .replace("profile: upload ", "profile: other ");
    fixture.finish_at_with_listing(&job, 1, Some(1), Class::Pass, Some(fallback.as_bytes()));
    let projected = report(&fixture.case.state).unwrap();
    assert_eq!(projected["jobs"][0]["credited"], false);
    assert_eq!(
        projected["jobs"][0]["reason"],
        "bound inspection facts are unavailable"
    );
    let row = profile(&projected, "upload");
    assert_eq!(row["declaration"]["declared"], true);
    assert_eq!(row["declaration"]["support"], "implemented");
    assert_eq!(
        projected["profiles"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["declaration"]["profile"] == "upload")
            .count(),
        1
    );
}

#[test]
fn an_inspection_admitted_only_by_its_own_listing_still_earns_credit() {
    let fixture = Fixture::new();
    let own = include_str!("../../../testdata/admission-listing.txt");
    let probe = own.replace("profile: upload ", "profile: other ");
    fixture.probe_listing(probe.as_bytes());
    let job = fixture.admit(0);
    fixture.finish_at_with_listing(&job, 1, Some(1), Class::Pass, Some(own.as_bytes()));
    let projected = report(&fixture.case.state).unwrap();
    assert_eq!(projected["held"], json!([]));
    assert_eq!(projected["jobs"][0]["state"], "measured");
    assert_eq!(projected["jobs"][0]["credited"], true);
    assert_eq!(
        profile(&projected, "upload")["declaration"]["declared"],
        false
    );
}

#[test]
fn an_unsupported_frozen_profile_with_matching_inspection_facts_earns_no_credit() {
    let fixture = Fixture::new();
    let listing = include_str!("../../../testdata/admission-listing.txt").replacen(
        "support=implemented",
        "support=unsupported",
        1,
    );
    fixture.probe_listing(listing.as_bytes());
    let job = fixture.admit(0);
    fixture.finish(&job, Some(1));
    let projected = report(&fixture.case.state).unwrap();
    assert_eq!(projected["jobs"][0]["credited"], false);
    assert_eq!(profile(&projected, "upload")["state"], "unsupported");
    assert_eq!(
        projected["jobs"][0]["reason"],
        "capability declaration is unavailable"
    );
    assert_eq!(
        profile(&projected, "upload")["declaration"]["declared"],
        true
    );
}

#[test]
fn foreign_state_root_marks_population_completeness_unknown() {
    let fixture = Fixture::new();
    fixture.probe();
    let job = fixture.admit(0);
    fixture.finish(&job, Some(1));
    std::fs::write(fixture.case.state.join("foreign name"), b"damaged").unwrap();
    let projected = report(&fixture.case.state).unwrap();
    assert!(
        projected["held"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["path"] == "state")
    );
    assert_eq!(projected["totals"]["population_completeness"], "unknown");
}

#[test]
fn each_job_history_reads_its_attempt_evidence_once_per_report() {
    let reads = |run: &mut dyn FnMut()| {
        crate::step::install(Some(crate::step::Script::default()));
        run();
        crate::step::install(None)
            .unwrap()
            .reached
            .into_iter()
            .filter(|step| *step == crate::step::Step::Read)
            .count()
    };
    let fixture = Fixture::new();
    fixture.probe();
    let first = fixture.admit(0);
    fixture.finish(&first, Some(1));
    let one = reads(&mut || {
        report(&fixture.case.state).unwrap();
    });
    let second = fixture.admit(1);
    fixture.finish(&second, Some(1));
    let two = reads(&mut || {
        let report = report(&fixture.case.state).unwrap();
        assert_eq!(profile(&report, "upload")["state"], "credited");
    });
    let three = {
        let third = fixture.admit(2);
        fixture.finish(&third, Some(1));
        reads(&mut || {
            report(&fixture.case.state).unwrap();
        })
    };
    let view = crate::store::View::open(&fixture.case.state).unwrap();
    let admission_reads = |job: &Admission| {
        let jobs = view.shard_jobs(job.job().id()).unwrap().unwrap();
        reads(&mut || {
            crate::campaign::show::verified_job(&view, &jobs, &job.job().id().to_string()).unwrap();
        })
    };
    let frozen_admission_reads = admission_reads(&second);
    assert_eq!(frozen_admission_reads, 2);
    assert_eq!(admission_reads(&first), frozen_admission_reads);
    let attempt_reads = |job: &Admission| {
        reads(&mut || {
            let (root, _) = crate::attempt::history(&view, job).unwrap().unwrap();
            crate::attempt::completed_at(&view, job, &root, 1).unwrap();
        })
    };
    let attempt = attempt_reads(&second);
    assert_eq!(attempt_reads(&first), attempt);
    let attempt_evidence_reads = (two - one) - frozen_admission_reads;
    assert_eq!(
        (three - two) - frozen_admission_reads,
        attempt_evidence_reads
    );
    assert!(
        attempt_evidence_reads < 2 * attempt,
        "one more job adds {attempt_evidence_reads} attempt-evidence reads and {frozen_admission_reads} frozen-admission reads; verifying its attempt once takes {attempt}"
    );
    assert_eq!(three - two, two - one);
}

#[test]
fn a_report_holds_descriptors_for_one_job_at_a_time() {
    let _processes = crate::store::fixture::processes();
    if std::env::var_os("CAMPAIGN_REPORT_DESCRIPTOR_CHILD").is_none() {
        // The child's libtest lines stay in the captured output, so the parent run reports
        // one summary per target.
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "campaign::report::tests::a_report_holds_descriptors_for_one_job_at_a_time",
                "--nocapture",
            ])
            .env("CAMPAIGN_REPORT_DESCRIPTOR_CHILD", "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("test result: ok. 1 passed;"),
            "{output:?}"
        );
        return;
    }
    let fixture = Fixture::new();
    fixture.probe();
    let jobs = 30;
    for run in 0..jobs {
        let job = fixture.admit(run);
        fixture.finish(&job, Some(1));
    }
    drop(fixture.store);
    let open = std::fs::read_dir("/proc/self/fd").unwrap().count() as u64;
    // Room for the snapshot and one job's verification, below one
    // descriptor per job.
    crate::sys::restrict_descriptor_limit(open + 24).unwrap();
    let report = report(&fixture.case.state).unwrap();
    assert_eq!(
        report["held"],
        json!([]),
        "every job verifies under a descriptor budget below one per job"
    );
    assert_eq!(
        profile(&report, "upload")["credited"]
            .as_array()
            .unwrap()
            .len(),
        jobs as usize
    );
}

fn peak_resident_bytes() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let kib = status
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))
        .and_then(|value| value.trim().strip_suffix("kB"))
        .and_then(|value| value.trim().parse::<u64>().ok())
        .expect("the kernel reports VmHWM in kB");
    kib * 1024
}

#[test]
fn a_job_verified_after_its_builds_listing_releases_its_inspection_text_at_verification() {
    let _processes = crate::store::fixture::processes();
    if std::env::var_os("CAMPAIGN_REPORT_MEMORY_CHILD").is_none() {
        // VmHWM is process-wide, so a dedicated child isolates this test's
        // peak resident set.
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "campaign::report::tests::a_job_verified_after_its_builds_listing_releases_its_inspection_text_at_verification",
                "--nocapture",
            ])
            .env("CAMPAIGN_REPORT_MEMORY_CHILD", "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("test result: ok. 1 passed;"),
            "{output:?}"
        );
        return;
    }
    let fixture = Fixture::new();
    fixture.probe();
    let stream = vec![b'x'; crate::sim::OUTPUT];
    let jobs = 32;
    for run in 0..jobs {
        let job = fixture.admit(run);
        let directory = fixture.finish(&job, Some(1));
        revise_artifact(
            &fixture,
            &directory,
            Class::Pass,
            |artifact_dir, artifact| {
                fixture
                    .store
                    .replace(artifact_dir, &name("inspect.stdout"), &stream)
                    .unwrap();
                artifact.workers.get_mut(&text("inspect")).unwrap().stdout = Digest::of(&stream);
            },
        );
    }
    let before = peak_resident_bytes();
    let report = report(&fixture.case.state).unwrap();
    let grown = peak_resident_bytes() - before;
    assert_eq!(report["held"], json!([]));
    let rows = report["jobs"].as_array().unwrap();
    assert_eq!(rows.len(), jobs as usize);
    for row in rows {
        assert_eq!(
            row["reason"], "bound inspection facts are unavailable",
            "{row}"
        );
    }
    let streams = jobs * crate::sim::OUTPUT as u64;
    assert!(
        grown < streams / 2,
        "the report grew the peak resident set by {grown} bytes over {streams} bytes of inspection streams"
    );
}

/// A job verified ahead of its build's first listing keeps its inspection
/// text until projection, which parses it against the listing a later job
/// of that build declares.
#[test]
fn a_job_verified_before_its_builds_listing_is_parsed_against_that_listing() {
    let fixture = Fixture::new();
    let mut jobs = [fixture.admit(0), fixture.admit(1)];
    jobs.sort_by_key(|job| job.job().id().to_string());
    fixture.finish(&jobs[0], Some(1));
    fixture.finish_at_with_listing(
        &jobs[1],
        1,
        Some(1),
        Class::Pass,
        Some(include_bytes!("../../../testdata/admission-listing.txt")),
    );
    let projected = report(&fixture.case.state).unwrap();
    assert_eq!(projected["held"], json!([]));
    let rows = projected["jobs"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    for row in rows {
        assert_eq!(row["reason"], "bound passing outcome", "{row}");
        assert_eq!(row["credited"], true, "{row}");
    }
    assert_eq!(
        profile(&projected, "upload")["credited"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn empty_calibration_roots_are_listed_as_status_lists_them_and_leave_capacity_qualified() {
    let fixture = Fixture::new();
    let job = fixture.admit(0);
    let config = crate::campaign::calibration::tests::config();
    fixture
        .store
        .create_record(fixture.store.root(), &name("config.json"), &config)
        .unwrap();
    let capacity =
        crate::campaign::calibration::tests::stored_capacity(&fixture.store, job, config, 1);
    record_capacity(&fixture, &capacity);
    let roots = fixture
        .store
        .open_dir(fixture.store.root(), &name("calibrations"))
        .unwrap()
        .unwrap();
    let empty = Digest::of(b"empty root").to_string();
    fixture.store.mkdir(&roots, &name(&empty)).unwrap();
    fixture.store.mkdir(&roots, &name("misnamed")).unwrap();
    let projected = report(&fixture.case.state).unwrap();
    let view = crate::store::View::open(&fixture.case.state).unwrap();
    let status = crate::campaign::calibration::status(&view).unwrap();
    for (id, verdict) in [(empty.as_str(), "uncalibrated"), ("misnamed", "held")] {
        let row = projected["calibrations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["id"] == id)
            .unwrap_or_else(|| panic!("{id} has a row: {projected}"));
        let shown = status.iter().find(|row| row["id"] == id).unwrap();
        assert_eq!(row["verdict"], shown["verdict"]);
        assert_eq!(row["verdict"], verdict);
        assert_eq!(row["qualified"], false);
    }
    assert!(
        projected["held"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["path"] == "calibrations/misnamed")
    );
    let calibrated = projected["calibrations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == capacity.root().to_string())
        .unwrap();
    assert_eq!(
        calibrated["qualified"], true,
        "an empty root qualifies nothing and holds nothing: {projected}"
    );
}

/// Stores `capacity` as the capacity record of its contract and root.
fn record_capacity(fixture: &Fixture, capacity: &crate::record::Capacity) {
    fixture
        .store
        .mkdir(fixture.store.root(), &name("capacity"))
        .unwrap();
    let scopes = fixture
        .store
        .open_dir(fixture.store.root(), &name("capacity"))
        .unwrap()
        .unwrap();
    fixture
        .store
        .mkdir(&scopes, &name(&capacity.contract().key().to_string()))
        .unwrap();
    let scope = fixture
        .store
        .open_dir(&scopes, &name(&capacity.contract().key().to_string()))
        .unwrap()
        .unwrap();
    fixture
        .store
        .create_record(&scope, &name(&capacity.root().to_string()), capacity)
        .unwrap();
}

/// The report qualifies a capacity at the configured slots, which
/// dispatch runs, and not at the fewer slots its record names. The
/// capacity here measured two cores for an attempt and names one slot: it
/// fits one slot beside the reserve in the configuration's four cores,
/// and not the two slots the configuration runs.
#[test]
fn a_capacity_is_qualified_at_the_configured_slots() {
    let fixture = Fixture::new();
    fixture.probe();
    let job = fixture.admit(0);
    let config = crate::campaign::calibration::tests::config();
    let resources = crate::record::ResourceBounds {
        cpu_us: Some(2_000_000),
        memory_bytes: Some(100),
        pids: Some(1),
        wall_us: Some(1_000_000),
    };
    assert!(resources.fits(&config, 1) && !resources.fits(&config, config.value("slots")));
    let capacity = crate::campaign::calibration::tests::stored_capacity_with_resources(
        &fixture.store,
        job,
        config.clone(),
        1,
        resources,
    );
    record_capacity(&fixture, &capacity);
    fixture
        .store
        .create_record(fixture.store.root(), &name("config.json"), &config)
        .unwrap();
    let projected = report(&fixture.case.state).unwrap();
    let row = projected["calibrations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == capacity.root().to_string())
        .unwrap();
    assert_eq!(row["qualified"], false, "{projected}");
    assert_eq!(
        row["reason"],
        "capacity measurements exceed configuration or are missing"
    );
    assert_eq!(profile(&projected, "upload")["qualified"], false);
}

/// A calibration root whose contract cannot be read may belong to any
/// contract, so the report qualifies no capacity while one is present.
/// The root here holds an entry and no plan.
#[test]
fn a_calibration_root_of_unknown_scope_withholds_every_capacity() {
    let fixture = Fixture::new();
    fixture.probe();
    let job = fixture.admit(0);
    let config = crate::campaign::calibration::tests::config();
    let capacity = crate::campaign::calibration::tests::stored_capacity(
        &fixture.store,
        job,
        config.clone(),
        1,
    );
    record_capacity(&fixture, &capacity);
    fixture
        .store
        .create_record(fixture.store.root(), &name("config.json"), &config)
        .unwrap();
    let qualified = || {
        let report = report(&fixture.case.state).unwrap();
        report["calibrations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == capacity.root().to_string() && row["qualified"] == true)
    };
    assert!(qualified());
    let roots = fixture
        .store
        .open_dir(fixture.store.root(), &name("calibrations"))
        .unwrap()
        .unwrap();
    let unknown = name(&Digest::of(b"a root without a plan").to_string());
    fixture.store.mkdir(&roots, &unknown).unwrap();
    let root = fixture.store.open_dir(&roots, &unknown).unwrap().unwrap();
    fixture
        .store
        .create_once(&root, &name("stray"), b"no plan")
        .unwrap();
    assert!(!qualified());
}

#[test]
fn a_capacity_outside_the_current_configuration_is_unqualified() {
    let fixture = Fixture::new();
    fixture.probe();
    let job = fixture.admit(0);
    let config = crate::campaign::calibration::tests::config();
    let capacity = crate::campaign::calibration::tests::stored_capacity(
        &fixture.store,
        job,
        config.clone(),
        1,
    );
    record_capacity(&fixture, &capacity);
    let row = |projected: &Value| {
        projected["calibrations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["id"] == capacity.root().to_string())
            .unwrap()
            .clone()
    };
    let unconfigured = report(&fixture.case.state).unwrap();
    assert_eq!(row(&unconfigured)["qualified"], false);
    assert_eq!(row(&unconfigured)["reason"], "configuration is unavailable");
    assert_eq!(
        profile(&unconfigured, "upload")["qualification"],
        "configuration is unavailable"
    );
    fixture
        .store
        .create_record(fixture.store.root(), &name("config.json"), &config)
        .unwrap();
    let fitting = report(&fixture.case.state).unwrap();
    assert_eq!(row(&fitting)["qualified"], true, "{fitting}");
    assert_eq!(profile(&fitting, "upload")["qualified"], true);
    // The stored capacity measured 100 bytes of memory; a `tree_memory` of
    // 64 excludes it.
    let mut values = config.config().clone();
    values.insert(text("tree_memory"), 64);
    fixture
        .store
        .replace_record(
            fixture.store.root(),
            &name("config.json"),
            &crate::record::Configuration::new(values).unwrap(),
        )
        .unwrap();
    let shrunk = report(&fixture.case.state).unwrap();
    assert_eq!(row(&shrunk)["qualified"], false, "{shrunk}");
    assert_eq!(
        row(&shrunk)["reason"],
        "capacity measurements exceed configuration or are missing"
    );
    assert_eq!(profile(&shrunk, "upload")["qualified"], false);
    assert_eq!(
        profile(&shrunk, "upload")["qualification"],
        "capacity measurements exceed configuration or are missing"
    );
    assert!(
        shrunk["held"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| !row["path"].as_str().unwrap().starts_with("capacity/")),
        "{shrunk}"
    );
    fixture
        .store
        .replace_record(fixture.store.root(), &name("config.json"), &config)
        .unwrap();
    std::fs::write(
        fixture.case.state.join("calibrations").join("foreign name"),
        b"damaged",
    )
    .unwrap();
    let withheld = report(&fixture.case.state).unwrap();
    assert_eq!(
        profile(&withheld, "upload")["qualified"],
        false,
        "{withheld}"
    );
    assert!(
        withheld["held"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["path"].as_str().unwrap().starts_with("capacity/")),
        "{withheld}"
    );
    assert_eq!(
        profile(&withheld, "upload")["qualification"],
        "capacity record is held"
    );
    std::fs::remove_file(fixture.case.state.join("calibrations").join("foreign name")).unwrap();
    let scope_path = fixture
        .case
        .state
        .join("capacity")
        .join(capacity.contract().key().to_string());
    std::fs::write(scope_path.join(".stray"), b"damaged").unwrap();
    let unlistable = report(&fixture.case.state).unwrap();
    assert!(
        unlistable["held"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| { row["path"] == format!("capacity/{}", capacity.contract().key()) }),
        "{unlistable}"
    );
    assert_eq!(
        profile(&unlistable, "upload")["qualification"],
        "capacity record is held"
    );
    std::fs::remove_dir_all(&scope_path).unwrap();
    std::fs::write(&scope_path, b"damaged").unwrap();
    let unopenable = report(&fixture.case.state).unwrap();
    assert!(
        unopenable["held"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| { row["path"] == format!("capacity/{}", capacity.contract().key()) }),
        "{unopenable}"
    );
    assert_eq!(
        profile(&unopenable, "upload")["qualification"],
        "capacity record is held"
    );
}
