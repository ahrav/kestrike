use super::*;
use crate::archive::{Built, publish};
use crate::campaign::state_fixture::Sharded;
use crate::campaign::{admission, freeze};
use crate::custody::run_tests::Hosted;
use crate::record::*;
use crate::step::{self, Outcome, Script, Step as Seam};
use crate::store::fixture::{observed, processes, scripted};
use crate::store::{Store, View};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

struct Fixture {
    host: Hosted,
    store: Store,
    archive: std::path::PathBuf,
    id: String,
    finding: Finding,
    config: Configuration,
}
impl Fixture {
    fn new(index: usize) -> Self {
        Self::for_purpose(index, Purpose::Campaign)
    }
    fn for_purpose(index: usize, purpose: Purpose) -> Self {
        let host = Hosted::new(index);
        let digest = Digest::of(b"fixture");
        let executable = crate::store::canonical_host(std::path::Path::new("/bin/true")).unwrap();
        let built = Built {
            identity: crate::store::open_host(&executable).unwrap().identity(),
            executable,
            lock: b"version = 4\n".to_vec(),
            provenance: Provenance {
                cargo: text("cargo").unwrap(),
                command: text("test").unwrap(),
                dirty: false,
                environment: BTreeMap::new(),
                native: Native {
                    install_record: text("native").unwrap(),
                    install_record_sha256: digest,
                    link_plan_sha256: digest,
                    package: text("worker").unwrap(),
                },
                revision: text(&"a".repeat(40)).unwrap(),
                target: text("x86_64-unknown-linux-gnu").unwrap(),
                toolchain: text("rustc 1.99.0").unwrap(),
                untracked: 0,
            },
        };
        let archive = host.case.root.join("archive");
        let pins = publish(&archive, &built).unwrap().pins();
        let listing = crate::protocol::Listing::parse(include_str!(
            "../../../testdata/admission-listing.txt"
        ))
        .unwrap();
        let store = Store::open(&host.case.state).unwrap();
        let request = crate::campaign::Request {
            profile: text("upload").unwrap(),
            campaign: text(if purpose == Purpose::Calibration {
                "calibration"
            } else {
                "triage"
            })
            .unwrap(),
            run: 1,
            attempts: 1,
            counts: BTreeMap::new(),
        };
        let _ = freeze::freeze(&listing, pins.clone(), &request).unwrap();
        let admission = admission::admit(
            &store,
            &listing,
            pins,
            text(archive.to_str().unwrap()).unwrap(),
            &request,
            purpose,
        )
        .unwrap()
        .record;
        let id = if purpose == Purpose::Calibration {
            format!("{}-calibration-replay-0001", admission.job().id())
        } else {
            format!("{}-0001", admission.job().id())
        };
        let jobs = store.shard_jobs(admission.job().id()).unwrap().unwrap();
        let manifest = store
            .read(
                &jobs,
                &name(&format!("{}.manifest", admission.job().id())),
                BOUND,
            )
            .unwrap()
            .unwrap();
        let artifact = Artifact {
            archive: Digest::parse(admission.job().experiment().pins.build.as_str()),
            archive_path: Some(admission.archive().clone()),
            bundle: Some(Digest::of(b"bundle")),
            class: text("complete").unwrap(),
            command: text(if purpose == Purpose::Calibration {
                "replay"
            } else {
                "run"
            })
            .unwrap(),
            comparison: None,
            manifest: Some(admission.job().manifest_sha256()),
            output: None,
            reason: text("violation").unwrap(),
            run_id: text(&id).unwrap(),
            session: None,
            session_original: None,
            summary: Some(Self::summary("v1:original", false)),
            workers: BTreeMap::new(),
        };
        let attempt = Attempt {
            attempt: text(&id).unwrap(),
            file_bytes: 1 << 20,
            job: admission.job().id().digest(),
            manifest: admission.job().manifest_sha256(),
            number: 1,
        };
        let finished = Finished {
            attempt: text(&id).unwrap(),
            binding: Binding::Matching,
            bound: Some(BoundEvidence {
                artifact: digest,
                attempt: text(&id).unwrap(),
                bundle: artifact.bundle,
            }),
            class: Class::Violation,
            exit: Some(1),
            interruption: None,
            kernel: Default::default(),
            residual_members: false,
            signal: None,
            watchdog: false,
        };
        let finding = Finding {
            child: None,
            parent_attempt: None,
            calibration_root: (purpose == Purpose::Calibration)
                .then_some(admission.job().id().digest()),
            admission,
            artifact: Some(artifact),
            attempt,
            finished,
            kind: FindingKind::Violation,
        };
        store.mkdir(store.root(), &name("findings")).unwrap();
        let root = store
            .open_dir(store.root(), &name("findings"))
            .unwrap()
            .unwrap();
        store.mkdir(&root, &name(&id)).unwrap();
        let directory = store.open_dir(&root, &name(&id)).unwrap().unwrap();
        store
            .create_once(&directory, &name("manifest"), manifest.bytes())
            .unwrap();
        store
            .create_once(&directory, &name("bundle"), b"bundle")
            .unwrap();
        store
            .create_record(&directory, &name("finding.json"), &finding)
            .unwrap();
        if purpose == Purpose::Calibration {
            store
                .create_once(&directory, &name("input"), b"bundle")
                .unwrap();
        }
        let config = Configuration::new(
            [
                ("slots", 1),
                ("reserve_slots", 1),
                ("cores", 2),
                ("memory", 256 << 20),
                ("cpu", 60),
                ("tree_memory", 32 << 20),
                ("attempt_output", 1 << 20),
                ("attempt_inodes", 100),
                ("wall", 2),
                ("processes", 16),
                ("artifact_bytes", 64 << 20),
                ("artifact_inodes", 10000),
                ("backlog", 1),
                ("retained_builds", 1),
            ]
            .into_iter()
            .map(|(key, value)| (text(key).unwrap(), value))
            .collect(),
        )
        .unwrap();
        store
            .create_record(store.root(), &name("config.json"), &config)
            .unwrap();
        Self {
            host,
            store,
            archive,
            id,
            finding,
            config,
        }
    }
    fn summary(identity: &str, pass: bool) -> Summarized {
        Summarized {
            cause: None,
            counts: pass,
            decisions: Some(2),
            digest: Digest::of(b"semantic"),
            first_failure: Some(Event {
                node: None,
                operation: None,
                record: text("ff").unwrap(),
                semantic_record: 4,
                virtual_us: Some(10),
            }),
            identity: (!pass).then(|| text(identity).unwrap()),
            ledger: None,
            terminal: text(if pass {
                "complete pass fired=03 required=03"
            } else {
                "complete violation fired=03 required=03"
            })
            .unwrap(),
            unsuccessful: None,
        }
    }
    fn launch(&self, kind: StepKind, status: &str, number: u64) -> crate::attempt::Launch {
        let directory = self.host.case.root.join(format!("output-{number}"));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let output = Store::open(&directory).unwrap();
        let mut artifact = self.finding.artifact.clone().unwrap();
        artifact.command = text(kind.command()).unwrap();
        artifact.run_id = text(&format!("{}-triage-{number:04}", self.id)).unwrap();
        artifact.class = text(if status == "pass" {
            "counts"
        } else {
            "complete"
        })
        .unwrap();
        artifact.summary = Some(Self::summary(
            if status == "different" {
                "v1:different"
            } else {
                "v1:original"
            },
            status == "pass",
        ));
        if status == "reproduced" && kind != StepKind::Rerun {
            artifact.summary = self.finding.artifact.as_ref().unwrap().summary.clone();
        }
        if kind != StepKind::Rerun {
            artifact.comparison = Some(Comparison {
                candidate: None,
                divergence: Some(Difference {
                    committed: self
                        .finding
                        .artifact
                        .as_ref()
                        .unwrap()
                        .summary
                        .as_ref()
                        .and_then(|summary| summary.first_failure.clone()),
                    replayed: Some(Event {
                        node: (status == "diverged").then_some(7),
                        operation: (status == "diverged").then(|| text("commit").unwrap()),
                        record: text("fe").unwrap(),
                        semantic_record: 4,
                        virtual_us: Some(11),
                    }),
                }),
                failure_identity: Some(text("v1:original").unwrap()),
                failure_kind: Some(text("violation").unwrap()),
                observed: artifact.summary.clone(),
                original: self.finding.artifact.as_ref().unwrap().summary.clone(),
                output: None,
                status: text(status).unwrap(),
            });
        }
        if let Some(comparison) = artifact.comparison.as_mut() {
            if status == "reproduced" || status == "reduced" {
                comparison.divergence = None;
            }
            if kind == StepKind::Reduce {
                comparison.status = text("reduced").unwrap();
                comparison.failure_identity = artifact.summary.as_ref().unwrap().identity.clone();
                comparison.candidate = Some(Digest::of(b"b"));
                comparison.output = Some(
                    text(
                        self.store
                            .path()
                            .join("triage")
                            .join(&self.id)
                            .join("steps")
                            .join(format!("{number:04}"))
                            .join("reduced/regression.bundle")
                            .to_str()
                            .unwrap(),
                    )
                    .unwrap(),
                );
            }
        }
        for phase in ["run", "inspect"] {
            artifact.workers.insert(
                text(phase).unwrap(),
                Worker {
                    ended: text("exited").unwrap(),
                    exit: Some(if status == "pass" { 0 } else { 1 }),
                    signal: None,
                    stderr: Digest::of(b""),
                    stdout: Digest::of(b""),
                },
            );
            for stream in ["stdout", "stderr"] {
                output
                    .create_once(output.root(), &name(&format!("{phase}.{stream}")), b"")
                    .unwrap();
            }
        }
        let retained = executor::retained(&self.store, &self.id).unwrap();
        let manifest = self
            .store
            .read(&retained, &name("manifest"), BOUND)
            .unwrap()
            .unwrap();
        output
            .create_once(output.root(), &name("manifest"), manifest.bytes())
            .unwrap();
        if kind == StepKind::Reduce {
            output
                .create_once(output.root(), &name("candidate.manifest"), manifest.bytes())
                .unwrap();
        }
        output
            .create_once(
                output.root(),
                &name(if kind == StepKind::Rerun {
                    "bundle"
                } else {
                    "input"
                }),
                b"bundle",
            )
            .unwrap();
        if kind == StepKind::Reduce {
            let canonical = std::str::from_utf8(manifest.bytes())
                .unwrap()
                .lines()
                .filter(|line| !line.starts_with("cpu = "))
                .map(|line| format!("{line}\n"))
                .collect::<String>();
            let mut bundle = vec![0u8; 48];
            bundle[0] = 1;
            for chunk in canonical.as_bytes().chunks(43) {
                let mut record = [0u8; 48];
                record[0] = 2;
                record[1] = 1;
                record[4] = chunk.len() as u8;
                record[5..5 + chunk.len()].copy_from_slice(chunk);
                bundle.extend_from_slice(&record);
            }
            let mut body = [0u8; 48];
            body[0] = 3;
            bundle.extend_from_slice(&body);
            output
                .create_once(output.root(), &name("candidate.bundle"), &bundle)
                .unwrap();
            output
                .replace(
                    output.root(),
                    &name("candidate.manifest"),
                    &crate::sim::worker_manifest(&canonical),
                )
                .unwrap();
            artifact.comparison.as_mut().unwrap().candidate = Some(Digest::of(&bundle));
        }
        output
            .create_record(output.root(), &name("artifact"), &artifact)
            .unwrap();
        drop(output);
        let reduction = if kind == StepKind::Reduce {
            format!(
                "mkdir -m700 reduced; cp '{0}/candidate.bundle' reduced/regression.bundle; cp '{0}/candidate.manifest' reduced/regression.manifest\n",
                directory.display()
            )
        } else {
            String::new()
        };
        let launcher = self.host.case.root.join(format!("launcher-{number}"));
        fs::write(&launcher, format!("#!/bin/sh\nprintf '%s\\n' \"$@\" > argv\nwhile [ $# -gt 0 ]; do case \"$1\" in --artifacts) out=$2; shift;; --run-id) id=$2; shift;; esac; shift; done\nmkdir -m700 -p \"$out/$id\"\ncp '{}'/* \"$out/$id/\"\n{reduction}[ ! -f '{}' ] || {{ touch worker-seam; while [ ! -f release ]; do sleep 0.001; done; }}\nexit {}\n", directory.display(), self.host.case.root.join("stall").display(), if status == "pass" { 0 } else if status == "interrupted" { 5 } else if status == "incomplete" { 4 } else { 1 })).unwrap();
        fs::set_permissions(&launcher, fs::Permissions::from_mode(0o700)).unwrap();
        let gate = self.host.case.root.join("gate-script");
        fs::write(
            &gate,
            "#!/bin/sh\nIFS= read -r go\n[ \"$go\" = G ] || exit 125\nshift; shift\nexec \"$@\"\n",
        )
        .unwrap();
        fs::set_permissions(&gate, fs::Permissions::from_mode(0o700)).unwrap();
        crate::attempt::Launch {
            gate,
            launcher,
            environment: BTreeMap::new(),
            limits: crate::campaign::configuration::limits(&self.config),
        }
    }
    fn run(
        &self,
        custody: &mut crate::custody::Custody,
        kind: StepKind,
        status: &str,
        number: u64,
    ) -> TriageResult {
        let (step, running) = start(
            &self.store,
            custody,
            Request {
                id: &self.id,
                kind,
                archive: None,
            },
            &self.config,
            self.launch(kind, status, number),
            0,
        )
        .unwrap();
        step.finish(
            &self.store,
            custody.wait_any(vec![running]).unwrap().stopped,
        )
        .unwrap()
    }
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn rerun_pass_and_another_identity_stay_unresolved() {
    let _processes = processes();
    let f = Fixture::new(21001);
    let mut custody = f.host.custody(Duration::from_secs(1));
    let pass = f.run(&mut custody, StepKind::Rerun, "pass", 1);
    assert_eq!(pass.status, Some(ReplayStatus::Unreproduced));
    let different = f.run(&mut custody, StepKind::Rerun, "different", 2);
    assert_eq!(different.status, Some(ReplayStatus::Diverged));
    assert_eq!(
        history::finding(&f.store, &f.id).unwrap().record(),
        &f.finding
    );
    let view = View::open(f.store.path()).unwrap();
    let directory = crate::campaign::findings::directory(&view, &f.id).unwrap();
    assert!(
        crate::campaign::findings::history(&view, &directory, &f.id, &f.finding)
            .unwrap()
            .is_empty()
    );
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn replay_preserves_location_facts_and_publishes_create_once_candidate() {
    let _processes = processes();
    let f = Fixture::new(21002);
    let mut custody = f.host.custody(Duration::from_secs(1));
    let result = f.run(&mut custody, StepKind::Replay, "diverged", 1);
    assert_eq!(result.status, Some(ReplayStatus::Diverged));
    let difference = result
        .comparison
        .as_ref()
        .unwrap()
        .divergence
        .as_ref()
        .unwrap();
    assert_eq!(difference.committed.as_ref().unwrap().node, None);
    assert_eq!(difference.committed.as_ref().unwrap().operation, None);
    assert_eq!(difference.replayed.as_ref().unwrap().node, Some(7));
    assert_eq!(
        difference
            .replayed
            .as_ref()
            .unwrap()
            .operation
            .as_ref()
            .unwrap()
            .as_str(),
        "commit"
    );
    assert_eq!(
        f.run(&mut custody, StepKind::Replay, "reproduced", 2)
            .status,
        Some(ReplayStatus::Reproduced)
    );
    let root = history::root(&f.store, &f.id).unwrap().unwrap();
    let directory = f.store.open_dir(&root, &name("0002")).unwrap().unwrap();
    let candidate = f
        .store
        .read_record::<RegressionCandidate>(&directory, &name("candidate"))
        .unwrap()
        .unwrap();
    assert_eq!(
        candidate
            .record()
            .failure_identity
            .as_ref()
            .unwrap()
            .as_str(),
        "v1:original"
    );
    assert!(
        candidate
            .record()
            .command
            .iter()
            .any(|word| word.as_str() == "--from-run")
    );

    let before = candidate.read().bytes().to_vec();
    reconcile(&f.store, &mut custody).unwrap();
    assert_eq!(
        f.store
            .read_record::<RegressionCandidate>(&directory, &name("candidate"))
            .unwrap()
            .unwrap()
            .read()
            .bytes(),
        before
    );
    let state = f.store.path().to_str().unwrap().to_owned();
    let parent = f.store.path().parent().unwrap();
    fs::create_dir(parent.join("alias")).unwrap();
    let lexical = format!(
        "{}/alias/../{}",
        parent.to_str().unwrap(),
        f.store.path().file_name().unwrap().to_str().unwrap()
    );
    let spell =
        |value: &crate::record::Text| text(&value.as_str().replacen(&state, &lexical, 1)).unwrap();
    let mut legacy = candidate.record().clone();
    legacy.input = spell(&legacy.input);
    legacy.command = legacy.command.iter().map(spell).collect();
    assert_ne!(&legacy, candidate.record());
    f.store
        .replace_record(&directory, &name("candidate"), &legacy)
        .unwrap();
    assert!(
        reconcile(&f.store, &mut custody).unwrap().is_empty(),
        "a candidate naming the state directory through `..` binds the same inputs"
    );
    let (faulted, _) = scripted([(0, Outcome::Errno(libc::EIO))], || {
        candidate::same_location(&legacy, candidate.record())
    });
    let error = faulted.unwrap().unwrap_err();
    assert!(
        global(&error),
        "a host fault while resolving the recorded spelling is global: {error}"
    );
    let projected =
        crate::campaign::report::project(&View::open(&f.host.case.state).unwrap()).unwrap();
    assert_eq!(
        projected["regression_candidates"].as_array().unwrap().len(),
        1
    );
    let link = parent.join("link");
    std::os::unix::fs::symlink(f.store.path(), &link).unwrap();
    let alias = |value: &crate::record::Text| {
        text(&value.as_str().replacen(&state, link.to_str().unwrap(), 1)).unwrap()
    };
    let mut linked = candidate.record().clone();
    linked.input = alias(&linked.input);
    linked.command = linked.command.iter().map(alias).collect();
    assert_ne!(&linked, candidate.record());
    f.store
        .replace_record(&directory, &name("candidate"), &linked)
        .unwrap();
    let skipped = reconcile(&f.store, &mut custody).unwrap();
    assert!(
        skipped
            .get(&f.id)
            .is_some_and(|reason| reason.contains("candidate")),
        "a candidate naming the state directory through a symlink is held: {skipped:?}"
    );
    let projected =
        crate::campaign::report::project(&View::open(&f.host.case.state).unwrap()).unwrap();
    assert!(
        projected["regression_candidates"]
            .as_array()
            .unwrap()
            .is_empty(),
        "{projected}"
    );
    fs::create_dir_all(parent.join("nest/elsewhere")).unwrap();
    let detour = parent.join("detour");
    std::os::unix::fs::symlink(parent.join("nest/elsewhere"), &detour).unwrap();
    let detoured = format!(
        "{}/detour/../{}",
        parent.to_str().unwrap(),
        f.store.path().file_name().unwrap().to_str().unwrap()
    );
    let spell =
        |value: &crate::record::Text| text(&value.as_str().replacen(&state, &detoured, 1)).unwrap();
    let mut routed = candidate.record().clone();
    routed.input = spell(&routed.input);
    routed.command = routed.command.iter().map(spell).collect();
    assert_eq!(
        crate::store::lexical(std::path::Path::new(routed.input.as_str())),
        std::path::Path::new(candidate.record().input.as_str()),
        "the detour collapses lexically to the sealed input"
    );
    f.store
        .replace_record(&directory, &name("candidate"), &routed)
        .unwrap();
    let skipped = reconcile(&f.store, &mut custody).unwrap();
    assert!(
        skipped
            .get(&f.id)
            .is_some_and(|reason| reason.contains("candidate")),
        "a candidate whose `..` follows a symlink is held: {skipped:?}"
    );
    f.store
        .replace_record(&directory, &name("candidate"), candidate.record())
        .unwrap();
    assert_eq!(
        f.run(&mut custody, StepKind::Rerun, "pass", 3).status,
        Some(ReplayStatus::Unreproduced)
    );
    let directory = f.store.open_dir(&root, &name("0003")).unwrap().unwrap();
    f.store
        .create_record(&directory, &name("candidate"), candidate.record())
        .unwrap();
    let projected =
        crate::campaign::report::project(&View::open(&f.host.case.state).unwrap()).unwrap();
    assert!(projected["held"].as_array().unwrap().iter().any(|row| {
        row["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("candidate belongs to an ineligible step"))
    }));
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn minted_step_without_result_reports_pending_triage() {
    let _processes = processes();
    let f = Fixture::new(21013);
    let mut custody = f.host.custody(Duration::from_secs(1));
    f.run(&mut custody, StepKind::Replay, "diverged", 1);
    let (step, running) = start(
        &f.store,
        &mut custody,
        Request {
            id: &f.id,
            kind: StepKind::Replay,
            archive: None,
        },
        &f.config,
        f.launch(StepKind::Replay, "reproduced", 2),
        0,
    )
    .unwrap();
    let shown = crate::campaign::findings::findings(f.store.path()).unwrap();
    assert_eq!(
        shown["findings"][0]["triage"],
        serde_json::json!({"state": "pending"})
    );
    step.finish(&f.store, custody.wait_any(vec![running]).unwrap().stopped)
        .unwrap();
    let shown = crate::campaign::findings::findings(f.store.path()).unwrap();
    assert_eq!(shown["findings"][0]["triage"]["latest"]["number"], 2);
    assert_eq!(shown["findings"][0]["triage"]["stalled"], false);
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn listing_holds_a_result_whose_sealed_finish_differs() {
    let _processes = processes();
    let f = Fixture::new(21015);
    let mut custody = f.host.custody(Duration::from_secs(1));
    let result = f.run(&mut custody, StepKind::Replay, "diverged", 1);
    let root = history::root(&f.store, &f.id).unwrap().unwrap();
    let directory = f.store.open_dir(&root, &name("0001")).unwrap().unwrap();
    let mut finished = result.finished.clone();
    finished.exit = Some(0);
    f.store
        .replace_record(&directory, &name("finished"), &finished)
        .unwrap();
    let shown = crate::campaign::findings::findings(f.store.path()).unwrap();
    assert_eq!(
        shown["findings"][0]["triage"],
        serde_json::json!({"held": "triage status binding differs"})
    );
    f.store.delete(&directory, &name("finished")).unwrap();
    let shown = crate::campaign::findings::findings(f.store.path()).unwrap();
    assert_eq!(
        shown["findings"][0]["triage"],
        serde_json::json!({"held": "step finish missing"})
    );
    let projected =
        crate::campaign::report::project(&View::open(&f.host.case.state).unwrap()).unwrap();
    assert_eq!(projected["triage"][0]["state"], "held", "{projected}");
    assert!(
        projected["held"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["path"] == format!("triage/{}/steps/0001", f.id)),
        "{projected}"
    );
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn report_classifies_triage_steps_as_reconciliation_does() {
    let _processes = processes();
    let f = Fixture::new(21023);
    let mut custody = f.host.custody(Duration::from_secs(1));
    let project =
        || crate::campaign::report::project(&View::open(&f.host.case.state).unwrap()).unwrap();
    let held_paths = |projected: &serde_json::Value| {
        projected["held"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["path"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>()
    };
    f.store.mkdir(f.store.root(), &name("triage")).unwrap();
    let triage = f
        .store
        .open_dir(f.store.root(), &name("triage"))
        .unwrap()
        .unwrap();
    f.store.mkdir(&triage, &name(&f.id)).unwrap();
    let foreign = "b".repeat(64) + "-0001";
    f.store.mkdir(&triage, &name(&foreign)).unwrap();
    let projected = project();
    assert_eq!(
        projected["triage"],
        serde_json::json!([{"finding": f.id, "state": "inconclusive", "reason": "triage root holds no step"}]),
        "a triage root without steps is a row and a foreign root is held: {projected}"
    );
    assert_eq!(held_paths(&projected), vec![format!("triage/{foreign}")]);
    fs::remove_dir(f.host.case.state.join("triage").join(&foreign)).unwrap();
    let id_root = f.store.open_dir(&triage, &name(&f.id)).unwrap().unwrap();
    f.store.mkdir(&id_root, &name("steps")).unwrap();
    let projected = project();
    assert_eq!(
        projected["triage"],
        serde_json::json!([{"finding": f.id, "state": "inconclusive", "reason": "triage root holds no step"}]),
        "an empty step history is a row: {projected}"
    );
    assert!(held_paths(&projected).is_empty(), "{projected}");
    f.run(&mut custody, StepKind::Replay, "diverged", 1);
    let root = history::root(&f.store, &f.id).unwrap().unwrap();
    let first = f.store.open_dir(&root, &name("0001")).unwrap().unwrap();
    let sealed = f
        .store
        .read_record::<TriageResult>(&first, &name("result"))
        .unwrap()
        .unwrap();
    f.store.delete(&first, &name("result")).unwrap();
    let projected = project();
    assert_eq!(
        projected["triage"][0]["state"], "inconclusive",
        "the newest finished step without a result resumes: {projected}"
    );
    assert_eq!(
        projected["triage"][0]["reason"],
        "step result is unpublished"
    );
    assert!(held_paths(&projected).is_empty(), "{projected}");
    f.store
        .create_once(&first, &name("candidate"), b"damaged")
        .unwrap();
    let projected = project();
    assert_eq!(
        projected["triage"][0]["reason"], "unpublished step holds a candidate record",
        "a candidate beside an unpublished result holds: {projected}"
    );
    assert_eq!(
        held_paths(&projected),
        vec![format!("triage/{}/steps/0001", f.id)]
    );
    f.store.delete(&first, &name("candidate")).unwrap();
    let dependencies = f
        .store
        .read_record::<ReplayDependencies>(&first, &name("dependencies"))
        .unwrap()
        .unwrap();
    f.store.delete(&first, &name("dependencies")).unwrap();
    let projected = project();
    assert_eq!(
        projected["triage"][0]["reason"], "launched step lacks input commit marker",
        "a finished step without its input commit marker holds: {projected}"
    );
    assert_eq!(
        held_paths(&projected),
        vec![format!("triage/{}/steps/0001", f.id)]
    );
    f.store
        .create_record(&first, &name("dependencies"), dependencies.record())
        .unwrap();
    f.store
        .create_record(&first, &name("result"), sealed.record())
        .unwrap();
    let (step, running) = start(
        &f.store,
        &mut custody,
        Request {
            id: &f.id,
            kind: StepKind::Replay,
            archive: None,
        },
        &f.config,
        f.launch(StepKind::Replay, "reproduced", 2),
        0,
    )
    .unwrap();
    let second = f.store.open_dir(&root, &name("0002")).unwrap().unwrap();
    let held_step = format!("triage/{}/steps/0002", f.id);
    f.store.delete(&second, &name("reservation")).unwrap();
    let projected = project();
    assert_eq!(projected["triage"][1]["state"], "held", "{projected}");
    assert_eq!(
        projected["triage"][1]["reason"],
        "unfinished step lacks reservation"
    );
    assert_eq!(held_paths(&projected), vec![held_step.clone()]);
    f.store.delete(&second, &name("dependencies")).unwrap();
    let projected = project();
    assert_eq!(
        projected["triage"][1]["reason"],
        "launched step lacks input commit marker"
    );
    assert_eq!(held_paths(&projected), vec![held_step.clone()]);
    for record in ["finished", "result"] {
        f.store.delete(&first, &name(record)).unwrap();
    }
    let projected = project();
    assert_eq!(
        projected["triage"][0]["reason"], "unfinished step precedes a later step",
        "an unfinished step below the newest is damage: {projected}"
    );
    assert_eq!(
        held_paths(&projected),
        vec![format!("triage/{}/steps/0001", f.id), held_step]
    );
    let stopped = custody.wait_any(vec![running]).unwrap().stopped;
    assert!(step.finish(&f.store, stopped).is_err());
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn listing_holds_a_pending_step_whose_token_names_another_finding() {
    let _processes = processes();
    let f = Fixture::new(21016);
    let mut custody = f.host.custody(Duration::from_secs(1));
    f.run(&mut custody, StepKind::Replay, "diverged", 1);
    let root = history::root(&f.store, &f.id).unwrap().unwrap();
    let first = f.store.open_dir(&root, &name("0001")).unwrap().unwrap();
    let mut step = f
        .store
        .read_record::<TriageStep>(&first, &name("step"))
        .unwrap()
        .unwrap()
        .record()
        .clone();
    step.attempt.number = 2;
    step.attempt.attempt = text(&format!("{}-triage-0002", f.id)).unwrap();
    step.finding = text("another").unwrap();
    f.store.mkdir(&root, &name("0002")).unwrap();
    let second = f.store.open_dir(&root, &name("0002")).unwrap().unwrap();
    f.store
        .create_record(&second, &name("step"), &step)
        .unwrap();
    let shown = crate::campaign::findings::findings(f.store.path()).unwrap();
    assert_eq!(
        shown["findings"][0]["triage"],
        serde_json::json!({"held": "triage step binding differs"})
    );
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn listing_binds_every_step_as_selection_does() {
    let _processes = processes();
    let f = Fixture::new(21018);
    let mut custody = f.host.custody(Duration::from_secs(1));
    f.run(&mut custody, StepKind::Replay, "diverged", 1);
    f.run(&mut custody, StepKind::Replay, "reproduced", 2);
    let root = history::root(&f.store, &f.id).unwrap().unwrap();
    let first = f.store.open_dir(&root, &name("0001")).unwrap().unwrap();
    let token = f
        .store
        .read_record::<TriageStep>(&first, &name("step"))
        .unwrap()
        .unwrap()
        .record()
        .clone();
    let mut foreign = token.clone();
    foreign.attempt.manifest = Digest::of(b"other");
    f.store
        .replace_record(&first, &name("step"), &foreign)
        .unwrap();
    let shown = crate::campaign::findings::findings(f.store.path()).unwrap();
    assert_eq!(
        shown["findings"][0]["triage"],
        serde_json::json!({"held": "triage step binding differs"})
    );
    f.store
        .replace_record(&first, &name("step"), &token)
        .unwrap();
    let shown = crate::campaign::findings::findings(f.store.path()).unwrap();
    assert_eq!(shown["findings"][0]["triage"]["latest"]["number"], 2);
    for number in [3u64, 4] {
        let mut minted = token.clone();
        minted.attempt.number = number;
        minted.attempt.attempt = text(&format!("{}-triage-{number:04}", f.id)).unwrap();
        let entry = name(&format!("{number:04}"));
        f.store.mkdir(&root, &entry).unwrap();
        let directory = f.store.open_dir(&root, &entry).unwrap().unwrap();
        f.store
            .create_record(&directory, &name("step"), &minted)
            .unwrap();
    }
    let shown = crate::campaign::findings::findings(f.store.path()).unwrap();
    assert_eq!(
        shown["findings"][0]["triage"],
        serde_json::json!({"held": "step result missing"})
    );
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn late_ancestor_misfit_stops_running_trees_before_rejecting_admission() {
    let _processes = processes();
    let f = Fixture::new(21017);
    let backlog = f.additional_finding(2);
    fs::write(f.host.case.root.join("stall"), b"1").unwrap();
    let mut widened = f.config.config().clone();
    widened.insert(text("reserve_slots").unwrap(), 2);
    widened.insert(text("cores").unwrap(), 3);
    let config = Configuration::new(widened).unwrap();
    f.store
        .replace_record(f.store.root(), &name("config.json"), &config)
        .unwrap();
    let mut custody = f.host.custody(Duration::from_secs(1));
    let (step, mut running) = start(
        &f.store,
        &mut custody,
        Request {
            id: &f.id,
            kind: StepKind::Replay,
            archive: None,
        },
        &config,
        f.launch(StepKind::Replay, "reproduced", 1),
        0,
    )
    .unwrap();
    let shares = config.value("slots") + config.value("reserve_slots");
    fs::write(
        f.host.root.join("memory.max"),
        (shares * config.value("tree_memory")).to_string(),
    )
    .unwrap();
    let rejected = admit(
        &f.store,
        &mut custody,
        Request {
            id: backlog.attempt.attempt.as_str(),
            kind: StepKind::Replay,
            archive: None,
        },
        &config,
        f.launch(StepKind::Replay, "reproduced", 2),
        Occupancy {
            census: &mut Some(crate::campaign::census::Census::count(&f.store).unwrap()),
            steps: 0,
            committed_output: 0,
            running: std::slice::from_mut(&mut running),
        },
    );
    assert!(
        matches!(rejected, Err(Error::Rejected(ref reason)) if reason.contains("ancestor")),
        "{:?}",
        rejected.as_ref().err()
    );
    let waited = custody.wait_any(vec![running]).unwrap();
    assert_eq!(
        waited.stopped.interruption(),
        Some(crate::sys::KILL_SIGNAL as i32),
        "a rejected aggregate fit stops the running trees"
    );
    assert!(!waited.stopped.watchdog());
    step.finish(&f.store, waited.stopped).unwrap();
    fs::write(f.host.root.join("memory.max"), "max").unwrap();
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn archive_drift_and_another_build_refuse_before_step_or_spawn() {
    let _processes = processes();
    let f = Fixture::new(21003);
    let mut custody = f.host.custody(Duration::from_secs(1));
    fs::set_permissions(
        f.archive.join("Cargo.lock"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fs::write(f.archive.join("Cargo.lock"), b"drift").unwrap();
    let mut spawns = 0;
    observed(
        move |step| {
            if step == Seam::Spawn {
                spawns += 1;
                assert_eq!(spawns, 0);
            }
        },
        || {
            assert!(
                start(
                    &f.store,
                    &mut custody,
                    Request {
                        id: &f.id,
                        kind: StepKind::Replay,
                        archive: None
                    },
                    &f.config,
                    f.launch(StepKind::Replay, "reproduced", 1),
                    0
                )
                .is_err()
            );
        },
    );
    assert!(history::root(&f.store, &f.id).unwrap().is_none());
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn lost_started_step_and_exit_five_keep_dependencies_and_clear_status() {
    let _processes = processes();
    let f = Fixture::new(21004);
    let mut custody = f.host.custody(Duration::from_secs(1));
    fs::write(f.host.case.root.join("stall"), b"1").unwrap();
    let (step, running) = start(
        &f.store,
        &mut custody,
        Request {
            id: &f.id,
            kind: StepKind::Replay,
            archive: None,
        },
        &f.config,
        f.launch(StepKind::Replay, "reproduced", 1),
        0,
    )
    .unwrap();
    assert!(
        f.store
            .read_record::<Started>(&step.directory, &name("started"))
            .unwrap()
            .is_some()
    );
    let deps = step.dependencies(&f.store).unwrap();
    drop(running);
    reconcile(&f.store, &mut custody).unwrap();
    let rows = history::results(&f.store, &f.id).unwrap();
    assert_eq!(rows[0].1.state, StepState::Interrupted);
    assert_eq!(rows[0].1.elapsed_ms, None);
    assert_eq!(rows[0].1.status, None);
    assert_eq!(step.dependencies(&f.store).unwrap(), deps);
    assert!(
        f.store
            .read_record::<RegressionCandidate>(&step.directory, &name("candidate"))
            .unwrap()
            .is_none()
    );
    fs::remove_file(f.host.case.root.join("stall")).unwrap();
    let exit = f.run(&mut custody, StepKind::Replay, "interrupted", 2);
    assert_eq!(exit.state, StepState::Interrupted);
    assert_eq!(exit.status, None);
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn started_seam_loss_reconciles_and_two_unchanged_steps_stall() {
    let _processes = processes();
    let f = Fixture::new(21005);
    let mut custody = f.host.custody(Duration::from_secs(1));
    let script = Script {
        nth: Some((Seam::Started, 0, Outcome::Errno(libc::EIO))),
        ..Script::default()
    };
    step::install(Some(script));
    let result = start(
        &f.store,
        &mut custody,
        Request {
            id: &f.id,
            kind: StepKind::Replay,
            archive: None,
        },
        &f.config,
        f.launch(StepKind::Replay, "reproduced", 1),
        0,
    );
    let reached = step::install(None).unwrap().reached;
    assert!(result.is_err());
    assert!(reached.contains(&Seam::Started));
    let root = history::root(&f.store, &f.id).unwrap().unwrap();
    let directory = f.store.open_dir(&root, &name("0001")).unwrap().unwrap();
    assert!(
        f.store
            .read_record::<Started>(&directory, &name("started"))
            .unwrap()
            .is_some()
    );
    reconcile(&f.store, &mut custody).unwrap();
    for number in 2..=2 {
        assert_eq!(
            f.run(&mut custody, StepKind::Replay, "interrupted", number)
                .status,
            None
        );
    }
    assert!(
        start(
            &f.store,
            &mut custody,
            Request {
                id: &f.id,
                kind: StepKind::Replay,
                archive: None
            },
            &f.config,
            f.launch(StepKind::Replay, "reproduced", 3),
            0
        )
        .err()
        .unwrap()
        .to_string()
        .contains("stalled")
    );
    assert_eq!(history::numbers(&f.store, &root, &f.id).unwrap(), [1, 2]);
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn dispatch_replays_findings_on_reserved_capacity_and_serializes_explicit_steps() {
    let _processes = processes();
    let f = Fixture::new(21006);
    let mut custody = f.host.custody(Duration::from_secs(1));
    let launch = f.launch(StepKind::Replay, "reproduced", 1);
    let options = crate::campaign::dispatch::Options {
        archive: f.archive.clone(),
        gate: launch.gate,
        launcher: launch.launcher,
        environment: launch.environment,
        deadline: None,
        max_attempts: Some(0),
    };
    let report = crate::campaign::dispatch::dispatch(&f.store, &mut custody, &options).unwrap();
    assert_eq!(
        report.exit(),
        crate::exit::Supervisor::Success,
        "{report:?}"
    );
    assert_eq!(report.started, 0);
    assert_eq!(report.triage_started, 3);
    assert_eq!(report.counts["triage"], 3);
    assert_eq!(
        report
            .triage_completed
            .iter()
            .map(|result| result.status)
            .collect::<Vec<_>>(),
        vec![
            Some(ReplayStatus::Reproduced),
            Some(ReplayStatus::InsufficientEvidence),
            Some(ReplayStatus::InsufficientEvidence)
        ]
    );
    assert_eq!(
        report.triage_completed[0].status,
        Some(ReplayStatus::Reproduced)
    );
    let root = history::root(&f.store, &f.id).unwrap().unwrap();
    let first = f.store.open_dir(&root, &name("0001")).unwrap().unwrap();
    let record = f
        .store
        .read_record::<TriageStep>(&first, &name("step"))
        .unwrap()
        .unwrap();
    assert_eq!(record.record().kind, StepKind::Replay);
    assert!(
        f.store
            .read_record::<Started>(&first, &name("started"))
            .unwrap()
            .is_some()
    );
    assert!(
        crate::custody::charged(&f.store, &first, &record.record().attempt.attempt)
            .unwrap()
            .is_none()
    );
    let (step, running) = start(
        &f.store,
        &mut custody,
        Request {
            id: &f.id,
            kind: StepKind::Replay,
            archive: None,
        },
        &f.config,
        f.launch(StepKind::Replay, "reproduced", 4),
        0,
    )
    .unwrap();
    let refused = start(
        &f.store,
        &mut custody,
        Request {
            id: &f.id,
            kind: StepKind::Replay,
            archive: None,
        },
        &f.config,
        f.launch(StepKind::Replay, "reproduced", 5),
        0,
    )
    .err()
    .unwrap();
    assert!(refused.to_string().contains("reserve slots"));
    assert_eq!(
        history::numbers(&f.store, &root, &f.id).unwrap(),
        [1, 2, 3, 4]
    );
    step.finish(&f.store, custody.wait_any(vec![running]).unwrap().stopped)
        .unwrap();
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn backlog_hold_stops_ordinary_starts_and_triage_still_replays_the_finding() {
    let _processes = processes();
    let f = Fixture::new(21024);
    let queued = f.additional_job(2);
    // One failure pin without a resolved disposition fills `backlog = 1`,
    // and its finding stays eligible for replay.
    let job = f.finding.admission.job();
    let jobs =
        crate::layout::make_shard(&f.store, crate::layout::JOBS, &job.id().to_string()).unwrap();
    f.store
        .create_record(
            &jobs,
            &name(&format!("{}{}", job.id(), Pin::SUFFIX)),
            &Pin {
                result: JobResult {
                    attempt: 1,
                    finished: f.finding.finished.clone(),
                    job: job.id().digest(),
                    manifest: job.manifest_sha256(),
                },
            },
        )
        .unwrap();
    assert_eq!(crate::campaign::dispatch::backlog(&f.store).unwrap(), 1);
    let mut custody = f.host.custody(Duration::from_secs(1));
    let launch = f.launch(StepKind::Replay, "reproduced", 1);
    let options = crate::campaign::dispatch::Options {
        archive: f.archive.clone(),
        gate: launch.gate,
        launcher: launch.launcher,
        environment: launch.environment,
        deadline: None,
        max_attempts: None,
    };
    let settled = [job.id().to_string()];
    let report =
        crate::campaign::dispatch::run_with_settled(&f.store, &mut custody, &options, &settled)
            .unwrap();
    assert_eq!(report.exit(), crate::exit::Supervisor::Held, "{report:?}");
    assert_eq!(report.state, crate::campaign::dispatch::State::Held);
    assert_eq!(
        report.refusals,
        [
            "backlog holds 1 failure pins without a resolved disposition at limit 1; dispose findings or raise backlog"
        ]
    );
    assert!(report.paused.is_empty(), "{report:?}");
    assert_eq!(report.started, 0);
    assert!(
        !f.host
            .case
            .state
            .join(crate::campaign::state_fixture::attempts_dir(
                queued.job().id().to_string()
            ))
            .exists()
    );
    assert!(report.triage_started >= 1, "{report:?}");
    assert_eq!(
        report.counts["triage"],
        report.triage_completed.len() as u64
    );
    assert_eq!(
        report.counts.values().sum::<u64>(),
        (report.completed.len() + report.triage_completed.len()) as u64
    );
    assert_eq!(
        report.triage_completed.len() as u64,
        report.triage_started,
        "{report:?}"
    );
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn reduction_rejects_another_identity_and_reserve_exhaustion_starts_nothing() {
    let _processes = processes();
    let f = Fixture::new(21007);
    let mut custody = f.host.custody(Duration::from_secs(1));
    let result = f.run(&mut custody, StepKind::Reduce, "different", 1);
    assert_eq!(result.finished.binding, Binding::Matching);
    assert_eq!(
        result.comparison.as_ref().unwrap().status.as_str(),
        "reduced"
    );
    assert_eq!(result.status, Some(ReplayStatus::Diverged));
    let root = history::root(&f.store, &f.id).unwrap().unwrap();
    let first = f.store.open_dir(&root, &name("0001")).unwrap().unwrap();
    assert_eq!(
        fs::read(
            f.store
                .path()
                .join("triage")
                .join(&f.id)
                .join("steps/0001/reduced/regression.bundle")
        )
        .unwrap(),
        fs::read(f.host.case.root.join("output-1/candidate.bundle")).unwrap()
    );
    assert!(
        f.store
            .read_record::<RegressionCandidate>(&first, &name("candidate"))
            .unwrap()
            .is_none()
    );
    let refused = start(
        &f.store,
        &mut custody,
        Request {
            id: &f.id,
            kind: StepKind::Replay,
            archive: None,
        },
        &f.config,
        f.launch(StepKind::Replay, "reproduced", 2),
        f.config.value("artifact_bytes"),
    )
    .err()
    .unwrap();
    assert!(refused.to_string().contains("artifact_bytes"));
    assert_eq!(history::numbers(&f.store, &root, &f.id).unwrap(), [1]);
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn insufficient_rerun_settles_and_incomplete_identity_skips_reduction() {
    let _processes = processes();
    for index in 0..2 {
        let mut f = Fixture::new(21008 + index);
        if index == 0 {
            f.finding.artifact.as_mut().unwrap().bundle = None;
            f.finding.finished.bound.as_mut().unwrap().bundle = None;
        } else {
            f.finding
                .artifact
                .as_mut()
                .unwrap()
                .summary
                .as_mut()
                .unwrap()
                .identity = None;
        }
        if index == 0 {
            assert_eq!(
                verdict::reduction(&f.store, &f.finding).unwrap(),
                Some("triage step needs a retained bundle")
            );
        }
        let retained = executor::retained(&f.store, &f.id).unwrap();
        if index == 0 {
            f.store.delete(&retained, &name("bundle")).unwrap();
        }
        f.store
            .replace_record(&retained, &name("finding.json"), &f.finding)
            .unwrap();
        let kind = if index == 0 {
            StepKind::Rerun
        } else {
            StepKind::Replay
        };
        let launch = f.launch(kind, "reproduced", 1);
        if index == 0 {
            fs::remove_file(f.host.case.root.join("output-1/artifact")).unwrap();
        }
        let options = crate::campaign::dispatch::Options {
            archive: f.archive.clone(),
            gate: launch.gate,
            launcher: launch.launcher,
            environment: launch.environment,
            deadline: None,
            max_attempts: Some(0),
        };
        let mut custody = f.host.custody(Duration::from_secs(1));
        let report = crate::campaign::dispatch::dispatch(&f.store, &mut custody, &options).unwrap();
        assert_eq!(
            report.exit(),
            crate::exit::Supervisor::Success,
            "{report:?}"
        );
        assert_eq!(report.triage_started, 1, "{report:?}");
        assert_eq!(
            report.triage_completed[0].status,
            Some(if index == 0 {
                ReplayStatus::InsufficientEvidence
            } else {
                ReplayStatus::Reproduced
            })
        );
        assert!(
            select(
                &f.store,
                Digest::parse(f.finding.admission.job().experiment().pins.build.as_str()).unwrap(),
                &f.config,
                &Default::default()
            )
            .unwrap()
            .next
            .is_none()
        );
    }
}
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn divergent_reduction_retries_once_then_stalls_until_limits_change() {
    let _processes = processes();
    let mut f = Fixture::new(21010);
    let mut custody = f.host.custody(Duration::from_secs(1));
    let build = Digest::parse(f.finding.admission.job().experiment().pins.build.as_str()).unwrap();
    f.run(&mut custody, StepKind::Replay, "reproduced", 1);
    assert_eq!(
        f.run(&mut custody, StepKind::Reduce, "different", 2).status,
        Some(ReplayStatus::Diverged)
    );
    assert_eq!(
        select(&f.store, build, &f.config, &Default::default())
            .unwrap()
            .next,
        Some((f.id.clone(), StepKind::Reduce))
    );
    assert_eq!(
        f.run(&mut custody, StepKind::Reduce, "different", 3).status,
        Some(ReplayStatus::Diverged)
    );
    assert!(
        select(&f.store, build, &f.config, &Default::default())
            .unwrap()
            .next
            .is_none()
    );
    let mut limits = f.config.config().clone();
    limits.insert(text("wall").unwrap(), 3);
    f.config = Configuration::new(limits).unwrap();
    assert_eq!(
        select(&f.store, build, &f.config, &Default::default())
            .unwrap()
            .next,
        Some((f.id.clone(), StepKind::Reduce))
    );
    assert_eq!(
        f.run(&mut custody, StepKind::Reduce, "different", 4).number,
        4
    );
    let rows = history::results(&f.store, &f.id).unwrap();
    let mut records = vec![rows[0].clone(), rows[1].clone()];
    for status in [ReplayStatus::Reduced, ReplayStatus::Unreducible] {
        records[1].1.status = Some(status);
        assert_eq!(history::next(&f.finding, &records, true), None);
    }
    for status in [
        None,
        Some(ReplayStatus::Diverged),
        Some(ReplayStatus::InsufficientEvidence),
    ] {
        records[1].1.status = status;
        assert_eq!(
            history::next(&f.finding, &records, true),
            Some(StepKind::Reduce)
        );
    }
    for status in [
        ReplayStatus::Diverged,
        ReplayStatus::InsufficientEvidence,
        ReplayStatus::Unreproduced,
        ReplayStatus::Reproduced,
    ] {
        let mut tail = [rows[1].clone(), rows[2].clone()];
        for (step, result) in &mut tail {
            step.limits = f.config.config().clone();
            result.status = Some(status);
        }
        assert!(history::stalled(&tail, &f.config, StepKind::Reduce));
        tail[1].1.status = Some(if status == ReplayStatus::Diverged {
            ReplayStatus::InsufficientEvidence
        } else {
            ReplayStatus::Diverged
        });
        assert!(!history::stalled(&tail, &f.config, StepKind::Reduce));
    }
    for (kind, status, expected) in [
        (
            StepKind::Replay,
            ReplayStatus::InsufficientEvidence,
            Some(StepKind::Rerun),
        ),
        (StepKind::Replay, ReplayStatus::Diverged, None),
        (StepKind::Replay, ReplayStatus::Unreproduced, None),
    ] {
        let mut row = rows[0].clone();
        row.0.kind = kind;
        row.1.status = Some(status);
        assert_eq!(history::next(&f.finding, &[row], true), expected);
    }
    for status in [ReplayStatus::Reduced, ReplayStatus::Unreducible] {
        let mut tail = [rows[1].clone(), rows[2].clone()];
        for (step, result) in &mut tail {
            step.limits = f.config.config().clone();
            result.status = Some(status);
        }
        assert!(!history::stalled(&tail, &f.config, StepKind::Reduce));
    }
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn watchdog_after_started_record_keeps_dependencies_and_clears_replay_status() {
    let _processes = processes();
    let mut f = Fixture::new(21011);
    let mut limits = f.config.config().clone();
    limits.insert(text("wall").unwrap(), 1);
    f.config = Configuration::new(limits).unwrap();
    let mut custody = f.host.custody(Duration::from_secs(1));
    fs::write(f.host.case.root.join("stall"), b"1").unwrap();
    let (step, running) = start(
        &f.store,
        &mut custody,
        Request {
            id: &f.id,
            kind: StepKind::Replay,
            archive: None,
        },
        &f.config,
        f.launch(StepKind::Replay, "reproduced", 1),
        0,
    )
    .unwrap();
    let deps = step.dependencies(&f.store).unwrap();
    assert!(
        f.store
            .read_record::<Started>(&step.directory, &name("started"))
            .unwrap()
            .is_some()
    );
    let directory = f.store.path().join("triage").join(&f.id).join("steps/0001");
    let stopped = custody.wait_any(vec![running]).unwrap().stopped;
    assert!(directory.join("worker-seam").exists());
    let result = step.finish(&f.store, stopped).unwrap();
    assert!(result.finished.watchdog);
    assert_eq!(result.state, StepState::Interrupted);
    assert_eq!(result.status, None);
    assert_eq!(result.comparison, None);
    let root = history::root(&f.store, &f.id).unwrap().unwrap();
    let step = history::load(
        &f.store,
        &root,
        history::finding(&f.store, &f.id).unwrap(),
        1,
    )
    .unwrap();
    assert_eq!(step.dependencies(&f.store).unwrap(), deps);
    assert!(
        f.store
            .read_record::<RegressionCandidate>(&step.directory, &name("candidate"))
            .unwrap()
            .is_none()
    );
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn alternate_build_refuses_before_mint_and_storage_pause_preserves_dispatch() {
    let _processes = processes();
    let f = Fixture::new(21012);
    let alternate = f.host.case.root.join("alternate");
    fs::create_dir(&alternate).unwrap();
    fs::set_permissions(&alternate, fs::Permissions::from_mode(0o700)).unwrap();
    let view = View::open(&f.archive).unwrap();
    let mut build = view
        .read_record::<Build>(view.root(), &name("build"))
        .unwrap()
        .unwrap()
        .record()
        .clone();
    build.provenance.revision = text(&"b".repeat(40)).unwrap();
    let store = Store::open(&alternate).unwrap();
    store
        .create_record(store.root(), &name("build"), &build)
        .unwrap();
    drop(store);
    let mut custody = f.host.custody(Duration::from_secs(1));
    observed(
        |seam| assert_ne!(seam, Seam::Spawn),
        || {
            let error = start(
                &f.store,
                &mut custody,
                Request {
                    id: &f.id,
                    kind: StepKind::Replay,
                    archive: Some(&alternate),
                },
                &f.config,
                f.launch(StepKind::Replay, "reproduced", 1),
                0,
            )
            .err()
            .unwrap();
            assert!(
                matches!(error,Error::Rejected(ref reason) if reason=="another build cannot triage this finding")
            );
        },
    );
    assert!(history::root(&f.store, &f.id).unwrap().is_none());
    let worker = f.archive.join("worker");
    fs::set_permissions(&worker, fs::Permissions::from_mode(0o700)).unwrap();
    std::io::Write::write_all(
        &mut fs::OpenOptions::new().append(true).open(&worker).unwrap(),
        b"drift",
    )
    .unwrap();
    let share = f.config.charge().bytes;
    let mut probes = 0;
    while u128::from(
        crate::campaign::census::census(&f.store, &f.config)
            .unwrap()
            .bytes,
    ) + share
        < u128::from(f.config.value("artifact_bytes"))
    {
        // A probe holding an unlisted entry keeps its directory, so the
        // dispatch-owned collect pass cannot lower the fill.
        crate::campaign::state_fixture::probe(&f.store, &format!("probe-fill-{probes}"), 1);
        probes += 1;
    }
    let launch = f.launch(StepKind::Replay, "reproduced", 2);
    let options = crate::campaign::dispatch::Options {
        archive: f.archive.clone(),
        gate: launch.gate,
        launcher: launch.launcher,
        environment: launch.environment,
        deadline: None,
        max_attempts: Some(0),
    };
    let report = crate::campaign::dispatch::dispatch(&f.store, &mut custody, &options).unwrap();
    assert_eq!(
        report.exit(),
        crate::exit::Supervisor::Success,
        "{report:?}"
    );
    assert!(report.paused.contains("artifact_bytes"));
    assert_eq!(
        (report.collect_passes, report.collect_finished),
        (1, Some(false))
    );
    assert_eq!(report.triage_started, 0);
    assert!(report.refusals.is_empty() && report.rejections.is_empty());
    // With no attempt limit the ordinary queue empties first, and the
    // triage storage pause names the window's state.
    let unlimited = crate::campaign::dispatch::Options {
        max_attempts: None,
        ..options
    };
    let settled = [f.id.rsplit_once('-').unwrap().0.to_owned()];
    let report =
        crate::campaign::dispatch::run_with_settled(&f.store, &mut custody, &unlimited, &settled)
            .unwrap();
    assert_eq!(
        report.exit(),
        crate::exit::Supervisor::Success,
        "{report:?}"
    );
    assert_eq!(
        report.state,
        crate::campaign::dispatch::State::Paused,
        "{report:?}"
    );
    assert!(report.paused.contains("artifact_bytes"), "{report:?}");
    assert_eq!((report.started, report.triage_started), (0, 0));
    assert_eq!(
        (report.collect_passes, report.collect_finished),
        (1, Some(false))
    );
    let before = crate::store::fixture::snapshot(f.store.path());
    let error = execute(
        &f.store,
        &mut custody,
        &f.id,
        StepKind::Replay,
        None,
        &f.config,
        f.launch(StepKind::Replay, "reproduced", 3),
    )
    .unwrap_err();
    assert!(matches!(error,Error::Rejected(ref reason) if reason.contains("artifact_bytes")));
    assert_eq!(crate::store::fixture::snapshot(f.store.path()), before);
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn missing_input_commit_resumes_and_unrecorded_mint_holds_only_its_finding() {
    let _processes = processes();
    for index in 0..2 {
        let f = Fixture::new(21013 + index);
        let mut custody = f.host.custody(Duration::from_secs(1));
        f.store.mkdir(f.store.root(), &name("triage")).unwrap();
        let triage = f
            .store
            .open_dir(f.store.root(), &name("triage"))
            .unwrap()
            .unwrap();
        f.store.mkdir(&triage, &name(&f.id)).unwrap();
        let directory = f.store.open_dir(&triage, &name(&f.id)).unwrap().unwrap();
        assert!(reconcile(&f.store, &mut custody).unwrap().is_empty());
        assert_eq!(history::reserved(&f.store).unwrap(), 0);
        f.store.mkdir(&directory, &name("steps")).unwrap();
        let steps = f
            .store
            .open_dir(&directory, &name("steps"))
            .unwrap()
            .unwrap();
        f.store.mkdir(&steps, &name("0001")).unwrap();
        let directory = f.store.open_dir(&steps, &name("0001")).unwrap().unwrap();
        if index == 0 {
            let attempt = Attempt {
                attempt: text(&format!("{}-triage-0001", f.id)).unwrap(),
                file_bytes: f.config.file_bytes(),
                job: f.finding.attempt.job,
                manifest: f.finding.attempt.manifest,
                number: 1,
            };
            f.store
                .create_record(
                    &directory,
                    &name("step"),
                    &TriageStep {
                        attempt,
                        finding: text(&f.id).unwrap(),
                        kind: StepKind::Replay,
                        launcher: text("/bin/true").unwrap(),
                        limits: f.config.config().clone(),
                    },
                )
                .unwrap();
            assert!(reconcile(&f.store, &mut custody).unwrap().is_empty());
            let result = f
                .store
                .read_record::<TriageResult>(&directory, &name("result"))
                .unwrap()
                .unwrap();
            assert_eq!(result.record().state, StepState::Interrupted);
            assert_eq!(result.record().status, None);
            assert!(
                f.store
                    .read_record::<ReplayDependencies>(&directory, &name("dependencies"))
                    .unwrap()
                    .is_some()
            );
        } else {
            let skipped = reconcile(&f.store, &mut custody).unwrap();
            assert!(skipped[&f.id].contains("step record missing"));
            assert!(f.store.open_dir(&steps, &name("0001")).unwrap().is_some());
            let launch = f.launch(StepKind::Replay, "reproduced", 1);
            let report = crate::campaign::dispatch::dispatch(
                &f.store,
                &mut custody,
                &crate::campaign::dispatch::Options {
                    archive: f.archive.clone(),
                    gate: launch.gate,
                    launcher: launch.launcher,
                    environment: launch.environment,
                    deadline: None,
                    max_attempts: Some(0),
                },
            )
            .unwrap();
            assert_eq!(report.exit(), crate::exit::Supervisor::Success);
            assert_eq!(report.triage_started, 0);
            assert!(report.triage_skipped[&f.id].contains("step record missing"));
            assert_eq!(history::reserved(&f.store).unwrap(), 0);
        }
    }
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn every_start_sync_cut_reconciles_or_scopes_the_uncommitted_mint() {
    let _processes = processes();
    let f = Fixture::new(21100);
    let mut custody = f.host.custody(Duration::from_secs(1));
    let launch = f.launch(StepKind::Replay, "reproduced", 1);
    step::install(Some(Script::default()));
    let (started, running) = start(
        &f.store,
        &mut custody,
        Request {
            id: &f.id,
            kind: StepKind::Replay,
            archive: None,
        },
        &f.config,
        launch,
        0,
    )
    .unwrap();
    let reached = step::install(None).unwrap().reached;
    let syncs = reached.iter().filter(|seam| **seam == Seam::Sync).count();
    assert!(syncs > 10);
    println!("triage start witness: {syncs} fsync indices injected");
    started
        .finish(&f.store, custody.wait_any(vec![running]).unwrap().stopped)
        .unwrap();
    drop(custody);
    drop(f);
    let (mut held_mint, mut interrupted, mut custody_held) = (0, 0, 0);
    for index in 0..syncs {
        let f = Fixture::new(21101 + index);
        let mut custody = f.host.custody(Duration::from_secs(1));
        let launch = f.launch(StepKind::Replay, "reproduced", 1);
        step::install(Some(Script {
            nth: Some((Seam::Sync, index, Outcome::Errno(libc::EIO))),
            ..Script::default()
        }));
        let result = start(
            &f.store,
            &mut custody,
            Request {
                id: &f.id,
                kind: StepKind::Replay,
                archive: None,
            },
            &f.config,
            launch,
            0,
        );
        let script = step::install(None).unwrap();
        assert!(script.nth.is_none(), "sync {index} was not reached");
        assert!(result.is_err(), "sync {index} accepted a failure");
        drop(custody);
        let Fixture {
            host, store, id, ..
        } = f;
        drop(store);
        let store = Store::open(&host.case.state).unwrap();
        let mut custody = host.custody(Duration::from_secs(1));
        let reconciled = reconcile(&store, &mut custody);
        if let Err(error) = &reconciled {
            custody_held += 1;
            assert!(
                error.to_string().contains("cgroup lacks matching started"),
                "sync {index}: {error}"
            );
            let root = history::root(&store, &id).unwrap().unwrap();
            let directory = store.open_dir(&root, &name("0001")).unwrap().unwrap();
            assert!(
                store
                    .read_record::<ReplayDependencies>(&directory, &name("dependencies"))
                    .unwrap()
                    .is_some()
            );
            assert!(
                store
                    .read_record::<TriageResult>(&directory, &name("result"))
                    .unwrap()
                    .is_none()
            );
            assert!(
                crate::custody::charged(
                    &store,
                    &directory,
                    &text(&format!("{id}-triage-0001")).unwrap()
                )
                .unwrap()
                .is_some()
            );
            continue;
        }
        let skipped = reconciled.unwrap();
        if let Some(root) = history::root(&store, &id).unwrap() {
            let numbers = history::numbers(&store, &root, &id).unwrap();
            if let Some(number) = numbers.last() {
                let directory = store
                    .open_dir(&root, &name(&format!("{number:04}")))
                    .unwrap()
                    .unwrap();
                if store
                    .read_record::<TriageStep>(&directory, &name("step"))
                    .unwrap()
                    .is_none()
                {
                    held_mint += 1;
                    assert!(skipped[&id].contains("step record missing"));
                    assert!(
                        store
                            .open_dir(&root, &name(&format!("{number:04}")))
                            .unwrap()
                            .is_some()
                    );
                } else {
                    interrupted += 1;
                    assert!(skipped.is_empty(), "sync {index}: {skipped:?}");
                    let result = store
                        .read_record::<TriageResult>(&directory, &name("result"))
                        .unwrap()
                        .unwrap();
                    assert_eq!(
                        result.record().state,
                        StepState::Interrupted,
                        "sync {index}"
                    );
                    assert_eq!(result.record().status, None);
                    assert!(
                        store
                            .read_record::<ReplayDependencies>(&directory, &name("dependencies"))
                            .unwrap()
                            .is_some()
                    );
                    assert!(
                        crate::custody::charged(
                            &store,
                            &directory,
                            &result.record().finished.attempt
                        )
                        .unwrap()
                        .is_none()
                    );
                }
            }
        }
    }
    assert!(held_mint > 0 && interrupted > 0 && custody_held > 0);
    let pre_mint = syncs - held_mint - interrupted - custody_held;
    assert!(pre_mint > 0);
    println!(
        "triage start cuts: {pre_mint} pre-mint, {held_mint} held mint, {interrupted} interrupted, {custody_held} custody held"
    );
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn custody_reconcile_failure_with_live_intent_holds_globally() {
    let _processes = processes();
    let f = Fixture::new(21300);
    let mut custody = f.host.custody(Duration::from_secs(1));
    fs::write(f.host.case.root.join("stall"), b"1").unwrap();
    let (started, mut running) = start(
        &f.store,
        &mut custody,
        Request {
            id: &f.id,
            kind: StepKind::Replay,
            archive: None,
        },
        &f.config,
        f.launch(StepKind::Replay, "reproduced", 1),
        0,
    )
    .unwrap();
    let record = f
        .store
        .read_record::<Started>(&started.directory, &name("started"))
        .unwrap()
        .unwrap();
    assert!(
        fs::read_to_string(
            std::path::Path::new(record.record().cgroup.as_str()).join("cgroup.events")
        )
        .unwrap()
        .contains("populated 1")
    );
    step::install(Some(Script {
        nth: Some((Seam::Kill, 0, Outcome::Errno(libc::EPERM))),
        ..Script::default()
    }));
    let held = reconcile(&f.store, &mut custody);
    let script = step::install(None).unwrap();
    assert!(script.nth.is_none());
    assert!(matches!(
        held,
        Err(Error::Custody(_)) | Err(Error::Store(_))
    ));
    assert!(
        f.store
            .read_record::<Finished>(&started.directory, &name("finished"))
            .unwrap()
            .is_none()
    );
    assert!(
        crate::custody::charged(&f.store, &started.directory, started.identity())
            .unwrap()
            .is_some()
    );
    let original = f.store.path().join("findings").join(&f.id);
    let moved = f.host.case.root.join("retained-finding");
    fs::rename(&original, &moved).unwrap();
    assert!(
        matches!(reconcile(&f.store, &mut custody), Err(Error::Custody(ref reason)) if reason.contains("unknown finding"))
    );
    fs::rename(&moved, &original).unwrap();
    running.request_stop();
    started
        .finish(&f.store, custody.wait_any(vec![running]).unwrap().stopped)
        .unwrap();
}

/// Once a step's custody is settled, a stored class that differs from the
/// class its bound evidence derives holds only that step's finding; recovery
/// and dispatch continue.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn quiescent_step_with_a_differing_stored_class_holds_only_its_finding() {
    let _processes = processes();
    let f = Fixture::new(24100);
    let mut custody = f.host.custody(Duration::from_secs(1));
    let (started, running) = start(
        &f.store,
        &mut custody,
        Request {
            id: &f.id,
            kind: StepKind::Replay,
            archive: None,
        },
        &f.config,
        f.launch(StepKind::Replay, "reproduced", 2),
        0,
    )
    .unwrap();
    started
        .finish(&f.store, custody.wait_any(vec![running]).unwrap().stopped)
        .unwrap();
    assert!(reconcile(&f.store, &mut custody).unwrap().is_empty());
    let root = history::root(&f.store, &f.id).unwrap().unwrap();
    let directory = f.store.open_dir(&root, &name("0001")).unwrap().unwrap();
    let mut finished = f
        .store
        .read_record::<Finished>(&directory, &name("finished"))
        .unwrap()
        .unwrap()
        .record()
        .clone();
    finished.class = if finished.class == Class::Violation {
        Class::Inconclusive
    } else {
        Class::Violation
    };
    f.store
        .replace_record(&directory, &name("finished"), &finished)
        .unwrap();
    let skipped = reconcile(&f.store, &mut custody).unwrap();
    assert!(
        skipped[&f.id].contains("stored outcome differs from bound evidence"),
        "{skipped:?}"
    );
    let report = triage_dispatch(&f, &mut custody);
    assert_eq!(report.exit(), crate::exit::Supervisor::Success);
    assert!(report.refusals.is_empty(), "{:?}", report.refusals);
    assert!(report.triage_skipped[&f.id].contains("stored outcome differs"));
    assert_eq!(report.triage_started, 0);
    assert_eq!(history::reserved(&f.store).unwrap(), 0);
}

impl Fixture {
    fn additional_job(&self, run: u64) -> crate::record::Admission {
        let listing = crate::protocol::Listing::parse(include_str!(
            "../../../testdata/admission-listing.txt"
        ))
        .unwrap();
        let archive = crate::archive::Archive::load(&self.archive).unwrap();
        let request = crate::campaign::Request {
            profile: text("upload").unwrap(),
            campaign: text("triage").unwrap(),
            run,
            attempts: 1,
            counts: BTreeMap::new(),
        };
        admission::admit(
            &self.store,
            &listing,
            archive.pins(),
            text(self.archive.to_str().unwrap()).unwrap(),
            &request,
            Purpose::Campaign,
        )
        .unwrap()
        .record
    }
    fn additional_finding(&self, run: u64) -> Finding {
        let admission = self.additional_job(run);
        let mut finding = self.finding.clone();
        let id = format!("{}-0001", admission.job().id());
        let manifest = admission.job().manifest_sha256();
        finding.admission = admission;
        finding.attempt.attempt = text(&id).unwrap();
        finding.attempt.job = finding.admission.job().id().digest();
        finding.attempt.manifest = manifest;
        finding.finished.attempt = text(&id).unwrap();
        finding.finished.bound.as_mut().unwrap().attempt = text(&id).unwrap();
        let artifact = finding.artifact.as_mut().unwrap();
        artifact.run_id = text(&id).unwrap();
        artifact.manifest = Some(manifest);
        let root = self
            .store
            .open_dir(self.store.root(), &name("findings"))
            .unwrap()
            .unwrap();
        self.store.mkdir(&root, &name(&id)).unwrap();
        let directory = self.store.open_dir(&root, &name(&id)).unwrap().unwrap();
        let jobs = self
            .store
            .shard_jobs(finding.admission.job().id())
            .unwrap()
            .unwrap();
        let bytes = self
            .store
            .read(
                &jobs,
                &name(&format!("{}.manifest", finding.admission.job().id())),
                BOUND,
            )
            .unwrap()
            .unwrap();
        self.store
            .create_once(&directory, &name("manifest"), bytes.bytes())
            .unwrap();
        self.store
            .create_once(&directory, &name("bundle"), b"bundle")
            .unwrap();
        self.store
            .create_record(&directory, &name("finding.json"), &finding)
            .unwrap();
        finding
    }
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn selection_ranks_metadata_and_hashes_only_reached_findings() {
    let _processes = processes();
    let mut f = Fixture::new(21301);
    let second = f.additional_finding(2);
    let third = f.additional_finding(3);
    let mut findings = [f.finding.clone(), second, third];
    findings.sort_by_key(|finding| finding.attempt.attempt.clone());
    let lowest = findings[0].attempt.attempt.as_str().to_owned();
    let highest = findings[2].attempt.attempt.as_str().to_owned();
    fs::write(
        f.store
            .path()
            .join("findings")
            .join(&highest)
            .join("bundle"),
        b"changed",
    )
    .unwrap();
    let build = Digest::parse(f.finding.admission.job().experiment().pins.build.as_str()).unwrap();
    let selected = select(&f.store, build, &f.config, &Default::default()).unwrap();
    assert_eq!(selected.next, Some((lowest.clone(), StepKind::Replay)));
    assert!(selected.skipped.is_empty());
    assert!(selected.ineligible.is_empty());
    let foreign = select(
        &f.store,
        Digest::of(b"foreign"),
        &f.config,
        &Default::default(),
    )
    .unwrap();
    assert!(foreign.next.is_none());
    assert_eq!(
        foreign.ineligible,
        findings
            .iter()
            .map(|finding| finding.attempt.attempt.as_str().to_owned())
            .collect()
    );
    f.id = lowest.clone();
    f.finding = findings[0].clone();
    let mut custody = f.host.custody(Duration::from_secs(1));
    f.run(&mut custody, StepKind::Replay, "reproduced", 1);
    assert_eq!(
        select(&f.store, build, &f.config, &Default::default())
            .unwrap()
            .next,
        Some((
            findings[1].attempt.attempt.as_str().to_owned(),
            StepKind::Replay
        ))
    );
    let root = history::root(&f.store, &lowest).unwrap().unwrap();
    let directory = f.store.open_dir(&root, &name("0001")).unwrap().unwrap();
    let candidate = f
        .store
        .read_record::<RegressionCandidate>(&directory, &name("candidate"))
        .unwrap()
        .unwrap()
        .read()
        .bytes()
        .to_vec();
    f.store.delete(&directory, &name("candidate")).unwrap();
    assert!(reconcile(&f.store, &mut custody).unwrap().is_empty());
    assert_eq!(
        f.store
            .read_record::<RegressionCandidate>(&directory, &name("candidate"))
            .unwrap()
            .unwrap()
            .read()
            .bytes(),
        candidate
    );
    let mut wrong = f
        .store
        .read_record::<RegressionCandidate>(&directory, &name("candidate"))
        .unwrap()
        .unwrap()
        .record()
        .clone();
    wrong.finding = text("another").unwrap();
    f.store
        .replace_record(&directory, &name("candidate"), &wrong)
        .unwrap();
    let skipped = reconcile(&f.store, &mut custody).unwrap();
    assert!(skipped[&lowest].contains("candidate differs"));
    fs::write(
        f.store.path().join("findings").join(&lowest).join("bundle"),
        b"changed",
    )
    .unwrap();
    let skip = findings[1..]
        .iter()
        .map(|finding| finding.attempt.attempt.as_str().to_owned())
        .collect();
    let selected = select(&f.store, build, &f.config, &skip).unwrap();
    assert!(selected.skipped[&lowest].contains("finding dependency differs"));
    assert!(selected.next.is_none());
    assert_eq!(
        select(&f.store, build, &f.config, &Default::default())
            .unwrap()
            .next,
        Some((
            findings[1].attempt.attempt.as_str().to_owned(),
            StepKind::Replay
        ))
    );
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn malformed_unlaunched_step_skips_only_its_finding_and_healthy_steps_run() {
    let _processes = processes();
    let mut f = Fixture::new(21302);
    let healthy = f.additional_finding(2);
    let held = f.id.clone();
    f.store.mkdir(f.store.root(), &name("triage")).unwrap();
    let triage = f
        .store
        .open_dir(f.store.root(), &name("triage"))
        .unwrap()
        .unwrap();
    f.store.mkdir(&triage, &name(&held)).unwrap();
    let root = f.store.open_dir(&triage, &name(&held)).unwrap().unwrap();
    f.store.mkdir(&root, &name("steps")).unwrap();
    let steps = f.store.open_dir(&root, &name("steps")).unwrap().unwrap();
    f.store.mkdir(&steps, &name("0001")).unwrap();
    let directory = f.store.open_dir(&steps, &name("0001")).unwrap().unwrap();
    f.store
        .create_once(&directory, &name("step"), b"malformed")
        .unwrap();
    f.id = healthy.attempt.attempt.as_str().to_owned();
    f.finding = healthy;
    let launch = f.launch(StepKind::Replay, "reproduced", 1);
    let mut custody = f.host.custody(Duration::from_secs(1));
    let report = crate::campaign::dispatch::dispatch(
        &f.store,
        &mut custody,
        &crate::campaign::dispatch::Options {
            archive: f.archive.clone(),
            gate: launch.gate,
            launcher: launch.launcher,
            environment: launch.environment,
            deadline: None,
            max_attempts: Some(0),
        },
    )
    .unwrap();
    assert_eq!(
        report.exit(),
        crate::exit::Supervisor::Success,
        "{report:?}"
    );
    assert!(report.triage_skipped[&held].contains("JSON"));
    assert!(
        report
            .triage_completed
            .iter()
            .any(|result| result.finding.as_str() == f.id
                && result.status == Some(ReplayStatus::Reproduced))
    );
    assert_eq!(
        f.store
            .read(&directory, &name("step"), 100)
            .unwrap()
            .unwrap()
            .bytes(),
        b"malformed"
    );
}

#[test]
fn stopped_execution_table_requires_interrupted_triage_without_status() {
    for class in Class::ALL {
        for exit in [None, Some(0), Some(1), Some(5), Some(6)] {
            for watchdog in [false, true] {
                for interruption in [None, Some(15)] {
                    let finished = Finished {
                        attempt: text("step").unwrap(),
                        binding: Binding::Missing,
                        bound: None,
                        class: *class,
                        exit,
                        interruption,
                        kernel: Default::default(),
                        residual_members: false,
                        signal: None,
                        watchdog,
                    };
                    let limit = matches!(
                        class,
                        Class::Interrupted
                            | Class::Oom
                            | Class::PidLimit
                            | Class::CpuLimit
                            | Class::MixedLimits
                            | Class::OutputLimit
                            | Class::Watchdog
                    );
                    assert_eq!(
                        finished.interrupted_step(),
                        limit
                            || watchdog
                            || interruption.is_some()
                            || exit.is_none()
                            || exit == Some(5)
                            || exit == Some(6),
                        "{class:?} {exit:?}"
                    );
                    if *class == Class::Oom
                        && exit == Some(1)
                        && !watchdog
                        && interruption.is_none()
                    {
                        let record = TriageResult {
                            comparison: None,
                            elapsed_ms: None,
                            file_limited: false,
                            finding: text("finding").unwrap(),
                            finished,
                            number: 1,
                            output_limited: false,
                            state: StepState::Complete,
                            status: Some(ReplayStatus::Reproduced),
                        };
                        let bytes = serde_json::to_vec(&record).unwrap();
                        assert!(serde_json::from_slice::<TriageResult>(&bytes).is_err());
                    }
                }
            }
        }
    }
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn reduction_finish_sync_cuts_preserve_candidate_inputs_or_interrupted_roots() {
    let _processes = processes();
    let f = Fixture::new(21400);
    let mut custody = f.host.custody(Duration::from_secs(1));
    let (step_value, running) = start(
        &f.store,
        &mut custody,
        Request {
            id: &f.id,
            kind: StepKind::Reduce,
            archive: None,
        },
        &f.config,
        f.launch(StepKind::Reduce, "reduced", 1),
        0,
    )
    .unwrap();
    let stopped = custody.wait_any(vec![running]).unwrap().stopped;
    step::install(Some(Script::default()));
    step_value.finish(&f.store, stopped).unwrap();
    let syncs = step::install(None)
        .unwrap()
        .reached
        .iter()
        .filter(|seam| **seam == Seam::Sync)
        .count();
    assert!(syncs > 10);
    println!("triage reduce finish witness: {syncs} fsync indices injected");
    drop(custody);
    drop(f);
    let (mut interrupted, mut candidates, mut held, mut null_candidates) = (0, 0, 0, 0);
    for index in 0..syncs {
        let f = Fixture::new(21401 + index);
        let mut custody = f.host.custody(Duration::from_secs(1));
        let (step_value, running) = start(
            &f.store,
            &mut custody,
            Request {
                id: &f.id,
                kind: StepKind::Reduce,
                archive: None,
            },
            &f.config,
            f.launch(StepKind::Reduce, "reduced", 1),
            0,
        )
        .unwrap();
        let stopped = custody.wait_any(vec![running]).unwrap().stopped;
        step::install(Some(Script {
            nth: Some((Seam::Sync, index, Outcome::Errno(libc::EIO))),
            ..Script::default()
        }));
        let result = step_value.finish(&f.store, stopped);
        let script = step::install(None).unwrap();
        assert!(script.nth.is_none());
        assert!(result.is_err());
        drop(custody);
        let Fixture {
            host, store, id, ..
        } = f;
        drop(store);
        let store = Store::open(&host.case.state).unwrap();
        let mut custody = host.custody(Duration::from_secs(1));
        let skipped = reconcile(&store, &mut custody).unwrap();
        let root = history::root(&store, &id).unwrap().unwrap();
        let directory = store.open_dir(&root, &name("0001")).unwrap().unwrap();
        assert!(
            store
                .read_record::<ReplayDependencies>(&directory, &name("dependencies"))
                .unwrap()
                .is_some()
        );
        if skipped.contains_key(&id) {
            held += 1;
            assert!(skipped[&id].contains("candidate"));
            continue;
        }
        let result = store
            .read_record::<TriageResult>(&directory, &name("result"))
            .unwrap()
            .unwrap();
        if result.record().state == StepState::Interrupted {
            interrupted += 1;
            assert_eq!(result.record().status, None);
            assert!(
                store
                    .read_record::<RegressionCandidate>(&directory, &name("candidate"))
                    .unwrap()
                    .is_none()
            );
        } else {
            candidates += 1;
            assert_eq!(result.record().status, Some(ReplayStatus::Reduced));
            let candidate = store
                .read_record::<RegressionCandidate>(&directory, &name("candidate"))
                .unwrap()
                .unwrap();
            let expected = fs::read(host.case.root.join("output-1/candidate.bundle")).unwrap();
            assert_eq!(candidate.record().bundle, Some(Digest::of(&expected)));
            assert_eq!(candidate.record().bytes, Some(expected.len() as u64));
            let projection =
                crate::campaign::report::project(&View::open(&host.case.state).unwrap()).unwrap();
            let projected = projection["regression_candidates"]
                .as_array()
                .unwrap()
                .first()
                .unwrap();
            assert_eq!(
                projected,
                &serde_json::json!(candidate.record()),
                "{projection}"
            );
            if result.record().elapsed_ms.is_none() {
                null_candidates += 1;
                assert_eq!(projected["step_ms"], serde_json::Value::Null);
                assert_eq!(projected["tier"], "pinned-corpus");
            }
            let source =
                View::open(std::path::Path::new(candidate.record().input.as_str())).unwrap();
            assert_eq!(
                source
                    .read(source.root(), &name("input"), BOUND)
                    .unwrap()
                    .unwrap()
                    .bytes(),
                expected
            );
            assert_eq!(
                Digest::of(
                    source
                        .read(source.root(), &name("manifest"), BOUND)
                        .unwrap()
                        .unwrap()
                        .bytes()
                ),
                candidate.record().manifest
            );
            let input_name = name(&format!("{}-triage-0001-candidate", id));
            let inputs = store.open_dir(&directory, &input_name).unwrap().unwrap();
            store
                .replace(&inputs, &name("artifact"), b"damaged")
                .unwrap();
            let rejected =
                crate::campaign::report::project(&View::open(&host.case.state).unwrap()).unwrap();
            assert!(
                rejected["regression_candidates"]
                    .as_array()
                    .unwrap()
                    .is_empty()
            );
            assert!(
                rejected["held"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|row| row["path"] == format!("triage/{id}/steps/0001"))
            );
        }
    }
    assert!(
        null_candidates > 0,
        "a reduced candidate has unmeasured elapsed time"
    );
    assert_eq!(held, 0, "every finish cut must converge");
    assert!(
        interrupted > 0 && candidates > 0,
        "outcomes: {interrupted} interrupted, {candidates} candidates, {held} held"
    );
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn explicit_and_dispatch_drains_keep_minted_steps_interrupted() {
    let _processes = processes();
    for index in 0..6 {
        let f = Fixture::new(21600 + index);
        let mut custody = f.host.custody(Duration::from_secs(1));
        let launch = f.launch(StepKind::Replay, "reproduced", 1);
        if index == 0 {
            custody.set_release_deadline(Some(std::time::Instant::now()));
        }
        let signaled = std::rc::Rc::new(std::cell::Cell::new(false));
        let sent = signaled.clone();
        let point = if index == 0 || index == 1 || index == 3 {
            Seam::Census
        } else {
            Seam::Started
        };
        observed(
            move |seam| {
                if index != 0 && seam == point && !sent.get() {
                    sent.set(true);
                    if index == 5 {
                        std::thread::sleep(Duration::from_millis(400));
                    } else {
                        crate::sys::interrupt(libc::SIGTERM).unwrap();
                    }
                }
            },
            || {
                if index < 3 {
                    let outcome = execute(
                        &f.store,
                        &mut custody,
                        &f.id,
                        StepKind::Replay,
                        None,
                        &f.config,
                        launch,
                    )
                    .unwrap();
                    let value = outcome.value();
                    if index == 0 || index == 1 {
                        assert_eq!(
                            value,
                            serde_json::json!({"finding":f.id,"started":false,"state":"drained","status":null})
                        );
                        assert!(history::root(&f.store, &f.id).unwrap().is_none());
                    } else {
                        assert_eq!(value["state"], "interrupted");
                        assert!(value["status"].is_null());
                    }
                } else {
                    let report = crate::campaign::dispatch::dispatch(
                        &f.store,
                        &mut custody,
                        &crate::campaign::dispatch::Options {
                            archive: f.archive.clone(),
                            gate: launch.gate,
                            launcher: launch.launcher,
                            environment: launch.environment,
                            deadline: (index == 5)
                                .then(|| std::time::Instant::now() + Duration::from_millis(200)),
                            max_attempts: Some(0),
                        },
                    )
                    .unwrap();
                    assert_eq!(
                        report.exit(),
                        crate::exit::Supervisor::Success,
                        "{report:?}"
                    );
                    assert!(report.refusals.is_empty());
                    assert_eq!(
                        report.state,
                        if index == 5 {
                            crate::campaign::dispatch::State::Deadline
                        } else {
                            crate::campaign::dispatch::State::Interrupted
                        },
                        "{report:?}"
                    );
                    if index == 3 {
                        assert_eq!(report.triage_started, 0);
                        assert!(report.triage_completed.is_empty());
                        assert!(history::root(&f.store, &f.id).unwrap().is_none());
                    } else {
                        assert_eq!(report.triage_completed[0].state, StepState::Interrupted);
                        assert_eq!(report.triage_completed[0].status, None);
                    }
                }
            },
        );
        assert_eq!(signaled.get(), index != 0);
        if index == 2 || index >= 4 {
            let root = history::root(&f.store, &f.id).unwrap().unwrap();
            let directory = f.store.open_dir(&root, &name("0001")).unwrap().unwrap();
            assert!(
                f.store
                    .read_record::<ReplayDependencies>(&directory, &name("dependencies"))
                    .unwrap()
                    .is_some()
            );
            assert!(
                crate::custody::charged(
                    &f.store,
                    &directory,
                    &text(&format!("{}-triage-0001", f.id)).unwrap()
                )
                .unwrap()
                .is_none()
            );
            assert!(
                !f.store
                    .path()
                    .join("triage")
                    .join(&f.id)
                    .join("steps/0001/worker-seam")
                    .exists()
            );
        }
    }
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn triage_census_bound_is_a_global_hold_before_mint_and_spawn() {
    let _processes = processes();
    let f = Fixture::new(21700);
    let mut custody = f.host.custody(Duration::from_secs(1));
    let census = crate::campaign::census::Census::count(&f.store).unwrap();
    let (shard, jobs) = fs::read_dir(f.store.path().join("jobs"))
        .unwrap()
        .map(|shard| {
            let shard = shard.unwrap();
            (
                shard.file_name().into_string().unwrap(),
                fs::read_dir(shard.path()).unwrap().count(),
            )
        })
        .max_by_key(|(_, entries)| *entries)
        .unwrap();
    let launch = f.launch(StepKind::Replay, "reproduced", 1);
    step::install(Some(Script {
        scan_bound: Some(jobs),
        observe: Some(Box::new(|seam| assert_ne!(seam, Seam::Spawn))),
        ..Script::default()
    }));
    {
        let held = super::admit(
            &f.store,
            &mut custody,
            Request {
                id: &f.id,
                kind: StepKind::Replay,
                archive: None,
            },
            &f.config,
            launch,
            Occupancy {
                census: &mut Some(census),
                steps: 0,
                committed_output: 0,
                running: &mut [],
            },
        );
        let Err(error) = held else {
            panic!("census bound admitted triage");
        };
        assert!(matches!(error, Error::Bound { .. }), "{error}");
        assert_eq!(error.exit(), crate::exit::Supervisor::Held);
        assert!(history::global(&error), "{error}");
        assert_eq!(
            error.to_string(),
            format!("jobs/{shard} holds {jobs} entries at bound {jobs}; collect or shard")
        );
    }
    step::install(None);
    assert!(history::root(&f.store, &f.id).unwrap().is_none());
    fs::create_dir(f.store.path().join("triage")).unwrap();
    for n in 0..33 {
        fs::create_dir(f.store.path().join(format!("triage/retained-{n}"))).unwrap();
    }
    step::install(Some(Script {
        scan_bound: Some(32),
        ..Default::default()
    }));
    let error = history::reserved(&f.store).unwrap_err();
    step::install(None);
    assert_eq!(
        error.to_string(),
        "triage holds more than 32 entries at bound 32; collect or shard"
    );
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn explicit_replay_without_bundle_refuses_without_spawn_mint_or_mutation() {
    let _processes = processes();
    let mut f = Fixture::new(21800);
    f.finding.artifact.as_mut().unwrap().bundle = None;
    f.finding.finished.bound.as_mut().unwrap().bundle = None;
    let directory = executor::retained(&f.store, &f.id).unwrap();
    f.store
        .replace_record(&directory, &name("finding.json"), &f.finding)
        .unwrap();
    let launch = f.launch(StepKind::Replay, "reproduced", 1);
    let mut custody = f.host.custody(Duration::from_secs(1));
    let before = crate::store::fixture::snapshot(f.store.path());
    observed(
        |point| assert_ne!(point, Seam::Spawn),
        || {
            let error = execute(
                &f.store,
                &mut custody,
                &f.id,
                StepKind::Replay,
                None,
                &f.config,
                launch,
            )
            .unwrap_err();
            assert!(
                matches!(error,Error::Rejected(ref reason) if reason=="triage step needs a retained bundle")
            );
        },
    );
    assert!(history::root(&f.store, &f.id).unwrap().is_none());
    assert_eq!(crate::store::fixture::snapshot(f.store.path()), before);
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn explicit_ancestor_limit_refuses_without_spawn_mint_or_mutation() {
    let _processes = processes();
    let mut f = Fixture::new(21801);
    let mut settings = f.config.config().clone();
    settings.insert(text("tree_memory").unwrap(), 2 << 30);
    settings.insert(text("memory").unwrap(), 8 << 30);
    f.config = Configuration::new(settings).unwrap();
    f.store
        .replace_record(f.store.root(), &name("config.json"), &f.config)
        .unwrap();
    fs::write(f.host.root.join("memory.max"), (3u64 << 30).to_string()).unwrap();
    let launch = f.launch(StepKind::Replay, "reproduced", 1);
    let mut custody = f.host.custody(Duration::from_secs(1));
    let expected = format!(
        "aggregate memory limit must be strictly below ancestor {}",
        f.host.root.display()
    );
    let before = crate::store::fixture::snapshot(f.store.path());
    observed(
        |point| assert_ne!(point, Seam::Spawn),
        || {
            let error = execute(
                &f.store,
                &mut custody,
                &f.id,
                StepKind::Replay,
                None,
                &f.config,
                launch,
            )
            .unwrap_err();
            assert!(
                matches!(error,Error::Rejected(ref reason) if reason==&expected),
                "{error:?}"
            );
        },
    );
    assert!(history::root(&f.store, &f.id).unwrap().is_none());
    assert_eq!(crate::store::fixture::snapshot(f.store.path()), before);
}

#[test]
fn step_numbers_refuse_noncanonical_entries_and_gaps() {
    for entry in ["0002", "00001", "0", "bad"] {
        let case = crate::store::fixture::Case::new();
        let store = Store::open(&case.state).unwrap();
        store.mkdir(store.root(), &name("steps")).unwrap();
        let root = store
            .open_dir(store.root(), &name("steps"))
            .unwrap()
            .unwrap();
        assert!(
            history::numbers(&store, &root, "finding")
                .unwrap()
                .is_empty()
        );
        store.mkdir(&root, &name(entry)).unwrap();
        assert!(
            matches!(
                history::numbers(&store, &root, "finding"),
                Err(Error::Held(_))
            ),
            "{entry}"
        );
    }
}

#[test]
fn steps_listings_past_the_scan_bound_name_the_steps_directory() {
    let case = crate::store::fixture::Case::new();
    let store = Store::open(&case.state).unwrap();
    let steps = case.state.join("triage/finding/steps");
    fs::create_dir_all(&steps).unwrap();
    for number in 1..=33 {
        fs::create_dir(steps.join(format!("{number:04}"))).unwrap();
    }
    let root = history::root(&store, "finding").unwrap().unwrap();
    assert_eq!(
        history::numbers(&store, &root, "finding").unwrap().len(),
        33
    );
    assert_eq!(history::reserved(&store).unwrap(), 0);
    step::install(Some(Script {
        scan_bound: Some(32),
        ..Default::default()
    }));
    let held = [
        history::numbers(&store, &root, "finding").map(drop),
        history::reserved(&store).map(drop),
    ];
    step::install(None);
    for error in held {
        let error = error.unwrap_err();
        assert_eq!(
            error.to_string(),
            "triage/finding/steps holds more than 32 entries at bound 32; collect or shard"
        );
        assert!(history::global(&error), "{error}");
    }
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn custody_and_publish_checks_name_a_steps_directory_past_the_scan_bound() {
    let _processes = processes();
    let f = Fixture::new(21750);
    let custody = f.host.custody(Duration::from_secs(1));
    mint_pending_step(&f, 1);
    let root = history::root(&f.store, &f.id).unwrap().unwrap();
    f.store.mkdir(&root, &name("0002")).unwrap();
    let step = history::pending(
        &f.store,
        &root,
        history::finding(&f.store, &f.id).unwrap(),
        1,
    )
    .unwrap();
    assert!(history::custodial_records(&f.store, &custody, &f.id).is_ok());
    step::install(Some(Script {
        scan_bound: Some(1),
        ..Default::default()
    }));
    let custodial = history::custodial_records(&f.store, &custody, &f.id).unwrap_err();
    let token = crate::attempt::Publisher::current_token(&step, &f.store).unwrap_err();
    step::install(None);
    let expected = format!(
        "triage/{}/steps holds more than 1 entries at bound 1; collect or shard",
        f.id
    );
    assert_eq!(custodial.to_string(), expected);
    assert!(history::global(&custodial), "{custodial}");
    assert_eq!(token.to_string(), expected);
    assert_eq!(token.exit(), crate::exit::Supervisor::Held);
}

struct Siblings {
    _case: crate::store::fixture::Case,
    store: Store,
    build: Digest,
    config: Configuration,
    children: Vec<String>,
    others: std::collections::BTreeSet<String>,
}

fn resolved_siblings() -> Siblings {
    use crate::campaign::findings;
    let case = crate::store::fixture::Case::new();
    let store = Store::open(&case.state).unwrap();
    let listing =
        crate::protocol::Listing::parse(include_str!("../../../testdata/admission-listing.txt"))
            .unwrap();
    let build = Digest::of(b"build");
    let ordinary = crate::campaign::admit(
        &store,
        &listing,
        Pins {
            build: text(&build.to_string()).unwrap(),
            executable: text(&Digest::of(b"exe").to_string()).unwrap(),
            platform: text("linux").unwrap(),
            toolchain: text("rustc").unwrap(),
        },
        text("/archive").unwrap(),
        &crate::campaign::Request {
            profile: text("upload").unwrap(),
            campaign: text("c1").unwrap(),
            run: 0,
            attempts: 1,
            counts: Default::default(),
        },
        Purpose::Campaign,
    )
    .unwrap()
    .record;
    let bundle = [0u8; 48];
    let manifest = format!("build = {build}\n");
    let prefix = Digest::of(b"prefix");
    let mut experiment = ordinary.job().experiment().clone();
    experiment.format = 2;
    experiment.target = Some(Target {
        asset: Digest::of(b"asset"),
        boundary: 13,
        build,
        bundle: Digest::of(&bundle),
        bytes: 48,
        decisions: 1,
        form: ForkForm::Branch {
            siblings: 2,
            suffixes: 1,
        },
        manifest: Digest::of(manifest.as_bytes()),
        milestone: text("pending-put").unwrap(),
        prefix,
        root: 1,
        semantic: 5,
    });
    let job = Job::targeted(experiment).unwrap();
    let admission =
        crate::record::Admission::targeted(text("/archive").unwrap(), job.clone(), 1).unwrap();
    let id = job.id().to_string();
    let jobs = crate::layout::make_shard(&store, crate::layout::JOBS, &id).unwrap();
    store
        .create_record(&jobs, &name(&format!("{id}.json")), &admission)
        .unwrap();
    store
        .create_once(&jobs, &name(&format!("{id}.manifest")), manifest.as_bytes())
        .unwrap();
    store
        .create_once(&jobs, &name(&format!("{id}.bundle")), &bundle)
        .unwrap();
    let descend = |parent: &crate::store::Dir, component: &str| {
        store.mkdir(parent, &name(component)).unwrap();
        store.open_dir(parent, &name(component)).unwrap().unwrap()
    };
    let attempt = crate::record::Attempt {
        attempt: text(&format!("{id}-0001")).unwrap(),
        file_bytes: 4096,
        job: job.id().digest(),
        manifest: job.manifest_sha256(),
        number: 1,
    };
    let root = descend(
        &crate::layout::make_shard(&store, crate::layout::ATTEMPTS, &id).unwrap(),
        &id,
    );
    let directory = descend(&root, "0001");
    let evidence = descend(&descend(&directory, "artifacts"), attempt.attempt.as_str());
    let child = Digest::of(b"child");
    let output = format!(
        "milestone: pending-put boundary=13 semantic=5 decisions=1 prefix={prefix}\nwitness: pending-put holds=true boundary=13 upload=attempt:1,grant:3,held:2,outcome:0 armed=false\nparent: reproduced\nchild: suffix=0 sibling=0 class=success digest={child} terminal=complete violation fired=03 required=03\nchild: suffix=0 sibling=1 class=success digest={child} terminal=complete violation fired=03 required=03\nbranch: 2 children, 2 credited, 0 problems\n"
    );
    for (entry, bytes) in [
        ("input", bundle.as_slice()),
        ("manifest", manifest.as_bytes()),
        ("branch.stdout", output.as_bytes()),
        ("branch.stderr", b"".as_slice()),
    ] {
        store.create_once(&evidence, &name(entry), bytes).unwrap();
    }
    let forks = descend(&evidence, "branch");
    for sibling in 0..2 {
        store
            .create_once(
                &forks,
                &name(&format!("suffix-0-{sibling}.bundle")),
                b"child bytes",
            )
            .unwrap();
    }
    let artifact = Artifact {
        archive: Some(build),
        archive_path: None,
        bundle: Some(Digest::of(&bundle)),
        class: text("complete").unwrap(),
        command: text("branch").unwrap(),
        comparison: None,
        manifest: Some(job.manifest_sha256()),
        output: None,
        reason: text("branch").unwrap(),
        run_id: attempt.attempt.clone(),
        session: None,
        session_original: None,
        summary: None,
        workers: [(
            text("branch").unwrap(),
            Worker {
                ended: text("exited").unwrap(),
                exit: Some(0),
                signal: None,
                stderr: Digest::of(b""),
                stdout: Digest::of(output.as_bytes()),
            },
        )]
        .into(),
    };
    store
        .create_record(&evidence, &name("artifact"), &artifact)
        .unwrap();
    let stored = store
        .read_record::<Artifact>(&evidence, &name("artifact"))
        .unwrap()
        .unwrap();
    let bound = BoundEvidence {
        artifact: Digest::of(stored.read().bytes()),
        attempt: attempt.attempt.clone(),
        bundle: artifact.bundle,
    };
    store
        .create_record(&directory, &name("attempt"), &attempt)
        .unwrap();
    store
        .create_record(
            &directory,
            &name("intent"),
            &Intent {
                attempt: attempt.attempt.clone(),
                boot: text("boot").unwrap(),
                cgroup: text(case.state.join("absent-cgroup").to_str().unwrap()).unwrap(),
            },
        )
        .unwrap();
    store
        .create_record(&directory, &name("bound"), &bound)
        .unwrap();
    store
        .create_record(
            &directory,
            &name("finished"),
            &Finished {
                attempt: attempt.attempt.clone(),
                binding: Binding::Matching,
                bound: Some(bound),
                class: Class::Violation,
                exit: Some(1),
                interruption: None,
                kernel: Kernel::default(),
                residual_members: false,
                signal: None,
                watchdog: false,
            },
        )
        .unwrap();
    let value: serde_json::Value =
        serde_json::from_str(include_str!("../../../testdata/configuration.json")).unwrap();
    let config: Configuration = serde_json::from_value(value["record"].clone()).unwrap();
    store
        .create_record(store.root(), &name("config.json"), &config)
        .unwrap();
    let (directory, record, completed) =
        crate::attempt::completed_at(&store, &admission, &root, 1).unwrap();
    crate::attempt::capture(&store, &admission, &completed, &directory, &record, None).unwrap();
    let view = View::open(store.path()).unwrap();
    let mut children = Vec::new();
    let mut others = std::collections::BTreeSet::new();
    for entry in fs::read_dir(case.state.join("findings")).unwrap() {
        let id = entry.unwrap().file_name().into_string().unwrap();
        let retained = findings::directory(&view, &id).unwrap();
        if findings::load(&view, &retained, &id)
            .unwrap()
            .record()
            .parent_attempt
            .is_none()
        {
            others.insert(id);
            continue;
        }
        findings::append(
            &store,
            &view,
            text(&id).unwrap(),
            Decision::Resolved,
            text("evidence").unwrap(),
        )
        .unwrap();
        children.push(id);
    }
    children.sort();
    Siblings {
        _case: case,
        store,
        build,
        config,
        children,
        others,
    }
}

fn steps<T>(op: impl FnOnce() -> T) -> (T, usize) {
    let reached = std::rc::Rc::new(std::cell::Cell::new(0));
    let seen = std::rc::Rc::clone(&reached);
    let result = observed(move |_| seen.set(seen.get() + 1), op);
    (result, reached.get())
}

#[test]
fn resolved_sibling_findings_share_one_parent_verification_per_selection() {
    use crate::campaign::{findings, lineage};
    let f = resolved_siblings();
    let [first, second] = f.children.as_slice() else {
        panic!("the branch captures two children: {:?}", f.children);
    };
    let view = View::open(f.store.path()).unwrap();
    let retained = findings::directory(&view, first).unwrap();
    let finding = findings::load(&view, &retained, first).unwrap();
    let (verified, verification) =
        steps(|| lineage::verify(&view, finding.record(), &Default::default()));
    verified.unwrap();
    assert!(verification > 0);
    let cost = |skipped: &[&String]| {
        let skip = f.others.iter().chain(skipped.iter().copied()).cloned();
        let (selection, cost) = steps(|| select(&f.store, f.build, &f.config, &skip.collect()));
        let selection = selection.unwrap();
        assert!(selection.next.is_none());
        assert!(selection.skipped.is_empty(), "{:?}", selection.skipped);
        assert_eq!(selection.ineligible.len(), 2 - skipped.len());
        cost
    };
    let both = cost(&[]);
    let alone = cost(&[second]) + cost(&[first]);
    let neither = cost(&[first, second]);
    assert_eq!(alone - both - neither, verification);
}

fn changed_artifact_step(
    f: &Fixture,
    custody: &mut crate::custody::Custody,
    kind: StepKind,
    number: u64,
    mutate: impl FnOnce(&mut Artifact),
) -> Result<TriageResult, Error> {
    changed_artifact_step_with(f, custody, kind, "reproduced", number, mutate)
}

fn changed_artifact_step_with(
    f: &Fixture,
    custody: &mut crate::custody::Custody,
    kind: StepKind,
    status: &str,
    number: u64,
    mutate: impl FnOnce(&mut Artifact),
) -> Result<TriageResult, Error> {
    let launch = f.launch(kind, status, number);
    let output = Store::open(&f.host.case.root.join(format!("output-{number}"))).unwrap();
    let mut artifact = output
        .read_record::<Artifact>(output.root(), &name("artifact"))
        .unwrap()
        .unwrap()
        .record()
        .clone();
    mutate(&mut artifact);
    if artifact.workers.contains_key(&text("replay").unwrap()) {
        output
            .create_once(output.root(), &name("replay.stdout"), b"")
            .unwrap();
        output
            .create_once(output.root(), &name("replay.stderr"), b"")
            .unwrap();
    }
    output
        .replace_record(output.root(), &name("artifact"), &artifact)
        .unwrap();
    drop(output);
    let (step, running) = start(
        &f.store,
        custody,
        Request {
            id: &f.id,
            kind,
            archive: None,
        },
        &f.config,
        launch,
        0,
    )
    .unwrap();
    let stopped = custody.wait_any(vec![running]).unwrap().stopped;
    let elapsed = stopped.elapsed_ms();
    std::thread::sleep(Duration::from_millis(3));
    let result = step.finish(&f.store, stopped)?;
    assert_eq!(result.elapsed_ms, elapsed);
    Ok(result)
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn passing_rerun_on_another_archive_is_misbound_not_unreproduced() {
    let _processes = processes();
    let f = Fixture::new(21014);
    let mut custody = f.host.custody(Duration::from_secs(1));
    let result =
        changed_artifact_step_with(&f, &mut custody, StepKind::Rerun, "pass", 1, |artifact| {
            artifact.archive = Some(Digest::of(b"other"))
        })
        .unwrap();
    assert_eq!(result.finished.class, Class::MisboundEvidence);
    assert_eq!(result.status, Some(ReplayStatus::InsufficientEvidence));
    let bound =
        changed_artifact_step_with(&f, &mut custody, StepKind::Rerun, "pass", 2, |_| {}).unwrap();
    assert_eq!(bound.finished.class, Class::Pass);
    assert_eq!(bound.status, Some(ReplayStatus::Unreproduced));
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn unreducible_requires_the_reproduced_baseline() {
    let _processes = processes();
    let f = Fixture::new(21019);
    let mut custody = f.host.custody(Duration::from_secs(1));
    let plain = changed_artifact_step(&f, &mut custody, StepKind::Reduce, 1, |artifact| {
        artifact.comparison.as_mut().unwrap().status = text("unreducible").unwrap();
    })
    .unwrap();
    assert_eq!(plain.status, Some(ReplayStatus::Unreducible));
    let observed = changed_artifact_step(&f, &mut custody, StepKind::Reduce, 2, |artifact| {
        let comparison = artifact.comparison.as_mut().unwrap();
        comparison.status = text("unreducible").unwrap();
        comparison.observed.as_mut().unwrap().digest = Digest::of(b"other");
    })
    .unwrap();
    assert_eq!(observed.status, Some(ReplayStatus::Diverged));
    let diverged = changed_artifact_step(&f, &mut custody, StepKind::Reduce, 3, |artifact| {
        let comparison = artifact.comparison.as_mut().unwrap();
        comparison.status = text("unreducible").unwrap();
        comparison.divergence = Some(fixture_divergence());
    })
    .unwrap();
    assert_eq!(diverged.status, Some(ReplayStatus::Diverged));
    drop(custody);
    let mut source = Fixture::for_purpose(21501, Purpose::Calibration);
    let mut observed = source
        .finding
        .artifact
        .as_ref()
        .unwrap()
        .summary
        .clone()
        .unwrap();
    observed.counts = false;
    observed.terminal = text("complete violation fired=03 required=03").unwrap();
    let mut healthy = observed.clone();
    healthy.counts = true;
    healthy.identity = None;
    healthy.first_failure = None;
    healthy.terminal = text("complete pass fired=03 required=03").unwrap();
    let comparison = Comparison {
        candidate: None,
        divergence: None,
        failure_identity: None,
        failure_kind: None,
        observed: Some(observed),
        original: Some(healthy.clone()),
        output: None,
        status: text("diverged").unwrap(),
    };
    let artifact = source.finding.artifact.as_mut().unwrap();
    artifact.command = text("replay").unwrap();
    artifact.summary = Some(healthy.clone());
    artifact.comparison = Some(comparison.clone());
    let retained = executor::retained(&source.store, &source.id).unwrap();
    let mut bundle = source
        .store
        .open_file(&retained, &name("bundle"))
        .unwrap()
        .unwrap();
    source
        .store
        .copy_once(&retained, &name("input"), &mut bundle, 0o600)
        .unwrap();
    source
        .store
        .replace_record(&retained, &name("finding.json"), &source.finding)
        .unwrap();
    let mut custody = source.host.custody(Duration::from_secs(1));
    let result = changed_artifact_step_with(
        &source,
        &mut custody,
        StepKind::Reduce,
        "diverged",
        1,
        |artifact| {
            artifact.summary = Some(healthy);
            artifact.comparison = Some(comparison);
        },
    )
    .unwrap();
    assert_eq!(result.status, Some(ReplayStatus::Reproduced), "{result:?}");
    let root = history::root(&source.store, &source.id).unwrap().unwrap();
    let directory = source
        .store
        .open_dir(&root, &name("0001"))
        .unwrap()
        .unwrap();
    let candidate = source
        .store
        .read_record::<RegressionCandidate>(&directory, &name("candidate"))
        .unwrap()
        .unwrap();
    assert!(candidate.record().command.windows(3).any(|args| {
        [args[0].as_str(), args[1].as_str(), args[2].as_str()] == ["sim", "replay", "--from-run"]
    }));
    assert!(
        candidate
            .record()
            .command
            .iter()
            .any(|arg| arg.as_str() == "--from-run")
    );
}

fn fixture_divergence() -> Difference {
    Difference {
        committed: None,
        replayed: Some(Event {
            node: Some(7),
            operation: Some(text("commit").unwrap()),
            record: text("fe").unwrap(),
            semantic_record: 4,
            virtual_us: Some(11),
        }),
    }
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn reduced_panic_requires_the_candidate_panic_line() {
    let _processes = processes();
    let mut f = Fixture::new(21021);
    f.finding.kind = FindingKind::Panic;
    f.finding.finished.class = Class::EngineFailure;
    let retained = executor::retained(&f.store, &f.id).unwrap();
    let listing = include_bytes!("../../../testdata/admission-listing.txt");
    let original = b"run: the run panicked at engine.rs:1:1: boom\n";
    for (phase, stdout) in [
        ("capabilities", listing.as_slice()),
        ("run", original.as_slice()),
    ] {
        for (stream, bytes) in [("stdout", stdout), ("stderr", b"".as_slice())] {
            f.store
                .create_once(&retained, &name(&format!("{phase}.{stream}")), bytes)
                .unwrap();
        }
        f.finding.artifact.as_mut().unwrap().workers.insert(
            text(phase).unwrap(),
            Worker {
                ended: text("failed").unwrap(),
                exit: Some(3),
                signal: None,
                stdout: Digest::of(stdout),
                stderr: Digest::of(b""),
            },
        );
    }
    f.store
        .replace_record(&retained, &name("finding.json"), &f.finding)
        .unwrap();
    let mut custody = f.host.custody(Duration::from_secs(1));
    for (number, candidate, expected) in [
        (1, original.as_slice(), ReplayStatus::Reduced),
        (
            2,
            b"run: the run panicked at other.rs:2:2: else\n".as_slice(),
            ReplayStatus::Diverged,
        ),
    ] {
        let output = f.host.case.root.join(format!("output-{number}"));
        let result =
            changed_artifact_step(&f, &mut custody, StepKind::Reduce, number, |artifact| {
                for (phase, stdout) in [
                    ("capabilities", listing.as_slice()),
                    ("panic-candidate", candidate),
                ] {
                    fs::write(output.join(format!("{phase}.stdout")), stdout).unwrap();
                    fs::write(output.join(format!("{phase}.stderr")), b"").unwrap();
                    artifact.workers.insert(
                        text(phase).unwrap(),
                        Worker {
                            ended: text("exited").unwrap(),
                            exit: Some(if phase == "capabilities" { 0 } else { 3 }),
                            signal: None,
                            stdout: Digest::of(stdout),
                            stderr: Digest::of(b""),
                        },
                    );
                }
                let comparison = artifact.comparison.as_mut().unwrap();
                comparison.failure_kind = Some(text("panic").unwrap());
                comparison.failure_identity = Some(text("engine.rs:1:1: boom").unwrap());
            })
            .unwrap();
        assert_eq!(result.status, Some(expected), "step {number}");
    }
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn damaged_evidence_of_a_completed_step_skips_only_its_finding() {
    let _processes = processes();
    let f = Fixture::new(21022);
    let mut custody = f.host.custody(Duration::from_secs(1));
    let result = f.run(&mut custody, StepKind::Replay, "diverged", 1);
    let root = history::root(&f.store, &f.id).unwrap().unwrap();
    let directory = f.store.open_dir(&root, &name("0001")).unwrap().unwrap();
    let mut rejudged = result.clone();
    rejudged.status = Some(ReplayStatus::InsufficientEvidence);
    f.store
        .replace_record(&directory, &name("result"), &rejudged)
        .unwrap();
    let skipped = reconcile(&f.store, &mut custody).unwrap();
    assert!(
        skipped[&f.id].contains("step result differs from evidence"),
        "a sealed status the current judgment does not produce holds its step: {skipped:?}"
    );
    assert_eq!(skipped.len(), 1);
    let projected =
        crate::campaign::report::project(&View::open(&f.host.case.state).unwrap()).unwrap();
    assert!(projected["held"].as_array().unwrap().iter().any(|row| {
        row["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("step result differs from evidence"))
    }));
    f.store
        .replace_record(&directory, &name("result"), &result)
        .unwrap();
    assert!(reconcile(&f.store, &mut custody).unwrap().is_empty());
    let stream = history::step_path(&f.store, &f.id, 1)
        .join("artifacts")
        .join(result.finished.attempt.as_str())
        .join("run.stdout");
    fs::set_permissions(&stream, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&stream, b"changed").unwrap();
    let skipped = reconcile(&f.store, &mut custody).unwrap();
    assert!(skipped.contains_key(&f.id), "{skipped:?}");
    assert_eq!(skipped.len(), 1);
    fs::write(&stream, b"").unwrap();
    let bound = history::step_path(&f.store, &f.id, 1).join("bound");
    fs::set_permissions(&bound, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&bound, b"junk").unwrap();
    let skipped = reconcile(&f.store, &mut custody).unwrap();
    assert!(skipped.contains_key(&f.id), "{skipped:?}");
    assert_eq!(skipped.len(), 1);
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn divergent_reduced_claim_is_diverged_without_a_candidate() {
    let _processes = processes();
    let f = Fixture::new(21020);
    let mut custody = f.host.custody(Duration::from_secs(1));
    let reduced = changed_artifact_step(&f, &mut custody, StepKind::Reduce, 1, |artifact| {
        artifact.comparison.as_mut().unwrap().divergence = Some(fixture_divergence());
    })
    .unwrap();
    assert_eq!(reduced.status, Some(ReplayStatus::Diverged));
    let root = history::root(&f.store, &f.id).unwrap().unwrap();
    let directory = f.store.open_dir(&root, &name("0001")).unwrap().unwrap();
    assert!(
        f.store
            .read_record::<RegressionCandidate>(&directory, &name("candidate"))
            .unwrap()
            .is_none()
    );
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn triage_failure_identity_and_output_limit_controls() {
    let _processes = processes();
    for (index, case) in [
        "abort-replay",
        "abort-replay-fresh",
        "abort-replay-source",
        "abort-replay-identity-bound",
        "abort-replay-identity-oversize",
        "oversize-rerun",
        "missing-panic-rerun-different-kind",
        "replay-unreducible",
        "reduce-wrong-kind",
        "reduce-wrong-identity",
        "reduce-foreign-version",
        "reduce-manifest-only",
        "reduce-missing-candidate",
        "reduce-missing-output",
        "reduce-different-original",
        "replay-different-observed",
        "replay-divergence",
        "reduce-unreducible-wrong-kind",
        "abort-rerun",
        "output-limit",
        "stream-prior-violation",
        "file-prior-violation",
    ]
    .iter()
    .enumerate()
    {
        let mut f = Fixture::for_purpose(
            21900 + index,
            if *case == "abort-replay-source" {
                Purpose::Calibration
            } else {
                Purpose::Campaign
            },
        );
        let kind = if case.starts_with("reduce") {
            StepKind::Reduce
        } else if case.ends_with("rerun") || *case == "missing-panic-rerun-different-kind" {
            StepKind::Rerun
        } else {
            StepKind::Replay
        };
        if *case == "oversize-rerun" || *case == "missing-panic-rerun-different-kind" {
            if *case == "oversize-rerun" {
                f.finding
                    .artifact
                    .as_mut()
                    .unwrap()
                    .summary
                    .as_mut()
                    .unwrap()
                    .identity =
                    Some(text(&"x".repeat((crate::record::BOUND / 16 + 1) as usize)).unwrap());
            } else {
                f.finding.kind = FindingKind::Panic;
                f.finding.artifact.as_mut().unwrap().summary = None;
            }
            let retained = executor::retained(&f.store, &f.id).unwrap();
            f.store
                .replace_record(&retained, &name("finding.json"), &f.finding)
                .unwrap();
        }
        if case.starts_with("abort") {
            f.finding.kind = FindingKind::Abort;
            f.finding.finished.class = Class::Signal;
            if *case == "abort-rerun" {
                f.finding.artifact.as_mut().unwrap().summary = None;
            }
            if matches!(*case, "abort-replay-fresh" | "abort-replay-source")
                || case.starts_with("abort-replay-identity")
            {
                let summary = f
                    .finding
                    .artifact
                    .as_mut()
                    .unwrap()
                    .summary
                    .as_mut()
                    .unwrap();
                summary.identity = if *case == "abort-replay-identity-bound" {
                    Some(text(&"x".repeat((crate::record::BOUND / 16) as usize)).unwrap())
                } else {
                    None
                };
                summary.first_failure = None;
                summary.terminal = text("infrastructure truncated").unwrap();
            }
            let retained = executor::retained(&f.store, &f.id).unwrap();
            if *case == "abort-replay-source" {
                let artifact = f.finding.artifact.as_mut().unwrap();
                artifact.command = text("replay").unwrap();
                artifact.comparison = Some(Comparison {
                    candidate: None,
                    divergence: None,
                    failure_identity: None,
                    failure_kind: None,
                    observed: None,
                    original: artifact.summary.clone(),
                    output: None,
                    status: text("incomplete").unwrap(),
                });
                let mut bundle = f
                    .store
                    .open_file(&retained, &name("bundle"))
                    .unwrap()
                    .unwrap();
                f.store
                    .copy_once(&retained, &name("input"), &mut bundle, 0o600)
                    .unwrap();
            }
            f.store
                .replace_record(&retained, &name("finding.json"), &f.finding)
                .unwrap();
        }
        let mut custody = f.host.custody(Duration::from_secs(1));
        let mutate = |artifact: &mut Artifact| {
            if *case == "abort-rerun"
                || matches!(*case, "abort-replay-fresh" | "abort-replay-source")
                || case.starts_with("abort-replay-identity")
            {
                artifact.summary = if case.starts_with("abort-replay-identity") {
                    f.finding.artifact.as_ref().unwrap().summary.clone()
                } else {
                    None
                };
                if *case == "abort-replay-identity-oversize" {
                    artifact.summary.as_mut().unwrap().identity =
                        Some(text(&"x".repeat((crate::record::BOUND / 16 + 1) as usize)).unwrap());
                }
                let worker = artifact.workers.get_mut(&text("run").unwrap()).unwrap();
                worker.ended = text("signaled").unwrap();
                worker.exit = None;
                worker.signal = Some(6);
                if matches!(*case, "abort-replay-fresh" | "abort-replay-source")
                    || case.starts_with("abort-replay-identity")
                {
                    let replay = worker.clone();
                    artifact.workers.insert(text("replay").unwrap(), replay);
                }
                if *case == "abort-replay-source" {
                    artifact.class = text("incomplete").unwrap();
                    let comparison = artifact.comparison.as_mut().unwrap();
                    comparison.status = text("incomplete").unwrap();
                    comparison.observed = None;
                }
            } else if *case == "oversize-rerun" {
                artifact.summary.as_mut().unwrap().identity = f
                    .finding
                    .artifact
                    .as_ref()
                    .unwrap()
                    .summary
                    .as_ref()
                    .unwrap()
                    .identity
                    .clone();
            } else if *case == "missing-panic-rerun-different-kind" {
            } else if *case == "output-limit" {
                artifact.summary = None;
                let worker = artifact.workers.get_mut(&text("run").unwrap()).unwrap();
                worker.signal = Some(crate::sys::OUTPUT_SIGNAL as u64);
                worker.exit = None;
                artifact
                    .workers
                    .get_mut(&text("run").unwrap())
                    .unwrap()
                    .ended = text("oversized").unwrap();
            } else if *case == "file-prior-violation" {
                artifact
                    .workers
                    .get_mut(&text("run").unwrap())
                    .unwrap()
                    .signal = Some(crate::sys::OUTPUT_SIGNAL as u64);
            } else if *case == "stream-prior-violation" {
                artifact
                    .workers
                    .get_mut(&text("run").unwrap())
                    .unwrap()
                    .ended = text("oversized").unwrap();
            } else {
                let comparison = artifact.comparison.as_mut().unwrap();
                match *case {
                    "abort-replay" => comparison.failure_kind = None,
                    "replay-unreducible" => comparison.status = text("unreducible").unwrap(),
                    "reduce-wrong-kind" => comparison.failure_kind = Some(text("panic").unwrap()),
                    "reduce-manifest-only" => {
                        let path = f.host.case.root.join("output-1/candidate.manifest");
                        let mut manifest = fs::read(&path).unwrap();
                        manifest.push(b'\n');
                        fs::write(path, manifest).unwrap();
                    }
                    "reduce-foreign-version" => {
                        let output = f.host.case.root.join("output-1");
                        let mut stager = crate::sim::Stager::new(std::io::Cursor::new(
                            fs::read(output.join("candidate.bundle")).unwrap(),
                        ));
                        std::io::copy(&mut stager, &mut std::io::sink()).unwrap();
                        let staged = stager.finish().unwrap();
                        let version = f
                            .finding
                            .admission
                            .job()
                            .experiment()
                            .manifest_version
                            .as_str();
                        let canonical = staged
                            .manifest
                            .replace(&format!("version = {version}\n"), "version = 4294967295\n");
                        assert_ne!(canonical, staged.manifest);
                        let mut bundle = vec![0u8; 48];
                        bundle[0] = 1;
                        for chunk in canonical.as_bytes().chunks(43) {
                            let mut record = [0u8; 48];
                            record[0] = 2;
                            record[1] = 1;
                            record[4] = chunk.len() as u8;
                            record[5..5 + chunk.len()].copy_from_slice(chunk);
                            bundle.extend(record);
                        }
                        let mut checkpoint = [0u8; 48];
                        checkpoint[0] = 9;
                        bundle.extend(checkpoint);
                        comparison.candidate = Some(Digest::of(&bundle));
                        fs::write(output.join("candidate.bundle"), bundle).unwrap();
                        fs::write(
                            output.join("candidate.manifest"),
                            crate::sim::worker_manifest(&canonical),
                        )
                        .unwrap();
                    }
                    "reduce-wrong-identity" => {
                        comparison.failure_identity = Some(text("other").unwrap())
                    }
                    "reduce-missing-candidate" => comparison.candidate = None,
                    "reduce-missing-output" => comparison.output = None,
                    "reduce-different-original" => comparison.original = None,
                    "replay-different-observed" => comparison.observed = None,
                    "replay-divergence" => {
                        comparison.divergence = Some(Difference {
                            committed: None,
                            replayed: None,
                        })
                    }
                    "reduce-unreducible-wrong-kind" => {
                        comparison.status = text("unreducible").unwrap();
                        comparison.failure_kind = Some(text("panic").unwrap());
                    }
                    _ => unreachable!(),
                }
            }
        };
        let outcome = if *case == "abort-replay-source" {
            changed_artifact_step_with(&f, &mut custody, kind, "incomplete", 1, mutate)
        } else {
            changed_artifact_step(&f, &mut custody, kind, 1, mutate)
        };
        if *case == "reduce-foreign-version" || *case == "reduce-manifest-only" {
            let error = outcome.unwrap_err();
            let reason = if *case == "reduce-foreign-version" {
                "version"
            } else {
                "candidate manifest differs from reduced bundle"
            };
            assert!(
                matches!(error, Error::Held(ref message) if message.contains(reason)),
                "{error}"
            );
            let root = history::root(&f.store, &f.id).unwrap().unwrap();
            let directory = f.store.open_dir(&root, &name("0001")).unwrap().unwrap();
            assert!(
                f.store
                    .read_record::<TriageResult>(&directory, &name("result"))
                    .unwrap()
                    .is_none()
            );
            assert!(
                f.store
                    .read_record::<RegressionCandidate>(&directory, &name("candidate"))
                    .unwrap()
                    .is_none()
            );
            assert!(
                f.store
                    .read_record::<ReplayDependencies>(&directory, &name("dependencies"))
                    .unwrap()
                    .is_some()
            );
            continue;
        }
        let result = outcome.unwrap();
        let expected = if *case == "abort-rerun"
            || *case == "abort-replay-fresh"
            || *case == "abort-replay-identity-bound"
        {
            Some(ReplayStatus::Reproduced)
        } else if *case == "output-limit"
            || *case == "stream-prior-violation"
            || *case == "file-prior-violation"
        {
            None
        } else if *case == "abort-replay"
            || *case == "abort-replay-source"
            || *case == "abort-replay-identity-oversize"
            || *case == "oversize-rerun"
        {
            Some(ReplayStatus::InsufficientEvidence)
        } else {
            Some(ReplayStatus::Diverged)
        };
        assert_eq!(result.status, expected, "{case}: {result:?}");
        if *case == "abort-replay-source" {
            assert_eq!(result.finished.class, Class::EngineFailure);
            assert_eq!(result.finished.exit, Some(4));
            assert_eq!(
                result.comparison.as_ref().unwrap().status.as_str(),
                "incomplete"
            );
        }
        if *case == "abort-rerun" {
            assert_eq!(result.finished.class, Class::EngineFailure);
            assert_eq!(result.state, StepState::Complete);
            let root = history::root(&f.store, &f.id).unwrap().unwrap();
            let directory = f.store.open_dir(&root, &name("0001")).unwrap().unwrap();
            let mut tampered = result.clone();
            tampered.output_limited = true;
            tampered.state = StepState::Interrupted;
            tampered.status = None;
            tampered.comparison = None;
            f.store
                .replace_record(&directory, &name("result"), &tampered)
                .unwrap();
            assert!(history::results(&f.store, &f.id).is_err());
            f.store
                .replace_record(&directory, &name("result"), &result)
                .unwrap();
        }
        if *case == "file-prior-violation" {
            assert!(result.file_limited);
            assert_eq!(result.state, StepState::Interrupted);
            assert_eq!(result.comparison, None);
        }
        if *case == "stream-prior-violation" {
            assert_eq!(result.finished.class, Class::Violation);
            assert!(result.output_limited);
            assert_eq!(result.state, StepState::Interrupted);
            assert_eq!(result.comparison, None);
        }
        if *case == "output-limit" {
            assert_eq!(result.state, StepState::Interrupted);
            assert_eq!(result.finished.class, Class::Violation);
            assert_eq!(result.status, None);
            assert_eq!(result.comparison, None);
            assert!(result.output_limited);
            changed_artifact_step(&f, &mut custody, kind, 2, mutate).unwrap();
            let shown = crate::campaign::findings::findings(f.store.path()).unwrap();
            assert_eq!(shown["findings"][0]["triage"]["stalled"], true);
            assert_eq!(
                shown["findings"][0]["triage"]["latest"]["finished"]["class"],
                "violation"
            );
            assert_eq!(shown["findings"][0]["verified"]["kind"], "violation");
            assert_eq!(shown["findings"][0]["blocker"], true);
            assert!(
                shown["release_blockers"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|id| id == &f.id)
            );
            assert_eq!(
                shown["findings"][0]["triage"]["limit_hit"],
                "file-size-limit"
            );
            assert!(result.file_limited);
            assert_eq!(
                shown["findings"][0]["triage"]["limits"]["attempt_output"],
                f.config.file_bytes()
            );
            let skipped = admit(
                &f.store,
                &mut custody,
                Request {
                    id: &f.id,
                    kind,
                    archive: None,
                },
                &f.config,
                f.launch(kind, "reproduced", 3),
                Occupancy {
                    census: &mut Some(crate::campaign::census::Census::count(&f.store).unwrap()),
                    steps: 0,
                    committed_output: 0,
                    running: &mut [],
                },
            )
            .unwrap();
            match skipped {
                super::Admission::Skip(reason) => {
                    assert!(reason.contains("class=violation"));
                    assert!(reason.contains("attempt_output="));
                }
                _ => panic!("the equal output limits must stall"),
            }
            let root = history::root(&f.store, &f.id).unwrap().unwrap();
            assert_eq!(history::numbers(&f.store, &root, &f.id).unwrap(), [1, 2]);
            let directory = f.store.open_dir(&root, &name("0002")).unwrap().unwrap();
            let saved = f
                .store
                .read_record::<TriageResult>(&directory, &name("result"))
                .unwrap()
                .unwrap()
                .record()
                .clone();
            let mut tampered = saved.clone();
            tampered.output_limited = false;
            f.store
                .replace_record(&directory, &name("result"), &tampered)
                .unwrap();
            assert!(history::results(&f.store, &f.id).is_err());
            f.store
                .replace_record(&directory, &name("result"), &saved)
                .unwrap();
        }
        assert_eq!(
            history::finding(&f.store, &f.id).unwrap().record(),
            &f.finding
        );
    }
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn malformed_original_panic_is_insufficient_evidence_and_remains_reconcilable() {
    let _processes = processes();
    let mut f = Fixture::new(21920);
    f.finding.kind = FindingKind::Panic;
    f.finding.finished.class = Class::EngineFailure;
    f.finding.artifact.as_mut().unwrap().summary = None;
    let retained = executor::retained(&f.store, &f.id).unwrap();
    let listing = include_bytes!("../../../testdata/admission-listing.txt");
    for (phase, stdout) in [
        ("capabilities", listing.as_slice()),
        ("run", b"run: the run panicked".as_slice()),
    ] {
        for (stream, bytes) in [("stdout", stdout), ("stderr", b"".as_slice())] {
            f.store
                .create_once(&retained, &name(&format!("{phase}.{stream}")), bytes)
                .unwrap();
        }
        f.finding.artifact.as_mut().unwrap().workers.insert(
            text(phase).unwrap(),
            Worker {
                ended: text("failed").unwrap(),
                exit: Some(3),
                signal: None,
                stdout: Digest::of(stdout),
                stderr: Digest::of(b""),
            },
        );
    }
    f.store
        .replace_record(&retained, &name("finding.json"), &f.finding)
        .unwrap();
    let launch = f.launch(StepKind::Replay, "reproduced", 1);
    let output = Store::open(&f.host.case.root.join("output-1")).unwrap();
    output
        .create_once(output.root(), &name("capabilities.stdout"), listing)
        .unwrap();
    output
        .create_once(output.root(), &name("capabilities.stderr"), b"")
        .unwrap();
    drop(output);
    let mut custody = f.host.custody(Duration::from_secs(1));
    let (step, running) = start(
        &f.store,
        &mut custody,
        Request {
            id: &f.id,
            kind: StepKind::Replay,
            archive: None,
        },
        &f.config,
        launch,
        0,
    )
    .unwrap();
    let result = step
        .finish(&f.store, custody.wait_any(vec![running]).unwrap().stopped)
        .unwrap();
    assert_eq!(result.state, StepState::Complete);
    assert_eq!(result.status, Some(ReplayStatus::InsufficientEvidence));
    assert!(reconcile(&f.store, &mut custody).unwrap().is_empty());
    assert_eq!(history::results(&f.store, &f.id).unwrap()[0].1, result);
}

fn mint_pending_step(f: &Fixture, number: u64) {
    let token = format!("{number:04}");
    let mut directory = None;
    for component in ["triage", &f.id, "steps", &token] {
        let parent = directory.as_ref().unwrap_or_else(|| f.store.root());
        f.store.mkdir(parent, &name(component)).unwrap();
        directory = Some(f.store.open_dir(parent, &name(component)).unwrap().unwrap());
    }
    let record = TriageStep {
        attempt: crate::record::Attempt {
            attempt: text(&format!("{}-triage-{token}", f.id)).unwrap(),
            file_bytes: f.config.file_bytes(),
            job: f.finding.attempt.job,
            manifest: f.finding.attempt.manifest,
            number,
        },
        finding: text(&f.id).unwrap(),
        kind: StepKind::Replay,
        launcher: text("/campaign").unwrap(),
        limits: f.config.config().clone(),
    };
    f.store
        .create_record(&directory.unwrap(), &name("step"), &record)
        .unwrap();
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn recovery_sync_faults_recover_twice_to_the_same_interrupted_step() {
    let _processes = processes();
    let f = Fixture::new(21930);
    mint_pending_step(&f, 1);
    let mut custody = f.host.custody(Duration::from_secs(1));
    step::install(Some(Script::default()));
    reconcile(&f.store, &mut custody).unwrap();
    let syncs = step::install(None)
        .unwrap()
        .reached
        .iter()
        .filter(|seam| **seam == Seam::Sync)
        .count();
    assert!(syncs > 10);
    let first = history::results(&f.store, &f.id).unwrap();
    reconcile(&f.store, &mut custody).unwrap();
    assert_eq!(history::results(&f.store, &f.id).unwrap(), first);
    drop(custody);
    drop(f);
    for index in 0..syncs {
        let f = Fixture::new(22000 + index);
        mint_pending_step(&f, 1);
        let mut custody = f.host.custody(Duration::from_secs(1));
        step::install(Some(Script {
            nth: Some((Seam::Sync, index, Outcome::Errno(libc::EIO))),
            ..Script::default()
        }));
        let failed = reconcile(&f.store, &mut custody);
        assert!(
            step::install(None).unwrap().nth.is_none(),
            "recovery sync {index}"
        );
        assert!(failed.is_err(), "recovery sync {index}");
        drop(custody);
        let Fixture {
            host,
            store,
            id,
            finding,
            ..
        } = f;
        drop(store);
        let store = Store::open(&host.case.state).unwrap();
        let mut custody = host.custody(Duration::from_secs(1));
        reconcile(&store, &mut custody).unwrap();
        let first = history::results(&store, &id).unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].1.state, StepState::Interrupted);
        assert_eq!(first[0].1.status, None);
        assert_eq!(first[0].1.elapsed_ms, None);
        assert_eq!(history::finding(&store, &id).unwrap().record(), &finding);
        reconcile(&store, &mut custody).unwrap();
        assert_eq!(history::results(&store, &id).unwrap(), first);
    }
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn free_ordinary_slot_starts_during_triage_and_capture_waits_for_drain() {
    let _processes = processes();
    let f = Fixture::new(22100);
    f.additional_finding(2);
    fs::write(f.host.case.root.join("stall"), b"1").unwrap();
    let mut custody = f.host.custody(Duration::from_secs(1));
    let launch = f.launch(StepKind::Replay, "reproduced", 1);
    let (step, running) = start(
        &f.store,
        &mut custody,
        Request {
            id: &f.id,
            kind: StepKind::Replay,
            archive: None,
        },
        &f.config,
        launch,
        0,
    )
    .unwrap();
    let ordinary = f.launch(StepKind::Rerun, "reproduced", 2);
    let options = crate::campaign::dispatch::Options {
        archive: f.archive.clone(),
        gate: ordinary.gate,
        launcher: ordinary.launcher,
        environment: ordinary.environment,
        deadline: None,
        max_attempts: Some(1),
    };
    crate::campaign::dispatch::ordinary_admission_during_triage(
        &f.store,
        &mut custody,
        &options,
        step,
        running,
    )
    .unwrap();
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn waiting_capture_pauses_triage_admission_until_the_running_set_drains() {
    let _processes = processes();
    let f = Fixture::new(22101);
    let backlog = f.additional_finding(2);
    let ordinary_job = f.additional_job(3);
    fs::write(f.host.case.root.join("stall"), b"1").unwrap();
    let mut widened = f.config.config().clone();
    widened.insert(text("reserve_slots").unwrap(), 2);
    widened.insert(text("cores").unwrap(), 3);
    let config = Configuration::new(widened).unwrap();
    f.store
        .replace_record(f.store.root(), &name("config.json"), &config)
        .unwrap();
    let mut custody = f.host.custody(Duration::from_secs(1));
    let launch = f.launch(StepKind::Replay, "reproduced", 1);
    let (step, running) = start(
        &f.store,
        &mut custody,
        Request {
            id: &f.id,
            kind: StepKind::Replay,
            archive: None,
        },
        &config,
        launch,
        0,
    )
    .unwrap();
    let ordinary = f.launch(StepKind::Rerun, "reproduced", 2);
    let stalling = f.host.case.root.join("launcher-stall");
    fs::write(
        &stalling,
        "#!/bin/sh\nwhile [ ! -f release ]; do sleep 0.001; done\n",
    )
    .unwrap();
    fs::set_permissions(&stalling, fs::Permissions::from_mode(0o700)).unwrap();
    let options = crate::campaign::dispatch::Options {
        archive: f.archive.clone(),
        gate: ordinary.gate,
        launcher: stalling,
        environment: ordinary.environment,
        deadline: None,
        max_attempts: Some(1),
    };
    crate::campaign::dispatch::triage_admission_waits_for_pending_capture(
        &f.store,
        &mut custody,
        &options,
        step,
        running,
        &[backlog.admission.job().id().to_string()],
        &ordinary_job.job().id().to_string(),
    )
    .unwrap();
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn reduction_binds_the_verified_manifest_and_refuses_a_changed_candidate_before_result() {
    let _processes = processes();
    for changed in [false, true] {
        let f = Fixture::new(23100 + usize::from(changed));
        let mut custody = f.host.custody(Duration::from_secs(1));
        let (step, running) = start(
            &f.store,
            &mut custody,
            Request {
                id: &f.id,
                kind: StepKind::Reduce,
                archive: None,
            },
            &f.config,
            f.launch(StepKind::Reduce, "reduced", 1),
            0,
        )
        .unwrap();
        let stopped = custody.wait_any(vec![running]).unwrap().stopped;
        let path = history::step_path(&f.store, &f.id, 1);
        if changed {
            fs::write(path.join("reduced/regression.bundle"), b"changed").unwrap();
            let result = step.finish(&f.store, stopped);
            assert!(
                matches!(result, Err(Error::Held(ref reason)) if reason == "reduced candidate digest differs")
            );
            let root = history::root(&f.store, &f.id).unwrap().unwrap();
            let directory = f.store.open_dir(&root, &name("0001")).unwrap().unwrap();
            assert!(
                f.store
                    .read_record::<TriageResult>(&directory, &name("result"))
                    .unwrap()
                    .is_none()
            );
            assert!(
                f.store
                    .read_record::<ReplayDependencies>(&directory, &name("dependencies"))
                    .unwrap()
                    .is_some()
            );
        } else {
            fs::write(
                path.join("reduced/regression.manifest"),
                b"stale worker manifest",
            )
            .unwrap();
            let result = step.finish(&f.store, stopped).unwrap();
            assert_eq!(result.status, Some(ReplayStatus::Reduced));
            let root = history::root(&f.store, &f.id).unwrap().unwrap();
            let directory = f.store.open_dir(&root, &name("0001")).unwrap().unwrap();
            let candidate = f
                .store
                .read_record::<RegressionCandidate>(&directory, &name("candidate"))
                .unwrap()
                .unwrap();
            assert_eq!(candidate.record().step_ms, None);
            assert_eq!(candidate.record().tier.as_str(), "pinned-corpus");
            let expected = fs::read(
                path.join("artifacts")
                    .join(format!("{}-triage-0001", f.id))
                    .join("candidate.manifest"),
            )
            .unwrap();
            let frozen = fs::read(
                path.join(format!("{}-triage-0001-candidate", f.id))
                    .join("manifest"),
            )
            .unwrap();
            assert_eq!(frozen, expected);
            assert_ne!(frozen, b"stale worker manifest");
        }
        assert_eq!(
            history::finding(&f.store, &f.id).unwrap().record(),
            &f.finding
        );
    }
}

fn stalling_reserve_pair(index: usize) -> Fixture {
    let mut f = Fixture::new(index);
    let mut settings = f.config.config().clone();
    settings.insert(text("reserve_slots").unwrap(), 2);
    settings.insert(text("cores").unwrap(), 3);
    f.config = Configuration::new(settings).unwrap();
    f.store
        .replace_record(f.store.root(), &name("config.json"), &f.config)
        .unwrap();
    f.additional_finding(2);
    fs::write(f.host.case.root.join("stall"), b"1").unwrap();
    f
}

fn triage_dispatch(
    f: &Fixture,
    custody: &mut crate::custody::Custody,
) -> crate::campaign::dispatch::Report {
    let launch = f.launch(StepKind::Replay, "reproduced", 1);
    crate::campaign::dispatch::dispatch(
        &f.store,
        custody,
        &crate::campaign::dispatch::Options {
            archive: f.archive.clone(),
            gate: launch.gate,
            launcher: launch.launcher,
            environment: launch.environment,
            deadline: None,
            max_attempts: Some(0),
        },
    )
    .unwrap()
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn lowered_ancestor_limit_at_triage_admission_drains_running_steps() {
    let _processes = processes();
    let f = stalling_reserve_pair(22300);
    fs::write(f.host.root.join("memory.max"), (128u64 << 20).to_string()).unwrap();
    let mut custody = f.host.custody(Duration::from_secs(1));
    let root = f.host.root.clone();
    let lowered = std::rc::Rc::new(std::cell::Cell::new(false));
    let witnessed = lowered.clone();
    let report = observed(
        move |seam| {
            if seam == Seam::Go && !witnessed.replace(true) {
                fs::write(root.join("memory.max"), (64u64 << 20).to_string()).unwrap();
            }
        },
        || triage_dispatch(&f, &mut custody),
    );
    assert!(lowered.get());
    assert_eq!(
        report.exit(),
        crate::exit::Supervisor::Rejected,
        "{report:?}"
    );
    assert!(
        report
            .rejections
            .iter()
            .any(|reason| reason.contains("aggregate memory")),
        "{report:?}"
    );
    assert_eq!(report.triage_started, 1, "{report:?}");
    let drained = &report.triage_completed[0];
    assert_eq!(drained.state, StepState::Interrupted);
    assert!(!drained.finished.watchdog, "{drained:?}");
    assert_eq!(drained.finished.interruption, Some(crate::sys::KILL_SIGNAL));
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn triage_admission_kills_a_live_step_past_its_watchdog_before_the_next_go() {
    let _processes = processes();
    let f = stalling_reserve_pair(22310);
    let mut custody = f.host.custody(Duration::from_secs(1));
    let order = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let seen = order.clone();
    let slept = std::cell::Cell::new(false);
    let wall = Duration::from_secs(f.config.value("wall"));
    let report = observed(
        move |seam| {
            let mut seen = seen.borrow_mut();
            if matches!(seam, Seam::Go | Seam::Kill) {
                seen.push(seam);
            }
            if seam == Seam::Sync && seen.as_slice() == [Seam::Go] && !slept.replace(true) {
                std::thread::sleep(wall + Duration::from_millis(500));
            }
        },
        || triage_dispatch(&f, &mut custody),
    );
    assert_eq!(report.triage_started, 2, "{report:?}");
    assert_eq!(
        order.borrow()[..3],
        [Seam::Go, Seam::Kill, Seam::Go],
        "{report:?}"
    );
}

#[test]
fn finding_view_refuses_changed_state_identity_before_listing() {
    let case = crate::store::fixture::Case::new();
    let store = Store::open(&case.state).unwrap();
    fs::rename(&case.state, case.root.join("pinned-state")).unwrap();
    fs::create_dir(&case.state).unwrap();
    fs::set_permissions(&case.state, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(
        history::finding(&store, "finding"),
        Err(Error::Store(crate::store::Error::Replaced))
    ));
}

/// The lengths of the finding's retained replay inputs.
fn retained_input_lengths(f: &Fixture) -> Vec<u64> {
    let retained = executor::retained(&f.store, &f.id).unwrap();
    crate::attempt::dependencies(&f.finding)
        .unwrap()
        .iter()
        .map(|(entry, _, _)| f.store.open_file(&retained, entry).unwrap().unwrap().len())
        .collect()
}

/// Input staging during recovery holds at the threshold of each storage
/// dimension it checks: the census usage plus the unstaged inputs reaching
/// `artifact_bytes` or `artifact_inodes`, or measured free bytes or inodes
/// down to what the copies need. A refused staging copies nothing and
/// commits no marker, and one unit of headroom stages the inputs.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn recovery_staging_holds_at_the_census_threshold() {
    let _processes = processes();
    let dimensions = ["artifact_bytes", "artifact_inodes", "disk", "disk_inodes"];
    for (index, dimension) in dimensions.into_iter().enumerate() {
        for headroom in [0, 1] {
            let f = Fixture::new(23300 + 2 * index + headroom as usize);
            mint_pending_step(&f, 1);
            let charge = f.config.charge();
            let shares = u128::from(f.config.value("slots") + f.config.value("reserve_slots"));
            let mut probes = 0;
            while probes < 7
                || dimension == "artifact_inodes"
                    && u128::from(
                        crate::campaign::census::census(&f.store, &f.config)
                            .unwrap()
                            .inodes,
                    ) < shares * charge.inodes
            {
                crate::campaign::state_fixture::probe(&f.store, &format!("probe-fill-{probes}"), 0);
                probes += 1;
            }
            let lengths = retained_input_lengths(&f);
            let inputs: u64 = lengths.iter().sum();
            let files = lengths.len() as u64;
            let usage = crate::campaign::census::census(&f.store, &f.config).unwrap();
            let mut settings = f.config.config().clone();
            let mut free = None;
            match dimension {
                "artifact_bytes" => {
                    settings.insert(
                        text("artifact_bytes").unwrap(),
                        usage.bytes + inputs + headroom,
                    );
                }
                "artifact_inodes" => {
                    settings.insert(text("artifact_bytes").unwrap(), 1 << 30);
                    settings.insert(
                        text("artifact_inodes").unwrap(),
                        usage.inodes + files + headroom,
                    );
                }
                "disk" => {
                    let disk = crate::record::Charge {
                        bytes: u128::from(inputs),
                        inodes: u128::from(files),
                    }
                    .disk(usage.fragment_bytes);
                    free = Some((disk as u64 + headroom, u64::MAX));
                }
                _ => free = Some((u64::MAX, files + headroom)),
            }
            let bounded = Configuration::new(settings).unwrap();
            f.store
                .replace_record(f.store.root(), &name("config.json"), &bounded)
                .unwrap();
            let mut custody = f.host.custody(Duration::from_secs(1));
            step::install(free.map(|free| Script {
                free_space: Some(free),
                ..Script::default()
            }));
            let skipped = reconcile(&f.store, &mut custody);
            step::install(None);
            let skipped = skipped.unwrap();
            let steps = history::root(&f.store, &f.id).unwrap().unwrap();
            let pending = history::pending(
                &f.store,
                &steps,
                history::finding(&f.store, &f.id).unwrap(),
                1,
            )
            .unwrap();
            let committed = f
                .store
                .read_record::<ReplayDependencies>(&pending.directory, &name("dependencies"))
                .unwrap()
                .is_some();
            let refusal = "triage input staging exceeds storage budget";
            if headroom == 0 {
                assert_eq!(
                    skipped.get(&f.id).map(String::as_str),
                    Some(refusal),
                    "{dimension}"
                );
                let source = f
                    .store
                    .open_dir(&pending.directory, &name(&f.id))
                    .unwrap()
                    .unwrap();
                assert!(
                    f.store
                        .list(&source, crate::scan_bound())
                        .unwrap()
                        .is_empty(),
                    "{dimension}"
                );
                assert!(!committed, "{dimension}");
            } else {
                assert_ne!(
                    skipped.get(&f.id).map(String::as_str),
                    Some(refusal),
                    "{dimension}"
                );
                assert!(committed, "{dimension}");
            }
        }
    }
}

/// A state-wide fault in a later step outranks a finding-local error in an
/// earlier one: a step whose record admits another step number holds only
/// its finding, and a free-space query that fails while the next step
/// stages its inputs holds the whole pass with exit 4.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_later_global_step_error_holds_the_reconcile_pass() {
    let _processes = processes();
    let f = Fixture::new(23320);
    mint_pending_step(&f, 1);
    let steps = history::root(&f.store, &f.id).unwrap().unwrap();
    let first = f.store.open_dir(&steps, &name("0001")).unwrap().unwrap();
    mint_pending_step(&f, 2);
    let second = f.store.open_dir(&steps, &name("0002")).unwrap().unwrap();
    let next = f
        .store
        .read_record::<TriageStep>(&second, &name("step"))
        .unwrap()
        .unwrap()
        .record()
        .clone();
    f.store
        .replace_record(&first, &name("step"), &next)
        .unwrap();
    let local = history::pending(
        &f.store,
        &steps,
        history::finding(&f.store, &f.id).unwrap(),
        1,
    )
    .err()
    .unwrap();
    assert!(!history::global(&local), "{local}");
    assert_eq!(local.to_string(), "triage step binding differs");
    let mut custody = f.host.custody(Duration::from_secs(1));
    step::install(Some(Script {
        nth: Some((Seam::Census, 0, Outcome::Errno(libc::EIO))),
        ..Script::default()
    }));
    let held = reconcile(&f.store, &mut custody);
    assert!(step::install(None).unwrap().nth.is_none());
    let error = held.unwrap_err();
    assert_eq!(error.exit(), crate::exit::Supervisor::Held);
    assert!(
        error
            .to_string()
            .contains("fstatvfs of the state directory failed: "),
        "{error}"
    );
}

/// A failed census holds the pass after one count. Later uncommitted steps
/// wait for that hold to clear, keeping recovery work bounded by one scan.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_failed_recovery_census_is_counted_once_per_pass() {
    let _processes = processes();
    let mut f = Fixture::new(23330);
    let other = f.additional_finding(2);
    mint_pending_step(&f, 1);
    let first_steps = history::root(&f.store, &f.id).unwrap().unwrap();
    let first = f
        .store
        .open_dir(&first_steps, &name("0001"))
        .unwrap()
        .unwrap();
    f.id = other.attempt.attempt.as_str().to_owned();
    f.finding = other;
    mint_pending_step(&f, 1);
    let steps = history::root(&f.store, &f.id).unwrap().unwrap();
    let second = f.store.open_dir(&steps, &name("0001")).unwrap().unwrap();
    for index in 0..6 {
        crate::campaign::state_fixture::probe(&f.store, &format!("probe-fill-{index}"), 0);
    }
    let mut custody = f.host.custody(Duration::from_secs(1));
    step::install(Some(Script {
        scan_bound: Some(6),
        ..Script::default()
    }));
    let result = reconcile(&f.store, &mut custody);
    let trace = step::install(None).unwrap();
    let error = result.unwrap_err();
    assert_eq!(
        error.to_string(),
        "probes holds 6 entries at bound 6; collect or shard"
    );
    assert_eq!(error.exit(), crate::exit::Supervisor::Held);
    assert_eq!(
        trace.reached.iter().filter(|at| **at == Seam::List).count(),
        18,
        "{:?}",
        trace.reached
    );
    for directory in [&first, &second] {
        assert!(
            f.store
                .read_record::<ReplayDependencies>(directory, &name("dependencies"))
                .unwrap()
                .is_none()
        );
    }
}

/// Recovery reuses one successful count across steps even when a new
/// probe appears after that count. Both steps commit their staged inputs.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn two_recovery_steps_reuse_one_census() {
    let _processes = processes();
    let mut f = Fixture::new(23331);
    let other = f.additional_finding(2);
    let first_id = f.id.clone();
    mint_pending_step(&f, 1);
    f.id = other.attempt.attempt.as_str().to_owned();
    f.finding = other;
    mint_pending_step(&f, 1);
    for index in 0..7 {
        crate::campaign::state_fixture::probe(&f.store, &format!("probe-fill-{index}"), 0);
    }
    let inputs: u64 = retained_input_lengths(&f).iter().sum();
    let usage = crate::campaign::census::census(&f.store, &f.config).unwrap();
    let mut values = f.config.config().clone();
    values.insert(text("artifact_bytes").unwrap(), usage.bytes + inputs + 1);
    let config = Configuration::new(values).unwrap();
    f.store
        .replace_record(f.store.root(), &name("config.json"), &config)
        .unwrap();
    let late = f.host.case.state.join("probes/probe-late");
    let mut planted = false;
    let mut custody = f.host.custody(Duration::from_secs(1));
    step::install(Some(Script {
        observe: Some(Box::new(move |at| {
            if at == Seam::Census && !planted {
                planted = true;
                fs::create_dir(&late).unwrap();
            }
        })),
        ..Script::default()
    }));
    let result = reconcile(&f.store, &mut custody);
    step::install(None);
    assert!(result.unwrap().is_empty());
    assert!(f.host.case.state.join("probes/probe-late").exists());
    for id in [&first_id, &f.id] {
        let steps = history::root(&f.store, id).unwrap().unwrap();
        let directory = f.store.open_dir(&steps, &name("0001")).unwrap().unwrap();
        assert!(
            f.store
                .read_record::<ReplayDependencies>(&directory, &name("dependencies"))
                .unwrap()
                .is_some()
        );
    }
}

/// Triage admission reads each charged dimension at the copy decision and
/// leaves the state unchanged on an equality refusal.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn triage_admission_checks_each_charged_threshold() {
    let _processes = processes();
    for (index, dimension) in ["artifact_bytes", "artifact_inodes"]
        .into_iter()
        .enumerate()
    {
        let mut f = Fixture::new(23340 + index);
        for n in 0..14 {
            crate::campaign::state_fixture::probe(&f.store, &format!("probe-budget-{n}"), 0);
        }
        let usage = crate::campaign::census::census(&f.store, &f.config).unwrap();
        let charge = f.config.charge();
        let threshold = if dimension == "artifact_bytes" {
            u128::from(usage.bytes) + charge.bytes
        } else {
            u128::from(usage.inodes) + charge.inodes
        };
        for headroom in [0, 1] {
            let mut values = f.config.config().clone();
            values.insert(text("artifact_bytes").unwrap(), 1 << 30);
            values.insert(text(dimension).unwrap(), threshold as u64 + headroom);
            f.config = Configuration::new(values).unwrap();
            f.store
                .replace_record(f.store.root(), &name("config.json"), &f.config)
                .unwrap();
            let launch = f.launch(StepKind::Replay, "reproduced", headroom + 1);
            let before = crate::store::fixture::snapshot(f.store.path());
            let mut custody = f.host.custody(Duration::from_secs(1));
            let mut slot = None;
            let admission = admit(
                &f.store,
                &mut custody,
                Request {
                    id: &f.id,
                    kind: StepKind::Replay,
                    archive: None,
                },
                &f.config,
                launch,
                Occupancy {
                    census: &mut slot,
                    steps: 0,
                    committed_output: 0,
                    running: &mut [],
                },
            )
            .unwrap();
            assert!(slot.is_some());
            if headroom == 0 {
                assert!(
                    matches!(admission, super::Admission::Pause(ref reasons) if reasons.contains(dimension))
                );
                assert_eq!(crate::store::fixture::snapshot(f.store.path()), before);
            } else {
                let super::Admission::Started(pair) = admission else {
                    panic!("headroom must admit")
                };
                let (step, running) = *pair;
                let stopped = custody.wait_any(vec![running]).unwrap().stopped;
                step.finish(&f.store, stopped).unwrap();
            }
        }
    }
}

/// A history at the listing bound completes its last step and refuses the
/// next explicit step before any state write or process launch.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn explicit_triage_preserves_a_history_at_its_listing_bound() {
    let _processes = processes();
    let f = Fixture::new(23342);
    let mut custody = f.host.custody(Duration::from_secs(1));
    let bound = 6;
    for number in 1..=bound {
        f.run(&mut custody, StepKind::Replay, "reproduced", number);
    }
    let launch = f.launch(StepKind::Replay, "reproduced", bound + 1);
    let before = crate::store::fixture::snapshot(f.store.path());
    step::install(Some(Script {
        scan_bound: Some(bound as usize),
        ..Default::default()
    }));
    let result = execute(
        &f.store,
        &mut custody,
        &f.id,
        StepKind::Replay,
        None,
        &f.config,
        launch,
    );
    let trace = step::install(None).unwrap();
    let error = result.unwrap_err();
    assert_eq!(
        error.to_string(),
        format!(
            "triage/{}/steps holds 7 entries at bound 6; collect or shard",
            f.id
        )
    );
    assert_eq!(error.exit(), crate::exit::Supervisor::Held);
    assert!(!trace.reached.contains(&Seam::Spawn));
    assert_eq!(crate::store::fixture::snapshot(f.store.path()), before);
}

/// A reserve-slot refusal uses no census even when the counted roots would
/// hold. Missing retained inputs also leave the recovery census empty.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn finding_local_refusals_leave_the_census_empty() {
    let _processes = processes();
    let f = Fixture::new(23343);
    mint_pending_step(&f, 1);
    let steps = history::root(&f.store, &f.id).unwrap().unwrap();
    let pending = history::pending(
        &f.store,
        &steps,
        history::finding(&f.store, &f.id).unwrap(),
        1,
    )
    .unwrap();
    crate::custody::charge(&f.store, &pending.directory, pending.identity()).unwrap();
    let launch = f.launch(StepKind::Replay, "reproduced", 1);
    let mut custody = f.host.custody(Duration::from_secs(1));
    let mut slot = None;
    step::install(Some(Script {
        scan_bound: Some(1),
        ..Default::default()
    }));
    let result = admit(
        &f.store,
        &mut custody,
        Request {
            id: &f.id,
            kind: StepKind::Replay,
            archive: None,
        },
        &f.config,
        launch,
        Occupancy {
            census: &mut slot,
            steps: 0,
            committed_output: 0,
            running: &mut [],
        },
    );
    step::install(None);
    assert!(matches!(result.unwrap(), super::Admission::Pause(_)));
    assert!(slot.is_none());
    let retained = executor::retained(&f.store, &f.id).unwrap();
    f.store.delete(&retained, &name("bundle")).unwrap();
    step::install(Some(Script {
        scan_bound: Some(1),
        ..Default::default()
    }));
    let error = pending.stage_inputs(&f.store, &mut slot).unwrap_err();
    step::install(None);
    assert_eq!(error.to_string(), "retained dependency missing");
    assert!(!global(&error));
    assert!(slot.is_none());
}

/// An earlier staging hold preserves reconciliation of a committed step in
/// another finding, including its finish and reservation release.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_staging_hold_allows_later_committed_steps_to_conclude() {
    let _processes = processes();
    let mut f = Fixture::new(23344);
    let other = f.additional_finding(2);
    let mut findings = [f.finding.clone(), other];
    findings.sort_by_key(|finding| finding.attempt.attempt.clone());
    let first_id = findings[0].attempt.attempt.as_str().to_owned();
    for finding in findings {
        f.id = finding.attempt.attempt.as_str().to_owned();
        f.finding = finding;
        mint_pending_step(&f, 1);
        if f.id != first_id {
            let steps = history::root(&f.store, &f.id).unwrap().unwrap();
            let pending = history::pending(
                &f.store,
                &steps,
                history::finding(&f.store, &f.id).unwrap(),
                1,
            )
            .unwrap();
            pending.stage_inputs(&f.store, &mut None).unwrap();
        }
    }
    for n in 0..6 {
        crate::campaign::state_fixture::probe(&f.store, &format!("probe-budget-{n}"), 0);
    }
    let mut custody = f.host.custody(Duration::from_secs(1));
    step::install(Some(Script {
        scan_bound: Some(6),
        ..Default::default()
    }));
    let result = reconcile(&f.store, &mut custody);
    step::install(None);
    assert!(matches!(result, Err(Error::Bound { ref root, .. }) if root == "probes"));
    let last = f
        .host
        .case
        .state
        .join(format!("triage/{}/steps/0001", f.id));
    assert!(last.join("finished").exists());
    assert!(!last.join("reservation").exists());
}

/// A lowered file-size limit refuses an oversized retained input before
/// counting a census that would hold.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn recovery_file_size_refusal_precedes_the_census() {
    const CHILD: &str = "CAMPAIGN_TEST_TRIAGE_FILE_LIMIT";
    if std::env::var_os(CHILD).is_none() {
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "campaign::triage::tests::recovery_file_size_refusal_precedes_the_census",
                "--include-ignored",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        return;
    }
    let _processes = processes();
    let f = Fixture::new(23345);
    mint_pending_step(&f, 1);
    let steps = history::root(&f.store, &f.id).unwrap().unwrap();
    let pending = history::pending(
        &f.store,
        &steps,
        history::finding(&f.store, &f.id).unwrap(),
        1,
    )
    .unwrap();
    let retained = executor::retained(&f.store, &f.id).unwrap();
    f.store
        .replace(&retained, &name("bundle"), &vec![0; 2 << 20])
        .unwrap();
    crate::sys::restrict_file_limit(1 << 20, 1 << 20).unwrap();
    let mut slot = None;
    step::install(Some(Script {
        scan_bound: Some(1),
        ..Default::default()
    }));
    let error = pending.stage_inputs(&f.store, &mut slot).unwrap_err();
    step::install(None);
    assert_eq!(
        error.to_string(),
        "triage copy exceeds controller RLIMIT_FSIZE"
    );
    assert!(!global(&error));
    assert!(slot.is_none());
}

/// A recovered staging shares its count with dispatch. Job settlement during
/// recovery adds its publication length before the first subsequent start.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn recovery_hands_its_census_and_settlement_deltas_to_dispatch() {
    let _processes = processes();
    let f = Fixture::new(23346);
    mint_pending_step(&f, 1);
    let launch = f.launch(StepKind::Replay, "reproduced", 2);
    let mut custody = f.host.custody(Duration::from_secs(1));
    let jobs = crate::layout::jobs(&f.store, &f.finding.admission.job().id().to_string())
        .unwrap()
        .unwrap();
    let job = f
        .store
        .read_record::<crate::record::Admission>(
            &jobs,
            &name(&format!("{}.json", f.finding.admission.job().id())),
        )
        .unwrap()
        .unwrap();
    let (attempt, running) = crate::attempt::start(
        &f.store,
        &mut custody,
        job,
        crate::attempt::Launch {
            gate: launch.gate.clone(),
            launcher: "/bin/true".into(),
            environment: launch.environment.clone(),
            limits: launch.limits,
        },
    )
    .unwrap();
    let stopped = custody.wait_any(vec![running]).unwrap().stopped;
    attempt
        .finish(&f.store, stopped, crate::attempt::EVIDENCE_BOUND)
        .unwrap();
    let before = crate::campaign::census::Census::count(&f.store).unwrap();
    let options = crate::campaign::dispatch::Options {
        archive: f.archive.clone(),
        gate: launch.gate,
        launcher: launch.launcher,
        environment: launch.environment,
        deadline: None,
        max_attempts: Some(0),
    };
    let listed = std::rc::Rc::new(std::cell::Cell::new(0));
    let counter = listed.clone();
    let mut started = false;
    step::install(Some(Script {
        observe: Some(Box::new(move |seam| {
            if seam == Seam::Go {
                started = true;
            }
            if seam == Seam::List && !started {
                counter.set(counter.get() + 1);
            }
        })),
        ..Default::default()
    }));
    let session = crate::campaign::dispatch::session(&f.store, &mut custody, &options);
    step::install(None);
    let (report, counted) = session.unwrap();
    assert!(report.refusals.is_empty(), "{report:?}");
    assert!(report.triage_started > 0, "{report:?}");
    let counted = counted.unwrap();
    assert_ne!(counted, before);
    assert_eq!(
        counted,
        crate::campaign::census::Census::count(&f.store).unwrap()
    );
    assert_eq!(
        listed.get(),
        70,
        "recovery and the first start share one census"
    );
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn triage_collects_until_storage_clears_after_ordinary_max_attempts() {
    let _processes = processes();
    let cap = crate::campaign::dispatch::PASS_DELETIONS;
    let mut stop_cut = None;
    for (index, (probes, variant)) in [
        (0, "plain"),
        (3, "plain"),
        (cap + 44, "plain"),
        (0, "signal"),
        (0, "deadline"),
        (cap + 44, "shared"),
        (3, "live"),
    ]
    .into_iter()
    .enumerate()
    {
        let mut f = Fixture::new(24400 + index);
        if variant == "shared" {
            f.additional_job(2);
        }
        if variant == "live" {
            f.additional_finding(2);
            let mut values = f.config.config().clone();
            values.insert(text("reserve_slots").unwrap(), 2);
            values.insert(text("cores").unwrap(), 3);
            values.insert(text("artifact_bytes").unwrap(), 4 << 30);
            f.config = Configuration::new(values).unwrap();
        }
        let sources = 15;
        for number in 0..sources {
            crate::campaign::state_fixture::finished_probe(
                &f.store,
                &format!("probe-source-{number:04}"),
                "/sys/fs/cgroup/campaign-released-probe",
                Digest::of(format!("source-{number}").as_bytes()),
                ProbeOutcome::Complete,
            );
        }
        for number in 0..probes {
            crate::campaign::state_fixture::released_probe(
                &f.store,
                &format!("probe-{number:04}"),
                "/sys/fs/cgroup/campaign-released-probe",
            );
        }
        let usage = crate::campaign::census::census(&f.store, &f.config).unwrap();
        let over = if probes > cap {
            (cap as u64 + 4) * crate::campaign::probe::OUTPUT_INODES
        } else {
            0
        };
        let shares = if variant == "live" { 2 } else { 1 };
        let limit = usage.inodes + shares * f.config.charge().inodes as u64 - over;
        let mut values = f.config.config().clone();
        values.insert(text("artifact_inodes").unwrap(), limit);
        values.insert(text("artifact_bytes").unwrap(), 4 << 30);
        f.config = Configuration::new(values).unwrap();
        f.store
            .replace_record(f.store.root(), &name("config.json"), &f.config)
            .unwrap();
        let mut custody = f.host.custody(Duration::from_secs(1));
        let launch = f.launch(StepKind::Replay, "reproduced", 1);
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let options = crate::campaign::dispatch::Options {
            archive: f.archive.clone(),
            gate: launch.gate,
            launcher: launch.launcher,
            environment: launch.environment,
            deadline: (variant == "deadline").then_some(deadline),
            max_attempts: (variant != "shared").then_some(0),
        };
        let fired = std::rc::Rc::new(std::cell::Cell::new(false));
        let witness = fired.clone();
        let mut at = 0;
        let mut started = false;
        let cut = if matches!(variant, "signal" | "deadline") {
            stop_cut
        } else {
            None
        };
        step::install(Some(Script {
            observe: Some(Box::new(move |point| {
                if point == Seam::Go {
                    started = true;
                }
                if variant == "live" && started && point == Seam::Census && !witness.replace(true) {
                    crate::sys::interrupt(libc::SIGTERM).unwrap();
                }
                if Some(at) == cut {
                    assert_eq!(point, Seam::Census);
                    witness.set(true);
                    if variant == "signal" {
                        crate::sys::interrupt(libc::SIGTERM).unwrap();
                    } else {
                        std::thread::sleep(
                            deadline.saturating_duration_since(std::time::Instant::now())
                                + Duration::from_millis(10),
                        );
                    }
                }
                at += 1;
            })),
            ..Script::default()
        }));
        let result = if variant == "shared" {
            crate::campaign::dispatch::run_with_settled(
                &f.store,
                &mut custody,
                &options,
                &[f.finding.admission.job().id().to_string()],
            )
            .map(|report| (report, None))
        } else {
            crate::campaign::dispatch::session(&f.store, &mut custody, &options)
        };
        let trace = step::install(None).unwrap().reached;
        let report = result.unwrap().0;
        if variant == "plain" && probes == 0 {
            stop_cut = trace.iter().rposition(|point| *point == Seam::Census);
            assert!(stop_cut.is_some());
        }
        if variant == "live" {
            assert!(fired.get());
            assert!(report.refusals.is_empty(), "{report:?}");
            assert_eq!(report.triage_started, 1, "{report:?}");
            assert_eq!(report.collect_passes, 0, "{report:?}");
            assert_eq!(report.state, crate::campaign::dispatch::State::Interrupted);
            assert_eq!(
                fs::read_dir(f.store.path().join("probes")).unwrap().count(),
                sources + probes
            );
            continue;
        }
        if matches!(variant, "signal" | "deadline") {
            assert!(fired.get());
            assert!(report.refusals.is_empty(), "{report:?}");
            assert_eq!(report.collect_passes, 1);
            assert_eq!(report.triage_started, 0);
            assert_eq!(
                report.state,
                if variant == "signal" {
                    crate::campaign::dispatch::State::Interrupted
                } else {
                    crate::campaign::dispatch::State::Deadline
                }
            );
            continue;
        }
        assert_eq!(report.started, u64::from(variant == "shared"), "{report:?}");
        if probes == 0 {
            assert_eq!(report.triage_started, 0, "{report:?}");
            assert_eq!(
                report.refusals,
                ["artifact_inodes exhausted and collect reclaims nothing; raise it with configure"]
            );
            assert_eq!(report.collect_passes, 1);
            assert_eq!(report.collect_finished, Some(true));
        } else {
            assert!(report.refusals.is_empty(), "{report:?}");
            assert!(report.triage_started > 0, "{report:?}");
            assert_eq!(
                report.counts["triage"],
                report.triage_completed.len() as u64
            );
            assert_eq!(report.collect_deletions, (probes - 1) as u64);
            assert_eq!(report.collect_passes, if probes > cap { 2 } else { 1 });
            if variant == "shared" {
                assert_eq!(report.pauses["artifact_inodes"], 2, "{report:?}");
            }
            assert_eq!(
                fs::read_dir(f.store.path().join("probes")).unwrap().count(),
                sources + 1
            );
        }
    }
}

/// A job start decision reserves `reserve_slots` charges beyond its own and
/// a triage step reserves none. With nothing running or collectible and an
/// artifact limit inside that reserve, the job start holds after its empty
/// pass and the window starts nothing more, the replayable finding
/// included. A window whose job starts end at `max_attempts` reaches no job
/// start decision, so its triage step starts within the reserve.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn an_artifact_exhaustion_hold_at_a_job_start_starts_no_triage_step() {
    let _processes = processes();
    for (index, max_attempts) in [None, Some(0)].into_iter().enumerate() {
        let mut f = Fixture::new(24420 + index);
        f.additional_job(2);
        let usage = crate::campaign::census::census(&f.store, &f.config).unwrap();
        let limit = usage.inodes + 2 * f.config.charge().inodes as u64 - 1;
        let mut values = f.config.config().clone();
        assert_eq!(values[&text("reserve_slots").unwrap()], 1);
        values.insert(text("artifact_inodes").unwrap(), limit);
        values.insert(text("artifact_bytes").unwrap(), 4 << 30);
        f.config = Configuration::new(values).unwrap();
        f.store
            .replace_record(f.store.root(), &name("config.json"), &f.config)
            .unwrap();
        let launch = f.launch(StepKind::Replay, "reproduced", 1);
        let options = crate::campaign::dispatch::Options {
            archive: f.archive.clone(),
            gate: launch.gate,
            launcher: launch.launcher,
            environment: launch.environment,
            deadline: None,
            max_attempts,
        };
        let report = crate::campaign::dispatch::run_with_settled(
            &f.store,
            &mut f.host.custody(Duration::from_secs(1)),
            &options,
            &[f.finding.admission.job().id().to_string()],
        )
        .unwrap();
        assert_eq!(report.started, 0, "{report:?}");
        if max_attempts.is_none() {
            assert_eq!(report.triage_started, 0, "{report:?}");
            assert_eq!(
                report.refusals,
                ["artifact_inodes exhausted and collect reclaims nothing; raise it with configure"]
            );
            assert_eq!(
                (report.collect_passes, report.collect_finished),
                (1, Some(true))
            );
        } else {
            assert!(report.triage_started > 0, "{report:?}");
            assert!(report.refusals.is_empty(), "{report:?}");
            assert_eq!(report.collect_passes, 0, "{report:?}");
        }
    }
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn backlog_held_triage_collects_successive_passes_before_replay() {
    let _processes = processes();
    let mut f = Fixture::new(24410);
    let queued = f.additional_job(2);
    let job = f.finding.admission.job().clone();
    let jobs =
        crate::layout::make_shard(&f.store, crate::layout::JOBS, &job.id().to_string()).unwrap();
    f.store
        .create_record(
            &jobs,
            &name(&format!("{}{}", job.id(), Pin::SUFFIX)),
            &Pin {
                result: JobResult {
                    attempt: 1,
                    finished: f.finding.finished.clone(),
                    job: job.id().digest(),
                    manifest: job.manifest_sha256(),
                },
            },
        )
        .unwrap();
    for number in 0..15 {
        crate::campaign::state_fixture::finished_probe(
            &f.store,
            &format!("probe-source-{number:04}"),
            "/sys/fs/cgroup/campaign-released-probe",
            Digest::of(format!("source-{number}").as_bytes()),
            ProbeOutcome::Complete,
        );
    }
    let cap = crate::campaign::dispatch::PASS_DELETIONS;
    let probes = cap + 44;
    for number in 0..probes {
        crate::campaign::state_fixture::released_probe(
            &f.store,
            &format!("probe-{number:04}"),
            "/sys/fs/cgroup/campaign-released-probe",
        );
    }
    let usage = crate::campaign::census::census(&f.store, &f.config).unwrap();
    let limit = usage.inodes + f.config.charge().inodes as u64
        - (cap as u64 + 4) * crate::campaign::probe::OUTPUT_INODES;
    let mut values = f.config.config().clone();
    values.insert(text("artifact_inodes").unwrap(), limit);
    values.insert(text("artifact_bytes").unwrap(), 4 << 30);
    f.config = Configuration::new(values).unwrap();
    f.store
        .replace_record(f.store.root(), &name("config.json"), &f.config)
        .unwrap();
    let launch = f.launch(StepKind::Replay, "reproduced", 1);
    let options = crate::campaign::dispatch::Options {
        archive: f.archive.clone(),
        gate: launch.gate,
        launcher: launch.launcher,
        environment: launch.environment,
        deadline: None,
        max_attempts: None,
    };
    let mut custody = f.host.custody(Duration::from_secs(1));
    let report = crate::campaign::dispatch::run_with_settled(
        &f.store,
        &mut custody,
        &options,
        &[job.id().to_string()],
    )
    .unwrap();
    assert_eq!(
        report.refusals,
        [
            "backlog holds 1 failure pins without a resolved disposition at limit 1; dispose findings or raise backlog"
        ]
    );
    assert!(report.triage_started > 0, "{report:?}");
    assert_eq!(
        (
            report.collect_passes,
            report.collect_deletions,
            report.collect_finished
        ),
        (2, (probes - 1) as u64, Some(false))
    );
    assert_eq!(report.started, 0);
    assert!(
        !f.host
            .case
            .state
            .join(crate::campaign::state_fixture::attempts_dir(
                queued.job().id().to_string()
            ))
            .exists()
    );
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn sampled_triage_diagnostics_keep_the_complete_skip_set() {
    let _processes = processes();
    let mut f = Fixture::new(24411);
    for run in 2..=33 {
        f.additional_finding(run);
    }
    let mut values = f.config.config().clone();
    values.insert(text("attempt_inodes").unwrap(), 4094);
    values.insert(text("artifact_inodes").unwrap(), 1_000_000);
    f.config = Configuration::new(values).unwrap();
    f.store
        .replace_record(f.store.root(), &name("config.json"), &f.config)
        .unwrap();
    let launch = f.launch(StepKind::Replay, "reproduced", 1);
    let options = crate::campaign::dispatch::Options {
        archive: f.archive.clone(),
        gate: launch.gate,
        launcher: launch.launcher,
        environment: launch.environment,
        deadline: Some(std::time::Instant::now() + Duration::from_secs(20)),
        max_attempts: Some(0),
    };
    let report = crate::campaign::dispatch::dispatch(
        &f.store,
        &mut f.host.custody(Duration::from_secs(1)),
        &options,
    )
    .unwrap();
    assert!(report.refusals.is_empty(), "{report:?}");
    assert_eq!(report.state, crate::campaign::dispatch::State::MaxAttempts);
    assert_eq!(report.triage_started, 0);
    assert_eq!(report.triage_skipped.len(), 16);
    assert_eq!(report.diagnostics_omitted["triage_skipped"], 33 - 16);
    assert!(
        report
            .triage_skipped
            .values()
            .all(|reason| reason == "triage evidence needs additional inode headroom")
    );
}
