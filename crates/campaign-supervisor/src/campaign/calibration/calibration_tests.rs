use super::*;
use crate::campaign::state_fixture::Sharded;
use crate::record::{
    Artifact, Binding, CalibrationEvidence, CalibrationVerdict, Class, Comparison, Configuration,
    Digest, Finished, Kernel, ResourceBounds, Summarized,
};
use std::collections::BTreeMap;

fn evidence(id: &str) -> CalibrationEvidence {
    let summary = Summarized {
        cause: None,
        counts: true,
        decisions: Some(3),
        digest: Digest::of(b"original"),
        first_failure: None,
        identity: None,
        ledger: None,
        terminal: text("complete pass fired=03 required=03").unwrap(),
        unsuccessful: None,
    };
    CalibrationEvidence {
        artifact: Some(Artifact {
            archive: Some(Digest::of(b"build")),
            archive_path: None,
            bundle: Some(Digest::of(b"bundle")),
            class: text("counts").unwrap(),
            command: text("run").unwrap(),
            comparison: None,
            manifest: Some(Digest::of(b"manifest")),
            output: None,
            reason: text("counting").unwrap(),
            run_id: text(id).unwrap(),
            session: None,
            session_original: None,
            summary: Some(summary),
            workers: BTreeMap::new(),
        }),
        finished: Finished {
            attempt: text(id).unwrap(),
            binding: Binding::Matching,
            bound: None,
            class: Class::Pass,
            exit: Some(0),
            interruption: None,
            kernel: Kernel::default(),
            residual_members: false,
            signal: None,
            watchdog: false,
        },
        job: Digest::of(b"job"),
        product: None,
        resources: ResourceBounds {
            cpu_us: Some(100),
            memory_bytes: Some(100),
            pids: Some(2),
            wall_us: Some(1000),
        },
    }
}
pub(super) fn record() -> Calibration {
    let healthy = evidence("healthy-0002");
    let summary = healthy.artifact.as_ref().unwrap().summary.clone();
    let replay = |id| {
        let mut replay = evidence(id);
        let artifact = replay.artifact.as_mut().unwrap();
        artifact.command = text("replay").unwrap();
        artifact.comparison = Some(Comparison {
            candidate: None,
            divergence: None,
            failure_identity: None,
            failure_kind: None,
            observed: summary.clone(),
            original: summary.clone(),
            output: None,
            status: text("reproduced").unwrap(),
        });
        replay
    };
    let mut lost = healthy.finished.clone();
    lost.attempt = text("healthy-0001").unwrap();
    lost.class = Class::Interrupted;
    lost.exit = None;
    Calibration {
        contract: CalibrationContract {
            build: Digest::of(b"build"),
            profile: text("upload").unwrap(),
            counts: BTreeMap::new(),
        },
        controls: BTreeMap::new(),
        defects: Vec::new(),
        detected: Vec::new(),
        healthy,
        lost,
        missing: vec![],
        reasons: vec![],
        replays: vec![replay("replay-0001"), replay("replay-0002")],
        root: Digest::of(b"root"),
        verdict: CalibrationVerdict::Uncalibrated,
    }
}

#[test]
fn two_fresh_replays_each_match_the_non_null_original() {
    let mut original = record();
    verdict::finish(&mut original).unwrap();
    assert_eq!(original.verdict, CalibrationVerdict::Calibrated);
    assert!(verdict::complete(&original));
    for mutation in [
        "first-digest",
        "second-digest",
        "mixed-missing-drift",
        "two-wrong",
        "decision",
        "terminal",
        "null-original",
        "matching-null-decisions",
        "matching-empty-terminal",
        "matching-false-counts",
        "observed-false-counts",
        "lost-same-attempt",
        "same-replay",
        "null-summary",
        "exit",
        "archive",
        "bundle",
        "missing-replay",
        "lost",
        "missing-control",
    ] {
        let mut changed = record();
        match mutation {
            "first-digest" | "second-digest" | "mixed-missing-drift" => {
                if mutation == "mixed-missing-drift" {
                    changed.missing.push(text("missing control").unwrap());
                }
                let index = usize::from(mutation != "first-digest");
                changed.replays[index]
                    .artifact
                    .as_mut()
                    .unwrap()
                    .comparison
                    .as_mut()
                    .unwrap()
                    .observed
                    .as_mut()
                    .unwrap()
                    .digest = Digest::of(b"wrong")
            }
            "two-wrong" => {
                for replay in &mut changed.replays {
                    let comparison = replay
                        .artifact
                        .as_mut()
                        .unwrap()
                        .comparison
                        .as_mut()
                        .unwrap();
                    comparison.observed.as_mut().unwrap().digest = Digest::of(b"same wrong");
                    comparison.original.as_mut().unwrap().digest = Digest::of(b"same wrong");
                }
            }
            "decision" => {
                changed.replays[1]
                    .artifact
                    .as_mut()
                    .unwrap()
                    .comparison
                    .as_mut()
                    .unwrap()
                    .observed
                    .as_mut()
                    .unwrap()
                    .decisions = Some(2)
            }
            "terminal" => {
                changed.replays[1]
                    .artifact
                    .as_mut()
                    .unwrap()
                    .comparison
                    .as_mut()
                    .unwrap()
                    .observed
                    .as_mut()
                    .unwrap()
                    .terminal = text("complete pass fired=01 required=01").unwrap()
            }
            "null-original" => {
                changed
                    .healthy
                    .artifact
                    .as_mut()
                    .unwrap()
                    .summary
                    .as_mut()
                    .unwrap()
                    .decisions = None
            }
            "matching-null-decisions" | "matching-empty-terminal" | "matching-false-counts" => {
                let mutate = |summary: &mut Summarized| match mutation {
                    "matching-null-decisions" => summary.decisions = None,
                    "matching-empty-terminal" => summary.terminal = text("").unwrap(),
                    _ => summary.counts = false,
                };
                mutate(
                    changed
                        .healthy
                        .artifact
                        .as_mut()
                        .unwrap()
                        .summary
                        .as_mut()
                        .unwrap(),
                );
                for replay in &mut changed.replays {
                    let comparison = replay
                        .artifact
                        .as_mut()
                        .unwrap()
                        .comparison
                        .as_mut()
                        .unwrap();
                    mutate(comparison.original.as_mut().unwrap());
                    if mutation != "matching-false-counts" {
                        mutate(comparison.observed.as_mut().unwrap());
                    }
                }
            }
            "observed-false-counts" => {
                changed.replays[1]
                    .artifact
                    .as_mut()
                    .unwrap()
                    .comparison
                    .as_mut()
                    .unwrap()
                    .observed
                    .as_mut()
                    .unwrap()
                    .counts = false
            }
            "lost-same-attempt" => changed.lost.attempt = changed.healthy.finished.attempt.clone(),
            "same-replay" => changed.replays[1] = changed.replays[0].clone(),
            "null-summary" => changed.healthy.artifact.as_mut().unwrap().summary = None,
            "exit" => changed.replays[1].finished.exit = Some(2),
            "archive" => {
                changed.replays[1].artifact.as_mut().unwrap().archive =
                    Some(Digest::of(b"different build"))
            }
            "bundle" => changed.replays[1].artifact.as_mut().unwrap().bundle = None,
            "missing-replay" => {
                changed.replays.pop();
            }
            "lost" => changed.lost.class = Class::Pass,
            "missing-control" => changed
                .missing
                .push(text("planted control absent").unwrap()),
            _ => unreachable!(),
        }
        verdict::finish(&mut changed).unwrap();
        let expected = if matches!(
            mutation,
            "missing-replay" | "lost" | "lost-same-attempt" | "missing-control"
        ) {
            CalibrationVerdict::Uncalibrated
        } else {
            CalibrationVerdict::Refused
        };
        assert_eq!(changed.verdict, expected, "{mutation}");
        assert!(!verdict::complete(&changed), "{mutation}");
    }
}

pub(crate) fn config() -> Configuration {
    Configuration::new(
        [
            ("slots", 2),
            ("reserve_slots", 1),
            ("cores", 4),
            ("memory", 1024),
            ("cpu", 2),
            ("tree_memory", 128),
            ("attempt_output", 100),
            ("attempt_inodes", 10),
            ("wall", 2),
            ("processes", 4),
            ("artifact_bytes", 1 << 30),
            ("artifact_inodes", 10000),
            ("backlog", 10),
            ("retained_builds", 1),
        ]
        .map(|(key, value)| (text(key).unwrap(), value))
        .into(),
    )
    .unwrap()
}

#[test]
fn missing_measurements_and_changed_limits_cannot_grant_capacity() {
    let baseline = record().healthy.resources;
    assert!(baseline.fits(&config(), 2));
    for dimension in ["cpu", "memory", "pids", "wall"] {
        let mut missing = baseline.clone();
        match dimension {
            "cpu" => missing.cpu_us = None,
            "memory" => missing.memory_bytes = None,
            "pids" => missing.pids = None,
            "wall" => missing.wall_us = None,
            _ => unreachable!(),
        }
        assert!(!missing.fits(&config(), 2), "{dimension}");
    }
    let mut exceeded = baseline;
    exceeded.cpu_us = Some(3_000_000);
    assert!(!exceeded.fits(&config(), 2));
    let mut changed = config().config().clone();
    changed.insert(text("cores").unwrap(), 2);
    changed.insert(text("slots").unwrap(), 1);
    assert!(
        !record()
            .healthy
            .resources
            .fits(&Configuration::new(changed).unwrap(), 2)
    );
}

#[test]
fn changed_build_profile_or_count_has_a_distinct_contract() {
    let baseline = record().contract;
    for dimension in ["build", "profile", "counts"] {
        let mut changed = baseline.clone();
        match dimension {
            "build" => changed.build = Digest::of(b"another build"),
            "profile" => changed.profile = text("long").unwrap(),
            "counts" => {
                changed.counts.insert(text("turns").unwrap(), 1);
            }
            _ => unreachable!(),
        }
        assert_ne!(changed.key(), baseline.key(), "{dimension}");
    }
}

pub(crate) fn stored_capacity(
    store: &Store,
    admission: crate::record::Admission,
    config: Configuration,
    slots: u64,
) -> Capacity {
    stored_capacity_with_resources(store, admission, config, slots, record().healthy.resources)
}

pub(crate) fn stored_capacity_with_resources(
    store: &Store,
    admission: crate::record::Admission,
    config: Configuration,
    slots: u64,
    resources: ResourceBounds,
) -> Capacity {
    let result = stored_root(store, admission, config.clone(), resources, |_, _| {});
    Capacity::new(
        result.contract.clone(),
        Digest::of(&serde_json::to_vec(&result).unwrap()),
        result.healthy.resources.clone(),
        result.root,
        slots,
        config,
    )
    .unwrap()
}

/// One attempt the calibration fixture stages: a bound artifact, or `None`
/// for an unbound stop, with its exit code and the class the classifier
/// derives from that exit and artifact. `read_completed` rejects any other
/// class.
pub(crate) struct Staged {
    pub artifact: Option<Artifact>,
    pub exit: Option<u64>,
    pub class: Class,
}

/// The calibration attempt a fixture edit receives.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role<'a> {
    Lost,
    Healthy,
    Control(&'a str),
    Replay(u64),
}

/// Seals a calibration root whose healthy, lost, control and replay snapshots
/// are read back from attempts staged in `store`, so each snapshot equals the
/// evidence `assess` verifies. `edit` may change each staged attempt, or clear
/// a replay, which leaves the root with only the remaining replays staged and
/// sealed. A control job whose first attempt is already finished in `store`
/// is reused; the control identity derives from the healthy experiment,
/// including its run number, and the calibration scope.
pub(crate) fn stored_root(
    store: &Store,
    admission: crate::record::Admission,
    config: Configuration,
    resources: ResourceBounds,
    mut edit: impl FnMut(Role<'_>, &mut Option<Staged>),
) -> Calibration {
    let baseline = record().healthy.resources;
    let build = Digest::parse(admission.job().experiment().pins.build.as_str()).unwrap();
    let mut plan = CalibrationPlan {
        config,
        controls: BTreeMap::new(),
        deduplicated: true,
        healthy: admission,
        missing: vec![],
    };
    let scoped = contract(&plan).unwrap();
    let root = plan.healthy.job().id().digest();
    let listing =
        crate::protocol::Listing::parse(include_str!("../../../testdata/admission-listing.txt"))
            .unwrap();
    let keys = listing
        .keys
        .iter()
        .map(|key| key.name.as_str())
        .collect::<Vec<_>>();
    let (_, manifest) =
        crate::record::Job::derive(plan.healthy.job().experiment().clone(), &keys).unwrap();
    admitted(store, &plan.healthy, &manifest);
    let mut lost = Some(Staged {
        artifact: None,
        exit: None,
        class: Class::Interrupted,
    });
    edit(Role::Lost, &mut lost);
    let lost = attempt_at(store, &plan.healthy, 1, lost.unwrap(), &baseline);
    captured(store, &plan.healthy, 1, root);
    let mut healthy = Some(Staged {
        artifact: Some(run_artifact(&plan.healthy, build, false)),
        exit: Some(0),
        class: Class::Pass,
    });
    edit(Role::Healthy, &mut healthy);
    let healthy = attempt_at(store, &plan.healthy, 2, healthy.unwrap(), &resources);
    captured(store, &plan.healthy, 2, root);
    settled(store, &plan.healthy, 2, &healthy);
    let mut controls = BTreeMap::new();
    let mut detected = Vec::new();
    for control in controls::declared(scoped.profile.as_str()) {
        let mut experiment = plan.healthy.job().experiment().clone();
        experiment.campaign = text("calibration").unwrap();
        experiment.profile = text(control.profile).unwrap();
        experiment.class = Some(text("control").unwrap());
        experiment.calibration_scope = Some(execution::control_scope(&scoped, &plan.config));
        let (job, manifest) = crate::record::Job::derive(experiment, &keys).unwrap();
        let admission = crate::record::Admission::new(
            plan.healthy.archive().clone(),
            job,
            crate::record::Purpose::Calibration,
        )
        .unwrap();
        admitted(store, &admission, &manifest);
        let evidence = match finished_attempt(store, &admission, 1) {
            Some(evidence) => evidence,
            None => {
                let mut staged = Some(Staged {
                    artifact: Some(run_artifact(&admission, build, true)),
                    exit: Some(1),
                    class: Class::Violation,
                });
                edit(Role::Control(control.profile), &mut staged);
                let evidence = attempt_at(store, &admission, 1, staged.unwrap(), &baseline);
                captured(store, &admission, 1, root);
                settled(store, &admission, 1, &evidence);
                evidence
            }
        };
        plan.controls
            .insert(text(control.profile).unwrap(), admission);
        detected.push(text(control.profile).unwrap());
        controls.insert(text(control.profile).unwrap(), evidence);
    }
    detected.sort();
    store.mkdir(store.root(), &name("calibrations")).unwrap();
    let roots = store
        .open_dir(store.root(), &name("calibrations"))
        .unwrap()
        .unwrap();
    store.mkdir(&roots, &name(&root.to_string())).unwrap();
    let directory = directory(store, root).unwrap();
    store
        .create_record(&directory, &name("plan"), &plan)
        .unwrap();
    let mut replays = Vec::new();
    for number in 1..=2 {
        let original = healthy
            .artifact
            .as_ref()
            .and_then(|artifact| artifact.summary.clone());
        let mut artifact = run_artifact(&plan.healthy, build, false);
        artifact.command = text("replay").unwrap();
        artifact.run_id = text(&format!(
            "{}-calibration-replay-{number:04}",
            plan.healthy.job().id()
        ))
        .unwrap();
        artifact.comparison = Some(Comparison {
            candidate: None,
            divergence: None,
            failure_identity: None,
            failure_kind: None,
            observed: original.clone(),
            original,
            output: None,
            status: text("reproduced").unwrap(),
        });
        let worker = artifact.workers[&text("run").unwrap()].clone();
        artifact.workers = ["replay", "inspect-original", "inspect-replay"]
            .into_iter()
            .map(|phase| (text(phase).unwrap(), worker.clone()))
            .collect();
        let mut staged = Some(Staged {
            artifact: Some(artifact),
            exit: Some(0),
            class: Class::Pass,
        });
        edit(Role::Replay(number), &mut staged);
        let Some(staged) = staged else {
            continue;
        };
        replays.push(replay_at(store, &plan, number, staged, &baseline));
    }
    let mut result = Calibration {
        contract: scoped,
        controls,
        defects: Vec::new(),
        detected,
        healthy,
        lost: lost.finished,
        missing: vec![],
        reasons: vec![],
        replays,
        root,
        verdict: CalibrationVerdict::Uncalibrated,
    };
    verdict::finish(&mut result).unwrap();
    store
        .create_record(&directory, &name("result"), &result)
        .unwrap();
    execution::resolve_controls(store, &result).unwrap();
    result
}

/// Records the capture of attempt `number` of `admission` as calibration
/// execution does for root `root`, retaining the finding a failure records.
fn captured(store: &Store, admission: &crate::record::Admission, number: u64, root: Digest) {
    let (attempts, _) = crate::attempt::history(store, admission).unwrap().unwrap();
    let (directory, attempt) =
        crate::attempt::read_attempt(store, admission, &attempts, number).unwrap();
    let completed =
        crate::attempt::read_completed(store, &directory, attempt.record(), "run").unwrap();
    crate::attempt::capture(
        store,
        admission,
        &completed,
        &directory,
        &attempt,
        Some(root),
    )
    .unwrap();
}

/// Publishes the job result that settlement selects for attempt `number`,
/// with the failure pin a pinning class requires.
fn settled(
    store: &Store,
    admission: &crate::record::Admission,
    number: u64,
    evidence: &CalibrationEvidence,
) {
    let id = admission.job().id();
    let jobs = &crate::layout::make_shard(store, crate::layout::JOBS, &id.to_string()).unwrap();
    let result = crate::record::JobResult {
        attempt: number,
        finished: evidence.finished.clone(),
        job: id.digest(),
        manifest: admission.job().manifest_sha256(),
    };
    if crate::attempt::pins(evidence.finished.class) {
        store
            .create_record(
                jobs,
                &name(&format!("{id}{}", crate::record::Pin::SUFFIX)),
                &crate::record::Pin {
                    result: result.clone(),
                },
            )
            .unwrap();
    }
    store
        .create_record(
            jobs,
            &name(&format!("{id}{}", crate::record::JobResult::SUFFIX)),
            &result,
        )
        .unwrap();
}

/// Publishes `admission` and its frozen `manifest` once; a repeat call
/// verifies the stored records equal them.
fn admitted(store: &Store, admission: &crate::record::Admission, manifest: &str) {
    let id = admission.job().id();
    let shard = crate::layout::make_shard(store, crate::layout::JOBS, &id.to_string()).unwrap();
    let jobs = &shard;
    super::super::once(store, jobs, &format!("{id}.json"), admission).unwrap();
    let entry = name(&format!("{id}.manifest"));
    match store.read(jobs, &entry, crate::record::BOUND).unwrap() {
        Some(found) => assert_eq!(found.bytes(), manifest.as_bytes()),
        None => {
            store
                .create_once(jobs, &entry, manifest.as_bytes())
                .unwrap();
        }
    }
}

fn run_artifact(admission: &crate::record::Admission, build: Digest, violation: bool) -> Artifact {
    let id = format!("{}-0000", admission.job().id());
    let mut artifact = crate::attempt::tests::artifact(&id, admission.job().manifest_sha256());
    artifact.archive = Some(build);
    let summary = artifact.summary.as_mut().unwrap();
    summary.decisions = Some(3);
    if violation {
        summary.counts = false;
        summary.terminal = text("complete violation fired=03 required=03").unwrap();
        artifact.class = text("complete").unwrap();
        artifact
            .workers
            .get_mut(&text("run").unwrap())
            .unwrap()
            .exit = Some(1);
    }
    artifact
}

fn finished_attempt(
    store: &Store,
    admission: &crate::record::Admission,
    number: u64,
) -> Option<CalibrationEvidence> {
    let (root, _) = crate::attempt::history(store, admission).unwrap()?;
    let directory = store
        .open_dir(&root, &name(&format!("{number:04}")))
        .unwrap()?;
    let attempt = store
        .read_record::<crate::record::Attempt>(&directory, &name("attempt"))
        .unwrap()
        .unwrap();
    Some(read_staged(
        store,
        &directory,
        attempt.record(),
        "run",
        admission,
    ))
}

fn attempt_at(
    store: &Store,
    admission: &crate::record::Admission,
    number: u64,
    staged: Staged,
    resources: &ResourceBounds,
) -> CalibrationEvidence {
    let id = admission.job().id().to_string();
    let attempts = crate::layout::make_shard(store, crate::layout::ATTEMPTS, &id).unwrap();
    store.mkdir(&attempts, &name(&id)).unwrap();
    let root = store.open_dir(&attempts, &name(&id)).unwrap().unwrap();
    store.mkdir(&root, &name(&format!("{number:04}"))).unwrap();
    let directory = store
        .open_dir(&root, &name(&format!("{number:04}")))
        .unwrap()
        .unwrap();
    let attempt = crate::record::Attempt {
        attempt: text(&format!("{id}-{number:04}")).unwrap(),
        file_bytes: crate::record::BOUND,
        job: admission.job().id().digest(),
        manifest: admission.job().manifest_sha256(),
        number,
    };
    store
        .create_record(&directory, &name("attempt"), &attempt)
        .unwrap();
    stage_finished(store, &directory, &attempt, "run", staged, resources);
    read_staged(store, &directory, &attempt, "run", admission)
}

fn replay_at(
    store: &Store,
    plan: &CalibrationPlan,
    number: u64,
    staged: Staged,
    resources: &ResourceBounds,
) -> CalibrationEvidence {
    let job = plan.healthy.job();
    let root = directory(store, job.id().digest()).unwrap();
    store.mkdir(&root, &name("replays")).unwrap();
    let replays = store.open_dir(&root, &name("replays")).unwrap().unwrap();
    store
        .mkdir(&replays, &name(&format!("{number:04}")))
        .unwrap();
    let directory = store
        .open_dir(&replays, &name(&format!("{number:04}")))
        .unwrap()
        .unwrap();
    let attempt = crate::record::Attempt {
        attempt: text(&format!("{}-calibration-replay-{number:04}", job.id())).unwrap(),
        file_bytes: plan.config.file_bytes(),
        job: job.id().digest(),
        manifest: job.manifest_sha256(),
        number,
    };
    let source = store
        .path()
        .join(crate::campaign::state_fixture::attempts_dir(
            job.id().to_string(),
        ))
        .join("0002")
        .join("artifacts")
        .join(format!("{}-0002", job.id()));
    store
        .create_record(
            &directory,
            &name("replay"),
            &crate::record::CalibrationReplay {
                attempt: attempt.clone(),
                original: Digest::of(b"bundle"),
                source: text(source.to_str().unwrap()).unwrap(),
            },
        )
        .unwrap();
    stage_finished(store, &directory, &attempt, "replay", staged, resources);
    store
        .create_record(&directory, &name("attempt"), &attempt)
        .unwrap();
    let verified = store
        .read_record::<crate::record::Attempt>(&directory, &name("attempt"))
        .unwrap()
        .unwrap();
    let completed = crate::attempt::read_completed(store, &directory, &attempt, "replay").unwrap();
    crate::attempt::capture(
        store,
        &plan.healthy,
        &completed,
        &directory,
        &verified,
        Some(job.id().digest()),
    )
    .unwrap();
    read_staged(store, &directory, &attempt, "replay", &plan.healthy)
}

/// Writes the custody witnesses, bound artifact, finish and resources of one
/// attempt beneath `directory`. Stream and bundle digests are recomputed from
/// the bytes written, so the staged evidence binds.
fn stage_finished(
    store: &Store,
    directory: &crate::store::Dir,
    attempt: &crate::record::Attempt,
    command: &str,
    staged: Staged,
    resources: &ResourceBounds,
) {
    let intent = crate::record::Intent {
        attempt: attempt.attempt.clone(),
        boot: text("boot").unwrap(),
        cgroup: text(store.path().join("gone").to_str().unwrap()).unwrap(),
    };
    store
        .create_record(directory, &name("intent"), &intent)
        .unwrap();
    store
        .create_record(
            directory,
            &name("started"),
            &crate::record::Started {
                attempt: intent.attempt.clone(),
                baseline: Kernel::default(),
                boot: intent.boot.clone(),
                cgroup: intent.cgroup.clone(),
                cgroup_inode: 1,
                launcher_pid: 1,
            },
        )
        .unwrap();
    let bound = staged.artifact.map(|mut artifact| {
        artifact.run_id = attempt.attempt.clone();
        artifact.manifest = Some(attempt.manifest);
        store.mkdir(directory, &name("artifacts")).unwrap();
        let artifacts = store
            .open_dir(directory, &name("artifacts"))
            .unwrap()
            .unwrap();
        store
            .mkdir(&artifacts, &name(attempt.attempt.as_str()))
            .unwrap();
        let evidence = store
            .open_dir(&artifacts, &name(attempt.attempt.as_str()))
            .unwrap()
            .unwrap();
        for (phase, worker) in &mut artifact.workers {
            let stdout = format!("{} stdout\n", phase.as_str());
            worker.stdout = Digest::of(stdout.as_bytes());
            worker.stderr = Digest::of(b"stderr");
            store
                .create_once(
                    &evidence,
                    &name(&format!("{}.stdout", phase.as_str())),
                    stdout.as_bytes(),
                )
                .unwrap();
            store
                .create_once(
                    &evidence,
                    &name(&format!("{}.stderr", phase.as_str())),
                    b"stderr",
                )
                .unwrap();
        }
        if artifact.bundle.is_some() {
            artifact.bundle = Some(Digest::of(b"bundle"));
            let bundle = if command == "run" { "bundle" } else { "input" };
            store
                .create_once(&evidence, &name(bundle), b"bundle")
                .unwrap();
        }
        let jobs = store.shard_jobs(attempt.job).unwrap().unwrap();
        let manifest = store
            .read(
                &jobs,
                &name(&format!("{}.manifest", attempt.job)),
                crate::record::BOUND,
            )
            .unwrap()
            .unwrap();
        store
            .create_once(&evidence, &name("manifest"), manifest.bytes())
            .unwrap();
        store
            .create_record(&evidence, &name("artifact"), &artifact)
            .unwrap();
        let read = store
            .read_record::<Artifact>(&evidence, &name("artifact"))
            .unwrap()
            .unwrap();
        let bound = crate::record::BoundEvidence {
            artifact: Digest::of(read.read().bytes()),
            attempt: attempt.attempt.clone(),
            bundle: artifact.bundle,
        };
        store
            .create_record(directory, &name("bound"), &bound)
            .unwrap();
        bound
    });
    let counter = |key: &str, value: Option<u64>| {
        value
            .map(|value| (text(key).unwrap(), value))
            .into_iter()
            .collect()
    };
    store
        .create_record(
            directory,
            &name("finished"),
            &Finished {
                attempt: attempt.attempt.clone(),
                binding: if bound.is_some() {
                    Binding::Matching
                } else {
                    Binding::Missing
                },
                bound,
                class: staged.class,
                exit: staged.exit,
                interruption: None,
                kernel: Kernel {
                    cpu: counter("usage_usec", resources.cpu_us),
                    memory: counter("peak", resources.memory_bytes),
                    pids: counter("peak", resources.pids),
                },
                residual_members: false,
                signal: None,
                watchdog: false,
            },
        )
        .unwrap();
    store
        .create_record(directory, &name("resources"), resources)
        .unwrap();
}

fn read_staged(
    store: &Store,
    directory: &crate::store::Dir,
    attempt: &crate::record::Attempt,
    command: &str,
    admission: &crate::record::Admission,
) -> CalibrationEvidence {
    let completed = crate::attempt::read_completed(store, directory, attempt, command).unwrap();
    let mut evidence = execution::snapshot(&completed, admission.job().id().digest());
    evidence.resources = store
        .read_record::<ResourceBounds>(directory, &name("resources"))
        .unwrap()
        .unwrap()
        .record()
        .clone();
    evidence
}

#[test]
fn capacity_requires_complete_matching_roots_and_measured_resources() {
    for mutation in [
        "missing",
        "refused",
        "incomplete-peer",
        "defective-peer",
        "evidence-digest",
        "resources",
    ] {
        let case = crate::store::fixture::Case::new();
        let store = Store::open(&case.state).unwrap();
        let listing = crate::protocol::Listing::parse(include_str!(
            "../../../testdata/admission-listing.txt"
        ))
        .unwrap();
        let digest = text(&Digest::of(b"build").to_string()).unwrap();
        let pins = crate::record::Pins {
            build: digest.clone(),
            executable: digest,
            platform: text("x86_64").unwrap(),
            toolchain: text("rustc").unwrap(),
        };
        let request = super::super::Request {
            profile: text("upload").unwrap(),
            campaign: text("calibration").unwrap(),
            run: 0,
            attempts: 2,
            counts: BTreeMap::new(),
        };
        let admission = super::super::admit(
            &store,
            &listing,
            pins.clone(),
            text("/archive").unwrap(),
            &request,
            crate::record::Purpose::Calibration,
        )
        .unwrap()
        .record;
        let mut campaign = request;
        campaign.campaign = text("campaign").unwrap();
        super::super::admit(
            &store,
            &listing,
            pins,
            text("/archive").unwrap(),
            &campaign,
            crate::record::Purpose::Campaign,
        )
        .unwrap();
        let config = config();
        let capacity = stored_capacity(&store, admission, config.clone(), 2);
        store.mkdir(store.root(), &name("capacity")).unwrap();
        let capacities = store
            .open_dir(store.root(), &name("capacity"))
            .unwrap()
            .unwrap();
        store
            .mkdir(&capacities, &name(&capacity.contract().key().to_string()))
            .unwrap();
        let capacities = store
            .open_dir(&capacities, &name(&capacity.contract().key().to_string()))
            .unwrap()
            .unwrap();
        store
            .create_record(&capacities, &name(&capacity.root().to_string()), &capacity)
            .unwrap();
        assert!(qualify(&store, &capacity).unwrap());
        store
            .create_record(store.root(), &name("config.json"), &config)
            .unwrap();
        // The report is the reader production runs: it qualifies the
        // capacity's calibration row.
        let reported = || {
            let view = crate::store::View::open(store.path()).unwrap();
            let report = crate::campaign::report::project(&view).unwrap();
            report["calibrations"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["id"] == capacity.root().to_string() && row["qualified"] == true)
        };
        assert!(reported(), "{mutation}");
        let root = directory(&store, capacity.root()).unwrap();
        let mut result = store
            .read_record::<Calibration>(&root, &name("result"))
            .unwrap()
            .unwrap()
            .record()
            .clone();
        match mutation {
            "missing" => {
                std::fs::remove_file(
                    case.state
                        .join("calibrations")
                        .join(capacity.root().to_string())
                        .join("result"),
                )
                .unwrap();
            }
            "refused" => {
                result.verdict = CalibrationVerdict::Refused;
                store
                    .replace_record(&root, &name("result"), &result)
                    .unwrap();
                let refused = Capacity::new(
                    capacity.contract().clone(),
                    Digest::of(&serde_json::to_vec(&result).unwrap()),
                    capacity.resources().clone(),
                    capacity.root(),
                    capacity.slots(),
                    capacity.budget().clone(),
                )
                .unwrap();
                store
                    .replace_record(&capacities, &name(&refused.root().to_string()), &refused)
                    .unwrap();
            }
            "evidence-digest" => {
                result
                    .controls
                    .values_mut()
                    .next()
                    .unwrap()
                    .resources
                    .wall_us = Some(999);
                store
                    .replace_record(&root, &name("result"), &result)
                    .unwrap();
            }
            "resources" => {
                let mut bounds = capacity.resources().clone();
                bounds.memory_bytes = None;
                let capacity = Capacity::new(
                    capacity.contract().clone(),
                    capacity.evidence(),
                    bounds,
                    capacity.root(),
                    2,
                    capacity.budget().clone(),
                )
                .unwrap();
                store
                    .replace_record(&capacities, &name(&capacity.root().to_string()), &capacity)
                    .unwrap();
            }
            "incomplete-peer" | "defective-peer" => {
                let mut plan = store
                    .read_record::<CalibrationPlan>(&root, &name("plan"))
                    .unwrap()
                    .unwrap()
                    .record()
                    .clone();
                let mut experiment = plan.healthy.job().experiment().clone();
                experiment.run = 1;
                let keys: Vec<_> = listing.keys.iter().map(|key| key.name.as_str()).collect();
                let (job, manifest) = crate::record::Job::derive(experiment, &keys).unwrap();
                plan.healthy = crate::record::Admission::new(
                    plan.healthy.archive().clone(),
                    job,
                    crate::record::Purpose::Calibration,
                )
                .unwrap();
                let jobs = store.shard_jobs(plan.healthy.job().id()).unwrap().unwrap();
                store
                    .create_record(
                        &jobs,
                        &name(&format!("{}.json", plan.healthy.job().id())),
                        &plan.healthy,
                    )
                    .unwrap();
                store
                    .create_once(
                        &jobs,
                        &name(&format!("{}.manifest", plan.healthy.job().id())),
                        manifest.as_bytes(),
                    )
                    .unwrap();
                let roots = store
                    .open_dir(store.root(), &name("calibrations"))
                    .unwrap()
                    .unwrap();
                let id = plan.healthy.job().id().to_string();
                store.mkdir(&roots, &name(&id)).unwrap();
                let peer = store.open_dir(&roots, &name(&id)).unwrap().unwrap();
                plan.controls.clear();
                store.create_record(&peer, &name("plan"), &plan).unwrap();
                store.mkdir(&peer, &name("replays")).unwrap();
                let replays = store.open_dir(&peer, &name("replays")).unwrap().unwrap();
                store.mkdir(&replays, &name("0001")).unwrap();
                store.mkdir(&replays, &name("0002")).unwrap();
                let target = store.open_dir(&replays, &name("0002")).unwrap().unwrap();
                let replay = crate::record::CalibrationReplay {
                    attempt: crate::record::Attempt {
                        attempt: text(&format!(
                            "{}-calibration-replay-0002",
                            plan.healthy.job().id()
                        ))
                        .unwrap(),
                        file_bytes: plan.config.file_bytes(),
                        job: plan.healthy.job().id().digest(),
                        manifest: plan.healthy.job().manifest_sha256(),
                        number: 2,
                    },
                    original: Digest::of(b"original"),
                    source: text("/unlaunched").unwrap(),
                };
                store
                    .create_record(&target, &name("replay"), &replay)
                    .unwrap();
                if mutation == "defective-peer" {
                    // A lost attempt of a product class makes the peer a
                    // partial defect, which withholds its contract.
                    let mut lost = record().lost;
                    lost.attempt = text(&format!("{id}-0001")).unwrap();
                    lost.class = Class::Disagreement;
                    store.create_record(&peer, &name("lost"), &lost).unwrap();
                }
            }
            _ => unreachable!(),
        }
        let stored = store
            .read_record::<Capacity>(&capacities, &name(&capacity.root().to_string()))
            .unwrap()
            .unwrap()
            .record()
            .clone();
        assert_eq!(
            qualify(&store, &stored).is_ok_and(|qualified| qualified),
            mutation == "incomplete-peer",
            "{mutation}"
        );
        assert_eq!(reported(), mutation == "incomplete-peer", "{mutation}");
    }
}

#[test]
fn declared_controls_require_their_obligation_rule_hash_or_planted_panic() {
    let listing =
        crate::protocol::Listing::parse(include_str!("../../../testdata/admission-listing.txt"))
            .unwrap();
    let violation = |obligation, rule: &str, version| {
        let identity = format!(
            "{version:02x}01{obligation:02x}00000000{}{}",
            Digest::of(rule.as_bytes()),
            "00".repeat(5)
        );
        let output = include_str!("../../../testdata/counting.summary")
            .replace("counts: true", "counts: false")
            .replace(
                "terminal: complete pass fired=03 required=03",
                "terminal: complete violation fired=03 required=03",
            );
        crate::protocol::Summary::parse(
            &format!("{output}cause: violation, violating Bytes\nidentity: {identity}\n"),
            &listing,
        )
        .unwrap()
    };
    let healthy = evidence("control");
    let mut failed = healthy.clone();
    failed.finished.class = Class::Violation;
    let routing = "a key was served from an owner its routing contract does not name";
    let control = &controls::declared("cluster-broad")[0];
    assert!(controls::detected(
        control,
        &failed,
        Some(&violation(2, routing, 2)),
        None
    ));
    for (obligation, rule, version) in [(1, routing, 2), (2, "another check", 2), (2, routing, 1)] {
        assert!(!controls::detected(
            control,
            &failed,
            Some(&violation(obligation, rule, version)),
            None
        ));
    }
    assert!(!controls::detected(
        control,
        &healthy,
        Some(&violation(2, routing, 2)),
        None
    ));
    let rule = "a key's version counter reached its end";
    let output = include_str!("../../../testdata/counting.summary")
        .replace("counts: true", "counts: false")
        .replace(
            "terminal: complete pass fired=03 required=03",
            "terminal: complete unsuccessful fired=03 required=03",
        );
    let summary = crate::protocol::Summary::parse(
        &format!("{output}cause: unsuccessful\nunsuccessful: {rule}\n"),
        &listing,
    )
    .unwrap();
    failed.finished.class = Class::Unsuccessful;
    let control = &controls::declared("cluster-pressure")[2];
    assert!(controls::detected(control, &failed, Some(&summary), None));
    let wrong = crate::protocol::Summary::parse(
        &format!("{output}cause: unsuccessful\nunsuccessful: another check\n"),
        &listing,
    )
    .unwrap();
    assert!(!controls::detected(control, &failed, Some(&wrong), None));
    failed.finished.class = Class::EngineFailure;
    let control = &controls::declared("upload")[3];
    assert!(controls::detected(
        control,
        &failed,
        None,
        Some("src/worker.rs:1:2: a planted panic once the upload published")
    ));
    assert!(!controls::detected(
        control,
        &failed,
        None,
        Some("src/worker.rs:1:2: another panic")
    ));
    assert!(!controls::detected(control, &failed, None, None));
}

#[test]
fn later_calibrated_roots_qualify_after_harness_loss_and_preserve_product_defects() {
    for history in [
        "interrupted",
        "product-defect",
        "null-original",
        "changed-contract",
    ] {
        let case = crate::store::fixture::Case::new();
        let store = Store::open(&case.state).unwrap();
        let listing = crate::protocol::Listing::parse(include_str!(
            "../../../testdata/admission-listing.txt"
        ))
        .unwrap();
        let digest = text(&Digest::of(b"build").to_string()).unwrap();
        let pins = crate::record::Pins {
            build: digest.clone(),
            executable: digest,
            platform: text("x86_64").unwrap(),
            toolchain: text("rustc").unwrap(),
        };
        let request = super::super::Request {
            profile: text("upload").unwrap(),
            campaign: text("calibration").unwrap(),
            run: 0,
            attempts: 2,
            counts: BTreeMap::new(),
        };
        let admission = super::super::admit(
            &store,
            &listing,
            pins.clone(),
            text("/archive").unwrap(),
            &request,
            crate::record::Purpose::Calibration,
        )
        .unwrap()
        .record;
        let capacity = stored_capacity(&store, admission, config(), 2);
        assert!(qualify(&store, &capacity).unwrap());
        let root = directory(&store, capacity.root()).unwrap();
        let mut old_request = request;
        old_request.run = 1;
        if history == "changed-contract" {
            old_request.counts.insert(text("turns").unwrap(), 20001);
        }
        let older_admission = super::super::admit(
            &store,
            &listing,
            pins,
            text("/archive").unwrap(),
            &old_request,
            crate::record::Purpose::Calibration,
        )
        .unwrap()
        .record;
        let mut older = stored_root(
            &store,
            older_admission,
            config(),
            record().healthy.resources,
            |role, staged| match (history, role) {
                ("interrupted", Role::Healthy) => {
                    *staged = Some(Staged {
                        artifact: None,
                        exit: None,
                        class: Class::Interrupted,
                    });
                }
                ("interrupted", Role::Replay(_)) => *staged = None,
                ("product-defect", Role::Replay(1)) => {
                    let artifact = staged.as_mut().unwrap().artifact.as_mut().unwrap();
                    let comparison = artifact.comparison.as_mut().unwrap();
                    comparison.observed.as_mut().unwrap().digest = Digest::of(b"product mismatch");
                }
                _ => {}
            },
        );
        if history == "null-original" {
            older
                .healthy
                .artifact
                .as_mut()
                .unwrap()
                .summary
                .as_mut()
                .unwrap()
                .decisions = None;
            older.defects = verdict::product_defects(&older);
            older.verdict = CalibrationVerdict::Refused;
            store
                .replace_record(
                    &directory(&store, older.root).unwrap(),
                    &name("result"),
                    &older,
                )
                .unwrap();
        }
        assert_eq!(
            older.verdict == CalibrationVerdict::Refused,
            history != "changed-contract",
            "{history}"
        );
        assert_eq!(
            qualify(&store, &capacity).is_ok_and(|qualified| qualified),
            matches!(history, "interrupted" | "changed-contract"),
            "{history}"
        );
        assert_ne!(capacity.root(), older.root);
        assert_eq!(
            capacity.evidence(),
            Digest::of(
                &serde_json::to_vec(
                    store
                        .read_record::<Calibration>(&root, &name("result"))
                        .unwrap()
                        .unwrap()
                        .record()
                )
                .unwrap()
            )
        );
        let before = std::fs::read(
            case.state
                .join("calibrations")
                .join(older.root.to_string())
                .join("result"),
        )
        .unwrap();
        let status = super::super::show(&case.state).unwrap();
        let rows = status["calibrations"].as_array().unwrap();
        assert_eq!(rows.len(), 2);
        assert!(
            rows.iter()
                .any(|row| row["id"] == capacity.root().to_string()
                    && row["verdict"] == "calibrated")
        );
        let older_verdict = if history == "changed-contract" {
            "calibrated"
        } else {
            "refused"
        };
        assert!(
            rows.iter()
                .any(|row| row["id"] == older.root.to_string() && row["verdict"] == older_verdict),
            "{history}"
        );
        assert_eq!(
            std::fs::read(
                case.state
                    .join("calibrations")
                    .join(older.root.to_string())
                    .join("result")
            )
            .unwrap(),
            before
        );
    }
}

#[test]
fn null_original_predicate_covers_partial_and_sealed_root_evidence() {
    let mut original = record();
    assert!(!verdict::null_original(&original.healthy));
    original
        .healthy
        .artifact
        .as_mut()
        .unwrap()
        .summary
        .as_mut()
        .unwrap()
        .decisions = None;
    assert!(verdict::null_original(&original.healthy));
    assert!(!verdict::product_defects(&original).is_empty());
    original.healthy.finished.class = Class::Interrupted;
    original.healthy.artifact = None;
    original.replays.clear();
    assert!(!verdict::null_original(&original.healthy));
    assert!(verdict::product_defects(&original).is_empty());
}

#[test]
fn lost_and_fresh_replay_product_failures_block_the_contract() {
    for class in [
        Class::Violation,
        Class::EngineFailure,
        Class::Unsuccessful,
        Class::Disagreement,
    ] {
        for target in [0, 1, 2] {
            let mut value = record();
            match target {
                0 => value.lost.class = class,
                1 => value.replays[0].finished.class = class,
                2 => value.replays[1].finished.class = class,
                _ => unreachable!(),
            }
            verdict::finish(&mut value).unwrap();
            assert_eq!(
                value.verdict,
                CalibrationVerdict::Refused,
                "{class:?} {target}"
            );
            assert!(!value.defects.is_empty());
            assert!(!verdict::complete(&value));
        }
    }
    let mut value = record();
    value
        .defects
        .push(text("earlier control disagreement").unwrap());
    verdict::finish(&mut value).unwrap();
    assert_eq!(value.verdict, CalibrationVerdict::Refused);
}

#[test]
fn bound_product_failures_preserve_defects_beside_kernel_limits() {
    for kind in [
        crate::record::FindingKind::Violation,
        crate::record::FindingKind::Panic,
        crate::record::FindingKind::Abort,
    ] {
        for target in [0, 1, 2] {
            let mut value = record();
            let evidence = match target {
                0 => &mut value.healthy,
                1 => &mut value.replays[0],
                _ => &mut value.replays[1],
            };
            evidence.finished.class = Class::Oom;
            evidence.product = Some(kind);
            verdict::finish(&mut value).unwrap();
            assert_eq!(value.verdict, CalibrationVerdict::Refused);
            assert!(!value.defects.is_empty());
            assert!(!verdict::complete(&value));
            let roundtrip: Calibration =
                serde_json::from_slice(&serde_json::to_vec(&value).unwrap()).unwrap();
            assert_eq!(roundtrip, value);
        }
    }
}

#[test]
fn full_control_scope_preserves_existing_identities_and_separates_limits_and_contracts() {
    let case = crate::store::fixture::Case::new();
    let store = Store::open(&case.state).unwrap();
    let listing =
        crate::protocol::Listing::parse(include_str!("../../../testdata/admission-listing.txt"))
            .unwrap();
    let contract = record().contract;
    let config = config();
    let pins = crate::record::Pins {
        build: text(&contract.build.to_string()).unwrap(),
        executable: text(&Digest::of(b"executable").to_string()).unwrap(),
        platform: text("x86_64").unwrap(),
        toolchain: text("rustc").unwrap(),
    };
    let request = super::super::Request {
        profile: text("upload").unwrap(),
        campaign: text("calibration").unwrap(),
        run: 0,
        attempts: 2,
        counts: Default::default(),
    };
    let scope = execution::control_scope(&contract, &config);
    let first = super::super::admission::admit_control(
        &store,
        &listing,
        pins.clone(),
        text("/archive").unwrap(),
        &request,
        scope,
    )
    .unwrap();
    let repeated = super::super::admission::admit_control(
        &store,
        &listing,
        pins.clone(),
        text("/archive").unwrap(),
        &request,
        scope,
    )
    .unwrap();
    assert!(repeated.existing);
    assert_eq!(first.record, repeated.record);
    assert_eq!(
        first.record.job().experiment().calibration_scope,
        Some(scope)
    );
    let encoded = serde_json::to_vec(&first.record).unwrap();
    let decoded: crate::record::Admission = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(decoded, first.record);
    for dimension in ["limits", "build", "profile", "count"] {
        let mut changed = contract.clone();
        let mut limits = config.config().clone();
        match dimension {
            "limits" => {
                limits.insert(
                    text("tree_memory").unwrap(),
                    config.value("tree_memory") + 1,
                );
            }
            "build" => changed.build = Digest::of(b"changed-build"),
            "profile" => changed.profile = text("changed-profile").unwrap(),
            "count" => {
                changed.counts.insert(text("turns").unwrap(), 19);
            }
            _ => unreachable!(),
        }
        let scope = execution::control_scope(&changed, &Configuration::new(limits).unwrap());
        let control = super::super::admission::admit_control(
            &store,
            &listing,
            pins.clone(),
            text("/archive").unwrap(),
            &request,
            scope,
        )
        .unwrap();
        assert!(!control.existing, "{dimension}");
        assert_ne!(
            control.record.job().id(),
            first.record.job().id(),
            "{dimension}"
        );
    }
    let mut campaign = request;
    campaign.campaign = text("campaign").unwrap();
    let ordinary = super::super::admit(
        &store,
        &listing,
        pins.clone(),
        text("/archive").unwrap(),
        &campaign,
        crate::record::Purpose::Campaign,
    )
    .unwrap();
    assert_eq!(ordinary.record.job().experiment().calibration_scope, None);
    let plain = serde_json::to_value(ordinary.record.job().experiment()).unwrap();
    assert!(plain.get("calibration_scope").is_none());
    let keys = listing
        .keys
        .iter()
        .map(|key| key.name.as_str())
        .collect::<Vec<_>>();
    let mut forged = ordinary.record.job().experiment().clone();
    forged.calibration_scope = Some(scope);
    let (job, _) = crate::record::Job::derive(forged, &keys).unwrap();
    assert!(
        crate::record::Admission::new(
            text("/archive").unwrap(),
            job.clone(),
            crate::record::Purpose::Campaign
        )
        .is_err()
    );
    let bytes = serde_json::to_vec(&serde_json::json!({"archive": "/archive", "job": job, "purpose": crate::record::Purpose::Campaign})).unwrap();
    assert!(serde_json::from_slice::<crate::record::Admission>(&bytes).is_err());
}

#[test]
fn declared_control_catalog_pins_every_required_profile() {
    for (profile, expected) in [
        ("upload", vec!["planted", "corrupted", "acked", "panicking"]),
        ("long", vec!["long-planted"]),
        ("rekey", vec!["rekey-stalled"]),
        (
            "cluster-broad",
            vec!["cluster-wrong-owner", "cluster-stale-read"],
        ),
        (
            "cluster-pressure",
            vec![
                "cluster-wrong-owner",
                "cluster-stale-read",
                "cluster-version-end",
            ],
        ),
        (
            "cluster-long",
            vec![
                "cluster-late-stale",
                "cluster-late-leak",
                "cluster-late-corrupt",
                "cluster-version-end",
            ],
        ),
    ] {
        assert_eq!(
            controls::declared(profile)
                .iter()
                .map(|control| control.profile)
                .collect::<Vec<_>>(),
            expected,
            "{profile}"
        );
    }
}

#[test]
fn unintended_control_outcomes_remain_contract_blocking_defects() {
    for class in [
        Class::Pass,
        Class::Disagreement,
        Class::Violation,
        Class::EngineFailure,
        Class::Unsuccessful,
    ] {
        let mut value = record();
        let mut control = evidence("control-0001");
        control.finished.class = class;
        value
            .controls
            .insert(text("long-planted").unwrap(), control);
        verdict::finish(&mut value).unwrap();
        assert_eq!(value.verdict, CalibrationVerdict::Refused, "{class:?}");
        assert!(!value.defects.is_empty());
        assert!(!verdict::complete(&value));
    }
}

#[test]
fn damaged_calibration_root_is_one_held_blocker_beside_other_rows() {
    let case = crate::store::fixture::Case::new();
    let store = Store::open(&case.state).unwrap();
    store.mkdir(store.root(), &name("calibrations")).unwrap();
    let roots = store
        .open_dir(store.root(), &name("calibrations"))
        .unwrap()
        .unwrap();
    let damaged = Digest::of(b"damaged root").to_string();
    store
        .create_once(&roots, &name(&damaged), b"not a directory")
        .unwrap();
    let healthy = Digest::of(b"healthy root").to_string();
    store.mkdir(&roots, &name(&healthy)).unwrap();
    let root = store.open_dir(&roots, &name(&healthy)).unwrap().unwrap();
    store.mkdir(&root, &name("replays")).unwrap();
    let replays = store.open_dir(&root, &name("replays")).unwrap().unwrap();
    store.mkdir(&replays, &name("0001")).unwrap();
    let replay = store.open_dir(&replays, &name("0001")).unwrap().unwrap();
    let mut finished = record().healthy.finished;
    finished.attempt = text(&format!("{healthy}-calibration-replay-0001")).unwrap();
    finished.class = Class::Violation;
    store
        .create_record(&replay, &name("finished"), &finished)
        .unwrap();
    let listed = crate::campaign::findings(&case.state).unwrap();
    let rows = listed["findings"].as_array().unwrap();
    let held = format!("calibrations/{damaged}");
    assert!(
        rows.iter()
            .any(|row| row["id"] == held && row["held"].is_string() && row["blocker"] == true),
        "{rows:?}"
    );
    let blockers = listed["release_blockers"].as_array().unwrap();
    assert!(blockers.iter().any(|id| *id == held));
    assert!(
        blockers
            .iter()
            .any(|id| *id == format!("{healthy}-calibration-replay-0001"))
    );
}

#[test]
fn replay_capture_marker_without_a_finish_is_held_like_an_attempt_marker() {
    let case = crate::store::fixture::Case::new();
    let store = Store::open(&case.state).unwrap();
    store.mkdir(store.root(), &name("calibrations")).unwrap();
    let roots = store
        .open_dir(store.root(), &name("calibrations"))
        .unwrap()
        .unwrap();
    let healthy = Digest::of(b"healthy root").to_string();
    store.mkdir(&roots, &name(&healthy)).unwrap();
    let root = store.open_dir(&roots, &name(&healthy)).unwrap().unwrap();
    store.mkdir(&root, &name("replays")).unwrap();
    let replays = store.open_dir(&root, &name("replays")).unwrap().unwrap();
    store.mkdir(&replays, &name("0001")).unwrap();
    let replay = store.open_dir(&replays, &name("0001")).unwrap().unwrap();
    let id = format!("{healthy}-calibration-replay-0001");
    store
        .create_record(
            &replay,
            &name("captured"),
            &crate::record::Captured {
                attempt: text(&id).unwrap(),
                finding: None,
                finished: Digest::of(b"unwritten finish"),
            },
        )
        .unwrap();
    let listed = crate::campaign::findings(&case.state).unwrap();
    let row = listed["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == id)
        .unwrap_or_else(|| panic!("the replay marker is held: {listed}"));
    assert_eq!(row["held"], "capture marker without a finish", "{row}");
    assert_eq!(row["blocker"], true);
    assert_eq!(listed["release_blockers"], serde_json::json!([id]));
}

#[test]
fn unsealed_root_status_is_distinct_from_a_sealed_uncalibrated_verdict() {
    let case = crate::store::fixture::Case::new();
    let store = Store::open(&case.state).unwrap();
    let listing =
        crate::protocol::Listing::parse(include_str!("../../../testdata/admission-listing.txt"))
            .unwrap();
    let digest = text(&Digest::of(b"build").to_string()).unwrap();
    let pins = crate::record::Pins {
        build: digest.clone(),
        executable: digest,
        platform: text("x86_64").unwrap(),
        toolchain: text("rustc").unwrap(),
    };
    let request = super::super::Request {
        profile: text("upload").unwrap(),
        campaign: text("calibration").unwrap(),
        run: 0,
        attempts: 2,
        counts: BTreeMap::new(),
    };
    let healthy = super::super::admit(
        &store,
        &listing,
        pins,
        text("/archive").unwrap(),
        &request,
        crate::record::Purpose::Calibration,
    )
    .unwrap()
    .record;
    let plan = CalibrationPlan {
        config: config(),
        controls: BTreeMap::new(),
        deduplicated: true,
        healthy,
        missing: vec![],
    };
    let id = plan.healthy.job().id().digest();
    store.mkdir(store.root(), &name("calibrations")).unwrap();
    let roots = store
        .open_dir(store.root(), &name("calibrations"))
        .unwrap()
        .unwrap();
    store.mkdir(&roots, &name(&id.to_string())).unwrap();
    let root = directory(&store, id).unwrap();
    store.create_record(&root, &name("plan"), &plan).unwrap();
    let shown = super::super::show(&case.state).unwrap();
    let row = &shown["calibrations"][0];
    assert_eq!(row["id"], id.to_string());
    assert_eq!(row["verdict"], "unsealed", "{row}");
    assert_eq!(row["missing"][0], "calibration result is missing");
}

#[test]
fn a_planless_root_with_retained_state_is_held_and_an_empty_one_is_uncalibrated() {
    // Reconciliation and eligibility hold a planless root that holds any entry,
    // so status reports the same root as held; an empty root is freshly
    // retained and uncalibrated.
    let case = crate::store::fixture::Case::new();
    let store = Store::open(&case.state).unwrap();
    store.mkdir(store.root(), &name("calibrations")).unwrap();
    let roots = store
        .open_dir(store.root(), &name("calibrations"))
        .unwrap()
        .unwrap();
    let empty = Digest::of(b"empty root");
    store.mkdir(&roots, &name(&empty.to_string())).unwrap();
    let retained = Digest::of(b"planless root");
    store.mkdir(&roots, &name(&retained.to_string())).unwrap();
    let root = directory(&store, retained).unwrap();
    store
        .create_record(&root, &name("result"), &record())
        .unwrap();
    let view = crate::store::View::open(store.path()).unwrap();
    let rows = super::status(&view).unwrap();
    let verdicts: BTreeMap<_, _> = rows
        .iter()
        .map(|row| {
            (
                row["id"].as_str().unwrap().to_owned(),
                row["verdict"].clone(),
            )
        })
        .collect();
    assert_eq!(verdicts[&empty.to_string()], "uncalibrated", "{rows:?}");
    assert_eq!(verdicts[&retained.to_string()], "held", "{rows:?}");
}
