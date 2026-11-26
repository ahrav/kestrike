use std::collections::BTreeMap;
use std::fs;
const SIMPLE_MANIFEST: &[u8] =
    b"build = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n";

#[path = "settle_tests.rs"]
pub(crate) mod settlement;

use super::binding::{self, Evidence};
use super::classify::classify;
use super::{Attempt, name};
use crate::record::{
    Admission, Artifact, Attempt as AttemptRecord, BOUND, Binding, Class, Digest, Finished, Intent,
    Kernel, Pins, Purpose, Summarized, Text, Worker,
};
use crate::step::{Outcome, Step};
use crate::store::Store;
use crate::store::fixture::{Case, scripted};

pub(crate) fn text(value: &str) -> Text {
    Text::new(value).unwrap()
}

fn job(store: &Store) -> Admission {
    admit_run(store, 0).unwrap().record
}

fn admit_run(store: &Store, run: u64) -> Result<crate::campaign::Outcome, crate::campaign::Error> {
    admit_request(
        store,
        &crate::campaign::Request {
            profile: text("upload"),
            campaign: text("c1"),
            run,
            attempts: 3,
            counts: BTreeMap::new(),
        },
    )
}

/// Admits `request` as a campaign job from the test listing with fixed pins.
pub(crate) fn admit_request(
    store: &Store,
    request: &crate::campaign::Request,
) -> Result<crate::campaign::Outcome, crate::campaign::Error> {
    let listing =
        crate::protocol::Listing::parse(include_str!("../../testdata/admission-listing.txt"))
            .unwrap();
    crate::campaign::admit(
        store,
        &listing,
        Pins {
            build: text(&"b".repeat(64)),
            executable: text(&"e".repeat(64)),
            platform: text("x86_64-linux"),
            toolchain: text("rustc"),
        },
        text("/archive"),
        request,
        Purpose::Campaign,
    )
}

fn verified_job(store: &Store, job: &Admission) -> crate::record::Verified<Admission> {
    let jobs = crate::layout::jobs(store, &job.job().id().to_string())
        .unwrap()
        .unwrap();
    store
        .read_record(&jobs, &name(&format!("{}.json", job.job().id())))
        .unwrap()
        .unwrap()
}

pub(crate) fn artifact(id: &str, manifest: Digest) -> Artifact {
    Artifact {
        archive: Digest::parse(&"b".repeat(64)),
        archive_path: None,
        bundle: Some(Digest::of(b"bundle")),
        class: text("counts"),
        command: text("run"),
        comparison: None,
        manifest: Some(manifest),
        output: None,
        reason: text("counts"),
        run_id: text(id),
        session: None,
        session_original: None,
        summary: Some(Summarized {
            cause: None,
            counts: true,
            decisions: Some(1),
            digest: Digest::of(b"semantic"),
            first_failure: None,
            identity: None,
            ledger: None,
            terminal: text("complete pass fired=03 required=03"),
            unsuccessful: None,
        }),
        workers: ["run", "inspect"]
            .into_iter()
            .map(|phase| {
                (
                    text(phase),
                    Worker {
                        ended: text("exited"),
                        exit: Some(0),
                        signal: None,
                        stdout: Digest::of(b"stdout"),
                        stderr: Digest::of(b"stderr"),
                    },
                )
            })
            .collect(),
    }
}

pub(crate) fn stage(
    store: &Store,
    directory: &crate::store::Dir,
    attempt: &AttemptRecord,
    artifact: &Artifact,
) -> crate::store::Dir {
    store.mkdir(directory, &name("artifacts")).unwrap();
    let artifacts = store
        .open_dir(directory, &name("artifacts"))
        .unwrap()
        .unwrap();
    store
        .mkdir(&artifacts, &name(attempt.attempt.as_str()))
        .unwrap();
    let dir = store
        .open_dir(&artifacts, &name(attempt.attempt.as_str()))
        .unwrap()
        .unwrap();
    store
        .replace_record(&dir, &name("artifact"), artifact)
        .unwrap();
    store.replace(&dir, &name("bundle"), b"bundle").unwrap();
    store
        .replace(&dir, &name("manifest"), SIMPLE_MANIFEST)
        .unwrap();
    for phase in ["run", "inspect"] {
        store
            .replace(&dir, &name(&format!("{phase}.stdout")), b"stdout")
            .unwrap();
        store
            .replace(&dir, &name(&format!("{phase}.stderr")), b"stderr")
            .unwrap();
    }
    dir
}

fn attempt_record() -> AttemptRecord {
    AttemptRecord {
        attempt: text("job-0001"),
        file_bytes: BOUND,
        job: Digest::of(b"job"),
        manifest: Digest::of(SIMPLE_MANIFEST),
        number: 1,
    }
}
fn finished() -> Finished {
    Finished {
        attempt: text("job-0001"),
        binding: Binding::Missing,
        bound: None,
        class: Class::Pass,
        exit: Some(0),
        interruption: None,
        kernel: Kernel::default(),
        residual_members: false,
        signal: None,
        watchdog: false,
    }
}

#[test]
fn every_class_has_a_discriminating_case_and_kernel_limits_override_pass() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let attempt = attempt_record();
    let baseline = artifact(attempt.attempt.as_str(), attempt.manifest);
    stage(&store, store.root(), &attempt, &baseline);
    let mut observed = std::collections::BTreeSet::new();
    let scenarios: Vec<(Class, Option<&str>, Option<u64>)> = vec![
        (Class::Pass, None, Some(0)),
        (
            Class::Violation,
            Some("complete violation fired=03 required=03"),
            Some(1),
        ),
        (
            Class::Unsuccessful,
            Some("complete unsuccessful fired=00 required=03"),
            Some(1),
        ),
        (
            Class::Inconclusive,
            Some("complete inconclusive fired=00 required=03"),
            Some(1),
        ),
        (Class::Incomplete, None, Some(4)),
        (Class::EngineFailure, Some("infrastructure defect"), Some(4)),
        (Class::Rejected, None, Some(2)),
        (Class::Interrupted, None, None),
        (Class::Watchdog, None, Some(6)),
        (Class::Signal, None, Some(0)),
        (Class::Oom, None, Some(0)),
        (Class::PidLimit, None, Some(0)),
        (Class::CpuLimit, None, Some(0)),
        (Class::OutputLimit, None, Some(0)),
        (Class::MixedLimits, None, Some(0)),
        (Class::MalformedEvidence, None, Some(0)),
        (Class::MisboundEvidence, None, Some(0)),
        (Class::Disagreement, None, Some(1)),
        (Class::Infrastructure, None, Some(125)),
    ];
    for (expected, terminal, exit) in scenarios {
        let mut record = baseline.clone();
        let mut result = finished();
        result.exit = exit;
        if let Some(terminal) = terminal {
            record.summary.as_mut().unwrap().terminal = text(terminal);
        }
        record.class = text(match exit {
            Some(1) => "complete",
            Some(2) => "rejected",
            Some(4) => "incomplete",
            Some(6) => "watchdog",
            _ => "counts",
        });
        match expected {
            Class::Rejected => {
                record.workers.get_mut(&text("run")).unwrap().exit = Some(2);
            }
            Class::Signal => {
                result.signal = Some(15);
            }
            Class::Oom => {
                result.kernel.memory.insert(text("oom_kill"), 1);
            }
            Class::PidLimit => {
                result.kernel.pids.insert(text("max"), 1);
            }
            Class::CpuLimit => {
                result.interruption = Some(crate::sys::CPU_SIGNAL as u64);
                result.kernel.cpu.insert(text("nr_throttled"), 1);
            }
            Class::OutputLimit => {
                result.interruption = Some(crate::sys::OUTPUT_SIGNAL as u64);
            }
            Class::MixedLimits => {
                result.kernel.memory.insert(text("oom"), 1);
                result.kernel.pids.insert(text("max"), 1);
            }
            Class::Disagreement => {
                record.class = text("counts");
            }
            _ => {}
        }
        stage(&store, store.root(), &attempt, &record);
        let evidence = match expected {
            Class::MalformedEvidence => Evidence::Malformed,
            Class::MisboundEvidence => Evidence::Misbound,
            _ => binding::read(&store, store.root(), &attempt).unwrap(),
        };
        assert_eq!(classify(&result, &evidence), expected);
        observed.insert(expected.name());
    }
    assert_eq!(observed.len(), Class::ALL.len());
}

#[test]
fn binding_reads_the_exact_directory_and_refuses_copied_resigned_and_tampered_bytes() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let attempt = attempt_record();
    let mut record = artifact(attempt.attempt.as_str(), attempt.manifest);
    stage(&store, store.root(), &attempt, &record);
    assert!(matches!(
        binding::read(&store, store.root(), &attempt).unwrap(),
        Evidence::Bound(_)
    ));
    record.run_id = text("job-0002");
    stage(&store, store.root(), &attempt, &record);
    assert!(matches!(
        binding::read(&store, store.root(), &attempt).unwrap(),
        Evidence::Misbound
    ));
    record.run_id = attempt.attempt.clone();
    record.manifest = Some(Digest::of(b"wrong"));
    stage(&store, store.root(), &attempt, &record);
    assert!(matches!(
        binding::read(&store, store.root(), &attempt).unwrap(),
        Evidence::Misbound
    ));
    record.manifest = Some(attempt.manifest);
    record.bundle = Some(Digest::of(b"wrong"));
    stage(&store, store.root(), &attempt, &record);
    assert!(matches!(
        binding::read(&store, store.root(), &attempt).unwrap(),
        Evidence::Misbound
    ));
    let artifacts = store
        .open_dir(store.root(), &name("artifacts"))
        .unwrap()
        .unwrap();
    let exact = store
        .open_dir(&artifacts, &name(attempt.attempt.as_str()))
        .unwrap()
        .unwrap();
    store.delete(&exact, &name("artifact")).unwrap();
    let mut later = attempt.clone();
    later.attempt = text("job-9999");
    stage(
        &store,
        store.root(),
        &later,
        &artifact(attempt.attempt.as_str(), attempt.manifest),
    );
    assert!(matches!(
        binding::read(&store, store.root(), &attempt).unwrap(),
        Evidence::Missing
    ));
    let artifacts = store
        .open_dir(store.root(), &name("artifacts"))
        .unwrap()
        .unwrap();
    let exact = store
        .open_dir(&artifacts, &name(attempt.attempt.as_str()))
        .unwrap()
        .unwrap();
    store.replace(&exact, &name("artifact"), b"{}").unwrap();
    assert!(matches!(
        binding::read(&store, store.root(), &attempt).unwrap(),
        Evidence::Malformed
    ));
}

#[test]
fn malformed_number_histories_hold_without_writes() {
    for (names, reason) in [
        (
            vec!["0001", "0003"],
            "attempt history has gaps or duplicates",
        ),
        (vec!["1"], "attempt number outside canonical frozen history"),
        (
            vec!["0001", "01"],
            "attempt number outside canonical frozen history",
        ),
        (
            vec!["0004"],
            "attempt number outside canonical frozen history",
        ),
        (
            vec!["0000"],
            "attempt number outside canonical frozen history",
        ),
        (vec!["18446744073709551616"], "attempt number malformed"),
    ] {
        let case = Case::new();
        let store = Store::open(&case.state).unwrap();
        let job = job(&store);
        let root = case
            .state
            .join(crate::campaign::state_fixture::attempts_dir(
                job.job().id().to_string(),
            ));
        fs::create_dir_all(&root).unwrap();
        for entry in names {
            fs::create_dir(root.join(entry)).unwrap();
        }
        let before = crate::store::fixture::snapshot(&case.state);
        assert!(
            matches!(Attempt::current(&store, verified_job(&store, &job)), Err(super::Error::Held(found)) if found == reason)
        );
        assert_eq!(crate::store::fixture::snapshot(&case.state), before);
    }
}

#[test]
fn evidence_walk_overflow_and_each_sync_error_keep_started_and_reservation() {
    let make = || {
        let case = Case::new();
        let store = Store::open(&case.state).unwrap();
        store
            .create_once(store.root(), &name("started"), b"started")
            .unwrap();
        store
            .create_once(store.root(), &name("reservation"), b"charged")
            .unwrap();
        store.mkdir(store.root(), &name("artifacts")).unwrap();
        let dir = store
            .open_dir(store.root(), &name("artifacts"))
            .unwrap()
            .unwrap();
        store.create_once(&dir, &name("bundle"), b"bundle").unwrap();
        (case, store)
    };
    let (_case, store) = make();
    let (result, reached) = scripted([], || store.evidence_barrier(store.root(), 16));
    assert!(result.unwrap().is_ok());
    assert_eq!(
        reached.iter().filter(|step| **step == Step::Sync).count(),
        7
    );
    for index in 0..reached.len() {
        let (case, store) = make();
        let (result, actual) = scripted([(index, Outcome::Errno(libc::EIO))], || {
            store.evidence_barrier(store.root(), 16)
        });
        assert!(actual.len() > index, "evidence cut {index}");
        assert!(result.unwrap().is_err());
        assert_eq!(fs::read(case.state.join("started")).unwrap(), b"started");
        assert_eq!(
            fs::read(case.state.join("reservation")).unwrap(),
            b"charged"
        );
        assert!(!case.state.join("finished").exists());
        assert!(matches!(
            store.create_once(store.root(), &name("finished"), b"finished"),
            Err(crate::store::Error::Poisoned)
        ));
    }
    let (case, store) = make();
    assert!(matches!(
        store.evidence_barrier(store.root(), 2),
        Err(crate::store::Error::ScanBound)
    ));
    assert_eq!(
        fs::read(case.state.join("reservation")).unwrap(),
        b"charged"
    );
    assert!(!case.state.join("finished").exists());
}

#[test]
fn stored_pass_is_rederived_and_a_stale_publish_token_is_held() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let job = job(&store);
    let root = case
        .state
        .join(crate::campaign::state_fixture::attempts_dir(
            job.job().id().to_string(),
        ));
    fs::create_dir_all(root.join("0001")).unwrap();
    let root_handle = crate::layout::attempts(&store, &job.job().id().to_string())
        .unwrap()
        .unwrap();
    let dir = store
        .open_dir(&root_handle, &name("0001"))
        .unwrap()
        .unwrap();
    let attempt = AttemptRecord {
        attempt: text(&format!("{}-0001", job.job().id())),
        job: job.job().id().digest(),
        manifest: job.job().manifest_sha256(),
        file_bytes: BOUND,
        number: 1,
    };
    store
        .create_record(&dir, &name("attempt"), &attempt)
        .unwrap();
    store
        .create_record(
            &dir,
            &name("intent"),
            &Intent {
                attempt: attempt.attempt.clone(),
                boot: text("boot"),
                cgroup: text("/sys/fs/cgroup/missing-attempt-lifecycle-test"),
            },
        )
        .unwrap();
    store
        .create_record(
            &dir,
            &name("started"),
            &crate::record::Started {
                attempt: attempt.attempt.clone(),
                baseline: Kernel::default(),
                boot: text("boot"),
                cgroup: text("/sys/fs/cgroup/missing-attempt-lifecycle-test"),
                cgroup_inode: 1,
                launcher_pid: 1,
            },
        )
        .unwrap();
    let artifact = artifact(attempt.attempt.as_str(), attempt.manifest);
    let evidence_dir = stage(&store, &dir, &attempt, &artifact);
    let jobs = crate::layout::jobs(&store, &job.job().id().to_string())
        .unwrap()
        .unwrap();
    let manifest = store
        .read(&jobs, &name(&format!("{}.manifest", job.job().id())), BOUND)
        .unwrap()
        .unwrap();
    store
        .replace(&evidence_dir, &name("manifest"), manifest.bytes())
        .unwrap();
    let Evidence::Bound(bound) = binding::read(&store, &dir, &attempt).unwrap() else {
        panic!("matching evidence binds")
    };
    store
        .create_record(&dir, &name("bound"), bound.binding())
        .unwrap();
    let mut result = finished();
    result.attempt = attempt.attempt.clone();
    result.binding = Binding::Matching;
    result.bound = Some(bound.binding().clone());
    store
        .create_record(&dir, &name("finished"), &result)
        .unwrap();
    let active = Attempt::current(&store, verified_job(&store, &job))
        .unwrap()
        .unwrap();
    assert_eq!(
        active
            .read_finished(&store)
            .unwrap()
            .finished()
            .record()
            .class,
        Class::Pass
    );
    crate::custody::charge(&store, &dir, &attempt.attempt).unwrap();
    assert!(matches!(
        active.read_finished(&store),
        Err(super::Error::Held("finished attempt remains charged"))
    ));
    store.delete(&dir, &name("reservation")).unwrap();
    let mut unsupported = result.clone();
    unsupported.kernel.memory.insert(text("oom_kill"), 1);
    store
        .replace_record(&dir, &name("finished"), &unsupported)
        .unwrap();
    assert!(matches!(
        active.read_finished(&store),
        Err(super::Error::Held(
            "stored outcome differs from bound evidence"
        ))
    ));
    store
        .replace_record(&dir, &name("finished"), &result)
        .unwrap();
    let mut copied = artifact.clone();
    copied.run_id = text("another-attempt");
    store
        .replace_record(&evidence_dir, &name("artifact"), &copied)
        .unwrap();
    assert!(matches!(
        active.read_finished(&store),
        Err(super::Error::Held(
            "stored outcome differs from bound evidence"
        ))
    ));
    store
        .replace_record(&evidence_dir, &name("artifact"), &artifact)
        .unwrap();
    assert_eq!(
        active
            .read_finished(&store)
            .unwrap()
            .finished()
            .record()
            .class,
        Class::Pass
    );
    fs::create_dir(root.join("0002")).unwrap();
    assert!(matches!(
        active.read_finished(&store),
        Err(super::Error::Held(
            "attempt is not the current publish token"
        ))
    ));
}

#[path = "classifier_tests.rs"]
mod matrix;

#[test]
fn missing_first_directory_holds_even_when_the_count_names_a_valid_record() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let job = job(&store);
    let attempts =
        crate::layout::make_shard(&store, crate::layout::ATTEMPTS, &job.job().id().to_string())
            .unwrap();
    store
        .mkdir(&attempts, &name(&job.job().id().to_string()))
        .unwrap();
    let root = store
        .open_dir(&attempts, &name(&job.job().id().to_string()))
        .unwrap()
        .unwrap();
    for number in [2, 3] {
        let entry = name(&format!("{number:04}"));
        store.mkdir(&root, &entry).unwrap();
        let directory = store.open_dir(&root, &entry).unwrap().unwrap();
        store
            .create_record(
                &directory,
                &name("attempt"),
                &AttemptRecord {
                    attempt: text(&format!("{}-{number:04}", job.job().id())),
                    number,
                    file_bytes: BOUND,
                    job: job.job().id().digest(),
                    manifest: job.job().manifest_sha256(),
                },
            )
            .unwrap();
    }
    let before = crate::store::fixture::snapshot(&case.state);
    assert!(matches!(
        Attempt::current(&store, verified_job(&store, &job)),
        Err(super::Error::Held("attempt history has gaps or duplicates"))
    ));
    assert_eq!(crate::store::fixture::snapshot(&case.state), before);
}

#[path = "factory_crash_tests.rs"]
mod factory_cuts;

#[test]
fn binding_rejects_command_and_file_controls_and_propagates_read_faults() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let attempt = attempt_record();
    for (control, expected) in [
        ("command", Binding::Misbound),
        ("manifest", Binding::Misbound),
        ("run.stdout", Binding::Misbound),
        ("run.stderr", Binding::Misbound),
        ("bundle", Binding::Misbound),
        ("deleted-manifest", Binding::Malformed),
        ("inspect.stderr", Binding::Malformed),
    ] {
        let mut record = artifact(attempt.attempt.as_str(), attempt.manifest);
        if control == "command" {
            record.command = text("inspect");
        }
        stage(&store, store.root(), &attempt, &record);
        let artifacts = store
            .open_dir(store.root(), &name("artifacts"))
            .unwrap()
            .unwrap();
        let directory = store
            .open_dir(&artifacts, &name(attempt.attempt.as_str()))
            .unwrap()
            .unwrap();
        match control {
            "command" => {}
            "deleted-manifest" => {
                store.delete(&directory, &name("manifest")).unwrap();
            }
            "bundle" | "inspect.stderr" => {
                store.delete(&directory, &name(control)).unwrap();
            }
            _ => {
                store.replace(&directory, &name(control), b"other").unwrap();
            }
        }
        assert_eq!(
            binding::read(&store, store.root(), &attempt)
                .unwrap()
                .state(),
            expected,
            "{control}"
        );
    }
    stage(
        &store,
        store.root(),
        &attempt,
        &artifact(attempt.attempt.as_str(), attempt.manifest),
    );
    crate::step::install(Some(crate::step::Script {
        nth: Some((Step::Read, 0, Outcome::Errno(libc::EIO))),
        ..crate::step::Script::default()
    }));
    let result = binding::read(&store, store.root(), &attempt);
    let script = crate::step::install(None).unwrap();
    assert!(script.nth.is_none());
    assert!(
        matches!(result, Err(super::Error::Store(crate::store::Error::Unreadable(error))) if error.faulted())
    );
}

#[test]
fn optional_bundle_binding_requires_exact_presence_and_digest() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let attempt = attempt_record();
    for present in [false, true] {
        for declared in [false, true] {
            let mut artifact = artifact(attempt.attempt.as_str(), attempt.manifest);
            artifact.bundle = declared.then(|| Digest::of(b"bundle"));
            let dir = stage(&store, store.root(), &attempt, &artifact);
            if !present {
                store.delete(&dir, &name("bundle")).unwrap();
            }
            let evidence = binding::read(&store, store.root(), &attempt).unwrap();
            assert_eq!(
                evidence.state(),
                if present == declared {
                    Binding::Matching
                } else {
                    Binding::Misbound
                }
            );
            if let Evidence::Bound(bound) = evidence {
                assert_eq!(bound.binding().bundle, artifact.bundle);
                assert_eq!(
                    classify(&finished(), &Evidence::Bound(bound)),
                    if present {
                        Class::Pass
                    } else {
                        Class::Incomplete
                    }
                );
            }
        }
    }
}

#[test]
fn residual_members_refuse_pass_and_keep_failure_priority() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let attempt = attempt_record();
    let mut artifact = artifact(attempt.attempt.as_str(), attempt.manifest);
    let mut final_record = finished();
    final_record.residual_members = true;
    stage(&store, store.root(), &attempt, &artifact);
    let evidence = binding::read(&store, store.root(), &attempt).unwrap();
    assert_eq!(classify(&final_record, &evidence), Class::Incomplete);
    artifact.summary.as_mut().unwrap().terminal = text("complete violation fired=03 required=03");
    stage(&store, store.root(), &attempt, &artifact);
    let evidence = binding::read(&store, store.root(), &attempt).unwrap();
    assert_eq!(classify(&final_record, &evidence), Class::Violation);
    final_record.kernel.memory.insert(text("oom_kill"), 1);
    assert_eq!(classify(&final_record, &evidence), Class::Oom);
}

#[test]
fn bound_stdout_panic_and_every_crash_signal_are_engine_failures() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let attempt = attempt_record();
    let mut artifact = artifact(attempt.attempt.as_str(), attempt.manifest);
    let stdout = b"run: the run panicked at source.rs:1:2: failure";
    artifact.workers.get_mut(&text("run")).unwrap().stdout = Digest::of(stdout);
    let dir = stage(&store, store.root(), &attempt, &artifact);
    store.replace(&dir, &name("run.stdout"), stdout).unwrap();
    assert_eq!(
        classify(
            &finished(),
            &binding::read(&store, store.root(), &attempt).unwrap()
        ),
        Class::EngineFailure
    );
    assert_eq!(
        crate::sys::CRASH_SIGNALS,
        &[
            libc::SIGILL as u64,
            libc::SIGTRAP as u64,
            libc::SIGABRT as u64,
            libc::SIGBUS as u64,
            libc::SIGFPE as u64,
            libc::SIGSEGV as u64,
            libc::SIGSYS as u64
        ]
    );
    for signal in crate::sys::CRASH_SIGNALS {
        let mut artifact = self::artifact(attempt.attempt.as_str(), attempt.manifest);
        artifact.workers.get_mut(&text("run")).unwrap().signal = Some(*signal);
        stage(&store, store.root(), &attempt, &artifact);
        assert_eq!(
            classify(
                &finished(),
                &binding::read(&store, store.root(), &attempt).unwrap()
            ),
            Class::EngineFailure
        );
    }
}

#[test]
fn evidence_bounds_cover_a_deep_exact_boundary_and_special_files() {
    let _processes = crate::store::fixture::processes();
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    store.mkdir(store.root(), &name("tree")).unwrap();
    let tree = store
        .open_dir(store.root(), &name("tree"))
        .unwrap()
        .unwrap();
    store.mkdir(&tree, &name("child")).unwrap();
    let child = store.open_dir(&tree, &name("child")).unwrap().unwrap();
    for entry in ["one", "two", "three"] {
        store
            .create_once(&child, &name(entry), b"evidence")
            .unwrap();
    }
    store.evidence_barrier(&tree, 4).unwrap();
    store
        .create_once(&child, &name("four"), b"evidence")
        .unwrap();
    let prior = crate::store::fixture::snapshot(&case.state);
    assert!(matches!(
        store.evidence_barrier(&tree, 4),
        Err(crate::store::Error::ScanBound)
    ));
    assert_eq!(crate::store::fixture::snapshot(&case.state), prior);

    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    assert!(
        std::process::Command::new("mkfifo")
            .arg(case.state.join("pipe"))
            .status()
            .unwrap()
            .success()
    );
    assert!(matches!(
        store.evidence_barrier(store.root(), super::EVIDENCE_BOUND),
        Err(crate::store::Error::Unreadable(
            crate::store::Unreadable::NotRegular
        ))
    ));
}

#[test]
fn wide_evidence_walk_and_oversized_bundle_have_bounded_reads() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    store.mkdir(store.root(), &name("tree")).unwrap();
    let tree = store
        .open_dir(store.root(), &name("tree"))
        .unwrap()
        .unwrap();
    for index in 0..256 {
        store.mkdir(&tree, &name(&format!("dir-{index}"))).unwrap();
    }
    store
        .evidence_barrier(&tree, super::EVIDENCE_BOUND)
        .unwrap();
    store.create_once(&tree, &name("bundle"), b"five!").unwrap();
    assert!(matches!(
        store.evidence_digest(&tree, &name("bundle"), 4),
        Err(crate::store::Unreadable::Oversize)
    ));
}

#[test]
fn non_directory_histories_hold_without_publication() {
    for symlink in [false, true] {
        let case = Case::new();
        let store = Store::open(&case.state).unwrap();
        let job = job(&store);
        let root = case
            .state
            .join(crate::campaign::state_fixture::attempts_dir(
                job.job().id().to_string(),
            ));
        fs::create_dir_all(&root).unwrap();
        if symlink {
            let outside = case.root.join("outside-file");
            fs::write(&outside, b"outside").unwrap();
            std::os::unix::fs::symlink(outside, root.join("0001")).unwrap();
        } else {
            fs::write(root.join("0001"), b"file").unwrap();
        }
        let prior = crate::store::fixture::snapshot(&case.state);
        assert!(matches!(
            Attempt::current(&store, verified_job(&store, &job)),
            Err(super::Error::Held("attempt entry is not a directory"))
        ));
        assert_eq!(crate::store::fixture::snapshot(&case.state), prior);
    }
}

#[test]
fn worker_output_uses_launcher_cap_and_artifact_digest_uses_envelope_bytes() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let attempt = attempt_record();
    let mut artifact = artifact(attempt.attempt.as_str(), attempt.manifest);
    let output = vec![b'x'; crate::sim::OUTPUT];
    artifact.workers.get_mut(&text("run")).unwrap().stdout = Digest::of(&output);
    let directory = stage(&store, store.root(), &attempt, &artifact);
    store
        .replace(&directory, &name("run.stdout"), &output)
        .unwrap();
    let Evidence::Bound(bound) = binding::read(&store, store.root(), &attempt).unwrap() else {
        panic!("launcher-sized output binds")
    };
    let path = case
        .state
        .join("artifacts")
        .join(attempt.attempt.as_str())
        .join("artifact");
    assert_eq!(
        bound.binding().artifact,
        Digest::of(&fs::read(path).unwrap())
    );
}

#[test]
fn controller_named_directories_are_walked_and_component_paths_cover_deep_trees() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    store.mkdir(store.root(), &name("tree")).unwrap();
    let root = store
        .open_dir(store.root(), &name("tree"))
        .unwrap()
        .unwrap();
    store.mkdir(&root, &name("bound")).unwrap();
    let bound = store.open_dir(&root, &name("bound")).unwrap().unwrap();
    store
        .create_once(&bound, &name("nested"), b"forensic")
        .unwrap();
    assert!(matches!(
        store.evidence_barrier(&root, 1),
        Err(crate::store::Error::ScanBound)
    ));
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    store.mkdir(store.root(), &name("tree")).unwrap();
    let root = store
        .open_dir(store.root(), &name("tree"))
        .unwrap()
        .unwrap();
    let component = name(&"a".repeat(80));
    store.mkdir(&root, &component).unwrap();
    let mut directory = store.open_dir(&root, &component).unwrap().unwrap();
    for _ in 1..60 {
        store.mkdir(&directory, &component).unwrap();
        directory = store.open_dir(&directory, &component).unwrap().unwrap();
    }
    store
        .create_once(&directory, &name("tail"), b"forensic")
        .unwrap();
    store.evidence_barrier(&root, 61).unwrap();
}

#[test]
fn incidental_stdout_panic_words_keep_matching_pass_evidence() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let attempt = attempt_record();
    let mut artifact = artifact(attempt.attempt.as_str(), attempt.manifest);
    let stdout = b"diagnostic: the fixture contains the words panicked at";
    artifact.workers.get_mut(&text("run")).unwrap().stdout = Digest::of(stdout);
    let directory = stage(&store, store.root(), &attempt, &artifact);
    store
        .replace(&directory, &name("run.stdout"), stdout)
        .unwrap();
    assert_eq!(
        classify(
            &finished(),
            &binding::read(&store, store.root(), &attempt).unwrap()
        ),
        Class::Pass
    );
}

#[test]
fn a_stderr_line_outside_the_rust_panic_form_keeps_matching_pass_evidence() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let attempt = attempt_record();
    let mut artifact = artifact(attempt.attempt.as_str(), attempt.manifest);
    let stderr = b"thread pool has not panicked at checkpoint";
    artifact.workers.get_mut(&text("run")).unwrap().stderr = Digest::of(stderr);
    let directory = stage(&store, store.root(), &attempt, &artifact);
    store
        .replace(&directory, &name("run.stderr"), stderr)
        .unwrap();
    let evidence = binding::read(&store, store.root(), &attempt).unwrap();
    assert_eq!(classify(&finished(), &evidence), Class::Pass);
    assert!(!evidence.into_bound().unwrap().panic());
}

/// The bulk of an evidence directory is its declared bundle, named by the
/// command, and every worker stream except the `inspect` and
/// `capabilities` stdout the report reads; a stream name the store refuses
/// gives no bulk.
#[test]
fn bulk_names_the_declared_bundle_and_the_unreported_streams() {
    let names = |artifact: &Artifact| {
        artifact.bulk().map(|names| {
            names
                .iter()
                .map(|entry| entry.as_str().to_owned())
                .collect::<Vec<_>>()
        })
    };
    let mut artifact = artifact("job-0001", Digest::of(b"manifest"));
    assert_eq!(
        names(&artifact).unwrap(),
        ["bundle", "inspect.stderr", "run.stdout", "run.stderr"]
    );
    artifact.command = text("replay");
    let worker = artifact.workers[&text("run")].clone();
    artifact
        .workers
        .insert(text("capabilities"), worker.clone());
    assert_eq!(
        names(&artifact).unwrap(),
        [
            "input",
            "capabilities.stderr",
            "inspect.stderr",
            "run.stdout",
            "run.stderr"
        ]
    );
    artifact.bundle = None;
    assert_eq!(names(&artifact).unwrap()[0], "capabilities.stderr");
    artifact.workers.insert(text("a/b"), worker);
    assert_eq!(names(&artifact), None);
}

pub(crate) fn bundle_launcher(require_started: bool) -> String {
    let guard = if require_started {
        "[ -f started ] || exit 9\n"
    } else {
        ""
    };
    format!(
        "#!/bin/sh\numask 077\nwhile [ $# -gt 0 ]; do\ncase \"$1\" in\n--run-id) shift; id=$1 ;;\n--artifacts) shift; artifacts=$1 ;;\n--manifest) shift; manifest=$1 ;;\nesac\nshift\ndone\n{guard}out=$artifacts/$id\nmkdir -p \"$out\"\nprintf bundle > \"$out/bundle\"\ncp \"$manifest\" \"$out/manifest\"\nfor phase in run inspect; do\nprintf stdout > \"$out/$phase.stdout\"\nprintf stderr > \"$out/$phase.stderr\"\ndone\ncp \"$ARTIFACT_TEMPLATE\" \"$out/artifact\"\n"
    )
}

pub(crate) fn write_bundle_template(store: &Store, job: &Admission) -> std::path::PathBuf {
    store.mkdir(store.root(), &name("template")).unwrap();
    let template = store
        .open_dir(store.root(), &name("template"))
        .unwrap()
        .unwrap();
    let mut record = artifact(
        &format!("{}-0001", job.job().id()),
        job.job().manifest_sha256(),
    );
    record.archive = Digest::parse(job.job().experiment().pins.build.as_str());
    if let Some(existing) = store
        .read_record::<Artifact>(&template, &name("record"))
        .unwrap()
    {
        assert_eq!(existing.record(), &record);
    } else {
        store
            .create_record(&template, &name("record"), &record)
            .unwrap();
    }
    store.path().join("template/record")
}
