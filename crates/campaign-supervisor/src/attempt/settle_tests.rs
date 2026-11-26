//! Settlement schedules check retained bytes, current-token fences and held history.

use super::{admit_run, artifact, job, name, stage, text, verified_job};
use crate::attempt::{Attempt, Completed, settle};
use crate::record::{
    Admission, Attempt as AttemptRecord, BOUND, Class, Finished, Intent, JobResult, Kernel, Pin,
    Started,
};
use crate::step::{Outcome, Step};
use crate::store::fixture::{Case, observed, scripted, snapshot};
use crate::store::{Dir, Error as StoreError, Store};
use std::fs;

const FILE_PARENT_SYNCS: usize = 2;
const TOKEN_SYNCS: usize = 2 * FILE_PARENT_SYNCS;
const PUBLICATION_SYNCS: usize = TOKEN_SYNCS + 2 * FILE_PARENT_SYNCS;
const CAPTURE_DEPENDENCIES: usize = 6;
const RECORD_CREATE_SYNCS: usize = 2 * FILE_PARENT_SYNCS;
const CAPTURE_RENAMES: usize = CAPTURE_DEPENDENCIES + 2;
const CAPTURE_CREATE_SYNCS: usize =
    2 + CAPTURE_DEPENDENCIES * FILE_PARENT_SYNCS + 2 * RECORD_CREATE_SYNCS;
const CAPTURE_RETAINED_SYNCS: usize =
    2 + CAPTURE_DEPENDENCIES * FILE_PARENT_SYNCS + 2 * FILE_PARENT_SYNCS;

fn selection_syncs(validated: usize) -> usize {
    let history_syncs = validated * 5 * FILE_PARENT_SYNCS;
    FILE_PARENT_SYNCS + TOKEN_SYNCS + history_syncs
}

fn only_capture_progress(
    before: &std::collections::BTreeMap<std::path::PathBuf, Option<Vec<u8>>>,
    after: &std::collections::BTreeMap<std::path::PathBuf, Option<Vec<u8>>>,
) {
    for (path, bytes) in before {
        assert_eq!(
            after.get(path),
            Some(bytes),
            "retained bytes changed at {path:?}"
        );
    }
    for path in after.keys().filter(|path| !before.contains_key(*path)) {
        assert!(
            path.starts_with("findings") || path.file_name().is_some_and(|name| name == "captured"),
            "unexpected publication {path:?}"
        );
    }
}

pub(crate) struct Fixture {
    pub(crate) case: Case,
    pub(crate) store: Store,
    pub(crate) job: Admission,
}
impl Fixture {
    pub(crate) fn new(classes: &[Class]) -> Self {
        let case = Case::new();
        let store = Store::open(&case.state).unwrap();
        let job = job(&store);
        let fixture = Self { case, store, job };
        for (index, class) in classes.iter().enumerate() {
            fixture.add(index as u64 + 1, *class);
        }
        fixture
    }
    fn add(&self, number: u64, class: Class) {
        let store = &self.store;
        let id = self.job.job().id();
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
        let record = AttemptRecord {
            attempt: text(&format!("{id}-{number:04}")),
            file_bytes: BOUND,
            job: id.digest(),
            manifest: self.job.job().manifest_sha256(),
            number,
        };
        store
            .create_record(&directory, &name("attempt"), &record)
            .unwrap();
        let intent = Intent {
            attempt: record.attempt.clone(),
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
        let exit = match class {
            Class::Violation | Class::Unsuccessful | Class::Inconclusive => 1,
            Class::EngineFailure | Class::Incomplete => 4,
            Class::Rejected => 2,
            Class::Interrupted => 5,
            Class::Watchdog => 6,
            Class::Infrastructure => 125,
            _ => 0,
        };
        let mut artifact = artifact(record.attempt.as_str(), record.manifest);
        artifact.archive =
            crate::record::Digest::parse(self.job.job().experiment().pins.build.as_str());
        artifact.class = text(match exit {
            1 => "complete",
            2 => "rejected",
            4 => "incomplete",
            5 => "interrupted",
            6 => "watchdog",
            _ => "counts",
        });
        artifact.summary.as_mut().unwrap().terminal = text(match class {
            Class::Violation => "complete violation fired=03 required=03",
            Class::EngineFailure => "infrastructure defect",
            Class::Unsuccessful => "complete unsuccessful fired=00 required=03",
            Class::Inconclusive => "complete inconclusive fired=00 required=03",
            _ => "complete pass fired=03 required=03",
        });
        if matches!(class, Class::Rejected | Class::Disagreement) {
            artifact.workers.get_mut(&text("run")).unwrap().exit = Some(2);
        }
        stage(store, &directory, &record, &artifact);
        let manifest = fs::read(
            self.case
                .state
                .join(crate::campaign::state_fixture::job_file(format!(
                    "{id}.manifest"
                ))),
        )
        .unwrap();
        let evidence_dir = self.artifact_directory(number);
        store
            .replace(&evidence_dir, &name("manifest"), &manifest)
            .unwrap();
        if class == Class::MalformedEvidence {
            store
                .replace(&evidence_dir, &name("artifact"), b"broken")
                .unwrap();
        }
        if class == Class::MisboundEvidence {
            store
                .replace(&evidence_dir, &name("bundle"), b"foreign")
                .unwrap();
        }
        let evidence = crate::attempt::binding::read(store, &directory, &record).unwrap();
        let mut kernel = Kernel::default();
        match class {
            Class::Oom => {
                kernel.memory.insert(text("oom_kill"), 1);
            }
            Class::PidLimit => {
                kernel.pids.insert(text("max"), 1);
            }
            Class::CpuLimit => {
                kernel.cpu.insert(text("nr_throttled"), 1);
            }
            Class::MixedLimits => {
                kernel.memory.insert(text("oom"), 1);
                kernel.pids.insert(text("max"), 1);
            }
            _ => {}
        }
        let finished = Finished {
            attempt: record.attempt,
            binding: evidence.state(),
            bound: evidence.binding().cloned(),
            class,
            exit: Some(exit),
            interruption: match class {
                Class::CpuLimit => Some(crate::sys::CPU_SIGNAL as u64),
                Class::OutputLimit => Some(crate::sys::OUTPUT_SIGNAL as u64),
                _ => None,
            },
            kernel,
            residual_members: false,
            signal: (class == Class::Signal).then_some(15),
            watchdog: class == Class::Watchdog,
        };
        assert_eq!(
            crate::attempt::classify::classify(&finished, &evidence),
            class
        );
        if let Some(bound) = &finished.bound {
            store
                .create_record(&directory, &name("bound"), bound)
                .unwrap();
        }
        store
            .create_record(&directory, &name("finished"), &finished)
            .unwrap();
    }
    fn directory(&self, number: u64) -> Dir {
        let root = crate::layout::attempts(&self.store, &self.job.job().id().to_string())
            .unwrap()
            .unwrap();
        self.store
            .open_dir(&root, &name(&format!("{number:04}")))
            .unwrap()
            .unwrap()
    }
    fn attempt_path(&self, number: u64) -> std::path::PathBuf {
        self.case
            .state
            .join(crate::campaign::state_fixture::attempts_dir(
                self.job.job().id().to_string(),
            ))
            .join(format!("{number:04}"))
    }
    fn artifact_directory(&self, number: u64) -> Dir {
        let dir = self.directory(number);
        let artifacts = self
            .store
            .open_dir(&dir, &name("artifacts"))
            .unwrap()
            .unwrap();
        self.store
            .open_dir(
                &artifacts,
                &name(&format!("{}-{number:04}", self.job.job().id())),
            )
            .unwrap()
            .unwrap()
    }
    fn expected(&self, number: u64) -> JobResult {
        let directory = self.directory(number);
        let finished = self
            .store
            .read_record::<Finished>(&directory, &name("finished"))
            .unwrap()
            .unwrap();
        JobResult {
            attempt: number,
            finished: finished.record().clone(),
            job: self.job.job().id().digest(),
            manifest: self.job.job().manifest_sha256(),
        }
    }
    fn completion(&self) -> Completed {
        Attempt::current(&self.store, verified_job(&self.store, &self.job))
            .unwrap()
            .unwrap()
            .read_finished(&self.store)
            .unwrap()
    }
    pub(crate) fn settle(
        &self,
    ) -> Result<Option<crate::record::Verified<crate::record::JobResult>>, crate::attempt::Error>
    {
        settle(
            &self.store,
            verified_job(&self.store, &self.job),
            self.completion(),
        )
    }
    fn reopen(self) -> Self {
        drop(self.store);
        Self {
            store: Store::open(&self.case.state).unwrap(),
            case: self.case,
            job: self.job,
        }
    }
    fn killed_at(classes: &[Class], index: usize) -> Self {
        let f = Self::new(classes);
        let completion = f.completion();
        let job = verified_job(&f.store, &f.job);
        assert!(
            scripted([(index, Outcome::Kill)], || settle(
                &f.store, job, completion
            ))
            .0
            .is_none()
        );
        f
    }
    fn path(&self, suffix: &str) -> std::path::PathBuf {
        let suffix = if suffix == "result" {
            "result.json"
        } else {
            suffix
        };
        self.case
            .state
            .join(crate::campaign::state_fixture::job_file(format!(
                "{}.{}",
                self.job.job().id(),
                suffix
            )))
    }
}

#[test]
fn stale_completion_after_new_intent_publishes_nothing() {
    let f = Fixture::new(&[Class::Violation]);
    let old = f.completion();
    f.add(2, Class::Pass);
    let latest = f.attempt_path(2);
    for record in ["started", "finished", "bound"] {
        fs::remove_file(latest.join(record)).unwrap();
    }
    let before = snapshot(&f.case.state);
    assert!(matches!(
        settle(&f.store, verified_job(&f.store, &f.job), old),
        Err(crate::attempt::Error::Held(
            "completion belongs to another publisher"
        ))
    ));
    assert_eq!(snapshot(&f.case.state), before);
    assert!(!f.path("pin").exists());
    assert!(!f.path("result").exists());
}

#[test]
fn earliest_failure_wins_and_later_pass_and_duplicate_preserve_bytes() {
    for failure in [Class::Violation, Class::EngineFailure] {
        let f = Fixture::new(&[failure]);
        let first = f.settle().unwrap().unwrap();
        assert_eq!(first.record(), &f.expected(1));
        let before = snapshot(&f.case.state);
        f.settle().unwrap();
        assert_eq!(snapshot(&f.case.state), before);
        let pin = fs::read(f.path("pin")).unwrap();
        let jobs = crate::layout::jobs(&f.store, &f.job.job().id().to_string())
            .unwrap()
            .unwrap();
        let retained = f
            .store
            .read_record::<Pin>(
                &jobs,
                &name(f.path("pin").file_name().unwrap().to_str().unwrap()),
            )
            .unwrap()
            .unwrap();
        assert_eq!(&retained.record().result, first.record());
        let result = fs::read(f.path("result")).unwrap();
        f.add(2, Class::Pass);
        let later = f.settle().unwrap().unwrap();
        assert_eq!(later.record(), first.record());
        assert_eq!(fs::read(f.path("pin")).unwrap(), pin);
        assert_eq!(fs::read(f.path("result")).unwrap(), result);
    }
    let f = Fixture::new(&[Class::EngineFailure, Class::Violation, Class::Pass]);
    assert_eq!(f.settle().unwrap().unwrap().record(), &f.expected(1));
}

#[test]
fn final_classes_publish_immediately_and_pass_publishes_once() {
    for class in [Class::Unsuccessful, Class::Inconclusive] {
        let f = Fixture::new(&[class]);
        assert_eq!(f.settle().unwrap().unwrap().record(), &f.expected(1));
        let before = snapshot(&f.case.state);
        assert_eq!(f.settle().unwrap().unwrap().record(), &f.expected(1));
        assert_eq!(snapshot(&f.case.state), before);
        assert!(!f.path("pin").exists());
    }
    let f = Fixture::new(&[Class::Pass]);
    assert_eq!(f.settle().unwrap().unwrap().record(), &f.expected(1));
    let before = snapshot(&f.case.state);
    f.settle().unwrap();
    assert_eq!(snapshot(&f.case.state), before);
    assert!(!f.path("pin").exists());
    // Re-admitting the settled job finds its record in the job's shard.
    let again = admit_run(&f.store, 0).unwrap();
    assert!(again.existing);
    assert_eq!(again.record, f.job);
    assert_eq!(snapshot(&f.case.state), before);
}

#[test]
fn history_continuing_past_a_verdict_is_held_unless_a_failure_pins() {
    for verdict in [Class::Pass, Class::Unsuccessful, Class::Inconclusive] {
        for later in [Class::Pass, Class::Unsuccessful, Class::Oom] {
            let f = Fixture::new(&[verdict, later]);
            let before = snapshot(&f.case.state);
            assert!(matches!(
                f.settle(),
                Err(crate::attempt::Error::Held(
                    "attempt history continues past a verdict"
                ))
            ));
            assert_eq!(snapshot(&f.case.state), before);
            assert!(!f.path("pin").exists());
            assert!(!f.path("result").exists());
        }
        let f = Fixture::new(&[verdict, Class::Violation]);
        assert_eq!(f.settle().unwrap().unwrap().record(), &f.expected(2));
        assert!(f.path("pin").exists());
        let f = Fixture::new(&[verdict, Class::Oom, Class::Pass]);
        let before = snapshot(&f.case.state);
        assert!(matches!(
            f.settle(),
            Err(crate::attempt::Error::Held(
                "attempt history continues past a verdict"
            ))
        ));
        assert_eq!(snapshot(&f.case.state), before);
        assert!(!f.path("result").exists());
    }
    let f = Fixture::new(&[Class::Pass]);
    assert_eq!(f.settle().unwrap().unwrap().record(), &f.expected(1));
    f.add(2, Class::Pass);
    let before = snapshot(&f.case.state);
    assert!(matches!(
        f.settle(),
        Err(crate::attempt::Error::Held(
            "attempt history continues past a verdict"
        ))
    ));
    assert_eq!(snapshot(&f.case.state), before);
}

#[test]
fn held_history_pin_or_result_grants_no_publication() {
    for (target, reason) in [
        ("attempt", None),
        ("finished", None),
        ("admission", None),
        ("pin", None),
        ("result", None),
        ("history", Some("attempt history has gaps or duplicates")),
        (
            "wrong-pin",
            Some("retained pin differs from failure history"),
        ),
        ("wrong-result", Some("result differs from selected outcome")),
        ("lost-pin", Some("failure result lacks retained pin")),
        ("manifest", Some("frozen manifest digest differs")),
        ("lost-manifest", Some("frozen manifest vanished")),
        ("lost-admission", Some("admission vanished")),
        ("lost-attempts", Some("job has no attempts")),
        (
            "different-admission",
            Some("admission differs from publisher"),
        ),
        (
            "changed-finished",
            Some("completion differs from finished record"),
        ),
        (
            "wrong-attempt",
            Some("attempt identity differs from frozen job"),
        ),
        ("missing-bound", Some("finished lacks bound record")),
        ("missing-intent", Some("attempt lacks intent")),
        ("wrong-intent", Some("intent names another attempt")),
        ("missing-started", Some("pass lacks started witness")),
        ("wrong-started-attempt", Some("started differs from intent")),
        ("wrong-started-boot", Some("started differs from intent")),
        ("wrong-started-cgroup", Some("started differs from intent")),
        ("non-cgroup-tree", None),
    ] {
        let f = Fixture::new(&[if target == "missing-started" {
            Class::Pass
        } else {
            Class::Violation
        }]);
        let completion = f.completion();
        let job = verified_job(&f.store, &f.job);
        let directory = f.attempt_path(1);
        match target {
            "wrong-attempt" => {
                let dir = f.directory(1);
                let record = f
                    .store
                    .read_record::<AttemptRecord>(&dir, &name("attempt"))
                    .unwrap()
                    .unwrap();
                let mut record = record.record().clone();
                record.manifest = crate::record::Digest::of(b"other manifest");
                f.store
                    .replace_record(&dir, &name("attempt"), &record)
                    .unwrap();
            }
            "missing-bound" => fs::remove_file(directory.join("bound")).unwrap(),
            "missing-intent" => fs::remove_file(directory.join("intent")).unwrap(),
            "missing-started" => fs::remove_file(directory.join("started")).unwrap(),
            "non-cgroup-tree" => fs::create_dir(f.case.state.join("gone")).unwrap(),
            "wrong-intent" => {
                let dir = f.directory(1);
                let intent = f
                    .store
                    .read_record::<Intent>(&dir, &name("intent"))
                    .unwrap()
                    .unwrap();
                let mut intent = intent.record().clone();
                intent.attempt = text("other-attempt");
                f.store
                    .replace_record(&dir, &name("intent"), &intent)
                    .unwrap();
            }
            "wrong-started-attempt" | "wrong-started-boot" | "wrong-started-cgroup" => {
                let dir = f.directory(1);
                let started = f
                    .store
                    .read_record::<Started>(&dir, &name("started"))
                    .unwrap()
                    .unwrap();
                let mut started = started.record().clone();
                match target {
                    "wrong-started-attempt" => started.attempt = text("other-attempt"),
                    "wrong-started-boot" => started.boot = text("other-boot"),
                    _ => started.cgroup = text("other-cgroup"),
                }
                f.store
                    .replace_record(&dir, &name("started"), &started)
                    .unwrap();
            }
            "different-admission" => {
                let jobs = crate::layout::jobs(&f.store, &f.job.job().id().to_string())
                    .unwrap()
                    .unwrap();
                let changed =
                    Admission::new(text("other-archive"), f.job.job().clone(), f.job.purpose())
                        .unwrap();
                f.store
                    .replace_record(
                        &jobs,
                        &name(&format!("{}.json", f.job.job().id())),
                        &changed,
                    )
                    .unwrap();
            }
            "changed-finished" => {
                let directory = f.directory(1);
                let mut changed = completion.finished().record().clone();
                changed.kernel.cpu.insert(text("usage_usec"), 1);
                f.store
                    .replace_record(&directory, &name("finished"), &changed)
                    .unwrap();
            }
            "lost-manifest" => fs::remove_file(f.path("manifest")).unwrap(),
            "lost-admission" => fs::remove_file(f.path("json")).unwrap(),
            "lost-attempts" => fs::remove_dir_all(f.case.state.join("attempts")).unwrap(),
            "lost-pin" => {
                f.settle().unwrap();
                fs::remove_file(f.path("pin")).unwrap();
            }
            "attempt" | "finished" => fs::write(directory.join(target), b"broken").unwrap(),
            "admission" => fs::write(f.path("json"), b"broken").unwrap(),
            "history" => fs::rename(&directory, directory.with_file_name("0003")).unwrap(),
            "wrong-pin" | "wrong-result" => {
                let jobs = crate::layout::jobs(&f.store, &f.job.job().id().to_string())
                    .unwrap()
                    .unwrap();
                let mut result = crate::record::JobResult {
                    attempt: 2,
                    finished: completion.finished().record().clone(),
                    job: f.job.job().id().digest(),
                    manifest: f.job.job().manifest_sha256(),
                };
                result.finished.class = Class::Pass;
                if target == "wrong-pin" {
                    f.store
                        .create_record(
                            &jobs,
                            &name(f.path("pin").file_name().unwrap().to_str().unwrap()),
                            &Pin { result },
                        )
                        .unwrap();
                } else {
                    f.store
                        .create_record(
                            &jobs,
                            &name(f.path("pin").file_name().unwrap().to_str().unwrap()),
                            &Pin {
                                result: f.expected(1),
                            },
                        )
                        .unwrap();
                    f.store
                        .create_record(
                            &jobs,
                            &name(f.path("result").file_name().unwrap().to_str().unwrap()),
                            &result,
                        )
                        .unwrap();
                }
            }
            _ => fs::write(f.path(target), b"broken").unwrap(),
        }
        let before = snapshot(&f.case.state);
        let error = settle(&f.store, job, completion).unwrap_err();
        if matches!(
            target,
            "attempt" | "finished" | "admission" | "pin" | "result"
        ) {
            assert!(
                matches!(error, crate::attempt::Error::Record(_)),
                "{target}: {error:?}"
            );
        }
        if target == "non-cgroup-tree" {
            assert!(
                matches!(&error, crate::attempt::Error::Io(io) if io.kind() == std::io::ErrorKind::InvalidInput),
                "{error:?}"
            );
        }
        if let Some(reason) = reason {
            assert!(
                matches!(error, crate::attempt::Error::Held(found) if found == reason),
                "{target}: {error:?}"
            );
        }
        if matches!(target, "pin" | "result" | "wrong-pin" | "wrong-result") {
            only_capture_progress(&before, &snapshot(&f.case.state));
            assert!(f.attempt_path(1).join("captured").exists());
        } else {
            assert_eq!(snapshot(&f.case.state), before, "{target}");
        }
    }
}

#[test]
fn every_publish_crash_recovers_retained_bytes_and_each_barrier_fault_poisons() {
    let baseline = Fixture::new(&[Class::Violation]);
    let completion = baseline.completion();
    let job = verified_job(&baseline.store, &baseline.job);
    let (result, steps) = scripted([], || settle(&baseline.store, job, completion));
    assert!(result.unwrap().unwrap().is_some());
    assert_eq!(
        steps.iter().filter(|step| **step == Step::Sync).count(),
        selection_syncs(1) + CAPTURE_CREATE_SYNCS + 2 * PUBLICATION_SYNCS
    );
    assert_eq!(
        steps.iter().filter(|step| **step == Step::Rename).count(),
        CAPTURE_RENAMES + 2
    );
    let finding_id = format!("{}-0001", baseline.job.job().id());
    let finding_bytes = fs::read(
        baseline
            .case
            .state
            .join("findings")
            .join(&finding_id)
            .join("finding.json"),
    )
    .unwrap();
    let before_result_rename = steps
        .iter()
        .enumerate()
        .rfind(|(_, step)| **step == Step::Rename)
        .unwrap()
        .0;
    let mut saw_pin_without_result = false;
    let mut saw_result = false;
    for (index, step) in steps.iter().enumerate() {
        let f = Fixture::new(&[Class::Violation]);
        let completion = f.completion();
        let job = verified_job(&f.store, &f.job);
        let (result, reached) = scripted([(index, Outcome::Kill)], || {
            settle(&f.store, job, completion)
        });
        assert!(result.is_none(), "{index} {step:?}");
        assert_eq!(reached.last(), Some(step));
        let pin = fs::read(f.path("pin")).ok();
        let result = fs::read(f.path("result")).ok();
        saw_pin_without_result |= pin.is_some() && result.is_none();
        saw_result |= result.is_some();
        assert_eq!(
            crate::campaign::findings(&f.case.state).unwrap()["release_blockers"],
            serde_json::json!([finding_id])
        );
        let f = f.reopen();
        let at_restart = snapshot(&f.case.state);
        let recovered = f.settle().unwrap().unwrap();
        if result.is_some() {
            assert_eq!(snapshot(&f.case.state), at_restart, "{index} {step:?}");
        }
        assert_eq!(recovered.record(), &f.expected(1));
        let listed = crate::campaign::findings(&f.case.state).unwrap();
        assert_eq!(
            listed["findings"][0]["verified"]["kind"], "violation",
            "{index} {step:?}"
        );
        assert!(listed["findings"][0].get("held").is_none());
        assert_eq!(listed["release_blockers"], serde_json::json!([finding_id]));
        assert_eq!(
            fs::read(
                f.case
                    .state
                    .join("findings")
                    .join(&finding_id)
                    .join("finding.json")
            )
            .unwrap(),
            finding_bytes
        );

        if let Some(pin) = pin {
            assert_eq!(fs::read(f.path("pin")).unwrap(), pin);
        }
        if let Some(result) = result {
            assert_eq!(fs::read(f.path("result")).unwrap(), result);
        }
        let once = snapshot(&f.case.state);
        f.settle().unwrap();
        assert_eq!(snapshot(&f.case.state), once);
        let mutation = matches!(
            step,
            Step::Sync | Step::Close | Step::Rename | Step::Write | Step::Unlink | Step::Mkdir
        ) || (*step == Step::Open && index > 0 && steps[index - 1] == Step::Unlink);
        let errors = if mutation {
            &[libc::EIO, libc::EROFS][..]
        } else {
            &[libc::EIO][..]
        };
        for &errno in errors {
            let f = Fixture::new(&[Class::Violation]);
            let completion = f.completion();
            let job = verified_job(&f.store, &f.job);
            let (result, reached) = scripted([(index, Outcome::Errno(errno))], || {
                settle(&f.store, job, completion)
            });
            assert!(result.unwrap().is_err(), "{index} {step:?}");
            assert_eq!(reached[index], *step);
            assert!(
                !reached[index + 1..].contains(&Step::Rename),
                "fault retried publication"
            );
            if index <= before_result_rename {
                assert!(!f.path("result").exists());
            }
            if mutation {
                assert!(matches!(
                    f.store
                        .create_once(f.store.root(), &name("forbidden"), b"write"),
                    Err(StoreError::Poisoned)
                ));
            }
        }
    }
    assert!(saw_pin_without_result);
    assert!(saw_result);
}

#[test]
fn a_failure_after_retry_selects_its_exact_number_and_holds_corrupt_earlier_history() {
    let f = Fixture::new(&[Class::Incomplete, Class::EngineFailure, Class::Violation]);
    let result = f.settle().unwrap().unwrap();
    assert_eq!(result.record(), &f.expected(2));
    let before = snapshot(&f.case.state);
    f.settle().unwrap();
    only_capture_progress(&before, &snapshot(&f.case.state));
    let f = Fixture::new(&[Class::Incomplete, Class::Violation]);
    let completion = f.completion();
    let earlier = f.attempt_path(1).join("finished");
    fs::write(earlier, b"broken").unwrap();
    let before = snapshot(&f.case.state);
    assert!(settle(&f.store, verified_job(&f.store, &f.job), completion).is_err());
    only_capture_progress(&before, &snapshot(&f.case.state));
    for (change, reason) in [
        ("foreign", "finished names another attempt"),
        ("missing", "attempt is unfinished"),
    ] {
        let f = Fixture::new(&[Class::Incomplete, Class::Violation]);
        let completion = f.completion();
        if change == "missing" {
            fs::remove_file(f.attempt_path(1).join("finished")).unwrap();
        } else {
            let mut finished = f.expected(1).finished;
            finished.attempt = text("other-attempt");
            f.store
                .replace_record(&f.directory(1), &name("finished"), &finished)
                .unwrap();
        }
        let before = snapshot(&f.case.state);
        assert!(matches!(
            settle(&f.store, verified_job(&f.store, &f.job), completion),
            Err(crate::attempt::Error::Held(found)) if found == reason
        ));
        only_capture_progress(&before, &snapshot(&f.case.state));
    }
}

#[test]
fn a_stale_finished_completion_is_refused_and_current_completion_can_publish() {
    let f = Fixture::new(&[Class::Incomplete]);
    let old = f.completion();
    let old_attempt = Attempt::current(&f.store, verified_job(&f.store, &f.job))
        .unwrap()
        .unwrap();
    f.add(2, Class::Pass);
    let before = snapshot(&f.case.state);
    assert!(matches!(
        old_attempt.current_token(&f.store),
        Err(crate::attempt::Error::Held(
            "attempt is not the current publish token"
        ))
    ));
    assert!(matches!(
        settle(&f.store, verified_job(&f.store, &f.job), old),
        Err(crate::attempt::Error::Held(
            "completion belongs to another publisher"
        ))
    ));
    assert_eq!(snapshot(&f.case.state), before);
    assert_eq!(f.settle().unwrap().unwrap().record(), &f.expected(2));
}

#[test]
fn every_pass_publish_crash_recovers_without_creating_a_pin() {
    let baseline = Fixture::new(&[Class::Pass]);
    let completion = baseline.completion();
    let job = verified_job(&baseline.store, &baseline.job);
    let (result, steps) = scripted([], || settle(&baseline.store, job, completion));
    assert!(result.unwrap().unwrap().is_some());
    assert_eq!(
        steps.iter().filter(|step| **step == Step::Sync).count(),
        selection_syncs(1) + RECORD_CREATE_SYNCS + PUBLICATION_SYNCS
    );
    let mut saw_result = false;
    for (index, step) in steps.iter().enumerate() {
        let f = Fixture::new(&[Class::Pass]);
        let completion = f.completion();
        let job = verified_job(&f.store, &f.job);
        let (result, reached) = scripted([(index, Outcome::Kill)], || {
            settle(&f.store, job, completion)
        });
        assert!(result.is_none());
        assert_eq!(reached.last(), Some(step));
        let bytes = fs::read(f.path("result")).ok();
        saw_result |= bytes.is_some();
        let f = f.reopen();
        let at_restart = snapshot(&f.case.state);
        let recovered = f.settle().unwrap().unwrap();
        if bytes.is_some() {
            assert_eq!(snapshot(&f.case.state), at_restart, "{index} {step:?}");
        }
        assert_eq!(recovered.record(), &f.expected(1));
        let once = snapshot(&f.case.state);
        f.settle().unwrap();
        assert_eq!(snapshot(&f.case.state), once);
        assert!(!f.path("pin").exists());
        if let Some(bytes) = bytes {
            assert_eq!(fs::read(f.path("result")).unwrap(), bytes);
        }
    }
    assert!(saw_result);
}

#[test]
fn matching_capture_markers_keep_prior_attempts_to_three_reads_and_one_barrier() {
    let cost = |classes: &[Class]| {
        let f = Fixture::new(classes);
        for number in 1..classes.len() as u64 {
            let directory = f.directory(number);
            let finish = f
                .store
                .read_record::<Finished>(&directory, &name("finished"))
                .unwrap()
                .unwrap();
            let marker = crate::record::Captured {
                attempt: finish.record().attempt.clone(),
                finding: None,
                finished: crate::record::Digest::of(finish.read().bytes()),
            };
            f.store
                .create_record(&directory, &name("captured"), &marker)
                .unwrap();
        }
        let completion = f.completion();
        let job = verified_job(&f.store, &f.job);
        let (result, steps) = scripted([], || settle(&f.store, job, completion));
        assert!(result.unwrap().unwrap().is_none(), "{classes:?}");
        let count = |kind| steps.iter().filter(|step| **step == kind).count();
        (count(Step::Sync), count(Step::Read))
    };
    let (syncs, reads) = cost(&[Class::Oom]);
    assert_eq!(syncs, selection_syncs(1) + RECORD_CREATE_SYNCS);
    assert_eq!(
        cost(&[Class::Oom, Class::Disagreement]),
        (syncs + FILE_PARENT_SYNCS, reads + 3)
    );
}

fn retry_to_limit(class: Class) {
    let f = Fixture::new(&[class]);
    let check = |before: std::collections::BTreeMap<std::path::PathBuf, Option<Vec<u8>>>,
                 number| {
        let after = snapshot(&f.case.state);
        if class == Class::Watchdog {
            for (entry, bytes) in &before {
                assert_eq!(after.get(entry), Some(bytes));
            }
            let new_paths: std::collections::BTreeSet<_> = after
                .keys()
                .filter(|entry| !before.contains_key(*entry))
                .cloned()
                .collect();
            let prefix = format!("findings/{}-{number:04}", f.job.job().id());
            let expected: std::collections::BTreeSet<_> = [
                "",
                "/manifest",
                "/bundle",
                "/run.stdout",
                "/run.stderr",
                "/inspect.stdout",
                "/inspect.stderr",
                "/finding.json",
            ]
            .into_iter()
            .map(|suffix| std::path::PathBuf::from(format!("{prefix}{suffix}")))
            .chain((number == 1).then(|| std::path::PathBuf::from("findings")))
            .chain([std::path::PathBuf::from(format!(
                "{}/captured",
                crate::layout::attempt_path(&f.job.job().id().to_string(), number).display()
            ))])
            .collect();
            assert_eq!(new_paths, expected);
        } else {
            let mut expected = before;
            let marker = std::path::PathBuf::from(format!(
                "{}/captured",
                crate::layout::attempt_path(&f.job.job().id().to_string(), number).display()
            ));
            expected.insert(marker.clone(), after[&marker].clone());
            assert_eq!(after, expected, "{class:?}");
        }
    };
    let before = snapshot(&f.case.state);
    assert!(f.settle().unwrap().is_none(), "{class:?}");
    check(before, 1);
    assert!(!f.path("pin").exists());
    assert!(!f.path("result").exists());
    f.add(2, class);
    let before = snapshot(&f.case.state);
    assert!(f.settle().unwrap().is_none(), "{class:?}");
    check(before, 2);
    f.add(3, class);
    let result = f.settle().unwrap().unwrap();
    assert_eq!(result.record(), &f.expected(3));
    let before = snapshot(&f.case.state);
    assert_eq!(f.settle().unwrap().unwrap().record(), &f.expected(3));
    assert_eq!(snapshot(&f.case.state), before);
    assert!(!f.path("pin").exists());
}

macro_rules! retry_cases {
    ($($name:ident => $class:ident),+ $(,)?) => {
        $(#[test] fn $name() { retry_to_limit(Class::$class); })+
    };
}
retry_cases! {
    incomplete_retries_until_the_limit => Incomplete,
    interrupted_retries_until_the_limit => Interrupted,
    watchdog_retries_until_the_limit => Watchdog,
    rejected_retries_until_the_limit => Rejected,
    infrastructure_retries_until_the_limit => Infrastructure,
    signal_retries_until_the_limit => Signal,
    oom_retries_until_the_limit => Oom,
    pid_limit_retries_until_the_limit => PidLimit,
    cpu_limit_retries_until_the_limit => CpuLimit,
    output_limit_retries_until_the_limit => OutputLimit,
    mixed_limits_retry_until_the_limit => MixedLimits,
    malformed_evidence_retries_until_the_limit => MalformedEvidence,
    misbound_evidence_retries_until_the_limit => MisboundEvidence,
    disagreement_retries_until_the_limit => Disagreement,
}

#[test]
fn retained_pin_and_result_barrier_faults_poison_recovery_and_keep_established_bytes() {
    for (classes, number) in [
        (&[Class::Violation][..], 1),
        (
            &[Class::Incomplete, Class::EngineFailure, Class::Pass][..],
            2,
        ),
    ] {
        let baseline = Fixture::new(classes);
        let completion = baseline.completion();
        let job = verified_job(&baseline.store, &baseline.job);
        let (_, publish_steps) = scripted([], || settle(&baseline.store, job, completion));
        let renames: Vec<_> = publish_steps
            .iter()
            .enumerate()
            .filter(|(_, step)| **step == Step::Rename)
            .map(|(index, _)| index)
            .collect();
        assert_eq!(renames.len(), CAPTURE_RENAMES + 2 + classes.len() - 1);
        let renames = &renames[renames.len() - 2..];
        for &cut in renames {
            let base = Fixture::killed_at(classes, cut + 1).reopen();
            assert!(base.path("pin").exists());
            assert_eq!(base.path("result").exists(), cut == renames[1]);
            let completion = base.completion();
            let job = verified_job(&base.store, &base.job);
            let (result, recovery_steps) = scripted([], || settle(&base.store, job, completion));
            let result = result.unwrap().unwrap().unwrap();
            assert_eq!(result.record(), &base.expected(number));
            let syncs: Vec<_> = recovery_steps
                .iter()
                .enumerate()
                .filter(|(_, step)| **step == Step::Sync)
                .collect();
            let result_retained = cut == renames[1];
            let selected_syncs = selection_syncs(1 + usize::from(number < classes.len() as u64));
            let marker_syncs = (classes.len() - 1) * FILE_PARENT_SYNCS;
            let capture_syncs = if number == classes.len() as u64 {
                CAPTURE_RETAINED_SYNCS
            } else {
                FILE_PARENT_SYNCS
            };
            assert_eq!(
                syncs.len(),
                selected_syncs
                    + FILE_PARENT_SYNCS
                    + marker_syncs
                    + capture_syncs
                    + if result_retained {
                        TOKEN_SYNCS + FILE_PARENT_SYNCS
                    } else {
                        PUBLICATION_SYNCS
                    }
            );
            assert_eq!(recovery_steps.contains(&Step::Write), !result_retained);
            if !result_retained {
                let write = recovery_steps
                    .iter()
                    .position(|step| *step == Step::Write)
                    .unwrap();
                assert_eq!(
                    recovery_steps[..write]
                        .iter()
                        .filter(|step| **step == Step::Sync)
                        .count(),
                    selected_syncs + FILE_PARENT_SYNCS + marker_syncs + capture_syncs + TOKEN_SYNCS
                );
            }
            for (index, step) in syncs {
                for errno in [libc::EIO, libc::EROFS] {
                    let f = Fixture::killed_at(classes, cut + 1).reopen();
                    assert!(f.path("pin").exists());
                    assert_eq!(f.path("result").exists(), cut == renames[1]);
                    let completion = f.completion();
                    let again = f.completion();
                    let job = verified_job(&f.store, &f.job);
                    let job_again = verified_job(&f.store, &f.job);
                    let pin = fs::read(f.path("pin")).ok();
                    let result = fs::read(f.path("result")).ok();
                    let (failed, reached) = scripted([(index, Outcome::Errno(errno))], || {
                        settle(&f.store, job, completion)
                    });
                    assert!(failed.unwrap().is_err(), "{index} {step:?}");
                    assert_eq!(reached[index], *step);
                    assert!(!reached[index + 1..].contains(&Step::Rename));
                    if let Some(pin) = pin {
                        assert_eq!(fs::read(f.path("pin")).unwrap(), pin);
                    }
                    if let Some(result) = result {
                        assert_eq!(fs::read(f.path("result")).unwrap(), result);
                    }
                    let before = snapshot(&f.case.state);
                    assert!(settle(&f.store, job_again, again).is_err());
                    assert_eq!(snapshot(&f.case.state), before);
                    assert!(matches!(
                        f.store
                            .create_once(f.store.root(), &name("forbidden"), b"write"),
                        Err(StoreError::Poisoned)
                    ));
                }
            }
        }
    }
}

#[test]
fn held_manifest_refuses_duplicate_settlement_and_keeps_publication_bytes() {
    for remove in [false, true] {
        let f = Fixture::new(&[Class::Violation]);
        f.settle().unwrap();
        let completion = f.completion();
        if remove {
            fs::remove_file(f.path("manifest")).unwrap();
        } else {
            fs::write(f.path("manifest"), b"broken").unwrap();
        }
        let before = snapshot(&f.case.state);
        assert!(settle(&f.store, verified_job(&f.store, &f.job), completion).is_err());
        assert_eq!(snapshot(&f.case.state), before);
    }
}

#[test]
fn local_admission_proof_supports_equal_admission_from_another_store() {
    let f = Fixture::new(&[Class::Pass]);
    let other = Fixture::new(&[Class::Pass]);
    assert_eq!(f.job, other.job);
    let result = settle(
        &f.store,
        verified_job(&other.store, &other.job),
        f.completion(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(result.record(), &f.expected(1));
}

#[test]
fn a_stray_pin_in_failure_free_history_refuses_publication() {
    let f = Fixture::new(&[Class::Pass]);
    let jobs = crate::layout::jobs(&f.store, &f.job.job().id().to_string())
        .unwrap()
        .unwrap();
    f.store
        .create_record(
            &jobs,
            &name(f.path("pin").file_name().unwrap().to_str().unwrap()),
            &Pin {
                result: f.expected(1),
            },
        )
        .unwrap();
    let before = snapshot(&f.case.state);
    assert!(matches!(
        f.settle(),
        Err(crate::attempt::Error::Held(
            "retained pin differs from failure history"
        ))
    ));
    assert_eq!(snapshot(&f.case.state), before);
    assert!(!f.path("result").exists());
}

#[test]
fn earlier_failure_publishes_when_current_attempt_is_retryable() {
    for failure in [Class::Violation, Class::EngineFailure] {
        for retry in [Class::Oom, Class::MisboundEvidence] {
            let f = Fixture::new(&[failure, retry]);
            let expected = f.expected(1);
            assert_eq!(f.settle().unwrap().unwrap().record(), &expected);
            let before = snapshot(&f.case.state);
            assert_eq!(f.settle().unwrap().unwrap().record(), &expected);
            assert_eq!(snapshot(&f.case.state), before);
        }
    }
}

#[test]
fn mixed_retry_history_publishes_the_final_class_unpinned() {
    let f = Fixture::new(&[Class::Oom]);
    let before = snapshot(&f.case.state);
    assert!(f.settle().unwrap().is_none());
    only_capture_progress(&before, &snapshot(&f.case.state));
    f.add(2, Class::Disagreement);
    let before = snapshot(&f.case.state);
    assert!(f.settle().unwrap().is_none());
    only_capture_progress(&before, &snapshot(&f.case.state));
    f.add(3, Class::Interrupted);
    assert_eq!(f.settle().unwrap().unwrap().record(), &f.expected(3));
    let before = snapshot(&f.case.state);
    assert_eq!(f.settle().unwrap().unwrap().record(), &f.expected(3));
    only_capture_progress(&before, &snapshot(&f.case.state));
    assert!(!f.path("pin").exists());
}

#[test]
fn show_reads_a_settled_job_as_one_verified_admission() {
    let f = Fixture::new(&[Class::Violation]);
    f.settle().unwrap();
    let before = snapshot(&f.case.state);
    let shown = crate::campaign::show(&f.case.state).unwrap();
    let jobs = shown["jobs"].as_array().unwrap();
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0]["id"], f.job.job().id().to_string());
    assert_eq!(jobs[0]["verified"], serde_json::to_value(&f.job).unwrap());
    assert!(jobs[0].get("held").is_none());
    assert_eq!(snapshot(&f.case.state), before);
}

/// The first `count` run numbers after 0 whose job ids share the shard of
/// `job`.
fn runs_in_shard(job: &Admission, count: usize) -> Vec<u64> {
    let shard = crate::layout::shard(&job.job().id().to_string());
    let mut experiment = job.job().experiment().clone();
    (1..)
        .filter(|run| {
            experiment.run = *run;
            crate::layout::shard(&experiment.id().to_string()) == shard
        })
        .take(count)
        .collect()
}

/// Runs `test` with the scan bound lowered to `bound`.
fn bounded<T>(bound: usize, test: impl FnOnce() -> T) -> T {
    crate::step::install(Some(crate::step::Script {
        scan_bound: Some(bound),
        ..crate::step::Script::default()
    }));
    let result = test();
    crate::step::install(None);
    result
}

#[test]
fn a_full_jobs_directory_keeps_room_for_settlement_and_stays_listable() {
    // Four entries of the shard remain free, and the unsettled job holds two
    // of them for its pin and result, so a second job's record, manifest, pin
    // and result fit only once two more entries are released.
    let f = Fixture::new(&[Class::Violation]);
    let id = f.job.job().id().to_string();
    let runs = runs_in_shard(&f.job, 2);
    let jobs = f
        .case
        .state
        .join("jobs")
        .join(crate::layout::shard(&id).as_str());
    let bound = 16;
    for index in 0..bound - 6 {
        fs::write(jobs.join(format!("retained-{index}")), b"").unwrap();
    }
    let shard = format!("jobs/{}", crate::layout::shard(&id).as_str());
    bounded(bound, || {
        let before = snapshot(&f.case.state);
        assert!(matches!(
            admit_run(&f.store, runs[0]),
            Err(crate::campaign::Error::Bound { root, entries: Some(projected), .. })
                if root == shard && projected == bound + 2
        ));
        assert_eq!(snapshot(&f.case.state), before);
        fs::remove_file(jobs.join("retained-0")).unwrap();
        fs::remove_file(jobs.join("retained-1")).unwrap();
        assert!(!admit_run(&f.store, runs[0]).unwrap().existing);
        f.settle().unwrap().unwrap();
        assert_eq!(fs::read_dir(&jobs).unwrap().count(), bound - 2);
        let shown = crate::campaign::show(&f.case.state).unwrap();
        assert_eq!(shown["jobs"].as_array().unwrap().len(), 2);
        let full = snapshot(&f.case.state);
        assert!(matches!(
            admit_run(&f.store, runs[1]),
            Err(crate::campaign::Error::Bound { root, entries: Some(projected), .. })
                if root == shard && projected == bound + 4
        ));
        assert_eq!(snapshot(&f.case.state), full);
    });
}

#[test]
fn a_published_result_without_a_pin_reserves_no_further_entries() {
    // A settled pass holds three files of its shard, and admission counts
    // only the new job's pin and result against the four remaining entries.
    let f = Fixture::new(&[Class::Pass]);
    f.settle().unwrap().unwrap();
    assert!(!f.path("pin").exists());
    let id = f.job.job().id().to_string();
    let runs = runs_in_shard(&f.job, 2);
    let jobs = f
        .case
        .state
        .join("jobs")
        .join(crate::layout::shard(&id).as_str());
    let bound = 16;
    for index in 0..bound - 7 {
        fs::write(jobs.join(format!("retained-{index}")), b"").unwrap();
    }
    assert_eq!(fs::read_dir(&jobs).unwrap().count(), bound - 4);
    let shard = format!("jobs/{}", crate::layout::shard(&id).as_str());
    bounded(bound, || {
        assert!(!admit_run(&f.store, runs[0]).unwrap().existing);
        let full = snapshot(&f.case.state);
        assert!(matches!(
            admit_run(&f.store, runs[1]),
            Err(crate::campaign::Error::Bound { root, entries: Some(projected), .. })
                if root == shard && projected == bound + 4
        ));
        assert_eq!(snapshot(&f.case.state), full);
    });
}

#[test]
fn new_attempt_between_pin_and_result_refuses_result_publication() {
    let f = Fixture::new(&[Class::Violation]);
    let completion = f.completion();
    let next = f.attempt_path(2);
    let created = std::rc::Rc::new(std::cell::Cell::new(false));
    let witness = created.clone();
    let pin = f.path("pin");
    let result = observed(
        move |step| {
            if step == Step::Sync && pin.exists() && !created.get() {
                fs::create_dir(&next).unwrap();
                created.set(true);
            }
        },
        || settle(&f.store, verified_job(&f.store, &f.job), completion),
    );
    assert!(witness.get());
    assert!(matches!(
        result,
        Err(crate::attempt::Error::Held(
            "attempt is not the current publish token"
        ))
    ));
    assert!(f.path("pin").exists());
    assert!(!f.path("result").exists());
}

#[test]
fn new_attempt_before_retained_acknowledgement_keeps_records_and_refuses() {
    let baseline = Fixture::new(&[Class::Violation]);
    baseline.settle().unwrap();
    let completion = baseline.completion();
    let job = verified_job(&baseline.store, &baseline.job);
    let (result, trace) = scripted([], || settle(&baseline.store, job, completion));
    assert!(result.unwrap().unwrap().is_some());
    let reads = trace.iter().filter(|step| **step == Step::Read).count();
    let f = Fixture::new(&[Class::Violation]);
    f.settle().unwrap();
    let pin = fs::read(f.path("pin")).unwrap();
    let result = fs::read(f.path("result")).unwrap();
    let completion = f.completion();
    let job = verified_job(&f.store, &f.job);
    let next = f.attempt_path(2);
    let created = std::rc::Rc::new(std::cell::Cell::new(false));
    let witness = created.clone();
    let mut seen = 0;
    let refused = observed(
        move |step| {
            if step == Step::Read {
                seen += 1;
                if seen == reads {
                    fs::create_dir(&next).unwrap();
                    created.set(true);
                }
            }
        },
        || settle(&f.store, job, completion),
    );
    assert!(witness.get());
    assert!(matches!(
        refused,
        Err(crate::attempt::Error::Held(
            "attempt is not the current publish token"
        ))
    ));
    assert_eq!(fs::read(f.path("pin")).unwrap(), pin);
    assert_eq!(fs::read(f.path("result")).unwrap(), result);
}

#[test]
fn absent_and_partial_bundles_preserve_abort_pins_and_interrupted_retries() {
    for (class, partial) in [
        (Class::EngineFailure, false),
        (Class::EngineFailure, true),
        (Class::Interrupted, false),
        (Class::Interrupted, true),
    ] {
        let f = Fixture::new(&[class]);
        let directory = f.directory(1);
        let attempt = f
            .store
            .read_record::<AttemptRecord>(&directory, &name("attempt"))
            .unwrap()
            .unwrap();
        let evidence_dir = f.artifact_directory(1);
        let artifact = f
            .store
            .read_record::<crate::record::Artifact>(&evidence_dir, &name("artifact"))
            .unwrap()
            .unwrap();
        let mut artifact = artifact.record().clone();
        let bundle = partial.then(|| crate::record::Digest::of(b"partial bundle"));
        artifact.bundle = bundle;
        if partial {
            f.store
                .replace(&evidence_dir, &name("bundle"), b"partial bundle")
                .unwrap();
        }
        artifact.summary = None;
        if class == Class::EngineFailure {
            let run = artifact.workers.get_mut(&text("run")).unwrap();
            run.signal = Some(libc::SIGABRT as u64);
            run.exit = None;
            run.ended = text("signaled");
        }
        f.store
            .replace_record(&evidence_dir, &name("artifact"), &artifact)
            .unwrap();
        if !partial {
            fs::remove_file(
                f.attempt_path(1)
                    .join("artifacts")
                    .join(attempt.record().attempt.as_str())
                    .join("bundle"),
            )
            .unwrap();
        }
        let evidence =
            crate::attempt::binding::read(&f.store, &directory, attempt.record()).unwrap();
        let binding = evidence.binding().unwrap();
        assert_eq!(binding.bundle, bundle);
        f.store
            .replace_record(&directory, &name("bound"), binding)
            .unwrap();
        let mut finished = f.expected(1).finished;
        finished.bound = Some(binding.clone());
        assert_eq!(
            crate::attempt::classify::classify(&finished, &evidence),
            class
        );
        f.store
            .replace_record(&directory, &name("finished"), &finished)
            .unwrap();
        let expected = f.expected(1);
        if class == Class::EngineFailure {
            assert_eq!(f.settle().unwrap().unwrap().record(), &expected);
            let pin = fs::read(f.path("pin")).unwrap();
            let result = fs::read(f.path("result")).unwrap();
            let f = f.reopen();
            f.add(2, Class::Pass);
            assert_eq!(f.settle().unwrap().unwrap().record(), &expected);
            assert_eq!(fs::read(f.path("pin")).unwrap(), pin);
            assert_eq!(fs::read(f.path("result")).unwrap(), result);
        } else {
            let before = snapshot(&f.case.state);
            assert!(f.settle().unwrap().is_none());
            only_capture_progress(&before, &snapshot(&f.case.state));
            f.add(2, Class::Pass);
            assert_eq!(f.settle().unwrap().unwrap().record(), &f.expected(2));
            let before = snapshot(&f.case.state);
            assert_eq!(f.settle().unwrap().unwrap().record(), &f.expected(2));
            only_capture_progress(&before, &snapshot(&f.case.state));
            assert!(!f.path("pin").exists());
        }
    }
}

#[test]
fn settlement_open_faults_remain_store_errors_and_refusals_are_held() {
    let baseline = Fixture::new(&[Class::Pass]);
    let completion = baseline.completion();
    let job = verified_job(&baseline.store, &baseline.job);
    let (result, trace) = scripted([], || settle(&baseline.store, job, completion));
    assert!(result.unwrap().unwrap().is_some());
    let open = trace.iter().position(|step| *step == Step::Open).unwrap();
    for errno in [libc::EIO, libc::ENOTDIR] {
        let f = Fixture::new(&[Class::Pass]);
        let completion = f.completion();
        let job = verified_job(&f.store, &f.job);
        let before = snapshot(&f.case.state);
        let (result, reached) = scripted([(open, Outcome::Errno(errno))], || {
            settle(&f.store, job, completion)
        });
        let result = result.unwrap();
        assert_eq!(reached.last(), Some(&Step::Open));
        if errno == libc::EIO {
            assert!(matches!(result, Err(crate::attempt::Error::Store(_))));
        } else {
            assert!(matches!(
                result,
                Err(crate::attempt::Error::Held("jobs unreadable"))
            ));
        }
        assert_eq!(snapshot(&f.case.state), before);
    }
}

#[path = "finding_tests.rs"]
mod findings;

/// `backlog` counts each pin while its finding's latest disposition is not
/// `resolved`, so two pins count two, and a later decision after a
/// resolution counts a pin again. A finding directory without its record
/// holds, naming the finding, and a pin copied under another job's name
/// holds instead of following the finding its result names.
#[test]
fn backlog_counts_pins_whose_latest_disposition_is_not_resolved() {
    use crate::record::Decision;
    let f = Fixture::new(&[Class::Violation]);
    f.settle().unwrap().unwrap();
    let first = f.job.clone();
    let second = admit_run(&f.store, 1).unwrap().record;
    let Fixture { case, store, .. } = f;
    let g = Fixture {
        case,
        store,
        job: second.clone(),
    };
    g.add(1, Class::Violation);
    g.settle().unwrap().unwrap();
    let Fixture { case, store, .. } = g;
    drop(store);
    let backlog = || {
        let store = Store::open(&case.state).unwrap();
        crate::campaign::dispatch::backlog(&store)
    };
    assert_eq!(backlog().unwrap(), 2);
    let finding = text(&format!("{}-0001", first.job().id()));
    let other = text(&format!("{}-0001", second.job().id()));
    for (id, decision, expected) in [
        (&finding, Decision::ReleaseBlocker, 2),
        (&finding, Decision::Resolved, 1),
        (&other, Decision::Resolved, 0),
        (&finding, Decision::ReleaseBlocker, 1),
        (&finding, Decision::Resolved, 0),
    ] {
        crate::campaign::dispose(&case.state, id.clone(), decision, text("evidence")).unwrap();
        assert_eq!(backlog().unwrap(), expected, "{} {decision:?}", id.as_str());
    }
    let jobs = case
        .state
        .join(crate::campaign::state_fixture::job_file(
            first.job().id().to_string(),
        ))
        .parent()
        .unwrap()
        .to_path_buf();
    fs::create_dir_all(case.state.join("jobs/00")).unwrap();
    let renamed = case
        .state
        .join(crate::campaign::state_fixture::job_file(format!(
            "{}{}",
            "0".repeat(64),
            crate::record::Pin::SUFFIX
        )));
    fs::copy(
        jobs.join(format!(
            "{}{}",
            first.job().id(),
            crate::record::Pin::SUFFIX
        )),
        &renamed,
    )
    .unwrap();
    assert_eq!(
        backlog().unwrap_err().to_string(),
        format!(
            "failure pin {}: settlement binding differs",
            renamed.file_name().unwrap().to_str().unwrap()
        )
    );
    fs::remove_file(&renamed).unwrap();
    let record = |id: &crate::record::Text| {
        case.state
            .join("findings")
            .join(id.as_str())
            .join("finding.json")
    };
    let saved = fs::read(record(&finding)).unwrap();
    fs::copy(record(&other), record(&finding)).unwrap();
    assert_eq!(
        backlog().unwrap_err().to_string(),
        format!("finding {}: finding binding differs", finding.as_str())
    );
    fs::write(record(&finding), &saved).unwrap();
    for (dependency, reason) in [
        ("bundle", "finding dependency differs"),
        ("manifest", "finding dependency missing"),
    ] {
        let path = case
            .state
            .join("findings")
            .join(finding.as_str())
            .join(dependency);
        let bytes = fs::read(&path).unwrap();
        if dependency == "bundle" {
            fs::write(&path, b"damaged").unwrap();
        } else {
            fs::remove_file(&path).unwrap();
        }
        assert_eq!(
            backlog().unwrap_err().to_string(),
            format!("finding {}: {reason}", finding.as_str())
        );
        let store = Store::open(&case.state).unwrap();
        let selected = crate::campaign::triage::select(
            &store,
            crate::record::Digest::parse(first.job().experiment().pins.build.as_str()).unwrap(),
            &crate::record::Configuration::new(
                [
                    ("slots", 1),
                    ("reserve_slots", 1),
                    ("cores", 2),
                    ("memory", 512 << 20),
                    ("cpu", 60),
                    ("tree_memory", 128 << 20),
                    ("attempt_output", 16 << 20),
                    ("attempt_inodes", 200),
                    ("wall", 120),
                    ("processes", 64),
                    ("artifact_bytes", 256 << 20),
                    ("artifact_inodes", 1 << 20),
                    ("backlog", 2),
                    ("retained_builds", 1),
                ]
                .into_iter()
                .map(|(key, value)| (text(key), value))
                .collect(),
            )
            .unwrap(),
            &Default::default(),
        )
        .unwrap();
        assert_eq!(
            selected.skipped.get(finding.as_str()).map(String::as_str),
            Some(reason)
        );
        drop(store);
        fs::write(&path, bytes).unwrap();
    }
    let pin = jobs.join(format!(
        "{}{}",
        first.job().id(),
        crate::record::Pin::SUFFIX
    ));
    let bytes = fs::read(&pin).unwrap();
    fs::write(&pin, b"damaged").unwrap();
    assert!(backlog().unwrap_err().to_string().starts_with(&format!(
        "failure pin {}:",
        pin.file_name().unwrap().to_str().unwrap()
    )));
    fs::write(&pin, bytes).unwrap();
    fs::remove_file(
        case.state
            .join("findings")
            .join(finding.as_str())
            .join("finding.json"),
    )
    .unwrap();
    assert_eq!(
        backlog().unwrap_err().to_string(),
        format!("finding {}: finding record missing", finding.as_str())
    );
}

#[test]
fn settle_pinning_reports_only_the_pin_this_call_published() {
    let pinning = |f: &Fixture| {
        super::super::settle_pinning(&f.store, verified_job(&f.store, &f.job), f.completion())
            .map(|s| (s.result.is_some(), s.pin_bytes, s.result_bytes))
    };
    let failed = Fixture::new(&[Class::Violation]);
    let published = pinning(&failed).unwrap();
    assert_eq!(
        published,
        (
            true,
            Some(fs::metadata(failed.path("pin")).unwrap().len()),
            Some(fs::metadata(failed.path("result")).unwrap().len())
        )
    );
    assert_eq!(pinning(&failed).unwrap(), (true, None, None));
    let passed = Fixture::new(&[Class::Pass]);
    let published = pinning(&passed).unwrap();
    assert_eq!(
        published,
        (
            true,
            None,
            Some(fs::metadata(passed.path("result")).unwrap().len())
        )
    );
    let retryable = Fixture::new(&[Class::Incomplete]);
    assert_eq!(pinning(&retryable).unwrap(), (false, None, None));
    let baseline = Fixture::new(&[Class::Violation]);
    let completed = baseline.completion();
    let job = verified_job(&baseline.store, &baseline.job);
    let (_, trace) = scripted([], || settle(&baseline.store, job, completed));
    let cut = trace
        .iter()
        .enumerate()
        .filter(|(_, step)| **step == Step::Rename)
        .nth(CAPTURE_RENAMES)
        .unwrap()
        .0
        + 1;
    let recovered = Fixture::killed_at(&[Class::Violation], cut).reopen();
    assert!(recovered.path("pin").exists());
    assert!(!recovered.path("result").exists());
    let published = pinning(&recovered).unwrap();
    assert_eq!(
        published,
        (
            true,
            None,
            Some(fs::metadata(recovered.path("result")).unwrap().len())
        )
    );
}

#[test]
fn findings_capture_and_disposition_holds_name_exact_bounds_without_writes() {
    use crate::record::Decision;
    for bound in [32, 31] {
        let f = Fixture::new(&[Class::Violation]);
        fs::create_dir(f.case.state.join("findings")).unwrap();
        for n in 0..32 {
            fs::create_dir(f.case.state.join(format!("findings/retained-{n}"))).unwrap();
        }
        let before = snapshot(&f.case.state);
        crate::step::install(Some(crate::step::Script {
            scan_bound: Some(bound),
            ..Default::default()
        }));
        let error = f.settle().unwrap_err();
        crate::step::install(None);
        let count = if bound == 32 { "32" } else { "more than 31" };
        assert_eq!(
            error.to_string(),
            format!("findings holds {count} entries at bound {bound}; collect or shard")
        );
        assert_eq!(snapshot(&f.case.state), before);
    }
    let f = Fixture::new(&[Class::Violation]);
    f.settle().unwrap().unwrap();
    let id = text(&format!("{}-0001", f.job.job().id()));
    let Fixture { case, store, .. } = f;
    drop(store);
    let entries = fs::read_dir(case.state.join("findings").join(id.as_str()))
        .unwrap()
        .count();
    for bound in [entries, entries - 1] {
        let before = snapshot(&case.state);
        crate::step::install(Some(crate::step::Script {
            scan_bound: Some(bound),
            ..Default::default()
        }));
        let error = crate::campaign::dispose(
            &case.state,
            id.clone(),
            Decision::Resolved,
            text("evidence"),
        )
        .unwrap_err();
        crate::step::install(None);
        let count = if bound == entries {
            entries.to_string()
        } else {
            format!("more than {bound}")
        };
        assert_eq!(
            error.to_string(),
            format!(
                "findings/{} holds {count} entries at bound {bound}; collect or shard",
                id.as_str()
            )
        );
        assert_eq!(snapshot(&case.state), before);
        if bound < entries {
            for command in [
                crate::campaign::findings
                    as fn(&std::path::Path) -> Result<serde_json::Value, crate::campaign::Error>,
                |path| crate::campaign::status(path).map(|_| serde_json::Value::Null),
            ] {
                crate::step::install(Some(crate::step::Script {
                    scan_bound: Some(bound),
                    ..Default::default()
                }));
                let error = command(&case.state).unwrap_err();
                crate::step::install(None);
                assert_eq!(error.exit(), crate::exit::Supervisor::Held);
                assert_eq!(
                    error.to_string(),
                    format!(
                        "findings/{} holds more than {bound} entries at bound {bound}; collect or shard",
                        id.as_str()
                    )
                );
            }
        }
    }
}

#[test]
fn resolved_dispositions_use_a_constant_descriptor_budget() {
    let _processes = crate::store::fixture::processes();
    if std::env::var_os("CAMPAIGN_DISPOSITION_DESCRIPTOR_CHILD").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "attempt::tests::settlement::resolved_dispositions_use_a_constant_descriptor_budget", "--nocapture"])
            .env("CAMPAIGN_DISPOSITION_DESCRIPTOR_CHILD", "1").output().unwrap();
        assert!(
            output.status.success()
                && String::from_utf8_lossy(&output.stdout).contains("test result: ok. 1 passed;"),
            "{output:?}"
        );
        return;
    }
    let f = Fixture::new(&[Class::Violation]);
    f.settle().unwrap().unwrap();
    let id = text(&format!("{}-0001", f.job.job().id()));
    let build = crate::record::Digest::parse(f.job.job().experiment().pins.build.as_str()).unwrap();
    let Fixture { case, store, .. } = f;
    drop(store);
    for n in 0..48 {
        let decision = if n == 47 {
            crate::record::Decision::Resolved
        } else {
            crate::record::Decision::ReleaseBlocker
        };
        crate::campaign::dispose(&case.state, id.clone(), decision, text("evidence")).unwrap();
    }
    let value: serde_json::Value =
        serde_json::from_str(include_str!("../../testdata/configuration.json")).unwrap();
    let config: crate::record::Configuration =
        serde_json::from_value(value["record"].clone()).unwrap();
    let open = fs::read_dir("/proc/self/fd").unwrap().count() as u64;
    crate::sys::restrict_descriptor_limit(open + 24).unwrap();
    let store = Store::open(&case.state).unwrap();
    assert_eq!(crate::campaign::dispatch::backlog(&store).unwrap(), 0);
    let selected =
        crate::campaign::triage::select(&store, build, &config, &Default::default()).unwrap();
    assert!(selected.skipped.is_empty(), "{:?}", selected.skipped);
    assert!(selected.ineligible.contains(id.as_str()));
}
