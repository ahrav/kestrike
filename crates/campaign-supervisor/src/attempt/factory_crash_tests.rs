use super::super::Launch;
use super::*;
use crate::custody::{Custody, Limits, Timing};
use crate::step::{self, Script};
use crate::store::fixture::processes;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;

struct Host {
    case: Case,
    root: PathBuf,
    delegation: PathBuf,
}

impl Host {
    fn new(index: usize) -> Self {
        let case = Case::new();
        let delegation = PathBuf::from(std::env::var_os("CAMPAIGN_CGROUP_ROOT").unwrap());
        fs::create_dir_all(delegation.join("controller")).unwrap();
        let root = delegation.join(format!("attempt-cuts-{}-{index}", std::process::id()));
        fs::create_dir(&root).unwrap();
        Self {
            case,
            root,
            delegation,
        }
    }
    fn custody(&self) -> Custody {
        Custody::open(
            &self.root,
            Timing {
                poll: Duration::from_millis(1),
                kill_wait: Duration::from_secs(1),
                watchdog: Duration::from_secs(5),
            },
        )
        .unwrap()
    }
    fn launch(&self, store: &Store, job: &Admission) -> Launch {
        let template = super::write_bundle_template(store, job);
        let gate = self.case.root.join("attempt-gate");
        fs::write(
            &gate,
            b"#!/bin/sh\nIFS= read -r go\n[ \"$go\" = G ] || exit 125\nshift\nshift\nexec \"$@\"\n",
        )
        .unwrap();
        fs::set_permissions(&gate, fs::Permissions::from_mode(0o700)).unwrap();
        let launcher = self.case.root.join("attempt-launcher");
        fs::write(&launcher, super::bundle_launcher(true)).unwrap();
        fs::set_permissions(&launcher, fs::Permissions::from_mode(0o700)).unwrap();
        Launch {
            gate,
            launcher,
            environment: [("ARTIFACT_TEMPLATE".into(), template.into_os_string())].into(),
            limits: Limits {
                cpu_quota_us: 1_000_000,
                memory_bytes: 1 << 30,
                pids: 64,
                file_bytes: 16 << 20,
                cpu_seconds: 300,
                output_bytes: u64::MAX,
                output_inodes: 4094,
            },
        }
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        fs::write(
            self.delegation.join("controller/cgroup.procs"),
            std::process::id().to_string(),
        )
        .unwrap();
        let _ = fs::write(self.root.join("cgroup.kill"), "1");
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while fs::read_to_string(self.root.join("cgroup.events"))
            .unwrap()
            .lines()
            .any(|line| line == "populated 1")
        {
            assert!(std::time::Instant::now() < deadline, "fixture tree drains");
            std::thread::sleep(Duration::from_millis(1));
        }
        for entry in fs::read_dir(&self.root).unwrap().flatten() {
            if entry.file_type().unwrap().is_dir() {
                loop {
                    match fs::remove_dir(entry.path()) {
                        Ok(()) => break,
                        Err(error) if error.raw_os_error() == Some(libc::EBUSY) => {
                            assert!(
                                std::time::Instant::now() < deadline,
                                "fixture group removes"
                            );
                            std::thread::sleep(Duration::from_millis(1));
                        }
                        Err(error) => panic!("fixture group removal: {error}"),
                    }
                }
            }
        }
        fs::remove_dir(&self.root).unwrap();
    }
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn every_factory_finish_sync_and_named_cut_reconciles_the_actual_attempt() {
    let _processes = processes();
    let host = Host::new(0);
    let store = Store::open(&host.case.state).unwrap();
    let job = super::job(&store);
    let mut custody = host.custody();
    let launch = host.launch(&store, &job);
    let (attempt, running) =
        super::super::start(&store, &mut custody, verified_job(&store, &job), launch).unwrap();
    let stopped = custody.wait_any(vec![running]).unwrap().stopped;
    assert!(stopped.started().is_some());
    let (baseline, trace) = scripted([], || {
        attempt.finish(&store, stopped, super::super::EVIDENCE_BOUND)
    });
    assert_eq!(
        baseline.unwrap().unwrap().finished().record().class,
        Class::Pass
    );
    let ordered: Vec<_> = trace
        .iter()
        .copied()
        .filter(|step| {
            matches!(
                step,
                Step::Evidence | Step::Finished | Step::Removed | Step::Released
            )
        })
        .collect();
    assert_eq!(
        ordered,
        [
            Step::Evidence,
            Step::Finished,
            Step::Removed,
            Step::Released
        ]
    );
    let syncs = trace.iter().filter(|step| **step == Step::Sync).count();
    assert_eq!(syncs, 41);
    drop(custody);
    drop(store);
    drop(host);
    let binding_read = trace
        .iter()
        .take_while(|step| **step != Step::Evidence)
        .filter(|step| **step == Step::Read)
        .count();
    let evidence_at = trace
        .iter()
        .position(|step| *step == Step::Evidence)
        .unwrap();
    let binding_reads = trace[evidence_at + 1..]
        .iter()
        .take_while(|step| **step != Step::Write)
        .filter(|step| **step == Step::Read)
        .count();
    assert_eq!(binding_reads, 8);
    let points: Vec<_> = (0..syncs)
        .map(|index| (Step::Sync, index))
        .chain(
            [
                Step::Evidence,
                Step::Finished,
                Step::Removed,
                Step::Released,
            ]
            .into_iter()
            .map(|step| (step, 0)),
        )
        .chain((binding_read..binding_read + binding_reads).map(|index| (Step::Read, index)))
        .collect();
    for (case_index, (point, occurrence)) in points.into_iter().enumerate() {
        for (mode, outcome) in [Outcome::Errno(libc::EIO), Outcome::Kill]
            .into_iter()
            .enumerate()
        {
            let host = Host::new(1 + case_index * 2 + mode);
            let store = Store::open(&host.case.state).unwrap();
            let job = super::job(&store);
            let mut custody = host.custody();
            let launch = host.launch(&store, &job);
            let (attempt, running) =
                super::super::start(&store, &mut custody, verified_job(&store, &job), launch)
                    .unwrap();
            let stopped = custody.wait_any(vec![running]).unwrap().stopped;
            let directory = host
                .case
                .state
                .join(crate::campaign::state_fixture::attempts_dir(
                    job.job().id().to_string(),
                ))
                .join("0001");
            let reservation_before = fs::read(directory.join("reservation")).unwrap();
            step::install(Some(Script {
                nth: Some((point, occurrence, outcome)),
                ..Script::default()
            }));
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                attempt.finish(&store, stopped, super::super::EVIDENCE_BOUND)
            }));
            let trace = step::install(None).unwrap();
            assert!(trace.nth.is_none(), "cut reached: {point:?}/{occurrence}");
            if point == Step::Read && mode == 0 {
                assert!(
                    matches!(&result, Ok(Err(super::super::Error::Store(crate::store::Error::Unreadable(error)))) if error.faulted())
                );
            }
            match result {
                Ok(result) => assert!(result.is_err()),
                Err(payload) => assert!(payload.is::<step::Killed>()),
            }
            let prior = fs::read(directory.join("finished")).ok();
            if point == Step::Read {
                assert!(directory.join("started").exists());
                assert!(prior.is_none());
                assert_eq!(
                    fs::read(directory.join("reservation")).unwrap(),
                    reservation_before
                );
                assert!(host.root.join(format!("{}-0001", job.job().id())).exists());
            }
            if !trace.reached.contains(&Step::Evidence) {
                assert!(prior.is_none());
            }
            if !host.root.join(format!("{}-0001", job.job().id())).exists() {
                assert!(prior.is_some(), "cgroup removal follows finished");
            }
            if !directory.join("reservation").exists() {
                assert!(prior.is_some());
                assert!(!host.root.join(format!("{}-0001", job.job().id())).exists());
            }
            if point == Step::Sync && mode == 0 {
                assert!(matches!(
                    store.create_once(store.root(), &name("later"), b"later"),
                    Err(crate::store::Error::Poisoned)
                ));
            }
            drop(custody);
            drop(store);
            let store = Store::open(&host.case.state).unwrap();
            let mut custody = host.custody();
            let attempt = Attempt::current(&store, verified_job(&store, &job))
                .unwrap()
                .unwrap();
            let completed = attempt
                .reconcile(&store, &mut custody, super::super::EVIDENCE_BOUND)
                .unwrap();
            let class = if prior.is_some() {
                Class::Pass
            } else {
                Class::Interrupted
            };
            assert_eq!(completed.finished().record().class, class);
            assert_eq!(completed.finished().record().binding, Binding::Matching);
            if let Some(prior) = prior {
                assert_eq!(fs::read(directory.join("finished")).unwrap(), prior);
            }
            assert!(!directory.join("reservation").exists());
            assert!(!host.root.join(format!("{}-0001", job.job().id())).exists());
            let attempt = Attempt::current(&store, verified_job(&store, &job))
                .unwrap()
                .unwrap();
            assert_eq!(
                attempt
                    .read_finished(&store)
                    .unwrap()
                    .finished()
                    .record()
                    .class,
                class
            );
            let before = fs::read(directory.join("finished")).unwrap();
            let attempt = Attempt::current(&store, verified_job(&store, &job))
                .unwrap()
                .unwrap();
            let again = attempt
                .reconcile(&store, &mut custody, super::super::EVIDENCE_BOUND)
                .unwrap();
            assert_eq!(
                again.finished().record().bound,
                completed.finished().record().bound
            );
            assert_eq!(fs::read(directory.join("finished")).unwrap(), before);
        }
    }
}

fn recovery_prefix(host: &Host) -> (Store, Custody, Admission, Attempt) {
    let store = Store::open(&host.case.state).unwrap();
    let job = super::job(&store);
    let mut custody = host.custody();
    let launch = host.launch(&store, &job);
    let (attempt, running) =
        super::super::start(&store, &mut custody, verified_job(&store, &job), launch).unwrap();
    let stopped = custody.wait_any(vec![running]).unwrap().stopped;
    step::install(Some(Script {
        nth: Some((Step::Evidence, 0, Outcome::Kill)),
        ..Script::default()
    }));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        attempt.finish(&store, stopped, super::super::EVIDENCE_BOUND)
    }));
    let reached = step::install(None).unwrap();
    assert!(reached.nth.is_none());
    assert!(matches!(result, Err(payload) if payload.is::<step::Killed>()));
    drop(custody);
    drop(store);
    let store = Store::open(&host.case.state).unwrap();
    let custody = host.custody();
    let attempt = Attempt::current(&store, verified_job(&store, &job))
        .unwrap()
        .unwrap();
    (store, custody, job, attempt)
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn recovery_sync_and_teardown_cuts_keep_reservations_until_finished_and_removed() {
    let _processes = processes();
    let host = Host::new(1000);
    let (store, mut custody, _, attempt) = recovery_prefix(&host);
    step::install(Some(Script::default()));
    let completed = attempt
        .reconcile(&store, &mut custody, super::super::EVIDENCE_BOUND)
        .unwrap();
    assert_eq!(completed.finished().record().class, Class::Interrupted);
    let trace = step::install(None).unwrap().reached;
    let mut occurrences = BTreeMap::new();
    let mut cuts = Vec::new();
    for step in trace {
        let index = occurrences.entry(format!("{step:?}")).or_insert(0usize);
        if [
            Step::Sync,
            Step::Kill,
            Step::Drained,
            Step::Evidence,
            Step::Finished,
            Step::Removed,
            Step::Released,
        ]
        .contains(&step)
        {
            cuts.push((step, *index));
        }
        *index += 1;
    }
    drop(custody);
    drop(store);
    drop(host);
    for (index, (point, occurrence)) in cuts.into_iter().enumerate() {
        for (mode, outcome) in [Outcome::Errno(libc::EIO), Outcome::Kill]
            .into_iter()
            .enumerate()
        {
            let host = Host::new(1001 + index * 2 + mode);
            let (store, mut custody, job, attempt) = recovery_prefix(&host);
            step::install(Some(Script {
                nth: Some((point, occurrence, outcome)),
                ..Script::default()
            }));
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                attempt.reconcile(&store, &mut custody, super::super::EVIDENCE_BOUND)
            }));
            let trace = step::install(None).unwrap();
            assert!(trace.nth.is_none(), "{point:?}/{occurrence}");
            match result {
                Ok(result) => assert!(result.is_err()),
                Err(payload) => assert!(payload.is::<step::Killed>()),
            }
            let directory = host
                .case
                .state
                .join(crate::campaign::state_fixture::attempts_dir(
                    job.job().id().to_string(),
                ))
                .join("0001");
            let group = host.root.join(format!("{}-0001", job.job().id()));
            let prior = fs::read(directory.join("finished")).ok();
            if group.exists() {
                assert!(directory.join("reservation").exists());
            }
            if !directory.join("reservation").exists() {
                assert!(prior.is_some());
                assert!(!group.exists());
            }
            drop(custody);
            drop(store);
            let store = Store::open(&host.case.state).unwrap();
            let mut custody = host.custody();
            let attempt = Attempt::current(&store, verified_job(&store, &job))
                .unwrap()
                .unwrap();
            let completed = attempt
                .reconcile(&store, &mut custody, super::super::EVIDENCE_BOUND)
                .unwrap();
            assert_eq!(completed.finished().record().class, Class::Interrupted);
            if let Some(prior) = prior {
                assert_eq!(fs::read(directory.join("finished")).unwrap(), prior);
            }
            assert!(!directory.join("reservation").exists());
            assert!(!group.exists());
            let attempt = Attempt::current(&store, verified_job(&store, &job))
                .unwrap()
                .unwrap();
            assert_eq!(
                attempt
                    .read_finished(&store)
                    .unwrap()
                    .finished()
                    .record()
                    .class,
                Class::Interrupted
            );
        }
    }
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn every_start_prefix_fault_preserves_minted_tokens_and_custody() {
    let _processes = processes();
    let host = Host::new(2000);
    let store = Store::open(&host.case.state).unwrap();
    let job = super::job(&store);
    let mut custody = host.custody();
    let launch = host.launch(&store, &job);
    let verified = verified_job(&store, &job);
    step::install(Some(Script::default()));
    let (attempt, running) = super::super::start(&store, &mut custody, verified, launch).unwrap();
    let trace = step::install(None).unwrap().reached;
    let stopped = custody.wait_any(vec![running]).unwrap().stopped;
    attempt
        .finish(&store, stopped, super::super::EVIDENCE_BOUND)
        .unwrap();
    drop(custody);
    drop(store);
    drop(host);
    let mut reservation_only = 0;
    let mut uncharged = 0;
    let mut retried = 0;
    for index in 0..trace.len() {
        for (mode, outcome) in [Outcome::Errno(libc::EIO), Outcome::Kill]
            .into_iter()
            .enumerate()
        {
            let host = Host::new(2001 + index * 2 + mode);
            let store = Store::open(&host.case.state).unwrap();
            let job = super::job(&store);
            let mut custody = host.custody();
            let launch = host.launch(&store, &job);
            let verified = verified_job(&store, &job);
            let (result, reached) = scripted([(index, outcome)], || {
                super::super::start(&store, &mut custody, verified, launch)
            });
            assert!(reached.len() > index, "start cut {index}");
            if let Some(result) = result {
                assert!(result.is_err(), "start cut {index}");
            }
            let directory = host
                .case
                .state
                .join(crate::campaign::state_fixture::attempts_dir(
                    job.job().id().to_string(),
                ))
                .join("0001");
            let group = host.root.join(format!("{}-0001", job.job().id()));
            assert!(!directory.join("finished").exists());
            if directory.join("intent").exists() {
                assert!(
                    directory.join("reservation").exists(),
                    "reservation precedes intent"
                );
            }
            if group.exists() {
                assert!(directory.join("intent").exists());
                assert!(directory.join("reservation").exists());
            }
            if !reached.contains(&Step::Go) {
                assert!(!directory.join("artifacts").exists());
            }
            drop(custody);
            drop(store);
            let store = Store::open(&host.case.state).unwrap();
            let job = verified_job(&store, &job);
            if directory.exists() && !directory.join("attempt").exists() {
                assert!(matches!(
                    Attempt::current(&store, job),
                    Err(super::super::Error::Held("attempt record missing"))
                ));
            } else if directory.exists() && !directory.join("intent").exists() {
                let attempt = Attempt::current(&store, job).unwrap().unwrap();
                let mut custody = host.custody();
                if directory.join("reservation").exists() {
                    reservation_only += 1;
                    let completed = attempt
                        .reconcile(&store, &mut custody, super::super::EVIDENCE_BOUND)
                        .unwrap_or_else(|error| panic!("start cut {index}: {error:?}"));
                    assert_ne!(completed.finished().record().class, Class::Pass);
                    assert!(directory.join("finished").exists());
                    assert!(!directory.join("reservation").exists());
                    assert!(!group.exists());
                } else {
                    uncharged += 1;
                    assert!(matches!(
                        attempt.reconcile(&store, &mut custody, super::super::EVIDENCE_BOUND),
                        Err(super::super::Error::Held(
                            "pending attempt lacks reservation"
                        ))
                    ));
                    assert!(!directory.join("finished").exists());
                }
            } else if directory.exists() && directory.join("intent").exists() {
                let active = Attempt::current(&store, job).unwrap().unwrap();
                let mut custody = host.custody();
                match active.reconcile(&store, &mut custody, super::super::EVIDENCE_BOUND) {
                    Ok(completed) => {
                        assert_ne!(completed.finished().record().class, Class::Pass);
                        assert!(!directory.join("reservation").exists());
                        assert!(!group.exists());
                    }
                    Err(_) => {
                        assert!(directory.join("reservation").exists());
                        assert!(!directory.join("finished").exists());
                    }
                }
            } else {
                let shard = directory
                    .parent()
                    .and_then(std::path::Path::parent)
                    .unwrap();
                retried += usize::from(shard.is_dir());
                let admission = job.record().clone();
                assert!(Attempt::current(&store, job).unwrap().is_none());
                let mut custody = host.custody();
                let launch = host.launch(&store, &admission);
                let verified = verified_job(&store, &admission);
                let (attempt, running) =
                    super::super::start(&store, &mut custody, verified, launch).unwrap();
                assert_eq!(attempt.number(), 1);
                let stopped = custody.wait_any(vec![running]).unwrap().stopped;
                let completed = attempt
                    .finish(&store, stopped, super::super::EVIDENCE_BOUND)
                    .unwrap();
                assert_eq!(
                    completed.finished().record().class,
                    Class::Pass,
                    "start cut {index}"
                );
                assert_eq!(completed.finished().record().binding, Binding::Matching);
                assert!(!directory.join("reservation").exists());
                assert!(!group.exists());
            }
        }
    }
    assert!(
        reservation_only > 0,
        "reservation-only recovery was reached"
    );
    assert!(uncharged > 0, "record-before-charge hold was reached");
    assert!(
        retried > 0,
        "retry over a first-use attempts shard was reached"
    );
}
