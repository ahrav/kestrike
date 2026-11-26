use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use super::{Custody, Error, Launch, Limits, Timing};
const RESERVATION_BYTES: &[u8] = br#"{"format":1,"kind":"reservation","record":{"attempt":"attempt-1"},"sha256":"a945b46bd87e829ed60949bb628c2714e60fcfef77d24882f457bda4c49e4277"}"#;
use crate::record::{Intent, Started, Text};
use crate::step::{self, Outcome, Script, Step};
use crate::store::Store;
use crate::store::fixture::{Case, name, processes, scripted};

pub(crate) struct Hosted {
    pub(crate) case: Case,
    pub(crate) root: PathBuf,
    delegation: PathBuf,
}

impl Hosted {
    pub(crate) fn new(index: usize) -> Self {
        let case = Case::new();
        let delegation = PathBuf::from(
            std::env::var_os("CAMPAIGN_CGROUP_ROOT")
                .expect("custody fault tests require user delegation"),
        );
        fs::create_dir_all(delegation.join("controller")).unwrap();
        let root = delegation.join(format!("fault-{}-{index}", std::process::id()));
        fs::create_dir(&root).unwrap();
        Self {
            case,
            root,
            delegation,
        }
    }

    pub(crate) fn custody(&self, kill_wait: Duration) -> Custody {
        Custody::open(
            &self.root,
            Timing {
                poll: Duration::from_millis(1),
                kill_wait,
                watchdog: Duration::from_millis(200),
            },
        )
        .unwrap()
    }

    pub(crate) fn launch(&self) -> Launch {
        launch(&self.case.root, &self.case.root.join("effect"))
    }
}

fn launch(directory: &Path, effect: &Path) -> Launch {
    fs::write(
        directory.join("gate"),
        b"IFS= read -r go\n[ \"$go\" = G ] || exit 125\nshift\nexec \"$@\"\n",
    )
    .unwrap();
    Launch {
        attempt: Text::new("attempt-1").unwrap(),
        name: name("attempt-1"),
        gate: "/bin/sh".into(),
        launcher: "/bin/sh".into(),
        args: vec![
            "-c".into(),
            format!("printf effect > '{}'", effect.display()).into(),
        ],
        directory: directory.to_owned(),
        environment: BTreeMap::new(),
        limits: Limits {
            cpu_quota_us: 100000,
            memory_bytes: 32 << 20,
            pids: 8,
            file_bytes: 4 << 20,
            cpu_seconds: 300,
            output_bytes: u64::MAX,
            output_inodes: 4094,
        },
    }
}

impl Drop for Hosted {
    fn drop(&mut self) {
        if let Err(error) = fs::write(
            self.delegation.join("controller/cgroup.procs"),
            std::process::id().to_string(),
        ) {
            eprintln!("custody fixture remains held: {error}");
            return;
        }
        let _ = fs::write(self.root.join("cgroup.kill"), "1");
        fn remove(path: &Path) {
            if let Ok(entries) = fs::read_dir(path) {
                for entry in entries.flatten() {
                    if entry.file_type().unwrap().is_dir() {
                        remove(&entry.path());
                    }
                }
            }
            let _ = fs::remove_dir(path);
        }
        remove(&self.root);
    }
}

fn prepared(index: usize) -> (Hosted, Custody, Store) {
    let hosted = Hosted::new(index);
    let custody = hosted.custody(Duration::from_secs(1));
    let store = Store::open(&hosted.case.state).unwrap();
    store
        .create_once(store.root(), &name("reservation"), RESERVATION_BYTES)
        .unwrap();
    (hosted, custody, store)
}

fn lifecycle(hosted: &Hosted, custody: &mut Custody, store: &Store) -> Result<(), Error> {
    let running = custody.launch(store, store.root(), hosted.launch())?;
    let stopped = custody.wait_any(vec![running])?.stopped;
    complete_stopped(stopped, store)
}

fn settle_before_observing(hosted: &Hosted) {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        let drained = match fs::read_to_string(hosted.root.join("attempt-1/cgroup.events")) {
            Ok(events) => events.contains("populated 0"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
            Err(error) => panic!("settling events: {error}"),
        };
        let controller = fs::read_to_string(hosted.root.join("controller/cgroup.procs")).unwrap();
        let only_controller = controller
            .split_whitespace()
            .all(|pid| pid == std::process::id().to_string());
        if drained && only_controller {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "released gate settles before the effect oracle"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

enum Cut {
    Fsync(usize),
    Point(Step),
}

fn at_point<T>(
    at: Step,
    outcome: Outcome,
    operation: impl FnOnce() -> T,
) -> (Option<T>, Vec<Step>) {
    at_occurrence(at, 0, outcome, operation)
}

fn at_occurrence<T>(
    at: Step,
    occurrence: usize,
    outcome: Outcome,
    operation: impl FnOnce() -> T,
) -> (Option<T>, Vec<Step>) {
    step::install(Some(Script {
        nth: Some((at, occurrence, outcome)),
        ..Script::default()
    }));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation));
    let script = step::install(None).unwrap();
    assert!(script.nth.is_none(), "named fault reached");
    assert!(script.reached.contains(&at));
    let result = match result {
        Ok(value) => Some(value),
        Err(payload) => {
            assert!(payload.is::<step::Killed>());
            None
        }
    };
    (result, script.reached)
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn named_launch_points_and_each_fsync_fault_preserve_durable_prefixes() {
    let _processes = processes();
    let (hosted, mut custody, store) = prepared(0);
    let (baseline, reached) = scripted([], || lifecycle(&hosted, &mut custody, &store));
    baseline.unwrap().unwrap();
    assert_eq!(
        fs::read(hosted.case.root.join("effect")).unwrap(),
        b"effect"
    );
    let names = [
        Step::Intent,
        Step::Created,
        Step::Spawn,
        Step::Spawned,
        Step::Moved,
        Step::Started,
        Step::Go,
        Step::ReleasedGate,
        Step::Exited,
        Step::Kill,
        Step::Killed,
        Step::Drained,
        Step::Evidence,
        Step::Finished,
        Step::Removed,
        Step::Released,
    ];
    let mut previous = 0;
    for named in names {
        let position = reached
            .iter()
            .position(|step| *step == named)
            .expect("named point reached");
        assert!(position >= previous, "named custody points preserve order");
        previous = position;
    }
    let cuts: Vec<_> = reached
        .iter()
        .filter(|step| **step == Step::Sync)
        .enumerate()
        .map(|(ordinal, _)| Cut::Fsync(ordinal))
        .chain(names.into_iter().map(Cut::Point))
        .collect();
    assert_eq!(
        reached.iter().filter(|step| **step == Step::Sync).count(),
        33,
        "launch 14, started and intent barriers 4, evidence files and directories 8, reservation barrier 2, finished publication and barrier 4, release 1"
    );
    drop(store);
    drop(custody);
    drop(hosted);
    for (ordinal, cut) in cuts.iter().enumerate() {
        for (mode, outcome) in [Outcome::Errno(libc::EIO), Outcome::Kill]
            .into_iter()
            .enumerate()
        {
            let (hosted, mut custody, store) = prepared(1 + ordinal * 2 + mode);
            let operation = || lifecycle(&hosted, &mut custody, &store);
            let (result, actual) = match *cut {
                Cut::Fsync(index) => at_occurrence(Step::Sync, index, outcome, operation),
                Cut::Point(at) => at_point(at, outcome, operation),
            };
            if let Cut::Fsync(index) = *cut {
                assert_eq!(
                    actual.iter().filter(|step| **step == Step::Sync).count(),
                    index + 1,
                    "planned fsync fault fired"
                );
                assert_eq!(actual.last(), Some(&Step::Sync));
            }
            assert!(
                result.is_none() || result.unwrap().is_err(),
                "fault refuses lifecycle"
            );
            settle_before_observing(&hosted);
            if !actual.contains(&Step::Go) {
                assert!(
                    !hosted.case.root.join("effect").exists(),
                    "a pre-go fault permits no worker effect"
                );
            }
            let cgroup = hosted.root.join("attempt-1");
            if matches!(cut, Cut::Fsync(_)) && !actual.contains(&Step::Intent) {
                assert!(!cgroup.exists(), "intent fsync fault precedes creation");
            }
            if cgroup.exists() {
                assert!(
                    hosted.case.state.join("intent").exists(),
                    "creation has durable intent"
                );
            }
            if hosted.case.root.join("effect").exists() {
                assert!(
                    hosted.case.state.join("started").exists(),
                    "effect has durable started"
                );
            }
            if hosted.case.state.join("reservation").exists() {
                assert_eq!(
                    fs::read(hosted.case.state.join("reservation")).unwrap(),
                    RESERVATION_BYTES
                );
            } else {
                assert!(hosted.case.state.join("finished").exists());
                assert!(!cgroup.exists(), "release follows finished and removal");
            }
            if !actual.contains(&Step::Evidence) {
                assert!(
                    !hosted.case.state.join("finished").exists(),
                    "finished follows a complete evidence barrier"
                );
            }
            if matches!(cut, Cut::Fsync(_)) && mode == 0 {
                assert!(matches!(
                    store.create_once(store.root(), &name("later"), b"later"),
                    Err(crate::store::Error::Poisoned)
                ));
                assert!(!hosted.case.state.join("later").exists());
            }
            drop(store);
            let recovered = Store::open(&hosted.case.state).unwrap();
            if let Some(intent) = recovered
                .read_record::<Intent>(recovered.root(), &name("intent"))
                .unwrap()
            {
                let started = recovered
                    .read_record::<Started>(recovered.root(), &name("started"))
                    .unwrap();
                if cgroup.exists() && started.is_none() {
                    for _ in 0..2 {
                        let result = custody.reconcile(&recovered, &intent, None);
                        assert!(matches!(
                            result,
                            Err(Error::Held("cgroup lacks matching started"))
                        ));
                    }
                    assert!(cgroup.exists());
                } else {
                    if hosted.case.state.join("reservation").exists() {
                        let stopped = custody
                            .reconcile(&recovered, &intent, started.as_ref())
                            .unwrap();
                        complete_stopped(stopped, &recovered).unwrap();
                    }
                    let bytes = fs::read(hosted.case.state.join("finished")).unwrap();
                    custody
                        .reconcile(&recovered, &intent, started.as_ref())
                        .unwrap();
                    assert_eq!(fs::read(hosted.case.state.join("finished")).unwrap(), bytes);
                    assert!(!hosted.case.state.join("reservation").exists());
                    assert!(!cgroup.exists());
                }
            } else {
                assert!(!cgroup.exists());
                assert!(!hosted.case.root.join("effect").exists());
                assert!(
                    recovered
                        .read_record::<Started>(recovered.root(), &name("started"))
                        .unwrap()
                        .is_none()
                );
            }
        }
    }
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn existing_launcher_outputs_hold_before_intent_and_preserve_their_bytes() {
    let _processes = processes();
    for (index, file, expected) in [
        (9100, "launcher.stdout", "launcher stdout already present"),
        (9101, "launcher.stderr", "launcher stderr already present"),
    ] {
        let (hosted, mut custody, store) = prepared(index);
        store
            .create_once(store.root(), &name(file), b"retained output")
            .unwrap();
        let result = custody.launch(&store, store.root(), hosted.launch());
        assert!(matches!(result, Err(Error::Held(reason)) if reason == expected));
        assert_eq!(
            fs::read(hosted.case.state.join(file)).unwrap(),
            b"retained output"
        );
        assert!(!hosted.case.state.join("intent").exists());
        assert!(!hosted.root.join("attempt-1").exists());
        assert!(hosted.case.state.join("reservation").exists());
    }
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn supervision_holds_a_draining_tree_past_its_kill_wait() {
    let _processes = processes();
    let (hosted, mut custody, store) = prepared(7301);
    custody.timing.kill_wait = Duration::from_millis(80);
    let mut running = custody
        .launch(&store, store.root(), hosted.launch())
        .unwrap();
    running.request_stop();
    custody
        .supervise(std::slice::from_mut(&mut running))
        .unwrap();
    let path = hosted.root.join("attempt-1");
    let mut member = Command::new("/bin/sleep").arg("20").spawn().unwrap();
    fs::write(path.join("cgroup.procs"), member.id().to_string()).unwrap();
    std::thread::sleep(Duration::from_millis(120));
    let result = custody.supervise(std::slice::from_mut(&mut running));
    assert!(
        matches!(
            result,
            Err(Error::Held(
                "cgroup populated or child unreaped past kill wait"
            ))
        ),
        "{result:?}"
    );
    assert_eq!(custody.held_identity().unwrap().as_str(), "attempt-1");
    fs::write(path.join("cgroup.kill"), "1").unwrap();
    assert!(!member.wait().unwrap().success());
    let waited = custody.wait_any(vec![running]).unwrap();
    assert_eq!(waited.stopped.interruption(), Some(libc::SIGKILL));
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_populated_tree_past_kill_wait_stays_held_until_the_next_drain() {
    let _processes = processes();
    let hosted = Hosted::new(1000);
    let mut custody = hosted.custody(Duration::from_millis(100));
    let store = Store::open(&hosted.case.state).unwrap();
    store
        .create_once(store.root(), &name("reservation"), RESERVATION_BYTES)
        .unwrap();
    custody.timing.watchdog = Duration::from_secs(5);
    let running = custody
        .launch(&store, store.root(), hosted.launch())
        .unwrap();
    let mut late_member = Command::new("/bin/sleep").arg("20").spawn().unwrap();
    let path = hosted.root.join("attempt-1");
    let procs = path.join("cgroup.procs");
    let pid = late_member.id();
    let mut killed = false;
    let mut injected = false;
    let reaped = std::rc::Rc::new(std::cell::Cell::new(false));
    let observed_reap = reaped.clone();
    step::install(Some(Script {
        observe: Some(Box::new(move |at| {
            if at == Step::Exited {
                observed_reap.set(true);
            }
            if at == Step::Kill {
                killed = true;
            }
            if killed && !injected && at == Step::Read {
                fs::write(&procs, pid.to_string()).unwrap();
                injected = true;
            }
        })),
        ..Script::default()
    }));
    let began = std::time::Instant::now();
    let result = custody.wait_any(vec![running]).map(|waited| waited.stopped);
    let trace = step::install(None).unwrap().reached;
    assert!(
        reaped.get(),
        "child reaped before the populated bound: {:?}, {trace:?}",
        result.as_ref().err()
    );
    assert!(began.elapsed() >= Duration::from_millis(100));
    assert!(began.elapsed() < Duration::from_secs(2));
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("populated past bound must hold"),
    };
    assert!(matches!(error, Error::Held(_)));
    assert_eq!(error.exit(), crate::exit::Supervisor::Held);
    assert!(
        fs::read_to_string(path.join("cgroup.events"))
            .unwrap()
            .contains("populated 1")
    );
    assert_eq!(trace.iter().filter(|at| **at == Step::Kill).count(), 1);
    assert!(path.exists());
    assert_eq!(
        fs::read(hosted.case.state.join("reservation")).unwrap(),
        RESERVATION_BYTES
    );
    drop(custody);
    let mut restarted = hosted.custody(Duration::from_secs(1));
    let intent = store
        .read_record::<Intent>(store.root(), &name("intent"))
        .unwrap()
        .unwrap();
    let started = store
        .read_record::<Started>(store.root(), &name("started"))
        .unwrap()
        .unwrap();
    restarted
        .reconcile(&store, &intent, Some(&started))
        .unwrap()
        .remove_group()
        .unwrap();
    assert!(!late_member.wait().unwrap().success());
    assert!(!path.exists());
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn output_census_covers_a_bounded_share_of_poll_wakes_and_the_exit_pass() {
    const FILES: usize = 2000;
    let _processes = processes();
    let (hosted, mut custody, store) = prepared(1001);
    custody.timing.watchdog = Duration::from_secs(5);
    let bulk = hosted.case.state.join("bulk");
    fs::create_dir(&bulk).unwrap();
    for index in 0..FILES {
        fs::write(bulk.join(index.to_string()), b"").unwrap();
    }
    let mut launch = hosted.launch();
    launch.args = vec!["-c".into(), "sleep 0.2".into()];
    let running = custody.launch(&store, store.root(), launch).unwrap();
    step::install(Some(Script::default()));
    let waited = custody.wait_any(vec![running]);
    let trace = step::install(None).unwrap().reached;
    let stopped = waited.unwrap().stopped;
    assert!(stopped.status().is_some_and(|status| status.success()));
    assert_eq!(stopped.interruption(), None);
    assert!(!stopped.watchdog());
    let wakes: Vec<(usize, bool)> = trace
        .split(|at| *at == Step::Poll)
        .map(|wake| {
            (
                wake.iter().filter(|at| **at == Step::Open).count(),
                wake.contains(&Step::Exited),
            )
        })
        .collect();
    let censuses = wakes.iter().filter(|(opens, _)| *opens >= FILES).count();
    assert!(
        wakes
            .iter()
            .any(|(opens, exited)| *exited && *opens >= FILES),
        "the exit pass measures output: {wakes:?}"
    );
    assert!(
        censuses * 4 <= wakes.len(),
        "{censuses} output censuses across {} poll wakes",
        wakes.len()
    );
    complete_stopped(stopped, &store).unwrap();

    drop(custody);
    let (hosted, mut custody, store) = prepared(1002);
    let mut launch = hosted.launch();
    launch.args = vec!["-c".into(), "sleep 20".into()];
    let running = custody.launch(&store, store.root(), launch).unwrap();
    let mut deep = hosted.case.state.join("deep");
    for _ in 0..64 {
        deep.push("d");
    }
    fs::create_dir_all(&deep).unwrap();
    let stopped = custody.wait_any(vec![running]).unwrap().stopped;
    assert!(stopped.kernel().is_ok());
    assert_eq!(stopped.interruption(), Some(crate::sys::OUTPUT_SIGNAL));
    assert!(!stopped.watchdog());
    complete_stopped(stopped, &store).unwrap();
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn controller_crashes_before_started_hold_empty_groups_for_an_operator() {
    let _processes = processes();
    if let Some(point) = std::env::var_os("CAMPAIGN_CUSTODY_CRASH_POINT") {
        let point = match point.to_str().unwrap() {
            "created" => Step::Created,
            "spawned" => Step::Spawned,
            "moved" => Step::Moved,
            _ => panic!("crash point"),
        };
        let root: PathBuf = std::env::var_os("CAMPAIGN_CUSTODY_CRASH_ROOT")
            .unwrap()
            .into();
        let state: PathBuf = std::env::var_os("CAMPAIGN_CUSTODY_CRASH_STATE")
            .unwrap()
            .into();
        let effect: PathBuf = std::env::var_os("CAMPAIGN_CUSTODY_CRASH_EFFECT")
            .unwrap()
            .into();
        let mut custody = Custody::open(
            &root,
            Timing {
                poll: Duration::from_millis(1),
                kill_wait: Duration::from_secs(1),
                watchdog: Duration::from_secs(1),
            },
        )
        .unwrap();
        let store = Store::open(&state).unwrap();
        store
            .create_once(store.root(), &name("reservation"), RESERVATION_BYTES)
            .unwrap();
        let launch = launch(&state, &effect);
        step::install(Some(Script {
            observe: Some(Box::new(move |at| {
                if at == point {
                    let _ = Command::new("/bin/kill")
                        .args(["-KILL", &std::process::id().to_string()])
                        .status();
                }
            })),
            ..Script::default()
        }));
        let _ = custody.launch(&store, store.root(), launch);
        panic!("controller must crash at the named point");
    }
    for (index, point) in ["created", "spawned", "moved"].into_iter().enumerate() {
        let hosted = Hosted::new(2000 + index);
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "custody::run_tests::controller_crashes_before_started_hold_empty_groups_for_an_operator",
                "--include-ignored",
                "--nocapture",
            ])
            .env("CAMPAIGN_CUSTODY_CRASH_POINT", point)
            .env("CAMPAIGN_CUSTODY_CRASH_ROOT", &hosted.root)
            .env("CAMPAIGN_CUSTODY_CRASH_STATE", &hosted.case.state)
            .env("CAMPAIGN_CUSTODY_CRASH_EFFECT", hosted.case.root.join("effect"))
            .output()
            .unwrap();
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(output.status.signal(), Some(libc::SIGKILL), "{output:?}");
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            let events = fs::read_to_string(hosted.root.join("attempt-1/cgroup.events")).unwrap();
            let controller =
                fs::read_to_string(hosted.root.join("controller/cgroup.procs")).unwrap();
            if events.contains("populated 0") && controller.trim().is_empty() {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "pre-start gate drains after controller crash"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(!hosted.case.root.join("effect").exists());
        let store = Store::open(&hosted.case.state).unwrap();
        let intent = store
            .read_record::<Intent>(store.root(), &name("intent"))
            .unwrap()
            .unwrap();
        assert!(
            store
                .read_record::<Started>(store.root(), &name("started"))
                .unwrap()
                .is_none()
        );
        let mut custody = hosted.custody(Duration::from_secs(1));
        assert!(matches!(
            custody.reconcile(&store, &intent, None),
            Err(Error::Held("cgroup lacks matching started"))
        ));
        assert!(hosted.root.join("attempt-1").exists());
        assert_eq!(
            fs::read(hosted.case.state.join("reservation")).unwrap(),
            RESERVATION_BYTES
        );
    }
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn populated_zero_events_wake_a_drain_with_its_child_already_reaped() {
    let _processes = processes();
    let hosted = Hosted::new(3000);
    let mut custody = Custody::open(
        &hosted.root,
        Timing {
            poll: Duration::from_secs(30),
            kill_wait: Duration::from_secs(10),
            watchdog: Duration::from_secs(20),
        },
    )
    .unwrap();
    let store = Store::open(&hosted.case.state).unwrap();
    store
        .create_once(store.root(), &name("reservation"), RESERVATION_BYTES)
        .unwrap();
    let running = custody
        .launch(&store, store.root(), hosted.launch())
        .unwrap();
    let mut member = Command::new("/bin/sleep").arg("20").spawn().unwrap();
    let path = hosted.root.join("attempt-1");
    let pid = member.id();
    let mut killed = false;
    let mut joined = false;
    let mut released = false;
    let release = std::rc::Rc::new(std::cell::RefCell::new(None));
    let observed_release = release.clone();
    step::install(Some(Script {
        observe: Some(Box::new(move |at| {
            if at == Step::Kill {
                killed = true;
            }
            if killed && !joined && at == Step::Read {
                fs::write(path.join("cgroup.procs"), pid.to_string()).unwrap();
                joined = true;
            }
            if joined && !released && at == Step::Poll {
                let path = path.clone();
                *observed_release.borrow_mut() = Some(std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(100));
                    fs::write(path.join("cgroup.kill"), "1").unwrap();
                }));
                released = true;
            }
        })),
        ..Script::default()
    }));
    let began = std::time::Instant::now();
    let result = custody.wait_any(vec![running]);
    let trace = step::install(None).unwrap().reached;
    release.borrow_mut().take().unwrap().join().unwrap();
    let stopped = result.unwrap().stopped;
    assert!(trace.iter().filter(|at| **at == Step::Poll).count() <= 8);
    assert!(began.elapsed() >= Duration::from_millis(100));
    assert!(
        began.elapsed() < Duration::from_secs(2),
        "cgroup events wake the drain before its timeout"
    );
    let kill = trace.iter().position(|at| *at == Step::Kill).unwrap();
    assert!(
        trace[kill + 1..].contains(&Step::Poll),
        "drain polling reached"
    );
    assert_eq!(stopped.status().unwrap().code(), Some(0));
    assert!(!member.wait().unwrap().success());
    stopped.remove_group().unwrap();
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn sibling_deadlines_and_interruptions_progress_during_a_populated_drain() {
    let _processes = processes();
    for interrupted in [false, true] {
        let (hosted, mut custody, store) = prepared(5000 + usize::from(interrupted));
        custody.timing.poll = Duration::from_secs(30);
        if interrupted {
            custody.timing.watchdog = Duration::from_secs(20);
        }
        store.mkdir(store.root(), &name("second")).unwrap();
        let second = store
            .open_dir(store.root(), &name("second"))
            .unwrap()
            .unwrap();
        let first = custody
            .launch(&store, store.root(), hosted.launch())
            .unwrap();
        let mut launch = hosted.launch();
        launch.attempt = Text::new("attempt-2").unwrap();
        launch.name = name("attempt-2");
        launch.launcher = "/bin/sleep".into();
        launch.args = vec!["20".into()];
        let second = custody.launch(&store, &second, launch).unwrap();
        let mut member = Command::new("/bin/sleep").arg("20").spawn().unwrap();
        let path = hosted.root.join("attempt-1");
        let pid = member.id();
        let mut killed = false;
        let joined = std::rc::Rc::new(std::cell::Cell::new(false));
        let observed_join = joined.clone();
        let signaled = std::rc::Rc::new(std::cell::Cell::new(false));
        let observed_signal = signaled.clone();
        step::install(Some(Script {
            observe: Some(Box::new(move |at| {
                if at == Step::Kill {
                    killed = true;
                }
                if killed && !observed_join.get() && at == Step::Read {
                    fs::write(path.join("cgroup.procs"), pid.to_string()).unwrap();
                    observed_join.set(true);
                }
                if interrupted && observed_join.get() && !observed_signal.get() && at == Step::Poll
                {
                    crate::sys::interrupt(libc::SIGTERM).unwrap();
                    observed_signal.set(true);
                }
            })),
            ..Script::default()
        }));
        let began = std::time::Instant::now();
        let result = custody.wait_any(vec![first, second]);
        let trace = step::install(None).unwrap().reached;
        assert!(trace.iter().filter(|at| **at == Step::Poll).count() <= 8);
        let waited = result.unwrap();
        assert!(joined.get());
        assert_eq!(signaled.get(), interrupted);
        assert!(began.elapsed() < Duration::from_secs(1));
        assert_eq!(
            waited
                .stopped
                .started()
                .as_ref()
                .unwrap()
                .record()
                .attempt
                .as_str(),
            "attempt-2"
        );
        assert_eq!(waited.stopped.watchdog(), !interrupted);
        assert_eq!(
            waited.stopped.interruption(),
            interrupted.then_some(libc::SIGTERM)
        );
        assert!(member.try_wait().unwrap().is_none());
        assert!(
            fs::read_to_string(hosted.root.join("attempt-1/cgroup.events"))
                .unwrap()
                .contains("populated 1")
        );
        assert!(
            fs::read_to_string(hosted.root.join("attempt-2/cgroup.events"))
                .unwrap()
                .contains("populated 0")
        );
        waited.stopped.remove_group().unwrap();
        fs::write(hosted.root.join("attempt-1/cgroup.kill"), "1").unwrap();
        member.wait().unwrap();
        let first = custody.wait_any(waited.to_drain).unwrap();
        assert!(!first.stopped.watchdog());
        assert_eq!(first.stopped.interruption(), None);
        first.stopped.remove_group().unwrap();
    }
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn interrupted_poll_recomputes_the_absolute_watchdog_deadline() {
    let _processes = processes();
    let (hosted, mut custody, store) = prepared(5100);
    custody.timing.poll = Duration::from_secs(30);
    custody.timing.watchdog = Duration::from_secs(2);
    let mut launch = hosted.launch();
    launch.launcher = "/bin/sleep".into();
    launch.args = vec!["20".into()];
    let running = custody.launch(&store, store.root(), launch).unwrap();
    let mut polls = 0;
    step::install(Some(Script {
        nth: Some((Step::Poll, 0, Outcome::Errno(libc::EINTR))),
        observe: Some(Box::new(move |at| {
            if at == Step::Poll {
                polls += 1;
                if polls <= 2 {
                    std::thread::sleep(Duration::from_millis(500));
                }
            }
        })),
        ..Script::default()
    }));
    let began = std::time::Instant::now();
    let result = custody.wait_any(vec![running]);
    let trace = step::install(None).unwrap().reached;
    let stopped = result.unwrap().stopped;
    let kill = trace.iter().position(|at| *at == Step::Kill).unwrap();
    assert_eq!(
        trace[..kill].iter().filter(|at| **at == Step::Poll).count(),
        2
    );
    assert!(stopped.watchdog());
    assert!(began.elapsed() >= Duration::from_secs(2));
    assert!(began.elapsed() < Duration::from_millis(2300));
    stopped.remove_group().unwrap();
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn replacement_between_inode_check_and_kill_preserves_its_member() {
    let _processes = processes();
    let (hosted, mut custody, store) = prepared(5200);
    let running = custody
        .launch(&store, store.root(), hosted.launch())
        .unwrap();
    drop(custody.wait_any(vec![running]).unwrap().stopped);
    let intent = store
        .read_record::<Intent>(store.root(), &name("intent"))
        .unwrap()
        .unwrap();
    let started = store
        .read_record::<Started>(store.root(), &name("started"))
        .unwrap()
        .unwrap();
    let mut sentinel = Command::new("/bin/sleep").arg("20").spawn().unwrap();
    let pid = sentinel.id();
    let path = hosted.root.join("attempt-1");
    let replaced = std::rc::Rc::new(std::cell::Cell::new(false));
    let observed = replaced.clone();
    step::install(Some(Script {
        observe: Some(Box::new(move |at| {
            if at == Step::Kill && !observed.get() {
                fs::remove_dir(&path).unwrap();
                fs::create_dir(&path).unwrap();
                fs::write(path.join("cgroup.procs"), pid.to_string()).unwrap();
                observed.set(true);
            }
        })),
        ..Script::default()
    }));
    let result = custody.reconcile(&store, &intent, Some(&started));
    step::install(None);
    assert!(replaced.get());
    assert!(matches!(result, Err(Error::Io(_))));
    for _ in 0..10 {
        assert!(sentinel.try_wait().unwrap().is_none());
        assert!(
            fs::read_to_string(hosted.root.join("attempt-1/cgroup.events"))
                .unwrap()
                .contains("populated 1")
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    fs::write(hosted.root.join("attempt-1/cgroup.kill"), "1").unwrap();
    sentinel.wait().unwrap();
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn reconcile_faults_retain_reservations_until_a_successful_redrain() {
    let _processes = processes();
    for (index, point) in [Step::Kill, Step::Drained, Step::Removed]
        .into_iter()
        .enumerate()
    {
        for (mode, outcome) in [Outcome::Errno(libc::EIO), Outcome::Kill]
            .into_iter()
            .enumerate()
        {
            let (hosted, mut custody, store) = prepared(5300 + index * 2 + mode);
            let running = custody
                .launch(&store, store.root(), hosted.launch())
                .unwrap();
            drop(custody.wait_any(vec![running]).unwrap().stopped);
            let intent = store
                .read_record::<Intent>(store.root(), &name("intent"))
                .unwrap()
                .unwrap();
            let started = store
                .read_record::<Started>(store.root(), &name("started"))
                .unwrap()
                .unwrap();
            let (result, _) = at_point(point, outcome, || {
                custody
                    .reconcile(&store, &intent, Some(&started))?
                    .remove_group()
            });
            assert!(result.is_none() || result.unwrap().is_err());
            assert_eq!(
                fs::read(hosted.case.state.join("reservation")).unwrap(),
                RESERVATION_BYTES
            );
            assert_eq!(
                hosted.root.join("attempt-1").exists(),
                point != Step::Removed
            );
            drop(custody);
            let mut restarted = hosted.custody(Duration::from_secs(1));
            restarted
                .reconcile(&store, &intent, Some(&started))
                .unwrap()
                .remove_group()
                .unwrap();
            assert!(!hosted.root.join("attempt-1").exists());
            assert_eq!(
                fs::read(hosted.case.state.join("reservation")).unwrap(),
                RESERVATION_BYTES
            );
        }
    }
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn invalid_limits_commands_and_reserved_names_leave_no_attempt_effects() {
    let _processes = processes();
    let (hosted, mut custody, store) = prepared(6000);
    let base = hosted.launch().limits;
    for limits in [
        Limits {
            cpu_quota_us: 999,
            ..base
        },
        Limits {
            cpu_quota_us: 1 << 44,
            ..base
        },
        Limits {
            cpu_quota_us: u64::MAX,
            ..base
        },
        Limits {
            memory_bytes: 0,
            ..base
        },
        Limits {
            cpu_seconds: 0,
            ..base
        },
        Limits {
            cpu_seconds: crate::sys::CPU_HARD_MAX,
            ..base
        },
        Limits {
            output_bytes: 0,
            ..base
        },
        Limits {
            output_inodes: 0,
            ..base
        },
        Limits {
            output_inodes: 4095,
            ..base
        },
        Limits { pids: 0, ..base },
        Limits {
            pids: 4 * 1024 * 1024 + 1,
            ..base
        },
        Limits {
            file_bytes: 0,
            ..base
        },
        Limits {
            file_bytes: (1 << 63) - 1,
            ..base
        },
        Limits {
            file_bytes: u64::MAX,
            ..base
        },
    ] {
        let mut launch = hosted.launch();
        launch.limits = limits;
        assert!(matches!(
            custody.launch(&store, store.root(), launch),
            Err(Error::Rejected("invalid custody limits"))
        ));
        assert!(!hosted.case.state.join("intent").exists());
        assert!(custody.unrecorded(&[], 10).unwrap().is_empty());
    }
    for index in 0..7 {
        use std::os::unix::ffi::OsStringExt;
        let mut launch = hosted.launch();
        let nul = std::ffi::OsString::from_vec(b"bad\0word".to_vec());
        match index {
            0 => launch.gate = nul.into(),
            1 => launch.launcher = nul.into(),
            2 => launch.directory = nul.into(),
            3 => launch.args.push(nul),
            4 => {
                launch.environment.insert(nul, "value".into());
            }
            5 => {
                launch.environment.insert("key".into(), nul);
            }
            6 => {
                launch.environment.insert("bad=key".into(), "value".into());
            }
            _ => unreachable!(),
        }
        assert!(matches!(
            custody.launch(&store, store.root(), launch),
            Err(Error::Rejected("invalid custody command"))
        ));
        assert!(!hosted.case.state.join("intent").exists());
        assert!(custody.unrecorded(&[], 10).unwrap().is_empty());
    }
    for component in [
        "controller",
        "sweep",
        "cpu.max",
        "memory.max",
        "cgroup.procs",
        "pids.current",
    ] {
        let mut launch = hosted.launch();
        launch.name = name(component);
        assert!(matches!(
            custody.launch(&store, store.root(), launch),
            Err(Error::Rejected("invalid custody cgroup name"))
        ));
        assert!(!hosted.case.state.join("intent").exists());
        assert!(custody.unrecorded(&[], 10).unwrap().is_empty());
    }
    let intent = Intent {
        attempt: Text::new("controller").unwrap(),
        boot: custody.boot.clone(),
        cgroup: Text::new(hosted.root.join("controller").to_str().unwrap()).unwrap(),
    };
    store
        .create_record(store.root(), &name("controller-intent"), &intent)
        .unwrap();
    let intent = store
        .read_record::<Intent>(store.root(), &name("controller-intent"))
        .unwrap()
        .unwrap();
    assert!(
        matches!(custody.reconcile(&store, &intent, None), Err(Error::Io(error))
        if error.kind() == std::io::ErrorKind::InvalidInput)
    );
    assert!(
        fs::read_to_string(hosted.root.join("controller/cgroup.procs"))
            .unwrap()
            .split_whitespace()
            .any(|pid| pid == std::process::id().to_string())
    );
    assert!(matches!(
        custody.wait_any(Vec::new()),
        Err(Error::Rejected("empty custody wait set"))
    ));
    assert_eq!(
        Error::Rejected("arguments").exit(),
        crate::exit::Supervisor::Rejected
    );
    assert_eq!(
        Error::from(crate::store::Error::Busy).exit(),
        crate::exit::Supervisor::Busy
    );
    assert_eq!(
        Error::from(crate::store::Error::Poisoned).exit(),
        crate::exit::Supervisor::Held
    );
}

#[test]
fn root_syntax_refusals_match_between_the_check_and_open() {
    let timing = Timing {
        poll: Duration::from_millis(1),
        kill_wait: Duration::from_secs(1),
        watchdog: Duration::from_secs(1),
    };
    for (root, reason) in [
        ("relative", "invalid custody root path"),
        ("/delegated/../outside", "invalid custody root path"),
        (
            "/non\nprintable",
            "cgroup path contains non-printable bytes",
        ),
    ] {
        let root = Path::new(root);
        assert!(matches!(
            Custody::check_root(root),
            Err(Error::Rejected(found)) if found == reason
        ));
        assert!(matches!(
            Custody::open(root, timing),
            Err(Error::Rejected(found)) if found == reason
        ));
    }
    assert!(Custody::check_root(Path::new("/delegated/./root")).is_ok());
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn invalid_timing_is_rejected_before_delegation_initialization() {
    let _processes = processes();
    let hosted = Hosted::new(6100);
    let base = Timing {
        poll: Duration::from_millis(1),
        kill_wait: Duration::from_secs(1),
        watchdog: Duration::from_secs(1),
    };
    for timing in [
        Timing {
            poll: Duration::ZERO,
            ..base
        },
        Timing {
            kill_wait: Duration::ZERO,
            ..base
        },
        Timing {
            watchdog: Duration::ZERO,
            ..base
        },
        Timing {
            kill_wait: Duration::MAX,
            ..base
        },
        Timing {
            watchdog: Duration::MAX,
            ..base
        },
    ] {
        assert!(matches!(
            Custody::open(&hosted.root, timing),
            Err(Error::Rejected("invalid custody timing"))
        ));
        assert!(!hosted.root.join("controller").exists());
    }
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn supported_upper_limit_values_are_installed_exactly() {
    let _processes = processes();
    let (hosted, mut custody, store) = prepared(6200);
    let mut launch = hosted.launch();
    launch.limits.cpu_quota_us = (1 << 44) - 1;
    launch.limits.pids = 4 * 1024 * 1024;
    launch.limits.file_bytes = (1 << 63) - 2;
    let running = custody.launch(&store, store.root(), launch).unwrap();
    assert_eq!(
        fs::read_to_string(hosted.root.join("attempt-1/cpu.max")).unwrap(),
        format!("{} 100000\n", (1_u64 << 44) - 1)
    );
    assert_eq!(
        fs::read_to_string(hosted.root.join("attempt-1/pids.max")).unwrap(),
        "4194304\n"
    );
    let stopped = custody.wait_any(vec![running]).unwrap().stopped;
    assert!(stopped.status().unwrap().success());
    stopped.remove_group().unwrap();
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn existing_lifecycle_records_hold_every_relaunch() {
    let _processes = processes();
    let (hosted, mut custody, store) = prepared(6300);
    let running = custody
        .launch(&store, store.root(), hosted.launch())
        .unwrap();
    custody
        .wait_any(vec![running])
        .unwrap()
        .stopped
        .remove_group()
        .unwrap();
    let intent = fs::read(hosted.case.state.join("intent")).unwrap();
    let started_bytes = fs::read(hosted.case.state.join("started")).unwrap();
    assert!(matches!(
        custody.launch(&store, store.root(), hosted.launch()),
        Err(Error::Held("lifecycle already recorded"))
    ));
    assert!(!hosted.root.join("attempt-1").exists());
    assert_eq!(fs::read(hosted.case.state.join("intent")).unwrap(), intent);
    assert_eq!(
        fs::read(hosted.case.state.join("started")).unwrap(),
        started_bytes
    );
    let started = store
        .read_record::<Started>(store.root(), &name("started"))
        .unwrap()
        .unwrap();
    store.mkdir(store.root(), &name("second")).unwrap();
    let second = store
        .open_dir(store.root(), &name("second"))
        .unwrap()
        .unwrap();
    store
        .create_record(&second, &name("started"), started.record())
        .unwrap();
    let mut launch = launch(&hosted.case.root, &hosted.case.root.join("second-effect"));
    launch.attempt = Text::new("attempt-2").unwrap();
    launch.name = name("attempt-2");
    assert!(matches!(
        custody.launch(&store, &second, launch),
        Err(Error::Held("lifecycle already recorded"))
    ));
    assert!(!hosted.case.root.join("second-effect").exists());
    assert!(!hosted.root.join("attempt-2").exists());
    assert!(!hosted.case.state.join("second/intent").exists());
    assert_eq!(
        fs::read(hosted.case.state.join("second/started")).unwrap(),
        started_bytes
    );
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn unavailable_limit_interfaces_refuse_open_before_any_attempt() {
    let _processes = processes();
    let hosted = Hosted::new(6400);
    let (result, trace) = scripted([], || hosted.custody(Duration::from_secs(1)));
    drop(result.unwrap());
    let last_write = trace.iter().rposition(|at| *at == Step::Write).unwrap();
    let probes: Vec<_> = trace
        .iter()
        .enumerate()
        .filter_map(|(index, at)| (index > last_write && *at == Step::Open).then_some(index))
        .collect();
    assert_eq!(probes.len(), 6, "kill and five writable limit probes");
    for &index in &probes[1..] {
        let (result, actual) = scripted([(index, Outcome::Errno(libc::ENOENT))], || {
            Custody::open(
                &hosted.root,
                Timing {
                    poll: Duration::from_millis(1),
                    kill_wait: Duration::from_secs(1),
                    watchdog: Duration::from_millis(200),
                },
            )
        });
        assert_eq!(actual.len(), index + 1);
        assert!(matches!(result.unwrap(), Err(Error::Io(error))
            if error.kind() == std::io::ErrorKind::NotFound));
        assert!(!hosted.case.state.join("intent").exists());
        assert!(!hosted.root.join("attempt-1").exists());
    }
    let boot_read = trace.iter().rposition(|at| *at == Step::Read).unwrap();
    assert!(boot_read > *probes.last().unwrap());
    assert_eq!(boot_read + 1, trace.len());
    let (result, actual) = scripted([(boot_read, Outcome::Errno(libc::EIO))], || {
        Custody::open(
            &hosted.root,
            Timing {
                poll: Duration::from_millis(1),
                kill_wait: Duration::from_secs(1),
                watchdog: Duration::from_millis(200),
            },
        )
    });
    assert_eq!(actual.len(), boot_read + 1);
    assert!(
        matches!(result.unwrap(), Err(Error::Io(error)) if error.raw_os_error() == Some(libc::EIO))
    );
    assert!(!hosted.case.state.join("intent").exists());
    assert!(!hosted.root.join("attempt-1").exists());
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn invalid_launch_paths_are_rejected_before_durable_intent() {
    let _processes = processes();
    let (hosted, mut custody, store) = prepared(6500);
    let non_executable = hosted.case.root.join("plain");
    fs::write(&non_executable, b"plain").unwrap();
    for index in 0..7 {
        let mut launch = hosted.launch();
        match index {
            0 => launch.gate = "campaign".into(),
            1 => launch.gate = hosted.case.root.join("missing-gate"),
            2 => launch.gate = non_executable.clone(),
            3 => launch.directory = hosted.case.root.join("missing-directory"),
            4 => launch.directory = ".".into(),
            5 => launch.directory = non_executable.clone(),
            6 => launch.gate = hosted.case.root.clone(),
            _ => unreachable!(),
        }
        let result = custody.launch(&store, store.root(), launch);
        assert!(matches!(
            result,
            Err(Error::Rejected("invalid custody launch paths"))
        ));
        assert!(!hosted.case.state.join("intent").exists());
        assert!(custody.unrecorded(&[], 10).unwrap().is_empty());
    }
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_gate_removed_after_preflight_leaves_durable_intent_and_a_held_group() {
    let _processes = processes();
    let (hosted, mut custody, store) = prepared(6510);
    let executable = hosted.case.root.join("gate-executable");
    fs::copy("/bin/sh", &executable).unwrap();
    let mut launch = hosted.launch();
    launch.gate = executable.clone();
    let reached = std::rc::Rc::new(std::cell::Cell::new(false));
    let observed = reached.clone();
    step::install(Some(Script {
        observe: Some(Box::new(move |at| {
            if at == Step::Intent && !observed.get() {
                fs::remove_file(&executable).unwrap();
                observed.set(true);
            }
        })),
        ..Script::default()
    }));
    let result = custody.launch(&store, store.root(), launch);
    step::install(None);
    assert!(reached.get());
    assert!(
        matches!(result, Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound)
    );
    assert!(hosted.case.state.join("intent").exists());
    assert!(!hosted.case.state.join("started").exists());
    assert!(hosted.root.join("attempt-1").exists());
    assert!(!hosted.case.root.join("effect").exists());
    let intent = store
        .read_record::<Intent>(store.root(), &name("intent"))
        .unwrap()
        .unwrap();
    assert!(matches!(
        custody.reconcile(&store, &intent, None),
        Err(Error::Held("cgroup lacks matching started"))
    ));
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn each_limit_install_failure_holds_its_intent_only_group() {
    let _processes = processes();
    let (hosted, mut custody, store) = prepared(6600);
    let (result, trace) = scripted([], || lifecycle(&hosted, &mut custody, &store));
    result.unwrap().unwrap();
    let intent = trace.iter().position(|at| *at == Step::Intent).unwrap();
    let created = trace.iter().position(|at| *at == Step::Created).unwrap();
    let cuts: Vec<_> = trace
        .iter()
        .enumerate()
        .filter_map(|(index, at)| {
            (index > intent && index < created && *at == Step::Write).then_some(index)
        })
        .collect();
    assert_eq!(cuts.len(), 5);
    drop(store);
    drop(custody);
    drop(hosted);
    for (ordinal, index) in cuts.into_iter().enumerate() {
        let (hosted, mut custody, store) = prepared(6601 + ordinal);
        let (result, trace) = scripted([(index, Outcome::Errno(libc::EIO))], || {
            custody.launch(&store, store.root(), hosted.launch())
        });
        assert_eq!(trace.len(), index + 1);
        assert!(
            matches!(result.unwrap(), Err(Error::Io(error)) if error.raw_os_error() == Some(libc::EIO))
        );
        assert!(hosted.root.join("attempt-1").exists());
        assert!(!hosted.case.state.join("started").exists());
        assert!(!hosted.case.root.join("effect").exists());
        let intent = store
            .read_record::<Intent>(store.root(), &name("intent"))
            .unwrap()
            .unwrap();
        assert!(matches!(
            custody.reconcile(&store, &intent, None),
            Err(Error::Held("cgroup lacks matching started"))
        ));
    }
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_delegation_without_child_controllers_is_refused_before_move() {
    let _processes = processes();
    let hosted = Hosted::new(6700);
    let root = hosted.root.join("child");
    fs::create_dir(&root).unwrap();
    assert!(
        fs::read_to_string(root.join("cgroup.controllers"))
            .unwrap()
            .trim()
            .is_empty()
    );
    assert!(matches!(Custody::open(&root, Timing {
        poll: Duration::from_millis(1),
        kill_wait: Duration::from_secs(1),
        watchdog: Duration::from_secs(1),
    }), Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::InvalidInput));
    assert!(!root.join("controller").exists());
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_repopulated_stopped_group_holds_removal_until_reconciled() {
    let _processes = processes();
    let (hosted, mut custody, store) = prepared(6800);
    let running = custody
        .launch(&store, store.root(), hosted.launch())
        .unwrap();
    let stopped = custody.wait_any(vec![running]).unwrap().stopped;
    let mut member = Command::new("/bin/sleep").arg("20").spawn().unwrap();
    fs::write(
        hosted.root.join("attempt-1/cgroup.procs"),
        member.id().to_string(),
    )
    .unwrap();
    assert!(matches!(
        stopped.remove_group(),
        Err(Error::Held("cgroup populated before removal"))
    ));
    assert!(hosted.root.join("attempt-1").exists());
    assert!(member.try_wait().unwrap().is_none());
    let intent = store
        .read_record::<Intent>(store.root(), &name("intent"))
        .unwrap()
        .unwrap();
    let started = store
        .read_record::<Started>(store.root(), &name("started"))
        .unwrap()
        .unwrap();
    custody
        .reconcile(&store, &intent, Some(&started))
        .unwrap()
        .remove_group()
        .unwrap();
    member.wait().unwrap();
    assert!(!hosted.root.join("attempt-1").exists());
    assert_eq!(
        fs::read(hosted.case.state.join("reservation")).unwrap(),
        RESERVATION_BYTES
    );
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_latched_interruption_consumes_later_notifications_during_drain() {
    let _processes = processes();
    let (hosted, mut custody, store) = prepared(6900);
    custody.timing.poll = Duration::from_secs(30);
    custody.timing.watchdog = Duration::from_secs(20);
    let running = custody
        .launch(&store, store.root(), hosted.launch())
        .unwrap();
    let mut member = Command::new("/bin/sleep").arg("20").spawn().unwrap();
    let path = hosted.root.join("attempt-1");
    let pid = member.id();
    let mut killed = false;
    let mut joined = false;
    let mut polls = 0;
    let release = std::rc::Rc::new(std::cell::RefCell::new(None));
    let observed_release = release.clone();
    step::install(Some(Script {
        observe: Some(Box::new(move |at| {
            if at == Step::Kill {
                killed = true;
            }
            if killed && !joined && at == Step::Read {
                fs::write(path.join("cgroup.procs"), pid.to_string()).unwrap();
                joined = true;
            }
            if joined && at == Step::Poll {
                polls += 1;
                if polls == 1 {
                    crate::sys::interrupt(libc::SIGTERM).unwrap();
                } else if polls == 2 {
                    crate::sys::interrupt(libc::SIGINT).unwrap();
                    let path = path.clone();
                    *observed_release.borrow_mut() = Some(std::thread::spawn(move || {
                        std::thread::sleep(Duration::from_millis(100));
                        fs::write(path.join("cgroup.kill"), "1").unwrap();
                    }));
                }
            }
        })),
        ..Script::default()
    }));
    let result = custody.wait_any(vec![running]);
    let trace = step::install(None).unwrap().reached;
    release.borrow_mut().take().unwrap().join().unwrap();
    let stopped = result.unwrap().stopped;
    assert_eq!(stopped.interruption(), None);
    assert_eq!(custody.interruption().unwrap(), Some(libc::SIGTERM));
    assert!(trace.iter().filter(|at| **at == Step::Poll).count() <= 8);
    assert!(!member.wait().unwrap().success());
    stopped.remove_group().unwrap();
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn late_observed_exits_preserve_expired_watchdogs() {
    let _processes = processes();
    let (hosted, mut custody, store) = prepared(7000);
    custody.timing.poll = Duration::from_secs(30);
    let marker = hosted.case.root.join("expired");
    let mut launch = hosted.launch();
    launch.args = vec![
        "-c".into(),
        format!(
            "until [ -e '{}' ]; do sleep 0.001; done; exit 0",
            marker.display()
        )
        .into(),
    ];
    let running = custody.launch(&store, store.root(), launch).unwrap();
    let mut delayed = false;
    step::install(Some(Script {
        observe: Some(Box::new(move |at| {
            if at == Step::Poll && !delayed {
                std::thread::sleep(Duration::from_millis(250));
                fs::write(&marker, b"expired").unwrap();
                std::thread::sleep(Duration::from_millis(100));
                delayed = true;
            }
        })),
        ..Script::default()
    }));
    let result = custody.wait_any(vec![running]);
    step::install(None);
    let stopped = result.unwrap().stopped;
    assert_eq!(stopped.status().unwrap().code(), Some(0));
    assert!(stopped.watchdog());
    stopped.remove_group().unwrap();
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn fatal_wait_errors_kill_all_remaining_pinned_groups_and_hold_their_names() {
    let _processes = processes();
    for point in [Step::Reap, Step::Kill] {
        let (hosted, mut custody, store) = prepared(7010 + usize::from(point == Step::Kill));
        custody.timing.watchdog = Duration::from_secs(20);
        store.mkdir(store.root(), &name("second")).unwrap();
        let second = store
            .open_dir(store.root(), &name("second"))
            .unwrap()
            .unwrap();
        let mut launch = hosted.launch();
        launch.launcher = "/bin/sleep".into();
        launch.args = vec!["20".into()];
        let first = custody.launch(&store, store.root(), launch).unwrap();
        let mut launch = hosted.launch();
        launch.attempt = Text::new("attempt-2").unwrap();
        launch.name = name("attempt-2");
        launch.launcher = "/bin/sleep".into();
        launch.args = vec!["20".into()];
        let second_running = custody.launch(&store, &second, launch).unwrap();
        crate::sys::interrupt(libc::SIGTERM).unwrap();
        let (result, trace) = at_point(point, Outcome::Errno(libc::EIO), || {
            custody.wait_any(vec![first, second_running])
        });
        assert!(
            matches!(result.unwrap(), Err(Error::Io(error)) if error.raw_os_error() == Some(libc::EIO))
        );
        assert!(trace.iter().filter(|at| **at == Step::Kill).count() >= 2);
        for component in ["attempt-1", "attempt-2"] {
            let path = hosted.root.join(component);
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            while !fs::read_to_string(path.join("cgroup.events"))
                .unwrap()
                .contains("populated 0")
            {
                assert!(std::time::Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(1));
            }
            assert!(path.exists());
        }
        for directory in [store.root(), &second] {
            let intent = store
                .read_record::<Intent>(directory, &name("intent"))
                .unwrap()
                .unwrap();
            let started = store
                .read_record::<Started>(directory, &name("started"))
                .unwrap()
                .unwrap();
            custody
                .reconcile(&store, &intent, Some(&started))
                .unwrap()
                .remove_group()
                .unwrap();
        }
        assert_eq!(
            fs::read(hosted.case.state.join("reservation")).unwrap(),
            RESERVATION_BYTES
        );
    }
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn host_faults_and_effective_permissions_are_checked_before_intent() {
    let _processes = processes();
    let (hosted, mut custody, store) = prepared(7020);
    let (result, _) = at_point(Step::Stat, Outcome::Errno(libc::EIO), || {
        custody.launch(&store, store.root(), hosted.launch())
    });
    assert!(
        matches!(result.unwrap(), Err(Error::Io(error)) if error.raw_os_error() == Some(libc::EIO))
    );
    assert!(!hosted.case.state.join("intent").exists());
    use std::os::unix::fs::PermissionsExt;
    let executable = hosted.case.root.join("wrong-execute-class");
    fs::write(&executable, b"exit 0\n").unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o601)).unwrap();
    let mut launch = hosted.launch();
    launch.gate = executable;
    assert!(matches!(
        custody.launch(&store, store.root(), launch),
        Err(Error::Rejected("invalid custody launch paths"))
    ));
    let directory = hosted.case.root.join("not-searchable");
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o600)).unwrap();
    let mut launch = hosted.launch();
    launch.directory = directory.clone();
    assert!(matches!(
        custody.launch(&store, store.root(), launch),
        Err(Error::Rejected("invalid custody launch paths"))
    ));
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(!hosted.case.state.join("intent").exists());
    assert!(custody.unrecorded(&[], 10).unwrap().is_empty());
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn inherited_file_limits_are_rejected_before_intent() {
    let _processes = processes();
    if std::env::var_os("CAMPAIGN_FSIZE_PREFLIGHT_CHILD").is_none() {
        let output = Command::new("/bin/sh")
            .args(["-c", "ulimit -f 8; exec \"$@\"", "fsize-preflight"])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "custody::run_tests::inherited_file_limits_are_rejected_before_intent",
                "--include-ignored",
                "--nocapture",
            ])
            .env("CAMPAIGN_FSIZE_PREFLIGHT_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success()
                && String::from_utf8_lossy(&output.stdout).contains("test result: ok. 1 passed;"),
            "{output:?}"
        );
        return;
    }
    let (hosted, mut custody, store) = prepared(7030);
    assert!(crate::sys::file_limit().unwrap() < hosted.launch().limits.file_bytes);
    assert!(matches!(
        custody.launch(&store, store.root(), hosted.launch()),
        Err(Error::Rejected("file limit exceeds inherited hard bound"))
    ));
    assert!(!hosted.case.state.join("intent").exists());
    assert!(custody.unrecorded(&[], 10).unwrap().is_empty());
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn intent_oversize_is_rejected_and_started_oversize_keeps_the_created_group_held() {
    let _processes = processes();
    let (hosted, mut custody, store) = prepared(7040);
    let mut launch = hosted.launch();
    launch.attempt = Text::new(&"a".repeat(crate::record::BOUND as usize)).unwrap();
    assert!(matches!(
        custody.launch(&store, store.root(), launch),
        Err(Error::Rejected("intent exceeds record bound"))
    ));
    assert!(!hosted.case.state.join("intent").exists());
    assert!(custody.unrecorded(&[], 10).unwrap().is_empty());
    let baseline = Intent {
        attempt: Text::new("a").unwrap(),
        boot: custody.boot.clone(),
        cgroup: Text::new(hosted.root.join("attempt-1").to_str().unwrap()).unwrap(),
    };
    store
        .create_record(store.root(), &name("size"), &baseline)
        .unwrap();
    let size = fs::metadata(hosted.case.state.join("size")).unwrap().len();
    let mut launch = hosted.launch();
    launch.attempt = Text::new(&"a".repeat((crate::record::BOUND - size + 1) as usize)).unwrap();
    assert!(matches!(
        custody.launch(&store, store.root(), launch),
        Err(Error::Store(crate::store::Error::Oversize))
    ));
    assert_eq!(
        fs::metadata(hosted.case.state.join("intent"))
            .unwrap()
            .len(),
        crate::record::BOUND
    );
    assert!(!hosted.case.state.join("started").exists());
    assert!(hosted.root.join("attempt-1").exists());
    assert!(!hosted.case.root.join("effect").exists());
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn every_reconcile_barrier_fault_preserves_live_membership_and_poisoned_store_state() {
    let _processes = processes();
    let (hosted, mut custody, store) = prepared(7100);
    let mut launch = hosted.launch();
    launch.launcher = "/bin/sleep".into();
    launch.args = vec!["20".into()];
    let running = custody.launch(&store, store.root(), launch).unwrap();
    let intent = store
        .read_record::<Intent>(store.root(), &name("intent"))
        .unwrap()
        .unwrap();
    let started = store
        .read_record::<Started>(store.root(), &name("started"))
        .unwrap()
        .unwrap();
    let (result, baseline) = scripted([], || custody.reconcile(&store, &intent, Some(&started)));
    drop(result.unwrap().unwrap());
    custody
        .wait_any(vec![running])
        .unwrap()
        .stopped
        .remove_group()
        .unwrap();
    let kill = baseline.iter().position(|at| *at == Step::Kill).unwrap();
    let cuts: Vec<_> = baseline[..kill]
        .iter()
        .enumerate()
        .filter_map(|(index, at)| (*at == Step::Sync).then_some(index))
        .collect();
    assert_eq!(cuts.len(), 4);
    drop(started);
    drop(intent);
    drop(store);
    drop(custody);
    drop(hosted);
    for (ordinal, index) in cuts.into_iter().enumerate() {
        for (mode, outcome) in [Outcome::Errno(libc::EIO), Outcome::Kill]
            .into_iter()
            .enumerate()
        {
            let (hosted, mut custody, store) = prepared(7110 + ordinal * 2 + mode);
            let mut launch = hosted.launch();
            launch.launcher = "/bin/sleep".into();
            launch.args = vec!["20".into()];
            let running = custody.launch(&store, store.root(), launch).unwrap();
            let intent = store
                .read_record::<Intent>(store.root(), &name("intent"))
                .unwrap()
                .unwrap();
            let started = store
                .read_record::<Started>(store.root(), &name("started"))
                .unwrap()
                .unwrap();
            let mut member = Command::new("/bin/sleep").arg("20").spawn().unwrap();
            fs::write(
                hosted.root.join("attempt-1/cgroup.procs"),
                member.id().to_string(),
            )
            .unwrap();
            let (result, trace) = scripted([(index, outcome)], || {
                custody.reconcile(&store, &intent, Some(&started))
            });
            assert_eq!(trace.len(), index + 1);
            assert_eq!(trace[index], Step::Sync);
            assert!(!trace.contains(&Step::Kill));
            assert!(result.is_none() || result.unwrap().is_err());
            assert!(member.try_wait().unwrap().is_none());
            assert!(
                fs::read_to_string(hosted.root.join("attempt-1/cgroup.events"))
                    .unwrap()
                    .contains("populated 1")
            );
            if mode == 0 {
                assert!(matches!(
                    store.create_once(store.root(), &name("later"), b"later"),
                    Err(crate::store::Error::Poisoned)
                ));
            }
            drop(started);
            drop(intent);
            drop(store);
            drop(custody);
            let store = Store::open(&hosted.case.state).unwrap();
            let mut custody = hosted.custody(Duration::from_secs(1));
            let intent = store
                .read_record::<Intent>(store.root(), &name("intent"))
                .unwrap()
                .unwrap();
            let started = store
                .read_record::<Started>(store.root(), &name("started"))
                .unwrap()
                .unwrap();
            drop(custody.reconcile(&store, &intent, Some(&started)).unwrap());
            member.wait().unwrap();
            custody
                .wait_any(vec![running])
                .unwrap()
                .stopped
                .remove_group()
                .unwrap();
            assert!(!hosted.root.join("attempt-1").exists());
            assert_eq!(
                fs::read(hosted.case.state.join("reservation")).unwrap(),
                RESERVATION_BYTES
            );
        }
    }
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn held_drains_stop_siblings_and_reconcile_after_a_drain_time_interruption() {
    let _processes = processes();
    for interrupted in [false, true] {
        let (hosted, mut custody, store) = prepared(7200 + usize::from(interrupted));
        custody.timing.poll = Duration::from_secs(30);
        custody.timing.watchdog = Duration::from_secs(20);
        custody.timing.kill_wait = Duration::from_millis(80);
        store.mkdir(store.root(), &name("second")).unwrap();
        let second = store
            .open_dir(store.root(), &name("second"))
            .unwrap()
            .unwrap();
        let first = custody
            .launch(&store, store.root(), hosted.launch())
            .unwrap();
        let mut launch = hosted.launch();
        launch.attempt = Text::new("attempt-2").unwrap();
        launch.name = name("attempt-2");
        launch.launcher = "/bin/sleep".into();
        launch.args = vec!["20".into()];
        let second_running = custody.launch(&store, &second, launch).unwrap();
        let mut member = Command::new("/bin/sleep").arg("20").spawn().unwrap();
        let path = hosted.root.join("attempt-1");
        let pid = member.id();
        let mut killed = false;
        let mut joined = false;
        let mut sent = false;
        step::install(Some(Script {
            observe: Some(Box::new(move |at| {
                if at == Step::Kill {
                    killed = true;
                }
                if killed && !joined && at == Step::Read {
                    fs::write(path.join("cgroup.procs"), pid.to_string()).unwrap();
                    joined = true;
                }
                if interrupted && joined && !sent && at == Step::Poll {
                    crate::sys::interrupt(libc::SIGTERM).unwrap();
                    sent = true;
                }
            })),
            ..Script::default()
        }));
        let result = match custody.wait_any(vec![first, second_running]) {
            Ok(waited) => {
                assert!(interrupted);
                assert_eq!(waited.stopped.interruption(), Some(libc::SIGTERM));
                drop(waited.stopped);
                custody.wait_any(waited.to_drain)
            }
            Err(error) => Err(error),
        };
        step::install(None);
        assert!(matches!(
            result,
            Err(Error::Held(
                "cgroup populated or child unreaped past kill wait"
            ))
        ));
        assert_eq!(custody.held_identity().unwrap().as_str(), "attempt-1");
        assert!(
            fs::read_to_string(hosted.root.join("attempt-1/cgroup.events"))
                .unwrap()
                .contains("populated 1")
        );
        fs::write(hosted.root.join("attempt-1/cgroup.kill"), "1").unwrap();
        assert!(!member.wait().unwrap().success());
        for component in ["attempt-1", "attempt-2"] {
            let path = hosted.root.join(component);
            assert!(path.exists());
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            while !fs::read_to_string(path.join("cgroup.events"))
                .unwrap()
                .contains("populated 0")
            {
                assert!(
                    std::time::Instant::now() < deadline,
                    "fatal wait stops every sibling"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        drop(custody);
        let mut restarted = hosted.custody(Duration::from_secs(1));
        for directory in [store.root(), &second] {
            let intent = store
                .read_record::<Intent>(directory, &name("intent"))
                .unwrap()
                .unwrap();
            let started = store
                .read_record::<Started>(directory, &name("started"))
                .unwrap()
                .unwrap();
            restarted
                .reconcile(&store, &intent, Some(&started))
                .unwrap()
                .remove_group()
                .unwrap();
        }
        assert!(restarted.unrecorded(&[], 10).unwrap().is_empty());
        assert_eq!(
            fs::read(hosted.case.state.join("reservation")).unwrap(),
            RESERVATION_BYTES
        );
    }
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn the_earliest_watchdog_stops_its_attempt_while_a_later_deadline_stays_live() {
    let _processes = processes();
    for short_first in [false, true] {
        let (hosted, mut custody, store) = prepared(7300 + usize::from(short_first));
        custody.timing.poll = Duration::from_secs(30);
        custody.timing.watchdog = Duration::from_secs(20);
        store.mkdir(store.root(), &name("second")).unwrap();
        let second = store
            .open_dir(store.root(), &name("second"))
            .unwrap()
            .unwrap();
        let mut launch = hosted.launch();
        launch.launcher = "/bin/sleep".into();
        launch.args = vec!["20".into()];
        let first = custody.launch(&store, store.root(), launch).unwrap();
        custody.timing.watchdog = Duration::from_millis(200);
        let mut launch = hosted.launch();
        launch.attempt = Text::new("attempt-2").unwrap();
        launch.name = name("attempt-2");
        launch.launcher = "/bin/sleep".into();
        launch.args = vec!["20".into()];
        let began = std::time::Instant::now();
        let second = custody.launch(&store, &second, launch).unwrap();
        let set = if short_first {
            vec![second, first]
        } else {
            vec![first, second]
        };
        let waited = custody.wait_any(set).unwrap();
        assert!(began.elapsed() >= Duration::from_millis(200));
        assert!(began.elapsed() < Duration::from_secs(2));
        assert!(waited.stopped.watchdog());
        assert_eq!(
            waited.stopped.started().unwrap().record().attempt.as_str(),
            "attempt-2"
        );
        assert!(
            fs::read_to_string(hosted.root.join("attempt-1/cgroup.events"))
                .unwrap()
                .contains("populated 1")
        );
        waited.stopped.remove_group().unwrap();
        fs::write(hosted.root.join("attempt-1/cgroup.kill"), "1").unwrap();
        custody
            .wait_any(waited.to_drain)
            .unwrap()
            .stopped
            .remove_group()
            .unwrap();
    }
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn empty_commands_and_unrecordable_root_paths_are_rejected_before_attempt_effects() {
    let _processes = processes();
    let (hosted, mut custody, store) = prepared(7310);
    for index in 0..3 {
        let mut launch = hosted.launch();
        match index {
            0 => launch.gate = PathBuf::new(),
            1 => launch.launcher = PathBuf::new(),
            2 => {
                launch
                    .environment
                    .insert(std::ffi::OsString::new(), "value".into());
            }
            _ => unreachable!(),
        }
        let result = custody.launch(&store, store.root(), launch);
        assert!(matches!(result, Err(Error::Rejected(_))));
        assert!(!hosted.case.state.join("intent").exists());
        assert!(custody.unrecorded(&[], 10).unwrap().is_empty());
    }
    let timing = custody.timing;
    drop(custody);
    assert!(matches!(
        Custody::open(Path::new("relative"), timing),
        Err(Error::Rejected("invalid custody root path"))
    ));
    assert!(matches!(
        Custody::open(&hosted.root.join("../traversal"), timing),
        Err(Error::Rejected("invalid custody root path"))
    ));
    let root = hosted.root.join("nonprint\n");
    assert!(matches!(
        Custody::open(&root, timing),
        Err(Error::Rejected("cgroup path contains non-printable bytes"))
    ));
    assert!(!root.join("controller").exists());
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn reconcile_poll_interruptions_recompute_the_kill_wait_deadline() {
    let _processes = processes();
    let (hosted, mut custody, store) = prepared(7400);
    custody.timing.poll = Duration::from_secs(30);
    custody.timing.kill_wait = Duration::from_millis(100);
    let running = custody
        .launch(&store, store.root(), hosted.launch())
        .unwrap();
    drop(custody.wait_any(vec![running]).unwrap().stopped);
    let intent = store
        .read_record::<Intent>(store.root(), &name("intent"))
        .unwrap()
        .unwrap();
    let started = store
        .read_record::<Started>(store.root(), &name("started"))
        .unwrap()
        .unwrap();
    let mut member = Command::new("/bin/sleep").arg("20").spawn().unwrap();
    let path = hosted.root.join("attempt-1");
    let pid = member.id();
    let mut killed = false;
    let mut joined = false;
    step::install(Some(Script {
        nth: Some((Step::Poll, 0, Outcome::Errno(libc::EINTR))),
        observe: Some(Box::new(move |at| {
            if at == Step::Kill {
                killed = true;
            }
            if killed && !joined && at == Step::Read {
                fs::write(path.join("cgroup.procs"), pid.to_string()).unwrap();
                joined = true;
            }
            if at == Step::Poll {
                std::thread::sleep(Duration::from_millis(150));
            }
        })),
        ..Script::default()
    }));
    let result = custody.reconcile(&store, &intent, Some(&started));
    let trace = step::install(None).unwrap().reached;
    assert!(matches!(
        result,
        Err(Error::Held("cgroup populated past kill wait"))
    ));
    assert_eq!(trace.iter().filter(|at| **at == Step::Poll).count(), 1);
    assert!(member.try_wait().unwrap().is_none());
    fs::write(hosted.root.join("attempt-1/cgroup.kill"), "1").unwrap();
    member.wait().unwrap();
    custody
        .reconcile(&store, &intent, Some(&started))
        .unwrap()
        .remove_group()
        .unwrap();
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn reconcile_drain_captures_an_interruption_then_restart_removes_the_held_name() {
    let _processes = processes();
    let (hosted, mut custody, store) = prepared(7500);
    custody.timing.poll = Duration::from_secs(30);
    let running = custody
        .launch(&store, store.root(), hosted.launch())
        .unwrap();
    drop(custody.wait_any(vec![running]).unwrap().stopped);
    let intent = store
        .read_record::<Intent>(store.root(), &name("intent"))
        .unwrap()
        .unwrap();
    let started = store
        .read_record::<Started>(store.root(), &name("started"))
        .unwrap()
        .unwrap();
    let mut member = Command::new("/bin/sleep").arg("20").spawn().unwrap();
    let path = hosted.root.join("attempt-1");
    let pid = member.id();
    let mut killed = false;
    let mut joined = false;
    let release = std::rc::Rc::new(std::cell::RefCell::new(None));
    let observed = release.clone();
    step::install(Some(Script {
        observe: Some(Box::new(move |at| {
            if at == Step::Kill {
                killed = true;
            }
            if killed && !joined && at == Step::Read {
                fs::write(path.join("cgroup.procs"), pid.to_string()).unwrap();
                joined = true;
            }
            if joined && observed.borrow().is_none() && at == Step::Poll {
                crate::sys::interrupt(libc::SIGTERM).unwrap();
                let path = path.clone();
                *observed.borrow_mut() = Some(std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(100));
                    fs::write(path.join("cgroup.kill"), "1").unwrap();
                }));
            }
        })),
        ..Script::default()
    }));
    let result = custody.reconcile(&store, &intent, Some(&started));
    let trace = step::install(None).unwrap().reached;
    release.borrow_mut().take().unwrap().join().unwrap();
    drop(result.unwrap());
    assert_eq!(custody.interrupted, Some(libc::SIGTERM));
    assert!(trace.iter().filter(|at| **at == Step::Poll).count() <= 8);
    assert!(!member.wait().unwrap().success());
    assert!(hosted.root.join("attempt-1").exists());
    drop(custody);
    let mut restarted = hosted.custody(Duration::from_secs(1));
    restarted
        .reconcile(&store, &intent, Some(&started))
        .unwrap()
        .remove_group()
        .unwrap();
    assert!(!hosted.root.join("attempt-1").exists());
    assert_eq!(
        fs::read(hosted.case.state.join("reservation")).unwrap(),
        RESERVATION_BYTES
    );
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_slow_reap_scan_recomputes_the_absolute_poll_deadline() {
    let _processes = processes();
    let (hosted, mut custody, store) = prepared(7510);
    custody.timing.poll = Duration::from_secs(30);
    custody.timing.watchdog = Duration::from_secs(2);
    let mut launch = hosted.launch();
    launch.launcher = "/bin/sleep".into();
    launch.args = vec!["20".into()];
    let running = custody.launch(&store, store.root(), launch).unwrap();
    let mut delayed_reap = false;
    let mut delayed_poll = false;
    step::install(Some(Script {
        observe: Some(Box::new(move |at| {
            if at == Step::Reap && !delayed_reap {
                std::thread::sleep(Duration::from_millis(500));
                delayed_reap = true;
            }
            if at == Step::Poll && !delayed_poll {
                std::thread::sleep(Duration::from_millis(500));
                delayed_poll = true;
            }
        })),
        ..Script::default()
    }));
    let began = std::time::Instant::now();
    let result = custody.wait_any(vec![running]);
    let trace = step::install(None).unwrap().reached;
    let stopped = result.unwrap().stopped;
    let kill = trace.iter().position(|at| *at == Step::Kill).unwrap();
    assert_eq!(
        trace[..kill].iter().filter(|at| **at == Step::Poll).count(),
        1
    );
    assert!(stopped.watchdog());
    assert!(began.elapsed() >= Duration::from_secs(2));
    assert!(began.elapsed() < Duration::from_millis(2300));
    stopped.remove_group().unwrap();
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_successful_exit_reaped_after_the_deadline_is_a_watchdog() {
    let _processes = processes();
    let (hosted, mut custody, store) = prepared(7511);
    custody.timing.watchdog = Duration::from_millis(200);
    let finish = hosted.case.root.join("finish");
    let effect = hosted.case.root.join("late-exit");
    let mut launch = hosted.launch();
    launch.args = vec![
        "-c".into(),
        format!(
            "while [ ! -e '{}' ]; do sleep 0.001; done; printf late > '{}'",
            finish.display(),
            effect.display()
        )
        .into(),
    ];
    let running = custody.launch(&store, store.root(), launch).unwrap();
    let pid = running.started().record().launcher_pid;
    let mut delayed = false;
    step::install(Some(Script {
        observe: Some(Box::new(move |at| {
            if at == Step::Reap && !delayed {
                std::thread::sleep(Duration::from_millis(400));
                fs::write(&finish, b"finish").unwrap();
                let deadline = std::time::Instant::now() + Duration::from_secs(1);
                loop {
                    let status = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
                    if status.split_whitespace().nth(2) == Some("Z") {
                        break;
                    }
                    assert!(
                        std::time::Instant::now() < deadline,
                        "child must exit before the delayed reap"
                    );
                    std::thread::sleep(Duration::from_millis(1));
                }
                delayed = true;
            }
        })),
        ..Script::default()
    }));
    let result = custody.wait_any(vec![running]);
    step::install(None);
    let stopped = result.unwrap().stopped;
    assert_eq!(fs::read(effect).unwrap(), b"late");
    assert!(stopped.status().unwrap().success());
    assert!(stopped.watchdog());
    stopped.remove_group().unwrap();
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn event_notifications_are_acknowledged_before_the_next_blocking_poll() {
    let _processes = processes();
    let hosted = Hosted::new(4000);
    let mut custody = Custody::open(
        &hosted.root,
        Timing {
            poll: Duration::from_secs(30),
            kill_wait: Duration::from_secs(1),
            watchdog: Duration::from_millis(300),
        },
    )
    .unwrap();
    let store = Store::open(&hosted.case.state).unwrap();
    let mut launch = hosted.launch();
    launch.launcher = "/bin/sleep".into();
    launch.args = vec!["20".into()];
    let running = custody.launch(&store, store.root(), launch).unwrap();
    let (result, trace) = scripted([], || custody.wait_any(vec![running]));
    let stopped = result.unwrap().unwrap().stopped;
    assert!(stopped.watchdog());
    let killed = trace.iter().position(|at| *at == Step::Kill).unwrap();
    let polls = trace[..killed]
        .iter()
        .filter(|at| **at == Step::Poll)
        .count();
    assert!(
        (1..=2).contains(&polls),
        "acknowledged event waits block: {polls} polls"
    );
    stopped.remove_group().unwrap();
}

fn complete_stopped(stopped: super::Stopped, store: &Store) -> Result<(), Error> {
    let finished = store
        .read_record::<crate::record::Finished>(store.root(), &name("finished"))?
        .map(|record| record.record().clone())
        .unwrap_or(stopped.finished(
            crate::record::Class::Infrastructure,
            crate::record::Binding::Missing,
            None,
        )?);
    stopped
        .evidence(store, store.root(), crate::attempt::EVIDENCE_BOUND)?
        .complete(store, &finished)?;
    Ok(())
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn removed_cut_keeps_finished_and_charge_after_cgroup_removal() {
    let _processes = processes();
    let (hosted, mut custody, store) = prepared(9000);
    let running = custody
        .launch(&store, store.root(), hosted.launch())
        .unwrap();
    let stopped = custody.wait_any(vec![running]).unwrap().stopped;
    let finished = stopped
        .finished(
            crate::record::Class::Infrastructure,
            crate::record::Binding::Missing,
            None,
        )
        .unwrap();
    let evidence = stopped
        .evidence(&store, store.root(), crate::attempt::EVIDENCE_BOUND)
        .unwrap();
    step::install(Some(Script {
        nth: Some((Step::Removed, 0, Outcome::Errno(libc::EIO))),
        ..Script::default()
    }));
    let result = evidence.complete(&store, &finished);
    let script = step::install(None).unwrap();
    assert!(result.is_err());
    assert!(script.nth.is_none());
    assert!(!script.reached.contains(&Step::Released));
    let stored = store
        .read_record::<crate::record::Finished>(store.root(), &name("finished"))
        .unwrap()
        .unwrap();
    assert_eq!(stored.record(), &finished);
    assert!(!hosted.root.join("attempt-1").exists());
    assert_eq!(
        fs::read(hosted.case.state.join("reservation")).unwrap(),
        RESERVATION_BYTES
    );
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn inactive_proof_refuses_recorded_foreign_and_existing_groups() {
    let _processes = processes();
    let (host, mut custody, store) = prepared(25020);
    let running = custody.launch(&store, store.root(), host.launch()).unwrap();
    let intent = store
        .read_record::<Intent>(store.root(), &name("intent"))
        .unwrap()
        .unwrap();
    assert!(!custody.inactive(intent.record()).unwrap());
    let foreign = Hosted::new(25021);
    let mut foreign_intent = intent.record().clone();
    foreign_intent.cgroup = Text::new(foreign.root.to_str().unwrap()).unwrap();
    assert!(custody.inactive(&foreign_intent).is_err());
    let stopped = custody.stop(running).unwrap();
    assert!(!custody.inactive(intent.record()).unwrap());
    stopped.remove_group().unwrap();
    assert!(custody.inactive(intent.record()).unwrap());
}
