#![cfg(all(target_os = "linux", target_pointer_width = "64"))]

use campaign_supervisor::record::{Hardware, HardwareDisposition};
use campaign_supervisor::store::{Name, Store};
use serde_json::{Value, json};
use std::cell::RefCell;
use std::fs;
use std::marker::PhantomData;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{MutexGuard, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant};

#[path = "hardware/additional.rs"]
mod additional;

#[path = "hardware/review.rs"]
mod review;

const FAKE: &str = r#"import ctypes, json, os, pathlib, signal, subprocess, sys, time
def flag(name): return sys.argv[sys.argv.index(name) + 1]
root = pathlib.Path(flag('--episode-manifest') if sys.argv[1] == 'fleet' else flag('--artifacts')).parent
assert json.loads((root / 'intent').read_text())['record']['phase'] == 'intent'
assert json.loads((root / 'started').read_text())['record']['phase'] == 'started'
assert not (root / 'finished').exists()
(root / 'cwd').write_text(os.getcwd())
(root / 'platform').write_text(os.environ.get('KESTRIKE_HARDWARE_PLATFORM', ''))
def term(sig, frame):
    with (root / 'signals').open('a') as out: out.write(str(sig) + '\n')
    if os.environ.get('FAKE_MODE') == 'term-exit': sys.exit(3)
signal.signal(signal.SIGTERM, term)
pdeath = ctypes.c_int(-1)
assert ctypes.CDLL(None).prctl(2, ctypes.byref(pdeath), 0, 0, 0) == 0
assert pdeath.value == 0
member = None
if os.environ.get('FAKE_MEMBER'):
    member = subprocess.Popen(['python3', '-c', '''import pathlib, signal, sys, time
root = pathlib.Path(sys.argv[1])
def received(sig, frame):
    with (root / 'member-signals').open('a') as out: out.write(str(sig) + '\\n')
signal.signal(signal.SIGTERM, received)
(root / 'member-ready').write_text('ready')
while not (root / 'release').exists(): time.sleep(.01)
(root / 'member-exit').write_text('ended')
''', str(root)])
    while not (root / 'member-ready').exists(): time.sleep(.01)
(root / 'argv.json').write_text(json.dumps(sys.argv[1:]))
(root / 'roles').write_text(os.environ.get('KESTRIKE_HARDWARE_ROLES', ''))
(root / 'ready').write_text(str(os.getpid()))
mode = os.environ.get('FAKE_MODE', 'exit')
if mode in ('linger', 'term-exit', 'linger-marker'):
    if mode == 'linger-marker':
        custody = pathlib.Path(flag('--custody'))
        custody.mkdir(parents=True, exist_ok=True)
        (custody / 'held.json').write_text('custody remains')
    while not (root / 'release').exists():
        (root / 'alive').write_text(str(time.monotonic()))
        time.sleep(.01)
    if member is not None: member.wait(timeout=5)
    (root / 'exit-marker').write_text('controller released itself')
elif mode in ('marker', 'transient'):
    custody = pathlib.Path(flag('--custody'))
    custody.mkdir(parents=True, exist_ok=True)
    marker = custody / 'held.json'
    marker.write_text('custody remains')
    if mode == 'transient':
        time.sleep(.15)
        marker.unlink()
elif mode == 'change-mode':
    custody = pathlib.Path(flag('--custody'))
    custody.mkdir(parents=True, exist_ok=True)
    custody.chmod(int(os.environ.get('FAKE_CUSTODY_MODE', '777'), 8))
elif mode == 'replace-custody':
    custody = pathlib.Path(flag('--custody'))
    custody.rename(custody.with_name('custody-old'))
    custody.mkdir(mode=0o700)
elif mode == 'remove-custody':
    pathlib.Path(flag('--custody')).rmdir()
elif mode == 'controller-records':
    artifacts = pathlib.Path(flag('--artifacts'))
    artifacts.mkdir()
    os.mkfifo(artifacts / 'close.pipe')
    (artifacts / 'receipt.json').write_bytes(b'{"controller":"authoritative"}\n')
elif mode == 'signal':
    os.kill(os.getpid(), signal.SIGUSR1)
if sys.argv[1] == 'fleet':
    state = pathlib.Path(flag('--state'))
    state.mkdir(exist_ok=True)
    if (state / 'held').exists(): sys.exit(4)
    if os.environ.get('FAKE_FLEET_HELD'): (state / 'held').write_text('controller custody')
    (state / 'verdict.json').write_bytes(b'{"verdict":"inconclusive","credit":false}\n')
    (root / 'admitted-manifest').write_bytes(pathlib.Path(flag('--episode-manifest')).read_bytes())
sys.exit(int(os.environ.get('FAKE_EXIT', '0')))
"#;

/// Held shared by the cases of a test that only starts child processes,
/// and exclusively by the cases of a test that opens a store in this
/// process. A child holds a copy of every descriptor of this process from
/// its fork until its exec, a store's locked directory handle included,
/// so a store that one test dropped could stay locked by another test's
/// child.
static FORKS: RwLock<()> = RwLock::new(());

/// One thread's hold on [`FORKS`].
enum Hold {
    Shared {
        _guard: RwLockReadGuard<'static, ()>,
    },
    Alone {
        _guard: RwLockWriteGuard<'static, ()>,
    },
}

thread_local! {
    /// This thread's live cases and, while any lives, the one hold they
    /// share; a thread never takes a second guard, which a waiting writer
    /// would block.
    static HELD: RefCell<(usize, Option<Hold>)> = const { RefCell::new((0, None)) };
}

/// A test's own directory with its state directory, lane and manifest,
/// removed on drop. A case stays on the thread that made it, whose count
/// of live cases it keeps.
struct Case {
    root: PathBuf,
    state: PathBuf,
    lane: PathBuf,
    manifest: PathBuf,
    _thread: PhantomData<MutexGuard<'static, ()>>,
}
impl Case {
    /// A case for a test that starts child processes and opens no store in
    /// this process.
    fn new(label: &str) -> Self {
        Self::held(label, || Hold::Shared {
            _guard: FORKS.read().unwrap_or_else(PoisonError::into_inner),
        })
    }

    /// A case for a test that opens a store in this process: it waits for
    /// every other thread's case to drop and holds new ones off until it
    /// drops, so no other test's child holds a copy of the store's handle.
    ///
    /// # Panics
    ///
    /// When this thread holds a case, whose hold would block the exclusive
    /// one forever.
    fn alone(label: &str) -> Self {
        let live = HELD.with_borrow(|(live, _)| *live);
        assert_eq!(live, 0, "a test makes its `alone` case first");
        Self::held(label, || Hold::Alone {
            _guard: FORKS.write().unwrap_or_else(PoisonError::into_inner),
        })
    }

    /// A case whose thread takes `hold` when it holds no case yet.
    fn held(label: &str, hold: impl FnOnce() -> Hold) -> Self {
        HELD.with_borrow_mut(|(live, held)| {
            if *live == 0 {
                *held = Some(hold());
            }
            *live += 1;
        });
        let root = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("hardware-{label}-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let state = root.join("state");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let lane = root.join("fake controller.py");
        fs::write(&lane, FAKE).unwrap();
        let manifest = root.join("hardware.json");
        let machine = std::env::consts::ARCH;
        fs::write(&manifest, json!({"platforms": {"local": {"supported": true, "machine": machine}}, "profiles": {"profile": {"platforms": {"local": "runs"}, "roles": {"owner": {}}}}}).to_string()).unwrap();
        Self {
            root,
            state,
            lane,
            manifest,
            _thread: PhantomData,
        }
    }
    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_campaign"));
        command
            .args(["hardware", "run", "--state"])
            .arg(&self.state)
            .args([
                "--profile",
                "profile",
                "--platform",
                "local",
                "--wall",
                "30",
                "--grace",
                "0.2",
                "--manifest",
            ])
            .arg(&self.manifest)
            .arg("--lane")
            .arg(&self.lane)
            .arg("--custody")
            .arg(self.root.join("custody"));
        command.env_remove("KESTRIKE_HARDWARE_ROLES");
        command
    }
    fn run(&self, mode: &str, exit: i32) -> Output {
        self.command()
            .env("FAKE_MODE", mode)
            .env("FAKE_EXIT", exit.to_string())
            .output()
            .unwrap()
    }
    fn dir(&self, number: u64) -> PathBuf {
        self.state
            .join("hardware/runs")
            .join(format!("{number:04}"))
    }
    fn dispose(&self, evidence: &str) -> Output {
        Command::new(env!("CARGO_BIN_EXE_campaign"))
            .args(["hardware", "dispose", "--state"])
            .arg(&self.state)
            .args(["--run", "1", "--evidence", evidence])
            .output()
            .unwrap()
    }
    fn report(&self) -> Value {
        let output = self.report_output();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }
}
impl Drop for Case {
    fn drop(&mut self) {
        if let Ok(entries) = fs::read_dir(self.state.join("hardware/runs")) {
            for entry in entries.flatten() {
                if entry.path().join("alive").exists() || entry.path().join("member-ready").exists()
                {
                    let _ = fs::write(entry.path().join("release"), "go");
                    let began = Instant::now();
                    while !entry.path().join("exit-marker").exists()
                        && !entry.path().join("member-exit").exists()
                        && began.elapsed() < Duration::from_secs(2)
                    {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                }
            }
        }
        let _ = fs::remove_dir_all(&self.root);
        HELD.with_borrow_mut(|(live, held)| {
            *live -= 1;
            if *live == 0 {
                *held = None;
            }
        });
    }
}
fn result(output: &Output, code: i32) -> Value {
    assert_eq!(
        output.status.code(),
        Some(code),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
fn wait(path: &Path) {
    let began = Instant::now();
    while !path.exists() {
        assert!(
            began.elapsed() < Duration::from_secs(10),
            "missing {}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn assert_alive(dir: &Path) {
    let path = dir.join("alive");
    wait(&path);
    let before = fs::read_to_string(&path).unwrap();
    let began = Instant::now();
    loop {
        let after = fs::read_to_string(&path).unwrap();
        if !after.is_empty() && after != before {
            return;
        }
        assert!(
            began.elapsed() < Duration::from_secs(5),
            "controller heartbeat stopped"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn signal(pid: u32) {
    assert!(
        Command::new("/bin/kill")
            .args(["-TERM", &pid.to_string()])
            .status()
            .unwrap()
            .success()
    );
}

#[test]
fn every_test_makes_a_case() {
    let sources = [
        include_str!("hardware.rs"),
        include_str!("hardware/additional.rs"),
        include_str!("hardware/review.rs"),
    ];
    let mut bare = Vec::new();
    for source in sources {
        let mut tests = 0;
        let mut lines = source.lines();
        while let Some(attribute) = lines.next() {
            if attribute.trim_start() != "#[test]" {
                continue;
            }
            tests += 1;
            let end = attribute.replace("#[test]", "}");
            let body: Vec<&str> = lines.by_ref().take_while(|line| *line != end).collect();
            let makes = |line: &&str| line.contains("Case::new(") || line.contains("Case::alone(");
            if !body.iter().any(makes) {
                let name = |line: &&str| line.trim_start().starts_with("fn ");
                bare.push(body.iter().copied().find(name).unwrap_or(attribute));
            }
        }
        assert_ne!(tests, 0, "a source lists no test");
    }
    assert_eq!(
        bare, [""; 0],
        "an `alone` case does not hold off the child processes of a test that makes no case"
    );
}

#[test]
fn one_sigterm_holds_a_live_controller_and_disposition_releases_admission() {
    let case = Case::new("stop");
    let dir = case.dir(1);
    let mut supervisor = Case::options(&case, &[("--grace", Some("1"))])
        .env("FAKE_MODE", "linger")
        .env("FAKE_MEMBER", "1")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    wait(&dir.join("ready"));
    signal(supervisor.id());
    wait(&dir.join("signals"));
    assert!(supervisor.try_wait().unwrap().is_none());
    signal(supervisor.id());
    let output = supervisor.wait_with_output().unwrap();
    assert_eq!(result(&output, 4)["class"], "held");
    wait(&dir.join("signals"));
    assert_eq!(fs::read_to_string(dir.join("signals")).unwrap(), "15\n");
    assert!(!dir.join("member-signals").exists());
    wait(&dir.join("member-ready"));
    assert!(!dir.join("exit-marker").exists());
    assert_alive(&dir);
    assert_eq!(case.run("exit", 0).status.code(), Some(4));
    assert!(!case.dir(2).exists());
    assert_eq!(fs::read_to_string(dir.join("signals")).unwrap(), "15\n");
    assert_eq!(case.dispose(" ").status.code(), Some(2));
    result(&case.dispose("contained: operator log /evidence/host"), 0);
    let first = fs::read(dir.join("disposition")).unwrap();
    assert_eq!(
        result(&case.dispose("later evidence"), 0),
        json!({"run": 1, "disposed": true, "recorded": false})
    );
    assert_eq!(fs::read(dir.join("disposition")).unwrap(), first);
    assert_eq!(result(&case.run("exit", 0), 0)["class"], "completed");
    fs::write(dir.join("release"), "go").unwrap();
    wait(&dir.join("exit-marker"));
    assert!(dir.join("member-exit").exists());
    assert!(!dir.join("member-signals").exists());
    assert_eq!(case.report()["hardware"][0]["disposed"], true);
}

#[test]
fn restart_records_held_and_sends_no_signal() {
    let case = Case::new("restart");
    let dir = case.dir(1);
    let mut supervisor = case
        .command()
        .env("FAKE_MODE", "linger")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    wait(&dir.join("ready"));
    supervisor.kill().unwrap();
    supervisor.wait().unwrap();
    let snapshot = case.report();
    assert_eq!(snapshot["hardware"][0]["class"], "held");
    assert_eq!(snapshot["hardware"][0]["phase"], "started");
    assert!(!dir.join("finished").exists());
    assert_eq!(case.run("exit", 0).status.code(), Some(4));
    assert!(!case.dir(2).exists());
    assert!(!dir.join("signals").exists());
    assert_alive(&dir);
    assert_eq!(case.report()["hardware"][0]["class"], "held");
    fs::write(dir.join("release"), "go").unwrap();
    wait(&dir.join("exit-marker"));
    assert!(!dir.join("signals").exists());
}

#[test]
fn remaining_marker_holds_and_removed_sentinel_completes() {
    let case = Case::new("marker");
    assert_eq!(result(&case.run("marker", 0), 4)["class"], "held");
    assert_eq!(case.run("exit", 0).status.code(), Some(4));
    assert_eq!(
        case.options(&[("--grace", Some("NaN"))])
            .output()
            .unwrap()
            .status
            .code(),
        Some(4)
    );
    assert!(!case.dir(2).exists());
    assert_eq!(case.report()["hardware"][0]["class"], "held");
    let case = Case::new("transient");
    assert_eq!(result(&case.run("transient", 0), 0)["class"], "completed");
    assert_eq!(case.report()["hardware"][0]["class"], "completed");
}

#[test]
fn platform_status_support_and_machine_gate_without_spawn() {
    for (index, supported, machine, status) in [
        (0, false, std::env::consts::ARCH, "runs"),
        (1, true, "foreign", "runs"),
        (2, true, std::env::consts::ARCH, "pending"),
    ] {
        let case = Case::new(&format!("gate-{index}"));
        fs::write(&case.manifest, json!({"platforms": {"local": {"supported": supported, "machine": machine}}, "profiles": {"profile": {"platforms": {"local": status}, "roles": {"owner": {}}}}}).to_string()).unwrap();
        let row = result(&case.run("exit", 0), 0);
        assert_eq!(row["class"], "gated");
        assert!(row["reason"].as_str().unwrap().contains(status));
        assert!(!case.dir(1).join("ready").exists());
        fs::write(&case.manifest, json!({"platforms": {"local": {"supported": true, "machine": std::env::consts::ARCH}}, "profiles": {"profile": {"platforms": {"local": "runs"}, "roles": {"owner": {}}}}}).to_string()).unwrap();
        assert_eq!(result(&case.run("exit", 0), 0)["class"], "completed");
        assert_eq!(case.report()["hardware"][0]["class"], "gated");
    }
}

#[test]
fn controller_exit_and_signal_are_authoritative() {
    for (code, class, supervisor_code) in [
        (0, "completed", 0),
        (1, "uncredited", 0),
        (2, "rejected", 0),
        (4, "held", 4),
        (5, "interrupted", 0),
        (9, "infrastructure", 0),
    ] {
        let case = Case::new(&format!("exit-{code}"));
        let row = result(&case.run("exit", code), supervisor_code);
        assert_eq!(row["class"], class);
        assert_eq!(row["exit"], code);
        if supervisor_code == 0 {
            assert_eq!(result(&case.run("exit", 0), 0)["class"], "completed");
            assert!(case.dir(2).join("ready").exists());
        }
    }
    let case = Case::new("signal");
    let row = result(&case.run("signal", 0), 4);
    assert_eq!(row["signal"], 10);
    assert_eq!(row["class"], "held");
}

#[test]
fn damaged_run_and_disposition_stay_as_found() {
    let case = Case::new("damage");
    result(&case.run("exit", 0), 0);
    let dir = case.dir(1);
    fs::write(dir.join("finished"), b"damaged evidence").unwrap();
    assert_eq!(case.run("exit", 0).status.code(), Some(4));
    result(&case.dispose("contained with receipt"), 0);
    assert_eq!(fs::read(dir.join("finished")).unwrap(), b"damaged evidence");
    result(&case.run("exit", 0), 0);
    assert!(case.dir(2).join("ready").exists());
    fs::write(dir.join("disposition"), b"damaged disposition").unwrap();
    assert_eq!(case.dispose("replacement evidence").status.code(), Some(4));
    assert_eq!(
        fs::read(dir.join("disposition")).unwrap(),
        b"damaged disposition"
    );
    assert_eq!(case.run("exit", 0).status.code(), Some(4));
    assert_eq!(case.report()["hardware"][0]["disposed"], false);
}

#[test]
fn fleet_preserves_verdict_records_and_admitted_manifest() {
    let case = Case::alone("fleet");
    let manifest = case.root.join("fleet.json");
    let bytes = b"{\"workload\":{\"profile\":\"profile\"},\"hosts\":{\"host\":{}},\"deadlines\":{\"grace_seconds\":3}}\n";
    fs::write(&manifest, bytes).unwrap();
    let output = case
        .command()
        .arg("--fleet")
        .arg(&manifest)
        .env("FAKE_EXIT", "1")
        .output()
        .unwrap();
    let row = result(&output, 0);
    assert_eq!(row["kind"], "fleet");
    assert_eq!(row["exit"], 1);
    assert_eq!(row["class"], "uncredited");
    assert_eq!(row["custody_directory"], Value::Null);
    assert_eq!(
        fs::read(case.dir(1).join("admitted-manifest")).unwrap(),
        bytes
    );
    assert_eq!(
        fs::read(case.state.join("hardware/fleet/verdict.json")).unwrap(),
        b"{\"verdict\":\"inconclusive\",\"credit\":false}\n"
    );
    let store = Store::open(&case.state.join("hardware")).unwrap();
    let hardware = store
        .open_dir(store.root(), &Name::new("runs").unwrap())
        .unwrap()
        .unwrap();
    let run = store
        .open_dir(&hardware, &Name::new("0001").unwrap())
        .unwrap()
        .unwrap();
    let record = store
        .read_record::<Hardware>(&run, &Name::new("finished").unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(record.record().exit, Some(1));
}
