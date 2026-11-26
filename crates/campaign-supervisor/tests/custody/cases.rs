#[path = "dispatch.rs"]
mod dispatch;
pub(super) use dispatch::dispatch_cli_runs_and_reports_held_reservations;

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use campaign_supervisor::archive::{Archive, Built, publish};
use campaign_supervisor::custody::{Custody, Error, Launch, Limits, Timing};
use campaign_supervisor::exit::Supervisor;
use campaign_supervisor::record::{
    Artifact, Digest, Intent, Native, ProbeFinished, ProbeOutcome, Provenance, Record, Reservation,
    Started, Text,
};
use campaign_supervisor::store::{Name, Store, View, create_dir, open_host};

fn text(value: &str) -> Text {
    Text::new(value).unwrap()
}
fn name(value: &str) -> Name {
    Name::new(value).unwrap()
}

fn probe_record<R: Record + Clone>(path: &Path, entry: &str) -> R {
    let view = View::open(path).unwrap();
    view.read_record::<R>(view.root(), &name(entry))
        .unwrap()
        .unwrap()
        .record()
        .clone()
}

struct ArchiveFixture {
    path: PathBuf,
    verification: Duration,
}

fn archive_fixture() -> &'static ArchiveFixture {
    static ARCHIVE: OnceLock<ArchiveFixture> = OnceLock::new();
    ARCHIVE.get_or_init(|| {
        let path = if let Some(path) = std::env::var_os("CUSTODY_TEST_ARCHIVE") {
            PathBuf::from(path)
        } else {
            build_archive()
        };
        let began = Instant::now();
        let mut archive = Archive::load(&path).expect("load re-exec archive");
        let _ = archive.verify().expect("verify re-exec archive");
        ArchiveFixture {
            path,
            verification: began.elapsed(),
        }
    })
}

pub(super) fn archive() -> &'static Path {
    &archive_fixture().path
}

fn archive_wait(cpu_quota_us: u64) -> Duration {
    let periods = u32::try_from(100000_u64.div_ceil(cpu_quota_us))
        .unwrap()
        .max(1);
    Duration::from_secs(2)
        .saturating_add(archive_fixture().verification.saturating_mul(4 * periods))
}

fn build_archive() -> PathBuf {
    let path = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("custody-archive-{}", std::process::id()));
    let executable = std::env::current_exe().unwrap();
    let identity = open_host(&executable).unwrap().identity();
    let digest = Digest::of(b"fake");
    let built = Built {
        executable,
        identity,
        lock: b"version = 4\n".to_vec(),
        provenance: Provenance {
            cargo: text("cargo fake"),
            command: text("test --test custody"),
            dirty: false,
            environment: BTreeMap::new(),
            native: Native {
                install_record: text("none"),
                install_record_sha256: digest,
                link_plan_sha256: digest,
                package: text("none"),
            },
            revision: text(&"0".repeat(40)),
            target: text("x86_64-unknown-linux-gnu"),
            toolchain: text("rustc fake"),
            untracked: 0,
        },
    };
    publish(&path, &built)
        .expect("re-exec archive")
        .path()
        .to_owned()
}

struct Case {
    path: PathBuf,
    root: PathBuf,
    delegation: PathBuf,
}

impl Case {
    fn new(action: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let number = NEXT.fetch_add(1, Ordering::Relaxed);
        let id = format!("custody-{}-{number}", std::process::id());
        let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join(&id);
        create_dir(&path).unwrap();
        create_dir(&path.join("state")).unwrap();
        fs::write(path.join("action"), action).unwrap();
        let delegation = PathBuf::from(
            std::env::var_os("CAMPAIGN_CGROUP_ROOT")
                .expect("custody tests require their own delegated user scope"),
        );
        fs::create_dir_all(delegation.join("controller")).unwrap();
        let root = delegation.join(id);
        fs::create_dir(&root).unwrap();
        Self {
            path,
            root,
            delegation,
        }
    }

    fn custody(&self) -> Custody {
        Custody::open(
            &self.root,
            Timing {
                poll: Duration::from_millis(1),
                kill_wait: Duration::from_secs(2),
                watchdog: archive_wait(100000),
            },
        )
        .unwrap()
    }

    fn store(&self) -> Store {
        let store = Store::open(&self.path.join("state")).unwrap();
        store
            .create_record(
                store.root(),
                &name("reservation"),
                &Reservation {
                    attempt: text("attempt-1"),
                },
            )
            .unwrap();
        store
    }

    fn launch(&self) -> Launch {
        Launch {
            attempt: text("attempt-1"),
            name: name("attempt-1"),
            gate: PathBuf::from(env!("CARGO_BIN_EXE_campaign")),
            launcher: PathBuf::from(env!("CARGO_BIN_EXE_campaign")),
            args: ["sim", "capabilities", "--archive"]
                .into_iter()
                .map(Into::into)
                .chain([
                    archive().as_os_str().to_owned(),
                    "--artifacts".into(),
                    self.path.join("artifacts").into_os_string(),
                    "--run-id".into(),
                    "attempt-1".into(),
                ])
                .collect(),
            directory: self.path.clone(),
            environment: BTreeMap::from([
                (
                    "CAMPAIGN_CUSTODY_STALL_SECONDS".into(),
                    archive_wait(100000)
                        .saturating_mul(4)
                        .saturating_add(Duration::from_secs(10))
                        .as_secs()
                        .saturating_add(1)
                        .to_string()
                        .into(),
                ),
                (
                    "CAMPAIGN_CUSTODY_WORKER".into(),
                    self.path.as_os_str().to_owned(),
                ),
                (
                    "CAMPAIGN_CUSTODY_CONTROLLER".into(),
                    std::process::id().to_string().into(),
                ),
            ]),
            limits: Limits {
                cpu_quota_us: 100000,
                memory_bytes: 64 << 20,
                pids: 32,
                file_bytes: 4 << 20,
                cpu_seconds: 300,
                output_bytes: u64::MAX,
                output_inodes: 4094,
            },
        }
    }

    fn intent(&self, store: &Store) -> campaign_supervisor::record::Verified<Intent> {
        store
            .read_record(store.root(), &name("intent"))
            .unwrap()
            .unwrap()
    }

    fn released(&self) {
        assert!(!self.path.join("state/reservation").exists());
        assert!(self.path.join("state/finished").exists());
    }

    fn charged(&self) {
        let view = campaign_supervisor::store::View::open(&self.path.join("state")).unwrap();
        let reservation = view
            .read_record::<Reservation>(view.root(), &name("reservation"))
            .unwrap()
            .unwrap();
        if let Some(intent) = view
            .read_record::<Intent>(view.root(), &name("intent"))
            .unwrap()
        {
            assert_eq!(reservation.record().attempt, intent.record().attempt);
        }
    }
}

impl Drop for Case {
    fn drop(&mut self) {
        if let Err(error) = fs::write(
            self.delegation.join("controller/cgroup.procs"),
            std::process::id().to_string(),
        ) {
            eprintln!("custody fixture remains held: {error}");
            return;
        }
        let _ = fs::write(self.root.join("cgroup.kill"), "1");
        remove_groups(&self.root);
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn remove_groups(root: &Path) {
    if let Ok(entries) = fs::read_dir(root) {
        for entry in entries.flatten() {
            if entry.file_type().unwrap().is_dir() {
                remove_groups(&entry.path());
            }
        }
    }
    let _ = fs::remove_dir(root);
}

fn admission_command(case: &Case) -> Command {
    admission_command_at(case, &case.root)
}

fn admission_command_at(case: &Case, root: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_campaign"));
    command
        .arg("admit")
        .arg("--state")
        .arg(case.path.join("state"))
        .arg("--archive")
        .arg(archive())
        .arg("--cgroup-root")
        .arg(root)
        .args(["--profile", "upload", "--campaign", "c1", "--watchdog"])
        .arg(archive_wait(100000).as_secs_f64().to_string())
        .env(
            "CAMPAIGN_CUSTODY_STALL_SECONDS",
            archive_wait(100000)
                .saturating_mul(4)
                .saturating_add(Duration::from_secs(10))
                .as_secs()
                .saturating_add(1)
                .to_string(),
        )
        .env("CAMPAIGN_CUSTODY_WORKER", &case.path);
    command
}

fn stopped_probe(case: &Case) -> (PathBuf, PathBuf) {
    let mut controller = admission_command(case)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + archive_wait(100000).saturating_mul(4);
    while !case.path.join("seen").exists() {
        assert!(
            Instant::now() < deadline,
            "worker must reach durable started"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    controller.kill().unwrap();
    controller.wait().unwrap();
    let probe = fs::read_dir(case.path.join("state/probes"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.join("reservation").exists())
        .unwrap();
    let group = PathBuf::from(format!(
        "/sys/fs/cgroup{}",
        fs::read_to_string(case.path.join("seen"))
            .unwrap()
            .lines()
            .next()
            .unwrap()
    ));
    assert!(group.is_dir());
    assert_eq!(
        probe_record::<Reservation>(&probe, "reservation")
            .attempt
            .as_str(),
        probe.file_name().unwrap().to_str().unwrap()
    );
    assert!(!probe.join("finished").exists());
    (probe, group)
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(super) fn corrupt_released_probe_does_not_leave_a_healthy_charged_probe_running() {
    let case = Case::new("admission");
    assert_eq!(
        admission_command(&case).output().unwrap().status.code(),
        Some(0)
    );
    let old = fs::read_dir(case.path.join("state/probes"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    fs::write(case.path.join("action"), "admission-stall").unwrap();
    fs::remove_file(case.path.join("seen")).unwrap();
    let (charged, group) = stopped_probe(&case);
    assert!(old.file_name().unwrap() < charged.file_name().unwrap());
    let mut survivor = Command::new("/bin/sleep").arg("120").spawn().unwrap();
    fs::write(group.join("cgroup.procs"), survivor.id().to_string()).unwrap();
    assert!(
        !fs::read_to_string(group.join("cgroup.procs"))
            .unwrap()
            .trim()
            .is_empty()
    );
    fs::write(old.join("finished"), b"corrupt").unwrap();
    fs::write(case.path.join("action"), "admission").unwrap();
    let refused = admission_command(&case).output().unwrap();
    assert_eq!(refused.status.code(), Some(4));
    assert!(refused.stdout.is_empty());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("no JSON"));
    assert_eq!(fs::read(old.join("finished")).unwrap(), b"corrupt");
    assert!(!group.exists());
    assert!(!survivor.wait().unwrap().success());
    assert!(!charged.join("reservation").exists());
    assert_eq!(
        probe_record::<ProbeFinished>(&charged, "finished").outcome,
        ProbeOutcome::Held
    );
    assert_eq!(
        fs::read_dir(case.path.join("state/probes"))
            .unwrap()
            .count(),
        2
    );
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(super) fn live_probe_reservation_damage_prevents_release_and_admission() {
    for missing in [false, true] {
        let case = Case::new("admission-controlled");
        let mut controller = admission_command(&case)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + archive_wait(100000).saturating_mul(4);
        while !case.path.join("seen").exists() {
            assert!(Instant::now() < deadline);
            assert!(controller.try_wait().unwrap().is_none());
            std::thread::sleep(Duration::from_millis(1));
        }
        let probe = fs::read_dir(case.path.join("state/probes"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let started = probe_record::<Started>(&probe, "started");
        if missing {
            fs::remove_file(probe.join("reservation")).unwrap();
        } else {
            fs::write(probe.join("reservation"), b"corrupt").unwrap();
        }
        fs::write(case.path.join("finish"), b"finish").unwrap();
        let refused = controller.wait_with_output().unwrap();
        assert_eq!(refused.status.code(), Some(4));
        assert!(refused.stdout.is_empty());
        assert!(
            fs::read_to_string(Path::new(started.cgroup.as_str()).join("cgroup.procs"))
                .unwrap()
                .trim()
                .is_empty()
        );
        assert_eq!(
            fs::read(probe.join("reservation")).ok(),
            if missing {
                None
            } else {
                Some(b"corrupt".to_vec())
            }
        );
        let finished =
            probe_record::<campaign_supervisor::record::ProbeFinished>(&probe, "finished");
        assert_eq!(finished.attempt, started.attempt);
        assert!(Path::new(started.cgroup.as_str()).exists());
        assert!(!case.path.join("state/jobs").exists());
    }
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(super) fn invalid_archive_refuses_without_probe_or_job_publication() {
    let case = Case::new("admission");
    let empty = case.path.join("empty-archive");
    create_dir(&empty).unwrap();
    let refused = Command::new(env!("CARGO_BIN_EXE_campaign"))
        .args(["admit", "--state"])
        .arg(case.path.join("state"))
        .arg("--archive")
        .arg(&empty)
        .args(["--profile", "upload", "--campaign", "c1", "--cgroup-root"])
        .arg(&case.root)
        .output()
        .unwrap();
    assert_eq!(refused.status.code(), Some(2));
    assert!(refused.stdout.is_empty());
    assert!(!case.path.join("state/probes").exists());
    assert!(!case.path.join("state/jobs").exists());
    assert!(!case.path.join("seen").exists());
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(super) fn released_probes_allow_a_different_delegated_root() {
    let case = Case::new("admission");
    assert_eq!(
        admission_command(&case).output().unwrap().status.code(),
        Some(0)
    );
    let other = case.root.with_file_name(format!(
        "{}-other",
        case.root.file_name().unwrap().to_str().unwrap()
    ));
    fs::create_dir(&other).unwrap();
    let next = admission_command_at(&case, &other).output().unwrap();
    remove_groups(&other);
    assert_eq!(
        next.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&next.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&next.stdout).unwrap()["state"],
        "existing"
    );
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(super) fn reappeared_released_cgroups_stay_held_and_alive() {
    let case = Case::new("admission");
    assert_eq!(
        admission_command(&case).output().unwrap().status.code(),
        Some(0)
    );
    let group = PathBuf::from(format!(
        "/sys/fs/cgroup{}",
        fs::read_to_string(case.path.join("seen"))
            .unwrap()
            .lines()
            .next()
            .unwrap()
    ));
    fs::create_dir(&group).unwrap();
    let mut sentinel = Command::new("/bin/sleep").arg("20").spawn().unwrap();
    fs::write(group.join("cgroup.procs"), sentinel.id().to_string()).unwrap();
    let other = case.root.with_file_name(format!(
        "{}-reappeared",
        case.root.file_name().unwrap().to_str().unwrap()
    ));
    fs::create_dir(&other).unwrap();
    let refused = admission_command_at(&case, &other).output().unwrap();
    remove_groups(&other);
    assert_eq!(refused.status.code(), Some(4));
    assert!(refused.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("released probe has an existing cgroup")
    );
    assert_eq!(
        fs::read_dir(case.path.join("state/probes"))
            .unwrap()
            .count(),
        1
    );
    assert!(sentinel.try_wait().unwrap().is_none());
    fs::write(group.join("cgroup.kill"), "1").unwrap();
    sentinel.wait().unwrap();
    fs::remove_dir(&group).unwrap();
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(super) fn probe_retention_and_foreign_groups_refuse_before_launch() {
    let full = Case::new("admission");
    let store = Store::open(&full.path.join("state")).unwrap();
    store.mkdir(store.root(), &name("probes")).unwrap();
    let probes = full.path.join("state/probes");
    for index in 0..65536 {
        fs::create_dir(probes.join(format!("probe-{index}"))).unwrap();
    }
    drop(store);
    let refused = admission_command(&full).output().unwrap();
    assert_eq!(refused.status.code(), Some(4));
    assert!(refused.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&refused.stderr),
        format!(
            "campaign admit: probes holds {0} entries at bound {0}; collect or shard\n",
            campaign_supervisor::SCAN_BOUND
        )
    );
    assert_eq!(fs::read_dir(&probes).unwrap().count(), 65536);
    assert!(!full.path.join("state/jobs").exists());
    let foreign = Case::new("admission");
    fs::create_dir(foreign.root.join("unknown")).unwrap();
    let refused = admission_command(&foreign).output().unwrap();
    assert_eq!(refused.status.code(), Some(4));
    assert!(refused.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&refused.stderr),
        "campaign admit: custody contains unrecorded probes\n"
    );
    assert!(!foreign.path.join("state/probes").exists());
    assert!(!foreign.path.join("state/jobs").exists());
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(super) fn interrupted_probe_reconciles_before_new_admission() {
    let case = Case::new("admission-stall");
    let (probe, group) = stopped_probe(&case);
    fs::write(case.path.join("action"), "admission").unwrap();
    let next = admission_command(&case).output().unwrap();
    assert_eq!(
        next.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&next.stderr)
    );
    assert_eq!(finished_class(&probe), ProbeOutcome::Held);
    assert!(!probe.join("reservation").exists());
    assert!(!group.exists());
    assert!(case.path.join("state/jobs").is_dir());
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(super) fn probe_lifecycle_marker_damage_keeps_the_tree_held() {
    for fault in 0..8 {
        let case = Case::new("admission");
        let admitted = admission_command(&case).output().unwrap();
        assert_eq!(
            admitted.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&admitted.stderr)
        );
        let probe = fs::read_dir(case.path.join("state/probes"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let attempt = text(probe.file_name().unwrap().to_str().unwrap());
        let store = Store::open(&case.path.join("state")).unwrap();
        let probes = store
            .open_dir(store.root(), &name("probes"))
            .unwrap()
            .unwrap();
        let directory = store
            .open_dir(&probes, &name(attempt.as_str()))
            .unwrap()
            .unwrap();
        match fault {
            0 => store.delete(&directory, &name("finished")).unwrap(),
            1 => {
                store
                    .create_record(
                        &directory,
                        &name("reservation"),
                        &Reservation {
                            attempt: attempt.clone(),
                        },
                    )
                    .unwrap();
                store
                    .replace(&directory, &name("finished"), b"corrupt")
                    .unwrap();
            }
            2 => {
                store
                    .create_once(&directory, &name("reservation"), b"charged")
                    .unwrap();
            }
            3 => {
                store
                    .replace_record(
                        &directory,
                        &name("finished"),
                        &ProbeFinished {
                            attempt: text("other-probe"),
                            outcome: ProbeOutcome::Complete,
                        },
                    )
                    .unwrap();
            }
            4 => {
                store
                    .create_record(
                        &directory,
                        &name("reservation"),
                        &Reservation {
                            attempt: text("other-probe"),
                        },
                    )
                    .unwrap();
            }
            5 => {
                store.delete(&directory, &name("intent")).unwrap();
            }
            6 => {
                let mut intent = store
                    .read_record::<Intent>(&directory, &name("intent"))
                    .unwrap()
                    .unwrap()
                    .record()
                    .clone();
                intent.attempt = text("other-probe");
                store
                    .replace_record(&directory, &name("intent"), &intent)
                    .unwrap();
            }
            7 => {
                store
                    .replace(&directory, &name("intent"), b"corrupt")
                    .unwrap();
            }
            _ => unreachable!(),
        }
        let finished_before = fs::read(probe.join("finished")).ok();
        let charge_before = fs::read(probe.join("reservation")).ok();
        let seen = fs::read(case.path.join("seen")).unwrap();
        drop(store);
        let refused = admission_command(&case).output().unwrap();
        assert_eq!(refused.status.code(), Some(4));
        assert!(refused.stdout.is_empty());
        assert_eq!(fs::read(probe.join("finished")).ok(), finished_before);
        assert_eq!(fs::read(probe.join("reservation")).ok(), charge_before);
        assert_eq!(fs::read(case.path.join("seen")).unwrap(), seen);
        assert_eq!(
            fs::read_dir(case.path.join("state/probes"))
                .unwrap()
                .count(),
            1
        );
    }
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(super) fn admission_watchdog_and_sigterm_stop_reached_workers() {
    for signal in [false, true] {
        let case = Case::new("admission-stall");
        let mut command = admission_command(&case);
        let arguments: Vec<_> = command
            .get_args()
            .map(|arg| arg.to_str().unwrap().to_owned())
            .collect();
        let watchdog = arguments[arguments
            .iter()
            .position(|arg| arg == "--watchdog")
            .unwrap()
            + 1]
        .clone();
        let mut controller = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + archive_wait(100000).saturating_mul(4);
        while !case.path.join("seen").exists() {
            assert!(Instant::now() < deadline, "worker must reach its stall");
            assert!(
                controller.try_wait().unwrap().is_none(),
                "controller must remain live until the worker starts"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let probe = fs::read_dir(case.path.join("state/probes"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let started = probe_record::<Started>(&probe, "started");
        let args = fs::read(format!("/proc/{}/cmdline", started.launcher_pid)).unwrap();
        let args: Vec<_> = args
            .split(|byte| *byte == 0)
            .filter(|arg| !arg.is_empty())
            .map(|arg| std::str::from_utf8(arg).unwrap())
            .collect();
        let forwarded = args[args.iter().position(|arg| *arg == "--watchdog").unwrap() + 1]
            .parse::<f64>()
            .unwrap();
        assert!((forwarded - watchdog.parse::<f64>().unwrap()).abs() < 1e-8);
        if signal {
            assert!(
                Command::new("kill")
                    .args(["-TERM", &controller.id().to_string()])
                    .status()
                    .unwrap()
                    .success()
            );
        }
        let result = controller.wait_with_output().unwrap();
        assert_eq!(result.status.code(), Some(4));
        assert!(result.stdout.is_empty());
        assert_eq!(
            String::from_utf8_lossy(&result.stderr),
            "campaign admit: capabilities probe interrupted or timed out\n"
        );
        assert_eq!(
            probe_record::<ProbeFinished>(&probe, "finished").outcome,
            ProbeOutcome::Held
        );
        assert!(!probe.join("reservation").exists());
        assert!(!Path::new(started.cgroup.as_str()).exists());
        assert!(!case.path.join("state/jobs").exists());
    }
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(super) fn held_probe_records_block_new_admission() {
    let case = Case::new("admission-stall");
    let (probe, group) = stopped_probe(&case);
    fs::write(probe.join("started"), b"corrupt").unwrap();
    fs::write(case.path.join("action"), "admission").unwrap();
    let refused = admission_command(&case).output().unwrap();
    assert_eq!(refused.status.code(), Some(4));
    assert!(refused.stdout.is_empty());
    assert_eq!(
        fs::read_dir(case.path.join("state/probes"))
            .unwrap()
            .count(),
        1
    );
    assert_eq!(fs::read(probe.join("started")).unwrap(), b"corrupt");
    assert_eq!(
        probe_record::<Reservation>(&probe, "reservation")
            .attempt
            .as_str(),
        probe.file_name().unwrap().to_str().unwrap()
    );
    assert!(group.exists());
    assert!(!case.path.join("state/jobs").exists());
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(super) fn failed_probe_releases_custody_and_allows_retry() {
    let case = Case::new("admission-failed");
    let failed = admission_command(&case).output().unwrap();
    assert_eq!(failed.status.code(), Some(4));
    assert!(failed.stdout.is_empty());
    assert!(!case.path.join("state/jobs").exists());
    let probe = fs::read_dir(case.path.join("state/probes"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    assert_eq!(finished_class(&probe), ProbeOutcome::Held);
    assert!(!probe.join("reservation").exists());
    let group = PathBuf::from(format!(
        "/sys/fs/cgroup{}",
        fs::read_to_string(case.path.join("seen"))
            .unwrap()
            .lines()
            .next()
            .unwrap()
    ));
    assert!(!group.exists());
    let collected = Command::new(env!("CARGO_BIN_EXE_campaign"))
        .args(["collect", "--state"])
        .arg(case.path.join("state"))
        .output()
        .unwrap();
    assert_eq!(
        collected.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&collected.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&collected.stdout).unwrap();
    assert_eq!(report["probes"]["swept"], true);
    assert_eq!(
        report["probes"]["removed"],
        serde_json::json!([probe.file_name().unwrap().to_str().unwrap()])
    );
    assert_eq!(report["probes"]["kept"], serde_json::json!([]));
    assert!(!probe.exists());
    fs::write(case.path.join("action"), "admission").unwrap();
    let retry = admission_command(&case).output().unwrap();
    assert_eq!(
        retry.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&retry.stderr)
    );
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(super) fn show_scan_overflow_has_no_partial_stdout() {
    let case = Case::new("normal");
    let store = Store::open(&case.path.join("state")).unwrap();
    drop(crate::sharded::jobs(&store, "00"));
    let jobs = case.path.join("state/jobs/00");
    for index in 0..=65536u64 {
        fs::write(jobs.join(format!("{index:064x}.json")), b"").unwrap();
    }
    let count = fs::read_dir(&jobs).unwrap().count();
    assert_eq!(count, 65537);
    let shown = Command::new(env!("CARGO_BIN_EXE_campaign"))
        .args(["show", "--state"])
        .arg(case.path.join("state"))
        .output()
        .unwrap();
    assert_eq!(shown.status.code(), Some(4));
    assert!(shown.stdout.is_empty());
    assert_eq!(fs::read_dir(&jobs).unwrap().count(), count);
    for entry in fs::read_dir(&jobs).unwrap() {
        assert!(fs::read(entry.unwrap().path()).unwrap().is_empty());
    }
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(super) fn admission_probe_and_frozen_jobs() {
    let case = Case::new("admission");
    let invoke = |extra: &[&str]| admission_command(&case).args(extra).output().unwrap();
    let first = invoke(&[]);
    assert_eq!(
        first.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let row: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(row["state"], "admitted");
    let id = row["id"].as_str().unwrap();
    let admission = probe_record::<campaign_supervisor::record::Admission>(
        &case
            .path
            .join("state")
            .join(crate::sharded::job_file(id).parent().unwrap()),
        &format!("{id}.json"),
    );
    assert_eq!(admission.job().experiment().run, 0);
    assert_eq!(admission.job().experiment().attempts, 3);
    let seed = row["seed"].as_u64().unwrap();
    assert_ne!(seed, 0);
    assert!(case.path.join("seen").exists());
    let probes: Vec<_> = fs::read_dir(case.path.join("state/probes"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(probes.len(), 1);
    let view = campaign_supervisor::store::View::open(&case.path.join("state")).unwrap();
    let dir = view
        .open_dir(view.root(), &name("probes"))
        .unwrap()
        .unwrap();
    let dir = view
        .open_dir(
            &dir,
            &name(probes[0].file_name().unwrap().to_str().unwrap()),
        )
        .unwrap()
        .unwrap();
    let started = view
        .read_record::<Started>(&dir, &name("started"))
        .unwrap()
        .unwrap();
    assert!(
        fs::read_to_string(case.path.join("seen"))
            .unwrap()
            .starts_with(
                started
                    .record()
                    .cgroup
                    .as_str()
                    .strip_prefix("/sys/fs/cgroup")
                    .unwrap()
            )
    );
    assert!(!Path::new(started.record().cgroup.as_str()).exists());
    assert_eq!(finished_class(&probes[0]), ProbeOutcome::Complete);
    assert!(!probes[0].join("reservation").exists());
    let duplicate = invoke(&[]);
    assert_eq!(
        duplicate.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&duplicate.stderr)
    );
    let duplicate: serde_json::Value = serde_json::from_slice(&duplicate.stdout).unwrap();
    assert_eq!(duplicate["id"], id);
    assert_eq!(duplicate["seed"], seed);
    assert_eq!(duplicate["state"], "existing");
    // collect removes one of the two probes the real admissions left,
    // finished and released, with every name it holds, and keeps the other
    // as the report's listing for the build.
    let mut admitted: Vec<_> = fs::read_dir(case.path.join("state/probes"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    admitted.sort();
    assert_eq!(admitted.len(), 2);
    let kept_path = case.path.join("state/probes").join(&admitted[1]);
    let kept_before = super::calibration::tree_bytes(&kept_path);
    let collected = Command::new(env!("CARGO_BIN_EXE_campaign"))
        .arg("collect")
        .arg("--state")
        .arg(case.path.join("state"))
        .output()
        .unwrap();
    assert_eq!(
        collected.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&collected.stderr)
    );
    let collected: serde_json::Value = serde_json::from_slice(&collected.stdout).unwrap();
    assert_eq!(
        collected["probes"]["removed"],
        serde_json::json!([admitted[0]]),
        "{collected}"
    );
    assert_eq!(
        collected["probes"]["kept"],
        serde_json::json!([{"probe": admitted[1], "code": "listing-source", "reason": "probe holds a verified listing source for its build"}]),
        "{collected}"
    );
    assert!(!case.path.join("state/probes").join(&admitted[0]).exists());
    assert_eq!(super::calibration::tree_bytes(&kept_path), kept_before);

    let changed = invoke(&["--set", "turns=20001"]);
    assert_eq!(changed.status.code(), Some(0));
    assert_ne!(
        serde_json::from_slice::<serde_json::Value>(&changed.stdout).unwrap()["id"],
        id
    );
    let job = case
        .path
        .join("state")
        .join(crate::sharded::job_file(format!("{id}.json")));
    let manifest = case
        .path
        .join("state")
        .join(crate::sharded::job_file(format!("{id}.manifest")));
    let frozen_manifest = fs::read(&manifest).unwrap();
    fs::write(&job, b"corrupt").unwrap();
    let held = invoke(&[]);
    assert_eq!(held.status.code(), Some(4));
    assert_eq!(fs::read(&job).unwrap(), b"corrupt");
    assert_eq!(fs::read(&manifest).unwrap(), frozen_manifest);
    let shown = Command::new(env!("CARGO_BIN_EXE_campaign"))
        .arg("show")
        .arg("--state")
        .arg(case.path.join("state"))
        .output()
        .unwrap();
    assert_eq!(shown.status.code(), Some(0));
    let shown: serde_json::Value = serde_json::from_slice(&shown.stdout).unwrap();
    assert!(
        shown["jobs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["id"] == id && r["held"].is_string())
    );
    assert_eq!(fs::read(&job).unwrap(), b"corrupt");
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(super) fn admission_cli_rejections_and_configuration() {
    let case = Case::new("admission");
    let missing = case.path.join("uncreated");
    for extra in [
        vec!["--campaign", "calibration"],
        vec!["--campaign", ""],
        vec!["--campaign", " c1"],
        vec!["--campaign", "c1", "--attempts", "65537"],
        vec!["--campaign", "c1", "--attempts", "0"],
        vec!["--campaign", "c1", "--run", "-1"],
        vec!["--campaign", "c1", "--set", "root=1"],
        vec!["--campaign", "c1", "--set", "turns=01"],
        vec!["--campaign", "c1", "--cgroup-root", "relative"],
        vec!["--campaign", "c1", "--cgroup-root", "/root/../outside"],
        vec!["--campaign", "c1", "--cgroup-root", "/invalid\nroot"],
        vec![
            "--campaign",
            "c1",
            "--cgroup-root",
            "/absent",
            "--watchdog",
            "86401",
        ],
    ] {
        let refused = Command::new(env!("CARGO_BIN_EXE_campaign"))
            .arg("admit")
            .arg("--state")
            .arg(&missing)
            .args(["--archive", "/absent", "--profile", "upload"])
            .args(extra)
            .output()
            .unwrap();
        assert_eq!(refused.status.code(), Some(2));
        assert!(!missing.exists());
    }
    let shared = case.path.join("shared");
    fs::create_dir(&shared).unwrap();
    fs::set_permissions(&shared, std::os::unix::fs::PermissionsExt::from_mode(0o777)).unwrap();
    let unsafe_state = shared.join("state");
    let refused = Command::new(env!("CARGO_BIN_EXE_campaign"))
        .args(["admit", "--state"])
        .arg(&unsafe_state)
        .args([
            "--archive",
            "/absent",
            "--profile",
            "upload",
            "--campaign",
            "c1",
            "--cgroup-root",
            "/absent",
        ])
        .output()
        .unwrap();
    assert_eq!(refused.status.code(), Some(2));
    assert_eq!(
        String::from_utf8_lossy(&refused.stderr),
        format!("campaign admit: the state directory is refused: Ancestor({shared:?})\n")
    );
    assert!(!unsafe_state.exists());
    for command in ["admit", "configure", "show", "dispatch"] {
        let refused = Command::new(env!("CARGO_BIN_EXE_campaign"))
            .args([command, "--state", ""])
            .output()
            .unwrap();
        assert_eq!(refused.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&refused.stderr).contains("nonempty value"));
    }
    let settings = [
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
    ];
    let configure = |raised: Option<&str>| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_campaign"));
        command
            .args(["configure", "--state"])
            .arg(case.path.join("state"));
        for (key, value) in settings {
            command.arg("--set").arg(format!(
                "{key}={}",
                if raised == Some(key) {
                    value + 1
                } else {
                    value
                }
            ));
        }
        command.output().unwrap()
    };
    assert_eq!(configure(Some("slots")).status.code(), Some(2));
    assert!(!case.path.join("state/config.json").exists());
    assert_eq!(configure(None).status.code(), Some(0));
    let before = fs::read(case.path.join("state/config.json")).unwrap();
    // One more share needs more inodes than `artifact_inodes` covers.
    for key in ["slots", "reserve_slots"] {
        assert_eq!(configure(Some(key)).status.code(), Some(2));
        assert_eq!(
            fs::read(case.path.join("state/config.json")).unwrap(),
            before
        );
    }
    for key in ["cores", "memory"] {
        assert_eq!(configure(Some(key)).status.code(), Some(0));
        assert_ne!(
            fs::read(case.path.join("state/config.json")).unwrap(),
            before
        );
    }
    assert_eq!(configure(None).status.code(), Some(0));
    assert_eq!(
        fs::read(case.path.join("state/config.json")).unwrap(),
        before
    );
    for value in [
        ((1u64 << 63) - 2).to_string(),
        u64::MAX.to_string(),
        "9".repeat(5000),
    ] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_campaign"));
        command
            .args(["configure", "--state"])
            .arg(case.path.join("state"));
        for (key, count) in settings {
            command.arg("--set").arg(format!("{key}={count}"));
        }
        command.arg("--set").arg(format!("cpu={value}"));
        assert_eq!(command.output().unwrap().status.code(), Some(2));
        assert_eq!(
            fs::read(case.path.join("state/config.json")).unwrap(),
            before
        );
    }
    let mut limited = Command::new("sh");
    limited
        .args([
            "-c",
            "set -e; ulimit -St 30; ulimit -Ht 30; exec \"$0\" \"$@\"",
        ])
        .arg(env!("CARGO_BIN_EXE_campaign"))
        .args(["configure", "--state"])
        .arg(&missing);
    for (key, count) in settings {
        limited.arg("--set").arg(format!("{key}={count}"));
    }
    let refused = limited.output().unwrap();
    assert_eq!(refused.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("largest installable limit 29"));
    assert!(!missing.exists());
    let edge = case.path.join("limited-edge");
    for cpu in [30, 29] {
        let mut command = Command::new("sh");
        command
            .args([
                "-c",
                "set -e; ulimit -St 30; ulimit -Ht 30; exec \"$0\" \"$@\"",
            ])
            .arg(env!("CARGO_BIN_EXE_campaign"))
            .args(["configure", "--state"])
            .arg(&edge);
        for (key, count) in settings {
            command.arg("--set").arg(format!("{key}={count}"));
        }
        command.arg("--set").arg(format!("cpu={cpu}"));
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(if cpu == 30 { 2 } else { 0 }));
        if cpu == 30 {
            assert!(!edge.exists());
        } else {
            let view = campaign_supervisor::store::View::open(&edge).unwrap();
            let record = view
                .read_record::<campaign_supervisor::record::Configuration>(
                    view.root(),
                    &name("config.json"),
                )
                .unwrap()
                .unwrap();
            assert_eq!(record.record().value("cpu"), 29);
        }
    }
    let file_edge = case.path.join("file-edge");
    let file_bound = 32768;
    for output in [file_bound + 1, file_bound] {
        let mut command = Command::new("sh");
        command
            .args([
                "-c",
                "set -e; ulimit -Sf 64; ulimit -Hf 64; exec \"$0\" \"$@\"",
            ])
            .arg(env!("CARGO_BIN_EXE_campaign"))
            .args(["configure", "--state"])
            .arg(&file_edge);
        for (key, count) in settings {
            let count = match key {
                "attempt_output" => output,
                "artifact_bytes" => 50_000_000,
                _ => count,
            };
            command.arg("--set").arg(format!("{key}={count}"));
        }
        let configured = command.output().unwrap();
        assert_eq!(
            configured.status.code(),
            Some(if output > file_bound { 2 } else { 0 })
        );
        if output > file_bound {
            assert!(
                String::from_utf8_lossy(&configured.stderr)
                    .contains("output exceeds largest installable limit 32768"),
                "{}",
                String::from_utf8_lossy(&configured.stderr)
            );
            assert!(!file_edge.exists());
        } else {
            let view = campaign_supervisor::store::View::open(&file_edge).unwrap();
            let record = view
                .read_record::<campaign_supervisor::record::Configuration>(
                    view.root(),
                    &name("config.json"),
                )
                .unwrap()
                .unwrap();
            assert_eq!(record.record().file_bytes(), file_bound);
        }
    }
    let shown = Command::new("sh")
        .args([
            "-c",
            "set -e; ulimit -St 30; ulimit -Ht 30; exec \"$0\" \"$@\"",
        ])
        .arg(env!("CARGO_BIN_EXE_campaign"))
        .args(["show", "--state"])
        .arg(case.path.join("state"))
        .output()
        .unwrap();
    assert_eq!(shown.status.code(), Some(0));
    assert!(
        serde_json::from_slice::<serde_json::Value>(&shown.stdout).unwrap()["config"]["verified"]
            .is_object()
    );
    assert_eq!(
        fs::read(case.path.join("state/config.json")).unwrap(),
        before
    );
    for extra in [
        vec!["--archive", "/absent"],
        vec![
            "--archive",
            "/absent",
            "--cgroup-root",
            "/absent",
            "--watchdog",
            "0",
        ],
    ] {
        let refused = Command::new(env!("CARGO_BIN_EXE_campaign"))
            .args(["admit", "--state"])
            .arg(&missing)
            .args(["--profile", "upload", "--campaign", "c1"])
            .args(extra)
            .env_remove("CAMPAIGN_CGROUP_ROOT")
            .output()
            .unwrap();
        assert_eq!(refused.status.code(), Some(2));
        assert!(!missing.exists());
    }
    let mut invalid = Command::new(env!("CARGO_BIN_EXE_campaign"));
    invalid.args(["configure", "--state"]).arg(&missing);
    for (key, count) in settings {
        invalid.arg("--set").arg(format!("{key}={count}"));
    }
    let invalid = invalid.args(["--set", "unknown=1"]).output().unwrap();
    assert_eq!(invalid.status.code(), Some(2));
    assert!(!missing.exists());
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(super) fn durable_records_precede_worker_effects_and_the_mask_is_empty() {
    let case = Case::new("normal");
    let mut custody = case.custody();
    let store = case.store();
    let running = custody.launch(&store, store.root(), case.launch()).unwrap();
    assert_eq!(running.started().record().attempt.as_str(), "attempt-1");
    let intent = case.intent(&store);
    assert_eq!(running.started().record().cgroup, intent.record().cgroup);
    let stopped = custody
        .wait_any(vec![running])
        .map(|waited| waited.stopped)
        .unwrap();
    assert_eq!(
        stopped.status().unwrap().code(),
        Some(0),
        "watchdog={}, counters={:?}",
        stopped.watchdog(),
        stopped.after()
    );
    assert!(!stopped.watchdog());
    assert!(
        case.path.join("seen").exists(),
        "worker observed durable started and membership"
    );
    assert!(
        fs::read_to_string(case.path.join("seen"))
            .unwrap()
            .ends_with("0000000000000000\n")
    );
    assert!(
        case.root.join("attempt-1").exists(),
        "drain retains custody until removal"
    );
    let artifact_store =
        campaign_supervisor::store::View::open(&case.path.join("artifacts/attempt-1")).unwrap();
    let artifact = artifact_store
        .read_record::<Artifact>(artifact_store.root(), &name("artifact"))
        .unwrap()
        .unwrap();
    assert_eq!(artifact.record().class.as_str(), "counts");
    case.charged();
    stopped.retire(&[&store]).unwrap();
    assert!(!case.root.join("attempt-1").exists());
    case.released();
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(super) fn kill_drain_remove_contains_session_escapees() {
    let case = Case::new("escapee");
    let mut custody = case.custody();
    let store = case.store();
    let running = custody.launch(&store, store.root(), case.launch()).unwrap();
    let stopped = custody
        .wait_any(vec![running])
        .map(|waited| waited.stopped)
        .unwrap();
    assert_eq!(stopped.status().unwrap().code(), Some(0));
    assert!(
        case.path.join("escapee-ready").exists(),
        "session escapee reached its write"
    );
    let pid = fs::read_to_string(case.path.join("escapee-ready")).unwrap();
    let process = fs::read_to_string(format!("/proc/{}/status", pid.trim()));
    assert!(
        process.is_err() || process.unwrap().contains("State:\tZ"),
        "escapee stopped"
    );
    assert!(
        fs::read_to_string(case.root.join("attempt-1/cgroup.events"))
            .unwrap()
            .contains("populated 0")
    );
    assert!(!case.path.join("late").exists());
    stopped.retire(&[&store]).unwrap();
    assert!(!case.root.join("attempt-1").exists());
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(super) fn nested_empty_children_hold_removal_and_redrain_on_restart() {
    let case = Case::new("normal");
    let mut custody = case.custody();
    let store = case.store();
    let running = custody.launch(&store, store.root(), case.launch()).unwrap();
    let stopped = custody
        .wait_any(vec![running])
        .map(|waited| waited.stopped)
        .unwrap();
    let path = case.root.join("attempt-1");
    fs::create_dir(path.join("nested")).unwrap();
    assert!(
        fs::read_to_string(path.join("cgroup.events"))
            .unwrap()
            .contains("populated 0")
    );
    let error = stopped.retire(&[&store]).unwrap_err();
    assert!(
        matches!(error, Error::Io(ref error) if matches!(error.raw_os_error(), Some(libc::EBUSY | libc::ENOTEMPTY)))
    );
    assert_eq!(error.exit(), Supervisor::Held);
    assert!(path.exists(), "held removal branch reached");
    case.charged();
    let intent = case.intent(&store);
    let started = store
        .read_record::<Started>(store.root(), &name("started"))
        .unwrap()
        .unwrap();
    let stopped = custody.reconcile(&store, &intent, Some(&started)).unwrap();
    assert_eq!(
        stopped.retire(&[&store]).unwrap_err().exit(),
        Supervisor::Held
    );
    case.charged();
    fs::remove_dir(path.join("nested")).unwrap();
    custody
        .reconcile(&store, &intent, Some(&started))
        .unwrap()
        .retire(&[&store])
        .unwrap();
    assert!(!path.exists());
    assert!(matches!(
        custody
            .reconcile(&store, &intent, Some(&started))
            .unwrap()
            .retire(&[&store]),
        Err(Error::Held("stopped attempt lacks reservation"))
    ));
    case.released();
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(super) fn restart_stops_membership_and_preserves_a_live_sentinel() {
    let case = Case::new("stall");
    let mut custody = case.custody();
    let store = case.store();
    let running = custody.launch(&store, store.root(), case.launch()).unwrap();
    let mut sentinel = Command::new("/bin/sleep").arg("20").spawn().unwrap();
    let recorded = running.started().record();
    let planted = Started {
        launcher_pid: u64::from(sentinel.id()),
        ..recorded.clone()
    };
    store
        .replace_record(store.root(), &name("started"), &planted)
        .unwrap();
    let sentinel_record = store
        .read_record::<Started>(store.root(), &name("started"))
        .unwrap()
        .unwrap();
    assert_eq!(
        sentinel_record.record().launcher_pid,
        u64::from(sentinel.id())
    );
    drop(custody);
    let mut restarted = case.custody();
    let intent = case.intent(&store);
    let stopped = restarted
        .reconcile(&store, &intent, Some(&sentinel_record))
        .unwrap();
    assert!(
        stopped.status().is_none(),
        "restart uses membership without adoption"
    );
    assert!(
        sentinel.try_wait().unwrap().is_none(),
        "numeric pid sentinel stays alive"
    );
    assert!(
        fs::read_to_string(case.root.join("attempt-1/cgroup.events"))
            .unwrap()
            .contains("populated 0")
    );
    restarted
        .wait_any(vec![running])
        .map(|waited| waited.stopped)
        .unwrap();
    case.charged();
    stopped.retire(&[&store]).unwrap();
    sentinel.kill().unwrap();
    sentinel.wait().unwrap();
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(super) fn unknown_and_foreign_root_cgroups_stay_held() {
    let case = Case::new("normal");
    let mut custody = case.custody();
    let store = case.store();
    let unknown = case.root.join("unknown");
    fs::create_dir(&unknown).unwrap();
    assert_eq!(custody.unrecorded(&[], 200).unwrap(), vec![unknown.clone()]);
    assert!(unknown.exists());
    let current = custody.launch(&store, store.root(), case.launch()).unwrap();
    let current_intent = case.intent(&store);
    assert_eq!(
        custody.unrecorded(&[&current_intent], 200).unwrap(),
        vec![unknown.clone()]
    );
    let foreign = case
        .delegation
        .join(format!("foreign-{}", std::process::id()));
    fs::create_dir(&foreign).unwrap();
    let mut member = Command::new("/bin/sleep").arg("20").spawn().unwrap();
    fs::write(foreign.join("cgroup.procs"), member.id().to_string()).unwrap();
    let intent = Intent {
        attempt: text("foreign"),
        boot: text(
            fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .unwrap()
                .trim(),
        ),
        cgroup: text(foreign.to_str().unwrap()),
    };
    store
        .create_record(store.root(), &name("foreign-intent"), &intent)
        .unwrap();
    let intent = store
        .read_record::<Intent>(store.root(), &name("foreign-intent"))
        .unwrap()
        .unwrap();
    let error = match custody.reconcile(&store, &intent, None) {
        Err(error) => error,
        Ok(_) => panic!("foreign root must hold"),
    };
    assert!(
        matches!(error, Error::Io(ref error) if error.kind() == std::io::ErrorKind::InvalidInput && error.to_string() == "recorded cgroup is outside delegated root")
    );
    assert_eq!(error.exit(), Supervisor::Held);
    assert!(member.try_wait().unwrap().is_none());
    assert!(
        fs::read_to_string(foreign.join("cgroup.events"))
            .unwrap()
            .contains("populated 1")
    );
    case.charged();
    fs::write(foreign.join("cgroup.kill"), "1").unwrap();
    member.wait().unwrap();
    fs::remove_dir(&foreign).unwrap();
    fs::remove_dir(&unknown).unwrap();
    custody
        .wait_any(vec![current])
        .unwrap()
        .stopped
        .retire(&[&store])
        .unwrap();
    let one = case.root.join("scan-one");
    let two = case.root.join("scan-two");
    fs::create_dir(&one).unwrap();
    fs::create_dir(&two).unwrap();
    let mut names = custody.unrecorded(&[], 2).unwrap();
    names.sort();
    assert_eq!(names, vec![one.clone(), two.clone()]);
    assert!(
        matches!(custody.unrecorded(&[], 1), Err(Error::Io(ref error)) if error.kind() == std::io::ErrorKind::InvalidInput && error.to_string() == "cgroup scan exceeds bound")
    );
    fs::remove_dir(one).unwrap();
    fs::remove_dir(two).unwrap();
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(super) fn pid_memory_and_cpu_limits_preserve_kernel_events() {
    for action in ["burst", "oom", "cpu"] {
        let case = Case::new(action);
        let mut custody = if action == "cpu" {
            Custody::open(
                &case.root,
                Timing {
                    poll: Duration::from_millis(1),
                    kill_wait: Duration::from_secs(2),
                    watchdog: archive_wait(20000),
                },
            )
            .unwrap()
        } else {
            case.custody()
        };
        let store = case.store();
        let mut launch = case.launch();
        if action == "burst" {
            launch.limits.pids = 8;
        }
        if action == "oom" {
            launch.limits.memory_bytes = 128 << 20;
        }
        if action == "cpu" {
            launch.limits.cpu_quota_us = 20000;
        }
        let running = custody.launch(&store, store.root(), launch).unwrap();
        let stopped = custody
            .wait_any(vec![running])
            .map(|waited| waited.stopped)
            .unwrap();
        assert!(
            case.path.join("seen").exists(),
            "worker limit branch reached: {action}"
        );
        assert!(!stopped.watchdog(), "limit evidence comes from the worker");
        let before = stopped.before().unwrap();
        let after = stopped.after().unwrap();
        match action {
            "burst" => {
                assert!(
                    case.path.join("fork-refused").exists(),
                    "worker stderr: {}",
                    fs::read_to_string(case.path.join("artifacts/attempt-1/capabilities.stderr"))
                        .unwrap()
                );
                assert!(after.pids["max"] > before.pids["max"]);
            }
            "oom" => {
                assert!(after.memory["oom_kill"] > before.memory["oom_kill"]);
                assert!(!stopped.status().unwrap().success());
            }
            "cpu" => {
                assert!(after.cpu["nr_throttled"] > before.cpu["nr_throttled"]);
                assert!(after.cpu["throttled_usec"] > before.cpu["throttled_usec"]);
            }
            _ => unreachable!(),
        }
        case.charged();
        stopped.retire(&[&store]).unwrap();
        assert!(!case.root.join("attempt-1").exists());
    }
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(super) fn file_size_limit_stops_a_worker_and_preserves_partial_bytes() {
    let case = Case::new("fsize");
    let mut custody = case.custody();
    let store = case.store();
    let mut launch = case.launch();
    launch.launcher = std::env::current_exe().unwrap();
    launch.args.clear();
    launch.limits.file_bytes = 4096;
    let running = custody.launch(&store, store.root(), launch).unwrap();
    let stopped = custody.wait_any(vec![running]).unwrap().stopped;
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(stopped.status().unwrap().signal(), Some(libc::SIGXFSZ));
    assert!(!stopped.watchdog());
    assert!(case.path.join("seen").exists());
    assert_eq!(
        fs::metadata(case.path.join("oversize")).unwrap().len(),
        4096
    );
    assert!(
        fs::read_to_string(case.root.join("attempt-1/cgroup.events"))
            .unwrap()
            .contains("populated 0")
    );
    case.charged();
    stopped.retire(&[&store]).unwrap();
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(super) fn ignored_sigint_still_reaches_the_signal_descriptor() {
    let output = Command::new("/bin/sh")
        .args(["-c", "trap '' INT; exec \"$@\"", "custody-ignored-int"])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "--ignored",
            "signal_descriptor_interruptions_stop_the_attempt",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success()
            && String::from_utf8_lossy(&output.stdout).contains("test result: ok. 1 passed;"),
        "{output:?}"
    );
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(super) fn signal_descriptor_interruptions_stop_the_attempt() {
    for (action, signal) in [
        ("interrupt", libc::SIGTERM),
        ("interrupt-int", libc::SIGINT),
    ] {
        let case = Case::new(action);
        let mut custody = Custody::open(
            &case.root,
            Timing {
                poll: archive_wait(100000)
                    .saturating_mul(4)
                    .max(Duration::from_secs(30)),
                kill_wait: Duration::from_secs(2),
                watchdog: archive_wait(100000).saturating_mul(2),
            },
        )
        .unwrap();
        let store = case.store();
        let running = custody.launch(&store, store.root(), case.launch()).unwrap();
        let began = Instant::now();
        let stopped = custody.wait_any(vec![running]).unwrap().stopped;
        assert!(
            began.elapsed() < archive_wait(100000),
            "signal descriptor wake"
        );
        assert_eq!(stopped.interruption(), Some(signal));
        assert!(case.path.join("seen").exists());
        stopped.retire(&[&store]).unwrap();
        case.released();
    }
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(super) fn gate_failures_own_125_and_non_gate_commands_exclude_it() {
    for args in [vec!["gate"], vec!["gate", "--", "/missing-custody-exec"]] {
        let mut gate = Command::new(env!("CARGO_BIN_EXE_campaign"))
            .args(args)
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        let _ = gate.stdin.take().unwrap().write_all(b"G");
        assert_eq!(gate.wait().unwrap().code(), Some(125));
    }
    let mut gate = Command::new(env!("CARGO_BIN_EXE_campaign"))
        .args(["gate", "--", "/bin/true"])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    gate.stdin.take().unwrap().write_all(b"X").unwrap();
    assert_eq!(gate.wait().unwrap().code(), Some(125));
    let gate = Command::new(env!("CARGO_BIN_EXE_campaign"))
        .args(["gate", "--", "/bin/true"])
        .stdin(Stdio::null())
        .status()
        .unwrap();
    assert_eq!(gate.code(), Some(125));
    for args in [
        vec!["unknown"],
        vec!["sim"],
        vec!["sim", "run"],
        vec!["sim", "capabilities"],
    ] {
        assert_eq!(
            Command::new(env!("CARGO_BIN_EXE_campaign"))
                .args(args)
                .status()
                .unwrap()
                .code(),
            Some(2)
        );
    }
    let case = Case::new("normal");
    let mut custody = case.custody();
    let store = case.store();
    let mut launch = case.launch();
    launch.launcher = "/missing-custody-launcher".into();
    let running = custody.launch(&store, store.root(), launch).unwrap();
    let stopped = custody
        .wait_any(vec![running])
        .map(|waited| waited.stopped)
        .unwrap();
    assert_eq!(stopped.status().unwrap().code(), Some(125));
    assert!(!case.path.join("seen").exists());
    stopped.retire(&[&store]).unwrap();
    assert!(matches!(
        Custody::open(
            Path::new("/"),
            Timing {
                poll: Duration::from_millis(1),
                kill_wait: Duration::from_millis(1),
                watchdog: Duration::from_millis(1)
            }
        ),
        Err(Error::Io(_))
    ));
}

pub(super) fn controller(path: &Path, root: &Path) -> std::process::ExitCode {
    let case = std::mem::ManuallyDrop::new(Case {
        path: path.to_owned(),
        root: root.to_owned(),
        delegation: std::env::var_os("CAMPAIGN_CGROUP_ROOT").unwrap().into(),
    });
    let mut custody = case.custody();
    let store = case.store();
    let running = custody.launch(&store, store.root(), case.launch()).unwrap();
    custody
        .wait_any(vec![running])
        .map(|waited| waited.stopped)
        .unwrap();
    std::process::ExitCode::SUCCESS
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(super) fn returning_controller_preserves_the_parent_test_membership() {
    let case = Case::new("normal");
    let initial = case.custody();
    let status = Command::new(std::env::current_exe().unwrap())
        .env("CAMPAIGN_CUSTODY_TEST_CONTROLLER", &case.path)
        .env("CAMPAIGN_CUSTODY_TEST_ROOT", &case.root)
        .env("CUSTODY_TEST_ARCHIVE", archive())
        .status()
        .unwrap();
    assert!(status.success());
    assert!(case.path.join("seen").exists());
    assert!(
        fs::read_to_string(case.root.join("controller/cgroup.procs"))
            .unwrap()
            .split_whitespace()
            .any(|pid| pid == std::process::id().to_string())
    );
    drop(initial);
    let store = Store::open(&case.path.join("state")).unwrap();
    let mut custody = case.custody();
    let intent = case.intent(&store);
    let started = store
        .read_record::<Started>(store.root(), &name("started"))
        .unwrap()
        .unwrap();
    custody
        .reconcile(&store, &intent, Some(&started))
        .unwrap()
        .retire(&[&store])
        .unwrap();
    case.released();
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(super) fn controller_sigkill_preserves_records_for_membership_reconciliation() {
    let case = Case::new("escapee-stall");
    let _custody = case.custody();
    let mut controller = Command::new(std::env::current_exe().unwrap())
        .env("CAMPAIGN_CUSTODY_TEST_CONTROLLER", &case.path)
        .env("CAMPAIGN_CUSTODY_TEST_ROOT", &case.root)
        .env("CUSTODY_TEST_ARCHIVE", archive())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + archive_wait(100000).saturating_mul(2);
    while !case.path.join("seen").exists() || !case.path.join("escapee-ready").exists() {
        assert!(
            controller.try_wait().unwrap().is_none(),
            "controller stays live until crash witness"
        );
        assert!(Instant::now() < deadline, "started worker witness bound");
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(case.path.join("state/intent").exists());
    assert!(case.path.join("state/started").exists());
    controller.kill().unwrap();
    assert!(!controller.wait().unwrap().success());
    assert!(
        fs::read_to_string(case.root.join("attempt-1/cgroup.events"))
            .unwrap()
            .contains("populated 1"),
        "session survivor exists before restart stop"
    );
    let store = Store::open(&case.path.join("state")).unwrap();
    case.charged();
    drop(_custody);
    let mut custody = case.custody();
    let intent = case.intent(&store);
    let started = store
        .read_record::<Started>(store.root(), &name("started"))
        .unwrap()
        .unwrap();
    let stopped = custody.reconcile(&store, &intent, Some(&started)).unwrap();
    assert!(stopped.status().is_none());
    assert!(
        fs::read_to_string(case.root.join("attempt-1/cgroup.events"))
            .unwrap()
            .contains("populated 0")
    );
    case.charged();
    assert!(!case.path.join("late").exists());
    stopped.retire(&[&store]).unwrap();
    assert!(!case.root.join("attempt-1").exists());
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(super) fn all_pidfds_stop_a_later_attempt_that_exits_first() {
    let first = Case::new("stall");
    let second = Case::new("escapee");
    let mut custody = Custody::open(
        &first.root,
        Timing {
            poll: archive_wait(100000)
                .saturating_mul(4)
                .max(Duration::from_secs(30)),
            kill_wait: Duration::from_secs(2),
            watchdog: archive_wait(100000).saturating_mul(2),
        },
    )
    .unwrap();
    let first_store = first.store();
    let second_store = second.store();
    second_store
        .replace_record(
            second_store.root(),
            &name("reservation"),
            &Reservation {
                attempt: text("attempt-2"),
            },
        )
        .unwrap();
    let first_running = custody
        .launch(&first_store, first_store.root(), first.launch())
        .unwrap();
    let mut second_launch = second.launch();
    second_launch.attempt = text("attempt-2");
    second_launch.name = name("attempt-2");
    *second_launch.args.last_mut().unwrap() = "attempt-2".into();
    let second_running = custody
        .launch(&second_store, second_store.root(), second_launch)
        .unwrap();
    let began = Instant::now();
    let waited = custody
        .wait_any(vec![first_running, second_running])
        .unwrap();
    assert!(
        began.elapsed() < archive_wait(100000),
        "pidfd wakes before the poll timeout"
    );
    assert_eq!(waited.stopped.status().unwrap().code(), Some(0));
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
    assert!(second.path.join("escapee-ready").exists());
    assert!(!second.path.join("late").exists());
    assert_eq!(waited.to_drain.len(), 1);
    assert_eq!(
        waited.to_drain[0].started().record().attempt.as_str(),
        "attempt-1"
    );
    assert!(waited.to_drain[0].interruption().is_none());
    assert!(second.path.join("seen").exists());
    assert!(
        fs::read_to_string(first.root.join("attempt-1/cgroup.events"))
            .unwrap()
            .contains("populated 1")
    );
    assert!(
        fs::read_to_string(first.root.join("attempt-2/cgroup.events"))
            .unwrap()
            .contains("populated 0")
    );
    waited
        .stopped
        .retire(&[&first_store, &second_store])
        .unwrap();
    assert!(!first.root.join("attempt-2").exists());
    fs::write(first.root.join("attempt-1/cgroup.kill"), "1").unwrap();
    custody
        .wait_any(waited.to_drain)
        .unwrap()
        .stopped
        .retire(&[&first_store, &second_store])
        .unwrap();
    first.released();
    second.released();
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(super) fn interruption_marks_every_remaining_attempt_for_drain() {
    let first = Case::new("stall");
    let second = Case::new("interrupt");
    let mut custody = Custody::open(
        &first.root,
        Timing {
            poll: archive_wait(100000)
                .saturating_mul(4)
                .max(Duration::from_secs(30)),
            kill_wait: Duration::from_secs(2),
            watchdog: archive_wait(100000).saturating_mul(2),
        },
    )
    .unwrap();
    let first_store = first.store();
    let second_store = second.store();
    second_store
        .replace_record(
            second_store.root(),
            &name("reservation"),
            &Reservation {
                attempt: text("attempt-2"),
            },
        )
        .unwrap();
    let first_running = custody
        .launch(&first_store, first_store.root(), first.launch())
        .unwrap();
    let mut second_launch = second.launch();
    second_launch.attempt = text("attempt-2");
    second_launch.name = name("attempt-2");
    *second_launch.args.last_mut().unwrap() = "attempt-2".into();
    let second_running = custody
        .launch(&second_store, second_store.root(), second_launch)
        .unwrap();
    let began = Instant::now();
    let waited = custody
        .wait_any(vec![first_running, second_running])
        .unwrap();
    assert!(
        began.elapsed() < archive_wait(100000),
        "signal descriptor wakes before the poll timeout"
    );
    assert_eq!(waited.stopped.interruption(), Some(libc::SIGTERM));
    assert_eq!(waited.to_drain.len(), 1);
    assert_eq!(waited.to_drain[0].interruption(), Some(libc::SIGTERM));
    for component in ["attempt-1", "attempt-2"] {
        let deadline = Instant::now() + archive_wait(100000);
        while !fs::read_to_string(first.root.join(component).join("cgroup.events"))
            .unwrap()
            .contains("populated 0")
        {
            assert!(
                Instant::now() < deadline,
                "one interrupted pass kills every sibling"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    waited
        .stopped
        .retire(&[&first_store, &second_store])
        .unwrap();
    let drained = custody.wait_any(waited.to_drain).unwrap();
    assert_eq!(drained.stopped.interruption(), Some(libc::SIGTERM));
    assert!(drained.to_drain.is_empty());
    drained
        .stopped
        .retire(&[&first_store, &second_store])
        .unwrap();
    assert!(!first.root.join("attempt-1").exists());
    assert!(!first.root.join("attempt-2").exists());
    let fresh = Case::new("normal");
    let fresh_store = fresh.store();
    let mut fresh_launch = fresh.launch();
    fresh_launch.name = name("attempt-3");
    assert!(matches!(
        custody.launch(&fresh_store, fresh_store.root(), fresh_launch),
        Err(Error::Held("controller interruption requires drain"))
    ));
    assert!(!fresh.path.join("state/intent").exists());
    assert!(!first.root.join("attempt-3").exists());
    first.released();
    second.released();
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(super) fn existing_groups_stay_held_after_intent_without_started() {
    let case = Case::new("normal");
    let mut custody = case.custody();
    let store = case.store();
    let path = case.root.join("attempt-1");
    fs::create_dir(&path).unwrap();
    let mut member = Command::new("/bin/sleep").arg("20").spawn().unwrap();
    fs::write(path.join("cgroup.procs"), member.id().to_string()).unwrap();
    let error = match custody.launch(&store, store.root(), case.launch()) {
        Err(error) => error,
        Ok(_) => panic!("exclusive creation must hold existing group"),
    };
    assert!(
        matches!(error, Error::Io(ref error) if error.kind() == std::io::ErrorKind::AlreadyExists)
    );
    let intent = case.intent(&store);
    assert!(
        store
            .read_record::<Started>(store.root(), &name("started"))
            .unwrap()
            .is_none()
    );
    for _ in 0..2 {
        let error = match custody.reconcile(&store, &intent, None) {
            Err(error) => error,
            Ok(_) => panic!("existing group requires started"),
        };
        assert!(matches!(
            error,
            Error::Held("cgroup lacks matching started")
        ));
        assert!(member.try_wait().unwrap().is_none());
        assert!(
            fs::read_to_string(path.join("cgroup.events"))
                .unwrap()
                .contains("populated 1")
        );
        case.charged();
    }
    for (index, field) in ["attempt", "boot", "cgroup"].into_iter().enumerate() {
        let mut mismatched = Started {
            baseline: Default::default(),
            attempt: intent.record().attempt.clone(),
            boot: intent.record().boot.clone(),
            cgroup: intent.record().cgroup.clone(),
            cgroup_inode: {
                use std::os::unix::fs::MetadataExt;
                fs::metadata(&path).unwrap().ino()
            },
            launcher_pid: u64::from(member.id()),
        };
        match field {
            "attempt" => mismatched.attempt = text("other-attempt"),
            "boot" => mismatched.boot = text("other-boot"),
            "cgroup" => mismatched.cgroup = text(case.root.join("other-cgroup").to_str().unwrap()),
            _ => unreachable!(),
        }
        let entry = name(&format!("mismatched-{index}"));
        store
            .create_record(store.root(), &entry, &mismatched)
            .unwrap();
        let mismatched = store
            .read_record::<Started>(store.root(), &entry)
            .unwrap()
            .unwrap();
        assert!(matches!(
            custody.reconcile(&store, &intent, Some(&mismatched)),
            Err(Error::Held("cgroup lacks matching started"))
        ));
        assert!(member.try_wait().unwrap().is_none());
        assert!(
            fs::read_to_string(path.join("cgroup.events"))
                .unwrap()
                .contains("populated 1")
        );
        case.charged();
    }
    fs::write(path.join("cgroup.kill"), "1").unwrap();
    member.wait().unwrap();
    fs::remove_dir(&path).unwrap();
    custody
        .reconcile(&store, &intent, None)
        .unwrap()
        .retire(&[&store])
        .unwrap();
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(super) fn prior_boot_absence_reconciles_and_reused_paths_stay_held() {
    let case = Case::new("normal");
    let mut custody = case.custody();
    let store = case.store();
    store
        .replace_record(
            store.root(),
            &name("reservation"),
            &Reservation {
                attempt: text("old-1"),
            },
        )
        .unwrap();
    let charge = store
        .read(
            store.root(),
            &name("reservation"),
            campaign_supervisor::record::BOUND,
        )
        .unwrap()
        .unwrap()
        .bytes()
        .to_vec();
    let foreign = case
        .delegation
        .join(format!("prior-boot-{}", std::process::id()));
    let intent = Intent {
        attempt: text("old-1"),
        boot: text("prior-boot"),
        cgroup: text(foreign.to_str().unwrap()),
    };
    store
        .create_record(store.root(), &name("intent"), &intent)
        .unwrap();
    let intent = store
        .read_record::<Intent>(store.root(), &name("intent"))
        .unwrap()
        .unwrap();
    custody
        .reconcile(&store, &intent, None)
        .unwrap()
        .retire(&[&store])
        .unwrap();
    case.released();
    store
        .create_once(store.root(), &name("reservation"), &charge)
        .unwrap();
    fs::create_dir(&foreign).unwrap();
    let mut member = Command::new("/bin/sleep").arg("20").spawn().unwrap();
    fs::write(foreign.join("cgroup.procs"), member.id().to_string()).unwrap();
    assert!(matches!(
        custody.reconcile(&store, &intent, None),
        Err(Error::Held("prior-boot path now contains a cgroup"))
    ));
    assert!(member.try_wait().unwrap().is_none());
    case.charged();
    assert!(
        fs::read_to_string(foreign.join("cgroup.events"))
            .unwrap()
            .contains("populated 1")
    );
    case.charged();
    let local = case.root.join("prior-boot-local");
    fs::create_dir(&local).unwrap();
    fs::write(local.join("cgroup.procs"), member.id().to_string()).unwrap();
    let local_intent = Intent {
        cgroup: text(local.to_str().unwrap()),
        ..intent.record().clone()
    };
    store
        .create_record(store.root(), &name("old-local-intent"), &local_intent)
        .unwrap();
    let local_intent = store
        .read_record::<Intent>(store.root(), &name("old-local-intent"))
        .unwrap()
        .unwrap();
    assert!(matches!(
        custody.reconcile(&store, &local_intent, None),
        Err(Error::Held("cgroup belongs to another boot"))
    ));
    assert!(member.try_wait().unwrap().is_none());
    case.charged();
    fs::write(local.join("cgroup.kill"), "1").unwrap();
    member.wait().unwrap();
    fs::remove_dir(&local).unwrap();
    fs::remove_dir(&foreign).unwrap();
    store.delete(store.root(), &name("reservation")).unwrap();
    store
        .replace_record(store.root(), &name("intent"), local_intent.record())
        .unwrap();
    assert!(matches!(
        custody
            .reconcile(&store, &local_intent, None)
            .unwrap()
            .retire(&[&store]),
        Err(Error::Held("stopped attempt lacks reservation"))
    ));
    case.released();
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(super) fn idle_interruption_is_typed_and_refuses_a_fresh_launch() {
    let case = Case::new("normal");
    let mut custody = case.custody();
    let store = case.store();
    assert!(custody.interruption().unwrap().is_none());
    assert!(
        Command::new("/bin/kill")
            .args(["-INT", &std::process::id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(custody.interruption().unwrap(), Some(libc::SIGINT));
    assert_eq!(custody.interruption().unwrap(), Some(libc::SIGINT));
    assert!(matches!(
        custody.launch(&store, store.root(), case.launch()),
        Err(Error::Held("controller interruption requires drain"))
    ));
    assert!(!case.path.join("state/intent").exists());
    assert!(!case.root.join("attempt-1").exists());
    case.charged();
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(super) fn watchdog_stops_a_reached_stalled_worker() {
    let case = Case::new("stall");
    let budget = archive_wait(100000);
    let mut custody = case.custody();
    let store = case.store();
    let began = Instant::now();
    let running = custody.launch(&store, store.root(), case.launch()).unwrap();
    let stopped = custody.wait_any(vec![running]).unwrap().stopped;
    assert!(began.elapsed() >= budget);
    assert!(began.elapsed() < budget.saturating_add(Duration::from_secs(4)));
    assert!(
        case.path.join("seen").exists(),
        "stalled worker reached its body"
    );
    assert!(stopped.watchdog());
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(stopped.status().unwrap().signal(), Some(libc::SIGKILL));
    case.charged();
    stopped.retire(&[&store]).unwrap();
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(super) fn gate_setup_clears_mask_and_sets_group_before_direct_exec() {
    let case = Case::new("normal");
    let mut custody = case.custody();
    let store = case.store();
    let mut launch = case.launch();
    launch.launcher = std::env::current_exe().unwrap();
    launch.args.clear();
    let running = custody.launch(&store, store.root(), launch).unwrap();
    let stopped = custody.wait_any(vec![running]).unwrap().stopped;
    assert_eq!(stopped.status().unwrap().code(), Some(0));
    assert!(
        fs::read_to_string(case.path.join("seen"))
            .unwrap()
            .ends_with("0000000000000000\n")
    );
    stopped.retire(&[&store]).unwrap();
}

pub(super) fn remove_archive() {
    if std::env::var_os("CUSTODY_TEST_ARCHIVE").is_none() {
        let path = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("custody-archive-{}", std::process::id()));
        if path.exists() {
            fs::remove_dir_all(path).unwrap();
        }
    }
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(super) fn recreated_cgroup_instance_keeps_a_live_sentinel_held() {
    use std::os::unix::fs::MetadataExt;
    let case = Case::new("normal");
    let mut custody = case.custody();
    let store = case.store();
    let charge = store
        .read(
            store.root(),
            &name("reservation"),
            campaign_supervisor::record::BOUND,
        )
        .unwrap()
        .unwrap()
        .bytes()
        .to_vec();
    let running = custody.launch(&store, store.root(), case.launch()).unwrap();
    let stopped = custody.wait_any(vec![running]).unwrap().stopped;
    let old_inode = stopped.started().as_ref().unwrap().record().cgroup_inode;
    let intent = case.intent(&store);
    let started = store
        .read_record::<Started>(store.root(), &name("started"))
        .unwrap()
        .unwrap();
    stopped.retire(&[&store]).unwrap();
    store
        .create_once(store.root(), &name("reservation"), &charge)
        .unwrap();
    let path = case.root.join("attempt-1");
    fs::create_dir(&path).unwrap();
    assert_ne!(
        fs::metadata(&path).unwrap().ino(),
        old_inode,
        "recreated kernel instance witness"
    );
    let mut sentinel = Command::new("/bin/sleep").arg("20").spawn().unwrap();
    fs::write(path.join("cgroup.procs"), sentinel.id().to_string()).unwrap();
    assert!(matches!(
        custody.reconcile(&store, &intent, Some(&started)),
        Err(Error::Held("cgroup instance differs from started"))
    ));
    assert!(sentinel.try_wait().unwrap().is_none());
    assert!(
        fs::read_to_string(path.join("cgroup.events"))
            .unwrap()
            .contains("populated 1")
    );
    case.charged();
    fs::write(path.join("cgroup.kill"), "1").unwrap();
    sentinel.wait().unwrap();
    fs::remove_dir(path).unwrap();
}

trait Retire {
    fn retire(self, stores: &[&Store]) -> Result<(), Error>;
}
impl Retire for campaign_supervisor::custody::Stopped {
    fn retire(self, stores: &[&Store]) -> Result<(), Error> {
        let store = if stores.len() == 1 {
            stores[0]
        } else {
            stores
                .iter()
                .copied()
                .find(|store| {
                    store
                        .read_record::<Intent>(store.root(), &name("intent"))
                        .ok()
                        .flatten()
                        .is_some_and(|intent| intent.record().attempt == *self.identity())
                })
                .expect("the stopped attempt has its store")
        };
        let finished = store
            .read_record::<campaign_supervisor::record::Finished>(store.root(), &name("finished"))?
            .map(|record| record.record().clone())
            .unwrap_or(self.finished(
                campaign_supervisor::record::Class::Infrastructure,
                campaign_supervisor::record::Binding::Missing,
                None,
            )?);
        self.evidence(
            store,
            store.root(),
            campaign_supervisor::attempt::EVIDENCE_BOUND,
        )?
        .complete(store, &finished)?;
        Ok(())
    }
}

fn finished_class(directory: &Path) -> ProbeOutcome {
    let view = campaign_supervisor::store::View::open(directory).unwrap();
    view.read_record::<ProbeFinished>(view.root(), &name("finished"))
        .unwrap()
        .unwrap()
        .record()
        .outcome
}

#[path = "attempts.rs"]
mod attempts;
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(super) fn numbered_attempts_classify_kernel_limits_and_rederive_binding() {
    attempts::numbered_outcomes_and_binding()
}
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(super) fn held_history_and_evidence_overflow_preserve_a_started_campaign_witness() {
    attempts::held_history_and_overflow_with_started_campaign()
}
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(super) fn straggler_pass_is_fenced_by_stopped_membership() {
    attempts::straggler_pass_is_fenced_by_stopped_membership()
}
pub(super) fn attempt_launcher(plan: &Path) -> std::process::ExitCode {
    attempts::launcher(plan)
}
pub(super) fn attempt_straggler(plan: &Path) -> std::process::ExitCode {
    attempts::straggler(plan)
}

#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(super) fn numbered_retries_enforce_limits_and_reconcile_finished_evidence() {
    attempts::numbered_retry_limits_and_finished_reconciliation()
}
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
pub(super) fn started_attempt_reconciles_membership_after_owner_drop() {
    attempts::started_attempt_reconciles_membership_after_owner_drop()
}

pub(crate) use super::triage::{
    cli_signal_drain_smoke_preserves_minted_results,
    retained_rerun_and_reduction_keep_full_identity,
    retained_run_replays_in_fresh_processes_and_drift_starts_nothing,
    retained_step_owner_loss_at_worker_seam_is_interrupted_and_exclusive,
    storage_pause_is_successful_dispatch_and_explicit_refusal_without_mutation,
    triage_runs_on_reserve_while_the_ordinary_slot_is_full,
};

pub(crate) fn copy_tree(source: &std::path::Path, target: &std::path::Path) {
    std::fs::create_dir(target).unwrap();
    for entry in std::fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target.join(entry.file_name()));
        } else {
            std::fs::copy(entry.path(), target.join(entry.file_name())).unwrap();
        }
    }
}

pub(crate) use super::calibration::{
    calibrated_controls_lost_attempt_and_two_fresh_replays_grant_scoped_capacity,
    lost_calibration_replay_reconciles_under_dispatch_and_preserves_dependencies,
    missing_controls_and_disagreeing_fresh_replays_preserve_explicit_verdicts,
};

#[path = "corpus.rs"]
mod corpus;
pub(crate) use corpus::{
    corpus_duplicate_bundles_preserve_version_and_skip_workers,
    corpus_duplicate_semantics_and_caps_refuse_at_reached_guards,
    corpus_failed_prefix_and_interruption_keep_history_without_admission,
    corpus_lost_probe_reservation_reconciles_before_new_registration,
    corpus_registration_retirement_and_report_keep_frozen_roots,
    targeted_admission_freezes_versions_retirement_and_dispatch_roots,
    targeted_child_capture_binds_actual_parent_and_retains_independent_bundle,
    targeted_exploration_freezes_manifest_bounds_and_rejudges_retired_inputs,
    targeted_explore_nodes_and_leaves_keep_separate_findings_and_waiting_nodes,
    targeted_missing_facts_settle_one_replay_and_explicit_steps_can_repeat,
};

pub(crate) use super::calibration::unsealed_replay_disagreement_blocks_every_later_capacity_root;

pub(crate) use super::calibration::calibration_replay_panic_is_a_release_blocker_with_root_provenance;

pub(crate) use super::calibration::undetected_control_preserves_its_release_blocker;
