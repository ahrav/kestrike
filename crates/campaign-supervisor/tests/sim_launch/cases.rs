//! The cases: each drives `campaign sim` with a plan for the fake worker
//! and checks the exit, the artifact record and what the worker saw.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use campaign_supervisor::archive::{Archive, Built, publish};
use campaign_supervisor::record::{Artifact, Digest, Native, Pins, Provenance, Text};
use campaign_supervisor::store::{Name, View, open_host};

use super::worker::{COUNTING, LISTING, PLAN, bundle};

/// The archive every case runs: this executable as the worker.
fn archive() -> &'static (PathBuf, Pins) {
    static ARCHIVE: OnceLock<(PathBuf, Pins)> = OnceLock::new();
    ARCHIVE.get_or_init(|| {
        let path = scratch().join("archive");
        let text = |value: &str| Text::new(value).expect("ASCII");
        let digest = Digest::of(b"fake");
        let executable = std::env::current_exe().expect("the test has a path");
        let identity = open_host(&executable)
            .expect("the test executable opens")
            .identity();
        let built = Built {
            executable,
            identity,
            lock: b"version = 4\n".to_vec(),
            provenance: Provenance {
                cargo: text("cargo 1.0.0 (fake)"),
                command: text("test --test sim_launch"),
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
                toolchain: text("rustc 1.0.0 (fake)"),
                untracked: 0,
            },
        };
        let archive = publish(&path, &built).expect("the test archive publishes");
        (archive.path().to_owned(), archive.pins())
    })
}

/// This run's scratch directory, on the checkout's filesystem.
pub(crate) fn scratch() -> &'static Path {
    static SCRATCH: OnceLock<PathBuf> = OnceLock::new();
    SCRATCH.get_or_init(|| {
        let path = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("sim_launch-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("the scratch directory is created");
        path
    })
}

/// One case's directory: its plan files, its manifest and its artifacts.
struct Case {
    dir: PathBuf,
}

impl Drop for Case {
    fn drop(&mut self) {
        let Ok(pid) = fs::read_to_string(self.dir.join("escapee")) else {
            return;
        };
        let Ok(pid) = pid.trim().parse::<i32>() else {
            return;
        };
        if pid <= 1 {
            return;
        }
        // SAFETY: pidfd_open takes integers and returns a new descriptor.
        let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if descriptor < 0 {
            return;
        }
        // SAFETY: the successful syscall returned a fresh owned descriptor.
        let process =
            unsafe { OwnedFd::from_raw_fd(i32::try_from(descriptor).expect("descriptor")) };
        let expected = format!("{PLAN}={}", self.dir.display());
        if fs::read(format!("/proc/{pid}/environ")).is_ok_and(|bytes| {
            bytes
                .split(|byte| *byte == 0)
                .any(|value| value == expected.as_bytes())
        }) {
            // SAFETY: signaling stays tied to the opened descriptor across PID reuse.
            // The null siginfo pointer requests the kernel's default signal information.
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    process.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                );
            }
        }
    }
}

struct Launcher(Child);

impl Launcher {
    fn id(&self) -> u32 {
        self.0.id()
    }
    fn kill(&mut self) -> std::io::Result<()> {
        self.0.kill()
    }
}

impl Drop for Launcher {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            match self.0.try_wait() {
                Ok(Some(_)) => return,
                Err(error) if error.kind() != std::io::ErrorKind::Interrupted => return,
                _ => std::thread::sleep(Duration::from_millis(10)),
            }
        }
    }
}

fn output(mut command: Command) -> Output {
    wait_output(Launcher(
        command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("campaign starts"),
    ))
}

fn wait_output(mut launcher: Launcher) -> Output {
    let child = &mut launcher.0;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let (done, streams) = std::sync::mpsc::channel();
    let read = |index, stream: Option<Box<dyn Read + Send>>| {
        let done = done.clone();
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            if let Some(stream) = stream {
                stream
                    .take(2 << 20)
                    .read_to_end(&mut bytes)
                    .expect("output reads");
            }
            let _ = done.send((index, bytes));
        });
    };
    read(0, stdout.map(|pipe| Box::new(pipe) as Box<dyn Read + Send>));
    read(1, stderr.map(|pipe| Box::new(pipe) as Box<dyn Read + Send>));
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait().expect("launcher status") {
            break status;
        }
        if Instant::now() >= deadline {
            timed_out = true;
            let _ = child.kill();
            let cleanup = Instant::now() + Duration::from_secs(5);
            let reaped = loop {
                if let Some(status) = child.try_wait().expect("cleanup status") {
                    break status;
                }
                assert!(
                    Instant::now() < cleanup,
                    "launcher cleanup exceeded five seconds"
                );
                std::thread::sleep(Duration::from_millis(10));
            };
            break reaped;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut kept: [Option<Vec<u8>>; 2] = [None, None];
    for _ in 0..2 {
        let (index, bytes) = streams
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .expect("launcher pipe deadline");
        kept[index] = Some(bytes);
    }
    let [stdout, stderr] = kept.map(|bytes| bytes.expect("one result per pipe"));
    let output = Output {
        status,
        stdout,
        stderr,
    };
    assert!(!timed_out, "launcher exceeded 90 seconds: {output:?}");
    output
}

impl Case {
    fn new(name: &str) -> Self {
        let dir = scratch().join(name);
        fs::create_dir(&dir).expect("the case directory is created");
        let case = Self {
            dir: dir.canonicalize().expect("canonical case directory"),
        };
        fs::write(case.dir.join("manifest"), manifest(&[])).expect("the manifest is written");
        case
    }

    /// Writes plan file `name`.
    fn plan(&self, name: &str, value: &str) -> &Self {
        fs::write(self.dir.join(name), value).expect("the plan is written");
        self
    }

    fn manifest(&self) -> PathBuf {
        self.dir.join("manifest")
    }

    /// The forms the worker ran, in order.
    fn calls(&self) -> Vec<String> {
        fs::read_to_string(self.dir.join("calls"))
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    /// The values a form's `FORM.seen` file records.
    fn seen(&self, form: &str) -> BTreeMap<String, String> {
        fs::read_to_string(self.dir.join(format!("{form}.seen")))
            .expect("the form ran")
            .lines()
            .filter_map(|line| line.split_once('='))
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .collect()
    }

    /// `campaign sim` with `args` and this case's artifacts directory and
    /// plan.
    fn command(&self, args: &[&OsStr]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_campaign"));
        command
            .arg("sim")
            .args(args)
            .arg("--artifacts")
            .arg(self.dir.join("artifacts"))
            .env(PLAN, &self.dir)
            .stdin(Stdio::null());
        command
    }

    /// The arguments of `sim run` of `manifest` under `archive`, with
    /// `extra` after them.
    fn run_args<'a>(
        &self,
        archive: &'a Path,
        manifest: &'a Path,
        extra: &'a [&'a str],
    ) -> Vec<&'a OsStr> {
        let mut args = vec![
            OsStr::new("run"),
            OsStr::new("--archive"),
            archive.as_os_str(),
            OsStr::new("--manifest"),
            manifest.as_os_str(),
        ];
        args.extend(extra.iter().map(OsStr::new));
        args
    }

    /// `sim run` of the case's manifest with `extra` arguments.
    fn run(&self, extra: &[&str]) -> Ended {
        let (archive, _) = archive();
        let manifest = self.manifest();
        let args = self.run_args(archive, &manifest, extra);
        self.ended(output(self.command(&args)))
    }

    /// `sim inspect` of `bundle` under run id `run`.
    fn inspect(&self, bundle: &Path, archive: &Path) -> Ended {
        let args = [
            OsStr::new("inspect"),
            bundle.as_os_str(),
            OsStr::new("--archive"),
            archive.as_os_str(),
            OsStr::new("--run-id"),
            OsStr::new("run"),
        ];
        self.ended(output(self.command(&args)))
    }

    fn ended(&self, output: Output) -> Ended {
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let line: Option<serde_json::Value> = serde_json::from_str(stdout.trim()).ok();
        let artifact = line.as_ref().and_then(|line| {
            let dir = PathBuf::from(line["artifact"].as_str()?);
            let view = View::open(&dir).ok()?;
            let name = Name::new("artifact").expect("a name");
            let verified = view.read_record::<Artifact>(view.root(), &name).ok()??;
            Some((dir, verified.record().clone()))
        });
        Ended {
            code: output.status.code(),
            stdout,
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            artifact,
        }
    }
}

/// A finished `campaign sim` command.
struct Ended {
    code: Option<i32>,
    stdout: String,
    stderr: String,
    /// The artifact directory and its verified record.
    artifact: Option<(PathBuf, Artifact)>,
}

impl Ended {
    /// Asserts exit `code`, and that the artifact record's class names
    /// it; returns the record.
    fn class(&self, code: i32, class: &str) -> &Artifact {
        assert_eq!(self.code, Some(code), "{} {}", self.stdout, self.stderr);
        let (_, artifact) = self
            .artifact
            .as_ref()
            .expect("the command wrote its record");
        assert_eq!(artifact.class.as_str(), class, "{artifact:?}");
        artifact
    }

    fn reason(&self) -> &str {
        self.artifact
            .as_ref()
            .map_or("", |(_, artifact)| artifact.reason.as_str())
    }

    fn dir(&self) -> &Path {
        &self.artifact.as_ref().expect("an artifact directory").0
    }
}

/// A manifest pinning the test archive, with `extra` lines appended.
fn manifest(extra: &[&str]) -> String {
    let (_, pins) = archive();
    let mut text = format!(
        "version = 2\nprofile = upload\nscenario = ab\nroot = 3\nexecutable = {}\ntoolchain = {}\nbuild = {}\nplatform = {}\nrecords = 1000\nbytes = 48000\nsuffix_depth = 2\nsuffix_children = 3\nsuffix_faults = 12\nsuffix_advances = 16\n",
        pins.executable.as_str(),
        pins.toolchain.as_str(),
        pins.build.as_str(),
        pins.platform.as_str(),
    );
    for line in extra {
        text.push_str(line);
        text.push('\n');
    }
    text
}

/// `COUNTING` with each `(from, to)` edit applied once.
fn summary(edits: &[(&str, &str)]) -> String {
    let mut text = COUNTING.to_owned();
    for (from, to) in edits {
        assert!(text.contains(from), "{from}");
        text = text.replacen(from, to, 1);
    }
    text
}

const VIOLATION: [(&str, &str); 3] = [
    ("complete pass", "complete violation"),
    ("counts: true", "counts: false"),
    ("stop: goal\n", "stop: goal\ncause: violation\n"),
];

const CAPPED: [(&str, &str); 3] = [
    ("complete pass fired=03 required=03", "infrastructure cap"),
    ("counts: true", "counts: false"),
    ("stop: goal\n", "stop: goal\ncause: cap\n"),
];

/// A recovery profile's summary with `ledger` lines.
fn recovery(ledger: &str, counts: bool) -> String {
    let census =
        "stages: planned=1 reached=1 activated=1 recovered=1 checked=1 skipped=0\nlimits: cuts=1\n";
    let mut edits = vec![("profile: upload", "profile: recovery-512")];
    if !counts {
        edits.extend([
            ("counts: true", "counts: false"),
            (
                "stop: goal\n",
                "stop: goal\ncause: the campaign ledger is inconclusive\n",
            ),
        ]);
    }
    let mut text = summary(&edits);
    text.push_str(ledger);
    if !ledger.is_empty() {
        text.push_str(census);
    }
    text
}

/// Whether process `pid` is gone or a zombie.
fn dead(pid: &str) -> bool {
    assert!(
        pid.parse::<u32>().is_ok_and(|pid| pid > 1),
        "positive process ID: {pid}"
    );
    match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Err(_) => true,
        Ok(stat) => stat
            .rsplit_once(") ")
            .is_some_and(|(_, rest)| rest.starts_with('Z')),
    }
}

/// Waits up to `seconds` for `ready`.
fn within(seconds: u64, mut ready: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    while Instant::now() < deadline {
        if ready() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    ready()
}

/// A counting run exits 0 after the capability, run and inspect forms,
/// each in a group of its own with the parent-death signal, the null
/// device as its input and the archive's libraries as its whole library
/// path; the record names the frozen manifest, the bundle, the summary
/// and each form's stored output by digest.
pub(crate) fn a_counting_run_records_every_form_under_the_launch_contract() {
    let case = Case::new("counting");
    let (archive, _) = archive();
    let manifest = case.manifest();
    let args = case.run_args(archive, &manifest, &["--run-id", "attempt-1"]);
    // The launcher's own input holds bytes, so a worker that inherited it
    // would read them.
    let input = fs::File::open(&manifest).expect("the manifest opens");
    let mut command = case.command(&args);
    command.stdin(input);
    let output = output(command);
    let ended = case.ended(output);
    let artifact = ended.class(0, "counts");
    assert_eq!(case.calls(), ["capabilities", "run", "inspect"]);
    assert_eq!(ended.dir().file_name(), Some(OsStr::new("attempt-1")));
    for form in ["capabilities", "run", "inspect"] {
        let seen = case.seen(form);
        assert_eq!(seen["leader"], "true", "{form}");
        assert_eq!(seen["deathsig"], libc::SIGKILL.to_string(), "{form}");
        assert_eq!(seen["stdin"], "0", "{form}");
        assert_eq!(seen["blocked"], "0000000000000000", "{form}");
        assert_eq!(Path::new(&seen["cwd"]), ended.dir(), "{form}");
        assert_eq!(Path::new(&seen["libraries"]), archive.join("lib"), "{form}");
        let worker = &artifact.workers[&Text::new(form).expect("ASCII")];
        assert_eq!((worker.ended.as_str(), worker.exit), ("exited", Some(0)));
        let stdout = fs::read(ended.dir().join(format!("{form}.stdout"))).expect("stored");
        assert_eq!(worker.stdout, Digest::of(&stdout));
        assert_eq!(
            stdout,
            if form == "capabilities" {
                LISTING.as_bytes()
            } else {
                COUNTING.as_bytes()
            }
        );
        let stderr = fs::read(ended.dir().join(format!("{form}.stderr"))).expect("stored stderr");
        assert!(stderr.is_empty());
        assert_eq!(worker.stderr, Digest::of(&stderr));
    }
    for form in ["run", "inspect"] {
        let read = PathBuf::from(&case.seen(form)["manifest"]);
        assert_eq!(
            read,
            ended.dir().join("manifest"),
            "{form} reads the frozen copy"
        );
    }
    let frozen = fs::read(ended.dir().join("manifest")).expect("the manifest is frozen");
    assert_eq!(
        frozen,
        fs::read(case.manifest()).expect("the manifest reads")
    );
    assert_eq!(artifact.manifest, Some(Digest::of(&frozen)));
    let bundle = fs::read(ended.dir().join("bundle")).expect("the bundle is kept");
    assert_eq!(artifact.bundle, Some(Digest::of(&bundle)));
    let inspected = case.seen("inspect");
    assert_eq!(Path::new(&inspected["inspect"]), ended.dir().join("bundle"));
    assert_eq!(inspected["inspect_digest"], Digest::of(&bundle).to_string());
    let loaded = Archive::load(archive).expect("the archive loads");
    assert_eq!(artifact.archive, Some(loaded.id()));
    let summary = artifact.summary.as_ref().expect("a summary");
    assert_eq!((summary.counts, summary.decisions), (true, Some(61)));
    assert_eq!(
        summary.terminal.as_str(),
        "complete pass fired=03 required=03"
    );
    assert_eq!(summary.digest.to_string(), COUNTING[8..72]);
    assert_eq!(artifact.run_id.as_str(), "attempt-1");
    let line: serde_json::Value = serde_json::from_str(ended.stdout.trim()).expect("one JSON line");
    assert_eq!(line["class"], "counts");
}

/// A summary claiming credit with no decision exits 4 although the
/// worker exits 0.
pub(crate) fn counts_with_no_decision_is_incomplete() {
    let one = Case::new("one-decision");
    let printed = summary(&[("decisions: 61", "decisions: 1")]);
    one.plan("run.out", &printed).plan("inspect.out", &printed);
    one.run(&[]).class(0, "counts");
    let case = Case::new("no-decision");
    let printed = summary(&[("decisions: 61", "decisions: 0")]);
    case.plan("run.out", &printed).plan("inspect.out", &printed);
    let ended = case.run(&[]);
    ended.class(4, "incomplete");
    assert!(
        ended.reason().contains("without a decision"),
        "{}",
        ended.reason()
    );
}

/// A complete violation the worker exits 1 for exits 1; a worker exit
/// that disagrees with the summary, and an infrastructure terminal beside
/// a worker exit of 0, exit 4.
pub(crate) fn the_worker_exit_alone_never_counts() {
    let violation = summary(&VIOLATION);
    let capped = summary(&CAPPED);
    for (name, printed, exit, code, class) in [
        ("violation", &violation, "1", 1, "complete"),
        ("violation-exit-0", &violation, "0", 4, "incomplete"),
        (
            "counting-exit-3",
            &COUNTING.to_owned(),
            "3",
            4,
            "incomplete",
        ),
        ("capped-exit-0", &capped, "0", 4, "incomplete"),
        ("capped-exit-3", &capped, "3", 4, "incomplete"),
    ] {
        let case = Case::new(name);
        case.plan("run.out", printed)
            .plan("inspect.out", printed)
            .plan("run.exit", exit);
        case.run(&[]).class(code, class);
    }
}

/// A recovery bundle counts only with a credited ledger: one without a
/// ledger line, or counting beside an inconclusive one, exits 4; an
/// inconclusive one that does not count exits 1.
pub(crate) fn a_recovery_run_counts_only_with_a_credited_ledger() {
    for (name, printed, exit, code, class) in [
        (
            "credited",
            recovery("ledger: credited\n", true),
            "0",
            0,
            "counts",
        ),
        ("no-ledger", recovery("", true), "0", 4, "incomplete"),
        (
            "counts-inconclusive",
            recovery("ledger: inconclusive Bound { cut: 1 }\n", true),
            "0",
            4,
            "incomplete",
        ),
        (
            "unrecorded",
            recovery("ledger: unrecorded\n", false),
            "1",
            1,
            "complete",
        ),
        (
            "inconclusive",
            recovery("ledger: inconclusive Bound { cut: 1 }\n", false),
            "1",
            1,
            "complete",
        ),
    ] {
        let case = Case::new(&format!("recovery-{name}"));
        fs::write(
            case.manifest(),
            manifest(&[]).replace("upload", "recovery-512"),
        )
        .expect("the manifest is written");
        case.plan("run.out", &printed)
            .plan("inspect.out", &printed)
            .plan("run.exit", exit);
        let ended = case.run(&[]);
        let artifact = ended.class(code, class);
        // A summary the parser refuses leaves the record without one.
        if code != 4 {
            let word = printed
                .lines()
                .find_map(|line| line.strip_prefix("ledger: "))
                .expect("the summary judges its ledger");
            let verdict = word.split(' ').next().expect("a verdict");
            let recorded = artifact
                .summary
                .as_ref()
                .expect("a summary")
                .ledger
                .as_ref();
            assert_eq!(recorded.map(Text::as_str), Some(verdict), "{name}");
        }
    }
}

/// A panic, an abort, a torn summary, a summary that differs between the
/// run and inspect forms, a torn listing and output past the bound each
/// exit 4.
pub(crate) fn a_worker_that_fails_its_output_is_incomplete() {
    let torn = COUNTING.trim_end().to_owned();
    let long = format!("{}\n", "x".repeat(1_000_000));
    let payload = format!(
        "run: the run panicked at src/x.rs:1:1: p{}\n",
        "\u{e9}".repeat(2500)
    );
    let other = summary(&[("turns: 57", "turns: 58")]);
    for (name, plans, reason) in [
        (
            "panic",
            &[
                ("run.out", "run: the run panicked at src/x.rs:1:1: boom\n"),
                ("run.exit", "3"),
                ("inspect.out", &summary(&CAPPED)),
            ][..],
            "the run panicked at src/x.rs:1:1: boom",
        ),
        (
            "long-panic",
            &[
                ("run.out", &payload),
                ("run.exit", "3"),
                ("inspect.out", &summary(&CAPPED)),
            ],
            "the run panicked at src/x.rs:1:1: p\\u{e9}",
        ),
        ("abort", &[("run.action", "abort")], "died from signal 6"),
        ("setsid", &[("run.action", "setsid")], "pipes closed=false"),
        (
            "torn",
            &[("run.out", &torn)],
            "the run form's output is refused",
        ),
        (
            "differs",
            &[("inspect.out", &other)],
            "differs from the inspected",
        ),
        (
            "torn-listing",
            &[("capabilities.out", LISTING.trim_end())],
            "the capability listing is refused",
        ),
        (
            "flood",
            &[("run.action", "flood")],
            "wrote more than 1048576 bytes",
        ),
        (
            "no-bundle",
            &[("run.nobundle", ""), ("run.exit", "3")],
            "without a bundle",
        ),
        (
            "refused-bundle",
            &[("inspect.exit", "2")],
            "refusing the bundle",
        ),
        (
            "flood-stderr",
            &[("run.action", "flood-stderr")],
            "wrote more than 1048576 bytes",
        ),
        (
            "squat",
            &[("run.action", "squat")],
            "the artifact entry run.stderr failed",
        ),
        (
            "long-line",
            &[("run.out", &long)],
            "the run form's output is refused",
        ),
        (
            "over-maximum",
            &[("run.records", "100")],
            "more than 8 records",
        ),
    ] {
        let case = Case::new(name);
        for (file, value) in plans {
            case.plan(file, value);
        }
        if name == "over-maximum" {
            let text = manifest(&[]).replace("records = 1000", "records = 8");
            fs::write(case.manifest(), text).expect("the manifest is written");
        }
        let ended = case.run(&[]);
        ended.class(4, "incomplete");
        assert!(
            ended.reason().contains(reason),
            "{name}: {}",
            ended.reason()
        );
        // The record escapes the reason the cut keeps; the printed line
        // holds it unescaped.
        let line: serde_json::Value =
            serde_json::from_str(ended.stdout.trim()).expect("one JSON line");
        let printed = line["reason"].as_str().expect("a reason");
        assert!(printed.len() <= 4096 + 3, "{name}: the reason is bounded");
        if name == "long-panic" {
            // The cut at byte 4096 lands inside a two-byte character, so
            // it keeps 4095 bytes.
            assert!(
                printed.ends_with("...") && ended.reason().ends_with("..."),
                "{printed}"
            );
            assert_eq!(printed.len(), 4095 + 3, "{printed}");
        }
        let key = Text::new("run").expect("key");
        if name != "torn-listing" {
            let run = ended
                .artifact
                .as_ref()
                .expect("artifact")
                .1
                .workers
                .get(&key)
                .expect("the run phase is recorded");
            match name {
                "abort" => assert_eq!(
                    (run.ended.as_str(), run.exit, run.signal),
                    ("signaled", None, Some(6))
                ),
                "setsid" => {
                    assert_eq!(
                        (run.ended.as_str(), run.exit, run.signal),
                        ("escaped", Some(0), None)
                    );
                    assert_eq!(
                        fs::read(ended.dir().join("run.stdout")).expect("partial output"),
                        COUNTING.as_bytes()
                    );
                }
                "squat" => {
                    assert_eq!(
                        (run.ended.as_str(), run.exit, run.signal),
                        ("exited", Some(0), None)
                    );
                    assert_eq!(
                        fs::read(ended.dir().join("run.stderr")).expect("the taken name"),
                        b"squatted"
                    );
                }
                "flood" | "flood-stderr" => {
                    assert_eq!(
                        (run.ended.as_str(), run.exit, run.signal),
                        ("oversized", None, None)
                    );
                    let stream = if name == "flood" {
                        "run.stdout"
                    } else {
                        "run.stderr"
                    };
                    assert_eq!(
                        fs::read(ended.dir().join(stream))
                            .expect("bounded output")
                            .len(),
                        1 << 20
                    );
                }
                _ => {}
            }
        }
    }
}

/// A summary naming another profile than the frozen manifest runs exits 4,
/// so the frozen manifest's profile selects the ledger rule.
pub(crate) fn a_summary_of_another_profile_is_incomplete() {
    let case = Case::new("other-profile");
    fs::write(
        case.manifest(),
        manifest(&[]).replace("upload", "recovery-512"),
    )
    .expect("the manifest is written");
    let ended = case.run(&[]);
    ended.class(4, "incomplete");
    assert!(
        ended.reason().contains("names profile"),
        "{}",
        ended.reason()
    );
}

/// A bundle rewritten during the inspection, and an archive whose library
/// changed while the run form ran, each exit 4.
pub(crate) fn evidence_changed_during_a_form_is_incomplete() {
    let case = Case::new("ancestor-changed-between-phases");
    case.plan("capabilities.action", "shared")
        .plan("rewrite.target", &case.dir.display().to_string());
    let (archived_worker, _) = archive();
    let input = case.manifest();
    let result = self::output(case.command(&case.run_args(archived_worker, &input, &[])));
    assert_eq!(case.calls(), ["capabilities"]);
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&case.dir, fs::Permissions::from_mode(0o700)).expect("private ancestor");
    let ended = case.ended(result);
    ended.class(4, "incomplete");
    assert!(
        ended
            .reason()
            .contains("artifact path is refused after capabilities")
    );

    for inspect_only in [false, true] {
        let case = Case::new(if inspect_only {
            "inspect-final-ancestor-drift"
        } else {
            "run-final-ancestor-drift"
        });
        case.plan("inspect.action", "shared")
            .plan("rewrite.target", &case.dir.display().to_string());
        let (worker, _) = archive();
        let result = if inspect_only {
            let source = case.dir.join("source.bundle");
            fs::write(&source, bundle(&manifest(&[]), 1)).expect("bundle");
            let args = [
                OsStr::new("inspect"),
                source.as_os_str(),
                OsStr::new("--archive"),
                worker.as_os_str(),
                OsStr::new("--run-id"),
                OsStr::new("fixed"),
            ];
            self::output(case.command(&args))
        } else {
            let input = case.manifest();
            self::output(case.command(&case.run_args(worker, &input, &["--run-id", "fixed"])))
        };
        assert_eq!(
            case.calls(),
            if inspect_only {
                vec!["capabilities", "inspect"]
            } else {
                vec!["capabilities", "run", "inspect"]
            }
        );
        fs::set_permissions(&case.dir, fs::Permissions::from_mode(0o700))
            .expect("private ancestor");
        let ended = case.ended(result);
        ended.class(4, "incomplete");
        assert!(
            ended
                .reason()
                .contains("artifact path is refused after inspect"),
            "{}",
            ended.reason()
        );
    }

    let case = Case::new("unsafe-artifact-root-mode");
    let root = case.dir.join("artifacts/fixed");
    case.plan("capabilities.action", "shared")
        .plan("rewrite.target", &root.display().to_string());
    let ended = case.run(&["--run-id", "fixed"]);
    assert_eq!(ended.code, Some(4));
    let result: serde_json::Value = serde_json::from_str(ended.stdout.trim()).expect("result");
    assert_eq!(result["class"], "incomplete");
    assert!(
        result["reason"]
            .as_str()
            .expect("reason")
            .contains("artifact record failed")
    );
    assert_eq!(case.calls(), ["capabilities"]);
    assert!(!root.join("artifact").exists());
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private root");

    // An `artifact` entry the inspect form creates before the launcher
    // writes its record leaves the command incomplete.
    let case = Case::new("artifact-entry-taken");
    let taken = case.dir.join("artifacts/fixed/artifact");
    case.plan("inspect.action", "replace")
        .plan("rewrite.target", &taken.display().to_string());
    let ended = case.run(&["--run-id", "fixed"]);
    assert_eq!(ended.code, Some(4), "{} {}", ended.stdout, ended.stderr);
    let result: serde_json::Value = serde_json::from_str(ended.stdout.trim()).expect("result");
    assert_eq!(result["class"], "incomplete");
    assert!(
        result["reason"]
            .as_str()
            .expect("reason")
            .contains("another artifact entry holds its name"),
        "{result}"
    );
    assert_eq!(
        fs::read(&taken).expect("the worker's entry stays"),
        b"changed while the worker ran"
    );
    assert_eq!(case.calls(), ["capabilities", "run", "inspect"]);

    let case = Case::new("raised-output-cap");
    let frozen = manifest(&[]).replace("records = 1000", "records = 20");
    fs::write(case.manifest(), frozen).expect("manifest");
    case.plan("run.manifest", &manifest(&[]))
        .plan("run.records", "100");
    let ended = case.run(&[]);
    ended.class(4, "incomplete");
    assert!(ended.reason().contains("frozen manifest's record maximum"));
    assert_eq!(case.calls(), ["capabilities", "run"]);

    let case = Case::new("normal-group-member");
    case.plan("run.action", "escape-exit");
    let ended = case.run(&[]);
    ended.class(0, "counts");
    let pid = fs::read_to_string(case.dir.join("escapee")).expect("positive member PID");
    assert!(pid.trim().parse::<u32>().is_ok_and(|pid| pid > 1));
    assert!(
        !Path::new(&format!("/proc/{}", pid.trim())).exists(),
        "member fully reaped"
    );

    let case = Case::new("exact-output-bound");
    case.plan("run.action", "exact-stderr");
    let ended = case.run(&[]);
    ended.class(0, "counts");
    assert_eq!(
        fs::read(ended.dir().join("run.stderr")).expect("retained stderr"),
        vec![b'x'; 1 << 20]
    );

    use std::os::unix::process::CommandExt;
    let case = Case::new("inherited-signals");
    let (archive, _) = archive();
    let manifest = case.manifest();
    let mut command = case.command(&case.run_args(archive, &manifest, &[]));
    // SAFETY: signal numbers are valid and the writable local signal set
    // outlives each call. The pre_exec closure allocates nothing.
    unsafe {
        command.pre_exec(|| {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&raw mut set);
            libc::sigaddset(&raw mut set, libc::SIGHUP);
            let code = libc::pthread_sigmask(libc::SIG_BLOCK, &raw const set, std::ptr::null_mut());
            if code != 0 {
                return Err(std::io::Error::from_raw_os_error(code));
            }
            libc::signal(libc::SIGCHLD, libc::SIG_IGN);
            Ok(())
        });
    }
    case.ended(output(command)).class(0, "counts");
    for form in ["capabilities", "run", "inspect"] {
        assert_eq!(case.seen(form)["blocked"], "0000000000000000");
    }

    let case = Case::new("archive-inherited-sigchld");
    let compiler = case.dir.join("rustc");
    fs::write(&compiler, "#!/bin/sh\nexit 23\n").expect("compiler fixture");
    fs::set_permissions(&compiler, fs::Permissions::from_mode(0o700)).expect("executable");
    let mut command = Command::new(env!("CARGO_BIN_EXE_campaign"));
    command
        .args(["sim", "archive", "--output"])
        .arg(case.dir.join("archive"))
        .env("RUSTC", &compiler)
        .stdin(Stdio::null());
    // SAFETY: the post-fork closure calls only signal with valid constants
    // and allocates nothing.
    unsafe {
        command.pre_exec(|| {
            libc::signal(libc::SIGCHLD, libc::SIG_IGN);
            Ok(())
        });
    }
    let archived = output(command);
    assert_eq!(archived.status.code(), Some(3), "{archived:?}");
    assert!(
        String::from_utf8_lossy(&archived.stderr).contains("exited exit status: 23"),
        "{archived:?}"
    );

    let case = Case::new("bundle-changed");
    let bundle = case.dir.join("artifacts/fixed/bundle");
    case.plan("inspect.action", "rewrite")
        .plan("rewrite.target", &bundle.display().to_string());
    let ended = case.run(&["--run-id", "fixed"]);
    ended.class(4, "incomplete");
    assert!(
        ended.reason().contains("bundle changed"),
        "{}",
        ended.reason()
    );
    let case = Case::new("archive-changed");
    let copy = case.dir.join("archive");
    copy_tree(archive, &copy);
    let library = first_library(&copy);
    case.plan("run.action", "chmod")
        .plan("rewrite.target", &library.display().to_string());
    let manifest = case.manifest();
    let args = case.run_args(&copy, &manifest, &[]);
    let ended = case.ended(self::output(case.command(&args)));
    ended.class(4, "incomplete");
    assert!(
        ended.reason().contains("no longer verifies after run"),
        "{}",
        ended.reason()
    );
    assert_eq!(case.calls(), ["capabilities", "run"]);
}

/// The first library of the archive at `archive`.
fn first_library(archive: &Path) -> PathBuf {
    fs::read_dir(archive.join("lib"))
        .expect("the library directory lists")
        .next()
        .expect("a library")
        .expect("the entry reads")
        .path()
}

/// A frozen manifest the worker rewrites is incomplete evidence.
pub(crate) fn a_manifest_changed_during_the_run_is_incomplete() {
    let restored = Case::new("manifest-restored");
    let frozen = restored.dir.join("artifacts/fixed/manifest");
    restored
        .plan("run.action", "restore")
        .plan("rewrite.target", &frozen.display().to_string());
    let ended = restored.run(&["--run-id", "fixed"]);
    ended.class(4, "incomplete");
    assert_eq!(
        fs::read(&frozen).expect("restored"),
        fs::read(restored.manifest()).expect("source")
    );
    assert!(ended.reason().contains("frozen file changed"));
    let case = Case::new("rewritten");
    // The run id fixes the frozen copy's path before the run starts.
    let frozen = case.dir.join("artifacts/fixed/manifest");
    case.plan("run.action", "rewrite")
        .plan("rewrite.target", &frozen.display().to_string());
    let ended = case.run(&["--run-id", "fixed"]);
    ended.class(4, "incomplete");
    assert!(
        ended.reason().contains("frozen file changed"),
        "{}",
        ended.reason()
    );
    // A frozen-manifest rewrite takes precedence over a run form's exit 2
    // without a bundle, so the command is incomplete.
    let refused = Case::new("rewritten-then-refused");
    let frozen = refused.dir.join("artifacts/fixed/manifest");
    refused
        .plan("run.nobundle", "")
        .plan("run.exit", "2")
        .plan("run.action", "rewrite")
        .plan("rewrite.target", &frozen.display().to_string());
    let ended = refused.run(&["--run-id", "fixed"]);
    ended.class(4, "incomplete");
    assert!(
        ended.reason().contains("frozen")
            && ended.reason().contains("manifest")
            && ended.reason().contains("changed"),
        "{}",
        ended.reason()
    );
    assert_eq!(refused.calls(), ["capabilities", "run"]);
}

/// The watchdog kills the worker's whole group, a forked member included,
/// and exits 6; the manifest's watchdog applies without the flag.
pub(crate) fn the_watchdog_kills_and_drains_the_group() {
    let case = Case::new("watchdog");
    case.plan("run.action", "escape");
    let started = Instant::now();
    let ended = case.run(&["--watchdog", "2"]);
    let artifact = ended.class(6, "watchdog");
    let run = &artifact.workers[&Text::new("run").expect("ASCII")];
    assert_eq!(run.ended.as_str(), "watchdog");
    // A drain that waited out its bound would take longer than the 2 s
    // watchdog and the 10 s drain together.
    assert!(started.elapsed() >= Duration::from_millis(1800));
    assert!(started.elapsed() < Duration::from_secs(12));
    let escapee = fs::read_to_string(case.dir.join("escapee")).expect("the member forked");
    assert!(dead(escapee.trim()), "the forked member {escapee} survived");
    assert!(dead(&case.seen("run")["pid"]));
    let case = Case::new("manifest-watchdog");
    fs::write(case.manifest(), manifest(&["watchdog = 2"])).expect("the manifest is written");
    case.plan("run.action", "hang");
    let started = Instant::now();
    case.run(&[]).class(6, "watchdog");
    assert!(started.elapsed() >= Duration::from_millis(1800));
    let case = Case::new("watchdog-override");
    fs::write(case.manifest(), manifest(&["watchdog = 2"])).expect("manifest");
    case.plan("run.action", "hang");
    let ended = case.run(&["--watchdog", "0.2"]);
    ended.class(6, "watchdog");
    assert!(
        ended.reason().contains("200ms watchdog"),
        "{}",
        ended.reason()
    );

    let case = Case::new("watchdog-late-signal");
    case.plan("run.action", "setsid-hang");
    let (archive, _) = archive();
    let manifest = case.manifest();
    let mut command = case.command(&case.run_args(archive, &manifest, &["--watchdog", "1"]));
    let child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map(Launcher)
        .expect("launcher");
    assert!(within(60, || case.dir.join("escapee").exists()));
    assert!(within(10, || dead(&case.seen("run")["pid"])));
    // SAFETY: the unreaped child reserves its positive PID.
    unsafe {
        libc::kill(i32::try_from(child.id()).expect("pid"), libc::SIGTERM);
    }
    let ended = case.ended(wait_output(child));
    let artifact = ended.class(6, "watchdog");
    assert_eq!(
        artifact.workers[&Text::new("run").expect("key")]
            .ended
            .as_str(),
        "watchdog"
    );
    assert!(ended.reason().contains("pipes closed=false"));
}

pub(crate) fn refused_inputs_run_no_worker() {
    let case = Case::new("tampered");
    let (archive, _) = archive();
    let copy = case.dir.join("archive");
    copy_tree(archive, &copy);
    let library = first_library(&copy);
    let mut permissions = fs::metadata(&library).expect("it exists").permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o600);
    fs::set_permissions(&library, permissions).expect("it is writable");
    let mut bytes = fs::read(&library).expect("it reads");
    *bytes.last_mut().expect("bytes") ^= 1;
    fs::write(&library, bytes).expect("it is rewritten");
    let manifest_path = case.manifest();
    let args = [
        OsStr::new("run"),
        OsStr::new("--archive"),
        copy.as_os_str(),
        OsStr::new("--manifest"),
        manifest_path.as_os_str(),
    ];
    let ended = case.ended(self::output(case.command(&args)));
    ended.class(2, "rejected");
    assert!(
        ended
            .reason()
            .contains("the archive is refused before capabilities"),
        "{}",
        ended.reason()
    );
    assert_eq!(case.calls(), Vec::<String>::new());
    for (name, text, reason) in [
        (
            "bad-manifest-watchdog",
            manifest(&["watchdog = 1.5"]),
            "watchdog",
        ),
        (
            "tiny-manifest-watchdog",
            manifest(&["watchdog = 1e-20"]),
            "watchdog",
        ),
        (
            "other-build",
            manifest(&[]).replace("build = ", "build = 0"),
            "the manifest pins build",
        ),
        (
            "no-pins",
            "version = 2\nprofile = upload\n".to_owned(),
            "pins no build",
        ),
    ] {
        let case = Case::new(name);
        fs::write(case.manifest(), text).expect("the manifest is written");
        let ended = case.run(&[]);
        ended.class(2, "rejected");
        assert!(
            ended.reason().contains(reason),
            "{name}: {}",
            ended.reason()
        );
        assert_eq!(case.calls(), Vec::<String>::new());
    }
    for (name, text) in [
        (
            "old-version",
            manifest(&[]).replace("version = 2", "version = 1"),
        ),
        ("no-version", manifest(&[]).replace("version = 2\n", "")),
    ] {
        let case = Case::new(name);
        fs::write(case.manifest(), text).expect("the manifest is written");
        let ended = case.run(&[]);
        ended.class(2, "rejected");
        assert!(
            ended.reason().contains("names version"),
            "{}",
            ended.reason()
        );
        assert_eq!(case.calls(), ["capabilities"]);
    }
    for (name, watchdog) in [("tiny-flag", "1e-20"), ("tiny-flag-2", "1e-10")] {
        let case = Case::new(name);
        let ended = case.run(&["--watchdog", watchdog]);
        assert_eq!(ended.code, Some(2));
        assert!(case.calls().is_empty());
    }
    let case = Case::new("missing-manifest");
    let missing = case.dir.join("absent");
    let ended = case.ended(self::output(case.command(&case.run_args(
        archive,
        &missing,
        &[],
    ))));
    ended.class(2, "rejected");
    assert!(case.calls().is_empty());
    let case = Case::new("non-utf8-manifest");
    fs::write(case.manifest(), [0xff]).expect("raw manifest");
    case.run(&[]).class(2, "rejected");
    assert!(case.calls().is_empty());
    let case = Case::new("absent-inspect-source");
    case.inspect(&case.dir.join("absent"), archive)
        .class(2, "rejected");
    assert!(case.calls().is_empty());
    let case = Case::new("absent-archive");
    let missing = case.dir.join("absent");
    let manifest = case.manifest();
    let ended = case.ended(self::output(case.command(&case.run_args(
        &missing,
        &manifest,
        &[],
    ))));
    let artifact = ended.class(2, "rejected");
    assert!(artifact.archive.is_none());
    assert!(case.calls().is_empty());
    let case = Case::new("bad-id-no-signal");
    let ended = case.run(&["--run-id", "../bad"]);
    assert_eq!(ended.code, Some(2));
    assert!(ended.artifact.is_none());
    assert!(case.calls().is_empty());
    let case = Case::new("nonzero-capabilities");
    case.plan("capabilities.exit", "1");
    let ended = case.run(&[]);
    ended.class(4, "incomplete");
    assert!(ended.reason().contains("without a capability listing"));
    assert_eq!(case.calls(), ["capabilities"]);
    let case = Case::new("worker-non-utf8");
    case.plan("run.action", "non-utf8");
    let ended = case.run(&[]);
    ended.class(4, "incomplete");
    assert!(ended.reason().contains("printed bytes that are no UTF-8"));
    assert_eq!(case.calls(), ["capabilities", "run"]);
    let case = Case::new("unsafe-artifact-ancestor");
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&case.dir, fs::Permissions::from_mode(0o777)).expect("shared ancestor");
    let ended = case.run(&[]);
    assert_eq!(ended.code, Some(2), "{} {}", ended.stdout, ended.stderr);
    assert!(ended.stderr.contains("artifact path is refused"));
    assert!(case.calls().is_empty());
    assert!(
        !case.dir.join("artifacts").exists(),
        "the refusal precedes every creation under the shared ancestor"
    );
    fs::set_permissions(&case.dir, fs::Permissions::from_mode(0o700)).expect("private ancestor");

    let case = Case::new("worker-refusal");
    case.plan("run.nobundle", "").plan("run.exit", "2");
    case.run(&[]).class(2, "rejected");
}

/// Copies directory `from` to the new `to`, each directory with mode
/// 0700 as an archive's are and each file with its mode.
pub(crate) fn copy_tree(from: &Path, to: &Path) {
    std::os::unix::fs::DirBuilderExt::mode(&mut fs::DirBuilder::new(), 0o700)
        .create(to)
        .expect("the copy is created");
    for entry in fs::read_dir(from).expect("the tree lists") {
        let entry = entry.expect("the entry reads");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("a type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).expect("the file copies");
        }
    }
}

/// An existing run id is refused with its directory unchanged; without
/// `--run-id` the directory is `local-SECONDS-PID`.
pub(crate) fn run_ids_name_new_artifact_directories() {
    let case = Case::new("run-ids");
    case.run(&["--run-id", "taken"]).class(0, "counts");
    let record = fs::read(case.dir.join("artifacts/taken/artifact")).expect("the record");
    let again = case.run(&["--run-id", "taken"]);
    assert_eq!(again.code, Some(2), "{}", again.stderr);
    assert!(again.artifact.is_none());
    assert_eq!(
        fs::read(case.dir.join("artifacts/taken/artifact")).expect("it stays"),
        record
    );
    assert_eq!(case.calls().len(), 3, "the refused command ran no worker");
    let (archive, _) = archive();
    // Relative paths resolve against the caller's directory, and the
    // worker receives absolute ones.
    let mut command = Command::new(env!("CARGO_BIN_EXE_campaign"));
    command
        .args([
            "sim",
            "run",
            "--manifest",
            "manifest",
            "--artifacts",
            "relative",
        ])
        .args(["--run-id", "here", "--archive"])
        .arg(archive)
        .current_dir(&case.dir)
        .env(PLAN, &case.dir)
        .stdin(Stdio::null());
    let ended = case.ended(output(command));
    ended.class(0, "counts");
    assert_eq!(ended.dir(), case.dir.join("relative/here"));
    let read = PathBuf::from(&case.seen("run")["manifest"]);
    assert_eq!(read, case.dir.join("relative/here/manifest"));
    let manifest = case.manifest();
    let args = [
        OsStr::new("run"),
        OsStr::new("--archive"),
        archive.as_os_str(),
        OsStr::new("--manifest"),
        manifest.as_os_str(),
    ];
    let child = case
        .command(&args)
        .stdout(Stdio::piped())
        .spawn()
        .map(Launcher)
        .expect("campaign runs");
    let pid = child.id();
    let ended = case.ended(wait_output(child));
    ended.class(0, "counts");
    let name = ended
        .dir()
        .file_name()
        .expect("a name")
        .to_string_lossy()
        .into_owned();
    let parts: Vec<&str> = name.split('-').collect();
    assert_eq!(parts.len(), 3, "{name}");
    assert_eq!(
        (parts[0], parts[2]),
        ("local", pid.to_string().as_str()),
        "{name}"
    );
    assert!(parts[1].parse::<u64>().is_ok(), "{name}");
}

/// SIGTERM or SIGINT during the inspect form exits 5 at once, with the
/// worker's group, a forked member included, gone.
pub(crate) fn an_interruption_during_inspect_exits_5() {
    for (name, signal) in [("sigterm", libc::SIGTERM), ("sigint", libc::SIGINT)] {
        let case = Case::new(&format!("interrupted-{name}"));
        case.plan("inspect.action", "escape");
        let (archive, _) = archive();
        let manifest = case.manifest();
        let args = case.run_args(archive, &manifest, &[]);
        let child = case
            .command(&args)
            .stdout(Stdio::piped())
            .spawn()
            .map(Launcher)
            .expect("campaign runs");
        assert!(
            within(60, || case.dir.join("escapee").exists()),
            "the inspection forked"
        );
        let started = Instant::now();
        // SAFETY: `kill` takes integers.
        unsafe { libc::kill(i32::try_from(child.id()).expect("a pid"), signal) };
        let ended = case.ended(wait_output(child));
        assert_eq!(
            ended.class(5, "interrupted").reason.as_str(),
            format!("interrupted by signal {signal} during inspect")
        );
        let inspected = &ended.class(5, "interrupted").workers[&Text::new("inspect").expect("key")];
        assert_eq!(
            (inspected.ended.as_str(), inspected.exit, inspected.signal),
            ("interrupted", None, None)
        );
        assert!(started.elapsed() < Duration::from_secs(10), "{name}");
        let escapee = fs::read_to_string(case.dir.join("escapee")).expect("recorded");
        assert!(dead(escapee.trim()), "{name}: the forked member survived");
        assert!(dead(&case.seen("inspect")["pid"]), "{name}");
    }
}

pub(crate) fn setup_refusals_preserve_pending_signals_and_infrastructure_classes() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::os::unix::process::CommandExt;

    for (name, run_id) in [
        ("bad-id", "../bad"),
        ("existing", "taken"),
        ("phase", "fixed"),
    ] {
        let case = Case::new(&format!("setup-{name}"));
        fs::create_dir_all(case.dir.join("artifacts/taken")).expect("existing output");
        let (archive, _) = archive();
        let manifest = case.manifest();
        let extra = ["--run-id", run_id];
        let args = case.run_args(archive, &manifest, &extra);
        let mut command = case.command(&args);
        // SAFETY: the closure uses only signal-mask and process syscalls
        // before exec, with a writable local signal set.
        unsafe {
            command.pre_exec(|| {
                let mut set: libc::sigset_t = std::mem::zeroed();
                libc::sigemptyset(&raw mut set);
                libc::sigaddset(&raw mut set, libc::SIGTERM);
                let error =
                    libc::pthread_sigmask(libc::SIG_BLOCK, &raw const set, std::ptr::null_mut());
                if error != 0 {
                    return Err(std::io::Error::from_raw_os_error(error));
                }
                if libc::kill(libc::getpid(), libc::SIGTERM) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let output = output(command);
        assert_eq!(output.status.code(), Some(5), "{output:?}");
        if name != "phase" {
            assert!(String::from_utf8_lossy(&output.stderr).contains("interrupted by signal 15"));
        }
        assert!(case.calls().is_empty());
        assert!(!case.dir.join("artifacts/taken/artifact").exists());
        if name == "phase" {
            let ended = case.ended(output);
            ended.class(5, "interrupted");
            assert!(ended.reason().contains("before capabilities"));
        }
    }

    // A read of the launcher's own memory at offset 0 fails with EIO, a host
    // fault of the manifest read.
    let case = Case::new("setup-manifest-fault");
    let (archive, _) = archive();
    let faulted = Path::new("/proc/self/mem");
    let ended = case.ended(output(case.command(&case.run_args(archive, faulted, &[]))));
    ended.class(4, "incomplete");
    assert!(
        ended.reason().contains("the manifest cannot be read"),
        "{}",
        ended.reason()
    );
    assert!(case.calls().is_empty());

    if fs::metadata(scratch()).expect("scratch metadata").uid() == 0 {
        return;
    }
    let case = Case::new("failed-publication");
    let staging = case.dir.join("artifacts/fixed/.staging");
    case.plan("inspect.action", "readonly")
        .plan("rewrite.target", &staging.display().to_string());
    let ended = case.run(&["--run-id", "fixed"]);
    fs::set_permissions(&staging, fs::Permissions::from_mode(0o700)).expect("staging restored");
    assert_eq!(ended.code, Some(4));
    let printed: serde_json::Value = serde_json::from_str(ended.stdout.trim()).expect("result");
    assert_eq!(printed["class"], "incomplete");
    let reason = printed["reason"].as_str().expect("reason");
    assert!(
        reason.contains("inspect.stdout") && reason.contains("artifact record failed"),
        "{reason}"
    );
    assert!(ended.artifact.is_none());
    assert!(!case.dir.join("artifacts/fixed/artifact").exists());

    let case = Case::new("setup-infrastructure");
    let artifacts = case.dir.join("artifacts");
    fs::create_dir(&artifacts).expect("artifact parent");
    fs::set_permissions(&artifacts, fs::Permissions::from_mode(0o0)).expect("parent inaccessible");
    let ended = case.run(&["--run-id", "run"]);
    fs::set_permissions(&artifacts, fs::Permissions::from_mode(0o700)).expect("parent accessible");
    assert_eq!(ended.code, Some(4), "{} {}", ended.stdout, ended.stderr);
    assert!(ended.artifact.is_none());
    assert!(case.calls().is_empty());
}

pub(crate) fn the_runner_applies_each_skip() {
    let listed = |args: &[&str]| {
        let mut command = Command::new(std::env::current_exe().expect("test executable"));
        command.arg("--list").args(args).env_remove(PLAN);
        let output = output(command);
        assert!(output.status.success(), "{output:?}");
        String::from_utf8(output.stdout).expect("listing text")
    };
    let filtered = listed(&["--skip", "watchdog", "--skip", "inspect"]);
    assert!(
        !filtered.lines().any(|line| line.ends_with(": test")
            && (line.contains("watchdog") || line.contains("inspect")))
    );
    assert!(filtered.contains("counts_with_no_decision_is_incomplete: test"));
    let equal_form = listed(&["--skip=watchdog", "--skip=inspect"]);
    assert_eq!(equal_form, filtered);
    let exact = listed(&["--exact", "--skip", "watchdog"]);
    assert!(exact.contains("the_watchdog_kills_and_drains_the_group: test"));
    let exact = listed(&[
        "--exact",
        "--skip",
        "the_watchdog_kills_and_drains_the_group",
    ]);
    assert!(!exact.contains("the_watchdog_kills_and_drains_the_group: test"));
}

/// A command run from a directory whose absolute path is no UTF-8 text,
/// with the relative default artifacts directory, is refused with exit 2:
/// it prints that path as JSON text.
pub(crate) fn a_non_utf8_artifact_directory_is_refused() {
    use std::os::unix::ffi::OsStrExt;
    let case = Case::new("non-utf8");
    let here = case.dir.join(OsStr::from_bytes(b"bad\xff"));
    fs::create_dir(&here).expect("the directory is made");
    let (archive, _) = archive();
    let manifest = case.manifest();
    let mut command = Command::new(env!("CARGO_BIN_EXE_campaign"));
    command
        .arg("sim")
        .args(case.run_args(archive, &manifest, &[]))
        .current_dir(&here)
        .env(PLAN, &case.dir)
        .stdin(Stdio::null());
    let output = output(command);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let refusal = String::from_utf8_lossy(&output.stderr);
    assert!(
        refusal.contains("the artifact path must be UTF-8"),
        "{refusal}"
    );
    assert_eq!(case.calls(), Vec::<String>::new());
}

/// A launcher killed with SIGKILL takes its worker with it.
pub(crate) fn the_worker_dies_with_the_launcher() {
    let case = Case::new("orphaned");
    case.plan("run.action", "hang");
    let (archive, _) = archive();
    let manifest = case.manifest();
    let args = [
        OsStr::new("run"),
        OsStr::new("--archive"),
        archive.as_os_str(),
        OsStr::new("--manifest"),
        manifest.as_os_str(),
    ];
    let mut child = case
        .command(&args)
        .spawn()
        .map(Launcher)
        .expect("campaign runs");
    assert!(
        within(60, || case.dir.join("run.seen").exists()),
        "the run started"
    );
    child.kill().expect("the launcher is killed");
    wait_output(child);
    let pid = case.seen("run")["pid"].clone();
    assert!(
        within(10, || dead(&pid)),
        "the worker {pid} outlived its launcher"
    );
}

/// `sim inspect` stages a raw bundle, inspects the copy under its own
/// recorded manifest, and classes the summary.
pub(crate) fn inspect_classes_a_staged_bundle() {
    let case = Case::new("inspect");
    let (archive, _) = archive();
    let recorded = manifest(&[]);
    let raw = bundle(&recorded, 3);
    let source = case.dir.join("in.bundle");
    fs::write(&source, &raw).expect("the bundle is written");
    let ended = case.inspect(&source, archive);
    let artifact = ended.class(0, "counts");
    assert_eq!(case.calls(), ["capabilities", "inspect"]);
    assert_eq!(fs::read(ended.dir().join("input")).expect("staged"), raw);
    let frozen = fs::read_to_string(ended.dir().join("manifest")).expect("frozen");
    assert_eq!(frozen, format!("{recorded}cpu = unrecorded\n"));
    assert_eq!(artifact.bundle, Some(Digest::of(&raw)));
    let seen = case.seen("inspect");
    assert_eq!(Path::new(&seen["inspect"]), ended.dir().join("input"));
    assert_eq!(seen["inspect_digest"], Digest::of(&raw).to_string());
    for (name, printed, code, class) in [
        ("complete", summary(&VIOLATION), 1, "complete"),
        ("capped", summary(&CAPPED), 4, "incomplete"),
        ("malformed", "digest: wrong\n".to_owned(), 4, "incomplete"),
        (
            "one-decision",
            summary(&[("decisions: 61", "decisions: 1")]),
            0,
            "counts",
        ),
    ] {
        let case = Case::new(&format!("inspect-class-{name}"));
        let source = case.dir.join("in.bundle");
        fs::write(&source, bundle(&manifest(&[]), 1)).expect("bundle");
        case.plan("inspect.out", &printed);
        case.inspect(&source, archive).class(code, class);
        assert_eq!(case.calls(), ["capabilities", "inspect"]);
    }
}

/// A bundle pinning another build, one past its record maximum and one
/// without pins are refused before any worker; one the worker refuses,
/// or that changes while the worker runs, exits 4; SIGTERM exits 5.
/// `inspect` rejects schema version 1 with exit code 2.
pub(crate) fn inspect_refuses_foreign_oversized_and_changed_bundles() {
    let (archive, _) = archive();
    for (name, raw, reason) in [
        (
            "inspect-other-build",
            bundle(&manifest(&[]).replace("build = ", "build = 0"), 1),
            "the bundle pins build",
        ),
        (
            "inspect-over",
            bundle(&manifest(&[]).replace("records = 1000", "records = 8"), 100),
            "more than 8 records",
        ),
        ("inspect-bare", bundle("", 4), "pins no build"),
    ] {
        let case = Case::new(name);
        let source = case.dir.join("in.bundle");
        fs::write(&source, raw).expect("the bundle is written");
        let ended = case.inspect(&source, archive);
        ended.class(2, "rejected");
        assert!(
            ended.reason().contains(reason),
            "{name}: {}",
            ended.reason()
        );
        assert_eq!(case.calls(), Vec::<String>::new());
    }
    let case = Case::new("inspect-large-frozen-manifest");
    let source = case.dir.join("in.bundle");
    let mut large = manifest(&[])
        .replace("records = 1000", "records = 100000")
        .replace("bytes = 48000", "bytes = 4800000");
    large.push_str(&"x".repeat((1 << 20) - large.len() - 8));
    fs::write(&source, bundle(&large, 1)).expect("large manifest bundle");
    let ended = case.inspect(&source, archive);
    ended.class(2, "rejected");
    assert!(
        ended
            .reason()
            .contains("frozen manifest exceeds its byte bound")
    );
    assert!(case.calls().is_empty());
    let case = Case::new("inspect-old-version");
    let source = case.dir.join("in.bundle");
    let old = manifest(&[]).replace("version = 2", "version = 1");
    fs::write(&source, bundle(&old, 1)).expect("the bundle is written");
    let ended = case.inspect(&source, archive);
    ended.class(2, "rejected");
    assert!(
        ended.reason().contains("the bundle names version"),
        "{}",
        ended.reason()
    );
    assert_eq!(case.calls(), ["capabilities"]);
    let case = Case::new("inspect-refused");
    let source = case.dir.join("in.bundle");
    fs::write(&source, bundle(&manifest(&[]), 1)).expect("the bundle is written");
    case.plan("inspect.exit", "2");
    case.inspect(&source, archive).class(4, "incomplete");
    let case = Case::new("inspect-changed");
    let source = case.dir.join("in.bundle");
    fs::write(&source, bundle(&manifest(&[]), 1)).expect("the bundle is written");
    case.plan("inspect.action", "rewrite")
        .plan("rewrite.target", &source.display().to_string());
    let ended = case.inspect(&source, archive);
    ended.class(4, "incomplete");
    assert!(
        ended.reason().contains("changed after admission"),
        "{}",
        ended.reason()
    );
    for (name, action, target, reason) in [
        (
            "staged-replaced",
            "replace",
            "artifacts/run/input",
            "frozen bundle changed",
        ),
        (
            "source-removed",
            "remove",
            "in.bundle",
            "cannot be read after",
        ),
        (
            "source-grown",
            "grow",
            "in.bundle",
            "changed after admission",
        ),
    ] {
        let case = Case::new(&format!("inspect-{name}"));
        let source = case.dir.join("in.bundle");
        fs::write(&source, bundle(&manifest(&[]), 1)).expect("bundle");
        case.plan("inspect.action", action).plan(
            "rewrite.target",
            &case.dir.join(target).display().to_string(),
        );
        let ended = case.inspect(&source, archive);
        ended.class(4, "incomplete");
        assert!(ended.reason().contains(reason), "{}", ended.reason());
        assert_eq!(case.calls(), ["capabilities", "inspect"]);
    }
    let case = Case::new("inspect-manifest-watchdog");
    let source = case.dir.join("in.bundle");
    fs::write(&source, bundle(&manifest(&["watchdog = 1"]), 1)).expect("bundle");
    case.plan("inspect.action", "hang");
    let ended = case.inspect(&source, archive);
    ended.class(6, "watchdog");
    assert!(ended.reason().contains("1s watchdog"), "{}", ended.reason());
    let case = Case::new("inspect-interrupted");
    let source = case.dir.join("in.bundle");
    fs::write(&source, bundle(&manifest(&[]), 1)).expect("the bundle is written");
    case.plan("inspect.action", "hang");
    let args = [
        OsStr::new("inspect"),
        source.as_os_str(),
        OsStr::new("--archive"),
        archive.as_os_str(),
    ];
    let child = case
        .command(&args)
        .stdout(Stdio::piped())
        .spawn()
        .map(Launcher)
        .expect("campaign runs");
    assert!(
        within(60, || case.dir.join("inspect.seen").exists()),
        "the inspection started"
    );
    // SAFETY: `kill` takes integers.
    unsafe { libc::kill(i32::try_from(child.id()).expect("a pid"), libc::SIGTERM) };
    case.ended(wait_output(child)).class(5, "interrupted");
}

fn triage_case(name: &str, failure: bool) -> (Case, PathBuf) {
    let case = Case::new(name);
    // The triage plan names phases from their input and output paths.
    case.plan("triage", "");
    let source = case.dir.join("source.bundle");
    let mut raw = bundle(&manifest(&[]), 2);
    if failure {
        let mut record = [0; 48];
        record[0] = 7;
        record[4] = 1;
        raw.extend_from_slice(&record);
        let summary = failing_summary();
        for phase in [
            "inspect-original",
            "inspect-baseline",
            "inspect-candidate",
            "inspect-candidate-replay",
            "inspect-replay",
        ] {
            case.plan(&format!("{phase}.out"), &summary);
        }
    }
    fs::write(&source, raw).expect("the source is written");
    (case, source)
}
fn failing_summary() -> String {
    format!(
        "{}cause: violation, violating Bytes\nidentity: {}\n",
        COUNTING
            .replace("complete pass", "complete violation")
            .replace("counts: true", "counts: false"),
        "ab".repeat(44)
    )
}
fn triage_command(case: &Case, source: &Path, form: &str) -> Command {
    triage_named(case, source, form, "triage")
}
fn triage_named(case: &Case, source: &Path, form: &str, id: &str) -> Command {
    let mut args = vec![
        OsStr::new(form),
        source.as_os_str(),
        OsStr::new("--archive"),
        archive().0.as_os_str(),
        OsStr::new("--run-id"),
        OsStr::new(id),
    ];
    let output = case.dir.join("reduction");
    if form == "reduce" {
        args.extend([OsStr::new("--output"), output.as_os_str()]);
    }
    case.command(&args)
}
pub(crate) fn capabilities_list_the_verified_worker_contract() {
    let case = Case::new("capability-command");
    let ended = case.ended(self::output(case.command(&[
        OsStr::new("capabilities"),
        OsStr::new("--archive"),
        archive().0.as_os_str(),
    ])));
    let record = ended.class(0, "counts");
    assert_eq!(case.calls(), ["capabilities"]);
    assert_eq!(
        record.archive_path.as_ref().expect("a path").as_str(),
        archive().0.to_str().expect("UTF-8")
    );
    let line: serde_json::Value = serde_json::from_str(ended.stdout.trim()).expect("JSON");
    assert_eq!(line["capabilities"].as_str(), Some(LISTING));
    assert!(
        ended
            .reason()
            .starts_with("capabilities 2, manifest 2, summary 1, "),
        "{}",
        ended.reason()
    );
}
pub(crate) fn fresh_replay_preserves_the_frozen_failure() {
    let (case, source) = triage_case("reproduced-failure", true);
    let before = fs::read(&source).expect("source");
    let ended = case.ended(self::output(triage_command(&case, &source, "replay")));
    let record = ended.class(1, "complete");
    let compared = record.comparison.as_ref().expect("comparison");
    assert_eq!(compared.status.as_str(), "reproduced");
    assert_eq!(compared.original, compared.observed);
    assert!(
        compared
            .original
            .as_ref()
            .expect("original")
            .first_failure
            .is_some()
    );
    assert_eq!(fs::read(&source).expect("source"), before);
    assert_eq!(
        case.calls(),
        [
            "capabilities",
            "inspect-original",
            "replay",
            "inspect-replay"
        ]
    );
    let pids: Vec<_> = case
        .calls()
        .iter()
        .map(|phase| case.seen(phase)["pid"].clone())
        .collect();
    assert_eq!(
        pids.iter().collect::<std::collections::BTreeSet<_>>().len(),
        4
    );
}
pub(crate) fn replay_records_the_first_semantic_divergence() {
    let (case, source) = triage_case("semantic-divergence", false);
    let mut raw = fs::read(&source).expect("source");
    // The first of two TURN records stores virtual time in bytes 4..12.
    let at = raw.len() - 96;
    raw[at + 4..at + 12].copy_from_slice(&734u64.to_le_bytes());
    raw[at + 48 + 4..at + 48 + 12].copy_from_slice(&900u64.to_le_bytes());
    fs::write(case.dir.join("replay.bundle"), raw).expect("a changed replay");
    let ended = case.ended(self::output(triage_command(&case, &source, "replay")));
    let record = ended.class(1, "complete");
    let compared = record.comparison.as_ref().expect("comparison");
    assert_eq!(compared.status.as_str(), "diverged");
    let diff = compared.divergence.as_ref().expect("first difference");
    let committed = diff.committed.as_ref().expect("committed");
    assert_eq!(committed.semantic_record, (at / 48) as u64);
    assert_eq!(committed.virtual_us, Some(0));
    assert_eq!(
        committed.record.as_str(),
        "040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    );
    let replayed = diff.replayed.as_ref().expect("replayed");
    assert_eq!(replayed.virtual_us, Some(734));
    assert!(replayed.node.is_none() && replayed.operation.is_none());
    assert_eq!(replayed.semantic_record, (at / 48) as u64);
    let bytes =
        fs::read(compared.output.as_ref().expect("output").as_str()).expect("replayed file");
    assert_eq!(compared.candidate, Some(Digest::of(&bytes)));
    assert_ne!(compared.candidate, record.bundle);
}
pub(crate) fn replay_result_and_summary_disagreements_remain_distinct() {
    for (name, summary, line, exit, status, class) in [
        (
            "intact-cap",
            summary(&CAPPED),
            "replay: diverged at the result: cap\n",
            "1",
            "diverged",
            1,
        ),
        (
            "intact-defect",
            summary(&CAPPED)
                .replace("infrastructure cap", "infrastructure defect")
                .replace("cause: cap", "cause: defect"),
            "replay: diverged at the result: defect\n",
            "1",
            "diverged",
            1,
        ),
        (
            "passing-rerun",
            COUNTING.to_owned(),
            "replay: diverged at the result: changed\n",
            "1",
            "unreproduced",
            1,
        ),
        (
            "different-identity",
            failing_summary().replace(&"ab".repeat(44), &"cd".repeat(44)),
            "replay: reproduced, complete violation fired=03 required=03, violating Bytes\n",
            "0",
            "diverged",
            1,
        ),
        (
            "different-digest",
            failing_summary().replace(
                COUNTING
                    .lines()
                    .next()
                    .expect("digest")
                    .strip_prefix("digest: ")
                    .expect("digest value"),
                &"cd".repeat(32),
            ),
            "replay: reproduced, complete violation fired=03 required=03, violating Bytes\n",
            "0",
            "diverged",
            1,
        ),
        (
            "fresh-replay-panicked",
            truncated_summary(),
            "replay: the run panicked at src/x.rs:1:1: boom\n",
            "1",
            "diverged",
            1,
        ),
        (
            "panic-line-with-complete-bundle",
            failing_summary(),
            "replay: the run panicked at src/x.rs:1:1: boom\n",
            "1",
            "incomplete",
            4,
        ),
        (
            "contradictory-terminal",
            failing_summary(),
            "replay: reproduced, complete pass fired=03 required=03\n",
            "0",
            "incomplete",
            4,
        ),
        (
            "contradictory-breach",
            failing_summary(),
            "replay: reproduced, complete violation fired=03 required=03, violating Restart\n",
            "0",
            "incomplete",
            4,
        ),
        (
            "matching-claim-exit-one",
            failing_summary(),
            "replay: reproduced, complete violation fired=03 required=03, violating Bytes\n",
            "1",
            "incomplete",
            4,
        ),
        (
            "matching-claim-exit-three",
            failing_summary(),
            "replay: reproduced, complete violation fired=03 required=03, violating Bytes\n",
            "3",
            "incomplete",
            4,
        ),
        (
            "truncated-fresh",
            truncated_summary(),
            "replay: diverged at the result: truncated\n",
            "1",
            "incomplete",
            4,
        ),
        (
            "missing-result",
            failing_summary(),
            "",
            "0",
            "incomplete",
            4,
        ),
        (
            "exit-disagreement",
            failing_summary(),
            "replay: diverged at the result: changed\n",
            "0",
            "incomplete",
            4,
        ),
        ("refused-replay", failing_summary(), "", "2", "rejected", 2),
        ("failed-replay", failing_summary(), "", "3", "incomplete", 4),
    ] {
        let (case, source) = triage_case(name, true);
        case.plan("replay.out", line)
            .plan("replay.exit", exit)
            .plan("inspect-replay.out", &summary);
        let ended = case.ended(self::output(triage_command(&case, &source, "replay")));
        let record = ended.class(
            class,
            if class == 1 {
                "complete"
            } else if class == 2 {
                "rejected"
            } else {
                "incomplete"
            },
        );
        assert_eq!(
            record
                .comparison
                .as_ref()
                .expect("comparison")
                .status
                .as_str(),
            status,
            "{name}: {}",
            ended.reason()
        );
    }
}
pub(crate) fn reduction_accepts_only_equal_full_failure_identity() {
    for (name, summary, status, class) in [
        ("equal-candidate", failing_summary(), "reduced", 1),
        (
            "other-candidate",
            failing_summary().replace(
                &"ab".repeat(44),
                &"ab"
                    .repeat(43)
                    .chars()
                    .chain("cd".chars())
                    .collect::<String>(),
            ),
            "diverged",
            1,
        ),
        ("passing-candidate", COUNTING.to_owned(), "unreproduced", 1),
        ("capped-candidate", summary(&CAPPED), "diverged", 1),
        ("torn-candidate", "summary: 1\n".to_owned(), "incomplete", 4),
    ] {
        let (case, source) = triage_case(name, true);
        case.plan("inspect-candidate.out", &summary)
            .plan("inspect-candidate-replay.out", &summary);
        if status == "reduced" {
            let mut raw = bundle(
                &manifest(&[]).replace("scenario = ab", "scenario = reduced"),
                1,
            );
            let mut failure = [0; 48];
            failure[0] = 7;
            failure[4] = 1;
            raw.extend_from_slice(&failure);
            fs::write(case.dir.join("reduce.bundle"), raw)
                .expect("the candidate changes its manifest");
        }
        if status == "reduced" {
            let candidate = fs::read(case.dir.join("reduce.bundle"))
                .unwrap_or_else(|_| fs::read(&source).expect("original"));
            let mut again = candidate.clone();
            let mut diagnostic = [0; 48];
            diagnostic[0] = 10;
            again.extend_from_slice(&diagnostic);
            fs::write(case.dir.join("candidate-replay.bundle"), again)
                .expect("independent replay bytes");
        }

        let ended = case.ended(self::output(triage_command(&case, &source, "reduce")));
        let record = ended.class(class, if class == 1 { "complete" } else { "incomplete" });
        let comparison = record.comparison.as_ref().expect("comparison");
        assert_eq!(
            comparison.status.as_str(),
            status,
            "{name}: {}",
            ended.reason()
        );
        assert_eq!(
            comparison.failure_kind.as_ref().expect("kind").as_str(),
            "violation"
        );
        assert_eq!(
            comparison
                .failure_identity
                .as_ref()
                .expect("identity")
                .as_str(),
            "ab".repeat(44)
        );
        if status == "reduced" {
            let output = comparison.output.as_ref().expect("output");
            let raw = fs::read(output.as_str()).expect("retained candidate");
            assert_eq!(comparison.candidate, Some(Digest::of(&raw)));
            assert_ne!(
                comparison.candidate,
                Some(Digest::of(
                    &fs::read(case.dir.join("candidate-replay.bundle")).expect("replayed")
                ))
            );
            assert_eq!(record.summary, comparison.original);
            assert!(case.calls().iter().any(|phase| phase == "candidate-replay"));
            let calls = case.calls();
            let again = self::output(triage_named(&case, &source, "reduce", "other"));
            let again = case.ended(again);
            again.class(2, "rejected");
            assert!(again.reason().contains("the reduction output is refused"));
            assert_eq!(case.calls(), calls);
        }
    }
}
pub(crate) fn frozen_inputs_are_checked_around_each_triage_phase() {
    for phase in [
        "capabilities",
        "inspect-original",
        "baseline",
        "inspect-baseline",
        "reduce",
        "inspect-candidate",
        "candidate-replay",
        "inspect-candidate-replay",
    ] {
        let (case, source) = triage_case(&format!("triage-changed-{phase}"), true);
        case.plan(&format!("{phase}.action"), "rewrite")
            .plan("rewrite.target", source.to_str().expect("UTF-8"));
        let ended = case.ended(self::output(triage_command(&case, &source, "reduce")));
        ended.class(4, "incomplete");
        assert_eq!(case.calls().last().map(String::as_str), Some(phase));
        assert!(
            ended.reason().contains("changed after admission"),
            "{phase}: {}",
            ended.reason()
        );
    }
    for (phase, target) in [
        ("inspect-baseline", "baseline.manifest"),
        ("inspect-candidate", "candidate.manifest"),
    ] {
        let (case, source) = triage_case(&format!("triage-manifest-{phase}"), true);
        case.plan(&format!("{phase}.action"), "replace").plan(
            "rewrite.target",
            case.dir
                .join("artifacts/triage")
                .join(target)
                .to_str()
                .expect("UTF-8"),
        );
        let ended = case.ended(self::output(triage_command(&case, &source, "reduce")));
        ended.class(4, "incomplete");
        assert!(ended.reason().contains("changed after admission"));
        assert_eq!(case.calls().last().map(String::as_str), Some(phase));
    }
}
pub(crate) fn replay_from_run_verifies_the_record_and_archive_before_workers() {
    let case = Case::new("from-run");
    let original = case.run(&["--run-id", "original"]);
    original.class(0, "counts");
    case.plan("triage", "");
    let run = case.dir.join("artifacts/original");
    let args = [
        OsStr::new("replay"),
        OsStr::new("--from-run"),
        run.as_os_str(),
        OsStr::new("--run-id"),
        OsStr::new("from-run"),
    ];
    let ended = case.ended(self::output(case.command(&args)));
    ended.class(0, "counts");
    let comparison = ended
        .artifact
        .as_ref()
        .expect("artifact")
        .1
        .comparison
        .as_ref()
        .expect("comparison");
    assert_eq!(comparison.status.as_str(), "reproduced");
    let calls = case.calls();
    fs::write(run.join("artifact"), b"held").expect("corruption");
    let mut args = args;
    args[4] = OsStr::new("held");
    case.ended(self::output(case.command(&args)))
        .class(2, "rejected");
    assert_eq!(case.calls(), calls);
}
pub(crate) fn replay_from_run_reproduces_a_summary_recorded_without_its_rule() {
    let case = Case::new("from-run-ruleless");
    let named = summary(&[
        ("complete pass", "complete unsuccessful"),
        ("counts: true", "counts: false"),
    ]) + "cause: unsuccessful\nunsuccessful: old read held\n";
    case.plan("run.out", &named)
        .plan("run.exit", "1")
        .plan("inspect.out", &named);
    let original = case.run(&["--run-id", "original"]);
    let recorded = original.class(1, "complete").summary.clone();
    let rule = |summary: &Option<campaign_supervisor::record::Summarized>| {
        let summary = summary.as_ref().expect("a summary");
        summary
            .unsuccessful
            .as_ref()
            .map(|rule| rule.as_str().to_owned())
    };
    assert_eq!(rule(&recorded).as_deref(), Some("old read held"));
    let run = case.dir.join("artifacts/original");
    case.plan("triage", "")
        .plan("inspect-original.out", &named)
        .plan("inspect-replay.out", &named);
    let replay = |id: &str| {
        let args = [
            OsStr::new("replay"),
            OsStr::new("--from-run"),
            run.as_os_str(),
            OsStr::new("--run-id"),
            OsStr::new(id),
        ];
        let ended = case.ended(self::output(case.command(&args)));
        let comparison = ended
            .class(1, "complete")
            .comparison
            .clone()
            .expect("comparison");
        assert_eq!(
            comparison.status.as_str(),
            "reproduced",
            "{id}: {}",
            ended.reason()
        );
        assert_eq!(comparison.observed, comparison.original, "{id}");
        assert_eq!(
            comparison.original.as_ref().map(|summary| summary.digest),
            recorded.as_ref().map(|summary| summary.digest),
            "{id}"
        );
        comparison
    };
    // A recorded rule stays in the comparison.
    assert_eq!(
        rule(&replay("kept").original).as_deref(),
        Some("old read held")
    );
    rewrite_artifact(&run, |record| {
        let summary = record["summary"]
            .as_object_mut()
            .expect("the run records its summary");
        summary.remove("unsuccessful").expect("the recorded rule");
    });
    assert_eq!(rule(&replay("replayed").original), None);
}
pub(crate) fn altered_triage_archives_start_no_worker() {
    for form in ["replay", "reduce", "capabilities"] {
        let (case, source) = triage_case(&format!("refused-{form}-archive"), true);
        let copy = case.dir.join("archive");
        copy_tree(&archive().0, &copy);
        let library = first_library(&copy);
        fs::set_permissions(
            &library,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .expect("writable library");
        fs::write(library, b"changed").expect("archive tampered");
        let output = case.dir.join("regression");
        let mut args = vec![OsStr::new(form)];
        if form != "capabilities" {
            args.push(source.as_os_str());
        }
        args.extend([OsStr::new("--archive"), copy.as_os_str()]);
        if form == "reduce" {
            args.extend([OsStr::new("--output"), output.as_os_str()]);
        }
        let ended = case.ended(self::output(case.command(&args)));
        ended.class(2, "rejected");
        assert!(case.calls().is_empty());
    }
}

pub(crate) fn every_replay_fact_has_a_divergence_oracle() {
    let original = failing_summary();
    let digest = COUNTING
        .lines()
        .next()
        .expect("digest")
        .strip_prefix("digest: ")
        .expect("digest value");
    for (name, changed) in [
        ("only-digest", original.replace(digest, &"cd".repeat(32))),
        (
            "only-decisions",
            original.replace("decisions: 61", "decisions: 62"),
        ),
        ("only-terminal", original.replace("fired=03", "fired=07")),
        (
            "only-cause",
            original.replace("violating Bytes", "violating Restart"),
        ),
        (
            "only-virtual-time",
            original.replace("virtual_us: 600", "virtual_us: 601"),
        ),
    ] {
        let (case, source) = triage_case(name, true);
        case.plan("inspect-replay.out", &changed);
        let ended = case.ended(self::output(triage_command(&case, &source, "replay")));
        let compared = ended
            .class(1, "complete")
            .comparison
            .as_ref()
            .expect("comparison");
        assert_eq!(compared.status.as_str(), "diverged");
        assert!(compared.divergence.is_none());
        if name == "only-virtual-time" {
            let dir = &ended.artifact.as_ref().expect("artifact").0;
            assert!(
                fs::read_to_string(dir.join("inspect-replay.stdout"))
                    .expect("phase output")
                    .contains("virtual_us: 601\n")
            );
        } else {
            assert_ne!(compared.original, compared.observed);
        }
    }
}
pub(crate) fn the_candidate_must_reproduce_in_an_independent_process() {
    for (name, line, exit, changed) in [
        (
            "candidate-diverged",
            "replay: diverged at semantic record 3: changed\n",
            "1",
            failing_summary(),
        ),
        (
            "candidate-identity-drift",
            "replay: reproduced, complete violation fired=03 required=03, violating Bytes\n",
            "0",
            failing_summary().replace(&"ab".repeat(44), &"cd".repeat(44)),
        ),
    ] {
        let (case, source) = triage_case(name, true);
        case.plan("candidate-replay.out", line)
            .plan("candidate-replay.exit", exit)
            .plan("inspect-candidate-replay.out", &changed);
        let ended = case.ended(self::output(triage_command(&case, &source, "reduce")));
        assert_eq!(
            ended
                .class(1, "complete")
                .comparison
                .as_ref()
                .expect("comparison")
                .status
                .as_str(),
            "diverged"
        );
        assert_eq!(
            case.calls().last().map(String::as_str),
            Some("inspect-candidate-replay")
        );
    }
    let (case, source) = triage_case("candidate-refused", true);
    case.plan("candidate-replay.exit", "2")
        .plan("candidate-replay.nobundle", "");
    let ended = case.ended(self::output(triage_command(&case, &source, "reduce")));
    ended.class(4, "incomplete");
    assert!(
        ended.reason().contains("worker refused replay"),
        "{}",
        ended.reason()
    );
    assert_eq!(
        case.calls().last().map(String::as_str),
        Some("candidate-replay")
    );
}
fn truncated_summary() -> String {
    COUNTING
        .replace(
            "complete pass fired=03 required=03",
            "infrastructure truncated",
        )
        .replace("counts: true", "counts: false")
        .replace("decisions: 61", "decisions: unavailable")
        .replace("turns: 57", "turns: unavailable")
        .replace("progress: 10", "progress: unavailable")
        .replace("virtual_us: 600", "virtual_us: unavailable")
        .replace("skipped_us: 0", "skipped_us: unavailable")
        + "cause: truncated\n"
}
pub(crate) fn panic_reduction_keeps_the_location_payload_and_bundle() {
    for (name, output, exit, status, class, rewrite) in [
        (
            "panic-equal",
            "run: the run panicked at src/x.rs:1:1: boom\n".to_owned(),
            "3",
            "reduced",
            1,
            false,
        ),
        (
            "panic-payload",
            "run: the run panicked at src/x.rs:1:1: other\n".to_owned(),
            "3",
            "diverged",
            1,
            false,
        ),
        (
            "panic-location",
            "run: the run panicked at src/y.rs:1:1: boom\n".to_owned(),
            "3",
            "diverged",
            1,
            false,
        ),
        (
            "panic-passes",
            COUNTING.to_owned(),
            "0",
            "unreproduced",
            1,
            false,
        ),
        (
            "panic-torn",
            "run: the run panicked".to_owned(),
            "3",
            "incomplete",
            4,
            false,
        ),
        (
            "panic-bundle",
            "run: the run panicked at src/x.rs:1:1: boom\n".to_owned(),
            "3",
            "diverged",
            1,
            true,
        ),
    ] {
        let (case, source) = triage_case(name, false);
        case.plan("inspect-original.out", &truncated_summary())
            .plan(
                "panic-original.out",
                "run: the run panicked at src/x.rs:1:1: boom\n",
            )
            .plan("panic-original.exit", "3")
            .plan("panic-candidate.out", &output)
            .plan("panic-candidate.exit", exit);
        if status == "reduced" {
            let candidate = bundle(
                &manifest(&[]).replace("scenario = ab", "scenario = reduced"),
                2,
            );
            fs::write(case.dir.join("reduce.bundle"), &candidate)
                .expect("candidate manifest changes");
        }
        if rewrite {
            fs::write(
                case.dir.join("panic-candidate.bundle"),
                bundle(&manifest(&[]), 1),
            )
            .expect("a differing rerun bundle");
        }
        let ended = case.ended(self::output(triage_command(&case, &source, "reduce")));
        let compared = ended
            .class(class, if class == 1 { "complete" } else { "incomplete" })
            .comparison
            .as_ref()
            .expect("comparison");
        assert_eq!(
            compared.status.as_str(),
            status,
            "{name}: {}",
            ended.reason()
        );
        if status == "reduced" {
            let bytes = fs::read(compared.output.as_ref().expect("output").as_str())
                .expect("candidate file");
            assert_eq!(compared.candidate, Some(Digest::of(&bytes)));
            assert_ne!(
                compared.candidate,
                Some(Digest::of(&fs::read(&source).expect("original")))
            );
        }
        if rewrite {
            let difference = compared
                .divergence
                .as_ref()
                .expect("retained panic difference");
            assert!(difference.committed.is_some());
            assert!(difference.replayed.is_none());
            assert!(compared.observed.is_some());
        }
        assert_eq!(
            compared.failure_kind.as_ref().expect("kind").as_str(),
            "panic"
        );
        assert_eq!(
            compared
                .failure_identity
                .as_ref()
                .expect("identity")
                .as_str(),
            "src/x.rs:1:1: boom"
        );
    }
}
pub(crate) fn unreducible_inputs_and_passing_reruns_have_distinct_statuses() {
    let no_identity = failing_summary().replace(&format!("identity: {}\n", "ab".repeat(44)), "");
    for (name, form, reduced_exit, original, observed, status) in [
        (
            "missing-reduction-identity",
            "reduce",
            "0",
            no_identity.clone(),
            no_identity.clone(),
            "unreducible",
        ),
        (
            "worker-unreducible",
            "reduce",
            "1",
            failing_summary(),
            failing_summary(),
            "unreducible",
        ),
        (
            "missing-identity-passes",
            "replay",
            "0",
            no_identity.clone(),
            COUNTING.to_owned(),
            "unreproduced",
        ),
        (
            "missing-identity-reproduces",
            "replay",
            "0",
            no_identity.clone(),
            no_identity,
            "reproduced",
        ),
    ] {
        let (case, source) = triage_case(name, true);
        case.plan("inspect-original.out", &original)
            .plan("inspect-baseline.out", &original)
            .plan("inspect-replay.out", &observed)
            .plan("reduce.exit", reduced_exit);
        if reduced_exit == "1" {
            case.plan("reduce.nobundle", "").plan("reduce.out", "");
        }
        let ended = case.ended(self::output(triage_command(&case, &source, form)));
        let comparison = ended
            .class(1, "complete")
            .comparison
            .clone()
            .expect("comparison");
        assert_eq!(
            comparison.status.as_str(),
            status,
            "{name}: {}",
            ended.reason()
        );
        if status == "unreducible" {
            assert!(!case.dir.join("reduction/regression.bundle").exists());
            assert_eq!(
                comparison.output, None,
                "{name} names a candidate it never wrote"
            );
            assert_eq!(comparison.candidate, None);
        }
    }
}
pub(crate) fn a_disappearing_replay_input_is_incomplete() {
    let (case, source) = triage_case("unreadable-replay", true);
    case.plan("replay.action", "remove")
        .plan("rewrite.target", source.to_str().expect("UTF-8"));
    let ended = case.ended(self::output(triage_command(&case, &source, "replay")));
    ended.class(4, "incomplete");
    assert!(!source.exists());
    assert_eq!(case.calls().last().map(String::as_str), Some("replay"));
}
pub(crate) fn relative_reduction_paths_resolve_against_the_caller() {
    let (case, source) = triage_case("relative-reduction", true);
    let args = [
        OsStr::new("reduce"),
        source.file_name().expect("a name"),
        OsStr::new("--archive"),
        archive().0.as_os_str(),
        OsStr::new("--output"),
        OsStr::new("relative"),
        OsStr::new("--run-id"),
        OsStr::new("relative"),
    ];
    let ended = case.ended({
        let mut command = case.command(&args);
        command.current_dir(&case.dir);
        output(command)
    });
    assert_eq!(
        ended
            .class(1, "complete")
            .comparison
            .as_ref()
            .expect("comparison")
            .status
            .as_str(),
        "reduced"
    );
    assert!(case.dir.join("relative/regression.bundle").is_file());
    let output = ended
        .artifact
        .as_ref()
        .expect("artifact")
        .1
        .comparison
        .as_ref()
        .expect("comparison")
        .output
        .as_ref()
        .expect("output");
    assert_eq!(
        output.as_str(),
        case.dir
            .canonicalize()
            .expect("canonical")
            .join("relative/regression.bundle")
            .to_str()
            .expect("UTF-8")
    );
}

fn replace_artifact(path: &Path, update: impl FnOnce(&mut Artifact)) {
    rewrite_artifact(path, |record| {
        let mut artifact: Artifact =
            serde_json::from_value(record.take()).expect("the record decodes");
        update(&mut artifact);
        *record = serde_json::to_value(artifact).expect("the record encodes");
    });
}

fn rewrite_artifact(path: &Path, update: impl FnOnce(&mut serde_json::Value)) {
    let store = campaign_supervisor::store::Store::open(path).expect("store opens");
    let name = Name::new("artifact").expect("name");
    let record = store
        .read_record::<Artifact>(store.root(), &name)
        .expect("verified")
        .expect("artifact")
        .record()
        .clone();
    let mut record = serde_json::to_value(record).expect("the record encodes");
    update(&mut record);
    let mut core = serde_json::json!({"format": 1, "kind": "artifact", "record": record});
    let digest = Digest::of(&serde_json::to_vec(&core).expect("core encodes"));
    core["sha256"] = serde_json::json!(digest);
    store
        .replace(
            store.root(),
            &name,
            &serde_json::to_vec(&core).expect("envelope encodes"),
        )
        .expect("record replaced");
}
pub(crate) fn replay_from_run_checks_every_frozen_binding() {
    for fault in [
        "manifest",
        "bundle",
        "bundle-symlink",
        "run-id",
        "archive-id",
        "archive-bytes",
        "archive-path",
        "omitted-options",
        "summary",
        "comparison-original",
        "capabilities",
    ] {
        let case = Case::new(&format!("from-run-{fault}"));
        let copy = case.dir.join("archive");
        copy_tree(&archive().0, &copy);
        let manifest = case.manifest();
        let args = case.run_args(&copy, &manifest, &["--run-id", "original"]);
        case.ended(self::output(case.command(&args)))
            .class(0, "counts");
        let run = case.dir.join("artifacts/original");
        let calls = case.calls();
        match fault {
            "archive-path" => replace_artifact(&run, |record| record.archive_path = None),
            "omitted-options" => rewrite_artifact(&run, |record| {
                let record = record.as_object_mut().expect("the record is an object");
                for key in ["archive_path", "comparison"] {
                    record.remove(key);
                }
                let summary = record["summary"]
                    .as_object_mut()
                    .expect("the run records its summary");
                for key in ["cause", "first_failure", "identity"] {
                    summary.remove(key);
                }
            }),
            "summary" => replace_artifact(&run, |record| record.summary = None),
            "comparison-original" => replace_artifact(&run, |record| {
                record.command = Text::new("reduce").expect("text")
            }),
            "capabilities" => replace_artifact(&run, |record| {
                record.command = Text::new("capabilities").expect("text")
            }),
            "manifest" => fs::write(run.join(fault), b"changed").expect("manifest changed"),
            "bundle" => fs::write(run.join(fault), bundle(&self::manifest(&[]), 3))
                .expect("valid changed bundle"),
            "bundle-symlink" => {
                fs::rename(run.join("bundle"), run.join("bundle.real")).expect("saved bundle");
                std::os::unix::fs::symlink("bundle.real", run.join("bundle")).expect("symlink");
            }
            "run-id" => replace_artifact(&run, |record| {
                record.run_id = Text::new("another").expect("text")
            }),
            "archive-id" => replace_artifact(&run, |record| {
                record.archive = Some(Digest::of(b"another archive"))
            }),
            "archive-bytes" => {
                let library = first_library(&copy);
                fs::set_permissions(
                    &library,
                    std::os::unix::fs::PermissionsExt::from_mode(0o600),
                )
                .expect("writable");
                fs::write(library, b"changed").expect("library changed");
            }
            _ => unreachable!(),
        }
        let args = [
            OsStr::new("replay"),
            OsStr::new("--from-run"),
            run.as_os_str(),
            OsStr::new("--run-id"),
            OsStr::new("replayed"),
        ];
        let ended = case.ended(self::output(case.command(&args)));
        ended.class(2, "rejected");
        let reason = match fault {
            "archive-path" | "omitted-options" => "the run records no archive path",
            "summary" | "comparison-original" => "the run records no original summary",
            "capabilities" => "the artifact records no replayable command",
            "manifest" => "the run manifest differs from the artifact",
            "bundle" => "the frozen bundle differs from the recorded run",
            "bundle-symlink" => "the run bundle is refused",
            "run-id" => "the artifact names another run id",
            "archive-id" => "the archive differs from the recorded run",
            "archive-bytes" => "the archive is refused",
            _ => unreachable!(),
        };
        assert!(
            ended.reason().contains(reason),
            "{fault}: {}",
            ended.reason()
        );
        assert_eq!(case.calls(), calls, "{fault}");
    }
}
pub(crate) fn replay_of_a_reduction_uses_its_original_frozen_summary() {
    let (case, source) = triage_case("replay-reduction-record", true);
    let observed = failing_summary().replace("decisions: 61", "decisions: 62");
    case.plan("inspect-candidate.out", &observed)
        .plan("inspect-candidate-replay.out", &observed);
    let reduced = case.ended(self::output(triage_command(&case, &source, "reduce")));
    let record = reduced.class(1, "complete");
    assert_eq!(
        record.summary.as_ref(),
        record
            .comparison
            .as_ref()
            .expect("comparison")
            .original
            .as_ref()
    );
    let run = case.dir.join("artifacts/triage");
    let args = [
        OsStr::new("replay"),
        OsStr::new("--from-run"),
        run.as_os_str(),
        OsStr::new("--run-id"),
        OsStr::new("replayed"),
    ];
    let replayed = case.ended(self::output(case.command(&args)));
    assert_eq!(
        replayed
            .class(1, "complete")
            .comparison
            .as_ref()
            .expect("comparison")
            .status
            .as_str(),
        "reproduced"
    );
}

pub(crate) fn incomplete_reductions_keep_their_class() {
    for (name, original) in [
        (
            "zero-decision-reduction",
            COUNTING.replace("decisions: 61", "decisions: 0"),
        ),
        ("infrastructure-reduction", summary(&CAPPED)),
    ] {
        let (case, source) = triage_case(name, false);
        case.plan("inspect-original.out", &original)
            .plan("inspect-baseline.out", &original);
        let ended = case.ended(self::output(triage_command(&case, &source, "reduce")));
        assert_eq!(
            ended
                .class(4, "incomplete")
                .comparison
                .as_ref()
                .expect("comparison")
                .status
                .as_str(),
            "incomplete"
        );
        assert!(!case.calls().iter().any(|phase| phase == "reduce"));
    }
}
pub(crate) fn triage_output_paths_admit_printable_ascii_before_workers() {
    let (case, source) = triage_case("output-characters", true);
    for (at, output) in ["nonascii-\u{e9}", "control-\n"].iter().enumerate() {
        let args = [
            OsStr::new("reduce"),
            source.as_os_str(),
            OsStr::new("--archive"),
            archive().0.as_os_str(),
            OsStr::new("--output"),
            OsStr::new(output),
            OsStr::new("--run-id"),
            OsStr::new(if at == 0 { "first" } else { "second" }),
        ];
        let ended = case.ended({
            let mut command = case.command(&args);
            command.current_dir(&case.dir);
            self::output(command)
        });
        ended.class(2, "rejected");
        assert!(case.calls().is_empty());
    }
    let (case, source) = triage_case("shared-output-parent", true);
    let parent = case.dir.join("shared");
    fs::create_dir(&parent).expect("parent");
    fs::set_permissions(&parent, std::os::unix::fs::PermissionsExt::from_mode(0o777))
        .expect("shared parent");
    let target = parent.join("candidate");
    let args = [
        OsStr::new("reduce"),
        source.as_os_str(),
        OsStr::new("--archive"),
        archive().0.as_os_str(),
        OsStr::new("--output"),
        target.as_os_str(),
    ];
    let ended = case.ended(self::output(case.command(&args)));
    ended.class(2, "rejected");
    assert!(ended.reason().contains("Ancestor"), "{}", ended.reason());
    assert!(case.calls().is_empty());
    assert!(!target.exists());

    let (case, source) = triage_case("unsupported-output-mount", true);
    let target = Path::new("/proc/self/campaign-reduction");
    let args = [
        OsStr::new("reduce"),
        source.as_os_str(),
        OsStr::new("--archive"),
        archive().0.as_os_str(),
        OsStr::new("--output"),
        target.as_os_str(),
    ];
    let ended = case.ended(self::output(case.command(&args)));
    ended.class(2, "rejected");
    assert!(ended.reason().contains("Filesystem"), "{}", ended.reason());
    assert!(case.calls().is_empty());
    assert!(!target.exists());

    let (case, source) = triage_case("output-parent-drift", true);
    let parent = case.dir.join("output");
    fs::create_dir(&parent).expect("private output parent");
    fs::set_permissions(&parent, std::os::unix::fs::PermissionsExt::from_mode(0o700))
        .expect("private mode");
    case.plan("capabilities.action", "shared")
        .plan("rewrite.target", parent.to_str().expect("UTF-8"));
    let target = parent.join("candidate");
    let args = [
        OsStr::new("reduce"),
        source.as_os_str(),
        OsStr::new("--archive"),
        archive().0.as_os_str(),
        OsStr::new("--output"),
        target.as_os_str(),
    ];
    let ended = case.ended(self::output(case.command(&args)));
    ended.class(4, "incomplete");
    assert!(
        ended
            .reason()
            .contains("reduction output changed before reduce")
    );
    assert!(!case.calls().iter().any(|phase| phase == "reduce"));
    assert!(!target.exists());

    let (case, source) = triage_case("replay-output-characters", false);
    let mut command = Command::new(env!("CARGO_BIN_EXE_campaign"));
    let artifacts = case.dir.join("nonascii-\u{e9}");
    command
        .args([
            OsStr::new("sim"),
            OsStr::new("replay"),
            source.as_os_str(),
            OsStr::new("--archive"),
            archive().0.as_os_str(),
            OsStr::new("--artifacts"),
            artifacts.as_os_str(),
        ])
        .env(PLAN, &case.dir);
    case.ended(self::output(command)).class(2, "rejected");
    assert!(case.calls().is_empty());
}
pub(crate) fn panic_replay_uses_the_verified_original_identity() {
    for (name, fresh, status, class) in [
        (
            "panic-replay-equal",
            "run: the run panicked at src/x.rs:1:1: boom\n".to_owned(),
            "reproduced",
            1,
        ),
        (
            "panic-replay-other",
            "run: the run panicked at src/y.rs:1:1: boom\n".to_owned(),
            "diverged",
            1,
        ),
        (
            "panic-replay-torn",
            "run: the run panicked".to_owned(),
            "incomplete",
            4,
        ),
    ] {
        let case = Case::new(name);
        case.plan("run.out", "run: the run panicked at src/x.rs:1:1: boom\n")
            .plan("run.exit", "3")
            .plan("inspect.out", &truncated_summary());
        let original = case.run(&["--run-id", "original"]);
        original.class(4, "incomplete");
        if status == "reproduced" {
            let mut bytes = fs::read(case.dir.join("artifacts/original/bundle")).expect("original");
            let mut diagnostic = [0; 48];
            diagnostic[0] = 10;
            bytes.extend_from_slice(&diagnostic);
            fs::write(case.dir.join("replay.bundle"), bytes).expect("rerun bytes");
        }
        case.plan("triage", "")
            .plan("inspect-original.out", &truncated_summary())
            .plan("inspect-replay.out", &truncated_summary())
            .plan("replay.out", &fresh)
            .plan("replay.exit", "3");
        let run = case.dir.join("artifacts/original");
        let args = [
            OsStr::new("replay"),
            OsStr::new("--from-run"),
            run.as_os_str(),
            OsStr::new("--run-id"),
            OsStr::new("replayed"),
        ];
        let ended = case.ended(self::output(case.command(&args)));
        let compared = ended
            .class(class, if class == 1 { "complete" } else { "incomplete" })
            .comparison
            .as_ref()
            .expect("comparison");
        assert_eq!(compared.status.as_str(), status, "{}", ended.reason());
        assert_eq!(
            compared
                .failure_identity
                .as_ref()
                .expect("identity")
                .as_str(),
            "src/x.rs:1:1: boom"
        );
        if class == 1 {
            assert!(
                compared
                    .output
                    .as_ref()
                    .expect("output")
                    .as_str()
                    .ends_with("/replay/replay.bundle")
            );
        } else {
            assert_eq!(compared.output, None, "{name}: {}", ended.reason());
            assert_eq!(compared.candidate, None);
        }
        if status == "reproduced" {
            assert_eq!(compared.original, compared.observed);
            let bytes =
                fs::read(compared.output.as_ref().expect("output").as_str()).expect("rerun file");
            assert_eq!(compared.candidate, Some(Digest::of(&bytes)));
            assert_ne!(
                compared.candidate,
                Some(Digest::of(
                    &fs::read(run.join("bundle")).expect("original file")
                ))
            );
            let prior = case.dir.join("artifacts/replayed");
            let again = [
                OsStr::new("replay"),
                OsStr::new("--from-run"),
                prior.as_os_str(),
                OsStr::new("--run-id"),
                OsStr::new("twice"),
            ];
            let repeated = case.ended(self::output(case.command(&again)));
            let comparison = repeated
                .class(1, "complete")
                .comparison
                .as_ref()
                .expect("comparison");
            assert_eq!(comparison.status.as_str(), "reproduced");
            assert_eq!(comparison.failure_identity, compared.failure_identity);
            assert_eq!(comparison.failure_kind, compared.failure_kind);
        }
    }
    let case = Case::new("recorded-panic-reduce-other-identity");
    case.plan("run.out", "run: the run panicked at src/x.rs:1:1: boom\n")
        .plan("run.exit", "3")
        .plan("inspect.out", &truncated_summary());
    case.run(&["--run-id", "original"]).class(4, "incomplete");
    case.plan("triage", "")
        .plan("inspect-original.out", &truncated_summary())
        .plan(
            "panic-original.out",
            "run: the run panicked at src/y.rs:1:1: boom\n",
        )
        .plan("panic-original.exit", "3")
        .plan("inspect-panic-original.out", &truncated_summary());
    let run = case.dir.join("artifacts/original");
    let reduced = case.dir.join("reduced-from-run");
    let ended = case.ended(self::output(case.command(&[
        OsStr::new("reduce"),
        OsStr::new("--from-run"),
        run.as_os_str(),
        OsStr::new("--output"),
        reduced.as_os_str(),
        OsStr::new("--run-id"),
        OsStr::new("reduced"),
    ])));
    let comparison = ended.class(1, "complete").comparison.as_ref().unwrap();
    assert_eq!(comparison.status.as_str(), "diverged");
    assert_eq!(
        comparison.failure_identity.as_ref().unwrap().as_str(),
        "src/x.rs:1:1: boom"
    );
    assert!(!case.calls().iter().any(|phase| phase == "reduce"));
    let case = Case::new("recorded-panic-complete-original");
    case.plan("run.out", "run: the run panicked at src/x.rs:1:1: boom\n")
        .plan("run.exit", "3")
        .plan("inspect.out", &failing_summary());
    case.run(&["--run-id", "original"]).class(4, "incomplete");
    case.plan("triage", "")
        .plan("inspect-original.out", &failing_summary());
    let run = case.dir.join("artifacts/original");
    let args = [
        OsStr::new("replay"),
        OsStr::new("--from-run"),
        run.as_os_str(),
        OsStr::new("--run-id"),
        OsStr::new("fresh"),
    ];
    let ended = case.ended(self::output(case.command(&args)));
    ended.class(4, "incomplete");
    assert!(
        ended
            .reason()
            .contains("recorded panic disagrees with the original terminal")
    );
    assert_eq!(
        case.calls().last().map(String::as_str),
        Some("inspect-original")
    );
}
pub(crate) fn worker_detail_bounds_keep_a_publishable_artifact() {
    let (case, source) = triage_case("oversized-cause", true);
    let oversized = failing_summary().replace(
        "cause: violation, violating Bytes",
        &format!("cause: {}", "x".repeat(4097)),
    );
    case.plan("inspect-original.out", &oversized);
    let ended = case.ended(self::output(triage_command(&case, &source, "replay")));
    ended.class(4, "incomplete");
    assert!(ended.reason().contains("exceeds 4096 bytes"));
    let (case, source) = triage_case("oversized-panic-identity", false);
    case.plan("inspect-original.out", &truncated_summary())
        .plan(
            "panic-original.out",
            &format!(
                "run: the run panicked at src/x.rs:1:1: {}\n",
                "x".repeat(4097)
            ),
        )
        .plan("panic-original.exit", "3");
    let ended = case.ended(self::output(triage_command(&case, &source, "reduce")));
    ended.class(4, "incomplete");
    assert!(ended.reason().contains("exceeds 4096 bytes"));
}
pub(crate) fn failed_capability_listings_are_incomplete() {
    for (name, code, output) in [
        ("failed-listing", "1", LISTING),
        ("missing-listing", "0", "manifest: 2\n"),
        ("torn-public-listing", "0", LISTING.trim_end()),
    ] {
        let case = Case::new(name);
        case.plan("capabilities.exit", code)
            .plan("capabilities.out", output);
        let ended = case.ended(self::output(case.command(&[
            OsStr::new("capabilities"),
            OsStr::new("--archive"),
            archive().0.as_os_str(),
        ])));
        ended.class(4, "incomplete");
        let json: serde_json::Value = serde_json::from_str(ended.stdout.trim()).expect("JSON");
        assert!(json["capabilities"].is_null());
    }
}
pub(crate) fn two_fresh_replays_keep_the_same_summary_and_inputs() {
    let (case, source) = triage_case("two-fresh-replays", false);
    let before = fs::read(&source).expect("source");
    let first = case.ended(self::output(triage_named(
        &case, &source, "replay", "first",
    )));
    first.class(0, "counts");
    let first_pid = case.seen("replay")["pid"].clone();
    let second = case.ended(self::output(triage_named(
        &case, &source, "replay", "second",
    )));
    second.class(0, "counts");
    assert_ne!(first_pid, case.seen("replay")["pid"]);
    assert_eq!(
        first.artifact.as_ref().expect("artifact").1.summary,
        second.artifact.as_ref().expect("artifact").1.summary
    );
    assert_eq!(fs::read(&source).expect("source"), before);
}

pub(crate) fn panic_output_and_summary_bindings_refuse_changed_evidence() {
    let case = Case::new("changed-panic-output");
    case.plan("run.out", "run: the run panicked at src/x.rs:1:1: boom\n")
        .plan("run.exit", "3")
        .plan("inspect.out", &truncated_summary());
    case.run(&["--run-id", "original"]).class(4, "incomplete");
    let run = case.dir.join("artifacts/original");
    let calls = case.calls();
    fs::write(
        run.join("run.stdout"),
        b"run: the run panicked at src/y.rs:1:1: other\n",
    )
    .expect("changed panic output");
    let args = [
        OsStr::new("replay"),
        OsStr::new("--from-run"),
        run.as_os_str(),
        OsStr::new("--run-id"),
        OsStr::new("changed"),
    ];
    let ended = case.ended(self::output(case.command(&args)));
    ended.class(2, "rejected");
    assert!(
        ended
            .reason()
            .contains("the run output differs from the artifact")
    );
    assert_eq!(case.calls(), calls);
    fs::remove_file(run.join("run.stdout")).expect("missing original output");
    let mut missing = args;
    missing[4] = OsStr::new("missing");
    let ended = case.ended(self::output(case.command(&missing)));
    ended.class(2, "rejected");
    assert!(ended.reason().contains("the run output is missing"));
    assert_eq!(case.calls(), calls);
    for file in ["manifest", "run.stdout"] {
        let case = Case::new(&format!("frozen-original-{file}"));
        case.plan("run.out", "run: the run panicked at src/x.rs:1:1: boom\n")
            .plan("run.exit", "3")
            .plan("inspect.out", &truncated_summary());
        case.run(&["--run-id", "original"]).class(4, "incomplete");
        let run = case.dir.join("artifacts/original");
        case.plan("triage", "")
            .plan("inspect-original.out", &truncated_summary())
            .plan(
                "replay.out",
                "run: the run panicked at src/x.rs:1:1: boom\n",
            )
            .plan("replay.exit", "3")
            .plan("replay.action", "replace")
            .plan("rewrite.target", run.join(file).to_str().expect("UTF-8"));
        let args = [
            OsStr::new("replay"),
            OsStr::new("--from-run"),
            run.as_os_str(),
            OsStr::new("--run-id"),
            OsStr::new("replayed"),
        ];
        let ended = case.ended(self::output(case.command(&args)));
        ended.class(4, "incomplete");
        assert!(ended.reason().contains("changed after admission"));
        assert_eq!(case.calls().last().map(String::as_str), Some("replay"));
    }
    let case = Case::new("changed-original-summary");
    case.run(&["--run-id", "original"]).class(0, "counts");
    case.plan("triage", "").plan(
        "inspect-original.out",
        &COUNTING.replace("decisions: 61", "decisions: 62"),
    );
    let run = case.dir.join("artifacts/original");
    let args = [
        OsStr::new("replay"),
        OsStr::new("--from-run"),
        run.as_os_str(),
        OsStr::new("--run-id"),
        OsStr::new("changed"),
    ];
    let ended = case.ended(self::output(case.command(&args)));
    ended.class(4, "incomplete");
    assert!(
        ended
            .reason()
            .contains("the original inspection differs from the recorded summary")
    );
    assert_eq!(
        case.calls().last().map(String::as_str),
        Some("inspect-original")
    );
    let refused = ended
        .class(4, "incomplete")
        .comparison
        .as_ref()
        .expect("comparison");
    assert_eq!(
        refused
            .original
            .as_ref()
            .expect("recorded original")
            .decisions,
        Some(61)
    );
    assert_eq!(
        refused.observed.as_ref().expect("new inspection").decisions,
        Some(62)
    );
    let failed = case.dir.join("artifacts/changed");
    let chained = [
        OsStr::new("replay"),
        OsStr::new("--from-run"),
        failed.as_os_str(),
        OsStr::new("--run-id"),
        OsStr::new("chained"),
    ];
    let repeated = case.ended(self::output(case.command(&chained)));
    let refused_again = repeated
        .class(4, "incomplete")
        .comparison
        .as_ref()
        .expect("comparison");
    assert_eq!(refused_again.original, refused.original);
    assert_eq!(refused_again.observed, refused.observed);
    assert!(!case.calls().iter().any(|phase| phase == "replay"));
}
pub(crate) fn fresh_panic_steps_keep_passing_and_different_failures_distinct() {
    for (name, original, candidate, code, bundle_changes, observed, status) in [
        (
            "original-passes",
            COUNTING.to_owned(),
            "".to_owned(),
            "0",
            false,
            truncated_summary(),
            "unreproduced",
        ),
        (
            "original-different",
            failing_summary(),
            "".to_owned(),
            "1",
            false,
            truncated_summary(),
            "diverged",
        ),
        (
            "original-bundle-drift",
            "run: the run panicked at src/x.rs:1:1: boom\n".to_owned(),
            "".to_owned(),
            "3",
            true,
            truncated_summary(),
            "diverged",
        ),
        (
            "candidate-different-kind",
            "run: the run panicked at src/x.rs:1:1: boom\n".to_owned(),
            failing_summary(),
            "1",
            false,
            truncated_summary(),
            "diverged",
        ),
    ] {
        let (case, source) = triage_case(name, false);
        case.plan("inspect-original.out", &truncated_summary());
        if name == "candidate-different-kind" {
            case.plan("panic-original.out", &original)
                .plan("panic-original.exit", "3")
                .plan("panic-candidate.out", &candidate)
                .plan("panic-candidate.exit", code);
        } else {
            case.plan("panic-original.out", &original)
                .plan("panic-original.exit", code);
            if bundle_changes {
                fs::write(
                    case.dir.join("panic-original.bundle"),
                    bundle(&manifest(&[]), 1),
                )
                .expect("changed rerun bundle");
            }
        }
        case.plan("inspect-replay.out", &observed);
        let ended = case.ended(self::output(triage_command(&case, &source, "reduce")));
        assert_eq!(
            ended
                .class(1, "complete")
                .comparison
                .as_ref()
                .expect("comparison")
                .status
                .as_str(),
            status,
            "{name}: {}",
            ended.reason()
        );
    }
    for (name, fresh, code, raw_change, observed, status) in [
        (
            "panic-replay-passes",
            COUNTING.to_owned(),
            "0",
            false,
            COUNTING.to_owned(),
            "unreproduced",
        ),
        (
            "panic-replay-other-kind",
            failing_summary(),
            "1",
            false,
            failing_summary(),
            "diverged",
        ),
        (
            "panic-replay-bundle-drift",
            "run: the run panicked at src/x.rs:1:1: boom\n".to_owned(),
            "3",
            true,
            truncated_summary(),
            "diverged",
        ),
        (
            "panic-replay-summary-drift",
            "run: the run panicked at src/x.rs:1:1: boom\n".to_owned(),
            "3",
            false,
            truncated_summary().replace(
                COUNTING
                    .lines()
                    .next()
                    .expect("digest")
                    .strip_prefix("digest: ")
                    .expect("value"),
                &"cd".repeat(32),
            ),
            "diverged",
        ),
    ] {
        let case = Case::new(name);
        case.plan("run.out", "run: the run panicked at src/x.rs:1:1: boom\n")
            .plan("run.exit", "3")
            .plan("inspect.out", &truncated_summary());
        case.run(&["--run-id", "original"]).class(4, "incomplete");
        case.plan("triage", "")
            .plan("inspect-original.out", &truncated_summary())
            .plan("replay.out", &fresh)
            .plan("replay.exit", code)
            .plan("inspect-replay.out", &observed);
        if raw_change {
            fs::write(case.dir.join("replay.bundle"), bundle(&manifest(&[]), 1))
                .expect("changed rerun bundle");
        }
        let run = case.dir.join("artifacts/original");
        let args = [
            OsStr::new("replay"),
            OsStr::new("--from-run"),
            run.as_os_str(),
            OsStr::new("--run-id"),
            OsStr::new("replayed"),
        ];
        let ended = case.ended(self::output(case.command(&args)));
        assert_eq!(
            ended
                .class(1, "complete")
                .comparison
                .as_ref()
                .expect("comparison")
                .status
                .as_str(),
            status,
            "{name}: {}",
            ended.reason()
        );
    }
    for (phase, printed, inspected, code, reason) in [
        (
            "panic-original",
            "run: the run panicked at src/x.rs:1:1: boom\n".to_owned(),
            truncated_summary(),
            "0",
            "supplies incomplete evidence",
        ),
        (
            "panic-candidate",
            COUNTING.to_owned(),
            COUNTING.to_owned(),
            "3",
            "worker exited 3",
        ),
        (
            "panic-original",
            COUNTING.to_owned(),
            truncated_summary(),
            "0",
            "summary differs",
        ),
        (
            "panic-original",
            "run: the run panicked at src/x.rs:1:1: boom\n".to_owned(),
            COUNTING.to_owned(),
            "3",
            "panic line disagrees",
        ),
        (
            "panic-candidate",
            COUNTING.to_owned(),
            truncated_summary(),
            "0",
            "summary differs",
        ),
        (
            "panic-candidate",
            "run: the run panicked at src/x.rs:1:1: boom\n".to_owned(),
            COUNTING.to_owned(),
            "3",
            "panic line disagrees",
        ),
    ] {
        let (case, source) = triage_case(
            &format!(
                "contradictory-{phase}-{code}-{}",
                printed.starts_with("run:")
            ),
            false,
        );
        case.plan("inspect-original.out", &truncated_summary())
            .plan(
                "panic-original.out",
                "run: the run panicked at src/x.rs:1:1: boom\n",
            )
            .plan("panic-original.exit", "3")
            .plan(&format!("{phase}.out"), &printed)
            .plan(&format!("{phase}.exit"), code)
            .plan(&format!("inspect-{phase}.out"), &inspected);
        let ended = case.ended(self::output(triage_command(&case, &source, "reduce")));
        ended.class(4, "incomplete");
        assert!(ended.reason().contains(reason), "{}", ended.reason());
    }
    for (phase, code, class) in [
        ("panic-original", 2, "rejected"),
        ("panic-candidate", 4, "incomplete"),
    ] {
        let (case, source) = triage_case(&format!("refused-{phase}"), false);
        case.plan("inspect-original.out", &truncated_summary())
            .plan(
                "panic-original.out",
                "run: the run panicked at src/x.rs:1:1: boom\n",
            )
            .plan("panic-original.exit", "3")
            .plan(&format!("{phase}.exit"), "2")
            .plan(&format!("{phase}.nobundle"), "");
        let ended = case.ended(self::output(triage_command(&case, &source, "reduce")));
        ended.class(code, class);
        assert!(ended.reason().contains("worker refused the panic rerun"));
        assert_eq!(case.calls().last().map(String::as_str), Some(phase));
    }
    for phase in ["panic-original", "panic-candidate", "replay"] {
        for (kind, printed, class, status) in [
            ("cap", summary(&CAPPED), 1, "diverged"),
            (
                "defect",
                summary(&CAPPED).replace("infrastructure cap", "infrastructure defect"),
                1,
                "diverged",
            ),
            ("truncated", truncated_summary(), 4, "incomplete"),
        ] {
            let name = format!("panic-summary-{phase}-{kind}");
            let (case, source) = triage_case(&name, false);
            case.plan("inspect-original.out", &truncated_summary())
                .plan(
                    "panic-original.out",
                    "run: the run panicked at src/x.rs:1:1: boom\n",
                )
                .plan("panic-original.exit", "3")
                .plan(&format!("{phase}.out"), &printed)
                .plan(&format!("{phase}.exit"), "3")
                .plan(&format!("inspect-{phase}.out"), &printed);
            let ended = if phase == "replay" {
                fs::remove_file(case.dir.join("triage")).expect("normal run phases");
                case.plan("run.out", "run: the run panicked at src/x.rs:1:1: boom\n")
                    .plan("run.exit", "3")
                    .plan("inspect.out", &truncated_summary());
                case.run(&["--run-id", "original"]).class(4, "incomplete");
                case.plan("triage", "");
                let run = case.dir.join("artifacts/original");
                let args = [
                    OsStr::new("replay"),
                    OsStr::new("--from-run"),
                    run.as_os_str(),
                    OsStr::new("--run-id"),
                    OsStr::new("fresh"),
                ];
                case.ended(self::output(case.command(&args)))
            } else {
                case.ended(self::output(triage_command(&case, &source, "reduce")))
            };
            assert_eq!(
                ended
                    .class(class, if class == 1 { "complete" } else { "incomplete" })
                    .comparison
                    .as_ref()
                    .expect("comparison")
                    .status
                    .as_str(),
                status,
                "{name}: {}",
                ended.reason()
            );
            if class == 4 {
                assert!(ended.reason().contains("supplies incomplete evidence"));
            }
        }
    }
    let (case, source) = triage_case("long-alternate-panic", true);
    case.plan(
        "replay.out",
        &format!(
            "replay: the run panicked at src/other.rs:1:1: {}\n",
            "x".repeat(4097)
        ),
    )
    .plan("replay.exit", "1")
    .plan("inspect-replay.out", &truncated_summary());
    let ended = case.ended(self::output(triage_command(&case, &source, "replay")));
    assert_eq!(
        ended
            .class(1, "complete")
            .comparison
            .as_ref()
            .expect("comparison")
            .status
            .as_str(),
        "diverged"
    );
    let (case, source) = triage_case("long-panic-candidate", false);
    case.plan("inspect-original.out", &truncated_summary())
        .plan(
            "panic-original.out",
            "run: the run panicked at src/x.rs:1:1: boom\n",
        )
        .plan("panic-original.exit", "3")
        .plan(
            "panic-candidate.out",
            &format!(
                "run: the run panicked at src/other.rs:1:1: {}\n",
                "x".repeat(4097)
            ),
        )
        .plan("panic-candidate.exit", "3");
    let ended = case.ended(self::output(triage_command(&case, &source, "reduce")));
    assert_eq!(
        ended
            .class(1, "complete")
            .comparison
            .as_ref()
            .expect("comparison")
            .status
            .as_str(),
        "diverged"
    );
}

pub(crate) fn a_changed_replay_ledger_is_divergence() {
    let (case, source) = triage_case("ledger-divergence", false);
    let raw = bundle(
        &manifest(&[]).replace("profile = upload", "profile = recovery-512"),
        2,
    );
    fs::write(&source, raw).expect("recovery bundle");
    let original = recovery("ledger: inconclusive first gap\n", false);
    let observed = recovery("ledger: inconclusive another gap\n", false);
    case.plan("inspect-original.out", &original)
        .plan("inspect-replay.out", &observed);
    let ended = case.ended(self::output(triage_command(&case, &source, "replay")));
    assert_eq!(
        ended
            .class(1, "complete")
            .comparison
            .as_ref()
            .expect("comparison")
            .status
            .as_str(),
        "diverged"
    );
}

pub(crate) fn a_replay_worker_killed_by_a_signal_is_incomplete() {
    let (case, source) = triage_case("replay-signaled", true);
    case.plan("replay.action", "abort");
    let ended = case.ended(self::output(triage_command(&case, &source, "replay")));
    ended.class(4, "incomplete");
    assert!(ended.reason().contains("replay died from signal"));
    assert_eq!(case.calls().last().map(String::as_str), Some("replay"));
}

pub(crate) fn reduction_stops_when_its_baseline_does_not_reproduce() {
    for (name, observed, status) in [
        ("baseline-passes", COUNTING.to_owned(), "unreproduced"),
        (
            "baseline-identity",
            failing_summary().replace(&"ab".repeat(44), &"cd".repeat(44)),
            "diverged",
        ),
    ] {
        let (case, source) = triage_case(name, true);
        case.plan("inspect-baseline.out", &observed);
        let ended = case.ended(self::output(triage_command(&case, &source, "reduce")));
        let comparison = ended
            .class(1, "complete")
            .comparison
            .clone()
            .expect("comparison");
        assert_eq!(comparison.status.as_str(), status);
        assert_eq!(
            comparison.output, None,
            "{name} names a candidate it never wrote"
        );
        assert_eq!(comparison.candidate, None);
        assert!(!case.calls().iter().any(|phase| phase == "reduce"));
    }
}
pub(crate) fn reduction_worker_exits_require_complete_result_evidence() {
    for (name, exit, output, class) in [
        ("reduce-refused", "2", "", 2),
        (
            "reduce-incomplete",
            "3",
            "reduce: reduced to 20 records, scenario ab\n",
            4,
        ),
        ("reduce-no-result", "0", "", 4),
        (
            "reduce-contradictory-unreducible",
            "1",
            "reduce: reduced to 20 records, scenario ab\n",
            4,
        ),
    ] {
        let (case, source) = triage_case(name, true);
        case.plan("reduce.exit", exit).plan("reduce.out", output);
        let ended = case.ended(self::output(triage_command(&case, &source, "reduce")));
        ended.class(class, if class == 2 { "rejected" } else { "incomplete" });
        if exit == "3" {
            assert!(ended.reason().contains("exited 3 reducing"));
        }
        assert_eq!(case.calls().last().map(String::as_str), Some("reduce"));
    }
    for (fault, reason) in [
        ("missing", "is unreadable"),
        (
            "large-manifest",
            "candidate manifest exceeds its byte bound",
        ),
        ("foreign", "the candidate pins build"),
        ("oversized", "manifest's maximum"),
        ("unknown", "unknown record tag"),
        ("scenario", "reduction result differs"),
        ("panic-kind", "reduction result differs"),
        ("count", "reduction result differs"),
    ] {
        let (case, source) = triage_case(&format!("candidate-{fault}"), true);
        let mut raw = fs::read(&source).expect("source");
        match fault {
            "large-manifest" => {
                let mut large = manifest(&[])
                    .replace("records = 1000", "records = 100000")
                    .replace("bytes = 48000", "bytes = 4800000");
                large.push_str(&"x".repeat((1 << 20) - large.len()));
                raw = bundle(&large, 2);
            }
            "missing" => {
                case.plan("reduce.nobundle", "")
                    .plan("reduce.out", "reduce: reduced to 20 records, scenario ab\n");
            }
            "foreign" => {
                raw = bundle(
                    &manifest(&[]).replace(
                        &format!("build = {}", archive().1.build.as_str()),
                        "build = other",
                    ),
                    1,
                );
            }
            "oversized" => {
                raw = bundle(&manifest(&[]).replace("records = 1000", "records = 1"), 2);
            }
            "unknown" => {
                let mut record = [0; 48];
                record[0] = 255;
                raw.extend_from_slice(&record);
            }
            "scenario" => {
                case.plan(
                    "reduce.out",
                    &format!(
                        "reduce: reduced to {} records, scenario other\n",
                        raw.len() / 48
                    ),
                );
            }
            "panic-kind" => {
                case.plan("reduce.out", &format!("reduce: reduced to {} records, scenario ab, the run panicked at src/x.rs:1:1: boom\n", raw.len() / 48));
            }
            "count" => {
                case.plan(
                    "reduce.out",
                    "reduce: reduced to 999 records, scenario ab\n",
                );
            }
            _ => unreachable!(),
        }
        if fault != "missing" {
            fs::write(case.dir.join("reduce.bundle"), raw).expect("worker candidate");
        }
        let ended = case.ended(self::output(triage_command(&case, &source, "reduce")));
        ended.class(4, "incomplete");
        assert!(
            ended.reason().contains(reason),
            "{fault}: {}",
            ended.reason()
        );
    }
    for (status, code) in [("watchdog", 6), ("interrupted", 5)] {
        let (case, source) = triage_case(&format!("triage-{status}"), true);
        case.plan("reduce.action", "hang");
        let mut command = triage_command(&case, &source, "reduce");
        if status == "watchdog" {
            command.args(["--watchdog", "1"]);
        }
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        let launcher = Launcher(command.spawn().expect("launcher"));
        assert!(within(60, || case.dir.join("reduce.seen").exists()));
        if status == "interrupted" {
            // SAFETY: The child remains unreaped until wait_output, preserving its PID during kill.
            unsafe { libc::kill(i32::try_from(launcher.id()).expect("pid"), libc::SIGTERM) };
        }
        let ended = case.ended(wait_output(launcher));
        let comparison = ended
            .class(code, status)
            .comparison
            .as_ref()
            .expect("comparison");
        assert_eq!(comparison.status.as_str(), status);
        assert!(comparison.original.is_some());
        assert_eq!(case.calls().last().map(String::as_str), Some("reduce"));
        assert!(source.exists());
    }
    let (case, source) = triage_case("replay-symlinked-evidence", true);
    case.plan("replay.action", "symlink").plan(
        "rewrite.target",
        case.dir
            .join("artifacts/triage/replay/replay.bundle")
            .to_str()
            .expect("UTF-8"),
    );
    let ended = case.ended(self::output(triage_command(&case, &source, "replay")));
    ended.class(4, "incomplete");
    assert!(ended.reason().contains("is unreadable"));
    assert_eq!(case.calls().last().map(String::as_str), Some("replay"));
    let (case, source) = triage_case("replay-missing-bundle", true);
    case.plan("replay.nobundle", "");
    let ended = case.ended(self::output(triage_command(&case, &source, "replay")));
    let comparison = ended
        .class(4, "incomplete")
        .comparison
        .clone()
        .expect("comparison");
    assert!(ended.reason().contains("is unreadable"));
    assert_eq!(
        comparison.output, None,
        "names a replay bundle the worker never wrote"
    );
    assert_eq!(comparison.candidate, None);

    let (case, source) = triage_case("panic-unreducible", false);
    case.plan("inspect-original.out", &truncated_summary())
        .plan(
            "panic-original.out",
            "run: the run panicked at src/x.rs:1:1: boom\n",
        )
        .plan("panic-original.exit", "3")
        .plan("reduce.exit", "1")
        .plan("reduce.out", "")
        .plan("reduce.nobundle", "");
    let ended = case.ended(self::output(triage_command(&case, &source, "reduce")));
    assert_eq!(
        ended
            .class(1, "complete")
            .comparison
            .as_ref()
            .expect("comparison")
            .status
            .as_str(),
        "unreducible"
    );
}
pub(crate) fn panic_reduction_requires_equal_inspected_summaries() {
    for phase in ["inspect-panic-original", "inspect-panic-candidate"] {
        let (case, source) = triage_case(&format!("summary-drift-{phase}"), false);
        case.plan("inspect-original.out", &truncated_summary())
            .plan(
                "panic-original.out",
                "run: the run panicked at src/x.rs:1:1: boom\n",
            )
            .plan("panic-original.exit", "3")
            .plan(
                "panic-candidate.out",
                "run: the run panicked at src/x.rs:1:1: boom\n",
            )
            .plan("panic-candidate.exit", "3");
        let changed = truncated_summary().replace(
            COUNTING
                .lines()
                .next()
                .expect("digest")
                .strip_prefix("digest: ")
                .expect("value"),
            &"cd".repeat(32),
        );
        case.plan(&format!("{phase}.out"), &changed);
        let ended = case.ended(self::output(triage_command(&case, &source, "reduce")));
        let comparison = ended
            .class(1, "complete")
            .comparison
            .as_ref()
            .expect("comparison");
        assert_eq!(comparison.status.as_str(), "diverged");
        assert_eq!(
            comparison
                .observed
                .as_ref()
                .expect("facts")
                .digest
                .to_string(),
            "cd".repeat(32)
        );
        if phase == "inspect-panic-original" {
            assert!(!case.calls().iter().any(|phase| phase == "reduce"));
        }
    }
    let (case, source) = triage_case("contradictory-reducer-panic", false);
    case.plan("inspect-original.out", &truncated_summary())
        .plan("panic-original.out", "run: the run panicked at src/x.rs:1:1: boom\n").plan("panic-original.exit", "3")
        .plan("panic-candidate.out", "run: the run panicked at src/x.rs:1:1: boom\n").plan("panic-candidate.exit", "3")
        .plan("reduce.out", &format!("reduce: reduced to {} records, scenario ab, the run panicked at src/x.rs:1:1: other\n", fs::read(&source).expect("source").len() / 48));
    let ended = case.ended(self::output(triage_command(&case, &source, "reduce")));
    ended.class(4, "incomplete");
    assert!(
        ended
            .reason()
            .contains("reduction result differs from the candidate panic")
    );
}

pub(crate) fn panic_candidates_keep_credit_and_terminals_distinct() {
    for (name, inspected, exit, class, status, reason) in [
        (
            "pass",
            COUNTING.to_owned(),
            "0",
            1,
            "unreproduced",
            "candidate passes",
        ),
        (
            "violation",
            failing_summary(),
            "0",
            1,
            "diverged",
            "another failure kind",
        ),
        (
            "zero",
            COUNTING.replace("decisions: 61", "decisions: 0"),
            "0",
            4,
            "incomplete",
            "without a decision",
        ),
        (
            "cap",
            summary(&CAPPED),
            "0",
            1,
            "diverged",
            "another failure kind",
        ),
        (
            "defect",
            summary(&CAPPED).replace("infrastructure cap", "infrastructure defect"),
            "0",
            1,
            "diverged",
            "another failure kind",
        ),
        (
            "sink",
            summary(&CAPPED).replace("infrastructure cap", "infrastructure sink"),
            "0",
            4,
            "incomplete",
            "candidate is incomplete",
        ),
        (
            "refused",
            truncated_summary(),
            "2",
            4,
            "incomplete",
            "exited 2 refusing the bundle",
        ),
    ] {
        let (case, source) = triage_case(&format!("panic-candidate-inspection-{name}"), false);
        case.plan("inspect-original.out", &truncated_summary())
            .plan(
                "panic-original.out",
                "run: the run panicked at src/x.rs:1:1: boom\n",
            )
            .plan("panic-original.exit", "3")
            .plan("inspect-candidate.out", &inspected)
            .plan("inspect-candidate.exit", exit);
        let ended = case.ended(self::output(triage_command(&case, &source, "reduce")));
        assert_eq!(
            ended
                .class(class, if class == 1 { "complete" } else { "incomplete" })
                .comparison
                .as_ref()
                .expect("comparison")
                .status
                .as_str(),
            status
        );
        assert!(ended.reason().contains(reason), "{}", ended.reason());
        assert_eq!(
            case.calls().last().map(String::as_str),
            Some("inspect-candidate")
        );
    }
}

pub(crate) fn permissive_caller_masks_keep_worker_outputs_private() {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;
    for form in ["replay", "reduce"] {
        let (case, source) = triage_case(&format!("permissive-mask-{form}"), true);
        let mut command = triage_command(&case, &source, form);
        // SAFETY: umask changes the child process's file-creation mask and allocates nothing.
        unsafe {
            command.pre_exec(|| {
                libc::umask(0);
                Ok(())
            });
        }
        let ended = case.ended(self::output(command));
        let comparison = ended
            .class(1, "complete")
            .comparison
            .as_ref()
            .expect("comparison");
        assert_eq!(
            comparison.status.as_str(),
            if form == "replay" {
                "reproduced"
            } else {
                "reduced"
            }
        );
        let directory = Path::new(comparison.output.as_ref().expect("output").as_str())
            .parent()
            .expect("directory");
        assert_eq!(
            fs::metadata(directory)
                .expect("worker directory")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
}

pub(crate) fn default_acls_preserve_private_worker_evidence_and_refuse_external_parents() {
    use std::os::unix::fs::PermissionsExt;
    let (case, source) = triage_case("default-acl", true);
    let set = Command::new("setfacl")
        .args(["-m", "d:u::rwx,d:g::rwx,d:o::---", "--"])
        .arg(&case.dir)
        .output()
        .expect("setfacl runs");
    if !set.status.success() && String::from_utf8_lossy(&set.stderr).contains("not supported") {
        eprintln!("ACL case skipped: filesystem reports unsupported default ACLs");
        return;
    }
    assert!(
        set.status.success(),
        "{}",
        String::from_utf8_lossy(&set.stderr)
    );
    let acl = |path: &Path| {
        let output = Command::new("getfacl")
            .args(["--default", "--omit-header", "--absolute-names", "--"])
            .arg(path)
            .output()
            .expect("getfacl runs");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    };
    let before = acl(&case.dir);
    assert!(!before.is_empty());
    let ended = case.ended(self::output(triage_named(
        &case,
        &source,
        "replay",
        "acl-replay",
    )));
    let comparison = ended
        .class(1, "complete")
        .comparison
        .as_ref()
        .expect("comparison");
    assert_eq!(comparison.status.as_str(), "reproduced");
    let run = case.dir.join("artifacts/acl-replay");
    assert!(acl(&run).is_empty());
    assert_eq!(
        fs::metadata(run.join("replay"))
            .expect("worker output")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let calls = case.calls();
    let refused = case.ended(self::output(triage_named(
        &case,
        &source,
        "reduce",
        "acl-refused",
    )));
    refused.class(2, "rejected");
    assert!(refused.reason().contains("DefaultAcl"));
    assert_eq!(case.calls(), calls);
    assert!(!case.dir.join("reduction").exists());
    assert_eq!(acl(&case.dir), before);
    let clean = case.dir.join("clean");
    campaign_supervisor::store::create_dir(&clean).expect("clean new directory");
    assert!(acl(&clean).is_empty());
    let target = clean.join("candidate");
    let args = [
        OsStr::new("reduce"),
        source.as_os_str(),
        OsStr::new("--archive"),
        archive().0.as_os_str(),
        OsStr::new("--output"),
        target.as_os_str(),
        OsStr::new("--run-id"),
        OsStr::new("acl-reduce"),
    ];
    let reduced = case.ended(self::output(case.command(&args)));
    assert_eq!(
        reduced
            .class(1, "complete")
            .comparison
            .as_ref()
            .expect("comparison")
            .status
            .as_str(),
        "reduced"
    );
    assert_eq!(
        fs::metadata(&target)
            .expect("reduced output")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(acl(&case.dir), before);
}

pub(crate) fn manual_truncated_replay_retains_incomplete_evidence() {
    let (case, source) = triage_case("manual-truncated", false);
    case.plan("inspect-original.out", &truncated_summary());
    let ended = case.ended(self::output(triage_command(&case, &source, "replay")));
    ended.class(4, "incomplete");
    assert!(
        ended
            .reason()
            .contains("no complete terminal or panic identity")
    );
    assert_eq!(
        case.calls().last().map(String::as_str),
        Some("inspect-original")
    );
    let (case, source) = triage_case("partial-inspection-summary", false);
    let mut raw = fs::read(&source).expect("source");
    raw.push(7);
    fs::write(&source, raw).expect("partial record");
    case.plan("inspect-original.out", &truncated_summary());
    let ended = case.inspect(&source, &archive().0);
    let record = ended.class(4, "incomplete");
    let retained = record.summary.as_ref().expect("parsed summary retained");
    assert_eq!(retained.terminal.as_str(), "infrastructure truncated");
    assert!(retained.first_failure.is_none());
}

fn session_fixture(case: &Case, name: &str) -> PathBuf {
    let dir = case.dir.join(name);
    fs::create_dir(&dir).unwrap();
    fs::create_dir(dir.join("windows")).unwrap();
    let manifest = fs::read(case.manifest()).unwrap();
    fs::write(dir.join("manifest"), &manifest).unwrap();
    let mut chain = Digest::of(&manifest);
    let mut lines = String::new();
    for at in 0u32..2 {
        let chunk = [3, 1, 0, 0, 0, at as u8];
        let digest = Digest::of(&chunk);
        let joined = [
            chain.bytes().as_slice(),
            &at.to_le_bytes(),
            digest.bytes().as_slice(),
        ]
        .concat();
        chain = Digest::of(&joined);
        fs::write(dir.join(format!("windows/{at:06}.chunk")), chunk).unwrap();
        lines.push_str(&format!("window {at} turns=1 digest={digest} chain={chain} verdict=pass carried=2 registry=3 outstanding=4 kept=5 published=6 hits=7 faults=8 reused=9 healed=10\n"));
    }
    fs::write(dir.join("index"), lines).unwrap();
    let tail = [4, 0, 0, 0, 0];
    fs::write(dir.join("windows/tail.chunk"), tail).unwrap();
    fs::write(dir.join("end"), format!("end: stop=goal terminal=complete pass fired=03 required=03 counts=true turns=2 virtual_us=600 skipped_us=500 rested_us=100 apply_ms=000000000001 failure=None carried=2 registry=3 outstanding=4 kept=5 window_bytes=64 windows=2 chain={chain} tail={}\n", Digest::of(&tail))).unwrap();
    dir
}
fn fixture_byte_budget(case: &Case, dir: &Path, files: &[&str], slack: u64) -> u64 {
    for _ in 0..10 {
        let budget = files
            .iter()
            .map(|name| fs::metadata(dir.join(name)).unwrap().len())
            .sum::<u64>()
            + slack;
        let manifest = fs::read_to_string(dir.join("manifest")).unwrap();
        let current = manifest
            .lines()
            .find_map(|line| line.strip_prefix("bytes = "))
            .unwrap();
        if current == budget.to_string() {
            return budget;
        }
        let updated = manifest.replace(&format!("bytes = {current}"), &format!("bytes = {budget}"));
        fs::write(case.manifest(), &updated).unwrap();
        fs::write(dir.join("manifest"), updated).unwrap();
        rechain_session(dir, [0, 1], false);
    }
    panic!("the fixture byte budget converges within ten digit-width adjustments");
}

fn rechain_session(dir: &Path, indexes: [u32; 2], false_digest: bool) {
    let mut chain = Digest::of(&fs::read(dir.join("manifest")).unwrap());
    let previous = fs::read_to_string(dir.join("index")).unwrap();
    let mut lines = String::new();
    for (at, (line, index)) in previous.lines().zip(indexes).enumerate() {
        let path = dir.join(format!("windows/{index:06}.chunk"));
        if !path.exists() {
            fs::copy(dir.join(format!("windows/{at:06}.chunk")), &path).unwrap();
        }
        let digest = if false_digest && at == 0 {
            Digest::parse(&"0".repeat(64)).unwrap()
        } else {
            Digest::of(&fs::read(path).unwrap())
        };
        chain = Digest::of(
            &[
                chain.bytes().as_slice(),
                &index.to_le_bytes(),
                digest.bytes().as_slice(),
            ]
            .concat(),
        );
        let rest = line.split_once(" verdict=").unwrap().1;
        lines.push_str(&format!(
            "window {index} turns=1 digest={digest} chain={chain} verdict={rest}\n"
        ));
    }
    fs::write(dir.join("index"), lines).unwrap();
    let path = dir.join("end");
    let end = fs::read_to_string(&path).unwrap();
    let old = end
        .split_whitespace()
        .find(|part| part.starts_with("chain="))
        .unwrap();
    fs::write(path, end.replace(old, &format!("chain={chain}"))).unwrap();
}

fn session_command(case: &Case, source: &Path, replay: bool, run: &str) -> Command {
    let mut args = vec![OsStr::new(if replay {
        "replay-session"
    } else {
        "session"
    })];
    if !replay {
        args.push(OsStr::new("--manifest"));
    }
    args.extend([
        source.as_os_str(),
        OsStr::new("--archive"),
        archive().0.as_os_str(),
        OsStr::new("--run-id"),
        OsStr::new(run),
    ]);
    case.command(&args)
}

pub(crate) fn sessions_verify_all_files_and_agree_with_the_worker() {
    for (exact_bytes, empty_tail) in [(false, false), (true, false), (true, true)] {
        let case = Case::new(if empty_tail {
            "session-exact-metadata-budget"
        } else if exact_bytes {
            "session-exact-byte-budget"
        } else {
            "session-exact-record-budget"
        });
        if !exact_bytes {
            let m = fs::read_to_string(case.manifest()).unwrap();
            fs::write(case.manifest(), m.replace("records = 1000", "records = 3")).unwrap();
        }
        let source = session_fixture(&case, "source");
        if empty_tail {
            fs::write(source.join("windows/tail.chunk"), b"").unwrap();
            let path = source.join("end");
            let end = fs::read_to_string(&path).unwrap();
            let old = end
                .split_whitespace()
                .find(|part| part.starts_with("tail="))
                .unwrap();
            fs::write(path, end.replace(old, &format!("tail={}", Digest::of(b"")))).unwrap();
        }
        let exact = exact_bytes.then(|| {
            fixture_byte_budget(
                &case,
                &source,
                &[
                    "manifest",
                    "index",
                    "end",
                    "windows/000000.chunk",
                    "windows/000001.chunk",
                    "windows/tail.chunk",
                ],
                0,
            )
        });
        case.plan("session.tree", source.to_str().unwrap());
        let ended = case.ended(output(session_command(
            &case,
            &case.manifest(),
            false,
            "result",
        )));
        let artifact = ended.class(0, "counts");
        let facts = artifact.session.as_ref().unwrap();
        assert_eq!(facts.verified_windows, 2);
        assert_eq!(facts.records, if empty_tail { 2 } else { 3 });
        if let Some(exact) = exact {
            assert_eq!(facts.bytes, exact);
        }
    }
    for (i, edit, exit, expected) in [
        (0, None, "0", 0),
        (1, None, "1", 4),
        (6, Some("index\nverdict=pass\nverdict=failed"), "0", 4),
        (7, Some("end\nstop=goal\nstop=halted"), "0", 4),
        (8, None, "2", 4),
        (2, Some("manifest\nroot = 3\nroot = 4"), "0", 4),
        (3, Some("index\nwindow 1\nwindow 2"), "0", 4),
        (4, Some("end\nwindows=2\nwindows=3"), "0", 4),
        (5, Some("end\nturns=2\nturns=0"), "0", 4),
    ] {
        let case = Case::new(&format!("session-agreement-{i}"));
        let fixture = session_fixture(&case, "fixture");
        case.plan("session.tree", fixture.to_str().unwrap())
            .plan("session.exit", exit);
        if let Some(edit) = edit {
            case.plan("session.edit", edit);
        }
        let ended = case.ended(output(session_command(
            &case,
            &case.manifest(),
            false,
            "session",
        )));
        let artifact = ended.class(
            expected,
            if expected == 0 {
                "counts"
            } else {
                "incomplete"
            },
        );
        assert_eq!(
            artifact.workers[&Text::new("session").unwrap()].exit,
            Some(exit.parse().unwrap())
        );
        assert!(artifact.output.is_none());
        let evidence = artifact.session.as_ref().unwrap();
        assert_eq!(evidence.complete, expected == 0);
        assert_eq!(evidence.counts, expected == 0);
        if expected == 0 {
            assert_eq!(evidence.verified_windows, 2);
            assert_eq!(
                evidence.digests,
                [
                    Digest::of(&[3, 1, 0, 0, 0, 0]),
                    Digest::of(&[3, 1, 0, 0, 0, 1])
                ]
            );
            assert_eq!(evidence.records, 3);
        }
    }
}

pub(crate) fn altered_session_sources_start_no_worker() {
    for fault in [
        "altered",
        "missing",
        "torn-index",
        "repeated",
        "out-chain",
        "missing-end",
        "missing-tail",
        "altered-tail",
        "torn-chunk",
        "repeated-field",
        "gap",
        "index-digest",
        "unknown-tag",
        "torn-body",
        "record-budget",
        "chunk-budget",
        "index-cap",
        "end-chain",
        "failed-window",
        "non-goal",
    ] {
        let case = Case::new(&format!("session-source-{fault}"));
        if fault == "record-budget" {
            let m = fs::read_to_string(case.manifest()).unwrap();
            fs::write(case.manifest(), m.replace("records = 1000", "records = 2")).unwrap();
        }
        if fault == "chunk-budget" || fault == "index-cap" {
            let m = fs::read_to_string(case.manifest()).unwrap();
            fs::write(
                case.manifest(),
                m.replace("bytes = 48000", "bytes = 1000000"),
            )
            .unwrap();
        }
        let fixture = session_fixture(&case, "source");
        if fault == "chunk-budget" {
            // Five remaining bytes read the second chunk's header before its six-byte size refuses.
            let budget = fixture_byte_budget(
                &case,
                &fixture,
                &["manifest", "index", "windows/000000.chunk"],
                5,
            );
            let used = fs::metadata(fixture.join("manifest")).unwrap().len()
                + fs::metadata(fixture.join("index")).unwrap().len()
                + fs::metadata(fixture.join("windows/000000.chunk"))
                    .unwrap()
                    .len();
            assert_eq!(budget - used, 5);
        }
        let chunk = fixture.join("windows/000000.chunk");
        let index = fixture.join("index");
        match fault {
            "altered" => fs::write(&chunk, [3, 1, 0, 0, 0, 9]).unwrap(),
            "missing" => fs::remove_file(chunk).unwrap(),
            "torn-chunk" => fs::write(chunk, [3, 10]).unwrap(),
            "torn-body" => fs::write(chunk, [3, 2, 0, 0, 0, 9]).unwrap(),
            "unknown-tag" => fs::write(chunk, [9, 1, 0, 0, 0, 9]).unwrap(),
            "repeated" => rechain_session(&fixture, [0, 0], false),
            "gap" => rechain_session(&fixture, [0, 2], false),
            "index-digest" => rechain_session(&fixture, [0, 1], true),
            "record-budget" | "chunk-budget" => {}
            "index-cap" => fs::write(index, vec![b'x'; (1 << 18) + 1]).unwrap(),
            "end-chain" | "non-goal" => {
                let path = fixture.join("end");
                let m = fs::read_to_string(&path).unwrap();
                let changed = if fault == "non-goal" {
                    m.replace("stop=goal", "stop=halted")
                } else {
                    let chain = m
                        .split_whitespace()
                        .find(|p| p.starts_with("chain="))
                        .unwrap();
                    m.replace(chain, &format!("chain={}", "0".repeat(64)))
                };
                fs::write(path, changed).unwrap();
            }
            "failed-window" => {
                let m = fs::read_to_string(&index).unwrap();
                fs::write(index, m.replacen("verdict=pass", "verdict=failed", 1)).unwrap();
            }
            "missing-end" => fs::remove_file(fixture.join("end")).unwrap(),
            "missing-tail" => fs::remove_file(fixture.join("windows/tail.chunk")).unwrap(),
            "altered-tail" => {
                fs::write(fixture.join("windows/tail.chunk"), [4, 1, 0, 0, 0, 1]).unwrap()
            }
            fault => {
                let original = fs::read_to_string(&index).unwrap();
                let changed = match fault {
                    "torn-index" => original.trim_end().to_owned(),
                    "out-chain" => {
                        let chain = original
                            .split_whitespace()
                            .find_map(|part| part.strip_prefix("chain="))
                            .unwrap();
                        original.replacen(chain, &"0".repeat(64), 1)
                    }
                    "repeated-field" => original.replacen("turns=1", "turns=1 turns=1", 1),
                    _ => panic!("a listed fault"),
                };
                fs::write(index, changed).unwrap();
            }
        }
        let ended = case.ended(output(session_command(&case, &fixture, true, "replay")));
        ended.class(2, "rejected");
        let reason = match fault {
            "altered" | "index-digest" => "differs from its index digest",
            "repeated" | "gap" => "out of order",
            "out-chain" => "out of its chain",
            "torn-chunk" | "torn-body" => "record is torn",
            "unknown-tag" => "unknown tag",
            "record-budget" | "chunk-budget" => "exceeds its manifest budget",
            "index-cap" => "Oversize",
            "end-chain" => "end names another window count or chain",
            "failed-window" => "counting end follows a failed window",
            "non-goal" => "counting end stops short of its goal",
            _ => "",
        };
        assert!(
            ended.reason().contains(reason),
            "{fault}: {}",
            ended.reason()
        );
        assert!(case.calls().is_empty(), "{fault} started a worker");
    }
}

pub(crate) fn session_replay_compares_every_fact_except_apply_time() {
    let end_edits = [
        ("apply_ms=000000000001", "apply_ms=000000000002", 0),
        ("stop=goal", "stop=limit turns", 4),
        ("turns=2", "turns=3", 4),
        ("virtual_us=600", "virtual_us=601", 4),
        ("skipped_us=500", "skipped_us=501", 4),
        ("rested_us=100", "rested_us=101", 4),
        ("carried=2", "carried=3", 4),
        ("registry=3", "registry=4", 4),
        ("outstanding=4", "outstanding=5", 4),
        ("kept=5", "kept=6", 4),
        ("window_bytes=64", "window_bytes=65", 4),
        ("fired=03 required=03", "fired=07 required=03", 4),
        (
            "terminal=complete pass fired=03 required=03 counts=true",
            "terminal=complete violation fired=03 required=03 counts=false",
            4,
        ),
    ];
    let index_edits = [
        ("turns=1", "turns=2"),
        ("verdict=pass", "verdict=failed"),
        ("carried=2", "carried=3"),
        ("registry=3", "registry=4"),
        ("outstanding=4", "outstanding=5"),
        ("kept=5", "kept=6"),
        ("published=6", "published=7"),
        ("hits=7", "hits=8"),
        ("faults=8", "faults=9"),
        ("reused=9", "reused=10"),
        ("healed=10", "healed=11"),
    ];
    for (i, (file, from, to, expected)) in end_edits
        .into_iter()
        .map(|(from, to, expected)| ("end", from, to, expected))
        .chain(
            index_edits
                .into_iter()
                .map(|(from, to)| ("index", from, to, 4)),
        )
        .enumerate()
    {
        let case = Case::new(&format!("session-replay-fact-{i}"));
        let fixture = session_fixture(&case, "source");
        if from == "stop=goal" || from == "verdict=pass" {
            let path = fixture.join("end");
            let end = fs::read_to_string(&path).unwrap();
            fs::write(
                path,
                end.replace(
                    "complete pass fired=03 required=03 counts=true",
                    "complete inconclusive fired=03 required=03 counts=false",
                ),
            )
            .unwrap();
        }
        case.plan("replay-session.edit", &format!("{file}\n{from}\n{to}"));
        let ended = case.ended(output(session_command(&case, &fixture, true, "replay")));
        let artifact = ended.class(
            expected,
            if expected == 0 {
                "counts"
            } else {
                "incomplete"
            },
        );
        assert!(
            artifact
                .session
                .as_ref()
                .unwrap()
                .verification_error
                .is_none(),
            "{artifact:?}"
        );
        assert_eq!(
            artifact.workers[&Text::new("replay-session").unwrap()].exit,
            Some(0)
        );
        if expected == 4 {
            assert!(
                ended
                    .reason()
                    .contains("verdict disagrees with its verified files or exit"),
                "{}",
                ended.reason()
            );
        }
        assert_eq!(case.calls(), ["capabilities", "replay-session"]);
    }
    let case = Case::new("session-replay-exit");
    let fixture = session_fixture(&case, "source");
    case.plan("replay-session.exit", "1");
    case.ended(output(session_command(&case, &fixture, true, "replay")))
        .class(4, "incomplete");
}

pub(crate) fn a_stop_in_the_second_window_publishes_the_verified_prefix() {
    for watchdog in [false, true] {
        let case = Case::new(if watchdog {
            "session-prefix-watchdog"
        } else {
            "session-prefix-interrupted"
        });
        let fixture = session_fixture(&case, "fixture");
        case.plan("session.tree", fixture.to_str().unwrap())
            .plan("session.prefix", if watchdog { "1" } else { "complete" })
            .plan("session.action", "hang");
        let mut command = session_command(&case, &case.manifest(), false, "prefix");
        command.args(["--watchdog", if watchdog { "10" } else { "30" }]);
        let child = Launcher(
            command
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        assert!(
            within(60, || case.dir.join("window-1-entered").exists()),
            "the named window seam was unreached"
        );
        if !watchdog {
            // SAFETY: the owned live launcher reserves this process identifier.
            assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGTERM) }, 0);
        }
        let ended = case.ended(wait_output(child));
        let record = ended.class(
            if watchdog { 6 } else { 5 },
            if watchdog { "watchdog" } else { "interrupted" },
        );
        let prefix = record.session.as_ref().unwrap();
        assert_eq!(prefix.verified_windows, 1);
        assert_eq!(prefix.digests, [Digest::of(&[3, 1, 0, 0, 0, 0])]);
        assert!(!prefix.complete && !prefix.counts);
        assert!(prefix.end.is_none());
        assert!(
            prefix
                .verification_error
                .as_ref()
                .unwrap()
                .as_str()
                .ends_with("/end is missing")
        );
        let stored = fs::read_to_string(ended.dir().join("session/index")).unwrap();
        assert!(stored.contains(&format!("chain={}", prefix.chain)));
    }
}

pub(crate) fn forked_summaries_require_worker_exit_agreement() {
    for form in ["branch", "explore"] {
        for fault in [
            "rewrite",
            "remove",
            "abort",
            "foreign",
            "unpinned",
            "overmaximum",
            "non-ascii",
            "control",
        ] {
            let case = Case::new(&format!("forked-input-{form}-{fault}"));
            let input = case.dir.join("bundle");
            let normal = manifest(&[]);
            let declared = match fault {
                "foreign" => normal.replace(
                    &format!("build = {}", archive().1.build.as_str()),
                    "build = foreign",
                ),
                "unpinned" => {
                    normal
                        .lines()
                        .filter(|l| !l.starts_with("build = "))
                        .collect::<Vec<_>>()
                        .join("\n")
                        + "\n"
                }
                "overmaximum" => normal.replace("records = 1000", "records = 1"),
                _ => normal,
            };
            fs::write(&input, bundle(&declared, 2)).unwrap();
            case.plan(&format!("{form}.out"), &forked_fixture(form, 1, 1));
            if ["rewrite", "remove", "abort"].contains(&fault) {
                case.plan(&format!("{form}.action"), fault)
                    .plan("rewrite.target", input.to_str().unwrap());
            }
            let milestone = match fault {
                "non-ascii" => "é",
                "control" => "pending\nput",
                _ => "pending-put",
            };
            let mut args = vec![
                OsStr::new(form),
                input.as_os_str(),
                OsStr::new("--archive"),
                archive().0.as_os_str(),
                OsStr::new("--milestone"),
                OsStr::new(milestone),
                OsStr::new("--run-id"),
                OsStr::new("result"),
            ];
            if form == "branch" {
                args.extend([OsStr::new("--suffixes"), OsStr::new("1")]);
            }
            let ended = case.ended(output(case.command(&args)));
            if ["rewrite", "remove", "abort"].contains(&fault) {
                let record = ended.class(4, "incomplete");
                assert_eq!(case.calls(), ["capabilities", form]);
                let raw = fs::read(ended.dir().join(format!("{form}.stdout"))).unwrap();
                assert_eq!(
                    record.workers[&Text::new(form).unwrap()].stdout,
                    Digest::of(&raw)
                );
                assert_eq!(raw, forked_fixture(form, 1, 1).as_bytes());
            } else {
                ended.class(2, "rejected");
                assert!(case.calls().is_empty());
            }
        }
    }
    for suffix in [None, Some("0")] {
        let case = Case::new(if suffix.is_none() {
            "explore-missing-depth"
        } else {
            "explore-zero-depth"
        });
        let input = case.dir.join("bundle");
        let normal = manifest(&[]);
        let changed = match suffix {
            None => normal.replace("suffix_depth = 2\n", ""),
            Some(value) => normal.replace("suffix_depth = 2", &format!("suffix_depth = {value}")),
        };
        fs::write(&input, bundle(&changed, 2)).unwrap();
        let ended = case.ended(output(case.command(&[
            OsStr::new("explore"),
            input.as_os_str(),
            OsStr::new("--archive"),
            archive().0.as_os_str(),
            OsStr::new("--milestone"),
            OsStr::new("pending-put"),
            OsStr::new("--run-id"),
            OsStr::new("result"),
        ])));
        ended.class(2, "rejected");
        assert!(ended.reason().contains("suffix_depth"));
        assert!(case.calls().is_empty());
    }
    let digest = "1f27fb908bebec8fe9cd01041d338f6565bef18f41ee2d4567bb73df1dfa035c";
    let head = format!(
        "milestone: pending-put boundary=13 semantic=501 decisions=100 prefix={digest}\nwitness: pending-put holds=true boundary=13 upload=attempt:1,grant:3,held:2,outcome:0 armed=false\nparent: reproduced\n"
    );
    let branch = format!(
        "{head}child: suffix=0 sibling=0 class=success digest={digest} terminal=complete pass fired=03 required=03\nbranch: 1 children, 1 credited, 0 problems\n"
    );
    let explore = format!(
        "label: composed-bounded\n{head}limits: depth=2 children=3 faults=12 advances=16\nnode: path=0 class=success wall_us=1 cpu_us=1 max_rss_kib=1\nleaf: path=0 digest={digest} unexplored=0 counts=true verdict=complete pass fired=03 required=03\nfrontier: nodes=1 credited=1 explored=1 failing=0 unexplored=0\nexplore: composed-bounded, 0 problems\n"
    );
    for (form, out) in [("branch", branch), ("explore", explore)] {
        for (i, exit, stdout, expected) in [
            (0, "0", out.clone(), 0),
            (1, "1", out.clone(), 4),
            (2, "3", out.clone(), 4),
            (
                3,
                "1",
                "parent: diverged before the milestone\n".to_owned(),
                1,
            ),
            (
                4,
                "0",
                out.replace("parent: reproduced", "parent: changed"),
                4,
            ),
            (5, "2", String::new(), 2),
            (7, "2", out.clone(), 4),
            (6, "0", out.trim_end().to_owned(), 4),
        ] {
            let case = Case::new(&format!("{form}-exit-agreement-{i}"));
            let input = case.dir.join("bundle");
            fs::write(&input, bundle(&manifest(&[]), 2)).unwrap();
            case.plan(&format!("{form}.out"), &stdout)
                .plan(&format!("{form}.exit"), exit);
            let mut args = vec![
                OsStr::new(form),
                input.as_os_str(),
                OsStr::new("--archive"),
                archive().0.as_os_str(),
                OsStr::new("--milestone"),
                OsStr::new("pending-put"),
                OsStr::new("--run-id"),
                OsStr::new("forked"),
            ];
            if form == "branch" {
                args.extend([OsStr::new("--suffixes"), OsStr::new("1")]);
            }
            case.ended(output(case.command(&args))).class(
                expected,
                match expected {
                    0 => "counts",
                    1 => "complete",
                    2 => "rejected",
                    _ => "incomplete",
                },
            );
        }
    }
}

pub(crate) fn branch_siblings_match_the_exact_requested_pairs_and_reports() {
    let digest = "1f27fb908bebec8fe9cd01041d338f6565bef18f41ee2d4567bb73df1dfa035c";
    let parent = format!(
        "milestone: pending-put boundary=13 semantic=501 decisions=100 prefix={digest}\nwitness: pending-put holds=true boundary=13 upload=attempt:1,grant:3,held:2,outcome:0 armed=false\nparent: reproduced\n"
    );
    let child = |sibling, digest: &str, terminal| {
        format!(
            "child: suffix=0 sibling={sibling} class=success digest={digest} terminal={terminal}\n"
        )
    };
    let pass = "complete pass fired=03 required=03";
    for (i, children, exit, expected) in [
        (0, child(0, digest, pass) + &child(1, digest, pass), "0", 0),
        (
            1,
            child(0, digest, pass) + &child(1, &"a".repeat(64), pass),
            "0",
            4,
        ),
        (
            2,
            child(0, digest, pass) + &child(1, digest, "complete violation fired=03 required=03"),
            "0",
            4,
        ),
        (3, child(0, digest, pass) + &child(2, digest, pass), "0", 4),
        (
            5,
            child(0, digest, pass) + &child(1, digest, "complete pass fired=07 required=03"),
            "0",
            4,
        ),
        (
            4,
            child(0, digest, pass) + &child(1, &"a".repeat(64), pass),
            "1",
            1,
        ),
    ] {
        let case = Case::new(&format!("branch-siblings-{i}"));
        let input = case.dir.join("bundle");
        fs::write(&input, bundle(&manifest(&[]), 2)).unwrap();
        case.plan(
            "branch.out",
            &format!("{parent}{children}branch: 2 children, 2 credited, 0 problems\n"),
        )
        .plan("branch.exit", exit);
        let args = [
            OsStr::new("branch"),
            input.as_os_str(),
            OsStr::new("--archive"),
            archive().0.as_os_str(),
            OsStr::new("--milestone"),
            OsStr::new("pending-put"),
            OsStr::new("--suffixes"),
            OsStr::new("1"),
            OsStr::new("--siblings"),
            OsStr::new("2"),
            OsStr::new("--run-id"),
            OsStr::new("siblings"),
        ];
        case.ended(output(case.command(&args))).class(
            expected,
            match expected {
                0 => "counts",
                1 => "complete",
                _ => "incomplete",
            },
        );
    }
    for (name, suffixes, siblings, mut printed, expected) in [
        ("surplus", "1", "1", forked_fixture("branch", 1, 2), 4),
        ("last-suffix", "3", "2", forked_fixture("branch", 3, 2), 4),
        (
            "independent-suffixes",
            "3",
            "2",
            forked_fixture("branch", 3, 2),
            0,
        ),
    ] {
        let case = Case::new(&format!("branch-pair-proof-{name}"));
        let input = case.dir.join("bundle");
        fs::write(&input, bundle(&manifest(&[]), 2)).unwrap();
        if name == "last-suffix" {
            let old = format!("suffix=2 sibling=1 class=success digest={digest}");
            printed = printed.replace(
                &old,
                &format!("suffix=2 sibling=1 class=success digest={}", "a".repeat(64)),
            );
        } else if name == "independent-suffixes" {
            for sibling in 0..2 {
                let old = format!("suffix=2 sibling={sibling} class=success digest={digest}");
                printed = printed.replace(
                    &old,
                    &format!(
                        "suffix=2 sibling={sibling} class=success digest={}",
                        "a".repeat(64)
                    ),
                );
            }
        }
        case.plan("branch.out", &printed);
        let ended = case.ended(output(case.command(&[
            OsStr::new("branch"),
            input.as_os_str(),
            OsStr::new("--archive"),
            archive().0.as_os_str(),
            OsStr::new("--milestone"),
            OsStr::new("pending-put"),
            OsStr::new("--suffixes"),
            OsStr::new(suffixes),
            OsStr::new("--siblings"),
            OsStr::new(siblings),
            OsStr::new("--run-id"),
            OsStr::new("result"),
        ])));
        ended.class(
            expected,
            if expected == 0 {
                "counts"
            } else {
                "incomplete"
            },
        );
        if name == "surplus" {
            assert!(ended.reason().contains("another milestone or child set"));
        }
    }
    for siblings in ["0", "5"] {
        let case = Case::new(&format!("invalid-siblings-{siblings}"));
        let input = case.dir.join("bundle");
        fs::write(&input, bundle(&manifest(&[]), 2)).unwrap();
        case.plan(
            "branch.out",
            &forked_fixture("branch", 1, siblings.parse().unwrap()),
        );
        let args = [
            OsStr::new("branch"),
            input.as_os_str(),
            OsStr::new("--archive"),
            archive().0.as_os_str(),
            OsStr::new("--milestone"),
            OsStr::new("pending-put"),
            OsStr::new("--suffixes"),
            OsStr::new("1"),
            OsStr::new("--siblings"),
            OsStr::new(siblings),
            OsStr::new("--run-id"),
            OsStr::new("refused"),
        ];
        let ended = case.ended(output(case.command(&args)));
        ended.class(2, "rejected");
        assert!(ended.reason().contains("suffixes must be from 1 to 16"));
        assert!(case.calls().is_empty());
    }
}

pub(crate) fn session_verdicts_require_files_stdout_and_source_stability() {
    for (fault, stdout, edit, exit, reason) in [
        (
            "wrong-windows",
            "replay: reproduced, 3 windows, chain {chain}\n",
            None,
            "0",
            "verdict disagrees",
        ),
        (
            "wrong-chain",
            "replay: reproduced, 2 windows, chain 0000000000000000000000000000000000000000000000000000000000000000\n",
            None,
            "0",
            "verdict disagrees",
        ),
        (
            "refused-with-result",
            "replay: reproduced, 2 windows, chain {chain}\n",
            None,
            "2",
            "refused session replay printed a result",
        ),
        ("empty-output", "", None, "0", "session replay output"),
        (
            "diverged-exit-zero",
            "replay: diverged after the last window: the end differs\n",
            Some("end\nkept=5\nkept=6"),
            "0",
            "verdict disagrees",
        ),
        (
            "diverged-exit-three",
            "replay: diverged after the last window: the end differs\n",
            Some("end\nkept=5\nkept=6"),
            "3",
            "verdict disagrees",
        ),
    ] {
        let case = Case::new(&format!("session-replay-verdict-{fault}"));
        let source = session_fixture(&case, "source");
        let end = fs::read_to_string(source.join("end")).unwrap();
        let chain = end
            .split_whitespace()
            .find_map(|part| part.strip_prefix("chain="))
            .unwrap();
        case.plan("replay-session.out", &stdout.replace("{chain}", chain))
            .plan("replay-session.exit", exit);
        if let Some(edit) = edit {
            case.plan("replay-session.edit", edit);
        }
        let ended = case.ended(output(session_command(&case, &source, true, "result")));
        ended.class(4, "incomplete");
        assert!(
            ended.reason().contains(reason),
            "{fault}: {}",
            ended.reason()
        );
    }
    for (i, replay, edit, stdout, exit, expected) in [
        (
            0,
            false,
            Some(
                "end\nterminal=complete pass fired=03 required=03 counts=true\nterminal=complete violation fired=03 required=03 counts=false",
            ),
            None,
            "1",
            1,
        ),
        (
            1,
            true,
            Some("end\nkept=5\nkept=6"),
            Some("replay: diverged after the last window: the end differs\n"),
            "1",
            1,
        ),
        (
            2,
            true,
            None,
            Some("replay: diverged after the last window: the end differs\n"),
            "1",
            4,
        ),
        (
            3,
            false,
            None,
            Some(
                "session: 2 windows, chain 0000000000000000000000000000000000000000000000000000000000000000\nend: stop=goal terminal=complete pass fired=03 required=03 counts=true turns=2 virtual_us=600 skipped_us=500 rested_us=100 apply_ms=000000000001 failure=None carried=2 registry=3 outstanding=4 kept=5 window_bytes=64\n",
            ),
            "0",
            4,
        ),
        (
            4,
            false,
            Some(
                "end\nterminal=complete pass fired=03 required=03 counts=true\nterminal=complete violation fired=03 required=03 counts=false",
            ),
            None,
            "0",
            4,
        ),
    ] {
        let case = Case::new(&format!("session-verified-verdict-{i}"));
        let fixture = session_fixture(&case, "source");
        let form = if replay { "replay-session" } else { "session" };
        case.plan(&format!("{form}.tree"), fixture.to_str().unwrap())
            .plan(&format!("{form}.exit"), exit);
        if let Some(edit) = edit {
            case.plan(&format!("{form}.edit"), edit);
        }
        if let Some(stdout) = stdout {
            case.plan(&format!("{form}.out"), stdout);
        }
        let input = if replay { fixture } else { case.manifest() };
        let ended = case.ended(output(session_command(&case, &input, replay, "result")));
        let record = ended.class(
            expected,
            if expected == 1 {
                "complete"
            } else {
                "incomplete"
            },
        );
        assert!(
            record
                .session
                .as_ref()
                .unwrap()
                .verification_error
                .is_none()
        );
        assert_eq!(
            record.workers[&Text::new(form).unwrap()].exit,
            Some(exit.parse().unwrap())
        );
        if i == 4 {
            assert!(
                ended
                    .reason()
                    .contains("worker exit disagrees with the session end")
            );
        }
        assert!(!record.session.as_ref().unwrap().counts);
    }
    for fault in ["failure", "tail", "source"] {
        let case = Case::new(&format!("session-extra-fact-{fault}"));
        let fixture = session_fixture(&case, "source");
        match fault {
            "failure" => {
                let path = fixture.join("end");
                let end = fs::read_to_string(&path)
                    .unwrap()
                    .replace(
                        "terminal=complete pass fired=03 required=03 counts=true",
                        "terminal=complete violation fired=03 required=03 counts=false",
                    )
                    .replace("failure=None", "failure=Some(a)");
                fs::write(path, end).unwrap();
                case.plan(
                    "replay-session.edit",
                    "end\nfailure=Some(a)\nfailure=Some(b)",
                );
            }
            "tail" => {
                case.plan("replay-session.tail", "\u{4}\u{1}\0\0\0x");
            }
            "source" => {
                case.plan("replay-session.action", "rewrite").plan(
                    "rewrite.target",
                    fixture.join("windows/000000.chunk").to_str().unwrap(),
                );
            }
            _ => panic!("a listed fault"),
        }
        let ended = case.ended(output(session_command(&case, &fixture, true, "result")));
        let record = ended.class(4, "incomplete");
        assert!(
            record
                .session
                .as_ref()
                .unwrap()
                .verification_error
                .is_none(),
            "{record:?}"
        );
        if fault == "source" {
            assert!(ended.reason().contains("changed after admission"));
        }
        assert_eq!(
            record.workers[&Text::new("replay-session").unwrap()].exit,
            Some(0)
        );
        if fault != "source" {
            assert!(
                ended
                    .reason()
                    .contains("verdict disagrees with its verified files or exit"),
                "{}",
                ended.reason()
            );
        }
    }
}

pub(crate) fn forked_false_credit_and_noncredit_classes_preserve_exit_agreement() {
    let digest = "1f27fb908bebec8fe9cd01041d338f6565bef18f41ee2d4567bb73df1dfa035c";
    let head = format!(
        "milestone: pending-put boundary=13 semantic=501 decisions=100 prefix={digest}\nwitness: pending-put holds=true boundary=13 upload=attempt:1,grant:3,held:2,outcome:0 armed=false\nparent: reproduced\n"
    );
    let mut rows = Vec::new();
    for class in [
        "failed",
        "mismatch",
        "signaled",
        "silent",
        "malformed",
        "watchdog",
        "lost",
    ] {
        rows.push(("branch", format!("{head}child: suffix=0 sibling=0 class={class}\nbranch: 1 children, 0 credited, 0 problems\n"), "1", 1));
    }
    for terminal in [
        "complete violation fired=03 required=03",
        "complete pass fired=01 required=03",
    ] {
        let text = format!(
            "{head}child: suffix=0 sibling=0 class=success digest={digest} terminal={terminal}\nbranch: 1 children, 1 credited, 0 problems\n"
        );
        rows.push(("branch", text.clone(), "0", 4));
        rows.push(("branch", text, "1", 1));
    }
    rows.push((
        "branch",
        format!("{head}branch: 0 children, 0 credited, 0 problems\n"),
        "0",
        4,
    ));
    rows.push(("branch", format!("{head}child: suffix=0 sibling=0 class=success\nbranch: 1 children, 1 credited, 0 problems\n"), "0", 4));
    let tree = format!(
        "label: composed-bounded\n{head}limits: depth=2 children=3 faults=12 advances=16\nnode: path=0 class=success wall_us=1 cpu_us=1 max_rss_kib=1\nleaf: path=0 digest={digest} unexplored=0 counts=false verdict=complete violation fired=03 required=03\nfrontier: nodes=1 credited=1 explored=1 failing=1 unexplored=0\nexplore: composed-bounded, 0 problems\n"
    );
    rows.push(("explore", tree.clone(), "0", 4));
    rows.push(("explore", tree, "1", 1));
    rows.push(("explore", format!("label: composed-bounded\n{head}limits: depth=2 children=3 faults=12 advances=16\nfrontier: nodes=0 credited=0 explored=0 failing=0 unexplored=0\nexplore: composed-bounded, 0 problems\n"), "0", 4));
    for (i, (form, stdout, exit, expected)) in rows.into_iter().enumerate() {
        let case = Case::new(&format!("forked-noncredit-{i}"));
        let input = case.dir.join("bundle");
        fs::write(&input, bundle(&manifest(&[]), 2)).unwrap();
        case.plan(&format!("{form}.out"), &stdout)
            .plan(&format!("{form}.exit"), exit);
        let mut args = vec![
            OsStr::new(form),
            input.as_os_str(),
            OsStr::new("--archive"),
            archive().0.as_os_str(),
            OsStr::new("--milestone"),
            OsStr::new("pending-put"),
            OsStr::new("--run-id"),
            OsStr::new("result"),
        ];
        if form == "branch" {
            args.extend([OsStr::new("--suffixes"), OsStr::new("1")]);
        }
        case.ended(output(case.command(&args))).class(
            expected,
            if expected == 1 {
                "complete"
            } else {
                "incomplete"
            },
        );
    }
}

pub(crate) fn forked_watchdogs_use_the_tripled_manifest_bound() {
    let case = Case::new("branch-tripled-watchdog");
    let input = case.dir.join("bundle");
    fs::write(&input, bundle(&manifest(&["watchdog = 2"]), 2)).unwrap();
    case.plan("branch.action", "hang");
    let args = [
        OsStr::new("branch"),
        input.as_os_str(),
        OsStr::new("--archive"),
        archive().0.as_os_str(),
        OsStr::new("--milestone"),
        OsStr::new("pending-put"),
        OsStr::new("--suffixes"),
        OsStr::new("1"),
        OsStr::new("--run-id"),
        OsStr::new("result"),
    ];
    let ended = case.ended(output(case.command(&args)));
    ended.class(6, "watchdog");
    assert!(ended.reason().contains("6s watchdog"), "{}", ended.reason());
    assert!(ended.reason().contains("branch"));
    assert_eq!(case.calls(), ["capabilities", "branch"]);
}

pub(crate) fn new_launcher_outputs_and_fork_bounds_refuse_before_workers() {
    for form in ["branch", "explore", "session", "replay-session"] {
        let case = Case::new(&format!("existing-{form}-output"));
        let input = case.dir.join("bundle");
        fs::write(&input, bundle(&manifest(&[]), 2)).unwrap();
        let source = session_fixture(&case, "source");
        let target = case.dir.join("existing");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("keep"), b"original").unwrap();
        let manifest = case.manifest();
        let mut args = vec![OsStr::new(form)];
        if form == "session" {
            args.extend([OsStr::new("--manifest"), manifest.as_os_str()]);
        } else {
            args.push(if form == "replay-session" {
                source.as_os_str()
            } else {
                input.as_os_str()
            });
        }
        args.extend([
            OsStr::new("--archive"),
            archive().0.as_os_str(),
            OsStr::new("--output"),
            target.as_os_str(),
            OsStr::new("--run-id"),
            OsStr::new("refused"),
        ]);
        if matches!(form, "branch" | "explore") {
            args.extend([OsStr::new("--milestone"), OsStr::new("pending-put")]);
        }
        if form == "branch" {
            args.extend([OsStr::new("--suffixes"), OsStr::new("1")]);
        }
        case.ended(output(case.command(&args))).class(2, "rejected");
        assert!(case.calls().is_empty());
        assert_eq!(fs::read(target.join("keep")).unwrap(), b"original");
    }
    for suffixes in ["0", "17"] {
        let case = Case::new(&format!("invalid-suffixes-{suffixes}"));
        let input = case.dir.join("bundle");
        fs::write(&input, bundle(&manifest(&[]), 2)).unwrap();
        case.plan(
            "branch.out",
            &forked_fixture("branch", suffixes.parse().unwrap(), 1),
        );
        let args = [
            OsStr::new("branch"),
            input.as_os_str(),
            OsStr::new("--archive"),
            archive().0.as_os_str(),
            OsStr::new("--milestone"),
            OsStr::new("pending-put"),
            OsStr::new("--suffixes"),
            OsStr::new(suffixes),
            OsStr::new("--run-id"),
            OsStr::new("refused"),
        ];
        let ended = case.ended(output(case.command(&args)));
        ended.class(2, "rejected");
        assert!(ended.reason().contains("suffixes must be from 1 to 16"));
        assert!(case.calls().is_empty());
    }
}

pub(crate) fn reproduced_sessions_use_the_end_credit_class() {
    for (name, ending, class, complete) in [
        (
            "pass",
            "terminal=complete pass fired=03 required=03 counts=true",
            0,
            true,
        ),
        (
            "violation",
            "terminal=complete violation fired=03 required=03 counts=false",
            1,
            true,
        ),
        (
            "infrastructure",
            "terminal=infrastructure sink counts=false",
            4,
            false,
        ),
    ] {
        let case = Case::new(&format!("reproduced-session-class-{name}"));
        let source = session_fixture(&case, "source");
        let end = source.join("end");
        let text = fs::read_to_string(&end).unwrap().replace(
            "terminal=complete pass fired=03 required=03 counts=true",
            ending,
        );
        fs::write(end, text).unwrap();
        let ended = case.ended(output(session_command(&case, &source, true, "result")));
        let record = ended.class(
            class,
            match class {
                0 => "counts",
                1 => "complete",
                _ => "incomplete",
            },
        );
        for evidence in [
            record.session.as_ref().unwrap(),
            record.session_original.as_ref().unwrap(),
        ] {
            assert_eq!(evidence.complete, complete);
            assert_eq!(evidence.counts, class == 0);
            assert!(evidence.verification_error.is_none());
        }
        assert_eq!(
            record.workers[&Text::new("replay-session").unwrap()].exit,
            Some(0)
        );
    }
}

pub(crate) fn altered_archives_refuse_every_new_command_before_workers() {
    for form in ["branch", "explore", "session", "replay-session"] {
        let case = Case::new(&format!("altered-archive-{form}"));
        let archive = case.dir.join("archive");
        copy_tree(&self::archive().0, &archive);
        let library = first_library(&archive);
        fs::set_permissions(
            &library,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();
        fs::write(library, b"changed").unwrap();
        let source = session_fixture(&case, "source");
        let manifest_path = case.manifest();
        let input = case.dir.join("bundle");
        fs::write(&input, bundle(&manifest(&[]), 2)).unwrap();
        let mut args = vec![OsStr::new(form)];
        if form == "session" {
            args.extend([OsStr::new("--manifest"), manifest_path.as_os_str()]);
        } else {
            args.push(if form == "replay-session" {
                source.as_os_str()
            } else {
                input.as_os_str()
            });
        }
        args.extend([
            OsStr::new("--archive"),
            archive.as_os_str(),
            OsStr::new("--run-id"),
            OsStr::new("refused"),
        ]);
        if matches!(form, "branch" | "explore") {
            args.extend([OsStr::new("--milestone"), OsStr::new("pending-put")]);
        }
        if form == "branch" {
            args.extend([OsStr::new("--suffixes"), OsStr::new("1")]);
        }
        case.ended(output(case.command(&args))).class(2, "rejected");
        assert!(case.calls().is_empty());
    }
}

pub(crate) fn a_diverged_infrastructure_session_retains_incomplete_window_state() {
    let case = Case::new("diverged-infrastructure-state");
    let fixture = session_fixture(&case, "source");
    case.plan("replay-session.edit", "end\nterminal=complete pass fired=03 required=03 counts=true\nterminal=infrastructure sink counts=false")
        .plan("replay-session.out", "replay: diverged after the last window: the end differs\n")
        .plan("replay-session.exit", "1");
    let ended = case.ended(output(session_command(&case, &fixture, true, "result")));
    let record = ended.class(1, "complete");
    let observed = record.session.as_ref().unwrap();
    assert!(!observed.complete && !observed.counts);
    assert!(observed.verification_error.is_none());
    assert_eq!(observed.verified_windows, 2);
}

fn forked_fixture(form: &str, suffixes: u32, siblings: u32) -> String {
    let digest = "1f27fb908bebec8fe9cd01041d338f6565bef18f41ee2d4567bb73df1dfa035c";
    let head = format!(
        "milestone: pending-put boundary=13 semantic=501 decisions=100 prefix={digest}\nwitness: pending-put holds=true boundary=13 upload=attempt:1,grant:3,held:2,outcome:0 armed=false\nparent: reproduced\n"
    );
    if form == "explore" {
        return format!(
            "label: composed-bounded\n{head}limits: depth=2 children=3 faults=12 advances=16\nnode: path=0 class=success wall_us=1 cpu_us=1 max_rss_kib=1\nleaf: path=0 digest={digest} unexplored=0 counts=true verdict=complete pass fired=03 required=03\nfrontier: nodes=1 credited=1 explored=1 failing=0 unexplored=0\nexplore: composed-bounded, 0 problems\n"
        );
    }
    let mut out = head;
    for suffix in 0..suffixes {
        for sibling in 0..siblings {
            out.push_str(&format!("child: suffix={suffix} sibling={sibling} class=success digest={digest} terminal=complete pass fired=03 required=03\n"));
        }
    }
    out.push_str(&format!(
        "branch: {} children, {} credited, 0 problems\n",
        suffixes * siblings,
        suffixes * siblings
    ));
    out
}

pub(crate) fn forked_rules_reach_nodes_milestones_problems_and_maximum_pairs() {
    let mut rows = Vec::new();
    for form in ["branch", "explore"] {
        let original = forked_fixture(form, 1, 1);
        rows.push((
            form,
            original.replace("pending-put", "another-milestone"),
            "0",
            4,
        ));
        let last = if form == "branch" {
            "branch: 1 children, 1 credited, 0 problems"
        } else {
            "explore: composed-bounded, 0 problems"
        };
        let changed = last.replace("0 problems", "1 problems");
        rows.push((
            form,
            original.replace(last, &format!("problem: a failed check\n{changed}")),
            "0",
            4,
        ));
    }
    let original = forked_fixture("explore", 1, 1);
    rows.push(("explore", original.replace("depth=2", "depth=1"), "0", 4));
    let dangling = original
        .replace(
            "leaf: path=0",
            "node: path=1 class=success wall_us=1 cpu_us=1 max_rss_kib=1\nleaf: path=0",
        )
        .replace("nodes=1 credited=1", "nodes=2 credited=2");
    rows.push(("explore", dangling, "0", 4));
    let interior_leaf = original
        .replace("leaf: path=0", "node: path=0.0 class=success wall_us=1 cpu_us=1 max_rss_kib=1\nleaf: path=0")
        .replace("frontier:", "leaf: path=0.0 digest=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa unexplored=0 counts=true verdict=complete pass fired=03 required=03\nfrontier:")
        .replace("nodes=1 credited=1 explored=1", "nodes=2 credited=2 explored=2");
    rows.push(("explore", interior_leaf, "0", 4));
    let nested = original
        .replace(
            "leaf: path=0 digest=",
            "node: path=0.0 class=success wall_us=1 cpu_us=1 max_rss_kib=1\nleaf: path=0.0 digest=",
        )
        .replace("nodes=1 credited=1", "nodes=2 credited=2");
    rows.push(("explore", nested.replace("0.0", "0.3"), "0", 4));
    let too_deep = nested
        .replace(
            "leaf: path=0.0",
            "node: path=0.0.0 class=success wall_us=1 cpu_us=1 max_rss_kib=1\nleaf: path=0.0.0",
        )
        .replace("nodes=2 credited=2", "nodes=3 credited=3");
    rows.push(("explore", too_deep, "0", 4));
    rows.push(("explore", nested, "0", 0));
    for (class, problem, exit, expected) in
        [("signaled", false, "0", 4), ("watchdog", true, "1", 1)]
    {
        let original = forked_fixture("explore", 1, 1);
        let extra = format!("node: path=1 class={class} wall_us=1 cpu_us=1 max_rss_kib=1\n");
        let mut changed = original
            .replace("leaf: path=0", &format!("{extra}leaf: path=0"))
            .replace("nodes=1 credited=1", "nodes=2 credited=1");
        if problem {
            changed = changed.replace(
                "explore: composed-bounded, 0 problems",
                "problem: a child expired\nexplore: composed-bounded, 1 problems",
            );
        }
        rows.push(("explore", changed, exit, expected));
    }
    for (i, (form, stdout, exit, expected)) in rows.into_iter().enumerate() {
        let case = Case::new(&format!("forked-rule-witness-{i}"));
        let input = case.dir.join("bundle");
        fs::write(&input, bundle(&manifest(&[]), 2)).unwrap();
        case.plan(&format!("{form}.out"), &stdout)
            .plan(&format!("{form}.exit"), exit);
        let mut args = vec![
            OsStr::new(form),
            input.as_os_str(),
            OsStr::new("--archive"),
            archive().0.as_os_str(),
            OsStr::new("--milestone"),
            OsStr::new("pending-put"),
            OsStr::new("--run-id"),
            OsStr::new("result"),
        ];
        if form == "branch" {
            args.extend([OsStr::new("--suffixes"), OsStr::new("1")]);
        }
        let ended = case.ended(output(case.command(&args)));
        ended.class(
            expected,
            match expected {
                0 => "counts",
                1 => "complete",
                _ => "incomplete",
            },
        );
        assert_eq!(case.calls(), ["capabilities", form]);
    }
    let case = Case::new("maximum-suffix-sibling-pairs");
    let input = case.dir.join("bundle");
    fs::write(&input, bundle(&manifest(&[]), 2)).unwrap();
    case.plan("branch.out", &forked_fixture("branch", 16, 4));
    let args = [
        OsStr::new("branch"),
        input.as_os_str(),
        OsStr::new("--archive"),
        archive().0.as_os_str(),
        OsStr::new("--milestone"),
        OsStr::new("pending-put"),
        OsStr::new("--suffixes"),
        OsStr::new("16"),
        OsStr::new("--siblings"),
        OsStr::new("4"),
        OsStr::new("--run-id"),
        OsStr::new("result"),
    ];
    case.ended(output(case.command(&args))).class(0, "counts");
}

pub(crate) fn session_manifest_and_stdout_facts_have_independent_oracles() {
    for fault in ["manifest", "cpu", "stdout-windows", "stdout-end"] {
        let case = Case::new(&format!("session-fact-witness-{fault}"));
        let original = fs::read_to_string(case.manifest()).unwrap();
        let changed = if fault == "manifest" {
            original.replace("root = 3", "root = 4")
        } else if fault == "cpu" {
            format!("{original}cpu = other-features\n")
        } else {
            original.clone()
        };
        fs::write(case.manifest(), changed).unwrap();
        let fixture = session_fixture(&case, "fixture");
        let source = if fault == "cpu" {
            format!("{original}cpu = recorded-features\n")
        } else {
            original
        };
        fs::write(case.manifest(), source).unwrap();
        case.plan("session.tree", fixture.to_str().unwrap());
        if fault.starts_with("stdout") {
            let index = fs::read_to_string(fixture.join("index")).unwrap();
            let chain = index
                .lines()
                .last()
                .unwrap()
                .split_whitespace()
                .find_map(|field| field.strip_prefix("chain="))
                .unwrap();
            let end = fs::read_to_string(fixture.join("end")).unwrap();
            let end = end.split(" windows=").next().unwrap();
            let printed = format!("session: 2 windows, chain {chain}\n{end}\n");
            case.plan(
                "session.out",
                &if fault == "stdout-windows" {
                    printed.replace("session: 2", "session: 1")
                } else {
                    printed.replace("kept=5", "kept=6")
                },
            );
        }
        let ended = case.ended(output(session_command(
            &case,
            &case.manifest(),
            false,
            "result",
        )));
        let record = ended.class(
            if fault == "cpu" { 0 } else { 4 },
            if fault == "cpu" {
                "counts"
            } else {
                "incomplete"
            },
        );
        if fault == "manifest" {
            assert!(ended.reason().contains("differs from the frozen input"));
        } else {
            assert!(
                record
                    .session
                    .as_ref()
                    .unwrap()
                    .verification_error
                    .is_none()
            );
        }
    }
}

pub(crate) fn explicit_fork_watchdogs_keep_the_supplied_wait() {
    let case = Case::new("explicit-fork-watchdog");
    let input = case.dir.join("bundle");
    fs::write(&input, bundle(&manifest(&["watchdog = 1"]), 2)).unwrap();
    case.plan("branch.action", "hang");
    let args = [
        OsStr::new("branch"),
        input.as_os_str(),
        OsStr::new("--archive"),
        archive().0.as_os_str(),
        OsStr::new("--milestone"),
        OsStr::new("pending-put"),
        OsStr::new("--suffixes"),
        OsStr::new("1"),
        OsStr::new("--watchdog"),
        OsStr::new("2"),
        OsStr::new("--run-id"),
        OsStr::new("result"),
    ];
    let ended = case.ended(output(case.command(&args)));
    ended.class(6, "watchdog");
    assert!(ended.reason().contains("2s watchdog"), "{}", ended.reason());
    assert!(ended.reason().contains("branch"));
    assert_eq!(case.calls(), ["capabilities", "branch"]);
}

pub(crate) fn panicked_session_sources_verify_before_replaying_without_credit() {
    for broken in [false, true] {
        let case = Case::new(if broken {
            "panicked-source-chain"
        } else {
            "panicked-source-replay"
        });
        let source = session_fixture(&case, "source");
        let end_path = source.join("end");
        let end = fs::read_to_string(&end_path).unwrap();
        let footer = end.rsplit_once(" windows=").unwrap().1;
        fs::write(
            &end_path,
            format!("end: panicked src/world.rs:1:2: planted windows={footer}"),
        )
        .unwrap();
        if broken {
            let path = source.join("index");
            let index = fs::read_to_string(&path).unwrap();
            let chain = index
                .split_whitespace()
                .find_map(|f| f.strip_prefix("chain="))
                .unwrap();
            fs::write(path, index.replacen(chain, &"0".repeat(64), 1)).unwrap();
        }
        case.plan("replay-session.exit", "3")
            .plan("replay-session.out", "");
        let ended = case.ended(output(session_command(&case, &source, true, "result")));
        let record = ended.class(
            if broken { 2 } else { 4 },
            if broken { "rejected" } else { "incomplete" },
        );
        if broken {
            assert!(case.calls().is_empty());
            assert!(ended.reason().contains("out of its chain"));
        } else {
            assert!(ended.reason().contains("session replay panicked"));
            assert!(ended.reason().contains("reproduced=true"));
            assert_eq!(case.calls(), ["capabilities", "replay-session"]);
            for facts in [
                record.session.as_ref().unwrap(),
                record.session_original.as_ref().unwrap(),
            ] {
                assert_eq!(facts.verified_windows, 2);
                assert!(!facts.complete && !facts.counts);
                assert!(facts.verification_error.is_none());
                assert!(
                    facts
                        .end
                        .as_ref()
                        .unwrap()
                        .as_str()
                        .contains("end: panicked")
                );
            }
        }
    }
}

pub(crate) fn forked_argv_keeps_the_manifest_milestone_and_requested_pairs() {
    for (form, siblings) in [("branch", 1), ("branch", 2), ("explore", 1)] {
        let case = Case::new(&format!("argv-{form}-{siblings}"));
        let input = case.dir.join("bundle");
        fs::write(&input, bundle(&manifest(&[]), 2)).unwrap();
        case.plan(&format!("{form}.out"), &forked_fixture(form, 1, siblings));
        let mut args = vec![
            OsStr::new(form),
            input.as_os_str(),
            OsStr::new("--archive"),
            archive().0.as_os_str(),
            OsStr::new("--milestone"),
            OsStr::new("pending-put"),
            OsStr::new("--run-id"),
            OsStr::new("result"),
        ];
        let sib = siblings.to_string();
        if form == "branch" {
            args.extend([
                OsStr::new("--suffixes"),
                OsStr::new("1"),
                OsStr::new("--siblings"),
                OsStr::new(&sib),
            ]);
        }
        let ended = case.ended(output(case.command(&args)));
        let artifact = ended.class(0, "counts");
        assert_eq!(
            artifact.output.as_ref().unwrap().as_str(),
            ended.dir().join(form).to_str().unwrap()
        );
        let seen = case.seen(form);
        let argv: Vec<String> = serde_json::from_str(&seen["args"]).unwrap();
        let mut expected = vec![
            format!("--{form}"),
            ended.dir().join("input").display().to_string(),
            "--milestone".into(),
            "pending-put".into(),
            "--output".into(),
            ended.dir().join(form).display().to_string(),
        ];
        if form == "branch" {
            expected.extend(["--suffixes".into(), "1".into()]);
            expected.extend(["--siblings".into(), sib]);
        }
        assert_eq!(argv, expected);
    }
}

pub(crate) fn a_session_output_at_the_record_name_cannot_publish_credit() {
    for (form, entry) in [
        ("session", "artifact"),
        ("replay-session", "artifact"),
        ("branch", "artifact"),
        ("explore", "artifact"),
        ("reduce", "artifact"),
        ("reduce", "reduction"),
    ] {
        let case = Case::new(&format!("{form}-{entry}-name-collision"));
        let source = session_fixture(&case, "source");
        let target = case.dir.join("artifacts/result").join(entry);
        let mut command = if matches!(form, "session" | "replay-session") {
            let input = if form == "session" {
                case.manifest()
            } else {
                source
            };
            session_command(&case, &input, form == "replay-session", "result")
        } else {
            let input = case.dir.join("bundle");
            fs::write(&input, bundle(&manifest(&[]), 2)).unwrap();
            let mut args = vec![
                OsStr::new(form),
                input.as_os_str(),
                OsStr::new("--archive"),
                archive().0.as_os_str(),
                OsStr::new("--run-id"),
                OsStr::new("result"),
            ];
            if form != "reduce" {
                args.extend([OsStr::new("--milestone"), OsStr::new("pending-put")]);
            }
            if form == "branch" {
                args.extend([OsStr::new("--suffixes"), OsStr::new("1")]);
            }
            case.command(&args)
        };
        command.arg("--output").arg(&target);
        let ended = case.ended(output(command));
        ended.class(2, "rejected");
        assert!(ended.reason().contains("reserved artifact entry"));
        assert!(case.calls().is_empty());
        assert!(!target.is_dir());
    }
}

pub(crate) fn session_host_read_faults_are_incomplete_before_workers() {
    let case = Case::new("session-manifest-host-fault");
    let ended = case.ended(output(session_command(
        &case,
        Path::new("/proc/self/mem"),
        false,
        "result",
    )));
    ended.class(4, "incomplete");
    assert!(case.calls().is_empty());
    let case = Case::new("session-index-host-fault");
    let source = session_fixture(&case, "source");
    fs::remove_file(source.join("index")).unwrap();
    std::os::unix::fs::symlink("/proc/self/mem", source.join("index")).unwrap();
    let ended = case.ended(output(session_command(&case, &source, true, "result")));
    ended.class(4, "incomplete");
    assert!(case.calls().is_empty());
}

pub(crate) fn session_metadata_bounds_keep_a_published_prefix() {
    for replay in [false, true] {
        let case = Case::new(if replay {
            "oversized-source-end"
        } else {
            "oversized-output-end"
        });
        let source = session_fixture(&case, "source");
        let path = source.join("end");
        let old = fs::read_to_string(&path).unwrap();
        let footer = old.rsplit_once(" windows=").unwrap().1;
        fs::write(
            path,
            format!("end: panicked {} windows={footer}", "x".repeat(16 * 1024)),
        )
        .unwrap();
        case.plan("session.tree", source.to_str().unwrap())
            .plan("session.exit", "3");
        let input = if replay { source } else { case.manifest() };
        let ended = case.ended(output(session_command(&case, &input, replay, "result")));
        let record = ended.class(4, "incomplete");
        let facts = if replay {
            record.session_original.as_ref()
        } else {
            record.session.as_ref()
        }
        .unwrap();
        assert_eq!(facts.verified_windows, 2);
        assert!(!facts.complete && !facts.counts);
        assert!(
            facts
                .verification_error
                .as_ref()
                .unwrap()
                .as_str()
                .contains("16384 bytes")
        );
        if replay {
            assert!(case.calls().is_empty());
        }
    }
}

pub(crate) fn session_refusals_and_panic_divergence_reach_their_guards() {
    for replay in [false, true] {
        for key in ["records", "bytes"] {
            let case = Case::new(&format!("session-missing-budget-{replay}-{key}"));
            let normal = fs::read_to_string(case.manifest()).unwrap();
            let changed = normal
                .lines()
                .filter(|line| !line.starts_with(&format!("{key} = ")))
                .collect::<Vec<_>>()
                .join("\n")
                + "\n";
            fs::write(case.manifest(), changed).unwrap();
            let source = session_fixture(&case, "source");
            let input = if replay { source } else { case.manifest() };
            let ended = case.ended(output(session_command(&case, &input, replay, "result")));
            ended.class(2, "rejected");
            assert!(ended.reason().contains(&format!("names no {key} count")));
            assert!(case.calls().is_empty());
        }
    }
    for replay in [false, true] {
        let case = Case::new(if replay {
            "refused-session-replay"
        } else {
            "refused-session"
        });
        let source = session_fixture(&case, "source");
        let form = if replay { "replay-session" } else { "session" };
        case.plan(&format!("{form}.notree"), "")
            .plan(&format!("{form}.exit"), "2")
            .plan(&format!("{form}.out"), "");
        let input = if replay { source } else { case.manifest() };
        case.ended(output(session_command(&case, &input, replay, "result")))
            .class(2, "rejected");
    }
    for replay in [false, true] {
        let case = Case::new(if replay {
            "refused-session-replay-occupied-output"
        } else {
            "refused-session-occupied-output"
        });
        let source = session_fixture(&case, "source");
        let occupant = session_fixture(&case, "occupant");
        let form = if replay { "replay-session" } else { "session" };
        case.plan(&format!("{form}.tree"), occupant.to_str().unwrap())
            .plan(&format!("{form}.exit"), "2")
            .plan(&format!("{form}.out"), "");
        let input = if replay { source } else { case.manifest() };
        let ended = case.ended(output(session_command(&case, &input, replay, "result")));
        let record = ended.class(2, "rejected");
        assert!(
            ended.reason().contains("the worker refused the session"),
            "{}",
            ended.reason()
        );
        assert!(record.session.is_none(), "{:?}", record.session);
        assert_eq!(record.session_original.is_some(), replay);
    }
    for (name, replay, exit, stdout, expected_reason) in [
        ("session", false, "3", "", "the session panicked: planted"),
        (
            "session-wrong-exit",
            false,
            "0",
            "",
            "disagrees with its stdout or exit",
        ),
        (
            "replay-new-panic",
            true,
            "3",
            "",
            "session replay panicked: planted; reproduced=false",
        ),
        (
            "replay-panic-with-stdout",
            true,
            "3",
            "replay: reproduced, 2 windows, chain bad\n",
            "disagrees with its stdout or exit",
        ),
    ] {
        let case = Case::new(&format!("verified-panic-{name}"));
        let source = session_fixture(&case, "source");
        let panic = session_fixture(&case, "panic");
        let path = panic.join("end");
        let end = fs::read_to_string(&path).unwrap();
        let footer = end.rsplit_once(" windows=").unwrap().1;
        fs::write(path, format!("end: panicked planted windows={footer}")).unwrap();
        let form = if replay { "replay-session" } else { "session" };
        case.plan(&format!("{form}.tree"), panic.to_str().unwrap())
            .plan(&format!("{form}.exit"), exit)
            .plan(&format!("{form}.out"), stdout);
        let input = if replay { source } else { case.manifest() };
        let ended = case.ended(output(session_command(&case, &input, replay, "result")));
        let record = ended.class(4, "incomplete");
        assert!(
            ended.reason().contains(expected_reason),
            "{}",
            ended.reason()
        );
        assert_eq!(
            record.workers[&Text::new(form).unwrap()].exit,
            Some(exit.parse().unwrap())
        );
    }
    let case = Case::new("panic-source-now-diverges");
    let source = session_fixture(&case, "source");
    let normal = session_fixture(&case, "normal");
    let path = source.join("end");
    let end = fs::read_to_string(&path).unwrap();
    let footer = end.rsplit_once(" windows=").unwrap().1;
    fs::write(path, format!("end: panicked planted windows={footer}")).unwrap();
    case.plan("replay-session.tree", normal.to_str().unwrap())
        .plan(
            "replay-session.out",
            "replay: diverged after the last window: the end differs\n",
        )
        .plan("replay-session.exit", "1");
    let ended = case.ended(output(session_command(&case, &source, true, "result")));
    ended.class(4, "incomplete");
    assert!(
        ended
            .reason()
            .contains("panicked source session remains incomplete")
    );
}

pub(crate) fn session_argv_uses_frozen_manifest_and_canonical_source() {
    {
        use std::os::unix::fs::PermissionsExt;
        let case = Case::new("session-shared-host-source");
        let shared = case.dir.join("shared");
        fs::create_dir(&shared).unwrap();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
        let source = session_fixture(&case, "shared/source");
        let ended = case.ended(output(session_command(&case, &source, true, "result")));
        let artifact = ended.class(0, "counts");
        assert_eq!(
            artifact.session_original.as_ref().unwrap().verified_windows,
            2
        );
        assert_eq!(case.calls(), ["capabilities", "replay-session"]);
    }
    {
        use std::os::unix::ffi::OsStrExt;
        let case = Case::new("session-non-utf8-source");
        let parent = case.dir.join(OsStr::from_bytes(b"bad\xff"));
        fs::create_dir(&parent).unwrap();
        let source = parent.join("source");
        fs::rename(session_fixture(&case, "source"), &source).unwrap();
        let ended = case.ended(output(session_command(&case, &source, true, "result")));
        let artifact = ended.class(2, "rejected");
        assert!(
            ended
                .reason()
                .contains("the source session path must be UTF-8"),
            "{}",
            ended.reason()
        );
        assert_eq!(
            artifact.session_original.as_ref().unwrap().verified_windows,
            2
        );
        assert!(artifact.workers.is_empty());
        assert_eq!(case.calls(), Vec::<String>::new());
    }
    for replay in [false, true] {
        for name in [
            "manifest",
            "index",
            "end",
            "windows/000000.chunk",
            "windows/tail.chunk",
            "windows",
        ] {
            let case = Case::new(&format!(
                "session-output-link-{replay}-{}",
                name.replace('/', "-")
            ));
            let source = session_fixture(&case, "source");
            let form = if replay { "replay-session" } else { "session" };
            case.plan(&format!("{form}.tree"), source.to_str().unwrap())
                .plan(&format!("{form}.symlink"), name);
            let input = if replay { source } else { case.manifest() };
            let ended = case.ended(output(session_command(&case, &input, replay, "result")));
            let record = ended.class(4, "incomplete");
            assert_eq!(record.workers[&Text::new(form).unwrap()].exit, Some(0));
            let error = record
                .session
                .as_ref()
                .unwrap()
                .verification_error
                .as_ref()
                .unwrap()
                .as_str();
            assert!(
                error.contains("cannot be read") || error.contains("evidence path is refused"),
                "{error}"
            );
        }
    }
    for replay in [false, true] {
        let case = Case::new(if replay {
            "session-replay-argv"
        } else {
            "session-argv"
        });
        let source = session_fixture(&case, "source");
        case.plan("session.tree", source.to_str().unwrap());
        let input = if replay { source } else { case.manifest() };
        let supplied = if replay {
            let alias = case.dir.join("source-alias");
            std::os::unix::fs::symlink(&input, &alias).unwrap();
            alias
        } else {
            input.clone()
        };
        let form = if replay { "replay-session" } else { "session" };
        let ended = case.ended(output(session_command(&case, &supplied, replay, "result")));
        ended.class(0, "counts");
        let actual: Vec<String> = serde_json::from_str(&case.seen(form)["args"]).unwrap();
        assert_eq!(
            actual,
            vec![
                format!("--{form}"),
                if replay {
                    input.display().to_string()
                } else {
                    ended.dir().join("manifest").display().to_string()
                },
                "--output".into(),
                ended.dir().join(form).display().to_string()
            ]
        );
    }
}

pub(crate) fn session_end_budget_and_lossy_diagnostics_have_reached_oracles() {
    let case = Case::new("source-end-byte-budget");
    let normal = fs::read_to_string(case.manifest()).unwrap();
    fs::write(
        case.manifest(),
        normal.replace("bytes = 48000", "bytes = 1000"),
    )
    .unwrap();
    let initial = session_fixture(&case, "initial");
    let used = fs::metadata(initial.join("manifest")).unwrap().len()
        + fs::metadata(initial.join("index")).unwrap().len()
        + 12;
    fs::write(
        case.manifest(),
        normal.replace("bytes = 48000", &format!("bytes = {}", used + 100)),
    )
    .unwrap();
    let source = session_fixture(&case, "source");
    let ended = case.ended(output(session_command(&case, &source, true, "result")));
    let record = ended.class(2, "rejected");
    assert!(case.calls().is_empty());
    let facts = record.session_original.as_ref().unwrap();
    assert_eq!(facts.verified_windows, 2);
    assert_eq!(
        facts.verification_error.as_ref().unwrap().as_str(),
        "the session exceeds its manifest byte budget"
    );

    use std::os::unix::ffi::OsStringExt;
    let case = Case::new("lossy-source-diagnostic");
    let mut names = vec![vec![0xff; 200]; 7];
    let prospective = |names: &[Vec<u8>]| {
        names.iter().fold(case.dir.clone(), |path, name| {
            path.join(std::ffi::OsString::from_vec(name.clone()))
        })
    };
    while prospective(&names)
        .join("index")
        .to_string_lossy()
        .is_char_boundary(4096)
    {
        names[0].insert(0, b'x');
    }
    let mut source = case.dir.clone();
    for name in names {
        source.push(std::ffi::OsString::from_vec(name));
        fs::create_dir(&source).unwrap();
    }
    assert!(
        !source
            .join("index")
            .to_string_lossy()
            .is_char_boundary(4096)
    );
    fs::write(source.join("manifest"), fs::read(case.manifest()).unwrap()).unwrap();
    let ended = case.ended(output(session_command(&case, &source, true, "result")));
    let record = ended.class(2, "rejected");
    assert!(case.calls().is_empty());
    let error = record
        .session_original
        .as_ref()
        .unwrap()
        .verification_error
        .as_ref()
        .unwrap()
        .as_str();
    let full = format!("{} is missing", source.join("index").display());
    let cut = &full[..full.floor_char_boundary(4096)];
    let expected: String = cut
        .chars()
        .flat_map(|char| {
            if (' '..='~').contains(&char) {
                char.to_string().chars().collect::<Vec<_>>()
            } else {
                char.escape_default().collect()
            }
        })
        .collect();
    assert_eq!(error, expected);
}
