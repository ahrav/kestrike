//! Each case builds a [`Fixture`]: a state directory of its own under `CARGO_TARGET_TMPDIR` with a Git
//! repository of two commits, the `cargo` stand-in and a plan that tells the stand-in what to answer.
//!
//! The process sets umask 022 and the child-subreaper flag once, so an orphaned descendant of a run becomes
//! a child of the test process and an exited one stays a zombie, which [`Fixture::assert_gone`] counts as
//! gone. No case changes the process's directory, environment or signal dispositions. Each start gets the
//! test process's environment without `GIT_*`, `CARGO_MUTANTS_*`, `CARGO_PROFILE_*` and `*RUSTFLAGS`,
//! with SIGINT, SIGTERM and SIGHUP at their default dispositions.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::OnceLock;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use kestrike_tools::json::{self, Object, Value};
use kestrike_tools::ownership::shared_directories;
use kestrike_tools::text::Text;

use super::standins::{CARGO, GIT, RECORDED, SLEEPER};

pub const BINARY: &str = env!("CARGO_BIN_EXE_kestrike-tools");
pub const SOURCE: &str = "crates/kestrike/src";
pub const DEFAULT_TESTS: [&str; 8] = [
    "--lib", "--", "--skip", "bind::", "--skip", "native::", "--skip", "soak",
];
pub const DIFF: [&str; 2] = ["diff", "--full-index"];
pub const CONFIG: &str = "# Tool pin: cargo-mutants 27.1.0
exclude_globs = [
    # A comment between entries.
    \"crates/kestrike/src/bind/**\",
]
exclude_re = [\"tests::\"]
additional_cargo_args = [\"--config\", \"profile.dev.debug-assertions=false\"]
";
pub const WORKFLOW: &str = "env:\n  STABLE: \"1.99.0\"\n  NIGHTLY: \"nightly-2026-07-27\"\n";
pub const RUN_LIMIT: Duration = Duration::from_secs(120);
pub const MARKER_LIMIT: Duration = Duration::from_secs(30);
pub const GONE_LIMIT: Duration = Duration::from_secs(5);
pub const HANGUP_PAUSE: Duration = Duration::from_secs(1);
const PAUSE: Duration = Duration::from_millis(100);
const HOST_PROGRAMS: [&str; 4] = ["sh", "setsid", "sha256sum", "git"];

pub type Env = Vec<(OsString, OsString)>;

static HOST: OnceLock<Result<PathBuf, String>> = OnceLock::new();

/// `on_path` returns the first executable file named `program` in a `PATH` entry.
fn on_path(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|entry| entry.join(program))
        .find(|candidate| {
            fs::metadata(candidate)
                .is_ok_and(|status| status.is_file() && status.permissions().mode() & 0o111 != 0)
        })
}

/// `prepare_host` sets the umask and the subreaper flag and checks the host programs and the scratch
/// directory once; it returns the real `git` or fails the case with the reason.
fn prepare_host() -> PathBuf {
    let prepared = HOST.get_or_init(|| {
        // SAFETY: `umask` takes and returns a mode and touches no memory of the caller.
        unsafe { libc::umask(0o022) };
        // SAFETY: `prctl` with `PR_SET_CHILD_SUBREAPER` reads its integer arguments alone.
        if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } != 0 {
            return Err(format!("prctl(PR_SET_CHILD_SUBREAPER) failed: {}", std::io::Error::last_os_error()));
        }
        for program in HOST_PROGRAMS {
            if on_path(program).is_none() {
                return Err(format!("the stand-ins need `{program}` on PATH"));
            }
        }
        let fraction = Command::new("sleep").arg("0.01").status();
        if !fraction.is_ok_and(|status| status.success()) {
            return Err("the stand-ins need a `sleep` that takes a fractional second".to_owned());
        }
        let scratch = Path::new(env!("CARGO_TARGET_TMPDIR"));
        fs::create_dir_all(scratch).map_err(|error| format!("{}: {error}", scratch.display()))?;
        let shared = shared_directories(scratch).map_err(|error| error.to_string())?;
        if !shared.is_empty() {
            return Err(format!(
                "the runner refuses an artifacts directory under {shared:?}, which another user can write; \
                 move CARGO_TARGET_TMPDIR under a private directory"
            ));
        }
        Ok(on_path("git").expect("git is on PATH"))
    });
    prepared.clone().unwrap_or_else(|reason| panic!("{reason}"))
}

pub fn t(text: &str) -> Text {
    Text::from(text)
}

/// What the `cargo` stand-in answers: the listed mutants as `(file, name)`, each mutant's summary, and
/// the shapes of the tool's answers.
#[derive(Clone, Debug, Default)]
pub struct Plan {
    pub listed: Vec<(Text, Text)>,
    pub outcomes: Vec<(Text, &'static str)>,
    pub exit: i32,
    pub baseline: Option<&'static str>,
    pub totals: Vec<(&'static str, u64)>,
    pub host: Option<&'static str>,
    pub version: Option<&'static str>,
    pub absent: bool,
    pub list_exit: Option<i32>,
    pub list_hang: bool,
    pub hang: bool,
    pub hold: bool,
    pub stray: bool,
    pub drop_git: bool,
    /// The tool's run leaves two directories of mode 0500 in the worktree, each holding a file, among
    /// other entries.
    pub locked: bool,
    /// The tool's run leaves a link at the run directory's `report.json` to the state's `victim`.
    pub report_link: bool,
    pub no_outcomes: bool,
    pub raw_listing: Option<Vec<u8>>,
    pub raw_outcomes: Option<String>,
}

impl Plan {
    pub fn new(listed: &[(Text, Text)], outcomes: &[(Text, &'static str)]) -> Self {
        Self {
            listed: listed.to_vec(),
            outcomes: outcomes.to_vec(),
            ..Self::default()
        }
    }

    /// `caught` plans each listed mutant caught.
    pub fn caught(listed: &[(Text, Text)]) -> Self {
        let outcomes: Vec<(Text, &str)> = listed
            .iter()
            .map(|(_, name)| (name.clone(), "CaughtMutant"))
            .collect();
        Self::new(listed, &outcomes)
    }

    fn entry(file: &Text, name: &Text) -> Value {
        let mut entry = Object::new();
        entry.insert("name", Value::String(name.clone()));
        entry.insert("file", Value::String(file.clone()));
        entry.insert("package", Value::String(t("kestrike")));
        entry.insert("genre", Value::String(t("FnValue")));
        entry.insert("diff", Value::String(Text::from(format!("--- {name}"))));
        Value::Object(entry)
    }

    fn phases() -> Value {
        let phase = |name: &str, duration: f64| {
            let mut phase = Object::new();
            phase.insert("phase", Value::String(t(name)));
            phase.insert("duration", Value::Float(duration));
            phase.insert("process_status", Value::String(t("Success")));
            phase.insert("argv", Value::Array(Vec::new()));
            Value::Object(phase)
        };
        Value::Array(vec![phase("Build", 1.25), phase("Test", 0.5)])
    }

    /// `outcome_file` writes the outcome file the tool holds after `records` mutant records.
    fn outcome_file(&self, records: &[Value]) -> String {
        let mut baseline = Object::new();
        baseline.insert("scenario", Value::String(t("Baseline")));
        baseline.insert(
            "summary",
            Value::String(t(self.baseline.unwrap_or("Success"))),
        );
        baseline.insert("phase_results", Self::phases());
        let mut all = vec![Value::Object(baseline)];
        all.extend_from_slice(records);
        let mut file = Object::new();
        file.insert("outcomes", Value::Array(all));
        let mut totals = vec![
            ("total_mutants", records.len() as u64),
            ("missed", 0),
            ("caught", 0),
            ("timeout", 0),
            ("unviable", 0),
        ];
        for (name, value) in &self.totals {
            totals.retain(|(known, _)| known != name);
            totals.push((name, *value));
        }
        for (name, value) in totals {
            file.insert(name, Value::Integer(value.into()));
        }
        json::text(&Value::Object(file))
    }

    /// `write` writes the plan into `directory`, with the listing, the outcome file and the outcome file at
    /// the hang for the whole listing and for each shard `K/N` with `N` up to 4.
    fn write(&self, directory: &Path) {
        let _ = fs::remove_dir_all(directory);
        fs::create_dir_all(directory).expect("the plan directory is made");
        let put = |name: &str, text: &str| {
            fs::write(directory.join(name), text).expect("the plan file is written")
        };
        put("host", self.host.unwrap_or("aarch64-unknown-linux-gnu"));
        put("version", self.version.unwrap_or("27.1.0"));
        put("exit", &self.exit.to_string());
        for (flag, name) in [
            (self.absent, "absent"),
            (self.list_hang, "list_hang"),
            (self.hang, "hang"),
            (self.hold, "hold"),
            (self.stray, "stray"),
            (self.drop_git, "drop_git"),
            (self.locked, "locked"),
            (self.report_link, "report_link"),
            (self.no_outcomes, "no_outcomes"),
        ] {
            if flag {
                put(name, "");
            }
        }
        if let Some(code) = self.list_exit {
            put("list_exit", &code.to_string());
        }
        if let Some(listing) = &self.raw_listing {
            let bytes = [listing.as_slice(), b"\n"].concat();
            fs::write(directory.join("raw_listing"), bytes).expect("the plan file is written");
        }
        if let Some(outcomes) = &self.raw_outcomes {
            put("raw_outcomes", outcomes);
        }
        let mut shards = vec![(String::new(), self.listed.clone())];
        for n in 1..=4usize {
            let size = self.listed.len().div_ceil(n);
            for k in 0..n {
                let slice = self
                    .listed
                    .iter()
                    .skip(k * size)
                    .take(size)
                    .cloned()
                    .collect();
                shards.push((format!("-{k}-{n}"), slice));
            }
        }
        for (suffix, listed) in shards {
            let entries: Vec<Value> = listed
                .iter()
                .map(|(file, name)| Self::entry(file, name))
                .collect();
            if !entries.is_empty() {
                put(
                    &format!("list{suffix}"),
                    &format!("{}\n", json::text(&Value::Array(entries.clone()))),
                );
            }
            let records: Vec<Value> = entries
                .iter()
                .zip(&listed)
                .filter_map(|(entry, (_, name))| {
                    let (_, summary) = self.outcomes.iter().find(|(planned, _)| planned == name)?;
                    let mut scenario = Object::new();
                    scenario.insert("Mutant", entry.clone());
                    let mut record = Object::new();
                    record.insert("scenario", Value::Object(scenario));
                    record.insert("summary", Value::String(t(summary)));
                    record.insert("phase_results", Self::phases());
                    Some(Value::Object(record))
                })
                .collect();
            put(&format!("outcomes{suffix}"), &self.outcome_file(&records));
            if !records.is_empty() {
                put(
                    &format!("at-hang{suffix}"),
                    &self.outcome_file(&records[..1]),
                );
            }
        }
    }
}

/// One finished start of the tool.
#[derive(Debug)]
pub struct Out {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Out {
    pub fn all(&self) -> String {
        format!("exit {}\n{}{}", self.code, self.stdout, self.stderr)
    }

    pub fn lines(&self) -> Vec<&str> {
        self.stdout.lines().collect()
    }
}

fn code_of(status: ExitStatus) -> i32 {
    status.code().unwrap_or_else(|| {
        -status
            .signal()
            .expect("a child ends with a code or a signal")
    })
}

fn reader(stream: Option<impl Read + Send + 'static>) -> JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        if let Some(mut stream) = stream {
            let _ = stream.read_to_end(&mut bytes);
        }
        bytes
    })
}

/// A tool started in the background. Dropping it kills a tool that still runs and a sleeper of the
/// stand-in that `grandchild.pid` names while `/proc/<pid>/cmdline` still names the sleeper.
pub struct Runner {
    child: Option<Child>,
    stdout: Option<JoinHandle<Vec<u8>>>,
    stderr: Option<JoinHandle<Vec<u8>>>,
    state: PathBuf,
}

impl Runner {
    pub fn pid(&self) -> libc::pid_t {
        let child = self.child.as_ref().expect("the runner is started");
        libc::pid_t::try_from(child.id()).expect("a process id fits pid_t")
    }

    pub fn signal(&self, signal: i32) {
        // SAFETY: `kill` takes two integers. A case signals a runner before it observes the runner's exit,
        // so the process id still names the runner.
        assert_eq!(
            unsafe { libc::kill(self.pid(), signal) },
            0,
            "signal {signal} reaches the runner"
        );
    }

    pub fn poll(&mut self) -> Option<ExitStatus> {
        self.child
            .as_mut()
            .and_then(|child| child.try_wait().expect("the runner can be polled"))
    }

    pub fn kill(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
        }
    }

    /// `communicate` waits up to `limit` for the runner and returns its exit and both streams.
    pub fn communicate(&mut self, limit: Duration) -> Out {
        let start = Instant::now();
        let status = loop {
            if let Some(status) = self.poll() {
                break status;
            }
            if start.elapsed() >= limit {
                self.kill();
                let child = self.child.as_mut().expect("the runner is started");
                let _ = child.wait();
                let out = self.collect(None);
                panic!("the runner ran past {limit:?}: {}", out.all());
            }
            thread::sleep(Duration::from_millis(10));
        };
        self.collect(Some(status))
    }

    fn collect(&mut self, status: Option<ExitStatus>) -> Out {
        let text = |handle: Option<JoinHandle<Vec<u8>>>| {
            let bytes = handle
                .map(|handle| handle.join().expect("a reader returns its bytes"))
                .unwrap_or_default();
            String::from_utf8_lossy(&bytes).into_owned()
        };
        Out {
            code: status.map_or(-libc::SIGKILL, code_of),
            stdout: text(self.stdout.take()),
            stderr: text(self.stderr.take()),
        }
    }
}

/// `names_sleeper` holds while the process `pid` runs the stand-ins' sleeper.
pub fn names_sleeper(pid: libc::pid_t) -> bool {
    let needle = format!("sleep\0{SLEEPER}\0");
    fs::read(format!("/proc/{pid}/cmdline")).is_ok_and(|cmdline| {
        cmdline
            .windows(needle.len())
            .any(|window| window == needle.as_bytes())
    })
}

impl Drop for Runner {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut()
            && matches!(child.try_wait(), Ok(None))
        {
            let _ = child.kill();
            let _ = child.wait();
        }
        let pid = fs::read_to_string(self.state.join("grandchild.pid"))
            .ok()
            .and_then(|pid| pid.trim().parse().ok());
        if let Some(pid) = pid.filter(|&pid: &libc::pid_t| pid > 0 && names_sleeper(pid)) {
            // SAFETY: `kill` takes two integers; the pid names the stand-ins' sleeper.
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
    }
}

/// One record of the `cargo` stand-in's `calls` file.
#[derive(Clone, Debug)]
pub struct Call {
    pub argv: Vec<String>,
    pub cwd: String,
    pub vars: BTreeMap<&'static str, Option<String>>,
    pub diff_sha256: Option<String>,
    pub config_sha256: Option<String>,
    pub lock: Option<String>,
}

impl Call {
    pub fn var(&self, name: &str) -> Option<&str> {
        self.vars.get(name).and_then(|value| value.as_deref())
    }

    /// `tests` is the arguments after the first `--`, or `None` without one.
    pub fn tests(&self) -> Option<Vec<String>> {
        let at = self.argv.iter().position(|arg| arg == "--")?;
        Some(self.argv[at + 1..].to_vec())
    }

    pub fn value(&self, flag: &str) -> &str {
        let at = self
            .argv
            .iter()
            .position(|arg| arg == flag)
            .unwrap_or_else(|| panic!("{flag} in {:?}", self.argv));
        &self.argv[at + 1]
    }

    pub fn is_listing(&self) -> bool {
        self.argv.iter().any(|arg| arg == "--list")
    }
}

fn parse_calls(bytes: &[u8]) -> Vec<Call> {
    let mut fields = bytes
        .split(|&byte| byte == 0)
        .map(|field| String::from_utf8_lossy(field).into_owned());
    let mut calls = Vec::new();
    let set = |field: String| field.strip_prefix('S').map(str::to_owned);
    while let Some(marker) = fields.next() {
        if marker.is_empty() {
            break;
        }
        assert_eq!(marker, "call", "a call record starts with `call`");
        let count: usize = fields
            .next()
            .and_then(|count| count.parse().ok())
            .expect("a call record counts its arguments");
        let argv = (0..count)
            .map(|_| fields.next().expect("each counted argument"))
            .collect();
        let cwd = fields.next().expect("the working directory");
        let vars = RECORDED
            .iter()
            .map(|&name| (name, set(fields.next().expect("each variable"))))
            .collect();
        let mut next = || set(fields.next().expect("each recorded file"));
        let (diff_sha256, config_sha256, lock) = (next(), next(), next());
        calls.push(Call {
            argv,
            cwd,
            vars,
            diff_sha256,
            config_sha256,
            lock,
        });
    }
    calls
}

/// `executable` writes the stand-in at `path` through a child, the one process that holds the file open
/// for writing. `execve` refuses a file that any process holds open for writing with `ETXTBSY`, and a
/// child that another test thread forks inherits every descriptor of this process until its own
/// `execve`, so no descriptor of the stand-in is ever open in this process.
pub fn executable(path: &Path, text: &str) {
    let mut writer = Command::new("sh")
        .args(["-c", r#"cat > "$1" && chmod 755 "$1""#, "sh"])
        .arg(path)
        .stdin(Stdio::piped())
        .spawn()
        .expect("the stand-in's writer starts");
    std::io::Write::write_all(
        &mut writer.stdin.take().expect("the writer's input is a pipe"),
        text.as_bytes(),
    )
    .expect("the stand-in's text reaches the writer");
    let status = writer.wait().expect("the stand-in's writer is reaped");
    assert!(status.success(), "the stand-in is written: {status}");
}

/// `limit_file_size` makes the process `command` starts run with SIGXFSZ at its default action, not
/// blocked, and a soft file size limit of `bytes`.
pub fn limit_file_size(command: &mut Command, bytes: u64) {
    // SAFETY: the hook runs in the forked child before `exec` and calls only `signal`, `sigemptyset`,
    // `sigaddset`, `sigprocmask`, `getrlimit` and `setrlimit`, which are async-signal-safe; it writes only
    // locals that it initializes first.
    unsafe {
        command.pre_exec(move || {
            libc::signal(libc::SIGXFSZ, libc::SIG_DFL);
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGXFSZ);
            libc::sigprocmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
            let mut limit: libc::rlimit = std::mem::zeroed();
            if libc::getrlimit(libc::RLIMIT_FSIZE, &mut limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            limit.rlim_cur = bytes.min(limit.rlim_max);
            if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// How [`start_tool`] starts the binary beyond its command line.
#[derive(Clone, Copy)]
struct Launch {
    ignore_hangup: bool,
    blocked: bool,
    file_limit: Option<u64>,
}

/// `start_tool` starts the binary as `kestrike-tools <top> mutants-diff ARGS` in `cwd` with `env`.
fn start_tool(args: &[OsString], cwd: &Path, env: &Env, launch: Launch, state: &Path) -> Runner {
    let Launch {
        ignore_hangup,
        blocked,
        file_limit,
    } = launch;
    let top = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut command = Command::new(BINARY);
    command
        .arg(top)
        .arg("mutants-diff")
        .args(args)
        .current_dir(cwd)
        .env_clear()
        .envs(env.iter().cloned())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: the hook runs in the forked child before `exec` and calls only `signal`, `sigemptyset`,
    // `sigaddset` and `sigprocmask`, which are async-signal-safe; the set it passes is a local value that
    // `sigemptyset` initializes.
    unsafe {
        command.pre_exec(move || {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
                libc::signal(signal, libc::SIG_DFL);
                libc::sigaddset(&mut set, signal);
            }
            if ignore_hangup {
                libc::signal(libc::SIGHUP, libc::SIG_IGN);
            }
            let how = if blocked {
                libc::SIG_BLOCK
            } else {
                libc::SIG_UNBLOCK
            };
            libc::sigprocmask(how, &set, std::ptr::null_mut());
            Ok(())
        });
    }
    if let Some(bytes) = file_limit {
        limit_file_size(&mut command, bytes);
    }
    let mut child = command.spawn().expect("the tool starts");
    let (stdout, stderr) = (reader(child.stdout.take()), reader(child.stderr.take()));
    Runner {
        child: Some(child),
        stdout: Some(stdout),
        stderr: Some(stderr),
        state: state.to_path_buf(),
    }
}

/// One start of the tool, with the fixture's command line, working directory and environment unless a
/// method replaces them.
pub struct Start<'a> {
    fixture: &'a Fixture,
    args: Vec<OsString>,
    base: Option<String>,
    head: Option<String>,
    artifacts: Option<PathBuf>,
    env: Option<Env>,
    cwd: Option<PathBuf>,
    raw: bool,
    ignore_hangup: bool,
    blocked: bool,
    file_limit: Option<u64>,
}

impl Start<'_> {
    pub fn args<S: AsRef<OsStr>>(mut self, args: impl IntoIterator<Item = S>) -> Self {
        self.args
            .extend(args.into_iter().map(|arg| arg.as_ref().to_owned()));
        self
    }

    /// `raw` drops the fixture's `--base`, `--head`, `--artifacts` and `--cargo`.
    pub fn raw(mut self) -> Self {
        self.raw = true;
        self
    }

    pub fn base(mut self, base: &str) -> Self {
        self.base = Some(base.to_owned());
        self
    }

    pub fn head(mut self, head: &str) -> Self {
        self.head = Some(head.to_owned());
        self
    }

    pub fn artifacts(mut self, artifacts: &Path) -> Self {
        self.artifacts = Some(artifacts.to_path_buf());
        self
    }

    pub fn env(mut self, env: Env) -> Self {
        self.env = Some(env);
        self
    }

    pub fn cwd(mut self, cwd: &Path) -> Self {
        self.cwd = Some(cwd.to_path_buf());
        self
    }

    pub fn ignore_hangup(mut self) -> Self {
        self.ignore_hangup = true;
        self
    }

    /// `blocked` starts the tool with SIGINT, SIGTERM and SIGHUP blocked.
    pub fn blocked(mut self) -> Self {
        self.blocked = true;
        self
    }

    /// `file_limit` starts the tool with a soft file size limit of `bytes` and SIGXFSZ at its default.
    pub fn file_limit(mut self, bytes: u64) -> Self {
        self.file_limit = Some(bytes);
        self
    }

    fn argv(&self) -> Vec<OsString> {
        if self.raw {
            return self.args.clone();
        }
        let fixture = self.fixture;
        let mut argv: Vec<OsString> = vec![
            "--base".into(),
            self.base
                .clone()
                .unwrap_or_else(|| fixture.base.clone())
                .into(),
            "--head".into(),
            self.head
                .clone()
                .unwrap_or_else(|| fixture.head.clone())
                .into(),
            "--artifacts".into(),
            self.artifacts
                .clone()
                .unwrap_or_else(|| fixture.artifacts.clone())
                .into(),
            "--cargo".into(),
            fixture.cargo.clone().into(),
        ];
        argv.extend(self.args.iter().cloned());
        argv
    }

    pub fn spawn(self) -> Runner {
        let fixture = self.fixture;
        let cwd = self.cwd.clone().unwrap_or_else(|| fixture.repo.clone());
        let env = self.env.clone().unwrap_or_else(|| fixture.env.clone());
        let launch = Launch {
            ignore_hangup: self.ignore_hangup,
            blocked: self.blocked,
            file_limit: self.file_limit,
        };
        start_tool(&self.argv(), &cwd, &env, launch, &fixture.state)
    }

    /// `run` starts the tool and waits up to [`RUN_LIMIT`] for it.
    pub fn run(self) -> Out {
        self.spawn().communicate(RUN_LIMIT)
    }
}

/// The worktree listing, the bytes of every file outside `.git` and `target`, and the index bytes.
pub type Snapshot = (String, BTreeMap<PathBuf, Vec<u8>>, Vec<u8>);

fn files(root: &Path, directory: &Path, found: &mut BTreeMap<PathBuf, Vec<u8>>) {
    let mut entries: Vec<_> = fs::read_dir(directory)
        .expect("the directory is readable")
        .map(|entry| entry.expect("an entry is readable").path())
        .collect();
    entries.sort();
    for path in entries {
        let relative = path
            .strip_prefix(root)
            .expect("an entry under the root")
            .to_path_buf();
        let top = relative
            .components()
            .next()
            .map(|part| part.as_os_str().to_owned());
        if directory == root
            && (top.as_deref() == Some(OsStr::new(".git"))
                || top.as_deref() == Some(OsStr::new("target")))
        {
            continue;
        }
        let link = fs::symlink_metadata(&path).expect("an entry has a status");
        if link.is_dir() {
            files(root, &path, found);
        } else if fs::metadata(&path).is_ok_and(|status| status.is_file()) {
            found.insert(relative, fs::read(&path).expect("a file is readable"));
        }
    }
}

pub struct Fixture {
    pub state: PathBuf,
    pub cargo: PathBuf,
    pub artifacts: PathBuf,
    pub repo: PathBuf,
    pub env: Env,
    pub base: String,
    pub head: String,
    real_git: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        unlock(&self.state);
        let _ = fs::remove_dir_all(&self.state);
    }
}

/// `unlock` gives `dir` and each directory below it mode 0700 before it lists them, so a case that ends
/// early, a panic included, leaves a tree its owner can remove. It follows no link.
fn unlock(dir: &Path) {
    let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            unlock(&entry.path());
        }
    }
}

/// `with` returns `env` with each pair set, replacing a value the environment holds.
pub fn with(env: &Env, pairs: &[(&str, &OsStr)]) -> Env {
    let mut env = env.clone();
    for (name, value) in pairs {
        env.retain(|(key, _)| key != name);
        env.push((OsString::from(name), value.to_os_string()));
    }
    env
}

/// `names` holds `prefix:name` style entries `(file, name)` for the listed mutants of one file.
pub fn listed(file: &str, names: &[String]) -> Vec<(Text, Text)> {
    names
        .iter()
        .map(|name| (t(file), Text::from(name.as_str())))
        .collect()
}

pub fn lib_rs() -> String {
    format!("{SOURCE}/lib.rs")
}

impl Fixture {
    /// `new` builds the fixture of the case `name`: a repository whose base adds `lib.rs` with `one` and
    /// whose head adds `two`, an untracked `Cargo.lock`, and the `cargo` stand-in.
    pub fn new(name: &str) -> Self {
        let real_git = prepare_host();
        let parent = Path::new(env!("CARGO_TARGET_TMPDIR")).join("mutants-diff");
        fs::create_dir_all(&parent).expect("the scratch parent is made");
        let prefix = format!("{name}-");
        let state = kestrike_tools::temp_dir::make_temp_dir(&prefix, &parent)
            .expect("the state directory is made");
        let cargo = state.join("cargo");
        executable(&cargo, CARGO);
        let repo = state.join("repo");
        fs::create_dir(&repo).expect("the repository directory is made");
        let mut env: Env = std::env::vars_os()
            .filter(|(name, _)| {
                let name = name.as_bytes();
                !(name.starts_with(b"GIT_")
                    || name.starts_with(b"CARGO_MUTANTS_")
                    || name.starts_with(b"CARGO_PROFILE_")
                    || name.ends_with(b"RUSTFLAGS"))
            })
            .collect();
        let gitconfig = state.join("gitconfig");
        env = with(
            &env,
            &[
                ("FAKE_STATE", state.as_os_str()),
                ("GIT_CONFIG_NOSYSTEM", OsStr::new("1")),
                ("GIT_CONFIG_GLOBAL", gitconfig.as_os_str()),
                ("GIT_AUTHOR_NAME", OsStr::new("t")),
                ("GIT_AUTHOR_EMAIL", OsStr::new("t@t")),
                ("GIT_COMMITTER_NAME", OsStr::new("t")),
                ("GIT_COMMITTER_EMAIL", OsStr::new("t@t")),
            ],
        );
        let mut fixture = Self {
            artifacts: state.join("artifacts"),
            state,
            cargo,
            repo,
            env,
            base: String::new(),
            head: String::new(),
            real_git,
        };
        fixture.git(&["init", "-q"]);
        fixture.write(".gitignore", "/target\nCargo.lock\n");
        fixture.write("Cargo.toml", "[workspace]\n");
        fixture.write(".cargo/mutants.toml", CONFIG);
        fixture.write(".github/workflows/agent-checks.yml", WORKFLOW);
        fixture.write(&lib_rs(), "pub fn one() -> u32 { 1 }\n");
        fixture.write("README.md", "readme\n");
        fixture.base = fixture.commit("base");
        fixture.write(
            &lib_rs(),
            "pub fn one() -> u32 { 1 }\npub fn two() -> u32 { 2 }\n",
        );
        fixture.head = fixture.commit("head");
        fs::write(fixture.repo.join("Cargo.lock"), "# lock\n").expect("the lock is written");
        fixture
    }

    /// `git_in` runs Git with `args` in `cwd` and returns its standard output, failing the case on an
    /// exit other than 0.
    pub fn git_in<S: AsRef<OsStr>>(&self, cwd: &Path, args: &[S]) -> String {
        let output = Command::new("git")
            .args(args)
            .current_dir(cwd)
            .env_clear()
            .envs(self.env.iter().cloned())
            .output()
            .expect("git starts");
        let shown: Vec<_> = args
            .iter()
            .map(|arg| arg.as_ref().to_string_lossy().into_owned())
            .collect();
        assert!(
            output.status.success(),
            "git {shown:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    pub fn git<S: AsRef<OsStr>>(&self, args: &[S]) -> String {
        self.git_in(&self.repo, args)
    }

    pub fn write(&self, name: &str, text: &str) {
        let path = self.repo.join(name);
        fs::create_dir_all(path.parent().expect("a file has a directory"))
            .expect("the directory is made");
        fs::write(path, text).expect("the file is written");
    }

    pub fn commit_in(&self, cwd: &Path, message: &str) -> String {
        self.git_in(cwd, &["add", "-A"]);
        self.git_in(cwd, &["commit", "-q", "-m", message]);
        self.git_in(cwd, &["rev-parse", "HEAD"]).trim().to_owned()
    }

    pub fn commit(&self, message: &str) -> String {
        self.commit_in(&self.repo, message)
    }

    pub fn plan(&self, plan: &Plan) {
        plan.write(&self.state.join("plan"));
    }

    pub fn start(&self) -> Start<'_> {
        Start {
            fixture: self,
            args: Vec::new(),
            base: None,
            head: None,
            artifacts: None,
            env: None,
            cwd: None,
            raw: false,
            ignore_hangup: false,
            blocked: false,
            file_limit: None,
        }
    }

    /// `git_wrapper` returns an environment whose `git` is the wrapper in `mode`.
    pub fn git_wrapper(&self, mode: &str) -> Env {
        let bin = self.state.join("bin");
        if !bin.exists() {
            fs::create_dir(&bin).expect("the wrapper directory is made");
            let real = self
                .real_git
                .to_str()
                .expect("the real git's path is UTF-8");
            executable(&bin.join("git"), &GIT.replace("__REAL__", real));
        }
        let path = self
            .env
            .iter()
            .find(|(name, _)| name == "PATH")
            .map(|(_, value)| value.clone())
            .unwrap_or_default();
        let mut joined = bin.into_os_string();
        joined.push(":");
        joined.push(path);
        with(
            &self.env,
            &[("PATH", &joined), ("FAKE_GIT_MODE", OsStr::new(mode))],
        )
    }

    pub fn snapshot(&self) -> Snapshot {
        let mut found = BTreeMap::new();
        files(&self.repo, &self.repo, &mut found);
        let index = fs::read(self.repo.join(".git/index")).expect("the index is readable");
        (self.git(&["worktree", "list", "--porcelain"]), found, index)
    }

    pub fn calls(&self) -> Vec<Call> {
        fs::read(self.state.join("calls")).map_or_else(|_| Vec::new(), |bytes| parse_calls(&bytes))
    }

    pub fn builds(&self) -> Vec<Call> {
        self.calls()
            .into_iter()
            .filter(|call| !call.is_listing())
            .collect()
    }

    pub fn listings(&self) -> Vec<Call> {
        self.calls().into_iter().filter(Call::is_listing).collect()
    }

    /// `reports` returns each `<artifacts>/*/report.json`, sorted.
    pub fn reports_in(&self, artifacts: &Path) -> Vec<PathBuf> {
        let Ok(entries) = fs::read_dir(artifacts) else {
            return Vec::new();
        };
        let mut found: Vec<PathBuf> = entries
            .map(|entry| {
                entry
                    .expect("an entry is readable")
                    .path()
                    .join("report.json")
            })
            .filter(|path| path.is_file())
            .collect();
        found.sort();
        found
    }

    pub fn reports(&self) -> Vec<PathBuf> {
        self.reports_in(&self.artifacts)
    }

    pub fn clear(&self) {
        for path in self.reports() {
            fs::remove_file(path).expect("a stale report is removed");
        }
        for name in ["ready", "terminated", "terminating", "release", "calls"] {
            let _ = fs::remove_file(self.state.join(name));
        }
    }

    /// `report_in` reads the one report under `artifacts`, failing the case when there is none or more, or
    /// when it holds a number JSON has no form for.
    pub fn report_in(&self, out: Option<&Out>, artifacts: &Path) -> Object {
        let reports = self.reports_in(artifacts);
        let [path] = reports.as_slice() else {
            panic!(
                "expected one report, found {reports:?}: {}",
                out.map_or_else(String::new, Out::all)
            );
        };
        let text = fs::read_to_string(path).expect("the report is UTF-8");
        let Value::Object(report) = json::parse(&text).expect("the report parses") else {
            panic!("the report is an object: {text}");
        };
        for constant in ["NaN", "Infinity"] {
            assert!(
                !text.contains(constant),
                "the report holds {constant}: {text}"
            );
        }
        report
    }

    pub fn report(&self, out: Option<&Out>) -> Object {
        self.report_in(out, &self.artifacts)
    }

    /// `assert_gone` waits up to [`GONE_LIMIT`] for the process the marker `name` names to be gone or a
    /// zombie.
    pub fn assert_gone(&self, name: &str) {
        let pid: i64 = fs::read_to_string(self.state.join(name))
            .expect("the marker is written")
            .trim()
            .parse()
            .expect("the marker holds a process id");
        assert!(pid > 0);
        assert!(
            Path::new("/proc/self/stat").is_file(),
            "the process check needs procfs"
        );
        let start = Instant::now();
        while start.elapsed() < GONE_LIMIT {
            let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
                return;
            };
            let state = stat
                .rsplit_once(')')
                .map(|(_, rest)| rest.split_whitespace().next().unwrap_or(""));
            if state == Some("Z") {
                return;
            }
            thread::sleep(PAUSE);
        }
        panic!("the stand-in's process {pid} outlived the run");
    }

    /// `start_until_ready` starts `start` and returns it once the stand-in has published `marker`.
    pub fn start_until_ready(&self, start: Start<'_>, marker: &str) -> Runner {
        let mut runner = start.spawn();
        self.wait_for(marker, &mut runner);
        runner
    }

    pub fn wait_for(&self, marker: &str, runner: &mut Runner) {
        let start = Instant::now();
        while start.elapsed() < MARKER_LIMIT
            && !self.state.join(marker).exists()
            && runner.poll().is_none()
        {
            thread::sleep(PAUSE);
        }
        if !self.state.join(marker).exists() {
            runner.kill();
            panic!(
                "the stand-in never published {marker}: {}",
                runner.communicate(RUN_LIMIT).all()
            );
        }
    }
}

/// `two_mutants` lists the two mutants of `two` in `lib.rs`.
pub fn two_mutants() -> Vec<(Text, Text)> {
    let names: Vec<String> = (0..2)
        .map(|n| format!("{SOURCE}/lib.rs:2:1: replace two -> u32 with {n}"))
        .collect();
    listed(&lib_rs(), &names)
}

/// `registered` counts the worktrees the fixture repository's listing names.
pub fn registered(fixture: &Fixture) -> usize {
    fixture
        .git(&["worktree", "list", "--porcelain"])
        .matches("worktree ")
        .count()
}
