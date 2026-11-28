//! A clone of the checkout for the cases of `weaken-orderings run`, with `cargo`, `rustc` and the GenMC
//! lane replaced by stand-ins, and readers of the report the run leaves.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use kestrike_tools::genmc::read_source;
use kestrike_tools::json::{self, Object, Text, Value};
use kestrike_tools::orderings::check::CATALOG;
use kestrike_tools::orderings::sources::loom_site;

use super::standins::{suffixed, wrapper};
use super::{BINARY, Scratch, top};

pub const FILL_MODEL: &str = "storage::fill_model::";
pub const RUN_FENCE: &str = "fill-run-fence";
pub const RUN_FAILURE: &str = "a departed record whose owner had not ended";
pub const DEPART_ROW: &str = "fill-depart-release";
pub const JOIN_ROW: &str = "row-detach";
pub const JOIN_FREED: &str = "a follower's record was freed or reissued under it";
pub const CREDIT_ROW: &str = "credit-add";
pub const CREDIT_CASES: [&str; 4] = [
    "credit-seq-empty",
    "credit-seq-pool1",
    "credit-seq-stale",
    "credit-seq-two",
];
pub const CREDIT_FLAGGED: &str = "a record holding credits is flagged";
pub const GRACE_ROW: &str = "grace-pin-store";
pub const ANCHOR_RELEASED: &str = "protection violated: anchor released under a pinned reader";
pub const RETAIN: &str = "protection violated: a pinned reader's retain refused";
pub const CUTOFF: &str =
    "protection violated: a scan after the close missed an admitted interval's live pin";
pub const REVISION: &str = "0000000000000000000000000000000000000000";

pub fn run_tests() -> [String; 2] {
    [
        format!("{FILL_MODEL}two_owners_on_one_key_and_a_servicer_observing_the_run"),
        format!("{FILL_MODEL}three_participants_over_two_keys_observing_the_run"),
    ]
}

pub fn depart_tests() -> Vec<String> {
    let mut tests = vec![
        format!("{FILL_MODEL}two_owners_on_one_key_and_a_servicer"),
        format!("{FILL_MODEL}three_participants_over_two_keys_reach_the_serial_maximum"),
    ];
    tests.extend(run_tests());
    tests
}

pub fn run_site() -> (String, usize) {
    let top = top();
    let read = |path: &str| read_source(&top, path);
    loom_site(&run_tests()[0], RUN_FAILURE, &read).expect("the failure has one site")
}

pub fn run_at() -> String {
    let (path, line) = run_site();
    format!("{path}:{line}")
}

pub fn text(value: &str) -> Value {
    Value::String(Text::from(value))
}

pub fn texts(values: &[&str]) -> Value {
    Value::Array(values.iter().map(|value| text(value)).collect())
}

pub fn object(members: &[(&str, Value)]) -> Value {
    let mut object = Object::new();
    for (key, value) in members {
        object.insert(*key, value.clone());
    }
    Value::Object(object)
}

pub fn entry(lane: &str, tests: &[&str], failure: &str) -> Value {
    object(&[
        ("lane", text(lane)),
        ("tests", texts(tests)),
        ("failure", text(failure)),
    ])
}

pub fn seeded() -> Vec<(&'static str, Vec<Value>)> {
    let run = run_tests();
    let run: Vec<&str> = run.iter().map(String::as_str).collect();
    let depart = depart_tests();
    let depart: Vec<&str> = depart.iter().map(String::as_str).collect();
    vec![
        (RUN_FENCE, vec![entry("loom", &run, RUN_FAILURE)]),
        (DEPART_ROW, vec![entry("loom", &depart, RUN_FAILURE)]),
        (
            JOIN_ROW,
            vec![entry("genmc", &["join-production"], JOIN_FREED)],
        ),
        (
            CREDIT_ROW,
            vec![entry("genmc", &CREDIT_CASES, CREDIT_FLAGGED)],
        ),
        (
            GRACE_ROW,
            vec![
                entry("genmc", &["grace1-seq"], ANCHOR_RELEASED),
                entry("genmc", &["grace1-seq"], RETAIN),
                entry("genmc", &["cutoff-pinfirst"], CUTOFF),
            ],
        ),
    ]
}

pub fn row<'c>(catalog: &'c mut Value, id: &str) -> &'c mut Object {
    let Value::Object(catalog) = catalog else {
        panic!("the catalog is an object");
    };
    let Some(Value::Array(rows)) = catalog.get_mut("rows") else {
        panic!("the catalog lists rows");
    };
    rows.iter_mut()
        .find_map(|row| match row {
            Value::Object(row) if row.get("id") == Some(&text(id)) => Some(row),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no row {id}"))
}

pub fn decided(catalog: &mut Value, id: &str, kind: &str, value: Value) {
    let planted = row(catalog, id);
    for key in ["kill", "survives", "unrun"] {
        planted.remove(key);
    }
    planted.insert("revision", text(REVISION));
    planted.insert(kind, value);
}

pub fn needing(catalog: &mut Value, id: &str, needs: Vec<Value>) {
    let planted = row(catalog, id);
    for key in ["kill", "survives", "unrun", "revision"] {
        planted.remove(key);
    }
    planted.insert("unrun", object(&[("needs", Value::Array(needs))]));
}

pub fn row_ids(catalog: &Value) -> Vec<String> {
    match get(catalog, "rows") {
        Value::Array(rows) => rows.iter().map(|row| string(get(row, "id"))).collect(),
        _ => panic!("the catalog lists rows"),
    }
}

pub fn get<'v>(value: &'v Value, key: &str) -> &'v Value {
    match value {
        Value::Object(object) => object
            .get(key)
            .unwrap_or_else(|| panic!("no member {key:?} in {value:?}")),
        _ => panic!("{value:?} is no object"),
    }
}

pub fn has(value: &Value, key: &str) -> bool {
    matches!(value, Value::Object(object) if object.get(key).is_some())
}

pub fn string(value: &Value) -> String {
    match value {
        Value::String(text) => text.to_string(),
        _ => panic!("{value:?} is no string"),
    }
}

pub fn items(value: &Value) -> &[Value] {
    match value {
        Value::Array(items) => items,
        _ => panic!("{value:?} is no list"),
    }
}

pub fn strings_of(value: &Value) -> Vec<String> {
    items(value).iter().map(string).collect()
}

pub fn number(value: &Value) -> i64 {
    match value {
        Value::Integer(integer) => integer.to_string().parse().expect("a small integer"),
        _ => panic!("{value:?} is no integer"),
    }
}

pub fn results(report: &Value, id: &str) -> Vec<String> {
    row_results(report, id)
        .iter()
        .map(|result| string(get(result, "result")))
        .collect()
}

pub fn row_results<'r>(report: &'r Value, id: &str) -> &'r [Value] {
    items(get(get(get(report, "rows"), id), "results"))
}

pub fn sha256_of(path: &Path) -> String {
    kestrike_tools::python::hexdigest(
        &fs::read(path).unwrap_or_else(|error| panic!("{}: {error}", path.display())),
    )
}

pub fn read_json(path: &Path) -> Value {
    let read =
        fs::read_to_string(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    json::parse(&read).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn git(repo: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .expect("git starts");
    assert!(output.status.success(), "git {args:?}: {output:?}");
    String::from_utf8(output.stdout).expect("UTF-8")
}

pub fn status(repo: &Path) -> String {
    git(
        repo,
        &[
            "status",
            "--porcelain",
            "--ignored",
            "--untracked-files=all",
        ],
    )
}

/// A run's exit, its two streams and the report it left, `None` where it wrote none.
pub struct Ran {
    pub status: ExitStatus,
    pub stdout: String,
    pub stderr: String,
    pub report: Option<Value>,
}

impl Ran {
    pub fn code(&self) -> Option<i32> {
        self.status.code()
    }

    pub fn report(&self) -> &Value {
        self.report
            .as_ref()
            .unwrap_or_else(|| panic!("no report.json; stderr: {}", self.stderr))
    }
}

#[derive(Default)]
pub struct Opts {
    pub work: Option<PathBuf>,
    pub plan: Option<Value>,
    pub env: Vec<Setting>,
    pub umask: Option<libc::mode_t>,
}

/// A clone of the checkout with its tracked changes and untracked files, `cargo` and `rustc` stand-ins in
/// `bin/` and the lane stand-in in place of `scripts/rust-lane.sh`. `base` is the resolved directory that
/// holds them and `given` the path the runs name it by, which reaches `base` through a link where the
/// fixture stands behind one.
pub struct Fixture {
    _scratch: Scratch,
    pub base: PathBuf,
    pub given: PathBuf,
    pub repo: PathBuf,
    pub plan: PathBuf,
    pub catalog: Value,
}

impl Fixture {
    pub fn new(label: &str) -> Self {
        let scratch = Scratch::new(label);
        let base = scratch.0.canonicalize().expect("the scratch resolves");
        Self::within(scratch, base.clone(), base)
    }

    pub fn behind_link(label: &str) -> Self {
        let scratch = Scratch::new(label);
        let real = scratch.0.join("real");
        fs::create_dir(&real).expect("made");
        let alias = scratch.0.join("alias");
        symlink("real", &alias).expect("linked");
        let base = real.canonicalize().expect("resolves");
        Self::within(scratch, base, alias)
    }

    fn within(scratch: Scratch, base: PathBuf, given: PathBuf) -> Self {
        let top = top();
        let repo = base.join("repo");
        let cloned = Command::new("git")
            .args(["clone", "-q", "--shared"])
            .arg(&top)
            .arg(&repo)
            .status()
            .expect("git starts");
        assert!(cloned.success());
        let changed = git(&top, &["diff", "--name-only", "-z", "HEAD"]);
        let untracked = git(&top, &["ls-files", "-z", "--others", "--exclude-standard"]);
        for name in changed.split('\0').chain(untracked.split('\0')) {
            if name.is_empty() {
                continue;
            }
            let (source, target) = (top.join(name), repo.join(name));
            if source.is_file() {
                fs::create_dir_all(target.parent().expect("a parent")).expect("made");
                fs::copy(&source, &target).expect("copied");
            } else if target.exists() {
                fs::remove_file(&target).expect("removed");
            }
        }
        let bin = base.join("bin");
        fs::create_dir(&bin).expect("made");
        let stands = [
            ("cargo", wrapper("cargo")),
            ("rustc", "#!/bin/sh\necho \"rustc $1-stub\"\n".to_owned()),
            ("lane", wrapper("lane")),
        ];
        for (name, script) in stands {
            fs::write(bin.join(name), script).expect("written");
            fs::set_permissions(bin.join(name), fs::Permissions::from_mode(0o755))
                .expect("changed");
        }
        let lane = format!("exec '{}' \"$@\"\n", bin.join("lane").display());
        fs::write(repo.join("scripts/rust-lane.sh"), lane).expect("written");
        let plan = base.join("plan.json");
        fs::write(&plan, "{}").expect("written");
        let catalog = read_json(&repo.join(CATALOG));
        Self {
            _scratch: scratch,
            base,
            given,
            repo,
            plan,
            catalog,
        }
    }

    /// `commit` writes the catalog with the seeded rows and `change` and commits every change of the clone,
    /// returning the commit.
    pub fn commit_with(&self, change: impl FnOnce(&mut Value)) -> String {
        let mut planted = self.catalog.clone();
        for (id, needs) in seeded() {
            needing(&mut planted, id, needs);
        }
        change(&mut planted);
        fs::write(self.repo.join(CATALOG), json::line(&planted)).expect("written");
        git(&self.repo, &["add", "-A"]);
        git(
            &self.repo,
            &[
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "core.hooksPath=/dev/null",
                "commit",
                "-qm",
                "planted",
                "--allow-empty",
            ],
        );
        git(&self.repo, &["rev-parse", "HEAD"]).trim().to_owned()
    }

    pub fn commit(&self) -> String {
        self.commit_with(|_| {})
    }

    pub fn work(&self, name: &str) -> PathBuf {
        self.given.join(name)
    }

    pub fn resolved(&self, name: &str) -> PathBuf {
        self.base.join(name)
    }

    fn command(
        &self,
        rows: &[&str],
        work: &Path,
        plan: Option<&Value>,
        env: &[(&str, Option<String>)],
    ) -> Command {
        let written = plan.map_or_else(|| "{}".to_owned(), json::line);
        fs::write(&self.plan, written).expect("written");
        for suffix in [
            ".seen",
            ".log",
            ".lane",
            ".env",
            ".sleeping",
            ".stopped",
            ".failed",
            ".parent",
        ] {
            let _ = fs::remove_file(suffixed(&self.plan, suffix));
        }
        let mut path = OsString::from(self.base.join("bin"));
        path.push(":");
        path.push(std::env::var_os("PATH").unwrap_or_default());
        let mut command = Command::new(BINARY);
        command
            .arg(&self.repo)
            .args(["weaken-orderings", "run", "--work"])
            .arg(work)
            .args(rows.iter().map(|row| format!("--row={row}")))
            .current_dir(&self.base)
            .env("PATH", path)
            .env("STUB_PLAN", &self.plan)
            .env("LOOM_MAX_PREEMPTIONS", "9")
            .env("CARGO_ENCODED_RUSTFLAGS", "--cfg\u{1f}x")
            .env("CARGO_TERM_COLOR", "always")
            .env("CARGO_TERM_QUIET", "true");
        for (name, value) in env {
            match value {
                Some(value) => command.env(name, value),
                None => command.env_remove(name),
            };
        }
        default_signals(&mut command);
        command
    }

    fn report_of(work: &Path) -> Option<Value> {
        let path = work.join("report.json");
        path.is_file().then(|| read_json(&path))
    }

    fn standins_held(&self) {
        let failed = suffixed(&self.plan, ".failed");
        if let Ok(failed) = fs::read_to_string(failed) {
            panic!("a stand-in failed: {failed}");
        }
    }

    pub fn run_rows(&self, rows: &[&str]) -> Ran {
        self.run_with(rows, Opts::default())
    }

    pub fn run_with(&self, rows: &[&str], opts: Opts) -> Ran {
        let work = opts.work.unwrap_or_else(|| self.work("work"));
        let mut command = self.command(rows, &work, opts.plan.as_ref(), &opts.env);
        if let Some(mask) = opts.umask {
            // SAFETY: the hook runs in the forked child before `exec` and calls only `umask`, which is
            // async-signal-safe.
            unsafe {
                command.pre_exec(move || {
                    libc::umask(mask);
                    Ok(())
                });
            }
        }
        let output = command
            .stdin(Stdio::null())
            .output()
            .expect("the binary starts");
        self.standins_held();
        Ran {
            status: output.status,
            stdout: String::from_utf8(output.stdout).expect("UTF-8"),
            stderr: String::from_utf8(output.stderr).expect("UTF-8"),
            report: Self::report_of(&work),
        }
    }

    pub fn start(&self, rows: &[&str], work: &Path, plan: Value) -> Running {
        let child = self
            .command(rows, work, Some(&plan), &[])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("the binary starts");
        Running(child)
    }

    pub fn wait_for(&self, suffix: &str) {
        let marker = suffixed(&self.plan, suffix);
        let start = Instant::now();
        while !marker.exists() {
            self.standins_held();
            assert!(
                start.elapsed() < Duration::from_secs(60),
                "no {suffix} marker"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    pub fn exists(&self, suffix: &str) -> bool {
        suffixed(&self.plan, suffix).exists()
    }

    pub fn lines(&self, suffix: &str) -> Vec<String> {
        fs::read_to_string(suffixed(&self.plan, suffix))
            .map(|text| text.lines().map(str::to_owned).collect())
            .unwrap_or_default()
    }

    pub fn stub_calls(&self) -> Vec<Value> {
        self.lines(".env")
            .iter()
            .map(|line| json::parse(line).expect("a call is JSON"))
            .collect()
    }

    pub fn logged(&self, phase: &str) -> Vec<String> {
        self.lines(".log")
            .iter()
            .filter(|line| line.split(' ').nth(1) == Some(phase))
            .map(|line| line.split(' ').next().unwrap_or_default().to_owned())
            .collect()
    }

    /// Each scoped file of the copy under `work` holds the clone's bytes, and no staging file stands.
    pub fn assert_restored(&self, work: &Path) {
        for name in super::standins::scoped_files(&self.repo) {
            assert_eq!(
                fs::read(work.join("copy").join(&name)).expect("reads"),
                fs::read(self.repo.join(&name)).expect("reads"),
                "{name}"
            );
        }
        assert_eq!(staged(&work.join("copy")), Vec::<PathBuf>::new());
        let listing = |directory: &Path| {
            let mut names: Vec<_> = fs::read_dir(directory)
                .expect("lists")
                .map(|entry| entry.expect("lists").file_name())
                .collect();
            names.sort();
            names
        };
        for name in super::standins::scoped_files(&self.repo) {
            let parent = Path::new(&name).parent().expect("a parent");
            assert_eq!(
                listing(&work.join("copy").join(parent)),
                listing(&self.repo.join(parent)),
                "{}",
                parent.display()
            );
        }
    }
}

/// `staged` lists the files under `directory` whose name ends in `.weaken`.
pub fn staged(directory: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![directory.to_owned()];
    while let Some(at) = pending.pop() {
        for entry in fs::read_dir(&at).expect("lists") {
            let entry = entry.expect("lists");
            let kind = entry.file_type().expect("a type");
            if kind.is_dir() {
                pending.push(entry.path());
            } else if entry.file_name().to_string_lossy().ends_with(".weaken") {
                found.push(entry.path());
            }
        }
    }
    found
}

fn default_signals(command: &mut Command) {
    // SAFETY: the hook runs in the forked child before `exec` and calls only `signal`, `sigemptyset`,
    // `sigaddset` and `sigprocmask`, which are async-signal-safe, on a local set.
    unsafe {
        command.pre_exec(|| {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            for number in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
                libc::signal(number, libc::SIG_DFL);
                libc::sigaddset(&mut set, number);
            }
            libc::sigprocmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
            Ok(())
        });
    }
}

/// A started run, killed and reaped when the case ends while it still runs.
pub struct Running(Child);

impl Running {
    pub fn signal(&mut self, number: libc::c_int) {
        assert!(
            matches!(self.0.try_wait(), Ok(None)),
            "the run still runs unreaped"
        );
        let pid = libc::pid_t::try_from(self.0.id()).expect("a pid");
        // SAFETY: `kill` takes two integers; the child is unreaped, so its pid names it.
        assert_eq!(unsafe { libc::kill(pid, number) }, 0);
    }

    pub fn id(&self) -> u32 {
        self.0.id()
    }

    /// `wait` reaps the run within `limit`, or kills it and fails the case.
    pub fn wait(&mut self, limit: Duration) -> ExitStatus {
        let start = Instant::now();
        loop {
            if let Some(status) = self.0.try_wait().expect("the wait succeeds") {
                return status;
            }
            assert!(start.elapsed() < limit, "the run ended within {limit:?}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(None)) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

pub fn ended_by(status: ExitStatus, number: libc::c_int) -> bool {
    status.signal() == Some(number)
}

/// `plan` maps each test or case to its modes, each a `(phase, mode)` pair.
pub fn plan(tests: &[(&str, &[(&str, &str)])]) -> Value {
    let mut plan = Object::new();
    for (test, modes) in tests {
        let modes: Vec<(&str, Value)> = modes
            .iter()
            .map(|(phase, mode)| (*phase, text(mode)))
            .collect();
        plan.insert(*test, object(&modes));
    }
    Value::Object(plan)
}

/// `workflow_pin` is the value of `name` in the `env` block of `repo`'s workflow, its quotes cut.
pub fn workflow_pin(repo: &Path, name: &str) -> String {
    let workflow =
        fs::read_to_string(repo.join(".github/workflows/agent-checks.yml")).expect("reads");
    let block = workflow.split("\njobs:").next().unwrap_or_default();
    let wanted = format!("  {name}:");
    block
        .lines()
        .rev()
        .find_map(|line| line.strip_prefix(&wanted))
        .map(|value| value.trim().trim_matches('"').to_owned())
        .unwrap_or_else(|| panic!("no {name} pin"))
}

pub fn pairs(value: &Value) -> BTreeMap<String, String> {
    match value {
        Value::Object(object) => object
            .iter()
            .map(|(name, value)| (name.to_string(), string(value)))
            .collect(),
        _ => panic!("{value:?} is no object"),
    }
}

/// An environment change: a name and its value, or `None` to remove the name.
pub type Setting = (&'static str, Option<String>);

pub fn env(pairs: &[(&'static str, &str)]) -> Vec<Setting> {
    pairs
        .iter()
        .map(|(name, value)| (*name, Some((*value).to_owned())))
        .collect()
}
