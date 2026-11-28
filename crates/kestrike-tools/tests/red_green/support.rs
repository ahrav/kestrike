//! A case's fixture: a scratch directory of its own under `CARGO_TARGET_TMPDIR`, mode 0700, holding the
//! stand-ins' state, a repository with a base and a head commit, and the temporary directory the run
//! gets as `TMPDIR`. The run is this test executable started again in the role [`role`], with the
//! fixture's environment, which removes the caller's `GIT_`, `GITHUB_` and `CARGO_` variables and points
//! Git's system and global configuration at nothing and a file of the fixture.

use std::ffi::{OsStr, OsString};
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use kestrike_tools::json::{self, Value};
use kestrike_tools::process::INTERRUPT;
use kestrike_tools::red_green::run::{Facts, run_with};
use kestrike_tools::temp_dir::{TempDirError, make_temp_dir};

use super::standins;

pub const TEST: &str = "storage::device::table_tests::a_poll_reports_each_completion_once";
pub const EXPECT: &str = "a poll counts that completion as delivered";
pub const PASSED: &str =
    "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.00s";
pub const FAILED: &str = "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.00s";
pub const TWO_LINES: &str = "first payload line\nsecond payload line";
pub const NO_EVIDENCE: &str =
    "left no readable artifact.json or attempt output of its own in the receipt";
/// The arguments that lead each Git step that builds a leg tree.
pub const HOOKLESS: &str = "-c core.hooksPath=/dev/null ";

const ROLE: &str = "RED_GREEN_ROLE";
const ROLE_TEST: &str = "red_green::support::role";
/// The file that holds the role's top and arguments, which libtest would refuse on its command line
/// where they are not UTF-8.
const ARGS: &str = "RED_GREEN_ARGS";
/// The user ID the role's ownership checks judge by, in decimal.
pub const UID: &str = "RED_GREEN_UID";
/// The run directory's name the role gives the run.
pub const RUN_NAME: &str = "RED_GREEN_RUN_NAME";
/// A file to which the role appends, a line each, the parent of each temporary directory it makes.
pub const MADE: &str = "RED_GREEN_MADE";
/// How the role's maker of the temporary directory acts: `fail` fails with the text
/// `no temporary directory`, and `signal` makes the directory, appends its path to the file [`MADE`]
/// names and records SIGTERM.
pub const MAKE_TEMP: &str = "RED_GREEN_MAKE_TEMP";
/// How the role starts a runner: `signal` starts it, appends its process ID to the file [`SPAWNED`]
/// names and records SIGINT and then SIGTERM; `fail` records SIGTERM and fails with the text
/// `spawn failed`; `error` fails with that text alone.
pub const SPAWN: &str = "RED_GREEN_SPAWN";
/// The file to which the role's `signal` start appends the runner's process ID.
pub const SPAWNED: &str = "RED_GREEN_SPAWNED";

/// The built binary that `scripts/tool.sh` starts.
pub const BINARY: &str = env!("CARGO_BIN_EXE_kestrike-tools");

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// The checkout whose `scripts/` holds the real runner and selector.
pub fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the checkout resolves")
}

/// The role runs the tool in a process of its own: the file [`ARGS`] names holds the top and the tool's
/// arguments, each ended by a NUL, and the variables [`UID`], [`RUN_NAME`], [`MADE`], [`MAKE_TEMP`] and
/// [`SPAWN`] set its facts. The wrapper hands the caller's standard output over as descriptor 3 while
/// libtest writes its own output to `/dev/null`.
#[test]
fn role() {
    if std::env::var_os(ROLE).is_none() {
        return;
    }
    let list = std::env::var_os(ARGS).expect("the role is given its arguments");
    let args: Vec<OsString> = fs::read(&list)
        .unwrap_or_else(|error| panic!("{}: {error}", Path::new(&list).display()))
        .split(|&byte| byte == 0)
        .map(|arg| OsStr::from_bytes(arg).to_os_string())
        .collect();
    let (top, rest) = args.split_first().expect("the role is given the top");
    let uid = std::env::var(UID)
        .map_or_else(|_| me(), |uid| uid.parse().expect("the user ID is decimal"));
    let made = std::env::var_os(MADE);
    let make_temp = std::env::var(MAKE_TEMP).unwrap_or_default();
    let maker = |prefix: &str, parent: &Path| {
        if let Some(log) = &made {
            let mut line = parent.as_os_str().as_bytes().to_vec();
            line.push(b'\n');
            append(Path::new(log), &line);
        }
        if make_temp == "fail" {
            return Err(TempDirError::Random(std::io::Error::other(
                "no temporary directory",
            )));
        }
        let directory = make_temp_dir(prefix, parent)?;
        if make_temp == "signal" {
            if let Some(log) = &made {
                let mut line = directory.as_os_str().as_bytes().to_vec();
                line.push(b'\n');
                append(Path::new(log), &line);
            }
            INTERRUPT.record(libc::SIGTERM);
        }
        Ok(directory)
    };
    let spawn_mode = std::env::var(SPAWN).unwrap_or_default();
    let spawner = |command: &mut Command| match spawn_mode.as_str() {
        "signal" => {
            let child = command.spawn()?;
            if let Some(log) = std::env::var_os(SPAWNED) {
                append(Path::new(&log), format!("{}\n", child.id()).as_bytes());
            }
            INTERRUPT.record(libc::SIGINT);
            INTERRUPT.record(libc::SIGTERM);
            Ok(child)
        }
        "fail" => {
            INTERRUPT.record(libc::SIGTERM);
            Err(std::io::Error::other("spawn failed"))
        }
        "error" => Err(std::io::Error::other("spawn failed")),
        _ => command.spawn(),
    };
    let facts = Facts {
        uid,
        run_name: std::env::var_os(RUN_NAME),
        make_temp: &maker,
        spawn: &spawner,
        interrupt: &INTERRUPT,
    };
    // SAFETY: the wrapper opens descriptor 3 as the caller's standard output, and nothing else in this
    // process owns it; `dup2` and `close` take integers.
    unsafe {
        assert_eq!(
            libc::dup2(3, 1),
            1,
            "the caller's standard output is descriptor 3"
        );
        assert_eq!(libc::close(3), 0);
    }
    let code = run_with(Path::new(top), rest, &facts);
    std::process::exit(i32::from(code));
}

/// `me` is this process's real user ID.
pub fn me() -> u32 {
    // SAFETY: `getuid` takes no argument and always succeeds.
    unsafe { libc::getuid() }
}

static HOST: std::sync::Once = std::sync::Once::new();

/// `prepare_host` sets, once for the test process, the umask 022, so the fixtures get the same modes
/// under any caller's mask, and the subreaper flag, so a leg process that outlives the run it belongs
/// to becomes this process's zombie and is never reaped by another.
fn prepare_host() {
    HOST.call_once(|| {
        // SAFETY: `umask` takes an integer and always succeeds; `prctl` with
        // `PR_SET_CHILD_SUBREAPER` reads its integer arguments alone.
        unsafe {
            libc::umask(0o022);
            assert_eq!(libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0), 0);
        }
    });
}

pub fn append(path: &Path, bytes: &[u8]) {
    OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)
        .and_then(|mut file| file.write_all(bytes))
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
}

pub fn write(path: &Path, contents: impl AsRef<[u8]>) {
    fs::write(path, contents).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
}

pub fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

pub fn chmod(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
}

/// `private_dir` makes `path` with mode 0700 whatever the umask.
pub fn private_dir(path: &Path) {
    DirBuilder::new()
        .mode(0o700)
        .create(path)
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    chmod(path, 0o700);
}

/// `executable` writes `text` at `path` with mode 0755 through a child process, the one process that holds
/// the file open for writing, since `execve` refuses a file some process holds open for writing and a
/// child another test thread forks holds every descriptor of the test process until its own `execve`.
pub fn executable(path: &Path, text: &str) {
    let mut writer = Command::new("sh")
        .args(["-c", r#"cat > "$1" && chmod 755 "$1""#, "sh"])
        .arg(path)
        .stdin(Stdio::piped())
        .spawn()
        .expect("the writer starts");
    writer
        .stdin
        .take()
        .expect("the writer's input is piped")
        .write_all(text.as_bytes())
        .expect("the text reaches the writer");
    let status = writer.wait().expect("the writer ends");
    assert!(status.success(), "{} is written: {status}", path.display());
}

pub fn os(bytes: &[u8]) -> &OsStr {
    OsStr::from_bytes(bytes)
}

/// One finished run of the tool: its exit, or the negated signal that ended it, and both streams.
#[derive(Debug)]
pub struct Done {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Done {
    pub fn shown(&self) -> String {
        format!("exit {}\n{}{}", self.code, self.stdout, self.stderr)
    }

    /// `line` is the one line of standard output.
    pub fn line(&self) -> &str {
        let lines: Vec<&str> = self.stdout.lines().collect();
        assert_eq!(lines.len(), 1, "{}", self.shown());
        lines[0]
    }
}

/// The options of one call of the tool. `base`, `head` and `cargo` default to the fixture's own, and an
/// empty value leaves the option out; `carry` names no `--carry` when it is empty.
#[derive(Clone)]
pub struct Call {
    pub extra: Vec<OsString>,
    pub carry: Vec<OsString>,
    pub expect: String,
    pub base: Option<String>,
    pub head: Option<String>,
    pub package: String,
    pub target: String,
    pub cargo: Option<String>,
    pub watchdog: String,
    pub top: Option<PathBuf>,
    pub env: Option<Vec<(OsString, OsString)>>,
    pub cwd: Option<PathBuf>,
    pub input: Vec<u8>,
    pub umask: Option<u32>,
}

impl Default for Call {
    fn default() -> Self {
        Self {
            extra: Vec::new(),
            carry: vec![OsString::from("table_tests.rs")],
            expect: EXPECT.to_owned(),
            base: None,
            head: None,
            package: "kestrike".to_owned(),
            target: "lib".to_owned(),
            cargo: None,
            watchdog: "30".to_owned(),
            top: None,
            env: None,
            cwd: None,
            input: Vec::new(),
            umask: None,
        }
    }
}

pub fn words(words: &[&str]) -> Vec<OsString> {
    words.iter().map(OsString::from).collect()
}

/// The fixture of one case; its scratch directory goes on drop.
pub struct Fixture {
    pub root: PathBuf,
    pub state: PathBuf,
    pub repo: PathBuf,
    pub tmp: PathBuf,
    pub base: String,
    pub head: String,
    pub env: Vec<(OsString, OsString)>,
    pub status: String,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        opened(&self.root);
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// `opened` gives each directory under `path` its owner's full access, so the removal can list it.
fn opened(path: &Path) {
    let Ok(status) = fs::symlink_metadata(path) else {
        return;
    };
    if !status.is_dir() {
        return;
    }
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            opened(&entry.path());
        }
    }
}

/// `claimed` makes a new directory `PREFIX-PID-N` under `base`, mode 0700, taking the next `N` on each
/// collision, so the fixture removes only the directory it made.
fn claimed(base: &Path, prefix: &str) -> PathBuf {
    loop {
        let scratch = base.join(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        match DirBuilder::new().mode(0o700).create(&scratch) {
            Ok(()) => {
                chmod(&scratch, 0o700);
                return scratch;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("{}: {error}", scratch.display()),
        }
    }
}

impl Fixture {
    /// `new` builds the repository: a base of `.gitignore`, `Cargo.toml` and `table.rs`, and a head that
    /// fixes `table.rs` and adds the fix marker, the carried test file and files whose names a pathspec
    /// or a terminal could misread, with `origin/main` at the base.
    pub fn new() -> Self {
        prepare_host();
        let base = Path::new(env!("CARGO_TARGET_TMPDIR"));
        fs::create_dir_all(base).unwrap_or_else(|error| panic!("{}: {error}", base.display()));
        let root = claimed(base, "red-green")
            .canonicalize()
            .expect("the scratch directory resolves");
        let (state, repo, tmp) = (root.join("state"), root.join("repo"), root.join("tmp"));
        for directory in [&state, &repo, &tmp] {
            private_dir(directory);
        }
        executable(&state.join("kestrike"), &standins::executable());
        executable(&state.join("cargo"), standins::CARGO);
        executable(
            &state.join("rustc"),
            "#!/bin/sh\necho 'rustc 1.99.0 (00000000 2026-01-01)'\n",
        );
        let mut env: Vec<(OsString, OsString)> = std::env::vars_os()
            .filter(|(name, _)| {
                let name = name.as_bytes();
                !(name.starts_with(b"GIT_")
                    || name.starts_with(b"GITHUB_")
                    || name.starts_with(b"CARGO_"))
                    && name != ROLE.as_bytes()
            })
            .collect();
        for (name, value) in [
            ("GIT_CONFIG_NOSYSTEM", OsString::from("1")),
            ("GIT_CONFIG_GLOBAL", root.join("global").into_os_string()),
            ("GIT_CEILING_DIRECTORIES", root.clone().into_os_string()),
            ("GIT_AUTHOR_NAME", OsString::from("t")),
            ("GIT_AUTHOR_EMAIL", OsString::from("t@example.com")),
            ("GIT_COMMITTER_NAME", OsString::from("t")),
            ("GIT_COMMITTER_EMAIL", OsString::from("t@example.com")),
            ("FAKE_STATE", state.clone().into_os_string()),
            ("RUSTC", state.join("rustc").into_os_string()),
            ("TMPDIR", tmp.clone().into_os_string()),
        ] {
            env.push((OsString::from(name), value));
        }
        let mut fixture = Self {
            root,
            state,
            repo,
            tmp,
            base: String::new(),
            head: String::new(),
            env,
            status: String::new(),
        };
        fixture.plan("{}");
        fixture.git(&["init", "-q", "-b", "main"]);
        fixture.base = fixture.commit(&[
            (b".gitignore", "/target\n"),
            (b"Cargo.toml", "[package]\n"),
            (b"table.rs", "unfixed\n"),
        ]);
        private_dir(&fixture.repo.join("sub"));
        fixture.head = fixture.commit(&[
            (b"table.rs", "fixed\n"),
            (b"fix.marker", ""),
            (b"table_tests.rs", "#[test]\n"),
            (b"notes.txt", "a head file\n"),
            (b"sub/x.rs", "x\n"),
            (b"t[a-z].rs", ""),
            (b"tb.rs", ""),
            (b"\xff.rs", ""),
            (b"cr\r.rs", ""),
        ]);
        let base = fixture.base.clone();
        fixture.git(&["update-ref", "refs/remotes/origin/main", &base]);
        fixture.status = fixture.git(&["status", "--porcelain"]);
        fixture
    }

    /// `plan` writes the legs' plan, a JSON object.
    pub fn plan(&self, plan: &str) {
        write(&self.state.join("plan.json"), plan);
    }

    /// `git` runs Git in the repository with the fixture's environment and returns its stripped output.
    pub fn git(&self, args: &[&str]) -> String {
        let args: Vec<OsString> = words(args);
        self.git_os(&args, None)
    }

    pub fn git_os(&self, args: &[OsString], input: Option<&str>) -> String {
        let mut child = Command::new("git")
            .args(args)
            .current_dir(&self.repo)
            .env_clear()
            .envs(self.env.iter().cloned())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("git starts");
        let mut stdin = child.stdin.take().expect("the input is piped");
        stdin
            .write_all(input.unwrap_or_default().as_bytes())
            .expect("the input reaches git");
        drop(stdin);
        let output = child.wait_with_output().expect("git ends");
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    }

    /// `commit` writes each file, stages it and commits, and returns the new commit's ID.
    pub fn commit(&self, files: &[(&[u8], &str)]) -> String {
        for (name, content) in files {
            write(&self.repo.join(os(name)), content);
            self.git_os(
                &[
                    OsString::from("add"),
                    OsString::from("--"),
                    os(name).to_owned(),
                ],
                None,
            );
        }
        self.git(&["commit", "-q", "-m", "change"]);
        self.git(&["rev-parse", "HEAD"])
    }

    /// `with_env` is the fixture's environment with each of `vars` set.
    pub fn with_env(&self, vars: &[(&str, &OsStr)]) -> Vec<(OsString, OsString)> {
        let mut env: Vec<(OsString, OsString)> = self
            .env
            .iter()
            .filter(|(name, _)| !vars.iter().any(|(set, _)| name == set))
            .cloned()
            .collect();
        env.extend(
            vars.iter()
                .map(|(name, value)| (OsString::from(name), value.to_os_string())),
        );
        env
    }

    /// `path_env` is the fixture's environment with `directory` first on `PATH`.
    pub fn path_env(&self, directory: &Path) -> Vec<(OsString, OsString)> {
        let mut path = directory.as_os_str().to_os_string();
        path.push(":");
        path.push(std::env::var_os("PATH").unwrap_or_else(|| OsString::from("/usr/bin:/bin")));
        self.with_env(&[("PATH", &path)])
    }

    /// `command` is the tool's argument list for `call`.
    pub fn command(&self, call: &Call) -> Vec<OsString> {
        let given =
            |value: &Option<String>, own: &str| value.clone().unwrap_or_else(|| own.to_owned());
        let mut argv = words(&[
            "--package",
            &call.package,
            "--target",
            &call.target,
            "--test",
            TEST,
            "--expect",
            &call.expect,
        ]);
        if !call.carry.is_empty() {
            argv.push(OsString::from("--carry"));
            argv.extend(call.carry.iter().cloned());
        }
        let base = given(&call.base, &self.base);
        if !base.is_empty() {
            argv.extend(words(&["--base", &base]));
        }
        let head = given(&call.head, &self.head);
        if !head.is_empty() {
            argv.extend(words(&["--head", &head]));
        }
        let cargo = given(&call.cargo, &self.state.join("cargo").to_string_lossy());
        if !cargo.is_empty() {
            argv.push(OsString::from(format!("--cargo={cargo}")));
        }
        argv.extend(words(&["--watchdog", &call.watchdog]));
        argv.extend(call.extra.iter().cloned());
        argv
    }

    /// `start` prepares the run of `call`: this test executable in the role, with the caller's standard
    /// output on descriptor 3 and libtest's own on `/dev/null`.
    pub fn start(&self, call: &Call) -> Command {
        let exe = std::env::current_exe().expect("the test executable is known");
        let top = call.top.clone().unwrap_or_else(root);
        let mut script = String::new();
        if let Some(mask) = call.umask {
            script.push_str(&format!("umask {mask:03o}; "));
        }
        script.push_str(&format!(
            "exec \"$0\" --exact {ROLE_TEST} --nocapture --test-threads 1 3>&1 1>/dev/null"
        ));
        let list = self.root.join(format!(
            "call-{}.args",
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let mut listed = Vec::new();
        for arg in std::iter::once(top.into_os_string()).chain(self.command(call)) {
            listed.extend_from_slice(arg.as_bytes());
            listed.push(0);
        }
        listed.pop();
        write(&list, listed);
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg(script)
            .arg(exe)
            .current_dir(call.cwd.as_deref().unwrap_or(&self.repo))
            .env_clear()
            .envs(call.env.as_ref().unwrap_or(&self.env).iter().cloned())
            .env(ROLE, "run")
            .env(ARGS, &list);
        command
    }

    /// `start_tool` prepares the run of `call` as `scripts/tool.sh` starts the tool: the built binary
    /// with the checkout's top, the name `red-green` and the arguments, in `call.cwd` or the repository,
    /// with `call.env` or the fixture's environment.
    pub fn start_tool(&self, call: &Call) -> Command {
        let mut command = Command::new(BINARY);
        command
            .arg(call.top.clone().unwrap_or_else(root))
            .arg("red-green")
            .args(self.command(call))
            .current_dir(call.cwd.as_deref().unwrap_or(&self.repo))
            .env_clear()
            .envs(call.env.as_ref().unwrap_or(&self.env).iter().cloned());
        command
    }

    /// `red_green` runs `call` in the role to its end with `call.input` on its standard input.
    pub fn red_green(&self, call: &Call) -> Done {
        finish(self.start(call), &call.input)
    }

    /// `tool` runs `call` through the built binary to its end with `call.input` on its standard input.
    pub fn tool(&self, call: &Call) -> Done {
        finish(self.start_tool(call), &call.input)
    }

    /// `spawn_tool` starts `call` through the built binary with an empty standard input and both
    /// output streams read by threads of their own.
    pub fn spawn_tool(&self, call: &Call) -> Running {
        Running::start(self.start_tool(call))
    }

    /// `receipts` is each `receipt.json` in a run directory under the repository's `target/red-green/`.
    pub fn receipts(&self) -> Vec<PathBuf> {
        let parent = self.repo.join("target/red-green");
        let Ok(entries) = fs::read_dir(&parent) else {
            return Vec::new();
        };
        entries
            .map(|entry| entry.expect("an entry lists").path().join("receipt.json"))
            .filter(|path| fs::symlink_metadata(path).is_ok())
            .collect()
    }

    /// `run` runs the fixture's own call with `edit` applied.
    pub fn run(&self, edit: impl FnOnce(&mut Call)) -> Done {
        let mut call = Call::default();
        edit(&mut call);
        self.red_green(&call)
    }

    /// `builds` is each build the `cargo` stand-in logged, in order.
    pub fn builds(&self) -> Vec<Value> {
        let path = self.state.join("builds.txt");
        let Ok(text) = fs::read_to_string(&path) else {
            return Vec::new();
        };
        text.lines()
            .map(|line| json::parse(line).expect("a build line is JSON"))
            .collect()
    }

    /// `build_legs` is the leg of each logged build.
    pub fn build_legs(&self) -> Vec<String> {
        self.builds()
            .iter()
            .map(|build| text(at(build, "leg")))
            .collect()
    }

    pub fn clear_builds(&self) {
        let _ = fs::remove_file(self.state.join("builds.txt"));
    }

    /// `receipt` is the path the one `receipt: ` line names and the receipt it holds.
    pub fn receipt(&self, done: &Done) -> (PathBuf, Value) {
        let lines: Vec<&str> = done
            .stderr
            .lines()
            .filter_map(|line| line.strip_prefix("receipt: "))
            .collect();
        assert_eq!(lines.len(), 1, "{}", done.shown());
        let path = PathBuf::from(lines[0]);
        let value = json::parse(&read(&path)).expect("the receipt is JSON");
        (path, value)
    }

    /// `attempt_output` is the base leg's attempt output on `stream`.
    pub fn attempt_output(&self, receipt: &Value, stream: &str) -> String {
        let artifact = PathBuf::from(text(at(at(at(receipt, "legs"), "base"), "artifact")));
        read(&artifact.with_file_name(format!("attempt-1.{stream}")))
    }

    /// `tree_of` is the files the test executable listed in the leg's tree.
    pub fn tree_of(&self, leg: &str) -> Value {
        json::parse(&read(&self.state.join(format!("{leg}-tree.json")))).expect("a tree is JSON")
    }

    pub fn worktrees(&self) -> usize {
        self.git(&["worktree", "list", "--porcelain"])
            .matches("worktree ")
            .count()
    }

    /// The checkout holds one worktree and its first status, and the temporary directory is empty.
    pub fn assert_checkout_unchanged(&self) {
        assert_eq!(self.worktrees(), 1);
        assert_eq!(self.git(&["status", "--porcelain"]), self.status);
        let left: Vec<PathBuf> = fs::read_dir(&self.tmp)
            .expect("the temporary directory lists")
            .map(|entry| entry.expect("an entry lists").path())
            .collect();
        assert_eq!(left, Vec::<PathBuf>::new());
    }

    /// `git_wrapper` is the fixture's environment with a `git` first on `PATH` that runs `body`, a shell
    /// script in which `GIT` names the real Git.
    pub fn git_wrapper(&self, body: &str) -> Vec<(OsString, OsString)> {
        let binaries = self.root.join("bin");
        if !binaries.exists() {
            private_dir(&binaries);
        }
        let real = real_git();
        executable(
            &binaries.join("git"),
            &format!(
                "#!/bin/sh\n{}",
                body.replace("GIT", &format!("\"{}\"", real.display()))
            ),
        );
        self.path_env(&binaries)
    }
}

/// `real_git` is the `git` that `PATH` names.
pub fn real_git() -> PathBuf {
    let path = std::env::var_os("PATH").unwrap_or_else(|| OsString::from("/usr/bin:/bin"));
    std::env::split_paths(&path)
        .map(|directory| directory.join("git"))
        .find(|candidate| candidate.is_file())
        .expect("git stands on PATH")
}

/// `at` is the member `key` of the object `value`.
pub fn at<'a>(value: &'a Value, key: &str) -> &'a Value {
    match value {
        Value::Object(object) => object
            .get(key)
            .unwrap_or_else(|| panic!("no member {key} in {}", json::dump(value))),
        _ => panic!("{} is no object", json::dump(value)),
    }
}

pub fn has(value: &Value, key: &str) -> bool {
    matches!(value, Value::Object(object) if object.get(key).is_some())
}

/// `text` is the string `value` holds, as UTF-8 with each lone surrogate replaced.
pub fn text(value: &Value) -> String {
    match value {
        Value::String(text) => String::from_utf8_lossy(
            &text
                .to_os()
                .map_or_else(|| text.to_string().into_bytes(), OsString::into_vec),
        )
        .into_owned(),
        _ => panic!("{} is no string", json::dump(value)),
    }
}

pub fn texts(value: &Value) -> Vec<String> {
    match value {
        Value::Array(items) => items.iter().map(text).collect(),
        _ => panic!("{} is no array", json::dump(value)),
    }
}

/// `keys` is the member names of the object `value`, sorted.
pub fn keys(value: &Value) -> Vec<String> {
    match value {
        Value::Object(object) => {
            let mut names: Vec<String> = object.iter().map(|(key, _)| key.to_string()).collect();
            names.sort();
            names
        }
        _ => panic!("{} is no object", json::dump(value)),
    }
}

/// `sha256` is the SHA-256 of the file at `path`.
pub fn sha256(path: &Path) -> String {
    kestrike_tools::python::hexdigest(
        &fs::read(path).unwrap_or_else(|error| panic!("{}: {error}", path.display())),
    )
}

/// `assert_gone` waits up to 10 s for the process `pid` to end: its state file gone or its state `Z`.
pub fn assert_gone(pid: i32) {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(10) {
        if state_of(pid).is_none_or(|state| state == 'Z') {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("process {pid} outlived the command");
}

pub fn pid_in(path: &Path) -> i32 {
    let pid: i32 = read(path).trim().parse().expect("a process ID");
    assert!(
        pid > 1,
        "{} names a process of its own: {pid}",
        path.display()
    );
    pid
}

/// `json_of` is `value` as compact JSON, members in their order.
pub fn json_of(value: &Value) -> String {
    json::text(value)
}

/// `members` is each member of the object `value` with its string.
pub fn members(value: &Value) -> std::collections::BTreeMap<String, String> {
    match value {
        Value::Object(object) => object
            .iter()
            .map(|(key, member)| (key.to_string(), text(member)))
            .collect(),
        _ => panic!("{} is no object", json::text(value)),
    }
}

/// `split` is the words a POSIX shell reads from `command`.
pub fn split(command: &str) -> Vec<String> {
    kestrike_tools::shell::split(&kestrike_tools::text::Text::from(command))
        .expect("the command parses")
        .iter()
        .map(ToString::to_string)
        .collect()
}

/// `tree_keys` is the member names of the object `value` as texts, sorted.
pub fn tree_keys(value: &Value) -> Vec<kestrike_tools::text::Text> {
    match value {
        Value::Object(object) => {
            let mut names: Vec<_> = object.iter().map(|(key, _)| key.clone()).collect();
            names.sort();
            names
        }
        _ => panic!("{} is no object", json::text(value)),
    }
}

/// `code_of` is the exit code of `status`, or the negated signal that ended it.
fn code_of(status: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .or_else(|| status.signal().map(|signal| -signal))
        .expect("an exited run has a code or a signal")
}

/// `finish` runs `command` to its end with `input` on its standard input.
fn finish(mut command: Command, input: &[u8]) -> Done {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the run starts");
    let mut stdin = child.stdin.take().expect("the input is piped");
    stdin.write_all(input).expect("the input reaches the run");
    drop(stdin);
    let output = child.wait_with_output().expect("the run ends");
    Done {
        code: code_of(output.status),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// A run in progress: the child, a thread that reads its standard output to its end, and one that
/// hands over the first line of its standard error and then reads the rest. A run still going when
/// the value drops is killed and reaped.
pub struct Running {
    child: Option<std::process::Child>,
    stdout: Option<std::thread::JoinHandle<Vec<u8>>>,
    stderr: Option<std::thread::JoinHandle<Vec<u8>>>,
    first: std::sync::mpsc::Receiver<String>,
}

impl Running {
    fn start(mut command: Command) -> Self {
        use std::io::{BufRead, Read};
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the run starts");
        let mut out = child.stdout.take().expect("the output is piped");
        let err = child.stderr.take().expect("the errors are piped");
        let stdout = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            out.read_to_end(&mut bytes).expect("the output reads");
            bytes
        });
        let (send, first) = std::sync::mpsc::channel();
        let stderr = std::thread::spawn(move || {
            let mut reader = std::io::BufReader::new(err);
            let mut bytes = Vec::new();
            reader
                .read_until(b'\n', &mut bytes)
                .expect("the errors read");
            let _ = send.send(String::from_utf8_lossy(&bytes).into_owned());
            reader.read_to_end(&mut bytes).expect("the errors read");
            bytes
        });
        Self {
            child: Some(child),
            stdout: Some(stdout),
            stderr: Some(stderr),
            first,
        }
    }

    pub fn pid(&self) -> i32 {
        let child = self.child.as_ref().expect("the run is held");
        i32::try_from(child.id()).expect("a process ID fits i32")
    }

    /// `self` keeps the run unreaped, so its PID continues to identify the run.
    pub fn signal(&self, signal: i32) {
        assert!(kill(self.pid(), signal));
    }

    /// `first_stderr_line` is the first line of standard error, or `None` when none arrives within 30 s.
    pub fn first_stderr_line(&self) -> Option<String> {
        self.first.recv_timeout(Duration::from_secs(30)).ok()
    }

    /// `finish` waits up to 60 s for the run's exit and both streams' end; a run that outlasts the bound
    /// is killed and fails the case.
    pub fn finish(mut self) -> Done {
        let mut child = self.child.take().expect("the run is held");
        let start = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().expect("the run's state reads") {
                break status;
            }
            if start.elapsed() > Duration::from_secs(60) {
                let _ = child.kill();
                let _ = child.wait();
                panic!("the run outlived 60 s");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let stdout = self
            .stdout
            .take()
            .expect("held")
            .join()
            .expect("the reader ends");
        let stderr = self
            .stderr
            .take()
            .expect("held")
            .join()
            .expect("the reader ends");
        Done {
            code: code_of(status),
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// `state_of` is the state letter of the process `pid`, or `None` where it has no entry.
pub fn state_of(pid: i32) -> Option<char> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (_, rest) = stat.rsplit_once(')')?;
    rest.trim_start().chars().next()
}

/// `assert_alive` asserts that the process `pid` runs: it has an entry and is no zombie.
pub fn assert_alive(pid: i32) {
    let state = state_of(pid);
    assert!(
        state.is_some_and(|state| state != 'Z'),
        "process {pid} runs: {state:?}"
    );
}

/// `assert_ended` asserts at once, with no wait, that the process `pid` has ended: its entry is gone
/// or it is a zombie.
pub fn assert_ended(pid: i32) {
    let state = state_of(pid);
    assert!(
        state.is_none_or(|state| state == 'Z'),
        "process {pid} has ended: {state:?}"
    );
}

pub fn kill(pid: i32, signal: i32) -> bool {
    // SAFETY: `kill` imposes no caller-side memory safety preconditions.
    unsafe { libc::kill(pid, signal) == 0 }
}

/// `wait_for` waits up to 30 s for `path` to exist and fails the case otherwise.
pub fn wait_for(path: &Path) {
    let start = Instant::now();
    while fs::symlink_metadata(path).is_err() {
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "{} never appeared",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}
