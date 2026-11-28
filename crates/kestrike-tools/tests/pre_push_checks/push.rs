//! The fixture of the cases that start the tool: the scratch repository of the hook's self-test, a stand-in
//! `python3` first on `PATH`, and a push that starts the built binary as `pre-push-checks origin url` with
//! one ref line per pair of commits on standard input.
//!
//! The stand-in, a POSIX `sh` program, reads its arguments as `python3 [-I] SCRIPT ARGUMENT...`. A script
//! missing in the working directory exits 2, as the interpreter does. A script that holds a line
//! `sys.exit(N)` exits `N` and logs nothing. Any other script appends `NAME ARGUMENT...` to the file
//! `STUB_LOG` names, `NAME` being the script's file name, appends the same line to `STUB_LOG.isolated`
//! when the first argument is `-I`, and exits with the value of `STUB_<NAME>`, the name upper-cased
//! without `.py` and with each `-` as `_`, or 0. A script that holds the line `# hang` first starts a
//! child that writes its process id to `STUB_LOG.child` and sleeps, writes its own process id to
//! `STUB_LOG.leader`, and waits for the child; one that holds `# linger` starts the same child, writing
//! `STUB_LOG.lingering`, and exits 0 at once. A script that holds `# env` writes its environment to
//! `STUB_LOG.env`, its working directory and that directory's mode to `STUB_LOG.where`, the line
//! `output of NAME` to standard output and `error output of NAME` to standard error. A `# hang` script
//! sends its own two output streams and its child's to `/dev/null` first. A script that holds `# deaf`
//! ignores SIGINT, SIGTERM, SIGHUP and SIGQUIT and then hangs as `# hang` does; one that holds
//! `# release` hangs, then exits 0 once `STUB_LOG.release` stands or 60 seconds pass; one that holds
//! `# locked` makes the directory `locked` in its working directory, holding the empty file `kept`, with
//! mode 0500.
//!
//! A stand-in `cargo`, first on `PATH` beside it, appends `cargo ARGUMENT...` to the file `STUB_LOG`
//! names, the value of `CARGO_TARGET_DIR` to `STUB_LOG.target`, the values of `CARGO_BUILD_BUILD_DIR`
//! and `CARGO_CACHE_RUSTC_INFO` with the state of its working directory's `Cargo.lock` (`absent`,
//! `checkout` for the bytes of the lock under `STUB_TOP`, the checkout's top, or `own`) to
//! `STUB_LOG.build`, the count of its arguments and each argument on a line of its own to
//! `STUB_LOG.args`, and its physical working directory to `STUB_LOG.cwd`, and exits with the value of
//! `STUB_CARGO`, or 0.

use std::ffi::OsString;
use std::fs::{self, DirBuilder, File};
use std::io::{self, Read, Write};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub const BINARY: &str = env!("CARGO_BIN_EXE_kestrike-tools");
pub const ZERO: &str = "0000000000000000000000000000000000000000";

/// The stub every check script of the fixtures holds: the interpreter would run it as the stand-in does.
pub const STUB: &str = "import os, sys\nname = os.path.basename(sys.argv[0])\nwith open(os.environ[\"STUB_LOG\"], \"a\") as log:\n    log.write(\" \".join([name, *sys.argv[1:]]) + \"\\n\")\nsys.exit(int(os.environ.get(\"STUB_\" + name.replace(\"-\", \"_\").replace(\".py\", \"\").upper(), \"0\")))\n";

/// The longest wait for a file a stand-in writes and for a stopped process group to end.
pub const LIMIT: Duration = Duration::from_secs(10);

/// The longest run of the tool in a case.
pub const RUN_LIMIT: Duration = Duration::from_secs(120);

const PYTHON: &str = r#"#!/bin/sh
isolated=no
if [ "$1" = -I ]; then isolated=yes; shift; fi
script=$1
shift
if [ ! -f "$script" ]; then
  printf "python3: can't open file '%s': [Errno 2] No such file or directory\n" "$script" >&2
  exit 2
fi
fixed=$(sed -n 's/^sys\.exit(\([0-9][0-9]*\))$/\1/p' "$script" | head -n 1)
if [ -n "$fixed" ]; then exit "$fixed"; fi
name=${script##*/}
line=$name
for arg; do line="$line $arg"; done
printf '%s\n' "$line" >> "$STUB_LOG"
if [ "$isolated" = yes ]; then printf '%s\n' "$line" >> "$STUB_LOG.isolated"; fi
child() {
  sh -c 'printf "%s\n" "$$" > "$1.tmp" && mv "$1.tmp" "$1" && exec sleep 600' sh "$1" > /dev/null 2>&1 < /dev/null &
}
hang() {
  exec > /dev/null 2>&1
  child "$STUB_LOG.child"
  printf '%s\n' "$$" > "$STUB_LOG.leader.tmp" && mv "$STUB_LOG.leader.tmp" "$STUB_LOG.leader"
}
if grep -qx '# locked' "$script"; then mkdir locked && : > locked/kept && chmod 500 locked; fi
if grep -qx '# linger' "$script"; then child "$STUB_LOG.lingering"; exit 0; fi
if grep -qx '# deaf' "$script"; then trap '' INT TERM HUP QUIT; hang; wait; fi
if grep -qx '# hang' "$script"; then hang; wait; fi
if grep -qx '# release' "$script"; then
  hang
  n=0
  while [ ! -e "$STUB_LOG.release" ] && [ "$n" -lt 6000 ]; do sleep 0.01; n=$((n + 1)); done
  exit 0
fi
if grep -qx '# env' "$script"; then
  env > "$STUB_LOG.env"
  pwd > "$STUB_LOG.where"
  ls -ld . | cut -c1-10 >> "$STUB_LOG.where"
  printf 'output of %s\n' "$name"
  printf 'error output of %s\n' "$name" >&2
fi
var=$(printf '%s' "${name%.py}" | tr 'abcdefghijklmnopqrstuvwxyz-' 'ABCDEFGHIJKLMNOPQRSTUVWXYZ_')
eval "code=\${STUB_$var:-0}"
exit "$code"
"#;

const CARGO: &str = r#"#!/bin/sh
line=cargo
for arg; do line="$line $arg"; done
printf '%s\n' "$line" >> "$STUB_LOG"
printf '%s\n' "${CARGO_TARGET_DIR-unset}" >> "$STUB_LOG.target"
if [ ! -e Cargo.lock ]; then lock=absent
elif cmp -s Cargo.lock "$STUB_TOP/Cargo.lock"; then lock=checkout
else lock=own; fi
printf '%s %s %s\n' "${CARGO_BUILD_BUILD_DIR-unset}" "${CARGO_CACHE_RUSTC_INFO-unset}" "$lock" >> "$STUB_LOG.build"
printf '%s\n' "$#" "$@" >> "$STUB_LOG.args"
pwd -P >> "$STUB_LOG.cwd"
exit "${STUB_CARGO:-0}"
"#;

/// `fresh` makes a new directory of mode 0700 under `parent`, named `prefix` and eight random letters,
/// drawing again while a name is taken.
pub fn fresh(parent: &Path, prefix: &str) -> PathBuf {
    let mut random = File::open("/dev/urandom").expect("the random device opens");
    loop {
        let mut bytes = [0u8; 8];
        random
            .read_exact(&mut bytes)
            .expect("the random device reads");
        let name: String = bytes
            .iter()
            .map(|byte| char::from(b"abcdefghijklmnopqrstuvwxyz012345"[usize::from(byte % 32)]))
            .collect();
        let path = parent.join(format!("{prefix}{name}"));
        match DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => return path,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("{}: {error}", path.display()),
        }
    }
}

/// Opening `path` in the writer child keeps the writable descriptor out of the children of other test
/// threads. `execve` fails with `ETXTBSY` while a child holds `path` open for writing.
pub fn executable(path: &Path, text: &str) {
    let mut writer = Command::new("sh")
        .args(["-c", r#"cat > "$1" && chmod 755 "$1""#, "sh"])
        .arg(path)
        .stdin(Stdio::piped())
        .spawn()
        .expect("the program's writer starts");
    writer
        .stdin
        .take()
        .expect("the writer's standard input is a pipe")
        .write_all(text.as_bytes())
        .expect("the program's text reaches the writer");
    let status = writer.wait().expect("the program's writer is reaped");
    assert!(status.success(), "the program is written: {status}");
}

/// One run of the tool: its exit code and both streams.
#[derive(Debug)]
pub struct Run {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

/// The scratch directory, removed on drop, with the repository `repo`, the stand-in's `bin`, the tool's
/// `TMPDIR` and the log, and the environment each child starts in.
pub struct Fixture {
    pub temp: PathBuf,
    pub repo: PathBuf,
    pub log: PathBuf,
    pub tmp: PathBuf,
    pub bin: PathBuf,
    pub env: Vec<(OsString, OsString)>,
    pub base: String,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.temp)
            && !std::thread::panicking()
        {
            panic!("{}: {error}", self.temp.display());
        }
    }
}

impl Fixture {
    /// `new` builds the self-test's repository: the selection, admission and reconciliation scripts as
    /// stubs, a Verus inventory that names `crates/v.rs`, a plain Rust file and the test inventory, with
    /// `origin/main` at that commit.
    pub fn new() -> Self {
        Self::with(&[])
    }

    /// `with` is [`Fixture::new`] with `extra` added to the caller's environment before the fixture drops
    /// its `GIT_` and `GITHUB_` variables.
    pub fn with(extra: &[(&str, &str)]) -> Self {
        subreaper();
        let root = Path::new(env!("CARGO_TARGET_TMPDIR"));
        fs::create_dir_all(root).expect("the scratch root is made");
        let temp = fresh(root, "pre-push-tool-");
        let (repo, tmp, bin) = (temp.join("repo"), temp.join("tmp"), temp.join("bin"));
        for dir in [&repo, &tmp, &bin] {
            DirBuilder::new()
                .mode(0o700)
                .create(dir)
                .expect("the directory is made");
        }
        executable(&bin.join("python3"), PYTHON);
        executable(&bin.join("cargo"), CARGO);
        let log = temp.join("stub.log");
        let mut env: Vec<(OsString, OsString)> = std::env::vars_os()
            .chain(
                extra
                    .iter()
                    .map(|(key, value)| (OsString::from(key), OsString::from(value))),
            )
            .filter(|(key, _)| {
                let key = key.to_string_lossy();
                !key.starts_with("GIT_") && !key.starts_with("GITHUB_")
            })
            .collect();
        let path = std::env::var_os("PATH").unwrap_or_default();
        let mut searched = bin.clone().into_os_string();
        searched.push(":");
        searched.push(path);
        env.retain(|(key, _)| key != "PATH" && key != "TMPDIR");
        for (key, value) in [
            ("GIT_CONFIG_NOSYSTEM", OsString::from("1")),
            ("GIT_CONFIG_GLOBAL", temp.join("global").into_os_string()),
            ("GIT_CEILING_DIRECTORIES", temp.clone().into_os_string()),
            ("XDG_CONFIG_HOME", temp.join("config").into_os_string()),
            ("GIT_AUTHOR_NAME", "t".into()),
            ("GIT_AUTHOR_EMAIL", "t@example.com".into()),
            ("GIT_COMMITTER_NAME", "t".into()),
            ("GIT_COMMITTER_EMAIL", "t@example.com".into()),
            ("STUB_LOG", log.clone().into_os_string()),
            ("STUB_TOP", top().as_os_str().to_owned()),
            ("PATH", searched),
            ("TMPDIR", tmp.clone().into_os_string()),
        ] {
            env.push((OsString::from(key), value));
        }
        let mut fixture = Self {
            temp,
            repo,
            log,
            tmp,
            bin,
            env,
            base: String::new(),
        };
        fixture.git(&["init", "-q", "-b", "main"]);
        fixture.base = fixture.commit(&[
            ("scripts/test-select-tests.py", STUB),
            ("scripts/verify-receipts.py", STUB),
            ("scripts/judge-verus.py", STUB),
            (
                "verification/verus/inventory.json",
                r#"{"sources": {"crates/v.rs": "d"}}"#,
            ),
            ("crates/v.rs", "v\n"),
            ("crates/plain.rs", "p\n"),
            ("scripts/test-inventory.json", "{}"),
        ]);
        let base = fixture.base.clone();
        fixture.git(&["update-ref", "refs/remotes/origin/main", &base]);
        fixture
    }

    /// `command` prepares `program` in the repository with the fixture's environment alone.
    pub fn command(&self, program: impl AsRef<std::ffi::OsStr>) -> Command {
        let mut command = Command::new(program);
        command
            .env_clear()
            .envs(self.env.iter().cloned())
            .current_dir(&self.repo);
        command
    }

    /// `git` runs `git args`, fails the case unless it passes, and returns its trimmed standard output.
    pub fn git(&self, args: &[&str]) -> String {
        let output = self.command("git").args(args).output().expect("git starts");
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .expect("git writes UTF-8")
            .trim()
            .to_owned()
    }

    /// `commit` writes and stages each file, commits, and returns the commit.
    pub fn commit(&self, files: &[(&str, &str)]) -> String {
        self.commit_with(files, "change")
    }

    /// `commit_with` is [`Fixture::commit`] with `message` as the commit message.
    pub fn commit_with(&self, files: &[(&str, &str)], message: &str) -> String {
        for (name, content) in files {
            let path = self.repo.join(name);
            fs::create_dir_all(path.parent().expect("a file has a parent"))
                .expect("the parent is made");
            fs::write(path, content).expect("the file is written");
            self.git(&["add", "--", name]);
        }
        self.git(&["commit", "-q", "-m", message]);
        self.git(&["rev-parse", "HEAD"])
    }

    /// `link` commits a symlink at `name` pointing to `target`, replacing any tracked entry there, and
    /// returns the commit ID.
    pub fn link(&self, name: &str, target: &str) -> String {
        let path = self.repo.join(name);
        if path.symlink_metadata().is_ok() {
            self.git(&["rm", "-rq", "--", name]);
        }
        fs::create_dir_all(path.parent().expect("a link has a parent"))
            .expect("the parent is made");
        std::os::unix::fs::symlink(target, &path).expect("the link is made");
        self.git(&["add", "--", name]);
        self.git(&["commit", "-q", "-m", "link"]);
        self.git(&["rev-parse", "HEAD"])
    }

    /// `set` gives the environment `name` with `value`.
    pub fn set(&mut self, name: &str, value: impl Into<OsString>) {
        self.env.retain(|(key, _)| key != name);
        self.env.push((OsString::from(name), value.into()));
    }

    /// `unset` removes `name` from the environment.
    pub fn unset(&mut self, name: &str) {
        self.env.retain(|(key, _)| key != name);
    }

    /// `clear` removes the log, its `-I` record, the stand-ins' process id files, the target directories the
    /// stand-in `cargo` logged and the `git` wrapper's log.
    pub fn clear(&self) {
        for suffix in [
            "",
            ".isolated",
            ".child",
            ".leader",
            ".lingering",
            ".git",
            ".env",
            ".where",
            ".release",
            ".target",
            ".build",
            ".args",
            ".cwd",
        ] {
            let _ = fs::remove_file(self.logged(suffix));
        }
    }

    /// `logged` is the log's path with `suffix` appended.
    pub fn logged(&self, suffix: &str) -> PathBuf {
        let mut path = self.log.clone().into_os_string();
        path.push(suffix);
        PathBuf::from(path)
    }

    /// `ran` lists the log's lines, none when it was never written.
    pub fn ran(&self) -> Vec<String> {
        self.lines("")
    }

    /// `targets` lists the target directories the stand-in `cargo` was given, one for each of its runs.
    pub fn targets(&self) -> Vec<String> {
        self.lines(".target")
    }

    /// `builds` lists the build directory, the rustc cache setting and the lock's state the stand-in
    /// `cargo` logged, one line for each of its runs.
    pub fn builds(&self) -> Vec<String> {
        self.lines(".build")
    }

    /// `cargo_args` lists the stand-in `cargo`'s argument counts and arguments, a line each.
    pub fn cargo_args(&self) -> Vec<String> {
        self.lines(".args")
    }

    /// `cargo_dirs` lists the physical working directories of the stand-in `cargo`'s runs.
    pub fn cargo_dirs(&self) -> Vec<String> {
        self.lines(".cwd")
    }

    /// `isolated` lists the lines of the runs whose first argument was `-I`.
    pub fn isolated(&self) -> Vec<String> {
        self.lines(".isolated")
    }

    fn lines(&self, suffix: &str) -> Vec<String> {
        match fs::read_to_string(self.logged(suffix)) {
            Ok(text) => text.lines().map(str::to_owned).collect(),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(error) => panic!("the log reads: {error}"),
        }
    }

    /// `input` is one ref line `refs/heads/x LOCAL refs/heads/x REMOTE` for each pair of `pairs`.
    pub fn input(pairs: &[(&str, &str)]) -> String {
        pairs
            .iter()
            .map(|(local, remote)| format!("refs/heads/x {local} refs/heads/x {remote}\n"))
            .collect()
    }

    /// `start` starts the tool in the repository as `pre-push-checks origin url` with `input` on standard
    /// input and both output streams piped.
    pub fn start(&self, input: &str) -> Tool {
        self.start_in(&self.repo, input, &[])
    }

    /// `tool` prepares the built binary as `pre-push-checks origin url` in the repository, with the
    /// fixture's environment alone.
    pub fn tool(&self) -> Command {
        let mut command = self.command(BINARY);
        command
            .arg(top())
            .args(["pre-push-checks", "origin", "url"]);
        command
    }

    /// `start_in` is [`Fixture::start`] in `dir`, with each `STUB_<NAME>` of `codes` set for this run.
    pub fn start_in(&self, dir: &Path, input: &str, codes: &[(&str, i32)]) -> Tool {
        let mut command = self.tool();
        for (name, code) in codes {
            command.env(
                format!("STUB_{}", name.replace('-', "_").to_uppercase()),
                code.to_string(),
            );
        }
        command.current_dir(dir);
        spawn_with_input(&mut command, input)
    }

    /// `push` runs the tool on the ref lines of `pairs` and returns the run.
    pub fn push(&self, pairs: &[(&str, &str)]) -> Run {
        self.push_with(pairs, &[])
    }

    /// `push_with` is [`Fixture::push`] with each `STUB_<NAME>` of `codes` set for this run.
    pub fn push_with(&self, pairs: &[(&str, &str)], codes: &[(&str, i32)]) -> Run {
        finished(self.start_in(&self.repo, &Self::input(pairs), codes))
    }

    /// `worktrees` counts the worktrees `git worktree list` names, the repository's own included.
    pub fn worktrees(&self) -> usize {
        self.git(&["worktree", "list", "--porcelain"])
            .matches("worktree ")
            .count()
    }

    /// `left` lists the entries the tool left under its `TMPDIR`.
    pub fn left(&self) -> Vec<PathBuf> {
        fs::read_dir(&self.tmp)
            .expect("the tool's TMPDIR lists")
            .map(|entry| entry.expect("the tool's TMPDIR lists").path())
            .collect()
    }

    /// `wrap_git_around` puts a `git` first on `PATH` that runs the shell text `before` with Git's
    /// arguments as `$@`, then Git's own program with the arguments.
    pub fn wrap_git_around(&self, before: &str) {
        let git = which("git");
        executable(
            &self.bin.join("git"),
            &format!("#!/bin/sh\n{before}\nexec \"{}\" \"$@\"\n", git.display()),
        );
    }

    /// `wrap_git` puts a `git` first on `PATH` that runs `git worktree add` with `--lock` and then sends
    /// SIGTERM to its parent, and runs every other Git command as Git's own program.
    pub fn wrap_git(&self) {
        let git = which("git");
        executable(
            &self.bin.join("git"),
            &format!(
                "#!/bin/sh\nadd=no\n\
                 if [ \"$1\" = worktree ] && [ \"$2\" = add ]; then add=yes; shift 2; set -- worktree add --lock \"$@\"; fi\n\
                 \"{}\" \"$@\"\nstatus=$?\nif [ \"$add\" = yes ]; then kill -TERM \"$PPID\"; fi\nexit \"$status\"\n",
                git.display()
            ),
        );
    }
}

/// `top` is the checkout the executable was built from, two levels above the package.
pub fn top() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the package stands two levels below the checkout's top")
}

/// A started tool that a case has not yet passed to [`finished`]. Dropping it, as a failing case does when
/// it unwinds, sends the tool SIGKILL, which also ends a stopped tool, and reaps it, so no tool outlives
/// its case.
pub struct Tool(Option<Child>);

impl Tool {
    /// `id` is the tool's process id.
    pub fn id(&self) -> u32 {
        self.0.as_ref().expect("the tool is held").id()
    }
}

impl From<Child> for Tool {
    fn from(child: Child) -> Self {
        Self(Some(child))
    }
}

impl Drop for Tool {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// `spawn_with_input` starts `command` with both output streams piped, writes the bytes of `input` to its
/// standard input and closes it.
pub fn spawn_with_input(command: &mut Command, input: impl AsRef<[u8]>) -> Tool {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the tool starts");
    let mut stdin = child.stdin.take().expect("standard input is piped");
    let tool = Tool(Some(child));
    stdin
        .write_all(input.as_ref())
        .expect("the ref lines are written");
    tool
}

/// `finished` closes the child's standard input, reads both output streams and waits for the child against
/// [`RUN_LIMIT`]; a child still running then gets SIGKILL while it is held unreaped, and the case fails.
pub fn finished(mut tool: Tool) -> Run {
    let mut child = tool.0.take().expect("the tool is held");
    drop(child.stdin.take());
    let reader = |stream: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            if let Some(mut stream) = stream {
                stream.read_to_end(&mut bytes).expect("the stream reads");
            }
            String::from_utf8(bytes).expect("the stream is UTF-8")
        })
    };
    let stdout = reader(
        child
            .stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    );
    let stderr = reader(
        child
            .stderr
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    );
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("the tool is polled") {
            break Some(status);
        }
        if start.elapsed() >= RUN_LIMIT {
            child.kill().expect("the tool is killed");
            child.wait().expect("the tool is reaped");
            break None;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let streams = Instant::now();
    while !(stdout.is_finished() && stderr.is_finished()) {
        assert!(
            status.is_some() || streams.elapsed() < Duration::from_secs(1),
            "the tool ran past {RUN_LIMIT:?} and a process it started holds its output streams"
        );
        assert!(
            status.is_none() || start.elapsed() < RUN_LIMIT,
            "a process the tool started holds its output streams past {RUN_LIMIT:?}"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    let stdout = stdout.join().expect("standard output is read");
    let stderr = stderr.join().expect("standard error is read");
    let status = status.unwrap_or_else(|| panic!("the tool ran past {RUN_LIMIT:?}: {stderr}"));
    Run {
        code: status.code(),
        stdout,
        stderr,
    }
}

/// `which` finds `program` on this process's `PATH`.
pub fn which(program: &str) -> PathBuf {
    let path = std::env::var_os("PATH").expect("PATH is set");
    std::env::split_paths(&path)
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.is_file())
        .unwrap_or_else(|| panic!("{program} stands on PATH"))
}

/// `waited` polls `ready` until it holds or [`LIMIT`] passes, and returns whether it held.
pub fn waited(mut ready: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    let mut pause = Duration::from_millis(1);
    while !ready() {
        if start.elapsed() >= LIMIT {
            return false;
        }
        std::thread::sleep(pause);
        pause = (pause * 2).min(Duration::from_millis(50));
    }
    true
}

/// `process_id` waits for the file at `path`, which a stand-in publishes by a rename, and reads the process
/// id it holds.
pub fn process_id(path: &Path) -> libc::pid_t {
    assert!(waited(|| path.exists()), "{} is written", path.display());
    let pid: libc::pid_t = fs::read_to_string(path)
        .expect("the process id file reads")
        .trim()
        .parse()
        .expect("the file holds a process id");
    assert!(pid > 0, "{} holds a positive process id", path.display());
    pid
}

/// `subreaper` marks the test process a subreaper. When the test process is the nearest living subreaper
/// ancestor, it adopts a check's child that outlives its leader, and [`group_alive`] can reap it.
fn subreaper() {
    static SET: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    SET.get_or_init(|| {
        #[cfg(target_os = "linux")]
        {
            let (on, unused): (libc::c_ulong, libc::c_ulong) = (1, 0);
            // SAFETY: `prctl` with `PR_SET_CHILD_SUBREAPER` reads its four variadic operands as
            // `unsigned long` values, which these are, and touches no memory of the caller.
            let status =
                unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, on, unused, unused, unused) };
            assert_eq!(status, 0, "{}", io::Error::last_os_error());
        }
    });
}

/// `alive` holds while `pid` names a process, a zombie included.
pub fn alive(pid: libc::pid_t) -> bool {
    // SAFETY: `kill` with signal 0 sends nothing and touches no memory of the caller.
    unsafe { libc::kill(pid, 0) == 0 }
}

/// `group_ended` waits up to [`LIMIT`] for the group `group` to end and returns whether it did; a group
/// still alive then gets SIGKILL while [`group_alive`] has just read it alive, so a failing case leaves no
/// check running.
pub fn group_ended(group: libc::pid_t) -> bool {
    let ended = waited(|| !group_alive(group));
    if !ended && group_alive(group) {
        // SAFETY: `killpg` takes two integers and touches no memory of the caller.
        unsafe { libc::killpg(group, libc::SIGKILL) };
    }
    ended
}

/// `group_alive` holds while a process of the group `group` remains. It first reaps each member that ended
/// and is this process's child: on Linux [`Fixture::with`] makes the test process a subreaper, so a check's
/// orphaned child waits for this process's reap once it ends.
pub fn group_alive(group: libc::pid_t) -> bool {
    // SAFETY: `waitpid` with a null status pointer and `WNOHANG` reaps an ended child of the group, if any,
    // and touches no memory of the caller; `killpg` with signal 0 sends nothing.
    unsafe {
        while libc::waitpid(-group, std::ptr::null_mut(), libc::WNOHANG) > 0 {}
        libc::killpg(group, 0) == 0
    }
}

/// `signal` sends `signal` to `pid`.
pub fn signal(pid: u32, signal: i32) {
    let pid = libc::pid_t::try_from(pid).expect("a process id fits pid_t");
    // SAFETY: `kill` takes two integers and touches no memory of the caller.
    assert_eq!(unsafe { libc::kill(pid, signal) }, 0, "the signal is sent");
}
