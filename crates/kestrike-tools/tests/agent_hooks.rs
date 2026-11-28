//! Cases for the checkout's comment-marker scan, its commit hook, its ignore rules and its pre-push hook.
//! A pre-push case runs a copy of `.githooks/pre-push` beside a stand-in `scripts/tool.sh` that writes its
//! arguments to `tool.args` and its standard input to `tool.input` in the repository, or beside the
//! stand-in the case names. A stand-in of the global hook stands in the directory `shared hooks` of the
//! repository. Each stand-in finds the programs it starts on the `PATH` of the test run, or takes a
//! program's whole path from a variable the case sets. The scratch cases' stand-ins start the built tool.

use std::fmt;
use std::fs::{self, DirBuilder, File};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime};

use crate::pre_push_checks::push::{
    BINARY, RUN_LIMIT, Run, executable, finished, spawn_with_input,
};

/// The override marker the cases plant. Splitting its literal keeps the scan from matching this
/// definition in the case file.
const MARKER: &str = concat!("commentlin", "t: allow(JUDGE)");

/// The checkout the executable was built from, two levels above the package.
fn top() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the package stands two levels below the checkout's top")
}

/// A Git repository in a fresh owner-only directory under `CARGO_TARGET_TMPDIR`, removed when the
/// value drops.
struct Repo {
    path: PathBuf,
}

impl Repo {
    /// `Repo::new` retries name collisions to preserve directories left by interrupted runs.
    fn new(case: &str) -> Self {
        let scratch = Path::new(env!("CARGO_TARGET_TMPDIR"));
        fs::create_dir_all(scratch).expect("the scratch directory is made");
        let mut at = 0_usize;
        let path = loop {
            let path = scratch.join(format!("agent-hooks-{case}-{}-{at}", std::process::id()));
            match DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => break path,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => at += 1,
                Err(error) => panic!("{}: {error}", path.display()),
            }
        };
        let repo = Self { path };
        repo.git(&["init", "-q"]);
        repo
    }

    fn command(&self, program: &str) -> Command {
        let mut command = Command::new(program);
        for (name, _) in std::env::vars_os() {
            if name.as_bytes().starts_with(b"GIT_") {
                command.env_remove(name);
            }
        }
        let above = self.path.parent().expect("the repository has a parent");
        // Upward discovery stops at the repository's parent, so a child that starts in or below the
        // repository finds this repository. Setting `XDG_CONFIG_HOME` to the repository redirects
        // Git's default user-wide ignore and attributes lookups there.
        command
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", self.path.join("global-config"))
            .env("GIT_CEILING_DIRECTORIES", above)
            .env("XDG_CONFIG_HOME", &self.path)
            .current_dir(&self.path)
            .stdin(Stdio::null());
        command
    }

    fn git(&self, args: &[&str]) {
        let done = run(self.command("git").args(args));
        assert_eq!(done.code, Some(0), "git {args:?}: {done}");
    }

    fn stage(&self, name: &str, content: &str) {
        fs::write(self.path.join(name), content).expect("the file is written");
        self.git(&["add", "--", name]);
    }

    fn scan(&self) -> Command {
        let mut command = self.command("bash");
        command.arg(top().join("scripts/forbid-comment-markers.sh"));
        command
    }
}

impl Drop for Repo {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.path)
            && !std::thread::panicking()
        {
            panic!("{}: {error}", self.path.display());
        }
    }
}

impl fmt::Display for Run {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "exit {:?}\nstandard output:\n{}standard error:\n{}",
            self.code, self.stdout, self.stderr
        )
    }
}

/// Invalid UTF-8 in the child's standard output or standard error fails the case.
fn run(command: &mut Command) -> Run {
    ran(command.output().expect("the child starts"))
}

fn ran(done: Output) -> Run {
    Run {
        code: done.status.code(),
        stdout: String::from_utf8(done.stdout).expect("standard output is UTF-8"),
        stderr: String::from_utf8(done.stderr).expect("standard error is UTF-8"),
    }
}

#[test]
fn clean_staged_file_passes() {
    let repo = Repo::new("clean");
    repo.stage("a.rs", "let value = 1;\n");
    let done = run(repo.scan().arg("--staged"));
    assert_eq!(done.code, Some(0), "{done}");
}

#[test]
fn marker_reports_file_and_line() {
    let repo = Repo::new("report");
    repo.stage("clean.rs", "let a = 1;\nlet b = 2;\n");
    // The staged scan must flag the uppercase form of `MARKER`.
    let content = format!("let value = 1;\n// {}\n", MARKER.to_uppercase());
    repo.stage("file with spaces.rs", &content);
    let done = run(repo.scan().arg("--staged"));
    assert_eq!(done.code, Some(1), "{done}");
    assert!(done.stderr.contains("file with spaces.rs:2:"), "{done}");
    assert!(!done.stderr.contains("clean.rs:"), "{done}");
}

#[test]
fn leading_plus_does_not_hide_marker() {
    let repo = Repo::new("plus");
    repo.stage("a.rs", &format!("let value = 1;\n+value; // {MARKER}\n"));
    let done = run(repo.scan().arg("--staged"));
    assert_eq!(done.code, Some(1), "{done}");
}

#[test]
fn unstaged_cleanup_does_not_hide_staged_marker() {
    let repo = Repo::new("unstaged");
    repo.stage("a.rs", &format!("// {MARKER}\n"));
    fs::write(repo.path.join("a.rs"), "// A plain comment.\n").expect("the file is written");
    let done = run(repo.scan().arg("--staged"));
    assert_eq!(done.code, Some(1), "{done}");
    let done = run(&mut repo.scan());
    assert_eq!(done.code, Some(0), "{done}");
}

#[test]
fn full_scan_rejects_marker() {
    let repo = Repo::new("full");
    repo.stage("a.rs", &format!("// {MARKER}\n"));
    let done = run(&mut repo.scan());
    assert_eq!(done.code, Some(1), "{done}");
}

#[test]
fn binary_attributes_do_not_hide_markers() {
    let repo = Repo::new("binary");
    let mut unblocked = Vec::new();
    for attribute in ["binary", "-diff"] {
        repo.stage(".gitattributes", &format!("*.rs {attribute}\n"));
        repo.stage("a.rs", &format!("// {MARKER}\n"));
        for args in [&[][..], &["--staged"][..]] {
            let done = run(repo.scan().args(args));
            if done.code != Some(1) {
                unblocked.push(format!("{attribute} {args:?}: {done}"));
            }
        }
    }
    assert!(
        unblocked.is_empty(),
        "rows that exit other than 1:\n{}",
        unblocked.join("\n")
    );
}

#[test]
fn retired_local_artifacts_remain_ignored() {
    let repo = Repo::new("ignored");
    fs::copy(top().join(".gitignore"), repo.path.join(".gitignore")).expect("the rules are copied");
    let mut unignored = Vec::new();
    for name in [".bv/cache.json", ".perles/config.yaml"] {
        let done = run(repo
            .command("git")
            .args(["check-ignore", "--quiet", "--", name]));
        if done.code != Some(0) {
            unignored.push(format!("{name}: {done}"));
        }
    }
    assert!(
        unignored.is_empty(),
        "paths that check-ignore does not report:\n{}",
        unignored.join("\n")
    );
}

#[test]
fn full_scan_includes_parent_directories() {
    let repo = Repo::new("nested");
    repo.stage("a.rs", &format!("// {MARKER}\n"));
    let nested = repo.path.join("nested");
    fs::create_dir(&nested).expect("the directory is made");
    let done = run(repo.scan().current_dir(&nested));
    assert_eq!(done.code, Some(1), "{done}");
}

#[test]
fn staged_scan_ignores_textconv() {
    let repo = Repo::new("textconv");
    repo.stage(".gitattributes", "*.rs diff=hidden\n");
    repo.stage("a.rs", &format!("// {MARKER}\n"));
    repo.git(&["config", "diff.hidden.textconv", "true"]);
    let done = run(repo.scan().arg("--staged"));
    assert_eq!(done.code, Some(1), "{done}");
}

#[test]
fn staged_scan_ignores_external_diff() {
    let repo = Repo::new("external");
    repo.stage("a.rs", &format!("// {MARKER}\n"));
    let done = run(repo.scan().arg("--staged").env("GIT_EXTERNAL_DIFF", "true"));
    assert_eq!(done.code, Some(1), "{done}");
}

#[test]
fn git_failure_does_not_pass() {
    let repo = Repo::new("missing");
    let missing = repo.path.join("missing");
    let done = run(repo.scan().arg("--staged").env("GIT_DIR", &missing));
    assert_ne!(done.code, Some(0), "{done}");
    let done = run(repo.scan().env("GIT_DIR", &missing));
    assert_eq!(done.code, Some(2), "{done}");
}

#[test]
fn pre_commit_runs_repository_check() {
    let repo = Repo::new("pre-commit");
    let scripts = repo.path.join("scripts");
    fs::create_dir(&scripts).expect("the directory is made");
    let script = top().join("scripts/forbid-comment-markers.sh");
    symlink(script, scripts.join("forbid-comment-markers.sh")).expect("the link is made");
    repo.stage("a.rs", &format!("// {MARKER}\n"));
    let done = run(repo.command("bash").arg(top().join(".githooks/pre-commit")));
    assert_eq!(done.code, Some(1), "{done}");
}

const DELETION: &str = "(delete) 0000000000000000000000000000000000000000 refs/heads/gone 1111111111111111111111111111111111111111\n";

const TOOL: &str = "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$(dirname -- \"$0\")/../tool.args\"\ncat > \"$(dirname -- \"$0\")/../tool.input\"\nexit \"${TOOL_EXIT:-0}\"\n";

impl Repo {
    fn pre_push(&self) -> PathBuf {
        self.install(&hook_text(), TOOL)
    }

    fn push(&self, args: &[&str], input: &str) -> Run {
        self.push_with(args, input, "0")
    }

    fn push_with(&self, args: &[&str], input: &str, tool_exit: &str) -> Run {
        let hook = self.pre_push();
        let mut command = self.command("bash");
        command.arg(&hook).args(args).env("TOOL_EXIT", tool_exit);
        finished(spawn_with_input(&mut command, input))
    }

    fn launched(&self) -> (String, String) {
        let read = |name: &str| {
            fs::read_to_string(self.path.join(name))
                .unwrap_or_else(|error| panic!("{name}: {error}"))
        };
        (read("tool.args"), read("tool.input"))
    }
}

#[test]
fn pre_push_preserves_global_guard_arguments_input_and_failure() {
    let repo = Repo::new("pre-push-guard");
    let hooks = repo.path.join("shared hooks");
    fs::create_dir(&hooks).expect("the directory is made");
    let guard = hooks.join("pre-push");
    executable(&guard, "#!/bin/sh\nprintf \"%s\\n\" \"$@\"\ncat\nexit 37\n");
    let config = repo.path.join("global-config");
    let hooks_path = hooks.to_str().expect("the path is UTF-8");
    for mode in ["direct", "include", "includeIf"] {
        fs::write(&config, "").expect("the configuration is emptied");
        if mode == "direct" {
            repo.git(&["config", "--global", "core.hooksPath", hooks_path]);
        } else {
            let included = repo.path.join("included-config");
            let included = included.to_str().expect("the path is UTF-8");
            repo.git(&["config", "--file", included, "core.hooksPath", hooks_path]);
            let key = if mode == "include" {
                "include.path".to_owned()
            } else {
                format!("includeIf.gitdir:{}/.path", repo.path.display())
            };
            repo.git(&["config", "--global", &key, included]);
        }
        let done = repo.push(&["origin", "remote-url"], DELETION);
        assert_eq!(done.code, Some(37), "{mode}: {done}");
        assert_eq!(
            done.stdout,
            format!("origin\nremote-url\n{DELETION}"),
            "{mode}: {done}"
        );
        assert_eq!(
            repo.launched(),
            ("pre-push-checks\norigin\n".to_owned(), DELETION.to_owned()),
            "{mode}"
        );
    }
}

#[test]
fn pre_push_without_global_hook_path_passes() {
    let repo = Repo::new("pre-push-none");
    let done = repo.push(&[], "");
    assert_eq!(done.code, Some(0), "{done}");
    assert_eq!(
        repo.launched(),
        ("pre-push-checks\n\n".to_owned(), String::new())
    );
}

#[test]
fn pre_push_honors_explicitly_disabled_global_hooks() {
    let repo = Repo::new("pre-push-disabled");
    for value in ["/dev/null", ""] {
        repo.git(&["config", "--global", "core.hooksPath", value]);
        let done = repo.push(&[], "");
        assert_eq!(done.code, Some(0), "{value:?}: {done}");
    }
}

#[test]
fn pre_push_missing_configured_guard_fails() {
    let repo = Repo::new("pre-push-missing");
    let missing = repo.path.join("missing");
    repo.git(&[
        "config",
        "--global",
        "core.hooksPath",
        missing.to_str().expect("the path is UTF-8"),
    ]);
    let done = repo.push(&[], "");
    assert_ne!(done.code, Some(0), "{done}");
}

#[test]
fn pre_push_self_delegation_fails() {
    let repo = Repo::new("pre-push-self");
    let hooks = repo.path.join(".githooks");
    repo.git(&[
        "config",
        "--global",
        "core.hooksPath",
        hooks.to_str().expect("the path is UTF-8"),
    ]);
    let done = repo.push(&[], "");
    assert_eq!(done.code, Some(2), "{done}");
    assert_eq!(
        done.stderr,
        "pre-push: global hook path points back to this hook\n"
    );
}

#[test]
fn pre_push_ends_with_the_tool_s_failing_code_before_the_global_guard() {
    let repo = Repo::new("pre-push-tool-fails");
    let hooks = repo.path.join("shared hooks");
    fs::create_dir(&hooks).expect("the directory is made");
    let guard = hooks.join("pre-push");
    executable(
        &guard,
        "#!/bin/sh\ntouch \"$(dirname -- \"$0\")/guard.ran\"\n",
    );
    repo.git(&[
        "config",
        "--global",
        "core.hooksPath",
        hooks.to_str().expect("the path is UTF-8"),
    ]);
    for code in [1, 2, 120, 127, 143] {
        let done = repo.push_with(&["origin", "remote-url"], DELETION, &code.to_string());
        assert_eq!(done.code, Some(code), "{done}");
        assert!(!hooks.join("guard.ran").exists(), "{code}: the guard ran");
    }
    let done = repo.push(&["origin", "remote-url"], DELETION);
    assert_eq!(done.code, Some(0), "{done}");
    assert!(
        hooks.join("guard.ran").exists(),
        "the guard runs after a passing tool"
    );
}

/// A hook that keeps its input in a file it makes under `TMPDIR`, or under `/tmp`, and gives each reader
/// that file. It is the arm of a case in which an entry is made.
const SPOOLING: &str = r#"#!/usr/bin/env bash
set -euo pipefail
refs=$(mktemp "${TMPDIR:-/tmp}/kestrike-pre-push.XXXXXX")
trap 'rm -f "$refs"' EXIT
cat > "$refs"
bash "$(dirname -- "${BASH_SOURCE[0]}")/../scripts/tool.sh" pre-push-checks "${1-}" < "$refs"
status=0
hook_dir=$(git config --global --includes --path --get core.hooksPath) || status=$?
if [ "$status" -eq 1 ]; then
  exit 0
fi
if [ "$status" -ne 0 ]; then
  exit "$status"
fi
case "$hook_dir" in
  ""|/dev/null) exit 0 ;;
esac
if [ "$hook_dir/pre-push" -ef "$0" ]; then
  echo "pre-push: global hook path points back to this hook" >&2
  exit 2
fi
status=0
"$hook_dir/pre-push" "$@" < "$refs" || status=$?
exit "$status"
"#;

/// The launcher's stand-in that lists the directory `TMPDIR` names and its working directory as it starts,
/// before it writes a file. It then writes the two listings to `tool.scratch` and `tool.work` and its
/// standard input to `tool.input` in the repository.
const WATCHER: &str = r#"#!/bin/sh
scratch=$(ls -A "$TMPDIR") || exit 99
work=$(ls -A .) || exit 99
top=$(dirname -- "$0")/..
printf '%s\n' "$scratch" > "$top/tool.scratch" || exit 99
printf '%s\n' "$work" > "$top/tool.work" || exit 99
cat > "$top/tool.input"
"#;

/// The launcher's stand-in that reads no byte of its standard input: it makes `tool.ran` in the
/// repository and exits with the value of `TOOL_EXIT`, or 0.
const DEAF_TOOL: &str =
    "#!/bin/sh\n: > \"$(dirname -- \"$0\")/../tool.ran\"\nexit \"${TOOL_EXIT:-0}\"\n";

/// The launcher's stand-in that starts the program `TOOLS_BINARY` names with `TOOLS_TOP` and its own
/// arguments, on its own standard input.
const LAUNCHER: &str = "#!/bin/sh\nexec \"$TOOLS_BINARY\" \"$TOOLS_TOP\" \"$@\"\n";

/// The launcher's stand-in that writes its standard input to `tool.input` in the repository and then
/// makes the file `FAULT_AFTER` names, where the variable is set.
const DRAINER: &str = r#"#!/bin/sh
cat > "$(dirname -- "$0")/../tool.input" || exit 99
if [ -n "${FAULT_AFTER-}" ]; then : > "$FAULT_AFTER"; fi
"#;

/// The shell text by which a stand-in writes a record of its start to the file `$record`: the values of
/// its environment's `refs`, `LC_ALL` and `TMOUT`, each `absent` where the environment lacks it, and
/// `default` or `ignored` for its disposition of SIGPIPE. It reads the disposition from the exit status
/// of `yes` writing into a pipe whose reader has exited: 141 where the signal ends it. The text holds
/// under the shell options `errexit` and `pipefail`, which a reader inherits from the hook where the
/// hook's environment holds `SHELLOPTS`.
const RECORD: &str = r#"pipe=$( { { yes 2>/dev/null || echo "$?" >&3; } | :; } 3>&1 )
if [ "$pipe" = 141 ]; then pipe=default; else pipe=ignored; fi
printf '%s|%s|%s|%s' "${refs-absent}" "${LC_ALL-absent}" "${TMOUT-absent}" "$pipe" > "$record"
"#;

/// The global hook's stand-in that writes its standard input to `guard.input` beside itself and exits
/// with the value of `GUARD_EXIT`, or 37.
const KEEPER: &str =
    "#!/bin/sh\ncat > \"$(dirname -- \"$0\")/guard.input\"\nexit \"${GUARD_EXIT:-37}\"\n";

/// A startup file that bash reads through `BASH_ENV`. Its trap runs before each command of the hook, in
/// its subshells and command substitutions too. Before the write of the ref lines, where `FAULT` is set
/// and the file `FAULT_AFTER` names stands or the variable is unset, the trap ends the writing process
/// itself with SIGKILL for `kill`, or turns the builtin `printf` off in it for `disable`.
const FAULTS: &str = r#"set -T
trap 'if [[ $BASH_COMMAND == "builtin printf"* && -n ${FAULT-} && ( -z ${FAULT_AFTER-} || -e $FAULT_AFTER ) ]]; then
  case $FAULT in kill) kill -KILL "$BASHPID" ;; disable) enable -n printf ;; esac
fi' DEBUG
"#;

/// An instant in 2001 that a case gives a directory as its modification time: making or removing an
/// entry in the directory moves the time off it.
fn past() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000)
}

/// `hook_text` is the text of the checkout's `.githooks/pre-push`.
fn hook_text() -> String {
    fs::read_to_string(top().join(".githooks/pre-push")).expect("the hook reads")
}

/// `names` lists the entries of `dir`, sorted.
fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("{}: {error}", dir.display()))
        .map(|entry| {
            let name = entry.expect("the directory lists").file_name();
            name.into_string().expect("each entry is named in UTF-8")
        })
        .collect();
    names.sort_unstable();
    names
}

/// `ref_lines` is `count` ref lines of 118 bytes each: two branch names and two object ids.
fn ref_lines(count: usize) -> String {
    (0..count)
        .map(|at| {
            format!(
                "refs/heads/b{at:05} {} refs/heads/b{at:05} {}\n",
                "a".repeat(40),
                "b".repeat(40)
            )
        })
        .collect()
}

/// `past_a_pipe` is ref lines of more bytes than sixteen pages of this host, the capacity a pipe has on
/// Linux unless a process changes it, so a writer of them blocks until its reader reads or exits.
fn past_a_pipe() -> String {
    let answer = Command::new("getconf")
        .arg("PAGESIZE")
        .output()
        .expect("getconf starts");
    let page: usize = String::from_utf8(answer.stdout)
        .expect("getconf writes UTF-8")
        .trim()
        .parse()
        .expect("getconf prints the page size");
    let input = ref_lines(16 * page / 118 + 2);
    assert!(input.len() > 16 * page, "{} bytes", input.len());
    input
}

/// What a case writes to a hook's standard input.
enum Feed<'a> {
    /// The bytes, then the end of the input.
    Whole(&'a [u8]),
    /// The first bytes, a pause, the second bytes, then the end of the input.
    Paused(&'a [u8], Duration, &'a [u8]),
    /// The bytes, with the input held open until the hook has exited.
    Held(&'a [u8]),
}

/// `collect` starts `command` with its three streams piped, feeds its standard input from a thread of
/// its own and reads both output streams on two more, so a hook that reads nothing, or writes more than
/// a pipe holds, leaves the wait for its exit running. It returns the run and the result of the feed's
/// writes. A hook still running at `limit` gets SIGKILL and is reaped, and the call returns an error;
/// so does a call whose three threads still run five seconds after the hook's exit, as they do while a
/// process the hook started holds one of its streams.
fn collect(
    command: &mut Command,
    feed: Feed<'_>,
    limit: Duration,
) -> Result<(Run, io::Result<()>), String> {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the hook starts");
    let mut input = child.stdin.take().expect("standard input is piped");
    let (first, pause, second, held) = match feed {
        Feed::Whole(bytes) => (bytes.to_vec(), None, Vec::new(), false),
        Feed::Paused(first, pause, second) => (first.to_vec(), Some(pause), second.to_vec(), false),
        Feed::Held(bytes) => (bytes.to_vec(), None, Vec::new(), true),
    };
    let (exited, exit) = mpsc::channel::<()>();
    let feeder = std::thread::spawn(move || {
        let fed = input.write_all(&first).and_then(|()| {
            if let Some(pause) = pause {
                std::thread::sleep(pause);
            }
            input.write_all(&second)
        });
        if held {
            // The receive returns once the sender is dropped, after the hook's exit.
            let _ = exit.recv();
        }
        drop(input);
        fed
    });
    let drain = |mut stream: Box<dyn Read + Send>| {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes).map(|_| bytes)
        })
    };
    let stdout = drain(Box::new(
        child.stdout.take().expect("standard output is piped"),
    ));
    let stderr = drain(Box::new(
        child.stderr.take().expect("standard error is piped"),
    ));
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("the hook is polled") {
            break Some(status);
        }
        if start.elapsed() >= limit {
            child.kill().expect("the hook is killed");
            child.wait().expect("the hook is reaped");
            break None;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    drop(exited);
    let ended = Instant::now();
    while !(feeder.is_finished() && stdout.is_finished() && stderr.is_finished()) {
        if ended.elapsed() >= Duration::from_secs(5) {
            return Err("a process the hook started holds one of its streams".to_owned());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let Some(status) = status else {
        return Err(format!("the hook ran past {limit:?}"));
    };
    let text = |stream: std::thread::JoinHandle<io::Result<Vec<u8>>>| {
        let bytes = stream
            .join()
            .expect("the stream's thread ends")
            .expect("the stream reads");
        String::from_utf8(bytes).expect("the stream is UTF-8")
    };
    let run = Run {
        code: status.code(),
        stdout: text(stdout),
        stderr: text(stderr),
    };
    Ok((run, feeder.join().expect("the feed's thread ends")))
}

/// `fed` is [`collect`] with `input` whole against [`RUN_LIMIT`]. It returns the run alone: a hook that
/// exits before it has read its input fails the feed's write, and the case judges that run by its exit
/// code.
fn fed(command: &mut Command, input: impl AsRef<[u8]>) -> Run {
    match collect(command, Feed::Whole(input.as_ref()), RUN_LIMIT) {
        Ok((run, _)) => run,
        Err(error) => panic!("{error}"),
    }
}

impl Repo {
    /// `install` writes `hook` as `.githooks/pre-push` and `tool` as the stand-in `scripts/tool.sh`, and
    /// returns the hook's path.
    fn install(&self, hook: &str, tool: &str) -> PathBuf {
        let hooks = self.path.join(".githooks");
        let scripts = self.path.join("scripts");
        for dir in [&hooks, &scripts] {
            fs::create_dir_all(dir).expect("the directory is made");
        }
        let path = hooks.join("pre-push");
        fs::write(&path, hook).expect("the hook is written");
        fs::write(scripts.join("tool.sh"), tool).expect("the launcher's stand-in is written");
        path
    }

    /// `hook_with` installs `hook` beside `tool` and prepares `bash .githooks/pre-push origin remote-url`
    /// in the repository.
    fn hook_with(&self, hook: &str, tool: &str) -> Command {
        let path = self.install(hook, tool);
        let mut command = self.command("bash");
        command.arg(path).args(["origin", "remote-url"]);
        command
    }

    /// `guard` writes `text` as the global hook in the directory `shared hooks`, names that directory as
    /// the global `core.hooksPath`, and returns it.
    fn guard(&self, text: &str) -> PathBuf {
        let hooks = self.path.join("shared hooks");
        fs::create_dir(&hooks).expect("the directory is made");
        executable(&hooks.join("pre-push"), text);
        self.git(&[
            "config",
            "--global",
            "core.hooksPath",
            hooks.to_str().expect("the path is UTF-8"),
        ]);
        hooks
    }

    /// `scratch` makes the empty directory `scratch` of mode 0700 in the repository, with [`past`] as its
    /// modification time, and returns it.
    fn scratch(&self) -> PathBuf {
        let scratch = self.path.join("scratch");
        DirBuilder::new()
            .mode(0o700)
            .create(&scratch)
            .expect("the directory is made");
        age(&scratch);
        scratch
    }

    /// `listed` reads the listing a stand-in wrote to `name` in the repository and returns its entries
    /// that `before` lacks.
    fn listed(&self, name: &str, before: &[String]) -> Vec<String> {
        let text = fs::read_to_string(self.path.join(name))
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        text.lines()
            .filter(|entry| !entry.is_empty() && !before.iter().any(|stood| stood == entry))
            .map(str::to_owned)
            .collect()
    }

    /// `forget` removes each of `records` that stands, so a later run's record is that run's own.
    fn forget(records: &[PathBuf]) {
        for record in records {
            match fs::remove_file(record) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => panic!("{}: {error}", record.display()),
            }
        }
    }
}

/// `age` gives the directory `dir` the modification time [`past`].
fn age(dir: &Path) {
    File::open(dir)
        .and_then(|opened| opened.set_modified(past()))
        .unwrap_or_else(|error| panic!("{}: {error}", dir.display()));
}

/// `aged` tells whether the directory `dir` still has the modification time [`past`], which it loses when
/// an entry is made or removed in it.
fn aged(dir: &Path) -> bool {
    let modified = fs::metadata(dir)
        .and_then(|status| status.modified())
        .unwrap_or_else(|error| panic!("{}: {error}", dir.display()));
    modified == past()
}

/// `bytes` reads the file at `path` whole.
fn bytes(path: PathBuf) -> Vec<u8> {
    fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

/// Over a whole push with both readers and ten thousand ref lines, the directory `TMPDIR` names keeps
/// its modification time, so the hook made and removed no entry in it, and it is empty when the launcher
/// starts. The working directory holds the entries it held when the launcher starts, also with `TMPDIR`
/// naming that directory. Under the spooling hook, which differs in its text alone, the listing of
/// `TMPDIR` holds the spool and the directory's time moves.
#[test]
fn pre_push_makes_no_entry_under_tmpdir_or_its_working_directory() {
    let repo = Repo::new("pre-push-no-entry");
    let hooks = repo.guard(KEEPER);
    let scratch = repo.scratch();
    let checked = hook_text();
    let lines = ref_lines(10_000);
    for (hook, spools) in [(SPOOLING, true), (checked.as_str(), false)] {
        age(&scratch);
        let mut command = repo.hook_with(hook, WATCHER);
        command.env("TMPDIR", &scratch);
        let stood = names(&repo.path);
        let done = fed(&mut command, &lines);
        let arm = format!("spools {spools}, TMPDIR the scratch directory: {done}");
        assert_eq!(done.code, Some(37), "{arm}");
        let under_tmpdir = repo.listed("tool.scratch", &[]);
        if spools {
            assert_eq!(under_tmpdir.len(), 1, "{arm}: {under_tmpdir:?}");
            assert!(
                under_tmpdir[0].starts_with("kestrike-pre-push."),
                "{arm}: {under_tmpdir:?}"
            );
        } else {
            assert_eq!(under_tmpdir, Vec::<String>::new(), "{arm}");
        }
        assert_eq!(aged(&scratch), !spools, "{arm}");
        assert_eq!(names(&scratch), Vec::<String>::new(), "{arm}");
        assert_eq!(
            repo.listed("tool.work", &stood),
            Vec::<String>::new(),
            "{arm}"
        );
        assert!(
            bytes(repo.path.join("tool.input")) == lines.as_bytes(),
            "{arm}"
        );
        assert!(
            bytes(hooks.join("guard.input")) == lines.as_bytes(),
            "{arm}"
        );

        let mut command = repo.hook_with(hook, WATCHER);
        command.env("TMPDIR", &repo.path);
        let stood = names(&repo.path);
        let done = fed(&mut command, DELETION);
        let arm = format!("spools {spools}, TMPDIR the working directory: {done}");
        assert_eq!(done.code, Some(37), "{arm}");
        let in_work = repo.listed("tool.work", &stood);
        if spools {
            assert_eq!(in_work.len(), 1, "{arm}: {in_work:?}");
            assert!(
                in_work[0].starts_with("kestrike-pre-push."),
                "{arm}: {in_work:?}"
            );
        } else {
            assert_eq!(in_work, Vec::<String>::new(), "{arm}");
        }
        assert_eq!(
            bytes(repo.path.join("tool.input")),
            DELETION.as_bytes(),
            "{arm}"
        );
    }
}

/// The launcher and the global hook each receive the bytes of the hook's standard input: a final line
/// feed or its absence, an empty input, line feeds alone, and each byte value from 1 to 255, with the
/// characters a shell's word splitting, backslash reading and expansion act on.
#[test]
fn pre_push_gives_the_tool_and_the_global_hook_the_bytes_of_its_input() {
    let repo = Repo::new("pre-push-bytes");
    let hooks = repo.guard(KEEPER);
    let checked = hook_text();
    let every_byte: Vec<u8> = (1..=255).chain(1..=255).collect();
    let rows: [(&str, &[u8]); 8] = [
        ("a final line feed", DELETION.as_bytes()),
        ("no final line feed", DELETION.trim_end().as_bytes()),
        ("an empty input", b""),
        ("one line feed", b"\n"),
        ("line feeds alone", b"\n\n\n"),
        (
            "two lines, the last without its line feed",
            b"a b c d\ne f g h",
        ),
        (
            "blanks, backslashes, a pattern and an expansion",
            b"  \t a\\\nb\\n \\\\ * $HOME `id` %s %% -n -e \r\n \t ",
        ),
        ("each byte from 1 to 255, twice", &every_byte),
    ];
    for (row, input) in rows {
        let mut command = repo.hook_with(&checked, TOOL);
        let done = fed(&mut command, input);
        assert_eq!(done.code, Some(37), "{row}: {done}");
        assert_eq!(
            bytes(repo.path.join("tool.args")),
            b"pre-push-checks\norigin\n",
            "{row}: {done}"
        );
        assert_eq!(
            bytes(repo.path.join("tool.input")),
            input,
            "{row}: the launcher's input"
        );
        assert_eq!(
            bytes(hooks.join("guard.input")),
            input,
            "{row}: the global hook's input"
        );
    }
}

/// Ten thousand ref lines, 1,180,000 bytes, reach the launcher and the global hook unchanged.
#[test]
fn pre_push_gives_both_readers_ten_thousand_ref_lines_unchanged() {
    let repo = Repo::new("pre-push-ten-thousand");
    let hooks = repo.guard(KEEPER);
    let input = ref_lines(10_000);
    assert_eq!(input.len(), 1_180_000);
    let mut command = repo.hook_with(&hook_text(), TOOL);
    let done = fed(&mut command, &input);
    assert_eq!(done.code, Some(37), "{done}");
    assert!(
        bytes(repo.path.join("tool.input")) == input.as_bytes(),
        "the launcher's input differs"
    );
    assert!(
        bytes(hooks.join("guard.input")) == input.as_bytes(),
        "the global hook's input differs"
    );
}

/// An input that holds a NUL byte ends the hook with exit 2 and one sentence, and neither the launcher
/// nor the global hook starts. On the same lines without the byte both start.
#[test]
fn pre_push_refuses_an_input_that_holds_a_nul_byte_before_the_tool_starts() {
    let repo = Repo::new("pre-push-nul");
    let hooks = repo.guard(KEEPER);
    let checked = hook_text();
    let rows: [&[u8]; 4] = [
        b"\0",
        b"\0a b c d\n",
        b"a b c d\n\0",
        b"a b c d\ne f\0g h\ni j k l\n",
    ];
    for input in rows {
        let mut command = repo.hook_with(&checked, TOOL);
        let done = fed(&mut command, input);
        assert_eq!(done.code, Some(2), "{input:?}: {done}");
        assert_eq!(
            done.stderr, "pre-push: standard input holds a NUL byte\n",
            "{input:?}: {done}"
        );
        assert_eq!(done.stdout, "", "{input:?}: {done}");
        assert!(
            !repo.path.join("tool.args").exists(),
            "{input:?}: the launcher started"
        );
        assert!(
            !hooks.join("guard.input").exists(),
            "{input:?}: the global hook started"
        );
    }
    let mut command = repo.hook_with(&checked, TOOL);
    let done = fed(&mut command, "a b c d\ne fg h\ni j k l\n");
    assert_eq!(done.code, Some(37), "{done}");
    assert!(
        repo.path.join("tool.args").exists(),
        "the launcher starts on the lines without the NUL byte"
    );
    assert!(
        hooks.join("guard.input").exists(),
        "the global hook starts on the lines without the NUL byte"
    );
}

/// The global hook's stand-in that reads no byte of its standard input: it makes `guard.ran` beside
/// itself, writes the record of its start to `guard.environment` there, and exits with the value of
/// `GUARD_EXIT`, or 0.
fn deaf_guard() -> String {
    format!(
        "#!/bin/sh\nhere=$(dirname -- \"$0\")\n: > \"$here/guard.ran\"\nrecord=$here/guard.environment\n{RECORD}exit \"${{GUARD_EXIT:-0}}\"\n"
    )
}

/// The launcher's stand-in that writes the record of its start to `tool.environment` in the repository
/// and reads no byte of its standard input.
fn namer() -> String {
    format!("#!/bin/sh\nrecord=$(dirname -- \"$0\")/../tool.environment\n{RECORD}")
}

impl Repo {
    /// `entered` prepares the hook at `hook` as `bash HOOK origin remote-url`, started through a shell
    /// that first ignores SIGPIPE where `ignored` is set.
    fn entered(&self, hook: &Path, ignored: bool) -> Command {
        let mut command = if ignored {
            let mut command = self.command("sh");
            command.args(["-c", r#"trap '' PIPE; exec bash "$@""#, "sh"]);
            command
        } else {
            self.command("bash")
        };
        command.arg(hook).args(["origin", "remote-url"]);
        command
    }
}

/// A reader that exits before it reads its standard input decides the hook's exit code with its own:
/// the launcher's 2 ends the hook with 2 and the global hook does not start, a launcher and a global
/// hook that exit 0 end it with 0, and the global hook's 37 ends it with 37. The hook writes no line of
/// its own to standard error. Each row runs on one ref line and on more lines than a pipe holds, which
/// a writer cannot finish before the reader exits; with SIGPIPE at its default and ignored when the
/// hook starts; and in the hook's own locale and in a French one where this host's bash takes it, in
/// which a bash that reports a broken pipe words the report in French.
#[test]
fn pre_push_ends_with_the_exit_code_of_a_reader_that_reads_no_input() {
    let repo = Repo::new("pre-push-deaf");
    let hooks = repo.guard(&deaf_guard());
    let checked = hook_text();
    let lines = past_a_pipe();
    let french = Some("fr_FR.UTF-8").filter(|name| multibyte(&repo, name));
    let mut locales = vec![None];
    locales.extend(french.map(Some));
    for (locale, ignored) in locales
        .into_iter()
        .flat_map(|locale| [(locale, false), (locale, true)])
    {
        for input in [DELETION, lines.as_str()] {
            for (tool_exit, guard_exit, code, guarded) in [
                ("2", "0", 2, false),
                ("0", "0", 0, true),
                ("0", "37", 37, true),
            ] {
                Repo::forget(&[repo.path.join("tool.ran"), hooks.join("guard.ran")]);
                let hook = repo.install(&checked, DEAF_TOOL);
                let mut command = repo.entered(&hook, ignored);
                command
                    .env("TOOL_EXIT", tool_exit)
                    .env("GUARD_EXIT", guard_exit);
                if let Some(locale) = locale {
                    command.env("LC_ALL", locale);
                }
                let done = fed(&mut command, input);
                let row = format!(
                    "locale {locale:?}, SIGPIPE ignored {ignored}, {} bytes, launcher {tool_exit}, global hook {guard_exit}: {done}",
                    input.len()
                );
                assert_eq!(done.code, Some(code), "{row}");
                assert_eq!(done.stderr, "", "{row}");
                assert!(repo.path.join("tool.ran").exists(), "{row}");
                assert_eq!(hooks.join("guard.ran").exists(), guarded, "{row}");
            }
        }
    }
}

/// A standard input that cannot be read, a directory here, ends the hook with exit 1, and neither the
/// launcher nor the global hook starts, also where the hook's environment holds a variable `refs`. With
/// `/dev/null` in its place both start.
#[test]
fn pre_push_ends_with_exit_1_before_the_tool_starts_when_its_input_cannot_be_read() {
    let repo = Repo::new("pre-push-unreadable");
    let hooks = repo.guard(&deaf_guard());
    let checked = hook_text();
    let mut command = repo.hook_with(&checked, TOOL);
    let directory = File::open(&repo.path).expect("the directory opens");
    let done = run(command
        .env("refs", "inherited")
        .stdin(Stdio::from(directory)));
    assert_eq!(done.code, Some(1), "{done}");
    assert!(
        done.stderr
            .ends_with("pre-push: standard input could not be read to its end\n"),
        "{done}"
    );
    assert!(
        !repo.path.join("tool.args").exists(),
        "the launcher started"
    );
    assert!(!hooks.join("guard.ran").exists(), "the global hook started");
    let mut command = repo.hook_with(&checked, TOOL);
    let done = run(command.stdin(Stdio::null()));
    assert_eq!(done.code, Some(0), "{done}");
    assert!(
        repo.path.join("tool.args").exists(),
        "the launcher starts on an empty input"
    );
    assert!(
        hooks.join("guard.ran").exists(),
        "the global hook starts on an empty input"
    );
}

/// Each reader starts in the hook's environment less a variable `refs`, and with the hook's own
/// disposition of SIGPIPE: the ref lines stay in the hook's shell, and the locale and the time limit of
/// the hook's read and the writer's ignored SIGPIPE reach neither reader. The rows give the hook an
/// `LC_ALL` and a `TMOUT` of its own and none, the shell option `allexport`, and SIGPIPE ignored. A
/// reader that reports the default disposition shows that the hook started with it, since a shell
/// cannot restore a signal that it started with ignored.
#[test]
fn pre_push_starts_its_readers_in_its_own_environment_less_the_ref_lines() {
    let repo = Repo::new("pre-push-environment");
    let hooks = repo.guard(&deaf_guard());
    let checked = hook_text();
    let read = |path: PathBuf| String::from_utf8(bytes(path)).expect("the record is UTF-8");
    for (given, allexport, ignored, expected) in [
        (true, false, false, "absent|POSIX|7|default"),
        (false, false, false, "absent|absent|absent|default"),
        (false, true, false, "absent|absent|absent|default"),
        (false, false, true, "absent|absent|absent|ignored"),
    ] {
        let hook = repo.install(&checked, &namer());
        let mut command = repo.entered(&hook, ignored);
        command.env("refs", "inherited");
        if given {
            command.env("LC_ALL", "POSIX").env("TMOUT", "7");
        } else {
            command.env_remove("LC_ALL").env_remove("TMOUT");
        }
        if allexport {
            command.env("SHELLOPTS", "allexport");
        }
        let done = fed(&mut command, DELETION);
        let row = format!("allexport {allexport}, SIGPIPE ignored {ignored}: {done}");
        assert_eq!(done.code, Some(0), "{row}");
        assert_eq!(read(repo.path.join("tool.environment")), expected, "{row}");
        assert_eq!(read(hooks.join("guard.environment")), expected, "{row}");
    }
}

/// Under the shell option `allexport` the hook starts both readers on ref lines of 141,600 bytes, more
/// than Linux takes in one string of an environment, and each reader gets every byte.
#[test]
fn pre_push_starts_its_readers_on_long_ref_lines_under_allexport() {
    let repo = Repo::new("pre-push-allexport");
    let hooks = repo.guard(KEEPER);
    let input = ref_lines(1_200);
    assert!(input.len() > 131_072);
    let mut command = repo.hook_with(&hook_text(), TOOL);
    command.env("SHELLOPTS", "allexport");
    let done = fed(&mut command, &input);
    assert_eq!(done.code, Some(37), "{done}");
    assert!(
        bytes(repo.path.join("tool.input")) == input.as_bytes(),
        "the launcher's input differs"
    );
    assert!(
        bytes(hooks.join("guard.input")) == input.as_bytes(),
        "the global hook's input differs"
    );
}

/// The built tool's refusal of a malformed ref line passes through the hook: exit 2 with the tool's
/// sentence, the global hook does not start, and the directory `TMPDIR` names keeps its modification
/// time, so no entry was made or removed in it during the run. On an empty input the same arrangement
/// exits 0 and the global hook starts.
#[test]
fn pre_push_ends_with_the_built_tool_s_refusal_before_the_global_hook() {
    let repo = Repo::new("pre-push-refusal");
    let hooks = repo.guard(&deaf_guard());
    let scratch = repo.scratch();
    let checked = hook_text();
    for (input, code, stderr, guarded) in [
        (
            "ref-update\n",
            2,
            "pre-push: malformed ref line: 'ref-update'\n",
            false,
        ),
        ("", 0, "", true),
    ] {
        let mut command = repo.hook_with(&checked, LAUNCHER);
        command
            .env("TOOLS_BINARY", BINARY)
            .env("TOOLS_TOP", top())
            .env("TMPDIR", &scratch);
        let done = fed(&mut command, input);
        assert_eq!(done.code, Some(code), "{input:?}: {done}");
        assert_eq!(done.stderr, stderr, "{input:?}: {done}");
        assert_eq!(
            hooks.join("guard.ran").exists(),
            guarded,
            "{input:?}: {done}"
        );
        assert!(aged(&scratch), "{input:?}: an entry was made under TMPDIR");
        assert_eq!(names(&scratch), Vec::<String>::new(), "{input:?}");
    }
}

/// `multibyte` tells whether the `bash` the cases start counts a character of two bytes as one under the
/// locale `name`, which it does where the host has that locale and it is a multibyte one.
fn multibyte(repo: &Repo, name: &str) -> bool {
    let done = run(repo
        .command("bash")
        .args(["-c", r#"letter=$'\xc3\xa9'; printf '%s' "${#letter}""#])
        .env("LC_ALL", name));
    assert_eq!(done.code, Some(0), "{name}: {done}");
    done.stdout == "1"
}

/// The hook reads its input byte by byte under a UTF-8 locale. A byte that starts a character of several
/// bytes, followed by U+0001, reaches both readers with the bytes around it, and the same byte followed
/// by a NUL byte is refused as every NUL byte is. The case runs under each of `C.UTF-8` and `en_US.UTF-8`
/// that this host's bash takes as a multibyte locale, and fails on a host that has neither.
#[test]
fn pre_push_reads_each_byte_of_its_input_under_a_multibyte_locale() {
    let repo = Repo::new("pre-push-locale");
    let hooks = repo.guard(KEEPER);
    let checked = hook_text();
    let locales: Vec<&str> = ["C.UTF-8", "en_US.UTF-8"]
        .into_iter()
        .filter(|name| multibyte(&repo, name))
        .collect();
    assert!(
        !locales.is_empty(),
        "bash takes neither C.UTF-8 nor en_US.UTF-8 as a multibyte locale on this host"
    );
    for locale in locales {
        let input: &[u8] = b"a\x01b \xc3\x01 \xe2\x82\x01c d\n\xf0\x9f\x01\x7f\n";
        let mut command = repo.hook_with(&checked, TOOL);
        command.env("LC_ALL", locale);
        let done = fed(&mut command, input);
        assert_eq!(done.code, Some(37), "{locale}: {done}");
        assert_eq!(
            bytes(repo.path.join("tool.input")),
            input,
            "{locale}: the launcher's input"
        );
        assert_eq!(
            bytes(hooks.join("guard.input")),
            input,
            "{locale}: the global hook's input"
        );
        Repo::forget(&[repo.path.join("tool.args"), repo.path.join("tool.input")]);
        let mut command = repo.hook_with(&checked, TOOL);
        command.env("LC_ALL", locale);
        let done = fed(&mut command, b"a b \xc3\0c d\ne f g h\n");
        assert_eq!(done.code, Some(2), "{locale}: {done}");
        assert_eq!(
            done.stderr, "pre-push: standard input holds a NUL byte\n",
            "{locale}: {done}"
        );
        assert!(
            !repo.path.join("tool.args").exists(),
            "{locale}: the launcher started"
        );
    }
}

/// A `TMOUT` of one second sets no time limit on the hook's read, whether the hook's environment holds
/// it or a startup file makes it readonly: an input whose last line arrives two and a half seconds after
/// the rest reaches both readers whole. The first part is more than a pipe holds, so its write returns
/// once the hook's read has started. The hook's text without its own limit is the arm where the
/// environment's limit ends the read: that hook exits 1 with the sentence of an input not read to its
/// end and starts no launcher, so a part of the input passes to no reader.
#[test]
fn pre_push_reads_past_a_time_limit_of_its_environment_and_passes_on_no_partial_input() {
    let repo = Repo::new("pre-push-time-limit");
    let hooks = repo.guard(KEEPER);
    let checked = hook_text();
    let first = past_a_pipe();
    let second = b"e f g h\n";
    let whole = [first.as_bytes(), &second[..]].concat();
    let startup = repo.path.join("limit.env");
    fs::write(&startup, "readonly TMOUT=1\n").expect("the startup file is written");
    for readonly in [false, true] {
        Repo::forget(&[repo.path.join("tool.input"), hooks.join("guard.input")]);
        let mut command = repo.hook_with(&checked, TOOL);
        if readonly {
            command.env_remove("TMOUT").env("BASH_ENV", &startup);
        } else {
            command.env("TMOUT", "1");
        }
        let feed = Feed::Paused(first.as_bytes(), Duration::from_millis(2500), second);
        let (done, written) =
            collect(&mut command, feed, RUN_LIMIT).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(done.code, Some(37), "readonly {readonly}: {done}");
        assert!(written.is_ok(), "readonly {readonly}: {written:?}: {done}");
        assert!(
            bytes(repo.path.join("tool.input")) == whole,
            "readonly {readonly}: the launcher's input differs"
        );
        assert!(
            bytes(hooks.join("guard.input")) == whole,
            "readonly {readonly}: the global hook's input differs"
        );
    }
    Repo::forget(&[repo.path.join("tool.args"), repo.path.join("tool.input")]);

    let limited = checked.replace("limit=(-t 1000000000)", "limit=()");
    assert_ne!(
        limited, checked,
        "the hook's text holds `limit=(-t 1000000000)`"
    );
    let mut command = repo.hook_with(&limited, TOOL);
    command.env("TMOUT", "1");
    let (done, _) = collect(&mut command, Feed::Held(b"a b c d\n"), RUN_LIMIT)
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(done.code, Some(1), "{done}");
    assert_eq!(
        done.stderr, "pre-push: standard input could not be read to its end\n",
        "{done}"
    );
    assert!(
        !repo.path.join("tool.args").exists(),
        "the launcher started on a part of the input"
    );
}

/// A writer of the ref lines that fails otherwise than on a broken pipe fails the push, though its
/// reader reads to the end of its input and exits 0. The startup file's trap ends the writer with
/// SIGKILL, for exit 137, or turns its `printf` off, for exit 1 with the hook's sentence; it acts on the
/// launcher's writer or, once the launcher has read its input whole, on the global hook's. The reader of
/// a failed writer gets no byte, and after a failed first writer the global hook does not start. With no
/// fault named the same arrangement exits 0 with every byte at both readers.
#[test]
fn pre_push_fails_when_the_writer_of_the_ref_lines_fails_and_its_reader_exits_0() {
    let repo = Repo::new("pre-push-writer");
    let hooks = repo.guard(KEEPER);
    let checked = hook_text();
    let input = ref_lines(3);
    let startup = repo.path.join("faults.env");
    fs::write(&startup, FAULTS).expect("the startup file is written");
    let marker = repo.path.join("launcher.read");
    for (fault, second, code) in [
        (Some("kill"), false, 137),
        (Some("kill"), true, 137),
        (Some("disable"), false, 1),
        (Some("disable"), true, 1),
        (None, false, 0),
    ] {
        Repo::forget(&[
            repo.path.join("tool.input"),
            hooks.join("guard.input"),
            marker.clone(),
        ]);
        let mut command = repo.hook_with(&checked, DRAINER);
        command.env("BASH_ENV", &startup).env("GUARD_EXIT", "0");
        if let Some(fault) = fault {
            command.env("FAULT", fault);
        }
        if second {
            command.env("FAULT_AFTER", &marker);
        }
        let done = fed(&mut command, &input);
        let row = format!("fault {fault:?}, at the global hook's writer {second}: {done}");
        assert_eq!(done.code, Some(code), "{row}");
        if fault == Some("disable") {
            assert!(
                done.stderr
                    .contains("pre-push: the ref lines could not be written: "),
                "{row}"
            );
        }
        let whole = input.as_bytes();
        let (tool, guard): (&[u8], Option<&[u8]>) = match (fault, second) {
            (None, _) => (whole, Some(whole)),
            (Some(_), false) => (b"", None),
            (Some(_), true) => (whole, Some(b"")),
        };
        assert_eq!(bytes(repo.path.join("tool.input")), tool, "{row}");
        let guarded = hooks.join("guard.input");
        assert_eq!(guarded.exists(), guard.is_some(), "{row}");
        if let Some(guard) = guard {
            assert_eq!(bytes(guarded), guard, "{row}");
        }
    }
}

/// With the shell option `xtrace` in the hook's environment, a ref name of the input stands in neither
/// output stream of the hook, and both readers get the lines. The hook's text without its `set +x` is
/// the arm where the trace holds the name. The trace also shows the read's own words: with no `TMOUT`
/// in the environment the read has no time limit, and with one it has the hook's.
#[test]
fn pre_push_keeps_the_ref_lines_out_of_a_trace_of_the_hook() {
    let repo = Repo::new("pre-push-trace");
    let hooks = repo.guard(KEEPER);
    let checked = hook_text();
    let traced = checked.replace("  set +x\n", "");
    assert_ne!(traced, checked, "the hook's text holds `set +x`");
    let name = "refs/heads/a-name-of-this-case";
    let input = format!("{name} {} {name} {}\n", "a".repeat(40), "b".repeat(40));
    for (hook, shown, limit) in [
        (traced.as_str(), true, None),
        (checked.as_str(), false, None),
        (checked.as_str(), false, Some("7")),
    ] {
        let mut command = repo.hook_with(hook, TOOL);
        command.env("SHELLOPTS", "xtrace").env_remove("TMOUT");
        let read = match limit {
            Some(limit) => {
                command.env("TMOUT", limit);
                "+ read -r -d '' -t 1000000000 refs\n"
            }
            None => "+ read -r -d '' refs\n",
        };
        let done = fed(&mut command, &input);
        assert_eq!(done.code, Some(37), "{done}");
        assert!(done.stderr.contains("+ send"), "the hook is traced: {done}");
        assert!(done.stderr.contains(read), "TMOUT {limit:?}: {done}");
        assert_eq!(done.stderr.contains(name), shown, "{done}");
        assert!(!done.stdout.contains(name), "{done}");
        assert_eq!(bytes(repo.path.join("tool.input")), input.as_bytes());
        assert_eq!(bytes(hooks.join("guard.input")), input.as_bytes());
    }
}

/// A hook that reads no byte of an input larger than a pipe holds ends the case at the time limit:
/// [`collect`] returns its error within seconds of a one-second limit, with the hook ended.
#[test]
fn a_hook_that_reads_nothing_ends_its_case_at_the_time_limit() {
    let repo = Repo::new("pre-push-stuck");
    let mut command = repo.hook_with("exec sleep 600\n", TOOL);
    let input = past_a_pipe();
    let start = Instant::now();
    let outcome = collect(
        &mut command,
        Feed::Whole(input.as_bytes()),
        Duration::from_secs(1),
    );
    let took = start.elapsed();
    match outcome {
        Err(error) => assert_eq!(error, "the hook ran past 1s"),
        Ok((done, _)) => panic!("the hook ended: {done}"),
    }
    assert!(took < Duration::from_secs(30), "the case took {took:?}");
}

/// The launcher's stand-in of the scratch case: it writes the listing of the directory `TMPDIR` names to
/// `tool.scratch` in the repository as it starts, then starts the program `TOOLS_BINARY` names with
/// `TOOLS_TOP` and its own arguments, on its own standard input.
const SCRATCH_TOOL: &str = r#"#!/bin/sh
top=$(dirname -- "$0")/..
ls -A "$TMPDIR" > "$top/tool.scratch" || exit 99
exec "$TOOLS_BINARY" "$TOOLS_TOP" "$@"
"#;

/// With `TMPDIR` a directory that every user can write and that has no sticky bit, the built tool's
/// refusal of that directory ends the push through the hook: exit 2 with the tool's sentence, and the
/// global hook does not start. The same directory with the sticky bit passes and the global hook starts.
/// In both arms the directory is empty when the tool starts and keeps its modification time over the
/// push, so the hook made no entry in it.
#[test]
fn pre_push_ends_with_the_tool_s_refusal_of_a_scratch_directory_others_can_write() {
    use std::os::unix::fs::PermissionsExt;
    let repo = Repo::new("pre-push-scratch");
    let hooks = repo.guard(&deaf_guard());
    let scratch = repo.scratch();
    let checked = hook_text();
    let refusal = format!(
        "pre-push: the scratch directory {} is writable by its group or by other users and has no sticky \
         bit; set TMPDIR to a directory that you own and only you can write\n",
        scratch.display()
    );
    for (mode, code, stderr, guarded) in
        [(0o777, 2, refusal.as_str(), false), (0o1777, 0, "", true)]
    {
        fs::set_permissions(&scratch, fs::Permissions::from_mode(mode)).expect("the mode is set");
        age(&scratch);
        Repo::forget(&[hooks.join("guard.ran")]);
        let mut command = repo.hook_with(&checked, SCRATCH_TOOL);
        command
            .env("TOOLS_BINARY", BINARY)
            .env("TOOLS_TOP", &repo.path)
            .env("TMPDIR", &scratch);
        let done = fed(&mut command, DELETION);
        assert_eq!(done.code, Some(code), "{mode:o}: {done}");
        assert_eq!(done.stderr, stderr, "{mode:o}: {done}");
        assert_eq!(
            hooks.join("guard.ran").exists(),
            guarded,
            "{mode:o}: {done}"
        );
        assert_eq!(
            repo.listed("tool.scratch", &[]),
            Vec::<String>::new(),
            "{mode:o}: an entry stands under TMPDIR when the tool starts"
        );
        assert!(aged(&scratch), "{mode:o}: an entry was made under TMPDIR");
        assert_eq!(names(&scratch), Vec::<String>::new(), "{mode:o}");
    }
}
