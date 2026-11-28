//! Cases for the checkout's comment-marker scan, its commit hook, its ignore rules and its pre-push hook.
//! A pre-push case runs a copy of `.githooks/pre-push` beside a stand-in `scripts/tool.sh` that writes its
//! arguments to `tool.args` and its standard input to `tool.input` in the repository, or beside the
//! stand-in the case names. A stand-in of the global hook stands in the directory `shared hooks` of the
//! repository. Each stand-in finds the programs it starts on the `PATH` of the test run, or takes a
//! program's whole path from a variable the case sets.

use std::fmt;
use std::fs::{self, DirBuilder, File};
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{ChildStdin, Command, Output, Stdio};
use std::time::Duration;

use crate::pre_push_checks::push::{BINARY, Run, Tool, executable, finished, spawn_with_input};

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
        let hooks = self.path.join(".githooks");
        let scripts = self.path.join("scripts");
        for dir in [&hooks, &scripts] {
            fs::create_dir_all(dir).expect("the directory is made");
        }
        let hook = hooks.join("pre-push");
        fs::copy(top().join(".githooks/pre-push"), &hook).expect("the hook is copied");
        fs::write(scripts.join("tool.sh"), TOOL).expect("the launcher's stand-in is written");
        hook
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

/// The launcher's stand-in that writes the values of its environment's `refs`, `LC_ALL` and `TMOUT`, each
/// `absent` where the environment lacks it, to `tool.environment` in the repository.
const NAMER: &str = "#!/bin/sh\nprintf '%s|%s|%s' \"${refs-absent}\" \"${LC_ALL-absent}\" \"${TMOUT-absent}\" > \"$(dirname -- \"$0\")/../tool.environment\"\n";

/// The global hook's stand-in that writes its standard input to `guard.input` beside itself and exits 37.
const KEEPER: &str = "#!/bin/sh\ncat > \"$(dirname -- \"$0\")/guard.input\"\nexit 37\n";

/// The global hook's stand-in that reads no byte of its standard input: it makes `guard.ran` beside
/// itself, writes the values of its environment's `refs`, `LC_ALL` and `TMOUT`, each `absent` where the
/// environment lacks it, to `guard.environment` there, and exits with the value of `GUARD_EXIT`, or 0.
const DEAF_GUARD: &str = "#!/bin/sh\n: > \"$(dirname -- \"$0\")/guard.ran\"\nprintf '%s|%s|%s' \"${refs-absent}\" \"${LC_ALL-absent}\" \"${TMOUT-absent}\" > \"$(dirname -- \"$0\")/guard.environment\"\nexit \"${GUARD_EXIT:-0}\"\n";

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
}

/// When the launcher starts, the directory `TMPDIR` names and the hook's working directory hold the
/// entries they held before the hook started: a scratch directory that was empty is empty then, and so
/// is the difference of the working directory's two listings, also with `TMPDIR` naming that directory.
/// Under the spooling hook, which differs in its text alone, the listing of `TMPDIR` holds the spool.
#[test]
fn pre_push_makes_no_entry_under_tmpdir_or_its_working_directory() {
    let repo = Repo::new("pre-push-no-entry");
    let scratch = repo.path.join("scratch");
    DirBuilder::new()
        .mode(0o700)
        .create(&scratch)
        .expect("the directory is made");
    let checked = hook_text();
    for (hook, spools) in [(SPOOLING, true), (checked.as_str(), false)] {
        for tmpdir in [&scratch, &repo.path] {
            let mut command = repo.hook_with(hook, WATCHER);
            command.env("TMPDIR", tmpdir);
            let (before, stood) = (names(tmpdir), names(&repo.path));
            let done = finished(spawn_with_input(&mut command, DELETION));
            let arm = format!("spools {spools}, TMPDIR {}: {done}", tmpdir.display());
            assert_eq!(done.code, Some(0), "{arm}");
            let under_tmpdir = repo.listed("tool.scratch", &before);
            let in_work = repo.listed("tool.work", &stood);
            if spools {
                assert_eq!(under_tmpdir.len(), 1, "{arm}: {under_tmpdir:?}");
                assert!(
                    under_tmpdir[0].starts_with("kestrike-pre-push."),
                    "{arm}: {under_tmpdir:?}"
                );
                let expected = if *tmpdir == repo.path {
                    under_tmpdir.clone()
                } else {
                    Vec::new()
                };
                assert_eq!(in_work, expected, "{arm}");
            } else {
                assert_eq!(under_tmpdir, Vec::<String>::new(), "{arm}");
                assert_eq!(in_work, Vec::<String>::new(), "{arm}");
            }
            assert_eq!(
                fs::read(repo.path.join("tool.input")).expect("the launcher's input reads"),
                DELETION.as_bytes(),
                "{arm}"
            );
            assert_eq!(names(&scratch), Vec::<String>::new(), "{arm}");
        }
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
        let done = finished(spawn_with_input(&mut command, input));
        assert_eq!(done.code, Some(37), "{row}: {done}");
        assert_eq!(
            fs::read(repo.path.join("tool.args")).expect("the launcher's arguments read"),
            b"pre-push-checks\norigin\n",
            "{row}: {done}"
        );
        let tool = fs::read(repo.path.join("tool.input")).expect("the launcher's input reads");
        let guard = fs::read(hooks.join("guard.input")).expect("the global hook's input reads");
        assert_eq!(tool, input, "{row}: the launcher's input");
        assert_eq!(guard, input, "{row}: the global hook's input");
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
    let done = finished(spawn_with_input(&mut command, &input));
    assert_eq!(done.code, Some(37), "{done}");
    let tool = fs::read(repo.path.join("tool.input")).expect("the launcher's input reads");
    let guard = fs::read(hooks.join("guard.input")).expect("the global hook's input reads");
    assert!(tool == input.as_bytes(), "the launcher's input differs");
    assert!(guard == input.as_bytes(), "the global hook's input differs");
}

/// An input that holds a NUL byte ends the hook with exit 2 and one sentence, and neither the launcher
/// nor the global hook starts.
#[test]
fn pre_push_refuses_an_input_that_holds_a_nul_byte_before_the_tool_starts() {
    let repo = Repo::new("pre-push-nul");
    let hooks = repo.guard(DEAF_GUARD);
    let checked = hook_text();
    let rows: [&[u8]; 4] = [
        b"\0",
        b"\0a b c d\n",
        b"a b c d\n\0",
        b"a b c d\ne f\0g h\ni j k l\n",
    ];
    for input in rows {
        let mut command = repo.hook_with(&checked, TOOL);
        let done = finished(spawn_with_input(&mut command, input));
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
            !hooks.join("guard.ran").exists(),
            "{input:?}: the global hook started"
        );
    }
    let mut command = repo.hook_with(&checked, TOOL);
    let done = finished(spawn_with_input(&mut command, "a b c d\n"));
    assert_eq!(done.code, Some(0), "{done}");
    assert!(
        repo.path.join("tool.args").exists(),
        "the launcher starts on the lines without the NUL byte"
    );
    assert!(
        hooks.join("guard.ran").exists(),
        "the global hook starts on the lines without the NUL byte"
    );
}

/// A reader that exits before it reads its standard input decides the hook's exit code with its own:
/// the launcher's 2 ends the hook with 2 and the global hook does not start, a launcher and a global
/// hook that exit 0 end it with 0, and the global hook's 37 ends it with 37. The hook writes no line of
/// its own to standard error. Each row runs on one ref line and on a thousand, 118,000 bytes, which a
/// writer cannot finish before the reader exits; and with SIGPIPE at its default and ignored when the
/// hook starts.
#[test]
fn pre_push_ends_with_the_exit_code_of_a_reader_that_reads_no_input() {
    let repo = Repo::new("pre-push-deaf");
    let hooks = repo.guard(DEAF_GUARD);
    let checked = hook_text();
    let thousand = ref_lines(1_000);
    for ignored in [false, true] {
        for input in [DELETION, thousand.as_str()] {
            for (tool_exit, guard_exit, code, guarded) in [
                ("2", "0", 2, false),
                ("0", "0", 0, true),
                ("0", "37", 37, true),
            ] {
                for ran in [repo.path.join("tool.ran"), hooks.join("guard.ran")] {
                    match fs::remove_file(&ran) {
                        Ok(()) => {}
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                        Err(error) => panic!("{}: {error}", ran.display()),
                    }
                }
                let hook = repo.install(&checked, DEAF_TOOL);
                let mut command = if ignored {
                    let mut command = repo.command("sh");
                    command.args(["-c", r#"trap '' PIPE; exec bash "$@""#, "sh"]);
                    command
                } else {
                    repo.command("bash")
                };
                command
                    .arg(hook)
                    .args(["origin", "remote-url"])
                    .env("TOOL_EXIT", tool_exit)
                    .env("GUARD_EXIT", guard_exit);
                let done = finished(spawn_with_input(&mut command, input));
                let row = format!(
                    "SIGPIPE ignored {ignored}, {} bytes, launcher {tool_exit}, global hook {guard_exit}: {done}",
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
/// launcher nor the global hook starts. With `/dev/null` in its place both start.
#[test]
fn pre_push_ends_with_exit_1_before_the_tool_starts_when_its_input_cannot_be_read() {
    let repo = Repo::new("pre-push-unreadable");
    let hooks = repo.guard(DEAF_GUARD);
    let checked = hook_text();
    let mut command = repo.hook_with(&checked, TOOL);
    let directory = File::open(&repo.path).expect("the directory opens");
    let done = run(command.stdin(Stdio::from(directory)));
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

/// Each reader starts in the hook's environment less a variable `refs`: the ref lines stay in the hook's
/// shell, and the locale and the time limit that the hook sets for its own read reach neither reader. The
/// rows give the hook an `LC_ALL` and a `TMOUT` of its own and none.
#[test]
fn pre_push_starts_its_readers_in_its_own_environment_less_the_ref_lines() {
    let repo = Repo::new("pre-push-environment");
    let hooks = repo.guard(DEAF_GUARD);
    let checked = hook_text();
    let read = |path: PathBuf| {
        fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
    };
    for (given, expected) in [(true, "absent|POSIX|7"), (false, "absent|absent|absent")] {
        let mut command = repo.hook_with(&checked, NAMER);
        command.env("refs", "inherited");
        if given {
            command.env("LC_ALL", "POSIX").env("TMOUT", "7");
        } else {
            command.env_remove("LC_ALL").env_remove("TMOUT");
        }
        let done = finished(spawn_with_input(&mut command, DELETION));
        assert_eq!(done.code, Some(0), "{done}");
        assert_eq!(read(repo.path.join("tool.environment")), expected);
        assert_eq!(read(hooks.join("guard.environment")), expected);
    }
}

/// The built tool's refusal of a malformed ref line passes through the hook: exit 2 with the tool's
/// sentence, the global hook does not start, and the directory `TMPDIR` names stays empty. On an empty
/// input the same arrangement exits 0 and the global hook starts.
#[test]
fn pre_push_ends_with_the_built_tool_s_refusal_before_the_global_hook() {
    let repo = Repo::new("pre-push-refusal");
    let hooks = repo.guard(DEAF_GUARD);
    let scratch = repo.path.join("scratch");
    DirBuilder::new()
        .mode(0o700)
        .create(&scratch)
        .expect("the directory is made");
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
        let done = finished(spawn_with_input(&mut command, input));
        assert_eq!(done.code, Some(code), "{input:?}: {done}");
        assert_eq!(done.stderr, stderr, "{input:?}: {done}");
        assert_eq!(
            hooks.join("guard.ran").exists(),
            guarded,
            "{input:?}: {done}"
        );
        assert_eq!(names(&scratch), Vec::<String>::new(), "{input:?}");
    }
}

/// The hook reads its input byte by byte under a UTF-8 locale. A byte that starts a character of several
/// bytes, followed by U+0001, reaches both readers with the bytes around it, and the same byte followed
/// by a NUL byte is refused as every NUL byte is.
#[test]
fn pre_push_reads_each_byte_of_its_input_under_a_multibyte_locale() {
    let repo = Repo::new("pre-push-locale");
    let hooks = repo.guard(KEEPER);
    let checked = hook_text();
    for locale in ["C.UTF-8", "en_US.UTF-8"] {
        let input: &[u8] = b"a\x01b \xc3\x01 \xe2\x82\x01c d\n\xf0\x9f\x01\x7f\n";
        let mut command = repo.hook_with(&checked, TOOL);
        command.env("LC_ALL", locale);
        let done = finished(spawn_with_input(&mut command, input));
        assert_eq!(done.code, Some(37), "{locale}: {done}");
        let tool = fs::read(repo.path.join("tool.input")).expect("the launcher's input reads");
        let guard = fs::read(hooks.join("guard.input")).expect("the global hook's input reads");
        assert_eq!(tool, input, "{locale}: the launcher's input");
        assert_eq!(guard, input, "{locale}: the global hook's input");
        for name in ["tool.args", "tool.input"] {
            fs::remove_file(repo.path.join(name)).expect("the launcher's record is removed");
        }
        let mut command = repo.hook_with(&checked, TOOL);
        command.env("LC_ALL", locale);
        let done = finished(spawn_with_input(&mut command, b"a b \xc3\0c d\ne f g h\n"));
        assert_eq!(done.code, Some(2), "{locale}: {done}");
        assert!(
            done.stderr
                .ends_with("pre-push: standard input holds a NUL byte\n"),
            "{locale}: {done}"
        );
        assert!(
            !repo.path.join("tool.args").exists(),
            "{locale}: the launcher started"
        );
    }
}

impl Repo {
    /// `started` starts `command` with its three streams piped and writes `first` to its standard input,
    /// which stays open in the returned handle.
    fn started(command: &mut Command, first: &[u8]) -> (Tool, ChildStdin) {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the hook starts");
        let mut input = child.stdin.take().expect("standard input is piped");
        let tool = Tool::from(child);
        input.write_all(first).expect("the ref lines are written");
        (tool, input)
    }
}

/// A `TMOUT` of one second in the hook's environment sets no time limit on its read: an input whose
/// second line arrives after two and a half seconds reaches both readers whole. The hook's text without
/// its `TMOUT=0` is the arm where the limit ends the read after the first line: that hook exits 1 with
/// the sentence of an input not read to its end and starts no launcher, so a part of the input passes to
/// no reader.
#[test]
fn pre_push_reads_past_a_time_limit_of_its_environment_and_passes_on_no_partial_input() {
    let repo = Repo::new("pre-push-time-limit");
    let hooks = repo.guard(KEEPER);
    let checked = hook_text();
    let (first, second) = (b"a b c d\n", b"e f g h\n");

    let mut command = repo.hook_with(&checked, TOOL);
    command.env("TMOUT", "1");
    let (tool, mut input) = Repo::started(&mut command, first);
    std::thread::sleep(Duration::from_millis(2500));
    input.write_all(second).expect("the ref lines are written");
    drop(input);
    let done = finished(tool);
    assert_eq!(done.code, Some(37), "{done}");
    let whole = [&first[..], &second[..]].concat();
    let tool = fs::read(repo.path.join("tool.input")).expect("the launcher's input reads");
    let guard = fs::read(hooks.join("guard.input")).expect("the global hook's input reads");
    assert_eq!(tool, whole, "the launcher's input");
    assert_eq!(guard, whole, "the global hook's input");
    for name in ["tool.args", "tool.input"] {
        fs::remove_file(repo.path.join(name)).expect("the launcher's record is removed");
    }

    let limited = checked.replace("TMOUT=0 ", "");
    assert_ne!(limited, checked, "the hook's text holds `TMOUT=0 `");
    let mut command = repo.hook_with(&limited, TOOL);
    command.env("TMOUT", "1");
    let (tool, input) = Repo::started(&mut command, first);
    let done = finished(tool);
    drop(input);
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

/// The launcher's stand-in that, with `KILL_WRITER` set, first sends SIGKILL to every other child of the
/// hook and to each of that child's children, which are the processes that write the ref lines. It then
/// writes what it can read of its standard input to `tool.input` in the repository and exits 0.
const KILLER: &str = r#"#!/bin/sh
if [ -n "${KILL_WRITER-}" ]; then
  others=$(pgrep -P "$PPID") || exit 99
  for writer in $others; do
    [ "$writer" = "$$" ] && continue
    kill -KILL $(pgrep -P "$writer") "$writer" || exit 99
  done
fi
cat > "$(dirname -- "$0")/../tool.input"
"#;

/// A writer of the ref lines that a signal ends fails the push though the launcher exits 0: the hook
/// exits 137 on SIGKILL, the launcher has read a part of the lines, and the global hook does not start.
/// The input, a thousand lines, is more than a pipe holds, so the writer is still writing when the
/// stand-in starts. Without the signal the same arrangement exits 0 with every byte at the launcher.
#[test]
fn pre_push_fails_when_a_signal_ends_the_writer_of_the_ref_lines() {
    let repo = Repo::new("pre-push-writer");
    let hooks = repo.guard(DEAF_GUARD);
    let checked = hook_text();
    let input = ref_lines(1_000);
    let mut command = repo.hook_with(&checked, KILLER);
    command.env("KILL_WRITER", "1");
    let done = finished(spawn_with_input(&mut command, &input));
    assert_eq!(done.code, Some(137), "{done}");
    let tool = fs::read(repo.path.join("tool.input")).expect("the launcher's input reads");
    assert!(
        tool.len() < input.len() && input.as_bytes().starts_with(&tool),
        "the launcher read {} bytes of {}: {done}",
        tool.len(),
        input.len()
    );
    assert!(!hooks.join("guard.ran").exists(), "the global hook started");

    let mut command = repo.hook_with(&checked, KILLER);
    let done = finished(spawn_with_input(&mut command, &input));
    assert_eq!(done.code, Some(0), "{done}");
    let tool = fs::read(repo.path.join("tool.input")).expect("the launcher's input reads");
    assert!(tool == input.as_bytes(), "the launcher's input differs");
    assert!(
        hooks.join("guard.ran").exists(),
        "the global hook starts after a writer that ended on its own"
    );
}
