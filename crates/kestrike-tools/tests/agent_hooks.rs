//! Cases for the checkout's comment-marker scan, its commit hook, its ignore rules and its pre-push hook.
//! A pre-push case runs a copy of `.githooks/pre-push` beside a stand-in `scripts/tool.sh` that writes its
//! arguments to `tool.args` and its standard input to `tool.input` in the repository.

use std::fmt;
use std::fs::{self, DirBuilder};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use crate::pre_push_checks::push::{Run, executable, finished, spawn_with_input};

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
