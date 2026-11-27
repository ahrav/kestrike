//! Cases for the checkout's comment-marker scan, its commit hook and its ignore rules.

use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

const MARKER: &str = concat!("commentlin", "t: allow(JUDGE)");

/// The checkout the executable was built from, two levels above the package.
fn top() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the package stands two levels below the checkout's top")
}

/// A Git repository in a fresh directory under `CARGO_TARGET_TMPDIR`, removed when the value drops.
struct Repo {
    path: PathBuf,
}

impl Repo {
    /// `Repo::new` retries name collisions to preserve directories left by interrupted runs.
    fn new(case: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let scratch = Path::new(env!("CARGO_TARGET_TMPDIR"));
        fs::create_dir_all(scratch).expect("the scratch directory is made");
        let path = loop {
            let at = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = scratch.join(format!("agent-hooks-{case}-{}-{at}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => break path,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
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
        let (code, stderr) = exit(self.command("git").args(args));
        assert_eq!(code, Some(0), "git {args:?}: {stderr}");
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

fn exit(command: &mut Command) -> (Option<i32>, String) {
    let done = command.output().expect("the child starts");
    String::from_utf8(done.stdout).expect("standard output is UTF-8");
    let stderr = String::from_utf8(done.stderr).expect("standard error is UTF-8");
    (done.status.code(), stderr)
}

#[test]
fn clean_staged_file_passes() {
    let repo = Repo::new("clean");
    repo.stage("a.rs", "let value = 1;\n");
    let (code, stderr) = exit(repo.scan().arg("--staged"));
    assert_eq!(code, Some(0), "{stderr}");
}

#[test]
fn marker_reports_file_and_line() {
    let repo = Repo::new("report");
    repo.stage("clean.rs", "let a = 1;\nlet b = 2;\n");
    let content = format!("let value = 1;\n// {}\n", MARKER.to_uppercase());
    repo.stage("file with spaces.rs", &content);
    let (code, stderr) = exit(repo.scan().arg("--staged"));
    assert_eq!(code, Some(1), "{stderr}");
    assert!(stderr.contains("file with spaces.rs:2:"), "{stderr}");
    assert!(!stderr.contains("clean.rs:"), "{stderr}");
}

#[test]
fn leading_plus_does_not_hide_marker() {
    let repo = Repo::new("plus");
    repo.stage("a.rs", &format!("let value = 1;\n+value; // {MARKER}\n"));
    let (code, stderr) = exit(repo.scan().arg("--staged"));
    assert_eq!(code, Some(1), "{stderr}");
}

#[test]
fn unstaged_cleanup_does_not_hide_staged_marker() {
    let repo = Repo::new("unstaged");
    repo.stage("a.rs", &format!("// {MARKER}\n"));
    fs::write(repo.path.join("a.rs"), "// A plain comment.\n").expect("the file is written");
    let (code, stderr) = exit(repo.scan().arg("--staged"));
    assert_eq!(code, Some(1), "{stderr}");
    let (code, stderr) = exit(&mut repo.scan());
    assert_eq!(code, Some(0), "{stderr}");
}

#[test]
fn full_scan_rejects_marker() {
    let repo = Repo::new("full");
    repo.stage("a.rs", &format!("// {MARKER}\n"));
    let (code, stderr) = exit(&mut repo.scan());
    assert_eq!(code, Some(1), "{stderr}");
}

#[test]
fn binary_attributes_do_not_hide_markers() {
    let repo = Repo::new("binary");
    let mut unblocked = Vec::new();
    for attribute in ["binary", "-diff"] {
        repo.stage(".gitattributes", &format!("*.rs {attribute}\n"));
        repo.stage("a.rs", &format!("// {MARKER}\n"));
        for args in [&[][..], &["--staged"][..]] {
            let (code, stderr) = exit(repo.scan().args(args));
            if code != Some(1) {
                unblocked.push((attribute, args, code, stderr));
            }
        }
    }
    assert!(
        unblocked.is_empty(),
        "rows that exit other than 1: {unblocked:?}"
    );
}

#[test]
fn retired_local_artifacts_remain_ignored() {
    let repo = Repo::new("ignored");
    fs::copy(top().join(".gitignore"), repo.path.join(".gitignore")).expect("the rules are copied");
    let mut tracked = Vec::new();
    for name in [".bv/cache.json", ".perles/config.yaml"] {
        let path = repo.path.join(name);
        fs::create_dir_all(path.parent().expect("the path has a parent"))
            .expect("the directory is made");
        fs::write(&path, "local configuration\n").expect("the file is written");
        let (code, stderr) =
            exit(
                repo.command("git")
                    .args(["check-ignore", "--quiet", "--", name]),
            );
        if code != Some(0) {
            tracked.push((name, code, stderr));
        }
    }
    assert!(
        tracked.is_empty(),
        "paths that check-ignore does not report: {tracked:?}"
    );
}

#[test]
fn full_scan_includes_parent_directories() {
    let repo = Repo::new("nested");
    repo.stage("a.rs", &format!("// {MARKER}\n"));
    let nested = repo.path.join("nested");
    fs::create_dir(&nested).expect("the directory is made");
    let (code, stderr) = exit(repo.scan().current_dir(&nested));
    assert_eq!(code, Some(1), "{stderr}");
}

#[test]
fn staged_scan_ignores_textconv() {
    let repo = Repo::new("textconv");
    repo.stage(".gitattributes", "*.rs diff=hidden\n");
    repo.stage("a.rs", &format!("// {MARKER}\n"));
    repo.git(&["config", "diff.hidden.textconv", "true"]);
    let (code, stderr) = exit(repo.scan().arg("--staged"));
    assert_eq!(code, Some(1), "{stderr}");
}

#[test]
fn staged_scan_ignores_external_diff() {
    let repo = Repo::new("external");
    repo.stage("a.rs", &format!("// {MARKER}\n"));
    let (code, stderr) = exit(repo.scan().arg("--staged").env("GIT_EXTERNAL_DIFF", "true"));
    assert_eq!(code, Some(1), "{stderr}");
}

#[test]
fn git_failure_does_not_pass() {
    let repo = Repo::new("missing");
    let missing = repo.path.join("missing");
    let (code, stderr) = exit(repo.scan().arg("--staged").env("GIT_DIR", &missing));
    assert_ne!(code, Some(0), "{stderr}");
    let (code, stderr) = exit(repo.scan().env("GIT_DIR", &missing));
    assert_eq!(code, Some(2), "{stderr}");
}

#[test]
fn pre_commit_runs_repository_check() {
    let repo = Repo::new("pre-commit");
    let scripts = repo.path.join("scripts");
    fs::create_dir(&scripts).expect("the directory is made");
    let script = top().join("scripts/forbid-comment-markers.sh");
    symlink(script, scripts.join("forbid-comment-markers.sh")).expect("the link is made");
    repo.stage("a.rs", &format!("// {MARKER}\n"));
    let (code, stderr) = exit(repo.command("bash").arg(top().join(".githooks/pre-commit")));
    assert_eq!(code, Some(1), "{stderr}");
}
