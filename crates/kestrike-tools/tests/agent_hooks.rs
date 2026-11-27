//! Cases for the checkout's comment-marker scan.

use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
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
            .current_dir(&self.path)
            .stdin(Stdio::null());
        command
    }

    fn git(&self, args: &[&str]) {
        let done = run(self.command("git").args(args));
        assert!(
            done.status.success(),
            "git {args:?} exits {:?}: {}",
            done.status.code(),
            String::from_utf8_lossy(&done.stderr)
        );
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

fn run(command: &mut Command) -> Output {
    command.output().expect("the child starts")
}

#[test]
fn clean_staged_file_passes() {
    let repo = Repo::new("clean");
    repo.stage("a.rs", "let value = 1;\n");
    assert_eq!(run(repo.scan().arg("--staged")).status.code(), Some(0));
}

#[test]
fn marker_reports_file_and_line() {
    let repo = Repo::new("report");
    repo.stage("clean.rs", "let a = 1;\nlet b = 2;\n");
    let content = format!("let value = 1;\n// {}\n", MARKER.to_uppercase());
    repo.stage("file with spaces.rs", &content);
    let done = run(repo.scan().arg("--staged"));
    let stderr = String::from_utf8_lossy(&done.stderr);
    assert_eq!(done.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("file with spaces.rs:2:"), "{stderr}");
    assert!(!stderr.contains("clean.rs:"), "{stderr}");
}

#[test]
fn leading_plus_does_not_hide_marker() {
    let repo = Repo::new("plus");
    repo.stage("a.rs", &format!("let value = 1;\n+value; // {MARKER}\n"));
    assert_eq!(run(repo.scan().arg("--staged")).status.code(), Some(1));
}

#[test]
fn unstaged_cleanup_does_not_hide_staged_marker() {
    let repo = Repo::new("unstaged");
    repo.stage("a.rs", &format!("// {MARKER}\n"));
    fs::write(repo.path.join("a.rs"), "// A plain comment.\n").expect("the file is written");
    assert_eq!(run(repo.scan().arg("--staged")).status.code(), Some(1));
    assert_eq!(run(&mut repo.scan()).status.code(), Some(0));
}

#[test]
fn full_scan_rejects_marker() {
    let repo = Repo::new("full");
    repo.stage("a.rs", &format!("// {MARKER}\n"));
    assert_eq!(run(&mut repo.scan()).status.code(), Some(1));
}

#[test]
fn binary_attributes_do_not_hide_markers() {
    let repo = Repo::new("binary");
    let mut passed = Vec::new();
    for attribute in ["binary", "-diff"] {
        repo.stage(".gitattributes", &format!("*.rs {attribute}\n"));
        repo.stage("a.rs", &format!("// {MARKER}\n"));
        for args in [&[][..], &["--staged"][..]] {
            let code = run(repo.scan().args(args)).status.code();
            if code != Some(1) {
                passed.push((attribute, args, code));
            }
        }
    }
    assert!(passed.is_empty(), "rows that exit other than 1: {passed:?}");
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
        let check = ["check-ignore", "--quiet", "--", name];
        let code = run(repo.command("git").args(check)).status.code();
        if code != Some(0) {
            tracked.push((name, code));
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
    assert_eq!(run(repo.scan().current_dir(&nested)).status.code(), Some(1));
}

#[test]
fn staged_scan_ignores_textconv() {
    let repo = Repo::new("textconv");
    repo.stage(".gitattributes", "*.rs diff=hidden\n");
    repo.stage("a.rs", &format!("// {MARKER}\n"));
    repo.git(&["config", "diff.hidden.textconv", "true"]);
    assert_eq!(run(repo.scan().arg("--staged")).status.code(), Some(1));
}

#[test]
fn staged_scan_ignores_external_diff() {
    let repo = Repo::new("external");
    repo.stage("a.rs", &format!("// {MARKER}\n"));
    let mut scan = repo.scan();
    scan.arg("--staged").env("GIT_EXTERNAL_DIFF", "true");
    assert_eq!(run(&mut scan).status.code(), Some(1));
}

#[test]
fn git_failure_does_not_pass() {
    let repo = Repo::new("missing");
    let missing = repo.path.join("missing");
    let staged = run(repo.scan().arg("--staged").env("GIT_DIR", &missing));
    assert_ne!(staged.status.code(), Some(0));
    assert_eq!(
        run(repo.scan().env("GIT_DIR", &missing)).status.code(),
        Some(2)
    );
}

#[test]
fn pre_commit_runs_repository_check() {
    let repo = Repo::new("pre-commit");
    let scripts = repo.path.join("scripts");
    fs::create_dir(&scripts).expect("the directory is made");
    let script = top().join("scripts/forbid-comment-markers.sh");
    symlink(script, scripts.join("forbid-comment-markers.sh")).expect("the link is made");
    repo.stage("a.rs", &format!("// {MARKER}\n"));
    let hook = run(repo.command("bash").arg(top().join(".githooks/pre-commit")));
    assert_eq!(hook.status.code(), Some(1));
}
