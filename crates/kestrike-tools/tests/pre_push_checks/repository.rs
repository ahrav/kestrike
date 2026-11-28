//! A scratch repository for the rows that read Git, and the child that reads it. A row builds its
//! repository in the test process, then starts this test executable again for the same test with
//! [`ROLE`] set, in the repository and in its environment alone, so the library's Git reads find the
//! scratch repository and the row's environment, and the test process's own working directory and
//! environment stay as they are. The child reads the row's values from variables named `ROW_<name>`.

use std::ffi::{OsStr, OsString};
use std::fs::{self, DirBuilder};
use std::os::unix::fs::{DirBuilderExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// The variable that tells the child it runs a row's reads.
const ROLE: &str = "KESTRIKE_PRE_PUSH_ROW";

pub const ZERO: &str = "0000000000000000000000000000000000000000";

/// The stub every check script of the fixtures holds; the library starts no check, so its text is inert.
pub const STUB: &str = "import sys\nsys.exit(0)\n";

/// `child` returns the row's values when this process is the child of a row.
pub fn child() -> Option<Values> {
    std::env::var_os(ROLE).map(|_| Values)
}

/// The values a row passed to its child.
pub struct Values;

impl Values {
    /// `get` reads the value `name`.
    pub fn get(&self, name: &str) -> String {
        std::env::var(format!("ROW_{name}")).unwrap_or_else(|_| panic!("the row passes {name}"))
    }
}

/// A repository of its own in a new directory of mode 0700 under `CARGO_TARGET_TMPDIR`, which drop removes,
/// with an environment that keeps the caller's Git configuration and identity out.
pub struct Repository {
    temp: PathBuf,
    pub top: PathBuf,
    env: Vec<(OsString, OsString)>,
}

impl Drop for Repository {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.temp);
    }
}

impl Repository {
    /// `new` makes an empty repository on the branch `main`, in a directory it creates under a name no
    /// other entry holds; a name another entry holds is left alone and the next is tried.
    pub fn new(name: &str) -> Self {
        let root = Path::new(env!("CARGO_TARGET_TMPDIR"));
        fs::create_dir_all(root).expect("the scratch root is made");
        let temp = (0..1000)
            .map(|at| {
                root.join(format!(
                    "kestrike-pre-push-{name}-{}-{at}",
                    std::process::id()
                ))
            })
            .find(|temp| DirBuilder::new().mode(0o700).create(temp).is_ok())
            .expect("a new scratch directory is made");
        let top = temp.join("repo");
        fs::create_dir(&top).expect("the repository directory is made");
        let mut env: Vec<(OsString, OsString)> = std::env::vars_os()
            .filter(|(key, _)| {
                let key = key.to_string_lossy();
                !key.starts_with("GIT_") && !key.starts_with("GITHUB_") && !key.starts_with("ROW_")
            })
            .collect();
        for (key, value) in [
            ("GIT_CONFIG_NOSYSTEM", OsString::from("1")),
            ("GIT_CONFIG_GLOBAL", temp.join("global").into_os_string()),
            ("GIT_CEILING_DIRECTORIES", temp.clone().into_os_string()),
            ("GIT_AUTHOR_NAME", OsString::from("t")),
            ("GIT_AUTHOR_EMAIL", OsString::from("t@example.com")),
            ("GIT_COMMITTER_NAME", OsString::from("t")),
            ("GIT_COMMITTER_EMAIL", OsString::from("t@example.com")),
        ] {
            env.push((OsString::from(key), value));
        }
        let repository = Self { temp, top, env };
        repository.git(&["init", "-q", "-b", "main"]);
        repository
    }

    /// `command` starts `program` in the repository with the repository's environment alone.
    pub fn command(&self, program: impl AsRef<OsStr>) -> Command {
        let mut command = Command::new(program);
        command
            .env_clear()
            .envs(self.env.iter().cloned())
            .current_dir(&self.top);
        command
    }

    /// `git` runs `git args`, fails the row unless it passes, and returns its trimmed standard output.
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

    /// `commit` writes each file, stages it, commits, and returns the commit.
    pub fn commit(&self, files: &[(&str, &str)]) -> String {
        for (name, content) in files {
            let path = self.top.join(name);
            fs::create_dir_all(path.parent().expect("a file has a parent"))
                .expect("the parent is made");
            fs::write(path, content).expect("the file is written");
            self.git(&["add", "--", name]);
        }
        self.git(&["commit", "-q", "--allow-empty", "-m", "change"]);
        self.git(&["rev-parse", "HEAD"])
    }

    /// `link` commits `name` as a link to `target` in place of what stood there, and returns the commit.
    pub fn link(&self, name: &str, target: &str) -> String {
        let path = self.top.join(name);
        if path.symlink_metadata().is_ok() {
            self.git(&["rm", "-rq", "--", name]);
        }
        fs::create_dir_all(path.parent().expect("a link has a parent"))
            .expect("the parent is made");
        symlink(target, &path).expect("the link is made");
        self.git(&["add", "--", name]);
        self.git(&["commit", "-q", "-m", "link"]);
        self.git(&["rev-parse", "HEAD"])
    }

    /// `set` gives the child's environment `name` with `value`.
    pub fn set(&mut self, name: &str, value: &str) {
        self.env.retain(|(key, _)| key != name);
        self.env.push((OsString::from(name), OsString::from(value)));
    }

    /// `in_child` starts this test executable again for the test `id` in the repository, with `values`
    /// passed as `ROW_<name>` variables, fails the row unless that run passes, and returns the run's output.
    pub fn in_child(&self, id: &str, values: &[(&str, &str)]) -> Output {
        self.in_child_at(&self.top, id, values)
    }

    /// `in_child_at` is [`Repository::in_child`] with the child started in `dir`.
    pub fn in_child_at(&self, dir: &Path, id: &str, values: &[(&str, &str)]) -> Output {
        self.in_child_with(dir, id, values, &[])
    }

    /// `in_child_with` is [`Repository::in_child_at`] with `extra` added to the child's environment alone.
    pub fn in_child_with(
        &self,
        dir: &Path,
        id: &str,
        values: &[(&str, &str)],
        extra: &[(&str, &OsStr)],
    ) -> Output {
        let output = self
            .command(std::env::current_exe().expect("the test executable is known"))
            .envs(extra.iter().copied())
            .current_dir(dir)
            .args(["--exact", id, "--nocapture", "--test-threads", "1"])
            .env(ROLE, "1")
            .envs(
                values
                    .iter()
                    .map(|(name, value)| (format!("ROW_{name}"), *value)),
            )
            .stdin(Stdio::null())
            .output()
            .expect("the test executable starts");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let shown = format!(
            "{id}: {}\n{stdout}{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.status.success(), "{shown}");
        assert!(stdout.contains("1 passed"), "{shown}");
        output
    }
}

pub use crate::case_id as id;
