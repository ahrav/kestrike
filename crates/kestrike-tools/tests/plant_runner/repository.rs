//! A fixture repository for the plant run's checks: a scratch directory of its own under
//! `CARGO_TARGET_TMPDIR`, mode 0700, holding a one-commit checkout with a plant store of two plants,
//! `alpha` and `beta`, an ignored `Cargo.lock`, hooks that must never run, a `campaign` file the user may
//! execute, and a temporary directory for the default work directory.
//!
//! Git is kept from the caller's configuration and identity: every Git command, the fixture's and the
//! checks', runs in an environment built from scratch, with no system configuration, a global
//! configuration file of the fixture's own, a home of its own and a ceiling at the scratch directory, so
//! no repository above it is found. The hooks append their names to `hook-ran` in the scratch directory;
//! the repository's `core.hooksPath` names them after the first commit.

use std::ffi::{OsStr, OsString};
use std::fs::{self, DirBuilder};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

use kestrike_tools::environ::{Environ, set};
use kestrike_tools::ownership::shared_directories;
use kestrike_tools::plants::{Outcome, prepare};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// The hooks the fixture installs; each records its name when Git runs it.
pub const HOOKS: [&str; 6] = [
    "pre-commit",
    "commit-msg",
    "post-commit",
    "post-checkout",
    "post-index-change",
    "reference-transaction",
];
pub const LIB: &str = "pub fn f() -> u8 {\n    1\n}\n";
pub const UTIL: &str = "pub fn g() -> u8 {\n    1\n}\n";
pub const LOCK: &str = "# a lockfile the checks read once\nversion = 4\n";
pub const CAMPAIGN: &str = "#!/bin/sh\nexit 0\n";

/// `patch` is a patch that changes line 2 of `file`, which holds [`LIB`] or [`UTIL`].
pub fn patch(file: &str) -> String {
    format!(
        "diff --git a/{file} b/{file}\n--- a/{file}\n+++ b/{file}\n@@ -1,3 +1,3 @@\n \
         pub fn {f}() -> u8 {{\n-    1\n+    2\n }}\n",
        f = if file == "src/lib.rs" { "f" } else { "g" },
    )
}

/// `members` are the members of a valid record of plant `id` that changes `file`, as JSON text in the
/// order of the record's fields.
pub fn members(id: &str, file: &str) -> Vec<(String, String)> {
    [
        ("id", format!("\"{id}\"")),
        ("row", "7".to_owned()),
        (
            "fix",
            "{\"pull_request\": 12, \"commit\": \"0123abc\"}".to_owned(),
        ),
        ("files", format!("[\"{file}\"]")),
        ("restores", "\"the defect the fix removed\"".to_owned()),
        ("proof", "\"tests::the_proof\"".to_owned()),
        ("expected", "[\"smoke\", \"crash-loop\"]".to_owned()),
        ("miss_cause", "null".to_owned()),
    ]
    .map(|(name, value)| (name.to_owned(), value))
    .to_vec()
}

/// `record` writes `members` as one JSON object.
pub fn record(members: &[(String, String)]) -> String {
    let joined: Vec<String> = members
        .iter()
        .map(|(name, value)| format!("\"{name}\": {value}"))
        .collect();
    format!("{{{}}}\n", joined.join(", "))
}

/// `replaced` is a valid record of `alpha` with the member `name` given the JSON text `value`.
pub fn replaced(name: &str, value: &str) -> String {
    let mut members = members("alpha", "src/lib.rs");
    for member in &mut members {
        if member.0 == name {
            member.1 = value.to_owned();
        }
    }
    record(&members)
}

fn host_path() -> OsString {
    std::env::var_os("PATH").unwrap_or_else(|| OsString::from("/usr/bin:/bin"))
}

/// A change a row makes to a fixture before the checks run.
pub type Change<'a> = &'a dyn Fn(&Repository);

/// A call of the checks: the arguments after the tool's name, the environment and the invoking
/// directory.
#[derive(Clone, Debug)]
pub struct Call {
    pub args: Vec<OsString>,
    pub env: Environ,
    pub here: PathBuf,
}

impl Call {
    pub fn set(mut self, name: &str, value: impl AsRef<OsStr>) -> Self {
        set(&mut self.env, name, value.as_ref().to_os_string());
        self
    }

    pub fn unset(mut self, name: &str) -> Self {
        self.env.retain(|(key, _)| key != name);
        self
    }

    pub fn here(mut self, here: impl AsRef<Path>) -> Self {
        self.here = here.as_ref().to_path_buf();
        self
    }
}

/// A fixture repository; its scratch directory is removed on drop, with every mode restored first.
pub struct Repository {
    pub scratch: PathBuf,
    pub top: PathBuf,
    pub tmp: PathBuf,
    pub bin: PathBuf,
    env: Environ,
}

/// `private_dir` makes `path` a directory of mode 0700 whatever the umask.
pub fn private_dir(path: &Path) {
    DirBuilder::new()
        .recursive(true)
        .create(path)
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    chmod(path, 0o700);
}

pub fn chmod(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .unwrap_or_else(|error| panic!("chmod {}: {error}", path.display()));
}

/// `executable` writes `text` at `path` with mode 0755 through a child process, the one process that holds
/// the file open for writing. `execve` refuses a file some process holds open for writing (`ETXTBSY`), and a
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

/// `write` writes `contents` to `path`, making its parent first.
pub fn write(path: &Path, contents: impl AsRef<[u8]>) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap_or_else(|error| panic!("{}: {error}", parent.display()));
    }
    fs::write(path, contents).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
}

/// `claimed` makes a new directory `plants-PID-N` under `base`, mode 0700 whatever the umask, taking the
/// next `N` while a name is taken, so the fixture never adopts or later removes a path it did not make.
fn claimed(base: &Path) -> PathBuf {
    loop {
        let scratch = base.join(format!(
            "plants-{}-{}",
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

/// `tree` lists every path under `root` but those under `skip`, in sorted order; a directory it cannot
/// list ends its branch.
fn tree(root: &Path, skip: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path == skip {
            continue;
        }
        found.push(path.clone());
        if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            tree(&path, skip, found);
        }
    }
    found.sort();
}

impl Repository {
    /// `new` builds the fixture with both plants committed.
    pub fn new() -> Self {
        let base = Path::new(env!("CARGO_TARGET_TMPDIR"));
        fs::create_dir_all(base).unwrap_or_else(|error| panic!("{}: {error}", base.display()));
        let base = base.canonicalize().expect("the scratch base resolves");
        let shared = shared_directories(&base).expect("the scratch base's ancestors stat");
        assert!(
            shared.is_empty(),
            "the checks refuse a work directory under {shared:?}, which another user can write; \
             make those directories private or move CARGO_TARGET_TMPDIR under a private directory"
        );
        let scratch = claimed(&base);
        let (top, tmp, bin, home) = (
            scratch.join("checkout"),
            scratch.join("tmp"),
            scratch.join("bin"),
            scratch.join("home"),
        );
        for directory in [&top, &tmp, &bin, &home] {
            private_dir(directory);
        }
        write(
            &home.join("gitconfig"),
            "[user]\n\tname = Fixture\n\temail = fixture@invalid\n[init]\n\tdefaultBranch = main\n\
             [commit]\n\tgpgSign = false\n",
        );
        executable(&bin.join("campaign"), CAMPAIGN);
        let mut path = bin.as_os_str().to_os_string();
        path.push(":");
        path.push(host_path());
        let env: Environ = [
            ("PATH", path),
            ("HOME", home.into_os_string()),
            ("LANG", OsString::from("C.UTF-8")),
            ("GIT_CONFIG_NOSYSTEM", OsString::from("1")),
            (
                "GIT_CONFIG_GLOBAL",
                scratch.join("home/gitconfig").into_os_string(),
            ),
            ("GIT_CEILING_DIRECTORIES", scratch.clone().into_os_string()),
            ("TMPDIR", tmp.clone().into_os_string()),
        ]
        .map(|(name, value)| (OsString::from(name), value))
        .to_vec();
        let repository = Self {
            scratch,
            top,
            tmp,
            bin,
            env,
        };
        repository.git(&["init", "--quiet"]);
        repository.write(".gitignore", "Cargo.lock\n");
        repository.write("Cargo.lock", LOCK);
        repository.write("src/lib.rs", LIB);
        repository.write("src/util.rs", UTIL);
        for (id, file) in [("alpha", "src/lib.rs"), ("beta", "src/util.rs")] {
            repository.write(
                &format!("verification/plants/{id}/plant.json"),
                record(&members(id, file)),
            );
            repository.write(
                &format!("verification/plants/{id}/plant.patch"),
                patch(file),
            );
        }
        repository.commit();
        let hooks = repository.scratch.join("hooks");
        private_dir(&hooks);
        for hook in HOOKS {
            let ran = repository.scratch.join("hook-ran");
            executable(
                &hooks.join(hook),
                &format!("#!/bin/sh\necho {hook} >> '{}'\n", ran.display()),
            );
        }
        repository.git(&["config", "core.hooksPath", hooks.to_str().expect("UTF-8")]);
        repository
    }

    /// The environment every call of the checks starts from.
    pub fn env(&self) -> Environ {
        self.env.clone()
    }

    /// `call` is a call of the checks from the checkout's top with `args`.
    pub fn call(&self, args: &[&str]) -> Call {
        Call {
            args: args.iter().map(OsString::from).collect(),
            env: self.env(),
            here: self.top.clone(),
        }
    }

    /// `git` runs the host's Git in the checkout with the fixture's environment and hooks off, and returns
    /// its output.
    pub fn git(&self, args: &[&str]) -> String {
        let mut hooks_off = vec!["-c", "core.hooksPath=/dev/null"];
        hooks_off.extend_from_slice(args);
        self.hooked_git(&hooks_off)
    }

    /// `hooked_git` runs the host's Git as [`Repository::git`] does with the repository's hooks on.
    pub fn hooked_git(&self, args: &[&str]) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.top)
            .args(args)
            .env_clear()
            .envs(self.env.iter().cloned())
            .output()
            .expect("git starts");
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).expect("Git's output is UTF-8")
    }

    /// `commit` commits every change of the checkout.
    pub fn commit(&self) {
        self.git(&["add", "--all"]);
        self.git(&["commit", "--quiet", "--no-verify", "-m", "plants"]);
    }

    pub fn path(&self, relative: &str) -> PathBuf {
        self.top.join(relative)
    }

    /// `write` writes `contents` at `relative` under the checkout's top.
    pub fn write(&self, relative: &str, contents: impl AsRef<[u8]>) {
        write(&self.path(relative), contents);
    }

    /// `head` is the head commit's object name.
    pub fn head(&self) -> String {
        self.git(&["rev-parse", "HEAD"]).trim().to_owned()
    }

    /// `status` is `git status` of the whole checkout, ignored files included.
    pub fn status(&self) -> String {
        self.git(&[
            "--no-optional-locks",
            "status",
            "--porcelain",
            "--untracked-files=all",
            "--ignored",
        ])
    }

    /// `hooks_ran` is what the hooks recorded, empty when none ran.
    pub fn hooks_ran(&self) -> String {
        fs::read_to_string(self.scratch.join("hook-ran")).unwrap_or_default()
    }

    /// `paths` lists every path of the scratch directory outside the checkout's `.git`.
    pub fn paths(&self) -> Vec<PathBuf> {
        let mut found = Vec::new();
        tree(&self.scratch, &self.top.join(".git"), &mut found);
        found
    }

    /// `prepare` runs the checks for `call`.
    pub fn prepare(&self, call: &Call) -> Outcome {
        prepare(&call.args, call.env.clone(), Ok(call.here.clone()))
    }

    /// `refused` runs the checks for `call`, which must stop, and returns the stop as `rejected: REASON`,
    /// `failed: REASON` or `usage: LAST LINE`. The checks must leave every path of the scratch directory
    /// and the checkout's `git status` as they were.
    pub fn refused(&self, call: &Call) -> String {
        let (paths, status) = (self.paths(), self.status());
        let found = match self.prepare(call) {
            Outcome::Rejected(reason) => format!("rejected: {reason}"),
            Outcome::Failed(reason) => format!("failed: {reason}"),
            Outcome::Usage { code, text } => {
                assert_eq!(code, 2, "{text}");
                let last = text.lines().last().unwrap_or_default().to_owned();
                format!("usage: {last}")
            }
            other => panic!("{:?} stops, not {other:?}", call.args),
        };
        let after = self.paths();
        let made: Vec<&PathBuf> = after.iter().filter(|path| !paths.contains(path)).collect();
        let removed: Vec<&PathBuf> = paths.iter().filter(|path| !after.contains(path)).collect();
        assert!(
            made.is_empty() && removed.is_empty(),
            "{:?} makes {made:?} and removes {removed:?}",
            call.args
        );
        assert_eq!(self.status(), status, "{:?} changes git status", call.args);
        found
    }
}

impl Drop for Repository {
    fn drop(&mut self) {
        let mut found = Vec::new();
        tree(&self.scratch, Path::new(""), &mut found);
        for path in [&self.scratch].into_iter().chain(&found) {
            if fs::symlink_metadata(path).is_ok_and(|status| status.is_dir()) {
                let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
            }
        }
        let _ = fs::remove_dir_all(&self.scratch);
    }
}

/// `is_root` holds when the process runs as root, which every permission bit lets through.
pub fn is_root() -> bool {
    // SAFETY: `geteuid` takes no argument and always succeeds.
    unsafe { libc::geteuid() == 0 }
}

/// `shown` turns a path's bytes into text for an expected reason.
pub fn shown(path: &Path) -> String {
    String::from_utf8(path.as_os_str().as_bytes().to_vec()).expect("a fixture path is UTF-8")
}
