//! A run's fixture: a scratch directory of its own under `CARGO_TARGET_TMPDIR`, mode 0700, holding a
//! repository whose one file `mode` reads `base`, a plant store, the head's helper and selector under
//! `scripts/`, a `post-checkout` hook that records each tree it runs in, and the stand-ins of
//! `campaign` and `python3`. Each plant's patch rewrites `mode`, which the stand-ins read.
//!
//! The store starts with the plants of [`PLANTS`], and [`Fixture::stock`] adds each plant of
//! [`extra`] a run names, so a run checks the plants its case uses. Every Git command of the fixture and
//! of the tool runs with the caller's Git variables removed and the system and global configuration
//! replaced by files of the fixture. The tool runs as `kestrike-tools TOP plant-runner ARGS`, a child
//! process, with the checkout as its directory.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, DirBuilder};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use kestrike_tools::json::{self, Object, Value};

use super::repository::{chmod, executable, write};
use super::standins::wrapper;

pub const BINARY: &str = env!("CARGO_BIN_EXE_kestrike-tools");
static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// The fixture's helper: the lines the `python3` stand-in reads, its `RESULTS` and its `reported`.
pub const HELPER: &str = "#!/usr/bin/env python3
import json, os, signal, sys, time
RESULTS = {0: \"not reproduced\", 1: \"reproduced\", 2: \"rejected input\", 3: \"build failure\", 4: \"crash\", 6: \"watchdog expiry\"}

def reported(code, verdict):
    return code in (0, 1, 6) and verdict.startswith(RESULTS[code])
";

pub const CAUSE: &str = r#"{"cause": "workload", "evidence": "No run reaches the planted state."}"#;

/// A plant of the store: the mode its patch writes, its expected profiles, its `miss_cause` as JSON and
/// the line its patch replaces.
pub type Planted = (
    &'static str,
    &'static [&'static str],
    &'static str,
    &'static str,
);

/// The plants of the default store.
pub const PLANTS: [(&str, Planted); 11] = [
    ("p-catch", ("catch", &["a", "b"], "null", "base")),
    ("p-miss", ("pass", &["a"], CAUSE, "base")),
    ("p-nocause", ("pass", &["a"], "null", "base")),
    (
        "p-noprofile",
        (
            "pass",
            &[],
            r#"{"cause": "environment", "evidence": "No profile runs the file."}"#,
            "base",
        ),
    ),
    ("p-stale", ("pass", &["a"], CAUSE, "other")),
    ("p-nobuild", ("nobuild", &["a"], CAUSE, "base")),
    ("p-alarm", ("alarm", &["a"], CAUSE, "base")),
    ("p-headfail", ("headfail", &["a"], CAUSE, "base")),
    ("p-refuse", ("refuse", &["a"], CAUSE, "base")),
    ("p-other", ("other", &["a"], CAUSE, "base")),
    ("p-short", ("short", &["a"], CAUSE, "base")),
];

/// Plants for the cases of one test each, kept out of the default store: each is `p-<mode>`, sweeps `a`,
/// has a cause and replaces the line `base`.
pub const MODES: [&str; 89] = [
    "panic",
    "hangconfirm",
    "hangseed",
    "catchalarm",
    "second",
    "passthenfail",
    "dup",
    "mismatch",
    "watchdog",
    "rejectseed",
    "history",
    "hang",
    "hangbuild",
    "oddthen",
    "violatehead",
    "lonehead",
    "otherprofile",
    "otherseed",
    "laterfinding",
    "nomanifest",
    "damaged",
    "queued",
    "held",
    "heldnone",
    "heldother",
    "nopass",
    "unreached",
    "nocount",
    "wide",
    "badline",
    "dirlog",
    "deepconfirm",
    "refusedarchive",
    "lock",
    "othermanifest",
    "noid",
    "boolrun",
    "confirmfail",
    "noresult",
    "otherlock",
    "nolock",
    "loneline",
    "cutline",
    "disorder",
    "othercampaign",
    "exitone",
    "rootsuspect",
    "statusfail",
    "booltotal",
    "floattotal",
    "oddfinding",
    "notlive",
    "brokenproof",
    "hangproof",
    "silentpass",
    "silentfail",
    "relock",
    "unlock",
    "pintarget",
    "watchproof",
    "rejectproof",
    "crashproof",
    "swappass",
    "swapfail",
    "trailfail",
    "replaydiffers",
    "replayonly",
    "badrun",
    "replayunlisted",
    "replaylisted",
    "otherunlisted",
    "manyviolations",
    "nokeys",
    "oddkeys",
    "emptykeys",
    "shortkeys",
    "lowkey",
    "oddpass",
    "twopass",
    "heldrejected",
    "heldomitted",
    "heldmixed",
    "heldpaused",
    "norun",
    "overrun",
    "badbytes",
    "othercounts",
    "historynocount",
    "nowindow",
];

/// Plants that need a signal or leave the proof's worktree or target unfit for every later plant.
pub const APART: [&str; 8] = [
    "p-hang",
    "p-hangconfirm",
    "p-hangseed",
    "p-hangbuild",
    "p-hangproof",
    "p-relock",
    "p-unlock",
    "p-pintarget",
];

/// `extra` is the plant `name` outside the default store, when one is named so.
pub fn extra(name: &str) -> Option<Planted> {
    let planted: Planted = match name {
        "p-gapfirst" => ("gapfirst", &["a", "gap"], CAUSE, "base"),
        "p-gaplast" => ("gaplast", &["a", "gap"], CAUSE, "base"),
        "p-nolockarchive" => ("nolockarchive", &[], CAUSE, "base"),
        "p-slow" => ("pass", &["a", "slow"], CAUSE, "base"),
        "p-catchbroken" => ("catchbroken", &["a", "ghost"], CAUSE, "base"),
        "p-replayelsewhere" => ("replayelsewhere", &["a", "b"], CAUSE, "base"),
        "base" => ("catch", &["a"], CAUSE, "base"),
        _ => {
            let mode = name.strip_prefix("p-")?;
            let mode = MODES.iter().find(|known| **known == mode)?;
            (mode, &["a"], CAUSE, "base")
        }
    };
    Some(planted)
}

/// Every plant outside the default store, in a fixed order.
pub fn extras() -> Vec<String> {
    let mut names: Vec<String> = MODES.iter().map(|mode| format!("p-{mode}")).collect();
    for name in [
        "p-gapfirst",
        "p-gaplast",
        "p-nolockarchive",
        "p-slow",
        "p-catchbroken",
        "p-replayelsewhere",
        "base",
    ] {
        names.push(name.to_owned());
    }
    names
}

pub fn patch_of(mode: &str, before: &str) -> String {
    format!("--- a/mode\n+++ b/mode\n@@ -1 +1 @@\n-{before}\n+{mode}\n")
}

/// `json_text` is `text` as a JSON string.
pub fn json_text(text: &str) -> String {
    json::text(&Value::String(text.into()))
}

/// `write_plant` writes the plant `name` under `store`: its record, with each of `fields` replacing or
/// adding a member given as JSON text, and its patch, `patch` or the patch of `mode` over `before`.
pub fn write_plant(
    store: &Path,
    name: &str,
    (mode, expected, cause, before): Planted,
    fields: &[(&str, &str)],
    patch: Option<&str>,
) -> PathBuf {
    let place = store.join(name);
    fs::create_dir_all(&place).expect("the plant's directory is made");
    let expected: Vec<String> = expected.iter().map(|profile| json_text(profile)).collect();
    let mut members: Vec<(String, String)> = [
        ("id", json_text(name)),
        ("row", "1".to_owned()),
        (
            "fix",
            format!(
                "{{\"pull_request\": 1, \"commit\": \"{}\"}}",
                "0".repeat(40)
            ),
        ),
        ("files", "[\"mode\"]".to_owned()),
        ("restores", "\"A defect.\"".to_owned()),
        ("proof", "\"a::test\"".to_owned()),
        ("expected", format!("[{}]", expected.join(", "))),
        ("miss_cause", cause.to_owned()),
    ]
    .map(|(key, value)| (key.to_owned(), value))
    .to_vec();
    for (key, value) in fields {
        match members.iter_mut().find(|(name, _)| name == key) {
            Some(member) => member.1 = (*value).to_owned(),
            None => members.push(((*key).to_owned(), (*value).to_owned())),
        }
    }
    let joined: Vec<String> = members
        .iter()
        .map(|(key, value)| format!("\"{key}\": {value}"))
        .collect();
    write(
        &place.join("plant.json"),
        format!("{{{}}}", joined.join(", ")),
    );
    write(
        &place.join("plant.patch"),
        patch.map_or_else(|| patch_of(mode, before), str::to_owned),
    );
    place
}

/// One finished run of the tool: its exit and both streams.
#[derive(Debug)]
pub struct Done {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// `claimed` makes a new directory `run-PID-N` under `base`, mode 0700, taking the next `N` while a
/// name is taken.
fn claimed(base: &Path) -> PathBuf {
    loop {
        let scratch = base.join(format!(
            "run-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        match DirBuilder::new().create(&scratch) {
            Ok(()) => {
                chmod(&scratch, 0o700);
                return scratch
                    .canonicalize()
                    .expect("the scratch directory resolves");
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("{}: {error}", scratch.display()),
        }
    }
}

/// One repository, plant store and pair of stand-ins a case; the scratch directory goes on drop.
pub struct Fixture {
    pub scratch: PathBuf,
    pub repo: PathBuf,
    pub store: PathBuf,
    pub score: PathBuf,
    pub work: PathBuf,
    pub log: PathBuf,
    pub proofs: PathBuf,
    pub hooked: PathBuf,
    pub stand_in: PathBuf,
    pub bin: PathBuf,
    pub head: String,
    pub env: Vec<(OsString, OsString)>,
}

impl Fixture {
    /// `new` builds the repository with the default store committed.
    pub fn new() -> Self {
        let base = Path::new(env!("CARGO_TARGET_TMPDIR"));
        fs::create_dir_all(base).expect("the scratch base is made");
        let scratch = claimed(base);
        let (repo, standins) = (scratch.join("repo"), scratch.join("standins"));
        for directory in [&repo, &standins] {
            fs::create_dir(directory).expect("a fixture directory is made");
        }
        write(&scratch.join("gitconfig"), "");
        let mut path = standins.clone().into_os_string();
        path.push(":");
        path.push(std::env::var_os("PATH").unwrap_or_else(|| OsString::from("/usr/bin:/bin")));
        let mut env: Vec<(OsString, OsString)> = std::env::vars_os()
            .filter(|(name, _)| {
                let name = name.to_string_lossy();
                !name.starts_with("GIT_") && name != "PATH" && name != super::standins::ROLE
            })
            .collect();
        for (name, value) in [
            ("GIT_CONFIG_NOSYSTEM", OsString::from("1")),
            (
                "GIT_CONFIG_GLOBAL",
                scratch.join("gitconfig").into_os_string(),
            ),
            ("GIT_CEILING_DIRECTORIES", scratch.clone().into_os_string()),
            ("GIT_AUTHOR_NAME", OsString::from("fixture")),
            ("GIT_AUTHOR_EMAIL", OsString::from("fixture@invalid")),
            ("GIT_COMMITTER_NAME", OsString::from("fixture")),
            ("GIT_COMMITTER_EMAIL", OsString::from("fixture@invalid")),
            ("PATH", path),
        ] {
            env.push((OsString::from(name), value));
        }
        executable(&standins.join("python3"), &wrapper("python3"));
        let stand_in = scratch.join("campaign");
        executable(&stand_in, &wrapper("campaign"));
        let store = repo.join("verification").join("plants");
        let mut fixture = Self {
            score: store.join("score.json"),
            work: scratch.join("work"),
            log: scratch.join("calls.jsonl"),
            proofs: scratch.join("proofs.jsonl"),
            hooked: scratch.join("hooked"),
            bin: scratch.join("bin"),
            store,
            stand_in,
            repo,
            scratch,
            head: String::new(),
            env,
        };
        fixture.git(&["init", "--quiet"]);
        write(&fixture.repo.join("mode"), "base\n");
        write(&fixture.repo.join(".gitignore"), "Cargo.lock\n");
        write(
            &fixture.repo.join("Cargo.lock"),
            "# the checkout's resolution\n",
        );
        executable(
            &fixture.repo.join(".git/hooks/post-checkout"),
            &format!(
                "#!/bin/sh\necho \"$PWD\" >> '{}'\n",
                fixture.hooked.display()
            ),
        );
        write(&fixture.repo.join("scripts/reproduce-test.py"), HELPER);
        write(&fixture.repo.join("scripts/select-tests.py"), "");
        write(&fixture.proofs, "");
        write(&fixture.log, "");
        for (name, planted) in PLANTS {
            write_plant(&fixture.store, name, planted, &[], None);
        }
        fixture.commit("fixture");
        fixture
    }

    /// `git` runs Git in the repository with the fixture's environment and returns its output.
    pub fn git(&self, args: &[&str]) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.repo)
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

    /// `commit` commits every change and reads the new head.
    pub fn commit(&mut self, message: &str) {
        self.git(&["add", "--all"]);
        self.git(&["commit", "--quiet", "--no-gpg-sign", "--message", message]);
        self.head = self.git(&["rev-parse", "HEAD"]).trim().to_owned();
    }

    /// `stock` writes each named plant outside the default store that the store lacks and commits those
    /// plants alone, which moves the head.
    pub fn stock(&mut self, names: &[&str]) {
        let missing: Vec<&str> = names
            .iter()
            .copied()
            .filter(|name| extra(name).is_some() && !self.store.join(name).exists())
            .collect();
        if missing.is_empty() {
            return;
        }
        let mut paths = Vec::new();
        for name in &missing {
            let place = write_plant(
                &self.store,
                name,
                extra(name).expect("an extra plant"),
                &[],
                None,
            );
            paths.push(place.to_string_lossy().into_owned());
        }
        let mut add = vec!["add", "--"];
        add.extend(paths.iter().map(String::as_str));
        self.git(&add);
        let mut commit = vec![
            "commit",
            "--quiet",
            "--no-gpg-sign",
            "--message",
            "more plants",
            "--",
        ];
        commit.extend(paths.iter().map(String::as_str));
        self.git(&commit);
        self.head = self.git(&["rev-parse", "HEAD"]).trim().to_owned();
    }

    /// `args` are the tool's arguments for the plants `names`, stocked first: the stand-in `campaign`,
    /// the work directory, 2 workers, 1 s and 3 rounds a sweep, then `extra`.
    pub fn args(&mut self, names: &[&str], extra: &[&str], work: Option<&Path>) -> Vec<OsString> {
        self.stock(names);
        let work = work.unwrap_or(&self.work).as_os_str().to_os_string();
        let mut args: Vec<OsString> = vec![
            "--campaign".into(),
            self.stand_in.clone().into_os_string(),
            "--work".into(),
            work,
        ];
        args.extend(["--workers", "2", "--for", "1", "--rounds", "3"].map(OsString::from));
        args.extend(extra.iter().map(OsString::from));
        for name in names {
            args.extend([OsString::from("--plant"), OsString::from(name)]);
        }
        args
    }

    /// `environment` is the fixture's environment with the stand-ins' variables and `more`.
    pub fn environment(&self, more: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
        let mut env = self.env.clone();
        let watch = self.work.join("proof");
        let set: Vec<(&str, &std::ffi::OsStr)> = vec![
            ("STANDIN_LOG", self.log.as_os_str()),
            ("STANDIN_PROOF_LOG", self.proofs.as_os_str()),
            ("STANDIN_WATCH", watch.as_os_str()),
        ];
        for (name, value) in set {
            env.push((name.into(), value.to_os_string()));
        }
        for (name, value) in more {
            env.retain(|(known, _)| known != name);
            env.push(((*name).into(), (*value).into()));
        }
        env
    }

    /// `command` is the tool started with `args` and `env` in `cwd`.
    pub fn command(&self, args: &[OsString], env: &[(OsString, OsString)], cwd: &Path) -> Command {
        let mut command = Command::new(BINARY);
        command
            .arg(&self.repo)
            .arg("plant-runner")
            .args(args)
            .current_dir(cwd)
            .env_clear()
            .envs(env.iter().cloned())
            .stdin(Stdio::null());
        command
    }

    /// `run_with` runs the tool with `args` and `env` in `cwd`.
    pub fn run_with(&self, args: &[OsString], env: &[(OsString, OsString)], cwd: &Path) -> Done {
        let output = self
            .command(args, env, cwd)
            .output()
            .expect("the tool starts");
        self.no_stand_in_failed();
        Done {
            code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }

    /// `run` runs the plants `names` from the repository with `env` added.
    pub fn run(&mut self, names: &[&str], env: &[(&str, &str)]) -> Done {
        self.run_in(names, &[], env, None)
    }

    /// `run_in` runs the plants `names` with `extra` arguments, `env` added and work directory `work`.
    pub fn run_in(
        &mut self,
        names: &[&str],
        extra: &[&str],
        env: &[(&str, &str)],
        work: Option<&Path>,
    ) -> Done {
        let args = self.args(names, extra, work);
        let env = self.environment(env);
        let repo = self.repo.clone();
        self.run_with(&args, &env, &repo)
    }

    /// `spawn` starts the tool on the plants `names`, after `prefix` when one is given, with both
    /// streams in files of the scratch directory; with `group` it leads a process group of its own.
    pub fn spawn(&mut self, names: &[&str], prefix: &[&str], group: bool) -> Runner {
        self.spawn_with(names, prefix, group, |_| {})
    }

    /// `spawn_with` is [`Fixture::spawn`] with `configure` applied to the command before it starts.
    pub fn spawn_with(
        &mut self,
        names: &[&str],
        prefix: &[&str],
        group: bool,
        configure: impl FnOnce(&mut Command),
    ) -> Runner {
        let args = self.args(names, &[], None);
        let env = self.environment(&[]);
        let mut command = Command::new(prefix.first().copied().unwrap_or(BINARY));
        if let Some(rest) = prefix.get(1..) {
            command.args(rest).arg(BINARY);
        }
        let (out, err) = (self.scratch.join("tool.out"), self.scratch.join("tool.err"));
        command
            .arg(&self.repo)
            .arg("plant-runner")
            .args(&args)
            .current_dir(&self.repo)
            .env_clear()
            .envs(env.iter().cloned())
            .stdin(Stdio::null())
            .stdout(fs::File::create(&out).expect("the output file is made"))
            .stderr(fs::File::create(&err).expect("the error file is made"));
        if group {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        configure(&mut command);
        Runner {
            child: command.spawn().expect("the tool starts"),
            err,
        }
    }

    /// `no_stand_in_failed` fails the case when a stand-in panicked.
    pub fn no_stand_in_failed(&self) {
        let failed = self.scratch.join(super::standins::FAILED);
        if let Ok(text) = fs::read_to_string(&failed) {
            panic!("a stand-in failed: {text}");
        }
    }

    /// `results` is the score and its plants by id.
    pub fn results(&self) -> (Object, BTreeMap<String, Object>) {
        let text = fs::read_to_string(&self.score)
            .unwrap_or_else(|error| panic!("no readable score: {error}"));
        let Ok(Value::Object(written)) = json::parse(&text) else {
            panic!("the score is no JSON object: {text}");
        };
        let mut plants = BTreeMap::new();
        if let Some(Value::Array(entries)) = written.get("plants") {
            for entry in entries {
                let Value::Object(entry) = entry else {
                    panic!("a plant is an object")
                };
                let Some(Value::String(id)) = entry.get("id") else {
                    panic!("a plant names its id")
                };
                plants.insert(id.to_string(), entry.clone());
            }
        }
        (written, plants)
    }

    fn lines_of(path: &Path) -> Vec<Vec<Value>> {
        let text =
            fs::read_to_string(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        text.lines()
            .map(|line| match json::parse(line) {
                Ok(Value::Array(items)) => items,
                other => panic!("{line}: {other:?}"),
            })
            .collect()
    }

    /// `calls` are the stand-in's calls whose arguments start with `prefix`.
    pub fn calls(&self, prefix: &[&str]) -> Vec<Vec<String>> {
        Self::lines_of(&self.log)
            .into_iter()
            .map(|items| {
                items
                    .iter()
                    .map(|item| match item {
                        Value::String(arg) => arg.to_string(),
                        other => panic!("{other:?}"),
                    })
                    .collect::<Vec<String>>()
            })
            .filter(|call| {
                call.len() >= prefix.len() && call.iter().zip(prefix).all(|(arg, want)| arg == want)
            })
            .collect()
    }

    /// `proof_log` is each proof rerun's record: the mode, the directory, the target and build
    /// directories, the tree's lockfile, whether it led its session, and its arguments.
    pub fn proof_log(&self) -> Vec<Vec<Value>> {
        Self::lines_of(&self.proofs)
    }

    /// `proof_modes` are the modes of the proof log's records.
    pub fn proof_modes(&self) -> Vec<String> {
        self.proof_log()
            .iter()
            .map(|record| text_of(&record[0]))
            .collect()
    }

    /// `proof_tests` are the test ids of the proof log's records whose mode `keep` takes.
    pub fn proof_tests(&self, keep: impl Fn(&str) -> bool) -> Vec<String> {
        self.proof_log()
            .iter()
            .filter(|record| keep(&text_of(&record[0])))
            .map(|record| {
                let at = record
                    .iter()
                    .position(|item| text_of(item) == "--test")
                    .expect("--test");
                text_of(&record[at + 1])
            })
            .collect()
    }

    /// `rejected` asserts an exit 2 with `text` on standard error, no stand-in call, no work directory and
    /// no score.
    pub fn rejected(&self, done: &Done, text: &str) {
        assert_eq!(done.code, 2, "{}", done.stderr);
        assert!(done.stderr.contains(text), "{text:?} in {}", done.stderr);
        assert!(self.calls(&[]).is_empty());
        assert!(!self.work.exists());
        assert!(!self.score.exists());
    }

    /// `verdict` asserts the plant's result and a reason that holds `reason`, and returns its entry.
    pub fn verdict(&self, name: &str, result: &str, reason: &str) -> Object {
        let (_, plants) = self.results();
        let plant = plants
            .get(name)
            .unwrap_or_else(|| panic!("no plant {name}"))
            .clone();
        let found = text_of(plant.get("reason").expect("a reason"));
        assert_eq!(
            text_of(plant.get("result").expect("a result")),
            result,
            "{name}: {found}"
        );
        assert!(found.contains(reason), "{name}: {reason:?} in {found:?}");
        plant
    }

    /// `state` is what a run must leave as it was: the head, the status with ignored files, the
    /// worktrees, the refs, the stash, the local configuration, and the bytes of `mode`, the index, the
    /// checkout's `Cargo.lock`, the repository's configuration and its `post-checkout` hook.
    pub fn state(&self) -> Vec<Vec<u8>> {
        let mut state: Vec<Vec<u8>> = [
            &["rev-parse", "HEAD"][..],
            &[
                "status",
                "--porcelain",
                "--ignored",
                "--untracked-files=all",
            ],
            &["worktree", "list", "--porcelain"],
            &["for-each-ref"],
            &["stash", "list"],
            &["config", "--list", "--local"],
        ]
        .iter()
        .map(|args| self.git(args).into_bytes())
        .collect();
        for path in [
            "mode",
            ".git/index",
            "Cargo.lock",
            ".git/config",
            ".git/hooks/post-checkout",
        ] {
            state.push(fs::read(self.repo.join(path)).expect("a kept file reads"));
        }
        state
    }

    /// `git_shim` writes a `git` first on `PATH` that runs the shell text `action` in place of each Git
    /// command one of whose arguments is `word`, with the real Git as `$real`, and returns that `PATH`.
    pub fn git_shim(&self, word: &str, action: &str) -> (&'static str, String) {
        fs::create_dir_all(&self.bin).expect("the shim's directory is made");
        let real = which("git", &self.path());
        executable(
            &self.bin.join("git"),
            &format!(
                "#!/bin/sh\nreal={real}\nfor word in \"$@\"; do\n  if [ \"$word\" = {word} ]; then\n    \
                 {action}\n  fi\ndone\nexec \"$real\" \"$@\"\n"
            ),
        );
        ("PATH", format!("{}:{}", self.bin.display(), self.path()))
    }

    fn path(&self) -> String {
        self.env
            .iter()
            .find(|(name, _)| name == "PATH")
            .map(|(_, value)| value.to_string_lossy().into_owned())
            .unwrap_or_default()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = Command::new("chmod")
            .args(["-R", "u+rwx"])
            .arg(&self.scratch)
            .status();
        let _ = fs::remove_dir_all(&self.scratch);
    }
}

/// `which` finds `program` on `path`.
pub fn which(program: &str, path: &str) -> String {
    path.split(':')
        .map(|entry| Path::new(entry).join(program))
        .find(|candidate| candidate.is_file())
        .unwrap_or_else(|| panic!("no {program} on {path}"))
        .to_string_lossy()
        .into_owned()
}

/// `text_of` is a JSON string's text, or its JSON text otherwise.
pub fn text_of(value: &Value) -> String {
    match value {
        Value::String(text) => text.to_string(),
        other => json::text(other),
    }
}

/// `object` is `value` as a JSON object's JSON text, for a comparison with an expected text.
pub fn shown(value: Option<&Value>) -> String {
    value.map_or_else(|| "missing".to_owned(), json::text)
}

/// A tool started in the background, with its error output in a file.
pub struct Runner {
    pub child: Child,
    err: PathBuf,
}

impl Runner {
    /// `signal` sends `signal` to the tool, or to its process group with `group`.
    pub fn signal(&self, signal: i32, group: bool) {
        let pid = libc::pid_t::try_from(self.child.id()).expect("a pid fits");
        // SAFETY: `kill` and `killpg` take integers and touch no memory of the caller.
        let sent = unsafe {
            if group {
                libc::killpg(pid, signal)
            } else {
                libc::kill(pid, signal)
            }
        };
        assert_eq!(sent, 0, "the signal is sent");
    }

    /// `finish` waits at most 60 s for the tool and returns its exit and error output.
    pub fn finish(&mut self) -> (i32, String) {
        let start = Instant::now();
        let status = loop {
            if let Some(status) = self.child.try_wait().expect("the wait succeeds") {
                break status;
            }
            if start.elapsed() > Duration::from_secs(60) {
                let _ = self.child.kill();
                let _ = self.child.wait();
                panic!("the tool ran past 60 s");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let err = fs::read_to_string(&self.err).unwrap_or_default();
        if let Ok(text) = fs::read_to_string(self.err.with_file_name(super::standins::FAILED)) {
            panic!("a stand-in failed: {text}");
        }
        (status.code().unwrap_or(-1), err)
    }
}

impl Drop for Runner {
    fn drop(&mut self) {
        if let Ok(None) = self.child.try_wait() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// `wait_for` waits at most 30 s for `path`, failing once `child` exits first.
pub fn wait_for(path: &Path, child: &mut Child) {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(30) {
        if path.exists() {
            return;
        }
        if let Ok(Some(status)) = child.try_wait() {
            panic!("the tool exited {status} before {}", path.display());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("no {} within 30 s", path.display());
}

/// `umask` reads this process's umask from `/proc/self/status`.
pub fn umask() -> u32 {
    let status = fs::read_to_string("/proc/self/status").expect("the status reads");
    let line = status
        .lines()
        .find(|line| line.starts_with("Umask:"))
        .expect("a Umask line");
    u32::from_str_radix(line.trim_start_matches("Umask:").trim(), 8).expect("an octal umask")
}

pub fn mode_bits(path: &Path) -> u32 {
    fs::metadata(path)
        .expect("the path stats")
        .permissions()
        .mode()
        & 0o777
}
