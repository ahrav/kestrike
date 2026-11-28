//! One plant run after its checks: its worktrees, its proof reruns and its base archive, and the two
//! phases over the selected plants.
//!
//! The first phase checks that each patch applies in the plant's worktree, reruns on the head the proof
//! of each plant whose patch applies, then applies each such plant to the proof's worktree in turn,
//! reruns its proof and resets the tree, and removes the proof's worktree and target directory. The
//! second builds, sweeps and judges each plant the first left without a result; when the proof's
//! worktree or target directory remains, each of those plants has no verdict. A worktree is a detached
//! worktree of the head at `PLACE/tree`, added with hooks off, and the run removes each one it added when
//! it ends. The run trusts its work directory, which the checks made under ancestors only its user or
//! root can write, and reads and writes its files by name.

use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use super::child::{GitFailed, Halt, Step};
use super::entry::{Entry, Finished};
use super::git::{self, CallError, Done};
use super::output::Pins;
use super::prepare::Inputs;
use super::record::Plant;
use super::verdict::NoVerdict;
use crate::environ::{Environ, set};
use crate::ownership::make_private;
use crate::process::Interrupt;
use crate::text::{Text, text};

/// One run's checked inputs, its signal record, its worktrees, the proof's state and the base archive.
pub struct Run<'a> {
    pub(super) inputs: &'a Inputs,
    pub(super) interrupt: &'a Interrupt,
    /// The head's committer date in strict ISO 8601.
    pub(super) date: String,
    trees: Vec<PathBuf>,
    /// The staged helper's verdict texts of exits 0 and 1, once the proof's setup stands.
    pub(super) results: Option<[Text; 2]>,
    pub(super) on_head: Vec<(Text, Result<u8, NoVerdict>)>,
    pub(super) proof_tree: Option<PathBuf>,
    pub(super) proof_failure: Option<NoVerdict>,
    pub(super) base: Option<Result<(PathBuf, Pins), NoVerdict>>,
}

/// A worktree that remains after the run's removal: `None` when it still stands or is listed, or the
/// exit of a `git worktree list` that failed and so leaves it unknown.
pub type Remained = (PathBuf, Option<i32>);

/// `remove` removes `path` and everything under it, going past each entry it cannot remove; a link at
/// `path` stays.
pub fn remove(path: &Path) {
    let Ok(status) = fs::symlink_metadata(path) else {
        return;
    };
    if !status.is_dir() {
        return;
    }
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let inner = entry.path();
            match entry.file_type() {
                Ok(kind) if kind.is_dir() => remove(&inner),
                _ => drop(fs::remove_file(&inner)),
            }
        }
    }
    let _ = fs::remove_dir(path);
}

/// `exists` holds for a path that stands, a dangling link included.
pub(super) fn exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

/// `listed` holds when a line of `git worktree list --porcelain`, split at each of Python's line
/// breaks, names `tree`.
fn listed(listing: &str, tree: &Path) -> bool {
    let mut wanted = b"worktree ".to_vec();
    wanted.extend_from_slice(tree.as_os_str().as_bytes());
    Text::from(listing)
        .splitlines()
        .iter()
        .any(|line| line.to_os().is_some_and(|os| os.as_bytes() == wanted))
}

impl<'a> Run<'a> {
    /// `new` reads the head's committer date, the date of every planted commit.
    ///
    /// # Errors
    ///
    /// `git show` cannot run or exits nonzero, a failure outside a plant.
    pub fn new(inputs: &'a Inputs, interrupt: &'a Interrupt) -> Result<Self, Halt> {
        let args = [
            "show",
            "--no-patch",
            "--no-show-signature",
            "--format=%cI",
            inputs.head(),
        ]
        .map(OsStr::new);
        let shown = git::text(inputs.env(), inputs.top(), &args)
            .and_then(Done::checked)
            .map_err(|error| Halt::Failed(Text::from(error.to_string())))?;
        Ok(Self {
            inputs,
            interrupt,
            date: crate::text::strip_str(&shown.stdout).to_owned(),
            trees: Vec::new(),
            results: None,
            on_head: Vec::new(),
            proof_tree: None,
            proof_failure: None,
            base: None,
        })
    }

    pub(super) fn work(&self) -> &Path {
        self.inputs.work()
    }

    /// `place` is the directory of plant `id` under the work directory.
    pub(super) fn place(&self, id: &Text) -> PathBuf {
        let id = id.to_os().expect("a checked plant id is text");
        self.work().join("plants").join(id)
    }

    /// `in_work` names `path` from the work directory when it lies there.
    pub(super) fn in_work<'p>(&self, path: &'p Path) -> &'p Path {
        path.strip_prefix(self.work()).unwrap_or(path)
    }

    /// `git` runs a Git step in `dir` that a recorded signal ends.
    pub(super) fn git(&self, dir: &Path, args: &[&OsStr]) -> Result<Done<String>, CallError> {
        git::text_until(self.inputs.env(), dir, args, self.interrupt)
    }

    /// `env_with` is the run's environment with `settings` set.
    pub(super) fn env_with(&self, settings: &[(&str, &OsStr)]) -> Environ {
        let mut env = self.inputs.env().clone();
        for (name, value) in settings {
            set(&mut env, name, value.to_os_string());
        }
        env
    }

    /// `cargo_env` is the run's environment with `target` as Cargo's target and build directory and
    /// `settings` added; Cargo resolves from `lockfile` when one is given, and the caller's lockfile path
    /// is dropped otherwise.
    pub(super) fn cargo_env(
        &self,
        target: &Path,
        lockfile: Option<&Path>,
        settings: &[(&str, &OsStr)],
    ) -> Environ {
        let mut all = vec![
            ("CARGO_TARGET_DIR", target.as_os_str()),
            ("CARGO_BUILD_BUILD_DIR", target.as_os_str()),
        ];
        all.extend_from_slice(settings);
        let mut env = self.env_with(&all);
        env.retain(|(name, _)| name != "CARGO_RESOLVER_LOCKFILE_PATH");
        if let Some(lockfile) = lockfile {
            set(
                &mut env,
                "CARGO_RESOLVER_LOCKFILE_PATH",
                lockfile.as_os_str().to_os_string(),
            );
        }
        env
    }

    /// `tree` adds a detached worktree of the head at `place/tree`, with `place` and its missing ancestors
    /// made private. The add runs whole: a signal recorded during it ends the run after it.
    pub(super) fn tree(&mut self, place: &Path) -> Result<PathBuf, Step> {
        let tree = place.join("tree");
        make_private(place).map_err(|error| NoVerdict::failed(error.to_string()))?;
        self.trees.push(tree.clone());
        let args = [
            OsStr::new("worktree"),
            OsStr::new("add"),
            OsStr::new("--detach"),
            tree.as_os_str(),
            OsStr::new(self.inputs.head()),
        ];
        self.interrupt.check()?;
        let added = git::text(self.inputs.env(), self.inputs.top(), &args);
        self.interrupt.check()?;
        let _ = added.and_then(Done::checked)?;
        Ok(tree)
    }

    /// `listing` is the output of `git worktree list --porcelain` in the checkout, and its exit; with
    /// `whole` the listing runs whole and reads no signal record.
    fn listing(&self, whole: bool) -> Result<(String, i32), Halt> {
        let args = ["worktree", "list", "--porcelain"].map(OsStr::new);
        let listed = if whole {
            git::text(self.inputs.env(), self.inputs.top(), &args)
        } else {
            self.git(self.inputs.top(), &args)
        };
        match listed {
            Ok(done) => Ok((done.stdout, done.code)),
            Err(CallError::Interrupted(interrupted)) => Err(interrupted.into()),
            Err(error) => Err(Halt::Failed(Text::from(error.to_string()))),
        }
    }

    /// `remove_worktree` runs `git worktree remove --force --force TREE`, whose exit the caller reads from
    /// the listing after it.
    fn remove_worktree(&self, tree: &Path) -> Result<(), Halt> {
        let args = [
            OsStr::new("worktree"),
            OsStr::new("remove"),
            OsStr::new("--force"),
            OsStr::new("--force"),
            tree.as_os_str(),
        ];
        match git::text(self.inputs.env(), self.inputs.top(), &args) {
            Ok(_) | Err(CallError::NotUtf8 { .. }) => Ok(()),
            Err(error) => Err(Halt::Failed(Text::from(error.to_string()))),
        }
    }

    /// `remove_trees` removes the run's worktrees, locked ones included, and returns each one that
    /// remains. It reads no signal record: a signal recorded during it acts after it.
    ///
    /// # Errors
    ///
    /// Git cannot run or prints no UTF-8 listing.
    pub fn remove_trees(&self) -> Result<Vec<Remained>, Halt> {
        let mut remained = Vec::new();
        for tree in &self.trees {
            self.remove_worktree(tree)?;
            let (listing, code) = self.listing(true)?;
            if tree.exists() || listed(&listing, tree) {
                remained.push((tree.clone(), None));
            } else if code != 0 {
                remained.push((tree.clone(), Some(code)));
            }
        }
        Ok(remained)
    }

    /// `release_proof` removes the proof's worktree and target directory once the last proof has rerun,
    /// keeping its logs, and returns each of the two that remains. The two removals run whole.
    pub(super) fn release_proof(&self) -> Result<Vec<PathBuf>, Halt> {
        let place = self.work().join("proof");
        let (tree, target) = (place.join("tree"), place.join("target"));
        if self.trees.contains(&tree) {
            self.remove_worktree(&tree)?;
        }
        remove(&target);
        self.interrupt.check()?;
        let (listing, _) = self.listing(false)?;
        Ok([tree, target]
            .into_iter()
            .filter(|path| exists(path) || listed(&listing, path))
            .collect())
    }

    /// `write_lock` writes the run's `Cargo.lock` into `tree`, `what`, which must hold none.
    pub(super) fn write_lock(&self, tree: &Path, what: &str) -> Result<(), NoVerdict> {
        let path = tree.join("Cargo.lock");
        let written = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .and_then(|mut lock| lock.write_all(self.inputs.lock()));
        match written {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                Err(NoVerdict::plain(text!(what, " already holds a Cargo.lock")))
            }
            Err(error) => Err(NoVerdict::plain(text!(
                "the run's Cargo.lock cannot be written into ",
                what,
                ": ",
                super::files::strerror(&error)
            ))),
        }
    }

    /// `holds_lock` holds when `tree` holds a regular `Cargo.lock` of exactly the run's bytes, read
    /// through one descriptor that follows no link and waits for no writer, at most one byte past the
    /// run's lockfile.
    pub(super) fn holds_lock(&self, tree: &Path) -> bool {
        let lock = self.inputs.lock();
        let Ok(file) = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
            .open(tree.join("Cargo.lock"))
        else {
            return false;
        };
        let regular = file.metadata().is_ok_and(|status| status.is_file());
        let mut read = Vec::new();
        let bound = u64::try_from(lock.len()).map_or(u64::MAX, |len| len.saturating_add(1));
        regular && file.take(bound).read_to_end(&mut read).is_ok() && read == lock
    }

    /// `keep_git_error` appends a failed Git step's error output to `place/git.err`, going past a write
    /// that fails, and returns that path from the work directory.
    pub(super) fn keep_git_error(&self, place: &Path, failed: &GitFailed) -> PathBuf {
        let log = place.join("git.err");
        if let Ok(mut err) = OpenOptions::new().append(true).create(true).open(&log) {
            let kept = text!(
                "git ",
                failed.step,
                " exited ",
                failed.code,
                ":\n",
                failed.stderr
            );
            let _ = err.write_all(kept.as_bytes());
        }
        self.in_work(&log).to_path_buf()
    }

    /// `settle` sets the no verdict of a step that ended in `ending` on `entry`, whose plant's
    /// directory is `place`.
    ///
    /// # Errors
    ///
    /// The step ended the run.
    pub(super) fn settle(&self, entry: &mut Entry, place: &Path, ending: Step) -> Result<(), Halt> {
        match ending {
            Step::NoVerdict(ending) => entry.no_verdict(&ending),
            Step::Git(failed) => {
                let log = self.keep_git_error(place, &failed);
                entry.no_verdict(&NoVerdict::plain(text!(
                    failed.shown(),
                    "; its error is in ",
                    log
                )));
            }
            Step::Halt(halt) => return Err(halt),
        }
        Ok(())
    }
}

/// `said` writes `line` to `err`, which a failed write leaves as it is.
fn said(err: &mut impl Write, line: &Text) {
    let _ = writeln!(err, "{line}");
    let _ = err.flush();
}

/// `proof_line` is the line a plant prints once its proof reruns end: its result, or its exits.
fn proof_line(plant: &Plant, entry: &Entry, exits: Option<(u8, u8)>) -> Text {
    if let Some(verdict) = entry.verdict() {
        return text!(plant.id(), ": proof ", verdict.as_str());
    }
    let (head, planted) = exits.expect("a plant without a result has its proof's exits");
    text!(
        plant.id(),
        ": proof {'head': ",
        format!("{head}"),
        ", 'plant': ",
        format!("{planted}"),
        "}"
    )
}

impl Run<'_> {
    /// `run_store` runs the selected plants in the two phases and returns their entries in store order.
    /// Each plant writes a line to `err` as the first phase settles it, `ID: RESULT` or `ID: proof
    /// EXITS`, and as the second ends, `ID: RESULT`. The run reads the signal record after each step.
    ///
    /// # Errors
    ///
    /// A signal was recorded, or the run failed outside a plant.
    pub fn run_store(&mut self, err: &mut impl Write) -> Result<Vec<Finished>, Halt> {
        let plants = self.inputs.plants();
        let mut entries = Vec::with_capacity(plants.len());
        for plant in plants {
            let mut entry = Entry::new(plant);
            let place = self.place(plant.id());
            let tree = match self.applies(plant, &mut entry) {
                Ok(tree) => tree,
                Err(ending) => {
                    self.settle(&mut entry, &place, ending)?;
                    None
                }
            };
            self.interrupt.check()?;
            if let Some(verdict) = entry.verdict() {
                said(err, &text!(plant.id(), ": ", verdict.as_str()));
            }
            entries.push((plant, entry, tree));
        }
        let mut proofs: Vec<Text> = Vec::new();
        for (plant, entry, _) in &entries {
            if entry.verdict().is_none() && !proofs.contains(plant.proof()) {
                proofs.push(plant.proof().clone());
            }
        }
        if !proofs.is_empty() {
            self.prove_head(&proofs)?;
            self.interrupt.check()?;
        }
        for (plant, entry, _) in &mut entries {
            if entry.verdict().is_some() {
                continue;
            }
            let exits = match self.live(plant) {
                Ok((head, planted)) => {
                    entry.prove(head, planted);
                    Some((head, planted))
                }
                Err(ending) => {
                    let place = self.place(plant.id());
                    self.settle(entry, &place, ending)?;
                    None
                }
            };
            self.interrupt.check()?;
            said(err, &proof_line(plant, entry, exits));
        }
        let remained = self.release_proof()?;
        let held: Vec<Text> = remained
            .iter()
            .map(|path| text!(self.in_work(path)))
            .collect();
        let mut finished = Vec::with_capacity(entries.len());
        for (plant, mut entry, tree) in entries {
            if entry.verdict().is_none() && !held.is_empty() {
                entry.no_verdict(&NoVerdict::plain(text!(
                    "the proof's ",
                    Text::join(", ", &held),
                    " remained after the last proof rerun, so no archive builds beside it"
                )));
            } else if let (None, Some(tree)) = (entry.verdict(), tree) {
                if let Err(ending) = self.judge_plant(plant, &mut entry, &tree) {
                    let place = self.place(plant.id());
                    self.settle(&mut entry, &place, ending)?;
                }
                self.interrupt.check()?;
            }
            let done = entry
                .finish(self.work())
                .expect("every plant has its result once the second phase ends");
            said(err, &text!(done.id(), ": ", done.verdict().as_str()));
            finished.push(done);
        }
        Ok(finished)
    }
}
