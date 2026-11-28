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
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use super::ending::{GitFailed, Halt, Step};
use super::entry::{Entry, Finished};
use super::git::{self, CallError, Done};
use super::output::Pins;
use super::prepare::Inputs;
use super::record::Plant;
use super::removal::remove;
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
    /// The staged helper's source as read once at the proof's setup, which every question runs.
    pub(super) helper_source: Vec<u8>,
    pub(super) on_head: Vec<(Text, Result<u8, NoVerdict>)>,
    pub(super) proof_tree: Option<PathBuf>,
    pub(super) proof_failure: Option<NoVerdict>,
    pub(super) base: Option<Result<(PathBuf, Pins), NoVerdict>>,
}

/// Why [`Run::add_tree`] added no worktree: the step's ending, or a failure before Git answered,
/// given as its text.
pub(super) enum Unadded {
    Step(Step),
    Unprepared(String),
}

/// A worktree that remains after the run's removal: `None` when it still stands or is listed, or the
/// exit of a `git worktree list` that failed and so leaves it unknown.
pub type Remained = (PathBuf, Option<i32>);

/// `write_new` creates `path` new, refuses with `EFBIG` bytes that the soft file size limit forbids,
/// leaving the new file empty, and writes them.
///
/// # Errors
///
/// The create, the size check or the write fails; `AlreadyExists` for a path that stands.
pub(super) fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    crate::fixtures::fits(bytes.len())?;
    file.write_all(bytes)
}

/// `lock_bytes` reads the opened `file` from its start, at most one byte past the length of `lock`, and
/// returns `None` for a file that is no regular file; the extra byte shows trailing bytes after a
/// prefix that matches `lock`.
///
/// # Errors
///
/// The file's status or the read fails.
pub(super) fn lock_bytes(file: File, lock: &[u8]) -> io::Result<Option<Vec<u8>>> {
    if !file.metadata()?.is_file() {
        return Ok(None);
    }
    let bound = u64::try_from(lock.len()).map_or(u64::MAX, |len| len.saturating_add(1));
    let mut read = Vec::new();
    file.take(bound).read_to_end(&mut read)?;
    Ok(Some(read))
}

/// `open_lock` rejects a symbolic link in the final path component and opens a FIFO for reading even
/// when no writer is present.
pub(super) fn open_lock(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(path)
}

/// `stands` holds for a path whose status reads, through a link when `follow` holds and of the entry
/// itself otherwise; a status error that makes Python's `Path.exists` false reads as a path that does
/// not stand.
///
/// # Errors
///
/// The status read fails otherwise, with the path in the text.
pub(crate) fn stands(path: &Path, follow: bool) -> Result<bool, Halt> {
    let status = if follow {
        fs::metadata(path)
    } else {
        fs::symlink_metadata(path)
    };
    match status {
        Ok(_) => Ok(true),
        Err(error) if crate::ownership::ignored(&error) => Ok(false),
        Err(error) => Err(Halt::Failed(Text::from(
            crate::ownership::PathError::new(path, error).to_string(),
        ))),
    }
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
            helper_source: Vec::new(),
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
    /// made private, as [`Run::add_tree`] does; `prepared` words a failure before Git answered.
    pub(super) fn tree(
        &mut self,
        place: &Path,
        prepared: impl Fn(String) -> NoVerdict,
    ) -> Result<PathBuf, Step> {
        self.add_tree(place).map_err(|error| match error {
            Unadded::Step(ending) => ending,
            Unadded::Unprepared(why) => prepared(why).into(),
        })
    }

    /// `add_tree` adds a detached worktree of the head at `place/tree`, with `place` and its missing
    /// ancestors made private. The add runs whole: a signal recorded before it or during it ends the run
    /// after it. Each add registers `place/tree` among the run's worktrees, so a second add at one place
    /// registers it twice.
    ///
    /// # Errors
    ///
    /// `Unadded::Step`: a recorded signal, or a Git add that exited nonzero, with its error output.
    /// `Unadded::Unprepared`: `place` cannot be made private, or Git cannot be started or waited for or
    /// prints no UTF-8 text, given as the error's text.
    pub(super) fn add_tree(&mut self, place: &Path) -> Result<PathBuf, Unadded> {
        let tree = place.join("tree");
        make_private(place).map_err(|error| Unadded::Unprepared(error.to_string()))?;
        self.trees.push(tree.clone());
        let args = [
            OsStr::new("worktree"),
            OsStr::new("add"),
            OsStr::new("--detach"),
            tree.as_os_str(),
            OsStr::new(self.inputs.head()),
        ];
        let stop = |interrupted| Unadded::Step(Step::from(interrupted));
        self.interrupt.check().map_err(stop)?;
        let added = git::text(self.inputs.env(), self.inputs.top(), &args);
        self.interrupt.check().map_err(stop)?;
        let _ = added
            .map_err(|error| Unadded::Unprepared(error.to_string()))?
            .checked()
            .map_err(|error| Unadded::Step(error.into()))?;
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

    /// `remove_worktree` runs `git worktree remove --force --force TREE`; the caller reads the tree's
    /// status and the listing after it to tell whether the removal succeeded.
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
    /// remains, a worktree that still stands or is listed paired with `None`, and each one whose removal
    /// a failed listing leaves unknown, paired with that listing's exit. It reads no signal record: a
    /// signal recorded during it acts after it.
    ///
    /// # Errors
    ///
    /// Git cannot run or prints no UTF-8 listing, or a worktree's status cannot be read.
    pub fn remove_trees(&self) -> Result<Vec<Remained>, Halt> {
        let mut remained = Vec::new();
        for tree in &self.trees {
            self.remove_worktree(tree)?;
            let (listing, code) = self.listing(true)?;
            if stands(tree, true)? || listed(&listing, tree) {
                remained.push((tree.clone(), None));
            } else if code != 0 {
                remained.push((tree.clone(), Some(code)));
            }
        }
        Ok(remained)
    }

    /// `release_proof` removes the proof's worktree and target directory once the last proof has rerun,
    /// keeping its logs, and returns each of the two that remains. The two removals run whole; the read
    /// of the signal record after them ends that region, and the listing reads the record again before
    /// Git starts.
    ///
    /// # Errors
    ///
    /// A recorded signal, a listing that cannot run, or a status read that fails.
    pub(super) fn release_proof(&self) -> Result<Vec<PathBuf>, Halt> {
        let place = self.work().join("proof");
        let (tree, target) = (place.join("tree"), place.join("target"));
        if self.trees.contains(&tree) {
            self.remove_worktree(&tree)?;
        }
        remove(&target);
        self.interrupt.check()?;
        let (listing, _) = self.listing(false)?;
        let mut remained = Vec::new();
        for path in [tree, target] {
            if stands(&path, false)? || listed(&listing, &path) {
                remained.push(path);
            }
        }
        Ok(remained)
    }

    /// `write_lock` writes the run's `Cargo.lock` into `tree`, `what`, which must hold none.
    pub(super) fn write_lock(&self, tree: &Path, what: &str) -> Result<(), NoVerdict> {
        let path = tree.join("Cargo.lock");
        match write_new(&path, self.inputs.lock()) {
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
        open_lock(&tree.join("Cargo.lock"))
            .and_then(|file| lock_bytes(file, self.inputs.lock()))
            .is_ok_and(|read| read.as_deref() == Some(self.inputs.lock()))
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
            let held = err.metadata().map(|status| status.len());
            let fits = held.and_then(|held| {
                let held =
                    usize::try_from(held).map_err(|_| io::Error::from_raw_os_error(libc::EFBIG))?;
                crate::fixtures::fits(held.saturating_add(kept.as_bytes().len()))
            });
            if fits.is_ok() {
                let _ = err.write_all(kept.as_bytes());
            }
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

/// `said` writes `line` and a line feed to `err` and flushes it.
///
/// # Errors
///
/// The write or the flush fails.
pub(crate) fn said(err: &mut impl Write, line: &Text) -> io::Result<()> {
    writeln!(err, "{line}")?;
    err.flush()
}

/// A failed progress write ends the run.
fn progress(err: &mut impl Write, line: &Text) -> Result<(), Halt> {
    said(err, line).map_err(|error| {
        Halt::Failed(text!(
            "a progress line cannot be written: ",
            super::files::strerror(&error)
        ))
    })
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
    /// In the first phase a plant writes `ID: RESULT` to `err` when its apply check settles it, and
    /// `ID: proof RESULT` or `ID: proof {'head': H, 'plant': P}` once its proof reruns end; in the second
    /// every plant writes `ID: RESULT`. The run reads the signal record after each step.
    ///
    /// # Errors
    ///
    /// A signal was recorded, the run failed outside a plant, or a progress line cannot be written.
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
                progress(err, &text!(plant.id(), ": ", verdict.as_str()))?;
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
            progress(err, &proof_line(plant, entry, exits))?;
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
            progress(err, &text!(done.id(), ": ", done.verdict().as_str()))?;
            finished.push(done);
        }
        Ok(finished)
    }
}

#[cfg(test)]
#[path = "run_tests.rs"]
mod tests;
