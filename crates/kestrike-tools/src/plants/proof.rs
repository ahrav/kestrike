//! Steps 1 and 2 of a plant: the check that its patch applies in its worktree, and the proof's reruns on
//! the head and on the plant in the proof's worktree.
//!
//! The proof's worktree, `<work>/proof/tree`, holds the run's `Cargo.lock`; the proof reruns use the
//! target directory `<work>/proof/target`, resolve from that lockfile, and start the head's helper from
//! its copy under `<work>/proof/scripts/`, beside the copy of the selector, outside the tree a patch
//! changes. The verdict check is the staged helper's own: once the helpers are copied, and after each
//! rerun that exits 0 or 1, the run asks the copy. A setup that fails, an apply or a reset of the proof's
//! worktree that fails, and a rerun that leaves the tree without the run's lockfile are kept, so every
//! later plant reports that cause.

use std::ffi::{OsStr, OsString};
use std::fs::{DirBuilder, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use super::child::{Logged, PYTHON, counts, logged, verdict_texts};
use super::ending::{Halt, Step, Stopped};
use super::entry::Entry;
use super::git::{CallError, Done};
use super::record::Plant;
use super::rerun::{HelperVerdict, Rerun, judge_rerun};
use super::run::Run;
use super::verdict::{Kind, NoVerdict};
use crate::text::{Text, text};

/// The arguments of every proof rerun before `--test`.
const PROOF: [&str; 6] = [
    "--package",
    "kestrike",
    "--target",
    "lib",
    "--attempts",
    "1",
];
/// The head's helper and the selector it loads, copied out of the proof's worktree.
const HELPER: [&str; 2] = ["reproduce-test.py", "select-tests.py"];

fn os(text: &Text) -> OsString {
    text.to_os()
        .expect("a checked record's text names no lone surrogate")
}

/// `copy` opens `from` once, following links and waiting for no writer, refuses a named pipe judged
/// on the opened file, and reads through that descriptor at most one byte past the soft file size
/// limit, so a source the copy could not write is refused before it is read whole.
fn copy(from: &Path, to: &Path) -> io::Result<()> {
    let source = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(from)?;
    if source.metadata()?.file_type().is_fifo() {
        return Err(io::Error::other(format!(
            "`{}` is a named pipe",
            from.display()
        )));
    }
    let mut bytes = Vec::new();
    source.take(size_bound()?).read_to_end(&mut bytes)?;
    crate::fixtures::fits(bytes.len())?;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(to)?
        .write_all(&bytes)
}

/// `size_bound` is one byte past the soft file size limit, or no bound when the limit is infinite.
fn size_bound() -> io::Result<u64> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `getrlimit` writes one `rlimit` through the pointer, which refers to a live local.
    if unsafe { libc::getrlimit(libc::RLIMIT_FSIZE, &mut limit) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if limit.rlim_cur == libc::RLIM_INFINITY {
        return Ok(u64::MAX);
    }
    Ok(limit.rlim_cur.saturating_add(1))
}

impl Run<'_> {
    fn proof_place(&self) -> PathBuf {
        self.work().join("proof")
    }

    fn helper(&self) -> PathBuf {
        self.proof_place().join("scripts").join(HELPER[0])
    }

    /// `applies` adds the plant's worktree, stages the patch bytes read at the start in the plant's
    /// directory and checks them with `git apply --check --index`. It returns the worktree once they
    /// apply, and `None` once Git refuses them (exit 1), which settles the plant as `does not apply`.
    pub(super) fn applies(
        &mut self,
        plant: &Plant,
        entry: &mut Entry,
    ) -> Result<Option<PathBuf>, Step> {
        let place = self.place(plant.id());
        let tree = self.tree(&place, NoVerdict::failed)?;
        let patch = place.join("plant.patch");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&patch)
            .and_then(|mut staged| {
                crate::fixtures::fits(plant.patch().len())?;
                staged.write_all(plant.patch())
            })
            .map_err(|error| NoVerdict::unreadable(&patch, &error, self.work()))?;
        let args = [
            OsStr::new("apply"),
            OsStr::new("--check"),
            OsStr::new("--index"),
            patch.as_os_str(),
        ];
        let checked = self.git(&tree, &args)?;
        if checked.code == 1 {
            let reason = Text::from(checked.stderr.as_str())
                .strip()
                .splitlines()
                .into_iter()
                .next()
                .unwrap_or_else(|| Text::from("git apply --check failed"));
            entry.does_not_apply(reason);
            return Ok(None);
        }
        let _ = checked.checked()?;
        Ok(Some(tree))
    }

    /// `setup` makes the proof's worktree with the run's `Cargo.lock`, copies the head's helpers out of
    /// it and asks the staged helper for its verdict texts. A signal recorded during the question ends
    /// the run after it.
    fn setup(&mut self) -> Result<PathBuf, Step> {
        let place = self.proof_place();
        let tree = self.tree(&place, |why| {
            NoVerdict::plain(text!("the proof's worktree cannot be prepared: ", why))
        })?;
        self.write_lock(&tree, "the proof's worktree")?;
        let scripts = place.join("scripts");
        DirBuilder::new().create(&scripts).map_err(|error| {
            NoVerdict::plain(text!(
                "the proof's worktree cannot be prepared: ",
                super::files::strerror(&error)
            ))
        })?;
        for name in HELPER {
            copy(&tree.join("scripts").join(name), &scripts.join(name)).map_err(|error| {
                NoVerdict::plain(text!(
                    "the head's scripts/",
                    name,
                    " cannot be copied: ",
                    super::files::strerror(&error)
                ))
            })?;
        }
        self.interrupt.check()?;
        let answer = verdict_texts(self.inputs.env(), &self.helper());
        self.interrupt.check()?;
        match answer {
            Ok(results) => self.results = Some(results),
            Err(why) => {
                return Err(Step::NoVerdict(NoVerdict::plain(text!(
                    "the head's scripts/",
                    HELPER[0],
                    " gives no verdict check: ",
                    why
                ))));
            }
        }
        Ok(tree)
    }

    /// `prove_head` prepares the proof's worktree and reruns each of `proofs` on the head, so the head
    /// builds once. A setup that fails is kept for every plant. A head rerun that fails is kept for its
    /// proof; one whose library tests do not build fails every proof not yet rerun with that reason; one
    /// that leaves the tree without the run's lockfile ends the head's reruns and is kept for every plant.
    ///
    /// # Errors
    ///
    /// The run ended.
    pub(super) fn prove_head(&mut self, proofs: &[Text]) -> Result<(), Halt> {
        let tree = match self.setup() {
            Ok(tree) => tree,
            Err(Step::Halt(halt)) => return Err(halt),
            Err(Step::NoVerdict(ending)) => {
                self.proof_failure = Some(ending);
                return Ok(());
            }
            Err(Step::Git(failed)) => {
                let log = self.keep_git_error(&self.proof_place(), &failed);
                self.proof_failure = Some(NoVerdict::plain(text!(
                    "the proof's worktree: ",
                    failed.shown(),
                    "; its error is in ",
                    log
                )));
                return Ok(());
            }
        };
        self.proof_tree = Some(tree.clone());
        for (number, proof) in proofs.iter().enumerate() {
            match self.proof(&tree, proof, &format!("head-{number}")) {
                Ok(code) => self.on_head.push((proof.clone(), Ok(code))),
                Err(Stopped::NoVerdict(ending)) if ending.kind() == Kind::Relocked => {
                    self.proof_failure = Some(ending);
                    return Ok(());
                }
                Err(Stopped::NoVerdict(ending)) if ending.kind() == Kind::Unbuilt => {
                    let shared = NoVerdict::plain(text!(
                        "the head's library tests do not build, so no proof reruns on the head: ",
                        ending.reason()
                    ));
                    for later in &proofs[number..] {
                        self.on_head.push((later.clone(), Err(shared.clone())));
                    }
                    return Ok(());
                }
                Err(Stopped::NoVerdict(ending)) => self.on_head.push((proof.clone(), Err(ending))),
                Err(Stopped::Halt(halt)) => return Err(halt),
            }
        }
        Ok(())
    }

    /// `proof` reruns `proof` in the proof's worktree `tree` as it stands, logged as `label`, and returns
    /// its exit, 0 or 1, once the tree holds the run's `Cargo.lock` and the staged helper counts the
    /// rerun's last line beside that exit. A signal recorded during the helper's question ends the run
    /// after it.
    fn proof(&self, tree: &Path, proof: &Text, label: &str) -> Result<u8, Stopped> {
        let place = self.proof_place();
        let (log, kept) = (place.join(label), place.join("artifacts").join(label));
        let mut argv = vec![OsString::from(PYTHON), self.helper().into_os_string()];
        argv.extend(PROOF.map(OsString::from));
        argv.extend([
            OsString::from("--test"),
            os(proof),
            OsString::from("--artifacts"),
        ]);
        argv.push(kept.clone().into_os_string());
        let env = self.cargo_env(&place.join("target"), Some(&tree.join("Cargo.lock")), &[]);
        let started = Logged {
            log: &log,
            argv: &argv,
            what: HELPER[0],
            cwd: Some(tree),
            env: &env,
            session: true,
            work: self.work(),
        };
        let (code, out) = logged(&started, self.interrupt)?;
        self.interrupt.check()?;
        let rerun = Rerun {
            proof,
            log: self.in_work(&log),
            kept: self.in_work(&kept),
            holds_lock: self.holds_lock(tree),
            code,
            out: &out,
        };
        let results = self
            .results
            .as_ref()
            .expect("a rerun follows the helper's setup");
        let judged = judge_rerun(&rerun, |code, line| {
            let expected = results[usize::from(code == 1)].clone();
            match counts(self.inputs.env(), &self.helper(), code, line) {
                Ok(true) => Ok(HelperVerdict::Counted),
                Ok(false) => Ok(HelperVerdict::Uncounted { expected }),
                Err(why) => Err(text!(
                    "the head's verdict check failed on the rerun of the proof ",
                    proof,
                    ": ",
                    why
                )),
            }
        });
        self.interrupt.check()?;
        Ok(judged?)
    }

    /// `reset` is `git reset --hard --quiet` of the proof's worktree.
    fn reset(&self, tree: &Path) -> Result<Done<String>, CallError> {
        let args = ["reset", "--hard", "--quiet"].map(OsStr::new);
        self.git(tree, &args).and_then(Done::checked)
    }

    /// `live` returns the proof's exits on the head and on the plant. The plant's patch, the head's
    /// bytes, is applied to the proof's worktree, its proof rerun, and the tree reset. An apply or a reset
    /// that fails, or a rerun that leaves the tree without the run's lockfile, is kept for every later
    /// plant; the reset's failure outranks the rerun's ending.
    pub(super) fn live(&mut self, plant: &Plant) -> Result<(u8, u8), Step> {
        if let Some(failure) = &self.proof_failure {
            return Err(failure.clone().into());
        }
        let head = match self
            .on_head
            .iter()
            .find(|(proof, _)| proof == plant.proof())
        {
            Some((_, Ok(code))) => *code,
            Some((_, Err(ending))) => return Err(ending.clone().into()),
            None => unreachable!("the head reran every applying plant's proof"),
        };
        let tree = self
            .proof_tree
            .clone()
            .expect("a head rerun stands in the proof's worktree");
        let patch = self.place(plant.id()).join("plant.patch");
        let args = [
            OsStr::new("apply"),
            OsStr::new("--index"),
            patch.as_os_str(),
        ];
        let broken = |error: CallError, run: &mut Self| {
            if !matches!(error, CallError::Interrupted(_)) {
                run.proof_failure = Some(NoVerdict::plain(text!(
                    "the proof's worktree is no longer the head's tree: ",
                    error.to_string(),
                    " at the plant ",
                    plant.id()
                )));
            }
            Step::from(error)
        };
        if let Err(error) = self.git(&tree, &args).and_then(Done::checked) {
            return Err(broken(error, self));
        }
        let planted = self.proof(
            &tree,
            plant.proof(),
            &text!("plant-", plant.id()).to_string(),
        );
        if let Err(Stopped::Halt(halt)) = planted {
            return Err(halt.into());
        }
        if let Err(error) = self.reset(&tree) {
            return Err(broken(error, self));
        }
        match planted {
            Ok(code) => Ok((head, code)),
            Err(Stopped::NoVerdict(ending)) if ending.kind() == Kind::Relocked => {
                self.proof_failure = Some(ending.clone());
                Err(ending.into())
            }
            Err(ending) => Err(ending.into()),
        }
    }
}
