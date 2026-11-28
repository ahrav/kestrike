//! Steps 3 to 6 of a live plant: its planted commit and archive, its sweeps, `campaign confirm` and the
//! seed checks on the unpatched head's archive, which the run builds once, at the first seed check.
//!
//! The planted commit takes the head's date and a fixed identity, which the environment sets above every
//! configuration scope, so it depends on the head and the patch alone. Every archive build writes the
//! run's `Cargo.lock` into its tree, builds with `CARGO_PROFILE_DEV_OPT_LEVEL=3` and
//! `CARGO_PROFILE_DEV_DEBUG_ASSERTIONS=true` into a target and build directory of its own, and removes
//! that directory after the build; the removal runs whole.

use std::cell::Cell;
use std::ffi::{OsStr, OsString};
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

use super::child::{Logged, logged};
use super::ending::{Halt, Step, Stopped};
use super::entry::Entry;
use super::git::{self, Done};
use super::judgment::{Ask, Sweep, judge};
use super::output::{Pins, archive_pins, first_object};
use super::record::Plant;
use super::run::{Run, open_lock, remove};
use super::seed::Manifest;
use super::status::profile_runs;
use super::suspects::Suspect;
use super::verdict::NoVerdict;
use crate::json::{Integer, Object};
use crate::ownership::make_private;
use crate::text::{Text, text};

/// The identity of every planted commit.
const IDENTITY: [(&str, &str); 4] = [
    ("GIT_AUTHOR_NAME", "plant-runner"),
    ("GIT_AUTHOR_EMAIL", "plant-runner@invalid"),
    ("GIT_COMMITTER_NAME", "plant-runner"),
    ("GIT_COMMITTER_EMAIL", "plant-runner@invalid"),
];

fn os(text: &impl std::fmt::Display) -> OsString {
    OsString::from(text.to_string())
}

/// `rounds` is `--rounds` as a count of sweeps; a count past `u64` is reached by no run.
fn rounds(value: &Integer) -> u64 {
    value.to_string().parse().unwrap_or(u64::MAX)
}

impl Run<'_> {
    fn campaign(&self, args: &[OsString]) -> Vec<OsString> {
        let mut argv = vec![self.inputs.campaign().as_os_str().to_os_string()];
        argv.extend_from_slice(args);
        argv
    }

    /// `command` runs `campaign ARGS` with its output in `LOG.out` and `LOG.err`.
    fn command(
        &self,
        log: &Path,
        args: &[OsString],
        cwd: Option<&Path>,
        env: Option<&crate::environ::Environ>,
    ) -> Result<(i32, String), Stopped> {
        let what = text!("campaign ", Text::from_os(&args[0])).to_string();
        let argv = self.campaign(args);
        let started = Logged {
            log,
            argv: &argv,
            what: &what,
            cwd,
            env: env.unwrap_or(self.inputs.env()),
            session: false,
            work: self.work(),
        };
        logged(&started, self.interrupt)
    }

    /// `json` is the JSON object the first line of `campaign ARGS` prints.
    fn json(&self, log: &Path, args: &[OsString]) -> Result<Object, Stopped> {
        let (code, out) = self.command(log, args, None, None)?;
        let name = args[0].to_string_lossy().into_owned();
        if code != 0 {
            return Err(NoVerdict::plain(text!("`campaign ", name, "` exited ", code)).into());
        }
        Ok(first_object(&out, &name)?)
    }

    /// `archive` builds the archive of `tree`, `what`, at `place/archive` and returns it with its pins.
    /// The run's `Cargo.lock` goes into the tree first, and the target directory goes after the build,
    /// whatever its ending.
    fn archive(
        &self,
        place: &Path,
        tree: &Path,
        what: &str,
        unread: &Cell<bool>,
    ) -> Result<(PathBuf, Pins), Step> {
        let target = place.join("target");
        let env = self.cargo_env(
            &target,
            None,
            &[
                ("CARGO_PROFILE_DEV_OPT_LEVEL", OsStr::new("3")),
                ("CARGO_PROFILE_DEV_DEBUG_ASSERTIONS", OsStr::new("true")),
            ],
        );
        let output = place.join("archive");
        self.write_lock(tree, what)?;
        let args = ["sim", "archive", "--output"].map(OsString::from);
        let mut args = args.to_vec();
        args.push(output.clone().into_os_string());
        let built = self.command(&output, &args, Some(tree), Some(&env));
        remove(&target);
        self.interrupt.check()?;
        let (code, out) = built?;
        let err = self.in_work(place).join("archive.err");
        let pins = archive_pins(code, &out, what, &err)?;
        let kept = output.join("Cargo.lock");
        let unequal = || {
            NoVerdict::plain(text!(
                "the archive of ",
                what,
                " keeps no regular Cargo.lock equal to the run's"
            ))
        };
        let file = match open_lock(&kept) {
            Ok(file) => file,
            Err(error) => {
                return Err(match fs::symlink_metadata(&kept) {
                    Ok(status) if status.is_file() => {
                        unread.set(true);
                        NoVerdict::unreadable(&kept, &error, self.work())
                    }
                    _ => unequal(),
                }
                .into());
            }
        };
        match self.lock_bytes(file) {
            Ok(Some(bytes)) if bytes == self.inputs.lock() => {}
            Ok(_) => return Err(unequal().into()),
            Err(error) => {
                unread.set(true);
                return Err(NoVerdict::unreadable(&kept, &error, self.work()).into());
            }
        }
        Ok((output, pins))
    }

    /// `base_archive` caches the unpatched head's archive and pins on success. It caches a `NoVerdict`
    /// from `Step::Git`, or from `Step::NoVerdict` when `unread` is false; an `unread` failure returns
    /// uncached, so the next call builds again.
    fn base_archive(&mut self) -> Result<Result<(PathBuf, Pins), NoVerdict>, Halt> {
        if self.base.is_none() {
            let place = self.work().join("base");
            let unread = Cell::new(false);
            let built = self
                .tree(&place, |why| {
                    unread.set(true);
                    NoVerdict::plain(why)
                })
                .and_then(|tree| self.archive(&place, &tree, "the unpatched head", &unread));
            self.base = Some(match built {
                Ok(base) => Ok(base),
                Err(Step::Halt(halt)) => return Err(halt),
                Err(Step::NoVerdict(ending)) if unread.get() => return Ok(Err(ending)),
                Err(Step::NoVerdict(ending)) => Err(ending),
                Err(Step::Git(failed)) => {
                    let log = self.keep_git_error(&place, &failed);
                    Err(NoVerdict::plain(text!(
                        "the unpatched head's worktree: ",
                        failed.shown(),
                        "; its error is in ",
                        log
                    )))
                }
            });
        }
        Ok(self.base.clone().expect("the base archive is built"))
    }

    /// `sweep` sweeps the plant's profiles until each one's `next` reaches `--runs`, for at most
    /// `--rounds` sweeps, and returns the last sweep's exit and status; a sweep that exits 1 ends the
    /// loop.
    fn sweep(&self, plant: &Plant, archive: &Path, place: &Path) -> Result<(i32, Object), Stopped> {
        let options = self.inputs.options();
        let root = place.join("root");
        let expected = plant.expected();
        let (mut code, mut status) = (0, Object::new());
        for number in 1..=rounds(options.rounds()) {
            let args = [
                os(&"sweep"),
                os(&"--root"),
                root.clone().into_os_string(),
                os(&"--archive"),
                archive.as_os_str().to_os_string(),
                os(&"--campaign"),
                os(&text!("plant-", plant.id())),
                os(&"--profiles"),
                os(&Text::join(",", expected.iter().copied())),
                os(&"--workers"),
                os(options.workers()),
                os(&"--for"),
                os(options.seconds()),
            ];
            (code, _) = self.command(&place.join(format!("sweep-{number}")), &args, None, None)?;
            if code != 0 && code != 1 {
                return Err(NoVerdict::plain(text!("`campaign sweep` exited ", code)).into());
            }
            let asked = [
                os(&"sweep-status"),
                os(&"--root"),
                root.clone().into_os_string(),
            ];
            status = self.json(&place.join(format!("status-{number}")), &asked)?;
            if code == 1 {
                break;
            }
            let mut reached = true;
            for profile in &expected {
                if profile_runs(&status, profile)?.next() < options.runs() {
                    reached = false;
                    break;
                }
            }
            if reached {
                break;
            }
        }
        Ok((code, status))
    }

    /// `judge_plant` commits the plant's patch in its worktree `tree`, builds the planted tree's archive,
    /// sweeps it and sets the plant's result on `entry`.
    pub(super) fn judge_plant(
        &mut self,
        plant: &Plant,
        entry: &mut Entry,
        tree: &Path,
    ) -> Result<(), Step> {
        let place = self.place(plant.id());
        let patch = place.join("plant.patch");
        let apply = [
            OsStr::new("apply"),
            OsStr::new("--index"),
            patch.as_os_str(),
        ];
        let _ = self.git(tree, &apply).and_then(Done::checked)?;
        let mut dated = vec![
            ("GIT_AUTHOR_DATE", OsStr::new(&self.date)),
            ("GIT_COMMITTER_DATE", OsStr::new(&self.date)),
        ];
        dated.extend(IDENTITY.map(|(name, value)| (name, OsStr::new(value))));
        let env = self.env_with(&dated);
        let message = os(&text!("plant ", plant.id()));
        let commit = [
            OsStr::new("commit"),
            OsStr::new("--quiet"),
            OsStr::new("--no-verify"),
            OsStr::new("--no-gpg-sign"),
            OsStr::new("--message"),
            &message,
        ];
        let _ = git::text_until(&env, tree, &commit, self.interrupt).and_then(Done::checked)?;
        let parsed = |name: &str| -> Result<Text, Step> {
            let args = [OsStr::new("rev-parse"), OsStr::new(name)];
            let done = self.git(tree, &args).and_then(Done::checked)?;
            Ok(Text::from(crate::text::strip_str(&done.stdout)))
        };
        entry.set_commit(&parsed("HEAD")?);
        entry.set_tree(&parsed("HEAD^{tree}")?);
        let (archive, pins) = self.archive(&place, tree, "the planted tree", &Cell::new(false))?;
        if !entry.archived(&pins) {
            return Ok(());
        }
        let (code, status) = self.sweep(plant, &archive, &place)?;
        let options = self.inputs.options();
        let work = self.inputs.work();
        let sweep = Sweep::new(code, &status, &place, work, options)
            .expect("a sweep that ended in the loop exited 0 or 1");
        let mut asking = Asking {
            run: self,
            place: &place,
            archive: &archive,
            halted: None,
        };
        judge(entry, &sweep, &mut asking);
        asking.halted.map_or(Ok(()), |halt| Err(halt.into()))
    }
}

/// The reason an ask gives once the run has ended.
const ENDED: &str = "the run has ended";

/// The children the judgment asks of a run. Once one of them ends the run, every later ask returns
/// its error with no child started.
struct Asking<'r, 'a> {
    run: &'r mut Run<'a>,
    place: &'r Path,
    archive: &'r Path,
    halted: Option<Halt>,
}

impl Asking<'_, '_> {
    fn halt(&mut self, halt: Halt) -> Text {
        self.halted.get_or_insert(halt);
        Text::from(ENDED)
    }

    fn halted(&self) -> Option<Text> {
        self.halted.as_ref().map(|_| Text::from(ENDED))
    }
}

impl Ask for Asking<'_, '_> {
    fn confirm(&mut self) -> Result<(i32, String), NoVerdict> {
        if let Some(ended) = self.halted() {
            return Err(NoVerdict::plain(ended));
        }
        let args = [
            os(&"confirm"),
            os(&"--root"),
            self.place.join("root").into_os_string(),
            os(&"--archive"),
            self.archive.as_os_str().to_os_string(),
        ];
        match self
            .run
            .command(&self.place.join("confirm"), &args, None, None)
        {
            Ok(done) => Ok(done),
            Err(Stopped::NoVerdict(ending)) => Err(ending),
            Err(Stopped::Halt(halt)) => Err(NoVerdict::plain(self.halt(halt))),
        }
    }

    fn run_seed(&mut self, suspect: &Suspect, manifest: &Manifest) -> Result<(i32, String), Text> {
        if let Some(ended) = self.halted() {
            return Err(ended);
        }
        let (archive, pins) = match self.run.base_archive() {
            Ok(Ok(base)) => base,
            Ok(Err(ending)) => return Err(ending.reason().clone()),
            Err(halt) => return Err(self.halt(halt)),
        };
        let profile = suspect
            .profile()
            .to_os()
            .ok_or_else(|| text!(suspect.profile().repr(), " names no directory"))?;
        let check = self.place.join("seeds").join(profile).join(format!(
            "{}-{}",
            suspect.run(),
            suspect.seed()
        ));
        let parent = check
            .parent()
            .expect("a seed check lies in its profile's directory");
        make_private(parent).map_err(|error| Text::from(error.to_string()))?;
        let shown = |error: std::io::Error, path: &Path| {
            Text::from(crate::ownership::PathError::new(path, error).to_string())
        };
        DirBuilder::new()
            .mode(0o700)
            .create(&check)
            .map_err(|error| shown(error, &check))?;
        let written = check.join("manifest");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&written)
            .and_then(|mut file| {
                let pinned = manifest.pinned(&pins);
                crate::fixtures::fits(pinned.as_bytes().len())?;
                file.write_all(pinned.as_bytes())
            })
            .map_err(|error| shown(error, &written))?;
        let args = [
            os(&"sim"),
            os(&"run"),
            os(&"--archive"),
            archive.into_os_string(),
            os(&"--manifest"),
            written.into_os_string(),
            os(&"--artifacts"),
            check.join("artifacts").into_os_string(),
        ];
        match self.run.command(&check.join("run"), &args, None, None) {
            Ok(done) => Ok(done),
            Err(Stopped::NoVerdict(ending)) => Err(ending.reason().clone()),
            Err(Stopped::Halt(halt)) => Err(self.halt(halt)),
        }
    }
}
