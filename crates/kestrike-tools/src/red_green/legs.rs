//! The steps of a run between its directories and its receipt: the build lock, the worktrees and the
//! overlay, the comparison of each tree with its commit, the legs and the removal of the worktrees.
//!
//! The run reads the signal record between its steps and at each pause of its waits, pauses that start
//! at 0.5 ms and double up to 20 ms. The steps that make the temporary directory, a worktree or the
//! overlay, and the start of a runner, run whole and act on a signal once they return; each records
//! what it made first, so the cleanup finds it. A Git step outside them is killed on a signal. The waits
//! for the lock and for a runner have no deadline: the lock's ends at the holder's release or a signal,
//! a runner's at its exit and the end of both its pipes. A signal while a runner runs sends it SIGTERM,
//! by its process ID while it is held unreaped, and waits for its exit and its pipes; from a runner's
//! exit on, a signal waits until that leg is judged and stops the run only before a head leg starts.
//! Each runner leads a session of its own, with the handled signals at their default actions, and reads
//! the held lock file as its standard input.

use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ExitStatus, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::evidence::{self, Evidence};
use super::reasons;
use super::record::Leg;
use super::run::{
    Checked, Done, Facts, Halt, TEMP_PREFIX, TOOL, could_not_run, git_step, lock_problem, os, say,
    short, words,
};
use super::runner;
use super::tree::{self, Entries};
use crate::environ::{self, Environ};
use crate::git;
use crate::process::{self, Interrupt};
use crate::python;
use crate::text::{Text, text};

const FIRST_PAUSE: Duration = Duration::from_micros(500);
const PAUSE: Duration = Duration::from_millis(20);

/// The arguments that lead each Git step that builds a leg tree.
const HOOKLESS: [&str; 2] = ["-c", "core.hooksPath=/dev/null"];

/// A thread that reads one of the runner's pipes to its end.
type Reader = JoinHandle<io::Result<Vec<u8>>>;

/// One run's steps and what they made: its temporary directory, its worktrees, the held build lock and
/// the legs that ran.
pub(super) struct Run<'a> {
    facts: &'a Facts<'a>,
    env: &'a Environ,
    checked: &'a Checked,
    directory: &'a Path,
    sources: &'a [(&'static str, Vec<u8>)],
    temp: Option<PathBuf>,
    worktrees: Vec<PathBuf>,
    lock: Option<File>,
    legs: Vec<(&'static str, Leg)>,
    /// While set, a recorded signal waits for the end of the step.
    holding: bool,
    /// A record no handler writes, for the Git steps that run whole.
    whole: Interrupt,
}

impl<'a> Run<'a> {
    pub fn new(
        facts: &'a Facts<'a>,
        env: &'a Environ,
        checked: &'a Checked,
        directory: &'a Path,
        sources: &'a [(&'static str, Vec<u8>)],
    ) -> Self {
        Self {
            facts,
            env,
            checked,
            directory,
            sources,
            temp: None,
            worktrees: Vec::new(),
            lock: None,
            legs: Vec::new(),
            holding: false,
            whole: Interrupt::new(),
        }
    }

    /// `recorded` is each leg that ran, in order, with its judgment.
    pub fn recorded(&self) -> &[(&'static str, Leg)] {
        &self.legs
    }

    /// `check` is the recorded signal, unless a step that runs whole or a judged leg holds it back.
    fn check(&self) -> Result<(), Halt> {
        if self.holding {
            return Ok(());
        }
        Ok(self.facts.interrupt.check()?)
    }

    /// `run_whole` runs `step` whole and then acts on a signal recorded while it ran, ahead of the step's
    /// own result. A step records what it makes before it returns, so the cleanup finds it.
    fn run_whole<T>(&mut self, step: impl FnOnce(&mut Self) -> Result<T, Halt>) -> Result<T, Halt> {
        self.check()?;
        self.holding = true;
        let done = step(self);
        self.holding = false;
        self.check()?;
        done
    }

    /// `git` runs a Git step in `cwd`, or the invoking directory; a recorded signal kills it outside a
    /// step that runs whole.
    fn git<S: AsRef<OsStr>>(&self, args: &[S], cwd: Option<&Path>) -> Result<Done, Halt> {
        let interrupt = if self.holding {
            &self.whole
        } else {
            self.facts.interrupt
        };
        git_step(self.env, args, cwd, interrupt)?.map_err(|error| could_not_run(&error))
    }

    /// `hookless` runs a Git step that builds a leg tree, with hooks disabled, and refuses its failure by
    /// the step's own arguments.
    fn hookless(&self, args: &[OsString], cwd: Option<&Path>) -> Result<(), Halt> {
        let mut argv: Vec<OsString> = HOOKLESS.map(OsString::from).to_vec();
        argv.extend(args.iter().cloned());
        let done = self.git(&argv, cwd)?;
        if done.code != 0 {
            return Err(Halt::Refused(text!(
                "git ",
                words(args),
                ": ",
                done.error()
            )));
        }
        Ok(())
    }

    /// `lock_build` opens the build directory's lock file, refuses one that is no regular file or that
    /// another user owns or can write, waits while another run holds it, and empties it once held.
    fn lock_build(&mut self) -> Result<(), Halt> {
        let target = &self.checked.target_dir;
        let path = target.join("red-green.lock");
        let cannot =
            |why: &str| Halt::Refused(text!("the build lock ", &path, " cannot be opened: ", why));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o644)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)
            .map_err(|error| cannot(&error.to_string()))?;
        let status = file.metadata().map_err(|error| could_not_run(&error))?;
        if let Some(problem) = lock_problem(&status, self.facts.uid) {
            return Err(cannot(problem));
        }
        if !locked(&file).map_err(|error| could_not_run(&error))? {
            let line = text!(TOOL, ": waiting for another run that builds in ", target);
            say(true, &line).map_err(|error| could_not_run(&error))?;
            let mut pause = FIRST_PAUSE;
            loop {
                self.check()?;
                thread::sleep(pause);
                if locked(&file).map_err(|error| could_not_run(&error))? {
                    break;
                }
                pause = (pause * 2).min(PAUSE);
            }
        }
        file.set_len(0).map_err(|error| could_not_run(&error))?;
        self.lock = Some(file);
        Ok(())
    }

    /// `commit_entries` is each path `commit` names with its mode and object ID.
    fn commit_entries(&self, commit: &Text) -> Result<Entries, Halt> {
        let args = [
            OsStr::new("ls-tree"),
            OsStr::new("-r"),
            OsStr::new("-z"),
            OsStr::new("--full-tree"),
            &os(commit),
        ];
        let done = self.git(&args, None)?;
        if done.code != 0 {
            return Err(Halt::Refused(text!(
                "git ls-tree ",
                short(commit),
                ": ",
                done.error()
            )));
        }
        tree::named_entries(&done.stdout).map_err(|tree::Malformed(record)| {
            Halt::Failed(text!(
                "git ls-tree ",
                short(commit),
                " printed a record that is no mode, type, ID and path: ",
                Text::from_os(OsStr::from_bytes(&record)).repr()
            ))
        })
    }

    /// `add_worktree` adds a detached worktree of `commit` named `name` in the run's temporary directory,
    /// which the first call creates.
    fn add_worktree(&mut self, name: &str, commit: &Text) -> Result<PathBuf, Halt> {
        let temp = match &self.temp {
            Some(temp) => temp.clone(),
            None => self.run_whole(|run| {
                let made = (run.facts.make_temp)(TEMP_PREFIX, &run.checked.temp_root)
                    .map_err(|error| could_not_run(&error))?;
                run.temp = Some(made.clone());
                Ok(made)
            })?,
        };
        let tree = temp.join(name);
        self.worktrees.push(tree.clone());
        let args = ["worktree", "add", "--quiet", "--detach"]
            .map(OsString::from)
            .into_iter()
            .chain([tree.clone().into_os_string(), os(commit)])
            .collect::<Vec<_>>();
        self.run_whole(|run| run.hookless(&args, None))?;
        Ok(tree)
    }

    /// `write_runner` writes the runner and selector bytes read at startup into `temp/scripts/`, each as a
    /// new file in the place of any entry there, and returns the runner's path.
    fn write_runner(&self, temp: &Path) -> Result<PathBuf, Halt> {
        let scripts = temp.join("scripts");
        let failed = |path: &Path, error: io::Error| {
            could_not_run(&crate::ownership::PathError::new(path, error))
        };
        match fs::create_dir(&scripts) {
            Err(error) if error.kind() != io::ErrorKind::AlreadyExists || !scripts.is_dir() => {
                return Err(failed(&scripts, error));
            }
            _ => {}
        }
        for (name, data) in self.sources {
            let path = scripts.join(name);
            match fs::remove_file(&path) {
                Err(error) if error.kind() != io::ErrorKind::NotFound => {
                    return Err(failed(&path, error));
                }
                _ => {}
            }
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .and_then(|mut file| file.write_all(data))
                .map_err(|error| failed(&path, error))?;
        }
        Ok(scripts.join(self.sources[0].0))
    }

    /// `compare_tree` refuses a leg whose worktree differs from the entries `named` gives.
    fn compare_tree(&self, leg: &str, tree: &Path, named: &Entries) -> Result<(), Halt> {
        self.check()?;
        let found = tree::tree_difference(tree, named).map_err(|error| could_not_run(&error))?;
        self.check()?;
        match found {
            Some(path) => Err(Halt::Refused(reasons::tree_reason(leg, &path))),
            None => Ok(()),
        }
    }

    /// `run_leg` runs the runner in `tree` as leg `name` and returns its entry once the runner has exited
    /// and both its pipes have ended. From the runner's exit on, a signal waits for the judgment.
    fn run_leg(&mut self, name: &'static str, tree: &Path, runner: &Path) -> Result<Leg, Halt> {
        let options = &self.checked.options;
        let flag = |name: &str, value: &OsStr| {
            let mut joined = OsString::from(format!("--{name}="));
            joined.push(value);
            joined
        };
        let watchdog = python::repr_float(options.watchdog);
        let run_id = self.directory.file_name().unwrap_or_default();
        let mut argv = vec![
            runner.as_os_str().to_os_string(),
            flag("package", &os(&options.package)),
            flag("target", &os(&options.target)),
            flag("test", &os(&options.test)),
            OsString::from("--attempts=1"),
            flag("watchdog", OsStr::new(&watchdog)),
            flag("artifacts", self.directory.as_os_str()),
            flag("run-id", run_id),
            flag("lane", OsStr::new(name)),
            flag("cargo", &os(&options.cargo)),
        ];
        if options.release {
            argv.push(OsString::from("--release"));
        }
        let mut env = self.env.clone();
        for variable in ["CARGO_TARGET_DIR", "CARGO_BUILD_BUILD_DIR"] {
            environ::set(
                &mut env,
                variable,
                self.checked.target_dir.clone().into_os_string(),
            );
        }
        let lock = self
            .lock
            .as_ref()
            .expect("the lock is held before any leg")
            .try_clone()
            .map_err(|error| could_not_run(&error))?;
        let mut command = git::command(&env, "python3");
        command
            .args(&argv)
            .current_dir(tree)
            .stdin(Stdio::from(lock))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        session(&mut command);
        let started = Instant::now();
        self.check()?;
        self.holding = true;
        let spawned = (self.facts.spawn)(&mut command);
        self.holding = false;
        let mut child = match spawned {
            Ok(child) => child,
            Err(error) => {
                self.check()?;
                return Err(could_not_run(&error));
            }
        };
        let readers =
            drain(child.stdout.take()).and_then(|out| Ok((out, drain(child.stderr.take())?)));
        let (out, err) = match readers {
            Ok(readers) => readers,
            Err(error) => {
                terminate(&mut child, None)?;
                return Err(could_not_run(&error));
            }
        };
        if let Err(stop) = self.check() {
            terminate(&mut child, Some((out, err)))?;
            return Err(stop);
        }
        let (status, stdout, stderr) = self.wait(&mut child, out, err)?;
        self.holding = true;
        let seconds = started.elapsed().as_secs_f64();
        let attempt = std::env::var_os("GITHUB_RUN_ATTEMPT").unwrap_or_else(|| OsString::from("1"));
        let announced = runner::announcement(&stderr);
        let mut leg = Leg {
            exit: process::exit_code(status),
            verdict: runner::verdict(&stdout),
            seconds,
            evidence: Evidence::Absent,
            expect_streams: None,
        };
        let read = evidence::evidence(
            self.directory,
            &Text::from_os(&attempt),
            name,
            announced.as_ref(),
        );
        match read {
            Ok(found) => leg.evidence = found,
            Err(error) => {
                self.legs.push((name, leg));
                return Err(could_not_run(&error));
            }
        }
        Ok(leg)
    }

    /// `wait` waits with no deadline for the runner's exit and the end of both pipes, reading its exit
    /// before the signal record at each pause. A signal while the runner runs sends it SIGTERM and waits
    /// for it and its pipes; one after its exit ends the wait at once.
    fn wait(
        &self,
        child: &mut Child,
        out: Reader,
        err: Reader,
    ) -> Result<(ExitStatus, Vec<u8>, Vec<u8>), Halt> {
        let mut status = None;
        let mut pause = FIRST_PAUSE;
        loop {
            if status.is_none() {
                status = child.try_wait().map_err(|error| could_not_run(&error))?;
            }
            if let Some(status) = status
                && out.is_finished()
                && err.is_finished()
            {
                let stdout = joined(out).map_err(|error| could_not_run(&error))?;
                let stderr = joined(err).map_err(|error| could_not_run(&error))?;
                return Ok((status, stdout, stderr));
            }
            if let Err(stop) = self.check() {
                if status.is_none() {
                    terminate(child, Some((out, err)))?;
                }
                return Err(stop);
            }
            thread::sleep(pause);
            pause = (pause * 2).min(PAUSE);
        }
    }

    /// `legs` takes the lock, builds the base leg's tree, runs and judges it, and on a red base does the
    /// same for the head. It returns `None` for a proven run and the refusal's reason otherwise.
    ///
    /// # Errors
    ///
    /// A refusal a step makes, a recorded signal, or a failure outside the run's outcomes.
    pub fn legs(&mut self) -> Result<Option<Text>, Halt> {
        let checked = self.checked;
        self.check()?;
        self.lock_build()?;
        let head_files = self.commit_entries(&checked.head)?;
        let base_tree = self.add_worktree("base", &checked.base)?;
        let temp = self
            .temp
            .clone()
            .expect("the first worktree made the temporary directory");
        let runner = self.write_runner(&temp)?;
        let mut overlay: Vec<OsString> = ["--literal-pathspecs", "checkout"]
            .map(OsString::from)
            .to_vec();
        overlay.push(os(&checked.head));
        overlay.push(OsString::from("--"));
        overlay.extend(checked.options.carry.iter().map(os));
        self.run_whole(|run| run.hookless(&overlay, Some(&base_tree)))?;
        let base_files = self.commit_entries(&checked.base)?;
        let named = tree::base_entries(&base_files, &head_files, &checked.options.carry)
            .map_err(|path| Halt::Failed(text!("the head names no carried path ", path.repr())))?;
        self.compare_tree("base", &base_tree, &named)?;
        let mut base = self.run_leg("base", &base_tree, &runner)?;
        let reason = reasons::base_reason(&mut base, &checked.options);
        self.legs.push(("base", base));
        if reason.is_some() {
            return Ok(reason);
        }
        self.holding = false;
        self.check()?;
        let head_tree = self.add_worktree("head", &checked.head)?;
        let runner = self.write_runner(&temp)?;
        self.compare_tree("head", &head_tree, &head_files)?;
        let head = self.run_leg("head", &head_tree, &runner)?;
        let reason = reasons::head_reason(&head);
        self.legs.push(("head", head));
        Ok(reason)
    }

    /// `remove_trees` removes each worktree the run added by its path, then the temporary directory, then
    /// once more each worktree whose first removal failed, and names on standard error each one that
    /// stays registered or present. Its Git steps run whole.
    ///
    /// # Errors
    ///
    /// A Git step cannot start, or a line cannot be written.
    pub fn remove_trees(&mut self) -> Result<(), Text> {
        self.holding = true;
        let remove = |tree: &Path| -> Result<Done, Text> {
            let mut args = ["worktree", "remove", "--force", "--force"]
                .map(OsString::from)
                .to_vec();
            args.push(tree.as_os_str().to_os_string());
            self.whole_git(&args)
        };
        let mut failed = Vec::new();
        for tree in &self.worktrees {
            if remove(tree)?.code != 0 {
                failed.push(tree.clone());
            }
        }
        if let Some(temp) = &self.temp {
            remove_tree(temp);
        }
        for tree in failed {
            let removed = remove(&tree)?;
            let listed = self.whole_git(&["worktree", "list", "--porcelain"])?;
            let entry = [b"worktree ", tree.as_os_str().as_bytes(), b"\n"].concat();
            let registered = listed
                .stdout
                .windows(entry.len())
                .any(|window| window == entry.as_slice());
            if removed.code != 0 && (registered || tree.exists()) {
                let line = text!(
                    TOOL,
                    ": could not remove worktree ",
                    &tree,
                    ": ",
                    removed.error()
                );
                say(true, &line).map_err(|error| text!(error.to_string()))?;
            }
        }
        Ok(())
    }

    fn whole_git<S: AsRef<OsStr>>(&self, args: &[S]) -> Result<Done, Text> {
        match git_step(self.env, args, None, &self.whole) {
            Ok(Ok(done)) => Ok(done),
            Ok(Err(error)) => Err(text!("git: ", error.to_string())),
            Err(_) => unreachable!("no handler records into the cleanup's own record"),
        }
    }
}

/// `locked` takes the exclusive lock on `file` without waiting and tells whether it holds it.
fn locked(file: &File) -> io::Result<bool> {
    // SAFETY: `flock` takes the open descriptor `file` owns and two flags, and touches no memory.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
        return Ok(false);
    }
    Err(error)
}

/// `session` makes the child lead a session of its own and start with SIGINT, SIGTERM and SIGHUP at
/// their default actions and unblocked.
fn session(command: &mut std::process::Command) {
    let handled = process::handled_set();
    // SAFETY: the hook runs in the forked child before `exec` and calls only `setsid` and
    // `child_defaults`, whose contract states that it calls only async-signal-safe functions; the error
    // path reads `errno` alone. The closure owns its initialized `handled` set.
    unsafe {
        command.pre_exec(move || {
            if libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            process::child_defaults(&handled)
        });
    }
}

fn drain(stream: Option<impl Read + Send + 'static>) -> io::Result<Reader> {
    thread::Builder::new().spawn(move || {
        let mut bytes = Vec::new();
        if let Some(mut stream) = stream {
            stream.read_to_end(&mut bytes)?;
        }
        Ok(bytes)
    })
}

fn joined(reader: Reader) -> io::Result<Vec<u8>> {
    reader.join().expect("a reader thread returns its bytes")
}

/// `terminate` sends SIGTERM to the runner, which the caller holds unreaped, and waits with no deadline
/// for its exit and, where `readers` stand, for both its pipes to end.
///
/// # Errors
///
/// The signal cannot be sent, which leaves the runner unwaited, or the wait or a read fails.
fn terminate(child: &mut Child, readers: Option<(Reader, Reader)>) -> Result<(), Halt> {
    let failed =
        |error: io::Error| Halt::Failed(text!("the runner cannot be stopped: ", error.to_string()));
    let pid = libc::pid_t::try_from(child.id()).expect("a process id fits pid_t");
    // SAFETY: `kill` takes two integers and touches no memory of the caller.
    if unsafe { libc::kill(pid, libc::SIGTERM) } != 0 {
        return Err(failed(io::Error::last_os_error()));
    }
    child.wait().map_err(failed)?;
    if let Some((out, err)) = readers {
        joined(out).and_then(|_| joined(err)).map_err(failed)?;
    }
    Ok(())
}

/// `remove_tree` removes `path` and everything under it as far as it can, passing over each entry it
/// cannot remove; it follows no link.
fn remove_tree(path: &Path) {
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let inner = entry.path();
            match entry.file_type() {
                Ok(kind) if kind.is_dir() => remove_tree(&inner),
                _ => {
                    let _ = fs::remove_file(&inner);
                }
            }
        }
    }
    let _ = fs::remove_dir(path);
}
