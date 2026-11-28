//! Steps 2 to 5 of a run: the lock and the run directory, the diff, the worktree, the listing, the tool, the
//! removal of the worktree and the report.
//!
//! The run writes under the artifacts directory and in the worktree's entry of the repository's Git
//! directory alone, which the removal deletes.

use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use super::config::debug_assertions;
use super::options::{Options, TOOL};
use super::outcomes::{Judgment, Listed, Outcome, Outcomes, judge, read_listing, read_outcomes};
use super::preflight::{CONFIG, GitError, Prepared, git, is_file, preflight, read_regular};
use super::process::{INTERRUPT, ignore_signals, install_handlers, supervise};
use super::rundir::{self, OpenError, make_temp_dir};
use super::stop::{COMPLETE, Fault, INCOMPLETE, REJECTED, Stop};
use crate::args::Parsed;
use crate::json::{self, Integer, Object, Value};
use crate::plants::{Creation, publish_with, remove};
use crate::process::refuse_ignored_sigchld;
use crate::python::{hexdigest, say};
use crate::stream::emit;
use crate::text::{Text, text};

const PACKAGE: &str = "kestrike";
const SOURCE: &str = "crates/kestrike/src";
const DIFF: [&str; 17] = [
    "-c",
    "diff.suppressBlankEmpty=false",
    "diff",
    "--text",
    "--full-index",
    "--no-color",
    "--no-ext-diff",
    "--no-textconv",
    "--src-prefix=a/",
    "--dst-prefix=b/",
    "--find-renames",
    "--diff-algorithm=myers",
    "--unified=3",
    "--inter-hunk-context=0",
    "--indent-heuristic",
    "--no-relative",
    "-O/dev/null",
];
/// The tool exits 4 on a failed baseline, else 3 when a mutant timed out, else 2 when one is missed, else 0.
const TOOL_RESULTS: [i32; 3] = [0, 2, 3];
const BASELINE_FAILED: i32 = 4;
/// The exit code of a run whose write to standard output or standard error failed.
const STREAM_FAILED: u8 = 120;

/// Standard output and standard error of the run. A write that fails turns the exit code into 120.
#[derive(Default)]
struct Streams {
    failed: bool,
}

impl Streams {
    /// `out` writes `line` to standard output and flushes it.
    fn out(&mut self, line: &Text) {
        let mut out = io::stdout().lock();
        self.failed |= say(&mut out, line).and_then(|()| out.flush()).is_err();
    }

    fn err(&mut self, line: &Text) {
        self.failed |= say(&mut io::stderr().lock(), line).is_err();
    }

    fn code(&self, code: u8) -> u8 {
        if self.failed { STREAM_FAILED } else { code }
    }

    /// `refuse` prints a stop that ends the run without a report and returns its exit code.
    fn refuse(&mut self, stop: &Stop) -> u8 {
        if stop.is_fatal() {
            self.err(&text!(TOOL, ": ", stop.reason()));
        } else {
            self.err(&text!("mutants rejected: ", stop.reason()));
        }
        self.code(stop.code())
    }
}

/// One invocation's lock, run directory, worktree, listing and report fields.
pub struct Run {
    prepared: Prepared,
    lock: Option<File>,
    dir: Option<PathBuf>,
    tree: Option<PathBuf>,
    listed: Vec<Listed>,
    diff_sha256: Option<String>,
    config_sha256: Option<String>,
    debug_assertions: Option<String>,
    tool_exit: Option<i32>,
    judgment: Option<Judgment>,
    streams: Streams,
}

fn failed(path: &Path) -> impl FnOnce(io::Error) -> Stop + '_ {
    move |error| Stop::failed(&Fault::os(&error, Some(path.as_os_str())))
}

/// `output` runs `command` with standard input inherited and returns its output.
fn output(command: &mut Command) -> Result<Output, Stop> {
    command
        .stdin(Stdio::inherit())
        .output()
        .map_err(|error| Stop::fatal(Fault::os(&error, Some(OsStr::new("git"))).to_text()))
}

/// `ascii_strip` removes space, tab, line feed, vertical tab, form feed and carriage return from both ends.
pub(super) fn ascii_strip(bytes: &[u8]) -> &[u8] {
    let space = |byte: &u8| b" \t\n\x0b\x0c\r".contains(byte);
    let start = bytes
        .iter()
        .position(|byte| !space(byte))
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !space(byte))
        .map_or(start, |at| at + 1);
    &bytes[start..end]
}

fn os_args<'a>(args: &'a [&'a str]) -> impl Iterator<Item = &'a OsStr> {
    args.iter().map(OsStr::new)
}

impl Run {
    pub fn new(prepared: Prepared) -> Self {
        Self {
            prepared,
            lock: None,
            dir: None,
            tree: None,
            listed: Vec::new(),
            diff_sha256: None,
            config_sha256: None,
            debug_assertions: None,
            tool_exit: None,
            judgment: None,
            streams: Streams::default(),
        }
    }

    fn options(&self) -> &Options {
        &self.prepared.options
    }

    fn open(&mut self) -> Result<PathBuf, OpenError> {
        let dir = rundir::open(&self.prepared.artifacts, &mut self.lock)?;
        self.dir = Some(dir.clone());
        Ok(dir)
    }
}

impl Run {
    fn dir(&self) -> &Path {
        self.dir
            .as_deref()
            .expect("the run directory exists once execute opened it")
    }

    fn shard_args(&self) -> Vec<&OsStr> {
        match &self.options().shard {
            Some(shard) => vec![OsStr::new("--shard"), shard.value.as_os_str()],
            None => Vec::new(),
        }
    }

    /// `tool_outcomes` reads the run's outcome file; a tool exit of 4 reads as a failed baseline whatever
    /// the file holds.
    fn tool_outcomes(&self) -> Option<Outcomes> {
        let path = self.dir.as_ref()?.join("tool/mutants.out/outcomes.json");
        let outcomes = read_outcomes(&fs::read(path).ok()?)?;
        Some(if self.tool_exit == Some(BASELINE_FAILED) {
            outcomes.failed()
        } else {
            outcomes
        })
    }

    /// `install` makes the handled signals record into the run's interrupt from here on.
    ///
    /// # Errors
    ///
    /// A disposition cannot be read or set.
    pub fn install(&self) -> Result<(), Stop> {
        install_handlers().map_err(|error| Stop::failed(&Fault::os(&error, None)))
    }

    fn diff(&mut self) -> Result<PathBuf, Stop> {
        let prepared = &self.prepared;
        let mut args: Vec<&OsStr> = os_args(&DIFF).collect();
        args.extend([OsStr::new(&prepared.base), OsStr::new(&prepared.head)]);
        args.extend(os_args(&["--", SOURCE]));
        let patch = git(&prepared.git_env, prepared.top.as_os_str(), &args)
            .map_err(GitError::incomplete)?;
        let diff = self.dir().join("diff.patch");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&diff)
            .map_err(failed(&diff))?;
        file.write_all(&patch).map_err(failed(&diff))?;
        self.diff_sha256 = Some(hexdigest(&patch));
        Ok(diff)
    }

    /// `add_worktree` adds a detached worktree of the head, with hooks disabled, under the run directory.
    fn add_worktree(&mut self) -> Result<PathBuf, Stop> {
        let dir = self.dir().to_path_buf();
        let tree = make_temp_dir("worktree-", &dir).map_err(|fault| Stop::failed(&fault))?;
        self.tree = Some(tree.clone());
        let prepared = &self.prepared;
        let mut argv: Vec<&OsStr> = vec![
            OsStr::new("git"),
            OsStr::new("-C"),
            prepared.top.as_os_str(),
        ];
        argv.extend(os_args(&[
            "-c",
            "core.hooksPath=/dev/null",
            "worktree",
            "add",
            "--quiet",
            "--detach",
        ]));
        argv.extend([tree.as_os_str(), OsStr::new(&prepared.head)]);
        let (stdout, stderr) = (dir.join("worktree.stdout"), dir.join("worktree.stderr"));
        let added = supervise(&INTERRUPT, &argv, &stdout, &stderr, None, &prepared.git_env)?;
        if added != 0 {
            return Err(Stop::incomplete(text!(format!(
                "git worktree add exited {added}"
            ))));
        }
        Ok(tree)
    }

    /// `copy_lock` copies the invoking checkout's `Cargo.lock` into the worktree when it is a regular file
    /// and the worktree holds no entry at that path, a dangling link included; a worktree with an entry
    /// there leaves the source unread. The lock is opened once and its check and copy read that open,
    /// ahead of the target's creation. Exclusive creation fails on an entry that appears after the first
    /// look, so the copy never writes through a link.
    fn copy_lock(&self, tree: &Path) -> Result<(), Stop> {
        let target = tree.join("Cargo.lock");
        match fs::symlink_metadata(&target) {
            Ok(_) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(failed(&target)(error)),
        }
        let source = self.prepared.top.join("Cargo.lock");
        let Some(bytes) = read_regular(&source).map_err(|fault| Stop::failed(&fault))? else {
            return Ok(());
        };
        let mut copy = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)
        {
            Ok(copy) => copy,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => return Ok(()),
            Err(error) => return Err(failed(&target)(error)),
        };
        copy.write_all(&bytes).map_err(failed(&target))
    }

    /// `read_config` records the digest and the debug-assertion entry of the worktree configuration.
    fn read_config(&mut self, tree: &Path) -> Result<(), Stop> {
        let config = tree.join(CONFIG);
        let Some(data) = read_regular(&config).map_err(|fault| Stop::failed(&fault))? else {
            return Ok(());
        };
        self.config_sha256 = Some(hexdigest(&data));
        let read = debug_assertions(&String::from_utf8_lossy(&data)).map_err(|error| {
            Stop::incomplete(text!("the worktree configuration does not parse: ", error))
        })?;
        self.debug_assertions = read;
        Ok(())
    }
}

impl Run {
    /// `list` lists the diff's mutants into `list.json` and reads them.
    fn list(&mut self, diff: &Path, tree: &Path) -> Result<(), Stop> {
        let manifest = tree.join("Cargo.toml");
        if !is_file(&manifest).map_err(|fault| Stop::failed(&fault))? {
            return Err(Stop::incomplete(Text::from(
                "the head has no root Cargo.toml, so Cargo would take an enclosing workspace",
            )));
        }
        let dir = self.dir().to_path_buf();
        let prepared = &self.prepared;
        let mut argv: Vec<&OsStr> = vec![prepared.cargo.as_os_str(), OsStr::new("mutants")];
        argv.extend(os_args(&["--list", "--json", "-p", PACKAGE, "--in-diff"]));
        argv.push(diff.as_os_str());
        argv.extend(self.shard_args());
        let (listing, stderr) = (dir.join("list.json"), dir.join("list.stderr"));
        let status = supervise(
            &INTERRUPT,
            &argv,
            &listing,
            &stderr,
            Some(tree),
            &prepared.env,
        )?;
        if status != 0 {
            return Err(Stop::incomplete(text!(format!(
                "the listing exited {status}"
            ))));
        }
        let unparsed =
            |error: String| Stop::incomplete(text!("the listing does not parse: ", error));
        let bytes = fs::read(&listing).map_err(failed(&listing))?;
        let text = std::str::from_utf8(&bytes).map_err(|error| unparsed(error.to_string()))?;
        self.listed = read_listing(text).map_err(unparsed)?;
        Ok(())
    }

    /// `within_limit` holds when the listing is no longer than `--max-mutants`.
    fn within_limit(&self) -> bool {
        Integer::from(self.listed.len()) <= self.options().max_mutants
    }

    /// `execute` runs steps 2 to 4 and the outcome reading of step 5 and records their fields.
    ///
    /// # Errors
    ///
    /// The stop that ends the run before its report: a rejected lock or limit, a failed step, or a
    /// recorded signal.
    pub fn execute(&mut self) -> Result<(), Stop> {
        if self.dir.is_some() {
            return Err(Stop::fatal(Text::from("a run executes once")));
        }
        self.open().map_err(OpenError::into_stop)?;
        INTERRUPT.check()?;
        let diff = self.diff()?;
        INTERRUPT.check()?;
        let tree = self.add_worktree()?;
        self.copy_lock(&tree)?;
        self.read_config(&tree)?;
        INTERRUPT.check()?;
        if fs::metadata(&diff).map_err(failed(&diff))?.len() > 0 {
            self.list(&diff, &tree)?;
        }
        INTERRUPT.check()?;
        if !self.within_limit() {
            let limit = &self.options().max_mutants;
            let line = format!(
                "mutants: {} listed, above --max-mutants {limit}",
                self.listed.len()
            );
            self.streams.out(&Text::from(line));
            return Err(Stop::rejected(Text::from(
                "raise --max-mutants or pass --shard K/N",
            )));
        }
        if self.listed.is_empty() {
            self.judgment = Some(judge(&[], Some(&Outcomes::empty()), None));
            return Ok(());
        }
        self.test_mutants(&diff, &tree)
    }

    /// `test_mutants` runs the tool over the listed mutants in the worktree and judges its outcomes.
    fn test_mutants(&mut self, diff: &Path, tree: &Path) -> Result<(), Stop> {
        let dir = self.dir().to_path_buf();
        let output = dir.join("tool");
        let count = self.listed.len();
        let line = text!(
            format!("mutants: testing {count} mutants; tool output in "),
            output
        );
        self.streams.err(&line);
        let prepared = &self.prepared;
        let mut argv: Vec<&OsStr> = vec![prepared.cargo.as_os_str(), OsStr::new("mutants")];
        argv.extend(os_args(&["--in-place", "-p", PACKAGE, "--in-diff"]));
        argv.extend([diff.as_os_str(), OsStr::new("--output"), output.as_os_str()]);
        argv.extend(self.shard_args());
        argv.push(OsStr::new("--"));
        let tests: Vec<OsString> = prepared
            .tests
            .iter()
            .map(|word| {
                word.to_os()
                    .expect("a word split from an argument encodes to its bytes")
            })
            .collect();
        argv.extend(tests.iter().map(OsString::as_os_str));
        let (stdout, stderr) = (dir.join("tool.stdout"), dir.join("tool.stderr"));
        let env = &prepared.env;
        let exit = supervise(&INTERRUPT, &argv, &stdout, &stderr, Some(tree), env)?;
        self.tool_exit = Some(exit);
        let known = TOOL_RESULTS.contains(&exit) || exit == BASELINE_FAILED;
        let reason = (!known).then(|| text!(format!("the tool exited {exit}")));
        self.judgment = Some(judge(&self.listed, self.tool_outcomes().as_ref(), reason));
        Ok(())
    }

    /// `hand_off` sets the handled signals to be ignored, so the removal's children inherit that, and then
    /// reads the interrupt once more: a signal recorded by then makes the run interrupted, whatever
    /// `executed` holds. It returns the stop that ended the run, or `None` when it ran through.
    pub fn hand_off(&self, executed: Result<(), Stop>) -> Option<Stop> {
        let ignored = ignore_signals().map_err(|error| Stop::failed(&Fault::os(&error, None)));
        if let Some(signal) = INTERRUPT.recorded() {
            return Some(Stop::interrupted(signal));
        }
        executed.and(ignored).err()
    }
}

impl Run {
    /// `remove_worktree` removes the worktree and returns why its directory or registration remains.
    ///
    /// A stopped `worktree add` leaves its `initializing` lock, which the second `--force` overrides. Git
    /// refuses a directory without a valid `.git` file and drops the registration once the directory is
    /// gone, so a removal that failed is repeated after the directory's removal, which goes past each
    /// entry it cannot remove and leaves a link at the tree's path. The listing prints a
    /// path's bytes as they are, so the whole record is matched in the listing's bytes.
    fn remove_worktree(&self, tree: &Path) -> Result<Option<Text>, Stop> {
        let prepared = &self.prepared;
        let git = |args: &[&OsStr]| {
            let mut command = Command::new("git");
            command
                .arg("-C")
                .arg(&prepared.top)
                .args(args)
                .env_clear()
                .envs(prepared.git_env.iter().cloned());
            command
        };
        let mut unregister: Vec<&OsStr> =
            os_args(&["worktree", "remove", "--force", "--force"]).collect();
        unregister.push(tree.as_os_str());
        let mut removed = output(&mut git(&unregister))?;
        remove(tree);
        if !removed.status.success() {
            removed = output(&mut git(&unregister))?;
        }
        let listing: Vec<&OsStr> = os_args(&["worktree", "list", "--porcelain"]).collect();
        let listed = output(&mut git(&listing))?;
        let registered = !listed.status.success() || {
            let resolved = crate::paths::resolve(tree)
                .map_err(|error| Stop::fatal(Fault::os(&error, None).to_text()))?;
            let mut record = b"\nworktree ".to_vec();
            record.extend_from_slice(resolved.as_os_str().as_bytes());
            record.push(b'\n');
            let mut records = b"\n".to_vec();
            records.extend_from_slice(&listed.stdout);
            records
                .windows(record.len())
                .any(|window| window == record.as_slice())
        };
        if !registered && fs::symlink_metadata(tree).is_err() {
            return Ok(None);
        }
        let mut detail = ascii_strip(&removed.stderr);
        if detail.is_empty() {
            detail = ascii_strip(&listed.stderr);
        }
        Ok(Some(text!(
            "the worktree ",
            tree,
            " remains: ",
            OsStr::from_bytes(detail)
        )))
    }

    fn report(&self, judgment: &Judgment) -> Object {
        let prepared = &self.prepared;
        let string =
            |value: Option<&str>| value.map_or(Value::Null, |value| Value::String(value.into()));
        let mut report = Object::new();
        report.insert("base", Value::String(prepared.base.as_str().into()));
        report.insert("head", Value::String(prepared.head.as_str().into()));
        report.insert("tool_version", Value::String(prepared.version.clone()));
        report.insert("machine", Value::String(prepared.machine.clone()));
        let shard = self.options().shard.as_ref().map_or(Value::Null, |shard| {
            let mut numbers = Object::new();
            numbers.insert("k", Value::Integer(shard.k.clone()));
            numbers.insert("n", Value::Integer(shard.n.clone()));
            Value::Object(numbers)
        });
        report.insert("shard", shard);
        let tests = prepared.tests.iter().cloned().map(Value::String);
        report.insert("tests", Value::Array(tests.collect()));
        report.insert("diff_sha256", string(self.diff_sha256.as_deref()));
        report.insert("config_sha256", string(self.config_sha256.as_deref()));
        report.insert("debug_assertions", string(self.debug_assertions.as_deref()));
        let exit = self.tool_exit.map_or(Value::Null, |exit| {
            let digits = exit.unsigned_abs().to_string();
            Value::Integer(Integer::from_digits(exit < 0, &digits).expect("an exit code is digits"))
        });
        report.insert("tool_exit", exit);
        judgment.fields(&mut report);
        report
    }

    fn result_line(&self, judgment: &Judgment) -> Text {
        let prepared = &self.prepared;
        let short = |id: &str| id.chars().take(12).collect::<String>();
        let mut place = text!(
            format!(
                "{} against {} on ",
                short(&prepared.head),
                short(&prepared.base)
            ),
            prepared.machine
        );
        if let Some(shard) = &self.options().shard {
            place = text!(place, format!(", shard {}/{}", shard.k, shard.n));
        }
        let state = if judgment.complete() {
            "complete"
        } else {
            "incomplete"
        };
        let count = |outcome| judgment.count(outcome);
        text!(
            "mutants: ",
            place,
            format!(
                ": {} listed, {} caught, {} missed, {} timeout, {} unviable; {state}",
                judgment.listed(),
                count(Outcome::Caught),
                count(Outcome::Missed),
                count(Outcome::Timeout),
                count(Outcome::Unviable)
            )
        )
    }
}

impl Run {
    /// `write_report` writes `report.json` into the run directory, which it creates when execute made
    /// none, through a new file beside it that it renames over the report, and returns its path.
    fn write_report(&mut self, judgment: &Judgment) -> Result<PathBuf, Text> {
        let dir = match self.dir.clone() {
            Some(dir) => dir,
            None => self.open().map_err(|error| error.text())?,
        };
        let path = dir.join("report.json");
        let mut written = json::indented(&Value::Object(self.report(judgment)))
            .expect("every phase time of a report is finite");
        written.push('\n');
        publish_with(&path, &written, Creation::Mode(0o666)).map_err(|error| {
            Fault::os(error.error(), Some(error.path().as_os_str()))
                .text()
                .clone()
        })?;
        Ok(path)
    }

    /// `finish` removes the worktree and, unless `stop` rejected the input, writes the report and prints
    /// its lines, and returns the exit code.
    ///
    /// `stop` is the stop that ended execute, or `None` when it ran through. A stop with exit 1, or a
    /// worktree that remains after the removal, makes the report incomplete even when every listed mutant
    /// was judged; a run that is already incomplete keeps its own reason.
    pub fn finish(mut self, stop: Option<Stop>) -> u8 {
        let _ = ignore_signals();
        let leftover = match self.tree.clone() {
            Some(tree) => match self.remove_worktree(&tree) {
                Ok(leftover) => leftover,
                Err(fatal) => return self.streams.refuse(&fatal),
            },
            None => None,
        };
        if let Some(stop) = stop
            .as_ref()
            .filter(|stop| stop.code() == REJECTED || stop.is_fatal())
        {
            let code = self.streams.refuse(stop);
            if let Some(leftover) = &leftover {
                self.streams.err(&text!("mutants: ", leftover));
            }
            return self.streams.code(code);
        }
        let mut reason = stop.map(|stop| stop.reason().clone());
        if let Some(leftover) = leftover {
            self.streams.err(&text!("mutants: ", leftover));
            let judged = self
                .judgment
                .as_ref()
                .and_then(|judgment| judgment.reason.clone());
            reason = reason.or(judged).or(Some(leftover));
        }
        if reason.is_some() {
            let outcomes = self.tool_outcomes();
            self.judgment = Some(judge(&self.listed, outcomes.as_ref(), reason));
        }
        let judgment = self.judgment.take().unwrap_or_else(|| {
            let reason = Text::from("the run ended before its steps ran");
            judge(&self.listed, None, Some(reason))
        });
        let path = match self.write_report(&judgment) {
            Ok(path) => path,
            Err(error) => {
                let line = text!("mutants: the report could not be written: ", error);
                self.streams.err(&line);
                return self.streams.code(INCOMPLETE);
            }
        };
        self.streams.err(&text!("report: ", path));
        self.print_result(&judgment)
    }

    /// `print_result` prints the result line, the reason of an incomplete run and each missed mutant, or
    /// `mutants: 0 listed` for a complete run with no mutant, and returns the exit code.
    fn print_result(&mut self, judgment: &Judgment) -> u8 {
        if judgment.mutants.is_empty() && judgment.complete() {
            self.streams.out(&Text::from("mutants: 0 listed"));
            return self.streams.code(COMPLETE);
        }
        let line = self.result_line(judgment);
        self.streams.out(&line);
        if let Some(reason) = &judgment.reason {
            self.streams.out(&text!("reason: ", reason));
        }
        for entry in judgment.mutants.iter().filter(|entry| entry.is_missed()) {
            self.streams.out(&text!("missed: ", entry.name()));
        }
        self.streams.code(if judgment.complete() {
            COMPLETE
        } else {
            INCOMPLETE
        })
    }
}

/// `run` is the tool's entry: it reads the command line, refuses a start with SIGCHLD ignored, runs step
/// 1, then the run with the handlers installed, the hand-off and the finish.
pub fn run(_top: &Path, args: &[OsString]) -> u8 {
    let options = match super::options::parse(args) {
        Parsed::Run(options) => options,
        Parsed::Help(help) => {
            let Err(error) = emit(io::stdout().as_fd(), &help) else {
                return COMPLETE;
            };
            let line = format!("{TOOL}: standard output: {error}\n");
            let _ = emit(io::stderr().as_fd(), &line);
            return STREAM_FAILED;
        }
        Parsed::Refused { code, text } => {
            let written = io::stderr().write_all(text.as_bytes());
            return if written.is_ok() { code } else { STREAM_FAILED };
        }
    };
    if let Err(refusal) = refuse_ignored_sigchld() {
        return Streams::default().refuse(&Stop::rejected(Text::from(refusal)));
    }
    let prepared = match preflight(options) {
        Ok(prepared) => prepared,
        Err(stop) => return Streams::default().refuse(&stop),
    };
    let mut run = Run::new(prepared);
    let executed = run.install().and_then(|()| run.execute());
    let stop = run.hand_off(executed);
    run.finish(stop)
}
