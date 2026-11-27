//! Steps 2 to 5 of a run: the lock and the run directory, the diff, the worktree, the listing, the tool, the
//! removal of the worktree and the report.
//!
//! The run writes under the artifacts directory and in the worktree's entry of the repository's Git
//! directory alone, which the removal deletes.

use std::ffi::{OsStr, OsString};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use super::config::debug_assertions;
use super::options::{Options, TOOL};
use super::outcomes::{Judgment, Listed, Outcomes, judge, read_listing, read_outcomes};
use super::pieces::text;
use super::preflight::{CONFIG, GitError, Prepared, git, is_file, preflight};
use super::process::{INTERRUPT, ignore_signals, install_handlers, supervise};
pub use super::stop::Stop;
use super::stop::{COMPLETE, Fault, INCOMPLETE, REJECTED};
use crate::args::Parsed;
use crate::json::{self, Integer, Object, Value};
use crate::ownership::{PrivateError, make_private, real_uid};
use crate::python::say;
use crate::text::Text;

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
const NAME_LETTERS: &[u8; 37] = b"abcdefghijklmnopqrstuvwxyz0123456789_";
const NAME_LENGTH: usize = 8;
const NAME_ATTEMPTS: usize = 10_000;

/// The run directory could not be made: an unexpected error, or a lock the run refuses.
enum OpenError {
    Fault(Fault),
    Stop(Stop),
}

/// Standard output and standard error of the run. A write that fails turns the exit code into 120.
#[derive(Default)]
struct Streams {
    failed: bool,
}

impl Streams {
    fn say(&mut self, stderr: bool, line: &Text) {
        let written = if stderr {
            say(&mut io::stderr().lock(), line)
        } else {
            let mut out = io::stdout().lock();
            say(&mut out, line).and_then(|()| out.flush())
        };
        self.failed |= written.is_err();
    }

    fn code(&self, code: u8) -> u8 {
        if self.failed { 120 } else { code }
    }

    /// `refuse` prints a stop that ends the run before the run directory and returns its exit code.
    fn refuse(&mut self, stop: &Stop) -> u8 {
        if stop.is_fatal() {
            self.say(true, &text!(TOOL, ": ", stop.reason()));
        } else {
            self.say(true, &text!("mutants rejected: ", stop.reason()));
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

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn os_fault(path: &Path) -> impl FnOnce(io::Error) -> Fault + '_ {
    move |error| Fault::os(&error, Some(path.as_os_str()))
}

fn failed(path: &Path) -> impl FnOnce(io::Error) -> Stop + '_ {
    move |error| Stop::failed(&Fault::os(&error, Some(path.as_os_str())))
}

/// `random_letters` fills `letters` with letters of [`NAME_LETTERS`] drawn uniformly from the kernel's
/// random bytes.
fn random_letters(letters: &mut [u8]) -> io::Result<()> {
    let mut filled = 0;
    while filled < letters.len() {
        let mut byte = 0u8;
        // SAFETY: `getrandom` writes at most one byte into `byte`, a valid, writable local.
        let read = unsafe { libc::getrandom((&raw mut byte).cast(), 1, 0) };
        if read < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        let span = u8::try_from(NAME_LETTERS.len()).expect("the letters fit a byte");
        if read == 1 && byte < span * (u8::MAX / span) {
            letters[filled] = NAME_LETTERS[usize::from(byte % span)];
            filled += 1;
        }
    }
    Ok(())
}

/// `make_temp_dir` creates `parent/PREFIX` and eight random letters as a directory of mode 0700, drawing
/// a new name while one is taken.
fn make_temp_dir(prefix: &str, parent: &Path) -> io::Result<PathBuf> {
    for _ in 0..NAME_ATTEMPTS {
        let mut letters = [0u8; NAME_LENGTH];
        random_letters(&mut letters)?;
        let mut name = prefix.as_bytes().to_vec();
        name.extend_from_slice(&letters);
        let path = parent.join(OsStr::from_bytes(&name));
        match DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "no usable temporary directory name found",
    ))
}

/// `utc_stamp` writes the UTC wall clock as `YYYYmmddTHHMMSSZ-`.
fn utc_stamp() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    let (days, rest) = (seconds / 86_400, seconds % 86_400);
    let days = i64::try_from(days).expect("the day count fits i64") + 719_468;
    let era = days.div_euclid(146_097);
    let of_era = days.rem_euclid(146_097);
    let year_of_era = (of_era - of_era / 1460 + of_era / 36_524 - of_era / 146_096) / 365;
    let of_year = of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted = (5 * of_year + 2) / 153;
    let day = of_year - (153 * shifted + 2) / 5 + 1;
    let month = if shifted < 10 {
        shifted + 3
    } else {
        shifted - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    let (hour, minute, second) = (rest / 3600, rest / 60 % 60, rest % 60);
    format!("{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}Z-")
}

/// `take_lock` locks `path` for the life of the returned file. The open follows no link and waits on no
/// FIFO; the lock must be a regular file this user owns and no other run may hold it.
fn take_lock(path: &Path) -> Result<File, OpenError> {
    let opened = OpenOptions::new()
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path);
    let lock = opened.map_err(|error| {
        let fault = Fault::os(&error, Some(path.as_os_str()));
        OpenError::Stop(Stop::rejected(text!(
            path,
            " cannot be opened as a lock file: ",
            fault.text()
        )))
    })?;
    let status = lock
        .metadata()
        .map_err(|error| OpenError::Fault(os_fault(path)(error)))?;
    if !status.is_file() || status.uid() != real_uid() {
        return Err(OpenError::Stop(Stop::rejected(text!(
            path,
            " is not a regular file the invoking user owns"
        ))));
    }
    // SAFETY: `flock` takes the descriptor of `lock`, which stays open across the call, and two flags.
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
            return Err(OpenError::Stop(Stop::rejected(text!(
                "another run holds ",
                path
            ))));
        }
        return Err(OpenError::Fault(Fault::os(&error, None)));
    }
    Ok(lock)
}

fn private_fault(error: &PrivateError) -> Fault {
    match error {
        PrivateError::Io(error) => Fault::os(error.error(), Some(error.path().as_os_str())),
        PrivateError::Shared(_) => Fault::library("PrivateError", error),
    }
}

/// `output` runs `command` with standard input inherited and returns its output.
fn output(command: &mut Command) -> Result<Output, Stop> {
    command
        .stdin(Stdio::inherit())
        .output()
        .map_err(|error| Stop::fatal(Fault::os(&error, Some(OsStr::new("git"))).to_text()))
}

/// `ascii_strip` removes space, tab, line feed, vertical tab, form feed and carriage return from both ends.
fn ascii_strip(bytes: &[u8]) -> &[u8] {
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

    /// `open` makes the artifacts directory private, takes its lock once, and creates a new run directory
    /// named by the UTC wall clock after the lock is held.
    fn open(&mut self) -> Result<PathBuf, OpenError> {
        let artifacts = self.prepared.artifacts.clone();
        make_private(&artifacts).map_err(|error| OpenError::Fault(private_fault(&error)))?;
        if self.lock.is_none() {
            self.lock = Some(take_lock(&artifacts.join("build.lock"))?);
        }
        let dir = make_temp_dir(&utc_stamp(), &artifacts)
            .map_err(|error| OpenError::Fault(os_fault(&artifacts)(error)))?;
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
        let patch =
            git(&prepared.git_env, prepared.top.as_os_str(), &args).map_err(
                |error| match error {
                    GitError::Failed(reason) => Stop::incomplete(reason),
                    GitError::Start(fault) => Stop::failed(&fault),
                    GitError::Interrupted(stop) => stop,
                },
            )?;
        let diff = self.dir().join("diff.patch");
        fs::write(&diff, &patch).map_err(failed(&diff))?;
        self.diff_sha256 = Some(sha256(&fs::read(&diff).map_err(failed(&diff))?));
        Ok(diff)
    }

    /// `add_worktree` adds a detached worktree of the head, with hooks disabled, under the run directory.
    fn add_worktree(&mut self) -> Result<PathBuf, Stop> {
        let dir = self.dir().to_path_buf();
        let tree = make_temp_dir("worktree-", &dir).map_err(failed(&dir))?;
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

    /// `copy_lock` copies the invoking checkout's `Cargo.lock` into the worktree when the worktree holds no
    /// entry at that path. Exclusive creation fails on any existing entry, a dangling link included, so the
    /// copy never writes through a link.
    fn copy_lock(&self, tree: &Path) -> Result<(), Stop> {
        let source = self.prepared.top.join("Cargo.lock");
        if !is_file(&source).map_err(failed(&source))? {
            return Ok(());
        }
        let target = tree.join("Cargo.lock");
        let mut copy = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)
        {
            Ok(copy) => copy,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => return Ok(()),
            Err(error) => return Err(failed(&target)(error)),
        };
        let bytes = fs::read(&source).map_err(failed(&source))?;
        copy.write_all(&bytes).map_err(failed(&target))
    }

    /// `read_config` records the digest and the debug-assertion entry of the worktree configuration.
    fn read_config(&mut self, tree: &Path) -> Result<(), Stop> {
        let config = tree.join(CONFIG);
        if !is_file(&config).map_err(failed(&config))? {
            return Ok(());
        }
        let data = fs::read(&config).map_err(failed(&config))?;
        self.config_sha256 = Some(sha256(&data));
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
        if !is_file(&tree.join("Cargo.toml")).map_err(failed(tree))? {
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
    fn within_limit(&self) -> Result<bool, Stop> {
        let Some(limit) = &self.options().max_mutants else {
            let fault = Fault::library("InvalidInput", &"--max-mutants=-- holds no limit");
            return Err(Stop::failed(&fault));
        };
        let listed = self.listed.len().to_string();
        Ok(listed.len() < limit.len() || (listed.len() == limit.len() && listed <= *limit))
    }

    /// `execute` runs steps 2 to 4 and the outcome reading of step 5 and records their fields.
    ///
    /// # Errors
    ///
    /// The stop that ends the run before its report: a rejected lock or limit, a failed step, or a
    /// recorded signal.
    pub fn execute(&mut self) -> Result<(), Stop> {
        match self.open() {
            Ok(_) => {}
            Err(OpenError::Fault(fault)) => return Err(Stop::failed(&fault)),
            Err(OpenError::Stop(stop)) => return Err(stop),
        }
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
        if !self.within_limit()? {
            let limit = self.options().max_mutants.clone().unwrap_or_default();
            let line = format!(
                "mutants: {} listed, above --max-mutants {limit}",
                self.listed.len()
            );
            self.streams.say(false, &Text::from(line));
            return Err(Stop::rejected(Text::from(
                "raise --max-mutants or pass --shard K/N",
            )));
        }
        if self.listed.is_empty() {
            self.judgment = Some(judge(&[], Some(&Outcomes::empty()), None));
            return Ok(());
        }
        let dir = self.dir().to_path_buf();
        let output = dir.join("tool");
        let line = text!(
            format!(
                "mutants: testing {} mutants; tool output in ",
                self.listed.len()
            ),
            output
        );
        self.streams.say(true, &line);
        let prepared = &self.prepared;
        let mut argv: Vec<&OsStr> = vec![prepared.cargo.as_os_str(), OsStr::new("mutants")];
        argv.extend(os_args(&["--in-place", "-p", PACKAGE, "--in-diff"]));
        argv.extend([diff.as_os_str(), OsStr::new("--output"), output.as_os_str()]);
        argv.extend(self.shard_args());
        argv.push(OsStr::new("--"));
        argv.extend(prepared.tests.iter().map(OsString::as_os_str));
        let (stdout, stderr) = (dir.join("tool.stdout"), dir.join("tool.stderr"));
        let exit = supervise(
            &INTERRUPT,
            &argv,
            &stdout,
            &stderr,
            Some(&tree),
            &prepared.env,
        )?;
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
    /// gone, so a removal that failed is repeated after the directory's removal. The listing prints a
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
        let mut remove: Vec<&OsStr> =
            os_args(&["worktree", "remove", "--force", "--force"]).collect();
        remove.push(tree.as_os_str());
        let mut removed = output(&mut git(&remove))?;
        if !fs::symlink_metadata(tree).is_ok_and(|status| status.is_symlink()) {
            let _ = fs::remove_dir_all(tree);
        }
        if !removed.status.success() {
            removed = output(&mut git(&remove))?;
        }
        let listing: Vec<&OsStr> = os_args(&["worktree", "list", "--porcelain"]).collect();
        let listed = output(&mut git(&listing))?;
        let resolved = crate::paths::resolve(tree)
            .map_err(|error| Stop::fatal(Fault::os(&error, None).to_text()))?;
        let mut record = b"\nworktree ".to_vec();
        record.extend_from_slice(resolved.as_os_str().as_bytes());
        record.push(b'\n');
        let mut records = b"\n".to_vec();
        records.extend_from_slice(&listed.stdout);
        let registered = !listed.status.success()
            || records
                .windows(record.len())
                .any(|window| window == record.as_slice());
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
        let tests = prepared
            .tests
            .iter()
            .map(|word| Value::String(Text::from_os(word)));
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
        let count = |kind| judgment.count(kind);
        text!(
            "mutants: ",
            place,
            format!(
                ": {} listed, {} caught, {} missed, {} timeout, {} unviable; {state}",
                count("listed"),
                count("caught"),
                count("missed"),
                count("timeout"),
                count("unviable")
            )
        )
    }
}

impl Run {
    /// `write_report` writes `report.json` into the run directory, which it creates when execute made
    /// none, and returns its path.
    fn write_report(&mut self, judgment: &Judgment) -> Result<PathBuf, Text> {
        let dir = match self.dir.clone() {
            Some(dir) => dir,
            None => self.open().map_err(|error| match error {
                OpenError::Fault(fault) => fault.text().clone(),
                OpenError::Stop(stop) => stop.reason().clone(),
            })?,
        };
        let path = dir.join("report.json");
        let mut written = json::indented(&Value::Object(self.report(judgment)))
            .expect("every phase time of a report is finite");
        written.push('\n');
        fs::write(&path, written)
            .map_err(|error| Fault::os(&error, Some(path.as_os_str())).text().clone())?;
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
                self.streams.say(true, &text!("mutants: ", leftover));
            }
            return self.streams.code(code);
        }
        let mut reason = stop.map(|stop| stop.reason().clone());
        if let Some(leftover) = leftover {
            self.streams.say(true, &text!("mutants: ", leftover));
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
        let judgment = self
            .judgment
            .take()
            .expect("a run that ran through or stopped holds a judgment");
        let path = match self.write_report(&judgment) {
            Ok(path) => path,
            Err(error) => {
                let line = text!("mutants: the report could not be written: ", error);
                self.streams.say(true, &line);
                return self.streams.code(INCOMPLETE);
            }
        };
        self.streams.say(true, &text!("report: ", path));
        if judgment.mutants.is_empty() && judgment.complete() {
            self.streams.say(false, &Text::from("mutants: 0 listed"));
            return self.streams.code(COMPLETE);
        }
        let line = self.result_line(&judgment);
        self.streams.say(false, &line);
        if let Some(reason) = &judgment.reason {
            self.streams.say(false, &text!("reason: ", reason));
        }
        for entry in judgment.mutants.iter().filter(|entry| entry.is_missed()) {
            self.streams.say(false, &text!("missed: ", entry.name()));
        }
        self.streams.code(if judgment.complete() {
            COMPLETE
        } else {
            INCOMPLETE
        })
    }
}

/// `run` is the tool's entry: it reads the command line, runs step 1, then the run with the handlers
/// installed, the hand-off and the finish.
pub fn run(_top: &Path, args: &[OsString]) -> u8 {
    let options = match super::options::parse(args) {
        Parsed::Run(options) => options,
        Parsed::Help(help) => {
            let mut out = io::stdout().lock();
            let written = out.write_all(help.as_bytes()).and_then(|()| out.flush());
            return if written.is_ok() { COMPLETE } else { 120 };
        }
        Parsed::Refused { code, text } => {
            let written = io::stderr().write_all(text.as_bytes());
            return if written.is_ok() { code } else { 120 };
        }
    };
    let prepared = match preflight(options) {
        Ok(prepared) => prepared,
        Err(stop) => return Streams::default().refuse(&stop),
    };
    let mut run = Run::new(prepared);
    let executed = run.install().and_then(|()| run.execute());
    let stop = run.hand_off(executed);
    run.finish(stop)
}
