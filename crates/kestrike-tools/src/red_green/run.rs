//! A red-green run: the rejections found before any worktree or build, the creation of the build and
//! receipt directories, the legs, the receipt and the lines that report the outcome.
//!
//! [`run_with`] reads `scripts/reproduce-test.py` and `scripts/select-tests.py` under the checkout's top
//! before it reads its arguments; the receipt's `scripts` digests those bytes, and each leg runs a fresh
//! copy of them. Every Git child starts in the invoking directory with the environment of
//! [`git::push_environ`], and the run changes no variable of its own process. The handlers of SIGINT,
//! SIGTERM and SIGHUP record into the facts' record whatever disposition the process inherited. Until
//! the run directory stands, a recorded signal ends the run at the next check with 128 plus its number
//! and no output, and a Git child that runs then is killed. [`Facts`] holds what a caller may set in the
//! place of the host's own: the user ID the ownership checks judge by, the run directory's name, the
//! maker of the temporary directory, the start of a runner and the signal record.

use std::ffi::{OsStr, OsString};
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{SystemTime, UNIX_EPOCH};

use super::legs::Run;
use super::options::{self, Options};
use super::record::{self, Record};
use super::tree;
use crate::args::Parsed;
use crate::environ::Environ;
use crate::git;
use crate::ownership::{self, PathError};
use crate::paths;
use crate::process::{self, INTERRUPT, Interrupt, Interrupted};
use crate::python;
use crate::temp_dir::{self, TempDirError};
use crate::text::{Text, text};

/// The tool's name in its lines.
pub const TOOL: &str = "red-green";

const USAGE: &str =
    "usage: red-green [-h] --package PACKAGE --target TARGET --test TEST --expect EXPECT
                 --carry CARRY [CARRY ...] [--base BASE] [--head HEAD]
                 [--watchdog WATCHDOG] [--artifacts ARTIFACTS] [--cargo CARGO]
                 [--release]";

const OPTIONS: &str = "options:
  -h, --help            show this help message and exit
  --package PACKAGE
  --target TARGET       lib or an integration test target name
  --test TEST           the full test ID as the harness lists it
  --expect EXPECT       a substring of the base leg's failing attempt output
                        outside libtest framing and backtraces; choose text
                        specific to the intended failure, such as its
                        assertion message
  --carry CARRY [CARRY ...]
                        test files from the head
  --base BASE           default: the merge base of the head with origin/main
  --head HEAD
  --watchdog WATCHDOG   seconds per attempt (default 1500)
  --artifacts ARTIFACTS
                        receipt parent directory (default target/red-green)
  --cargo CARGO
  --release             build the release profile
";

/// The runner and its selector under `scripts/`, the runner first.
pub const SOURCES: [&str; 2] = ["reproduce-test.py", "select-tests.py"];

/// The prefix of the run's temporary directory.
pub const TEMP_PREFIX: &str = "kestrike-red-green-";

/// The facts a run reads from its host, each a value its caller sets.
pub struct Facts<'a> {
    /// The user ID by which the ownership checks and the lock judge an owner.
    pub uid: u32,
    /// The run directory's name; `None` names it `local-SECONDS-PID` from the wall clock's whole seconds
    /// and the process ID.
    pub run_name: Option<OsString>,
    /// `make_temp(prefix, parent)` makes the run's temporary directory under `parent`.
    pub make_temp: &'a dyn Fn(&str, &Path) -> Result<PathBuf, TempDirError>,
    /// `spawn(command)` starts a leg's runner from `command`, which holds its program, arguments,
    /// directory, environment, streams and session.
    pub spawn: &'a dyn Fn(&mut Command) -> io::Result<Child>,
    /// The record into which the handlers write the first of the handled signals.
    pub interrupt: &'static Interrupt,
}

impl Facts<'static> {
    /// `host` is the real user ID, a name from the clock, [`temp_dir::make_temp_dir`],
    /// [`Command::spawn`] and [`INTERRUPT`].
    pub fn host() -> Self {
        Self {
            uid: ownership::real_uid(),
            run_name: None,
            make_temp: &temp_dir::make_temp_dir,
            spawn: &spawn,
            interrupt: &INTERRUPT,
        }
    }
}

/// `spawn` starts `command` as [`Command::spawn`] does.
///
/// # Errors
///
/// [`Command::spawn`]'s.
pub fn spawn(command: &mut Command) -> io::Result<Child> {
    command.spawn()
}

/// How a step ends the run when it does not return.
#[derive(Debug)]
pub(super) enum Halt {
    /// Rejected input: exit 2.
    Rejected(Text),
    /// A refusal's reason: exit 1, with a receipt once the run directory stands.
    Refused(Text),
    /// A recorded signal: exit 128 plus its number.
    Interrupted(i32),
    /// A failure outside the run's outcomes: exit 1 and the line `red-green: MESSAGE`.
    Failed(Text),
}

impl From<Interrupted> for Halt {
    fn from(Interrupted(signal): Interrupted) -> Self {
        Self::Interrupted(signal)
    }
}

/// `could_not_run` is the refusal of a step of the legs that fails with a system error.
pub(super) fn could_not_run(error: &impl std::fmt::Display) -> Halt {
    Halt::Refused(text!("a leg could not run: ", error.to_string()))
}

/// `os` is the bytes of `text`, which a text read from an argument or a path always encodes to.
pub(super) fn os(text: &Text) -> OsString {
    text.to_os()
        .expect("a text read from bytes encodes back to them")
}

pub(super) fn shown(path: &Path) -> Text {
    Text::from_os(path.as_os_str())
}

/// `say` writes `line` escaped as one line on standard error where `err` holds, else on standard output.
pub(super) fn say(err: bool, line: &Text) -> io::Result<()> {
    if err {
        let mut stream = io::stderr().lock();
        python::say(&mut stream, line).and_then(|()| stream.flush())
    } else {
        let mut stream = io::stdout().lock();
        python::say(&mut stream, line).and_then(|()| stream.flush())
    }
}

/// A finished Git child: its exit code, or the negated signal that ended it, and both streams.
pub(super) struct Done {
    pub code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl Done {
    /// Standard error decoded as file names decode, white space stripped at both ends.
    pub fn error(&self) -> Text {
        Text::from_os(OsStr::from_bytes(&self.stderr)).strip()
    }

    pub fn text(&self) -> Text {
        Text::from_os(OsStr::from_bytes(&self.stdout))
    }
}

/// `git_step` runs `git ARGS` in `cwd`, or the invoking directory, with `env`, through
/// [`process::capture`]: a signal recorded in `interrupt` while Git runs kills it.
///
/// # Errors
///
/// The outer error is a recorded signal; the inner one a start, a read or a wait that fails.
pub(super) fn git_step<S: AsRef<OsStr>>(
    env: &Environ,
    args: &[S],
    cwd: Option<&Path>,
    interrupt: &Interrupt,
) -> Result<io::Result<Done>, Interrupted> {
    let mut command = git::command(env, "git");
    command.args(args);
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    let output = process::capture(&mut command, interrupt)?;
    Ok(output.map(|output| Done {
        code: process::exit_code(output.status),
        stdout: output.stdout,
        stderr: output.stderr,
    }))
}

/// `words` is the text of `args` joined by single spaces.
pub(super) fn words<S: AsRef<OsStr>>(args: &[S]) -> Text {
    let texts: Vec<Text> = args.iter().map(|arg| Text::from_os(arg.as_ref())).collect();
    Text::join(" ", &texts)
}

/// `resolved_by` makes `path` absolute with its links resolved by `resolve`, then reads its status:
/// a path that does not exist yet passes, and any other failure is rejected.
///
/// # Errors
///
/// The rejection `a receipt or build directory cannot be resolved` with the failure's text, for the
/// temporary directory too.
pub fn resolved_by(
    path: &Path,
    resolve: impl Fn(&Path) -> io::Result<PathBuf>,
) -> Result<PathBuf, Text> {
    let rejected = |error: &dyn std::fmt::Display| {
        text!(
            "a receipt or build directory cannot be resolved: ",
            error.to_string()
        )
    };
    let path = resolve(path).map_err(|error| rejected(&error))?;
    match fs::metadata(&path) {
        Ok(_) => Ok(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(path),
        Err(error) => Err(rejected(&PathError::new(&path, error))),
    }
}

/// `resolved_dir` is [`resolved_by`] with [`paths::resolve`].
///
/// # Errors
///
/// [`resolved_by`]'s rejection.
pub fn resolved_dir(path: &Path) -> Result<PathBuf, Text> {
    resolved_by(path, paths::resolve)
}

/// `temp_root` is `TMPDIR` when it is set and not empty, and `/tmp` otherwise.
fn temp_root() -> PathBuf {
    match std::env::var_os("TMPDIR") {
        Some(value) if !value.is_empty() => PathBuf::from(value),
        _ => PathBuf::from("/tmp"),
    }
}

/// `absolute` joins `path` to the invoking directory and drops each `.` and each `..` with the name
/// before it, as text.
fn absolute(path: &Text) -> io::Result<Text> {
    let here = std::env::current_dir()?;
    let joined = paths::join(here.as_os_str().as_bytes(), &os(path).into_encoded_bytes());
    Ok(Text::from_os(OsStr::from_bytes(&paths::normalize(&joined))))
}

/// What the checks found: the options with an absolute `--cargo` path, both commits, the carried paths
/// with their blobs, and the resolved receipt parent, build directory and temporary directory.
pub(super) struct Checked {
    pub options: Options,
    pub base: Text,
    pub head: Text,
    pub carried: Vec<(Text, Text)>,
    pub parent: PathBuf,
    pub target_dir: PathBuf,
    pub temp_root: PathBuf,
}

/// The rejection checks, in their order, with the signal record read between them.
struct Checks<'a> {
    facts: &'a Facts<'a>,
    env: &'a Environ,
}

impl Checks<'_> {
    fn stop(&self) -> Result<(), Halt> {
        Ok(self.facts.interrupt.check()?)
    }

    /// `git` runs a check's Git step, which a recorded signal kills.
    fn git(&self, args: &[&OsStr]) -> Result<Done, Halt> {
        let done = git_step(self.env, args, None, self.facts.interrupt)?;
        done.map_err(|error| Halt::Failed(text!("git: ", error.to_string())))
    }

    /// `commit` is the full ID of the commit `rev` names.
    fn commit(&self, rev: &Text) -> Result<Text, Halt> {
        let spec = os(&text!(rev, "^{commit}"));
        let args = ["rev-parse", "--verify", "--quiet", "--end-of-options"].map(OsStr::new);
        let found = self.git(&[&args[..], &[spec.as_os_str()]].concat())?;
        if found.code != 0 {
            return Err(Halt::Rejected(text!(rev.repr(), " names no commit")));
        }
        Ok(found.text().strip())
    }

    fn shared(&self, found: Vec<PathBuf>, then: &str) -> Result<(), Halt> {
        if found.is_empty() {
            return Ok(());
        }
        let shown: Vec<Text> = found.iter().map(|path| shown(path)).collect();
        Err(Halt::Rejected(text!(
            "another user owns or can write ",
            Text::join(", ", &shown),
            then
        )))
    }

    fn resolved_path(path: &Path) -> Result<PathBuf, Halt> {
        resolved_dir(path).map_err(Halt::Rejected)
    }

    fn failed(error: &PathError) -> Halt {
        Halt::Failed(text!(error.to_string()))
    }

    fn checked(&self, mut options: Options) -> Result<Checked, Halt> {
        if options.cargo.as_bytes().contains(&b'/') {
            options.cargo =
                absolute(&options.cargo).map_err(|error| Halt::Failed(text!(error.to_string())))?;
        }
        options::check_given(&options).map_err(Halt::Rejected)?;
        let overrides: Vec<Text> = git::REPOSITORY_VARIABLES
            .iter()
            .filter(|name| std::env::var_os(name).is_some())
            .map(|name| Text::from(*name))
            .collect();
        if !overrides.is_empty() {
            return Err(Halt::Rejected(text!(
                Text::join(", ", &overrides),
                " would point the leg worktrees at another repository or index; unset them"
            )));
        }
        self.stop()?;
        let temp_root = Self::resolved_path(&temp_root())?;
        let foreign = ownership::foreign_toolchain_paths_for(&temp_root, self.facts.uid)
            .map_err(|error| Self::failed(&error))?;
        self.shared(
            foreign,
            ", and so can configure Cargo or rustup in the leg worktrees; set TMPDIR to a directory only \
             you control",
        )?;
        process::refuse_ignored_sigchld()
            .map_err(|sentence| Halt::Rejected(Text::from(sentence)))?;
        self.stop()?;
        let top = self.git(&["rev-parse", "--show-toplevel"].map(OsStr::new))?;
        if top.code != 0 {
            return Err(Halt::Rejected(Text::from(
                "the invoking directory is not in a Git checkout",
            )));
        }
        options::check_expect(&options).map_err(Halt::Rejected)?;
        options::check_watchdog(options.watchdog).map_err(Halt::Rejected)?;
        let head = self.commit(&options.head)?;
        let base = match &options.base {
            Some(base) => base.clone(),
            None => {
                let found = self.git(&[
                    OsStr::new("merge-base"),
                    OsStr::new("origin/main"),
                    &os(&head),
                ])?;
                if found.code != 0 {
                    return Err(Halt::Rejected(text!(
                        "the head ",
                        short(&head),
                        " has no merge base with origin/main; name --base"
                    )));
                }
                found.text().strip()
            }
        };
        let base = self.commit(&base)?;
        let ancestor = self.git(&[
            OsStr::new("merge-base"),
            OsStr::new("--is-ancestor"),
            &os(&base),
            &os(&head),
        ])?;
        if base == head || ancestor.code != 0 {
            return Err(Halt::Rejected(text!(
                "the base ",
                short(&base),
                " is not an ancestor of the head ",
                short(&head),
                " other than the head"
            )));
        }
        let carried = self.carried(&head, &options.carry)?;
        self.only_carried(&base, &head, &options.carry)?;
        let checkout = top.stdout.strip_suffix(b"\n").unwrap_or(&top.stdout);
        let checkout = Path::new(OsStr::from_bytes(checkout));
        let parent = match &options.artifacts {
            Some(artifacts) => PathBuf::from(os(artifacts)),
            None => checkout.join("target/red-green"),
        };
        let parent = Self::resolved_path(&parent)?;
        let target_dir = match std::env::var_os("CARGO_TARGET_DIR") {
            Some(inherited) if !inherited.is_empty() => PathBuf::from(inherited).join("red-green"),
            _ => checkout.join("target/red-green/build"),
        };
        let target_dir = Self::resolved_path(&target_dir)?;
        let shared = ownership::shared_directories_for(&target_dir, self.facts.uid)
            .map_err(|error| Self::failed(&error))?;
        self.shared(
            shared,
            ", and so can replace what the legs build and run; set CARGO_TARGET_DIR to a directory only \
             you control",
        )?;
        options::check_receipt_directory(&parent).map_err(Halt::Rejected)?;
        self.stop()?;
        Ok(Checked {
            options,
            base,
            head,
            carried,
            parent,
            target_dir,
            temp_root,
        })
    }

    /// `carried` is each carried path with its blob ID at the head.
    fn carried(&self, head: &Text, carry: &[Text]) -> Result<Vec<(Text, Text)>, Halt> {
        let mut blobs = Vec::new();
        for path in carry {
            let words = ["--literal-pathspecs", "ls-tree", "-z", "--full-tree"].map(OsStr::new);
            let (head_os, path_os) = (os(head), os(path));
            let args = [
                &words[..],
                &[head_os.as_os_str(), OsStr::new("--"), &path_os],
            ]
            .concat();
            let found = self.git(&args)?;
            if found.code != 0 {
                return Err(Halt::Rejected(text!(
                    "git ls-tree ",
                    short(head),
                    " ",
                    path.repr(),
                    ": ",
                    found.error()
                )));
            }
            let blob = tree::carried_blob(head.to_str().unwrap_or_default(), path, &found.stdout)
                .map_err(Halt::Rejected)?;
            blobs.push((path.clone(), blob));
        }
        Ok(blobs)
    }

    /// `only_carried` rejects a head whose every change from the base lies in a path the overlay of
    /// `carry` decides.
    fn only_carried(&self, base: &Text, head: &Text, carry: &[Text]) -> Result<(), Halt> {
        let words = ["diff", "--name-only", "-z", "--no-renames", "--no-relative"].map(OsStr::new);
        let (base_os, head_os) = (os(base), os(head));
        let args = [
            &words[..],
            &[base_os.as_os_str(), &head_os, OsStr::new("--")],
        ]
        .concat();
        let found = self.git(&args)?;
        if found.code != 0 {
            return Err(Halt::Rejected(text!(
                "git diff ",
                short(base),
                " ",
                short(head),
                ": ",
                found.error()
            )));
        }
        let all = found
            .stdout
            .split(|&byte| byte == 0)
            .filter(|path| !path.is_empty())
            .all(|path| tree::overlaid(&Text::from_os(OsStr::from_bytes(path)), carry));
        if all {
            return Err(Halt::Rejected(text!(
                "the head ",
                short(head),
                " changes only carried paths, so both legs would run the same tree"
            )));
        }
        Ok(())
    }
}

/// `short` is the first twelve characters of a commit ID.
pub(super) fn short(id: &Text) -> String {
    crate::hook::short(id)
}

/// `install` makes SIGINT, SIGTERM and SIGHUP record into `interrupt` whatever disposition the process
/// inherited, and unblocks the three in the calling thread. The three stay blocked while the handlers
/// register, so a signal sent then is recorded at the unblock; the caller starts no thread before.
///
/// # Errors
///
/// A mask change or a registration fails; the mask is restored either way.
fn install(interrupt: &'static Interrupt) -> io::Result<()> {
    let handled = process::handled_set();
    mask(libc::SIG_BLOCK, &handled)?;
    let registered = process::SIGNALS.into_iter().try_for_each(|signal| {
        // SAFETY: the action is one atomic compare-exchange on a static, which is async-signal-safe.
        unsafe { signal_hook::low_level::register(signal, move || interrupt.record(signal)) }
            .map(drop)
    });
    let unblocked = mask(libc::SIG_UNBLOCK, &handled);
    registered.and(unblocked)
}

fn mask(how: libc::c_int, set: &libc::sigset_t) -> io::Result<()> {
    // SAFETY: `set` is an initialized signal set that outlives the call, and a null old set makes
    // `pthread_sigmask` write nothing back.
    let status = unsafe { libc::pthread_sigmask(how, set, std::ptr::null_mut()) };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status));
    }
    Ok(())
}

/// `lock_problem` is why a build lock of `status` is refused when `uid` judges it: no regular file, or
/// one that another user owns or that its group or all users can write.
pub fn lock_problem(status: &fs::Metadata, uid: u32) -> Option<&'static str> {
    use std::os::unix::fs::MetadataExt;
    if !status.is_file() {
        return Some("it is not a regular file");
    }
    if status.uid() != uid || status.mode() & ownership::SHARED != 0 {
        return Some("another user owns or can write it");
    }
    None
}

/// `failed` prints `red-green: MESSAGE` on standard error and returns exit 1.
fn failed(message: &Text) -> u8 {
    let _ = say(true, &text!(TOOL, ": ", message));
    1
}

/// `refused` prints the refusal on standard output and returns exit 1.
fn refused(reason: &Text) -> u8 {
    let _ = say(false, &text!(TOOL, " refused: ", reason));
    1
}

/// `interrupted` is the exit of a recorded signal.
fn interrupted(signal: i32) -> u8 {
    u8::try_from(128 + signal).unwrap_or(u8::MAX)
}

/// `read_sources` reads the runner and its selector under `top/scripts/`, each once and whole.
fn read_sources(top: &Path) -> Result<Vec<(&'static str, Vec<u8>)>, PathError> {
    SOURCES
        .iter()
        .map(|name| {
            let path = top.join("scripts").join(name);
            fs::read(&path)
                .map(|data| (*name, data))
                .map_err(|error| PathError::new(&path, error))
        })
        .collect()
}

/// `executable` is the SHA-256 of the running image, read once through `/proc/self/exe`, or `None`
/// where that read fails.
fn executable() -> Option<String> {
    let mut data = Vec::new();
    fs::File::open("/proc/self/exe")
        .and_then(|mut file| file.read_to_end(&mut data))
        .ok()?;
    Some(python::hexdigest(&data))
}

/// `run` is the tool's entry with the host's facts.
pub fn run(top: &Path, args: &[OsString]) -> u8 {
    run_with(top, args, &Facts::host())
}

/// `run_with` runs the tool from the checkout at `top` with `args` and `facts`, prints its lines and
/// returns its exit code. It installs the signal handlers once the arguments read, so the caller holds
/// no thread of its own then.
pub fn run_with(top: &Path, args: &[OsString], facts: &Facts<'_>) -> u8 {
    let sources = match read_sources(top) {
        Ok(sources) => sources,
        Err(error) => return failed(&text!(error.to_string())),
    };
    let help = format!("{USAGE}\n\n{}\n{OPTIONS}", include_str!("help.md"));
    let options = match options::read(args, TOOL, USAGE, &help) {
        Parsed::Run(options) => options,
        Parsed::Help(text) => {
            let mut out = io::stdout().lock();
            return match out.write_all(text.as_bytes()).and_then(|()| out.flush()) {
                Ok(()) => 0,
                Err(_) => 1,
            };
        }
        Parsed::Refused { code, text } => {
            let _ = io::stderr().lock().write_all(text.as_bytes());
            return code;
        }
    };
    if let Err(error) = install(facts.interrupt) {
        return failed(&text!("the signal handlers: ", error.to_string()));
    }
    let env = git::push_environ();
    let checks = Checks { facts, env: &env };
    match checks.checked(options) {
        Ok(checked) => finish(&checked, &sources, facts, &env),
        Err(Halt::Rejected(reason)) => match say(true, &text!(TOOL, " rejected: ", reason)) {
            Ok(()) => 2,
            Err(_) => 1,
        },
        Err(Halt::Interrupted(signal)) => interrupted(signal),
        Err(Halt::Failed(message) | Halt::Refused(message)) => failed(&message),
    }
}

/// `run_name` is `local-SECONDS-PID`, from the wall clock's whole seconds since the epoch and this
/// process's ID.
fn run_name() -> OsString {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    OsString::from(format!("local-{seconds}-{}", std::process::id()))
}

/// `create_receipt_directory` creates `directory` exclusively, and its missing ancestors first where
/// its parent is missing, each with mode 0777 under the umask.
fn create_receipt_directory(directory: &Path) -> io::Result<()> {
    match DirBuilder::new().create(directory) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let parent = directory.parent().unwrap_or(Path::new("/"));
            DirBuilder::new().recursive(true).create(parent)?;
            DirBuilder::new().create(directory)
        }
        done => done,
    }
}

/// `finish` creates the build directory and the run directory, runs the legs, removes the worktrees and
/// writes the receipt and the result line.
fn finish(
    checked: &Checked,
    sources: &[(&'static str, Vec<u8>)],
    facts: &Facts<'_>,
    env: &Environ,
) -> u8 {
    let name = facts.run_name.clone().unwrap_or_else(run_name);
    let directory = checked.parent.join(name);
    let target_dir = &checked.target_dir;
    if let Err(Interrupted(signal)) = facts.interrupt.check() {
        return interrupted(signal);
    }
    let exists = |path: &Path| Ok(ownership::status(path)?.is_some());
    if let Err(error) = ownership::make_private_with(target_dir, facts.uid, &exists) {
        return refused(&text!(
            "the build directory ",
            target_dir,
            " could not be created: ",
            error.to_string()
        ));
    }
    if let Err(Interrupted(signal)) = facts.interrupt.check() {
        return interrupted(signal);
    }
    if let Err(error) = create_receipt_directory(&directory) {
        return refused(&text!(
            "the receipt directory ",
            &directory,
            " could not be created: ",
            error.to_string()
        ));
    }
    if let Err(Interrupted(signal)) = facts.interrupt.check() {
        return interrupted(signal);
    }
    let mut run = Run::new(facts, env, checked, &directory, sources);
    let outcome = run.legs();
    if let Err(message) = run.remove_trees() {
        return failed(&message);
    }
    let reason = match outcome {
        Ok(reason) => reason,
        Err(Halt::Refused(reason)) => Some(reason),
        Err(Halt::Interrupted(signal)) => return interrupted(signal),
        Err(Halt::Failed(message) | Halt::Rejected(message)) => return failed(&message),
    };
    receipt(checked, sources, &run, &directory, reason)
}

/// `receipt` writes `receipt.json` exclusively in the run directory and prints its lines: a receipt
/// that cannot be written turns the result into a refusal that names it.
fn receipt(
    checked: &Checked,
    sources: &[(&'static str, Vec<u8>)],
    run: &Run<'_>,
    directory: &Path,
    reason: Option<Text>,
) -> u8 {
    let options = &checked.options;
    let scripts: Vec<(&str, String)> = sources
        .iter()
        .map(|(name, data)| (*name, python::hexdigest(data)))
        .collect();
    let executable = executable();
    let command = options::repeat(options, &checked.base, &checked.head, directory);
    let record = Record {
        options,
        base: &checked.base,
        head: &checked.head,
        carried: &checked.carried,
        cargo_target_dir: &checked.target_dir,
        scripts: &scripts,
        executable: executable.as_deref(),
        legs: run.recorded(),
        reason: reason.as_ref(),
        command: &command,
    };
    let written = match record::record(&record) {
        Ok(written) => written,
        Err(error) => {
            return failed(&text!(format!(
                "the receipt holds a value that is not finite: {}",
                error.value()
            )));
        }
    };
    let result = reason
        .as_ref()
        .map_or_else(|| Text::from("proven"), |reason| text!("refused: ", reason));
    let path = directory.join("receipt.json");
    let wrote = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .and_then(|mut file| file.write_all(written.as_bytes()));
    let reason = match wrote {
        Err(error) => Some(text!(
            "the receipt ",
            &path,
            " could not be written: ",
            error.to_string(),
            "; ",
            result
        )),
        Ok(()) => {
            if say(true, &text!("receipt: ", &path)).is_err() {
                return 1;
            }
            reason
        }
    };
    if let Some(reason) = reason {
        return refused(&reason);
    }
    let line = text!(
        TOOL,
        ": ",
        &options.test,
        " failed on ",
        short(&checked.base),
        " with \"",
        &options.expect,
        "\" and passed on ",
        short(&checked.head)
    );
    match say(false, &line) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}
