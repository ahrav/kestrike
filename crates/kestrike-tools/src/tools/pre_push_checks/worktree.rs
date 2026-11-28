//! The worktree of one pushed tip and the checks that run in it.
//!
//! The worktree's directory is `kestrike-pre-push-` and eight letters of `a` to `z`, `0` to `9` and `_`,
//! made with mode 0700 under `TMPDIR` when it is set and not empty, else under `/tmp`, and drawn again
//! while a name is taken. On every way out of [`run_checks`] after the directory is made,
//! `git worktree remove --force --force` runs once, the second `--force` removing a worktree that a killed
//! `git worktree add` left locked, and then the directory is removed if it still stands. An add that ends
//! after registering a locked worktree whose directory lacks its `.git` file leaves that registration: the
//! removal reads the directory as no working tree and fails, and the tool names the worktree it could not
//! remove.
//!
//! The tool assumes the invoking user controls the worktree's parent directory. Where another user can
//! rename entries in that parent, as in one writable by others without the sticky bit, that user can swap
//! the worktree's directory between the steps that name it.
//!
//! `git worktree add` and `git worktree remove` each lead a process group of their own, so a signal sent to
//! the tool's process group reaches them only through the tool. A recorded cancellation signal causes the
//! tool to stop `git worktree add` as it would a running check, also after Git exits while a process of
//! its group still holds one of its output streams. A process that holds such a stream from outside the
//! group gets no signal, and the tool waits for the stream's end with no limit unless a signal is
//! recorded. The tool waits for `git worktree remove` to finish.
//!
//! An add stopped before it writes the worktree's `gitdir` file can leave an entry under the common
//! `.git/worktrees` directory that holds only its `locked` file; Git lists no such worktree, the removal
//! names a tree Git does not know, and the entry stays.

use std::ffi::{OsStr, OsString};
use std::fs::{self, DirBuilder, File};
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::thread;

use crate::environ::Environ;
use crate::git::{self, GitError};
use crate::hook::{Check, argument, short};
use crate::text::{Text, strip_str};

use super::cancel::{self, Unwaited};
use super::{Exit, NAME, fail, say};

const PREFIX: &str = "kestrike-pre-push-";
const LETTERS: &[u8; 37] = b"abcdefghijklmnopqrstuvwxyz0123456789_";
const NAME_LENGTH: usize = 8;
const NAME_ATTEMPTS: usize = 10_000;

#[cfg(test)]
#[path = "worktree_tests.rs"]
mod tests;

/// How the checks of a tip ended before their last one returned.
enum Ended {
    /// A signal was recorded; the field is the exit code.
    Cancelled(u8),
    /// A signal was recorded and the running check could not be stopped or reaped:
    /// `pre-push-checks: <message>` is printed once the worktree is removed, and the field is the exit code.
    Unstopped(u8, String),
    /// A failed write to standard error; the field is the exit code.
    Stream(u8),
    /// `git worktree add` exited nonzero or wrote standard output that is not UTF-8: once the worktree is
    /// removed, `pre-push: <error>` is printed, and the exit is 2, or 1 where Git could not start for the
    /// removal.
    Git(GitError),
    /// A check or `git worktree add` could not be started or waited on: `pre-push-checks: <message>` is
    /// printed once the worktree is removed, and the exit is 1.
    Fault(String),
}

/// `run_checks` adds a detached worktree of `tip`, runs each of `checks` in it in order, and returns the
/// failed checks' commands. Each check starts in `environ` with the worktree as its working directory and
/// the tool's three streams, leading a process group of its own, and fails on any status but 0.
///
/// # Errors
///
/// The exit code where the push ends here: `128 + n` for a recorded signal, after a line that names the
/// running check where it could not be stopped or reaped, 120 for a failed write to
/// standard error, 2 for a `git worktree add` that exits nonzero or writes output that is not UTF-8, and 1
/// where the directory cannot be made or removed, if starting or waiting for a check or for
/// `git worktree add` fails, or if Git fails to start for `git worktree remove`.
pub(super) fn run_checks(
    environ: &Environ,
    tip: &Text,
    checks: &[Check],
) -> Result<Vec<String>, Exit> {
    let tree = match make_tree() {
        Ok(tree) => tree,
        Err(error) => {
            cancel::check()?;
            return Err(fail(&format!("{NAME}: {error}"), 1));
        }
    };
    let ran = checks_in(environ, &tree, tip, checks);
    let removed = remove(environ, &tree);
    let cleared = match fs::remove_dir_all(&tree) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    };
    if let Err(Ended::Unstopped(code, message)) = &ran {
        let _ = say(&format!("{NAME}: {message}"));
        return Err(*code);
    }
    cancel::check()?;
    let unstarted = !removed?;
    let failures = match ran {
        Ok(failures) => failures,
        Err(Ended::Cancelled(code) | Ended::Stream(code) | Ended::Unstopped(code, _)) => {
            return Err(code);
        }
        Err(Ended::Git(error)) => {
            return Err(fail(
                &format!("pre-push: {error}"),
                if unstarted { 1 } else { 2 },
            ));
        }
        Err(Ended::Fault(message)) => {
            return Err(fail(&format!("{NAME}: {message}"), 1));
        }
    };
    if unstarted {
        return Err(1);
    }
    if let Err(error) = cleared {
        return Err(fail(&format!("{NAME}: {}: {error}", shown(&tree)), 1));
    }
    Ok(failures)
}

/// `checks_in` adds the worktree at `tree` and runs the checks there.
fn checks_in(
    environ: &Environ,
    tree: &Path,
    tip: &Text,
    checks: &[Check],
) -> Result<Vec<String>, Ended> {
    cancel::check().map_err(Ended::Cancelled)?;
    add(environ, tree, tip)?;
    let mut failures = Vec::new();
    for check in checks {
        cancel::check().map_err(Ended::Cancelled)?;
        let argv = check.row().argv;
        let command = argv.join(" ");
        let said = say(&format!("pre-push: {}: {command}", short(tip)));
        cancel::check().map_err(Ended::Cancelled)?;
        said.map_err(Ended::Stream)?;
        let (program, args) = argv.split_first().expect("every check has a program");
        let mut child = git::command(environ, program)
            .args(args)
            .current_dir(tree)
            .process_group(0)
            .spawn()
            .map_err(|error| Ended::Fault(format!("{program}: {error}")))?;
        let status =
            cancel::wait(&mut child, || true).map_err(|unwaited| ended(program, unwaited))?;
        if !status.success() {
            failures.push(command);
        }
    }
    Ok(failures)
}

/// `ended` is how a run of `program` ended where [`cancel::wait`] gave no status.
fn ended(program: &str, unwaited: Unwaited) -> Ended {
    match unwaited {
        Unwaited::Cancelled(code) => Ended::Cancelled(code),
        Unwaited::Unstopped(code, error) => Ended::Unstopped(code, format!("{program}: {error}")),
        Unwaited::Failed(error) => Ended::Fault(format!("{program}: {error}")),
    }
}

/// A reader of one of Git's output streams: the stream's bytes to its end, or the read's error.
type Reader = thread::JoinHandle<io::Result<Vec<u8>>>;

/// `add` runs `git worktree add --quiet --detach <tree> <tip>`, reading its two output streams to their
/// ends on threads of their own. The leader stays unreaped until it has ended and both streams have
/// reached their ends, so a signal recorded while a process of the add's group holds a stream still stops
/// that group. A successful add whose standard output is not UTF-8 is a refusal.
fn add(environ: &Environ, tree: &Path, tip: &Text) -> Result<(), Ended> {
    let tip = argument(tip);
    let args = [
        OsStr::new("worktree"),
        "add".as_ref(),
        "--quiet".as_ref(),
        "--detach".as_ref(),
        tree.as_os_str(),
        &tip,
    ];
    let mut child = git::git_command(environ)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(|error| Ended::Fault(format!("git: {error}")))?;
    let readers = drain(child.stdout.take())
        .and_then(|stdout| drain(child.stderr.take()).map(|stderr| (stdout, stderr)));
    let (stdout, stderr) = match readers {
        Ok(readers) => readers,
        Err(error) => {
            return Err(match cancel::stop(&mut child, false) {
                Ok(()) => Ended::Fault(format!("git: {error}")),
                Err(stopped) => Ended::Fault(format!(
                    "git: {error}; the stop that followed failed: {stopped}"
                )),
            });
        }
    };
    let status = cancel::wait(&mut child, || stdout.is_finished() && stderr.is_finished())
        .map_err(|unwaited| ended("git", unwaited))?;
    let stdout = drained(stdout)?;
    let stderr = drained(stderr)?;
    if status.success() {
        return String::from_utf8(stdout).map(drop).map_err(|error| {
            Ended::Git(GitError::NotUtf8(format!("{}: {error}", git::label(&args))))
        });
    }
    Err(Ended::Git(git::failed(&args, &stderr)))
}

/// `drain` reads `stream` to its end on a thread of its own.
///
/// # Errors
///
/// The stream is missing, or the thread cannot start.
fn drain(stream: Option<impl Read + Send + 'static>) -> io::Result<Reader> {
    let mut stream = stream.ok_or_else(|| io::Error::other("a captured stream is missing"))?;
    thread::Builder::new().spawn(move || {
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).map(|_| bytes)
    })
}

/// `drained` joins a reader of `drain` that has finished.
///
/// # Errors
///
/// The read failed, or the reader panicked.
fn drained(reader: Reader) -> Result<Vec<u8>, Ended> {
    match reader.join() {
        Ok(Ok(bytes)) => Ok(bytes),
        Ok(Err(error)) => Err(Ended::Fault(format!("git: {error}"))),
        Err(_) => Err(Ended::Fault(
            "git: a reader of Git's output panicked".to_owned(),
        )),
    }
}

/// `remove` runs `git worktree remove --force --force` on `tree` in its own process group, prints
/// `pre-push: could not remove worktree <tree>: <reason>` when it fails, and returns whether Git started.
/// `remove` converts CRLF and CR in Git's standard error to LF; for an error starting or waiting for Git it
/// formats `GitError::Start(error)`. It trims either reason before printing.
fn remove(environ: &Environ, tree: &Path) -> Result<bool, Exit> {
    let args = [
        OsStr::new("worktree"),
        "remove".as_ref(),
        "--force".as_ref(),
        "--force".as_ref(),
        tree.as_os_str(),
    ];
    let ran = git::git_command(environ)
        .args(args)
        .process_group(0)
        .output();
    let (reason, started) = match ran {
        Ok(output) if output.status.success() => return Ok(true),
        Ok(output) => (
            crate::text::newlines(String::from_utf8_lossy(&output.stderr).into_owned()),
            true,
        ),
        Err(error) => (GitError::Start(error).to_string(), false),
    };
    say(&format!(
        "pre-push: could not remove worktree {}: {}",
        shown(tree),
        strip_str(&reason)
    ))?;
    Ok(started)
}

/// `shown` writes `path` as a line names it, each byte outside UTF-8 as `\udcXX`.
fn shown(path: &Path) -> Text {
    Text::from_os(path.as_os_str())
}

/// `parent` is `TMPDIR` when it is set and not empty, else `/tmp`, made absolute against the working
/// directory.
fn parent() -> io::Result<PathBuf> {
    let chosen = std::env::var_os("TMPDIR")
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| OsString::from("/tmp"));
    std::path::absolute(chosen)
}

/// `make_tree` makes the worktree's directory.
///
/// # Errors
///
/// The working directory or the random bytes cannot be read, a `mkdir` fails with another error than a
/// taken name, or every name drawn is taken; the text names the path where a `mkdir` failed.
fn make_tree() -> Result<PathBuf, String> {
    let parent = parent().map_err(|error| error.to_string())?;
    let mut random =
        File::open("/dev/urandom").map_err(|error| format!("/dev/urandom: {error}"))?;
    for _ in 0..NAME_ATTEMPTS {
        let mut name = PREFIX.as_bytes().to_vec();
        name.extend(letters(&mut random).map_err(|error| format!("/dev/urandom: {error}"))?);
        let path = parent.join(OsStr::from_bytes(&name));
        match DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(format!("{}: {error}", shown(&path))),
        }
    }
    Err(format!(
        "{}: no usable temporary directory name found",
        shown(&parent)
    ))
}

/// `letters` draws [`NAME_LENGTH`] letters of [`LETTERS`] uniformly from `random`, passing over each byte
/// at or above the largest multiple of the letters' count.
fn letters(random: &mut impl Read) -> io::Result<[u8; NAME_LENGTH]> {
    let span = u8::try_from(LETTERS.len()).expect("the letters fit a byte");
    let mut drawn = [0u8; NAME_LENGTH];
    let mut filled = 0;
    let mut bytes = [0u8; 32];
    while filled < NAME_LENGTH {
        random.read_exact(&mut bytes)?;
        for &byte in &bytes {
            if filled < NAME_LENGTH && byte < span * (u8::MAX / span) {
                drawn[filled] = LETTERS[usize::from(byte % span)];
                filled += 1;
            }
        }
    }
    Ok(drawn)
}
