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
//! tool to stop `git worktree add` as it would a running check. The tool waits for `git worktree remove`
//! to finish.

use std::ffi::{OsStr, OsString};
use std::fs::{self, DirBuilder, File};
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::thread;
use std::time::Duration;

use crate::environ::Environ;
use crate::git::{self, GitError};
use crate::hook::{Check, TOOLS_TARGET, argument, short};
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
    top: &Path,
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
    let ran = checks_in(environ, top, &tree, tip, checks);
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

/// `checks_in` adds the worktree at `tree` and runs the checks there. A row with `tools_target` runs
/// with `CARGO_TARGET_DIR` set to [`TOOLS_TARGET`] under `top`.
fn checks_in(
    environ: &Environ,
    top: &Path,
    tree: &Path,
    tip: &Text,
    checks: &[Check],
) -> Result<Vec<String>, Ended> {
    cancel::check().map_err(Ended::Cancelled)?;
    add(environ, tree, tip)?;
    let mut failures = Vec::new();
    for check in checks {
        cancel::check().map_err(Ended::Cancelled)?;
        let row = check.row();
        let argv = row.argv;
        let command = argv.join(" ");
        let said = say(&format!("pre-push: {}: {command}", short(tip)));
        cancel::check().map_err(Ended::Cancelled)?;
        said.map_err(Ended::Stream)?;
        let (program, args) = argv.split_first().expect("every check has a program");
        let mut started = git::command(environ, program);
        if row.tools_target {
            started.env("CARGO_TARGET_DIR", top.join(TOOLS_TARGET));
        }
        let mut child = started
            .args(args)
            .current_dir(tree)
            .process_group(0)
            .spawn()
            .map_err(|error| Ended::Fault(format!("{program}: {error}")))?;
        let status = cancel::wait(&mut child).map_err(|unwaited| match unwaited {
            Unwaited::Cancelled(code) => Ended::Cancelled(code),
            Unwaited::Unstopped(code, error) => {
                Ended::Unstopped(code, format!("{program}: {error}"))
            }
            Unwaited::Failed(error) => Ended::Fault(format!("{program}: {error}")),
        })?;
        if !status.success() {
            failures.push(command);
        }
    }
    Ok(failures)
}

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
    let stdout = drain(child.stdout.take());
    let stderr = drain(child.stderr.take());
    let status = cancel::wait(&mut child).map_err(|unwaited| match unwaited {
        Unwaited::Cancelled(code) => Ended::Cancelled(code),
        Unwaited::Unstopped(code, error) => Ended::Unstopped(code, format!("git: {error}")),
        Unwaited::Failed(error) => Ended::Fault(format!("git: {error}")),
    })?;
    let stdout = drained(stdout)?;
    if status.success() {
        return String::from_utf8(stdout).map(drop).map_err(|error| {
            Ended::Git(GitError::NotUtf8(format!("{}: {error}", git::label(&args))))
        });
    }
    let stderr = drained(stderr)?;
    Err(Ended::Git(git::failed(&args, &stderr)))
}

/// `drain` reads `stream` to its end on a thread of its own. Where the thread cannot start, the stream is
/// closed and its bytes read as none.
fn drain(stream: Option<impl Read + Send + 'static>) -> Option<thread::JoinHandle<Vec<u8>>> {
    let mut stream = stream?;
    thread::Builder::new()
        .spawn(move || {
            let mut bytes = Vec::new();
            let _ = stream.read_to_end(&mut bytes);
            bytes
        })
        .ok()
}

/// `drained` waits for the reader of `drain`, reading the signal record between polls, since a descendant
/// of Git can hold the stream open after Git exits.
///
/// # Errors
///
/// A signal was recorded while the reader ran.
fn drained(reader: Option<thread::JoinHandle<Vec<u8>>>) -> Result<Vec<u8>, Ended> {
    let Some(reader) = reader else {
        return Ok(Vec::new());
    };
    let mut pause = Duration::from_micros(500);
    while !reader.is_finished() {
        cancel::check().map_err(Ended::Cancelled)?;
        thread::sleep(pause);
        pause = (pause * 2).min(Duration::from_millis(20));
    }
    Ok(reader.join().unwrap_or_default())
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
