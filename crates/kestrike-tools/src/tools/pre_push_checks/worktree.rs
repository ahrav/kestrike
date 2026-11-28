//! The worktree of one pushed tip and the checks that run in it.
//!
//! The worktree's directory is `kestrike-pre-push-` and eight letters of `a` to `z`, `0` to `9` and `_`,
//! made with mode 0700 under `TMPDIR` when it is set and not empty, else under `/tmp`, and drawn again
//! while a name is taken. On every way out of [`run_checks`] after the directory is made,
//! `git worktree remove --force --force` runs once, the second `--force` removing a worktree that a killed
//! `git worktree add` left locked, and then the directory is removed if it still stands.

use std::ffi::{OsStr, OsString};
use std::fs::{self, DirBuilder, File};
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};

use crate::environ::Environ;
use crate::git::{self, GitError};
use crate::hook::Check;
use crate::text::Text;

use super::cancel::{self, Unwaited};
use super::{Exit, NAME, fail, os, say, short};

const PREFIX: &str = "kestrike-pre-push-";
const LETTERS: &[u8; 37] = b"abcdefghijklmnopqrstuvwxyz0123456789_";
const NAME_LENGTH: usize = 8;
const NAME_ATTEMPTS: usize = 10_000;

/// How the checks of a tip ended before their last one returned.
enum Ended {
    /// A signal was recorded; the field is the exit code.
    Cancelled(u8),
    /// A signal was recorded and the running check could not be stopped or reaped:
    /// `pre-push-checks: <message>` is printed once the worktree is removed, and the field is the exit code.
    Unstopped(u8, String),
    /// A failed write to standard error; the field is the exit code.
    Stream(u8),
    /// `git worktree add` failed: `pre-push: <error>` is printed once the worktree is removed, and the exit
    /// is 2.
    Git(GitError),
    /// A check could not be started or waited on: `pre-push-checks: <message>` is printed once the worktree
    /// is removed, and the exit is 1.
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
/// standard error, 2 for a failed `git worktree add`, and 1 where the directory cannot be made or
/// removed or a check cannot be started or waited on.
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
        return Err(fail(&format!("{NAME}: {message}"), *code));
    }
    cancel::check()?;
    let failures = match ran {
        Ok(failures) => {
            removed?;
            failures
        }
        Err(Ended::Cancelled(code) | Ended::Stream(code) | Ended::Unstopped(code, _)) => {
            return Err(code);
        }
        Err(Ended::Git(error)) => {
            removed?;
            return Err(fail(&format!("pre-push: {error}"), 2));
        }
        Err(Ended::Fault(message)) => {
            removed?;
            return Err(fail(&format!("{NAME}: {message}"), 1));
        }
    };
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
    let added = git::git(
        environ,
        &[
            OsStr::new("worktree"),
            "add".as_ref(),
            "--quiet".as_ref(),
            "--detach".as_ref(),
            tree.as_os_str(),
            &os(tip),
        ],
    );
    cancel::check().map_err(Ended::Cancelled)?;
    added.map_err(Ended::Git)?;
    let mut failures = Vec::new();
    for check in checks {
        cancel::check().map_err(Ended::Cancelled)?;
        let argv = check.row().argv;
        let command = argv.join(" ");
        say(&format!("pre-push: {}: {command}", short(tip))).map_err(Ended::Stream)?;
        let (program, args) = argv.split_first().expect("every check has a program");
        let mut child = git::command(environ, program)
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

/// `remove` runs `git worktree remove --force --force` on `tree` and prints
/// `pre-push: could not remove worktree <tree>: <Git's standard error>` when it fails.
fn remove(environ: &Environ, tree: &Path) -> Result<(), Exit> {
    let args = [
        OsStr::new("worktree"),
        "remove".as_ref(),
        "--force".as_ref(),
        "--force".as_ref(),
        tree.as_os_str(),
    ];
    let reason = match git::output(environ, &args) {
        Ok(output) if output.status.success() => return Ok(()),
        Ok(output) => String::from_utf8_lossy(&output.stderr).into_owned(),
        Err(error) => error.to_string(),
    };
    say(&format!(
        "pre-push: could not remove worktree {}: {}",
        shown(tree),
        crate::text::strip_str(&reason)
    ))
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
