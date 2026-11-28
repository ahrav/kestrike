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
//! The parent is the run's scratch directory, and the hook's spool of the ref lines stands in it too. A
//! user whom a directory's mode gives write access while it has no sticky bit can rename or remove any
//! entry of it, and so can the directory's owner. Such a user could swap the spool, the worktree's
//! directory or a directory on the way to them between the steps that name them. [`scratch`] therefore
//! refuses, before the tool reads its standard input, a parent that a user other than the tool's real
//! user and root owns, and a parent or a directory above it whose mode gives its group or every user
//! write access without the sticky bit. The directories above are those in which the parent's path looks
//! a name up, from the root down and through the links on the way. [`make_tree`] reads those statuses
//! again before each directory it makes. A sticky directory passes, since only an entry's owner, the
//! directory's owner and root can rename the entry there, so `/tmp` passes. Any user can make a link in
//! such a directory and replace it later, so [`scratch`] also refuses a parent whose path passes through
//! a link that a user other than the real user and root owns in a directory its group or every user can
//! write; a link in a directory that only its owner can write is trusted with that owner. The tool
//! trusts the owner of a directory above the parent, whoever that is: where root's directories read as
//! another id, as in a user namespace that maps the real user alone, a `TMPDIR` the user owns still
//! passes, and a sticky `/tmp` whose owner reads as another id is refused.
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
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::thread;

use crate::environ::Environ;
use crate::git::{self, GitError};
use crate::hook::{Check, argument, short};
use crate::ownership::{SHARED, ignored, real_uid, status, traversed};
use crate::text::{Text, strip_str};

use super::cancel::{self, Unwaited};
use super::{Exit, NAME, fail, say};

const PREFIX: &str = "kestrike-pre-push-";
const LETTERS: &[u8; 37] = b"abcdefghijklmnopqrstuvwxyz0123456789_";
const NAME_LENGTH: usize = 8;
const NAME_ATTEMPTS: usize = 10_000;

/// The sticky bit of a directory's mode: only an entry's owner, the directory's owner and root can rename
/// or remove the entry.
const STICKY: u32 = 0o1000;

/// The most links [`foreign_link`] reads on one path, the most Linux follows in one path's resolution.
const MAX_LINKS: usize = 40;

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
/// standard error, 2 for a parent directory that [`checked`] refuses and for a
/// `git worktree add` that exits nonzero or writes output that is not UTF-8, and 1
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
            return Err(error.exit());
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

/// Why a scratch parent is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Exposure {
    /// A user other than the tool's real user and root owns the directory.
    Owned,
    /// The directory's mode gives its group or every user write access, and it has no sticky bit.
    Writable,
    /// A link on the way that [`planted`] holds for.
    Linked,
}

/// `exposed` judges the scratch parent by its owner and its mode, for the real user `user`: a directory
/// another user than `user` and root owns is [`Exposure::Owned`] whatever its mode, since its owner can
/// rename its entries, and one [`writable`] holds for is [`Exposure::Writable`].
pub(super) fn exposed(owner: u32, mode: u32, user: u32) -> Option<Exposure> {
    if ![user, 0].contains(&owner) {
        Some(Exposure::Owned)
    } else {
        writable(mode).then_some(Exposure::Writable)
    }
}

/// `writable` holds for a mode with a group or other write bit and no sticky bit, the one test of a
/// directory above the scratch parent, whose owner the tool trusts.
pub(super) fn writable(mode: u32) -> bool {
    mode & SHARED != 0 && mode & STICKY == 0
}

/// `planted` holds for a link that `owner` owns in a directory of mode `holder`, for the real user `user`:
/// the mode gives the directory's group or every user write access, so any of them can make an entry
/// there, and the link's owner, who can replace the link, is neither `user` nor root. A link in a
/// directory that only its owner can write is trusted with that owner.
pub(super) fn planted(owner: u32, holder: u32, user: u32) -> bool {
    holder & SHARED != 0 && ![user, 0].contains(&owner)
}

/// `foreign_link` returns the first link that [`planted`] holds for, for the real user `user`, among the
/// links that resolving the absolute `path` passes through, the path's own name included. It reads each
/// name from the root down with `lstat`, and at a link it goes on from the link's directory through the
/// link's target and the names that follow. It returns `None` where the walk reaches an absent name, the
/// path's end or the link after the first [`MAX_LINKS`] before it meets such a link.
///
/// # Errors
///
/// [`Unusable::Fault`] where an `lstat` fails with another error than an absent path's, or a link
/// cannot be read.
pub(super) fn foreign_link(path: &Path, user: u32) -> Result<Option<PathBuf>, Unusable> {
    let fault = |at: &Path, error: io::Error| Unusable::Fault(format!("{}: {error}", shown(at)));
    let mut path = path.to_path_buf();
    for _ in 0..=MAX_LINKS {
        let (mut holder, mut mode) = (PathBuf::from("/"), 0);
        let mut names = path.components();
        let (link, owner) = loop {
            let Some(name) = names.next() else {
                return Ok(None);
            };
            let entry = holder.join(name);
            match fs::symlink_metadata(&entry) {
                Ok(found) if found.is_symlink() => break (entry, found.uid()),
                Ok(found) => (holder, mode) = (entry, found.mode()),
                Err(error) if ignored(&error) => return Ok(None),
                Err(error) => return Err(fault(&entry, error)),
            }
        };
        if planted(owner, mode, user) {
            return Ok(Some(link));
        }
        let target = fs::read_link(&link).map_err(|error| fault(&link, error))?;
        path = holder.join(target).join(names.as_path());
    }
    Ok(None)
}

/// Why the run has no directory to make a worktree in.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Unusable {
    /// The scratch parent `parent` is refused for `at`: itself, by [`exposed`], a directory its path is
    /// reached through, by [`writable`], or a link on the way, by [`foreign_link`]. `pre-push:
    /// <sentence>` names both and the cause, and the exit is 2.
    Exposed {
        parent: PathBuf,
        at: PathBuf,
        exposure: Exposure,
    },
    /// A signal was recorded by the time the statuses were read; the field is the exit code, and nothing
    /// is printed.
    Cancelled(u8),
    /// A failed step of the tool's own; `pre-push-checks: <text>` is printed, and the exit is 1.
    Fault(String),
}

impl Unusable {
    /// `exit` prints the line of `self`, where it has one, and returns its exit code.
    fn exit(&self) -> Exit {
        match self {
            Self::Exposed {
                parent,
                at,
                exposure,
            } => {
                let cause = match exposure {
                    Exposure::Owned => "is owned by another user",
                    Exposure::Writable => {
                        "is writable by its group or by other users and has no sticky bit"
                    }
                    Exposure::Linked => "another user owns",
                };
                let named = if *exposure == Exposure::Linked {
                    format!(
                        "the scratch directory {} is reached through the link {}, which {cause}",
                        shown(parent),
                        shown(at)
                    )
                } else if at == parent {
                    format!("the scratch directory {} {cause}", shown(parent))
                } else {
                    format!(
                        "the scratch directory {} is reached through {}, which {cause}",
                        shown(parent),
                        shown(at)
                    )
                };
                fail(
                    &format!(
                        "pre-push: {named}; set TMPDIR to a directory that you own and only you can \
                         write"
                    ),
                    2,
                )
            }
            Self::Cancelled(code) => *code,
            Self::Fault(text) => fail(&format!("{NAME}: {text}"), 1),
        }
    }
}

/// `parent` is `TMPDIR` when it is set and not empty, else `/tmp`, as [`checked`] returns it.
fn parent() -> Result<PathBuf, Unusable> {
    let chosen = std::env::var_os("TMPDIR")
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| OsString::from("/tmp"));
    checked(&chosen)
}

/// `checked` is [`judged`] for the tool's real user.
pub(super) fn checked(chosen: &OsStr) -> Result<PathBuf, Unusable> {
    judged(chosen, real_uid())
}

/// `judged` makes `chosen` absolute against the working directory and reads, for the real user `user`,
/// the status of each directory in which that path looks a name up, from the root down and through the
/// links on the way, then the owner of each link on the way, and then the status of the path itself,
/// following links. A path that names no directory, an absent one included, is returned as it is, and
/// the `mkdir` under it reports the failure.
///
/// # Errors
///
/// [`Unusable::Cancelled`] where a signal is recorded once the statuses are read, whatever the reads
/// gave; else [`Unusable::Exposed`] for the first directory above the path that is [`writable`], for the
/// link [`foreign_link`] returns, or for the path itself where [`exposed`] refuses it, and
/// [`Unusable::Fault`] where the working directory or a link on the way cannot be read, or a `stat` or
/// an `lstat` fails with another error than an absent path's.
pub(super) fn judged(chosen: &OsStr, user: u32) -> Result<PathBuf, Unusable> {
    let fault = |error: crate::ownership::PathError| Unusable::Fault(error.to_string());
    let read = || {
        let parent =
            std::path::absolute(chosen).map_err(|error| Unusable::Fault(error.to_string()))?;
        let directory = |at: &Path| Ok(status(at).map_err(fault)?.filter(fs::Metadata::is_dir));
        for at in traversed(&parent).map_err(fault)? {
            if directory(&at)?.is_some_and(|found| writable(found.mode())) {
                let exposure = Exposure::Writable;
                return Err(Unusable::Exposed {
                    parent,
                    at,
                    exposure,
                });
            }
        }
        if let Some(at) = foreign_link(&parent, user)? {
            let exposure = Exposure::Linked;
            return Err(Unusable::Exposed {
                parent,
                at,
                exposure,
            });
        }
        let found = directory(&parent)?;
        match found.and_then(|found| exposed(found.uid(), found.mode(), user)) {
            Some(exposure) => Err(Unusable::Exposed {
                at: parent.clone(),
                parent,
                exposure,
            }),
            None => Ok(parent),
        }
    };
    let read = read();
    cancel::check().map_err(Unusable::Cancelled)?;
    read
}

/// `scratch` refuses the run where [`parent`] refuses the directory its worktrees go under, which is also
/// the directory the hook spools the ref lines in. The tool calls it before it reads its standard input,
/// so a refused directory ends the push before a byte of the spool is read.
///
/// # Errors
///
/// The exit code: `128 + n` for a recorded signal, 2 for a parent that [`checked`] refuses, after the
/// line that names it, 1 where a status cannot be read, and 120 where the line cannot be written.
pub(super) fn scratch() -> Result<(), Exit> {
    parent().map(drop).map_err(|unusable| unusable.exit())
}

/// `make_tree` makes the worktree's directory.
///
/// # Errors
///
/// [`parent`] refuses the parent, cannot read it or finds a signal recorded, the random bytes cannot be
/// read, a `mkdir` fails with another error than a taken name, or every name drawn is taken; the text
/// names the path where a `mkdir` failed.
fn make_tree() -> Result<PathBuf, Unusable> {
    let parent = parent()?;
    let random = |error: io::Error| Unusable::Fault(format!("/dev/urandom: {error}"));
    let mut source = File::open("/dev/urandom").map_err(random)?;
    for _ in 0..NAME_ATTEMPTS {
        let mut name = PREFIX.as_bytes().to_vec();
        name.extend(letters(&mut source).map_err(random)?);
        let path = parent.join(OsStr::from_bytes(&name));
        match DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(Unusable::Fault(format!("{}: {error}", shown(&path)))),
        }
    }
    Err(Unusable::Fault(format!(
        "{}: no usable temporary directory name found",
        shown(&parent)
    )))
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
