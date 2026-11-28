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
//! write. In a directory writable only by its owner, the directory owner's trust extends to links in that directory.
//! [`foreign_entry`] tests the owner of each entry along the path.
//! In a group-writable or world-writable directory, an entry passes the [`foreign_entry`] owner test only if the tool's real user or root owns it.
//! In a directory writable only by its owner, an entry of any owner passes the [`foreign_entry`] owner test.
//! When a user namespace maps only a nonroot real UID, root-owned directories appear to have the overflow UID.
//! When only the owner of `/` can write to `/`, `/tmp` with the overflow UID passes the [`foreign_entry`] owner test on the path to a user-owned `TMPDIR`.
//! [`scratch`] rejects that `/tmp` as the scratch directory itself.
//!
//! Cargo and rustup search the ancestors of their working directory for configuration. For a row with
//! `tools_target`, [`refusal`] fails the row before Cargo starts when [`foreign_toolchain_paths`] names
//! a path for the worktree's parent: a directory of its lineage that another user owns or can write, or a
//! Cargo or rustup entry there that another user owns or can write. The default `/tmp` is such a
//! directory. The failure line names the paths. The check covers configuration another user plants above
//! the worktree. The check trusts the tip's files and the pusher's environment.
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
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::thread;

use crate::environ::Environ;
use crate::git::{self, GitError};
use crate::hook::{Check, TOOLS_TARGET, argument, short};
use crate::ownership::{
    self, Opened, SHARED, foreign_toolchain_paths, ignored, real_uid, status, traversed,
};
use crate::text::{Text, strip_str};

use super::cancel::{self, Unwaited};
use super::lock::{self, Unheld};
use super::{Exit, NAME, fail, say};

const PREFIX: &str = "kestrike-pre-push-";
const LETTERS: &[u8; 37] = b"abcdefghijklmnopqrstuvwxyz0123456789_";
const NAME_LENGTH: usize = 8;
const NAME_ATTEMPTS: usize = 10_000;

/// The name of the tool's directory under [`TOOLS_TARGET`]. A Cargo profile's name holds letters, digits,
/// `-` and `_`. The dot distinguishes `pre-push.d` from Cargo profile names.
pub(super) const OWN: &str = "pre-push.d";

/// [`OWN`] contains the lock file named by [`LOCK`].
pub(super) const LOCK: &str = "lock";

const CONFIGURATION: [&str; 4] = [
    ".cargo/config.toml",
    ".cargo/config",
    "rust-toolchain",
    "rust-toolchain.toml",
];

/// The most bytes of one configuration file that [`differs`] compares.
const CONFIGURATION_LIMIT: u64 = 1 << 20;

/// The sticky bit of a directory's mode: only an entry's owner, the directory's owner and root can rename
/// or remove the entry.
const STICKY: u32 = 0o1000;

/// The most links [`foreign_entry`] reads on one path, the most Linux follows in one path's resolution.
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
    top: &Path,
    tip: &Text,
    checks: &[Check],
) -> Result<Vec<String>, Exit> {
    let shared = checks.iter().any(|check| check.row().tools_target);
    let tree = match make_tree(shared.then_some(top)) {
        Ok(tree) => tree,
        Err(error) => {
            cancel::check()?;
            return Err(error.exit());
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

/// A row with `tools_target` keeps its build in [`TOOLS_TARGET`] under `top`, past the worktree's
/// removal, with Cargo's cache of rustc's answers disabled.
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
        if let Some(line) = unrunnable(*check, cfg!(target_os = "linux")) {
            say(&format!("pre-push: {}: {line}", short(tip))).map_err(Ended::Stream)?;
            continue;
        }
        let mut started = git::command(environ, program);
        let mut held = None;
        if row.tools_target {
            let target = top.join(TOOLS_TARGET);
            if let Some(reason) = refusal(tree, &target)? {
                failures.push(format!("{command}: {reason}"));
                continue;
            }
            copy_lock(top, tree)?;
            for name in CONFIGURATION {
                if differs(&top.join(name), &tree.join(name)) {
                    let said = say(&format!(
                        "pre-push: {}: the working copy's {name} differs from the tip's, and the \
                         row's build reads it beside the tip's",
                        short(tip)
                    ));
                    cancel::check().map_err(Ended::Cancelled)?;
                    said.map_err(Ended::Stream)?;
                }
            }
            started
                .env("CARGO_TARGET_DIR", &target)
                .env("CARGO_BUILD_BUILD_DIR", &target)
                .env("CARGO_CACHE_RUSTC_INFO", "0");
            let path = tree.parent().unwrap_or(tree).join(LOCK);
            let waiting = || {
                say(&format!(
                    "pre-push: {}: waiting for the lock {}, which another push of this checkout holds",
                    short(tip),
                    shown(&path)
                ))
            };
            held = match lock::take(&path, waiting) {
                Ok(lock) => Some(lock),
                Err(Unheld::Refused(reason)) => {
                    failures.push(format!("{command}: {reason}"));
                    continue;
                }
                Err(Unheld::Cancelled(code)) => return Err(Ended::Cancelled(code)),
                Err(Unheld::Unsaid(code)) => return Err(Ended::Stream(code)),
                Err(Unheld::Fault(message)) => return Err(Ended::Fault(message)),
            };
        }
        let mut child = started
            .args(args)
            .current_dir(tree)
            .process_group(0)
            .spawn()
            .map_err(|error| Ended::Fault(format!("{program}: {error}")))?;
        let status =
            cancel::wait(&mut child, || true).map_err(|unwaited| ended(program, unwaited))?;
        drop(held);
        if !status.success() {
            failures.push(command);
        }
    }
    Ok(failures)
}

/// On non-Linux hosts, the push skips the `HostStop` row and reports that the workspace job runs its
/// cases, which run only on Linux.
fn unrunnable(check: Check, linux: bool) -> Option<&'static str> {
    (check == Check::HostStop && !linux).then_some(
        "the host stop controller's cases run on Linux alone, so this host runs none of them; the workspace job runs them",
    )
}

/// A `tools_target` row fails before Cargo starts if [`foreign_toolchain_paths`] finds a path another
/// user owns or can write for the worktree's parent, or if `target` holds a brace, which Cargo reads in a
/// build directory as a template.
///
/// # Errors
///
/// The ownership check fails to read a path.
fn refusal(tree: &Path, target: &Path) -> Result<Option<String>, Ended> {
    let parent = tree.parent().unwrap_or(tree);
    let foreign = foreign_toolchain_paths(parent)
        .map_err(|error| Ended::Fault(format!("{}: {}", shown(error.path()), error.error())))?;
    if !foreign.is_empty() {
        let named: Vec<Text> = foreign.iter().map(|path| shown(path)).collect();
        return Ok(Some(format!(
            "another user owns or can write {}, and so can configure Cargo or rustup in the tip's \
             worktree, which stands under the checkout",
            Text::join(", ", &named)
        )));
    }
    let bytes = target.as_os_str().as_bytes();
    if bytes.contains(&b'{') || bytes.contains(&b'}') {
        return Ok(Some(format!(
            "{} holds a brace, which Cargo reads in a build directory as a template",
            shown(target)
        )));
    }
    Ok(None)
}

/// `copy_lock` uses the checkout's lockfile to supply dependency versions for the tip's manifests.
/// Exclusive creation preserves any existing worktree `Cargo.lock`, including a symlink.
///
/// # Errors
///
/// For a lockfile I/O error, `Ended::Fault` identifies the affected path.
fn copy_lock(top: &Path, tree: &Path) -> Result<(), Ended> {
    let fault = |path: &Path, error: &io::Error| Ended::Fault(format!("{}: {error}", shown(path)));
    let source = top.join("Cargo.lock");
    let opened =
        ownership::open_regular(&source).map_err(|error| fault(error.path(), error.error()))?;
    let Opened::File(mut file) = opened else {
        return Ok(());
    };
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| fault(&source, &error))?;
    let target = tree.join("Cargo.lock");
    let mut copy = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&target)
    {
        Ok(copy) => copy,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => return Ok(()),
        Err(error) => return Err(fault(&target, &error)),
    };
    copy.write_all(&bytes)
        .map_err(|error| fault(&target, &error))
}

/// `differs` reads up to one byte past [`CONFIGURATION_LIMIT`] through the same descriptor to detect oversized files.
/// An unreadable file, a non-regular entry and an oversized file each count as differing.
fn differs(ours: &Path, theirs: &Path) -> bool {
    let read = |path: &Path| match ownership::open_regular(path) {
        Ok(Opened::Absent) => Some(None),
        Ok(Opened::File(file)) => {
            let mut bytes = Vec::new();
            let read = file
                .take(CONFIGURATION_LIMIT + 1)
                .read_to_end(&mut bytes)
                .ok()?;
            (u64::try_from(read).ok()? <= CONFIGURATION_LIMIT).then_some(Some(bytes))
        }
        Ok(Opened::Other) | Err(_) => None,
    };
    match (read(ours), read(theirs)) {
        (Some(ours), Some(theirs)) => ours != theirs,
        _ => true,
    }
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
    /// The path traversal encounters a directory whose owner and parent mode satisfy [`planted`].
    Planted,
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

/// `planted` holds when the mode `holder` of a directory has a group or other write bit and `owner`, the
/// owner of an entry in that directory, differs from both `user` and root.
pub(super) fn planted(owner: u32, holder: u32, user: u32) -> bool {
    holder & SHARED != 0 && ![user, 0].contains(&owner)
}

/// `foreign_entry` resolves the absolute `path` from the root with `lstat`, following each link through
/// its target, and returns the first eligible link or intermediate directory whose owner and containing
/// directory's mode satisfy [`planted`].
/// It returns a link with [`Exposure::Linked`].
/// It returns a directory that has a later name on the path with [`Exposure::Planted`].
/// `foreign_entry` treats `trusted` and its ancestors as trusted entries.
/// `foreign_entry` returns `None` when it encounters an absent name or exhausts the path.
///
/// # Errors
///
/// [`Unusable::Fault`] where an `lstat` fails with another error than an absent path's, or a link
/// cannot be read.
pub(super) fn foreign_entry(
    trusted: &Path,
    path: &Path,
    user: u32,
) -> Result<Option<(PathBuf, Exposure)>, Unusable> {
    let fault = |at: &Path, error: io::Error| Unusable::Fault(format!("{}: {error}", shown(at)));
    let mut path = path.to_path_buf();
    for _ in 0..=MAX_LINKS {
        let (mut holder, mut mode) = (PathBuf::from("/"), 0);
        let mut names = path.components();
        let link = loop {
            let Some(name) = names.next() else {
                return Ok(None);
            };
            let entry = holder.join(name);
            let found = match fs::symlink_metadata(&entry) {
                Ok(found) => found,
                Err(error) if ignored(&error) => return Ok(None),
                Err(error) => return Err(fault(&entry, error)),
            };
            let passed = found.is_dir() && !names.as_path().as_os_str().is_empty();
            let exposure = if found.is_symlink() {
                Some(Exposure::Linked)
            } else {
                (passed && name != Component::ParentDir).then_some(Exposure::Planted)
            };
            if let Some(exposure) = exposure
                && !trusted.starts_with(&entry)
                && planted(found.uid(), mode, user)
            {
                return Ok(Some((entry, exposure)));
            }
            if found.is_symlink() {
                break entry;
            }
            (holder, mode) = (entry, found.mode());
        };
        let target = fs::read_link(&link).map_err(|error| fault(&link, error))?;
        path = holder.join(target).join(names.as_path());
    }
    Ok(None)
}

/// Why the run has no directory to make a worktree in.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Unusable {
    /// The scratch parent `parent` is refused for `at`: itself, by [`exposed`], a directory its path is
    /// reached through, by [`writable`], or a link or a directory on the way, by [`foreign_entry`].
    /// `pre-push: <sentence>` names both and the cause, and the exit is 2.
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
    /// [`own`] refuses the entry `at` for `state`. `exit` prints `pre-push: <sentence>` and returns 2.
    Taken { at: PathBuf, state: Taken },
}

/// The state of an entry that [`own`] refuses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Taken {
    Link,
    Other,
    Owned,
    Writable,
}

/// Only its owner and root can replace an entry of a directory whose mode has no group or other write
/// bit.
fn own(top: &Path) -> Result<PathBuf, Unusable> {
    let read = || {
        let fault =
            |at: &Path, error: io::Error| Unusable::Fault(format!("{}: {error}", shown(at)));
        let target = top.join(TOOLS_TARGET);
        let at = target.join(OWN);
        fs::create_dir_all(&target).map_err(|error| fault(&target, error))?;
        match DirBuilder::new().mode(0o700).create(&at) {
            Err(error) if error.kind() != io::ErrorKind::AlreadyExists => {
                return Err(fault(&at, error));
            }
            _ => {}
        }
        let found = fs::symlink_metadata(&at).map_err(|error| fault(&at, error))?;
        let state = if found.is_symlink() {
            Taken::Link
        } else if !found.is_dir() {
            Taken::Other
        } else if found.uid() != real_uid() {
            Taken::Owned
        } else if found.mode() & SHARED != 0 {
            Taken::Writable
        } else {
            return Ok(at);
        };
        Err(Unusable::Taken { at, state })
    };
    let read = read();
    cancel::check().map_err(Unusable::Cancelled)?;
    read
}

impl Unusable {
    /// `exit` prints the line of `self`, where it has one, and returns its exit code.
    fn exit(&self) -> Exit {
        match self.line() {
            Ok((line, code)) => fail(&line, code),
            Err(code) => code,
        }
    }

    /// `line` returns `Err(code)` for a recorded signal; otherwise it returns `Ok((line, code))`, where
    /// `exit` prints `line` and returns `code`.
    pub(super) fn line(&self) -> Result<(String, Exit), Exit> {
        match self {
            Self::Exposed {
                parent,
                at,
                exposure,
            } => {
                let (parent, entry) = (shown(parent), shown(at));
                let named = match exposure {
                    Exposure::Linked => format!(
                        "the scratch directory {parent} is reached through the link {entry}, which \
                         another user owns"
                    ),
                    Exposure::Planted => format!(
                        "the scratch directory {parent} is reached through {entry}, which another \
                         user owns in a directory that its group or other users can write"
                    ),
                    Exposure::Owned | Exposure::Writable => {
                        let cause = if *exposure == Exposure::Owned {
                            "is owned by another user"
                        } else {
                            "is writable by its group or by other users and has no sticky bit"
                        };
                        if parent == entry {
                            format!("the scratch directory {parent} {cause}")
                        } else {
                            format!(
                                "the scratch directory {parent} is reached through {entry}, which \
                                 {cause}"
                            )
                        }
                    }
                };
                Ok((
                    format!(
                        "pre-push: {named}; set TMPDIR to a directory that you own and only you can \
                         write"
                    ),
                    2,
                ))
            }
            Self::Cancelled(code) => Err(*code),
            Self::Fault(text) => Ok((format!("{NAME}: {text}"), 1)),
            Self::Taken { at, state } => {
                let state = match state {
                    Taken::Link => "is a link",
                    Taken::Other => "is no directory",
                    Taken::Owned => "is owned by another user",
                    Taken::Writable => "is writable by its group or by other users",
                };
                Ok((
                    format!(
                        "pre-push: the worktree directory {} {state}; remove it, and the next push \
                         makes it",
                        shown(at)
                    ),
                    2,
                ))
            }
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
    judged(Path::new("/"), chosen, real_uid())
}

/// `judged` makes `chosen` absolute against the working directory and reads, for the real user `user`,
/// the status of each directory in which that path looks a name up, from the root down and through the
/// links along the path, then the owner of each entry [`foreign_entry`] tests, then the status of the path itself,
/// following links. A path that names no directory, an absent one included, is returned as it is, and
/// the `mkdir` under it reports the failure.
///
/// # Errors
///
/// [`Unusable::Cancelled`] where a signal is recorded once the statuses are read, whatever the reads
/// gave; else [`Unusable::Exposed`] for the first directory above the path that is [`writable`], for the
/// entry [`foreign_entry`] returns, or for the path itself where [`exposed`] refuses it, and
/// [`Unusable::Fault`] where the working directory or a link on the way cannot be read, or a `stat` or
/// an `lstat` fails with another error than an absent path's.
pub(super) fn judged(trusted: &Path, chosen: &OsStr, user: u32) -> Result<PathBuf, Unusable> {
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
        if let Some((at, exposure)) = foreign_entry(trusted, &parent, user)? {
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
/// [`own`] or [`parent`] refuses the directory, cannot read it, or detects a recorded signal, the random bytes cannot be
/// read, a `mkdir` fails with another error than a taken name, or every name drawn is taken; the text
/// names the path where a `mkdir` failed.
fn make_tree(top: Option<&Path>) -> Result<PathBuf, Unusable> {
    let parent = match top {
        Some(top) => own(top)?,
        None => parent()?,
    };
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
