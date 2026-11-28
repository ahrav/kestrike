//! `pre-push-checks` runs the checks a push needs against the commits being pushed.
//!
//! The pre-push hook starts it as `pre-push-checks REMOTE` with Git's ref lines on standard input. It
//! takes its first argument as the name of the remote the push goes to and ignores later ones. Before it
//! reads standard input it refuses a scratch directory, `TMPDIR` or `/tmp`, that a user other than its
//! real user and root owns, or where the group or other users can write it or a directory its path is
//! reached through while that directory has no sticky bit, or whose path passes through a link that such a
//! user owns in a directory its group or other users can write. It then reads
//! standard input whole, decodes it as UTF-8 with each other byte kept as a surrogate, and splits it into
//! lines, and refuses the input before any Git read where a line's local or remote field is no full
//! object id. [`Plan`] decides each line's checks, scans and guarded records; the tool then runs the
//! weakened-test scan of each range through [`scan_range`], with standard error as its report stream, the
//! chaos record guard, and each tip's checks in a worktree of the tip that the run adds and removes. Every
//! failure is printed as `pre-push: failed: <failure>` at the end.
//!
//! Exit 0 passes; 1 is a failed check or a failed step of the tool's own, a scratch directory whose
//! status cannot be read, a Git start error with a raw OS error code and a
//! failed read or write of the batch read's Git child among them, named by a `pre-push-checks: ` line, or
//! for Git that cannot start for the worktree's removal by the line `pre-push: could not remove worktree
//! <tree>: git: <error>`; a guarded chaos record that is missing or not JSON is a failure listed at the
//! end with the failed checks. 2 is every other refusal before the checks, named by a `pre-push: ` line:
//! a scratch directory that another user can reach by ownership, a write bit or a link, a malformed ref
//! line, a
//! Git read that exits nonzero where the read is not a presence test, Git output
//! that is not UTF-8, a tree entry or a raw diff record of a form Git's manual does not give,
//! and a `git worktree add` that exits nonzero, which exits 1
//! where Git cannot start for the removal; 2 is also signal handlers that cannot be installed and a
//! checkout's top that cannot be made absolute, each named by a `pre-push-checks: ` line.
//! A presence read, and a read of the inventory or the registry, whose Git
//! command exits nonzero reads as an absent file, and a removal that Git refuses is a warning. 120 is a
//! failed write to standard error; 101 a panic in the scan; and
//! `128 + n` the first signal `n` that [`cancel`] records, regardless of its inherited disposition. The
//! tool checks the signal record after reading the scratch directory's status, after reading standard
//! input, after each Git read of a ref line's plan and
//! of the guard, through the plan's probe, after each scan, after each line it prints, and while a check or
//! `git worktree add` runs. After a Git read or scan returns, the tool honors the recorded signal
//! regardless of the result and starts no further read, scan or check, and it then prints only a failed
//! worktree removal and a running check whose SIGKILL or reap failed.

mod cancel;
mod lock;
mod worktree;

use std::ffi::{OsStr, OsString};
use std::io::{self, Read};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use crate::git::GitError;
use crate::hook::{Failure, Plan, argument, short};
use crate::stream::emit;
use crate::text::Text;
use crate::tools::scan_weakened_tests::scan_range;

pub const NAME: &str = "pre-push-checks";

/// A failed write to standard error.
const STREAM_FAILED: u8 = 120;

/// The exit code of a push that ends, with everything it prints already written.
type Exit = u8;

/// `run` installs the signal record, then runs the push's checks and returns the exit code.
///
/// `run` is meant to run once, in a process of its own, whether a caller names it or reaches it through
/// the tool table: it replaces the handlers of SIGINT, SIGTERM, SIGHUP and SIGQUIT and SIGCHLD's
/// disposition, changes the calling thread's signal mask, and restores none of them, and the first signal
/// it records stays recorded for the life of the process. Where the installation fails, part of those
/// changes can stand, the four signals blocked in the calling thread among them.
pub fn run(top: &Path, args: &[OsString]) -> u8 {
    if let Err(error) = cancel::install() {
        return fail(&format!("{NAME}: the signal handlers: {error}"), 2);
    }
    let destination = args.first().map_or(OsStr::new(""), OsString::as_os_str);
    let top = match std::path::absolute(top) {
        Ok(top) => top,
        Err(error) => {
            let shown = Text::from_os(top.as_os_str());
            return fail(&format!("{NAME}: the checkout's top {shown}: {error}"), 2);
        }
    };
    push(&top, destination).unwrap_or_else(|code| code)
}

/// The longest slice of a line that `say` writes after one poll: POSIX's least `PIPE_BUF`, so a pipe that
/// reports room for a write takes the slice whole unless another writer fills it first.
const SLICE: usize = 512;

/// `say` writes `line` and a line feed to standard error; a failed write is exit 120. It writes the line
/// in slices of at most [`SLICE`] bytes, each cut at a character's edge, and before each slice it waits
/// until standard error can take a write, reading the signal record while it waits, so a recorded signal
/// ends the wait with its exit code and the rest of the line is not written. A stream that another writer
/// fills between the poll and the write can still hold a slice's write until its reader drains it.
fn say(line: &str) -> Result<(), Exit> {
    said(io::stderr().as_fd(), &format!("{line}\n"))
}

/// `said` is [`say`] on `stream`, writing `text` as it stands.
fn said(stream: BorrowedFd<'_>, text: &str) -> Result<(), Exit> {
    let mut rest = text;
    while !rest.is_empty() {
        let mut end = rest.len().min(SLICE);
        while !rest.is_char_boundary(end) {
            end -= 1;
        }
        let (slice, after) = rest.split_at(end);
        cancel::writable(stream)?;
        emit(stream, slice).map_err(|_| STREAM_FAILED)?;
        rest = after;
    }
    Ok(())
}

/// `fail` writes `line` to standard error and returns `code`, or 120 where the write fails. A signal
/// recorded by the time the write returns outranks both: `fail` then returns its `128 + n`, the write
/// done or not.
fn fail(line: &str, code: Exit) -> Exit {
    let written = say(line);
    match cancel::check() {
        Err(signal) => signal,
        Ok(()) => written.map_or_else(|failed| failed, |()| code),
    }
}

/// `refused` ends the push on `failure`.
/// For a recorded signal, `refused` returns the signal's exit code and prints nothing.
/// For a Git start error with a raw OS error code or a batch-child I/O error, `refused` passes `pre-push-checks: <failure>` and status 1 to `fail`.
/// For every other failure, `refused` passes `pre-push: <failure>` and status 2 to `fail`.
fn refused(failure: &Failure) -> Exit {
    match failure {
        Failure::Cancelled(code) => *code,
        Failure::Git(GitError::Start(error)) if error.raw_os_error().is_some() => {
            fail(&format!("{NAME}: {failure}"), 1)
        }
        Failure::Git(GitError::Io(_)) => fail(&format!("{NAME}: {failure}"), 1),
        _ => fail(&format!("pre-push: {failure}"), 2),
    }
}

/// `push` checks the scratch directory, reads the ref lines from standard input, checks the form of every
/// line, plans them, and runs the scans, the guard and the checks
/// in that order. It returns the exit code, through `Err` where the push ends early.
fn push(top: &Path, destination: &OsStr) -> Result<Exit, Exit> {
    let mut input = Vec::new();
    worktree::scratch()?;
    let read = io::stdin().lock().read_to_end(&mut input);
    cancel::check()?;
    if let Err(error) = read {
        return Err(fail(&format!("{NAME}: standard input: {error}"), 1));
    }
    let lines = Text::from_os(OsStr::from_bytes(&input)).splitlines();
    drop(input);
    for line in &lines {
        Plan::object_ids(&argument(line)).map_err(|failure| refused(&failure))?;
    }
    let started = Plan::new(destination, cancel::check);
    cancel::check()?;
    let mut plan = started.map_err(|failure| refused(&failure))?;
    for line in &lines {
        let mut noted = Ok(());
        let planned = plan.line(&argument(line), |skipped| {
            noted = say(&format!("pre-push: {skipped}"));
        });
        cancel::check()?;
        noted?;
        planned.map_err(|failure| refused(&failure))?;
    }
    let environ = plan.environ();
    let mut failures = Vec::new();
    for (base, tip) in plan.scans() {
        let said = say(&format!(
            "pre-push: {}: tool.sh scan-weakened-tests --base {}",
            short(tip),
            short(base)
        ));
        cancel::check()?;
        said?;
        let code = scan_range(
            environ,
            &argument(base),
            &argument(tip),
            io::stderr().as_fd(),
        );
        cancel::check()?;
        if code != 0 {
            failures.push(format!(
                "scripts/tool.sh scan-weakened-tests --base {base} --head {tip}"
            ));
        }
    }
    let guarded = plan.guard();
    cancel::check()?;
    failures.extend(guarded.map_err(|failure| refused(&failure))?);
    for (tip, checks) in plan.checks() {
        failures.extend(worktree::run_checks(environ, top, tip, &checks)?);
    }
    for failure in &failures {
        let said = say(&format!("pre-push: failed: {failure}"));
        cancel::check()?;
        said?;
    }
    Ok(u8::from(!failures.is_empty()))
}
