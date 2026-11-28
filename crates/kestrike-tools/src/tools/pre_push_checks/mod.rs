//! `pre-push-checks` runs the checks a push needs against the commits being pushed.
//!
//! The pre-push hook starts it as `pre-push-checks REMOTE` with Git's ref lines on standard input. It
//! takes its first argument as the name of the remote the push goes to and ignores later ones. It reads
//! standard input whole, decodes it as UTF-8 with each other byte kept as a surrogate, and splits it into
//! lines. [`Plan`] decides each line's checks, scans and guarded records; the tool then runs the
//! weakened-test scan of each range through [`scan_range`], with standard error as its report stream, the
//! chaos record guard, and each tip's checks in a worktree of the tip that the run adds and removes. Every
//! failure is printed as `pre-push: failed: <failure>` at the end.
//!
//! Exit 0 passes, 1 is a failed check, 2 a malformed ref line or a failed Git read, 120 a failed write to
//! standard error, and `128 + n` the first of SIGINT, SIGTERM and SIGHUP that arrived, which [`cancel`]
//! records whatever disposition the tool inherited. The record is read between steps and while a check
//! runs; a Git read and a scan run to their end, and the record is acted on once they return, whatever
//! they returned. On a record the tool starts no further step and prints no check line and no failure
//! list; a failed worktree removal and a running check whose SIGKILL or reap failed are still named.

mod cancel;
mod worktree;

use std::ffi::{OsStr, OsString};
use std::io::{self, Read};
use std::os::fd::AsFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use crate::hook::{Failure, Plan};
use crate::stream::emit;
use crate::text::Text;
use crate::tools::scan_weakened_tests::scan_range;

pub const NAME: &str = "pre-push-checks";

/// A failed write to standard error.
const STREAM_FAILED: u8 = 120;

/// The exit code of a push that ends, with everything it prints already written.
type Exit = u8;

/// `run` installs the signal record, then runs the push's checks and returns the exit code.
pub fn run(_top: &Path, args: &[OsString]) -> u8 {
    if let Err(error) = cancel::install() {
        return fail(&format!("{NAME}: the signal handlers: {error}"), 2);
    }
    let destination = args.first().map_or(OsStr::new(""), OsString::as_os_str);
    push(destination).unwrap_or_else(|code| code)
}

/// `say` writes `line` and a line feed to standard error; a failed write is exit 120.
fn say(line: &str) -> Result<(), Exit> {
    emit(io::stderr().as_fd(), &format!("{line}\n")).map_err(|_| STREAM_FAILED)
}

/// `fail` writes `line` to standard error and returns `code`, or 120 where the write fails.
fn fail(line: &str, code: Exit) -> Exit {
    say(line).map_or_else(|failed| failed, |()| code)
}

/// `short` writes the first twelve code points of `commit`.
fn short(commit: &Text) -> Text {
    Text::from_code_points(commit.code_points().take(12))
        .expect("a prefix of a text holds its code points")
}

/// `os` is `text` as a program argument; a text decoded from bytes or read from Git encodes as bytes.
fn os(text: &Text) -> OsString {
    text.to_os()
        .expect("a text decoded from bytes encodes as those bytes")
}

/// `refused` prints the failure that ends the push before its checks start and returns exit 2.
fn refused(failure: &Failure) -> Exit {
    fail(&format!("pre-push: {failure}"), 2)
}

/// `push` reads the ref lines from standard input, plans them, and runs the scans, the guard and the checks
/// in that order. It returns the exit code, through `Err` where the push ends early.
fn push(destination: &OsStr) -> Result<Exit, Exit> {
    let mut input = Vec::new();
    let read = io::stdin().lock().read_to_end(&mut input);
    cancel::check()?;
    if let Err(error) = read {
        return Err(fail(&format!("{NAME}: standard input: {error}"), 1));
    }
    let lines = Text::from_os(OsStr::from_bytes(&input)).splitlines();
    let started = Plan::new(destination);
    cancel::check()?;
    let mut plan = started.map_err(|failure| refused(&failure))?;
    for line in &lines {
        let mut noted = Ok(());
        let planned = plan.line(&os(line), |skipped| {
            noted = say(&format!("pre-push: {skipped}"));
        });
        cancel::check()?;
        noted?;
        planned.map_err(|failure| refused(&failure))?;
    }
    let environ = plan.environ();
    let mut failures = Vec::new();
    for (base, tip) in plan.scans() {
        say(&format!(
            "pre-push: {}: tool.sh scan-weakened-tests --base {}",
            short(tip),
            short(base)
        ))?;
        let code = scan_range(environ, &os(base), &os(tip), io::stderr().as_fd());
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
        failures.extend(worktree::run_checks(environ, tip, &checks)?);
    }
    for failure in &failures {
        say(&format!("pre-push: failed: {failure}"))?;
    }
    Ok(u8::from(!failures.is_empty()))
}
