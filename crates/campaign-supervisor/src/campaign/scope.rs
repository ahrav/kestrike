//! A delegated systemd scope for a controller started with no cgroup root.
//!
//! `campaign sweep`, `campaign confirm` and `campaign fuzz` each need a
//! cgroup they may divide. Started with none, the command runs itself
//! again in a new systemd user scope with `Delegate=yes`, where the inner
//! command uses the scope's own cgroup. On the first SIGINT or SIGTERM it receives, the
//! outer command sends SIGTERM to the inner one. The outer command ends in
//! the class the inner one exited with when that is a rejection or a busy
//! state, and holds on every other failure of it but one.
//!
//! `systemd-run` exits 1 when it cannot start the scope, which is also
//! the exit of a `sweep` whose totals carry `alarm`, `no_pass`,
//! `unreached` or `no_window` and of a `fuzz` whose control was missed.
//! The outer command therefore gives an inner `sweep` or `fuzz` a token as
//! `--verdict`, and an inner command that ends with that verdict writes
//! `scope.TOKEN.verdict`, which holds the token, under its root. The
//! outer command removes that file and takes an exit 1 for the verdict
//! only when the file held its token. Each command's file is its own, so
//! two scoped commands of one root that end close together keep both
//! verdicts.

use std::ffi::OsString;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::time::Duration;

use super::Error;

fn held(error: std::io::Error) -> Error {
    Error::Held(error.to_string())
}

/// A command that runs this executable with `args` in a new systemd user
/// scope with `Delegate=yes`.
///
/// # Errors
///
/// A failed resolution of this executable's path.
fn scoped(args: Vec<OsString>) -> Result<Command, Error> {
    let executable = crate::store::canonical_host(Path::new("/proc/self/exe")).map_err(held)?;
    let mut command = Command::new("systemd-run");
    command
        .args(["--user", "--scope", "-p", "Delegate=yes", "--quiet", "--"])
        .arg(executable)
        .args(args)
        .env_remove("CAMPAIGN_CGROUP_ROOT")
        .stdin(Stdio::null());
    Ok(command)
}

/// Runs this executable with `args` in a new delegated scope and returns
/// its exit status. On the first SIGINT or SIGTERM this command receives,
/// it sends SIGTERM to the inner command. The inner command writes to this
/// command's standard output and error.
///
/// # Errors
///
/// A failed signal mask, resolution of this executable's path or spawn;
/// or a failed wait, signal read or signal send, after which the inner
/// command is sent SIGTERM and awaited.
pub(super) fn run(args: Vec<OsString>) -> Result<ExitStatus, Error> {
    crate::sys::block_interruptions().map_err(held)?;
    let mut inner = scoped(args)?.spawn().map_err(held)?;
    let waited = awaited(&mut inner);
    if waited.is_err() {
        let _ = crate::sys::terminate_child(&mut inner);
        let _ = inner.wait();
    }
    waited
}

/// A token that names this command to the one it runs in its scope: its
/// process and the time.
pub(super) fn token() -> OsString {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_nanos());
    format!("{}-{now}", std::process::id()).into()
}

/// Whether `token` has the form of one [`token`] gives: decimal digits
/// and hyphens alone, so its verdict's file name is one component of the
/// root.
pub(super) fn names(token: &OsString) -> bool {
    let bytes = token.as_encoded_bytes();
    !bytes.is_empty()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_digit() || *byte == b'-')
}

/// The file under `root`, the root of a sweep or of a fuzz run, that
/// holds the verdict of the scoped command named `token`.
fn verdict(root: &Path, token: &OsString) -> std::path::PathBuf {
    let mut name = OsString::from("scope.");
    name.push(token);
    name.push(".verdict");
    root.join(name)
}

/// Records under `root`, the root of a sweep or of a fuzz run, that the
/// scoped command the outer command named `token` ends with a verdict.
///
/// # Errors
///
/// A failed write under the root.
pub(super) fn record_verdict(root: &Path, token: &OsString) -> Result<(), Error> {
    crate::store::replace_host(&verdict(root, token), token.as_encoded_bytes()).map_err(held)
}

/// Whether the scoped `sweep` or `fuzz` this command named `token`
/// recorded a verdict under `root`: its record is there and holds
/// `token`. A record that was read is removed, whatever it holds.
///
/// # Errors
///
/// A record that cannot be read or removed.
pub(super) fn recorded_verdict(root: &Path, token: &OsString) -> Result<bool, Error> {
    let path = verdict(root, token);
    let recorded = crate::store::read_host(&path, 256)?;
    crate::store::remove_host(&path).map_err(held)?;
    Ok(recorded.is_some_and(|recorded| recorded == token.as_encoded_bytes()))
}

/// Waits for `inner`, sending it SIGTERM on the first SIGINT or SIGTERM.
fn awaited(inner: &mut std::process::Child) -> Result<ExitStatus, Error> {
    let mut sent = false;
    loop {
        if let Some(status) = inner.try_wait().map_err(held)? {
            return Ok(status);
        }
        let signal = crate::sys::interruption(Duration::from_millis(250)).map_err(held)?;
        if signal.is_some() && !sent {
            sent = true;
            crate::sys::terminate_child(inner).map_err(held)?;
        }
    }
}

/// The result of a scoped `command` whose run ended with `status`. The
/// command ends in the class its run exited with when that is a rejection
/// or a busy state, so it exits alike with and without a cgroup root.
///
/// # Errors
///
/// [`Error::Rejected`] for a run that exited rejected, a busy store for
/// one that exited busy, and [`Error::Held`] for every other end than
/// success: another exit code, a signal, or a `systemd-run` that fails
/// before it runs the command.
pub(super) fn ended(command: &str, status: ExitStatus) -> Result<(), Error> {
    use crate::exit::{Exit, Supervisor};
    if status.success() {
        return Ok(());
    }
    let exited = |class| status.code() == Some(i32::from(Exit::Supervisor(class).code()));
    Err(if exited(Supervisor::Rejected) {
        Error::Rejected(format!("the scoped {command} ended with {status}"))
    } else if exited(Supervisor::Busy) {
        Error::Store(crate::store::Error::Busy)
    } else {
        Error::Held(format!("the scoped {command} ended with {status}"))
    })
}

#[cfg(test)]
#[path = "scope_tests.rs"]
mod tests;
