//! Runs one libtest case in a fresh process of the test executable and
//! credits it only from that process's completed one-test run.
//!
//! The parent re-executes its own executable with `--exact <id>
//! --test-threads=1 --nocapture` and the command-local marker set to the
//! ID, so the child runs exactly that case on one test thread and the case's
//! body runs only where the marker names it. A child started through
//! [`ExactChild::spawn_under`] runs under a wrapper program and also passes
//! `--include-ignored`, so it runs an ignored case. The parent owns the
//! child from spawn to reap: [`ExactChild::finish`] waits up to a deadline, and a child
//! still running at that deadline, or when its [`ExactChild`] drops,
//! including during a panic's unwind, is killed and waited for. Credit
//! comes only from a child that exits after completing its one test, and
//! the parent's own test result is the credited one. A signal that ends the
//! parent without unwinding skips this cleanup, and the child can outlive
//! the parent.
//!
//! The child spawns through [`spawn_quiet`] once no fixture or
//! lock-holding test membership of the parent lives, and the crate opens
//! every lock close-on-exec. The executed child starts with the crate's lock
//! descriptors closed. Callers release every fixture and lock-holding test
//! membership before spawning, because `spawn_quiet` waits for them to end.

use std::fmt;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use crate::bind::fixture::spawn_quiet;

/// The environment variable that names the one test ID whose body a child
/// runs. Only the child's command sets it.
const MARKER: &str = "KESTRIKE_EXACT_CHILD";

/// Prefixes every line a child reports, so the parent separates it from
/// libtest's own output.
const PREFIX: &str = "exact child: ";

/// Bounds the wait for a reaped child's output pipes to close.
const DRAIN: Duration = Duration::from_secs(5);

pub(crate) const DRAINS: Duration = Duration::from_secs(2 * DRAIN.as_secs());

/// Runs `body` as test `id` in a fresh child and panics unless that child
/// completes exactly one passing test, after entering `body`, before
/// `deadline` passes. The deadline starts once the child has spawned.
///
/// `id` is the calling test's own libtest ID, which libtest also gives the
/// test's thread as its name. Inside the child, where the marker names
/// `id`, it reports entry and runs `body`. The child's libtest skips
/// ignored tests, so an ignored test's child reports its one case ignored
/// and fails; [`ExactChild::spawn_under`] starts a child that includes
/// ignored tests.
///
/// # Panics
///
/// - If the calling thread's name differs from `id`, before any spawn.
/// - If the child fails to spawn.
/// - If polling the child's exit status fails.
/// - If [`credited`] rejects the child's [`Outcome`] for `id`.
pub(crate) fn run(id: &str, deadline: Duration, body: impl FnOnce()) {
    let caller = thread::current();
    assert_eq!(
        caller.name(),
        Some(id),
        "the test on this thread declares another ID"
    );
    if is_child(id) {
        report(&entered(id));
        body();
        return;
    }
    let outcome = ExactChild::spawn(id, &[])
        .unwrap_or_else(|error| panic!("spawn {id}: {error}"))
        .finish(Instant::now() + deadline);
    assert!(credited(id, &outcome), "{id} in a fresh child: {outcome:?}");
}

/// Whether the marker names `id`, which holds only in that case's child.
pub(crate) fn is_child(id: &str) -> bool {
    std::env::var_os(MARKER).is_some_and(|marker| marker == id)
}

/// Writes one report line for the supervising parent and flushes it, so the
/// parent sees it before the child stalls or dies.
pub(crate) fn report(line: &str) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{PREFIX}{line}");
    let _ = out.flush();
}

/// The report a child writes on entering `id`'s body.
pub(crate) fn entered(id: &str) -> String {
    format!("entered {id}")
}

/// Whether `outcome` credits `id`: a completed one-test passing run whose
/// reports include the entry report for `id`.
pub(crate) fn credited(id: &str, outcome: &Outcome) -> bool {
    matches!(outcome, Outcome::Completed { reports } if reports.contains(&entered(id)))
}

/// How a supervised child ended.
pub(crate) enum Outcome {
    /// It exited zero after libtest ran one test, which passed.
    Completed { reports: Vec<String> },
    /// It exited with a status libtest's one-test success does not admit:
    /// a nonzero code, or zero with a summary other than one passing test.
    Failed {
        status: ExitStatus,
        stdout: Vec<String>,
        stderr: Vec<String>,
    },
    /// A signal ended it before the deadline.
    Crashed {
        signal: i32,
        stdout: Vec<String>,
        stderr: Vec<String>,
    },
    /// It was still running at the deadline, after reporting `reports`; the
    /// supervisor then killed and reaped it. `stdout` holds the collected
    /// standard-output lines.
    Stalled {
        reports: Vec<String>,
        stdout: Vec<String>,
        stderr: Vec<String>,
    },
}

impl fmt::Debug for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (end, stdout, stderr): (String, &[String], &[String]) = match self {
            Self::Completed { reports } => ("completed".into(), reports, &[]),
            Self::Failed {
                status,
                stdout,
                stderr,
            } => (format!("failed with {status}"), stdout, stderr),
            Self::Crashed {
                signal,
                stdout,
                stderr,
            } => (format!("crashed by signal {signal}"), stdout, stderr),
            Self::Stalled { stdout, stderr, .. } => ("stalled".into(), stdout, stderr),
        };
        write!(
            f,
            "{end}\nstdout:\n{}\nstderr:\n{}",
            stdout.join("\n"),
            stderr.join("\n")
        )
    }
}

/// One supervised child running one test ID. Dropping it kills and reaps
/// a child that has not been reaped.
pub(crate) struct ExactChild {
    child: Child,
    reaped: bool,
    stdout: Receiver<String>,
    stderr: Receiver<String>,
    seen: Vec<String>,
}

impl ExactChild {
    /// Starts the current test executable on test `id` alone, with the
    /// marker naming it and `env` added to the child's command. `spawn`
    /// blocks until no fixture or lock-holding test membership lives, so the
    /// caller holds none while it calls `spawn`.
    ///
    /// # Errors
    ///
    /// - If the current executable's path cannot be resolved.
    /// - If the child process fails to spawn.
    pub(crate) fn spawn(id: &str, env: &[(&str, &str)]) -> std::io::Result<Self> {
        let mut command = Command::new(std::env::current_exe()?);
        command.args(["--exact", id, "--test-threads=1", "--nocapture"]);
        Self::start(command, id, env)
    }

    /// Starts test `id` as [`Self::spawn`] does, through `program` and its
    /// `leading` arguments, which execute the test executable's command line
    /// after them, such as `unshare --net`. The child includes ignored
    /// tests, so an ignored case runs by its exact ID.
    ///
    /// # Errors
    ///
    /// As [`Self::spawn`].
    pub(crate) fn spawn_under(
        program: &str,
        leading: &[&str],
        id: &str,
        env: &[(&str, &str)],
    ) -> std::io::Result<Self> {
        let mut command = Command::new(program);
        command.args(leading).arg(std::env::current_exe()?).args([
            "--exact",
            id,
            "--include-ignored",
            "--test-threads=1",
            "--nocapture",
        ]);
        Self::start(command, id, env)
    }

    fn start(mut command: Command, id: &str, env: &[(&str, &str)]) -> std::io::Result<Self> {
        command
            .env(MARKER, id)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (key, value) in env {
            command.env(key, value);
        }
        let quiet = spawn_quiet();
        let child = command.spawn()?;
        drop(quiet);
        let mut supervised = Self {
            child,
            reaped: false,
            stdout: mpsc::channel().1,
            stderr: mpsc::channel().1,
            seen: Vec::new(),
        };
        supervised.stdout = lines(supervised.child.stdout.take());
        supervised.stderr = lines(supervised.child.stderr.take());
        Ok(supervised)
    }

    pub(crate) fn id(&self) -> u32 {
        self.child.id()
    }

    /// Waits until `until` for the child's next report line. Every line it
    /// reads stays in the transcript [`Self::finish`] classifies. Returns
    /// `None` once `until` passes or the child's stdout closes.
    pub(crate) fn next_report(&mut self, until: Instant) -> Option<String> {
        loop {
            let left = until.saturating_duration_since(Instant::now());
            let line = self.stdout.recv_timeout(left).ok()?;
            let report = report_in(&line).map(str::to_owned);
            self.seen.push(line);
            if report.is_some() {
                return report;
            }
        }
    }

    /// Waits until `deadline` for the child to exit and classifies its end.
    /// A child still running at the deadline is killed and reaped.
    ///
    /// # Panics
    ///
    /// If polling the child's exit status fails.
    pub(crate) fn finish(self, deadline: Instant) -> Outcome {
        self.finish_observed(deadline).0
    }

    /// The returned stderr includes diagnostics when the outcome is `Outcome::Completed`.
    pub(crate) fn finish_observed(mut self, deadline: Instant) -> (Outcome, Vec<String>) {
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => {
                    self.reaped = true;
                    return self.exited(status);
                }
                Ok(None) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(10));
                }
                Ok(None) => {
                    self.kill_and_reap();
                    let stdout = self.drain_stdout();
                    let stderr = drain(&self.stderr);
                    return (
                        Outcome::Stalled {
                            reports: reports(&stdout),
                            stdout,
                            stderr: stderr.clone(),
                        },
                        stderr,
                    );
                }
                Err(error) => panic!("wait for child {}: {error}", self.child.id()),
            }
        }
    }

    /// `kill` sends `SIGKILL` to the child and reaps it before returning. The
    /// outcome carries the collected stdout and stderr; it is
    /// [`Outcome::Crashed`] by `SIGKILL` unless the child had already ended.
    ///
    /// # Panics
    ///
    /// If the kill or the wait fails.
    pub(crate) fn kill(mut self) -> Outcome {
        self.child
            .kill()
            .unwrap_or_else(|error| panic!("kill child {}: {error}", self.child.id()));
        let status = self
            .child
            .wait()
            .unwrap_or_else(|error| panic!("wait for child {}: {error}", self.child.id()));
        self.reaped = true;
        self.exited(status).0
    }

    fn exited(&mut self, status: ExitStatus) -> (Outcome, Vec<String>) {
        let stdout = self.drain_stdout();
        let stderr = drain(&self.stderr);
        let outcome = if let Some(signal) = status.signal() {
            Outcome::Crashed {
                signal,
                stdout,
                stderr: stderr.clone(),
            }
        } else if status.success() && one_test_passed(&stdout) {
            Outcome::Completed {
                reports: reports(&stdout),
            }
        } else {
            Outcome::Failed {
                status,
                stdout,
                stderr: stderr.clone(),
            }
        };
        (outcome, stderr)
    }

    fn kill_and_reap(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            self.reaped = self.child.wait().is_ok();
        }
    }

    fn drain_stdout(&mut self) -> Vec<String> {
        let mut stdout = std::mem::take(&mut self.seen);
        stdout.extend(drain(&self.stdout));
        stdout
    }
}

impl Drop for ExactChild {
    fn drop(&mut self) {
        self.kill_and_reap();
    }
}

/// Forwards each line of `pipe`, decoded lossily, to the returned receiver
/// from a detached thread, which ends when the pipe closes. The child exists
/// as an [`ExactChild`] before either thread starts, so a failed thread
/// spawn still reaps it.
fn lines(pipe: Option<impl Read + Send + 'static>) -> Receiver<String> {
    let (send, receive) = mpsc::channel();
    if let Some(pipe) = pipe {
        thread::spawn(move || {
            for line in BufReader::new(pipe).split(b'\n').map_while(Result::ok) {
                if send
                    .send(String::from_utf8_lossy(&line).into_owned())
                    .is_err()
                {
                    break;
                }
            }
        });
    }
    receive
}

/// Collects a reaped child's remaining lines until its pipe closes or
/// [`DRAIN`] passes.
fn drain(lines: &Receiver<String>) -> Vec<String> {
    let until = Instant::now() + DRAIN;
    let mut drained = Vec::new();
    while let Ok(line) = lines.recv_timeout(until.saturating_duration_since(Instant::now())) {
        drained.push(line);
    }
    drained
}

/// The report a stdout line carries. Under `--nocapture` libtest prints
/// `test NAME ... ` without a newline before a test's own output, so a
/// report can follow that prefix on one line.
fn report_in(line: &str) -> Option<&str> {
    line.split_once(PREFIX).map(|(_, report)| report)
}

fn reports(stdout: &[String]) -> Vec<String> {
    stdout
        .iter()
        .filter_map(|line| report_in(line))
        .map(str::to_owned)
        .collect()
}

/// Whether libtest's output records one selected test that passed: the
/// `running 1 test` header and a summary of one pass with no failure,
/// ignore or measurement.
fn one_test_passed(stdout: &[String]) -> bool {
    let summaries: Vec<&String> = stdout
        .iter()
        .filter(|line| line.starts_with("test result: "))
        .collect();
    stdout.iter().any(|line| line == "running 1 test")
        && matches!(
            summaries.as_slice(),
            [summary] if summary.starts_with("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; ")
        )
}
