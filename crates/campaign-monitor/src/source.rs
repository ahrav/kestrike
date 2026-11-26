//! Snapshot sources: a local or ssh `campaign status` command, or a file.
//! Every fetch is bounded: at most [`Limits::max_bytes`] of snapshot are
//! read, and a command that has not exited and closed its output by
//! [`Limits::timeout`] has its process group killed. A fetch that hits
//! either bound returns an error and parses no snapshot. Error messages
//! carry command, path and standard-error text with control characters
//! replaced. An [`InFlight`] handle names the process group of the command
//! a fetch is running, so another thread can kill it.

use std::collections::BTreeSet;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::panic::{self, AssertUnwindSafe};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use crate::signals::bytes;
use crate::snapshot::Snapshot;

const STDERR_KEPT: u64 = 64 << 10;
/// The first and the longest sleep between checks for the exit of a command
/// whose pipes have closed. The sleep doubles from `FIRST_PAUSE` up to `POLL`.
const FIRST_PAUSE: Duration = Duration::from_micros(50);
const POLL: Duration = Duration::from_millis(20);
/// The exit-polling deadline in [`stop`] after the kill signal.
const REAP_WAIT: Duration = Duration::from_secs(1);

/// The bounds of one fetch. `max_bytes` caps the command output or file
/// read. `timeout` caps how long a command may run and hold its output
/// open, after which its process group is killed, and how long a file read
/// may take.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_bytes: u64,
    pub timeout: Duration,
}

impl Default for Limits {
    /// 256 MiB and 300 s.
    fn default() -> Self {
        Self {
            max_bytes: 256 << 20,
            timeout: Duration::from_secs(300),
        }
    }
}

/// Where a snapshot comes from. `Command` runs `program` with `args`,
/// without a shell, in its own process group, and parses its standard
/// output. `File` reads a regular file.
#[derive(Debug, Clone)]
pub enum Source {
    Command { program: String, args: Vec<String> },
    File(PathBuf),
}

/// The command a fetch is running, shared with threads that may stop it.
/// The stopped flag preserves cancellation across the gap between spawning
/// a command and registering its pid.
#[derive(Debug, Clone, Default)]
pub struct InFlight(Arc<Mutex<Slot>>);

#[derive(Debug, Default)]
struct Slot {
    pid: Option<libc::pid_t>,
    stopped: bool,
}

impl InFlight {
    fn slot(&self) -> MutexGuard<'_, Slot> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// `kill` permanently marks this handle stopped, so later `start`
    /// calls return false.
    pub fn kill(&self) {
        let mut slot = self.slot();
        slot.stopped = true;
        if let Some(group) = slot.pid {
            // SAFETY: `kill` reads no memory; a negative pid names the
            // process group the unreaped command leads.
            unsafe { libc::kill(-group, libc::SIGKILL) };
        }
    }

    fn start(&self, child: &Child) -> bool {
        let mut slot = self.slot();
        slot.pid = libc::pid_t::try_from(child.id()).ok();
        !slot.stopped
    }

    /// `try_wait` on `child` with the slot held, clearing the slot when it
    /// reaps the command.
    fn try_wait(&self, child: &mut Child) -> std::io::Result<Option<ExitStatus>> {
        let mut slot = self.slot();
        let status = child.try_wait();
        if matches!(status, Ok(Some(_))) {
            slot.pid = None;
        }
        status
    }
}

impl Source {
    pub fn local(campaign: &str, state: &str) -> Self {
        Self::Command {
            program: campaign.to_owned(),
            args: vec!["status".into(), "--state".into(), state.to_owned()],
        }
    }

    /// `BatchMode=yes` makes ssh fail when it would prompt for a password.
    /// `--` ends ssh's options, so `host` and the remote command are never
    /// read as options. A leading `~/` in `campaign` or `state` expands to
    /// the remote home directory.
    pub fn ssh(host: &str, campaign: &str, state: &str) -> Self {
        Self::Command {
            program: "ssh".into(),
            args: vec![
                "-o".into(),
                "BatchMode=yes".into(),
                "--".into(),
                host.to_owned(),
                format!(
                    "{} status --state {}",
                    remote_word(campaign),
                    remote_word(state)
                ),
            ],
        }
    }

    /// The command line with each word quoted as a literal POSIX shell
    /// word, or the file path.
    pub fn describe(&self) -> String {
        match self {
            Self::Command { program, args } => std::iter::once(program)
                .chain(args)
                .map(|word| shell_quote(word))
                .collect::<Vec<_>>()
                .join(" "),
            Self::File(path) => path.display().to_string(),
        }
    }

    /// Fetches and parses one snapshot within `limits`.
    ///
    /// # Errors
    ///
    /// A message when the command fails to spawn or to start its output
    /// readers, exits unsuccessfully, runs or holds its output open past
    /// `limits.timeout`, or writes more than `limits.max_bytes`; when the
    /// file fails to open or read within `limits.timeout`, is not a regular
    /// file, or holds more than `limits.max_bytes`; or when the bytes are
    /// not UTF-8 or not a format-1 snapshot.
    pub fn fetch(&self, limits: Limits) -> Result<Snapshot, String> {
        self.fetch_tracked(limits, &InFlight::default())
    }

    /// [`Source::fetch`], with a command's process group stored in
    /// `running` while the command runs.
    ///
    /// # Errors
    ///
    /// As [`Source::fetch`], and a failure when [`InFlight::kill`] stopped
    /// the command.
    pub fn fetch_tracked(&self, limits: Limits, running: &InFlight) -> Result<Snapshot, String> {
        let output = match self {
            Self::Command { program, args } => self.run(program, args, limits, running)?,
            Self::File(path) => read_file_within(path.clone(), limits)?,
        };
        let text =
            String::from_utf8(output).map_err(|_| "status output is not UTF-8".to_owned())?;
        Snapshot::parse(&text)
    }

    /// Runs the command until it exits and both pipes close, or until a
    /// bound stops it. Each pipe has a reader thread that sends exactly one
    /// [`Stream`] message, a panic included, so this thread blocks on the
    /// channel until the next message or the deadline. The command is reaped
    /// only after both pipes close, so its pid still names its process group
    /// when a refusal kills the group and the command before reaping it.
    fn run(
        &self,
        program: &str,
        args: &[String],
        limits: Limits,
        running: &InFlight,
    ) -> Result<Vec<u8>, String> {
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn()
            .map_err(|error| printable(&format!("{program}: {error}")))?;
        if !running.start(&child) {
            stop(child, false, running);
            return Err(printable(&format!("`{}` was stopped", self.describe())));
        }
        let stdout = child.stdout.take().expect("stdout is piped");
        let mut stderr = child.stderr.take().expect("stderr is piped");
        let max = limits.max_bytes;
        let unstarted = |error: std::io::Error, child: Child| {
            stop(child, false, running);
            printable(&format!(
                "{program}: cannot start an output reader: {error}"
            ))
        };
        let (events, received) = mpsc::channel();
        let out_events = events.clone();
        let out = thread::Builder::new().spawn(move || {
            let read = panic::catch_unwind(AssertUnwindSafe(|| {
                let mut kept = Vec::new();
                stdout
                    .take(max.saturating_add(1))
                    .read_to_end(&mut kept)
                    .map(|_| kept)
            }));
            let _ = out_events.send(Stream::Out(read));
        });
        if let Err(error) = out {
            return Err(unstarted(error, child));
        }
        let err = thread::Builder::new().spawn(move || {
            let read = panic::catch_unwind(AssertUnwindSafe(|| {
                let mut kept = Vec::new();
                let _ = (&mut stderr).take(STDERR_KEPT).read_to_end(&mut kept);
                let _ = std::io::copy(&mut stderr, &mut std::io::sink());
                kept
            }));
            let _ = events.send(Stream::Err(read.unwrap_or_default()));
        });
        if let Err(error) = err {
            return Err(unstarted(error, child));
        }
        let deadline = Instant::now().checked_add(limits.timeout);
        let left = || {
            deadline.map_or(Duration::MAX, |deadline| {
                deadline.saturating_duration_since(Instant::now())
            })
        };
        let timed_out = || {
            format!(
                "`{}` ran or held its output open past {:?}; its process group was killed",
                self.describe(),
                limits.timeout
            )
        };
        let mut reaped = false;
        let mut kept = None;
        let mut stderr = None;
        let mut pause = FIRST_PAUSE;
        let finished = loop {
            if left().is_zero() {
                break Err(timed_out());
            }
            if kept.is_some() && stderr.is_some() {
                match running.try_wait(&mut child) {
                    Ok(Some(status)) => {
                        reaped = true;
                        // A finish observed after the deadline is refused,
                        // so the deadline bounds every accepted fetch.
                        if left().is_zero() {
                            break Err(timed_out());
                        }
                        break Ok((status, kept.take().expect("output is kept")));
                    }
                    Ok(None) => {
                        thread::sleep(pause.min(left()));
                        pause = (pause * 2).min(POLL);
                        continue;
                    }
                    Err(error) => break Err(error.to_string()),
                }
            }
            match received.recv_timeout(left()) {
                Ok(Stream::Out(Ok(Ok(output)))) if output.len() as u64 > max => {
                    break Err(oversize(limits));
                }
                Ok(Stream::Out(Ok(Ok(output)))) => kept = Some(output),
                Ok(Stream::Out(Ok(Err(error)))) => break Err(error.to_string()),
                Ok(Stream::Out(Err(_))) => break Err("the output reader panicked".to_owned()),
                Ok(Stream::Err(text)) => stderr = Some(text),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    unreachable!("each reader sends one message before its sender drops")
                }
            }
        };
        let (status, kept) = match finished {
            Ok(finished) => finished,
            Err(error) => {
                stop(child, reaped, running);
                return Err(printable(&error));
            }
        };
        let stderr = stderr.unwrap_or_default();
        if !status.success() {
            return Err(printable(&format!(
                "`{}` exited with {status}: {}",
                self.describe(),
                String::from_utf8_lossy(&stderr)
            )));
        }
        Ok(kept)
    }
}

/// One reader thread's result: the bounded standard output or the reader's
/// panic, or the kept head of standard error.
enum Stream {
    Out(thread::Result<std::io::Result<Vec<u8>>>),
    Err(Vec<u8>),
}

/// Paths whose reader thread is still running. A fetch of such a path
/// fails at once instead of starting a second reader, so a filesystem that
/// stalls holds one thread per path however long the monitor polls it.
static READING: Mutex<BTreeSet<PathBuf>> = Mutex::new(BTreeSet::new());

fn reading() -> MutexGuard<'static, BTreeSet<PathBuf>> {
    READING.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Reads the file on a worker thread and waits for it until
/// `limits.timeout`, so a stalled filesystem costs the caller at most the
/// timeout. A worker past the timeout is left to finish on its own.
fn read_file_within(path: PathBuf, limits: Limits) -> Result<Vec<u8>, String> {
    let target = path.clone();
    read_within(path, limits.timeout, move || read_file(&target, limits))?
}

/// Runs `read` for `path` on a worker thread and waits for it until
/// `timeout`. While an earlier worker for the same path is still running,
/// the read is refused.
fn read_within<T: Send + 'static>(
    path: PathBuf,
    timeout: Duration,
    read: impl FnOnce() -> T + Send + 'static,
) -> Result<T, String> {
    let shown = path.display().to_string();
    if !reading().insert(path.clone()) {
        return Err(printable(&format!(
            "{shown}: an earlier read is still running"
        )));
    }
    let (sender, receiver) = std::sync::mpsc::channel();
    let spawned = thread::Builder::new().spawn({
        let path = path.clone();
        move || {
            let result = read();
            reading().remove(&path);
            let _ = sender.send(result);
        }
    });
    if let Err(error) = spawned {
        reading().remove(&path);
        return Err(printable(&format!(
            "{shown}: cannot start the file reader: {error}"
        )));
    }
    match receiver.recv_timeout(timeout) {
        Ok(read) => Ok(read),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(printable(&format!(
            "{shown}: the read ran past {timeout:?}"
        ))),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            reading().remove(&path);
            Err(printable(&format!("{shown}: the file reader panicked")))
        }
    }
}

/// Reads the regular file at `path` through the byte bound. `O_NONBLOCK`
/// keeps the open of a FIFO from waiting for a writer, and `O_NOCTTY` keeps
/// a terminal from becoming the controlling one, before the file-type
/// check refuses them.
fn read_file(path: &std::path::Path, limits: Limits) -> Result<Vec<u8>, String> {
    let failed = |error: std::io::Error| printable(&format!("{}: {error}", path.display()));
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)
        .map_err(failed)?;
    let metadata = file.metadata().map_err(failed)?;
    if !metadata.is_file() {
        return Err(printable(&format!(
            "{}: not a regular file",
            path.display()
        )));
    }
    let mut kept = Vec::new();
    let hint = metadata.len().min(limits.max_bytes).saturating_add(1);
    let _ = kept.try_reserve(usize::try_from(hint).unwrap_or(0));
    file.take(limits.max_bytes.saturating_add(1))
        .read_to_end(&mut kept)
        .map_err(failed)?;
    if kept.len() as u64 > limits.max_bytes {
        return Err(oversize(limits));
    }
    Ok(kept)
}

/// Kills the command's process group and the command itself, then reaps
/// the command, unless the command is already `reaped`. The command's pid
/// names its group until the reap, so the group signal reaches only the
/// command's group. Uninterruptible kernel I/O can delay process exit
/// after `SIGKILL`; if exit polling reaches [`REAP_WAIT`], `stop`
/// attempts to spawn a reaper thread so the fetch can return. `running` is
/// cleared after the kill and before any reap, so a later
/// [`InFlight::kill`] never signals a reused pid.
fn stop(mut child: Child, reaped: bool, running: &InFlight) {
    if reaped {
        return;
    }
    let mut slot = running.slot();
    if let Ok(group) = libc::pid_t::try_from(child.id()) {
        // SAFETY: `kill` reads no memory; a negative pid names the process
        // group the unreaped command leads.
        unsafe { libc::kill(-group, libc::SIGKILL) };
    }
    let _ = child.kill();
    slot.pid = None;
    drop(slot);
    let deadline = Instant::now() + REAP_WAIT;
    let mut pause = FIRST_PAUSE;
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(None) => {
                thread::sleep(pause);
                pause = (pause * 2).min(POLL);
            }
            Ok(Some(_)) | Err(_) => return,
        }
    }
    let _ = thread::Builder::new().spawn(move || {
        let _ = child.wait();
    });
}

fn oversize(limits: Limits) -> String {
    format!(
        "the snapshot exceeds the {}-byte bound ({})",
        limits.max_bytes,
        bytes(limits.max_bytes)
    )
}

/// `text` trimmed, with each control character other than newline and tab
/// replaced by `?`, so command output, paths and names cannot drive the
/// terminal.
pub(crate) fn printable(text: &str) -> String {
    text.trim()
        .chars()
        .map(|c| {
            if c.is_control() && c != '\n' && c != '\t' {
                '?'
            } else {
                c
            }
        })
        .collect()
}

/// `text` as one literal POSIX shell word: bare when made only of
/// letters, digits and `/._-`, else single-quoted.
pub(crate) fn shell_quote(text: &str) -> String {
    if !text.is_empty()
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"/._-".contains(&byte))
    {
        text.to_owned()
    } else {
        format!("'{}'", text.replace('\'', r"'\''"))
    }
}

/// `text` as one word for a remote POSIX shell. A leading `~/`, or a lone
/// `~`, stays bare so the remote shell expands it to the home directory;
/// the rest is a literal word.
fn remote_word(text: &str) -> String {
    match text.strip_prefix("~/") {
        Some("") => "~/".to_owned(),
        Some(rest) => format!("~/{}", shell_quote(rest)),
        None if text == "~" => text.to_owned(),
        None => shell_quote(text),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reader still running past its timeout is the one thread that path
    /// holds: a second read of the path is refused until the first ends,
    /// and the next read after that runs.
    #[test]
    fn a_read_still_running_past_its_timeout_refuses_a_second_reader_until_it_ends() {
        let path = PathBuf::from("/campaign-monitor-test/stalled-read");
        let (release, held) = mpsc::channel::<()>();
        let timeout = Duration::from_millis(20);
        let first = read_within(path.clone(), timeout, move || held.recv().is_ok());
        assert!(first.unwrap_err().contains("ran past"));
        let second = read_within(path.clone(), timeout, || true);
        assert!(second.unwrap_err().contains("still running"));
        release.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match read_within(path.clone(), timeout, || true) {
                Ok(true) => break,
                Ok(false) => panic!("the released reader returned false"),
                Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
                Err(error) => panic!("{error}"),
            }
        }
    }

    const SNAPSHOT: &str = r#"{"format": 1, "observed_ms": 5, "state": "/s", "config": null, "probes": 0, "held_probes": [], "space": {"free_bytes": 1, "free_inodes": 1}, "jobs": [], "findings": [], "failure_groups": []}"#;

    fn shell(script: &str) -> Source {
        Source::Command {
            program: "sh".into(),
            args: vec!["-c".into(), script.into()],
        }
    }

    fn scratch(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("campaign-monitor-{name}-{}", std::process::id()))
    }

    /// Signal 0 succeeds for zombies as well as running processes.
    fn alive(path: &std::path::Path) -> bool {
        let pid: libc::pid_t = std::fs::read_to_string(path)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let started = Instant::now();
        // SAFETY: `kill` with signal 0 reads no memory and sends nothing.
        while unsafe { libc::kill(pid, 0) } == 0 {
            let state = Command::new("ps")
                .args(["-o", "stat=", "-p", &pid.to_string()])
                .output()
                .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
                .unwrap_or_default();
            if state.starts_with('Z') {
                return false;
            }
            if started.elapsed() > Duration::from_secs(5) {
                return true;
            }
            thread::sleep(Duration::from_millis(20));
        }
        false
    }

    #[test]
    fn ssh_sources_end_options_before_the_host_and_quote_paths_for_the_remote_shell() {
        let Source::Command { args, .. } =
            Source::ssh("-oProxyCommand=x", "/bin/campaign", "/a b/it's")
        else {
            unreachable!("ssh builds a command source");
        };
        assert_eq!(args[2..4], ["--", "-oProxyCommand=x"]);
        assert_eq!(
            args.last().unwrap(),
            r"/bin/campaign status --state '/a b/it'\''s'"
        );
        let Source::Command { args, .. } = Source::ssh("xxl", "A=b", "/s") else {
            unreachable!("ssh builds a command source");
        };
        assert_eq!(args.last().unwrap(), "'A=b' status --state /s");
        let Source::Command { args, .. } = Source::ssh("xxl", "~/my tools/campaign", "~/it's")
        else {
            unreachable!("ssh builds a command source");
        };
        assert_eq!(
            args.last().unwrap(),
            r"~/'my tools/campaign' status --state ~/'it'\''s'"
        );
        let Source::Command { args, .. } = Source::ssh("xxl", "~/bin/campaign", "~") else {
            unreachable!("ssh builds a command source");
        };
        assert_eq!(args.last().unwrap(), "~/bin/campaign status --state ~");
    }

    #[test]
    fn describe_quotes_a_local_tilde_as_the_literal_word_the_command_receives() {
        assert_eq!(
            Source::local("campaign", "~/state").describe(),
            "campaign status --state '~/state'"
        );
    }

    #[test]
    fn a_failing_command_reports_its_exit_and_printable_standard_error() {
        let error = shell("printf 'refused\\033]0;x\\007' >&2; exit 4")
            .fetch(Limits::default())
            .unwrap_err();
        assert!(error.contains("refused?]0;x?"), "{error}");
        let error = Source::local("no-such\u{1b}]0;x", "/s")
            .fetch(Limits::default())
            .unwrap_err();
        assert!(error.starts_with("no-such?]0;x: "), "{error}");
    }

    #[test]
    fn a_snapshot_at_the_byte_bound_is_fetched_from_a_command_and_a_file() {
        let limits = Limits {
            max_bytes: SNAPSHOT.len() as u64,
            timeout: Duration::from_secs(20),
        };
        let fetched = shell(&format!("printf '%s' '{SNAPSHOT}'"))
            .fetch(limits)
            .unwrap();
        assert_eq!(fetched.observed_ms, 5);
        let path = scratch("fit");
        std::fs::write(&path, SNAPSHOT).unwrap();
        let fetched = Source::File(path.clone()).fetch(limits);
        std::fs::remove_file(path).unwrap();
        assert_eq!(fetched.unwrap().observed_ms, 5);
    }

    #[test]
    fn output_past_the_byte_bound_is_refused_and_the_command_killed() {
        let limits = Limits {
            max_bytes: 1025,
            timeout: Duration::from_secs(20),
        };
        let pid = scratch("oversize-pid");
        let started = Instant::now();
        let error = shell(&format!(
            "echo $$ > {}; head -c 4096 /dev/zero; exec sleep 30",
            shell_quote(&pid.display().to_string())
        ))
        .fetch(limits)
        .unwrap_err();
        assert!(
            error.contains("exceeds the 1025-byte bound (1.0 KiB)"),
            "{error}"
        );
        assert!(started.elapsed() < Duration::from_secs(10));
        assert!(!alive(&pid));
        std::fs::remove_file(pid).unwrap();
    }

    #[test]
    fn a_command_past_its_timeout_is_killed() {
        let limits = Limits {
            max_bytes: 1 << 20,
            timeout: Duration::from_secs(2),
        };
        let pid = scratch("timeout-pid");
        let started = Instant::now();
        let error = shell(&format!(
            "echo $$ > {}; exec sleep 30",
            shell_quote(&pid.display().to_string())
        ))
        .fetch(limits)
        .unwrap_err();
        assert!(
            error.contains("held its output open past 2s; its process group was killed"),
            "{error}"
        );
        assert!(started.elapsed() < Duration::from_secs(10));
        assert!(!alive(&pid));
        std::fs::remove_file(pid).unwrap();
    }

    #[test]
    fn a_command_that_closes_its_output_and_keeps_running_is_killed_at_the_timeout() {
        let limits = Limits {
            max_bytes: 1 << 20,
            timeout: Duration::from_secs(2),
        };
        let pid = scratch("closed-pid");
        let started = Instant::now();
        let error = shell(&format!(
            "echo $$ > {}; exec >&- 2>&-; exec sleep 30",
            shell_quote(&pid.display().to_string())
        ))
        .fetch(limits)
        .unwrap_err();
        assert!(error.contains("was killed"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(10));
        assert!(!alive(&pid));
        std::fs::remove_file(pid).unwrap();
    }

    #[test]
    fn a_descendant_holding_the_output_after_the_command_exits_is_killed_at_the_timeout() {
        let limits = Limits {
            max_bytes: 1 << 20,
            timeout: Duration::from_secs(2),
        };
        let pid = scratch("descendant-pid");
        let started = Instant::now();
        let error = shell(&format!(
            "sleep 30 & echo $! > {}; exit 0",
            shell_quote(&pid.display().to_string())
        ))
        .fetch(limits)
        .unwrap_err();
        assert!(
            error.contains("past 2s; its process group was killed"),
            "{error}"
        );
        assert!(started.elapsed() < Duration::from_secs(10));
        assert!(!alive(&pid));
        std::fs::remove_file(pid).unwrap();
    }

    #[test]
    fn unbounded_limits_do_not_overflow() {
        let limits = Limits {
            max_bytes: u64::MAX,
            timeout: Duration::MAX,
        };
        assert_eq!(
            shell(&format!("printf '%s' '{SNAPSHOT}'"))
                .fetch(limits)
                .unwrap()
                .observed_ms,
            5
        );
    }

    #[test]
    fn a_file_larger_than_the_byte_bound_is_refused() {
        let path = scratch("big");
        std::fs::write(&path, vec![b' '; 4096]).unwrap();
        let limits = Limits {
            max_bytes: 1024,
            timeout: Duration::from_secs(1),
        };
        let error = Source::File(path.clone()).fetch(limits).unwrap_err();
        std::fs::remove_file(path).unwrap();
        assert!(error.contains("exceeds the 1024-byte bound"), "{error}");
    }

    #[test]
    fn a_fifo_file_source_is_refused_without_waiting_for_a_writer() {
        let path = scratch("fifo");
        let _ = std::fs::remove_file(&path);
        let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: `name` is a NUL-terminated path that outlives the call.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let started = Instant::now();
        let error = Source::File(path.clone())
            .fetch(Limits::default())
            .unwrap_err();
        std::fs::remove_file(path).unwrap();
        assert!(error.contains("not a regular file"), "{error}");
        let missing = scratch("missing\u{1b}]0;x");
        let error = Source::File(missing).fetch(Limits::default()).unwrap_err();
        assert!(error.contains("missing?]0;x"), "{error}");
        assert!(!error.contains('\u{1b}'), "{error}");
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    /// A quit on another thread stops the fetch's command and every process
    /// in its group, and the fetch then returns.
    #[test]
    fn killing_the_in_flight_command_stops_its_process_group() {
        let pid = scratch("in-flight-pid");
        let _ = std::fs::remove_file(&pid);
        let source = shell(&format!(
            "sleep 30 & echo $! > {}; wait",
            shell_quote(&pid.display().to_string())
        ));
        let running = InFlight::default();
        let fetching = running.clone();
        let started = Instant::now();
        let fetch = thread::spawn(move || {
            source.fetch_tracked(
                Limits {
                    max_bytes: 1 << 20,
                    timeout: Duration::from_secs(60),
                },
                &fetching,
            )
        });
        while std::fs::read_to_string(&pid).map_or(true, |text| text.trim().is_empty()) {
            assert!(started.elapsed() < Duration::from_secs(10), "no pid file");
            thread::sleep(Duration::from_millis(10));
        }
        running.kill();
        let error = fetch.join().unwrap().unwrap_err();
        assert!(error.contains("exited with"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(10));
        assert!(!alive(&pid));
        assert!(
            running.slot().pid.is_none(),
            "a reaped command leaves the slot empty"
        );
        std::fs::remove_file(pid).unwrap();
    }

    #[test]
    fn a_kill_before_the_fetch_starts_stops_the_command_it_starts() {
        let pid = scratch("stopped-pid");
        let _ = std::fs::remove_file(&pid);
        let source = shell(&format!(
            "sleep 30 & echo $! > {}; wait",
            shell_quote(&pid.display().to_string())
        ));
        let running = InFlight::default();
        running.kill();
        let started = Instant::now();
        let limits = Limits {
            max_bytes: 1 << 20,
            timeout: Duration::from_secs(60),
        };
        assert!(source.fetch_tracked(limits, &running).is_err());
        assert!(source.fetch_tracked(limits, &running).is_err());
        assert!(started.elapsed() < Duration::from_secs(10));
        let written = std::fs::read_to_string(&pid).unwrap_or_default();
        if !written.trim().is_empty() {
            assert!(!alive(&pid));
        }
        let _ = std::fs::remove_file(pid);
    }
}
