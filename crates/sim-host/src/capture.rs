//! Short-lived helper children whose output the caller reads: `aws`, `tar`,
//! `git`, `cargo` and the `campaign` commands that report or check. Each
//! child runs in its own process group with both pipes drained on threads
//! and capped, and ends by a deadline: at the deadline, or when the
//! caller's [`Halt`] fires, the whole group gets SIGKILL and is reaped
//! before the call returns. A leader that exits on its own gets 5 seconds
//! more for its pipes to close, and then its group gets SIGKILL too, so a
//! descendant left in the group ends when the call returns. A process that
//! called `setsid` or `setpgid` has left the group and keeps running. A
//! child also gets SIGKILL when the thread that started it ends, so no
//! helper outlives its runner.
//!
//! The exit poll and the group kill rely on the unreaped leader keeping
//! its pid and group id reserved. That holds while SIGCHLD has its default
//! disposition without `SA_NOCLDWAIT` until the child is reaped, and while
//! no other code reaps the child. [`crate::signal::install`] restores that
//! disposition; every entry point calls it before its first helper, and
//! [`run`] relies on that without checking it.

use std::io::Read;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const POLL: Duration = Duration::from_millis(20);
const DRAIN: Duration = Duration::from_secs(5);

/// When a helper's caller gives up on it besides its deadline.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Halt {
    /// When the process received SIGTERM or SIGINT.
    OnStop,
    /// At this instant, also during a stop.
    At(Instant),
}

impl Halt {
    pub fn halted(self) -> bool {
        match self {
            Self::OnStop => crate::signal::stopping(),
            Self::At(at) => Instant::now() >= at,
        }
    }
}

/// A helper that exited on its own.
#[derive(Debug)]
pub struct Output {
    /// The exit code, or 128 plus the signal for a signalled child.
    pub code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl Output {
    pub fn success(&self) -> bool {
        self.code == 0
    }

    /// The last non-blank line of standard error, at most 512 characters.
    pub fn reason(&self) -> String {
        let text = String::from_utf8_lossy(&self.stderr);
        let line = text
            .lines()
            .rev()
            .find(|line| !line.trim().is_empty())
            .unwrap_or("");
        line.chars().take(512).collect()
    }
}

fn reader(mut pipe: impl Read + Send + 'static, bound: u64) -> mpsc::Receiver<Vec<u8>> {
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = (&mut pipe)
            .take(bound.saturating_add(1))
            .read_to_end(&mut bytes);
        // The pipe stays drained past the bound, so the child never blocks
        // on a full pipe; the extra bytes are dropped.
        let _ = std::io::copy(&mut pipe, &mut std::io::sink());
        let _ = sender.send(bytes);
    });
    receiver
}

fn kill_group(pid: u32) {
    if let Ok(pid) = libc::pid_t::try_from(pid) {
        // SAFETY: `kill` with a negative pid signals the process group the
        // child leads. Every caller runs before `wait` reaps the child, and
        // SIGCHLD keeps its default disposition without `SA_NOCLDWAIT`, so
        // the kernel has not reaped it either: the unreaped leader keeps
        // the group id reserved.
        unsafe { libc::kill(-pid, libc::SIGKILL) };
    }
}

fn exited(pid: u32) -> std::io::Result<bool> {
    let id = libc::id_t::try_from(pid).map_err(std::io::Error::other)?;
    // SAFETY: an all-zero `siginfo_t` is a valid value for the call to
    // fill.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: `info` is valid for writes, and `WNOWAIT` leaves the child
    // waitable, so its pid stays reserved for the later `wait` while
    // SIGCHLD keeps its default disposition without `SA_NOCLDWAIT`.
    let waited = unsafe {
        libc::waitid(
            libc::P_PID,
            id,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if waited != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `waitid` returned 0 and filled `info` for a `P_PID` wait.
    Ok(unsafe { info.si_pid() } != 0)
}

/// Runs `command` to its exit, at most `wait`, reading at most `bound`
/// bytes of each output stream.
///
/// # Errors
///
/// A failed spawn or wait, a child that outlives `wait` or meets `halt`,
/// output pipes that stay open 5 seconds after the child exits, or a
/// stream longer than `bound`. The 5 seconds start when the child exits
/// and run past `wait` and `halt`. The message names `name`.
pub fn run(
    name: &str,
    command: &mut Command,
    wait: Duration,
    bound: u64,
    halt: Halt,
) -> Result<Output, String> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    crate::child::die_with_parent(command, libc::SIGKILL);
    let mut child = command
        .spawn()
        .map_err(|error| format!("{name} did not start: {error}"))?;
    let pid = child.id();
    let out = reader(child.stdout.take().expect("stdout is piped"), bound);
    let err = reader(child.stderr.take().expect("stderr is piped"), bound);
    let deadline = Instant::now().checked_add(wait);
    let ended = loop {
        match exited(pid) {
            Ok(true) => break Ok(()),
            Ok(false) if halt.halted() => {
                break Err(match halt {
                    Halt::OnStop => format!("{name} stopped at a stop request"),
                    Halt::At(_) => format!("{name} reached its time limit"),
                });
            }
            Ok(false) if deadline.is_some_and(|deadline| Instant::now() >= deadline) => {
                break Err(format!("{name} outlived {} seconds", wait.as_secs()));
            }
            Ok(false) => std::thread::sleep(POLL),
            Err(error) => break Err(format!("waiting for {name}: {error}")),
        }
    };
    if let Err(error) = ended {
        kill_group(pid);
        let _ = child.wait();
        return Err(error);
    }
    let drained = Instant::now() + DRAIN;
    let mut streams = Vec::new();
    for receiver in [out, err] {
        let left = drained.saturating_duration_since(Instant::now());
        match receiver.recv_timeout(left) {
            Ok(bytes) => streams.push(bytes),
            Err(_) => {
                kill_group(pid);
                let _ = child.wait();
                return Err(format!("{name} left a process holding its output"));
            }
        }
    }
    kill_group(pid);
    let status = child
        .wait()
        .map_err(|error| format!("waiting for {name}: {error}"))?;
    let code = status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0));
    let stderr = streams.pop().unwrap_or_default();
    let stdout = streams.pop().unwrap_or_default();
    for (stream, bytes) in [("output", &stdout), ("error output", &stderr)] {
        if bytes.len() as u64 > bound {
            return Err(format!(
                "{name} printed more than {bound} bytes of {stream}"
            ));
        }
    }
    Ok(Output {
        code,
        stdout,
        stderr,
    })
}

#[cfg(test)]
mod tests {
    use std::process::Command;
    use std::time::{Duration, Instant};

    use super::{Halt, run};

    fn shell(script: &str) -> Command {
        let mut command = Command::new("sh");
        command.args(["-c", script]);
        command
    }

    #[test]
    fn a_child_ends_by_its_deadline_its_halt_or_its_output_bound() {
        let output = run(
            "sh",
            &mut shell("echo out; echo err >&2; exit 3"),
            Duration::from_secs(10),
            64,
            Halt::OnStop,
        )
        .expect("it runs");
        assert_eq!(output.code, 3);
        assert_eq!(output.stdout, b"out\n");
        assert_eq!(output.reason(), "err");
        let marker = std::env::temp_dir()
            .canonicalize()
            .expect("the temporary directory")
            .join(format!("sim-host-capture-{}", std::process::id()));
        let _ = std::fs::remove_file(&marker);
        let started = Instant::now();
        let late = run(
            "sh",
            &mut shell(&format!("(sleep 1; touch {}) & sleep 30", marker.display())),
            Duration::from_millis(200),
            64,
            Halt::OnStop,
        )
        .expect_err("a late child");
        assert!(late.contains("outlived"), "{late}");
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the leader was killed"
        );
        std::thread::sleep(Duration::from_secs(2));
        assert!(!marker.exists(), "the whole group was killed");
        let halted = run(
            "sh",
            &mut shell("sleep 30"),
            Duration::from_secs(30),
            64,
            Halt::At(Instant::now()),
        )
        .expect_err("a halted child");
        assert!(halted.contains("time limit"), "{halted}");
        let held = run(
            "sh",
            &mut shell(&format!("(sleep 7; touch {}) & exit 0", marker.display())),
            Duration::from_secs(30),
            64,
            Halt::OnStop,
        )
        .expect_err("a child whose descendant holds its output");
        assert!(held.contains("holding its output"), "{held}");
        std::thread::sleep(Duration::from_secs(3));
        assert!(!marker.exists(), "the holder was killed");
        let detached = run(
            "sh",
            &mut shell(&format!(
                "(sleep 1; touch {}) >/dev/null 2>&1 & exit 0",
                marker.display()
            )),
            Duration::from_secs(30),
            64,
            Halt::OnStop,
        )
        .expect("a leader that exits with its descendant's output redirected");
        assert_eq!(detached.code, 0);
        std::thread::sleep(Duration::from_secs(2));
        assert!(
            !marker.exists(),
            "the descendant left in the group was killed"
        );
        let loud = run(
            "sh",
            &mut shell("head -c 200000 /dev/zero >&2; echo {}"),
            Duration::from_secs(10),
            1024,
            Halt::OnStop,
        )
        .expect_err("a child past its bound");
        assert!(
            loud.contains("more than 1024 bytes of error output"),
            "{loud}"
        );
    }
}
