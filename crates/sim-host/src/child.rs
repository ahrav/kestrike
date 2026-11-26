//! The long-lived children the runner watches: `campaign sweep` and
//! `campaign confirm`. Each writes its output to files under `logs/`, gets
//! a death signal when the thread that started it ends, and is stopped by
//! SIGTERM and then reaped by the runner.

use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const TAIL: u64 = 64 << 10;

pub struct Child {
    process: std::process::Child,
    out: PathBuf,
    err: PathBuf,
    terminated: bool,
    exit: Option<i32>,
}

/// Arms `command` so its child gets the signal `death` when the thread
/// that started it ends. SIGTERM returns to its default disposition
/// before the death signal is armed, so a SIGTERM that arrives before exec
/// ends the child.
pub fn die_with_parent(command: &mut Command, death: libc::c_int) {
    let parent = std::process::id();
    // SAFETY: between fork and exec the hook calls `signal`, `prctl` and
    // `getppid` and builds errors from raw codes, all async-signal-safe.
    unsafe {
        command.pre_exec(move || {
            if libc::signal(libc::SIGTERM, libc::SIG_DFL) == libc::SIG_ERR {
                return Err(io::Error::last_os_error());
            }
            let death = libc::c_ulong::try_from(death).unwrap_or_default();
            if libc::prctl(libc::PR_SET_PDEATHSIG, death, 0 as libc::c_ulong) != 0 {
                return Err(io::Error::last_os_error());
            }
            // The parent may have died before the death signal was armed.
            if libc::getppid().cast_unsigned() != parent {
                return Err(io::Error::from_raw_os_error(libc::ESRCH));
            }
            Ok(())
        });
    }
}

/// Starts `program` with `args`, its output in `logs/<name>.out` and
/// `logs/<name>.err`.
///
/// # Errors
///
/// A log file that cannot be created or a failed spawn; nothing runs.
pub fn spawn(name: &str, program: &Path, args: &[String], logs: &Path) -> io::Result<Child> {
    let out = logs.join(format!("{name}.out"));
    let err = logs.join(format!("{name}.err"));
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(crate::file::create_fresh(&out)?)
        .stderr(crate::file::create_fresh(&err)?);
    die_with_parent(&mut command, libc::SIGTERM);
    let process = command.spawn()?;
    Ok(Child {
        process,
        out,
        err,
        terminated: false,
        exit: None,
    })
}

impl Child {
    /// The exit code, 128 plus the signal for a signalled child, or `None`
    /// while it runs.
    pub fn try_exit(&mut self) -> io::Result<Option<i32>> {
        if self.exit.is_none() {
            self.exit = self.process.try_wait()?.map(|status| {
                status
                    .code()
                    .unwrap_or_else(|| 128 + status.signal().unwrap_or(0))
            });
        }
        Ok(self.exit)
    }

    pub fn terminate(&mut self) {
        if self.terminated || !matches!(self.try_exit(), Ok(None)) {
            return;
        }
        self.terminated = true;
        if let Ok(pid) = libc::pid_t::try_from(self.process.id()) {
            // SAFETY: `exit` is `None`, so `try_wait` has not reaped the
            // child, and SIGCHLD has its default disposition, so the
            // kernel has not reaped it either: `pid` still names it.
            unsafe { libc::kill(pid, libc::SIGTERM) };
        }
    }

    /// Sends SIGTERM and waits until the child exits. The wait lasts as
    /// long as the child takes to stop: a sweep stops after each worker's
    /// current run, within the sweep's wall limit.
    pub fn stop(&mut self) -> Option<i32> {
        self.terminate();
        loop {
            match self.try_exit() {
                Ok(Some(code)) => return Some(code),
                Ok(None) => std::thread::sleep(std::time::Duration::from_millis(100)),
                Err(_) => return None,
            }
        }
    }

    /// Whether [`Child::terminate`] signalled the child.
    pub fn terminated(&self) -> bool {
        self.terminated
    }

    pub fn stdout_path(&self) -> &Path {
        &self.out
    }

    /// The last 64 KiB of the child's standard error. `None` when
    /// `open_regular` returns `Err` or `Ok(None)`, or when the metadata
    /// lookup, the seek or the read fails.
    pub fn stderr(&self) -> Option<String> {
        tail(&self.err)
    }

    /// The last non-blank line of standard error, at most 512 characters.
    pub fn reason(&self) -> String {
        let text = self.stderr().unwrap_or_default();
        let line = text
            .lines()
            .rev()
            .find(|line| !line.trim().is_empty())
            .unwrap_or("");
        line.chars().take(512).collect()
    }
}

fn tail(path: &Path) -> Option<String> {
    let mut file = crate::file::open_regular(path).ok()??;
    let length = file.metadata().ok()?.len();
    file.seek(SeekFrom::Start(length.saturating_sub(TAIL)))
        .ok()?;
    let mut bytes = Vec::new();
    file.take(TAIL).read_to_end(&mut bytes).ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}
