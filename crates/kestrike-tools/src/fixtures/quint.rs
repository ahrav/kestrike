//! [`run`] starts one `quint run` and waits for it under a time limit and the interrupt rule.
//!
//! The interrupt rule: after [`handle_interrupts`], a SIGINT outside [`run`] ends the process by SIGINT at
//! once. A SIGINT while [`run`] waits gives the child 250 ms to exit, then sends it SIGKILL, reaps it and
//! ends the process by SIGINT, so no child outlives an interrupted writer.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

pub const LIMIT: Duration = Duration::from_secs(120);

const POLL: Duration = Duration::from_millis(50);

/// How long an interrupted child has to exit before it is sent SIGKILL.
const GRACE: Duration = Duration::from_millis(250);

/// The search path used when `PATH` is unset.
const DEFAULT_PATH: &[u8] = b"/bin:/usr/bin";

static INTERRUPTED: AtomicBool = AtomicBool::new(false);
static WAITING: AtomicBool = AtomicBool::new(false);

#[derive(Debug)]
pub enum Failure {
    /// No candidate program could be started; the error is the first one other than a missing file or
    /// directory, else the last one.
    Start(io::Error),
    /// Waiting for the child failed with an error other than `ECHILD`.
    Wait(io::Error),
    /// The child exited with a status other than success.
    Exit(ExitStatus),
    /// The limit passed and the child was sent SIGKILL. `status` records the status the reap returned,
    /// including a natural exit between the last poll and the signal.
    Limit {
        limit: Duration,
        status: Option<ExitStatus>,
    },
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Start(error) => write!(f, "Quint did not start: {error}"),
            Self::Wait(error) => write!(f, "waiting for Quint failed: {error}"),
            Self::Exit(status) => write!(f, "Quint ended with {status}"),
            Self::Limit { limit, .. } => write!(
                f,
                "Quint ran past {} seconds and was sent SIGKILL",
                limit.as_secs_f64()
            ),
        }
    }
}

extern "C" fn on_interrupt(_: libc::c_int) {
    INTERRUPTED.store(true, Ordering::SeqCst);
    if !WAITING.load(Ordering::SeqCst) {
        die_by_interrupt();
    }
}

/// `die_by_interrupt` restores SIGINT's default disposition and raises it, so the process ends with the
/// status of a process killed by SIGINT. It calls only async-signal-safe functions.
fn die_by_interrupt() -> ! {
    // SAFETY: `signal` with `SIG_DFL` and `raise` are async-signal-safe and take no pointers.
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_DFL);
        libc::raise(libc::SIGINT);
    }
    std::process::abort()
}

/// `handle_interrupts` installs the interrupt rule of this module for SIGINT, and keeps SIGINT ignored when
/// the process started with it ignored. Call it once, before the first [`run`].
pub fn handle_interrupts() {
    let handler = on_interrupt as extern "C" fn(libc::c_int) as libc::sighandler_t;
    // SAFETY: `on_interrupt` stores to atomics and calls `die_by_interrupt`, which is async-signal-safe;
    // `signal` takes no pointers.
    unsafe {
        if libc::signal(libc::SIGINT, handler) == libc::SIG_IGN {
            libc::signal(libc::SIGINT, libc::SIG_IGN);
        }
    }
}

/// `candidates` lists the files `program` names: `program` itself when it contains a `/`, else `program`
/// in each directory of `PATH`, or of `/bin:/usr/bin` when `PATH` is unset, in order. An empty entry
/// names `program` in the child's working directory.
fn candidates(program: &OsStr) -> Vec<PathBuf> {
    if program.as_bytes().contains(&b'/') {
        return vec![PathBuf::from(program)];
    }
    let path = std::env::var_os("PATH");
    let path = path.as_ref().map_or(DEFAULT_PATH, |path| path.as_bytes());
    path.split(|&byte| byte == b':')
        .map(|directory| Path::new(OsStr::from_bytes(directory)).join(program))
        .collect()
}

/// `start` tries each candidate in order with `program` as `argv[0]` and returns the first child that
/// starts. The child runs in `directory`, so a relative candidate names a file there, with standard output
/// discarded and every descriptor above 2 closed at exec.
fn start(program: &OsStr, args: &[OsString], directory: &Path) -> Result<Child, Failure> {
    let mut first = None;
    let mut last = None;
    for candidate in candidates(program) {
        let mut command = Command::new(&candidate);
        command
            .arg0(program)
            .args(args)
            .current_dir(directory)
            .stdout(Stdio::null());
        #[cfg(target_os = "linux")]
        // SAFETY: the closure makes one `close_range` system call, which is async-signal-safe, and reads
        // `errno`; it allocates nothing and takes no lock. `CLOSE_RANGE_CLOEXEC` marks the descriptors
        // and leaves the standard library's exec-error pipe open until exec.
        unsafe {
            command.pre_exec(|| {
                let flags = libc::c_long::from(libc::CLOSE_RANGE_CLOEXEC);
                if libc::syscall(libc::SYS_close_range, 3, libc::c_uint::MAX, flags) == 0 {
                    Ok(())
                } else {
                    Err(io::Error::last_os_error())
                }
            });
        }
        match command.spawn() {
            Ok(child) => return Ok(child),
            Err(error) => {
                let missing = matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                );
                if !missing && first.is_none() {
                    first = Some(error);
                } else {
                    last = Some(error);
                }
            }
        }
    }
    Err(Failure::Start(first.or(last).unwrap_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "no candidate program")
    })))
}

/// `run` starts `program` in `directory` and waits for it. The monotonic timer starts once the child has
/// started; when `limit` passes, the child is sent SIGKILL with no SIGTERM first and reaped. A wait that
/// fails with `ECHILD`, as it does when SIGCHLD is ignored and the child was reaped by the kernel, counts
/// as a successful exit.
///
/// # Errors
///
/// `run` returns a [`Failure`] when the child does not start, the wait fails, the child exits with a
/// status other than success, or the limit passes.
pub fn run(
    program: &OsStr,
    args: &[OsString],
    directory: &Path,
    limit: Duration,
) -> Result<(), Failure> {
    WAITING.store(true, Ordering::SeqCst);
    let outcome = start(program, args, directory).and_then(|child| wait(child, limit));
    WAITING.store(false, Ordering::SeqCst);
    if INTERRUPTED.load(Ordering::SeqCst) {
        die_by_interrupt();
    }
    outcome
}

fn wait(mut child: Child, limit: Duration) -> Result<(), Failure> {
    let start = Instant::now();
    let mut pause = Duration::from_micros(500);
    loop {
        if INTERRUPTED.load(Ordering::SeqCst) {
            let grace = Instant::now();
            while matches!(child.try_wait(), Ok(None)) && grace.elapsed() < GRACE {
                thread::sleep(Duration::from_millis(5));
            }
            let _ = child.kill();
            let _ = child.wait();
            return Ok(());
        }
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(status)) => return Err(Failure::Exit(status)),
            Ok(None) => {}
            Err(error) if error.raw_os_error() == Some(libc::ECHILD) => return Ok(()),
            Err(error) => return Err(Failure::Wait(error)),
        }
        let elapsed = start.elapsed();
        if elapsed >= limit {
            let _ = child.kill();
            let status = child.wait().ok();
            return Err(Failure::Limit { limit, status });
        }
        pause = (pause * 2).min(limit - elapsed).min(POLL);
        thread::sleep(pause);
    }
}
