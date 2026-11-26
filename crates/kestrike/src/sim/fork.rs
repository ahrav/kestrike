//! Forked children of the single-threaded simulation worker, and the parent's
//! judgment of what each child reports.
//!
//! [`eligible`] admits a fork only at a stopped boundary of a process with
//! one thread, whose milestone predicate holds at that boundary and whose
//! recorder has written its prefix to the sink. One thread matters for
//! soundness: a child of a multi-threaded process inherits locks other
//! threads held, such as the allocator's, and may deadlock on its first
//! allocation.
//!
//! [`spawn`] flushes the standard streams, opens the report pipe and forks.
//! The child moves the pipe's write end to descriptor 3, closes every
//! descriptor above it, so it keeps only its standard streams and its
//! report, asks the kernel to kill it when its parent dies, and arms a
//! timer that ends it with `SIGALRM` at its deadline. A child
//! sends one frame through [`Report::send`] and ends through [`exit`],
//! which runs none of the exit handlers or buffered flushes the parent's
//! image carries.
//!
//! A frame is the magic, a verdict byte, the payload's length as `u32`
//! little-endian, the payload, and the SHA-256 of the verdict byte and the
//! payload. [`collect`] reads the child's pipe to end of file under a
//! deadline, then reaps the child. The parent credits a child only as
//! [`Classified::Success`]: one well-formed success frame read to end of
//! file from a child that exited 0. A signal death, a pipe that closes with
//! no frame, malformed or trailing bytes, a verdict that disagrees with the
//! exit status, and a child still running at the deadline are each their
//! own unsuccessful class. A child terminated by its `SIGALRM` timer, or
//! killed with `SIGKILL` and reaped by [`collect`] after the deadline, is
//! [`Classified::Watchdog`].

use std::fs::File;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

/// The frame's leading bytes.
const MAGIC: &[u8; 8] = b"icfork1\n";

/// The descriptor the child's report lives at.
pub(crate) const REPORT_FD: i32 = 3;

/// Payload bytes a frame may carry; a longer stream is malformed.
pub(crate) const MAX_PAYLOAD: usize = 1 << 16;

/// Bytes around a frame's payload: the magic, the verdict, the length and
/// the checksum.
const OVERHEAD: usize = MAGIC.len() + 1 + 4 + 32;

/// The exit code of a child that could not set up its report.
pub(crate) const SETUP_FAILED: i32 = 125;

/// The exit code of a child whose host refused a call its report needs
/// after the fork: listing its descriptors, writing its bundle, or a fork
/// below it. Its parent reads it as incomplete evidence for its suffix.
pub(crate) const HOST_FAILED: i32 = 3;

/// What a child's frame claims.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Verdict {
    Success = 1,
    Failure = 2,
}

/// Why a fork is refused at a boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The run is between the actions of a turn, not at a stopped boundary.
    Unstopped,
    /// The process runs this many threads; a fork needs exactly one.
    Threads(usize),
    /// The milestone's predicate is false at this boundary.
    Predicate,
    /// The recorder holds prefix records its sink has not received, or it
    /// closed and dropped records the run emitted.
    Unflushed,
    /// The host refused a call, or the thread count could not be read.
    Host(String),
}

/// A boundary a fork is asked at, as its caller observed it there. A
/// branch asks only from the controller's stopped-boundary hook, so it
/// always passes `stopped`; the field keeps the refusal explicit for any
/// other caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Boundary {
    pub(crate) stopped: bool,
    /// The milestone's predicate over the facts at this boundary.
    pub(crate) holds: bool,
    /// Whether the recorder is open and the sink received every record of
    /// the prefix.
    pub(crate) flushed: bool,
}

/// Threads of the running process, from `/proc/self/task`.
///
/// # Errors
///
/// The error text when the directory cannot be read or one of its entries
/// cannot be returned, so a count is complete whenever it is returned.
pub(crate) fn threads() -> Result<usize, String> {
    const TASKS: &str = "/proc/self/task";
    let listing = std::fs::read_dir(TASKS).map_err(|error| format!("{TASKS}: {error}"))?;
    let mut count = 0;
    for entry in listing {
        entry.map_err(|error| format!("{TASKS}: {error}"))?;
        count += 1;
    }
    Ok(count)
}

/// Admits a fork at `boundary`, checking in order that it is a stopped
/// boundary, that the process runs one thread, that the predicate holds and
/// that the prefix is flushed.
///
/// # Errors
///
/// The first [`Refusal`] that applies.
pub(crate) fn eligible(boundary: Boundary) -> Result<(), Refusal> {
    if !boundary.stopped {
        return Err(Refusal::Unstopped);
    }
    match threads() {
        Ok(1) => {}
        Ok(count) => return Err(Refusal::Threads(count)),
        Err(error) => return Err(Refusal::Host(error)),
    }
    if !boundary.holds {
        return Err(Refusal::Predicate);
    }
    if !boundary.flushed {
        return Err(Refusal::Unflushed);
    }
    Ok(())
}

/// A frame of `verdict` over `payload`.
pub(crate) fn frame(verdict: Verdict, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(OVERHEAD + payload.len());
    out.extend_from_slice(MAGIC);
    out.push(verdict as u8);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    let mut check = Sha256::new();
    check.update([verdict as u8]);
    check.update(payload);
    out.extend_from_slice(&check.finalize());
    out
}

/// The verdict and payload of `bytes` when they are exactly one
/// well-formed frame, `None` otherwise.
pub(crate) fn unframe(bytes: &[u8]) -> Option<(Verdict, &[u8])> {
    let rest = bytes.strip_prefix(MAGIC)?;
    let (&code, rest) = rest.split_first()?;
    let verdict = [Verdict::Success, Verdict::Failure]
        .into_iter()
        .find(|verdict| *verdict as u8 == code)?;
    let (len, rest) = rest.split_first_chunk::<4>()?;
    let len = u32::from_le_bytes(*len) as usize;
    if len > MAX_PAYLOAD || rest.len() != len + 32 {
        return None;
    }
    let (payload, sum) = rest.split_at(len);
    let mut check = Sha256::new();
    check.update([code]);
    check.update(payload);
    (check.finalize().as_slice() == sum).then_some((verdict, payload))
}

/// A forked child as its parent holds it: the process and the read end of
/// its report pipe.
#[derive(Debug)]
pub(crate) struct Child {
    pid: libc::pid_t,
    report: OwnedFd,
    /// When the parent forked it.
    started: Instant,
}

impl Child {
    pub(crate) fn pid(&self) -> i32 {
        self.pid
    }
}

/// The child's end of its report pipe, at [`REPORT_FD`].
#[derive(Debug)]
pub(crate) struct Report(File);

impl Report {
    /// Writes one frame of `verdict` over `payload`; returns whether the
    /// whole frame reached the pipe.
    pub(crate) fn send(&mut self, verdict: Verdict, payload: &[u8]) -> bool {
        self.write(&frame(verdict, payload))
    }

    /// Writes `bytes` as they are, a frame or not; returns whether they all
    /// reached the pipe.
    pub(crate) fn write(&mut self, bytes: &[u8]) -> bool {
        self.0.write_all(bytes).is_ok()
    }
}

/// Which side of a fork returned.
#[derive(Debug)]
pub(crate) enum Spawned {
    Parent(Child),
    Child(Report),
}

fn last_error(call: &str) -> String {
    format!("{call}: {}", std::io::Error::last_os_error())
}

/// Forks the process with a report pipe between parent and child, once it
/// runs one thread: the child of a process with more than one thread may
/// deadlock. The caller admits the boundary through [`eligible`] first.
///
/// The child returns only once its report sits at [`REPORT_FD`], every
/// other descriptor above the standard three is closed, the kernel kills it
/// if its parent dies, and its real-time timer ends it with `SIGALRM` at
/// `deadline`; a child that cannot arrange that exits [`SETUP_FAILED`].
/// The timer bounds the child while its parent is busy elsewhere, and
/// [`collect`] classifies a `SIGALRM` death as [`Classified::Watchdog`].
///
/// # Safety
///
/// The child closes or replaces descriptors that values it inherited still
/// own, such as files, pipes and the reports of children forked before it.
/// The child must neither use nor drop any such value, and must end through
/// [`exit`] on every path, a panic included.
///
/// # Errors
///
/// The thread count when the process runs more than one thread, the listing
/// error when the threads cannot be counted, a pipe end at a standard
/// stream's descriptor, or the failed call when the pipe or the fork fails;
/// only the parent sees one.
pub(crate) unsafe fn spawn(deadline: Instant) -> Result<Spawned, String> {
    match threads() {
        Ok(1) => {}
        Ok(count) => return Err(format!("a fork needs one thread, not {count}")),
        Err(error) => return Err(error),
    }
    // Buffered output the parent has not written would otherwise be written
    // twice, once by each process.
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
    let mut fds = [0; 2];
    // SAFETY: `fds` holds two descriptors, which `pipe2` writes on success.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(last_error("pipe2"));
    }
    // SAFETY: on success `pipe2` returned two open descriptors that nothing
    // else owns.
    let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    // A pipe end at a closed standard stream's number would stay open in
    // the child as that stream.
    if fds.iter().any(|&fd| fd <= 2) {
        return Err(format!(
            "a pipe end took a standard stream's descriptor: {fds:?}"
        ));
    }
    // SAFETY: `getpid` has no preconditions.
    let parent = unsafe { libc::getpid() };
    // SAFETY: `fork` has no memory preconditions. The process runs one
    // thread, so the child inherits no lock another thread holds.
    match unsafe { libc::fork() } {
        -1 => Err(last_error("fork")),
        0 => {
            // Both ends release their owners: the read end may stand at the
            // report descriptor, which `dup2` replaces.
            let _ = read.into_raw_fd();
            let write = write.into_raw_fd();
            // `dup2` onto the report descriptor closes whatever stood there,
            // the read end included, and `close_range` then closes every
            // descriptor above it, the read and write ends included.
            // SAFETY: `write` is open; `dup2` takes plain integers, touches no
            // memory, and closes any descriptor at `REPORT_FD` first, which the
            // caller's contract lets the child close.
            let moved = write == REPORT_FD || unsafe { libc::dup2(write, REPORT_FD) } == REPORT_FD;
            // SAFETY: `close_range` takes plain integers and touches no
            // memory; the caller's contract lets the child close every
            // inherited descriptor above the report. It needs Linux 5.9.
            let closed = unsafe {
                libc::syscall(
                    libc::SYS_close_range,
                    (REPORT_FD + 1) as libc::c_uint,
                    libc::c_uint::MAX,
                    0 as libc::c_uint,
                )
            } == 0;
            // SAFETY: `prctl` with `PR_SET_PDEATHSIG` takes plain integers;
            // `getppid` has no preconditions. A parent that died before the
            // call leaves the child with another parent, which the check
            // catches.
            let orphan_dies = unsafe {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong) == 0
                    && libc::getppid() == parent
            };
            if !(moved && closed && orphan_dies && expires(deadline)) {
                exit(SETUP_FAILED);
            }
            // SAFETY: `REPORT_FD` is open, holds the pipe's write end and,
            // with every descriptor above it closed, nothing else owns it.
            let report = unsafe { File::from_raw_fd(REPORT_FD) };
            Ok(Spawned::Child(Report(report)))
        }
        pid => {
            drop(write);
            Ok(Spawned::Parent(Child {
                pid,
                report: read,
                started: Instant::now(),
            }))
        }
    }
}

/// Arms the calling process's real-time timer to end it with `SIGALRM` at
/// `deadline`. Restoring `SIG_DFL` and unblocking `SIGALRM` make the timer's
/// signal terminate the process whatever disposition or mask it inherited.
fn expires(deadline: Instant) -> bool {
    // A zero `it_value` disarms the timer, so a deadline already past arms
    // it for one microsecond.
    let left = deadline
        .saturating_duration_since(Instant::now())
        .max(Duration::from_micros(1));
    let timer = libc::itimerval {
        it_interval: libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        },
        it_value: libc::timeval {
            tv_sec: left.as_secs().min(libc::time_t::MAX as u64) as libc::time_t,
            tv_usec: libc::suseconds_t::from(left.subsec_micros()),
        },
    };
    // SAFETY: `alarm` and `timer` stay live during the calls, `sigemptyset`
    // initializes `alarm` before the others read it, and null output
    // pointers discard the previous mask and timer.
    unsafe {
        let mut alarm = std::mem::zeroed::<libc::sigset_t>();
        libc::sigemptyset(&raw mut alarm) == 0
            && libc::sigaddset(&raw mut alarm, libc::SIGALRM) == 0
            && libc::signal(libc::SIGALRM, libc::SIG_DFL) != libc::SIG_ERR
            && libc::sigprocmask(libc::SIG_UNBLOCK, &raw const alarm, std::ptr::null_mut()) == 0
            && libc::setitimer(libc::ITIMER_REAL, &raw const timer, std::ptr::null_mut()) == 0
    }
}

/// Ends the calling process with `code` at once, running none of the exit
/// handlers, buffered flushes or destructors of the parent's image.
pub(crate) fn exit(code: i32) -> ! {
    // SAFETY: `_exit` has no preconditions.
    unsafe { libc::_exit(code) }
}

/// The open descriptors of the calling process, ascending, without the one
/// the listing itself holds.
///
/// # Errors
///
/// The error text when `/proc/self/fd` cannot be listed, an entry cannot be
/// read or its link followed, or an entry's name is not a descriptor number,
/// so the list is complete whenever it is returned.
pub(crate) fn descriptors() -> Result<Vec<i32>, String> {
    let listing = std::fs::read_dir("/proc/self/fd").map_err(|error| error.to_string())?;
    let mut out = Vec::new();
    for entry in listing {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        let target =
            std::fs::read_link(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        let name = entry.file_name();
        let fd: i32 = name
            .to_str()
            .and_then(|name| name.parse().ok())
            .ok_or_else(|| format!("{}: not a descriptor number", path.display()))?;
        let own = target.starts_with("/proc") && target.ends_with("fd");
        if !own {
            out.push(fd);
        }
    }
    out.sort_unstable();
    Ok(out)
}

/// How a child ended, as its parent judges it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Classified {
    /// A success frame, read to end of file, from a child that exited 0:
    /// the frame's payload. The only credited class.
    Success(Vec<u8>),
    /// A failure frame from a child that exited `code`, nonzero.
    Failed { code: i32, payload: Vec<u8> },
    /// A frame whose verdict disagrees with the exit status `code`.
    Mismatch { code: i32, verdict: Verdict },
    /// The child died from this signal.
    Signaled(i32),
    /// The pipe closed with no byte from a child that exited `code`.
    Silent(i32),
    /// Bytes that are not exactly one frame, from a child that exited
    /// `code`.
    Malformed(i32),
    /// The child was still running at its deadline, so its own timer or its
    /// parent killed it.
    Watchdog,
    /// The host failed to read the pipe or reap the child.
    Lost(String),
}

impl Classified {
    pub(crate) fn credited(&self) -> bool {
        matches!(self, Self::Success(_))
    }

    /// The class's name as the worker prints it.
    pub(crate) fn name(&self) -> &'static str {
        match self {
            Self::Success(_) => "success",
            Self::Failed { .. } => "failed",
            Self::Mismatch { .. } => "mismatch",
            Self::Signaled(_) => "signaled",
            Self::Silent(_) => "silent",
            Self::Malformed(_) => "malformed",
            Self::Watchdog => "watchdog",
            Self::Lost(_) => "lost",
        }
    }
}

/// Kills `pid` and reaps it, retrying a wait a signal interrupted.
fn kill(pid: libc::pid_t) {
    // SAFETY: `kill` takes plain integers.
    unsafe { libc::kill(pid, libc::SIGKILL) };
    let mut status = 0;
    // SAFETY: `waitpid` writes the status into a live local.
    while unsafe { libc::waitpid(pid, &raw mut status, 0) } < 0
        && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
    {}
}

/// Polling interval while a child that closed its pipe has not exited.
const REAP_POLL: Duration = Duration::from_millis(5);

/// Reads `child`'s report to end of file and reaps it, killing it once
/// `deadline` passes, and classifies how it ended, as [`collect_all`] does
/// for one child.
pub(crate) fn collect(child: Child, deadline: Instant) -> Classified {
    collect_all(vec![child], deadline)
        .pop()
        .map_or(Classified::Lost("no child".into()), |(class, _)| class)
}

/// What a reaped child cost. `wall` runs from the fork to the parent seeing
/// the child's pipe close. `cpu` and `max_rss_kib` are the kernel's
/// accounting for the child and every descendant it reaped, so an interior
/// node of a tree counts its subtree, and the resident high water includes
/// the pages resident at the fork. A child its parent killed, at the
/// deadline or after a failed read or reap, reports zero for each; a child
/// its own timer ended is reaped and reports what it cost, and its class
/// records how it ended.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Usage {
    pub(crate) wall: Duration,
    pub(crate) cpu: Duration,
    pub(crate) max_rss_kib: i64,
}

/// One child's pipe as the parent reads it.
#[derive(Debug)]
struct Pipe {
    child: Child,
    bytes: Vec<u8>,
    over: bool,
    /// When the parent saw the pipe close.
    closed: Option<Instant>,
    ended: Option<(Classified, Usage)>,
}

impl Pipe {
    /// Kills and reaps the child and ends it with `class` at no cost.
    fn end(&mut self, class: Classified) {
        kill(self.child.pid);
        self.ended = Some((class, Usage::default()));
    }
}

/// Reads every child's report concurrently to end of file and reaps each,
/// and reports how each ended and what it cost, in the given order. A
/// child whose pipe is open, or which has not exited, once `deadline`
/// passes is killed, reaped and classified by the watchdog. Past the
/// deadline a pipe is read only for the bytes it already holds, up to the
/// frame bound, so a child that finished before the parent looked keeps
/// its report and a child that still writes is killed.
pub(crate) fn collect_all(children: Vec<Child>, deadline: Instant) -> Vec<(Classified, Usage)> {
    let mut pipes: Vec<Pipe> = children
        .into_iter()
        .map(|child| Pipe {
            child,
            bytes: Vec::new(),
            over: false,
            closed: None,
            ended: None,
        })
        .collect();
    let mut buffer = [0u8; 4096];
    loop {
        let open: Vec<usize> = (0..pipes.len())
            .filter(|&at| pipes[at].closed.is_none() && pipes[at].ended.is_none())
            .collect();
        if open.is_empty() {
            break;
        }
        let left = deadline.saturating_duration_since(Instant::now());
        let late = left.is_zero();
        let mut polls: Vec<libc::pollfd> = open
            .iter()
            .map(|&at| libc::pollfd {
                fd: pipes[at].child.report.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        let millis = if late {
            0
        } else {
            left.as_millis().clamp(1, i32::MAX as u128) as i32
        };
        // SAFETY: `poll` reads and writes the live `pollfd`s it is given.
        let ready = unsafe { libc::poll(polls.as_mut_ptr(), polls.len() as libc::nfds_t, millis) };
        if ready < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            let lost = last_error("poll");
            for &at in &open {
                pipes[at].end(Classified::Lost(lost.clone()));
            }
            break;
        }
        for (poll, &at) in polls.iter().zip(&open) {
            let pipe = &mut pipes[at];
            if poll.revents == 0 {
                if late {
                    pipe.end(Classified::Watchdog);
                }
                continue;
            }
            // SAFETY: `buffer` is a live local of the length passed.
            let read = unsafe { libc::read(poll.fd, buffer.as_mut_ptr().cast(), buffer.len()) };
            match read {
                0 => pipe.closed = Some(Instant::now()),
                n if n > 0 => {
                    let n = n as usize;
                    if pipe.bytes.len() + n <= MAX_PAYLOAD + OVERHEAD {
                        pipe.bytes.extend_from_slice(&buffer[..n]);
                    } else {
                        pipe.over = true;
                    }
                }
                _ if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted => {}
                _ => pipe.end(Classified::Lost(last_error("read"))),
            }
            if late && pipe.over && pipe.closed.is_none() {
                pipe.end(Classified::Watchdog);
            }
        }
    }
    loop {
        let mut waiting = false;
        for pipe in pipes.iter_mut().filter(|pipe| pipe.ended.is_none()) {
            reap(pipe, deadline);
            waiting |= pipe.ended.is_none();
        }
        if !waiting {
            break;
        }
        std::thread::sleep(REAP_POLL);
    }
    pipes
        .into_iter()
        .map(|pipe| pipe.ended.expect("every child ended"))
        .collect()
}

/// Reaps `pipe`'s child once without waiting and ends it with its class
/// and cost, or kills it as hung once `deadline` passes.
fn reap(pipe: &mut Pipe, deadline: Instant) {
    let mut status = 0;
    // SAFETY: an all-zero `rusage` is a valid value of the plain C struct.
    let mut rusage: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: `wait4` writes the status and the usage into live locals.
    let reaped = unsafe {
        libc::wait4(
            pipe.child.pid,
            &raw mut status,
            libc::WNOHANG,
            &raw mut rusage,
        )
    };
    match reaped {
        0 if Instant::now() >= deadline => pipe.end(Classified::Watchdog),
        0 => {}
        reaped if reaped == pipe.child.pid => {
            let time = |value: libc::timeval| {
                Duration::from_secs(value.tv_sec as u64)
                    + Duration::from_micros(value.tv_usec as u64)
            };
            let closed = pipe.closed.unwrap_or_else(Instant::now);
            let usage = Usage {
                wall: closed.saturating_duration_since(pipe.child.started),
                cpu: time(rusage.ru_utime) + time(rusage.ru_stime),
                max_rss_kib: rusage.ru_maxrss,
            };
            pipe.ended = Some((classify(status, &pipe.bytes, pipe.over), usage));
        }
        _ if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted => {}
        _ => pipe.end(Classified::Lost(last_error("wait4"))),
    }
}

/// The class of a reaped child that exited with wait status `status` after
/// writing `bytes`, `over` when it wrote past the frame bound.
fn classify(status: i32, bytes: &[u8], over: bool) -> Classified {
    if libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGALRM {
        return Classified::Watchdog;
    }
    if libc::WIFSIGNALED(status) {
        return Classified::Signaled(libc::WTERMSIG(status));
    }
    let code = libc::WEXITSTATUS(status);
    if bytes.is_empty() {
        return Classified::Silent(code);
    }
    match (over, unframe(bytes)) {
        (false, Some((Verdict::Success, payload))) if code == 0 => {
            Classified::Success(payload.to_vec())
        }
        (false, Some((Verdict::Failure, payload))) if code != 0 => Classified::Failed {
            code,
            payload: payload.to_vec(),
        },
        (false, Some((verdict, _))) => Classified::Mismatch { code, verdict },
        _ => Classified::Malformed(code),
    }
}
