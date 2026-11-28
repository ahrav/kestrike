//! Signals and child processes that two tools share: the record of the first handled signal and its
//! handlers, the refusal of a run with SIGCHLD ignored, the reading of a child's exit, the wait for a
//! child that sees a recorded signal, the captured child, and the stop of a process group that a child
//! leads.
//!
//! The handlers of SIGINT, SIGTERM and SIGHUP record the first of them in [`INTERRUPT`]; a later signal
//! changes nothing. A tool reads the record between its steps and while it waits for a child, so a signal
//! that arrives while a child is being started is acted on once that child has started. A wait polls the
//! child and the record at pauses that start at 0.5 ms and double up to a cap, 20 ms unless the caller
//! names another, on the monotonic clock.
//!
//! A group's stop reads its leader's state from `/proc/<pid>/stat` and reaps the leader only after its
//! last signal, so while the stop signals the group the leader's id names that group alone.

use std::fs;
use std::io::{self, Read};
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub const SIGNALS: [i32; 3] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP];
/// The wait for a captured child after SIGKILL.
pub(crate) const GRACE: Duration = Duration::from_secs(10);
/// The longest pause between two checks of a child and of the record while a tool waits; the pause
/// starts at [`FIRST_PAUSE`] and doubles up to this bound.
pub(crate) const POLL: Duration = Duration::from_millis(20);
const FIRST_PAUSE: Duration = Duration::from_micros(500);

/// The first handled signal, or 0 while none has arrived.
#[derive(Debug, Default)]
pub struct Interrupt(AtomicI32);

/// The handlers [`install_handlers`] installs record into this value.
pub static INTERRUPT: Interrupt = Interrupt::new();

/// A recorded signal that ended a step: the signal's number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Interrupted(pub i32);

impl Interrupt {
    pub const fn new() -> Self {
        Self(AtomicI32::new(0))
    }

    /// `record` keeps `signal` unless a signal is already recorded. It makes no allocation and takes no
    /// lock, so a signal handler may call it.
    pub fn record(&self, signal: i32) {
        let _ = self
            .0
            .compare_exchange(0, signal, Ordering::SeqCst, Ordering::SeqCst);
    }

    pub fn recorded(&self) -> Option<i32> {
        Some(self.0.load(Ordering::SeqCst)).filter(|&signal| signal != 0)
    }

    /// `check` is the interruption of a recorded signal.
    ///
    /// # Errors
    ///
    /// A signal is recorded.
    pub fn check(&self) -> Result<(), Interrupted> {
        self.recorded()
            .map_or(Ok(()), |signal| Err(Interrupted(signal)))
    }
}

/// `ignored` holds when the signal's disposition is to ignore it.
fn ignored(signal: i32) -> io::Result<bool> {
    // SAFETY: `sigaction` is a plain C struct for which all-zero bytes are a valid value. A null new
    // action makes `sigaction` only write the current disposition into `current`, which outlives the call.
    let (status, current) = unsafe {
        let mut current: libc::sigaction = std::mem::zeroed();
        let status = libc::sigaction(signal, std::ptr::null(), &mut current);
        (status, current)
    };
    if status != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(current.sa_sigaction == libc::SIG_IGN)
}

/// `handled_set` is the signal set that holds each of [`SIGNALS`].
pub(crate) fn handled_set() -> libc::sigset_t {
    // SAFETY: `sigemptyset` initializes the set that `set` points to, and `sigaddset` adds a valid signal
    // number to that initialized set; neither can fail on these arguments.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for signal in SIGNALS {
            libc::sigaddset(&mut set, signal);
        }
        set
    }
}

/// `install_handlers` makes each of [`SIGNALS`] that is not ignored record into [`INTERRUPT`], then
/// unblocks the three in the calling thread, so a run started with one of them blocked still receives it
/// and the threads and children started from that thread start with none of the three blocked. A signal
/// ignored at the start stays ignored, so a run under `nohup` outlives its terminal.
///
/// After blocking [`SIGNALS`], the calling thread attempts to unblock them whether registration
/// succeeds or fails.
///
/// # Errors
///
/// Reading a disposition, installing a handler or changing the signal mask fails.
pub fn install_handlers() -> io::Result<()> {
    let handled = handled_set();
    mask(libc::SIG_BLOCK, &handled)?;
    let installed = SIGNALS.into_iter().try_for_each(|signal| {
        if ignored(signal)? {
            return Ok(());
        }
        // SAFETY: the action only calls `Interrupt::record`, one atomic compare-exchange on a static,
        // which is async-signal-safe.
        unsafe { signal_hook::low_level::register(signal, move || INTERRUPT.record(signal)) }
            .map(drop)
    });
    let unblocked = mask(libc::SIG_UNBLOCK, &handled);
    installed.and(unblocked)
}

fn mask(how: libc::c_int, set: &libc::sigset_t) -> io::Result<()> {
    // SAFETY: `set` is an initialized signal set that outlives the call, and a null old set makes
    // `pthread_sigmask` write nothing back.
    let status = unsafe { libc::pthread_sigmask(how, set, std::ptr::null_mut()) };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status));
    }
    Ok(())
}

/// `child_defaults` resets caught signals in [`SIGNALS`] to `SIG_DFL` and unblocks the signals in
/// `handled`; it calls only async-signal-safe functions, so a `pre_exec` hook may call it.
///
/// # Errors
///
/// A `sigaction` or `sigprocmask` call fails.
pub(crate) fn child_defaults(handled: &libc::sigset_t) -> io::Result<()> {
    for signal in SIGNALS {
        // SAFETY: zero is a valid value of `current`; the query writes the disposition into it, and
        // the update reads it with `sa_sigaction` set to `SIG_DFL`. `sigaction` is async-signal-safe.
        unsafe {
            let mut current: libc::sigaction = std::mem::zeroed();
            if libc::sigaction(signal, std::ptr::null(), &mut current) != 0 {
                return Err(io::Error::last_os_error());
            }
            if current.sa_sigaction != libc::SIG_IGN && current.sa_sigaction != libc::SIG_DFL {
                current.sa_sigaction = libc::SIG_DFL;
                if libc::sigaction(signal, &current, std::ptr::null_mut()) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
        }
    }
    // SAFETY: `handled` is an initialized signal set, and a null old set makes `sigprocmask` write
    // nothing back; the call is async-signal-safe.
    if unsafe { libc::sigprocmask(libc::SIG_UNBLOCK, handled, std::ptr::null_mut()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `exit_code` is the child's exit status, or the negated number of the signal that ended it.
pub(crate) fn exit_code(status: ExitStatus) -> i32 {
    status
        .code()
        .or_else(|| status.signal().map(|signal| -signal))
        .expect("an exited child has a code or a signal")
}

/// `exited_within` waits up to `limit` for the child to exit and returns its status, polling it with a
/// pause that grows to [`POLL`]; an `interrupt` that holds a signal ends the wait early with `Ok(None)`.
///
/// # Errors
///
/// The wait fails.
pub(crate) fn exited_within(
    child: &mut Child,
    limit: Duration,
    interrupt: Option<&Interrupt>,
) -> io::Result<Option<ExitStatus>> {
    let start = Instant::now();
    let mut pause = FIRST_PAUSE;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        let waited = start.elapsed();
        if waited >= limit || interrupt.is_some_and(|interrupt| interrupt.recorded().is_some()) {
            return Ok(None);
        }
        thread::sleep(pause.min(limit - waited));
        pause = (pause * 2).min(POLL);
    }
}

/// The refusal of a tool started with SIGCHLD ignored: the kernel then reaps each child as it ends, so
/// every wait fails once the child has run and the child's outcome is unknown.
pub(crate) const SIGCHLD_IGNORED: &str = "SIGCHLD is ignored, so the child's exit cannot be read";

/// `refuse_ignored_sigchld` is the refusal of a start with SIGCHLD ignored. A tool that starts children
/// through this module calls it before its first child starts and ends the run with the returned sentence
/// as it ends a run whose child failed to start.
///
/// # Errors
///
/// [`SIGCHLD_IGNORED`] when SIGCHLD is ignored, or the sentence of a disposition that cannot be read.
pub(crate) fn refuse_ignored_sigchld() -> Result<(), String> {
    match ignored(libc::SIGCHLD) {
        Ok(false) => Ok(()),
        Ok(true) => Err(SIGCHLD_IGNORED.to_owned()),
        Err(error) => Err(format!("SIGCHLD's disposition cannot be read: {error}")),
    }
}

/// The state of a child that leads its process group, read from `/proc/<pid>/stat` without reaping it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Leader {
    /// A state other than `Z`, or `Z` while another thread of the process still runs.
    Running,
    /// The state `Z` with one thread left: the process exited and is held unreaped, so its id still names
    /// its group.
    Exited,
    /// The state file is gone: a wait outside this module reaped the leader.
    Reaped,
}

/// `parsed` reads `stat` as the `/proc/<pid>/stat` record of the group leader `pid`, a child of `parent`.
/// `parsed` takes the last `)` as the end of the command name because the name can contain spaces and
/// parentheses. The state follows the last `)`. Offsets 1, 2 and 17 after the state identify the parent,
/// the process group and the thread count. A leader whose main thread ended reads `Z` while other threads
/// run, so `Z` with one thread is an exited process.
///
/// # Errors
///
/// `parsed` returns an error if it cannot locate a one-byte state after the command name, the parent PID,
/// process group ID or thread count fails to parse as `u64`, the parent PID differs from `parent`, or the
/// process group ID differs from `pid`.
fn parsed(stat: &[u8], pid: u32, parent: u32) -> Result<Leader, String> {
    let close = stat
        .iter()
        .rposition(|&byte| byte == b')')
        .ok_or("holds no command name")?;
    let rest = stat[close + 1..]
        .strip_prefix(b" ")
        .ok_or("holds no state field")?;
    let fields: Vec<&[u8]> = rest.split(|&byte| byte == b' ').collect();
    let number = |at: usize| {
        let field = fields.get(at)?;
        std::str::from_utf8(field)
            .ok()?
            .trim_end()
            .parse::<u64>()
            .ok()
    };
    let state = match fields.first() {
        Some(&[state]) => state,
        _ => return Err("holds no state field".to_owned()),
    };
    let named = number(1).ok_or("holds no parent")?;
    if named != u64::from(parent) {
        return Err(format!(
            "names the parent {named}, so the process is no child of the process {parent}"
        ));
    }
    let group = number(2).ok_or("holds no process group")?;
    if group != u64::from(pid) {
        return Err(format!(
            "names the process group {group}, so the child leads no group of its own"
        ));
    }
    let threads = number(17).ok_or("holds no thread count")?;
    Ok(if *state == b'Z' && threads <= 1 {
        Leader::Exited
    } else {
        Leader::Running
    })
}

fn at(path: &str, error: &io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("{path}: {error}"))
}

/// `own_view` returns `Ok` when the first field of `/proc/self/stat` is this process's id, which holds
/// for the `/proc` of this process's PID namespace.
///
/// # Errors
///
/// `own_view` returns an error if `/proc/self/stat` cannot be read, as when `/proc` is not mounted, or
/// its first field is not this process's id.
fn own_view() -> io::Result<()> {
    const OWN: &str = "/proc/self/stat";
    let stat = fs::read(OWN).map_err(|error| at(OWN, &error))?;
    let named = stat
        .split(|&byte| byte == b' ')
        .next()
        .and_then(|field| std::str::from_utf8(field).ok())
        .and_then(|field| field.parse::<u32>().ok());
    let id = std::process::id();
    if named == Some(id) {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("{OWN} names no process {id}, so /proc shows another PID namespace"),
    ))
}

/// `leader` reads the state of the group leader `pid`, a child of this process, from
/// `/proc/<pid>/stat`. A missing state file is [`Leader::Reaped`] once [`own_view`] holds.
///
/// # Errors
///
/// `leader` returns an error if the read fails other than with `ENOENT` or `ESRCH`, [`own_view`] fails
/// after a missing state file, or [`parsed`] refuses the record. Each error names the path it concerns.
pub(crate) fn leader(pid: u32) -> io::Result<Leader> {
    let path = format!("/proc/{pid}/stat");
    match fs::read(&path) {
        Ok(stat) => parsed(&stat, pid, std::process::id()).map_err(|reason| {
            io::Error::new(io::ErrorKind::InvalidData, format!("{path} {reason}"))
        }),
        Err(error) if matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ESRCH)) => {
            own_view()?;
            Ok(Leader::Reaped)
        }
        Err(error) => Err(at(&path, &error)),
    }
}

/// `polled` calls `step` until it returns a value, `limit` passes on the monotonic clock or `ended`
/// holds, pausing between two calls for a time that starts at [`FIRST_PAUSE`] and doubles up to `cap`.
/// It returns `None` when the limit passes or `ended` holds first.
fn polled<T>(
    limit: Duration,
    cap: Duration,
    ended: &dyn Fn() -> bool,
    mut step: impl FnMut() -> io::Result<Option<T>>,
) -> io::Result<Option<T>> {
    let start = Instant::now();
    let mut pause = FIRST_PAUSE.min(cap);
    loop {
        if let Some(value) = step()? {
            return Ok(Some(value));
        }
        let waited = start.elapsed();
        if waited >= limit || ended() {
            return Ok(None);
        }
        thread::sleep(pause.min(limit - waited));
        pause = (pause * 2).min(cap);
    }
}

/// `leader_left_within` reads the state of the leader `pid` until it leaves [`Leader::Running`], `limit`
/// passes or `ended` holds, at the pauses of [`polled`] up to `cap`, and returns the last state read. It
/// reaps nothing.
///
/// # Errors
///
/// A read of the state fails as [`leader`] states.
pub(crate) fn leader_left_within(
    pid: u32,
    limit: Duration,
    cap: Duration,
    ended: &dyn Fn() -> bool,
) -> io::Result<Leader> {
    let left = polled(limit, cap, ended, || {
        Ok(Some(leader(pid)?).filter(|&state| state != Leader::Running))
    })?;
    Ok(left.unwrap_or(Leader::Running))
}

/// `signal_group` sends `signal` to the process group `group` and returns false when no member is left.
///
/// # Errors
///
/// `killpg` fails with an error other than `ESRCH`.
fn signal_group(group: libc::pid_t, signal: i32) -> io::Result<bool> {
    // SAFETY: `killpg` takes two integers and touches no memory of the caller.
    if unsafe { libc::killpg(group, signal) } == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        return Ok(false);
    }
    Err(error)
}

/// How [`stop_group`] stops the process group a child leads.
#[derive(Clone, Copy)]
pub(crate) struct GroupStop<'a> {
    grace: Duration,
    ends_grace: Option<&'a dyn Fn() -> bool>,
    second_grace: bool,
    reap: Option<Duration>,
    poll: Duration,
}

impl<'a> GroupStop<'a> {
    /// `new` is a stop whose grace after SIGTERM lasts `grace`, whose reap is bounded by `reap` (`None`
    /// permits an unbounded reap wait), and which pauses up to `poll` between two reads of the leader's
    /// state. Each grace ends once `ends` holds, as when a further signal is delivered; the stop calls
    /// `ends` at each pause of a grace. `ends` must preserve each child's wait status for its reaper.
    ///
    /// # Panics
    ///
    /// `poll` is zero, which would read the state with no pause.
    pub(crate) const fn new(
        grace: Duration,
        ends: Option<&'a dyn Fn() -> bool>,
        reap: Option<Duration>,
        poll: Duration,
    ) -> Self {
        assert!(!poll.is_zero(), "a stop pauses between two reads");
        Self {
            grace,
            ends_grace: ends,
            second_grace: false,
            reap,
            poll,
        }
    }

    /// `with_second_grace` sends SIGKILL after a grace the leader outlives and waits a second grace of the
    /// same length before the closing SIGKILL.
    #[must_use]
    pub(crate) const fn with_second_grace(mut self) -> Self {
        self.second_grace = true;
        self
    }

    fn ends(&self) -> bool {
        self.ends_grace.is_some_and(|ends| ends())
    }
}

/// How [`stop_group`] left the child.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GroupStopped {
    /// The reap's status.
    Reaped(ExitStatus),
    /// The leader still ran when the reap's bound passed and stays unreaped.
    Running,
    /// A wait outside this module reaped the leader, so the stop sent no signal after it saw that.
    ReapedElsewhere,
}

/// What [`signals`] leaves to do.
enum Signalled {
    /// The leader is held unreaped and the reap follows.
    Reap,
    /// The leader's state file is gone.
    Gone,
}

/// `stop_group` stops the process group that `child`, held unreaped, leads, and then reaps it: SIGTERM to
/// the group; a grace for the leader's exit; when the leader still runs and the stop has a second grace,
/// SIGKILL to the group and the second grace; a closing SIGKILL to the group; and the reap within its
/// bound. Each grace starts once its signal is sent and ends at the leader's exit, at its bound or when the
/// stop's check holds. The caller holds the only wait for `child` until the stop returns. Keeping the
/// leader unreaped reserves its id, and so its group's, throughout signaling. If a signal finds the group
/// empty, `stop_group` proceeds to the reap. The stop detects a wait elsewhere only after that wait has
/// reaped the leader. A missing state file stops the signals and prompts a wait for the child: `ECHILD`
/// from that wait or from the reap is [`GroupStopped::ReapedElsewhere`].
///
/// # Errors
///
/// A read of the leader's state, a signal other than to an empty group, or the reap fails, or the state
/// file is gone while the child still runs. If `child.try_wait()` then finds the child running,
/// `stop_group` attempts SIGKILL on the group and the child, retries the reap, and returns the first
/// error.
pub(crate) fn stop_group(child: &mut Child, stop: &GroupStop<'_>) -> io::Result<GroupStopped> {
    stop_with(child, stop, &mut signal_group)
}

/// `stop_with` is [`stop_group`] with `send` sending each signal to the group.
fn stop_with(
    child: &mut Child,
    stop: &GroupStop<'_>,
    send: &mut dyn FnMut(libc::pid_t, i32) -> io::Result<bool>,
) -> io::Result<GroupStopped> {
    let group = libc::pid_t::try_from(child.id()).expect("a process id fits pid_t");
    let ended = signals(child.id(), group, stop, send).and_then(|signalled| match signalled {
        Signalled::Reap => reap(child, stop),
        Signalled::Gone => match child.try_wait() {
            Err(error) if error.raw_os_error() == Some(libc::ECHILD) => {
                Ok(GroupStopped::ReapedElsewhere)
            }
            Err(error) => Err(error),
            Ok(Some(status)) => Ok(GroupStopped::Reaped(status)),
            Ok(None) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the state file of a running child is gone",
            )),
        },
    });
    ended.inspect_err(|_error| {
        if matches!(child.try_wait(), Ok(None)) {
            let _ = send(group, libc::SIGKILL);
            let _ = child.kill();
            let _ = reap(child, stop);
        }
    })
}

/// `signals` sends the stop's signals. Once a read of the leader's state finds its state file gone it
/// sends no further signal.
fn signals(
    pid: u32,
    group: libc::pid_t,
    stop: &GroupStop<'_>,
    send: &mut dyn FnMut(libc::pid_t, i32) -> io::Result<bool>,
) -> io::Result<Signalled> {
    if leader(pid)? == Leader::Reaped {
        return Ok(Signalled::Gone);
    }
    if !send(group, libc::SIGTERM)? {
        return Ok(Signalled::Reap);
    }
    let ends = || stop.ends();
    let mut state = leader_left_within(pid, stop.grace, stop.poll, &ends)?;
    if state == Leader::Running && stop.second_grace {
        if !send(group, libc::SIGKILL)? {
            return Ok(Signalled::Reap);
        }
        state = leader_left_within(pid, stop.grace, stop.poll, &ends)?;
    }
    if state == Leader::Reaped {
        return Ok(Signalled::Gone);
    }
    send(group, libc::SIGKILL)?;
    Ok(Signalled::Reap)
}

fn reap(child: &mut Child, stop: &GroupStop<'_>) -> io::Result<GroupStopped> {
    let status = match stop.reap {
        Some(limit) => polled(limit, stop.poll, &|| false, || child.try_wait()),
        None => child.wait().map(Some),
    };
    match status {
        Ok(status) => Ok(status.map_or(GroupStopped::Running, GroupStopped::Reaped)),
        Err(error) if error.raw_os_error() == Some(libc::ECHILD) => {
            Ok(GroupStopped::ReapedElsewhere)
        }
        Err(error) => Err(error),
    }
}

fn drain(
    stream: Option<impl Read + Send + 'static>,
) -> io::Result<JoinHandle<io::Result<Vec<u8>>>> {
    thread::Builder::new().spawn(move || {
        let mut bytes = Vec::new();
        if let Some(mut stream) = stream {
            stream.read_to_end(&mut bytes)?;
        }
        Ok(bytes)
    })
}

fn joined(reader: JoinHandle<io::Result<Vec<u8>>>) -> io::Result<Vec<u8>> {
    reader.join().expect("a reader thread returns its bytes")
}

/// `capture` runs `command` with standard input inherited and returns its output once the child has
/// exited and both of its output pipes have closed. A signal recorded in `interrupt` before then kills a
/// child that still runs with SIGKILL, waits up to [`GRACE`] for it and returns the interruption, leaving
/// a pipe that a descendant holds to its reader.
///
/// # Errors
///
/// The outer error is a recorded signal; the inner one a start, a reader thread, a read or a wait that
/// fails.
pub(crate) fn capture(
    command: &mut Command,
    interrupt: &Interrupt,
) -> Result<io::Result<Output>, Interrupted> {
    let spawned = command
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    match spawned {
        Ok(child) => captured(child, interrupt),
        Err(error) => Ok(Err(error)),
    }
}

/// `captured` reads a started child's piped output streams and waits for it as [`capture`] does.
///
/// # Errors
///
/// The outer error is a recorded signal; the inner one a reader thread, a read or a wait that fails.
pub(crate) fn captured(
    mut child: Child,
    interrupt: &Interrupt,
) -> Result<io::Result<Output>, Interrupted> {
    let readers = drain(child.stdout.take()).and_then(|out| Ok((out, drain(child.stderr.take())?)));
    let (out, err) = match readers {
        Ok(readers) => readers,
        Err(error) => {
            let _ = child.kill();
            let _ = exited_within(&mut child, GRACE, None);
            return Ok(Err(error));
        }
    };
    let mut status = None;
    let mut pause = FIRST_PAUSE;
    loop {
        if status.is_none() {
            match child.try_wait() {
                Ok(exited) => status = exited,
                Err(error) => return Ok(Err(error)),
            }
        }
        if let Some(status) = status
            && out.is_finished()
            && err.is_finished()
        {
            let output = joined(out).and_then(|stdout| Ok((stdout, joined(err)?)));
            return Ok(output.map(|(stdout, stderr)| Output {
                status,
                stdout,
                stderr,
            }));
        }
        if let Err(stop) = interrupt.check() {
            if status.is_none() {
                let _ = child.kill();
                let _ = exited_within(&mut child, GRACE, None);
            }
            return Err(stop);
        }
        thread::sleep(pause);
        pause = (pause * 2).min(POLL);
    }
}

#[cfg(test)]
#[path = "process_tests.rs"]
mod tests;
