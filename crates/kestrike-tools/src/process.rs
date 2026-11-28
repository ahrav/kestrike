//! Signals and child processes that two tools share: the record of the handled signals and its
//! handlers, the hold and the block of those signals, the refusal of a run with SIGCHLD ignored, the
//! reading of a child's exit, the wait for a child that sees a recorded signal, the captured child, and
//! the stop of a process group that a child leads.
//!
//! The handlers of SIGINT, SIGTERM and SIGHUP record the first of them in [`INTERRUPT`] and count each
//! delivery; a later signal leaves the first one as it is. A tool reads the record between its steps and
//! while it waits for a child, so a signal that arrives while a child is being started is acted on once
//! that child has started. A wait polls the child and the record at pauses that start at 0.5 ms and
//! double up to a cap, 20 ms unless the caller names another, on the monotonic clock.
//!
//! A group's stop reads its leader's state from `/proc/<pid>/stat` and reaps the leader only after its
//! last signal, so while the stop signals the group the leader's id names that group alone. That holds
//! while the caller is the leader's only waiter from its start until the stop returns: no other code of
//! the process waits for that child or for any child, and SIGCHLD is neither ignored nor set with
//! `SA_NOCLDWAIT`. A missing state file, `ECHILD` and [`GroupStopped::ReapedElsewhere`] report a reap
//! outside the stop after it happened; they do not prevent one.

use std::fs;
use std::io::{self, Read};
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub const SIGNALS: [i32; 3] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP];
/// The wait for a captured child after SIGKILL.
pub(crate) const GRACE: Duration = Duration::from_secs(10);
/// The longest pause between two checks of a child and of the record while a tool waits; the pause
/// starts at [`FIRST_PAUSE`] and doubles up to this bound.
pub(crate) const POLL: Duration = Duration::from_millis(20);
const FIRST_PAUSE: Duration = Duration::from_micros(500);

/// The record of the handled signals: the first one, 0 while none has arrived, the count of deliveries,
/// and the depth of the holds that stand.
#[derive(Debug, Default)]
pub struct Interrupt {
    first: AtomicI32,
    deliveries: AtomicUsize,
    holds: AtomicUsize,
}

/// The handlers [`install_handlers`] installs record into this value.
pub static INTERRUPT: Interrupt = Interrupt::new();

/// A recorded signal that ended a step: the signal's number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Interrupted(pub i32);

impl Interrupt {
    pub const fn new() -> Self {
        Self {
            first: AtomicI32::new(0),
            deliveries: AtomicUsize::new(0),
            holds: AtomicUsize::new(0),
        }
    }

    /// `record` keeps `signal` unless a signal is already recorded, and counts the delivery; the count
    /// stops at `usize::MAX`. It makes no allocation and takes no lock, so a signal handler may call it.
    pub fn record(&self, signal: i32) {
        let _ = self
            .first
            .compare_exchange(0, signal, Ordering::SeqCst, Ordering::SeqCst);
        let _ = self
            .deliveries
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
                count.checked_add(1)
            });
    }

    /// The first recorded signal.
    pub fn recorded(&self) -> Option<i32> {
        Some(self.first.load(Ordering::SeqCst)).filter(|&signal| signal != 0)
    }

    /// The count of the signals recorded so far, the first included.
    pub fn deliveries(&self) -> usize {
        self.deliveries.load(Ordering::SeqCst)
    }

    /// `hold` starts a hold of the recorded signals, which lasts until [`Hold::release`] or its drop. Holds
    /// nest: the release that ends the last hold standing reports the first signal recorded by then, in
    /// whatever order the holds end, and every other release reports nothing. Within a hold the holder's
    /// own steps decide where a recorded signal takes effect.
    pub fn hold(&self) -> Hold<'_> {
        self.holds.fetch_add(1, Ordering::SeqCst);
        Hold { interrupt: self }
    }

    /// Whether a hold stands.
    pub fn held(&self) -> bool {
        self.holds.load(Ordering::SeqCst) > 0
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

/// A hold of an [`Interrupt`]'s signals; [`Interrupt::hold`] starts one.
#[derive(Debug)]
#[must_use = "a hold lasts until its release or its drop"]
pub struct Hold<'a> {
    interrupt: &'a Interrupt,
}

impl Hold<'_> {
    /// `release` ends the hold.
    ///
    /// # Errors
    ///
    /// The release ends the last hold that stands while a signal is recorded: the interruption of the
    /// first one.
    pub fn release(self) -> Result<(), Interrupted> {
        let interrupt = self.interrupt;
        std::mem::forget(self);
        if interrupt.holds.fetch_sub(1, Ordering::SeqCst) == 1 {
            return interrupt.check();
        }
        Ok(())
    }
}

impl Drop for Hold<'_> {
    fn drop(&mut self) {
        self.interrupt.holds.fetch_sub(1, Ordering::SeqCst);
    }
}

/// `blocked` runs `body` with each of [`SIGNALS`] blocked in the calling thread, and then sets the thread's
/// signal mask back to the one it held before. A signal delivered to the thread meanwhile stays pending
/// until the mask is set back, and its handler then runs.
///
/// # Errors
///
/// The mask cannot be changed, before `body` runs, or set back after it, when `body`'s value is dropped.
pub fn blocked<T>(body: impl FnOnce() -> T) -> io::Result<T> {
    let handled = handled_set();
    // SAFETY: all-zero bytes are a valid `sigset_t`, which `pthread_sigmask` overwrites with the mask it
    // held.
    let mut previous: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: `handled` is an initialized set and `previous` a set the call writes; both outlive it.
    let status = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &handled, &mut previous) };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status));
    }
    /// Sets the mask back when `body` unwinds; the normal path sets it back itself and reports a failure.
    struct Restore(Option<libc::sigset_t>);
    impl Drop for Restore {
        fn drop(&mut self) {
            if let Some(previous) = self.0.take() {
                let _ = mask(libc::SIG_SETMASK, &previous);
            }
        }
    }
    let mut restore = Restore(Some(previous));
    let value = body();
    restore.0 = None;
    mask(libc::SIG_SETMASK, &previous)?;
    Ok(value)
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
/// The three signals are blocked in the calling thread while the handlers register, because a handler
/// is installed in the kernel before its recording action is published: a signal sent in that window
/// stays pending and is recorded at the unblock. This holds only while the calling thread is the one
/// thread of the process able to receive the three, so a tool calls `install_handlers` before it starts
/// another thread. After blocking [`SIGNALS`], the calling thread attempts to unblock them whether
/// registration succeeds or fails.
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
        // SAFETY: the action only calls `Interrupt::record`, a compare-exchange and a bounded-increment
        // update of two atomics of a static, which take no lock and allocate nothing, so the action is
        // async-signal-safe.
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

/// `ignore_file_size_signal` sets SIGXFSZ to be ignored in this process, so a write past the soft
/// file size limit returns `EFBIG` to its caller and ends no process.
///
/// # Errors
///
/// The disposition cannot be set.
pub(crate) fn ignore_file_size_signal() -> io::Result<()> {
    // SAFETY: `signal` takes a signal number and a disposition constant and touches no memory of the
    // caller.
    if unsafe { libc::signal(libc::SIGXFSZ, libc::SIG_IGN) } == libc::SIG_ERR {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `file_size_signal_default` sets SIGXFSZ back to its default action; it calls only
/// async-signal-safe functions, so a `pre_exec` hook may call it before a child runs its program.
///
/// # Errors
///
/// The disposition cannot be set.
pub(crate) fn file_size_signal_default() -> io::Result<()> {
    // SAFETY: `signal` takes a signal number and a disposition constant, touches no memory of the
    // caller, and is async-signal-safe.
    if unsafe { libc::signal(libc::SIGXFSZ, libc::SIG_DFL) } == libc::SIG_ERR {
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

/// `exited_within` polls the child for its exit as [`polled`] does, with a pause that grows to [`POLL`],
/// and returns its status: a status or an error of the poll comes first, and only a poll that finds the
/// child running leads to the check of `limit` and of `interrupt`, either of which ends the wait with
/// `Ok(None)`.
///
/// # Errors
///
/// The wait fails.
pub(crate) fn exited_within(
    child: &mut Child,
    limit: Duration,
    interrupt: Option<&Interrupt>,
) -> io::Result<Option<ExitStatus>> {
    let recorded = || interrupt.is_some_and(|interrupt| interrupt.recorded().is_some());
    polled(limit, POLL, &recorded, || child.try_wait())
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
    /// The state file is gone, or the record names another parent, so the id names a process that is no
    /// child of this one: a wait outside this module reaped the leader.
    Reaped,
}

/// `parsed` reads `stat` as the `/proc/<pid>/stat` record of the group leader `pid`, a child of `parent`.
/// `parsed` takes the last `)` as the end of the command name because the name can contain spaces and
/// parentheses. The state follows the last `)`. Offsets 1, 2 and 17 after the state identify the parent,
/// the process group and the thread count. A leader whose main thread ended reads `Z` while other threads
/// run, so `Z` with one thread is an exited process. A record that names another parent is
/// [`Leader::Reaped`]: the leader was reaped outside the stop and its id taken by another process.
///
/// # Errors
///
/// `parsed` returns an error if it cannot locate a one-byte state after the command name, the parent PID,
/// process group ID or thread count fails to parse as `u64`, or the process group ID differs from `pid`.
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
        return Ok(Leader::Reaped);
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

fn at(path: &Path, error: &io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("{}: {error}", path.display()))
}

/// `own_view` returns `Ok` when the `NStgid` line of `<root>/self/status` holds one id, `own`. One id
/// there means the procfs at `root` is that of the PID namespace this process lives in, so the ids it
/// shows are the ids this process signals and waits for.
///
/// # Errors
///
/// `own_view` returns an error if `<root>/self/status` cannot be read, as when `/proc` is not mounted, or
/// its `NStgid` line is missing or holds anything other than the one id `own`.
fn own_view(root: &Path, own: u32) -> io::Result<()> {
    let path = root.join("self/status");
    let status = fs::read(&path).map_err(|error| at(&path, &error))?;
    let single = status
        .split(|&byte| byte == b'\n')
        .find_map(|line| line.strip_prefix(b"NStgid:"))
        .and_then(|ids| {
            let mut ids = ids
                .split(u8::is_ascii_whitespace)
                .filter(|id| !id.is_empty());
            let first = ids.next()?;
            ids.next().is_none().then_some(first)
        })
        .and_then(|id| std::str::from_utf8(id).ok()?.parse::<u32>().ok());
    if single == Some(own) {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "{} holds no NStgid line of the one id {own}, so /proc shows another PID namespace",
            path.display()
        ),
    ))
}

/// `leader` reads the state of the group leader `pid`, a child of this process, from
/// `/proc/<pid>/stat` after [`own_view`] confirms that `/proc` is this process's view. A missing state
/// file is [`Leader::Reaped`].
///
/// # Errors
///
/// `leader` returns an error if [`own_view`] fails, the read of the state file fails other than with
/// `ENOENT` or `ESRCH`, or [`parsed`] refuses the record. Each error names the path it concerns and a
/// failed read keeps its kind.
pub(crate) fn leader(pid: u32) -> io::Result<Leader> {
    leader_under(Path::new("/proc"), pid, std::process::id())
}

/// `leader_under` is [`leader`] with `root` as the procfs and `own` as this process's id.
fn leader_under(root: &Path, pid: u32, own: u32) -> io::Result<Leader> {
    own_view(root, own)?;
    let path = root.join(pid.to_string()).join("stat");
    match fs::read(&path) {
        Ok(stat) => parsed(&stat, pid, own).map_err(|reason| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} {reason}", path.display()),
            )
        }),
        Err(error) if matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ESRCH)) => {
            Ok(Leader::Reaped)
        }
        Err(error) => Err(at(&path, &error)),
    }
}

/// `polled` calls `step` first and returns its value or its error. Only after `step` returns `Ok(None)`
/// does it read the limit on the monotonic clock and then `ended`, and it returns `Ok(None)` when either
/// holds; otherwise it pauses for a time that starts at [`FIRST_PAUSE`], doubles up to `cap` and is cut to
/// the time left, and calls `step` again, so one more call runs at the limit and its value is returned.
/// The length of one call of `step` has no bound.
fn polled<T>(
    limit: Duration,
    cap: Duration,
    ended: &dyn Fn() -> bool,
    step: impl FnMut() -> io::Result<Option<T>>,
) -> io::Result<Option<T>> {
    polled_until(Instant::now().checked_add(limit), cap, ended, step)
}

/// `polled_until` is [`polled`] with the limit an instant of the monotonic clock, `None` for none.
fn polled_until<T>(
    cutoff: Option<Instant>,
    cap: Duration,
    ended: &dyn Fn() -> bool,
    mut step: impl FnMut() -> io::Result<Option<T>>,
) -> io::Result<Option<T>> {
    let mut pause = FIRST_PAUSE.min(cap);
    loop {
        if let Some(value) = step()? {
            return Ok(Some(value));
        }
        let left = cutoff.map(|cutoff| cutoff.saturating_duration_since(Instant::now()));
        if left == Some(Duration::ZERO) || ended() {
            return Ok(None);
        }
        thread::sleep(left.map_or(pause, |left| pause.min(left)));
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
    leader_left_by(pid, Instant::now().checked_add(limit), cap, ended)
}

/// `leader_left_by` is [`leader_left_within`] with the limit an instant of the monotonic clock, `None`
/// for none, so a wait whose budget counts from an earlier reading ends at that reading plus the budget.
///
/// # Errors
///
/// A read of the state fails as [`leader`] states.
pub(crate) fn leader_left_by(
    pid: u32,
    cutoff: Option<Instant>,
    cap: Duration,
    ended: &dyn Fn() -> bool,
) -> io::Result<Leader> {
    let left = polled_until(cutoff, cap, ended, || {
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
/// stop's check holds. Keeping the leader unreaped reserves its id, and so its group's, throughout
/// signaling, which holds only while the caller is `child`'s only waiter from its start until the stop
/// returns: no other code of the process waits for `child` or for any child, and SIGCHLD is neither
/// ignored nor set with `SA_NOCLDWAIT`. An exited leader held unreaped meets that. If a signal finds the
/// group empty, `stop_group` proceeds to the reap. The stop detects a wait elsewhere only after that wait
/// has reaped the leader, and does not prevent it. A missing state file stops the signals and prompts a
/// wait for the child: `ECHILD` from that wait or from the reap is [`GroupStopped::ReapedElsewhere`].
///
/// # Errors
///
/// A read of the leader's state, a signal other than to an empty group, or the reap fails, or the state
/// file is gone while the child still runs. `stop_group` then reads the leader's state once more: a
/// leader that reads running or exited, or whose read fails, gets SIGKILL to its group before any wait,
/// since the sole-waiter precondition holds it unreaped; a caller that breaks that precondition while the
/// read fails gets one SIGKILL to a group id that may have been taken again. A leader whose state file is
/// gone, or whose record names another parent, gets that SIGKILL only where `child.try_wait()` then finds
/// it running. A running child
/// also gets SIGKILL to itself, and the reap runs again. `stop_group` returns the first error.
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
        let gone = matches!(leader(child.id()), Ok(Leader::Reaped));
        if !gone {
            let _ = send(group, libc::SIGKILL);
        }
        if matches!(child.try_wait(), Ok(None)) {
            if gone {
                let _ = send(group, libc::SIGKILL);
            }
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
/// The kill by process id is sound only while the caller holds the child unreaped and is its one
/// waiter: no other code of the process waits for any child, and SIGCHLD is not ignored.
///
/// # Errors
///
/// The outer error is a recorded signal; the inner one a start, a reader thread, a read or a wait that
/// fails. After a failed wait the child's state is unknown: no signal goes to it, no further wait
/// runs, and the reader threads are left unjoined.
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
/// The kill by process id is sound only while the caller holds the child unreaped and is its one
/// waiter: no other code of the process waits for any child, and SIGCHLD is not ignored.
///
/// # Errors
///
/// The outer error is a recorded signal; the inner one a reader thread, a read or a wait that fails,
/// which leaves the child as [`capture`] states.
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
