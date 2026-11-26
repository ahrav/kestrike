//! The step-keyed fault seam. Every filesystem call and named protocol point
//! of the store passes through [`call`], [`write`] or [`last`] with the
//! [`Step`] it is. Outside the crate's own tests each of them invokes its
//! call directly. Under `cfg(test)` a thread-local [`Script`] counts every
//! step the thread reaches and, at any set of step indices, can fail the
//! step with an errno, shorten a write, or kill the thread, before the
//! call takes effect.
//!
//! [`call`] and [`write`] retry a call that fails with `EINTR` and no other
//! error. [`last`] never retries. It runs `close`, which on Linux releases
//! the descriptor even when it reports `EINTR`, and `poll`, whose callers
//! treat `EINTR` as a wake.

use std::io;

/// One kind of filesystem call or protocol point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Step {
    /// An open of a file or directory, or the resolution of a path to an
    /// absolute or canonical path.
    Open,
    /// A status query of an open descriptor or of a path.
    Stat,
    Limits,
    Chmod,
    /// The state directory's lock.
    Lock,
    /// The whole bounded read of a file's bytes, however many `read`
    /// calls it takes, or one read of an opened file's stream or at an
    /// offset.
    Read,
    /// One `write` of a file's bytes.
    Write,
    /// An `fsync` of a file or directory, or a `syncfs` of a filesystem.
    Sync,
    Close,
    /// A rename into a record's directory, or the startup rename probe.
    Rename,
    /// A directory creation.
    Mkdir,
    /// An unlink of a file or the removal of an empty directory.
    Unlink,
    /// One batch of a directory listing, or a whole `read_dir` listing
    /// with its open and each entry's type lookup.
    List,
    /// The comparison of a store's or a view's directory path with the
    /// pinned inode.
    Check,
    Census,
    Reservation,
    /// The custody launch points, in launch order: the intent record is
    /// durable, the attempt cgroup exists, the gate is spawned (a `spawn`
    /// call), the gate's process descriptor is open, the gate is in the
    /// cgroup, the started record is durable, and the go byte is about to be
    /// written.
    Intent,
    Created,
    Spawn,
    Spawned,
    Moved,
    Started,
    Go,
    ReleasedGate,
    /// `waitid` polls the gate's process descriptor and reaps the gate
    /// after exit.
    Reap,
    Exited,
    Kill,
    Killed,
    Drained,
    Evidence,
    Finished,
    Removed,
    Released,
    /// One `poll` over attempt descriptors and the interruption descriptor.
    Poll,
}

pub(crate) fn space(measured: (u64, u64)) -> io::Result<(u64, u64)> {
    call(Step::Census, || {
        #[cfg(test)]
        if let Some(value) =
            SCRIPT.with(|cell| cell.borrow().as_ref().and_then(|script| script.free_space))
        {
            return Ok(value);
        }
        Ok(measured)
    })
}

/// `bound`, or the scan bound this thread's test script sets in its place.
#[inline(always)]
pub(crate) fn scan_bound(bound: usize) -> usize {
    #[cfg(test)]
    if let Some(value) =
        SCRIPT.with(|cell| cell.borrow().as_ref().and_then(|script| script.scan_bound))
    {
        return value;
    }
    bound
}

/// Whether this thread runs under a test script, which counts and scripts
/// only this thread's steps. Work that could run on other threads stays on
/// this one while it does.
#[inline(always)]
pub(crate) fn scripted_thread() -> bool {
    #[cfg(test)]
    return SCRIPT.with(|cell| cell.borrow().is_some());
    #[cfg(not(test))]
    false
}

/// Runs `call` for step `at`, retrying it while it fails with `EINTR`.
#[inline(always)]
pub(crate) fn call<T>(at: Step, mut call: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    retry(at, 0, |_| call())
}

/// Runs `write` over `len` bytes for one [`Step::Write`], retrying it while
/// it fails with `EINTR`; `write` receives the byte count to pass, `len`
/// unless a test shortens it.
#[inline(always)]
pub(crate) fn write(
    len: usize,
    write: impl FnMut(usize) -> io::Result<usize>,
) -> io::Result<usize> {
    retry(Step::Write, len, write)
}

#[inline(always)]
fn retry<T>(at: Step, len: usize, mut call: impl FnMut(usize) -> io::Result<T>) -> io::Result<T> {
    loop {
        match enter(at, len).and_then(&mut call) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            result => return result,
        }
    }
}

/// Runs `call` for step `at` once, whatever it returns.
#[inline(always)]
pub(crate) fn last<T>(at: Step, call: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    enter(at, 0)?;
    call()
}

/// The byte count the step passes on, or the errno a test scripted for it.
#[inline(always)]
fn enter(_at: Step, len: usize) -> io::Result<usize> {
    #[cfg(test)]
    match scripted(_at) {
        Some(Outcome::Errno(errno)) => return Err(io::Error::from_raw_os_error(errno)),
        Some(Outcome::Kill) => std::panic::resume_unwind(Box::new(Killed)),
        Some(Outcome::Short(count)) => {
            assert_eq!(_at, Step::Write, "a short count is scripted at {_at:?}");
            return Ok(count.min(len));
        }
        None => {}
    }
    Ok(len)
}

/// What a test scripts for the step at one scripted index.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// The step fails with this errno before its call takes effect.
    Errno(i32),
    /// The write passes at most this many bytes to the file.
    Short(usize),
    /// The thread unwinds with [`Killed`] before the call takes effect, as
    /// a killed process runs no more of its code. The unwind runs
    /// destructors, which a killed process skips, so this models a kill
    /// while no destructor in the store writes to the filesystem: the
    /// store's destructors only close descriptors and release the lock.
    Kill,
}

/// The unwind payload of [`Outcome::Kill`].
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct Killed;

/// The thread's script: the outcome for each step index in `at`, every
/// step reached in order, and an observer that runs as each step is reached,
/// before its outcome. Steps the observer itself reaches run unscripted and
/// uncounted, so it can act as another controller would at that moment.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct Script {
    pub(crate) at: Vec<(usize, Outcome)>,
    pub(crate) nth: Option<(Step, usize, Outcome)>,
    pub(crate) reached: Vec<Step>,
    pub(crate) free_space: Option<(u64, u64)>,
    /// The scan bound [`scan_bound`] returns in place of its argument.
    pub(crate) scan_bound: Option<usize>,
    pub(crate) observe: Option<Box<dyn FnMut(Step)>>,
}

#[cfg(test)]
thread_local! {
    static SCRIPT: std::cell::RefCell<Option<Script>> = const { std::cell::RefCell::new(None) };
}

/// Installs `script` on this thread, returning the one it replaces.
#[cfg(test)]
pub(crate) fn install(script: Option<Script>) -> Option<Script> {
    SCRIPT.with(|cell| cell.replace(script))
}

#[cfg(test)]
fn scripted(at: Step) -> Option<Outcome> {
    let mut script = install(None)?;
    let index = script.reached.len();
    script.reached.push(at);
    if let Some(observe) = script.observe.as_mut() {
        observe(at);
    }
    let outcome = script
        .at
        .iter()
        .find(|&&(target, _)| target == index)
        .map(|&(_, outcome)| outcome);
    let outcome = outcome.or_else(|| {
        let (target, remaining, outcome) = script.nth.as_mut()?;
        if *target != at {
            return None;
        }
        if *remaining == 0 {
            let outcome = *outcome;
            script.nth = None;
            Some(outcome)
        } else {
            *remaining -= 1;
            None
        }
    });
    install(Some(script));
    outcome
}
