//! The signal record: the first of SIGINT, SIGTERM and SIGHUP delivered and not yet raised, and the
//! arming and the hold that decide when a read of the record raises that signal.
//!
//! The handlers that [`install`] registers keep the first pending signal in a [`Delivered`]. A
//! [`Record`] over that value raises the stored signal at [`Record::read`], in one of three states:
//!
//! - unarmed: the signal waits;
//! - armed and not held: the read takes the signal, disarms the record and returns [`Interrupted`];
//! - held, during a mark's write: the signal waits for the write's end. [`Record::holding`] reads the
//!   record before the hold, so a signal that may raise ends the step before the write starts; it
//!   reads the record again when the write succeeds, and on a failed write it ends the hold and leaves
//!   the signal pending.

use std::io;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

/// The longest time a wait or a sleep runs between two reads of the record.
pub const SLICE: Duration = Duration::from_millis(50);

/// The time left until `end`, or one [`SLICE`] for an end past the range of [`Instant`], which never
/// comes, so a loop on it reads the record once a slice without end.
pub(super) fn left(end: Option<Instant>) -> Duration {
    left_at(end, Instant::now())
}

/// [`left`] for a clock that reads `now`.
pub(super) fn left_at(end: Option<Instant>, now: Instant) -> Duration {
    end.map_or(SLICE, |end| end.saturating_duration_since(now))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signal {
    Interrupt,
    Terminate,
    Hangup,
}

impl Signal {
    pub const ALL: [Self; 3] = [Self::Interrupt, Self::Terminate, Self::Hangup];

    pub fn number(self) -> i32 {
        match self {
            Self::Interrupt => libc::SIGINT,
            Self::Terminate => libc::SIGTERM,
            Self::Hangup => libc::SIGHUP,
        }
    }

    /// The name the C headers give the signal, `SIGTERM` for [`Signal::Terminate`].
    pub fn name(self) -> &'static str {
        match self {
            Self::Interrupt => "SIGINT",
            Self::Terminate => "SIGTERM",
            Self::Hangup => "SIGHUP",
        }
    }

    fn of(number: i32) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|signal| signal.number() == number)
    }
}

/// The first signal delivered and not yet raised, or none.
#[derive(Debug, Default)]
pub struct Delivered(AtomicI32);

/// Pass `DELIVERED` to [`install`] to have the registered handlers store signals in `DELIVERED`.
pub static DELIVERED: Delivered = Delivered::new();

impl Delivered {
    pub const fn new() -> Self {
        Self(AtomicI32::new(0))
    }

    /// `deliver` uses one atomic compare-exchange to store `signal` when the value is empty.
    pub fn deliver(&self, signal: Signal) {
        let _ = self
            .0
            .compare_exchange(0, signal.number(), Ordering::SeqCst, Ordering::SeqCst);
    }

    pub fn stored(&self) -> Option<Signal> {
        Signal::of(self.0.load(Ordering::SeqCst))
    }

    fn take(&self) -> Option<Signal> {
        Signal::of(self.0.swap(0, Ordering::SeqCst))
    }
}

/// The signal that [`Record::read`] raised.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Interrupted(pub Signal);

impl std::fmt::Display for Interrupted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0.name())
    }
}

/// A `Record` controls when a read can raise a stored signal.
#[derive(Debug)]
pub struct Record<'a> {
    delivered: &'a Delivered,
    armed: bool,
    held: bool,
}

impl<'a> Record<'a> {
    pub fn new(delivered: &'a Delivered) -> Self {
        Self {
            delivered,
            armed: false,
            held: false,
        }
    }

    pub fn arm(&mut self) {
        self.armed = true;
    }

    pub fn disarm(&mut self) {
        self.armed = false;
    }

    pub fn is_armed(&self) -> bool {
        self.armed
    }

    pub fn is_held(&self) -> bool {
        self.held
    }

    pub fn pending(&self) -> Option<Signal> {
        self.delivered.stored()
    }

    /// `read` raises only when the record is armed, not held, and holds a stored signal: it takes the
    /// signal and disarms the record. Every other read preserves the record's state. Taking the signal
    /// frees `Delivered` to accept a later delivery.
    ///
    /// # Errors
    ///
    /// [`Interrupted`] names the signal taken from the record.
    pub fn read(&mut self) -> Result<(), Interrupted> {
        if !self.armed || self.held {
            return Ok(());
        }
        match self.delivered.take() {
            Some(signal) => {
                self.armed = false;
                Err(Interrupted(signal))
            }
            None => Ok(()),
        }
    }

    pub fn hold(&mut self) {
        self.held = true;
    }

    /// Ends a hold and reads the record.
    ///
    /// # Errors
    ///
    /// The signal that waited during the hold, when the record is armed.
    pub fn release(&mut self) -> Result<(), Interrupted> {
        self.held = false;
        self.read()
    }

    /// Ends a hold; a stored signal remains pending.
    pub fn end_hold(&mut self) {
        self.held = false;
    }

    /// Reads the record, then runs `write` held. A signal that may raise before the hold raises there
    /// and `write` does not run. A write that succeeds is followed by [`Record::release`]; a write that
    /// fails ends the hold and returns its own error with the signal still stored.
    ///
    /// # Errors
    ///
    /// The outer error is a signal raised before the hold, or at the release after a successful
    /// write. A `write` that panics leaves the record held.
    pub fn holding<T, E>(
        &mut self,
        write: impl FnOnce() -> Result<T, E>,
    ) -> Result<Result<T, E>, Interrupted> {
        self.read()?;
        self.hold();
        match write() {
            Ok(value) => self.release().map(|()| Ok(value)),
            Err(error) => {
                self.end_hold();
                Ok(Err(error))
            }
        }
    }
}

/// Registers a handler that stores its signal into `delivered` for each of SIGINT, SIGTERM and SIGHUP
/// whose disposition at the call is the default action or a handler. An ignored signal keeps its
/// disposition, which child processes inherit. `register` blocks the signal in the calling thread
/// alone during registration, so a signal sent to the process can reach another running thread then.
/// If `install` returns an error, handlers it registered before the error remain registered.
///
/// # Errors
///
/// `install` returns the first error from `ignored` or `register`.
pub fn install(delivered: &'static Delivered) -> io::Result<()> {
    for signal in Signal::ALL {
        if !ignored(signal.number())? {
            register(signal, delivered)?;
        }
    }
    Ok(())
}

/// Whether the disposition of the signal `number` is to ignore it.
pub(super) fn ignored(number: i32) -> io::Result<bool> {
    // SAFETY: all-zero bytes are a valid `sigaction`. A null new action makes `sigaction` only write
    // the current disposition of `number`, a signal number the caller names, into `current`, which
    // outlives the call.
    let (status, current) = unsafe {
        let mut current: libc::sigaction = std::mem::zeroed();
        let status = libc::sigaction(number, std::ptr::null(), &mut current);
        (status, current)
    };
    if status != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(current.sa_sigaction == libc::SIG_IGN)
}

fn register(signal: Signal, delivered: &'static Delivered) -> io::Result<()> {
    let number = signal.number();
    let action = move || delivered.deliver(signal);
    // SAFETY: each `sigset_t` is zeroed, then filled by `sigemptyset` or `pthread_sigmask`, and
    // outlives the calls that use it. `sigaddset` and `sigdelset` require `number` to be a valid
    // signal number. `SIG_BLOCK` defers delivery of `number` on this thread during
    // `signal_hook::low_level::register`. A successful `SIG_SETMASK` unblocks `number` regardless of
    // the registration result and restores every other signal's prior mask setting.
    // `delivered: &'static Delivered` keeps the handler's reference valid for its lifetime.
    // `Delivered::deliver` must be async-signal-safe.
    unsafe {
        let mut blocked: libc::sigset_t = std::mem::zeroed();
        let mut before: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut blocked);
        libc::sigaddset(&mut blocked, number);
        let status = libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, &mut before);
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status));
        }
        let registered = signal_hook::low_level::register(number, action);
        libc::sigdelset(&mut before, number);
        let restored = libc::pthread_sigmask(libc::SIG_SETMASK, &before, std::ptr::null_mut());
        if restored != 0 {
            return Err(io::Error::from_raw_os_error(restored));
        }
        registered.map(drop)
    }
}
