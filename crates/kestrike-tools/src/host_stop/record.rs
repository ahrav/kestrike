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
    end.map_or(SLICE, |end| end.saturating_duration_since(Instant::now()))
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

/// The value the handlers that [`install`] registers store their signal into.
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

impl std::error::Error for Interrupted {}

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

    /// Whether a read would raise: the record is armed, not held, and a signal is stored.
    pub fn may_raise(&self) -> bool {
        self.armed && !self.held && self.pending().is_some()
    }

    /// When [`Record::may_raise`] holds, `read` takes the stored signal, so the record can store a
    /// later delivery, and disarms the record. Otherwise `read` keeps the record's state.
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
/// disposition, which child processes inherit.
///
/// # Errors
///
/// Reading a disposition or registering a handler fails.
pub fn install(delivered: &'static Delivered) -> io::Result<()> {
    for signal in Signal::ALL {
        if !ignored(signal)? {
            register(signal, delivered)?;
        }
    }
    Ok(())
}

fn ignored(signal: Signal) -> io::Result<bool> {
    // SAFETY: all-zero bytes are a valid `sigaction`. A null new action makes `sigaction` only write
    // the current disposition into `current`, which outlives the call.
    let (status, current) = unsafe {
        let mut current: libc::sigaction = std::mem::zeroed();
        let status = libc::sigaction(signal.number(), std::ptr::null(), &mut current);
        (status, current)
    };
    if status != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(current.sa_sigaction == libc::SIG_IGN)
}

fn register(signal: Signal, delivered: &'static Delivered) -> io::Result<()> {
    // SAFETY: the action makes one compare-exchange on a lock-free 32-bit atomic that lives to the
    // process's end, which is async-signal-safe; it takes no lock, allocates nothing and cannot panic,
    // since `Signal::number` is a total match and the exchange's result is dropped.
    unsafe { signal_hook::low_level::register(signal.number(), move || delivered.deliver(signal)) }
        .map(drop)
}
