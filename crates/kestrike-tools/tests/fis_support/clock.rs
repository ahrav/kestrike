//! [`Clock`], a monotonic clock that a case moves: by a sleep, by the time a reply or a case's wait
//! takes, and by a step at each reading, which is zero until the case sets one.
//!
//! A reading returns the clock's time and then moves it by the step. With no step, a reading at a
//! deadline stays at that deadline, so a loop that leaves only on a reading past its deadline needs a
//! step to end. A sleep, a call and a wait each move the clock through [`Clock::pass`], which reads
//! the signal record before and after the time passes. A signal the case set for a time is delivered
//! once the clock reaches that time, by a reading's step or inside a pass, where the record is read
//! at that time.

use std::cell::{Cell, RefCell};
use std::io;
use std::rc::Rc;
use std::time::Duration;

use kestrike_tools::hardware_host::Clocks;
use kestrike_tools::host_stop::{Delivered, Interrupted, Record, Signal};

/// The wall clock's reading, which the observer log records.
pub(crate) const WALL: f64 = 1_700_000_000.25;

#[derive(Default)]
struct State {
    now: Cell<u64>,
    step: Cell<u64>,
    readings: Cell<usize>,
    failing: Cell<bool>,
    sleeps: RefCell<Vec<Duration>>,
    signal: Cell<Option<(u64, Signal, &'static Delivered)>>,
}

/// A shared clock: each clone reads and moves the same time.
#[derive(Clone, Default)]
pub(crate) struct Clock(Rc<State>);

impl Clock {
    /// A clock at `seconds`.
    pub(crate) fn at(seconds: f64) -> Self {
        let clock = Self::default();
        clock.0.now.set(nanoseconds(seconds));
        clock
    }

    /// Sets the step each later reading moves the clock by.
    pub(crate) fn step(&self, step: Duration) {
        self.0
            .step
            .set(u64::try_from(step.as_nanos()).expect("a step fits"));
    }

    /// Makes each later reading fail with `EIO`.
    pub(crate) fn fail(&self) {
        self.0.failing.set(true);
    }

    /// Delivers `signal` to `delivered` once the clock passes `seconds`.
    pub(crate) fn signal_at(&self, seconds: f64, signal: Signal, delivered: &'static Delivered) {
        self.0
            .signal
            .set(Some((nanoseconds(seconds), signal, delivered)));
    }

    pub(crate) fn now(&self) -> u64 {
        self.0.now.get()
    }

    /// The count of readings so far.
    pub(crate) fn readings(&self) -> usize {
        self.0.readings.get()
    }

    /// The length of each sleep so far.
    pub(crate) fn sleeps(&self) -> Vec<Duration> {
        self.0.sleeps.borrow().clone()
    }

    /// Delivers the signal set for a time the clock has reached.
    fn deliver_due(&self) {
        if let Some((at, signal, delivered)) = self.0.signal.get()
            && at <= self.now()
        {
            self.0.signal.set(None);
            delivered.deliver(signal);
        }
    }

    /// Whether `other` reads and moves this clock's time.
    pub(crate) fn same(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }

    /// Moves the clock by `length`: reads the record, delivers a signal set inside the span when the
    /// clock reaches its time and reads the record there, then moves the rest and reads it again.
    ///
    /// # Errors
    ///
    /// The signal the record raised; the clock stands where the read raised it.
    pub(crate) fn pass(
        &self,
        record: &mut Record<'_>,
        length: Duration,
    ) -> Result<(), Interrupted> {
        record.read()?;
        let length = u64::try_from(length.as_nanos()).unwrap_or(u64::MAX);
        let end = self.now().saturating_add(length);
        if let Some((at, signal, delivered)) = self.0.signal.get().filter(|(at, ..)| *at <= end) {
            self.0.signal.set(None);
            self.0.now.set(at.max(self.now()));
            delivered.deliver(signal);
            record.read()?;
        }
        self.0.now.set(end);
        record.read()
    }
}

impl Clocks for Clock {
    fn monotonic_ns(&self) -> io::Result<u64> {
        self.0.readings.set(self.0.readings.get() + 1);
        if self.0.failing.get() {
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
        let now = self.now();
        self.0.now.set(now.saturating_add(self.0.step.get()));
        self.deliver_due();
        Ok(now)
    }

    fn wall(&self) -> f64 {
        WALL
    }

    fn sleep(&mut self, record: &mut Record<'_>, length: Duration) -> Result<(), Interrupted> {
        self.0.sleeps.borrow_mut().push(length);
        self.pass(record, length)
    }
}

/// `seconds` on the clock, to the nearest nanosecond.
pub(crate) fn nanoseconds(seconds: f64) -> u64 {
    (seconds * 1e9).round() as u64
}
