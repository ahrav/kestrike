//! The seam between a command and the system: the call, the wall clock, the monotonic clock and the
//! sleep. [`System`] is the system's; a test implements [`Seam`] with its own clocks and calls.

use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::launch::{Call, Ended, launch};
use super::record::{Interrupted, Record, SLICE, left};

/// The call, the two clocks and the sleep a command takes as one value.
pub trait Seam {
    /// Runs one `aws` call and returns its standard output.
    ///
    /// # Errors
    ///
    /// [`Ended`] names a failed call or a signal the record raised during it.
    fn call(&mut self, record: &mut Record<'_>, call: &Call<'_>) -> Result<String, Ended>;

    /// Seconds since the epoch on the wall clock, which counts a suspend and can step back.
    fn wall(&self) -> f64;

    /// Seconds on the monotonic clock, which stands still in a suspend and never steps back.
    fn monotonic(&self) -> f64;

    /// Sleeps `length` on the monotonic clock.
    ///
    /// # Errors
    ///
    /// A signal the record raised during the sleep.
    fn sleep(&mut self, record: &mut Record<'_>, length: Duration) -> Result<(), Interrupted>;
}

/// The system's seam: [`launch`], [`SystemTime`] and [`Instant`], which reads `CLOCK_MONOTONIC`. Its
/// monotonic clock counts from the value's creation.
#[derive(Clone, Copy, Debug)]
pub struct System {
    origin: Instant,
}

impl System {
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for System {
    fn default() -> Self {
        Self::new()
    }
}

impl Seam for System {
    fn call(&mut self, record: &mut Record<'_>, call: &Call<'_>) -> Result<String, Ended> {
        launch(record, call)
    }

    fn wall(&self) -> f64 {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(since) => since.as_secs_f64(),
            Err(before) => -before.duration().as_secs_f64(),
        }
    }

    fn monotonic(&self) -> f64 {
        self.origin.elapsed().as_secs_f64()
    }

    fn sleep(&mut self, record: &mut Record<'_>, length: Duration) -> Result<(), Interrupted> {
        sleep(record, length)
    }
}

/// Sleeps `length` on the monotonic clock in slices of at most [`SLICE`], reading the record before
/// the first slice and at the end of each, and ends after the full length or at the read that
/// raises.
///
/// # Errors
///
/// A signal the record raised.
pub fn sleep(record: &mut Record<'_>, length: Duration) -> Result<(), Interrupted> {
    let end = Instant::now().checked_add(length);
    loop {
        record.read()?;
        let left = left(end);
        if left.is_zero() {
            return Ok(());
        }
        thread::sleep(left.min(SLICE));
    }
}
