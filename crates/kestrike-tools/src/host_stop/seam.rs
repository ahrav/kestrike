//! The seam between a command and the system: the call, the wall clock, the monotonic clock and the
//! sleep. [`System`] is the system's; a test implements [`Seam`] with its own clocks and calls.

use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::launch::{Call, Ended, launch};
use super::record::{Interrupted, Record, SLICE, left};

/// The call, the two clocks and the sleep a command takes as one value.
pub trait Seam {
    /// Runs one `aws` call and returns its standard output as text.
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

/// The first call to `System::monotonic` sets the time origin for all `System` instances in the
/// process.
#[derive(Clone, Copy, Debug, Default)]
pub struct System;

impl Seam for System {
    fn call(&mut self, record: &mut Record<'_>, call: &Call<'_>) -> Result<String, Ended> {
        launch(record, call)
    }

    fn wall(&self) -> f64 {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(since) => seconds(since),
            Err(before) => -seconds(before.duration()),
        }
    }

    fn monotonic(&self) -> f64 {
        static ORIGIN: OnceLock<Instant> = OnceLock::new();
        ORIGIN.get_or_init(Instant::now).elapsed().as_secs_f64()
    }

    fn sleep(&mut self, record: &mut Record<'_>, length: Duration) -> Result<(), Interrupted> {
        sleep(record, length)
    }
}

/// For whole seconds, only the cast to `f64` can round the result. For fractional seconds, the
/// nanosecond cast and the division by 1e9 can each round.
fn seconds(since: Duration) -> f64 {
    if since.subsec_nanos() == 0 {
        since.as_secs() as f64
    } else {
        since.as_nanos() as f64 / 1e9
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

#[cfg(test)]
#[path = "seam_tests.rs"]
mod tests;
