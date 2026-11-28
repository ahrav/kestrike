//! The deadline rules of an episode, on the monotonic clock in seconds, which stands still in a
//! suspend and never steps back.
//!
//! - [`Deadlines::window`]: one reading plus the seconds given, cut at the run's deadline while one is
//!   set.
//! - [`Deadlines::nap`]: the limit starts at the poll's seconds; for each deadline given and then for
//!   the run's deadline, where set, one reading, and the limit becomes the lesser of itself and the time
//!   left, never under zero; then one sleep of the limit. An armed record ends the sleep with the
//!   signal it raises; an unarmed one lets the sleep run its length.
//! - [`Deadlines::limit`]: the limit of one call starts at the call's seconds and is cut the same way
//!   at the phase's deadline and then the run's, with no floor; a limit of zero or less makes no call,
//!   which reads as no reply.
//!
//! A deadline is an absolute reading, so a retry within a window keeps the window's end. A reading is
//! [`seconds`] of the clock's nanoseconds, and a sleep's or a call's length is [`duration`] of its
//! seconds.

use std::ffi::OsString;
use std::time::Duration;

use super::failure::{Failure, SystemError};
use super::seam::Seam;
use crate::hardware_host::Clocks;
use crate::host_stop::Record;
use crate::json::Value;
use crate::text::Text;

/// The poll's and the call's seconds, and the run's deadline while the run's phases are under way.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Deadlines {
    poll: f64,
    call: f64,
    run: Option<f64>,
}

impl Deadlines {
    /// The rules for a poll of `poll` seconds and calls of `call` seconds, with no run deadline.
    ///
    /// # Errors
    ///
    /// [`Failure::Refused`] for a `poll` that is not finite and above zero, or a `call` that is not
    /// finite.
    pub fn new(poll: f64, call: f64) -> Result<Self, Failure> {
        if !(poll.is_finite() && poll > 0.0) {
            return Err(Failure::Refused(Text::from(format!(
                "the poll of {poll} s is no finite duration above zero"
            ))));
        }
        if !call.is_finite() {
            return Err(Failure::Refused(Text::from(format!(
                "the call's {call} s is no finite duration"
            ))));
        }
        Ok(Self {
            poll,
            call,
            run: None,
        })
    }

    pub fn poll(&self) -> f64 {
        self.poll
    }

    pub fn call(&self) -> f64 {
        self.call
    }

    /// The run's deadline, while one is set.
    pub fn run(&self) -> Option<f64> {
        self.run
    }

    /// Sets or clears the run's deadline.
    pub fn set_run(&mut self, deadline: Option<f64>) {
        self.run = deadline;
    }

    /// The end of a window of `length` seconds from one reading, cut at the run's deadline.
    ///
    /// # Errors
    ///
    /// The reading's system error.
    pub fn window(&self, clocks: &impl Clocks, length: f64) -> Result<f64, Failure> {
        let deadline = now(clocks)? + length;
        Ok(match self.run {
            Some(run) if run < deadline => run,
            _ => deadline,
        })
    }

    /// Sleeps one poll, cut at the earliest of `deadlines` and the run's deadline.
    ///
    /// # Errors
    ///
    /// A reading's system error, before any sleep; the signal an armed record raised in the sleep.
    pub fn nap(
        &self,
        clocks: &mut impl Clocks,
        record: &mut Record<'_>,
        deadlines: &[Option<f64>],
    ) -> Result<(), Failure> {
        let mut limit = self.poll;
        for deadline in deadlines.iter().chain([&self.run]).flatten() {
            let left = deadline - now(clocks)?;
            let left = if 0.0 > left { 0.0 } else { left };
            if left < limit {
                limit = left;
            }
        }
        clocks.sleep(record, duration(limit))?;
        Ok(())
    }

    /// The limit of one call cut at `deadline` and the run's deadline, or none where it is zero or
    /// less.
    ///
    /// # Errors
    ///
    /// A reading's system error.
    pub fn limit(
        &self,
        clocks: &impl Clocks,
        deadline: Option<f64>,
    ) -> Result<Option<Duration>, Failure> {
        let mut limit = self.call;
        for cut in [deadline, self.run].into_iter().flatten() {
            let left = cut - now(clocks)?;
            if left < limit {
                limit = left;
            }
        }
        Ok((limit > 0.0).then(|| duration(limit)))
    }
}

/// Makes one call of `words` through `seam` under [`Deadlines::limit`] at `deadline`: none without a
/// call where the limit is zero or less, else the seam's reply or none.
///
/// # Errors
///
/// A reading's system error, and the signal the record raised during the call.
pub fn call(
    seam: &mut impl Seam,
    deadlines: &Deadlines,
    record: &mut Record<'_>,
    words: &[OsString],
    deadline: Option<f64>,
) -> Result<Option<Value>, Failure> {
    let Some(limit) = deadlines.limit(seam.clocks(), deadline)? else {
        return Ok(None);
    };
    Ok(seam.call(record, words, limit)?)
}

/// One reading of the monotonic clock in seconds.
///
/// # Errors
///
/// The reading's system error.
pub fn now(clocks: &impl Clocks) -> Result<f64, Failure> {
    clocks
        .monotonic_ns()
        .map(seconds)
        .map_err(|error| Failure::System(SystemError::of(&error, &[])))
}

/// `nanoseconds` in seconds: a whole count of seconds converts exactly, and any other count is divided
/// by 1e9 after its conversion to `f64`, each step rounding to the nearest double.
pub fn seconds(nanoseconds: u64) -> f64 {
    const NANOSECONDS: u64 = 1_000_000_000;
    if nanoseconds.is_multiple_of(NANOSECONDS) {
        (nanoseconds / NANOSECONDS) as f64
    } else {
        nanoseconds as f64 / 1e9
    }
}

/// `seconds`, at least zero, as a length: the product with 1e9 as a double, rounded up to a whole
/// nanosecond. A length past the range of `u64` nanoseconds is [`Duration::MAX`]; zero, a negative
/// value and NaN give zero.
pub fn duration(seconds: f64) -> Duration {
    let nanoseconds = (seconds * 1e9).ceil();
    if nanoseconds.is_nan() || nanoseconds <= 0.0 {
        return Duration::ZERO;
    }
    if nanoseconds >= 18_446_744_073_709_551_616.0 {
        return Duration::MAX;
    }
    Duration::from_nanos(nanoseconds as u64)
}
