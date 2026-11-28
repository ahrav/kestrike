//! [`Clocks`] lets a test supply fixed clock readings and its own sleep.

use std::io;
use std::time::Duration;

use crate::host_stop::{self, Interrupted, Record, Seam};

/// The two clock readings and the sleep; [`System`] is the system's.
pub trait Clocks {
    /// `CLOCK_MONOTONIC` in whole nanoseconds. The clock pauses during a suspend and never steps back,
    /// and the processes of one time namespace read the same clock; a time namespace can offset it.
    ///
    /// # Errors
    ///
    /// The error of `clock_gettime`, or a reading past the range of `u64`.
    fn monotonic_ns(&self) -> io::Result<u64>;

    /// Seconds since the epoch on the wall clock, which counts a suspend and can step back.
    fn wall(&self) -> f64;

    /// Sleeps `length` on the monotonic clock, reading `record` at least once a
    /// [`SLICE`](host_stop::SLICE).
    ///
    /// # Errors
    ///
    /// The signal the record raised.
    fn sleep(&mut self, record: &mut Record<'_>, length: Duration) -> Result<(), Interrupted>;
}

/// The system's clocks, and the sleep of [`host_stop::sleep`].
#[derive(Clone, Copy, Debug, Default)]
pub struct System;

impl Clocks for System {
    fn monotonic_ns(&self) -> io::Result<u64> {
        monotonic_ns()
    }

    fn wall(&self) -> f64 {
        host_stop::System.wall()
    }

    fn sleep(&mut self, record: &mut Record<'_>, length: Duration) -> Result<(), Interrupted> {
        host_stop::sleep(record, length)
    }
}

fn monotonic_ns() -> io::Result<u64> {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `now` is a valid, writable `timespec` that outlives the call, and `clock_gettime` writes
    // only that struct.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let outside = || io::Error::other("the monotonic clock reads outside the range of u64");
    let seconds = u64::try_from(now.tv_sec).map_err(|_| outside())?;
    let nanoseconds = u64::try_from(now.tv_nsec).map_err(|_| outside())?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|whole| whole.checked_add(nanoseconds))
        .ok_or_else(outside)
}

#[cfg(test)]
#[path = "clock_tests.rs"]
mod tests;
