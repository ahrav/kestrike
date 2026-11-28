//! The seam a phase takes: the call, the clocks with their sleep, and the lane's case. A phase reaches
//! the system through one [`Seam`] value and its [`Case`], so a test passes its own plane, clock and
//! case.

use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::time::Duration;

use super::failure::Failure;
use crate::hardware_host::{Clocks, Reservation};
use crate::host_stop::{Interrupted, Record};
use crate::json::Value;

/// The call, the clocks and the case's start.
pub trait Seam {
    type Clocks: Clocks;
    type Case: Case;

    /// Makes one AWS call of `words`, the arguments after the command, the service and the operation
    /// first, within `limit`, and returns its decoded reply, or none for a call that ended without
    /// one: a failed start, a nonzero exit, an output that is no JSON value, or the limit reached.
    ///
    /// # Errors
    ///
    /// The signal an armed record raised during the call.
    fn call(
        &mut self,
        record: &mut Record<'_>,
        words: &[OsString],
        limit: Duration,
    ) -> Result<Option<Value>, Interrupted>;

    /// The clocks and the sleep.
    fn clocks(&mut self) -> &mut Self::Clocks;

    /// Starts the lane's case as `launch` describes it.
    ///
    /// # Errors
    ///
    /// The error of the start.
    fn start(&mut self, launch: &Launch<'_>) -> io::Result<Self::Case>;
}

/// What the case's start takes: its words, the variables added to the environment, the open log
/// that takes its standard output and standard error, and the host reservation it inherits, where
/// the controller holds one.
#[derive(Debug)]
pub struct Launch<'a> {
    pub words: &'a [OsString],
    pub environment: &'a [(OsString, OsString)],
    pub log: &'a File,
    pub reservation: Option<&'a Reservation>,
}

/// The lane's started case. An exit code is Python's: the status a case exited with, or the negated
/// number of the signal that ended it.
pub trait Case {
    /// The exit code of a case that ended, or none while it runs; the call does not block.
    ///
    /// # Errors
    ///
    /// The error of the check.
    fn ended(&mut self) -> io::Result<Option<i32>>;

    /// Waits up to `bound` for the case's end and returns its exit code, or none when the bound
    /// passed first.
    ///
    /// # Errors
    ///
    /// The wait's system error, and the signal an armed record raised during it.
    fn wait(&mut self, record: &mut Record<'_>, bound: Duration) -> Result<Option<i32>, Failure>;

    /// Sends SIGTERM to a case that has not been reaped.
    ///
    /// # Errors
    ///
    /// The error of the signal.
    fn terminate(&mut self) -> io::Result<()>;

    /// Sends SIGKILL to a case that has not been reaped, then waits for its end with no bound and
    /// returns its exit code.
    ///
    /// # Errors
    ///
    /// The kill's or the wait's system error, and the signal an armed record raised during the wait.
    fn kill(&mut self, record: &mut Record<'_>) -> Result<i32, Failure>;
}
