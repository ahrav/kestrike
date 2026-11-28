//! [`Plane`], the seam of the cases: one clock and one part per effect, each part in a file of its
//! own with its own scripted answers, so the answers of one effect never wait on the order of
//! another's. The calls are [`Calls`] and the case starts [`Starts`]; an effect a later phase adds is
//! a part of its own, one field here and one method of the seam's impl.

use std::ffi::OsString;
use std::io;
use std::time::Duration;

use kestrike_tools::fis_controller::{Launch, Seam};
use kestrike_tools::host_stop::{Interrupted, Record};
use kestrike_tools::json::Value;

use super::calls::{Calls, Reply};
use super::case::Case;
use super::clock::Clock;
use super::starts::Starts;

#[derive(Default)]
pub(crate) struct Plane {
    pub(crate) clock: Clock,
    pub(crate) calls: Calls,
    pub(crate) starts: Starts,
}

impl Plane {
    /// A plane on `clock` whose calls take `replies` in order.
    pub(crate) fn new(clock: Clock, replies: Vec<Reply>) -> Self {
        Self {
            clock,
            calls: Calls::new(replies),
            ..Self::default()
        }
    }

    /// Adds a case the next start hands out.
    pub(crate) fn hold(&mut self, case: Case) {
        self.starts.hold(&self.clock, case);
    }
}

impl Seam for Plane {
    type Clocks = Clock;
    type Case = Case;

    fn call(
        &mut self,
        record: &mut Record<'_>,
        words: &[OsString],
        limit: Duration,
    ) -> Result<Option<Value>, Interrupted> {
        self.calls.call(&self.clock, record, words, limit)
    }

    fn clocks(&mut self) -> &mut Clock {
        &mut self.clock
    }

    fn start(&mut self, launch: &Launch<'_>) -> io::Result<Case> {
        self.starts.start(launch)
    }
}
