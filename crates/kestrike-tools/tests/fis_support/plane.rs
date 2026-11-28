//! [`Plane`], the seam of the cases: one clock and one part per effect, each part in a file of its
//! own with its own scripted answers, so the answers of one effect never wait on the order of
//! another's. The calls are [`Calls`], and the case starts take the cases [`Plane::hold`] gives.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::io;
use std::time::Duration;

use kestrike_tools::fis_controller::{Launch, Seam};
use kestrike_tools::host_stop::{Interrupted, Record};
use kestrike_tools::json::Value;

use super::calls::{Calls, Reply};
use super::case::Case;
use super::clock::Clock;

pub(crate) struct Plane {
    pub(crate) clock: Clock,
    pub(crate) calls: Calls,
    cases: VecDeque<Case>,
    /// The words of each case started, in order.
    pub(crate) starts: Vec<Vec<String>>,
}

impl Plane {
    pub(crate) fn new(clock: Clock, replies: Vec<Reply>) -> Self {
        Self {
            clock,
            calls: Calls::new(replies),
            cases: VecDeque::new(),
            starts: Vec::new(),
        }
    }

    /// Adds a case the next start hands out.
    pub(crate) fn hold(&mut self, case: Case) {
        self.cases.push_back(case);
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

    /// Hands out the next case held, or fails with `ENOENT` where none is held.
    fn start(&mut self, launch: &Launch<'_>) -> io::Result<Case> {
        self.starts.push(
            launch
                .words
                .iter()
                .map(|word| word.to_string_lossy().into_owned())
                .collect(),
        );
        self.cases
            .pop_front()
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))
    }
}
