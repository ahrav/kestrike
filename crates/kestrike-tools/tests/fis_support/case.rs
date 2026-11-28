//! [`Case`], a lane's case whose end the test sets: at once, at a time on the plane's clock, or a
//! delay after SIGTERM. A wait moves the clock to the end where it comes within the bound, else by
//! the whole bound. A signal is sent, and logged, only to a case that runs: SIGTERM ends it where the
//! test set a close after SIGTERM, unless an earlier end stands, and SIGKILL ends it with `-9` at once, which no later end
//! changes.

use std::cell::{Cell, RefCell};
use std::io;
use std::rc::Rc;
use std::time::Duration;

use kestrike_tools::fis_controller::{self, Failure};
use kestrike_tools::host_stop::Record;

use super::clock::{Clock, nanoseconds};

#[derive(Default)]
struct State {
    code: Cell<Option<i32>>,
    ends_at: Cell<Option<(u64, i32)>>,
    closes: Cell<Option<(u64, i32)>>,
    signals: RefCell<Vec<&'static str>>,
}

/// The case a plane hands out.
pub(crate) struct Case {
    clock: Clock,
    state: Rc<State>,
}

/// The test's hold on a case: it sets the end and reads the signals sent.
#[derive(Clone)]
pub(crate) struct Handle(Rc<State>);

impl Case {
    pub(crate) fn new(clock: Clock) -> (Self, Handle) {
        let state = Rc::new(State::default());
        (
            Self {
                clock,
                state: Rc::clone(&state),
            },
            Handle(state),
        )
    }

    pub(crate) fn clock(&self) -> &Clock {
        &self.clock
    }

    /// The case's code, once it ended; an end set for a time the clock reached takes effect here.
    fn settled(&self) -> Option<i32> {
        let now = self.clock.now();
        if self.state.code.get().is_none()
            && let Some((_, code)) = self.state.ends_at.get().filter(|(at, _)| *at <= now)
        {
            self.state.code.set(Some(code));
        }
        self.state.code.get()
    }
}

impl Handle {
    /// Ends the case now with `code`, where it has not ended.
    pub(crate) fn end(&self, code: i32) {
        if self.0.code.get().is_none() {
            self.0.code.set(Some(code));
        }
    }

    /// Ends the case with `code` `seconds` after a SIGTERM reaches it.
    pub(crate) fn close_on_sigterm(&self, seconds: f64, code: i32) {
        self.0.closes.set(Some((nanoseconds(seconds), code)));
    }

    /// Ends the case with `code` once the clock reaches `seconds`.
    pub(crate) fn end_at(&self, seconds: f64, code: i32) {
        self.0.ends_at.set(Some((nanoseconds(seconds), code)));
    }

    pub(crate) fn signals(&self) -> Vec<&'static str> {
        self.0.signals.borrow().clone()
    }
}

impl fis_controller::Case for Case {
    fn ended(&mut self) -> io::Result<Option<i32>> {
        Ok(self.settled())
    }

    fn wait(&mut self, record: &mut Record<'_>, bound: Duration) -> Result<Option<i32>, Failure> {
        if let Some(code) = self.settled() {
            return Ok(Some(code));
        }
        let bound_ns = u64::try_from(bound.as_nanos()).unwrap_or(u64::MAX);
        let span = match self.state.ends_at.get() {
            Some((at, _)) if at.saturating_sub(self.clock.now()) <= bound_ns => {
                Duration::from_nanos(at.saturating_sub(self.clock.now()))
            }
            _ => bound,
        };
        self.clock.pass(record, span)?;
        Ok(self.settled())
    }

    fn terminate(&mut self) -> io::Result<()> {
        if self.settled().is_none() {
            self.state.signals.borrow_mut().push("SIGTERM");
            if let Some((delay, code)) = self.state.closes.take() {
                let at = self.clock.now().saturating_add(delay);
                let earlier = self.state.ends_at.get().filter(|(end, _)| *end <= at);
                self.state.ends_at.set(Some(earlier.unwrap_or((at, code))));
            }
        }
        Ok(())
    }

    fn kill(&mut self, record: &mut Record<'_>) -> Result<i32, Failure> {
        if self.settled().is_none() {
            self.state.signals.borrow_mut().push("SIGKILL");
            self.state.code.set(Some(-9));
        }
        record.read()?;
        Ok(self.settled().unwrap_or(-9))
    }
}
