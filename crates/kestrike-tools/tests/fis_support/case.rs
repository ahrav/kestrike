//! [`Case`], a lane's case whose end the test sets: at once, or at a time on the plane's clock. A wait
//! moves the clock to the end where it comes within the bound, else by the whole bound. SIGTERM is
//! logged and changes nothing; SIGKILL ends a running case with `-9`.

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

    fn settled(&self) -> Option<i32> {
        let now = self.clock.now();
        if let Some((_, code)) = self.state.ends_at.get().filter(|(at, _)| *at <= now) {
            self.state.code.set(Some(code));
            self.state.ends_at.set(None);
        }
        self.state.code.get()
    }
}

impl Handle {
    /// Ends the case now with `code`.
    pub(crate) fn end(&self, code: i32) {
        self.0.code.set(Some(code));
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
        self.state.signals.borrow_mut().push("SIGTERM");
        Ok(())
    }

    fn kill(&mut self, record: &mut Record<'_>) -> Result<i32, Failure> {
        self.state.signals.borrow_mut().push("SIGKILL");
        record.read()?;
        let code = self.settled().unwrap_or(-9);
        self.state.code.set(Some(code));
        Ok(code)
    }
}
