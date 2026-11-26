//! A scripted physical-clock provider for tests: it hands out queued readings in order, repeats the last one once the queue is spent, and reads untrusted with [`Untrusted::NoSnapshot`] until a reading is queued.
//!
//! A test keeps the [`ClockScript`] handle to queue readings, count reads and record, at each read, a value an observer returns, such as the number of monotonic samples a test platform handed out, which orders the reading against those samples.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use super::clock::{ClockScale, PhysicalClock, Reading, Trust, Untrusted};

type Observer = Box<dyn Fn() -> usize + Send>;

/// The earliest bound of [`ScriptedClock::trusted`]'s reading: 2023-11-14T22:13:20Z in nanoseconds since the Unix epoch.
pub(crate) const TEST_EARLIEST: u64 = 1_700_000_000_000_000_000;

#[derive(Default)]
struct Script {
    queue: VecDeque<Reading>,
    last: Option<Reading>,
    observer: Option<Observer>,
    observed: Vec<usize>,
}

/// The shared handle to a [`ScriptedClock`]'s script.
#[derive(Clone, Default)]
pub(crate) struct ClockScript(Arc<Mutex<Script>>);

impl ClockScript {
    /// Appends `readings` to the queue.
    pub(crate) fn queue(&self, readings: &[Reading]) {
        self.0
            .lock()
            .unwrap()
            .queue
            .extend(readings.iter().copied());
    }

    /// Queues one trusted reading `[earliest, latest]`.
    pub(crate) fn trusted(&self, earliest: u64, latest: u64) {
        self.queue(&[Reading {
            earliest,
            latest,
            trust: Trust::Trusted,
        }]);
    }

    /// Records `observer`'s value at every later read.
    pub(crate) fn observe(&self, observer: impl Fn() -> usize + Send + 'static) {
        self.0.lock().unwrap().observer = Some(Box::new(observer));
    }

    /// The observer's value at each read since [`observe`](Self::observe), in read order.
    pub(crate) fn observed(&self) -> Vec<usize> {
        self.0.lock().unwrap().observed.clone()
    }
}

/// A provider that reads its [`ClockScript`] on its own scale.
pub(crate) struct ScriptedClock(ClockScript, ClockScale);

impl ScriptedClock {
    /// A boxed provider on [`ClockScale::UtcSmeared`] with an empty script, and the script's handle.
    pub(crate) fn with_script() -> (Box<dyn PhysicalClock>, ClockScript) {
        Self::on(ClockScale::UtcSmeared)
    }

    /// A boxed provider on `scale` with an empty script, and the script's handle.
    pub(crate) fn on(scale: ClockScale) -> (Box<dyn PhysicalClock>, ClockScript) {
        let script = ClockScript::default();
        (Box::new(Self(script.clone(), scale)), script)
    }

    /// A boxed provider whose script stays empty, so every reading is untrusted.
    pub(crate) fn untrusted() -> Box<dyn PhysicalClock> {
        Self::with_script().0
    }

    /// A boxed provider that reads `[TEST_EARLIEST, TEST_EARLIEST + 2 ms]`, trusted, on every read.
    pub(crate) fn trusted() -> Box<dyn PhysicalClock> {
        let (clock, script) = Self::with_script();
        script.trusted(TEST_EARLIEST, TEST_EARLIEST + 2_000_000);
        clock
    }
}

impl super::clock::sealed::Sealed for ScriptedClock {}

impl PhysicalClock for ScriptedClock {
    fn scale(&self) -> ClockScale {
        self.1
    }

    fn read(&mut self) -> Reading {
        let mut script = self.0.0.lock().unwrap();
        if let Some(value) = script.observer.as_ref().map(|observer| observer()) {
            script.observed.push(value);
        }
        if let Some(reading) = script.queue.pop_front() {
            script.last = Some(reading);
        }
        script
            .last
            .unwrap_or(Reading::untrusted(Untrusted::NoSnapshot))
    }
}
