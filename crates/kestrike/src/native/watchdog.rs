//! The teardown and recovery watchdogs and the supervisor they escalate to.
//!
//! A teardown step is a native call that can stall while the device still
//! reaches memory, and the device can keep reaching it after the process
//! exits. The stalled call stays in place and its memory stays held: at
//! expiry the watchdog asks the [`Supervisor`] to fence the endpoint and
//! reset the device or host, and marks itself expired so the teardown skips
//! every later step and keeps the memory held.
//!
//! One worker loop decides disarm against expiry under the state's mutex:
//! a disarm that acquires the lock before expiry commits the worker to
//! skip containment, and an expiry decided under the lock is published
//! before the lock is released and the supervisor runs, so containment
//! entry always sees the watchdog expired. The loop's time source and timed
//! wait are one [`Timer`] bound when the worker starts.
//!
//! In-place recovery reuses one worker across its episodes through
//! [`Rearmable`]: the worker starts idle, each episode's arm stamps its start
//! instant under the lock and wakes the worker, and each disarm clears the
//! stamp under the lock. The worker contains at most once; after an expiry it
//! ends and every later arm is refused.

use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// The process supervisor, which can fence this endpoint and reset its
/// devices or host. [`contain`](Self::contain) runs on the watchdog's thread
/// when a teardown missed its deadline, possibly while the owner thread is
/// still inside a stalled call, so `contain` works only with state shared
/// across threads. Dropping the watchdog waits for `contain` to return, so the
/// owner thread stays parked until the supervisor has acted on the request.
pub trait Supervisor: Send + Sync {
    fn contain(&self);

    /// Whether the supervisor observed the containment it was asked for take
    /// effect; a supervisor that observes no such proof reports `false`.
    fn verified(&self) -> bool {
        false
    }
}

/// The worker's time source and timed wait, shared by the owner and the
/// worker. `now` is a reading on the timer's own clock, and a deadline runs
/// from the reading its arm took. The owner reads `now` to stamp an arm,
/// and the worker calls both methods with the state lock held; `wait` is
/// the one point that releases it.
pub(crate) trait Timer: Send + Sync + 'static {
    fn now(&self) -> Duration;

    /// Waits on `wake` for up to `timeout`, releasing `state` meanwhile and
    /// returning it relocked; a wake before the timeout returns early.
    fn wait<'a>(
        &self,
        state: MutexGuard<'a, State>,
        wake: &Condvar,
        timeout: Duration,
    ) -> MutexGuard<'a, State>;
}

// the production timer: elapsed since the worker's start, over `Condvar::wait_timeout`
struct Monotonic(Instant);

impl Timer for Monotonic {
    fn now(&self) -> Duration {
        self.0.elapsed()
    }

    fn wait<'a>(
        &self,
        state: MutexGuard<'a, State>,
        wake: &Condvar,
        timeout: Duration,
    ) -> MutexGuard<'a, State> {
        wake.wait_timeout(state, timeout)
            .unwrap_or_else(PoisonError::into_inner)
            .0
    }
}

/// The watchdog's locked state: `done` once dropped, `expired` once the
/// worker decided expiry, and `armed`, the instant on the timer's clock the
/// running deadline started, `None` while the worker idles.
#[derive(Default)]
pub(crate) struct State {
    done: bool,
    expired: bool,
    armed: Option<Duration>,
}

/// The state and the condvar the owner uses to wake the worker, shared
/// between the [`Watchdog`] and its thread.
pub(crate) type Shared = Arc<(Mutex<State>, Condvar)>;

/// A deadline over one teardown. Dropping it disarms it.
pub struct Watchdog {
    shared: Shared,
    timer: Arc<dyn Timer>,
    thread: Option<JoinHandle<()>>,
}

impl Watchdog {
    /// Starts the deadline. At expiry, unless disarmed first, it marks
    /// itself expired and calls `supervisor`.
    ///
    /// # Errors
    ///
    /// The OS error when the watchdog thread cannot start.
    pub fn arm(deadline: Duration, supervisor: Arc<dyn Supervisor>) -> std::io::Result<Self> {
        Self::arm_with(deadline, supervisor, Monotonic(Instant::now()))
    }

    /// [`arm`](Self::arm) over `timer`, whose clock the deadline is measured
    /// on and whose wait the worker blocks in.
    ///
    /// # Errors
    ///
    /// The OS error when the watchdog thread cannot start.
    pub(crate) fn arm_with(
        deadline: Duration,
        supervisor: Arc<dyn Supervisor>,
        timer: impl Timer,
    ) -> std::io::Result<Self> {
        Self::start(
            "teardown-watchdog",
            deadline,
            supervisor,
            Arc::new(timer),
            true,
        )
    }

    /// Spawns the worker thread `name`. With `armed`, the deadline starts at
    /// the timer's current reading; otherwise the worker idles until a
    /// rearm.
    fn start(
        name: &str,
        deadline: Duration,
        supervisor: Arc<dyn Supervisor>,
        timer: Arc<dyn Timer>,
        armed: bool,
    ) -> std::io::Result<Self> {
        let state = State {
            armed: armed.then(|| timer.now()),
            ..State::default()
        };
        let shared: Shared = Arc::new((Mutex::new(state), Condvar::new()));
        let watched = Arc::clone(&shared);
        let clock = Arc::clone(&timer);
        let thread = thread::Builder::new()
            .name(name.into())
            .spawn(move || run(&watched, deadline, &*clock, &*supervisor))?;
        Ok(Self {
            shared,
            timer,
            thread: Some(thread),
        })
    }

    /// Whether the worker decided expiry: the deadline passed on its clock
    /// before a disarm reached it.
    pub fn expired(&self) -> bool {
        expired(&self.shared)
    }

    /// The state the worker decides under, for a test's supervisor to read
    /// at containment entry, and a wake of the worker's wait.
    #[cfg(test)]
    pub(crate) fn shared(&self) -> Shared {
        Arc::clone(&self.shared)
    }
}

/// One watchdog worker that every recovery episode reuses by rearming its
/// deadline. It runs [`Watchdog`]'s worker loop and contains at most once.
/// Dropping it ends the worker after any containment the worker entered
/// returns.
pub(crate) struct Rearmable(Watchdog);

impl Rearmable {
    /// A worker of `deadline` over `supervisor` that idles until
    /// [`rearm`](Self::rearm) starts a deadline.
    ///
    /// # Errors
    ///
    /// The OS error when the watchdog thread cannot start.
    pub(crate) fn idle(
        deadline: Duration,
        supervisor: Arc<dyn Supervisor>,
    ) -> std::io::Result<Self> {
        let timer = Arc::new(Monotonic(Instant::now()));
        Watchdog::start("recovery-watchdog", deadline, supervisor, timer, false).map(Self)
    }

    #[cfg(test)]
    pub(crate) fn idle_with(
        deadline: Duration,
        supervisor: Arc<dyn Supervisor>,
        timer: impl Timer,
    ) -> std::io::Result<Self> {
        let timer = Arc::new(timer);
        Watchdog::start("recovery-watchdog", deadline, supervisor, timer, false).map(Self)
    }

    /// Starts a deadline at the timer's current reading, wakes the worker to
    /// time it, and returns `true`. After the worker decides expiry, `rearm`
    /// returns `false` and the state stays expired.
    ///
    /// # Panics
    ///
    /// - In debug builds, if a deadline is running: each rearm follows a
    ///   [`disarm`](Self::disarm).
    pub(crate) fn rearm(&self) -> bool {
        let (lock, wake) = &*self.0.shared;
        let mut state = lock.lock().unwrap_or_else(PoisonError::into_inner);
        if state.expired {
            return false;
        }
        debug_assert!(state.armed.is_none(), "each rearm follows a disarm");
        state.armed = Some(self.0.timer.now());
        drop(state);
        wake.notify_all();
        true
    }

    /// Ends the running deadline and returns whether the worker decided
    /// expiry first. After an expiry it joins the worker, so the supervisor's
    /// containment has ended by its return or its unwind; otherwise the
    /// worker idles until the next [`rearm`](Self::rearm).
    pub(crate) fn disarm(&mut self) -> bool {
        let expired = {
            let mut state = self
                .0
                .shared
                .0
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            state.armed = None;
            state.expired
        };
        if expired && let Some(thread) = self.0.thread.take() {
            let _ = thread.join();
        }
        expired
    }

    /// Whether the worker decided expiry, which it does at most once.
    pub(crate) fn expired(&self) -> bool {
        self.0.expired()
    }

    #[cfg(test)]
    pub(crate) fn shared(&self) -> Shared {
        self.0.shared()
    }
}

/// Reads `expired` under the lock, so a read after the worker released the
/// lock to run the supervisor sees the expiry.
pub(crate) fn expired(shared: &Shared) -> bool {
    shared
        .0
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .expired
}

/// The worker: waits under the lock until dropped or a running deadline
/// passes on `timer`'s clock, rechecking both after every wake, spurious
/// ones included. While idle it waits for the wake of the next arm. A drop
/// seen under the lock ends the worker. An expiry is recorded under the
/// lock, then the lock is released and the supervisor runs once.
fn run(shared: &Shared, deadline: Duration, timer: &dyn Timer, supervisor: &dyn Supervisor) {
    let (lock, wake) = &**shared;
    let mut state = lock.lock().unwrap_or_else(PoisonError::into_inner);
    loop {
        if state.done {
            return;
        }
        let timeout = match state.armed {
            // `Condvar::wait_timeout` treats a timeout beyond the clock's range as infinite.
            None => Duration::MAX,
            Some(at) => {
                let elapsed = timer.now().saturating_sub(at);
                if elapsed >= deadline {
                    break;
                }
                deadline - elapsed
            }
        };
        state = timer.wait(state, wake, timeout);
    }
    state.expired = true;
    drop(state);
    supervisor.contain();
}

impl Drop for Watchdog {
    /// Dropping `Watchdog` disarms under the lock, wakes the worker and
    /// joins it, so a containment the worker entered runs to its return
    /// before the drop returns.
    fn drop(&mut self) {
        let (lock, wake) = &*self.shared;
        lock.lock().unwrap_or_else(PoisonError::into_inner).done = true;
        wake.notify_all();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
#[path = "watchdog_rearm_tests.rs"]
mod rearm_tests;
