//! With debug assertions, a rearm of a worker whose deadline is running and unexpired panics with
//! `each rearm follows a disarm`; a rearm after a disarm starts a deadline.

#![cfg(debug_assertions)]

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, MutexGuard, PoisonError};
use std::time::Duration;

use super::{Rearmable, State, Supervisor, Timer};

/// Counts the containments the worker asks for.
#[derive(Default)]
struct Counting(AtomicUsize);

impl Supervisor for Counting {
    fn contain(&self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// A clock that stands at one reading, so a deadline above zero keeps running, with an untimed wait.
struct Stopped(Duration);

impl Timer for Stopped {
    fn now(&self) -> Duration {
        self.0
    }

    fn wait<'a>(
        &self,
        state: MutexGuard<'a, State>,
        wake: &Condvar,
        _timeout: Duration,
    ) -> MutexGuard<'a, State> {
        wake.wait(state).unwrap_or_else(PoisonError::into_inner)
    }
}

/// The deadline's start as the worker's state holds it.
fn armed(watchdog: &Rearmable) -> Option<Duration> {
    watchdog
        .shared()
        .0
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .armed
}

/// A second `rearm` while the first deadline runs unexpired panics, naming the rule that each rearm follows a
/// disarm: a rearm in place would restart the deadline of an episode still under way. After a disarm the same call
/// starts a deadline. The clock stands still, so no deadline passes and the supervisor never runs.
#[test]
fn a_rearm_while_a_deadline_runs_panics_and_a_rearm_after_a_disarm_does_not() {
    let supervisor = Arc::new(Counting::default());
    let at = Duration::from_secs(5);
    let mut watchdog =
        Rearmable::idle_with(Duration::from_secs(3600), supervisor.clone(), Stopped(at)).unwrap();
    assert_eq!(armed(&watchdog), None, "the worker starts idle");

    assert!(watchdog.rearm(), "the first rearm starts a deadline");
    assert_eq!(armed(&watchdog), Some(at));
    assert!(!watchdog.expired());

    let second = catch_unwind(AssertUnwindSafe(|| watchdog.rearm()));
    let message = second.expect_err("a rearm while a deadline runs panics under debug assertions");
    let text = message
        .downcast_ref::<&str>()
        .map(|text| (*text).to_owned())
        .or_else(|| message.downcast_ref::<String>().cloned())
        .unwrap_or_default();
    assert!(
        text.contains("each rearm follows a disarm"),
        "the panic names the rule: {text}"
    );
    assert!(!watchdog.expired());

    assert!(!watchdog.disarm(), "the worker decided no expiry");
    assert_eq!(armed(&watchdog), None);
    assert!(watchdog.rearm(), "a rearm after a disarm starts a deadline");
    assert_eq!(armed(&watchdog), Some(at));
    assert!(!watchdog.disarm());
    drop(watchdog);
    assert_eq!(
        supervisor.0.load(Ordering::SeqCst),
        0,
        "no deadline passed, so the supervisor never ran"
    );
}
