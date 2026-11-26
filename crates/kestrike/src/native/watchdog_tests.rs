//! The watchdog's worker over a scripted timer whose clock the tests advance
//! and whose waits they wake, a bounded real-clock check through the
//! production binding, and a supervised child that stalls inside containment.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use super::watchdog::{self, Rearmable, Shared, State, Supervisor, Timer, Watchdog};
use crate::exact_child::{self, ExactChild, Outcome};

const DEADLINE: Duration = Duration::from_secs(10);
const SETTLE: Duration = Duration::from_millis(300);
const BOUND: Duration = Duration::from_secs(20);

/// A clock the test sets and an untimed wait the test wakes; every wait
/// records the timeout the worker asked for.
#[derive(Default)]
struct Script {
    now: Mutex<Duration>,
    waits: Mutex<Vec<Duration>>,
    waited: Condvar,
}

impl Timer for Arc<Script> {
    fn now(&self) -> Duration {
        *self.now.lock().unwrap()
    }

    fn wait<'a>(
        &self,
        state: MutexGuard<'a, State>,
        wake: &Condvar,
        timeout: Duration,
    ) -> MutexGuard<'a, State> {
        self.waits.lock().unwrap().push(timeout);
        self.waited.notify_all();
        wake.wait(state).unwrap_or_else(PoisonError::into_inner)
    }
}

impl Script {
    /// Blocks until the worker has entered its `count`-th wait.
    fn until_waiting(&self, count: usize) -> Vec<Duration> {
        let waits = self.waits.lock().unwrap();
        let (waits, timeout) = self
            .waited
            .wait_timeout_while(waits, BOUND, |waits| waits.len() < count)
            .unwrap();
        assert!(!timeout.timed_out(), "the worker entered wait {count}");
        waits.clone()
    }

    /// Sets the clock to `now` and wakes the worker under the watchdog's
    /// lock, so the worker sees the new time on this wake.
    fn advance_and_wake(&self, shared: &Shared, now: Duration) {
        let guard = shared.0.lock().unwrap_or_else(PoisonError::into_inner);
        *self.now.lock().unwrap() = now;
        shared.1.notify_all();
        drop(guard);
    }

    /// Sets the clock without waking the worker.
    fn advance(&self, now: Duration) {
        *self.now.lock().unwrap() = now;
    }
}

/// A watchdog's shared state handed to its supervisor after the arm; the
/// supervisor waits for it, so a containment that starts before the hand
/// still reads the watchdog's own state.
#[derive(Default)]
struct Watched(Mutex<Option<Shared>>, Condvar);

impl Watched {
    fn set(&self, shared: Shared) {
        *self.0.lock().unwrap() = Some(shared);
        self.1.notify_all();
    }

    fn expired(&self) -> bool {
        let slot = self.0.lock().unwrap();
        let (slot, _) = self
            .1
            .wait_timeout_while(slot, BOUND, |slot| slot.is_none())
            .unwrap();
        let shared = slot
            .as_ref()
            .expect("the supervisor was handed its watchdog's state");
        watchdog::expired(shared)
    }
}

/// Records each containment: whether the watchdog read expired at entry and
/// whether it returned; a closed gate holds it inside containment.
struct Observer {
    watched: Watched,
    expired_at_entry: Mutex<Vec<bool>>,
    returned: AtomicBool,
    gate: Mutex<Option<Receiver<()>>>,
}

impl Observer {
    fn new(gate: Option<Receiver<()>>) -> Arc<Self> {
        Arc::new(Self {
            watched: Watched::default(),
            expired_at_entry: Mutex::new(Vec::new()),
            returned: AtomicBool::new(false),
            gate: Mutex::new(gate),
        })
    }

    fn watch(&self, watchdog: &Watchdog) {
        self.watched.set(watchdog.shared());
    }

    fn entries(&self) -> usize {
        self.expired_at_entry.lock().unwrap().len()
    }

    /// Blocks until containment has entered once.
    fn until_entered(&self) {
        let start = Instant::now();
        while self.entries() == 0 && start.elapsed() < BOUND {
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(self.entries(), 1, "containment entered");
    }
}

impl Supervisor for Observer {
    fn contain(&self) {
        let expired = self.watched.expired();
        self.expired_at_entry.lock().unwrap().push(expired);
        if let Some(gate) = self.gate.lock().unwrap().take() {
            let _ = gate.recv_timeout(BOUND);
        }
        self.returned.store(true, Ordering::Release);
    }
}

fn armed(gate: Option<Receiver<()>>) -> (Watchdog, Arc<Script>, Arc<Observer>) {
    let script = Arc::new(Script::default());
    let observer = Observer::new(gate);
    let watchdog = Watchdog::arm_with(DEADLINE, observer.clone(), script.clone()).unwrap();
    observer.watch(&watchdog);
    (watchdog, script, observer)
}

#[test]
fn a_disarm_before_the_deadline_joins_the_worker_without_containment() {
    let (watchdog, script, observer) = armed(None);
    assert_eq!(script.until_waiting(1), [DEADLINE]);
    assert!(!watchdog.expired());
    drop(watchdog);
    assert_eq!(observer.entries(), 0);
    assert_eq!(*script.waits.lock().unwrap(), [DEADLINE]);
}

#[test]
fn the_exact_deadline_expires_and_contains_once_with_expiry_visible_at_entry() {
    let (watchdog, script, observer) = armed(None);
    script.until_waiting(1);
    script.advance_and_wake(&watchdog.shared(), DEADLINE);
    observer.until_entered();
    assert!(watchdog.expired());
    assert_eq!(*observer.expired_at_entry.lock().unwrap(), [true]);
    for _ in 0..3 {
        script.advance_and_wake(&watchdog.shared(), DEADLINE * 2);
    }
    drop(watchdog);
    assert_eq!(observer.entries(), 1, "containment runs once");
    assert!(observer.returned.load(Ordering::Acquire));
}

#[test]
fn a_spurious_wake_and_a_partial_advance_each_wait_again_for_the_remaining_time() {
    let (watchdog, script, observer) = armed(None);
    script.until_waiting(1);
    script.advance_and_wake(&watchdog.shared(), Duration::ZERO);
    assert_eq!(script.until_waiting(2), [DEADLINE, DEADLINE]);
    script.advance_and_wake(&watchdog.shared(), Duration::from_secs(4));
    assert_eq!(
        script.until_waiting(3),
        [DEADLINE, DEADLINE, Duration::from_secs(6)]
    );
    assert_eq!(observer.entries(), 0);
    assert!(!watchdog.expired());
    script.advance_and_wake(&watchdog.shared(), Duration::from_secs(9));
    script.until_waiting(4);
    script.advance_and_wake(&watchdog.shared(), DEADLINE + Duration::from_secs(1));
    observer.until_entered();
    drop(watchdog);
    assert_eq!(observer.entries(), 1);
    assert_eq!(*observer.expired_at_entry.lock().unwrap(), [true]);
}

/// The clock passes the deadline, and the disarm reaches the worker first:
/// the locked decision is the disarm, so the worker returns on it and the
/// drop joins a worker that made zero containment calls.
#[test]
fn a_disarm_that_wins_the_locked_race_prevents_containment_past_the_deadline() {
    let (watchdog, script, observer) = armed(None);
    assert_eq!(script.until_waiting(1), [DEADLINE]);
    let shared = watchdog.shared();
    script.advance(DEADLINE * 2);
    drop(watchdog);
    assert_eq!(observer.entries(), 0);
    assert!(
        !watchdog::expired(&shared),
        "the expiry flag stays clear after the disarm"
    );
    assert_eq!(
        *script.waits.lock().unwrap(),
        [DEADLINE],
        "the worker's only wait is its first, for the full deadline"
    );
}

/// The expiry reaches the worker first and its containment is gated: the
/// drop blocks until the gate opens, then returns with the worker joined.
#[test]
fn an_expiry_that_wins_the_locked_race_contains_and_blocks_the_drop_until_the_gate_opens() {
    let (open, gate) = mpsc::channel();
    let (watchdog, script, observer) = armed(Some(gate));
    assert_eq!(script.until_waiting(1), [DEADLINE]);
    assert!(!watchdog.expired());
    script.advance_and_wake(&watchdog.shared(), DEADLINE);
    observer.until_entered();
    assert!(
        watchdog.expired() && !observer.returned.load(Ordering::Acquire),
        "the owner reads the expiry while containment is held at its gate"
    );
    assert_eq!(*observer.expired_at_entry.lock().unwrap(), [true]);
    let (dropped, dropping) = mpsc::channel();
    thread::spawn(move || {
        drop(watchdog);
        dropped.send(()).unwrap();
    });
    assert_eq!(
        dropping.recv_timeout(SETTLE),
        Err(RecvTimeoutError::Timeout),
        "the drop stays blocked while containment is gated"
    );
    assert!(!observer.returned.load(Ordering::Acquire));
    open.send(()).unwrap();
    assert_eq!(dropping.recv_timeout(BOUND), Ok(()));
    assert!(observer.returned.load(Ordering::Acquire));
    assert_eq!(observer.entries(), 1);
}

fn idle() -> (Rearmable, Arc<Script>, Arc<Observer>) {
    let script = Arc::new(Script::default());
    let observer = Observer::new(None);
    let watchdog = Rearmable::idle_with(DEADLINE, observer.clone(), script.clone()).unwrap();
    observer.watched.set(watchdog.shared());
    (watchdog, script, observer)
}

#[test]
fn an_idle_worker_never_contains_and_a_rearm_times_a_full_deadline_from_its_own_reading() {
    let (mut watchdog, script, observer) = idle();
    assert_eq!(script.until_waiting(1), [Duration::MAX]);
    script.advance_and_wake(&watchdog.shared(), DEADLINE * 3);
    assert_eq!(script.until_waiting(2), [Duration::MAX; 2]);
    assert!(watchdog.rearm());
    assert_eq!(script.until_waiting(3)[2], DEADLINE);
    script.advance_and_wake(&watchdog.shared(), DEADLINE * 3 + Duration::from_secs(9));
    assert_eq!(script.until_waiting(4)[3], Duration::from_secs(1));
    assert_eq!(observer.entries(), 0);
    script.advance_and_wake(&watchdog.shared(), DEADLINE * 4);
    observer.until_entered();
    assert!(watchdog.disarm(), "the disarm reports the expiry");
    assert!(observer.returned.load(Ordering::Acquire));
    assert_eq!(*observer.expired_at_entry.lock().unwrap(), [true]);
    assert!(!watchdog.rearm(), "an expired worker refuses a rearm");
    drop(watchdog);
    assert_eq!(observer.entries(), 1);
}

#[test]
fn a_disarm_before_the_deadline_returns_the_worker_to_idle_for_the_next_rearm() {
    let (mut watchdog, script, observer) = idle();
    script.until_waiting(1);
    assert!(watchdog.rearm());
    assert_eq!(script.until_waiting(2)[1], DEADLINE);
    assert!(!watchdog.disarm());
    script.advance_and_wake(&watchdog.shared(), DEADLINE * 2);
    assert_eq!(script.until_waiting(3)[2], Duration::MAX);
    assert_eq!(observer.entries(), 0);
    assert!(watchdog.rearm());
    assert_eq!(script.until_waiting(4)[3], DEADLINE);
    drop(watchdog);
    assert_eq!(observer.entries(), 0);
}

/// The production timer: a short deadline expires and contains within the
/// bound, and a long one disarms within the bound.
#[test]
fn the_monotonic_timer_expires_a_short_deadline_and_disarms_a_long_one_within_bounds() {
    let observer = Observer::new(None);
    let watchdog = Watchdog::arm(Duration::from_millis(20), observer.clone()).unwrap();
    observer.watch(&watchdog);
    let start = Instant::now();
    while !watchdog.expired() && start.elapsed() < BOUND {
        thread::sleep(Duration::from_millis(5));
    }
    assert!(watchdog.expired(), "the real clock reached the deadline");
    drop(watchdog);
    assert_eq!(observer.entries(), 1);
    assert_eq!(*observer.expired_at_entry.lock().unwrap(), [true]);
    assert!(observer.returned.load(Ordering::Acquire));

    let observer = Observer::new(None);
    let watchdog = Watchdog::arm(Duration::from_secs(600), observer.clone()).unwrap();
    observer.watch(&watchdog);
    let start = Instant::now();
    drop(watchdog);
    assert!(
        start.elapsed() < BOUND,
        "the disarm joins the worker promptly"
    );
    assert_eq!(observer.entries(), 0);
}

#[test]
fn the_monotonic_timer_idles_past_its_deadline_and_expires_a_rearmed_one() {
    let deadline = Duration::from_millis(20);
    let observer = Observer::new(None);
    let mut watchdog = Rearmable::idle(deadline, observer.clone()).unwrap();
    observer.watched.set(watchdog.shared());
    thread::sleep(deadline * 3);
    assert!(!watchdog.expired(), "an idle worker never expires");
    assert!(watchdog.rearm());
    let start = Instant::now();
    while !watchdog.expired() && start.elapsed() < BOUND {
        thread::sleep(Duration::from_millis(5));
    }
    assert!(
        watchdog.expired(),
        "the real clock reached the rearmed deadline"
    );
    assert!(watchdog.disarm());
    assert_eq!(observer.entries(), 1);
    assert_eq!(*observer.expired_at_entry.lock().unwrap(), [true]);
    assert!(observer.returned.load(Ordering::Acquire));
}

#[derive(Default)]
struct Unwinding(Mutex<u32>);

impl Supervisor for Unwinding {
    fn contain(&self) {
        *self.0.lock().unwrap() += 1;
        panic!("containment unwinds");
    }
}

#[test]
fn a_containment_that_unwinds_still_lets_the_disarm_report_the_expiry() {
    let script = Arc::new(Script::default());
    let supervisor = Arc::new(Unwinding::default());
    let mut watchdog = Rearmable::idle_with(DEADLINE, supervisor.clone(), script.clone()).unwrap();
    script.until_waiting(1);
    assert!(watchdog.rearm());
    script.until_waiting(2);
    script.advance_and_wake(&watchdog.shared(), DEADLINE);
    let start = Instant::now();
    while !watchdog.expired() && start.elapsed() < BOUND {
        thread::sleep(Duration::from_millis(5));
    }
    assert!(watchdog.disarm(), "the disarm reports the expiry");
    assert_eq!(*supervisor.0.lock().unwrap(), 1);
    assert!(!watchdog.rearm(), "an expired worker refuses a rearm");
    drop(watchdog);
}

const STALL_CHILD: &str = "native::watchdog_tests::a_stall_child";
const STALL_SCENARIO: &str = "KESTRIKE_WATCHDOG_STALL";
const ENTERED: &str = "contained with expiry visible";
const WITNESSES: usize = 3;
const BLOCKED: &str = "drop blocked";

/// Holds its caller inside containment for the rest of the process after
/// reporting entry with the expiry it saw.
struct Stalling {
    watched: Watched,
    parked: Sender<()>,
}

/// `STRAY` bounds a stall child's lifetime if its parent is killed.
const STRAY: Duration = Duration::from_secs(600);

fn stall_until_killed() -> ! {
    let start = Instant::now();
    while start.elapsed() < STRAY {
        thread::park_timeout(STRAY);
    }
    std::process::exit(4)
}

impl Supervisor for Stalling {
    fn contain(&self) {
        let expired = self.watched.expired();
        exact_child::report(if expired {
            ENTERED
        } else {
            "contained before expiry"
        });
        self.parked.send(()).unwrap();
        loop {
            thread::park();
        }
    }
}

#[test]
fn a_stall_child() {
    if !exact_child::is_child(STALL_CHILD) {
        return;
    }
    exact_child::report(&exact_child::entered(STALL_CHILD));
    let (parked, entered) = mpsc::channel();
    let supervisor = Arc::new(Stalling {
        watched: Watched::default(),
        parked,
    });
    let watchdog = Watchdog::arm(Duration::from_millis(20), supervisor.clone()).unwrap();
    supervisor.watched.set(watchdog.shared());
    entered.recv_timeout(BOUND).unwrap();
    if std::env::var_os(STALL_SCENARIO).is_some_and(|scenario| scenario == "exit-after-entry") {
        std::process::exit(0);
    }
    let (dropped, dropping) = mpsc::channel();
    thread::spawn(move || {
        drop(watchdog);
        dropped.send(()).unwrap();
    });
    if dropping.recv_timeout(SETTLE) == Err(RecvTimeoutError::Timeout) {
        exact_child::report(BLOCKED);
    } else {
        exact_child::report("drop returned");
    }
    stall_until_killed()
}

/// The stall child's run as the parent saw it: its reports in order and
/// how the supervisor ended it.
#[derive(Debug)]
struct Stall {
    reports: Vec<String>,
    outcome: Outcome,
}

fn stall(scenario: &[(&str, &str)]) -> Stall {
    let mut child = ExactChild::spawn(STALL_CHILD, scenario).unwrap();
    let until = Instant::now() + BOUND;
    let mut reports = Vec::new();
    for _ in 0..WITNESSES {
        let Some(report) = child.next_report(until) else {
            break;
        };
        reports.push(report);
    }
    let outcome = child.finish(Instant::now() + SETTLE);
    Stall { reports, outcome }
}

/// The parent requires three reports in order: the child's entry report,
/// containment entered with expiry visible, and the blocked drop; then a
/// stall the deadline ended.
fn witnessed(stall: &Stall) -> Result<(), String> {
    let expected: [String; WITNESSES] = [
        exact_child::entered(STALL_CHILD),
        ENTERED.into(),
        BLOCKED.into(),
    ];
    if stall.reports != expected {
        return Err(format!("witnesses {:?}", stall.reports));
    }
    match &stall.outcome {
        Outcome::Stalled { .. } => Ok(()),
        other => Err(format!("ended {other:?}")),
    }
}

#[test]
fn a_stalled_containment_is_witnessed_with_a_blocked_drop_then_killed() {
    let stall = stall(&[]);
    assert_eq!(witnessed(&stall), Ok(()), "{stall:?}");
}

#[test]
fn a_child_that_exits_after_entry_lacks_the_blocked_drop_witness_and_fails() {
    let stall = stall(&[(STALL_SCENARIO, "exit-after-entry")]);
    let refused = witnessed(&stall).unwrap_err();
    assert!(refused.starts_with("witnesses"), "{refused}: {stall:?}");
    assert!(matches!(stall.outcome, Outcome::Failed { .. }), "{stall:?}");
}

mod replay;
