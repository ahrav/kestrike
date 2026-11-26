//! The one-word gate: exclusive access to one pool's tables, one index
//! shard's tables, the grace certification pass, or the maintain or close
//! cursor. Allocator and publication paths make one nonblocking attempt;
//! pool report paths wait.
//!
//! The gate occupies one word in a control mapping or in the storage owner.
//! It is open, held, or
//! poisoned. Taking it is one relaxed read and one acquire compare-exchange;
//! releasing it is one release store, so table writes made under the gate are
//! visible to the next holder and the release never pays for waiter
//! bookkeeping.
//!
//! [`Gate::try_lock`] makes one attempt and returns.
//! [`Gate::lock`] polls with backoff; releasing the gate wakes no waiter.
//!
//! A holder that panics poisons the gate on release. A poisoned gate admits
//! nobody: nothing here repairs tables a holder may have left half-written.
//!
//! The gate runs over any [`GateWord`]: the std word in production and,
//! under `--cfg loom`, a model atomic, so a model takes and releases the
//! production gate. The models take it through [`Gate::try_lock`] alone;
//! [`Gate::lock`]'s backoff runs on the std word.
//!
//! The word is padded so no table shares its cache lines: one 64-byte line
//! plus the adjacent line an x86 spatial prefetcher pairs with it. Every busy
//! try reads the gate's line, so a table sharing it would cost the holder an
//! invalidation before each write to that table.

use std::sync::atomic::{AtomicU32, Ordering};

/// The gate's word: the three accesses the gate makes, so the same gate
/// runs over the mapped word and, under `--cfg loom`, over a model atomic.
pub(crate) trait GateWord {
    fn load(&self, order: Ordering) -> u32;
    fn compare_exchange(
        &self,
        current: u32,
        new: u32,
        success: Ordering,
        failure: Ordering,
    ) -> Result<u32, u32>;
    fn store(&self, value: u32, order: Ordering);
}

macro_rules! forward_gate_word {
    ($atomic:ty) => {
        impl GateWord for $atomic {
            #[inline(always)]
            fn load(&self, order: Ordering) -> u32 {
                Self::load(self, order)
            }

            #[inline(always)]
            fn compare_exchange(
                &self,
                current: u32,
                new: u32,
                success: Ordering,
                failure: Ordering,
            ) -> Result<u32, u32> {
                Self::compare_exchange(self, current, new, success, failure)
            }

            #[inline(always)]
            fn store(&self, value: u32, order: Ordering) {
                Self::store(self, value, order);
            }
        }
    };
}

forward_gate_word!(AtomicU32);
#[cfg(all(test, loom))]
forward_gate_word!(loom::sync::atomic::AtomicU32);

/// A gate word over `W` whose take, with `TAKE`, or whose release stores,
/// with `!TAKE`, are `Relaxed`, which leaves one holder's gate-held writes
/// unordered with the next holder's accesses.
#[cfg(all(test, any(miri, loom, kestrike_tsan)))]
pub(crate) struct WeakGate<W, const TAKE: bool>(pub(crate) W);

#[cfg(all(test, any(miri, loom, kestrike_tsan)))]
impl<W: GateWord, const TAKE: bool> GateWord for WeakGate<W, TAKE> {
    fn load(&self, order: Ordering) -> u32 {
        self.0.load(order)
    }

    fn compare_exchange(
        &self,
        current: u32,
        new: u32,
        success: Ordering,
        failure: Ordering,
    ) -> Result<u32, u32> {
        let success = if TAKE { Ordering::Relaxed } else { success };
        self.0.compare_exchange(current, new, success, failure)
    }

    fn store(&self, value: u32, order: Ordering) {
        let order = if TAKE { order } else { Ordering::Relaxed };
        self.0.store(value, order);
    }
}

/// Why the gate could not be taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateError {
    /// Another holder has the gate; nothing was changed.
    Contended,
    /// A previous holder panicked. Admission stays closed and charges stay
    /// retained; nothing here repairs the tables.
    Poisoned,
}

const OPEN: u32 = 0;
const HELD: u32 = 1;
const POISONED: u32 = 2;

/// The gate occupies one word in a control mapping or in the storage owner.
#[repr(align(128))]
pub(crate) struct Gate<W = AtomicU32>(W);

/// Proof of holding a gate. Dropping it releases the gate, poisoned when the
/// drop unwinds from a panic that began after the gate was taken.
pub(crate) struct GateGuard<'a, W: GateWord = AtomicU32> {
    gate: &'a Gate<W>,
    /// Whether the taker was already unwinding. A panic that started before
    /// the gate was taken did not interrupt any table write.
    panicking: bool,
}

impl Gate {
    pub(crate) fn open() -> Self {
        Self(AtomicU32::new(OPEN))
    }
}

impl<W: GateWord> Gate<W> {
    /// An open gate over the word `make` builds from the open value.
    #[cfg(all(test, any(miri, loom, kestrike_tsan)))]
    pub(crate) fn open_over(make: impl FnOnce(u32) -> W) -> Self {
        Self(make(OPEN))
    }

    /// One nonblocking attempt.
    ///
    /// # Errors
    ///
    /// `Contended` if held elsewhere, `Poisoned` if a holder panicked.
    #[inline]
    pub(crate) fn try_lock(&self) -> Result<GateGuard<'_, W>, GateError> {
        self.attempt(|| crate::sim::chaos::chaos!(GateBusy))
    }

    /// One nonblocking attempt, as [`try_lock`](Self::try_lock) documents,
    /// whose `refuse` runs only once the relaxed read saw the word open and
    /// before the exchange; `true` returns `Contended` and writes nothing.
    /// [`lock`](Self::lock) passes a `refuse` that answers `false`.
    #[inline(always)]
    fn attempt(&self, refuse: impl FnOnce() -> bool) -> Result<GateGuard<'_, W>, GateError> {
        // Reading first keeps a busy try from taking the line away from the
        // holder: only the holder's release then moves it.
        match self.0.load(Ordering::Relaxed) {
            OPEN => {}
            POISONED => return Err(GateError::Poisoned),
            _ => return Err(GateError::Contended),
        }
        if refuse() {
            return Err(GateError::Contended);
        }
        match self
            .0
            .compare_exchange(OPEN, HELD, Ordering::Acquire, Ordering::Relaxed)
        {
            Ok(_) => Ok(GateGuard {
                gate: self,
                panicking: std::thread::panicking(),
            }),
            Err(POISONED) => Err(GateError::Poisoned),
            Err(_) => Err(GateError::Contended),
        }
    }

    /// Whether a holder poisoned the gate, by its panic or by
    /// [`GateGuard::poison`], as one relaxed read of the word sees it; a
    /// poisoning concurrent with the read is seen by the next read or
    /// attempt.
    #[inline]
    pub(crate) fn is_poisoned(&self) -> bool {
        self.0.load(Ordering::Relaxed) == POISONED
    }

    /// Waits for the gate; `None` once it is poisoned. A thread that already
    /// holds this gate must not call it: the wait would never end.
    ///
    /// A hold can be long, such as a report copying a table under the gate.
    /// A waiter that yields for the whole hold burns a core,
    /// or under a CPU quota the very time the holder needs, so after a brief
    /// spin and a few yields the waiter sleeps with a doubling interval
    /// capped at [`WAIT_SLEEP_MAX`], which bounds both its wake-up rate and
    /// the latency it adds once the gate opens.
    pub(crate) fn lock(&self) -> Option<GateGuard<'_, W>> {
        let mut attempt: u32 = 0;
        let mut sleep = WAIT_SLEEP_MIN;
        loop {
            match self.attempt(|| false) {
                Ok(guard) => return Some(guard),
                Err(GateError::Poisoned) => return None,
                Err(GateError::Contended) => {}
            }
            if attempt < WAIT_SPINS {
                std::hint::spin_loop();
            } else if attempt < WAIT_SPINS + WAIT_YIELDS {
                std::thread::yield_now();
            } else {
                #[expect(
                    clippy::disallowed_methods,
                    reason = "whether the single-threaded simulator reaches this contended sleep is unverified"
                )]
                std::thread::sleep(sleep);
                sleep = (sleep * 2).min(WAIT_SLEEP_MAX);
            }
            attempt = attempt.saturating_add(1);
        }
    }
}

const WAIT_SPINS: u32 = 64;
const WAIT_YIELDS: u32 = 16;
const WAIT_SLEEP_MIN: std::time::Duration = std::time::Duration::from_micros(20);
const WAIT_SLEEP_MAX: std::time::Duration = std::time::Duration::from_millis(1);

impl<W: GateWord> GateGuard<'_, W> {
    /// Releases the gate with one release store at the end of a hold that
    /// completed or refused with its tables consistent. A hold that ends by
    /// unwinding releases through `Drop`, which reads `panicking` again to
    /// decide poisoning.
    #[inline(always)]
    pub(crate) fn release(self) {
        self.gate.0.store(OPEN, Ordering::Release);
        std::mem::forget(self);
    }

    /// Makes the hold's drop poison the gate whenever the thread is
    /// unwinding, whatever it was doing at the take: for a holder that ends
    /// every completed or refused hold through [`release`](Self::release) or
    /// [`poison`](Self::poison), so that only a panic inside the hold drops
    /// the guard. A take made while the thread already unwinds would
    /// otherwise release such a panic's gate open.
    #[inline]
    pub(crate) fn poison_on_unwind(mut self) -> Self {
        self.panicking = false;
        self
    }

    /// Ends the hold by poisoning the gate: for a holder that found the
    /// tables it guards malformed and must not let anyone act on them.
    pub(crate) fn poison(self) {
        self.gate.0.store(POISONED, Ordering::Release);
        std::mem::forget(self);
    }
}

/// A gate whose every completed or refused hold ends through
/// [`GateGuard::release`] or [`GateGuard::poison`], so that only a panic
/// inside a hold drops its guard. That drop poisons the gate whenever the
/// thread is unwinding, whatever it was doing at the take: a hold taken by a
/// thread that already unwinds would otherwise release its own panic's gate
/// open.
pub(crate) struct RootGate(Gate);

impl RootGate {
    pub(crate) fn open() -> Self {
        Self(Gate::open())
    }

    /// One nonblocking attempt, as [`Gate::try_lock`].
    ///
    /// # Errors
    ///
    /// `Contended` if held elsewhere, `Poisoned` if a holder panicked.
    #[inline]
    pub(crate) fn try_lock(&self) -> Result<GateGuard<'_>, GateError> {
        let mut guard = self.0.try_lock()?;
        guard.panicking = false;
        Ok(guard)
    }
}

impl<W: GateWord> Drop for GateGuard<'_, W> {
    #[inline]
    fn drop(&mut self) {
        let state = if !self.panicking && std::thread::panicking() {
            POISONED
        } else {
            OPEN
        };
        self.gate.0.store(state, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use std::cell::UnsafeCell;
    use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

    #[cfg(any(miri, kestrike_tsan))]
    use super::WeakGate;
    use super::{Gate, GateError, GateWord};

    /// A plain counter that only a gate holder may touch. Miri's race
    /// detector fails the test, and ThreadSanitizer reports a data race, if
    /// two holders ever overlap or if a holder's write is not ordered before
    /// the next holder's read.
    struct Guarded(UnsafeCell<usize>);

    // SAFETY: every access happens under the gate, or after every thread has
    // joined.
    unsafe impl Sync for Guarded {}

    #[test]
    fn gate_is_exclusive_and_reopens_on_release() {
        let gate = Gate::open();
        assert_eq!((size_of::<Gate>(), align_of::<Gate>()), (128, 128));
        let held = gate.try_lock().unwrap();
        assert_eq!(gate.try_lock().err(), Some(GateError::Contended));
        drop(held);
        assert!(gate.try_lock().is_ok());
        assert!(gate.lock().is_some());
    }

    /// When `GateBusy` fires, `try_lock` returns `GateError::Contended` and
    /// leaves the word open, so the next try without a fire takes the gate.
    /// A waiting `lock` with every point armed at odds 1 takes an open gate
    /// and leaves the chooser's decision count unchanged, as does a try of a
    /// held or poisoned word.
    #[test]
    fn a_fired_gate_busy_point_leaves_the_word_open() {
        use crate::sim::chaos::{acting, arm, sites};
        use std::{cell::RefCell, rc::Rc};
        // Each fed zero lets the armed point fire once.
        let chooser = Rc::new(RefCell::new(crate::sim::choice::Chooser::fed(
            &sites(1),
            vec![0; 3],
        )));
        let incarnation = chooser.borrow_mut().launch(1);
        let gate = Gate::open();
        let armed = arm(&chooser, (1, incarnation), [1, 1, 1]);
        assert_eq!(acting(|| gate.try_lock()).err(), Some(GateError::Contended));
        assert!(!gate.is_poisoned());
        assert_eq!(chooser.borrow().decisions(), 1);
        acting(|| gate.attempt(|| false))
            .expect("a fired point leaves the word open")
            .release();
        assert_eq!(chooser.borrow().decisions(), 1);
        let waited = acting(|| gate.lock()).expect("an open gate");
        assert_eq!(
            chooser.borrow().decisions(),
            1,
            "a waiting lock decides nothing"
        );
        assert_eq!(acting(|| gate.try_lock()).err(), Some(GateError::Contended));
        assert_eq!(chooser.borrow().decisions(), 1, "a held word refuses first");
        waited.poison();
        assert_eq!(acting(|| gate.try_lock()).err(), Some(GateError::Poisoned));
        assert_eq!(
            chooser.borrow().decisions(),
            1,
            "a poisoned word refuses first"
        );
        assert_eq!(armed.disarm(), None);
        assert_eq!(acting(|| gate.try_lock()).err(), Some(GateError::Poisoned));
        let open = Gate::open();
        let armed = arm(&chooser, (1, incarnation), [1, 1, 1]);
        assert_eq!(acting(|| open.try_lock()).err(), Some(GateError::Contended));
        assert_eq!(armed.disarm(), None);
        assert!(acting(|| open.try_lock()).is_ok());

        let counted = Gate(Counted {
            word: AtomicU32::new(super::OPEN),
            writes: AtomicUsize::new(0),
        });
        let writes = || counted.0.writes.load(Ordering::Relaxed);
        let armed = arm(&chooser, (1, incarnation), [1, 1, 1]);
        assert_eq!(
            acting(|| counted.try_lock()).err(),
            Some(GateError::Contended)
        );
        assert_eq!(writes(), 0, "a fired attempt writes nothing");
        assert_eq!(armed.disarm(), None);
        assert_eq!(chooser.borrow().decisions(), 3);
        let held = counted.try_lock().expect("an unfired try of an open word");
        assert_eq!(writes(), 1, "the take is one exchange");
        held.release();
    }

    struct Counted {
        word: AtomicU32,
        writes: AtomicUsize,
    }

    impl GateWord for Counted {
        fn load(&self, order: Ordering) -> u32 {
            self.word.load(order)
        }

        fn compare_exchange(
            &self,
            current: u32,
            new: u32,
            success: Ordering,
            failure: Ordering,
        ) -> Result<u32, u32> {
            self.writes.fetch_add(1, Ordering::Relaxed);
            self.word.compare_exchange(current, new, success, failure)
        }

        fn store(&self, value: u32, order: Ordering) {
            self.writes.fetch_add(1, Ordering::Relaxed);
            self.word.store(value, order);
        }
    }

    #[test]
    fn waiting_takes_the_gate_once_the_holder_releases() {
        let gate = Gate::open();
        let held = gate.try_lock().unwrap();
        std::thread::scope(|scope| {
            let waiter = scope.spawn(|| gate.lock().is_some());
            drop(held);
            assert!(waiter.join().unwrap());
        });
    }

    /// Takers and waiters contend for `gate`, each holder incrementing a
    /// plain counter under it; returns the holds and the counter's value.
    /// The waiters' blocking locks each hold every round, so holds pass
    /// between spawned threads through the gate alone; the `Relaxed`-take
    /// control's data race is the evidence of that passing.
    fn contend<W: super::GateWord + Sync>(gate: &Gate<W>) -> (usize, usize) {
        let guarded = Guarded(UnsafeCell::new(0));
        let inside = AtomicUsize::new(0);
        let holds = AtomicUsize::new(0);
        let (threads, rounds) = if cfg!(miri) { (4, 50) } else { (8, 20_000) };
        std::thread::scope(|scope| {
            for thread in 0..threads {
                let (gate, guarded, inside, holds) = (gate, &guarded, &inside, &holds);
                scope.spawn(move || {
                    for round in 0..rounds {
                        // Odd threads wait, even threads try once and move on.
                        let guard = if thread % 2 == 1 {
                            gate.lock()
                        } else {
                            gate.try_lock().ok()
                        };
                        let Some(guard) = guard else { continue };
                        assert_eq!(inside.fetch_add(1, Ordering::Relaxed), 0);
                        // SAFETY: the gate is held; no other reference exists.
                        unsafe { *guarded.0.get() += 1 };
                        holds.fetch_add(1, Ordering::Relaxed);
                        inside.fetch_sub(1, Ordering::Relaxed);
                        drop(guard);
                        std::hint::black_box(round);
                    }
                });
            }
        });
        let holds = holds.load(Ordering::Relaxed);
        // Waiters always get in, so at least their rounds were held.
        assert!(holds >= threads / 2 * rounds);
        // SAFETY: every thread has joined; no reference into the cell remains.
        (holds, unsafe { *guarded.0.get() })
    }

    #[test]
    fn contending_takers_and_waiters_never_overlap_and_see_each_other() {
        let gate = Gate::open();
        let (holds, counted) = contend(&gate);
        assert_eq!(counted, holds);
        assert!(gate.try_lock().is_ok());
    }

    /// The contention workload over a gate whose take is `Relaxed`: the
    /// interpreter's data-race detector and ThreadSanitizer each report the
    /// second holder's counter access as a data race. The Miri lane and the
    /// `rust-lane.sh tsan` step each run this test on its own and require that
    /// report.
    #[cfg(any(miri, kestrike_tsan))]
    #[test]
    fn negative_control_a_relaxed_take_races_the_guarded_counter() {
        contend(&Gate::open_over(|open| {
            WeakGate::<_, true>(std::sync::atomic::AtomicU32::new(open))
        }));
    }

    #[test]
    fn panicking_holder_poisons_the_gate_for_everyone() {
        let gate = Gate::open();
        std::thread::scope(|scope| {
            let handle = scope.spawn(|| {
                let _held = gate.try_lock().unwrap();
                panic!("poison the gate");
            });
            assert!(handle.join().is_err());
        });
        assert_eq!(gate.try_lock().err(), Some(GateError::Poisoned));
        assert!(gate.lock().is_none());
    }

    /// A hold taken while already unwinding (an owner's drop during a panic)
    /// releases cleanly: the panic predates the hold, so it is not the hold's
    /// fault.
    #[test]
    fn gate_taken_during_unwinding_is_released_not_poisoned() {
        struct TakesGateOnDrop<'a>(&'a Gate);
        impl Drop for TakesGateOnDrop<'_> {
            fn drop(&mut self) {
                let guard = self.0.try_lock().unwrap();
                assert!(std::thread::panicking());
                drop(guard);
            }
        }
        let gate = Gate::open();
        let outcome = std::panic::catch_unwind(|| {
            let _owner = TakesGateOnDrop(&gate);
            panic!("unwind with a live owner");
        });
        assert!(outcome.is_err());
        assert!(gate.try_lock().is_ok());
    }

    /// CPU time this thread has consumed so far.
    fn thread_cpu_time() -> std::time::Duration {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: `ts` is a valid, writable `timespec` and the clock id is a
        // constant the kernel defines.
        let rc = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
        assert_eq!(rc, 0);
        std::time::Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
    }

    /// A waiter behind a long hold must not spend the hold on the CPU: a
    /// preempted or throttled holder is only delayed further by waiters that
    /// burn the cores or the quota the holder needs to finish.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "reads the thread CPU-time clock, which Miri does not provide"
    )]
    fn waiting_for_a_long_hold_consumes_little_cpu() {
        const HOLD: std::time::Duration = std::time::Duration::from_millis(200);
        let gate = Gate::open();
        let held = gate.try_lock().unwrap();
        let waited = std::thread::scope(|scope| {
            let waiter = scope.spawn(|| {
                let before = thread_cpu_time();
                let guard = gate.lock().expect("gate is not poisoned");
                let spent = thread_cpu_time() - before;
                drop(guard);
                spent
            });
            std::thread::sleep(HOLD);
            drop(held);
            waiter.join().unwrap()
        });
        assert!(
            waited < HOLD / 10,
            "waiter spent {waited:?} of CPU during a {HOLD:?} hold"
        );
        assert!(gate.try_lock().is_ok());
    }
}
