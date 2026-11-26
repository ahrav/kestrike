//! Test-only observer of selected primitive steps on the maintenance and
//! admission paths: deciding loads, stores, compare-exchanges,
//! read-modify-write transitions and gate attempts by outcome, counted per
//! thread, plus each armed thread's log of protocol events.
//!
//! The observer is independent of the work budget: the budget records what a
//! call charged, the observer records what it did, and a test compares the
//! two so that "observed steps never exceed what was charged" rests on two
//! ledgers, not one. A step is one abstract primitive at the granularity the
//! work inventory charges: a validation that reads several words of one slot
//! for one decision counts as one load, and a prepaid transition counts as
//! one read-modify-write however many attempts its compare-exchange makes,
//! such as the anchor release's exchange that clears the flag and
//! decrements the count together. Service's sighting is counted
//! as one load per slot the call examines, whether it read the slot's flag,
//! its retired or parked bit, or only the ledger's retired count.
//!
//! Outside test builds every entry point is an empty inline function, so
//! production carries no counter and no branch; inside them the counters are
//! per-thread cells and the log is a buffer reserved when the observer is
//! armed, so observing allocates nothing and the allocation-free proofs of
//! the paths it observes still hold with the observer in place.

/// One primitive operation, by kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Primitive {
    Load,
    Store,
    /// A compare-exchange, successful or not.
    Cas,
    /// A read-modify-write other than a compare-exchange.
    Rmw,
    /// A nonblocking gate attempt that took the gate.
    GateTaken,
    /// A nonblocking gate attempt that found the gate held.
    GateBusy,
    /// A nonblocking gate attempt that found the gate poisoned.
    GatePoisoned,
}

/// One protocol event with the values the operation read or wrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Event {
    /// A certification pass sampled its start era.
    CertifyStart { era: u64 },
    /// A certification pass loaded one registration record's pin.
    CertifyVisit { index: usize, pin: u64 },
    /// A completed pass published: `bound` is the pass's own value, `certified`
    /// the word's value after the publication.
    CertifyPublish { bound: u64, certified: u64 },
    /// Service released one anchor: `previous` is the count before the
    /// decrement.
    AnchorRelease { slot: usize, previous: usize },
    /// Service returned one slot's block.
    Return { slot: usize },
    /// Service returned extent `extent` of `slot`'s incarnation
    /// `incarnation`, from ledger phase `phase`, ahead of the slot's final
    /// return.
    ExtentReturn {
        slot: usize,
        incarnation: u32,
        extent: u32,
        phase: super::extent::HeldPhase,
    },
    /// An invalidation or a publication stored the odd sequence, or an invalidation found or made the shard terminal; `sequence` is then `TERMINAL`.
    Inhibit { sequence: u64 },
    /// An invalidation or a publication read the admission cutoff inside its inhibition.
    Cutoff { closed: bool },
    /// A publication took its live time sample inside its inhibition, after the odd store and before the cutoff read.
    Sampled { ticks: Option<u64> },
    /// An invalidation cleared the resident's pair.
    Cleared { slot: usize },
    /// An invalidation, or a publication within its own hold, revoked the current attempt's association.
    Revoked { serial: u64 },
    /// An invalidation or a publication committed its even sequence store,
    /// or left the terminal value in place.
    Committed { sequence: u64 },
    /// An obligation for `slot` was parked without the pool gate.
    Parked { slot: usize },
    /// A pool-gate hold observed the current retirement of linked `slot`
    /// and removed it from its policy domain.
    Detached { slot: usize },
    /// Service found a retirement describing the current incarnation of
    /// resident `slot` whose count still holds it.
    Sighted { slot: usize },
    /// An eviction commit found no pair naming the candidate of `slot`.
    Absent { slot: usize },
    /// A pending eviction mark for `slot` found the slot no longer holding
    /// the victim's incarnation and wrote nothing.
    StaleMark { slot: usize },
}

/// Records one primitive on this thread.
#[inline(always)]
pub(crate) fn note(primitive: Primitive) {
    note_n(primitive, 1);
}

/// Records `count` primitives of one kind on this thread.
#[inline(always)]
pub(crate) fn note_n(primitive: Primitive, count: usize) {
    #[cfg(test)]
    recording::note_n(primitive, count);
    #[cfg(not(test))]
    let _ = (primitive, count);
}

/// Records one event on this thread while the log is armed.
#[inline(always)]
pub(crate) fn event(event: Event) {
    #[cfg(test)]
    recording::event(event);
    #[cfg(not(test))]
    let _ = event;
}

#[cfg(test)]
pub(crate) use recording::{Counts, arm, counts, disarm, events};

#[cfg(test)]
mod recording {
    use std::cell::{Cell, RefCell};

    use super::{Event, Primitive};

    /// Primitives observed on this thread since the observer was armed.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub(crate) struct Counts {
        pub loads: usize,
        pub stores: usize,
        pub cas: usize,
        pub rmws: usize,
        pub gate_taken: usize,
        pub gate_busy: usize,
        pub gate_poisoned: usize,
    }

    impl Counts {
        /// Gate attempts of every outcome.
        pub(crate) fn gate_attempts(&self) -> usize {
            self.gate_taken + self.gate_busy + self.gate_poisoned
        }
    }

    /// The events logged on one thread since it was armed. `overflowed`
    /// records that the fixed capacity was reached and later events were
    /// dropped, so a test asserting on the log can tell a short log from a
    /// truncated one.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct Log {
        pub events: Vec<Event>,
        pub overflowed: bool,
    }

    /// Events one armed thread keeps. The buffer is reserved when the
    /// observer is armed, so logging an event allocates nothing.
    const CAPACITY: usize = 256;

    thread_local! {
        static COUNTS: Cell<Counts> = const { Cell::new(Counts {
            loads: 0,
            stores: 0,
            cas: 0,
            rmws: 0,
            gate_taken: 0,
            gate_busy: 0,
            gate_poisoned: 0,
        }) };
        static ARMED: Cell<bool> = const { Cell::new(false) };
        static LOG: RefCell<Log> = const { RefCell::new(Log { events: Vec::new(), overflowed: false }) };
    }

    pub(super) fn note_n(primitive: Primitive, count: usize) {
        COUNTS.with(|counts| {
            let mut value = counts.get();
            match primitive {
                Primitive::Load => value.loads += count,
                Primitive::Store => value.stores += count,
                Primitive::Cas => value.cas += count,
                Primitive::Rmw => value.rmws += count,
                Primitive::GateTaken => value.gate_taken += count,
                Primitive::GateBusy => value.gate_busy += count,
                Primitive::GatePoisoned => value.gate_poisoned += count,
            }
            counts.set(value);
        });
    }

    pub(super) fn event(event: Event) {
        if !ARMED.with(Cell::get) {
            return;
        }
        LOG.with(|log| {
            let mut log = log.borrow_mut();
            if log.events.len() < CAPACITY {
                log.events.push(event);
            } else {
                log.overflowed = true;
            }
        });
    }

    /// Starts observing on this thread: the counters are zeroed and the log
    /// is emptied with its capacity reserved.
    pub(crate) fn arm() {
        COUNTS.with(|counts| counts.set(Counts::default()));
        LOG.with(|log| {
            *log.borrow_mut() = Log {
                events: Vec::with_capacity(CAPACITY),
                overflowed: false,
            }
        });
        ARMED.with(|armed| armed.set(true));
    }

    /// Stops logging events on this thread; the log keeps its entries and
    /// the counters keep counting.
    pub(crate) fn disarm() {
        ARMED.with(|armed| armed.set(false));
    }

    /// The events logged on this thread since it was armed.
    pub(crate) fn events() -> Log {
        LOG.with(|log| log.borrow().clone())
    }

    /// Primitives counted on this thread since it was armed.
    pub(crate) fn counts() -> Counts {
        COUNTS.with(Cell::get)
    }
}
