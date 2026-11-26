//! The join, observe and release seam of a fill record under GenMC: a
//! producer that records a failure and departs without the gate, a follower
//! joined before the threads start that observes the record and then
//! detaches, and a service pass that frees a departed record
//! with no follower joined and regrants it to the next attempt. The record
//! word is the production `fill` module and the row the production `row`
//! module's `FillRow`, both included by path, so every access to them runs
//! the production body; the declaration binds the failure record, the
//! observations, the terminal read, the detach, the pass's observer check
//! and the regrant's reset to their production call sites and order.
//!
//! Model substitutions: `GATE` is the shard gate, one acquire exchange per
//! try and a release store, tried once by each holder. The pass's free and
//! the next grant's reset and occupied store run in one hold, where
//! production runs them in the pass's hold and a later grant's; both read
//! the observer count under the gate. The pass observes the record with
//! `fill::observe`, the path an under-funded pass takes; the funded pass's
//! `load_run` with its fence is covered by the Loom `fill_model` kernel.
//! Gate-held steps the kernel leaves out, each ordered by the gate: the
//! return of a publication's retained right and credit, the grant's refusal
//! of a row with a follower joined, and the exclusion of a record custody
//! names.
//!
//! The `seam` cfg picks the variant: `production` runs the production
//! orderings; `relaxedobserve` is the weakening control, the follower's
//! observation of the record at `Relaxed` in place of `fill::observe`'s
//! `Acquire`; `relaxeddepart` weakens the producer's departure to
//! `Relaxed`, through the production `depart` over a weakened word;
//! `earlydetach` plants the follower's detach before its observation, which
//! lets the pass free the record the follower then reads; and
//! `ignoresobservers` plants a pass that frees a departed record with a
//! follower joined.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::check::check;
use crate::join::fill::{self, FillSerial, Record};
use crate::join::row::{FillFailure, FillRow, Terminal};

/// The shard's next unissued serial once the regrant could have issued 2.
const NEXT: u64 = 3;
const ORIGINAL: FillSerial = FillSerial::new(1).unwrap();
const REGRANT: FillSerial = FillSerial::new(2).unwrap();
const FAILURE: FillFailure = FillFailure::TimedOut;

static GATE: AtomicBool = AtomicBool::new(false);
static STATE: AtomicU64 = AtomicU64::new(fill::FREE);
static ROW: FillRow = FillRow::new();

/// One gate try: the acquire exchange.
fn take() -> bool {
    GATE.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_ok()
}

/// The gate's release.
fn give() {
    GATE.store(false, Ordering::Release);
}

/// The record word with its departure's success ordering weakened to
/// `Relaxed`, for the `relaxeddepart` control.
#[cfg(seam = "relaxeddepart")]
struct Weakened<'w>(&'w AtomicU64);

#[cfg(seam = "relaxeddepart")]
impl fill::FillWord for Weakened<'_> {
    fn load(&self, order: Ordering) -> u64 {
        self.0.load(order)
    }

    fn acquire_fence() {
        std::sync::atomic::fence(Ordering::Acquire);
    }

    fn store(&self, value: u64, order: Ordering) {
        self.0.store(value, order)
    }

    fn fetch_or(&self, value: u64, order: Ordering) -> u64 {
        self.0.fetch_or(value, order)
    }

    fn compare_exchange(
        &self,
        current: u64,
        new: u64,
        _: Ordering,
        failure: Ordering,
    ) -> Result<u64, u64> {
        self.0
            .compare_exchange(current, new, Ordering::Relaxed, failure)
    }
}

/// The producer's failure: its terminal, then its departure.
fn producer() {
    ROW.record_failure(FAILURE);
    #[cfg(not(seam = "relaxeddepart"))]
    let departed = fill::depart(&STATE, ORIGINAL);
    #[cfg(seam = "relaxeddepart")]
    let departed = fill::depart(&Weakened(&STATE), ORIGINAL);
    check!(departed, c"the producer departs its own record");
}

/// The follower's detach before its observation, for the `earlydetach` control.
#[cfg(seam = "earlydetach")]
fn detach_early() {
    ROW.detach();
}

/// The follower: one observation, then its detach.
fn follower() {
    #[cfg(seam = "earlydetach")]
    detach_early();
    #[cfg(not(seam = "relaxedobserve"))]
    let record = fill::observe(&STATE, 2);
    #[cfg(seam = "relaxedobserve")]
    let record = fill::decode(STATE.load(Ordering::Relaxed), 2);
    match record {
        Ok(Record::Occupied {
            serial, departed, ..
        }) if serial == ORIGINAL => {
            if departed {
                let terminal = ROW.terminal();
                check!(
                    terminal == Ok(Terminal::Failed(FAILURE)),
                    c"a follower saw the departure without its terminal"
                );
            }
        }
        _ => check!(false, c"a follower's record was freed or reissued under it"),
    }
    #[cfg(not(seam = "earlydetach"))]
    ROW.detach();
}

/// One service pass over the record: a departed record with no follower
/// joined is freed and regranted.
fn servicer() {
    if !take() {
        return;
    }
    let departed = matches!(
        fill::observe(&STATE, NEXT),
        Ok(Record::Occupied { departed: true, .. })
    );
    #[cfg(not(seam = "ignoresobservers"))]
    let free = departed && ROW.observers() == 0;
    #[cfg(seam = "ignoresobservers")]
    let free = departed;
    if free {
        fill::release(&STATE);
        // The grant refuses a row with a follower joined; the planted pass
        // regrants regardless, which is its defect.
        let _ = ROW.reset();
        STATE.store(fill::occupied(REGRANT), Ordering::Relaxed);
    }
    give();
}

pub(crate) fn run() {
    // The grant, the reservation's upload grant and the follower's join,
    // all before the threads start.
    STATE.store(fill::occupied(ORIGINAL), Ordering::Relaxed);
    ROW.mark_ready(0, 0, 0);
    ROW.join();
    // SAFETY: every thread body touches only this module's statics.
    let (producing, servicing) = unsafe {
        (
            std::thread::spawn_f(producer),
            std::thread::spawn_f(servicer),
        )
    };
    // The follower runs on the main thread, so a violation it reports is
    // its last event and no join is pending behind it.
    follower();
    let _ = producing.join();
    let _ = servicing.join();
}
