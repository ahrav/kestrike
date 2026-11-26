//! The `credit_model` kernel under GenMC: one record's pool and return line
//! and its bit in one map word. A returner parks credits, a scanner runs the
//! scan's per-record steps and the main thread takes as the owner, all
//! through the production `credit` steps.
//!
//! The strength comes from the `strength` cfg:
//!
//! - `seq`: production `Sequential`, `SeqCst` accesses and no fences.
//! - `fenced`: `Release`/`Acquire` accesses with a `SeqCst` fence after the
//!   park's add and after the scan's clear, the Loom model's stand-in.
//! - `nopark` and `noclear`: the stand-in without the park's or the scan's
//!   fence, the two single-fence controls.
//!
//! The `state` cfg picks the record: `empty` (no credit, bit clear, one
//! return), `stale` (no credit, bit set, one return), `pool1` (one credit,
//! one return) and `two` (no credit, bit set, two returns). Each property
//! has its own check, so a control is matched on the hidden-credit check
//! alone.

#[cfg(not(strength = "seq"))]
use std::sync::atomic::fence;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crate::check::check;
#[cfg(strength = "seq")]
use crate::storage::credit::Sequential;
#[cfg(not(strength = "seq"))]
use crate::storage::credit::Strength;
use crate::storage::credit_steps::{BIT, Record};

/// `Release`/`Acquire` accesses with a `SeqCst` fence at each pair whose
/// parameter is `true`.
#[cfg(not(strength = "seq"))]
struct Model<const PARK: bool, const CLEAR: bool>;

#[cfg(not(strength = "seq"))]
impl<const PARK: bool, const CLEAR: bool> Strength for Model<PARK, CLEAR> {
    const ADD: Ordering = Ordering::Release;
    const BIT_LOAD: Ordering = Ordering::Acquire;
    const CLEAR: Ordering = Ordering::AcqRel;
    const RELOAD: Ordering = Ordering::Acquire;

    #[inline(always)]
    fn fence_park() {
        if PARK {
            fence(Ordering::SeqCst);
        }
    }

    #[inline(always)]
    fn fence_clear() {
        if CLEAR {
            fence(Ordering::SeqCst);
        }
    }
}

#[cfg(strength = "seq")]
type S = Sequential;
#[cfg(strength = "fenced")]
type S = Model<true, true>;
#[cfg(strength = "nopark")]
type S = Model<false, true>;
#[cfg(strength = "noclear")]
type S = Model<true, false>;

/// The record a case starts from.
struct Start {
    /// Credits in the pool.
    pool: usize,
    /// Whether the bit is set while the record holds none.
    stale_bit: bool,
    /// Credits the returner parks.
    returns: usize,
}

#[cfg(state = "empty")]
const START: Start = Start {
    pool: 0,
    stale_bit: false,
    returns: 1,
};
#[cfg(state = "stale")]
const START: Start = Start {
    pool: 0,
    stale_bit: true,
    returns: 1,
};
#[cfg(state = "pool1")]
const START: Start = Start {
    pool: 1,
    stale_bit: false,
    returns: 1,
};
#[cfg(state = "two")]
const START: Start = Start {
    pool: 0,
    stale_bit: true,
    returns: 2,
};

const INITIAL_POOL: usize = START.pool;
const RETURNS: usize = START.returns;
const INITIAL_MAP: u64 = if INITIAL_POOL > 0 || START.stale_bit {
    BIT
} else {
    0
};

static RECORD: Record<AtomicUsize, AtomicU64> = Record {
    pool: AtomicUsize::new(INITIAL_POOL),
    line: AtomicUsize::new(0),
    map: AtomicU64::new(INITIAL_MAP),
};
static SCANNER_TAKEN: AtomicUsize = AtomicUsize::new(0);

fn returner() {
    RECORD.give_back::<S>(RETURNS);
}

fn scanner() {
    SCANNER_TAKEN.store(RECORD.scan::<S>(), Ordering::Relaxed);
}

pub(crate) fn run() {
    // SAFETY: both thread bodies touch only the statics above.
    let (returner, scanner) = unsafe {
        (
            std::thread::spawn_f(returner),
            std::thread::spawn_f(scanner),
        )
    };
    let owner_taken = RECORD.owner_take::<S>();
    let _ = returner.join();
    let _ = scanner.join();
    check!(
        RECORD.held() + owner_taken + SCANNER_TAKEN.load(Ordering::Relaxed)
            == INITIAL_POOL + RETURNS,
        c"credits conserved"
    );
    check!(RECORD.owes_nothing(), c"no debt left behind");
    check!(
        RECORD.discoverable(),
        c"a record holding credits is flagged"
    );
}
