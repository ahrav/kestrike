//! The admission cutoff against a registration's pin under GenMC: an
//! entrant, a closer and a scanner that runs after it reads the cutoff
//! closed. The entrant is the production `enter`: the production `grace`
//! `pin` at `Sequential`, then the `SeqCst` cutoff load, a refusal that
//! clears the new pin with the production `unpin` before anything is
//! observed, and an admitted interval that marks its protected work done
//! and unpins. The closer is the production `close`, one `SeqCst` store of
//! the cutoff. The scanner is the production
//! `is_closed` load followed by a production `PassCursor` begin and one
//! visit of the record.
//!
//! The `order` cfg picks the entrant: `pinfirst` is production's; in
//! `cutofffirst` the cutoff load precedes the pin, the control in which a
//! close landing between the two lets a scan after the close read the
//! record `INACTIVE` while the interval it misses is admitted. The
//! `witness` cfg runs the production entrant with one check that some
//! execution admits the entry while a scan after the close sees its live
//! pin (`admitted`), or refuses it (`refused`), so each outcome is shown
//! reachable. The refused branch returns before the protected work, so a
//! refusal observes nothing by construction; its check is that the pin is
//! clear. The `refusal = "keeps"` control leaves a refused entry's pin
//! set.
//!
//! The scan flags a miss when it reads the cutoff closed, finds the record
//! `INACTIVE` and the interval's protected work not done: a scan that reads
//! the clearing store synchronizes with the release `unpin` and so also
//! reads the done mark sequenced before it. The flag is sufficient for a
//! miss; the litmus tests carry the exact miss condition, a read of the
//! initial value whatever the done mark holds.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::check::check;
use crate::storage::grace::{ERA_FIRST, INACTIVE, PassCursor, Sequential, pin, unpin};

static ERA: AtomicU64 = AtomicU64::new(ERA_FIRST);
static PIN: AtomicU64 = AtomicU64::new(INACTIVE);
static CLOSED: AtomicBool = AtomicBool::new(false);
static ADMITTED: AtomicBool = AtomicBool::new(false);
static REFUSED: AtomicBool = AtomicBool::new(false);
static DONE: AtomicBool = AtomicBool::new(false);
static MISSED: AtomicBool = AtomicBool::new(false);
static SAW_PIN: AtomicBool = AtomicBool::new(false);

/// The interval's protected work, ending with the done mark.
fn protected() {
    DONE.store(true, Ordering::SeqCst);
}

/// The production entry: the pin, then the cutoff. The `refusal = "keeps"`
/// control leaves the refused entry's pin set.
#[cfg(order = "pinfirst")]
fn entrant() {
    check!(pin::<_, Sequential>(&ERA, &PIN).is_ok(), c"pin refused");
    if CLOSED.load(Ordering::SeqCst) {
        #[cfg(not(refusal = "keeps"))]
        unpin(&PIN);
        REFUSED.store(true, Ordering::SeqCst);
        return;
    }
    ADMITTED.store(true, Ordering::SeqCst);
    protected();
    unpin(&PIN);
}

/// The control: the cutoff read first, then the pin.
#[cfg(order = "cutofffirst")]
fn entrant_cutoff_first() {
    let closed = CLOSED.load(Ordering::SeqCst);
    check!(pin::<_, Sequential>(&ERA, &PIN).is_ok(), c"pin refused");
    if closed {
        unpin(&PIN);
        REFUSED.store(true, Ordering::SeqCst);
        return;
    }
    ADMITTED.store(true, Ordering::SeqCst);
    protected();
    unpin(&PIN);
}

/// The production close.
fn closer() {
    CLOSED.store(true, Ordering::SeqCst);
}

/// A scan after the close: the cutoff load, then one visit of the record.
fn scanner() {
    if !CLOSED.load(Ordering::SeqCst) {
        return;
    }
    let mut cursor = PassCursor::begin::<_, Sequential>(&ERA);
    if cursor.visit::<_, Sequential>(&PIN) == INACTIVE {
        if !DONE.load(Ordering::SeqCst) {
            MISSED.store(true, Ordering::SeqCst);
        }
    } else {
        SAW_PIN.store(true, Ordering::SeqCst);
    }
}

pub(crate) fn run() {
    // SAFETY: every thread body touches only this module's statics.
    let (closing, scanning) =
        unsafe { (std::thread::spawn_f(closer), std::thread::spawn_f(scanner)) };
    #[cfg(order = "pinfirst")]
    entrant();
    #[cfg(order = "cutofffirst")]
    entrant_cutoff_first();
    let _ = closing.join();
    let _ = scanning.join();
    let admitted = ADMITTED.load(Ordering::SeqCst);
    let refused = REFUSED.load(Ordering::SeqCst);
    check!(
        admitted != refused,
        c"an entry neither admitted nor refused"
    );
    check!(
        !(admitted && MISSED.load(Ordering::SeqCst)),
        c"protection violated: a scan after the close missed an admitted interval's live pin"
    );
    check!(
        !refused || PIN.load(Ordering::SeqCst) == INACTIVE,
        c"a refused entry kept its pin"
    );
    #[cfg(witness = "admitted")]
    check!(
        !(admitted && SAW_PIN.load(Ordering::SeqCst)),
        c"witness reached: an admitted interval's live pin seen by a scan after the close"
    );
    #[cfg(witness = "refused")]
    check!(!refused, c"witness reached: an entry was refused");
}
