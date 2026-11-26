//! A terminal shard's removal under GenMC: a terminator, a later holder of
//! the shard and a reader whose snapshot started at the last usable even
//! sequence. The sequence is the production `index::sequence` module: the
//! terminator runs `terminate` from `TERMINAL - 2`, the exact terminal
//! boundary, and the reader runs `read_stable` and `still` around one
//! `SeqCst` load of the bucket field. The terminator hands the shard to the
//! holder with a release store the holder acquires, the model's gate. The
//! holder, once it acquires the handoff, makes the store that stands for
//! the production terminal path's bare stores: its own release fence, then
//! one `Relaxed` store of the field, as `remove.rs` issues behind its fence.
//!
//! The `fence` cfg picks the holder: `own` issues the fence, as production
//! does; `none` is the control, whose holder stores the field with the
//! terminator's fence, in another thread, as the last fence before it. A
//! fence orders the stores sequenced after it in its own thread, so in that
//! control a reader that copied the new field can read its starting
//! sequence again. The `witness = "observed"` cfg runs the fenced holder
//! with one check that some reader copies the removal's store, so the
//! guarded state is reachable.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::check::check;
use crate::sequence::{TERMINAL, read_stable, still, terminate};

const OLD: u64 = 1;
const NEW: u64 = 2;

static SEQUENCE: AtomicU64 = AtomicU64::new(TERMINAL - 2);
static FIELD: AtomicU64 = AtomicU64::new(OLD);
static HANDED: AtomicBool = AtomicBool::new(false);
static OBSERVED: AtomicBool = AtomicBool::new(false);

/// The hold that makes the shard terminal, then the gate's release.
fn terminator() {
    terminate(&SEQUENCE);
    HANDED.store(true, Ordering::Release);
}

/// The next hold of the terminal shard: the gate's acquire, then the
/// removal's fence and bare store.
fn holder() {
    if !HANDED.load(Ordering::Acquire) {
        return;
    }
    #[cfg(fence = "own")]
    std::sync::atomic::fence(Ordering::Release);
    FIELD.store(NEW, Ordering::Relaxed);
}

/// One snapshot attempt: a stable start, the field's copy and the recheck.
fn reader() {
    let Ok(started) = read_stable(&SEQUENCE) else {
        return;
    };
    check!(
        started != TERMINAL,
        c"the terminal value was a starting value"
    );
    let copy = FIELD.load(Ordering::SeqCst);
    if copy == NEW {
        OBSERVED.store(true, Ordering::SeqCst);
    }
    if still(&SEQUENCE, started) {
        check!(
            copy == OLD,
            c"a copy of the terminal removal's bare store was accepted under the old sequence"
        );
    }
}

pub(crate) fn run() {
    // SAFETY: every thread body touches only this module's statics.
    let (terminating, holding) = unsafe {
        (
            std::thread::spawn_f(terminator),
            std::thread::spawn_f(holder),
        )
    };
    reader();
    let _ = terminating.join();
    let _ = holding.join();
    #[cfg(witness = "observed")]
    check!(
        !OBSERVED.load(Ordering::SeqCst),
        c"witness reached: a reader copied the terminal removal's bare store"
    );
}
