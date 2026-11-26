//! Qualification cases for the patched checker, one per build:
//!
//! - `sb_sc`: store buffering with `SeqCst` stores and loads and no fences.
//!   RC11 forbids both loads reading 0, so the case completes with no
//!   violation.
//! - `sb_prior_rmw`: store buffering with a `SeqCst` fence in each thread,
//!   one thread first making a relaxed read-modify-write of the other's
//!   variable. RC11 forbids both loads reading 0 whatever that
//!   read-modify-write read.
//! - `sb_relaxed`: store buffering with `Release` stores, `Acquire` loads
//!   and no fences. RC11 allows both loads reading 0, so the case reports a
//!   violation at its check: the route explores weak outcomes, not only
//!   interleavings.
//! - `intrinsic_boundaries`: each saturating and min/max intrinsic the
//!   checker lowers, at zero, at overflow or underflow, at equality and at
//!   the signed boundaries, each result checked against its definition. The
//!   operations come from `genmc-boundary-ops`, built where LLVM emits the
//!   intrinsics, and the operands are loaded from atomics, so the intrinsic
//!   calls reach the checker with values it learns only at run time.
//! - `wrap_falsifier`: a check that zero minus one saturates to the wrapped
//!   value `u64::MAX`. A lowering that wraps would admit it; the correct
//!   lowering yields zero, so the case reports a violation at this check.

#[cfg(any(case = "sb_sc", case = "sb_prior_rmw", case = "sb_relaxed"))]
mod store_buffering {
    use std::sync::atomic::{AtomicU64, Ordering, fence};

    use crate::check::check;

    static X: AtomicU64 = AtomicU64::new(0);
    static Y: AtomicU64 = AtomicU64::new(0);
    static R0: AtomicU64 = AtomicU64::new(9);
    static R1: AtomicU64 = AtomicU64::new(9);
    static SEEN: AtomicU64 = AtomicU64::new(9);

    const PRIOR_RMW: bool = cfg!(case = "sb_prior_rmw");
    const SEQUENTIAL: bool = cfg!(case = "sb_sc");
    const STORE: Ordering = if SEQUENTIAL {
        Ordering::SeqCst
    } else {
        Ordering::Release
    };
    const LOAD: Ordering = if SEQUENTIAL {
        Ordering::SeqCst
    } else {
        Ordering::Acquire
    };

    fn first() {
        X.store(1, STORE);
        if PRIOR_RMW {
            fence(Ordering::SeqCst);
        }
        R0.store(Y.load(LOAD), Ordering::Relaxed);
    }

    fn second() {
        if PRIOR_RMW {
            SEEN.store(X.fetch_add(0, Ordering::Relaxed), Ordering::Relaxed);
        }
        Y.store(1, STORE);
        if PRIOR_RMW {
            fence(Ordering::SeqCst);
        }
        R1.store(X.load(LOAD), Ordering::Relaxed);
    }

    pub(super) fn run() {
        // SAFETY: both thread bodies touch only the statics above.
        let (a, b) = unsafe { (std::thread::spawn_f(first), std::thread::spawn_f(second)) };
        let _ = a.join();
        let _ = b.join();
        let (r0, r1) = (R0.load(Ordering::Relaxed), R1.load(Ordering::Relaxed));
        check!(
            !(r0 == 0 && r1 == 0),
            c"store buffering outcome r0 == r1 == 0"
        );
    }
}

#[cfg(any(case = "intrinsic_boundaries", case = "wrap_falsifier"))]
mod intrinsics {
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::check::check;

    static ZERO: AtomicU64 = AtomicU64::new(0);
    static ONE: AtomicU64 = AtomicU64::new(1);
    static SEVEN: AtomicU64 = AtomicU64::new(7);
    static MAX: AtomicU64 = AtomicU64::new(u64::MAX);
    static NEGATIVE_ONE: AtomicU64 = AtomicU64::new(-1i64 as u64);
    static SIGNED_MIN: AtomicU64 = AtomicU64::new(i64::MIN as u64);
    static SIGNED_MAX: AtomicU64 = AtomicU64::new(i64::MAX as u64);

    fn load(word: &AtomicU64) -> u64 {
        word.load(Ordering::Relaxed)
    }

    fn signed(word: &AtomicU64) -> i64 {
        load(word) as i64
    }

    #[cfg(case = "intrinsic_boundaries")]
    pub(super) fn run() {
        use genmc_boundary_ops::{smax, smin, uadd_sat, umax, umin, usub_sat};

        let (zero, one, seven, max) = (load(&ZERO), load(&ONE), load(&SEVEN), load(&MAX));
        check!(uadd_sat(zero, zero) == 0, c"uadd.sat at zero");
        check!(uadd_sat(max, one) == u64::MAX, c"uadd.sat at overflow");
        check!(
            uadd_sat(max - one, one) == u64::MAX,
            c"uadd.sat at the exact maximum"
        );
        check!(uadd_sat(one, seven) == 8, c"uadd.sat in range");
        check!(usub_sat(zero, one) == 0, c"usub.sat at underflow");
        check!(usub_sat(seven, seven) == 0, c"usub.sat at equality");
        check!(usub_sat(seven, one) == 6, c"usub.sat in range");
        check!(usub_sat(zero, zero) == 0, c"usub.sat at zero");
        check!(
            umin(zero, max) == 0 && umin(max, zero) == 0 && umin(seven, seven) == 7,
            c"umin"
        );
        check!(
            umax(zero, max) == u64::MAX && umax(max, zero) == u64::MAX && umax(seven, seven) == 7,
            c"umax"
        );
        let (negative_one, low, high) = (
            signed(&NEGATIVE_ONE),
            signed(&SIGNED_MIN),
            signed(&SIGNED_MAX),
        );
        check!(
            smin(negative_one, 0) == -1
                && smin(low, high) == i64::MIN
                && smin(negative_one, negative_one) == -1,
            c"smin"
        );
        check!(
            smax(negative_one, 0) == 0
                && smax(low, high) == i64::MAX
                && smax(high, high) == i64::MAX,
            c"smax"
        );
    }

    #[cfg(case = "wrap_falsifier")]
    pub(super) fn run() {
        let (zero, one) = (load(&ZERO), load(&ONE));
        check!(
            genmc_boundary_ops::usub_sat(zero, one) == u64::MAX,
            c"zero minus one saturated to the wrapped value"
        );
    }
}

pub(crate) fn run() {
    #[cfg(any(case = "sb_sc", case = "sb_prior_rmw", case = "sb_relaxed"))]
    store_buffering::run();
    #[cfg(any(case = "intrinsic_boundaries", case = "wrap_falsifier"))]
    intrinsics::run();
}
