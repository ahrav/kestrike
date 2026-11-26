//! Loom kernels for the escrow of the `builder` module, over every
//! schedule the search reaches within the preemption bound.
//!
//! The conservation kernel runs two builders that promise and place an
//! extent each and then cancel, refund as a drop does, or place their second
//! extent, against a gate holder that makes a direct claim. Model
//! substitutions: the pool gate is a loom mutex over the free units and the
//! escrow's gate-held term `promised`, the refund term `refunded` is a loom
//! atomic that a refund raises with one read-modify-write, and each builder
//! owns its remaining charge as a plain value. `U` is `promised - refunded`,
//! and a cancel tries the gate once, settling under it or refunding when the
//! try fails, as production does. Nine units hold both promises or one
//! promise and the direct claim's unit at once, so the schedule decides
//! whether the second promise or the claim refuses at the allocatable
//! boundary, or neither when a placement and refund run first.
//!
//! Properties: under every gate hold `U <= free`, and a direct claim never
//! spends a unit a builder holds promised; at the end `U` is zero and the
//! free units plus the placed and claimed units equal the volume. The
//! kernel restates the `builder` module's steps over its own counters.
//!
//! The sample kernel runs one builder that promises and places under the
//! gate and then refunds without it, against a thread that reads the escrow
//! without the gate as `Telemetry::escrow` does: `refunded`, then `promised`.
//! With a release refund and an acquire read, the sample stays within the
//! charge.
//!
//! Negative controls: with both builders refunding, a refund written as a
//! load and a store loses the other refund, and the end-state assertion on
//! `U` fails; a relaxed refund read by a relaxed sample lets the sample count
//! a refund without the promise behind it, and the sample's assertion fails.
//! Each control is matched on its assertion's message.
//!
//! Bounds: loom `0.7.2`, preemption bound 3. Run with
//! `RUSTFLAGS="--cfg loom" cargo test -p kestrike --lib --release escrow_model`.

use std::sync::atomic::Ordering;

use loom::sync::atomic::AtomicU64;
use loom::sync::{Arc, Mutex};
use loom::thread;

/// Units of the volume.
const VOLUME: u64 = 9;
/// The clean reserve.
const RESERVE: u64 = 1;
/// One builder's charge: two extents of two units.
const CHARGE: u64 = 4;
const EXTENT: u64 = 2;

struct Model {
    /// The free units and the escrow's gate-held term, which only the gate
    /// holder reads or writes.
    gate: Mutex<(u64, u64)>,
    refunded: AtomicU64,
    /// Units placed by builders or claimed directly.
    taken: AtomicU64,
}

#[derive(Clone, Copy)]
enum Refund {
    /// One read-modify-write, as production does.
    Atomic,
    /// A load and a store: the planted defect.
    LoadStore,
}

/// How a builder ends after its first placement.
#[derive(Clone, Copy)]
enum End {
    /// One gate try: settle under the gate, or refund when the try fails.
    Cancel,
    /// A refund without the gate, as a drop does.
    Refund,
    /// Places the second extent, leaving nothing to refund.
    Complete,
}

impl Model {
    /// Asserts `U <= free` for the gate-held `(free, promised)` and returns
    /// `U`. The caller holds `gate`.
    fn check(&self, (free, promised): (u64, u64)) -> u64 {
        let escrow = promised.wrapping_sub(self.refunded.load(Ordering::Acquire));
        assert!(escrow <= free, "the escrow passes the free units");
        escrow
    }

    /// Promises a builder's charge, or `None` when allocatable units fall
    /// short.
    fn promise(&self) -> Option<u64> {
        let mut held = self.gate.lock().unwrap();
        let allocatable = held.0 - self.check(*held);
        if allocatable < CHARGE + RESERVE {
            return None;
        }
        held.1 += CHARGE;
        Some(CHARGE)
    }

    /// Places one extent of a promise with `remaining` units.
    fn place(&self, remaining: &mut u64) {
        let mut held = self.gate.lock().unwrap();
        self.check(*held);
        held.0 -= EXTENT;
        held.1 -= EXTENT;
        self.taken.fetch_add(EXTENT, Ordering::Relaxed);
        *remaining -= EXTENT;
    }

    /// Refunds `remaining` without the gate.
    fn refund(&self, remaining: u64, refund: Refund) {
        match refund {
            Refund::Atomic => {
                self.refunded.fetch_add(remaining, Ordering::Release);
            }
            Refund::LoadStore => {
                let refunded = self.refunded.load(Ordering::Relaxed);
                thread::yield_now();
                self.refunded.store(refunded + remaining, Ordering::Release);
            }
        }
    }

    /// Settles `remaining` under one gate try, or refunds it without the
    /// gate when the try fails.
    fn cancel(&self, remaining: u64, refund: Refund) {
        match self.gate.try_lock() {
            Ok(mut held) => {
                self.check(*held);
                held.1 -= remaining;
            }
            Err(_) => self.refund(remaining, refund),
        }
    }

    /// A direct claim of one unit, which counts `U` against the free units.
    fn direct(&self) {
        let mut held = self.gate.lock().unwrap();
        if held.0 - self.check(*held) > RESERVE {
            held.0 -= 1;
            self.taken.fetch_add(1, Ordering::Relaxed);
        }
        self.check(*held);
    }

    /// Promises, places one extent and ends as `end`; a refused promise
    /// ends the builder with nothing held.
    fn builder(&self, end: End, refund: Refund) {
        if let Some(mut remaining) = self.promise() {
            self.place(&mut remaining);
            match end {
                End::Cancel => self.cancel(remaining, refund),
                End::Refund => self.refund(remaining, refund),
                End::Complete => {
                    self.place(&mut remaining);
                    assert_eq!(remaining, 0);
                }
            }
        }
    }
}

fn bounded() -> loom::model::Builder {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(3);
    builder
}

fn model(ends: [End; 2], refund: Refund) {
    bounded().check(move || {
        let model = Arc::new(Model {
            gate: Mutex::new((VOLUME, 0)),
            refunded: AtomicU64::new(0),
            taken: AtomicU64::new(0),
        });
        let builders = ends.map(|end| {
            let model = Arc::clone(&model);
            thread::spawn(move || model.builder(end, refund))
        });
        model.direct();
        for builder in builders {
            builder.join().unwrap();
        }
        let (free, promised) = *model.gate.lock().unwrap();
        assert_eq!(
            promised.wrapping_sub(model.refunded.load(Ordering::Acquire)),
            0,
            "the escrow returns to zero"
        );
        assert_eq!(
            free + model.taken.load(Ordering::Relaxed),
            VOLUME,
            "units are conserved"
        );
    });
}

/// One builder promises and places under the gate, then refunds without it
/// with `refund`, while the main thread samples the escrow without the gate,
/// reading `refunded` with `read` and then `promised`, as the pool report
/// does.
fn sample(refund: Ordering, read: Ordering) {
    bounded().check(move || {
        let gate = Arc::new(Mutex::new(()));
        let promised = Arc::new(AtomicU64::new(0));
        let refunded = Arc::new(AtomicU64::new(0));
        let builder = {
            let (gate, promised, refunded) = (gate.clone(), promised.clone(), refunded.clone());
            thread::spawn(move || {
                for delta in [CHARGE, EXTENT.wrapping_neg()] {
                    let _held = gate.lock().unwrap();
                    let value = promised.load(Ordering::Relaxed);
                    promised.store(value.wrapping_add(delta), Ordering::Relaxed);
                }
                refunded.fetch_add(CHARGE - EXTENT, refund);
            })
        };
        let counted = refunded.load(read);
        let escrow = promised.load(Ordering::Relaxed).wrapping_sub(counted);
        assert!(escrow <= CHARGE, "the sample wraps");
        builder.join().unwrap();
    });
}

#[test]
fn promises_placements_and_refunds_conserve_the_escrow() {
    for ends in [
        [End::Cancel, End::Complete],
        [End::Cancel, End::Refund],
        [End::Refund, End::Refund],
    ] {
        model(ends, Refund::Atomic);
    }
}

#[test]
#[should_panic(expected = "the escrow returns to zero")]
fn negative_control_a_load_store_refund_loses_a_refund() {
    model([End::Refund, End::Refund], Refund::LoadStore);
}

#[test]
fn a_released_refund_keeps_the_gate_free_sample_in_range() {
    sample(Ordering::Release, Ordering::Acquire);
}

#[test]
#[should_panic(expected = "the sample wraps")]
fn negative_control_a_relaxed_refund_lets_the_sample_wrap() {
    sample(Ordering::Relaxed, Ordering::Relaxed);
}
