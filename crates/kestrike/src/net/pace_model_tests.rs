//! Tests the datagram pacer against a `u128` model of its token contract.
//!
//! The model holds tokens in millionths, takes the rate and burst as at
//! least 1, caps the bucket at the burst saturated at `u64::MAX`, refills
//! only for time past the last forward sample, and saturates `ready_at` at
//! `u64::MAX`. Seeded histories over zero, boundary and maximal rates,
//! bursts, start times and time steps, including backward and equal
//! samples, compare the pacer's result and state with the model's after
//! every operation.

use super::pace::Pacer;
use crate::storage::seeded::SplitMix64;

const SCALE: u128 = 1_000_000;
const MAX: u128 = u64::MAX as u128;

/// The pacer's contract in `u128`: rate, cap, tokens and last sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Model {
    rate: u128,
    cap: u128,
    tokens: u128,
    last_us: u128,
}

impl Model {
    fn new(rate: u64, burst: u64, now_us: u64) -> Self {
        let cap = (u128::from(burst.max(1)) * SCALE).min(MAX);
        Self {
            rate: u128::from(rate.max(1)),
            cap,
            tokens: cap,
            last_us: u128::from(now_us),
        }
    }

    /// Adds credit for the time since `last_us`, up to the cap. A sample at
    /// or before `last_us` leaves `tokens` and `last_us` unchanged.
    fn refill(&mut self, now_us: u64) {
        let now = u128::from(now_us);
        if now > self.last_us {
            self.tokens = (self.tokens + (now - self.last_us) * self.rate).min(self.cap);
            self.last_us = now;
        }
    }

    fn ready(&mut self, now_us: u64) -> bool {
        self.refill(now_us);
        self.tokens >= SCALE
    }

    fn take(&mut self, now_us: u64) -> bool {
        let ready = self.ready(now_us);
        if ready {
            self.tokens -= SCALE;
        }
        ready
    }

    fn refund(&mut self) {
        self.tokens = (self.tokens + SCALE).min(self.cap);
    }

    fn ready_at(&mut self, now_us: u64) -> u64 {
        if self.ready(now_us) {
            return now_us;
        }
        // The wait runs from `last_us`, which a backward sample leaves in
        // place.
        let wait = (SCALE - self.tokens).div_ceil(self.rate);
        (self.last_us + wait).min(MAX) as u64
    }

    fn state(&self) -> (u64, u64, u64, u64) {
        let narrow = |value: u128| u64::try_from(value).expect("model state fits u64");
        (
            narrow(self.rate),
            narrow(self.cap),
            narrow(self.tokens),
            narrow(self.last_us),
        )
    }
}

/// One pacer call, carrying its time sample when the call takes one.
#[derive(Debug, Clone, Copy)]
enum Op {
    Ready(u64),
    Spend,
    Take(u64),
    Refund,
    ReadyAt(u64),
}

/// Rates at 0 and 1, around one token per microsecond, and large enough
/// that a refill product saturates `u64`.
const RATES: [u64; 9] = [
    0,
    1,
    2,
    999_999,
    1_000_000,
    1_000_001,
    1 << 40,
    u64::MAX / 2,
    u64::MAX,
];
/// Bursts at 0 and 1, the largest burst whose cap fits `u64`
/// (`u64::MAX / 1_000_000`), the next one, and bursts far past it.
const BURSTS: [u64; 7] = [
    0,
    1,
    3,
    18_446_744_073_709,
    18_446_744_073_710,
    1 << 50,
    u64::MAX,
];
/// Start times at 0, 1 ms, 5 s below the top of the clock, and `u64::MAX`.
const STARTS: [u64; 4] = [0, 1_000, u64::MAX - 5_000_000, u64::MAX];

/// The sample that follows `now`: up to 1 ms backward, equal, 1 µs ahead,
/// up to 2 ms ahead, up to 2^40 µs ahead, `u64::MAX / 3` ahead saturating,
/// within 2 µs of `u64::MAX`, or an absolute time below 2^20 µs.
fn next_time(rng: &mut SplitMix64, now: u64) -> u64 {
    match rng.below(8) {
        0 => now.saturating_sub(rng.below(1_000) + 1),
        1 => now,
        2 => now.saturating_add(1),
        3 => now.saturating_add(rng.below(2_000)),
        4 => now.saturating_add(rng.below(1 << 40)),
        5 => now.saturating_add(u64::MAX / 3),
        6 => u64::MAX - rng.below(3),
        _ => rng.below(1 << 20),
    }
}

/// Counts of the boundary cases the histories reached; the test requires
/// each count to be nonzero.
#[derive(Default)]
struct Reached {
    backward: u64,
    saturated_refill: u64,
    spend: u64,
    saturated_deadline_without_credit: u64,
    unsaturated_deadline: u64,
    refund_at_cap: u64,
    refused_take: u64,
}

/// Runs `steps` seeded operations on one pacer and its model, asserting
/// equal results and states after each, and records the boundary cases
/// reached. `Spend` is drawn only while the model holds a token, which
/// meets `spend`'s precondition.
fn run(rate: u64, burst: u64, start: u64, seed: u64, steps: u64, reached: &mut Reached) {
    let mut rng = SplitMix64::new(seed);
    let (mut pacer, mut model) = (
        Pacer::new(rate, burst, start),
        Model::new(rate, burst, start),
    );
    assert_eq!(pacer.parts(), model.state());
    let mut now = start;
    for step in 0..steps {
        let at = next_time(&mut rng, now);
        let op = match rng.below(6) {
            0 => Op::Ready(at),
            1 if model.tokens >= SCALE => Op::Spend,
            1 | 2 => Op::Take(at),
            3 => Op::Refund,
            _ => Op::ReadyAt(at),
        };
        if let Op::Ready(at) | Op::Take(at) | Op::ReadyAt(at) = op {
            let at = u128::from(at);
            reached.backward += u64::from(at < model.last_us);
            let product = at.saturating_sub(model.last_us) * model.rate;
            reached.saturated_refill += u64::from(model.tokens + product > MAX);
        }
        let (got, wanted) = match op {
            Op::Ready(at) => (u64::from(pacer.ready(at)), u64::from(model.ready(at))),
            Op::Spend => {
                reached.spend += 1;
                pacer.spend();
                model.tokens -= SCALE;
                (0, 0)
            }
            Op::Take(at) => {
                let taken = model.take(at);
                reached.refused_take += u64::from(!taken);
                (u64::from(pacer.take(at)), u64::from(taken))
            }
            Op::Refund => {
                reached.refund_at_cap += u64::from(model.tokens + SCALE > model.cap);
                pacer.refund();
                model.refund();
                (0, 0)
            }
            Op::ReadyAt(at) => {
                let deadline = model.ready_at(at);
                if deadline == u64::MAX && model.tokens < SCALE {
                    reached.saturated_deadline_without_credit += 1;
                } else {
                    // An unsaturated deadline is the first instant a token
                    // is available, checked on the pacer itself.
                    let mut probe = pacer;
                    let _ = probe.ready(at);
                    let mut at_deadline = probe;
                    assert!(at_deadline.ready(deadline), "{op:?} names {deadline}");
                    if deadline > at && model.tokens < SCALE {
                        reached.unsaturated_deadline += 1;
                        assert!(!probe.ready(deadline - 1), "{op:?} names {deadline}");
                    }
                }
                (pacer.ready_at(at), deadline)
            }
        };
        assert_eq!(
            (got, pacer.parts()),
            (wanted, model.state()),
            "rate {rate} burst {burst} start {start} step {step} {op:?}"
        );
        if matches!(op, Op::Ready(_) | Op::Take(_) | Op::ReadyAt(_)) {
            now = at;
        }
    }
}

/// Seeded 400-operation histories for every rate, burst and start time
/// agree with the model after every operation, and each unsaturated
/// deadline is the first instant the pacer holds a token. Together the
/// histories reach a backward sample, a refill past `u64::MAX`, a spend, a
/// saturated deadline with less than one token, a deadline ahead of its
/// sample, a refund the cap clips, and a refused take.
#[test]
fn ib_pacer_wide_model_every_operation_matches_the_u128_model() {
    let mut reached = Reached::default();
    let mut seed = 0;
    for rate in RATES {
        for burst in BURSTS {
            for start in STARTS {
                seed += 1;
                run(rate, burst, start, seed, 400, &mut reached);
            }
        }
    }
    assert!(reached.backward > 0, "a backward sample");
    assert!(reached.saturated_refill > 0, "a refill past u64::MAX");
    assert!(reached.spend > 0, "a spend");
    assert!(
        reached.saturated_deadline_without_credit > 0,
        "a saturated deadline"
    );
    assert!(reached.unsaturated_deadline > 0, "a deadline ahead");
    assert!(reached.refund_at_cap > 0 && reached.refused_take > 0);
}

/// A backward or equal sample leaves the tokens and the last forward sample
/// unchanged, so refill resumes from that sample, and a deadline asked at a
/// backward sample falls one full wait after the last forward sample.
#[test]
fn ib_pacer_wide_model_backward_time_adds_no_credit() {
    let mut pacer = Pacer::new(1_000, 1, 10_000);
    assert!(pacer.take(10_000));
    assert!(!pacer.ready(9_000));
    assert!(!pacer.ready(10_000));
    assert_eq!(pacer.parts(), (1_000, 1_000_000, 0, 10_000));
    // 999 µs after the last forward sample hold 999/1000 of a token.
    assert!(!pacer.ready(10_999));
    assert!(!pacer.ready(5_000));
    assert!(pacer.ready(11_000));
    assert_eq!(pacer.parts().3, 11_000);
    // A deadline asked at a backward sample runs from the last forward one.
    let mut pacer = Pacer::new(1_000, 1, 10_000);
    assert!(pacer.take(10_000));
    assert_eq!(pacer.ready_at(9_000), 11_000);
    assert!(!pacer.ready(10_999) && pacer.ready(11_000));
}

/// At rate 1 a token takes 1_000_000 µs, so a deadline asked 10 µs below
/// the top of the clock saturates at `u64::MAX`, where the bucket holds 10
/// millionths of a token. A saturated deadline bounds the wait, and `ready`
/// decides whether a token is available there.
#[test]
fn ib_pacer_wide_model_saturated_deadline_is_no_credit() {
    let now = u64::MAX - 10;
    let mut pacer = Pacer::new(1, 1, now);
    assert!(pacer.take(now));
    assert_eq!(pacer.ready_at(now), u64::MAX);
    assert!(!pacer.ready(u64::MAX));
    assert_eq!(pacer.parts().2, 10);
}
