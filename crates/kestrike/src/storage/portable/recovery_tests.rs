//! The test-only recovery conversion against hand-computed values, each withheld cause in its order, the local rate bound, the boundary at or below which a pair stays `Expired` under `Recovery::retained`, and a seeded `u128` oracle in true time that every recovery planted control fails by name.

use std::cell::Cell;
use std::rc::Rc;

use super::super::seeded::SplitMix64;
use super::clock::{ClockScale, Reading, Trust, Untrusted};
use super::contract::{CONTRACT_LEN, ClockContract};
use super::expiry::{NANOS_PER_MILLI, NANOS_PER_SECOND};
use super::plant::{Plant, plant};
use super::recovery::{Recovery, Scenario, Withheld, oracle_accepts, recover, recovered_deadline};
use super::scripted::ScriptedClock;

pub(super) const E: u64 = 1_700_000_000 * NANOS_PER_SECOND;
pub(super) const M: u64 = 50 * NANOS_PER_SECOND;

pub(super) fn contract(rate_error_ppb: u32) -> ClockContract {
    ClockContract {
        scale: ClockScale::UtcSmeared,
        max_uncertainty_ns: 4_000_000,
        rate_error_ppb,
        provenance: 7,
    }
}

pub(super) fn root(rate_error_ppb: u32) -> [u8; CONTRACT_LEN] {
    contract(rate_error_ppb).encode()
}

pub(super) fn reading(earliest: u64, latest: u64) -> Reading {
    Reading {
        earliest,
        latest,
        trust: Trust::Trusted,
    }
}

/// The pair a writer stored from `[E, E + 2 ms]` with ten seconds of life.
pub(super) const PAIR: (u64, u32) = (E + 10 * NANOS_PER_SECOND, 10_000);

/// With zero rate error, a recovery reading `[E + 4 s, E + 4.002 s]` after the sample `M` leaves 5.998 s, so the local deadline is `deadline_seconds(M + 5.998 s)`.
#[test]
fn a_recovery_reading_leaves_the_life_after_its_latest_bound() {
    let latest = E + 4 * NANOS_PER_SECOND + 2_000_000;
    let recovered = recovered_deadline(
        PAIR,
        &root(0),
        &contract(0),
        &reading(E + 4 * NANOS_PER_SECOND, latest),
        Some(M),
    );
    assert_eq!(
        recovered,
        Ok(((M + 5_998 * NANOS_PER_MILLI) / NANOS_PER_SECOND) as u32)
    );
}

/// A local rate error of 100 ppm over 5.998 s removes 599,800 ns; the rounded deadline moves below a second boundary only when that margin crosses one, which the sample one millisecond past `M` arranges.
#[test]
fn a_local_rate_error_shortens_by_its_margin() {
    let before = M + 2_001_000;
    let read = reading(
        E + 4 * NANOS_PER_SECOND,
        E + 4 * NANOS_PER_SECOND + 2_000_000,
    );
    // `before + 5.998 s` is `M + 6.000001 s`, one second boundary past `M + 5 s`.
    assert_eq!(
        recovered_deadline(PAIR, &root(0), &contract(0), &read, Some(before)),
        Ok((M / NANOS_PER_SECOND + 6) as u32)
    );
    // Shortened by 599,800 ns the end falls to `M + 5.9994 s`.
    assert_eq!(
        recovered_deadline(PAIR, &root(0), &contract(100_000), &read, Some(before)),
        Ok((M / NANOS_PER_SECOND + 5) as u32)
    );
}

/// Recovery converts through the recovering host's rate bound even when the root's is smaller.
#[test]
fn recovery_uses_the_local_rate_bound_over_the_roots() {
    let before = M + 2_001_000;
    let read = reading(
        E + 4 * NANOS_PER_SECOND,
        E + 4 * NANOS_PER_SECOND + 2_000_000,
    );
    assert_eq!(
        recovered_deadline(PAIR, &root(1_000), &contract(100_000), &read, Some(before)),
        Ok((M / NANOS_PER_SECOND + 5) as u32)
    );
}

/// Each withheld cause refuses by name, in its order: the pair first, then the contract, the reading's trust and width, a backward step and expiry, then the clamp.
#[test]
fn each_withheld_cause_refuses_by_name() {
    let local = contract(0);
    let read = reading(
        E + 4 * NANOS_PER_SECOND,
        E + 4 * NANOS_PER_SECOND + 2_000_000,
    );
    let recover = |pair, root: &[u8; CONTRACT_LEN], reading: &Reading, before| {
        recovered_deadline(pair, root, &local, reading, Some(before))
    };
    assert_eq!(
        recover((E, 0), &root(0), &read, M),
        Err(Withheld::Malformed)
    );
    // A deadline at the lifetime's span would put the earliest bound at zero; the check runs before any subtraction.
    assert_eq!(
        recover((10 * NANOS_PER_SECOND, 10_000), &root(0), &read, M),
        Err(Withheld::Malformed)
    );
    assert_eq!(
        recover((1, u32::MAX), &root(0), &read, M),
        Err(Withheld::Malformed)
    );
    let stepped = ClockContract {
        scale: ClockScale::UtcStepped,
        ..local
    };
    assert_eq!(
        recover(PAIR, &stepped.encode(), &read, M),
        Err(Withheld::ContractMismatch)
    );
    let mut foreign_guarantee = root(0);
    foreign_guarantee[3] = 2;
    assert_eq!(
        recover(PAIR, &foreign_guarantee, &read, M),
        Err(Withheld::ContractMismatch)
    );
    assert_eq!(
        recover(PAIR, &root(0), &Reading::untrusted(Untrusted::Stale), M),
        Err(Withheld::Untrusted)
    );
    assert_eq!(
        recovered_deadline((E, 0), &root(0), &local, &read, None),
        Err(Withheld::Malformed)
    );
    assert_eq!(
        recovered_deadline(PAIR, &root(0), &local, &read, None),
        Err(Withheld::Untrusted)
    );
    let wide = reading(
        E + 4 * NANOS_PER_SECOND,
        E + 4 * NANOS_PER_SECOND + 4_000_001,
    );
    assert_eq!(
        recover(PAIR, &root(0), &wide, M),
        Err(Withheld::WidthExceeded)
    );
    assert_eq!(
        recover(PAIR, &root(0), &reading(E - 3_000_000, E - 1), M),
        Err(Withheld::BackwardStep)
    );
    // The latest bound at the written earliest bound is no backward step.
    assert!(recover(PAIR, &root(0), &reading(E - 2_000_000, E), M).is_ok());
    assert_eq!(
        recover(PAIR, &root(0), &reading(PAIR.0 - 2_000_000, PAIR.0), M),
        Err(Withheld::Expired)
    );
    // One nanosecond of remaining life rounds to no usable local lifetime at a whole-second sample.
    assert_eq!(
        recover(PAIR, &root(0), &reading(PAIR.0 - 2_000_001, PAIR.0 - 1), M),
        Err(Withheld::Expired)
    );
    // Two failures name the earlier: a malformed pair under a foreign contract, and an untrusted reading of excess width.
    assert_eq!(
        recover((E, 0), &stepped.encode(), &read, M),
        Err(Withheld::Malformed)
    );
    assert_eq!(
        recover(
            PAIR,
            &root(0),
            &Reading {
                trust: Trust::Untrusted(Untrusted::Stale),
                ..wide
            },
            M
        ),
        Err(Withheld::Untrusted)
    );
    let far = u64::from(u32::MAX) * NANOS_PER_SECOND;
    assert_eq!(recover(PAIR, &root(0), &read, far), Err(Withheld::Overflow));
}

/// A well-formed pair written in 1970 is long expired under a present-day reading.
#[test]
fn a_well_formed_1970_deadline_withholds_expired() {
    let pair = (10 * NANOS_PER_SECOND + 1, 10_000);
    assert_eq!(
        recovered_deadline(pair, &root(0), &contract(0), &reading(E, E + 1), Some(M)),
        Err(Withheld::Expired)
    );
}

/// A leap second removed at the end of 2016 would skip the stepped label 23:59:59, so the ten stepped seconds from 23:59:55 to the pair's deadline span nine true seconds.
#[test]
fn a_stepped_recovery_ends_within_the_true_life_after_a_removed_leap_second() {
    let at = 1_483_228_795 * NANOS_PER_SECOND;
    let pair = (at + 10 * NANOS_PER_SECOND, 20_000);
    let stepped = ClockContract {
        scale: ClockScale::UtcStepped,
        ..contract(0)
    };
    assert_eq!(
        recovered_deadline(pair, &stepped.encode(), &stepped, &reading(at, at), Some(M)),
        Ok((M / NANOS_PER_SECOND + 9) as u32)
    );
    assert_eq!(
        recovered_deadline(pair, &root(0), &contract(0), &reading(at, at), Some(M)),
        Ok((M / NANOS_PER_SECOND + 10) as u32)
    );
}

/// A deterministic xorshift stream.
struct Seeds(u64);

impl Seeds {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

/// Runs seeded scenarios whose readings hold true time through [`recover`], sampling before reading with a scripted provider, and judges every recovered deadline by the oracle; `Err` names the first violation.
fn oracle_run() -> Result<usize, &'static str> {
    let mut seeds = Seeds(0x2545_F491_4F6C_DD1D);
    let mut judged = 0;
    for _ in 0..40_000 {
        let written_true = E + seeds.below(1 << 50);
        let written_early = seeds.below(2_000_001);
        let earliest = written_true - written_early;
        let lifetime_ms = 1 + seeds.below(10_000_000) as u32;
        let span = u64::from(lifetime_ms) * NANOS_PER_MILLI;
        let elapsed = seeds.below(span + span / 4);
        let recovered_true = written_true + elapsed;
        let (early, late) = (seeds.below(2_000_001), seeds.below(2_000_001));
        let before = NANOS_PER_SECOND + seeds.below(1 << 50);
        let gap = seeds.below(1_000_000);
        let (writer_rho, local_rho) = (seeds.below(500_000) as u32, seeds.below(1_000_000) as u32);
        let scenario = Scenario {
            deadline_ns: earliest + span,
            recovered_true,
            gap,
            before,
        };
        let (mut clock, script) = ScriptedClock::with_script();
        script.queue(&[reading(recovered_true - early, recovered_true + late)]);
        let taken = Rc::new(Cell::new(0usize));
        let counter = taken.clone();
        let mut sample = move || {
            counter.set(counter.get() + 1);
            before
        };
        let observed = taken.clone();
        let order = Cell::new(None);
        let result = {
            let probe = &order;
            struct Probe<'p> {
                inner: &'p mut dyn super::clock::PhysicalClock,
                taken: Rc<Cell<usize>>,
                seen: &'p Cell<Option<usize>>,
            }
            impl super::clock::sealed::Sealed for Probe<'_> {}
            impl super::clock::PhysicalClock for Probe<'_> {
                fn scale(&self) -> ClockScale {
                    self.inner.scale()
                }
                fn read(&mut self) -> Reading {
                    self.seen.set(Some(self.taken.get()));
                    self.inner.read()
                }
            }
            let mut probed = Probe {
                inner: &mut *clock,
                taken: observed,
                seen: probe,
            };
            recover(
                (earliest + span, lifetime_ms),
                &root(writer_rho),
                &contract(local_rho),
                &mut probed,
                &mut sample,
            )
        };
        if order.get() != Some(1) {
            return Err("the monotonic sample followed the reading");
        }
        if let Ok(seconds) = result {
            judged += 1;
            if !oracle_accepts(&scenario, local_rho, seconds) {
                return Err("a recovered deadline outlives the pair's deadline in true time");
            }
        }
    }
    Ok(judged)
}

/// Over seeded scenarios in true time, no recovered deadline ends after the pair's deadline, so no recovered lifetime exceeds the written lifetime minus the elapsed physical time.
#[test]
fn the_seeded_oracle_never_finds_a_recovered_deadline_past_the_pairs() {
    let judged = oracle_run().expect("every recovery shortens");
    assert!(judged > 10_000, "the seeds reach recovered deadlines");
}

/// Planted `RederiveTtl`: a deadline of the latest bound plus the stored lifetime ignores the elapsed time and fails the oracle.
#[test]
fn a_recovery_that_rederives_the_ttl_fails_the_oracle() {
    let _planted = plant(Plant::RederiveTtl);
    assert_eq!(
        oracle_run(),
        Err("a recovered deadline outlives the pair's deadline in true time")
    );
}

/// Planted `EarliestAtRecovery`: converting from the earliest bound counts the reading's width as life and fails the oracle.
#[test]
fn a_recovery_from_the_earliest_bound_fails_the_oracle() {
    let _planted = plant(Plant::EarliestAtRecovery);
    assert_eq!(
        oracle_run(),
        Err("a recovered deadline outlives the pair's deadline in true time")
    );
}

/// Planted `WriterRateAtRecovery`: converting through the writer's smaller rate bound on a host whose bound is larger fails the oracle.
#[test]
fn a_recovery_through_the_writers_rate_bound_fails_the_oracle() {
    let _planted = plant(Plant::WriterRateAtRecovery);
    assert_eq!(
        oracle_run(),
        Err("a recovered deadline outlives the pair's deadline in true time")
    );
}

/// Planted `SamplingOrder`: a recovery that reads before it samples fails the ordering check.
#[test]
fn a_recovery_that_reads_before_it_samples_fails_the_ordering_check() {
    let _planted = plant(Plant::SamplingOrder);
    assert_eq!(
        oracle_run(),
        Err("the monotonic sample followed the reading")
    );
}

/// The local lifetime recovery grants for `pair` from a reading whose latest bound lies one second below the written earliest bound, or the cause it withholds.
fn backward_step() -> Result<(), &'static str> {
    let read = reading(E - NANOS_PER_SECOND - 2_000_000, E - NANOS_PER_SECOND);
    match recovered_deadline(PAIR, &root(0), &contract(0), &read, Some(M)) {
        Err(Withheld::BackwardStep) => Ok(()),
        Ok(seconds) if u64::from(seconds) * NANOS_PER_SECOND - M > 10 * NANOS_PER_SECOND => {
            Err("a backward step extended the lifetime")
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_backward_step_withholds() {
    assert_eq!(backward_step(), Ok(()));
}

/// Planted `ExtendOnBackwardStep`: converting a reading below the written earliest bound grants more than the written lifetime.
#[test]
fn a_recovery_that_converts_a_backward_step_extends_the_lifetime() {
    let _planted = plant(Plant::ExtendOnBackwardStep);
    assert_eq!(
        backward_step(),
        Err("a backward step extended the lifetime")
    );
}

/// The conversion, which takes its floor in `u64` arithmetic, gives the `u128` formula's outcome, `floor(remaining * (1e9 - rho) / 1e9)` added to the sample in nanoseconds, over seeded pairs, readings, samples and rate bounds that reach the overflow, expiry and second boundaries.
#[test]
fn the_conversion_matches_the_widened_formula() {
    let giga = u128::from(NANOS_PER_SECOND);
    let formula = |(deadline_ns, _): (u64, u32), latest: u64, before: u64, rho: u32| {
        let remaining = u128::from(deadline_ns - latest);
        let instant = u128::from(before) + remaining * (giga - u128::from(rho)) / giga;
        let seconds = instant / giga;
        if seconds * giga <= u128::from(before) {
            Err(Withheld::Expired)
        } else if seconds >= u128::from(u32::MAX) {
            Err(Withheld::Overflow)
        } else {
            Ok(seconds as u32)
        }
    };
    let mut rng = SplitMix64::new(1151);
    let mut next = || rng.next_u64();
    let mut outcomes = [0usize; 3];
    for round in 0..200_000u64 {
        let rho = match round % 4 {
            0 => 0,
            1 => 999_999_999,
            _ => (next() % 1_000_000_000) as u32,
        };
        let lifetime_ms = 1 + (next() % u64::from(u32::MAX)) as u32;
        let span = u64::from(lifetime_ms) * NANOS_PER_MILLI;
        let latest = span + next() % (u64::MAX - 2 * span);
        let deadline_ns = latest + 1 + next() % span.min(u64::MAX - latest);
        let before = match round % 3 {
            0 => next(),
            1 => next() % (u64::from(u32::MAX) * NANOS_PER_SECOND),
            _ => (next() % u64::from(u32::MAX)) * NANOS_PER_SECOND,
        };
        let pair = (deadline_ns, lifetime_ms);
        let local = contract(rho);
        let found = recovered_deadline(
            pair,
            &root(rho),
            &local,
            &reading(latest, latest),
            Some(before),
        );
        assert_eq!(
            found,
            formula(pair, latest, before, rho),
            "{pair:?} {latest} {before} {rho}"
        );
        outcomes[match found {
            Ok(_) => 0,
            Err(Withheld::Overflow) => 1,
            Err(_) => 2,
        }] += 1;
    }
    assert!(outcomes.iter().all(|&seen| seen > 1000), "{outcomes:?}");
}

/// A pair that meets two refusals at once, a local deadline that rounds to a second at or before the sample and the `u32::MAX` whole-second clamp, withholds `Expired`: `Withheld` lists it ahead of `Overflow`, and the conversion refuses by the first cause in that order.
#[test]
fn a_deadline_that_rounds_to_the_sample_at_the_clamp_withholds_expired() {
    let clamp = u64::from(u32::MAX) * NANOS_PER_SECOND;
    // The deadline recovered at the sample `before` from a trusted reading whose latest bound leaves `remaining` nanoseconds before `PAIR`'s deadline.
    let recovered = |remaining: u64, before: u64| {
        let latest = PAIR.0 - remaining;
        recovered_deadline(
            PAIR,
            &root(0),
            &contract(0),
            &reading(latest - 1_000_000, latest),
            Some(before),
        )
    };
    // Each cause alone: 100 ns of life rounds down to the sample's own second, and five seconds of life from the clamp's instant pass the clamp.
    assert_eq!(
        recovered(100, clamp - NANOS_PER_SECOND + 5),
        Err(Withheld::Expired),
        "the rounded deadline at the sample's second, below the clamp"
    );
    assert_eq!(
        recovered(5 * NANOS_PER_SECOND, clamp),
        Err(Withheld::Overflow),
        "a deadline five seconds past the clamp's instant"
    );
    // Both at once: the sample lies five nanoseconds past the clamp's instant and 100 ns of life remain, so the local deadline rounds to the clamp's second, at or before the sample.
    assert_eq!(
        recovered(100, clamp + 5),
        Err(Withheld::Expired),
        "the first cause in `Withheld`'s order"
    );
    // Both again at the largest sample: 100 ns past `u64::MAX` nanoseconds lies past the clamp and rounds to the sample's own second, 18_446_744_073.
    assert_eq!(
        recovered(100, u64::MAX),
        Err(Withheld::Expired),
        "a sum past `u64::MAX` nanoseconds that rounds to the sample's second"
    );
    // The boundary, five nanoseconds into a second: `1e9 - 6` ns of life end one nanosecond before the next second and `1e9 - 5` ns end on it.
    assert_eq!(
        recovered(NANOS_PER_SECOND - 6, clamp + 5),
        Err(Withheld::Expired),
        "a life one nanosecond short of the sample's next second"
    );
    assert_eq!(
        recovered(NANOS_PER_SECOND - 5, clamp + 5),
        Err(Withheld::Overflow),
        "a life that reaches the sample's next second, past the clamp"
    );
    // Two seconds below the clamp the same life reaches second `u32::MAX - 1`, the largest that converts.
    assert_eq!(
        recovered(NANOS_PER_SECOND - 5, clamp - 2 * NANOS_PER_SECOND + 5),
        Ok(u32::MAX - 1),
        "a life that reaches the last second below the clamp"
    );
}

/// [`Recovery::retained`] keeps `Expired` only a pair whose deadline lies at or below the reading's earliest bound, less one second on a stepped scale: the pair every later recovery judges expired too. A pair one nanosecond above that boundary, which the reading's width or the sample's rounding alone expires, takes the sample's own whole second; an alive pair keeps [`Recovery::deadline`]'s answer; and a pair given the sample's second withholds `Overflow` at a sample whose whole second reaches the `u32::MAX` clamp.
#[test]
fn retained_keeps_expired_only_a_pair_at_or_below_the_earliest_bound() {
    let second = (M / NANOS_PER_SECOND) as u32;
    // The retained deadline of a pair that ends at `deadline`, under `local` from the reading `[earliest, latest]` after the sample `before`.
    let retained =
        |local: &ClockContract, (earliest, latest): (u64, u64), before: u64, deadline: u64| {
            let reading = reading(earliest, latest);
            Recovery::new(&local.encode(), local, &reading, Some(before))
                .retained((deadline, 10_000))
        };
    let smeared = contract(0);
    // A reading of zero width: a pair that ends at the reading expires there, and the rounding at `M` expires a pair with one nanosecond of life.
    assert_eq!(
        retained(&smeared, (E, E), M, E),
        Err(Withheld::Expired),
        "a deadline at the earliest bound"
    );
    assert_eq!(
        retained(&smeared, (E, E), M, E + 1),
        Ok(second),
        "a deadline one nanosecond above the earliest bound"
    );
    // A reading 2 ms wide: its latest bound expires both pairs, and the earliest bound alone decides which stays `Expired`.
    let wide = (E, E + 2 * NANOS_PER_MILLI);
    assert_eq!(
        retained(&smeared, wide, M, E),
        Err(Withheld::Expired),
        "a deadline at the earliest bound of a wide reading"
    );
    assert_eq!(
        retained(&smeared, wide, M, E + 1),
        Ok(second),
        "a deadline inside a wide reading"
    );
    // A stepped scale's labels repeat one second at an inserted leap second, so the boundary lies one second lower.
    let stepped = ClockContract {
        scale: ClockScale::UtcStepped,
        ..contract(0)
    };
    assert_eq!(
        retained(&stepped, (E, E), M, E - NANOS_PER_SECOND),
        Err(Withheld::Expired),
        "a stepped deadline one second below the earliest bound"
    );
    assert_eq!(
        retained(&stepped, (E, E), M, E - NANOS_PER_SECOND + 1),
        Ok(second),
        "a stepped deadline inside the repeated second"
    );
    assert_eq!(
        retained(&smeared, (E, E), M, PAIR.0),
        Ok(second + 10),
        "an alive pair keeps its converted deadline"
    );
    // A pair given the sample's own second names that second, and every deadline lies below the clamp's second.
    let clamp = u64::from(u32::MAX) * NANOS_PER_SECOND;
    assert_eq!(
        retained(&smeared, (E, E), clamp - NANOS_PER_SECOND, E + 1),
        Ok(u32::MAX - 1),
        "a sample in the last second below the clamp"
    );
    assert_eq!(
        retained(&smeared, (E, E), clamp, E + 1),
        Err(Withheld::Overflow),
        "a sample in the clamp's second"
    );
    assert_eq!(
        retained(&smeared, (E, E), clamp, E),
        Err(Withheld::Expired),
        "a pair at the earliest bound stays `Expired` at the clamp"
    );
}
