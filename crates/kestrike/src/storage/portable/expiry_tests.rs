//! The writer's conversion against hand-computed tables, each absent cause in its order, the lifetime cap, the rate margin, and a seeded `u128` oracle over the shortening bound.

use super::clock::{ClockScale, Reading, Trust};
use super::contract::ClockContract;
use super::expiry::{Absent, NANOS_PER_MILLI, NANOS_PER_SECOND, portable};
use super::pair::PortableExpiry;

const E: u64 = 1_700_000_000 * NANOS_PER_SECOND;
const MAX_WIDTH: u64 = 4_000_000;

/// A trusted reading `[E, E + 2 ms]` under zero rate error.
fn trusted(sample: Option<u64>, live_s: u32) -> Result<(u64, u32), Absent> {
    portable(E, E + 2_000_000, true, MAX_WIDTH, 0, sample, live_s)
}

/// Ten seconds of remaining life and no rate error give the earliest bound plus ten seconds and 10,000 ms.
#[test]
fn ten_seconds_of_life_under_no_rate_error_persist_whole() {
    assert_eq!(
        trusted(Some(5 * NANOS_PER_SECOND), 15),
        Ok((E + 10 * NANOS_PER_SECOND, 10_000))
    );
}

/// Each refusal names its own cause, and the earlier check wins when several fail.
#[test]
fn each_absent_cause_refuses_in_its_order() {
    let sample = Some(5 * NANOS_PER_SECOND);
    assert_eq!(
        portable(E, E + 1, false, MAX_WIDTH, 0, sample, 15),
        Err(Absent::Untrusted)
    );
    assert_eq!(
        portable(E, E + MAX_WIDTH, true, MAX_WIDTH, 0, sample, 15),
        Ok((E + 10 * NANOS_PER_SECOND, 10_000))
    );
    assert_eq!(
        portable(E, E + MAX_WIDTH + 1, true, MAX_WIDTH, 0, sample, 15),
        Err(Absent::WidthExceeded)
    );
    assert_eq!(
        portable(E, E - 1, true, MAX_WIDTH, 0, sample, 15),
        Err(Absent::WidthExceeded)
    );
    assert_eq!(
        portable(0, 1, true, MAX_WIDTH, 0, sample, 15),
        Err(Absent::EarliestZero)
    );
    assert_eq!(trusted(None, 15), Err(Absent::MonotonicUnavailable));
    assert_eq!(
        trusted(Some(15 * NANOS_PER_SECOND), 15),
        Err(Absent::LiveDeadlinePassed)
    );
    assert_eq!(
        trusted(Some(15 * NANOS_PER_SECOND - NANOS_PER_MILLI + 1), 15),
        Err(Absent::LiveDeadlinePassed)
    );
    assert_eq!(
        portable(
            u64::MAX - NANOS_PER_MILLI + 1,
            u64::MAX,
            true,
            MAX_WIDTH,
            0,
            sample,
            15
        ),
        Err(Absent::Overflow)
    );
    // An untrusted reading of zero width still names the provider's verdict first.
    assert_eq!(portable(0, 0, false, 0, 0, None, 0), Err(Absent::Untrusted));
    // Two adjacent failures name the earlier: a too-wide reading at zero, and a zero earliest bound with no sample.
    assert_eq!(
        portable(0, MAX_WIDTH + 1, true, MAX_WIDTH, 0, sample, 15),
        Err(Absent::WidthExceeded)
    );
    assert_eq!(
        portable(0, 1, true, MAX_WIDTH, 0, None, 15),
        Err(Absent::EarliestZero)
    );
    assert_eq!(
        portable(E, E, true, MAX_WIDTH, 0, None, 0),
        Err(Absent::MonotonicUnavailable)
    );
}

/// A live deadline at the `u32` seconds clamp shortens to the `u32::MAX` millisecond cap, about 49.7 days.
#[test]
fn a_clamped_live_deadline_shortens_to_the_lifetime_cap() {
    assert_eq!(
        trusted(Some(1), u32::MAX),
        Ok((E + u64::from(u32::MAX) * NANOS_PER_MILLI, u32::MAX))
    );
}

/// A rate error of `rho` shortens the life to `floor(L * 1e9 / (1e9 + rho))`: 100 ppm over ten seconds removes 999,900 ns, below one millisecond, so the lifetime rounds down to 9,999 ms.
#[test]
fn a_rate_error_shortens_the_life_by_its_margin() {
    let sample = Some(5 * NANOS_PER_SECOND);
    assert_eq!(
        portable(E, E, true, MAX_WIDTH, 100_000, sample, 15),
        Ok((E + 9_999 * NANOS_PER_MILLI, 9_999))
    );
    // A rate bound just below one part per one halves the life, rounded down.
    assert_eq!(
        portable(E, E, true, MAX_WIDTH, 999_999_999, sample, 15),
        Ok((E + 5_000 * NANOS_PER_MILLI, 5_000))
    );
}

/// Over seeded readings, samples, deadlines and rate bounds, every present pair satisfies `deadline - lifetime * 1e6 == earliest` and its lifetime, stretched by the writer's fastest rate, fits the remaining monotonic life, checked in `u128` apart from the conversion.
#[test]
fn seeded_pairs_never_outlive_the_live_deadline_through_the_rate_bound() {
    let mut state = 0x9E37_79B9_7F4A_7C15_u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut present = 0;
    for _ in 0..20_000 {
        let earliest = next() % (u64::MAX / 2) + 1;
        let width = next() % (2 * MAX_WIDTH);
        let rho = (next() % 1_000_000_000) as u32;
        let live_s = (next() % u64::from(u32::MAX)) as u32;
        let live = u128::from(live_s) * u128::from(NANOS_PER_SECOND);
        let sample = (next() as u128 % (live + 2)) as u64;
        let Ok((deadline, lifetime)) = portable(
            earliest,
            earliest.saturating_add(width),
            true,
            MAX_WIDTH,
            rho,
            Some(sample),
            live_s,
        ) else {
            continue;
        };
        present += 1;
        let span = u128::from(lifetime) * u128::from(NANOS_PER_MILLI);
        assert_eq!(u128::from(deadline) - span, u128::from(earliest));
        let stretched = span * (u128::from(NANOS_PER_SECOND) + u128::from(rho));
        assert!(stretched <= (live - u128::from(sample)) * u128::from(NANOS_PER_SECOND));
    }
    assert!(present > 5_000, "the seeds reach present pairs");
}

/// 2016-12-31T23:59:58Z in nanoseconds since the Unix epoch, two seconds before the leap second inserted at the end of 2016.
const BEFORE_LEAP: u64 = 1_483_228_798 * NANOS_PER_SECOND;

fn contract_on(scale: ClockScale) -> ClockContract {
    ClockContract {
        scale,
        max_uncertainty_ns: MAX_WIDTH,
        rate_error_ppb: 0,
        provenance: 1,
    }
}

fn exact(at: u64) -> Reading {
    Reading {
        earliest: at,
        latest: at,
        trust: Trust::Trusted,
    }
}

/// The inserted leap second repeats one stepped label, so ten true seconds from `BEFORE_LEAP` reach the stepped label `BEFORE_LEAP + 9 s`.
#[test]
fn a_stepped_pair_ends_at_or_before_the_label_after_an_inserted_leap_second() {
    let sample = Some(5 * NANOS_PER_SECOND);
    let stepped = PortableExpiry::of(
        &exact(BEFORE_LEAP),
        &contract_on(ClockScale::UtcStepped),
        sample,
        15,
    )
    .unwrap();
    assert!(
        stepped.deadline_ns <= BEFORE_LEAP + 9 * NANOS_PER_SECOND,
        "a stepped deadline {} passes the label after the leap second",
        stepped.deadline_ns
    );
    assert_eq!(
        stepped.deadline_ns - u64::from(stepped.lifetime_ms) * NANOS_PER_MILLI,
        BEFORE_LEAP
    );
    assert_eq!(
        PortableExpiry::of(
            &exact(BEFORE_LEAP),
            &contract_on(ClockScale::UtcSmeared),
            sample,
            15
        ),
        Ok(PortableExpiry {
            deadline_ns: BEFORE_LEAP + 10 * NANOS_PER_SECOND,
            lifetime_ms: 10_000,
        })
    );
    assert_eq!(
        PortableExpiry::of(
            &exact(BEFORE_LEAP),
            &contract_on(ClockScale::UtcStepped),
            Some(14 * NANOS_PER_SECOND),
            15
        ),
        Err(Absent::LiveDeadlinePassed)
    );
}

/// The capped lifetime of about 49.7 days from 2017-01-31T23:59:58Z holds the ends of January and February, and a leap second inserted at each repeats one stepped label.
#[test]
fn a_capped_stepped_pair_allows_a_leap_second_at_each_month_end_it_holds() {
    let at = 1_485_907_198 * NANOS_PER_SECOND;
    let stepped = PortableExpiry::of(
        &exact(at),
        &contract_on(ClockScale::UtcStepped),
        Some(1),
        u32::MAX,
    )
    .unwrap();
    assert!(
        stepped.deadline_ns <= at + u64::from(u32::MAX) * NANOS_PER_MILLI - 2 * NANOS_PER_SECOND,
        "a stepped deadline {} passes the label after two leap seconds",
        stepped.deadline_ns
    );
    assert_eq!(
        stepped.deadline_ns - u64::from(stepped.lifetime_ms) * NANOS_PER_MILLI,
        at
    );
}
