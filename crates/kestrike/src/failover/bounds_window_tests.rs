//! `Bounds::new` refuses a serving window at or below the Report period plus the Report deadline plus the clock error.
//!
//! The caller supplies every bound; construction refuses a zero bound and a serving window at or below the
//! Report period plus the Report deadline plus the clock error, so a belief taken from one Report outlives
//! the next Report's deadline.
//!
//! - `a_window_at_the_report_sum_is_refused_and_one_above_it_is_admitted`: for Report periods, Report deadlines
//!   and clock errors that are small, unequal, zero (the clock error alone) and at the top of the counter's
//!   range, `Bounds::new` refuses a window equal to their sum and a window one below it with
//!   `BoundsError::WindowTooShort` naming the window and the sum, and admits a window one above the sum with
//!   every bound kept as supplied. An admitted window reaches past the next Report's deadline by more than the
//!   clock error.
//! - `a_zero_bound_is_refused_with_its_parameter`: each of the five bounds at zero refuses with
//!   `BoundsError::Zero` naming it, the first zero in `Parameter`'s order when several are zero, ahead of the
//!   window check; the same bounds with a zero clock error alone are admitted.
//! - `a_report_sum_past_the_counter_is_refused_as_overflow`: a sum that does not fit the counter refuses with
//!   `BoundsError::Overflow` for every window, so no window is admitted against a wrapped sum.

use super::bounds::{Bounds, BoundsError, Parameter};

const REGISTRANTS: u32 = 8;
const RETRIES: u32 = 3;

/// Report period, Report deadline and clock error triples whose sum, and the sum plus one, fit the counter.
const TIMINGS: [(u64, u64, u64); 7] = [
    (1, 1, 0),
    (1, 1, 1),
    (1_000, 250, 40),
    (250, 1_000, 40),
    (5_000_000, 2_000_000, 0),
    (7, 3, 1_000_000_000),
    (u64::MAX / 2, u64::MAX / 4, u64::MAX / 8),
];

fn bounds(window: u64, timing: (u64, u64, u64)) -> Result<Bounds, BoundsError> {
    let (period, deadline, clock_error) = timing;
    Bounds::new(REGISTRANTS, RETRIES, window, deadline, period, clock_error)
}

#[test]
fn a_window_at_the_report_sum_is_refused_and_one_above_it_is_admitted() {
    assert!(
        TIMINGS.iter().any(|timing| timing.2 > 0) && TIMINGS.iter().any(|timing| timing.2 == 0),
        "the timings cover a nonzero and a zero clock error"
    );
    for timing in TIMINGS {
        let (period, deadline, clock_error) = timing;
        let sum = period + deadline + clock_error;
        assert_eq!(
            bounds(sum, timing),
            Err(BoundsError::WindowTooShort {
                window: sum,
                needed_above: sum,
            }),
            "a window equal to the Report period plus the Report deadline plus the clock error is refused, {timing:?}"
        );
        assert_eq!(
            bounds(sum - 1, timing),
            Err(BoundsError::WindowTooShort {
                window: sum - 1,
                needed_above: sum,
            }),
            "a window below the sum is refused and the refusal names the window and the sum, {timing:?}"
        );
        let admitted = bounds(sum + 1, timing).map(|bounds| {
            (
                bounds.window(),
                bounds.report_deadline(),
                bounds.report_period(),
            )
        });
        assert_eq!(
            admitted,
            Ok((sum + 1, deadline, period)),
            "a window one above the sum is admitted with the bounds as supplied, {timing:?}"
        );
        let kept = bounds(sum + 1, timing).expect("the admitted bounds");
        assert!(
            kept.window() - clock_error > kept.report_period() + kept.report_deadline(),
            "a belief taken from one Report outlives the next Report's deadline, {timing:?}"
        );
        assert_eq!(
            (kept.registrant_max(), kept.retry_max()),
            (REGISTRANTS, RETRIES),
            "the admitted bounds keep the registrant and retry bounds, {timing:?}"
        );
    }
}

#[test]
fn a_zero_bound_is_refused_with_its_parameter() {
    // A window of 100 over a period of 40, a deadline of 30 and a clock error of 20: admitted while no bound is zero.
    let new = |registrants: u32, retries: u32, window: u64, deadline: u64, period: u64| {
        Bounds::new(registrants, retries, window, deadline, period, 20)
            .map(|bounds| bounds.window())
    };
    assert_eq!(
        new(8, 3, 100, 30, 40),
        Ok(100),
        "the bounds without a zero are admitted"
    );
    let refusals = [
        (new(0, 3, 100, 30, 40), Parameter::RegistrantMax),
        (new(8, 0, 100, 30, 40), Parameter::RetryMax),
        (new(8, 3, 0, 30, 40), Parameter::Window),
        (new(8, 3, 100, 0, 40), Parameter::ReportDeadline),
        (new(8, 3, 100, 30, 0), Parameter::ReportPeriod),
        // Several zeros refuse with the first in `Parameter`'s order.
        (new(0, 0, 0, 0, 0), Parameter::RegistrantMax),
        (new(8, 0, 100, 0, 40), Parameter::RetryMax),
        (new(8, 3, 0, 0, 0), Parameter::Window),
        (new(8, 3, 100, 0, 0), Parameter::ReportDeadline),
    ];
    for (refusal, parameter) in refusals {
        assert_eq!(
            refusal,
            Err(BoundsError::Zero(parameter)),
            "a zero bound is refused with its parameter"
        );
    }
    assert_eq!(
        Bounds::new(8, 3, 71, 30, 40, 0).map(|bounds| bounds.window()),
        Ok(71),
        "the clock error is no bound and may be zero"
    );
    assert_eq!(
        Bounds::new(8, 3, 70, 30, 40, 0).map(|bounds| bounds.window()),
        Err(BoundsError::WindowTooShort {
            window: 70,
            needed_above: 70,
        }),
        "with a zero clock error the window must still exceed the Report period plus the Report deadline"
    );
}

#[test]
fn a_report_sum_past_the_counter_is_refused_as_overflow() {
    let wrapped = [
        (u64::MAX, 1, 0),
        (1, u64::MAX, 0),
        (u64::MAX - 1, 1, 1),
        (u64::MAX / 2 + 1, u64::MAX / 2 + 1, 0),
        (1, 1, u64::MAX - 1),
    ];
    for timing in wrapped {
        for window in [1, 2, u64::MAX] {
            assert_eq!(
                bounds(window, timing),
                Err(BoundsError::Overflow),
                "a Report sum past the counter's range admits no window, {timing:?} with window {window}"
            );
        }
    }
    // The largest sum the counter holds admits no window either: none lies above it.
    assert_eq!(
        bounds(u64::MAX, (u64::MAX - 2, 1, 1)),
        Err(BoundsError::WindowTooShort {
            window: u64::MAX,
            needed_above: u64::MAX,
        }),
        "a window equal to the largest sum is refused"
    );
}
