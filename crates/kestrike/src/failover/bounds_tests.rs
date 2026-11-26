//! Bounds validation tests.

use super::bounds::{Bounds, BoundsError, Parameter};

/// Each zero bound refuses by name, in the order the parameters are listed.
#[test]
fn a_zero_bound_refuses_by_name() {
    for (parameter, args) in [
        (Parameter::RegistrantMax, (0, 2, 100, 10, 20, 5)),
        (Parameter::RetryMax, (8, 0, 100, 10, 20, 5)),
        (Parameter::Window, (8, 2, 0, 10, 20, 5)),
        (Parameter::ReportDeadline, (8, 2, 100, 0, 20, 5)),
        (Parameter::ReportPeriod, (8, 2, 100, 10, 0, 5)),
    ] {
        let (n_reg, n_retry, delta, t_report, p_report, tau) = args;
        assert_eq!(
            Bounds::new(n_reg, n_retry, delta, t_report, p_report, tau),
            Err(BoundsError::Zero(parameter))
        );
    }
}

/// `delta` must exceed `P_report + T_report + tau`: equality refuses with the needed bound, one above admits, a zero clock error is admitted, and a sum past `u64::MAX` refuses `Overflow`.
#[test]
fn the_window_must_exceed_the_report_period_deadline_and_clock_error() {
    assert_eq!(
        Bounds::new(8, 2, 35, 10, 20, 5),
        Err(BoundsError::WindowTooShort {
            window: 35,
            needed_above: 35
        })
    );
    let bounds = Bounds::new(8, 2, 36, 10, 20, 5).unwrap();
    assert_eq!((bounds.window(), bounds.report_deadline()), (36, 10));
    assert_eq!((bounds.registrant_max(), bounds.retry_max()), (8, 2));
    assert_eq!(
        Bounds::new(8, 2, u64::MAX, u64::MAX, 1, 0),
        Err(BoundsError::Overflow)
    );
    assert!(Bounds::new(8, 2, 3, 1, 1, 0).is_ok());
    assert_eq!(
        Bounds::new(8, 2, 1, 1, 1, 0),
        Err(BoundsError::WindowTooShort {
            window: 1,
            needed_above: 2
        })
    );
}

#[test]
fn zero_refusal_order_and_clock_error_overflow_are_checked() {
    for (parameter, args) in [
        (Parameter::RegistrantMax, (0, 0, 0, 0, 0, 0)),
        (Parameter::RetryMax, (8, 0, 0, 0, 0, 0)),
        (Parameter::Window, (8, 2, 0, 0, 0, 0)),
        (Parameter::ReportDeadline, (8, 2, 100, 0, 0, 0)),
    ] {
        let (n_reg, n_retry, delta, t_report, p_report, tau) = args;
        assert_eq!(
            Bounds::new(n_reg, n_retry, delta, t_report, p_report, tau),
            Err(BoundsError::Zero(parameter))
        );
    }
    assert_eq!(
        Bounds::new(8, 2, u64::MAX, 1, 1, u64::MAX - 1),
        Err(BoundsError::Overflow)
    );
}

/// `N_reg` covers the recorded pairs exactly when it reaches the record's cap, and the pair cap is the smaller of
/// the two.
#[test]
fn registrant_bound_covers_the_recorded_pairs_at_the_record_cap() {
    let at = |n| Bounds::new(n, 2, 36, 10, 20, 5).unwrap();
    assert!(!at(7).covers_recorded_pairs());
    assert!(at(8).covers_recorded_pairs());
    assert!(at(9).covers_recorded_pairs());
    assert_eq!(
        [
            at(1).pair_cap(),
            at(7).pair_cap(),
            at(8).pair_cap(),
            at(u32::MAX).pair_cap()
        ],
        [1, 7, 8, 8]
    );
}
