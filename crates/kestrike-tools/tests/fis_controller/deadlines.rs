//! The deadline rules on the fake clock: a window, a poll's sleep and a call's limit with and without
//! a run deadline, a deadline already past, a signal in a sleep, the conversions between a reading,
//! seconds and a length, and a loop of polls that ends at its deadline. Each value and each count of
//! readings is the rule's on a clock that starts at 100 s.

use std::ffi::OsString;
use std::time::Duration;

use kestrike_tools::fis_controller::{Deadlines, Failure, call, duration, seconds};
use kestrike_tools::hardware_host::Clocks;
use kestrike_tools::host_stop::{Delivered, Interrupted, Record, Signal};
use kestrike_tools::json::{self, Value};

use crate::fis_support::calls::Reply;
use crate::fis_support::clock::{Clock, nanoseconds};
use crate::fis_support::delivered;
use crate::fis_support::plane::Plane;

fn rules(poll: f64, call: f64, run: Option<f64>) -> Deadlines {
    let mut deadlines = Deadlines::new(poll, call).expect("the seconds are admitted");
    deadlines.set_run(run);
    deadlines
}

/// A window ends its length after one reading, cut at the run's deadline while one is set, a run
/// deadline already past included.
#[test]
fn a_window_is_one_reading_plus_its_length_cut_at_the_run_s_deadline() {
    for (run, want) in [
        (None, 130.0),
        (Some(110.0), 110.0),
        (Some(140.0), 130.0),
        (Some(90.0), 90.0),
    ] {
        let clock = Clock::at(100.0);
        let window = rules(2.0, 60.0, run).window(&clock, 30.0);
        assert_eq!(window, Ok(want), "{run:?}");
        assert_eq!(clock.readings(), 1, "{run:?}");
    }
}

/// A poll sleeps its length, cut at the earliest of the deadlines given and the run's, never under
/// zero, with one reading for each deadline that is set; a NaN deadline leaves the poll whole.
#[test]
fn a_poll_sleeps_to_the_earliest_deadline_with_one_reading_for_each() {
    let delivered = Delivered::new();
    for (poll, run, given, slept, readings) in [
        (2.0, None, &[][..], 2.0, 0),
        (2.0, None, &[None][..], 2.0, 0),
        (100.0, None, &[Some(100.2)][..], 0.200_000_000_000_002_84, 1),
        (100.0, Some(100.2), &[][..], 0.200_000_000_000_002_84, 1),
        (
            100.0,
            Some(100.5),
            &[Some(100.2), None, Some(101.0)][..],
            0.200_000_000_000_002_84,
            3,
        ),
        (2.0, None, &[Some(200.0)][..], 2.0, 1),
        (100.0, None, &[Some(95.0)][..], 0.0, 1),
        (100.0, None, &[Some(100.0)][..], 0.0, 1),
        (2.0, Some(99.0), &[Some(150.0)][..], 0.0, 2),
        (2.0, None, &[Some(f64::NAN)][..], 2.0, 1),
    ] {
        let mut clock = Clock::at(100.0);
        let mut record = Record::new(&delivered);
        rules(poll, 60.0, run)
            .nap(&mut clock, &mut record, given)
            .expect("the poll sleeps");
        assert_eq!(
            clock.sleeps(),
            [duration(slept)],
            "{poll} {run:?} {given:?}"
        );
        assert_eq!(clock.readings(), readings, "{poll} {run:?} {given:?}");
    }
}

/// The operation of the calls of these rows.
const GET: &str = "fis get-experiment";

/// The words of a call after the AWS command.
fn words() -> Vec<OsString> {
    [
        "fis",
        "get-experiment",
        "--id",
        "EXP1",
        "--region",
        "r-1",
        "--output",
        "json",
    ]
    .iter()
    .map(OsString::from)
    .collect()
}

/// A call's limit is the call's seconds cut at the phase's and the run's deadline, one reading for
/// each; at or past either deadline, or with a limit of zero or less, no call is made and the reply
/// is none.
#[test]
fn a_call_is_cut_at_the_earliest_deadline_and_none_is_made_at_or_past_it() {
    let delivered = Delivered::new();
    let ok = json::parse(r#"{"ok": 1}"#).expect("the reply is JSON");
    for (call_seconds, run, deadline, limit, readings) in [
        (60.0, None, None, Some(60.0), 0),
        (60.0, None, Some(110.0), Some(10.0), 1),
        (60.0, Some(105.0), None, Some(5.0), 1),
        (60.0, Some(130.0), Some(120.0), Some(20.0), 2),
        (60.0, Some(103.0), Some(120.0), Some(3.0), 2),
        (5.0, Some(200.0), Some(300.0), Some(5.0), 2),
        (60.0, None, Some(100.0), None, 1),
        (60.0, Some(90.0), None, None, 1),
        (0.0, None, None, None, 0),
        (-1.0, None, None, None, 0),
    ] {
        let clock = Clock::at(100.0);
        let mut plane = Plane::new(
            clock.clone(),
            vec![Reply {
                operation: GET,
                value: Some(ok.clone()),
                takes: Duration::ZERO,
            }],
        );
        let mut record = Record::new(&delivered);
        let deadlines = rules(2.0, call_seconds, run);
        let reply =
            call(&mut plane, &deadlines, &mut record, &words(), deadline).expect("the call ends");
        let case = format!("{call_seconds} {run:?} {deadline:?}");
        match limit {
            Some(limit) => {
                assert_eq!(reply, Some(ok.clone()), "{case}");
                assert_eq!(plane.calls.log.len(), 1, "{case}");
                assert_eq!(plane.calls.log[0].limit, duration(limit), "{case}");
                assert_eq!(
                    plane.calls.log[0].words,
                    words()
                        .iter()
                        .map(|w| w.to_string_lossy().into_owned())
                        .collect::<Vec<_>>()
                );
            }
            None => {
                assert_eq!(reply, None, "{case}");
                assert!(plane.calls.log.is_empty(), "{case}: no call is made");
            }
        }
        assert_eq!(clock.readings(), readings, "{case}");
    }
}

/// A signal 0.1 s into a poll of 0.5 s: under an armed record, as during the run, the sleep ends
/// there with the signal; under an unarmed one, as during cleanup, the sleep runs its length and
/// the signal stays recorded. Control: the same poll with no signal runs its length under an armed
/// record.
#[test]
fn a_signal_in_a_poll_ends_it_while_armed_and_waits_while_unarmed() {
    for (armed, signalled, ends_at, raised) in [
        (true, true, 100.1, true),
        (false, true, 100.5, false),
        (true, false, 100.5, false),
    ] {
        let store = delivered();
        let mut clock = Clock::at(100.0);
        if signalled {
            clock.signal_at(100.1, Signal::Terminate, store);
        }
        let mut record = Record::new(store);
        if armed {
            record.arm();
        }
        let napped = rules(0.5, 60.0, None).nap(&mut clock, &mut record, &[]);
        let case = format!("armed {armed}, signalled {signalled}");
        assert_eq!(
            napped,
            if raised {
                Err(Failure::Interrupted(Interrupted(Signal::Terminate)))
            } else {
                Ok(())
            },
            "{case}"
        );
        assert_eq!(clock.now(), nanoseconds(ends_at), "{case}");
        assert_eq!(
            store.stored(),
            (signalled && !raised).then_some(Signal::Terminate),
            "{case}: an unraised signal stays recorded"
        );
    }
}

/// A failed reading ends a poll and a call before any sleep or call, with the reading's system
/// error. Control: the same deadline on a clock that reads gives a sleep and a call of the 10 s left.
#[test]
fn a_failed_reading_ends_the_step_before_it_sleeps_or_calls() {
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    for failing in [true, false] {
        let mut clock = Clock::at(100.0);
        if failing {
            clock.fail();
        }
        let mut plane = Plane::new(
            clock.clone(),
            vec![Reply {
                operation: GET,
                value: None,
                takes: Duration::ZERO,
            }],
        );
        let called = call(
            &mut plane,
            &rules(20.0, 60.0, None),
            &mut record,
            &words(),
            Some(110.0),
        );
        let napped = rules(20.0, 60.0, None).nap(&mut clock, &mut record, &[Some(110.0)]);
        if failing {
            let Err(Failure::System(error)) = napped else {
                panic!("{napped:?} is a system error");
            };
            assert_eq!(error.to_string(), "[Errno 5] Input/output error");
            assert!(clock.sleeps().is_empty(), "no sleep follows");
            assert!(matches!(called, Err(Failure::System(_))), "{called:?}");
            assert!(plane.calls.log.is_empty(), "no call follows");
        } else {
            assert_eq!(napped, Ok(()));
            assert_eq!(clock.sleeps(), [Duration::from_secs(10)]);
            assert_eq!(called, Ok(None));
            assert_eq!(plane.calls.log.len(), 1, "the control calls");
            assert_eq!(plane.calls.log[0].limit, duration(10.0));
        }
    }
}

/// A second call toward the same deadline gets what the first left of the window: no retry
/// restarts it. A signal delivered during an armed call ends it there.
#[test]
fn a_retry_keeps_its_window_and_a_signal_ends_an_armed_call() {
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    let clock = Clock::at(100.0);
    let reply = |takes| Reply {
        operation: GET,
        value: None,
        takes,
    };
    let mut plane = Plane::new(
        clock.clone(),
        vec![reply(Duration::from_secs(3)), reply(Duration::ZERO)],
    );
    let deadlines = rules(2.0, 60.0, None);
    for _ in 0..2 {
        call(&mut plane, &deadlines, &mut record, &words(), Some(110.0)).expect("the call ends");
    }
    let limits: Vec<Duration> = plane.calls.log.iter().map(|called| called.limit).collect();
    assert_eq!(limits, [duration(10.0), duration(7.0)]);

    let store = crate::fis_support::delivered();
    let clock = Clock::at(100.0);
    clock.signal_at(101.0, Signal::Terminate, store);
    let mut plane = Plane::new(clock.clone(), vec![reply(Duration::from_secs(5))]);
    let mut record = Record::new(store);
    record.arm();
    assert_eq!(
        call(&mut plane, &deadlines, &mut record, &words(), None),
        Err(Failure::Interrupted(Interrupted(Signal::Terminate)))
    );
    assert_eq!(
        clock.now(),
        nanoseconds(101.0),
        "the call ends at the signal"
    );
}

/// A reading converts whole seconds exactly and divides any other count of nanoseconds by 1e9; a
/// length is the seconds times 1e9 rounded up to a whole nanosecond, zero for zero, a negative value
/// and NaN, and [`Duration::MAX`] past the range of `u64` nanoseconds.
#[test]
fn readings_and_lengths_convert_with_the_interpreter_s_rounding() {
    assert_eq!(seconds(100_000_000_000), 100.0);
    assert_eq!(seconds(1_500_000_001), 1_500_000_001_f64 / 1e9);
    assert_eq!(seconds(100_200_000_000), 100.2);
    assert_eq!(
        duration(0.200_000_000_000_002_84),
        Duration::from_nanos(200_000_001)
    );
    assert_eq!(duration(2.0), Duration::from_secs(2));
    assert_eq!(duration(1e-10), Duration::from_nanos(1));
    assert_eq!(duration(0.0), Duration::ZERO);
    assert_eq!(duration(-1.0), Duration::ZERO);
    assert_eq!(duration(f64::NAN), Duration::ZERO);
    assert_eq!(duration(1e300), Duration::MAX);
}

/// The rules refuse a poll that is not finite and above zero and a call's seconds that are not
/// finite; a poll above zero and a call of zero or less are admitted.
#[test]
fn the_rules_refuse_a_poll_or_a_call_that_has_no_finite_length() {
    for (poll, call_seconds, admitted) in [
        (0.0, 60.0, false),
        (-1.0, 60.0, false),
        (f64::NAN, 60.0, false),
        (f64::INFINITY, 60.0, false),
        (2.0, f64::NAN, false),
        (2.0, f64::NEG_INFINITY, false),
        (1e-9, 0.0, true),
        (2.0, -5.0, true),
    ] {
        let made = Deadlines::new(poll, call_seconds);
        assert_eq!(made.is_ok(), admitted, "{poll} {call_seconds}");
        if !admitted {
            assert!(
                matches!(made, Err(Failure::Refused(_))),
                "{poll} {call_seconds}"
            );
        }
    }
}

/// A loop that leaves only on a reading past its deadline and polls toward it ends at the deadline
/// when each reading moves the clock by a step: the last poll is cut at the deadline, and the next
/// reading is past it. With no step the clock stands at the deadline, so the case bounds its
/// own loop and sees it go on.
#[test]
fn a_loop_of_polls_ends_at_its_deadline_once_readings_move_the_clock() {
    let delivered = Delivered::new();
    for step in [Duration::from_millis(1), Duration::ZERO] {
        let mut clock = Clock::at(100.0);
        clock.step(step);
        let mut record = Record::new(&delivered);
        let deadlines = rules(2.0, 60.0, None);
        let deadline = deadlines.window(&clock, 5.0).expect("the clock reads");
        let mut polls = 0;
        while clock.monotonic_ns().map(seconds).expect("the clock reads") <= deadline && polls < 100
        {
            deadlines
                .nap(&mut clock, &mut record, &[Some(deadline)])
                .expect("the poll sleeps");
            polls += 1;
        }
        if step.is_zero() {
            assert_eq!(
                polls, 100,
                "a clock that stands at the deadline keeps the loop going"
            );
            assert_eq!(clock.now(), nanoseconds(105.0));
        } else {
            assert_eq!(polls, 3, "three polls end the loop");
            assert!(
                clock.now() > nanoseconds(105.0),
                "the loop ends past its deadline"
            );
            assert_eq!(
                clock.sleeps(),
                [
                    Duration::from_secs(2),
                    Duration::from_secs(2),
                    Duration::from_millis(994)
                ],
                "the last poll is cut at the deadline"
            );
        }
    }
}

/// A reply the plane gives within the call's limit is the call's reply, and one that takes longer is
/// none, the call taking its whole limit.
#[test]
fn a_reply_longer_than_its_limit_is_no_reply() {
    let delivered = Delivered::new();
    let reply = |takes| Reply {
        operation: GET,
        value: Some(Value::Bool(true)),
        takes,
    };
    let clock = Clock::at(100.0);
    let mut plane = Plane::new(
        clock.clone(),
        vec![
            reply(Duration::from_secs(3)),
            reply(Duration::from_secs(30)),
        ],
    );
    let mut record = Record::new(&delivered);
    let deadlines = rules(2.0, 10.0, None);
    assert_eq!(
        call(&mut plane, &deadlines, &mut record, &words(), None),
        Ok(Some(Value::Bool(true)))
    );
    assert_eq!(clock.now(), nanoseconds(103.0));
    assert_eq!(
        call(&mut plane, &deadlines, &mut record, &words(), None),
        Ok(None)
    );
    assert_eq!(clock.now(), nanoseconds(113.0));
}
