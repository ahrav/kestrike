//! The fakes of the seam behave as the real plane does on the inputs a phase gives them: a case ends
//! when the test sets, a wait within a bound returns at the end or at the bound, SIGKILL ends a case
//! that runs, and a start hands out the cases held in order.

use std::ffi::OsString;
use std::fs::File;
use std::time::Duration;

use kestrike_tools::fis_controller::{Case as _, Failure, Launch, Seam};
use kestrike_tools::host_stop::{Delivered, Interrupted, Record, Signal};

use crate::fis_support::case::Case;
use crate::fis_support::clock::{Clock, nanoseconds};
use crate::fis_support::delivered;
use crate::fis_support::plane::Plane;

/// A wait returns the case's end once the clock reaches it, else none after its whole bound; a case
/// ended at once reads as ended with no time passing.
#[test]
fn a_case_ends_when_the_test_sets_and_a_wait_stops_at_its_bound() {
    let clock = Clock::at(100.0);
    let (mut case, handle) = Case::new(clock.clone());
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    handle.end_at(103.0, 0);
    assert_eq!(case.ended().expect("the check runs"), None);
    assert_eq!(case.wait(&mut record, Duration::from_secs(2)), Ok(None));
    assert_eq!(clock.now(), nanoseconds(102.0), "the wait takes its bound");
    assert_eq!(case.wait(&mut record, Duration::from_secs(5)), Ok(Some(0)));
    assert_eq!(
        clock.now(),
        nanoseconds(103.0),
        "the wait ends at the case's end"
    );
    let (mut other, ended) = Case::new(clock.clone());
    ended.end(2);
    assert_eq!(other.ended().expect("the check runs"), Some(2));
    assert_eq!(other.wait(&mut record, Duration::from_secs(5)), Ok(Some(2)));
    assert_eq!(
        clock.now(),
        nanoseconds(103.0),
        "an ended case's wait takes no time"
    );
}

/// SIGTERM is logged and leaves the case running; SIGKILL ends it with `-9`, and a case that ended
/// first keeps its own code.
#[test]
fn sigkill_ends_a_running_case_and_sigterm_is_logged() {
    let clock = Clock::at(100.0);
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    let (mut case, handle) = Case::new(clock.clone());
    case.terminate().expect("the signal is sent");
    assert_eq!(
        case.ended().expect("the check runs"),
        None,
        "SIGTERM ends nothing"
    );
    assert_eq!(case.kill(&mut record), Ok(-9));
    assert_eq!(handle.signals(), ["SIGTERM", "SIGKILL"]);
    let (mut done, ended) = Case::new(clock);
    ended.end(0);
    assert_eq!(done.kill(&mut record), Ok(0));
}

/// A signal set inside a wait ends an armed wait at its time and leaves an unarmed one its bound.
#[test]
fn a_signal_in_a_wait_ends_it_while_armed() {
    for armed in [true, false] {
        let store = delivered();
        let clock = Clock::at(100.0);
        clock.signal_at(101.0, Signal::Interrupt, store);
        let (mut case, _) = Case::new(clock.clone());
        let mut record = Record::new(store);
        if armed {
            record.arm();
        }
        let waited = case.wait(&mut record, Duration::from_secs(4));
        if armed {
            assert_eq!(
                waited,
                Err(Failure::Interrupted(Interrupted(Signal::Interrupt)))
            );
            assert_eq!(clock.now(), nanoseconds(101.0));
        } else {
            assert_eq!(waited, Ok(None));
            assert_eq!(clock.now(), nanoseconds(104.0));
        }
    }
}

/// Each start hands out the next case held and logs its words; with none held the start fails.
#[test]
fn a_start_hands_out_the_cases_held_in_order() {
    let clock = Clock::at(100.0);
    let mut plane = Plane::new(clock.clone(), Vec::new());
    let (first, one) = Case::new(clock.clone());
    plane.hold(first);
    let log = File::open("/dev/null").expect("the log opens");
    let words: Vec<OsString> = ["lane", "run"].iter().map(OsString::from).collect();
    let launch = Launch {
        words: &words,
        environment: &[],
        log: &log,
        reservation: None,
    };
    let mut started = plane.start(&launch).expect("a case is held");
    one.end(4);
    assert_eq!(started.ended().expect("the check runs"), Some(4));
    assert!(plane.start(&launch).is_err(), "no case is left");
    assert_eq!(plane.starts, [vec!["lane", "run"], vec!["lane", "run"]]);
}
