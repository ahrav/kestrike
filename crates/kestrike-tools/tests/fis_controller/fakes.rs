//! The fakes of the seam behave as the real plane does on the inputs a phase gives them: a case ends
//! when the test sets, a wait within a bound returns at the end or at the bound, SIGKILL ends a case
//! that runs, and a start hands out the cases held in order.

use std::ffi::OsString;
use std::fs::File;
use std::time::Duration;

use kestrike_tools::fis_controller::{self, Case as _, Failure, Launch, Seam};
use kestrike_tools::hardware_host::{Clocks, System};
use kestrike_tools::host_stop::{Delivered, Interrupted, Record, Signal};

use crate::fis_support::calls::Reply;
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
    let words: Vec<Vec<String>> = plane
        .starts
        .log
        .iter()
        .map(|started| started.words.clone())
        .collect();
    assert_eq!(words, [vec!["lane", "run"], vec!["lane", "run"]]);
    assert!(
        plane
            .starts
            .log
            .iter()
            .all(|started| !started.reserved && started.environment.is_empty())
    );
}

/// A kill ends the case with `-9` at once: a later end never replaces it, and a signal raised
/// during the kill's wait leaves the case ended, as a child sent SIGKILL is.
#[test]
fn a_killed_case_stays_killed() {
    let clock = Clock::at(100.0);
    let (mut case, handle) = Case::new(clock.clone());
    handle.end_at(101.0, 0);
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    assert_eq!(case.kill(&mut record), Ok(-9));
    assert_eq!(case.wait(&mut record, Duration::from_secs(5)), Ok(Some(-9)));
    assert_eq!(
        case.ended().expect("the check runs"),
        Some(-9),
        "a later end changes nothing"
    );

    let store = crate::fis_support::delivered();
    store.deliver(Signal::Terminate);
    let (mut case, _) = Case::new(clock);
    let mut record = Record::new(store);
    record.arm();
    assert_eq!(
        case.kill(&mut record),
        Err(Failure::Interrupted(Interrupted(Signal::Terminate)))
    );
    assert_eq!(
        case.ended().expect("the check runs"),
        Some(-9),
        "the interrupted kill stands"
    );
}

/// SIGTERM ends a case the test set to close on it, after the delay; a case that ended gets no
/// signal at all.
#[test]
fn sigterm_closes_a_case_set_to_close_and_an_ended_case_gets_no_signal() {
    let clock = Clock::at(100.0);
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    let (mut case, handle) = Case::new(clock.clone());
    handle.close_on_sigterm(2.0, 0);
    assert_eq!(
        case.ended().expect("the check runs"),
        None,
        "no SIGTERM, no close"
    );
    case.terminate().expect("the signal is sent");
    assert_eq!(case.wait(&mut record, Duration::from_secs(5)), Ok(Some(0)));
    assert_eq!(clock.now(), nanoseconds(102.0));
    case.terminate().expect("nothing is sent");
    assert_eq!(case.kill(&mut record), Ok(0));
    assert_eq!(
        handle.signals(),
        ["SIGTERM"],
        "an ended case gets no signal"
    );
}

/// A call under an armed record with a signal stored raises before it is logged or takes a reply;
/// the control with no signal logs the call and takes its reply.
#[test]
fn a_call_under_a_stored_signal_raises_before_it_is_made() {
    for signalled in [true, false] {
        let store = delivered();
        if signalled {
            store.deliver(Signal::Interrupt);
        }
        let clock = Clock::at(100.0);
        let reply = Reply {
            operation: "fis get-experiment",
            value: None,
            takes: Duration::ZERO,
        };
        let mut plane = Plane::new(clock, vec![reply]);
        let mut record = Record::new(store);
        record.arm();
        let words: Vec<OsString> = [
            "fis",
            "get-experiment",
            "--region",
            "r-1",
            "--output",
            "json",
        ]
        .iter()
        .map(OsString::from)
        .collect();
        let called = plane.call(&mut record, &words, Duration::from_secs(1));
        assert_eq!(called.is_err(), signalled);
        assert_eq!(
            plane.calls.log.len(),
            usize::from(!signalled),
            "signalled {signalled}"
        );
    }
}

/// What a clock of a phase does, run over the fake clock and the system's: readings never go back,
/// an unarmed sleep runs at least its length and leaves a stored signal stored, and an armed record
/// with a signal stored ends the sleep with it and disarms.
fn clocks_contract(clocks: &mut impl Clocks) {
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    let length = Duration::from_millis(20);
    let before = clocks.monotonic_ns().expect("the clock reads");
    delivered.deliver(Signal::Hangup);
    clocks
        .sleep(&mut record, length)
        .expect("an unarmed sleep runs its length");
    let after = clocks.monotonic_ns().expect("the clock reads");
    assert!(after >= before + 20_000_000, "{before} to {after}");
    assert_eq!(
        delivered.stored(),
        Some(Signal::Hangup),
        "the signal stays stored"
    );
    record.arm();
    assert_eq!(
        clocks.sleep(&mut record, length),
        Err(Interrupted(Signal::Hangup))
    );
    assert!(!record.is_armed(), "the raise disarms the record");
    assert!(clocks.monotonic_ns().expect("the clock reads") >= after);
}

#[test]
fn the_fake_clock_keeps_the_contract_the_system_s_clock_keeps() {
    clocks_contract(&mut System);
    clocks_contract(&mut Clock::at(100.0));
}

/// What a case of a phase does, here run over the fake case alone: a running case is not ended,
/// SIGTERM leaves it running, a wait within a bound it outlives returns none, and a kill ends it
/// with `-9` that a check then reads; a case that ended keeps its own code through a kill. `ended`
/// makes a second case end with 0 before the contract reads it.
fn case_contract<C: fis_controller::Case>(mut case: C, mut ended: C, end: impl FnOnce(&mut C)) {
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    assert_eq!(case.ended().expect("the check runs"), None);
    case.terminate().expect("the signal is sent");
    assert_eq!(
        case.ended().expect("the check runs"),
        None,
        "SIGTERM alone ends nothing"
    );
    assert_eq!(case.wait(&mut record, Duration::from_millis(20)), Ok(None));
    assert_eq!(case.kill(&mut record), Ok(-9));
    assert_eq!(case.ended().expect("the check runs"), Some(-9));
    end(&mut ended);
    assert_eq!(ended.wait(&mut record, Duration::from_secs(5)), Ok(Some(0)));
    assert_eq!(
        ended.kill(&mut record),
        Ok(0),
        "a kill keeps an ended case's code"
    );
}

#[test]
fn the_fake_case_keeps_the_case_contract() {
    let clock = Clock::at(100.0);
    let (ended, handle) = Case::new(clock.clone());
    case_contract(Case::new(clock).0, ended, |_| handle.end(0));
}

/// SIGTERM never puts off an end the case was set to reach first: a case set to end at 101 s and to
/// close 5 s after SIGTERM, terminated at 100 s, ends at 101 s. Control: with no earlier end it
/// closes at 105 s.
#[test]
fn sigterm_keeps_an_earlier_end() {
    for earlier in [true, false] {
        let clock = Clock::at(100.0);
        let (mut case, handle) = Case::new(clock.clone());
        if earlier {
            handle.end_at(101.0, 0);
        }
        handle.close_on_sigterm(5.0, 0);
        case.terminate().expect("the signal is sent");
        let delivered = Delivered::new();
        let mut record = Record::new(&delivered);
        assert_eq!(case.wait(&mut record, Duration::from_secs(10)), Ok(Some(0)));
        let at = if earlier { 101.0 } else { 105.0 };
        assert_eq!(clock.now(), nanoseconds(at), "earlier {earlier}");
    }
}

/// A signal set for a time a reading's step reaches is delivered at that reading, with no sleep
/// between. Control: a signal set past the readings stays undelivered.
#[test]
fn a_reading_s_step_delivers_a_signal_it_reaches() {
    for (at, delivered_after) in [(100.5, true), (102.5, false)] {
        let store = crate::fis_support::delivered();
        let clock = Clock::at(100.0);
        clock.step(Duration::from_secs(1));
        clock.signal_at(at, Signal::Terminate, store);
        clock.monotonic_ns().expect("the clock reads");
        clock.monotonic_ns().expect("the clock reads");
        assert_eq!(
            store.stored(),
            delivered_after.then_some(Signal::Terminate),
            "signal at {at}"
        );
    }
}
