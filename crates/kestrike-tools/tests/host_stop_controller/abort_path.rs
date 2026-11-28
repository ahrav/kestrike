//! Signals, panics, marks and the lock around the stop request and in the abort path: a signal
//! that stands as the stop call starts or returns, one raised inside a call, a panic with a signal
//! stored, a failed final stopped mark, the abort's status read, and the bounds at the request's
//! own second and at a cut of exactly no time.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use kestrike_tools::host_stop::{Disk, LIMIT_SECONDS, LockError, Signal, lock};
use kestrike_tools::json::Value;

use super::plane::{ALARMS, Action, STATUS, STOP, State};
use super::steps::{Step, errno, links, syncs};
use super::stop_run::{int, time};
use super::{Case, guardrails, member, set, text_of};

const ALL: [&str; 4] = ["roles", "stop", "stopped", "abort"];
const STOPPING: [&str; 3] = ["roles", "stop", "abort"];

/// A hook that delivers `signals` into the case's record in order and then answers.
fn delivering(case: &Case, signals: &'static [Signal], interrupt: bool) -> Action {
    let delivered = case.delivered;
    Action::Hook(Box::new(move |state: &mut State| {
        for signal in signals {
            delivered.deliver(*signal);
        }
        state.interrupt = interrupt;
        Action::Answer
    }))
}

fn detail(found: &std::collections::BTreeMap<String, Value>) -> String {
    text_of(&found["abort"], "detail")
}

/// A panic in an alarm read after the stop is shown, with a SIGTERM stored in the record, takes the
/// abort path with cause `exception`, which runs unarmed: the abort and stopped marks stand and the
/// signal raises nowhere.
#[test]
fn a_panic_with_a_signal_stored_still_writes_the_abort_and_stopped_marks() {
    let mut case = Case::new("panic-signal");
    let delivered = case.delivered;
    case.faulted(
        Action::Hook(Box::new(move |_| {
            delivered.deliver(Signal::Terminate);
            panic!("a planted fault")
        })),
        false,
    );
    case.assert_aborted("exception", &ALL, None, Some("panic: a planted fault"));
    assert!(!case.output().contains("Interrupted"), "{}", case.output());
}

/// After a panic in an alarm read, a SIGTERM delivered during the abort's status read, which reads
/// the record as a launch does, leaves the read whole: the abort path runs unarmed.
#[test]
fn a_signal_at_the_abort_status_read_after_a_panic_leaves_the_read() {
    let mut case = Case::new("panic-status");
    let delivered = case.delivered;
    case.faulted(
        Action::Hook(Box::new(move |state| {
            let status = Action::Hook(Box::new(move |state: &mut State| {
                delivered.deliver(Signal::Terminate);
                state.interrupt = true;
                Action::Answer
            }));
            state.script(STATUS, vec![status]);
            panic!("a planted fault")
        })),
        false,
    );
    case.assert_aborted("exception", &ALL, None, Some("panic: a planted fault"));
    let stdout = case.stdout();
    assert!(
        stdout.contains("host-stop-controller: the target reads {"),
        "{stdout}"
    );
    assert!(!case.output().contains("Interrupted"), "{}", case.output());
}

/// A SIGTERM delivered after the alarms' second read, at the check before the stop, stands as the
/// stop call would start: the record's read before the call raises it, so no stop request leaves
/// and the abort says none was sent.
#[test]
fn a_signal_that_stands_before_the_stop_call_starts_sends_no_stop_request() {
    let mut case = Case::new("signal-before-stop");
    let (delivered, sent) = (case.delivered, Rc::new(Cell::new(false)));
    case.plane.borrow_mut().reading = Some(Rc::new(move |state: &State| {
        let again = state
            .log
            .iter()
            .any(|l| l.op == ALARMS && l.marks.iter().any(|m| m == "stop"));
        if again && !sent.get() {
            sent.set(true);
            delivered.deliver(Signal::Terminate);
        }
    }));
    let found = case.assert_aborted("signal", &STOPPING, None, Some("signal SIGTERM"));
    assert!(case.stops().is_empty(), "{:?}", case.ops());
    assert!(
        detail(&found).starts_with("no stop request was sent"),
        "{}",
        detail(&found)
    );
    assert_eq!(case.ops().last().map(String::as_str), Some(ALARMS));
}

/// SIGINT then SIGTERM delivered during the stop call stand when it returns: the run reads the
/// record before the reply, aborts with cause `signal` naming the first, and says a request may
/// have left with its outcome unknown; the abort's status read alone follows the stop call.
#[test]
fn a_signal_that_stands_when_the_stop_call_returns_reads_as_an_unknown_outcome() {
    let mut case = Case::new("signal-at-stop");
    let hook = delivering(&case, &[Signal::Interrupt, Signal::Terminate], false);
    case.plane.borrow_mut().script(STOP, vec![hook]);
    let found = case.assert_aborted("signal", &STOPPING, None, None);
    let text = detail(&found);
    let said = "a stop request may have left and its outcome is unknown; signal SIGINT";
    assert!(text.starts_with(said), "{text}");
    assert!(!text.contains("SIGTERM"), "{text}");
    let ops = case.ops();
    let at = ops
        .iter()
        .position(|op| op == STOP)
        .expect("the stop request");
    assert_eq!(ops[at + 1..], [STATUS]);
}

/// A SIGHUP that a call's own wait raises, as a launch reads the record while its child runs, takes
/// the abort path with cause `signal`: after the stop is shown in an alarm read, and in the stop
/// call, where the abort says a request may have left.
#[test]
fn a_signal_raised_inside_a_call_takes_the_abort_path() {
    let mut case = Case::new("interrupt-alarms");
    case.faulted(delivering(&case, &[Signal::Hangup], true), false);
    let found = case.assert_aborted("signal", &ALL, None, Some("signal SIGHUP"));
    assert!(detail(&found).starts_with("the stop request was sent and answered"));

    let mut case = Case::new("interrupt-stop");
    let hook = delivering(&case, &[Signal::Hangup], true);
    case.plane.borrow_mut().script(STOP, vec![hook]);
    let found = case.assert_aborted("signal", &STOPPING, None, Some("signal SIGHUP"));
    let text = detail(&found);
    assert!(
        text.starts_with("a stop request may have left and its outcome is unknown; signal SIGHUP"),
        "{text}"
    );
}

/// Two signals delivered in one alarm read after the stop is shown: the abort names the first.
#[test]
fn the_first_of_two_signals_names_the_abort() {
    let mut case = Case::new("two-signals");
    let hook = delivering(&case, &[Signal::Terminate, Signal::Hangup], false);
    case.faulted(hook, false);
    let found = case.assert_aborted("signal", &ALL, None, Some("signal SIGTERM"));
    assert!(!detail(&found).contains("SIGHUP"), "{}", detail(&found));
}

/// A SIGTERM delivered at the abort mark's link after the stop is shown is left unraised: the
/// stopped mark follows, the abort's status read prints the target's status, and no line names an
/// interruption.
#[test]
fn a_signal_during_the_abort_path_after_the_stop_is_shown_is_left_unraised() {
    let mut case = Case::new("abort-path-signal");
    case.signal_at(Signal::Terminate, |step| links(step, "abort.json"));
    case.faulted(
        Action::Hook(Box::new(|state| {
            state.flip("gd2-guardrail-5", "ALARM");
            Action::Answer
        })),
        false,
    );
    case.assert_aborted("guardrail", &ALL, Some(&guardrails()[4]), None);
    let stdout = case.stdout();
    assert!(
        stdout.contains("host-stop-controller: the target reads {"),
        "{stdout}"
    );
    assert!(!case.output().contains("Interrupted"), "{}", case.output());
    assert_eq!(case.after_fault(), [STATUS]);
}

/// The abort's status read that fails prints that the target's state is unknown, with the failed
/// call's text.
#[test]
fn a_failed_abort_status_read_says_the_state_is_unknown() {
    let mut case = Case::new("status-refused");
    case.faulted(
        Action::Hook(Box::new(|state| {
            state.flip("gd2-guardrail-5", "ALARM");
            state.script(STATUS, vec![Action::Refuse]);
            Action::Answer
        })),
        false,
    );
    case.assert_aborted("guardrail", &ALL, Some(&guardrails()[4]), None);
    let line = "host-stop-controller: the target's state is unknown: CallFailed: ec2 \
                describe-instance-status gave no answer: refused\n";
    assert!(case.stdout().contains(line), "{}", case.stdout());
}

/// The run holds the lock of `injection/` through the abort path: another holder's lock taken at
/// the abort mark's link is refused as taken.
#[test]
fn the_run_holds_the_lock_of_injection_through_the_abort_path() {
    let mut case = Case::new("abort-lock");
    let (refusals, injection) = (
        Rc::new(RefCell::new(Vec::new())),
        case.evidence.join("injection"),
    );
    let seen = Rc::clone(&refusals);
    case.plant(Box::new(move |_, step| {
        if links(step, "abort.json") {
            seen.borrow_mut().push(lock(&Disk, &injection).err());
        }
        None
    }));
    case.faulted(
        Action::Hook(Box::new(|state| {
            state.flip("gd2-guardrail-5", "ALARM");
            Action::Answer
        })),
        false,
    );
    case.assert_aborted("guardrail", &ALL, Some(&guardrails()[4]), None);
    let refusals = refusals.borrow();
    assert_eq!(refusals.len(), 1);
    assert!(
        matches!(refusals[0], Some(LockError::Taken(_))),
        "{refusals:?}"
    );
}

/// Fails the first sync after the link of `stopped.json`.
fn unsynced_stopped(case: &Case) {
    let mut linked = false;
    case.plant(Box::new(move |_, step| {
        if links(step, "stopped.json") {
            linked = true;
        } else if linked && syncs(step) {
            linked = false;
            return Some(errno(libc::EIO));
        }
        None
    }));
}

/// A final stopped mark that stands with its durability unknown counts as written: the run takes
/// the abort path with cause `exception`, and the abort path writes no second stopped mark. One
/// that is unwritten is written by the abort path after the abort mark, with the value the
/// observation built.
#[test]
fn a_failed_final_stopped_mark_takes_the_abort_path() {
    let mut case = Case::new("stopped-unsynced");
    unsynced_stopped(&case);
    case.fail_once(
        libc::EACCES,
        |step| matches!(step, Step::Unlink(name) if *name == "stopped.json"),
    );
    let links_made = Rc::new(Cell::new(0));
    let counted = Rc::clone(&links_made);
    case.plant(Box::new(move |_, step| {
        if links(step, "stopped.json") {
            counted.set(counted.get() + 1);
        }
        None
    }));
    case.assert_aborted(
        "exception",
        &ALL,
        None,
        Some("stopped.json stands, but it cannot be synced"),
    );
    assert_eq!(links_made.get(), 1, "the stopped mark is linked once");

    let mut case = Case::new("stopped-unwritten");
    case.fail_once(libc::ENOSPC, |step| links(step, "stopped.json"));
    let found = case.assert_aborted("exception", &ALL, None, Some("No space left on device"));
    assert_eq!(member(&found["stopped"], "request"), &found["stop"]);
    assert_eq!(text_of(&found["stopped"], "state"), "stopped");
}

/// A stop mark's write that leaves the stop call exactly no time of its half of the effect timeout
/// gives the request no time: it never leaves. Quarter-second calls keep every time exact in
/// binary, so the cut reads exactly 0.
#[test]
fn a_stop_call_with_exactly_no_time_left_never_leaves() {
    let mut case = Case::new("no-time");
    set(
        &mut case.operator,
        &["snapshot_max_age_seconds"],
        int(LIMIT_SECONDS),
    );
    case.plane.borrow_mut().call_seconds = 0.25;
    let mut moved = false;
    case.plant(Box::new(move |state, step| {
        if !moved && links(step, "stop.json") {
            moved = true;
            let quiet = state
                .log
                .iter()
                .find(|l| l.op == ALARMS)
                .and_then(|l| l.time);
            let quiet = quiet.expect("the first alarm read answered");
            state.t = quiet + 60.0 / 2.0 - 0.25;
        }
        None
    }));
    let found = case.assert_aborted("stop-not-shown", &STOPPING, None, Some("never left"));
    assert!(case.stops().is_empty(), "{:?}", case.ops());
    assert!(
        detail(&found).starts_with("no stop request was sent"),
        "{}",
        detail(&found)
    );
}

/// A status read of `stopped` whose wall reading equals the stop mark's time shows the stop, and
/// the stopped mark is dated at that read. Quarter-second calls keep every time exact in binary.
#[test]
fn a_stopped_read_dated_at_the_requests_own_time_shows_the_stop() {
    let mut case = Case::new("at-request");
    let evidence = case.evidence.clone();
    let at_request = Action::Hook(Box::new(move |state: &mut State| {
        let stop =
            std::fs::read_to_string(evidence.join("injection/stop.json")).expect("stop.json");
        state.step = time(&crate::host_stop_support::value(&stop)) - (state.t + 0.25);
        Action::Answer
    }));
    {
        let mut plane = case.plane.borrow_mut();
        plane.call_seconds = 0.25;
        plane.script(STATUS, vec![Action::Answer, Action::Answer, at_request]);
    }
    let code = case.run();
    assert_eq!(code, 0, "{}", case.output());
    let marks = case.marks();
    assert_eq!(time(&marks["stopped"]), time(&marks["stop"]));
}
