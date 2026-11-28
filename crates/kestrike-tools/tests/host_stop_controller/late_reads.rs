use std::cell::Cell;
use std::rc::Rc;

use kestrike_tools::host_stop::{Number, Record, Signal};
use kestrike_tools::host_stop_controller::{Fault, Halt, Preflight};
use kestrike_tools::json::{Object, Value};

use super::plane::{ALARMS, Action, CALLER, MONOTONIC, RECORD, STATUS, State};
use super::steps::{Step, links};
use super::stop_run::operator_seconds;
use super::{COPY, Case, listing, text_of};
use crate::host_stop_support::{TARGET, object, value};

const ALL: [&str; 4] = ["roles", "stop", "stopped", "abort"];
const STOPPING: [&str; 3] = ["roles", "stop", "abort"];

fn detail(found: &std::collections::BTreeMap<String, Value>) -> String {
    text_of(&found["abort"], "detail")
}

/// Runs `deliver` once, at the first monotonic reading at which `when` holds.
fn at_reading(
    case: &Case,
    when: impl Fn(&State) -> bool + 'static,
    deliver: impl Fn(&mut State) + 'static,
) {
    let done = Cell::new(false);
    case.plane.borrow_mut().ticking = Some(Rc::new(move |state: &mut State| {
        if !done.get() && when(state) {
            done.set(true);
            deliver(state);
        }
    }));
}

/// SIGTERM delivered at the first monotonic reading after the alarm read that starts at or after
/// the observation's end returns: the run aborts with cause `signal`, all four marks standing.
#[test]
fn a_signal_after_the_observations_last_read_takes_the_abort_path() {
    let mut case = Case::new("signal-observation-end");
    let observe = operator_seconds(&case, "observe_seconds");
    let delivered = case.delivered;
    at_reading(
        &case,
        move |state| {
            let shown = state.log.iter().find(|l| l.op == RECORD).and_then(|l| l.time);
            let Some(shown) = shown else {
                return false;
            };
            state.log.last().is_some_and(|last| {
                last.op == ALARMS && last.time.is_some() && last.start >= shown + observe
            })
        },
        move |_| delivered.deliver(Signal::Terminate),
    );
    let found = case.assert_aborted("signal", &ALL, None, Some("signal SIGTERM"));
    assert!(
        detail(&found).starts_with("the stop request was sent and answered"),
        "{}",
        detail(&found)
    );
}

/// With the stop never shown, SIGTERM delivered when the first poll pause ends at or after the
/// effect timeout: the run aborts with cause `signal`.
#[test]
fn a_signal_in_the_polls_last_pause_takes_the_abort_path_with_its_own_cause() {
    let mut case = Case::new("signal-effect-end");
    let effect = operator_seconds(&case, "effect_timeout_seconds");
    let delivered = case.delivered;
    let mut sent = false;
    {
        let mut plane = case.plane.borrow_mut();
        plane.stop_after = None;
        plane.slept = Some(Box::new(move |state| {
            let Some(stop) = state.stops().first().map(|stop| stop.start) else {
                return;
            };
            let request = state
                .log
                .iter()
                .filter(|l| l.op == ALARMS && l.start < stop)
                .filter(|l| !l.marks.iter().any(|m| m == "stop"))
                .filter_map(|l| l.time)
                .fold(f64::MIN, f64::max);
            if !sent && state.t >= request + effect - 1e-6 {
                sent = true;
                delivered.deliver(Signal::Terminate);
            }
        }));
    }
    case.assert_aborted("signal", &STOPPING, None, Some("signal SIGTERM"));
}

impl Case {
    fn assert_signalled(&mut self, calls: &[&str]) {
        let code = self.run();
        assert_eq!(code, 2, "{}", self.output());
        assert_eq!(
            self.stderr(),
            "host-stop-controller: signal SIGTERM before any mark; nothing written\n"
        );
        assert_eq!(self.ops(), calls);
        assert_eq!(listing(&self.evidence), [COPY]);
    }
}

/// The first run delivers SIGTERM on the second monotonic reading after `STATUS` returns, and the
/// second run delivers SIGTERM inside `STATUS`. Both runs end before the first mark.
#[test]
fn a_signal_while_the_roles_mark_is_built_ends_the_run_before_any_mark() {
    let mut case = Case::new("signal-roles-built");
    let (delivered, readings) = (case.delivered, Rc::new(Cell::new(0)));
    at_reading(
        &case,
        move |state| {
            let answered = state.log.last().is_some_and(|l| l.op == STATUS && l.time.is_some());
            if answered {
                readings.set(readings.get() + 1);
            }
            readings.get() == 2
        },
        move |_| delivered.deliver(Signal::Terminate),
    );
    case.assert_signalled(&[CALLER, STATUS]);

    let mut case = Case::new("signal-in-status");
    let delivered = case.delivered;
    let hook = Action::Hook(Box::new(move |_| {
        delivered.deliver(Signal::Terminate);
        Action::Answer
    }));
    case.plane.borrow_mut().script(STATUS, vec![hook]);
    case.assert_signalled(&[CALLER, STATUS]);
}

fn at_stop_reading(case: &Case, at: usize, deliver: impl Fn(&mut State) + 'static) {
    let readings = Cell::new(0);
    at_reading(
        case,
        move |state| {
            let again = state.log.last().is_some_and(|l| {
                l.op == ALARMS && l.time.is_some() && l.marks.iter().any(|m| m == "stop")
            });
            if again && state.stops().is_empty() {
                readings.set(readings.get() + 1);
            }
            readings.get() == at
        },
        deliver,
    );
}

/// A signal or panic during a pre-dispatch clock reading aborts the stop call.
#[test]
fn a_signal_or_a_panic_at_the_stop_calls_bounds_sends_no_stop_request() {
    for at in 3..=6 {
        let mut case = Case::new("signal-stop-bounds");
        let delivered = case.delivered;
        at_stop_reading(&case, at, move |_| delivered.deliver(Signal::Terminate));
        let found = case.assert_aborted("signal", &STOPPING, None, Some("signal SIGTERM"));
        assert!(case.stops().is_empty(), "{at}: {:?}", case.ops());
        let text = detail(&found);
        assert!(text.starts_with("no stop request was sent"), "{at}: {text}");
    }

    let mut case = Case::new("panic-launch-reading");
    at_stop_reading(&case, 6, |_| panic!("a planted clock fault"));
    let found = case.assert_aborted("exception", &STOPPING, None, Some("panic: a planted"));
    assert!(case.stops().is_empty(), "{:?}", case.ops());
    let text = detail(&found);
    assert!(text.starts_with("no stop request was sent"), "{text}");
}

#[test]
fn a_panic_while_the_record_is_held_leaves_it_unheld_for_the_next_entry() {
    for at in ["mkdir", "abort link"] {
        let mut case = Case::new("held-panic");
        case.plant(Box::new(move |_, step| {
            let planted = match at {
                "mkdir" => matches!(step, Step::Mkdir(_)),
                _ => links(step, "abort.json"),
            };
            assert!(!planted, "a planted file fault");
            None
        }));
        if at == "abort link" {
            case.plane.borrow_mut().flip("gd2-guardrail-4", "ALARM");
        }
        let mut record = Record::new(case.delivered);
        let evidence = case.evidence.clone().into_os_string();
        let code = case.run_on(&mut record, evidence.clone());
        assert!(case.output().contains("a planted file fault"), "{at}: {}", case.output());
        assert!(!record.is_held() && !record.is_armed(), "{at}: {code} {record:?}");
        let (calls, before) = (case.ops(), listing(&case.evidence));
        case.delivered.deliver(Signal::Terminate);
        let code = case.run_on(&mut record, evidence);
        assert_eq!(code, 2, "{at}: {}", case.output());
        assert!(
            case.stderr()
                .ends_with("host-stop-controller: signal SIGTERM before any mark; nothing written\n"),
            "{at}: {}",
            case.stderr()
        );
        assert_eq!(case.ops(), calls, "{at}");
        assert_eq!(listing(&case.evidence), before, "{at}");
    }
}

#[test]
fn the_starts_clock_readings_precede_the_package_read() {
    let mut case = Case::new("start-readings");
    let (walls, ticks) = (Rc::new(Cell::new(0)), Rc::new(Cell::new(0)));
    let (w, t) = (Rc::clone(&walls), Rc::clone(&ticks));
    {
        let mut plane = case.plane.borrow_mut();
        plane.reading = Some(Rc::new(move |_: &State| w.set(w.get() + 1)));
        plane.ticking = Some(Rc::new(move |_: &mut State| t.set(t.get() + 1)));
    }
    std::fs::remove_file(&case.package).expect("the package is removed");
    let code = case.run();
    assert_eq!(code, 2, "{}", case.output());
    assert!(case.output().contains("the package"), "{}", case.output());
    assert_eq!((walls.get(), ticks.get()), (1, 1));
    assert!(case.ops().is_empty());
}

#[test]
fn a_deadline_reached_once_the_roles_mark_is_built_is_a_refusal() {
    let mut case = Case::new("deadline-roles-built");
    let readings = Rc::new(Cell::new(0));
    at_reading(
        &case,
        move |state| {
            let answered = state.log.last().is_some_and(|l| l.op == STATUS && l.time.is_some());
            if answered {
                readings.set(readings.get() + 1);
            }
            readings.get() == 2
        },
        |state| state.t = state.deadline.expect("the plane holds the deadline"),
    );
    case.assert_refused(&[CALLER, STATUS], "s passed before injection/ was made");
}

#[test]
fn a_signal_that_stands_as_a_poll_pauses_takes_the_abort_path() {
    let mut case = Case::new("signal-at-pause");
    let (delivered, sent) = (case.delivered, Cell::new(false));
    case.plane.borrow_mut().reading = Some(Rc::new(move |state: &State| {
        let stopping = state.instances[TARGET].state == "stopping";
        let polled = state.log.last().is_some_and(|l| l.op == STATUS);
        if !sent.get() && stopping && polled && !state.stops().is_empty() {
            sent.set(true);
            delivered.deliver(Signal::Terminate);
        }
    }));
    case.assert_aborted("signal", &STOPPING, None, Some("signal SIGTERM"));
    let ops = case.ops();
    assert_eq!(ops[ops.len() - 3..], [ALARMS, STATUS, STATUS], "{ops:?}");
    assert_eq!(case.plane.borrow().sleeps, 0);
}

#[test]
fn a_stop_awaited_with_no_target_read_is_an_order_fault() {
    let mut case = Case::new("await-no-target");
    let package = object(value(
        &std::fs::read_to_string(&case.package).expect("the package reads"),
    ));
    let monotonic = case.plane.borrow().t + MONOTONIC;
    let wall = case.plane.borrow().wall();
    let ended = case.controlled(|controller| {
        controller.set_preflight(Preflight::new(
            package,
            Number::from(100),
            Number::from(100),
            (wall, monotonic),
            monotonic + 56.0,
        ));
        controller.set_deadline(monotonic + 290.0);
        let mut request = Object::new();
        request.insert("time", Value::Float(wall));
        controller.await_stop(&Value::Object(request), monotonic + 60.0)
    });
    assert!(matches!(ended, Err(Halt::Fault(Fault::Order(_)))), "{ended:?}");
    assert!(case.ops().is_empty());
    assert_eq!(case.plane.borrow().sleeps, 0);
}

#[test]
fn a_failed_lookup_of_the_evidence_root_is_refused_with_no_call() {
    let mut case = Case::new("root-lookup");
    let root = case.evidence.clone();
    case.fail_once(libc::EIO, move |step| matches!(step, Step::Lstat(path) if *path == root));
    case.assert_refused(&[], "is no directory");
}
