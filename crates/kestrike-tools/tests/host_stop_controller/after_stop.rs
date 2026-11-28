//! The abort path after a stop request: each cause after the stop is shown, or between the request
//! and the stop shown, leaves the marks that stand and makes no call that changes an instance; after
//! the faulted call the abort path's one status read alone follows.

use std::fs;
use std::io;
use std::os::unix::process::ExitStatusExt;
use std::rc::Rc;

use kestrike_tools::host_stop::{
    DETAIL_MAX, Disk, LIMIT_SECONDS, LockError, Signal, install, lock,
};
use kestrike_tools::host_stop_controller::Halt;
use kestrike_tools::json::Value;

use super::plane::{ALARMS, Action, CALLER, MONOTONIC, RECORD, STATUS, State};
use super::steps::{Step, errno, links};
use super::stop_run::{int, operator_seconds, time};
use super::{CHILD, COPY, Case, child, guardrails, listing, set, tail, text_of};
use crate::host_stop_support::{START, Scratch, TARGET, free_lock};

const ALL: [&str; 4] = ["roles", "stop", "stopped", "abort"];
const STOPPING: [&str; 3] = ["roles", "stop", "abort"];

/// The run aborts with `cause` and `guardrail`, the marks `marks` standing, the abort's status read
/// alone after the faulted call, one stop request, and the abort mark dated at or after the stop
/// mark and the stopped mark.
fn check(
    case: &mut Case,
    cause: &str,
    guardrail: Option<&str>,
    marks: &[&str],
) -> std::collections::BTreeMap<String, Value> {
    let found = case.assert_aborted(cause, marks, guardrail, None);
    assert_eq!(case.after_fault(), [STATUS], "{:?}", case.ops());
    assert_eq!(case.stops().len(), 1);
    let abort = time(&found["abort"]);
    assert!(abort >= time(&found["stop"]), "{found:?}");
    let (log, step) = (case.log(), case.plane.borrow().step);
    let fault = &log[case.fault_index()];
    let faulted = fault.time.unwrap_or(fault.start) + step;
    let read = log.last().expect("the abort's status read").start + step;
    assert!(
        faulted <= abort && abort <= read,
        "{faulted} {abort} {read}"
    );
    if let Some(stopped) = found.get("stopped") {
        assert!(abort >= time(stopped), "{found:?}");
    }
    found
}

/// A fault on an alarm read after the stop request that starts less than 30 s before the deadline:
/// a delay of 40 s, which the call's cut at the deadline ends.
fn near_deadline(case: &Case) {
    case.plane.borrow_mut().fault = Some(Box::new(|state, op| {
        let near = state
            .deadline
            .is_some_and(|deadline| deadline - state.t < 30.0);
        (op == ALARMS && !state.stops().is_empty() && near).then_some(Action::Delay(40.0))
    }));
}

fn flip(name: &'static str, to: &'static str) -> Action {
    Action::Hook(Box::new(move |state| {
        state.flip(name, to);
        Action::Answer
    }))
}

fn operate(case: &mut Case, key: &str, seconds: i64) {
    set(&mut case.operator, &[key], int(seconds));
}

fn detail(found: &std::collections::BTreeMap<String, Value>) -> String {
    text_of(&found["abort"], "detail")
}

/// A guardrail alarm after the stop is shown aborts on that guardrail.
#[test]
fn a_guardrail_alarm() {
    let mut case = Case::new("guardrail");
    case.faulted(flip("gd2-guardrail-5", "ALARM"), false);
    check(&mut case, "guardrail", Some(&guardrails()[4]), &ALL);
}

/// An alarm without data after the stop is shown aborts on its guardrail.
#[test]
fn an_alarm_without_data() {
    let mut case = Case::new("no-data");
    case.faulted(flip("gd2-guardrail-2", "INSUFFICIENT_DATA"), false);
    check(&mut case, "guardrail", Some(&guardrails()[1]), &ALL);
}

/// An alarm that fired and recovered between two reads reads OK with a moved transition, and
/// aborts on its guardrail as one that changed state.
#[test]
fn an_alarm_that_fired_and_recovered_between_two_reads() {
    let mut case = Case::new("flicker");
    case.faulted(
        Action::Hook(Box::new(|state| {
            state.flip("gd2-guardrail-7", "ALARM");
            state.flip("gd2-guardrail-7", "OK");
            Action::Answer
        })),
        false,
    );
    let found = check(&mut case, "guardrail", Some(&guardrails()[6]), &ALL);
    assert!(
        detail(&found).contains("changed state"),
        "{}",
        detail(&found)
    );
}

/// The observation's final alarm read, the last call of a run, answers quiet but past the deadline:
/// the run aborts with cause `deadline`, and no call but the abort's status read starts after it.
/// The fault is planted on the first alarm read that starts 240 s after the confirming record read
/// returns.
#[test]
fn an_alarm_read_that_answers_past_the_deadline_aborts_the_run() {
    let mut case = Case::new("final-late");
    operate(&mut case, "effect_timeout_seconds", 40);
    operate(&mut case, "observe_seconds", 240);
    case.plane.borrow_mut().fault = Some(Box::new(|state, op| {
        let stopped = state.instances[TARGET].state == "stopped";
        let shown = state
            .log
            .iter()
            .find(|l| l.op == RECORD)
            .and_then(|l| l.time);
        let at_end = shown.is_some_and(|shown| stopped && state.t >= shown + 240.0 - 1e-6);
        (op == ALARMS && at_end).then_some(Action::Late)
    }));
    let found = check(&mut case, "deadline", None, &ALL);
    assert!(
        detail(&found).contains("the deadline of"),
        "{}",
        detail(&found)
    );
    let ops = case.ops();
    assert_eq!(ops[case.fault_index() + 1..], [STATUS]);
    let log = case.log();
    let shown = log.iter().find(|l| l.op == RECORD).and_then(|l| l.time);
    let planted = &log[case.fault_index()];
    assert!(
        planted.start >= shown.expect("the record read") + 240.0 - 1e-6,
        "{planted:?}"
    );
}

/// An observation that outlasts the deadline: the stop shows late, so a poll starts within 30 s of
/// the deadline, and that call's cut at the deadline aborts the run with cause `deadline`.
#[test]
fn the_deadline() {
    let mut case = Case::new("deadline");
    operate(&mut case, "effect_timeout_seconds", 40);
    operate(&mut case, "observe_seconds", 240);
    case.plane.borrow_mut().stop_after = Some(7);
    near_deadline(&case);
    let found = check(&mut case, "deadline", None, &ALL);
    assert!(case.log()[case.fault_index()].cut);
    assert!(
        detail(&found).contains("the deadline of"),
        "{}",
        detail(&found)
    );
}

/// An observation that ends 6 s before the deadline runs its polls into the deadline's last 20 s:
/// the call after an alarm read delayed to 20 s before the deadline is cut to the time left, and
/// every call's cut is at most the least of 60 s and the time left.
#[test]
fn a_call_near_the_deadline_is_cut_to_what_is_left() {
    let mut case = Case::new("near-deadline");
    let deadline = operator_seconds(&case, "deadline_seconds");
    operate(&mut case, "effect_timeout_seconds", 20);
    operate(&mut case, "observe_seconds", deadline as i64 - 25);
    let end = START + deadline - 20.0;
    case.plane.borrow_mut().fault = Some(Box::new(move |state, op| {
        let left = end - state.t;
        let planted = op == ALARMS && state.shown() && 0.0 < left && left < 59.0;
        planted.then_some(Action::Delay(left))
    }));
    let code = case.run();
    assert_eq!(code, 0, "{}", case.output());
    let log = case.log();
    let after = &log[case.fault_index() + 1];
    let left = after.left.expect("the deadline is set");
    assert!(after.timeout < 20.0, "{after:?}");
    assert!((after.timeout - left).abs() <= 1e-6, "{after:?}");
    for logged in &log {
        let bound = logged.left.expect("the deadline is set").min(60.0);
        assert!(logged.timeout <= bound + 1e-9, "{logged:?}");
    }
}

/// A panic in an alarm read after the stop is shown aborts with cause `exception`: the detail says
/// the request was sent and answered, names the panic, and is cut to its bound with the steps'
/// digest whole at its end.
#[test]
fn an_exception() {
    let mut case = Case::new("exception");
    case.faulted(
        Action::Hook(Box::new(|_| {
            panic!(
                "a planted fault in the alarm read {}",
                "x".repeat(DETAIL_MAX)
            )
        })),
        false,
    );
    let found = check(&mut case, "exception", None, &ALL);
    let text = detail(&found);
    assert!(
        text.starts_with("the stop request was sent and answered; panic: a planted fault"),
        "{}",
        text.chars().take(100).collect::<String>()
    );
    assert_eq!(text.chars().count(), DETAIL_MAX);
    assert!(
        text.ends_with(&format!("x{}", tail())),
        "the steps' digest stays whole"
    );
}

/// The record read's time anchors the observation; an alarm read that starts at or after the
/// observation's end and answers past the deadline aborts the run with cause `deadline`.
#[test]
fn the_observations_last_alarm_read_answering_past_the_deadline_aborts_the_run() {
    let mut case = Case::new("last-late");
    let deadline = operator_seconds(&case, "deadline_seconds");
    operate(&mut case, "effect_timeout_seconds", 20);
    operate(&mut case, "observe_seconds", deadline as i64 - 25);
    let observe = deadline - 25.0;
    case.plane.borrow_mut().fault = Some(Box::new(move |state, op| {
        let shown = state
            .log
            .iter()
            .find(|l| l.op == RECORD)
            .and_then(|l| l.time);
        let at_end = shown.is_some_and(|shown| state.t > shown + observe - 0.1);
        (op == ALARMS && at_end).then_some(Action::Late)
    }));
    let found = check(&mut case, "deadline", None, &ALL);
    assert!(
        detail(&found).contains("the deadline of"),
        "{}",
        detail(&found)
    );
    let planted = case.log()[case.fault_index()].time.expect("dated");
    let ends = case.plane.borrow().deadline.expect("the deadline is set");
    assert!(planted > ends, "{planted} {ends}");
}

/// The run holds the lock of `injection/` to its end: another holder's lock taken during the
/// observation is refused as taken, the lock is free once the run ends, and a missing directory's
/// lock is refused as unopened.
#[test]
fn the_run_holds_the_lock_of_injection_to_its_end() {
    let mut case = Case::new("lock");
    let refusals = Rc::new(std::cell::RefCell::new(Vec::new()));
    let (seen, injection) = (Rc::clone(&refusals), case.evidence.join("injection"));
    case.faulted(
        Action::Hook(Box::new(move |_| {
            seen.borrow_mut().push(lock(&Disk, &injection).err());
            Action::Answer
        })),
        false,
    );
    let code = case.run();
    assert_eq!(code, 0, "{}", case.output());
    let refusals = refusals.borrow();
    assert_eq!(refusals.len(), 1);
    assert!(
        matches!(refusals[0], Some(LockError::Taken(_))),
        "{refusals:?}"
    );
    drop(free_lock(&case.evidence.join("injection")));
    let missing = lock(&Disk, &case.evidence.join("no-such-directory"));
    assert!(matches!(missing, Err(LockError::Open(_))), "{missing:?}");
}

fn deliver(case: &Case, signal: Signal) -> Action {
    let delivered = case.delivered;
    Action::Hook(Box::new(move |_| {
        delivered.deliver(signal);
        Action::Answer
    }))
}

/// A SIGTERM delivered during an alarm read after the stop is shown aborts with cause `signal` when
/// the read returns, with the signal's name in the detail.
#[test]
fn a_process_signal() {
    let mut case = Case::new("signal");
    case.faulted(deliver(&case, Signal::Terminate), false);
    let found = check(&mut case, "signal", None, &ALL);
    assert!(detail(&found).contains("SIGTERM"), "{}", detail(&found));
}

/// Each cause between the stop request and the stop shown, with a target that never reads stopped,
/// aborts with the roles, stop and abort marks: a guardrail alarm, a signal, and the deadline that
/// a late start leaves inside the effect timeout.
#[test]
fn each_cause_between_the_stop_request_and_the_stop_shown() {
    let mut case = Case::new("between-guardrail");
    case.plane.borrow_mut().stop_after = None;
    case.faulted(flip("gd2-guardrail-3", "ALARM"), true);
    check(&mut case, "guardrail", Some(&guardrails()[2]), &STOPPING);

    let mut case = Case::new("between-signal");
    case.plane.borrow_mut().stop_after = None;
    case.faulted(deliver(&case, Signal::Interrupt), true);
    let found = check(&mut case, "signal", None, &STOPPING);
    assert!(detail(&found).contains("SIGINT"), "{}", detail(&found));

    let mut case = Case::new("between-deadline");
    case.plane.borrow_mut().stop_after = None;
    operate(&mut case, "deadline_seconds", 105);
    case.plane
        .borrow_mut()
        .script(CALLER, vec![Action::Delay(50.0)]);
    near_deadline(&case);
    check(&mut case, "deadline", None, &STOPPING);
}

/// A SIGTERM delivered during the final stopped mark's write is left unraised: the run ends with
/// exit 0 and its three marks.
#[test]
fn a_signal_during_the_final_stopped_mark_keeps_exit_0() {
    let mut case = Case::new("signal-stopped");
    case.signal_at(Signal::Terminate, |step| links(step, "stopped.json"));
    let code = case.run();
    assert_eq!(code, 0, "{}", case.output());
    let names: Vec<String> = case.marks().keys().cloned().collect();
    assert_eq!(names, ["roles", "stop", "stopped"]);
}

const KILLED: &str = "after_stop::a_run_killed_during_the_observation_leaves_no_stopped_mark";

/// A run killed by SIGKILL inside an alarm read of the observation leaves the roles and stop marks
/// alone. The kill ends a process of the case's own, whose scratch directory stands under the
/// parent's, and which names its evidence directory in the file `evidence` there.
#[test]
fn a_run_killed_during_the_observation_leaves_no_stopped_mark() {
    if let Some(place) = std::env::var_os(CHILD) {
        let mut case = Case::new("killed");
        let named = std::path::Path::new(&place).join("evidence");
        fs::write(&named, case.evidence.as_os_str().as_encoded_bytes()).expect("named");
        case.faulted(
            Action::Hook(Box::new(|_| {
                // SAFETY: `kill` of this process with SIGKILL takes no pointer.
                unsafe { libc::kill(libc::getpid(), libc::SIGKILL) };
                unreachable!("SIGKILL ends the process")
            })),
            false,
        );
        let code = case.run();
        panic!("the run ended with {code}, not by the kill");
    }
    let place = Scratch::new("killed-child");
    let (status, shown) = child(KILLED, &place.0, &[]);
    assert_eq!(status.signal(), Some(libc::SIGKILL), "{shown}");
    let evidence = fs::read_to_string(place.0.join("evidence")).expect("the child named it");
    let marks = listing(&std::path::Path::new(&evidence).join("injection"));
    assert_eq!(marks, ["roles.json", "stop.json"], "{shown}");
}

/// An abort mark that cannot be written leaves no stopped mark: the run exits 1, says the abort
/// mark is unwritten, and makes the abort's status read alone after the faulted call.
#[test]
fn a_failed_abort_mark_leaves_no_stopped_mark() {
    let mut case = Case::new("abort-unwritten");
    case.fail_once(libc::ENOSPC, |step| links(step, "abort.json"));
    case.faulted(flip("gd2-guardrail-1", "ALARM"), false);
    let code = case.run();
    let output = case.output();
    assert_eq!(code, 1, "{output}");
    let names: Vec<String> = case.marks().keys().cloned().collect();
    assert_eq!(names, ["roles", "stop"]);
    let stderr = case.stderr();
    assert!(
        stderr.starts_with("host-stop-controller: abort.json is unwritten: OSError: [Errno 28] "),
        "{stderr}"
    );
    assert!(!case.stdout().contains("abort.json"), "{}", case.stdout());
    assert_eq!(case.after_fault(), [STATUS]);
}

/// Streams whose every write fails with EIO, or takes no byte, change no outcome: a clean run exits
/// 0 and an abort after the stop exits 1 with its abort mark and the abort's status read alone
/// after the faulted call.
#[test]
fn a_failed_output_stream_changes_no_outcome() {
    let failures: [(&str, super::Writes); 2] = [
        ("EIO", Rc::new(|_| Some(Err(errno(libc::EIO))))),
        ("no byte taken", Rc::new(|_| Some(Ok(0)))),
    ];
    for (name, writes) in failures {
        for aborted in [false, true] {
            let mut case = Case::new("broken-stream");
            case.writes = Some(Rc::clone(&writes));
            if aborted {
                case.faulted(flip("gd2-guardrail-1", "ALARM"), false);
            }
            let code = case.run();
            assert_eq!(code, if aborted { 1 } else { 0 }, "{name}");
            assert_eq!(case.output(), "", "{name}: every write failed");
            assert_eq!(case.marks().contains_key("abort"), aborted, "{name}");
            if aborted {
                assert_eq!(case.after_fault(), [STATUS], "{name}");
            }
        }
    }
}

/// The disposition of `signal` in this process.
fn disposition(signal: i32) -> libc::sighandler_t {
    // SAFETY: all-zero bytes are a valid `sigaction`; a null new action only reads the current one
    // into `current`, which outlives the call.
    unsafe {
        let mut current: libc::sigaction = std::mem::zeroed();
        assert_eq!(libc::sigaction(signal, std::ptr::null(), &mut current), 0);
        current.sa_sigaction
    }
}

/// Ignores SIGHUP in this process, then registers the signal record's handlers as the tool does.
fn ignore_hangup_and_install(case: &Case) {
    // SAFETY: setting a disposition to SIG_IGN takes no handler code.
    let previous = unsafe { libc::signal(libc::SIGHUP, libc::SIG_IGN) };
    assert_ne!(previous, libc::SIG_ERR, "{}", io::Error::last_os_error());
    install(case.delivered).expect("the handlers are registered");
    assert_eq!(disposition(libc::SIGHUP), libc::SIG_IGN);
}

fn hang_up() {
    // SAFETY: `kill` of this process with SIGHUP takes no pointer.
    assert_eq!(unsafe { libc::kill(libc::getpid(), libc::SIGHUP) }, 0);
}

const IGNORED: &str = "after_stop::an_ignored_hangup_stays_ignored";

/// A SIGHUP ignored at the start stays ignored once the handlers are registered: one sent during
/// the observation changes nothing, and the run exits 0 with no abort mark. The case runs in a
/// process of its own, since it sets that process's dispositions.
#[test]
fn an_ignored_hangup_stays_ignored() {
    if std::env::var_os(CHILD).is_some() {
        let mut case = Case::new("ignored");
        ignore_hangup_and_install(&case);
        case.faulted(
            Action::Hook(Box::new(|_| {
                hang_up();
                Action::Answer
            })),
            false,
        );
        let code = case.run();
        assert_eq!(code, 0, "{}", case.output());
        assert!(!case.marks().contains_key("abort"));
        assert_eq!(disposition(libc::SIGHUP), libc::SIG_IGN);
        return;
    }
    let place = Scratch::new("ignored-child");
    let (status, shown) = child(IGNORED, &place.0, &[]);
    assert!(status.success(), "{shown}");
    assert!(shown.contains("1 passed"), "{shown}");
}

const READ: &str = "after_stop::a_signal_while_the_arguments_the_catalog_or_the_operator_file_are_read_ends_the_run_the_same_way";

/// Runs `case` with `signal` put into its record before the entry is called, where a signal that
/// arrives while the arguments, the catalog or the operator file are read stands at the arming.
fn signalled_before(case: &mut Case, signal: Signal) -> u8 {
    case.delivered.deliver(signal);
    case.run()
}

/// A signal while the arguments, the catalog or the operator file are read ends the run with exit
/// 2, `signal <name> before any mark; nothing written`, no call and nothing written; a second signal
/// while the first ends the run, or one while a refusal of the operator file is printed, changes
/// nothing. A SIGHUP ignored at the start stays ignored while the operator file is read, in a
/// process of its own, since it sets that process's dispositions.
#[test]
fn a_signal_while_the_arguments_the_catalog_or_the_operator_file_are_read_ends_the_run_the_same_way()
 {
    if std::env::var_os(CHILD).is_some() {
        let mut case = Case::new("read-ignored");
        ignore_hangup_and_install(&case);
        hang_up();
        let code = case.run();
        assert_eq!(code, 0, "{}", case.output());
        assert_eq!(disposition(libc::SIGHUP), libc::SIG_IGN);
        return;
    }
    for read in ["the arguments", "the catalog", "the operator file"] {
        for signal in Signal::ALL {
            let mut case = Case::new("read-signal");
            let code = signalled_before(&mut case, signal);
            let output = case.output();
            assert_eq!(code, 2, "{read}: {output}");
            let said = format!("signal {} before any mark; nothing written", signal.name());
            assert!(output.contains(&said), "{read}: {said:?} in {output}");
            assert_eq!(case.ops(), Vec::<String>::new(), "{read}");
            assert_eq!(listing(&case.evidence), [COPY], "{read}");
        }
    }

    let mut case = Case::new("read-second");
    let delivered = case.delivered;
    case.writes = Some(Rc::new(move |_| {
        delivered.deliver(Signal::Terminate);
        None
    }));
    let code = signalled_before(&mut case, Signal::Interrupt);
    let output = case.output();
    assert_eq!(code, 2, "{output}");
    assert_eq!(
        output,
        "host-stop-controller: signal SIGINT before any mark; nothing written\n"
    );
    assert_eq!(
        (case.ops(), listing(&case.evidence)),
        (Vec::new(), vec![COPY.to_owned()])
    );

    let mut case = Case::new("read-refusal");
    let delivered = case.delivered;
    case.writes = Some(Rc::new(move |_| {
        delivered.deliver(Signal::Terminate);
        None
    }));
    set(
        &mut case.operator,
        &["region"],
        super::plane::string("nowhere"),
    );
    let code = case.run();
    let output = case.output();
    assert_eq!(code, 2, "{output}");
    assert!(
        output.contains("refused: region 'nowhere' is no AWS region name; nothing written"),
        "{output}"
    );
    assert_eq!(
        (case.ops(), listing(&case.evidence)),
        (Vec::new(), vec![COPY.to_owned()])
    );

    let place = Scratch::new("read-ignored-child");
    let (status, shown) = child(READ, &place.0, &[]);
    assert!(status.success(), "{shown}");
    assert!(shown.contains("1 passed"), "{shown}");
}

/// A wall clock that steps 1000 s forward during the observation moves no bound: the observation
/// still runs `observe_seconds` on the monotonic clock. One that steps 1000 s back before the target
/// reads stopped moves none either: the polls end at the effect timeout, counted from the request,
/// with cause `stop-not-shown`.
#[test]
fn a_step_of_the_wall_clock_moves_no_bound() {
    let mut case = Case::new("step-forward");
    case.faulted(
        Action::Hook(Box::new(|state| {
            state.step = 1000.0;
            Action::Answer
        })),
        false,
    );
    let code = case.run();
    assert_eq!(code, 0, "{}", case.output());
    let log = case.log();
    let shown = log
        .iter()
        .filter(|l| l.op == STATUS)
        .filter_map(|l| l.time)
        .fold(f64::MIN, f64::max);
    let observe = operator_seconds(&case, "observe_seconds");
    assert!(log.last().and_then(|l| l.time).expect("dated") >= shown + observe);

    let mut case = Case::new("step-back");
    case.faulted(
        Action::Hook(Box::new(|state| {
            state.step = -1000.0;
            Action::Answer
        })),
        true,
    );
    let code = case.run();
    assert_eq!(code, 1, "{}", case.output());
    let marks = case.marks();
    let names: Vec<&String> = marks.keys().collect();
    assert_eq!(names, ["abort", "roles", "stop"]);
    assert_eq!(text_of(&marks["abort"], "cause"), "stop-not-shown");
    assert!(
        time(&marks["abort"]) < time(&marks["stop"]),
        "the abort mark takes the stepped wall reading"
    );
    let sent = case.stops()[0].start;
    let log = case.log();
    let last = log[..log.len() - 1]
        .iter()
        .filter_map(|l| l.time)
        .fold(f64::MIN, f64::max);
    let effect = operator_seconds(&case, "effect_timeout_seconds");
    assert!(last <= sent + effect + 1.0, "{last} {sent}");
}

/// An abort mark whose directory sync fails after its link is removed, and the removal's own sync
/// fails: the abort mark counts as unwritten, so no stopped mark follows, and the run says the
/// removal is unsynced.
#[test]
fn an_abort_mark_removed_after_a_failed_sync_leaves_no_stopped_mark() {
    let mut case = Case::new("abort-unsynced");
    let (injection, mut failed) = (case.evidence.join("injection"), 0);
    case.plant(Box::new(move |state: &mut State, step| {
        let faulted = state.log.last().is_some_and(|l| l.fault);
        let syncs = matches!(step, Step::FsyncDirectory(path) if *path == injection);
        (faulted && syncs && failed < 2).then(|| {
            failed += 1;
            errno(libc::EIO)
        })
    }));
    case.faulted(flip("gd2-guardrail-1", "ALARM"), false);
    let code = case.run();
    let output = case.output();
    assert_eq!(code, 1, "{output}");
    let names: Vec<String> = case.marks().keys().cloned().collect();
    assert_eq!(names, ["roles", "stop"]);
    assert!(output.contains("the removal is unsynced"), "{output}");
}

/// A late start leaves the observation's end past the deadline, so a pause ends at the deadline and
/// the next call's own check aborts the run before it leaves. An alarm read asked for at the
/// deadline aborts with cause `deadline` and makes no call.
#[test]
fn a_deadline_reached_between_two_calls_aborts_before_the_next() {
    let mut case = Case::new("between-calls");
    operate(&mut case, "effect_timeout_seconds", 60);
    operate(&mut case, "observe_seconds", 200);
    operate(&mut case, "snapshot_max_age_seconds", LIMIT_SECONDS);
    {
        let mut plane = case.plane.borrow_mut();
        plane.script(CALLER, vec![Action::Delay(52.5)]);
        plane.script(STATUS, vec![Action::Delay(30.0)]);
        plane.stop_after = Some(3);
    }
    let found = case.assert_aborted("deadline", &ALL, None, Some("the deadline of"));
    let log = case.log();
    let deadline = case.plane.borrow().deadline.expect("the deadline is set");
    let latest = log[..log.len() - 1]
        .iter()
        .map(|l| l.start)
        .fold(f64::MIN, f64::max);
    assert!(latest < deadline, "{latest} {deadline}");
    let read = log.last().expect("the abort's status read").start;
    assert!(
        (read - deadline).abs() < 1e-6,
        "the last pause ends at the deadline: {read}"
    );
    assert!(
        detail(&found).contains("the stop request was sent and answered"),
        "{}",
        detail(&found)
    );

    let plane = Rc::clone(&case.plane);
    let calls = plane.borrow().log.len();
    let halted = case.controlled(|controller| {
        controller.set_deadline(plane.borrow().t + MONOTONIC);
        controller.alarms(None)
    });
    match halted {
        Err(Halt::Aborted(aborted)) => assert_eq!(aborted.cause(), "deadline"),
        other => panic!("{other:?} is no abort on the deadline"),
    }
    assert_eq!(
        case.plane.borrow().log.len(),
        calls,
        "no call leaves at the deadline"
    );
}

/// A stop call cut at the deadline keeps its failure: the run aborts with cause `deadline`, the
/// detail holds the cut call's text and says a stop request may have left with its outcome unknown.
#[test]
fn a_stop_call_cut_at_the_deadline_keeps_its_failure() {
    let mut case = Case::new("stop-cut");
    operate(&mut case, "effect_timeout_seconds", 60);
    operate(&mut case, "observe_seconds", 10);
    operate(&mut case, "deadline_seconds", 70);
    {
        let mut plane = case.plane.borrow_mut();
        plane.script(CALLER, vec![Action::Delay(45.0)]);
        plane.script(super::plane::STOP, vec![Action::Stall]);
    }
    let found = case.assert_aborted("deadline", &STOPPING, None, Some("timed out"));
    assert!(
        detail(&found).contains("a stop request may have left and its outcome is unknown"),
        "{}",
        detail(&found)
    );
    assert!(case.stops()[0].cut);
}
