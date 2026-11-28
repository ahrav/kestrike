//! Signals delivered into the record at the step a case names: before `injection/` the run ends
//! with exit 2; from the making of `injection/` to the roles mark's end the signal waits; later it
//! takes the abort path; during the abort path it is left unraised.

use kestrike_tools::host_stop::Signal;

use super::plane::{Action, CALLER};
use super::steps::{Step, links};
use super::{COPY, Case, guardrails, listing};

/// A SIGHUP delivered while `injection/` is made waits for the roles mark, then aborts the run with
/// cause `signal` before any stop request.
#[test]
fn a_signal_while_injection_is_made_aborts_after_the_roles_mark() {
    let mut case = Case::new("signal-mkdir");
    case.signal_at(
        Signal::Hangup,
        |step| matches!(step, Step::Mkdir(path) if path.ends_with("injection")),
    );
    case.assert_aborted("signal", &["roles", "abort"], None, Some("signal SIGHUP"));
    assert!(case.stops().is_empty());
}

/// A SIGTERM delivered during the stop mark's write raises at the write's end, before the stop
/// request: the stop mark stands whole beside the roles and abort marks.
#[test]
fn a_signal_during_a_mark_waits_for_its_write() {
    let mut case = Case::new("signal-mark");
    case.signal_at(Signal::Terminate, |step| links(step, "stop.json"));
    let found = case.assert_aborted("signal", &["roles", "stop", "abort"], None, None);
    assert!(
        case.stops().is_empty(),
        "the signal raised before the stop request"
    );
    let names: Vec<String> = found.keys().map(|mark| format!("{mark}.json")).collect();
    assert_eq!(listing(&case.evidence.join("injection")), names);
}

/// A SIGTERM delivered during a stop mark's write that fails leaves the failure the cause: the run
/// aborts with cause `exception` and the system's text.
#[test]
fn a_signal_with_a_failed_write_still_ends_in_the_abort_path() {
    let mut case = Case::new("signal-failed-mark");
    case.signal_at(Signal::Terminate, |step| links(step, "stop.json"));
    case.fail_once(libc::ENOSPC, |step| links(step, "stop.json"));
    case.assert_aborted(
        "exception",
        &["roles", "abort"],
        None,
        Some("No space left on device"),
    );
}

/// A SIGTERM delivered during the abort path, at the abort mark's write, is left unraised: the
/// abort ends on its guardrail.
#[test]
fn a_signal_during_the_abort_path_is_ignored() {
    let mut case = Case::new("signal-abort");
    case.signal_at(Signal::Terminate, |step| links(step, "abort.json"));
    case.plane.borrow_mut().flip("gd2-guardrail-4", "ALARM");
    case.assert_aborted(
        "guardrail",
        &["roles", "abort"],
        Some(&guardrails()[3]),
        None,
    );
    let output = case.output();
    assert!(!output.contains("Interrupted"), "{output}");
    assert!(!output.contains("durability unknown"), "{output}");
}

/// A SIGTERM delivered during the evidence directory's sync waits for the roles mark, then aborts
/// the run with cause `signal` before any stop request.
#[test]
fn a_signal_during_the_evidence_directory_sync_aborts_after_the_roles_mark() {
    let mut case = Case::new("signal-sync");
    let evidence = case.evidence.clone();
    case.signal_at(
        Signal::Terminate,
        move |step| matches!(step, Step::FsyncDirectory(path) if *path == evidence),
    );
    case.assert_aborted("signal", &["roles", "abort"], None, None);
    assert!(case.stops().is_empty());
}

/// A SIGINT delivered during the caller's call raises when the call returns: the run ends with
/// exit 2 and nothing written.
#[test]
fn a_signal_before_injection_ends_the_run_with_nothing_written() {
    let mut case = Case::new("signal-caller");
    let delivered = case.delivered;
    case.plane.borrow_mut().script(
        CALLER,
        vec![Action::Hook(Box::new(move |_| {
            delivered.deliver(Signal::Interrupt);
            Action::Answer
        }))],
    );
    let code = case.run();
    let output = case.output();
    assert_eq!(code, 2, "{output}");
    assert_eq!(
        output,
        "host-stop-controller: signal SIGINT before any mark; nothing written\n"
    );
    assert_eq!(case.ops(), [CALLER]);
    assert_eq!(listing(&case.evidence), [COPY]);
}
