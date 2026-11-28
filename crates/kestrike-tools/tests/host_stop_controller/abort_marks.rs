use std::cell::Cell;
use std::os::unix::ffi::OsStringExt;
use std::rc::Rc;

use kestrike_tools::json::{Text, Value};

use super::plane::{Action, STATUS};
use super::steps::{Step, errno, links, syncs};
use super::{COPY, Case, guardrails, member, set};

const ALL: [&str; 4] = ["roles", "stop", "stopped", "abort"];

fn guardrail_after_stop(case: &Case) {
    case.faulted(
        Action::Hook(Box::new(|state| {
            state.flip("gd2-guardrail-5", "ALARM");
            Action::Answer
        })),
        false,
    );
}

fn unsynced(case: &Case, name: &'static str) {
    let mut linked = false;
    case.plant(Box::new(move |_, step| {
        if links(step, name) {
            linked = true;
        } else if linked && syncs(step) {
            linked = false;
            return Some(errno(libc::EIO));
        }
        None
    }));
}

#[test]
fn an_abort_mark_that_stands_unsynced_is_followed_by_the_stopped_mark() {
    let mut case = Case::new("abort-stands");
    guardrail_after_stop(&case);
    unsynced(&case, "abort.json");
    case.fail_once(
        libc::EACCES,
        |step| matches!(step, Step::Unlink(name) if *name == "abort.json"),
    );
    let found = case.assert_aborted("guardrail", &ALL, Some(&guardrails()[4]), None);
    assert_eq!(member(&found["stopped"], "request"), &found["stop"]);
    let stderr = case.stderr();
    assert!(
        stderr.starts_with("host-stop-controller: abort.json stands with its durability unknown: "),
        "{stderr}"
    );
    assert_eq!(stderr.lines().count(), 1, "{stderr}");
}

#[test]
fn a_panic_at_the_abort_marks_link_leaves_it_unwritten_and_the_steps_printed() {
    let mut case = Case::new("abort-link-panic");
    guardrail_after_stop(&case);
    case.plant(Box::new(|_, step| {
        assert!(!links(step, "abort.json"), "a planted link fault");
        None
    }));
    let code = case.run();
    assert_eq!(code, 1, "{}", case.output());
    let names: Vec<String> = case.marks().into_keys().collect();
    assert_eq!(names, ["roles", "stop"]);
    let stderr = case.stderr();
    assert!(
        stderr.starts_with(
            "host-stop-controller: abort.json is unwritten: panic: a planted link fault"
        ),
        "{stderr}"
    );
    let stdout = case.stdout();
    let last: Vec<&str> = stdout.lines().rev().take(2).collect();
    assert!(
        last[1].starts_with("host-stop-controller: the target reads {"),
        "{stdout}"
    );
    assert!(
        last[0].starts_with("GD-2's restoration steps: "),
        "{stdout}"
    );
    assert_eq!(case.after_fault(), [STATUS]);
}

#[test]
fn a_panic_in_the_abort_status_read_or_its_line_says_the_state_is_unknown() {
    let mut case = Case::new("status-panic");
    case.faulted(
        Action::Hook(Box::new(|state| {
            state.flip("gd2-guardrail-5", "ALARM");
            let panicking = Action::Hook(Box::new(|_| panic!("a planted status fault")));
            state.script(STATUS, vec![panicking]);
            Action::Answer
        })),
        false,
    );
    case.assert_aborted("guardrail", &ALL, Some(&guardrails()[4]), None);
    let line =
        "host-stop-controller: the target's state is unknown: panic: a planted status fault\n";
    assert!(case.stdout().contains(line), "{}", case.stdout());

    let mut case = Case::new("status-line-panic");
    guardrail_after_stop(&case);
    let panicked = Rc::new(Cell::new(false));
    let once = Rc::clone(&panicked);
    case.writes = Some(Rc::new(move |bytes: &[u8]| {
        let shown = bytes.starts_with(b"host-stop-controller: the target reads {");
        assert!(!shown || once.replace(true), "a planted stream fault");
        None
    }));
    case.assert_aborted("guardrail", &ALL, Some(&guardrails()[4]), None);
    assert!(panicked.get());
    let line =
        "host-stop-controller: the target's state is unknown: panic: a planted stream fault\n";
    assert!(case.stdout().contains(line), "{}", case.stdout());
    assert_eq!(case.after_fault(), [STATUS]);
}

#[test]
fn a_final_stopped_mark_removed_under_a_path_with_no_utf8_form_leaves_no_abort_mark() {
    let mut case = Case::new("bytes-path");
    let mut name = case.scratch.0.clone().into_os_string().into_vec();
    name.extend_from_slice(b"/ev\xff");
    let evidence = std::path::PathBuf::from(std::ffi::OsString::from_vec(name));
    std::fs::create_dir(&evidence).expect("the evidence directory is made");
    std::fs::copy(case.evidence.join(COPY), evidence.join(COPY)).expect("the copy is made");
    case.evidence.clone_from(&evidence);
    case.plane.borrow_mut().evidence = evidence;
    unsynced(&case, "stopped.json");
    let code = case.run();
    assert_eq!(code, 1, "{}", case.output());
    let names: Vec<String> = case.marks().into_keys().collect();
    assert_eq!(names, ["roles", "stop"]);
    let stderr = case.stderr();
    assert!(
        stderr.starts_with("host-stop-controller: abort.json is unwritten: Refusal: "),
        "{stderr}"
    );
    assert_eq!(stderr.lines().count(), 1, "{stderr}");
    assert!(
        case.stdout()
            .contains("ev\\udcff/injection/stopped.json cannot be synced")
    );
}

#[test]
fn a_stop_mark_past_the_mark_size_limit_is_refused_before_any_stop_request() {
    let mut case = Case::new("stop-too-large");
    let identity = format!(
        "arn:aws:sts::000000000000:assumed-role/{}",
        "r".repeat(6000)
    );
    set(
        &mut case.operator,
        &["identity"],
        Value::String(Text::from(identity.as_str())),
    );
    case.plane.borrow_mut().arn = identity;
    case.mark_limit = 5000;
    case.assert_aborted(
        "exception",
        &["roles", "abort"],
        None,
        Some("no stop request was sent; Refusal: injection/stop.json would hold "),
    );
    assert!(case.stops().is_empty(), "{:?}", case.ops());
}

#[test]
fn a_stopped_mark_that_fails_in_the_abort_path_is_named_unwritten() {
    let mut case = Case::new("abort-path-stopped");
    guardrail_after_stop(&case);
    case.fail_once(libc::ENOSPC, |step| links(step, "stopped.json"));
    case.assert_aborted(
        "guardrail",
        &["roles", "stop", "abort"],
        Some(&guardrails()[4]),
        None,
    );
    let stderr = case.stderr();
    assert!(
        stderr.starts_with("host-stop-controller: stopped.json is unwritten: OSError: [Errno 28]"),
        "{stderr}"
    );
    assert_eq!(stderr.lines().count(), 1, "{stderr}");
    assert_eq!(case.after_fault(), [STATUS]);
}
