use std::cell::Cell;
use std::rc::Rc;

use super::plane::{ALARMS, Action, CALLER, STATUS, State};
use super::steps::{Step, links, syncs};
use super::{COPY, Case, listing, text_of};

fn panic_in_the_sync_after(case: &Case, name: &'static str) {
    let mut linked = false;
    case.plant(Box::new(move |_, step| {
        if links(step, name) {
            linked = true;
        } else if linked && syncs(step) {
            panic!("a planted sync fault");
        }
        None
    }));
}

/// A sync panic after the link unwinds before the run counts `roles.json` as written. The run exits
/// 2 with `roles.json` as the only mark in `injection/`.
#[test]
fn a_panic_after_the_roles_marks_link_leaves_it_uncounted() {
    let mut case = Case::new("roles-panic-after-link");
    panic_in_the_sync_after(&case, "roles.json");
    let code = case.run();
    assert_eq!(code, 2, "{}", case.output());
    let stderr = case.stderr();
    assert!(
        stderr.contains("panic: a planted sync fault before roles.json stood"),
        "{stderr}"
    );
    assert!(stderr.contains("may stand"), "{stderr}");
    assert_eq!(case.ops(), [CALLER, STATUS]);
    assert_eq!(
        listing(&case.evidence),
        ["injection", "injection/roles.json", COPY]
    );
}

/// A sync panic after the link of `abort.json` unwinds before the abort path counts it as written:
/// `abort.json` stands beside `roles.json` and `stop.json`, standard error names `abort.json` as
/// unwritten and the run exits 1.
#[test]
fn a_panic_after_the_abort_marks_link_leaves_it_uncounted() {
    let mut case = Case::new("abort-panic-after-link");
    case.faulted(
        Action::Hook(Box::new(|state| {
            state.flip("gd2-guardrail-5", "ALARM");
            Action::Answer
        })),
        false,
    );
    panic_in_the_sync_after(&case, "abort.json");
    let code = case.run();
    assert_eq!(code, 1, "{}", case.output());
    let names: Vec<String> = case.marks().into_keys().collect();
    assert_eq!(names, ["abort", "roles", "stop"]);
    assert!(
        case.stderr().starts_with(
            "host-stop-controller: abort.json is unwritten: panic: a planted sync fault"
        ),
        "{}",
        case.stderr()
    );
}

/// The controller treats `EACCES` from the `injection/` lookup as a missing entry. `mkdir` then
/// fails because `injection/` already exists.
#[test]
fn a_failed_lookup_of_injection_reads_as_no_entry() {
    let mut case = Case::new("injection-lookup");
    let injection = case.evidence.join("injection");
    std::fs::create_dir(&injection).expect("injection/ is made");
    let at = injection.clone();
    case.fail_once(
        libc::EACCES,
        move |step| matches!(step, Step::Lstat(path) if *path == at),
    );
    let code = case.run();
    assert_eq!(code, 2, "{}", case.output());
    assert_eq!(case.ops(), [CALLER, STATUS]);
    let stderr = case.stderr();
    assert!(
        stderr.starts_with("host-stop-controller: refused: ")
            && stderr.contains("injection cannot be made: File exists; nothing written"),
        "{stderr}"
    );
    assert_eq!(listing(&case.evidence), ["injection", COPY]);
}

/// A stall of 3 s between the request's monotonic reading and its wall reading moves the window
/// that shows the stop 3 s later: a user's shutdown dated 4 s before the stop call's second shows
/// the stop without the stall, and with it the run aborts with cause `stop-not-shown`.
#[test]
fn a_stall_before_the_requests_wall_reading_moves_the_window_later() {
    for stall in [0.0, 3.0] {
        let mut case = Case::new("window-stall");
        case.plane.borrow_mut().transition_offset = -4;
        let readings = Cell::new(0);
        case.plane.borrow_mut().ticking = Some(Rc::new(move |state: &mut State| {
            let quiet = state.log.last().is_some_and(|l| {
                l.op == ALARMS && l.time.is_some() && !l.marks.iter().any(|m| m == "stop")
            });
            if quiet && state.stops().is_empty() {
                readings.set(readings.get() + 1);
                if readings.get() == 3 {
                    state.t += stall;
                }
            }
        }));
        if stall == 0.0 {
            let code = case.run();
            assert_eq!(code, 0, "{}", case.output());
            continue;
        }
        let found = case.assert_aborted(
            "stop-not-shown",
            &["roles", "stop", "abort"],
            None,
            Some("does not show the request"),
        );
        assert_eq!(text_of(&found["abort"], "cause"), "stop-not-shown");
    }
}
