use kestrike_tools::json::{Text, Value};

use super::plane::{Action, CALLER, STATUS};
use super::steps::{Step, links, syncs};
use super::{COPY, Case, listing};

/// A sync panic after the link unwinds before the run counts `roles.json` as written. The run exits
/// 2 and leaves `injection/roles.json` on disk.
#[test]
fn a_panic_after_the_roles_marks_link_leaves_it_uncounted() {
    let mut case = Case::new("roles-panic-after-link");
    let mut linked = false;
    case.plant(Box::new(move |_, step| {
        if links(step, "roles.json") {
            linked = true;
        } else if linked && syncs(step) {
            panic!("a planted sync fault");
        }
        None
    }));
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

/// A lone surrogate in the alarm reply's `StateValue` triggers a refusal to write `abort.json`; the
/// run exits 1 with `roles.json` and `stop.json` alone.
#[test]
fn a_lone_surrogate_in_an_alarm_reply_leaves_the_abort_mark_unwritten() {
    let mut case = Case::new("surrogate-reply");
    let surrogate = Text::from_code_points([0xd800]).expect("a text holds a lone surrogate");
    case.faulted(
        Action::Hook(Box::new(move |state| {
            state.row(
                "gd2-guardrail-5",
                "StateValue",
                Some(Value::String(surrogate)),
            );
            Action::Answer
        })),
        false,
    );
    let code = case.run();
    assert_eq!(code, 1, "{}", case.output());
    let names: Vec<String> = case.marks().into_keys().collect();
    assert_eq!(names, ["roles", "stop"]);
    let stderr = case.stderr();
    assert!(
        stderr.starts_with("host-stop-controller: abort.json is unwritten: Refusal: "),
        "{stderr}"
    );
}

/// A lookup of `injection/` that fails with EACCES reads as no entry: the run exits 0 with the
/// `roles`, `stop` and `stopped` marks.
#[test]
fn a_failed_lookup_of_injection_reads_as_no_entry() {
    let mut case = Case::new("injection-lookup");
    let injection = case.evidence.join("injection");
    case.fail_once(
        libc::EACCES,
        move |step| matches!(step, Step::Lstat(path) if *path == injection),
    );
    let code = case.run();
    assert_eq!(code, 0, "{}", case.output());
    let names: Vec<String> = case.marks().into_keys().collect();
    assert_eq!(names, ["roles", "stop", "stopped"]);
}
