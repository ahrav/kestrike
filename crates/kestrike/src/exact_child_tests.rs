//! The exact-child supervisor credits only a child's completed one-test run
//! and reaps every child it starts, whichever way the child ends.

use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::bind::DeviceLock;
use crate::exact_child::{self, ExactChild, Outcome, credited, entered};

const CONTROL: &str = "exact_child_tests::a_control_child";
const SCENARIO: &str = "KESTRIKE_EXACT_CHILD_SCENARIO";
const LOCKS: &str = "KESTRIKE_EXACT_CHILD_LOCKS";
const DEADLINE: Duration = Duration::from_secs(60);
/// `STRAY` bounds a stalled control child's lifetime if its parent is killed.
const STRAY: Duration = Duration::from_secs(600);

/// An ordinary run passes `a_control_child` immediately; its scenarios run
/// only under the supervisor.
#[test]
fn a_control_child() {
    if !exact_child::is_child(CONTROL) {
        return;
    }
    exact_child::report(&entered(CONTROL));
    match std::env::var(SCENARIO).as_deref() {
        Ok("pass") => exact_child::report("passing"),
        Ok("diagnostic") => eprintln!("passing child diagnostic"),
        Ok("exit") => std::process::exit(3),
        Ok("panic") => panic!("the control child's test fails"),
        Ok("crash") => std::process::abort(),
        Ok("stall") => {
            println!("stall marker on stdout");
            eprintln!("stall marker on stderr");
            exact_child::report("stalling");
            let start = Instant::now();
            while start.elapsed() < STRAY {
                std::thread::park_timeout(STRAY);
            }
            std::process::exit(4);
        }
        Ok("locks") => {
            let dir = std::env::var(LOCKS).unwrap();
            let lock = fs::canonicalize(format!("{dir}/0000:00:1f.0.lock")).unwrap();
            let held = fs::read_dir("/proc/self/fd")
                .unwrap()
                .filter_map(|entry| fs::read_link(entry.ok()?.path()).ok())
                .filter(|target| *target == lock)
                .count();
            let refused = DeviceLock::acquire(dir.as_ref(), "0000:00:1f.0")
                .is_err_and(|error| error.kind() == std::io::ErrorKind::WouldBlock);
            exact_child::report(&format!("lock descriptors {held} refused {refused}"));
        }
        other => panic!("unknown scenario {other:?}"),
    }
}

fn control(scenario: &str) -> ExactChild {
    ExactChild::spawn(CONTROL, &[(SCENARIO, scenario)]).unwrap()
}

/// A process keeps its `/proc` entry, as a zombie, until its parent collects
/// its exit status.
fn reaped(pid: u32) -> bool {
    !Path::new(&format!("/proc/{pid}")).exists()
}

#[test]
fn a_passing_child_completes_is_credited_and_is_reaped() {
    let child = control("pass");
    let pid = child.id();
    let outcome = child.finish(Instant::now() + DEADLINE);
    let Outcome::Completed { reports } = &outcome else {
        panic!("{outcome:?}");
    };
    assert_eq!(*reports, [entered(CONTROL), "passing".into()]);
    assert!(credited(CONTROL, &outcome));
    assert!(
        !credited("exact_child_tests::another_case", &outcome),
        "a completed child that entered another case's body credits only that case"
    );
    assert!(reaped(pid));
}

#[test]
fn a_passing_child_preserves_its_stderr_for_the_sanitizer_judge() {
    let child = control("diagnostic");
    let pid = child.id();
    let (outcome, stderr) = child.finish_observed(Instant::now() + DEADLINE);
    assert!(credited(CONTROL, &outcome));
    assert_eq!(stderr, ["passing child diagnostic"]);
    assert!(reaped(pid));
}

#[test]
fn a_selector_matching_no_test_fails_though_the_child_exits_zero() {
    let id = "exact_child_tests::no_such_test";
    let child = ExactChild::spawn(id, &[]).unwrap();
    let pid = child.id();
    let outcome = child.finish(Instant::now() + DEADLINE);
    let Outcome::Failed { status, stdout, .. } = &outcome else {
        panic!("{outcome:?}");
    };
    assert!(status.success(), "{outcome:?}");
    assert!(
        stdout.iter().any(|line| line == "running 0 tests"),
        "{outcome:?}"
    );
    assert!(!credited(id, &outcome));
    assert!(reaped(pid));
}

#[test]
fn a_test_that_declares_another_id_panics_before_it_spawns() {
    let declared = std::panic::catch_unwind(|| {
        exact_child::run(CONTROL, DEADLINE, || {});
    })
    .unwrap_err();
    let message = declared
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| declared.downcast_ref::<&str>().copied())
        .unwrap_or_default();
    assert!(message.contains("declares another ID"), "{message}");
}

#[test]
fn a_child_that_exits_nonzero_or_fails_its_test_fails() {
    for (scenario, code) in [("exit", 3), ("panic", 101)] {
        let child = control(scenario);
        let pid = child.id();
        let outcome = child.finish(Instant::now() + DEADLINE);
        let Outcome::Failed { status, .. } = &outcome else {
            panic!("{scenario}: {outcome:?}");
        };
        assert_eq!(status.code(), Some(code), "{scenario}: {outcome:?}");
        assert!(!credited(CONTROL, &outcome), "{scenario}");
        assert!(reaped(pid), "{scenario}");
    }
}

#[test]
fn a_crashing_child_reports_its_signal() {
    let child = control("crash");
    let pid = child.id();
    let outcome = child.finish(Instant::now() + DEADLINE);
    let Outcome::Crashed { signal, .. } = &outcome else {
        panic!("{outcome:?}");
    };
    assert_eq!(*signal, libc::SIGABRT);
    assert!(!credited(CONTROL, &outcome));
    assert!(reaped(pid));
}

#[test]
fn a_stalled_child_is_witnessed_then_killed_and_reaped_at_its_deadline() {
    let mut child = control("stall");
    let pid = child.id();
    let until = Instant::now() + DEADLINE;
    assert_eq!(child.next_report(until), Some(entered(CONTROL)));
    assert_eq!(child.next_report(until).as_deref(), Some("stalling"));
    assert!(!reaped(pid), "the stalled child is still running");
    let outcome = child.finish(Instant::now() + Duration::from_millis(200));
    let Outcome::Stalled { reports, .. } = &outcome else {
        panic!("{outcome:?}");
    };
    assert_eq!(*reports, [entered(CONTROL), "stalling".into()]);
    let transcript = format!("{outcome:?}");
    assert!(
        transcript.contains("stall marker on stdout"),
        "{transcript}"
    );
    assert!(
        transcript.contains("stall marker on stderr"),
        "{transcript}"
    );
    assert!(!credited(CONTROL, &outcome));
    assert!(reaped(pid));
}

#[test]
fn a_killed_child_is_reaped_and_keeps_its_transcript() {
    let mut child = control("stall");
    let pid = child.id();
    let until = Instant::now() + DEADLINE;
    assert_eq!(child.next_report(until), Some(entered(CONTROL)));
    assert_eq!(child.next_report(until).as_deref(), Some("stalling"));
    let outcome = child.kill();
    assert!(reaped(pid));
    let Outcome::Crashed {
        signal,
        stdout,
        stderr,
    } = &outcome
    else {
        panic!("{outcome:?}");
    };
    assert_eq!(*signal, libc::SIGKILL);
    assert!(
        stdout.iter().any(|line| line.contains("stalling")),
        "{outcome:?}"
    );
    assert!(
        stdout
            .iter()
            .any(|line| line.contains("stall marker on stdout")),
        "{outcome:?}"
    );
    assert!(
        stderr
            .iter()
            .any(|line| line.contains("stall marker on stderr")),
        "{outcome:?}"
    );
}

#[test]
fn a_dropped_supervisor_kills_and_reaps_its_running_child() {
    let mut child = control("stall");
    let pid = child.id();
    let until = Instant::now() + DEADLINE;
    assert_eq!(child.next_report(until), Some(entered(CONTROL)));
    assert_eq!(child.next_report(until).as_deref(), Some("stalling"));
    assert!(!reaped(pid), "the stalled child is still running");
    drop(child);
    assert!(reaped(pid));
}

#[test]
fn a_child_holds_no_descriptor_of_a_lock_its_parent_holds() {
    let dir = std::env::temp_dir().join(format!("exact-child-locks-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let lock = DeviceLock::acquire(&dir, "0000:00:1f.0").unwrap();
    let outcome = ExactChild::spawn(
        CONTROL,
        &[(SCENARIO, "locks"), (LOCKS, dir.to_str().unwrap())],
    )
    .unwrap()
    .finish(Instant::now() + DEADLINE);
    drop(lock);
    fs::remove_dir_all(&dir).unwrap();
    let Outcome::Completed { reports } = &outcome else {
        panic!("{outcome:?}");
    };
    assert_eq!(
        reports.last().map(String::as_str),
        Some("lock descriptors 0 refused true"),
        "the parent's lock stays held by the parent alone"
    );
}
