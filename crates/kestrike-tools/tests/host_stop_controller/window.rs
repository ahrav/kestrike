//! The window from the making of `injection/` to the roles mark: a failure there removes
//! `injection/` again and is a refusal, and a roles mark that stands takes the abort path.

use kestrike_tools::host_stop::Signal;

use super::plane::{CALLER, STATUS};
use super::steps::{Step, free_lock, links, syncs};
use super::{COPY, Case, listing};

const ENOSPC: i32 = libc::ENOSPC;

/// A `mkdir` of `injection/` that fails with ENOSPC is a refusal that names the system's text, after
/// the caller and the status read, with nothing written.
#[test]
fn an_injection_directory_that_cannot_be_made_is_a_refusal() {
    let mut case = Case::new("unmade");
    case.fail_once(
        ENOSPC,
        |step| matches!(step, Step::Mkdir(path) if path.ends_with("injection")),
    );
    case.assert_refused(
        &[CALLER, STATUS],
        "injection cannot be made: No space left on device",
    );
}

/// A signal delivered while `injection/` is held, here in the failing sync of the evidence
/// directory, raises nothing: the refusal is the failure's. A signal delivered at the first step
/// after a failed roles write has ended its hold, the removal of `injection/`, raises nothing either,
/// since the record is read at the points a run names and none stands between the hold's end and the
/// removal: the refusal is the failure's, with the same exit code and evidence directory.
#[test]
fn a_signal_beside_a_failure_before_the_roles_mark_stands_is_the_same_refusal() {
    let mut case = Case::new("signal-sync");
    let evidence = case.evidence.clone();
    let at_sync =
        move |step: &Step<'_>| matches!(step, Step::FsyncDirectory(path) if *path == evidence);
    case.signal_at(Signal::Terminate, at_sync.clone());
    case.fail_once(libc::EIO, at_sync);
    case.assert_refused(
        &[CALLER, STATUS],
        "Input/output error before roles.json stood",
    );
    assert!(
        case.output().contains("is removed; nothing written"),
        "{}",
        case.output()
    );

    let mut case = Case::new("signal-after-hold");
    case.fail_once(ENOSPC, |step| links(step, "roles.json"));
    case.signal_at(Signal::Terminate, |step| matches!(step, Step::Rmdir));
    case.assert_refused(
        &[CALLER, STATUS],
        "refused: OSError: [Errno 28] No space left on device before roles.json stood",
    );
}

/// A failed roles write whose `injection/` then cannot be removed, or whose removal cannot be
/// synced, is a refusal that names `injection/` as possibly standing and says nothing of what was
/// written; `injection/` stays in the first case and is gone in the second.
#[test]
fn an_injection_directory_that_cannot_be_removed_or_whose_removal_is_unsynced_is_named() {
    for removal in ["fails", "is unsynced"] {
        let mut case = Case::new("unremoved");
        case.fail_once(ENOSPC, |step| links(step, "roles.json"));
        let left: &[&str] = if removal == "fails" {
            case.fail_once(libc::EACCES, |step| matches!(step, Step::Rmdir));
            &["injection", COPY]
        } else {
            let evidence = case.evidence.clone();
            case.plant(Box::new(move |_, step| {
                let gone = !evidence.join("injection").exists();
                (gone && matches!(step, Step::FsyncDirectory(path) if *path == evidence))
                    .then(|| super::steps::errno(libc::EIO))
            }));
            &[COPY]
        };
        let code = case.run();
        let output = case.output();
        assert_eq!(code, 2, "{output}");
        assert!(
            output.contains(
                "refused: OSError: [Errno 28] No space left on device before roles.json stood"
            ),
            "{output}"
        );
        let named = format!("{} may stand", case.evidence.join("injection").display());
        assert!(output.contains(&named), "{output}");
        assert!(!output.contains("nothing written"), "{output}");
        assert_eq!(case.ops(), [CALLER, STATUS], "{output}");
        assert_eq!(listing(&case.evidence), left, "{removal}");
    }
}

/// A roles mark whose sync after its link fails and whose removal fails stands with its durability
/// unknown, so it counts as written and the run takes the abort path with cause `exception`, before
/// any stop request.
#[test]
fn a_roles_mark_that_stands_with_its_durability_unknown_takes_the_abort_path() {
    let mut case = Case::new("stands");
    let mut count = 0;
    case.plant(Box::new(move |_, step| {
        if syncs(step) {
            count += 1;
            if count == 3 {
                return Some(super::steps::errno(libc::EIO));
            }
        }
        None
    }));
    case.fail_once(
        libc::EACCES,
        |step| matches!(step, Step::Unlink(name) if *name == "roles.json"),
    );
    let found = case.assert_aborted(
        "exception",
        &["roles", "abort"],
        None,
        Some("roles.json stands, but it cannot be synced"),
    );
    assert!(case.stops().is_empty());
    let detail = super::text_of(&found["abort"], "detail");
    assert!(detail.contains("no stop request was sent"), "{detail}");
}

/// A panic after the caller's check, before any mark, exits 2 with one line that names the panic
/// and says nothing was written; the run made the caller's call alone.
#[test]
fn a_failure_the_controller_did_not_foresee_exits_2_and_names_what_stands() {
    let mut case = Case::new("unforeseen");
    case.plane.borrow_mut().reading = Some(std::rc::Rc::new(|state| {
        if state.log.len() == 1 && state.log[0].time.is_some() {
            panic!("a planted fault in the snapshot's read");
        }
    }));
    let code = case.run();
    let output = case.output();
    assert_eq!(code, 2, "{output}");
    assert!(
        output.contains("panic: a planted fault in the snapshot's read; nothing written"),
        "{output}"
    );
    assert_eq!(case.ops(), [CALLER]);
    assert_eq!(listing(&case.evidence), [COPY]);
}

/// A panic in an alarm read once `roles.json` stands takes the abort path with cause `exception`
/// and the panic's message in the detail; no stop request was sent.
#[test]
fn a_panic_after_the_roles_mark_is_written_takes_the_abort_path_with_cause_exception() {
    let mut case = Case::new("panic");
    case.plane.borrow_mut().script(
        super::plane::ALARMS,
        vec![super::plane::Action::Hook(Box::new(|_| {
            panic!("a planted panic in the alarm read")
        }))],
    );
    case.assert_aborted(
        "exception",
        &["roles", "abort"],
        None,
        Some("no stop request was sent; panic: a planted panic in the alarm read"),
    );
    assert!(case.stops().is_empty());
}

/// A panic in the abort path itself, at its wall reading for the abort mark, exits 2 with a line
/// that names the marks that stand, and frees the lock of `injection/`.
#[test]
fn a_failure_inside_the_abort_path_exits_2_and_names_the_marks_that_stand() {
    let mut case = Case::new("abort-failure");
    case.plane.borrow_mut().flip("gd2-guardrail-4", "ALARM");
    case.plane.borrow_mut().reading = Some(std::rc::Rc::new(|state| {
        if state.log.len() == 3 {
            panic!("a planted fault in the abort path");
        }
    }));
    let code = case.run();
    let output = case.output();
    assert_eq!(code, 2, "{output}");
    assert!(
        output.ends_with(
            "host-stop-controller: panic: a planted fault in the abort path; marks written: \
             ['roles']\n"
        ),
        "{output}"
    );
    assert_eq!(case.marks().keys().collect::<Vec<_>>(), ["roles"]);
    drop(free_lock(&case.evidence.join("injection")));
}
