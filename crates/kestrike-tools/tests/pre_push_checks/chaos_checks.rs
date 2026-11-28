//! The hook's cases of the chaos checks and the two self-tests, started through the tool: which tip runs
//! the contract check, the receipt replay, the judges' test and the game-day and host stop self-tests, that
//! each failure fails the push, and that the five checks that start as `python3 -I` pass `-I`, which the
//! stand-in records apart.

use std::fs;

use super::push::{Fixture, STUB, ZERO};

pub const CONTRACT_CHECK: &str = "validate_contract.py chaos/ledger.json --root . --project chaos/project.yaml --receipts chaos/receipts --check-claim chaos/READINESS.md";
const CONTROLS: &str = "crates/campaign-supervisor/src/campaign/calibration/controls.rs";

/// `contract` commits a chaos contract with the validator and the judges' test as stubs and returns the
/// commit.
pub fn contract(fx: &Fixture) -> String {
    fx.commit(&[
        ("chaos/ledger.json", "{}\n"),
        ("chaos/READINESS.md", "r\n"),
        ("chaos/tools/validate_contract.py", STUB),
        ("chaos/tests/test_judges.py", STUB),
        ("chaos/harness/run_scenario.py", "h\n"),
        ("chaos/judges/core/common.py", "j\n"),
        ("chaos/receipts/run/row.json", "{}\n"),
        ("chaos/runs/run/run.json", "{}\n"),
        ("chaos/project.yaml", "p\n"),
        ("chaos/approval-policy.md", "a\n"),
        ("chaos/survey.md", "s\n"),
    ])
}

/// A change to the claim runs the contract check, started as `python3 -I`.
#[test]
fn a_chaos_change_runs_the_contract_check() {
    let fx = Fixture::new();
    let base = contract(&fx);
    let head = fx.commit(&[("chaos/READINESS.md", "r\n\n")]);
    let run = fx.push(&[(&head, &base)]);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert_eq!(fx.ran(), [CONTRACT_CHECK]);
    assert_eq!(fx.isolated(), [CONTRACT_CHECK]);
}

/// A change to the calibration controls runs the judges' test at a tip that holds it and nothing at a tip
/// that lacks it.
#[test]
fn a_change_to_the_calibration_controls_runs_the_judges_test_of_a_tip_that_holds_it() {
    let fx = Fixture::new();
    let base = contract(&fx);
    let held = fx.commit(&[(CONTROLS, "depth, n and k\n")]);
    fx.git(&["checkout", "-q", "--detach", &base]);
    fx.git(&["rm", "-q", "--", "chaos/tests/test_judges.py"]);
    fx.git(&["commit", "-q", "-m", "remove"]);
    let start = fx.git(&["rev-parse", "HEAD"]);
    let lacking = fx.commit(&[(CONTROLS, "depth, n and k\n")]);
    let run = fx.push(&[(&held, &base), (&lacking, &start)]);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert_eq!(fx.ran(), ["test_judges.py"]);
}

/// A chaos change at a tip that holds the replay runs it after the contract check, as `python3 -I`, and its
/// failure fails the push; a push that removes the replay runs it and fails on the missing file.
#[test]
fn a_chaos_change_at_a_tip_that_holds_the_receipt_replay_runs_it_and_its_failure_blocks() {
    let fx = Fixture::new();
    let base = fx.commit(&[
        ("chaos/ledger.json", "r\n"),
        ("chaos/READINESS.md", "r\n"),
        ("chaos/tools/validate_contract.py", STUB),
        ("scripts/chaos-receipt-replay.py", STUB),
    ]);
    let head = fx.commit(&[("chaos/READINESS.md", "r\n\n")]);
    let run = fx.push_with(&[(&head, &base)], &[("chaos_receipt_replay", 1)]);
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    assert_eq!(fx.ran(), [CONTRACT_CHECK, "chaos-receipt-replay.py"]);
    assert_eq!(fx.isolated(), fx.ran());
    fx.git(&["rm", "-q", "--", "scripts/chaos-receipt-replay.py"]);
    fx.git(&["commit", "-q", "-m", "remove"]);
    let removed = fx.git(&["rev-parse", "HEAD"]);
    let run = fx.push(&[(&removed, &head)]);
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    assert!(
        run.stderr
            .contains("failed: python3 -I scripts/chaos-receipt-replay.py"),
        "{}",
        run.stderr
    );
}

/// A change to a file the game-day judge reads runs nothing at a tip without its self-test; at a tip that
/// holds it, with a base or with none, it runs the self-test as `python3 -I` and its failure fails the push;
/// a push that removes the self-test runs it and fails on the missing file.
#[test]
fn a_game_day_input_push_runs_the_isolated_self_test_and_its_failure_blocks() {
    let fx = Fixture::new();
    let gameday = "test-gameday-judge.py";
    let head = fx.commit(&[("verification/readiness/gamedays.json", "{}\n")]);
    assert_eq!(fx.push(&[(&head, &fx.base)]).code, Some(0));
    assert!(
        !fx.ran().iter().any(|line| line == gameday),
        "{:?}",
        fx.ran()
    );
    let held = fx.commit(&[("scripts/test-gameday-judge.py", STUB)]);
    let tip = fx.commit(&[("verification/readiness/gamedays.json", "{}\n\n")]);
    for remote in [held.as_str(), ZERO] {
        fx.clear();
        if remote == ZERO {
            fx.git(&["update-ref", "-d", "refs/remotes/origin/main"]);
        }
        let run = fx.push_with(&[(&tip, remote)], &[("test_gameday_judge", 1)]);
        assert_eq!(run.code, Some(1), "{}", run.stderr);
        assert!(
            fx.ran().iter().any(|line| line == gameday),
            "{:?}",
            fx.ran()
        );
        assert!(
            fx.isolated().iter().any(|line| line == gameday),
            "{:?}",
            fx.isolated()
        );
        assert!(
            run.stderr
                .contains("failed: python3 -I scripts/test-gameday-judge.py"),
            "{}",
            run.stderr
        );
        assert_eq!(
            run.stderr.contains("no comparison base"),
            remote == ZERO,
            "{}",
            run.stderr
        );
    }
    fx.git(&["rm", "-q", "--", "scripts/test-gameday-judge.py"]);
    fx.git(&["commit", "-q", "-m", "remove"]);
    let removed = fx.git(&["rev-parse", "HEAD"]);
    let run = fx.push(&[(&removed, &tip)]);
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    assert!(
        run.stderr
            .contains("failed: python3 -I scripts/test-gameday-judge.py"),
        "{}",
        run.stderr
    );
}

/// A push that changes no input of the host stop self-test asks Git nothing about it, though the trace
/// records the tool's other lookups.
#[test]
fn an_unrelated_push_asks_git_nothing_about_the_host_stop_self_test() {
    let mut fx = Fixture::new();
    let held = fx.commit(&[("scripts/test-host-stop-controller.py", STUB)]);
    let head = fx.commit(&[("docs/notes.md", "n\n")]);
    let trace = fx.temp.join("trace.log");
    fx.set("GIT_TRACE", trace.clone());
    assert_eq!(fx.push(&[(&head, &held)]).code, Some(0));
    fx.unset("GIT_TRACE");
    let text = fs::read_to_string(&trace).expect("the trace reads");
    let lookups: Vec<&str> = text
        .lines()
        .filter(|line| line.contains("cat-file"))
        .collect();
    assert!(
        !lookups.is_empty(),
        "the trace records the tool's other lookups"
    );
    assert!(
        !lookups
            .iter()
            .any(|line| line.contains("test-host-stop-controller.py")),
        "{lookups:?}"
    );
    assert!(
        !fx.ran()
            .iter()
            .any(|line| line == "test-host-stop-controller.py")
    );
}

/// The host stop self-test runs for a file it reads only at a tip that holds it, with a base or with none,
/// and its failure fails the push.
#[test]
fn the_hook_runs_the_host_stop_self_test_only_at_a_tip_that_holds_it() {
    let fx = Fixture::new();
    let name = "test-host-stop-controller.py";
    let head = fx.commit(&[("scripts/fis-profiles.json", "{}\n")]);
    assert_eq!(fx.push(&[(&head, &fx.base)]).code, Some(0));
    assert!(!fx.ran().iter().any(|line| line == name));
    let held = fx.commit(&[("scripts/test-host-stop-controller.py", STUB)]);
    fx.clear();
    let head = fx.commit(&[("scripts/fis-profiles.json", "{\"x\": 1}\n")]);
    assert_eq!(fx.push(&[(&head, &held)]).code, Some(0));
    assert_eq!(fx.ran(), [name]);
    fx.clear();
    let run = fx.push_with(&[(&head, &held)], &[("test_host_stop_controller", 1)]);
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    assert!(
        run.stderr
            .contains("failed: python3 -I scripts/test-host-stop-controller.py"),
        "{}",
        run.stderr
    );
    fx.git(&["update-ref", "-d", "refs/remotes/origin/main"]);
    fx.clear();
    assert_eq!(fx.push(&[(&head, ZERO)]).code, Some(0));
    assert!(fx.ran().iter().any(|line| line == name), "{:?}", fx.ran());
}

/// A failed contract check and a failed judges' test each fail the push, each started as `python3 -I`.
#[test]
fn a_failing_contract_check_or_judges_test_fails_the_push() {
    let fx = Fixture::new();
    let base = contract(&fx);
    let head = fx.commit(&[("chaos/judges/core/common.py", "edited\n")]);
    let run = fx.push_with(
        &[(&head, &base)],
        &[("validate_contract", 1), ("test_judges", 1)],
    );
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    assert_eq!(fx.ran(), [CONTRACT_CHECK, "test_judges.py"]);
    assert_eq!(fx.isolated(), fx.ran());
    for failed in [
        "python3 -I chaos/tools/validate_contract.py",
        "python3 -I chaos/tests/test_judges.py",
    ] {
        assert!(
            run.stderr.contains(&format!("failed: {failed}")),
            "{}",
            run.stderr
        );
    }
}

/// Without `origin/main`, each tip runs every check and the contract check and judges' test it holds.
#[test]
fn a_new_branch_without_origin_main_runs_the_contract_checks_its_tip_holds() {
    let fx = Fixture::new();
    let every = [
        "test-select-tests.py",
        "verify-receipts.py admit",
        "judge-verus.py reconcile",
    ];
    let base = contract(&fx);
    let mut tips = vec![base.clone()];
    let mut expected: Vec<String> = every.iter().map(|line| (*line).to_owned()).collect();
    expected.extend([CONTRACT_CHECK.to_owned(), "test_judges.py".to_owned()]);
    for (removed, checks) in [
        ("chaos/tests/test_judges.py", [CONTRACT_CHECK]),
        ("chaos/ledger.json", ["test_judges.py"]),
    ] {
        fx.git(&["checkout", "-q", "--detach", &base]);
        fx.git(&["rm", "-q", "--", removed]);
        fx.git(&["commit", "-q", "-m", "remove"]);
        tips.push(fx.git(&["rev-parse", "HEAD"]));
        expected.extend(every.iter().chain(&checks).map(|line| (*line).to_owned()));
    }
    fx.git(&["update-ref", "-d", "refs/remotes/origin/main"]);
    let run = fx.push(&[(&tips[0], ZERO), (&tips[1], ZERO), (&tips[2], ZERO)]);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert_eq!(fx.ran(), expected);
}
