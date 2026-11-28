//! The hook's cases of the chaos checks and the two self-tests, started through the tool: which tip runs
//! the contract check, the receipt replay, the judges' test, the game-day self-test and the host stop
//! controller's cases, that each failure fails the push, and that the four checks that start as
//! `python3 -I` pass `-I`, which the stand-in records apart.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

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

/// The module of the host stop controller's cases, whose presence at a tip says the tip holds them.
const HOST_STOP_CASES: &str = "crates/kestrike-tools/tests/host_stop_controller/mod.rs";

/// The line the stand-in `cargo` logs for the host stop controller's row.
const HOST_STOP_RUN: &str = "cargo test --package kestrike-tools --test tools -- host_stop:: host_stop_checks:: host_stop_controller:: host_stop_support::";

/// The words the stand-in `cargo` gets for the host stop controller's row, one argument each.
const HOST_STOP_ARGS: [&str; 10] = [
    "test",
    "--package",
    "kestrike-tools",
    "--test",
    "tools",
    "--",
    "host_stop::",
    "host_stop_checks::",
    "host_stop_controller::",
    "host_stop_support::",
];

/// A push that changes no input of the host stop controller's cases asks Git nothing about them, though the
/// trace records the tool's other lookups; the control, a push that changes a fixture they read, asks
/// Git for their module and runs them.
#[test]
fn an_unrelated_push_asks_git_nothing_about_the_host_stop_self_test() {
    let mut fx = Fixture::new();
    let held = fx.commit(&[(HOST_STOP_CASES, "")]);
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
        !lookups.iter().any(|line| line.contains(HOST_STOP_CASES)),
        "{lookups:?}"
    );
    assert!(!fx.ran().iter().any(|line| line.starts_with("cargo")));
    let fixture = fx.commit(&[("scripts/host-stop-fixtures/operator.json", "{}\n")]);
    fx.set("GIT_TRACE", trace.clone());
    let _ = fs::remove_file(&trace);
    assert_eq!(fx.push(&[(&fixture, &head)]).code, Some(0));
    fx.unset("GIT_TRACE");
    let text = fs::read_to_string(&trace).expect("the trace reads");
    assert!(
        text.lines()
            .any(|line| line.contains("cat-file") && line.contains(HOST_STOP_CASES)),
        "a push that changes a file the cases read asks Git for the cases' module: {text}"
    );
    assert!(fx.ran().iter().any(|line| line.starts_with("cargo")));
}

/// The host stop controller's cases run for a fixture they read only at a tip that holds them, with a base
/// or with none, in the launcher's target directory under the checkout's top, and their failure fails the
/// push. A tip that holds the Python self-test alone runs nothing for the row; a change to the Rust module
/// runs the row at a tip that lacks the cases, where its filter matches no case, and the weakened-test
/// scan blocks the removal.
#[test]
fn the_hook_runs_the_host_stop_self_test_only_at_a_tip_that_holds_it() {
    let fx = Fixture::new();
    let fixture = "scripts/host-stop-fixtures/operator.json";
    let target = super::push::top()
        .join("target/tools")
        .to_string_lossy()
        .into_owned();
    let head = fx.commit(&[(fixture, "{}\n")]);
    assert_eq!(fx.push(&[(&head, &fx.base)]).code, Some(0));
    assert!(!fx.ran().iter().any(|line| line.starts_with("cargo")));
    let python = fx.commit(&[("scripts/test-host-stop-controller.py", STUB)]);
    let head = fx.commit(&[(fixture, "{\"y\": 1}\n")]);
    assert_eq!(fx.push(&[(&head, &python)]).code, Some(0));
    assert_eq!(fx.ran(), Vec::<String>::new());
    let held = fx.commit(&[(HOST_STOP_CASES, "")]);
    fx.clear();
    let head = fx.commit(&[(fixture, "{\"x\": 1}\n")]);
    assert_eq!(fx.push(&[(&head, &held)]).code, Some(0));
    assert_eq!(fx.ran(), [HOST_STOP_RUN]);
    assert_eq!(fx.targets(), [target.as_str()]);
    assert_eq!(fx.builds(), [format!("{target} 0 checkout")]);
    let mut words = vec![HOST_STOP_ARGS.len().to_string()];
    words.extend(HOST_STOP_ARGS.iter().map(|word| (*word).to_owned()));
    assert_eq!(fx.cargo_args(), words);
    let tmp = fs::canonicalize(&fx.tmp).expect("the tool's TMPDIR resolves");
    let dirs = fx.cargo_dirs();
    assert_eq!(dirs.len(), 1, "{dirs:?}");
    let dir = Path::new(&dirs[0]);
    assert_eq!(dir.parent(), Some(tmp.as_path()), "{dirs:?}");
    assert!(
        dir.file_name()
            .is_some_and(|name| name.to_string_lossy().starts_with("kestrike-pre-push-")),
        "{dirs:?}"
    );
    fx.clear();
    let run = fx.push_with(&[(&head, &held)], &[("cargo", 1)]);
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    assert!(
        run.stderr.contains(&format!("failed: {HOST_STOP_RUN}")),
        "{}",
        run.stderr
    );
    fx.git(&["rm", "-q", "--", HOST_STOP_CASES]);
    let lacking = fx.commit(&[("crates/kestrike-tools/src/host_stop/launch.rs", "l\n")]);
    fx.clear();
    let run = fx.push(&[(&lacking, &head)]);
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    assert!(
        run.stderr
            .contains("blocks case-removed:crates/kestrike-tools/tests/host_stop_controller"),
        "{}",
        run.stderr
    );
    assert!(!run.stderr.contains(&format!("failed: {HOST_STOP_RUN}")));
    assert_eq!(fx.ran(), [HOST_STOP_RUN]);
    fx.git(&["update-ref", "-d", "refs/remotes/origin/main"]);
    fx.clear();
    assert_eq!(fx.push(&[(&head, ZERO)]).code, Some(0));
    assert!(
        fx.ran().iter().any(|line| line == HOST_STOP_RUN),
        "{:?}",
        fx.ran()
    );
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
    let listed: Vec<usize> = [
        "python3 -I chaos/tools/validate_contract.py",
        "python3 -I chaos/tests/test_judges.py",
    ]
    .iter()
    .map(|failed| {
        run.stderr
            .find(&format!("failed: {failed}"))
            .unwrap_or_else(|| panic!("{failed} is listed: {}", run.stderr))
    })
    .collect();
    assert!(listed[0] < listed[1], "{}", run.stderr);
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

/// A worktree parent that another user can write fails the host stop controller's row before `cargo`
/// starts, naming the parent; the control, the fixture's own `TMPDIR` of mode 0700, runs it.
#[test]
fn a_shared_worktree_parent_fails_the_host_stop_row_before_cargo_starts() {
    let mut fx = Fixture::new();
    let held = fx.commit(&[(HOST_STOP_CASES, "")]);
    let head = fx.commit(&[("scripts/host-stop-fixtures/operator.json", "{}\n")]);
    assert_eq!(fx.push(&[(&head, &held)]).code, Some(0));
    assert_eq!(fx.ran(), [HOST_STOP_RUN]);
    fx.clear();
    let shared = fx.temp.join("shared");
    fs::create_dir(&shared).expect("the shared directory is made");
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o777))
        .expect("the shared directory's mode is set");
    fx.set("TMPDIR", shared.clone());
    let run = fx.push(&[(&head, &held)]);
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    assert!(
        run.stderr.contains(&format!(
            "failed: {HOST_STOP_RUN}: another user owns or can write {}",
            shared.display()
        )),
        "{}",
        run.stderr
    );
    assert!(
        run.stderr
            .contains("set TMPDIR to a directory only you control"),
        "{}",
        run.stderr
    );
    assert_eq!(fx.ran(), Vec::<String>::new());
}

/// A tip that tracks its own `Cargo.lock` keeps it for the host stop controller's row, where a tip without
/// one gets the checkout's.
#[test]
fn a_tip_that_tracks_a_lock_keeps_it_for_the_host_stop_row() {
    let fx = Fixture::new();
    let held = fx.commit(&[(HOST_STOP_CASES, ""), ("Cargo.lock", "# own\n")]);
    let head = fx.commit(&[("scripts/host-stop-fixtures/operator.json", "{}\n")]);
    assert_eq!(fx.push(&[(&head, &held)]).code, Some(0));
    assert_eq!(fx.ran(), [HOST_STOP_RUN]);
    let builds = fx.builds();
    assert_eq!(builds.len(), 1, "{builds:?}");
    assert!(builds[0].ends_with(" 0 own"), "{builds:?}");
}

/// A relative checkout top is made absolute against the tool's working directory before the row names
/// its target directory; an empty top, which cannot be made absolute, exits 2 before any check.
#[test]
fn the_checkout_top_is_made_absolute_and_an_empty_one_is_refused() {
    let fx = Fixture::new();
    let held = fx.commit(&[(HOST_STOP_CASES, "")]);
    let head = fx.commit(&[("scripts/host-stop-fixtures/operator.json", "{}\n")]);
    let ups = fx.repo.components().count() - 1;
    let mut relative = PathBuf::new();
    for _ in 0..ups {
        relative.push("..");
    }
    relative.push(
        super::push::top()
            .strip_prefix("/")
            .expect("the top is absolute"),
    );
    let input = format!("refs/heads/x {head} refs/heads/x {held}\n");
    let mut command = fx.command(super::push::BINARY);
    command
        .arg(&relative)
        .args(["pre-push-checks", "origin", "url"]);
    let run = super::push::finished(super::push::spawn_with_input(&mut command, &input));
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    let target = fx.repo.join(&relative).join("target/tools");
    assert_eq!(fx.targets(), [target.to_string_lossy().into_owned()]);
    fx.clear();
    let mut command = fx.command(super::push::BINARY);
    command.arg("").args(["pre-push-checks", "origin", "url"]);
    let run = super::push::finished(super::push::spawn_with_input(&mut command, &input));
    assert_eq!(run.code, Some(2), "{}", run.stderr);
    assert!(
        run.stderr
            .starts_with("pre-push-checks: the checkout's top : "),
        "{}",
        run.stderr
    );
    assert_eq!(fx.ran(), Vec::<String>::new());
}
