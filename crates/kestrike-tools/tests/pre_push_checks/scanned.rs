//! The hook's scan cases, started through the tool: the weakened-test scan of each pushed range writes its
//! report and refusal lines to the tool's standard error, and a scan that returns nonzero fails the push
//! with the scan's command while the checks still run.

use std::fs;
use std::process::Stdio;

use super::push::{BINARY, Fixture, top};

const SELECTION: [&str; 2] = ["test-select-tests.py", "verify-receipts.py admit"];

fn ignore_an_existing_test(fx: &Fixture, message: &str) -> (String, String) {
    let existing = fx.commit(&[("crates/plain.rs", "#[test]\nfn churn() {}\n")]);
    let head = fx.commit_with(
        &[(
            "crates/plain.rs",
            "#[test]\n#[ignore = \"slow\"]\nfn churn() {}\n",
        )],
        message,
    );
    (existing, head)
}

fn scan_failure(base: &str, head: &str) -> String {
    format!("failed: scripts/tool.sh scan-weakened-tests --base {base} --head {head}")
}

#[test]
fn an_existing_test_that_gains_an_ignore_fails_the_push_and_the_checks_still_run() {
    let fx = Fixture::new();
    let (existing, head) = ignore_an_existing_test(&fx, "change");
    let run = fx.push(&[(&head, &existing)]);
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    assert!(
        run.stderr.contains(
            "blocks ignore-existing:crates/plain.rs churn: not ignored -> #[ignore = \"slow\"]"
        ),
        "{}",
        run.stderr
    );
    assert!(
        run.stderr.contains(&scan_failure(&existing, &head)),
        "{}",
        run.stderr
    );
    assert_eq!(fx.ran(), SELECTION);
    let scanned = run
        .stderr
        .find("tool.sh scan-weakened-tests --base")
        .expect("the scan is announced");
    let checked = run
        .stderr
        .find(&format!(
            "pre-push: {}: python3 scripts/test-select-tests.py",
            &head[..12]
        ))
        .expect("the selection check is announced");
    assert!(scanned < checked, "{}", run.stderr);
}

#[test]
fn a_blocking_finding_on_the_second_ref_line_fails_the_push() {
    let fx = Fixture::new();
    let (existing, head) = ignore_an_existing_test(&fx, "change");
    let run = fx.push(&[(&head, &fx.base), (&head, &existing)]);
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    assert!(
        run.stderr
            .contains("reports ignore-new:crates/plain.rs churn: absent -> #[ignore = \"slow\"]"),
        "{}",
        run.stderr
    );
    assert!(
        run.stderr
            .contains("blocks ignore-existing:crates/plain.rs churn"),
        "{}",
        run.stderr
    );
    assert!(
        run.stderr.contains(&scan_failure(&existing, &head)),
        "{}",
        run.stderr
    );
    assert!(
        !run.stderr.contains(&format!(
            "failed: scripts/tool.sh scan-weakened-tests --base {}",
            fx.base
        )),
        "{}",
        run.stderr
    );
    assert_eq!(fx.ran(), SELECTION);
}

#[test]
fn the_pushed_tip_and_not_the_checkout_is_scanned() {
    let fx = Fixture::new();
    let (existing, head) = ignore_an_existing_test(&fx, "change");
    fx.commit_with(
        &[("crates/plain.rs", "#[test]\nfn churn() {}\n")],
        "Restore churn\n\nWeakens-Test: ignore-existing:crates/plain.rs: written after the pushed tip",
    );
    let run = fx.push(&[(&head, &existing)]);
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    assert!(
        run.stderr
            .contains("blocks ignore-existing:crates/plain.rs churn"),
        "{}",
        run.stderr
    );
}

#[test]
fn a_lowered_budget_alone_fails_the_push_with_no_worktree_check() {
    let fx = Fixture::new();
    let budget = fx.commit(&[("crates/plain.rs", "const SEEDS: u64 = 12;\n")]);
    let head = fx.commit(&[("crates/plain.rs", "const SEEDS: u64 = 11;\n")]);
    let run = fx.push(&[(&head, &budget)]);
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    assert!(
        run.stderr
            .contains("blocks budget-lowered:crates/plain.rs SEEDS at line 1: 12 -> 11"),
        "{}",
        run.stderr
    );
    assert!(
        run.stderr.contains(&scan_failure(&budget, &head)),
        "{}",
        run.stderr
    );
    assert!(fx.ran().is_empty(), "{:?}", fx.ran());
}

// The fixture drops every `GITHUB_` variable from the push's environment, as the hook's own test did, so
// the summary the caller's environment names stays as it was; a fixture that passed it on would let the
// scan append its report lines there.
#[test]
fn an_inherited_step_summary_is_left_alone() {
    let summary_dir = super::push::fresh(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pre-push-summary-",
    );
    let summary = summary_dir.join("summary.md");
    fs::write(&summary, "earlier step\n").expect("the summary is written");
    let fx = Fixture::with(&[("GITHUB_STEP_SUMMARY", &summary.to_string_lossy())]);
    let (existing, head) = ignore_an_existing_test(&fx, "change");
    let run = fx.push(&[(&head, &existing)]);
    let left = fs::read_to_string(&summary).expect("the summary reads");
    fs::remove_dir_all(&summary_dir).expect("the summary's directory is removed");
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    assert!(
        run.stderr
            .contains("blocks ignore-existing:crates/plain.rs churn"),
        "{}",
        run.stderr
    );
    assert_eq!(left, "earlier step\n");
}

#[test]
fn a_scan_that_fails_for_another_reason_fails_the_push() {
    let fx = Fixture::new();
    let head = fx.commit(&[("scripts/test-inventory.json", "not json")]);
    let run = fx.push(&[(&head, &fx.base)]);
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    assert!(
        run.stderr.contains(&scan_failure(&fx.base, &head)),
        "{}",
        run.stderr
    );
    assert_eq!(fx.ran(), SELECTION);
}

#[test]
fn an_acknowledged_ignore_of_an_existing_test_passes_the_push() {
    let fx = Fixture::new();
    let (existing, head) = ignore_an_existing_test(
        &fx,
        "Ignore churn\n\nWeakens-Test: ignore-existing:crates/plain.rs: needs a cgroup scope",
    );
    let run = fx.push(&[(&head, &existing)]);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert!(
        run.stderr
            .contains("acknowledged ignore-existing:crates/plain.rs churn"),
        "{}",
        run.stderr
    );
    assert_eq!(fx.ran(), SELECTION);
}

#[test]
fn a_ref_without_a_comparison_base_prints_the_skipped_scan_and_runs_every_check() {
    let fx = Fixture::new();
    fx.git(&["update-ref", "-d", "refs/remotes/origin/main"]);
    let (_, head) = ignore_an_existing_test(&fx, "change");
    let run = fx.push(&[(&head, super::push::ZERO)]);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert!(
        run.stderr.contains(&format!(
            "pre-push: {}: no comparison base; weakened-test scan skipped",
            &head[..12]
        )),
        "{}",
        run.stderr
    );
    assert_eq!(
        fx.ran(),
        [
            "test-select-tests.py",
            "verify-receipts.py admit",
            "judge-verus.py reconcile"
        ]
    );
}

fn scan_lines<'a>(stderr: &'a str, head: &str) -> Vec<&'a str> {
    let announced = format!(
        "pre-push: {}: tool.sh scan-weakened-tests --base",
        &head[..12]
    );
    stderr
        .lines()
        .skip_while(|line| !line.starts_with(&announced))
        .skip(1)
        .take_while(|line| !line.starts_with("pre-push:"))
        .collect()
}

#[test]
fn a_scan_through_the_tool_gives_the_lines_and_code_of_scan_weakened_tests() {
    let fx = Fixture::new();
    let (existing, blocked) = ignore_an_existing_test(&fx, "change");
    fx.git(&["checkout", "-q", "--detach", &existing]);
    let acknowledged = fx.commit_with(
        &[(
            "crates/plain.rs",
            "#[test]\n#[ignore = \"slow\"]\nfn churn() {}\n",
        )],
        "Ignore churn\n\nWeakens-Test: ignore-existing:crates/plain.rs: needs a cgroup scope",
    );
    for (head, code) in [(&blocked, 1), (&acknowledged, 0)] {
        let base = fx.git(&["rev-parse", &format!("{head}~1")]);
        let scan = fx
            .command(BINARY)
            .arg(top())
            .args(["scan-weakened-tests", "--base", &base, "--head", head])
            .stdin(Stdio::null())
            .output()
            .expect("the scan starts");
        let mut lines = String::from_utf8(scan.stdout).expect("the scan writes UTF-8");
        lines.push_str(&String::from_utf8(scan.stderr).expect("the scan writes UTF-8"));
        assert_eq!(scan.status.code(), Some(code), "{lines}");
        assert!(!lines.is_empty());
        let run = fx.push(&[(head, &base)]);
        assert_eq!(run.code, Some(code), "{}", run.stderr);
        assert_eq!(
            scan_lines(&run.stderr, head),
            lines.lines().collect::<Vec<_>>(),
            "{}",
            run.stderr
        );
        assert_eq!(
            run.stderr.contains(&scan_failure(&base, head)),
            code != 0,
            "{}",
            run.stderr
        );
    }
}
