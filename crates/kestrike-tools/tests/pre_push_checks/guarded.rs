//! The chaos guard identifies each refused record by its path and the first 12 characters of its commit
//! ID.

use std::fs;

use super::chaos_checks::{CONTRACT_CHECK, contract};
use super::push::{Fixture, ZERO, finished, top};

const REFUSED: &str = "holds what may be an AWS account number";
const LEAK: &str = r#"{"account": 123456789012}"#;

fn failed(path: &str, commit: &str, said: &str) -> String {
    format!("failed: {path} at {} {said}", &commit[..12])
}

#[test]
fn a_chaos_record_with_an_account_number_fails_the_push() {
    let fx = Fixture::new();
    let base = contract(&fx);
    let refused = [
        (
            "chaos/receipts/run/row.json",
            r#"{"arn": "arn:aws:sts::123456789012:assumed-role/r"}"#,
            "chaos/receipts/run/row.json",
        ),
        (
            "chaos/receipts/run/a\nb.json",
            LEAK,
            "'chaos/receipts/run/a\\nb.json'",
        ),
        (
            "chaos/runs/run/run.json",
            r#"{"error": "denied\n1234-5678-9012"}"#,
            "chaos/runs/run/run.json",
        ),
        (
            "chaos/tests/runs/fixture/run.json",
            r#"{"bucket": "assets-123456789012-us-east-1"}"#,
            "chaos/tests/runs/fixture/run.json",
        ),
        (
            "chaos/tests/receipts/fixture/row.json",
            r#"{"detail": "role 123456789012 refused"}"#,
            "chaos/tests/receipts/fixture/row.json",
        ),
    ];
    let unread = [
        ("chaos/receipts/run/clean.json", r#"{"b": 0.000244140625}"#),
        (
            "chaos/runs/run/history.jsonl",
            r#"{"history": 123456789012}"#,
        ),
        (
            "chaos/runs/run/sweep-status.json",
            r#"{"status": 123456789012}"#,
        ),
        (
            "chaos/tests/runs/fixture/history.jsonl",
            r#"{"fixture": 123456789012}"#,
        ),
    ];
    let files: Vec<(&str, &str)> = refused
        .iter()
        .map(|(path, text, _)| (*path, *text))
        .chain(unread)
        .collect();
    let head = fx.commit(&files);
    let run = fx.push(&[(&head, &base)]);
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    assert_eq!(fx.ran(), [CONTRACT_CHECK, "test_judges.py"]);
    for (path, _, shown) in refused {
        assert_eq!(
            run.stderr.matches(&failed(shown, &head, REFUSED)).count(),
            1,
            "{path:?}: {}",
            run.stderr
        );
    }
    for (path, _) in unread {
        assert!(
            !run.stderr.contains(&format!("{path} at")),
            "{}",
            run.stderr
        );
    }
}

#[test]
fn a_link_under_chaos_fails_the_push() {
    let fx = Fixture::new();
    let base = contract(&fx);
    fx.commit(&[("chaos/elsewhere/row.json", LEAK), ("chaos/copy.md", "r\n")]);
    fx.link("chaos/receipts", "elsewhere");
    let head = fx.link("chaos/READINESS.md", "copy.md");
    let run = fx.push(&[(&head, &base)]);
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    for path in ["chaos/receipts", "chaos/READINESS.md"] {
        let line = failed(path, &head, "is a link or a submodule");
        assert!(run.stderr.contains(&line), "{line}: {}", run.stderr);
    }
}

#[test]
fn a_pushed_commit_with_an_account_number_fails_a_push_whose_tip_removed_it() {
    let fx = Fixture::new();
    let base = contract(&fx);
    let linked = fx.link("chaos/runs/linked/run.json", "123456789012");
    let test_receipt = "chaos/tests/receipts/fixture/row.json";
    let leaked = fx.commit(&[
        ("chaos/runs/run/run.json", LEAK),
        (test_receipt, r#"{"role": 123456789012}"#),
    ]);
    fx.git(&["rm", "-q", "--", "chaos/runs/linked/run.json", test_receipt]);
    let head = fx.commit(&[("chaos/runs/run/run.json", "{}\n")]);
    let run = fx.push(&[(&head, &base)]);
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    assert!(fx.ran().is_empty(), "{:?}", fx.ran());
    for path in ["chaos/runs/run/run.json", test_receipt] {
        let line = failed(path, &leaked, REFUSED);
        assert!(run.stderr.contains(&line), "{line}: {}", run.stderr);
    }
    assert_eq!(
        run.stderr
            .matches("failed: chaos/runs/linked/run.json at")
            .count(),
        1,
        "{}",
        run.stderr
    );
    let line = failed(
        "chaos/runs/linked/run.json",
        &linked,
        "is a chaos record that is not a regular file",
    );
    assert!(run.stderr.contains(&line), "{line}: {}", run.stderr);
}

#[test]
fn a_link_or_a_submodule_at_the_chaos_root_fails_a_push_with_a_base() {
    let fx = Fixture::new();
    fx.commit(&[("elsewhere/runs/run/run.json", LEAK)]);
    let linked = fx.link("chaos", "elsewhere");
    fx.git(&["checkout", "-q", "--detach", &fx.base]);
    fx.git(&["config", "diff.ignoreSubmodules", "all"]);
    fx.git(&[
        "update-index",
        "--add",
        "--cacheinfo",
        &format!("160000,{},chaos", fx.base),
    ]);
    fx.git(&["commit", "-q", "-m", "submodule"]);
    let submodule = fx.git(&["rev-parse", "HEAD"]);
    let run = fx.push(&[(&linked, &fx.base), (&submodule, &fx.base)]);
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    for head in [&linked, &submodule] {
        let line = failed("chaos", head, "is a link or a submodule");
        assert!(run.stderr.contains(&line), "{line}: {}", run.stderr);
    }
}

#[test]
fn a_merged_side_branch_with_an_account_number_fails_the_push() {
    let fx = Fixture::new();
    let base = contract(&fx);
    let leaked = fx.commit(&[("chaos/runs/run/run.json", LEAK)]);
    let side = fx.commit(&[("chaos/runs/run/run.json", "{}\n")]);
    fx.git(&["checkout", "-q", "--detach", &base]);
    fx.commit(&[("chaos/survey.md", "main line\n")]);
    fx.git(&["merge", "-q", "--no-ff", "-m", "merge", &side]);
    let head = fx.git(&["rev-parse", "HEAD"]);
    let run = fx.push(&[(&head, &base)]);
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    let line = failed("chaos/runs/run/run.json", &leaked, REFUSED);
    assert!(run.stderr.contains(&line), "{line}: {}", run.stderr);
}

#[test]
fn the_history_guard_skips_the_records_of_commits_the_destination_holds() {
    let fx = Fixture::new();
    // `new` and `merged` both have `held` as an ancestor, and `origin/team/topic` points at `held`, so the
    // guard passes over the refused record in its parent for both updates.
    let start = contract(&fx);
    fx.git(&["update-ref", "refs/remotes/origin/main", &start]);
    fx.commit(&[("chaos/runs/run/run.json", LEAK)]);
    let held = fx.commit(&[("chaos/runs/run/run.json", "{}\n")]);
    fx.git(&["update-ref", "refs/remotes/origin/team/topic", &held]);
    let new = fx.commit(&[("crates/plain.rs", "a new branch\n")]);
    fx.git(&["checkout", "-q", "--detach", &start]);
    let old = fx.commit(&[("crates/other.rs", "an older branch\n")]);
    fx.git(&["merge", "-q", "--no-ff", "-m", "merge", &held]);
    let merged = fx.git(&["rev-parse", "HEAD"]);
    let run = fx.push(&[(&new, ZERO), (&merged, &old)]);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert!(fx.ran().is_empty(), "{:?}", fx.ran());
}

#[test]
fn a_new_ref_reads_the_records_of_commits_only_another_remote_holds() {
    let fx = Fixture::new();
    // Besides `other`, a remote named `origin/fork` holds the commit, and its refs lie under `origin`'s.
    contract(&fx);
    let leaked = fx.commit(&[("chaos/runs/run/run.json", LEAK)]);
    fx.git(&["update-ref", "refs/remotes/other/x", &leaked]);
    fx.git(&["update-ref", "refs/remotes/origin/fork/x", &leaked]);
    fx.git(&["config", "remote.origin/fork.url", "elsewhere"]);
    fx.git(&["update-ref", "-d", "refs/remotes/origin/main"]);
    let head = fx.commit(&[("chaos/runs/run/run.json", "{}\n")]);
    let run = fx.push(&[(&head, ZERO)]);
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    let line = failed("chaos/runs/run/run.json", &leaked, REFUSED);
    assert!(run.stderr.contains(&line), "{line}: {}", run.stderr);
}

#[test]
fn the_history_guard_reads_pathspecs_whatever_mode_the_push_set() {
    let mut fx = Fixture::new();
    let base = contract(&fx);
    let leaked = fx.commit(&[("chaos/runs/run/run.json", LEAK)]);
    let head = fx.commit(&[("chaos/runs/run/run.json", "{}\n")]);
    // Git refuses the literal mode beside any other, so only a guard that clears every mode reads the record.
    for mode in [
        "GIT_LITERAL_PATHSPECS",
        "GIT_GLOB_PATHSPECS",
        "GIT_ICASE_PATHSPECS",
    ] {
        fx.set(mode, "1");
    }
    let run = fx.push(&[(&head, &base)]);
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    let line = failed("chaos/runs/run/run.json", &leaked, REFUSED);
    assert!(run.stderr.contains(&line), "{line}: {}", run.stderr);
}

#[test]
fn the_guard_reads_the_original_objects_past_a_replacement() {
    let fx = Fixture::new();
    let base = contract(&fx);
    let head = fx.commit(&[("chaos/runs/run/run.json", LEAK)]);
    let original = fx.git(&["rev-parse", &format!("{head}:chaos/runs/run/run.json")]);
    let blank = fx.temp.join("clean.json");
    fs::write(&blank, "{}\n").expect("the clean record is written");
    let clean = fx.git(&["hash-object", "-w", &blank.to_string_lossy()]);
    fx.git(&["replace", &original, &clean]);
    let run = fx.push(&[(&head, &base)]);
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    let line = failed("chaos/runs/run/run.json", &head, REFUSED);
    assert!(run.stderr.contains(&line), "{line}: {}", run.stderr);
}

#[test]
fn a_chaos_record_that_is_not_json_or_cannot_be_read_fails() {
    let fx = Fixture::new();
    let base = contract(&fx);
    let head = fx.commit(&[("chaos/runs/run/run.json", r#"{"a": "\n123456789012""#)]);
    let run = fx.push(&[(&head, &base)]);
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    let line = failed(
        "chaos/runs/run/run.json",
        &head,
        "is a chaos record that is not JSON",
    );
    assert!(run.stderr.contains(&line), "{line}: {}", run.stderr);
    let added = fx.commit(&[("chaos/runs/gone/run.json", "{\"gone\": 1}\n")]);
    let blob = fx.git(&["rev-parse", &format!("{added}:chaos/runs/gone/run.json")]);
    fx.git(&["rm", "-q", "--", "chaos/runs/gone/run.json"]);
    fx.git(&["commit", "-q", "-m", "remove"]);
    let removed = fx.git(&["rev-parse", "HEAD"]);
    // The pushed range still lists the record added at `added`, whose object is gone.
    fs::remove_file(
        fx.repo
            .join(".git/objects")
            .join(&blob[..2])
            .join(&blob[2..]),
    )
    .expect("the record's object is removed");
    let run = fx.push(&[(&removed, &head)]);
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    let line = failed(
        "chaos/runs/gone/run.json",
        &added,
        "is a chaos record Git could not read",
    );
    assert!(run.stderr.contains(&line), "{line}: {}", run.stderr);
}

#[test]
fn a_chaos_change_reads_every_record_of_the_tip_from_any_directory() {
    let fx = Fixture::new();
    contract(&fx);
    let base = fx.commit(&[("chaos/runs/old/run.json", LEAK)]);
    let head = fx.commit(&[("chaos/survey.md", "edited\n")]);
    let run = finished(fx.start_in(
        &fx.repo.join("crates"),
        &Fixture::input(&[(&head, &base)]),
        &[],
    ));
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    assert_eq!(fx.ran(), [CONTRACT_CHECK]);
    let line = failed("chaos/runs/old/run.json", &head, REFUSED);
    assert!(run.stderr.contains(&line), "{line}: {}", run.stderr);
}

#[test]
fn a_push_that_changes_nothing_under_chaos_reads_no_chaos_record() {
    let fx = Fixture::new();
    let base = fx.commit(&[("chaos/runs/run/run.json", LEAK)]);
    let head = fx.commit(&[("crates/plain.rs", "edited\n")]);
    let run = fx.push(&[(&head, &base)]);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert!(fx.ran().is_empty(), "{:?}", fx.ran());
}

#[test]
fn a_new_branch_without_origin_main_guards_the_chaos_records_of_its_tip() {
    let fx = Fixture::new();
    contract(&fx);
    fx.git(&["rm", "-q", "--", "chaos/ledger.json"]);
    fx.commit(&[
        ("chaos/runs/run/run.json", LEAK),
        ("chaos/elsewhere.json", "{}\n"),
    ]);
    let head = fx.link("chaos/runs/linked/run.json", "../../elsewhere.json");
    fx.git(&["update-ref", "-d", "refs/remotes/origin/main"]);
    let run = fx.push(&[(&head, ZERO)]);
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    for line in [
        failed("chaos/runs/run/run.json", &head, REFUSED),
        failed(
            "chaos/runs/linked/run.json",
            &head,
            "is a link or a submodule",
        ),
    ] {
        assert!(run.stderr.contains(&line), "{line}: {}", run.stderr);
    }
}

#[test]
fn the_recorded_run_is_a_record_the_pre_push_hook_guards() {
    let reach =
        fs::read_to_string(top().join("chaos/tests/test_reach.py")).expect("the reach suite reads");
    let declared: Vec<&str> = reach
        .lines()
        .filter_map(|line| line.strip_prefix("RECORDED = TESTS / "))
        .collect();
    assert_eq!(declared.len(), 1, "the reach suite declares RECORDED once");
    let mut record = String::from("chaos/tests");
    for part in declared[0].split(" / ") {
        let name = part
            .strip_prefix('"')
            .and_then(|part| part.strip_suffix('"'))
            .unwrap_or_else(|| panic!("{part} is a double-quoted name"));
        record.push('/');
        record.push_str(name);
    }
    record.push_str("/run.json");
    let record = record.as_str();
    assert!(
        top().join(record).is_file(),
        "the checkout holds the recorded run at {record}"
    );
    let fx = Fixture::new();
    let base = contract(&fx);
    let head = fx.commit(&[(record, LEAK)]);
    let run = fx.push(&[(&head, &base)]);
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    let line = failed(record, &head, REFUSED);
    assert!(run.stderr.contains(&line), "{line}: {}", run.stderr);
    fx.git(&["rm", "-q", "--", record]);
    fx.git(&["commit", "-q", "-m", "remove the record"]);
    let clean = fx.git(&["rev-parse", "HEAD"]);
    fx.clear();
    let run = fx.push(&[(&clean, &base)]);
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    assert!(run.stderr.contains(&line), "{line}: {}", run.stderr);
}

#[test]
fn the_guard_s_failures_are_listed_before_the_checks_failures() {
    let fx = Fixture::new();
    let base = contract(&fx);
    let head = fx.commit(&[("chaos/receipts/run/row.json", LEAK)]);
    let run = fx.push_with(&[(&head, &base)], &[("validate_contract", 1)]);
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    let guard = run
        .stderr
        .find(&failed("chaos/receipts/run/row.json", &head, REFUSED))
        .unwrap_or_else(|| panic!("the guard's failure is listed: {}", run.stderr));
    let check = run
        .stderr
        .find("failed: python3 -I chaos/tools/validate_contract.py")
        .unwrap_or_else(|| panic!("the check's failure is listed: {}", run.stderr));
    let announced = run
        .stderr
        .find("python3 -I chaos/tools/validate_contract.py")
        .expect("the check is announced");
    assert!(announced < guard && guard < check, "{}", run.stderr);
}

/// `weakened_with_a_record` commits a test, then an ignore on it beside a refused record, over the chaos
/// contract, and returns the test's commit and the tip.
fn weakened_with_a_record(fx: &Fixture) -> (String, String) {
    contract(fx);
    let existing = fx.commit(&[("crates/plain.rs", "#[test]\nfn churn() {}\n")]);
    let head = fx.commit(&[
        (
            "crates/plain.rs",
            "#[test]\n#[ignore = \"slow\"]\nfn churn() {}\n",
        ),
        ("chaos/receipts/run/row.json", LEAK),
    ]);
    (existing, head)
}

/// One range that fails the scan, the guard and a check lists their failures in that order.
#[test]
fn the_scan_s_guard_s_and_checks_failures_are_listed_in_that_order() {
    let fx = Fixture::new();
    let (existing, head) = weakened_with_a_record(&fx);
    let run = fx.push_with(&[(&head, &existing)], &[("validate_contract", 1)]);
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    let position = |line: &str| {
        run.stderr
            .find(line)
            .unwrap_or_else(|| panic!("{line} is listed: {}", run.stderr))
    };
    let scan = position(&format!(
        "failed: scripts/tool.sh scan-weakened-tests --base {existing} --head {head}"
    ));
    let guard = position(&failed("chaos/receipts/run/row.json", &head, REFUSED));
    let check = position("failed: python3 -I chaos/tools/validate_contract.py");
    assert!(scan < guard && guard < check, "{}", run.stderr);
}

/// A guard read that fails after the plan ends the push with exit 2 once the scan has run, and no check
/// starts.
#[test]
fn a_failed_guard_read_ends_the_push_after_the_scan_and_before_any_check() {
    let fx = Fixture::new();
    let (existing, head) = weakened_with_a_record(&fx);
    fx.wrap_git_around(
        "printf '%s\\n' \"$1\" >> \"$STUB_LOG.git\"\n\
         if [ \"$1\" = ls-tree ]; then echo 'fatal: refused by the stand-in' >&2; exit 128; fi",
    );
    let run = fx.push(&[(&head, &existing)]);
    assert_eq!(run.code, Some(2), "{}", run.stderr);
    let finding = run
        .stderr
        .find("blocks ignore-existing:crates/plain.rs churn")
        .unwrap_or_else(|| panic!("the scan reports: {}", run.stderr));
    let refusal = run
        .stderr
        .find("pre-push: git ls-tree")
        .unwrap_or_else(|| panic!("the guard's read is refused: {}", run.stderr));
    assert!(finding < refusal, "{}", run.stderr);
    assert!(
        run.stderr.ends_with("fatal: refused by the stand-in\n"),
        "{}",
        run.stderr
    );
    let invoked = fs::read_to_string(fx.logged(".git")).expect("the wrapper logs each Git command");
    let invoked: Vec<&str> = invoked.lines().collect();
    let scanned = invoked.iter().position(|name| *name == "-c");
    let guarded = invoked.iter().position(|name| *name == "ls-tree");
    assert!(
        scanned.is_some() && scanned < guarded,
        "the scan reads Git before the guard: {invoked:?}"
    );
    assert!(fx.ran().is_empty(), "{:?}", fx.ran());
    assert_eq!(fx.worktrees(), 1);
}
