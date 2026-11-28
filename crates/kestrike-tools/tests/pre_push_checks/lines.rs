//! Rows of a ref line's states: each reads the fixture repository of the hook's self-test in a child and
//! asserts the plan's checks, scans or failure.

use std::ffi::OsString;

use kestrike_tools::hook::{Check, Failure, Plan};

use super::repository::{Repository, STUB, ZERO, child, id};

/// `fixture` is the self-test's base: the selection, admission and reconciliation scripts as stubs, a
/// Verus inventory that names `crates/v.rs`, a plain Rust file and the test inventory, with
/// `origin/main` at that commit.
pub fn fixture(name: &str) -> (Repository, String) {
    let repository = Repository::new(name);
    let base = repository.commit(&[
        ("scripts/test-select-tests.py", STUB),
        ("scripts/verify-receipts.py", STUB),
        ("scripts/judge-verus.py", STUB),
        (
            "verification/verus/inventory.json",
            r#"{"sources": {"crates/v.rs": "d"}}"#,
        ),
        ("crates/v.rs", "v\n"),
        ("crates/plain.rs", "p\n"),
        ("scripts/test-inventory.json", "{}"),
    ]);
    repository.git(&["update-ref", "refs/remotes/origin/main", &base]);
    (repository, base)
}

/// `line` is a ref line that pushes `local` over `remote`.
pub fn line(local: &str, remote: &str) -> OsString {
    OsString::from(format!("refs/heads/x {local} refs/heads/x {remote}"))
}

/// `planned` reads `lines` into a plan of a push to `origin`, failing the row on any error.
pub fn planned(lines: &[OsString]) -> Plan {
    let mut plan = Plan::new("origin".as_ref(), || Ok(())).expect("the plan starts");
    for line in lines {
        plan.line(line, |_| {}).expect("the line reads");
    }
    plan
}

fn scans(plan: &Plan) -> Vec<(String, String)> {
    plan.scans()
        .iter()
        .map(|(base, tip)| (base.to_string(), tip.to_string()))
        .collect()
}

fn checks(plan: &Plan) -> Vec<(String, Vec<Check>)> {
    plan.checks()
        .into_iter()
        .map(|(tip, checks)| (tip.to_string(), checks))
        .collect()
}

/// A deleted ref plans no check, no scan and guards nothing.
#[test]
fn a_deletion_runs_no_check() {
    if child().is_some() {
        let deletion = OsString::from(format!(
            "(delete) {ZERO} refs/heads/gone {}",
            "1".repeat(40)
        ));
        let plan = planned(&[deletion]);
        assert_eq!((checks(&plan), scans(&plan)), (vec![], vec![]));
        assert_eq!(plan.guard().expect("the guard reads"), Vec::<String>::new());
        return;
    }
    let (repository, _) = fixture("deletion");
    repository.in_child(&id(module_path!(), "a_deletion_runs_no_check"), &[]);
}

/// A blank line plans nothing and refuses nothing.
#[test]
fn a_blank_ref_line_is_skipped() {
    if child().is_some() {
        let mut plan = Plan::new("origin".as_ref(), || Ok(())).expect("the plan starts");
        plan.line(" \t".as_ref(), |_| panic!("a blank line has no note"))
            .expect("a blank line reads");
        assert_eq!((checks(&plan), scans(&plan)), (vec![], vec![]));
        return;
    }
    let (repository, _) = fixture("blank");
    repository.in_child(&id(module_path!(), "a_blank_ref_line_is_skipped"), &[]);
}

/// A line of one field ends the push with its `repr`.
#[test]
fn a_malformed_ref_line_fails() {
    if child().is_some() {
        let mut plan = Plan::new("origin".as_ref(), || Ok(())).expect("the plan starts");
        let error = plan
            .line("ref-update".as_ref(), |_| {})
            .expect_err("the line is malformed");
        assert!(matches!(error, Failure::Malformed(_)), "{error:?}");
        assert_eq!(error.to_string(), "malformed ref line: 'ref-update'");
        return;
    }
    let (repository, _) = fixture("malformed");
    repository.in_child(&id(module_path!(), "a_malformed_ref_line_fails"), &[]);
}

/// `diverged` is the fixture with `origin/main` past the fork at a commit that edits `crates/v.rs` and adds
/// `crates/up.rs`, and a
/// local branch from the fork that makes the same edit and then edits `crates/plain.rs`, checked out; it
/// returns the fork. Only a diff from the fork holds the Verus source's change.
fn diverged(name: &str) -> (Repository, String) {
    let (repository, base) = fixture(name);
    let upstream = repository.commit(&[("crates/v.rs", "edited\n"), ("crates/up.rs", "u\n")]);
    repository.git(&["update-ref", "refs/remotes/origin/main", &upstream]);
    repository.git(&["checkout", "-q", "--detach", &base]);
    repository.commit(&[("crates/v.rs", "edited\n")]);
    repository.commit(&[("crates/plain.rs", "edited\n")]);
    (repository, base)
}

/// A new branch compares its tip with its merge base with `origin/main`, so a Verus source change at the
/// tip runs reconciliation and one scan of that range.
#[test]
fn a_new_branch_compares_against_origin_main() {
    if let Some(row) = child() {
        let (base, head) = (row.get("BASE"), row.get("HEAD"));
        let plan = planned(&[line(&head, ZERO)]);
        assert_eq!(
            (checks(&plan), scans(&plan)),
            (
                vec![(head.clone(), vec![Check::Reconcile])],
                vec![(base, head)]
            )
        );
        return;
    }
    let (repository, base) = diverged("new-branch");
    let head = repository.git(&["rev-parse", "HEAD"]);
    repository.in_child(
        &id(module_path!(), "a_new_branch_compares_against_origin_main"),
        &[("BASE", &base), ("HEAD", &head)],
    );
}

/// A remote commit this clone lacks compares the tip with its merge base with `origin/main`.
#[test]
fn an_unknown_remote_commit_compares_against_origin_main() {
    if let Some(row) = child() {
        let (base, head) = (row.get("BASE"), row.get("HEAD"));
        let plan = planned(&[line(&head, &"2".repeat(40))]);
        assert_eq!(
            (checks(&plan), scans(&plan)),
            (
                vec![(head.clone(), vec![Check::Reconcile])],
                vec![(base, head)]
            )
        );
        return;
    }
    let (repository, base) = diverged("unknown-remote");
    let head = repository.git(&["rev-parse", "HEAD"]);
    repository.in_child(
        &id(
            module_path!(),
            "an_unknown_remote_commit_compares_against_origin_main",
        ),
        &[("BASE", &base), ("HEAD", &head)],
    );
}

/// A line with no comparison base notes the skipped scan, plans no scan, and runs every check the tip's
/// tree can run.
#[test]
fn a_ref_without_a_comparison_base_prints_the_skipped_scan_and_runs_every_check() {
    if let Some(row) = child() {
        let head = row.get("HEAD");
        let mut plan = Plan::new("origin".as_ref(), || Ok(())).expect("the plan starts");
        let mut note = None;
        plan.line(&line(&head, ZERO), |skipped| note = Some(skipped))
            .expect("the line reads");
        assert_eq!(
            note.map(|note| note.to_string()),
            Some(format!(
                "{}: no comparison base; weakened-test scan skipped",
                &head[..12]
            ))
        );
        assert_eq!(
            (checks(&plan), scans(&plan)),
            (
                vec![(
                    head,
                    vec![Check::SelectTests, Check::Admit, Check::Reconcile]
                )],
                vec![]
            )
        );
        return;
    }
    let (repository, _) = fixture("no-base");
    repository.git(&["update-ref", "-d", "refs/remotes/origin/main"]);
    let head = repository.commit(&[(
        "crates/plain.rs",
        "#[test]\n#[ignore = \"slow\"]\nfn churn() {}\n",
    )]);
    repository.in_child(
        &id(
            module_path!(),
            "a_ref_without_a_comparison_base_prints_the_skipped_scan_and_runs_every_check",
        ),
        &[("HEAD", &head)],
    );
}

/// Two lines of one (base, tip) pair add one scan, and the tip's checks once.
#[test]
fn every_pushed_ref_is_checked_once_per_commit() {
    if let Some(row) = child() {
        let (base, plain, head) = (row.get("BASE"), row.get("PLAIN"), row.get("HEAD"));
        let plan = planned(&[
            line(&plain, &base),
            line(&head, &plain),
            line(&head, &plain),
        ]);
        assert_eq!(
            (checks(&plan), scans(&plan)),
            (
                vec![(head.clone(), vec![Check::Reconcile])],
                vec![(base, plain.clone()), (plain, head)]
            )
        );
        return;
    }
    let (repository, base) = fixture("once");
    let plain = repository.commit(&[("crates/plain.rs", "edited\n")]);
    let head = repository.commit(&[("crates/v.rs", "edited\n")]);
    repository.in_child(
        &id(
            module_path!(),
            "every_pushed_ref_is_checked_once_per_commit",
        ),
        &[("BASE", &base), ("PLAIN", &plain), ("HEAD", &head)],
    );
}

/// A tip on two lines gets the union of their checks: against itself nothing changed, against the base the
/// inventory did.
#[test]
fn one_commit_pushed_to_two_refs_runs_the_union_of_their_checks() {
    if let Some(row) = child() {
        let (base, head) = (row.get("BASE"), row.get("HEAD"));
        let plan = planned(&[line(&head, &head), line(&head, &base)]);
        assert_eq!(
            (checks(&plan), scans(&plan)),
            (
                vec![(head.clone(), vec![Check::SelectTests, Check::Admit])],
                vec![(head.clone(), head.clone()), (base, head)]
            )
        );
        return;
    }
    let (repository, base) = fixture("union");
    let head = repository.commit(&[("scripts/test-inventory.json", r#"{"rows": []}"#)]);
    repository.in_child(
        &id(
            module_path!(),
            "one_commit_pushed_to_two_refs_runs_the_union_of_their_checks",
        ),
        &[("BASE", &base), ("HEAD", &head)],
    );
}

/// An `origin/main` that names a missing commit ends the push with the merge base's Git failure.
#[test]
fn an_unreadable_origin_main_fails_the_push_with_a_git_error() {
    if let Some(row) = child() {
        let head = row.get("HEAD");
        let mut plan = Plan::new("origin".as_ref(), || Ok(())).expect("the plan starts");
        let error = plan
            .line(&line(&head, ZERO), |_| {
                panic!("a line whose base read fails has no note")
            })
            .expect_err("the merge base fails");
        assert!(matches!(error, Failure::Git(_)), "{error:?}");
        assert!(
            error
                .to_string()
                .starts_with(&format!("git merge-base origin/main {head}: ")),
            "{error}"
        );
        return;
    }
    let (repository, _) = fixture("unreadable-origin");
    let head = repository.commit(&[("crates/plain.rs", "edited\n")]);
    repository.git(&["update-ref", "-d", "refs/remotes/origin/main"]);
    let reference = repository.top.join(".git/refs/remotes/origin/main");
    std::fs::create_dir_all(reference.parent().expect("a ref has a parent"))
        .expect("the ref directory is made");
    std::fs::write(reference, format!("{}\n", "1".repeat(40))).expect("the ref is written");
    repository.in_child(
        &id(
            module_path!(),
            "an_unreadable_origin_main_fails_the_push_with_a_git_error",
        ),
        &[("HEAD", &head)],
    );
}

/// An inventory that is not JSON, or that is no object, runs reconciliation on any later change; a change
/// to the inventory itself also runs the selection checks.
#[test]
fn a_malformed_verus_inventory_runs_reconciliation() {
    if child().is_some() {
        return plan_row();
    }
    let (repository, base) = fixture("malformed-inventory");
    let text = repository.commit(&[
        ("verification/verus/inventory.json", "not json"),
        ("crates/plain.rs", "edited\n"),
    ]);
    let again = repository.commit(&[("crates/plain.rs", "edited again\n")]);
    repository.git(&["checkout", "-q", "-b", "other", &base]);
    let list = repository.commit(&[("verification/verus/inventory.json", "[]")]);
    let later = repository.commit(&[("crates/plain.rs", "again\n")]);
    let every = [Check::SelectTests, Check::Admit, Check::Reconcile];
    let reconcile = [Check::Reconcile];
    assert_plan(
        &repository,
        &id(
            module_path!(),
            "a_malformed_verus_inventory_runs_reconciliation",
        ),
        &[(&text, &base), (&again, &text), (&later, &list)],
        &[(&text, &every), (&again, &reconcile), (&later, &reconcile)],
    );
}

/// `plan_row` is the child of a row that [`assert_plan`] starts: it plans the lines of `ROW_LINES` and
/// compares the plan's checks with `ROW_EXPECTED`.
pub fn plan_row() {
    let row = child().expect("the row's child reads its values");
    let lines: Vec<OsString> = row
        .get("LINES")
        .split(';')
        .map(|pair| {
            let (local, remote) = pair.split_once(' ').expect("a pair is two commits");
            line(local, remote)
        })
        .collect();
    assert_eq!(
        format!("{:?}", checks(&planned(&lines))),
        row.get("EXPECTED")
    );
}

/// `assert_plan` starts the child of the row `id`, which plans `lines` of (local, remote) in the repository
/// and fails unless each tip gets the checks of `expected`, in that order.
pub fn assert_plan(
    repository: &Repository,
    id: &str,
    lines: &[(&str, &str)],
    expected: &[(&str, &[Check])],
) {
    let lines: Vec<String> = lines
        .iter()
        .map(|(local, remote)| format!("{local} {remote}"))
        .collect();
    let expected: Vec<(String, Vec<Check>)> = expected
        .iter()
        .map(|(tip, checks)| ((*tip).to_owned(), checks.to_vec()))
        .collect();
    repository.in_child(
        id,
        &[
            ("LINES", &lines.join(";")),
            ("EXPECTED", &format!("{expected:?}")),
        ],
    );
}

/// A line with no comparison base gives its note before the read of its pushed commits, so the note stands
/// when that read fails and the line ends with the read's Git error.
#[test]
fn an_unreadable_history_without_origin_main_still_notes_the_skipped_scan() {
    if let Some(row) = child() {
        let head = row.get("HEAD");
        let mut plan = Plan::new("origin".as_ref(), || Ok(())).expect("the plan starts");
        let mut note = None;
        let error = plan
            .line(&line(&head, ZERO), |skipped| {
                note = Some(skipped.to_string())
            })
            .expect_err("the history cannot be read");
        assert!(
            matches!(&error, Failure::Git(_)) && error.to_string().starts_with("git rev-list "),
            "{error}"
        );
        assert_eq!(
            note,
            Some(format!(
                "{}: no comparison base; weakened-test scan skipped",
                &head[..12]
            ))
        );
        assert!(plan.scans().is_empty() && plan.checks().is_empty());
        assert_eq!(
            plan.guard().expect("a plan with no line reads nothing"),
            Vec::<String>::new()
        );
        return;
    }
    let (repository, base) = fixture("unreadable-history");
    let head = repository.commit(&[("crates/plain.rs", "edited\n")]);
    repository.git(&["update-ref", "-d", "refs/remotes/origin/main"]);
    let tree = repository.git(&["rev-parse", &format!("{base}^{{tree}}")]);
    let object = repository
        .top
        .join(".git/objects")
        .join(&tree[..2])
        .join(&tree[2..]);
    std::fs::remove_file(object).expect("the base's tree is a loose object");
    repository.in_child(
        &id(
            module_path!(),
            "an_unreadable_history_without_origin_main_still_notes_the_skipped_scan",
        ),
        &[("HEAD", &head)],
    );
}

/// A 64-digit id of zeros is no deletion, which only the 40-digit one is: the line reads on and ends with
/// the error of the diff against a commit the clone lacks.
#[test]
fn a_sha256_null_id_is_read_as_a_commit() {
    if let Some(row) = child() {
        let mut plan = Plan::new("origin".as_ref(), || Ok(())).expect("the plan starts");
        let error = plan
            .line(&line(&"0".repeat(64), &row.get("BASE")), |_| {})
            .expect_err("the diff fails");
        assert!(error.to_string().starts_with("git diff "), "{error}");
        return;
    }
    let (repository, base) = fixture("long-null");
    repository.in_child(
        &id(module_path!(), "a_sha256_null_id_is_read_as_a_commit"),
        &[("BASE", &base)],
    );
}

/// The probe for `origin/main` lists refs under that name and the merge base resolves the short name: a
/// local branch named `origin/main` at the tip makes the tip its own base, and a clone that holds only a
/// ref under `refs/remotes/origin/main/` ends with the merge base's error.
#[test]
fn the_origin_main_probe_and_the_merge_base_read_the_name_differently() {
    if let Some(row) = child() {
        let head = row.get("HEAD");
        if row.get("CASE") == "branch" {
            let plan = planned(&[line(&head, ZERO)]);
            assert_eq!(
                (checks(&plan), scans(&plan)),
                (vec![], vec![(head.clone(), head)])
            );
        } else {
            let mut plan = Plan::new("origin".as_ref(), || Ok(())).expect("the plan starts");
            let error = plan
                .line(&line(&head, ZERO), |_| {})
                .expect_err("the merge base fails");
            assert!(
                error.to_string().starts_with("git merge-base origin/main "),
                "{error}"
            );
        }
        return;
    }
    let test = id(
        module_path!(),
        "the_origin_main_probe_and_the_merge_base_read_the_name_differently",
    );
    let (branch, _) = fixture("origin-main-branch");
    let head = branch.commit(&[("crates/v.rs", "edited\n")]);
    branch.git(&["branch", "origin/main", &head]);
    branch.in_child(&test, &[("CASE", "branch"), ("HEAD", &head)]);
    let (nested, base) = fixture("origin-main-nested");
    let head = nested.commit(&[("crates/v.rs", "edited\n")]);
    nested.git(&["update-ref", "-d", "refs/remotes/origin/main"]);
    nested.git(&["update-ref", "refs/remotes/origin/main/child", &base]);
    nested.in_child(&test, &[("CASE", "nested"), ("HEAD", &head)]);
}

/// The presence of a self-test is read only where an input of it changed and none of its own scripts
/// did: an unrelated edit at a tip that holds both self-tests asks Git for the replay and for neither.
#[test]
fn an_unrelated_edit_reads_no_self_test_presence() {
    if let Some(row) = child() {
        let (base, head) = (row.get("BASE"), row.get("HEAD"));
        let plan = planned(&[line(&head, &base)]);
        assert_eq!(checks(&plan), vec![]);
        return;
    }
    let (mut repository, _) = fixture("presence-reads");
    let base = repository.commit(&[
        ("scripts/test-host-stop-controller.py", STUB),
        ("scripts/test-gameday-judge.py", STUB),
    ]);
    let head = repository.commit(&[("crates/plain.rs", "edited\n")]);
    let trace = repository.top.join("../trace");
    repository.set(
        "GIT_TRACE",
        trace.to_str().expect("the scratch path is UTF-8"),
    );
    repository.in_child(
        &id(
            module_path!(),
            "an_unrelated_edit_reads_no_self_test_presence",
        ),
        &[("BASE", &base), ("HEAD", &head)],
    );
    let traced = std::fs::read_to_string(&trace).expect("the trace reads");
    let lookups: Vec<&str> = traced
        .lines()
        .filter(|line| line.contains("cat-file") && line.contains(" -e "))
        .collect();
    assert!(
        lookups
            .iter()
            .any(|line| line.contains("scripts/chaos-receipt-replay.py")),
        "{traced}"
    );
    assert!(
        !lookups
            .iter()
            .any(|line| line.contains("test-host-stop-controller.py")
                || line.contains("test-gameday-judge.py")),
        "{traced}"
    );
}

/// A ref line's local field reaches Git as an argument of its own, so a field shaped as an option is read
/// as one: `--output=<file>` over a known remote commit plans the line and leaves the file truncated by
/// the history read, with no check.
#[test]
fn a_local_field_shaped_as_an_option_reaches_git_as_one() {
    if let Some(row) = child() {
        let local = format!("--output={}", row.get("VICTIM"));
        let plan = planned(&[line(&local, &row.get("BASE"))]);
        assert_eq!(checks(&plan), vec![]);
        return;
    }
    let (repository, base) = fixture("option-field");
    let victim = repository.top.join("../victim");
    std::fs::File::create_new(&victim)
        .and_then(|mut file| std::io::Write::write_all(&mut file, b"kept\n"))
        .expect("the file is made");
    repository.in_child(
        &id(
            module_path!(),
            "a_local_field_shaped_as_an_option_reaches_git_as_one",
        ),
        &[
            ("BASE", &base),
            (
                "VICTIM",
                victim.to_str().expect("the scratch path is UTF-8"),
            ),
        ],
    );
    assert_eq!(std::fs::read(&victim).expect("the file reads"), b"");
}
