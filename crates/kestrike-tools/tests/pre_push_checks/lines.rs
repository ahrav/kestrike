//! Rows of a ref line's states: each reads the fixture repository of the hook's self-test in a child and
//! asserts the plan's checks, scans or failure.

use std::ffi::OsString;

use kestrike_tools::hook::{Check, Failure, Plan};

use super::repository::{Repository, STUB, ZERO, child, id};

/// `fixture` is the self-test's base: the selection, admission and reconciliation scripts as stubs, a
/// Verus inventory that names `crates/v.rs`, a plain Rust file and the test inventory, with
/// `origin/main` at that commit.
pub fn fixture(name: &str) -> (Repository, String) {
    based(Repository::new(name))
}

/// `based` commits the self-test's base in `repository` and puts `origin/main` at it.
fn based(repository: Repository) -> (Repository, String) {
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

/// A ref line's local and remote fields are full object ids of 40 or 64 hexadecimal digits. A line with
/// another field there ends as malformed with no Git read started and leaves the plan as it stood, also
/// where the local field is the null id of a deletion: a field shaped as an option, an id one digit short
/// or long of either length, a digit outside hexadecimal, a ref name and bytes outside UTF-8 are refused
/// alike. The control is a line of two full ids, which starts Git reads; and the option that a refused
/// field holds creates its file once the test itself gives it to Git's history read.
#[test]
fn a_field_that_is_no_full_object_id_is_refused_before_any_git_read() {
    use std::os::unix::ffi::OsStringExt;
    if let Some(row) = child() {
        let base = row.get("BASE");
        let mut plan = Plan::new("origin".as_ref(), || Ok(())).expect("the plan starts");
        let started = traced();
        assert_eq!(started, 1, "the plan's start lists the remotes");
        for field in [
            "--output=../made",
            "--output=../kept",
            "-h",
            &base[..39],
            &format!("{base}0"),
            &"1".repeat(63),
            &"1".repeat(65),
            &format!("{}g", &base[..39]),
            "HEAD",
            "refs/heads/main",
        ] {
            for refused in [line(field, &base), line(&base, field), line(ZERO, field)] {
                let shown = refused.to_str().expect("the line is UTF-8").to_owned();
                let error = plan
                    .line(&refused, |_| panic!("{shown}: a refused line has no note"))
                    .expect_err("the field is no object id");
                assert!(matches!(error, Failure::Malformed(_)), "{shown}: {error:?}");
                assert_eq!(error.to_string(), format!("malformed ref line: '{shown}'"));
                assert_eq!(
                    Plan::object_ids(&refused)
                        .expect_err("the field is no object id")
                        .to_string(),
                    error.to_string()
                );
            }
        }
        let mut bytes = b"refs/heads/x ".to_vec();
        bytes.extend([0xff; 40]);
        bytes.extend(format!(" refs/heads/x {base}").bytes());
        let error = plan
            .line(&OsString::from_vec(bytes), |_| {
                panic!("a refused line has no note")
            })
            .expect_err("the field is not UTF-8");
        assert!(matches!(error, Failure::Malformed(_)), "{error:?}");
        assert_eq!(traced(), started, "a refused line starts a Git read");
        assert_eq!((checks(&plan), scans(&plan)), (vec![], vec![]));
        assert_eq!(plan.guard().expect("the guard reads"), Vec::<String>::new());
        assert_eq!(traced(), started, "an empty plan's guard starts a Git read");
        plan.line(&line(&base, &base), |_| panic!("a based line has no note"))
            .expect("a line of two full ids reads");
        assert!(traced() > started, "a line of two full ids starts no read");
        return;
    }
    let (repository, base) = fixture("option-field");
    let (made, kept) = (
        repository.top.join("../made"),
        repository.top.join("../kept"),
    );
    std::fs::File::create_new(&kept)
        .and_then(|mut file| std::io::Write::write_all(&mut file, b"kept\n"))
        .expect("the file is made");
    let trace = repository.top.join("../trace");
    repository.in_child_with(
        &repository.top,
        &id(
            module_path!(),
            "a_field_that_is_no_full_object_id_is_refused_before_any_git_read",
        ),
        &[("BASE", &base)],
        &[("GIT_TRACE", trace.as_os_str())],
    );
    assert!(!made.exists(), "a refused field creates a file");
    assert_eq!(std::fs::read(&kept).expect("the file reads"), b"kept\n");
    repository.git(&["rev-list", "--full-history", "--output=../made", &base]);
    assert!(made.exists(), "the option creates no file in Git's hands");
}

/// `lettered` commits edits of `file` until a commit's id holds a letter, so its spelling in capitals
/// differs from the one Git writes, and returns that commit.
fn lettered(repository: &Repository, file: &str) -> String {
    (0..64)
        .map(|edit| repository.commit(&[(file, &format!("edit {edit}\n"))]))
        .find(|commit| commit.bytes().any(|byte| byte.is_ascii_lowercase()))
        .expect("a commit id holds a letter")
}

/// A line of full object ids is planned in a repository of either object format: 40 digits where the ids
/// are SHA-1 and 64 where they are SHA-256, over a remote commit the clone holds and, as Git writes a new
/// branch, over the null id of that length. An id in capitals is read as the id Git writes, in either
/// field: the line plans as its lowercase spelling does, and the two spellings of one line plan one set
/// of checks and one scan between them.
#[test]
fn a_line_of_full_object_ids_of_either_length_is_planned() {
    let test = id(
        module_path!(),
        "a_line_of_full_object_ids_of_either_length_is_planned",
    );
    if let Some(row) = child() {
        let (held, head) = (row.get("HELD"), row.get("HEAD"));
        let digits: usize = row.get("DIGITS").parse().expect("the row passes a count");
        assert_eq!((held.len(), head.len()), (digits, digits));
        let (capital_held, capital_head) = (held.to_uppercase(), head.to_uppercase());
        assert!(capital_held != held && capital_head != head);
        let expected = (
            vec![(head.clone(), vec![Check::Reconcile])],
            vec![(held.clone(), head.clone())],
        );
        for lines in [
            vec![line(&head, &held)],
            vec![line(&capital_head, &held)],
            vec![line(&head, &capital_held)],
            vec![line(&capital_head, &capital_held)],
            vec![line(&head, &held), line(&capital_head, &capital_held)],
        ] {
            let plan = planned(&lines);
            assert_eq!((checks(&plan), scans(&plan)), expected, "{lines:?}");
        }
        let plan = planned(&[line(&head, &"0".repeat(digits))]);
        assert_eq!(
            (checks(&plan), scans(&plan)),
            (
                vec![(head.clone(), vec![Check::Reconcile])],
                vec![(row.get("BASE"), head.clone())]
            )
        );
        return;
    }
    for (format, digits) in [("sha1", "40"), ("sha256", "64")] {
        let (repository, base) = based(Repository::of(&format!("ids-{format}"), format));
        let held = lettered(&repository, "crates/plain.rs");
        let head = lettered(&repository, "crates/v.rs");
        repository.in_child(
            &test,
            &[
                ("BASE", &base),
                ("HELD", &held),
                ("HEAD", &head),
                ("DIGITS", digits),
            ],
        );
    }
}

/// The number of probe calls of the running plan, and the call that reports `Err`, 0 for none.
static CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static FAILING: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
/// The number of Git commands the trace held when the failing call ran.
static TRACED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
/// The number of skipped-scan notes the running plan has given.
static NOTES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// `traced` counts the Git commands that `GIT_TRACE` has logged so far.
fn traced() -> usize {
    let trace = std::env::var_os("GIT_TRACE").expect("the row traces Git");
    std::fs::read_to_string(trace)
        .unwrap_or_default()
        .lines()
        .filter(|line| line.contains("trace: built-in: git"))
        .count()
}

/// `counting` reports `Err(143)` on the call [`FAILING`] names and `Ok` on every other call. While no
/// call is to fail, it requires the trace to hold one Git command for each call so far, less one for each
/// note given: every call but the one after a note follows a Git command of its own.
fn counting() -> Result<(), u8> {
    use std::sync::atomic::Ordering;
    let call = CALLS.fetch_add(1, Ordering::SeqCst) + 1;
    let failing = FAILING.load(Ordering::SeqCst);
    if failing == 0 {
        assert_eq!(
            traced(),
            call - NOTES.load(Ordering::SeqCst),
            "probe call {call} follows one traced Git command of its own, or a note"
        );
    }
    if call == failing {
        TRACED.store(traced(), Ordering::SeqCst);
        return Err(143);
    }
    Ok(())
}

/// `probed_plan` plans `lines` and then the guard with [`counting`], failing at call `failing`, and
/// returns the first error, with no note given after the failing call. [`NOTES`] counts its notes.
fn probed_plan(lines: &[OsString], failing: usize) -> Option<Failure> {
    use std::sync::atomic::Ordering;
    CALLS.store(0, Ordering::SeqCst);
    NOTES.store(0, Ordering::SeqCst);
    FAILING.store(failing, Ordering::SeqCst);
    let mut plan = match Plan::new("origin".as_ref(), counting) {
        Ok(plan) => plan,
        Err(failure) => return Some(failure),
    };
    for line in lines {
        let mut late = false;
        let planned = plan.line(line, |_| {
            NOTES.fetch_add(1, Ordering::SeqCst);
            late = failing != 0 && CALLS.load(Ordering::SeqCst) >= failing;
        });
        assert!(!late, "the note is given after the failing call");
        if let Err(failure) = planned {
            return Some(failure);
        }
    }
    plan.guard().err()
}

/// A probe that reports `Err` once any read of a plan returns ends the plan as [`Failure::Cancelled`]
/// with its code and starts no later Git read, for the reads this fixture's plan makes: a line with no
/// comparison base, a line whose remote commit the clone lacks so the merge base is read, a changed Rust
/// file whose ignore spans are read in a batch, and the guard's batch read of a chaos record the pushed
/// tip holds. In the plan with no failing call, each probe call finds one more Git command in the trace
/// than the call before it, but for the call that follows the skipped-scan note, which finds the same
/// count, and no Git command follows the last call. A Git read of this plan that the trace logs and no
/// probe follows therefore fails the row, and the loop over the calls reaches each of those reads.
#[test]
fn a_probe_that_reports_err_at_any_read_ends_the_plan_and_starts_no_later_read() {
    use std::sync::atomic::Ordering;
    if let Some(values) = child() {
        let lines = [
            line(&values.get("HEAD"), &"1".repeat(40)),
            line(&values.get("UNBASED"), ZERO),
        ];
        assert!(
            probed_plan(&lines, 0).is_none(),
            "the plan reads with no failing call"
        );
        let reads = CALLS.load(Ordering::SeqCst);
        assert!(reads > 8, "the plan reads {reads} times");
        let batches =
            std::fs::read_to_string(std::env::var_os("GIT_TRACE").expect("the row traces Git"))
                .expect("the trace reads")
                .lines()
                .filter(|line| line.contains("trace: built-in: git cat-file --batch"))
                .count();
        assert_eq!(
            batches, 2,
            "the ignore spans and the guard each read a batch"
        );
        assert_eq!(NOTES.load(Ordering::SeqCst), 1, "the unbased line is noted");
        assert_eq!(
            traced(),
            reads - 1,
            "a Git command follows the last probe call"
        );
        for failing in 1..=reads {
            let failure = probed_plan(&lines, failing);
            assert!(
                matches!(failure, Some(Failure::Cancelled(143))),
                "call {failing}: {failure:?}"
            );
            assert_eq!(
                traced(),
                TRACED.load(Ordering::SeqCst),
                "call {failing} is followed by a Git read"
            );
        }
        return;
    }
    let (repository, _) = fixture("probed");
    let head = repository.commit(&[
        ("crates/plain.rs", "#[test]\n#[ignore]\nfn t() {}\n"),
        ("chaos/runs/r/run.json", "{\"run\": 1}"),
    ]);
    let unbased = repository.git(&[
        "commit-tree",
        "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
        "-m",
        "an unrelated root",
    ]);
    let trace = repository.top.join("trace");
    repository.in_child_with(
        &repository.top,
        &id(
            module_path!(),
            "a_probe_that_reports_err_at_any_read_ends_the_plan_and_starts_no_later_read",
        ),
        &[("HEAD", &head), ("UNBASED", &unbased)],
        &[("GIT_TRACE", trace.as_os_str())],
    );
}

/// A signal recorded while the skipped-scan note is given ends the line before its next Git read: the
/// probe runs once the note returns.
#[test]
fn a_probe_after_the_skipped_scan_note_starts_no_later_read() {
    use std::sync::atomic::Ordering;
    if let Some(values) = child() {
        CALLS.store(0, Ordering::SeqCst);
        NOTES.store(0, Ordering::SeqCst);
        FAILING.store(0, Ordering::SeqCst);
        let mut plan = Plan::new("origin".as_ref(), counting).expect("the plan starts");
        let mut noted = None;
        let planned = plan.line(&line(&values.get("UNBASED"), ZERO), |_| {
            FAILING.store(CALLS.load(Ordering::SeqCst) + 1, Ordering::SeqCst);
            noted = Some(traced());
        });
        assert!(
            matches!(planned, Err(Failure::Cancelled(143))),
            "{planned:?}"
        );
        assert_eq!(noted, Some(traced()), "a Git read starts after the note");
        return;
    }
    let (repository, _) = fixture("noted");
    let unbased = repository.git(&[
        "commit-tree",
        "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
        "-m",
        "an unrelated root",
    ]);
    let trace = repository.top.join("trace");
    repository.in_child_with(
        &repository.top,
        &id(
            module_path!(),
            "a_probe_after_the_skipped_scan_note_starts_no_later_read",
        ),
        &[("UNBASED", &unbased)],
        &[("GIT_TRACE", trace.as_os_str())],
    );
}
