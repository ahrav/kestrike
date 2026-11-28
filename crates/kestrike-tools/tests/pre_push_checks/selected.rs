//! The hook's cases of which checks a push runs, started through the tool: each pushes ref lines over the
//! self-test's repository and asserts the stand-in's log, the exit code and the failure lines.

use std::fs;

use super::push::{Fixture, STUB, ZERO};

const SELECTION: [&str; 2] = ["test-select-tests.py", "verify-receipts.py admit"];
const RECONCILE: &str = "judge-verus.py reconcile";
const EVERY: [&str; 3] = [
    "test-select-tests.py",
    "verify-receipts.py admit",
    RECONCILE,
];

fn strings(lines: &[&str]) -> Vec<String> {
    lines.iter().map(|line| (*line).to_owned()).collect()
}

/// A changed test inventory runs the selection and the admission, and the selection's failure fails the
/// push with its command.
#[test]
fn an_inventory_change_runs_selection_checks_and_a_failure_blocks() {
    let fx = Fixture::new();
    let head = fx.commit(&[("scripts/test-inventory.json", r#"{"rows": []}"#)]);
    let run = fx.push_with(&[(&head, &fx.base)], &[("test_select_tests", 3)]);
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    assert_eq!(fx.ran(), strings(&SELECTION));
    assert!(
        run.stderr
            .contains("failed: python3 scripts/test-select-tests.py"),
        "{}",
        run.stderr
    );
    assert!(
        run.stdout.is_empty(),
        "the tool writes its lines to standard error: {}",
        run.stdout
    );
}

/// A file under `verification/intake/`, a line feed in its name included, runs the selection checks, and a
/// sibling directory whose name only starts the same runs none.
#[test]
fn an_intake_row_change_runs_selection_checks() {
    let fx = Fixture::new();
    for path in [
        "verification/intake/dsw-4.json",
        "verification/intake/exclusions/old/notes.md",
        "verification/intake/old\nrow.md",
    ] {
        fx.clear();
        fx.git(&["checkout", "-q", "--detach", &fx.base]);
        let head = fx.commit(&[(path, "{}\n")]);
        let run = fx.push(&[(&head, &fx.base)]);
        assert_eq!(run.code, Some(0), "{path:?}: {}", run.stderr);
        assert_eq!(fx.ran(), strings(&SELECTION), "{path:?}");
    }
    fx.clear();
    fx.git(&["checkout", "-q", "--detach", &fx.base]);
    let head = fx.commit(&[("verification/intake-old/dsw-4.json", "{}\n")]);
    assert_eq!(fx.push(&[(&head, &fx.base)]).code, Some(0));
    assert!(fx.ran().is_empty());
}

/// A change to a source the Verus inventory names runs reconciliation.
#[test]
fn a_verus_source_change_runs_reconciliation() {
    let fx = Fixture::new();
    let head = fx.commit(&[("crates/v.rs", "edited\n")]);
    assert_eq!(fx.push(&[(&head, &fx.base)]).code, Some(0));
    assert_eq!(fx.ran(), [RECONCILE]);
}

/// A change to a file no check reads runs no check.
#[test]
fn an_unrelated_change_runs_no_check() {
    let fx = Fixture::new();
    let head = fx.commit(&[("crates/plain.rs", "edited\n")]);
    assert_eq!(fx.push(&[(&head, &fx.base)]).code, Some(0));
    assert!(fx.ran().is_empty());
}

/// A new branch compares its tip with its merge base with `origin/main`.
#[test]
fn a_new_branch_compares_against_origin_main() {
    let fx = Fixture::new();
    let head = fx.commit(&[("crates/v.rs", "edited\n")]);
    assert_eq!(fx.push(&[(&head, ZERO)]).code, Some(0));
    assert_eq!(fx.ran(), [RECONCILE]);
}

/// A new branch in a clone without `origin/main` runs every check its tip holds.
#[test]
fn a_new_branch_without_origin_main_runs_every_check() {
    let fx = Fixture::new();
    fx.git(&["update-ref", "-d", "refs/remotes/origin/main"]);
    let head = fx.commit(&[("crates/plain.rs", "edited\n")]);
    assert_eq!(fx.push(&[(&head, ZERO)]).code, Some(0));
    assert_eq!(fx.ran(), strings(&EVERY));
}

const REGISTRY: &str = "verification/models/links.json";
const LINKS: [&str; 1] = ["model-links.py check"];
const LINKS_BOTH: [&str; 2] = ["model-links.py check", "test-model-links.py"];

/// `links` commits a links registry that enrolls `tla/M.tla` and cites `crates/cited.rs`, with the check
/// and its self-test as stubs, and returns the commit.
fn links(fx: &Fixture) -> String {
    let registry = r#"{"models": [{"path": "tla/M.tla", "kinds": ["action"]}], "rows": [{"model": "tla/M.tla", "kind": "action", "name": "A", "note": "n", "anchors": [{"path": "crates/cited.rs", "quote": "fn a("}]}, {"model": "tla/M.tla", "kind": "action", "name": "B", "note": "n", "abstraction": "no code site"}]}"#;
    fx.commit(&[
        (REGISTRY, registry),
        ("tla/M.tla", "m\n"),
        ("tla/Other.tla", "o\n"),
        ("crates/cited.rs", "fn a() {}\n"),
        ("scripts/model-links.py", STUB),
        ("scripts/test-model-links.py", STUB),
    ])
}

/// A change to a file a registry row cites runs the links check, and its failure fails the push.
#[test]
fn a_cited_file_change_runs_the_links_check_and_a_failure_blocks() {
    let fx = Fixture::new();
    let base = links(&fx);
    let head = fx.commit(&[("crates/cited.rs", "fn a() { 1; }\n")]);
    let run = fx.push_with(&[(&head, &base)], &[("model_links", 2)]);
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    assert_eq!(fx.ran(), LINKS);
    assert!(
        run.stderr
            .contains("failed: python3 scripts/model-links.py check"),
        "{}",
        run.stderr
    );
}

/// Each input of the links check runs it, a script it loads also its self-test, and a model or file the
/// registry names nowhere runs neither.
#[test]
fn each_links_input_runs_its_checks() {
    let fx = Fixture::new();
    let base = links(&fx);
    let both_and_selection: Vec<String> = strings(&SELECTION)
        .into_iter()
        .chain(strings(&LINKS_BOTH))
        .collect();
    let cases: [(&str, Vec<String>); 9] = [
        (REGISTRY, strings(&LINKS)),
        ("tla/M.tla", strings(&LINKS)),
        ("tla/Other.tla", vec![]),
        ("crates/plain.rs", vec![]),
        ("scripts/model-links.py", strings(&LINKS_BOTH)),
        ("scripts/test-model-links.py", strings(&LINKS_BOTH)),
        ("tla/check.py", both_and_selection.clone()),
        ("scripts/judge-verus.py", both_and_selection.clone()),
        ("scripts/judge-rc11.py", both_and_selection),
    ];
    for (path, expected) in cases {
        fx.clear();
        fx.git(&["checkout", "-q", "--detach", &base]);
        let text = fs::read_to_string(fx.repo.join(path)).unwrap_or_default();
        let head = fx.commit(&[(path, &format!("{text}\n"))]);
        let run = fx.push(&[(&head, &base)]);
        assert_eq!(run.code, Some(0), "{path}: {}", run.stderr);
        assert_eq!(fx.ran(), expected, "{path}");
    }
}

/// A registry that is not JSON, not an object, or whose model lacks its path runs the links check.
#[test]
fn an_unreadable_links_registry_runs_the_links_check() {
    let fx = Fixture::new();
    let base = links(&fx);
    for content in ["not json", "[]", r#"{"models": [{}], "rows": []}"#] {
        fx.clear();
        fx.git(&["checkout", "-q", "--detach", &base]);
        let remote = fx.commit(&[(REGISTRY, content)]);
        let head = fx.commit(&[("crates/plain.rs", "edited\n")]);
        let run = fx.push(&[(&head, &remote)]);
        assert_eq!(run.code, Some(0), "{content}: {}", run.stderr);
        assert_eq!(fx.ran(), LINKS, "{content}");
    }
}

/// A change to the links check under a registry that is not JSON runs the check and its self-test.
#[test]
fn a_script_change_under_an_unreadable_links_registry_runs_the_self_test() {
    let fx = Fixture::new();
    links(&fx);
    let base = fx.commit(&[(REGISTRY, "not json")]);
    let head = fx.commit(&[("scripts/model-links.py", &format!("{STUB}\n"))]);
    assert_eq!(fx.push(&[(&head, &base)]).code, Some(0));
    assert_eq!(fx.ran(), LINKS_BOTH);
}

/// A push that deletes or renames the registry runs the links check of a tip that keeps the check, and one
/// that removes the check with the registry runs nothing.
#[test]
fn a_push_that_removes_the_links_registry_runs_the_links_check_of_a_tip_that_keeps_it() {
    let fx = Fixture::new();
    let base = links(&fx);
    let removals: [(&[&str], Vec<String>); 3] = [
        (&["rm", "-q", "--", REGISTRY], strings(&LINKS)),
        (
            &["mv", REGISTRY, "verification/models/old.json"],
            strings(&LINKS),
        ),
        (
            &[
                "rm",
                "-q",
                "--",
                REGISTRY,
                "scripts/model-links.py",
                "scripts/test-model-links.py",
            ],
            vec![],
        ),
    ];
    for (removal, expected) in removals {
        fx.clear();
        fx.git(&["checkout", "-q", "--detach", &base]);
        fx.git(removal);
        fx.git(&["commit", "-q", "-m", "remove"]);
        let head = fx.git(&["rev-parse", "HEAD"]);
        let run = fx.push(&[(&head, &base)]);
        assert_eq!(run.code, Some(0), "{removal:?}: {}", run.stderr);
        assert_eq!(fx.ran(), expected, "{removal:?}");
    }
}

/// Without `origin/main`, a tip that holds the registry runs every check and both links checks.
#[test]
fn a_new_branch_without_origin_main_runs_the_links_checks_of_a_tip_with_a_registry() {
    let fx = Fixture::new();
    fx.git(&["update-ref", "-d", "refs/remotes/origin/main"]);
    let head = links(&fx);
    assert_eq!(fx.push(&[(&head, ZERO)]).code, Some(0));
    let expected: Vec<String> = strings(&EVERY)
        .into_iter()
        .chain(strings(&LINKS_BOTH))
        .collect();
    assert_eq!(fx.ran(), expected);
}

/// Without `origin/main`, a tip that keeps the links check without its registry runs both links checks.
#[test]
fn a_new_branch_without_origin_main_runs_the_links_checks_of_a_tip_that_keeps_only_the_check() {
    let fx = Fixture::new();
    fx.git(&["update-ref", "-d", "refs/remotes/origin/main"]);
    links(&fx);
    fx.git(&["rm", "-q", "--", REGISTRY]);
    fx.git(&["commit", "-q", "-m", "remove"]);
    let head = fx.git(&["rev-parse", "HEAD"]);
    assert_eq!(fx.push(&[(&head, ZERO)]).code, Some(0));
    let expected: Vec<String> = strings(&EVERY)
        .into_iter()
        .chain(strings(&LINKS_BOTH))
        .collect();
    assert_eq!(fx.ran(), expected);
}

/// The changed files are counted from the remote commit, so a change the remote already holds runs no check.
#[test]
fn the_diff_starts_at_the_remote_commit() {
    let fx = Fixture::new();
    let first = fx.commit(&[("scripts/test-inventory.json", r#"{"rows": []}"#)]);
    let head = fx.commit(&[("crates/plain.rs", "edited\n")]);
    assert_eq!(fx.push(&[(&head, &first)]).code, Some(0));
    assert!(fx.ran().is_empty());
}

/// A change in an earlier pushed commit selects its checks though the tip changes another file.
#[test]
fn the_diff_covers_every_pushed_commit_not_only_the_tip() {
    let fx = Fixture::new();
    fx.commit(&[("scripts/test-inventory.json", r#"{"rows": []}"#)]);
    let head = fx.commit(&[("crates/plain.rs", "edited\n")]);
    assert_eq!(fx.push(&[(&head, &fx.base)]).code, Some(0));
    assert_eq!(fx.ran(), strings(&SELECTION));
}

/// A remote commit this clone lacks compares the tip with its merge base with `origin/main`.
#[test]
fn an_unknown_remote_commit_compares_against_origin_main() {
    let fx = Fixture::new();
    let head = fx.commit(&[("crates/v.rs", "edited\n")]);
    assert_eq!(fx.push(&[(&head, &"2".repeat(40))]).code, Some(0));
    assert_eq!(fx.ran(), [RECONCILE]);
}

/// `ran_selection` pushes a commit of `crates/plain.rs` holding `text` over the base and asserts that the
/// selection checks alone ran.
fn ran_selection(text: &str) {
    let fx = Fixture::new();
    let head = fx.commit(&[("crates/plain.rs", text)]);
    let run = fx.push(&[(&head, &fx.base)]);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert_eq!(fx.ran(), strings(&SELECTION));
}

/// An added `#[ignore]` attribute runs the selection checks.
#[test]
fn an_ignore_attribute_change_runs_selection_checks() {
    ran_selection("#[ignore = \"slow\"]\nfn t() {}\n");
}

/// A new judge script runs the selection checks.
#[test]
fn a_judge_script_change_runs_selection_checks() {
    let fx = Fixture::new();
    let head = fx.commit(&[("scripts/judge-kani.py", "x = 1\n")]);
    assert_eq!(fx.push(&[(&head, &fx.base)]).code, Some(0));
    assert_eq!(fx.ran(), strings(&SELECTION));
}

/// Each input of the admission runs the selection checks, and the Verus inventory reconciliation too.
#[test]
fn each_admission_input_runs_its_checks() {
    let fx = Fixture::new();
    let with_reconcile: Vec<String> = strings(&SELECTION)
        .into_iter()
        .chain([RECONCILE.to_owned()])
        .collect();
    let cases: [(&str, &str, Vec<String>); 6] = [
        (
            "scripts/classify-atomics.py",
            "x = 1\n",
            strings(&SELECTION),
        ),
        ("tla/check.py", "x = 1\n", strings(&SELECTION)),
        ("quint/check.py", "x = 1\n", strings(&SELECTION)),
        (
            "verification/atomics/census.json",
            r#"{"surfaces": []}"#,
            strings(&SELECTION),
        ),
        (
            "verification/control-less.json",
            "[]\n",
            strings(&SELECTION),
        ),
        (
            "verification/verus/inventory.json",
            r#"{"sources": {"crates/v.rs": "e"}}"#,
            with_reconcile,
        ),
    ];
    for (path, content, expected) in cases {
        fx.clear();
        fx.git(&["checkout", "-q", "--detach", &fx.base]);
        let head = fx.commit(&[(path, content)]);
        let run = fx.push(&[(&head, &fx.base)]);
        assert_eq!(run.code, Some(0), "{path}: {}", run.stderr);
        assert_eq!(fx.ran(), expected, "{path}");
    }
}

/// `ran_after` pushes `crates/plain.rs` from `before` to `after` and asserts the checks that ran.
fn ran_after(before: &str, after: &str, expected: &[&str]) {
    let fx = Fixture::new();
    let ignored = fx.commit(&[("crates/plain.rs", before)]);
    let head = fx.commit(&[("crates/plain.rs", after)]);
    let run = fx.push(&[(&head, &ignored)]);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert_eq!(fx.ran(), strings(expected));
}

/// Renaming an ignored test changes the span from its attribute to its fn name and runs the selection.
#[test]
fn renaming_an_ignored_test_runs_selection_checks() {
    ran_after(
        "#[test]\n#[ignore = \"slow\"]\nfn churn() {}\n",
        "#[test]\n#[ignore = \"slow\"]\nfn churn_renamed() {}\n",
        &SELECTION,
    );
}

/// The span skips another attribute between the ignore and the fn, so a string in it stands for no name.
#[test]
fn renaming_an_ignored_test_behind_another_attribute_runs_selection_checks() {
    let attributes = "#[ignore = \"slow\"]\n#[should_panic(expected = \"fn sentinel\")]\n";
    ran_after(
        &format!("{attributes}fn churn() {{}}\n"),
        &format!("{attributes}fn churn_renamed() {{}}\n"),
        &SELECTION,
    );
}

/// Deleting a file that holds an ignored test runs the selection checks.
#[test]
fn deleting_a_file_with_an_ignored_test_runs_selection_checks() {
    let fx = Fixture::new();
    let ignored = fx.commit(&[("crates/plain.rs", "#[ignore = \"slow\"]\nfn churn() {}\n")]);
    fx.git(&["rm", "-q", "crates/plain.rs"]);
    fx.git(&["commit", "-q", "-m", "delete"]);
    let head = fx.git(&["rev-parse", "HEAD"]);
    assert_eq!(fx.push(&[(&head, &ignored)]).code, Some(0));
    assert_eq!(fx.ran(), strings(&SELECTION));
}

/// An edit beside an ignored test leaves every span equal and runs no check.
#[test]
fn an_edit_beside_an_ignored_test_runs_no_check() {
    ran_after(
        "#[ignore = \"slow\"]\nfn churn() {}\n",
        "fn helper() {}\n\n#[ignore = \"slow\"]\nfn churn() { helper() }\n",
        &[],
    );
}

/// An inventory that is not JSON runs reconciliation on any change, and one that is no object too.
#[test]
fn a_malformed_verus_inventory_runs_reconciliation() {
    let fx = Fixture::new();
    let head = fx.commit(&[
        ("verification/verus/inventory.json", "not json"),
        ("crates/plain.rs", "edited\n"),
    ]);
    assert_eq!(fx.push(&[(&head, &fx.base)]).code, Some(0));
    assert_eq!(fx.ran(), strings(&EVERY));
    fx.clear();
    fx.git(&["checkout", "-q", "-b", "other", &fx.base]);
    let remote = fx.commit(&[("verification/verus/inventory.json", "[]")]);
    let later = fx.commit(&[("crates/plain.rs", "again\n")]);
    assert_eq!(fx.push(&[(&later, &remote)]).code, Some(0));
    assert_eq!(fx.ran(), [RECONCILE]);
}

/// A tip pushed on several lines runs each of its checks once.
#[test]
fn every_pushed_ref_is_checked_once_per_commit() {
    let fx = Fixture::new();
    let plain = fx.commit(&[("crates/plain.rs", "edited\n")]);
    let head = fx.commit(&[("crates/v.rs", "edited\n")]);
    let run = fx.push(&[(&plain, &fx.base), (&head, &plain), (&head, &plain)]);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert_eq!(fx.ran(), [RECONCILE]);
}

/// One commit pushed to two refs runs the union of the two lines' checks.
#[test]
fn one_commit_pushed_to_two_refs_runs_the_union_of_their_checks() {
    let fx = Fixture::new();
    let head = fx.commit(&[("scripts/test-inventory.json", r#"{"rows": []}"#)]);
    let run = fx.push(&[(&head, &head), (&head, &fx.base)]);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert_eq!(fx.ran(), strings(&SELECTION));
}

/// An added ignore under `cfg_attr` for Miri runs the selection checks.
#[test]
fn a_miri_ignore_change_runs_selection_checks() {
    // The split keeps `cfg_attr(` and `miri` apart in this file's text, which the checkout's count of Miri
    // ignore attributes reads.
    ran_selection(concat!(
        "#[cfg_attr(",
        "miri, ignore = \"slow\")]\nfn t() {}\n"
    ));
}

/// An ignore under a nested predicate runs the selection checks.
#[test]
fn a_nested_predicate_ignore_change_runs_selection_checks() {
    ran_selection("#[cfg_attr(not(miri), ignore = \"slow\")]\nfn t() {}\n");
}

/// A `cfg_attr` ignore across lines runs the selection checks.
#[test]
fn a_multiline_miri_ignore_change_runs_selection_checks() {
    ran_selection("#[cfg_attr(\n    miri,\n    ignore = \"slow\"\n)]\nfn t() {}\n");
}

/// Ignores with no fn after them span to the end of the file, so a change after them runs the selection.
#[test]
fn ignores_with_no_fn_after_them_select_the_checks_when_their_suffix_changes() {
    ran_after(
        "#[ignore]\n#[ignore]\nconst N: u8 = 1;\n",
        "#[ignore]\n#[ignore]\nconst N: u8 = 2;\n",
        &SELECTION,
    );
}
