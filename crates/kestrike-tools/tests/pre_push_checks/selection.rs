//! Rows of the checks a plan selects from a tip's tree: the ignore spans of changed Rust files, the links
//! registry, the files a check asks the tip for, and the union of a tip's lines. Each reuses the input of
//! the hook case it is named for.

use kestrike_tools::hook::Check;

use super::guard::contract;
use super::lines::{assert_plan, fixture, plan_row};
use super::repository::{Repository, STUB, ZERO, child, id};

const SELECTION: [Check; 2] = [Check::SelectTests, Check::Admit];

/// `pair` commits `before` and then `after` on the fixture, plans the second over the first, and fails
/// unless the tip gets `expected`, or no check where `expected` is empty.
fn pair(
    name: &str,
    test: &str,
    before: &[(&str, &str)],
    after: &[(&str, &str)],
    expected: &[Check],
) {
    let (repository, _) = fixture(name);
    let base = repository.commit(before);
    let head = repository.commit(after);
    let planned: &[(&str, &[Check])] = if expected.is_empty() {
        &[]
    } else {
        &[(&head, expected)]
    };
    assert_plan(&repository, test, &[(&head, &base)], planned);
}

/// An added ignore attribute changes the file's spans and selects the selection checks.
#[test]
fn an_ignore_attribute_change_runs_selection_checks() {
    if child().is_some() {
        return plan_row();
    }
    pair(
        "ignore-added",
        &id(
            module_path!(),
            "an_ignore_attribute_change_runs_selection_checks",
        ),
        &[("crates/plain.rs", "fn t() {}\n")],
        &[("crates/plain.rs", "#[ignore = \"slow\"]\nfn t() {}\n")],
        &SELECTION,
    );
}

/// An edit beside an ignored test leaves each span equal and selects nothing.
#[test]
fn an_edit_beside_an_ignored_test_runs_no_check() {
    if child().is_some() {
        return plan_row();
    }
    pair(
        "edit-beside",
        &id(
            module_path!(),
            "an_edit_beside_an_ignored_test_runs_no_check",
        ),
        &[("crates/plain.rs", "#[ignore = \"slow\"]\nfn churn() {}\n")],
        &[(
            "crates/plain.rs",
            "fn helper() {}\n\n#[ignore = \"slow\"]\nfn churn() { helper() }\n",
        )],
        &[],
    );
}

/// A renamed ignored test behind a `should_panic` that holds `fn sentinel` changes its span.
#[test]
fn renaming_an_ignored_test_behind_another_attribute_runs_selection_checks() {
    if child().is_some() {
        return plan_row();
    }
    let attributes = "#[ignore = \"slow\"]\n#[should_panic(expected = \"fn sentinel\")]\n";
    pair(
        "rename-behind",
        &id(
            module_path!(),
            "renaming_an_ignored_test_behind_another_attribute_runs_selection_checks",
        ),
        &[("crates/plain.rs", &format!("{attributes}fn churn() {{}}\n"))],
        &[(
            "crates/plain.rs",
            &format!("{attributes}fn churn_renamed() {{}}\n"),
        )],
        &SELECTION,
    );
}

/// A deleted file reads as empty text at the tip, so its ignored test's span is gone.
#[test]
fn deleting_a_file_with_an_ignored_test_runs_selection_checks() {
    if child().is_some() {
        return plan_row();
    }
    let (repository, _) = fixture("delete-ignored");
    let base = repository.commit(&[("crates/plain.rs", "#[ignore = \"slow\"]\nfn churn() {}\n")]);
    repository.git(&["rm", "-q", "crates/plain.rs"]);
    let head = repository.commit(&[]);
    assert_plan(
        &repository,
        &id(
            module_path!(),
            "deleting_a_file_with_an_ignored_test_runs_selection_checks",
        ),
        &[(&head, &base)],
        &[(&head, &SELECTION)],
    );
}

/// A changed Rust path that holds a line feed selects the selection checks without a read.
#[test]
fn a_rust_path_holding_a_line_feed_runs_selection_checks() {
    if child().is_some() {
        return plan_row();
    }
    pair(
        "line-feed-path",
        &id(
            module_path!(),
            "a_rust_path_holding_a_line_feed_runs_selection_checks",
        ),
        &[],
        &[("crates/a\nb.rs", "fn t() {}\n")],
        &SELECTION,
    );
}

/// `links` commits a registry that enrolls `tla/M.tla` and cites `crates/cited.rs`, with the check and its
/// self-test as stubs, and returns the commit.
fn links(repository: &Repository) -> String {
    let registry = r#"{"models": [{"path": "tla/M.tla", "kinds": ["action"]}], "rows": [{"model": "tla/M.tla", "kind": "action", "name": "A", "note": "n", "anchors": [{"path": "crates/cited.rs", "quote": "fn a("}]}, {"model": "tla/M.tla", "kind": "action", "name": "B", "note": "n", "abstraction": "no code site"}]}"#;
    repository.commit(&[
        ("verification/models/links.json", registry),
        ("tla/M.tla", "m\n"),
        ("tla/Other.tla", "o\n"),
        ("crates/cited.rs", "fn a() {}\n"),
        ("scripts/model-links.py", STUB),
        ("scripts/test-model-links.py", STUB),
    ])
}

/// A model, a cited file and the registry run the links check, a script it loads also its self-test, and
/// a path the registry does not name runs neither.
#[test]
fn each_links_input_runs_its_checks() {
    if child().is_some() {
        return plan_row();
    }
    let (repository, _) = fixture("links-inputs");
    let base = links(&repository);
    let mut lines = Vec::new();
    for path in [
        "verification/models/links.json",
        "crates/cited.rs",
        "tla/Other.tla",
        "scripts/model-links.py",
    ] {
        repository.git(&["checkout", "-q", "--detach", &base]);
        let text = std::fs::read_to_string(repository.top.join(path)).expect("the file reads");
        lines.push(repository.commit(&[(path, &format!("{text}\n"))]));
    }
    let pushed: Vec<(&str, &str)> = lines
        .iter()
        .map(|tip| (tip.as_str(), base.as_str()))
        .collect();
    let check = [Check::Links];
    let both = [Check::Links, Check::LinksSelfTest];
    assert_plan(
        &repository,
        &id(module_path!(), "each_links_input_runs_its_checks"),
        &pushed,
        &[(&lines[0], &check), (&lines[1], &check), (&lines[3], &both)],
    );
}

/// A push that removes the registry from a tip that keeps the check runs the check; one that removes the
/// check too runs nothing.
#[test]
fn a_push_that_removes_the_links_registry_runs_the_links_check_of_a_tip_that_keeps_it() {
    if child().is_some() {
        return plan_row();
    }
    let (repository, _) = fixture("links-removed");
    let base = links(&repository);
    repository.git(&["rm", "-q", "--", "verification/models/links.json"]);
    let kept = repository.commit(&[]);
    repository.git(&["checkout", "-q", "--detach", &base]);
    repository.git(&[
        "rm",
        "-q",
        "--",
        "verification/models/links.json",
        "scripts/model-links.py",
        "scripts/test-model-links.py",
    ]);
    let gone = repository.commit(&[]);
    assert_plan(
        &repository,
        &id(
            module_path!(),
            "a_push_that_removes_the_links_registry_runs_the_links_check_of_a_tip_that_keeps_it",
        ),
        &[(&kept, &base), (&gone, &base)],
        &[(&kept, &[Check::Links])],
    );
}

/// With no comparison base, a tip runs every check, the links checks beside its registry, and each check
/// whose file it holds, the replay only beside the contract.
#[test]
fn a_new_branch_without_origin_main_runs_the_contract_checks_its_tip_holds() {
    if child().is_some() {
        return plan_row();
    }
    let (repository, _) = fixture("no-base-held");
    let base = contract(&repository);
    let full = repository.commit(&[
        ("scripts/chaos-receipt-replay.py", STUB),
        ("scripts/test-gameday-judge.py", STUB),
        ("scripts/test-host-stop-controller.py", STUB),
    ]);
    repository.git(&["rm", "-q", "--", "chaos/ledger.json"]);
    let unledgered = repository.commit(&[]);
    repository.git(&["checkout", "-q", "--detach", &base]);
    let linked = links(&repository);
    repository.git(&["update-ref", "-d", "refs/remotes/origin/main"]);
    let every = [Check::SelectTests, Check::Admit, Check::Reconcile];
    let with = |more: &[Check]| every.iter().chain(more).copied().collect::<Vec<_>>();
    let all = with(&[
        Check::Contract,
        Check::Replay,
        Check::Judges,
        Check::Gameday,
        Check::HostStop,
    ]);
    let unledgered_checks = with(&[Check::Judges, Check::Gameday, Check::HostStop]);
    let linked_checks = with(&[
        Check::Links,
        Check::LinksSelfTest,
        Check::Contract,
        Check::Judges,
    ]);
    assert_plan(
        &repository,
        &id(
            module_path!(),
            "a_new_branch_without_origin_main_runs_the_contract_checks_its_tip_holds",
        ),
        &[(&full, ZERO), (&unledgered, ZERO), (&linked, ZERO)],
        &[
            (&full, &all),
            (&unledgered, &unledgered_checks),
            (&linked, &linked_checks),
        ],
    );
}

const CONTROLS: &str = "crates/campaign-supervisor/src/campaign/calibration/controls.rs";

/// A change to the calibration controls runs the judges' test at a tip that holds it and not at one cut
/// after its removal.
#[test]
fn a_change_to_the_calibration_controls_runs_the_judges_test_of_a_tip_that_holds_it() {
    if child().is_some() {
        return plan_row();
    }
    let (repository, _) = fixture("controls");
    let base = contract(&repository);
    let held = repository.commit(&[(CONTROLS, "depth, n and k\n")]);
    repository.git(&["checkout", "-q", "--detach", &base]);
    repository.git(&["rm", "-q", "--", "chaos/tests/test_judges.py"]);
    let start = repository.commit(&[]);
    let lacking = repository.commit(&[(CONTROLS, "depth, n and k\n")]);
    assert_plan(
        &repository,
        &id(
            module_path!(),
            "a_change_to_the_calibration_controls_runs_the_judges_test_of_a_tip_that_holds_it",
        ),
        &[(&held, &base), (&lacking, &start)],
        &[(&held, &[Check::Judges])],
    );
}

/// A change to a file the host stop controller's self-test reads runs it only at a tip that holds it.
#[test]
fn the_hook_runs_the_host_stop_self_test_only_at_a_tip_that_holds_it() {
    if child().is_some() {
        return plan_row();
    }
    let (repository, base) = fixture("host-stop");
    let unheld = repository.commit(&[("scripts/fis-profiles.json", "{}\n")]);
    let held = repository.commit(&[("scripts/test-host-stop-controller.py", STUB)]);
    let head = repository.commit(&[("scripts/fis-profiles.json", "{\"x\": 1}\n")]);
    assert_plan(
        &repository,
        &id(
            module_path!(),
            "the_hook_runs_the_host_stop_self_test_only_at_a_tip_that_holds_it",
        ),
        &[(&unheld, &base), (&head, &held)],
        &[(&head, &[Check::HostStop])],
    );
}

/// A chaos change at a tip that holds the receipt replay runs it after the contract check; a tip cut
/// before the replay runs the contract check alone.
#[test]
fn a_chaos_change_at_a_tip_that_holds_the_receipt_replay_runs_it_and_its_failure_blocks() {
    if child().is_some() {
        return plan_row();
    }
    let (repository, _) = fixture("replay");
    let base = repository.commit(&[
        ("chaos/ledger.json", "r\n"),
        ("chaos/READINESS.md", "r\n"),
        ("chaos/tools/validate_contract.py", STUB),
    ]);
    let before = repository.commit(&[("chaos/READINESS.md", "r\n\n")]);
    let held = repository.commit(&[("scripts/chaos-receipt-replay.py", STUB)]);
    let head = repository.commit(&[("chaos/READINESS.md", "r\n\n\n")]);
    assert_plan(
        &repository,
        &id(
            module_path!(),
            "a_chaos_change_at_a_tip_that_holds_the_receipt_replay_runs_it_and_its_failure_blocks",
        ),
        &[(&before, &base), (&head, &held)],
        &[
            (&before, &[Check::Contract]),
            (&head, &[Check::Contract, Check::Replay]),
        ],
    );
}

/// A tip on two lines whose ranges select disjoint checks gets both sets, in run order, in either line
/// order.
#[test]
fn one_commit_pushed_to_two_refs_runs_the_union_of_their_disjoint_checks() {
    if child().is_some() {
        return plan_row();
    }
    let (repository, base) = fixture("disjoint-union");
    let inventory = repository.commit(&[("scripts/test-inventory.json", r#"{"rows": []}"#)]);
    let head = repository.commit(&[("crates/v.rs", "edited\n")]);
    repository.git(&["checkout", "-q", "--detach", &base]);
    let verus = repository.commit(&[("crates/v.rs", "edited\n")]);
    let union = [Check::SelectTests, Check::Admit, Check::Reconcile];
    let test = id(
        module_path!(),
        "one_commit_pushed_to_two_refs_runs_the_union_of_their_disjoint_checks",
    );
    for lines in [
        [(head.as_str(), inventory.as_str()), (&head, &verus)],
        [(&head, &verus), (&head, &inventory)],
    ] {
        assert_plan(&repository, &test, &lines, &[(&head, &union)]);
    }
}
