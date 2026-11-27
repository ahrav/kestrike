//! Rows of the chaos record guard: each builds the hook case's history, plans its push in a child, and
//! asserts the guard's failures.

use kestrike_tools::git::caller_environ;
use kestrike_tools::hook::{Record, account_numbers};
use kestrike_tools::text::Text;

use super::lines::{fixture, line, planned};
use super::repository::{Repository, STUB, ZERO, child, id};

const REFUSED: &str = "holds what may be an AWS account number";
const LEAK: &str = r#"{"account": 123456789012}"#;

/// `contract` commits a chaos contract with its validator and judges' test as stubs, and returns it.
pub fn contract(repository: &Repository) -> String {
    repository.commit(&[
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

/// `guarded` plans one push of `local` over `remote` and returns the guard's failures.
fn guarded(lines: &[(String, String)]) -> Vec<String> {
    let lines: Vec<_> = lines
        .iter()
        .map(|(local, remote)| line(local, remote))
        .collect();
    planned(&lines).guard().expect("the guard reads")
}

/// `pushed` reads the row's `HEAD` over `BASE` and returns the guard's failures.
fn pushed() -> Vec<String> {
    let row = child().expect("the row's child reads its values");
    guarded(&[(row.get("HEAD"), row.get("BASE"))])
}

fn at(path: &str, commit: &str, said: &str) -> String {
    format!("{path} at {} {said}", &commit[..12])
}

/// A link at a record directory and at another path under `chaos/` each fail the tip.
#[test]
fn a_link_under_chaos_fails_the_push() {
    if let Some(row) = child() {
        let head = row.get("HEAD");
        assert_eq!(
            pushed(),
            [
                at("chaos/READINESS.md", &head, "is a link or a submodule"),
                at("chaos/receipts", &head, "is a link or a submodule"),
            ]
        );
        return;
    }
    let (repository, _) = fixture("link-under-chaos");
    let base = contract(&repository);
    repository.commit(&[("chaos/elsewhere/row.json", LEAK), ("chaos/copy.md", "r\n")]);
    repository.link("chaos/receipts", "elsewhere");
    let head = repository.link("chaos/READINESS.md", "copy.md");
    repository.in_child(
        &id(module_path!(), "a_link_under_chaos_fails_the_push"),
        &[("BASE", &base), ("HEAD", &head)],
    );
}

/// A record directory that is a file fails the tip.
#[test]
fn a_record_directory_that_is_a_file_fails_the_push() {
    if let Some(row) = child() {
        assert_eq!(
            pushed(),
            [at("chaos/runs", &row.get("HEAD"), "is not a directory")]
        );
        return;
    }
    let (repository, _) = fixture("record-directory-file");
    let base = contract(&repository);
    repository.git(&["rm", "-rq", "--", "chaos/runs"]);
    let head = repository.commit(&[("chaos/runs", "a file\n")]);
    repository.in_child(
        &id(
            module_path!(),
            "a_record_directory_that_is_a_file_fails_the_push",
        ),
        &[("BASE", &base), ("HEAD", &head)],
    );
}

/// A record path that is a directory fails the tip, and the files under it are no records.
#[test]
fn a_record_path_that_is_a_directory_fails_the_push() {
    if let Some(row) = child() {
        assert_eq!(
            pushed(),
            [at(
                "chaos/receipts/dir.json",
                &row.get("HEAD"),
                "is a chaos record that is not a regular file"
            )]
        );
        return;
    }
    let (repository, _) = fixture("record-path-directory");
    let base = contract(&repository);
    let head = repository.commit(&[("chaos/receipts/dir.json/x.txt", LEAK)]);
    repository.in_child(
        &id(
            module_path!(),
            "a_record_path_that_is_a_directory_fails_the_push",
        ),
        &[("BASE", &base), ("HEAD", &head)],
    );
}

/// A pushed commit's record that a later commit removes still fails the push, and a commit that makes a
/// record path a link fails once, naming that commit.
#[test]
fn a_pushed_commit_with_an_account_number_fails_a_push_whose_tip_removed_it() {
    if let Some(row) = child() {
        let (linked, leaked) = (row.get("LINKED"), row.get("LEAKED"));
        assert_eq!(
            pushed(),
            [
                at(
                    "chaos/runs/linked/run.json",
                    &linked,
                    "is a chaos record that is not a regular file"
                ),
                at("chaos/runs/run/run.json", &leaked, REFUSED),
                at("chaos/tests/receipts/fixture/row.json", &leaked, REFUSED),
            ]
        );
        return;
    }
    let (repository, _) = fixture("removed-record");
    let base = contract(&repository);
    let linked = repository.link("chaos/runs/linked/run.json", "123456789012");
    let receipt = "chaos/tests/receipts/fixture/row.json";
    let leaked = repository.commit(&[
        ("chaos/runs/run/run.json", LEAK),
        (receipt, r#"{"role": 123456789012}"#),
    ]);
    repository.git(&["rm", "-q", "--", "chaos/runs/linked/run.json", receipt]);
    let head = repository.commit(&[("chaos/runs/run/run.json", "{}\n")]);
    repository.in_child(
        &id(
            module_path!(),
            "a_pushed_commit_with_an_account_number_fails_a_push_whose_tip_removed_it",
        ),
        &[
            ("BASE", &base),
            ("HEAD", &head),
            ("LINKED", &linked),
            ("LEAKED", &leaked),
        ],
    );
}

/// A record that is not JSON fails as such, a blob Git cannot read fails as unread, and a repeated key's
/// earlier value is read, so `{"a": <12 digits>, "a": 0}` holds an account number.
#[test]
fn a_chaos_record_that_is_not_json_or_cannot_be_read_fails() {
    if let Some(row) = child() {
        let head = row.get("HEAD");
        assert_eq!(
            pushed(),
            [
                at("chaos/runs/repeated/run.json", &head, REFUSED),
                at(
                    "chaos/runs/run/run.json",
                    &head,
                    "is a chaos record that is not JSON"
                ),
            ]
        );
        let missing = Record {
            commit: Text::from(head.as_str()),
            path: "chaos/runs/run/run.json".to_owned(),
            oid: ZERO.to_owned(),
        };
        assert_eq!(
            account_numbers(&caller_environ(), &[missing]).expect("the batch reads"),
            [at(
                "chaos/runs/run/run.json",
                &head,
                "is a chaos record Git could not read"
            )]
        );
        return;
    }
    let (repository, _) = fixture("not-json");
    let base = contract(&repository);
    let head = repository.commit(&[
        ("chaos/runs/run/run.json", r#"{"a": "\n123456789012""#),
        (
            "chaos/runs/repeated/run.json",
            r#"{"a": 123456789012, "a": 0}"#,
        ),
    ]);
    repository.in_child(
        &id(
            module_path!(),
            "a_chaos_record_that_is_not_json_or_cannot_be_read_fails",
        ),
        &[("BASE", &base), ("HEAD", &head)],
    );
}

/// A replace ref that stands a clean blob in for the record is passed over.
#[test]
fn the_guard_reads_the_original_objects_past_a_replacement() {
    if let Some(row) = child() {
        assert_eq!(
            pushed(),
            [at("chaos/runs/run/run.json", &row.get("HEAD"), REFUSED)]
        );
        return;
    }
    let (repository, _) = fixture("replacement");
    let base = contract(&repository);
    let head = repository.commit(&[("chaos/runs/run/run.json", LEAK)]);
    let original = repository.git(&["rev-parse", &format!("{head}:chaos/runs/run/run.json")]);
    std::fs::write(repository.top.join("clean"), "{}\n").expect("the clean text is written");
    let clean = repository.git(&["hash-object", "-w", "clean"]);
    repository.git(&["replace", &original, &clean]);
    repository.in_child(
        &id(
            module_path!(),
            "the_guard_reads_the_original_objects_past_a_replacement",
        ),
        &[("BASE", &base), ("HEAD", &head)],
    );
}

/// The caller's pathspec modes, the literal mode among them, leave the record directories' pathspecs read
/// with their magic, so a pushed commit's record is found.
#[test]
fn the_history_guard_reads_pathspecs_whatever_mode_the_push_set() {
    if let Some(row) = child() {
        assert_eq!(
            pushed(),
            [at("chaos/runs/run/run.json", &row.get("LEAKED"), REFUSED)]
        );
        return;
    }
    let (mut repository, _) = fixture("pathspec-modes");
    let base = contract(&repository);
    let leaked = repository.commit(&[("chaos/runs/run/run.json", LEAK)]);
    let head = repository.commit(&[("chaos/runs/run/run.json", "{}\n")]);
    for mode in [
        "GIT_LITERAL_PATHSPECS",
        "GIT_GLOB_PATHSPECS",
        "GIT_NOGLOB_PATHSPECS",
        "GIT_ICASE_PATHSPECS",
    ] {
        repository.set(mode, "1");
    }
    repository.in_child(
        &id(
            module_path!(),
            "the_history_guard_reads_pathspecs_whatever_mode_the_push_set",
        ),
        &[("BASE", &base), ("HEAD", &head), ("LEAKED", &leaked)],
    );
}

/// A merge's side branch counts as pushed, so its record is read.
#[test]
fn a_merged_side_branch_with_an_account_number_fails_the_push() {
    if let Some(row) = child() {
        assert_eq!(
            pushed(),
            [at("chaos/runs/run/run.json", &row.get("LEAKED"), REFUSED)]
        );
        return;
    }
    let (repository, _) = fixture("merged-side");
    let base = contract(&repository);
    let leaked = repository.commit(&[("chaos/runs/run/run.json", LEAK)]);
    let side = repository.commit(&[("chaos/runs/run/run.json", "{}\n")]);
    repository.git(&["checkout", "-q", "--detach", &base]);
    repository.commit(&[("chaos/survey.md", "main line\n")]);
    repository.git(&["merge", "-q", "--no-ff", "-m", "merge", &side]);
    let head = repository.git(&["rev-parse", "HEAD"]);
    repository.in_child(
        &id(
            module_path!(),
            "a_merged_side_branch_with_an_account_number_fails_the_push",
        ),
        &[("BASE", &base), ("HEAD", &head), ("LEAKED", &leaked)],
    );
}

/// A commit a remote-tracking ref of the destination reaches is held there, so the refused record of its
/// parent is not read for a new ref or for a merge of it.
#[test]
fn the_history_guard_skips_the_records_of_commits_the_destination_holds() {
    if let Some(row) = child() {
        let lines = [
            (row.get("NEW"), ZERO.to_owned()),
            (row.get("MERGED"), row.get("OLD")),
        ];
        assert_eq!(guarded(&lines), Vec::<String>::new());
        return;
    }
    let (repository, _) = fixture("destination-holds");
    let start = contract(&repository);
    repository.git(&["update-ref", "refs/remotes/origin/main", &start]);
    repository.commit(&[("chaos/runs/run/run.json", LEAK)]);
    let held = repository.commit(&[("chaos/runs/run/run.json", "{}\n")]);
    repository.git(&["update-ref", "refs/remotes/origin/team/topic", &held]);
    let new = repository.commit(&[("crates/plain.rs", "a new branch\n")]);
    repository.git(&["checkout", "-q", "--detach", &start]);
    let old = repository.commit(&[("crates/other.rs", "an older branch\n")]);
    repository.git(&["merge", "-q", "--no-ff", "-m", "merge", &held]);
    let merged = repository.git(&["rev-parse", "HEAD"]);
    repository.in_child(
        &id(
            module_path!(),
            "the_history_guard_skips_the_records_of_commits_the_destination_holds",
        ),
        &[("NEW", &new), ("MERGED", &merged), ("OLD", &old)],
    );
}

/// The refs of another remote, and of a remote whose name extends the destination's with `/`, do not
/// count as held, so a new ref reads the records of commits only they reach.
#[test]
fn a_new_ref_reads_the_records_of_commits_only_another_remote_holds() {
    if let Some(row) = child() {
        assert_eq!(
            guarded(&[(row.get("HEAD"), ZERO.to_owned())]),
            [at("chaos/runs/run/run.json", &row.get("LEAKED"), REFUSED)]
        );
        return;
    }
    let (repository, _) = fixture("another-remote");
    contract(&repository);
    let leaked = repository.commit(&[("chaos/runs/run/run.json", LEAK)]);
    repository.git(&["update-ref", "refs/remotes/other/x", &leaked]);
    repository.git(&["update-ref", "refs/remotes/origin/fork/x", &leaked]);
    repository.git(&["config", "remote.origin/fork.url", "elsewhere"]);
    repository.git(&["update-ref", "-d", "refs/remotes/origin/main"]);
    let head = repository.commit(&[("chaos/runs/run/run.json", "{}\n")]);
    repository.in_child(
        &id(
            module_path!(),
            "a_new_ref_reads_the_records_of_commits_only_another_remote_holds",
        ),
        &[("HEAD", &head), ("LEAKED", &leaked)],
    );
}

/// A chaos change reads every record of the tip, one that only the base added included, from a
/// subdirectory of the checkout as from its top.
#[test]
fn a_chaos_change_reads_every_record_of_the_tip_from_any_directory() {
    if let Some(row) = child() {
        assert_eq!(
            pushed(),
            [at("chaos/runs/old/run.json", &row.get("HEAD"), REFUSED)]
        );
        return;
    }
    let (repository, _) = fixture("tip-records");
    contract(&repository);
    let base = repository.commit(&[("chaos/runs/old/run.json", LEAK)]);
    let head = repository.commit(&[("chaos/survey.md", "edited\n")]);
    repository.in_child_at(
        &repository.top.join("crates"),
        &id(
            module_path!(),
            "a_chaos_change_reads_every_record_of_the_tip_from_any_directory",
        ),
        &[("BASE", &base), ("HEAD", &head)],
    );
}

/// With no comparison base the tip's records are guarded: its link fails as a link at the tip and as a
/// pushed record that is no regular file, and its record with an account number fails under the tip,
/// the first record that holds the blob.
#[test]
fn a_new_branch_without_origin_main_guards_the_chaos_records_of_its_tip() {
    if let Some(row) = child() {
        let head = row.get("HEAD");
        let linked = "chaos/runs/linked/run.json";
        assert_eq!(
            guarded(&[(head.clone(), ZERO.to_owned())]),
            [
                at(linked, &head, "is a link or a submodule"),
                at(
                    linked,
                    &head,
                    "is a chaos record that is not a regular file"
                ),
                at("chaos/runs/run/run.json", &head, REFUSED),
            ]
        );
        return;
    }
    let (repository, _) = fixture("no-base-guard");
    contract(&repository);
    repository.git(&["rm", "-q", "--", "chaos/ledger.json"]);
    let leaked = repository.commit(&[
        ("chaos/runs/run/run.json", LEAK),
        ("chaos/elsewhere.json", "{}\n"),
    ]);
    let head = repository.link("chaos/runs/linked/run.json", "../../elsewhere.json");
    repository.git(&["update-ref", "-d", "refs/remotes/origin/main"]);
    repository.in_child(
        &id(
            module_path!(),
            "a_new_branch_without_origin_main_guards_the_chaos_records_of_its_tip",
        ),
        &[("HEAD", &head), ("LEAKED", &leaked)],
    );
}

/// `chaos` as a link and as a submodule each fail the tip of a line with a base.
#[test]
fn a_link_or_a_submodule_at_the_chaos_root_fails_a_push_with_a_base() {
    if let Some(row) = child() {
        let (base, linked, submodule) = (row.get("BASE"), row.get("LINKED"), row.get("SUBMODULE"));
        assert_eq!(
            guarded(&[(linked.clone(), base.clone()), (submodule.clone(), base)]),
            [
                at("chaos", &linked, "is a link or a submodule"),
                at("chaos", &submodule, "is a link or a submodule"),
            ]
        );
        return;
    }
    let (repository, base) = fixture("chaos-root");
    repository.commit(&[("elsewhere/runs/run/run.json", LEAK)]);
    let linked = repository.link("chaos", "elsewhere");
    repository.git(&["checkout", "-q", "--detach", &base]);
    repository.git(&["config", "diff.ignoreSubmodules", "all"]);
    repository.git(&[
        "update-index",
        "--add",
        "--cacheinfo",
        &format!("160000,{base},chaos"),
    ]);
    let submodule = repository.commit(&[]);
    repository.in_child(
        &id(
            module_path!(),
            "a_link_or_a_submodule_at_the_chaos_root_fails_a_push_with_a_base",
        ),
        &[
            ("BASE", &base),
            ("LINKED", &linked),
            ("SUBMODULE", &submodule),
        ],
    );
}
