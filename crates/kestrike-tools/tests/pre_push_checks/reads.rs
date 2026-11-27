//! Rows of the two Git reads the hook adds and of the weakened-test scan's entry, each read in a child.

use std::ffi::OsStr;
use std::fs::File;
use std::os::fd::AsFd;

use kestrike_tools::git::{blob_bytes, caller_environ, output};
use kestrike_tools::tools::scan_weakened_tests::scan_range;

use super::lines::fixture;
use super::repository::{child, id};

/// The read of a whole outcome returns a failed lookup's status and its error text, and a shown file's
/// bytes; the presence test of the guard's reads reads the status alone.
#[test]
fn the_outcome_read_returns_the_status_and_both_streams() {
    if let Some(row) = child() {
        let head = row.get("HEAD");
        let environ = caller_environ();
        let absent =
            output(&environ, &["cat-file", "-e", &format!("{head}:missing")]).expect("git starts");
        assert_eq!(absent.status.code(), Some(128));
        assert!(absent.stdout.is_empty());
        assert!(
            String::from_utf8_lossy(&absent.stderr).contains("missing"),
            "{absent:?}"
        );
        let shown = output(
            &environ,
            &["show", &format!("{head}:scripts/test-inventory.json")],
        )
        .expect("git starts");
        assert_eq!(
            (shown.status.code(), shown.stdout),
            (Some(0), b"{\"rows\": []}".to_vec())
        );
        return;
    }
    let (repository, _) = fixture("outcome");
    let head = repository.commit(&[("scripts/test-inventory.json", r#"{"rows": []}"#)]);
    repository.in_child(
        &id(
            module_path!(),
            "the_outcome_read_returns_the_status_and_both_streams",
        ),
        &[("HEAD", &head)],
    );
}

/// The batch read of bytes tells a missing name and a tree from an empty blob, reads a blob by its object
/// id, and reads a name with a final carriage return as Git reads it, without the return.
#[test]
fn the_bytes_read_tells_a_missing_name_and_a_tree_from_an_empty_blob() {
    if let Some(row) = child() {
        let (head, empty) = (row.get("HEAD"), row.get("EMPTY"));
        let names: Vec<String> = [
            format!("{head}:crates/plain.rs"),
            format!("{head}:crates/gone.rs"),
            format!("{head}:crates"),
            format!("{head}:crates/empty.rs"),
            empty,
            format!("{head}:crates/plain.rs\r"),
        ]
        .into();
        let read = blob_bytes(&caller_environ(), &names).expect("the batch reads");
        assert_eq!(
            read,
            [
                Some(b"#[ignore = \"slow\"]\nfn churn() {}\n".to_vec()),
                None,
                None,
                Some(Vec::new()),
                Some(Vec::new()),
                Some(b"#[ignore = \"slow\"]\nfn churn() {}\n".to_vec()),
            ]
        );
        return;
    }
    let (repository, _) = fixture("batch-bytes");
    let head = repository.commit(&[
        ("crates/plain.rs", "#[ignore = \"slow\"]\nfn churn() {}\n"),
        ("crates/empty.rs", ""),
    ]);
    let empty = repository.git(&["rev-parse", &format!("{head}:crates/empty.rs")]);
    repository.in_child(
        &id(
            module_path!(),
            "the_bytes_read_tells_a_missing_name_and_a_tree_from_an_empty_blob",
        ),
        &[("HEAD", &head), ("EMPTY", &empty)],
    );
}

/// The scan's entry writes to the stream it is given the bytes the tool writes to standard output for the
/// same range, and to standard error the tool's refusal, and returns the tool's code; an empty range writes
/// nothing and returns 0, and two commits with no shared history return 2.
#[test]
fn an_existing_test_that_gains_an_ignore_writes_the_scan_s_lines_to_the_given_stream() {
    if let Some(row) = child() {
        let report = File::create(row.get("REPORT")).expect("the report file is made");
        let environ = caller_environ();
        for (base, head) in [
            (row.get("BASE"), row.get("HEAD")),
            (row.get("HEAD"), row.get("HEAD")),
            (row.get("HEAD"), row.get("ROOT")),
        ] {
            let code = scan_range(
                &environ,
                OsStr::new(&base),
                OsStr::new(&head),
                report.as_fd(),
            );
            println!("entry exited {code}");
        }
        return;
    }
    let (repository, _) = fixture("entry");
    let base = repository.commit(&[("crates/plain.rs", "#[test]\nfn churn() {}\n")]);
    let head = repository.commit(&[(
        "crates/plain.rs",
        "#[test]\n#[ignore = \"slow\"]\nfn churn() {}\n",
    )]);
    repository.git(&["checkout", "-q", "--orphan", "root"]);
    let root = repository.commit(&[("other.rs", "fn o() {}\n")]);
    let report = repository.top.join("../report");
    let entry = repository.in_child(
        &id(
            module_path!(),
            "an_existing_test_that_gains_an_ignore_writes_the_scan_s_lines_to_the_given_stream",
        ),
        &[
            ("BASE", &base),
            ("HEAD", &head),
            ("ROOT", &root),
            (
                "REPORT",
                report.to_str().expect("the scratch path is UTF-8"),
            ),
        ],
    );
    let tool = |base: &str, head: &str| {
        repository
            .command(env!("CARGO_BIN_EXE_kestrike-tools"))
            .args([".", "scan-weakened-tests", "--base", base, "--head", head])
            .output()
            .expect("the tool starts")
    };
    let (blocked, empty, unrelated) = (tool(&base, &head), tool(&head, &head), tool(&head, &root));
    assert_eq!(
        [
            blocked.status.code(),
            empty.status.code(),
            unrelated.status.code()
        ],
        [Some(1), Some(0), Some(2)]
    );
    assert!(
        String::from_utf8_lossy(&blocked.stdout)
            .starts_with("blocks ignore-existing:crates/plain.rs churn"),
        "{blocked:?}"
    );
    assert!(empty.stdout.is_empty() && empty.stderr.is_empty() && unrelated.stdout.is_empty());
    let written = std::fs::read(&report).expect("the report file reads");
    assert_eq!(written, blocked.stdout);
    let mut refusals = blocked.stderr.clone();
    refusals.extend(&unrelated.stderr);
    assert_eq!(entry.stderr, refusals);
    assert!(
        String::from_utf8_lossy(&entry.stdout)
            .contains("entry exited 1\nentry exited 0\nentry exited 2\n"),
        "{entry:?}"
    );
}
