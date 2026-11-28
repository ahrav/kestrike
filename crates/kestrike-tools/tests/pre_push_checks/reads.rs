//! Rows of the two Git reads the hook adds and of the weakened-test scan's entry, each read in a child.

use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::AsFd;

use kestrike_tools::environ::{remove, set};
use kestrike_tools::git::{GitError, blob_bytes, caller_environ, output};
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

/// The batch read of bytes tells a missing name and a tree from an empty blob and reads a blob by its object
/// id; a name with a final carriage return, which Git would read without it, is refused before Git starts.
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
            ]
        );
        let returned = [format!("{head}:crates/plain.rs\r")];
        assert!(matches!(
            blob_bytes(&caller_environ(), &returned),
            Err(GitError::Name(_))
        ));
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

/// The scan's entry, given standard error as its stream, writes there the bytes the tool writes to
/// standard output for the same range and then the tool's own standard error, and returns the tool's code;
/// an empty range writes nothing and returns 0, two commits with no shared history return 2, and a stream
/// that cannot be written returns 120. Its Git children start in the environment it is given, which here
/// alone names the repository, and it appends the step summary to the file the process's own environment
/// names, not the one the given environment names.
#[test]
fn an_existing_test_that_gains_an_ignore_writes_the_scan_s_lines_to_the_given_stream() {
    if let Some(row) = child() {
        let mut environ = caller_environ();
        remove(&mut environ, "GIT_DIR");
        set(
            &mut environ,
            "GITHUB_STEP_SUMMARY",
            row.get("GIVEN_SUMMARY").into(),
        );
        let unwritable = File::open("/dev/null").expect("the null device opens");
        let ranges = [
            (row.get("BASE"), row.get("HEAD")),
            (row.get("HEAD"), row.get("HEAD")),
            (row.get("HEAD"), row.get("ROOT")),
        ];
        for (base, head) in &ranges {
            let code = scan_range(
                &environ,
                OsStr::new(base),
                OsStr::new(head),
                io::stderr().as_fd(),
            );
            println!("entry exited {code}");
        }
        let (base, head) = &ranges[0];
        let code = scan_range(
            &environ,
            OsStr::new(base),
            OsStr::new(head),
            unwritable.as_fd(),
        );
        println!("entry exited {code}");
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
    let summary = repository.top.join("../summary");
    let given = repository.top.join("../given-summary");
    File::create_new(&summary)
        .and_then(|mut file| file.write_all(b"seed\n"))
        .expect("the summary is seeded");
    let missing = repository.top.join("../no-repository");
    let entry = repository.in_child_with(
        &repository.top,
        &id(
            module_path!(),
            "an_existing_test_that_gains_an_ignore_writes_the_scan_s_lines_to_the_given_stream",
        ),
        &[
            ("BASE", &base),
            ("HEAD", &head),
            ("ROOT", &root),
            (
                "GIVEN_SUMMARY",
                given.to_str().expect("the scratch path is UTF-8"),
            ),
        ],
        &[
            ("GIT_DIR", missing.as_os_str()),
            ("GITHUB_STEP_SUMMARY", summary.as_os_str()),
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
    assert!(!blocked.stderr.is_empty(), "{blocked:?}");
    assert!(empty.stdout.is_empty() && empty.stderr.is_empty() && unrelated.stdout.is_empty());
    let mut expected = blocked.stdout.clone();
    expected.extend(&blocked.stderr);
    expected.extend(&unrelated.stderr);
    expected.extend(b"scan-weakened-tests: standard output: Bad file descriptor (os error 9)\n");
    assert_eq!(
        String::from_utf8_lossy(&entry.stderr),
        String::from_utf8_lossy(&expected)
    );
    assert!(
        String::from_utf8_lossy(&entry.stdout)
            .contains("entry exited 1\nentry exited 0\nentry exited 2\nentry exited 120\n"),
        "{entry:?}"
    );
    let block = format!(
        "seed\nWeakened-test scan of {}..{}:\n\n```text\n{}```\n",
        &base[..12],
        &head[..12],
        String::from_utf8_lossy(&blocked.stdout)
    );
    assert_eq!(
        std::fs::read_to_string(&summary).expect("the summary reads"),
        block
    );
    assert!(!given.exists());
}

/// The tool started alone looks Git up as the process's own children are: a `git` with no `#!` line first
/// on `PATH` does not start, and the scan exits 2 with the system's error.
#[test]
fn a_git_without_an_interpreter_line_does_not_start_the_scan() {
    let (repository, _) = fixture("shebangless");
    let head = repository.git(&["rev-parse", "HEAD"]);
    let bin = repository.top.join("../bin");
    std::fs::create_dir(&bin).expect("the stand-in directory is made");
    super::push::executable(&bin.join("git"), "exec /usr/bin/env -u PATH git \"$@\"\n");
    let mut path = bin.into_os_string();
    path.push(":");
    path.push(std::env::var_os("PATH").unwrap_or_default());
    let output = repository
        .command(env!("CARGO_BIN_EXE_kestrike-tools"))
        .env("PATH", path)
        .args([".", "scan-weakened-tests", "--base", &head, "--head", &head])
        .output()
        .expect("the tool starts");
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .starts_with("scan-weakened-tests: git: Exec format error"),
        "{output:?}"
    );
}
