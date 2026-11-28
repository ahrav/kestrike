use std::fs;
use std::path::Path;
use std::process::Command;

use kestrike_tools::genmc::{package_sources, read_source};
use kestrike_tools::json::{self, Value};
use kestrike_tools::orderings::check::check;
use kestrike_tools::orderings::sites::EXTERNAL;

use super::{Scratch, tool, top};

fn status(top: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(["--no-optional-locks", "-C"])
        .arg(top)
        .args(["status", "--porcelain", "--untracked-files=all"])
        .args(args)
        .output()
        .expect("git starts");
    assert!(output.status.success(), "{output:?}");
    String::from_utf8(output.stdout).expect("UTF-8")
}

fn snapshot(top: &Path) -> (String, String) {
    (
        status(top, &[]),
        status(
            top,
            &["--ignored", "--", "scripts", "verification", "evidence"],
        ),
    )
}

/// `check` on the checkout exits 0 and prints the report the library's check gives, and leaves the
/// working directory it starts in empty and the checkout's status, ignored files included, as it was.
#[test]
fn the_command_prints_the_report_and_writes_nothing() {
    let top = top();
    let before = snapshot(&top);
    let scratch = Scratch::new("check");
    let run = tool(&top, &["check"], &scratch.0);
    assert_eq!(
        run.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let read = |path: &str| read_source(&top, path);
    let (expected, code) = check(&read, &top, &top, EXTERNAL, &package_sources);
    assert_eq!(code, 0);
    let printed = String::from_utf8(run.stdout).expect("UTF-8");
    assert_eq!(json::parse(&printed).expect("one JSON report"), expected);
    assert_eq!(printed, format!("{}\n", json::indented_in_order(&expected)));
    assert_eq!(fs::read_dir(&scratch.0).expect("lists").count(), 0);
    assert_eq!(snapshot(&top), before);
}

/// A tree that holds none of the check's inputs exits 2 with the report of one member, `error`, naming
/// the unreadable catalog; a word that names no command exits 2 with the usage on standard error and
/// nothing on standard output; and `--help` prints the help, which lists the refusals, and exits 0.
#[test]
fn a_helper_that_cannot_load_or_a_usage_error_exits_2() {
    let scratch = Scratch::new("unreadable");
    fs::create_dir(scratch.0.join("scripts")).expect("made");
    let run = tool(&scratch.0, &["check"], &scratch.0);
    assert_eq!(
        run.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let report =
        json::parse(&String::from_utf8(run.stdout).expect("UTF-8")).expect("one JSON report");
    let Value::Object(report) = report else {
        panic!("the report is an object");
    };
    assert_eq!(report.len(), 1);
    let Some(Value::String(error)) = report.get("error") else {
        panic!("the report names its error");
    };
    assert!(
        error.to_string().starts_with(
            "unreadable catalog or declaration: verification/orderings/expected.json: "
        ),
        "{error}"
    );
    let top = top();
    let run = tool(&top, &["bogus"], &scratch.0);
    assert_eq!(
        (run.status.code(), run.stdout.as_slice()),
        (Some(2), &b""[..])
    );
    let stderr = String::from_utf8(run.stderr).expect("UTF-8");
    assert!(stderr.contains("usage:"), "{stderr}");
    assert!(
        stderr.contains(
            "error: argument command: invalid choice: 'bogus' (choose from 'check', 'run')"
        ),
        "{stderr}"
    );
    let run = tool(&top, &["--help"], &scratch.0);
    assert_eq!(
        run.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(
        String::from_utf8(run.stdout)
            .expect("UTF-8")
            .contains("`check` refuses, each by name:")
    );
}

/// `copy_tree` copies the directory `from` to `to`, passing over each directory named `target` and
/// `__pycache__`; links are copied as the files they name.
fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir(to).expect("made");
    for entry in fs::read_dir(from).expect("lists") {
        let entry = entry.expect("an entry");
        let name = entry.file_name();
        let (source, copy) = (entry.path(), to.join(&name));
        if fs::metadata(&source).expect("stats").is_dir() {
            if name != "target" && name != "__pycache__" {
                copy_tree(&source, &copy);
            }
        } else {
            fs::copy(&source, &copy).expect("copied");
        }
    }
}

/// A tree that holds the scripts and the declarations but no crate source exits 1 with a report that
/// credits nothing and refuses each listed file as one the kernel package does not include.
#[test]
fn the_command_exits_1_and_prints_the_refusing_report() {
    let top = top();
    let scratch = Scratch::new("refusing");
    for name in ["scripts", "verification"] {
        copy_tree(&top.join(name), &scratch.0.join(name));
    }
    let run = tool(&scratch.0, &["check"], &scratch.0);
    assert_eq!(
        run.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let report =
        json::parse(&String::from_utf8(run.stdout).expect("UTF-8")).expect("one JSON report");
    let Value::Object(report) = report else {
        panic!("the report is an object");
    };
    assert_eq!(report.get("credited"), Some(&Value::Bool(false)));
    let expected = json::parse(
        r#"{"refusal": "scope file", "message": "crates/kestrike/src/storage/fill.rs is listed and the kernel package includes no production file there"}"#,
    )
    .expect("parses");
    let Some(Value::Array(refusals)) = report.get("refusals") else {
        panic!("the report lists its refusals");
    };
    assert!(refusals.contains(&expected), "{refusals:?}");
}
