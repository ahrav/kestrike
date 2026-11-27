use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::fixtures::quint::{Failure, LIMIT, run};
use crate::fixtures::{Model, Trace, case, generate, keep};
use crate::json::{Integer, Value, parse};
use crate::python;

#[test]
fn the_limit_ends_a_sleeping_child_with_sigkill() {
    let directory =
        std::env::temp_dir().join(format!("kestrike-tools-limit-{}", std::process::id()));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir_all(&directory).expect("the directory is made");
    let script = "trap 'echo term > terminated; exit 7' TERM; sleep 5 & wait";
    let args: Vec<OsString> = ["-c", script].map(OsString::from).to_vec();
    let start = Instant::now();
    let outcome = run(
        OsStr::new("sh"),
        &args,
        &directory,
        Duration::from_millis(300),
    );
    let elapsed = start.elapsed();
    let Err(Failure::Limit {
        status: Some(status),
        ..
    }) = outcome
    else {
        panic!("the child passes the limit and is reaped: {outcome:?}");
    };
    assert_eq!(status.signal(), Some(9), "SIGKILL ends the child");
    assert!(
        elapsed >= Duration::from_millis(300) && elapsed < Duration::from_secs(5),
        "{elapsed:?}"
    );
    assert!(
        !directory.join("terminated").exists(),
        "the child's TERM trap never runs"
    );
    fs::remove_dir_all(&directory).expect("the directory is removed");
    assert_eq!(LIMIT, Duration::from_secs(120));
}

#[test]
fn a_child_exit_status_reaches_the_caller() {
    let args: Vec<OsString> = ["-c", "exit 3"].map(OsString::from).to_vec();
    let outcome = run(OsStr::new("sh"), &args, &std::env::temp_dir(), LIMIT);
    assert!(
        matches!(outcome, Err(Failure::Exit(status)) if status.code() == Some(3)),
        "{outcome:?}"
    );
    let outcome = run(
        OsStr::new("/nonexistent/quint"),
        &[],
        &std::env::temp_dir(),
        LIMIT,
    );
    assert!(matches!(outcome, Err(Failure::Start(_))), "{outcome:?}");
}

#[test]
fn python_int_reads_the_forms_python_reads() {
    let int = |text: &str| python::int(&parse(text).expect("the value parses"));
    let integer = |digits: &str| Integer::from_digits(false, digits).expect("digits");
    assert_eq!(int(r#""1_0""#), Ok(integer("10")));
    assert_eq!(int(r#"" +7 ""#), Ok(integer("7")));
    assert_eq!(int(r#""\u00a0-0\u3000""#), Ok(integer("0")));
    assert_eq!(int(r#""007""#), Ok(integer("7")));
    assert_eq!(int("true"), Ok(integer("1")));
    assert_eq!(int("12"), Ok(integer("12")));
    for refused in [
        r#""1__0""#,
        r#""_1""#,
        r#""1_""#,
        r#""""#,
        r#""0x1""#,
        "[]",
        "{}",
        r#""- 1""#,
    ] {
        assert!(int(refused).is_err(), "{refused}");
    }
}

#[test]
fn python_len_counts_characters_items_and_members() {
    let len = |text: &str| python::len(&parse(text).expect("the value parses"));
    assert_eq!(len(r#""\u00e9a""#), Some(2));
    assert_eq!(len("[1,[2,3]]"), Some(2));
    assert_eq!(len(r#"{"a":1}"#), Some(1));
    assert_eq!(len("7"), None);
    assert_eq!(python::len(&Value::Bool(true)), None);
}

#[test]
fn a_writer_at_the_limit_exits_with_the_trace_named_and_writes_no_later_trace() {
    let scratch = std::env::temp_dir().join(format!(
        "kestrike-tools-writer-limit-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&scratch);
    fs::create_dir_all(&scratch).expect("the directory is made");
    let quint = scratch.join("quint");
    fs::write(&quint, "#!/bin/sh\nexec sleep 5\n").expect("the stand-in is written");
    fs::set_permissions(&quint, fs::Permissions::from_mode(0o755))
        .expect("the stand-in is executable");
    let model = Model {
        tool: "gate_fixtures",
        about: "About.",
        name: "gate",
    };
    let traces = ["first", "second"]
        .map(|name| Trace::new(name.to_owned(), 1, None, 12, case::gate, Vec::new()));
    let top = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = scratch.join("out");
    let limit = Duration::from_millis(300);
    let outcome = generate(
        &model,
        &top,
        Some(quint.as_os_str()),
        &output,
        &traces,
        keep,
        limit,
    );
    assert_eq!(
        outcome,
        Err("first: Quint ran past 0.3 seconds and was killed".to_owned())
    );
    assert!(output.join("first/case.qnt").exists());
    assert!(!output.join("second").exists());
    fs::remove_dir_all(&scratch).expect("the directory is removed");
}
