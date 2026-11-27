use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::process::ExitStatusExt;
use std::time::{Duration, Instant};

use crate::fixtures::quint::{Failure, LIMIT, run};
use crate::fixtures::{python_int, python_len};
use crate::json::{Integer, Value, parse};

#[test]
fn the_limit_ends_a_sleeping_child_with_sigkill_and_no_earlier_signal() {
    let directory =
        std::env::temp_dir().join(format!("kestrike-tools-limit-{}", std::process::id()));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir_all(&directory).expect("the directory is made");
    let script = "trap 'echo term > terminated' TERM; while :; do sleep 0.05; done";
    let args: Vec<OsString> = ["-c", script].map(OsString::from).to_vec();
    let start = Instant::now();
    let outcome = run(
        OsStr::new("sh"),
        &args,
        &directory,
        Duration::from_millis(300),
    );
    let elapsed = start.elapsed();
    let Err(Failure::Limit { status, .. }) = outcome else {
        panic!("the child passes the limit: {outcome:?}");
    };
    assert_eq!(status.signal(), Some(9), "SIGKILL ends the child");
    assert!(
        elapsed >= Duration::from_millis(300) && elapsed < Duration::from_secs(5),
        "{elapsed:?}"
    );
    assert!(
        !directory.join("terminated").exists(),
        "the child receives no SIGTERM"
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
    let int = |text: &str| python_int(&parse(text).expect("the value parses"));
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
    let len = |text: &str| python_len(&parse(text).expect("the value parses"));
    assert_eq!(len(r#""\u00e9a""#), Some(2));
    assert_eq!(len("[1,[2,3]]"), Some(2));
    assert_eq!(len(r#"{"a":1}"#), Some(1));
    assert_eq!(len("7"), None);
    assert_eq!(python_len(&Value::Bool(true)), None);
}
