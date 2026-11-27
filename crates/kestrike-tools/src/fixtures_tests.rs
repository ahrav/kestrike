use std::ffi::{OsStr, OsString};
use std::fs::{self, DirBuilder};
use std::io;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use crate::fixtures::quint::{Failure, run};
use crate::fixtures::{Model, Style, Trace, case, generate, keep};
use crate::json::{Integer, Value, parse};
use crate::python;
use crate::tools;

/// `Scratch` owns a new directory of mode 0700 under the temporary directory and removes it on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        loop {
            let at = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "kestrike-tools-{label}-{}-{at}",
                std::process::id()
            ));
            match DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => {
                    return Self(path.canonicalize().expect("the scratch directory resolves"));
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("{}: {error}", path.display()),
            }
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn the_limit_ends_a_sleeping_child_with_sigkill() {
    let scratch = Scratch::new("limit");
    let directory = &scratch.0;
    let script =
        "trap 'echo term > terminated; exit 7' TERM; sleep 5 </dev/null >/dev/null 2>&1 & wait";
    let args: Vec<OsString> = ["-c", script].map(OsString::from).to_vec();
    let start = Instant::now();
    let outcome = run(
        OsStr::new("sh"),
        &args,
        directory,
        Stdio::null(),
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
}

#[test]
fn one_quint_run_is_limited_to_120_seconds_for_format_writers_and_60_for_record_writers() {
    let models = [
        (tools::escrow_fixtures::MODEL, Style::Format, 120),
        (tools::gate_fixtures::MODEL, Style::Format, 120),
        (tools::marklog_fixtures::MODEL, Style::Format, 120),
        (tools::grace_fixtures::MODEL, Style::Record, 60),
        (tools::lookup_fixtures::MODEL, Style::Record, 60),
        (tools::reclaim_fixtures::MODEL, Style::Record, 60),
        (tools::register_fixtures::MODEL, Style::Record, 60),
    ];
    for (model, style, seconds) in models {
        assert_eq!(model.style, style, "{}", model.tool);
        assert_eq!(model.limit, Duration::from_secs(seconds), "{}", model.tool);
    }
}

#[test]
fn a_child_exit_status_reaches_the_caller() {
    let args: Vec<OsString> = ["-c", "exit 3"].map(OsString::from).to_vec();
    let limit = Duration::from_secs(120);
    let outcome = run(
        OsStr::new("sh"),
        &args,
        &std::env::temp_dir(),
        Stdio::null(),
        limit,
    );
    assert!(
        matches!(outcome, Err(Failure::Exit(status)) if status.code() == Some(3)),
        "{outcome:?}"
    );
    let outcome = run(
        OsStr::new("/nonexistent/quint"),
        &[],
        &std::env::temp_dir(),
        Stdio::null(),
        limit,
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
    for (name, style) in [("gate", Style::Format), ("grace", Style::Record)] {
        let scratch = Scratch::new("writer-limit");
        let scratch = &scratch.0;
        let quint = scratch.join("quint");
        fs::write(&quint, "#!/bin/sh\nexec sleep 5\n").expect("the stand-in is written");
        fs::set_permissions(&quint, fs::Permissions::from_mode(0o755))
            .expect("the stand-in is executable");
        let model = Model {
            tool: "writer",
            about: "About.",
            name,
            style,
            limit: Duration::from_millis(300),
        };
        let traces = ["first", "second"]
            .map(|name| Trace::new(name.to_owned(), 1, None, 12, case::gate, Vec::new()));
        let top = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let output = scratch.join("out");
        let outcome = generate(
            &model,
            &top,
            Some(quint.as_os_str()),
            &output,
            &traces,
            keep,
        );
        assert_eq!(
            outcome,
            Err("first: Quint ran past 0.3 seconds and was killed".to_owned()),
            "{style:?}"
        );
        assert!(output.join("first/case.qnt").exists());
        assert!(!output.join("second").exists());
    }
}

#[test]
fn a_seeded_trace_of_usize_max_steps_fails_its_state_count() {
    let scratch = Scratch::new("writer-count");
    let quint = scratch.0.join("quint");
    let script = "#!/bin/sh\nwhile [ $# -gt 0 ]; do [ \"$1\" = --out-itf ] && out=$2; shift; done\n\
                  printf '{\"states\":[]}' > \"$out\"\n";
    fs::write(&quint, script).expect("the stand-in is written");
    fs::set_permissions(&quint, fs::Permissions::from_mode(0o755))
        .expect("the stand-in is executable");
    let model = Model {
        tool: "writer",
        about: "About.",
        name: "grace",
        style: Style::Record,
        limit: Duration::from_secs(120),
    };
    let traces = ["first", "second"]
        .map(|name| Trace::new(name.to_owned(), 1, None, usize::MAX, case::gate, Vec::new()));
    let top = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = scratch.0.join("out");
    let outcome = generate(
        &model,
        &top,
        Some(quint.as_os_str()),
        &output,
        &traces,
        keep,
    );
    assert_eq!(
        outcome,
        Err("first: the trace stopped before its final action".to_owned())
    );
    assert_eq!(
        fs::read(output.join("first.itf.json")).expect("Quint's trace stays"),
        b"{\"states\":[]}"
    );
    assert!(!output.join("second").exists());
}
