use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::fixtures::quint::{Failure, run};
use crate::fixtures::{Model, Style, Trace, case, generate, keep};
use crate::json::{Value, parse};
use crate::paths_tests::Scratch;
use crate::tools;

const GATE: Model = Model {
    tool: "gate_fixtures",
    about: "About.",
    name: "gate",
    style: Style::Format,
    limit: Duration::from_secs(120),
};

fn script(path: &Path, text: &str) {
    fs::write(path, text).expect("the stand-in is written");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        .expect("the stand-in is executable");
}

fn checkout() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn seeded(name: &str, steps: usize) -> Trace {
    Trace::new(name.to_owned(), 1, None, steps, case::gate, Vec::new())
}

#[test]
fn the_limit_ends_a_sleeping_child_with_sigkill() {
    let scratch = Scratch::new("limit");
    let script =
        "trap 'echo term > terminated; exit 7' TERM; sleep 5 </dev/null >/dev/null 2>&1 & wait";
    let args: Vec<OsString> = ["-c", script].map(OsString::from).to_vec();
    let start = Instant::now();
    let outcome = run(
        OsStr::new("sh"),
        &args,
        &scratch.0,
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
        !scratch.0.join("terminated").exists(),
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
fn a_writer_at_the_limit_exits_with_the_trace_named_and_writes_no_later_trace() {
    for (name, style) in [("gate", Style::Format), ("grace", Style::Record)] {
        let scratch = Scratch::new("writer-limit");
        let quint = scratch.0.join("quint");
        script(&quint, "#!/bin/sh\nexec sleep 5\n");
        let model = Model {
            tool: "writer",
            about: "About.",
            name,
            style,
            limit: Duration::from_millis(300),
        };
        let traces = [seeded("first", 12), seeded("second", 12)];
        let output = scratch.0.join("out");
        let outcome = generate(
            &model,
            &checkout(),
            quint.as_os_str(),
            &output,
            &traces,
            keep,
        );
        assert_eq!(
            outcome,
            Err("first: Quint ran past 0.3 seconds and was sent SIGKILL".to_owned()),
            "{style:?}"
        );
        assert!(output.join("first/case.qnt").exists());
        assert!(!output.join("second").exists());
    }
}

/// A step count whose successor `usize` cannot hold fails the state-count check in every build profile,
/// and Quint's bytes stay at the trace path.
#[test]
fn a_step_count_of_usize_max_fails_the_state_count_check() {
    let scratch = Scratch::new("max-steps");
    let quint = scratch.0.join("quint");
    let raw = r##"{"#meta":{"format":"ITF"},"states":[]}"##;
    script(
        &quint,
        &format!("#!/bin/sh\nfor arg; do out=$arg; done\nprintf '%s' '{raw}' > \"$out\"\n"),
    );
    let output = scratch.0.join("out");
    let outcome = generate(
        &GATE,
        &checkout(),
        quint.as_os_str(),
        &output,
        &[seeded("huge", usize::MAX)],
        keep,
    );
    assert_eq!(
        outcome,
        Err("huge: the trace stopped before its final action".to_owned())
    );
    assert_eq!(
        fs::read_to_string(output.join("huge.itf.json")).expect("Quint's trace stays"),
        raw
    );
}

/// The model's digest comes from one read before the first trace, and each trace directory gets a fresh
/// read of the model, so a model changed during a run gives the later traces the new text under the first
/// digest.
#[test]
fn the_model_digest_is_read_once_and_each_copy_is_read_anew() {
    let scratch = Scratch::new("model-race");
    let top = scratch.0.join("top");
    fs::create_dir_all(top.join("quint")).expect("the private top is made");
    let model = top.join("quint/gate.qnt");
    fs::write(&model, "module gate { val a = 1 }\n").expect("the model is written");
    let quint = scratch.0.join("quint");
    script(
        &quint,
        &format!(
            "#!/bin/sh\nfor arg; do out=$arg; done\nprintf 'module gate {{ val b = 2 }}\\n' > '{}'\n\
             printf '%s' '{{\"#meta\":{{\"format\":\"ITF\"}},\"states\":[{{}}]}}' > \"$out\"\n",
            model.display()
        ),
    );
    let output = scratch.0.join("out");
    let outcome = generate(
        &GATE,
        &top,
        quint.as_os_str(),
        &output,
        &[seeded("first", 0), seeded("second", 0)],
        keep,
    );
    assert_eq!(outcome, Ok(()));
    assert_eq!(
        fs::read_to_string(output.join("second/gate.qnt")).expect("the copy reads"),
        "module gate { val b = 2 }\n"
    );
    let digest: String = Sha256::digest(b"module gate { val a = 1 }\n")
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let written = fs::read_to_string(output.join("second.itf.json")).expect("the trace reads");
    let Ok(Value::Object(data)) = parse(&written) else {
        panic!("the trace is an object: {written}");
    };
    let Some(Value::Object(meta)) = data.get("#meta") else {
        panic!("the trace has #meta: {written}");
    };
    let Some(Value::Object(record)) = meta.get("gate") else {
        panic!("#meta holds the writer's record: {written}");
    };
    assert_eq!(
        record.get("model_sha256"),
        Some(&Value::String(digest.as_str().into()))
    );
}

/// A Quint that exits 0 without writing leaves the file already at the trace path in place, and the writer
/// reads that file as the trace and writes it again under its own record.
#[test]
fn a_file_left_at_the_trace_path_is_read_as_the_trace_when_quint_writes_none() {
    let scratch = Scratch::new("leftover");
    let quint = scratch.0.join("quint");
    script(&quint, "#!/bin/sh\nexit 0\n");
    let output = scratch.0.join("out");
    fs::create_dir_all(&output).expect("the output directory is made");
    fs::write(
        output.join("first.itf.json"),
        r##"{"#meta":{"format":"ITF","source":"old"},"states":[{"left":"over"}]}"##,
    )
    .expect("the leftover trace is written");
    let outcome = generate(
        &GATE,
        &checkout(),
        quint.as_os_str(),
        &output,
        &[seeded("first", 0)],
        keep,
    );
    assert_eq!(outcome, Ok(()));
    let written = fs::read_to_string(output.join("first.itf.json")).expect("the trace reads");
    assert!(
        written.starts_with(r##"{"#meta":{"format":"ITF","gate":{"model_sha256":""##)
            && written.ends_with(
                r#""seed":"0x1","steps":0}},"states":[{"left":"over"}]}
"#
            ),
        "{written}"
    );
}
