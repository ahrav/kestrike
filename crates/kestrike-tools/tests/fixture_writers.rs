//! The test runs the fixture writers against a POSIX `sh` script that stands in for `quint`. The script
//! answers each call with a committed trace stripped of what the writer adds, and refuses a call whose
//! arguments belong to another trace.

use std::ffi::OsStr;
use std::fs::{self, DirBuilder};
use std::io::{self, Write};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

use kestrike_tools::json::{self, Object, Value};

const BINARY: &str = env!("CARGO_BIN_EXE_kestrike-tools");

struct Writer {
    tool: &'static str,
    model: &'static str,
    fixtures: &'static str,
    directed: (&'static str, &'static str),
    seeded: (&'static str, &'static str),
    count: usize,
    recipes: &'static [&'static str],
}

const WRITERS: [Writer; 3] = [
    Writer {
        tool: "escrow_fixtures",
        count: 14,
        recipes: &[
            "an_exact_promise_succeeds_and_a_short_one_refuses",
            "a_claim_beside_a_promise_spares_the_promised_units",
            "two_builders_interleave_and_each_exit_refunds_once",
            "the_reserve_refuses_a_promise_of_exactly_the_allocatable_units",
            "every_exit_at_every_cut",
            "refusals_beside_promises_and_claims",
        ],
        model: "escrow",
        fixtures: "crates/kestrike/src/storage/builder_tests/escrow_replay_fixtures",
        directed: (
            "every_exit_at_every_cut",
            "module escrowCase {\n  import escrow(BOUND = 15, VOLUME = 316).* from \"./escrow\"\n  action recipe = \
             any {\n    all { Set(0).contains(turn), promise(1, 2) },\n    all { Set(1, 7).contains(turn), cancel(1) \
             },\n    all { Set(2).contains(turn), promise(2, 3) },\n    all { Set(3, 11).contains(turn), release(2) \
             },\n    all { Set(4, 12, 13, 14).contains(turn), service },\n    all { Set(5).contains(turn), \
             promise(1, 3) },\n    all { Set(6).contains(turn), place(1) },\n    all { Set(8).contains(turn), \
             promise(2, 2) },\n    all { Set(9, 10).contains(turn), place(2) },\n  }\n}\n",
        ),
        seeded: (
            "step_e56",
            "module escrowCase {\n  import escrow(BOUND = 12, VOLUME = 315).* from \"./escrow\"\n}\n",
        ),
    },
    Writer {
        tool: "gate_fixtures",
        count: 26,
        recipes: &[
            "passes",
            "busy_then_foreign_registrant",
            "acquire_conflict",
            "report_times_out",
            "register_conflict",
            "submit_refused",
            "device_gone",
            "foreign_holder",
            "other_type",
            "duplicate_own_record",
            "own_pair_not_holding",
            "withheld_bytes",
            "failed_report",
            "deposing_report",
            "expiry_under_the_register",
            "withdrawal_under_the_acquire",
            "close_under_the_report",
            "close_before_the_register",
        ],
        model: "gate",
        fixtures: "crates/kestrike/src/storage/volume/gate_replay_fixtures",
        directed: (
            "passes",
            "module gateCase {\n  import gate(BOUND = 7).* from \"./gate\"\n  action recipe = any {\n    all { Set(0, \
             2, 4, 6).contains(turn), tick(\"none\") },\n    all { Set(1).contains(turn), register(true) },\n    all { \
             Set(3).contains(turn), acquire(true) },\n    all { Set(5).contains(turn), report(\"sole\") },\n  }\n}\n",
        ),
        seeded: (
            "step_1221",
            "module gateCase {\n  import gate(BOUND = 12).* from \"./gate\"\n}\n",
        ),
    },
    Writer {
        tool: "marklog_fixtures",
        count: 12,
        recipes: &[
            "partly_landed",
            "whole_replacement",
            "out_of_key_order",
            "raise_after_whole",
            "crashes",
            "whole_then_in_place",
        ],
        model: "marklog",
        fixtures: "crates/kestrike/src/storage/marklog_replay_fixtures",
        directed: (
            "crashes",
            "module marklogCase {\n  import marklog(BOUND = 8).* from \"./marklog\"\n  action recipe = any {\n    all \
             { turn == 0, read(Set(2)) },\n    all { turn == 1, write(2) },\n    all { turn == 2, crash(Set(2), \
             Set()) },\n    all { turn == 3, crash(Set(2), Set(2)) },\n    all { turn == 4, write(2) },\n    all { \
             turn == 5, crash(Set(1, 2), Set(2)) },\n    all { turn == 6, read(Set(1, 2)) },\n    all { turn == 7, \
             read(Set(1, 2, 3)) },\n  }\n}\n",
        ),
        seeded: (
            "step_6b01",
            "module marklogCase {\n  import marklog(BOUND = 14).* from \"./marklog\"\n}\n",
        ),
    },
];

fn top() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the checkout's top level resolves")
}

/// `Scratch` is a directory the test process created itself, with mode 0700, and removes on drop. A name
/// that already exists is left as it is and the next name is tried. The path is the resolved temporary
/// directory and the new name, as the writers resolve `--output`.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        loop {
            let at = NEXT.fetch_add(1, Ordering::Relaxed);
            let parent = std::env::temp_dir()
                .canonicalize()
                .expect("the temporary directory resolves");
            let path = parent.join(format!("kestrike-tools-test-{}-{at}", std::process::id()));
            match DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Self(path),
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

struct Committed {
    name: String,
    bytes: Vec<u8>,
    data: Object,
}

fn committed(writer: &Writer) -> Vec<Committed> {
    let directory = top().join(writer.fixtures);
    let mut traces: Vec<Committed> = fs::read_dir(&directory)
        .expect("the fixture directory reads")
        .map(|entry| entry.expect("the fixture directory lists").path())
        .map(|path| {
            let kind = fs::symlink_metadata(&path).expect("a fixture's type reads");
            assert!(
                kind.is_file() && path.to_string_lossy().ends_with(".itf.json"),
                "{} is a regular .itf.json file",
                path.display()
            );
            let bytes = fs::read(&path).expect("a committed trace reads");
            let text = std::str::from_utf8(&bytes).expect("a committed trace is UTF-8");
            let Value::Object(data) = json::parse(text).expect("a committed trace parses") else {
                panic!("{} holds a JSON value other than an object", path.display());
            };
            let file = path
                .file_name()
                .and_then(OsStr::to_str)
                .expect("a fixture's name is UTF-8");
            let name = file
                .strip_suffix(".itf.json")
                .expect("a fixture ends in .itf.json")
                .to_owned();
            Committed { name, bytes, data }
        })
        .collect();
    traces.sort_by(|left, right| left.name.cmp(&right.name));
    traces
}

fn object<'a>(value: Option<&'a Value>, what: &str) -> &'a Object {
    match value {
        Some(Value::Object(object)) => object,
        _ => panic!("{what} is a JSON object"),
    }
}

fn text<'a>(value: Option<&'a Value>, what: &str) -> &'a str {
    match value {
        Some(Value::String(text)) => text.as_str(),
        _ => panic!("{what} is a JSON string"),
    }
}

fn reply(trace: &Committed) -> String {
    let mut data = trace.data.clone();
    let format = object(data.get("#meta"), "#meta")
        .get("format")
        .cloned()
        .expect("#meta holds format");
    let mut meta = Object::new();
    meta.insert("format", format);
    for (key, value) in [
        (
            "format-description",
            "https://apalache-mc.org/docs/adr/015adr-trace.html",
        ),
        ("source", "case.qnt"),
        ("status", "ok"),
        (
            "description",
            "Created by Quint on Fri Nov 27 2026 02:39:48 GMT+0000 (Coordinated Universal Time)",
        ),
    ] {
        meta.insert(key, Value::String(value.into()));
    }
    meta.insert(
        "timestamp",
        json::parse("1795747188123").expect("an integer parses"),
    );
    data.insert("#meta", Value::Object(meta));
    if let Some(Value::Array(states)) = data.get_mut("states") {
        for state in states {
            if let Value::Object(state) = state {
                state.remove("call");
            }
        }
    }
    json::text(&Value::Object(data))
}

/// `expected_call` returns the arguments the writer passes to Quint for `trace`, each ended by a NUL byte.
fn expected_call(writer: &Writer, trace: &Committed, output: &Path) -> String {
    let record = object(
        object(trace.data.get("#meta"), "#meta").get(writer.model),
        "the writer's record",
    );
    let steps = match record.get("steps") {
        Some(Value::Integer(steps)) => steps.to_string(),
        _ => panic!("the record holds an integer steps"),
    };
    let mut call = vec!["run", "case.qnt", "--main"]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    call.push(format!("{}Case", writer.model));
    if record.get("recipe").is_some() {
        call.extend(["--step".to_owned(), "recipe".to_owned()]);
    }
    for arg in [
        "--backend",
        "typescript",
        "--mbt",
        "--invariant",
        "safety",
        "--seed",
    ] {
        call.push(arg.to_owned());
    }
    call.push(text(record.get("seed"), "seed").to_owned());
    call.extend(["--max-samples", "1", "--max-steps"].map(str::to_owned));
    call.push(steps);
    call.extend(["--n-traces", "1", "--out-itf"].map(str::to_owned));
    call.push(
        output
            .join(format!("{}.itf.json", trace.name))
            .to_str()
            .expect("the path is UTF-8")
            .to_owned(),
    );
    call.iter().map(|arg| format!("{arg}\0")).collect()
}

const STAND_IN: &str = r#"#!/bin/sh
replies="$(dirname "$0")/replies"
out= prev=
for arg in "$@"; do
  [ "$prev" = --out-itf ] && out=$arg
  prev=$arg
done
name=${out##*/}
name=${name%.itf.json}
[ -f "$replies/$name.call" ] || { echo "stand-in: no trace $name" >&2; exit 3; }
printf '%s\0' "$@" | cmp -s - "$replies/$name.call" || { echo "stand-in: a call of another trace" >&2; exit 3; }
here=$(pwd -P)
[ "${here##*/}" = "$name" ] || { echo "stand-in: $name runs outside its own directory" >&2; exit 3; }
[ -f case.qnt ] || { echo "stand-in: no case.qnt in the working directory" >&2; exit 3; }
echo "$name" >> "$replies/calls"
echo "stand-in: writing $name"
cat "$replies/$name.reply" > "$out"
"#;

/// Writes the executable script at `path` through a child process, the one process that holds the file open
/// for writing. `execve` refuses a file that any process holds open for writing with `ETXTBSY`, and a child
/// that another test thread forks inherits every descriptor of this process until its own `execve`. No
/// descriptor of the script is open here, so the script starts whatever the other threads fork.
fn write_script(path: &Path, text: &str) {
    let mut writer = Command::new("sh")
        .args(["-c", r#"cat > "$1" && chmod 755 "$1""#, "sh"])
        .arg(path)
        .stdin(Stdio::piped())
        .spawn()
        .expect("the script's writer starts");
    writer
        .stdin
        .take()
        .expect("the writer's standard input is a pipe")
        .write_all(text.as_bytes())
        .expect("the script's text reaches the writer");
    let status = writer.wait().expect("the script's writer is reaped");
    assert!(status.success(), "the script is written: {status}");
}

fn stand_in(
    scratch: &Path,
    writer: &Writer,
    output: &Path,
    reply: impl Fn(&Committed) -> String,
) -> PathBuf {
    let replies = scratch.join("replies");
    fs::create_dir_all(&replies).expect("the replies directory is created");
    for trace in committed(writer) {
        fs::write(
            replies.join(format!("{}.call", trace.name)),
            expected_call(writer, &trace, output),
        )
        .expect("the expected call is written");
        fs::write(replies.join(format!("{}.reply", trace.name)), reply(&trace))
            .expect("the reply is written");
    }
    let script = scratch.join("quint");
    write_script(&script, STAND_IN);
    script
}

fn run(tool: &str, args: &[&OsStr]) -> Output {
    Command::new(BINARY)
        .arg(top())
        .arg(tool)
        .args(args)
        .output()
        .expect("the binary starts")
}

fn write_traces(writer: &Writer, quint: &Path, output: &Path) -> Output {
    run(
        writer.tool,
        &[
            "--quint".as_ref(),
            quint.as_os_str(),
            "--output".as_ref(),
            output.as_os_str(),
        ],
    )
}

fn stderr(output: &Output) -> &str {
    std::str::from_utf8(&output.stderr).expect("standard error is UTF-8")
}

#[test]
fn each_committed_trace_is_written_byte_for_byte() {
    for writer in &WRITERS {
        let scratch = Scratch::new();
        let output = scratch.0.join("out");
        let quint = stand_in(&scratch.0, writer, &output, reply);
        let result = write_traces(writer, &quint, &output);
        assert_eq!(
            result.status.code(),
            Some(0),
            "{}: {}",
            writer.tool,
            stderr(&result)
        );
        assert!(
            result.stdout.is_empty() && result.stderr.is_empty(),
            "{} writes to neither stream",
            writer.tool
        );
        let traces = committed(writer);
        let model = fs::read(top().join("quint").join(format!("{}.qnt", writer.model)))
            .expect("the model reads");
        for trace in &traces {
            let written = fs::read(output.join(format!("{}.itf.json", trace.name)))
                .expect("the trace is written");
            assert!(
                written == trace.bytes,
                "{}: {} differs from its committed trace",
                writer.tool,
                trace.name
            );
            let copy = fs::read(
                output
                    .join(&trace.name)
                    .join(format!("{}.qnt", writer.model)),
            )
            .expect("copy reads");
            assert!(
                copy == model,
                "{}: the model beside {} differs from the model",
                writer.tool,
                trace.name
            );
        }
        for (name, expected) in [writer.directed, writer.seeded] {
            let case =
                fs::read_to_string(output.join(name).join("case.qnt")).expect("case.qnt reads");
            assert_eq!(case, expected, "{}: case.qnt of {name}", writer.tool);
        }
        let mut entries = 0;
        for entry in fs::read_dir(&output).expect("the output lists") {
            let path = entry.expect("the output lists").path();
            let kind = fs::symlink_metadata(&path).expect("an entry's type reads");
            let name = path
                .file_name()
                .and_then(OsStr::to_str)
                .expect("a UTF-8 name");
            let trace = name.strip_suffix(".itf.json").unwrap_or(name);
            assert!(
                traces.iter().any(|committed| committed.name == trace)
                    && (kind.is_file() == name.ends_with(".itf.json"))
                    && (kind.is_dir() != name.ends_with(".itf.json")),
                "{}: {name} is a trace file or a trace directory",
                writer.tool
            );
            entries += 1;
        }
        assert_eq!(
            entries,
            2 * traces.len(),
            "{}: one trace and one directory for each trace",
            writer.tool
        );
        assert_eq!(
            traces.len(),
            writer.count,
            "{}: the committed traces",
            writer.tool
        );
        let mut order: Vec<String> = writer
            .recipes
            .iter()
            .map(|name| (*name).to_owned())
            .collect();
        let mut seeds: Vec<String> = traces
            .iter()
            .map(|trace| trace.name.clone())
            .filter(|name| name.starts_with("step_"))
            .collect();
        seeds.sort_by_key(|name| {
            u64::from_str_radix(&name["step_".len()..], 16).expect("a seed is hexadecimal")
        });
        order.extend(seeds);
        let calls =
            fs::read_to_string(scratch.0.join("replies/calls")).expect("the calls log reads");
        assert_eq!(
            calls.lines().collect::<Vec<_>>(),
            order,
            "{}: the traces run in order",
            writer.tool
        );
    }
}

#[test]
fn a_missing_option_exits_2_naming_the_required_options() {
    let result = run("gate_fixtures", &["--quint".as_ref(), "quint".as_ref()]);
    assert_eq!(result.status.code(), Some(2));
    assert!(result.stdout.is_empty());
    assert_eq!(
        stderr(&result),
        "usage: gate_fixtures [-h] --quint QUINT --output OUTPUT\n\
         gate_fixtures: error: the following arguments are required: --output\n"
    );
}

#[test]
fn help_prints_the_usage_on_standard_output_and_exits_0() {
    for flag in ["-h", "--help"] {
        let result = run("marklog_fixtures", &[flag.as_ref()]);
        assert_eq!(result.status.code(), Some(0));
        assert!(result.stderr.is_empty());
        let stdout = std::str::from_utf8(&result.stdout).expect("the help is UTF-8");
        assert!(
            stdout.starts_with("usage: marklog_fixtures [-h] --quint QUINT --output OUTPUT\n"),
            "{stdout}"
        );
    }
}

#[test]
fn an_unknown_tool_exits_2() {
    let result = run("check", &[]);
    assert_eq!(result.status.code(), Some(2));
    let line = stderr(&result);
    let tools = line
        .strip_prefix("kestrike-tools: no tool is named check; the tools are ")
        .and_then(|rest| rest.strip_suffix('\n'))
        .unwrap_or_else(|| panic!("{line}"));
    let tools: Vec<&str> = tools.split(", ").collect();
    assert!(tools.is_sorted(), "{line}");
    for writer in &WRITERS {
        assert!(tools.contains(&writer.tool), "{line}");
    }
}

#[test]
fn an_existing_trace_directory_exits_1_at_that_trace_and_keeps_the_earlier_ones() {
    let writer = &WRITERS[0];
    let scratch = Scratch::new();
    let output = scratch.0.join("out");
    let quint = stand_in(&scratch.0, writer, &output, reply);
    let second = "a_claim_beside_a_promise_spares_the_promised_units";
    fs::create_dir_all(output.join(second)).expect("the earlier run's directory is made");
    let result = write_traces(writer, &quint, &output);
    assert_eq!(result.status.code(), Some(1));
    let line = format!(
        "escrow_fixtures: {}: File exists (os error 17)\n",
        output.join(second).display()
    );
    assert_eq!(stderr(&result), line);
    let first = "an_exact_promise_succeeds_and_a_short_one_refuses";
    let kept = fs::read(output.join(format!("{first}.itf.json"))).expect("the first trace stays");
    let expected = committed(writer)
        .into_iter()
        .find(|trace| trace.name == first)
        .expect("the first is committed");
    assert!(kept == expected.bytes, "the first trace is complete");
    assert!(
        !output.join(format!("{second}.itf.json")).exists(),
        "the run stops at the second trace"
    );
    assert!(
        !output
            .join("two_builders_interleave_and_each_exit_refunds_once")
            .exists()
    );
}

#[test]
fn a_quint_that_exits_1_ends_the_run_with_exit_1() {
    let scratch = Scratch::new();
    let quint = scratch.0.join("quint");
    write_script(
        &quint,
        "#!/bin/sh\necho 'quint: on standard output'\necho 'quint: on standard error' >&2\nexit 1\n",
    );
    let output = scratch.0.join("out");
    let result = write_traces(&WRITERS[1], &quint, &output);
    assert_eq!(result.status.code(), Some(1));
    assert!(
        result.stdout.is_empty(),
        "Quint's standard output is discarded"
    );
    assert_eq!(
        stderr(&result),
        "quint: on standard error\ngate_fixtures: passes: Quint ended with exit status: 1\n"
    );
    assert!(!output.join("passes.itf.json").exists());
    assert!(!output.join("busy_then_foreign_registrant").exists());
}

#[test]
fn a_short_trace_exits_1_naming_the_trace_and_keeps_quints_bytes() {
    let writer = &WRITERS[2];
    let scratch = Scratch::new();
    let output = scratch.0.join("out");
    let short = |trace: &Committed| {
        let Ok(Value::Object(mut data)) = json::parse(&reply(trace)) else {
            panic!("a reply parses as an object");
        };
        if let Some(Value::Array(states)) = data.get_mut("states") {
            states.pop();
        }
        json::text(&Value::Object(data))
    };
    let quint = stand_in(&scratch.0, writer, &output, short);
    let result = write_traces(writer, &quint, &output);
    assert_eq!(result.status.code(), Some(1));
    assert_eq!(
        stderr(&result),
        "marklog_fixtures: partly_landed: the trace stopped before its final action\n"
    );
    let raw = fs::read(output.join("partly_landed.itf.json")).expect("Quint's trace stays");
    assert_eq!(
        raw,
        fs::read(scratch.0.join("replies/partly_landed.reply")).expect("the reply reads")
    );
    assert!(!output.join("whole_replacement").exists());
}

#[test]
fn a_long_trace_exits_1_naming_the_trace() {
    let writer = &WRITERS[2];
    let scratch = Scratch::new();
    let output = scratch.0.join("out");
    let long = |trace: &Committed| {
        let mut data = trace.data.clone();
        if let Some(Value::Array(states)) = data.get_mut("states") {
            let last = states.last().cloned().expect("a trace has states");
            states.push(last);
        }
        json::dump(&Value::Object(data))
    };
    let quint = stand_in(&scratch.0, writer, &output, long);
    let result = write_traces(writer, &quint, &output);
    assert_eq!(result.status.code(), Some(1));
    assert_eq!(
        stderr(&result),
        "marklog_fixtures: partly_landed: the trace stopped before its final action\n"
    );
}

#[test]
fn a_trace_with_null_exits_1_naming_its_file() {
    let writer = &WRITERS[1];
    let scratch = Scratch::new();
    let output = scratch.0.join("out");
    let quint = stand_in(&scratch.0, writer, &output, |trace| {
        reply(trace).replacen("\"vars\"", "\"x\":null,\"vars\"", 1)
    });
    let result = write_traces(writer, &quint, &output);
    assert_eq!(result.status.code(), Some(1));
    let file = output.join("passes.itf.json");
    let stderr = stderr(&result);
    assert!(
        stderr.starts_with(&format!(
            "gate_fixtures: {}: null is refused at byte ",
            file.display()
        )),
        "{stderr}"
    );
}

#[test]
fn a_relative_output_resolves_against_the_working_directory() {
    let writer = &WRITERS[2];
    let scratch = Scratch::new();
    let output = scratch.0.join("out");
    let quint = stand_in(&scratch.0, writer, &output, reply);
    let result = Command::new(BINARY)
        .arg(top())
        .arg(writer.tool)
        .args([
            "--quint".as_ref(),
            quint.as_os_str(),
            "--output=out".as_ref(),
        ])
        .current_dir(&scratch.0)
        .output()
        .expect("the binary starts");
    assert_eq!(result.status.code(), Some(0), "{}", stderr(&result));
    assert!(output.join("step_6b0d.itf.json").exists());
}

/// With `--quint=--`, the fixture writer creates the first trace directory, writes the model copy and `case.qnt`
/// there, then exits with status 1.
#[test]
fn an_empty_quint_value_exits_1_after_the_first_trace_directory_is_written() {
    let scratch = Scratch::new();
    let output = scratch.0.join("out");
    let result = run(
        "gate_fixtures",
        &[
            "--quint=--".as_ref(),
            "--output".as_ref(),
            output.as_os_str(),
        ],
    );
    assert_eq!(result.status.code(), Some(1));
    assert_eq!(
        stderr(&result),
        "gate_fixtures: argument --quint: the value `--` leaves no program\n"
    );
    assert!(output.join("passes/gate.qnt").exists() && output.join("passes/case.qnt").exists());
    assert!(!output.join("busy_then_foreign_registrant").exists());
}

#[test]
fn help_on_a_full_standard_output_exits_120() {
    let full = fs::File::create("/dev/full").expect("/dev/full opens");
    let result = Command::new(BINARY)
        .arg(top())
        .args(["gate_fixtures", "-h"])
        .stdout(full)
        .output()
        .expect("the binary starts");
    assert_eq!(result.status.code(), Some(120));
    assert!(
        stderr(&result).starts_with("gate_fixtures: standard output: "),
        "{}",
        stderr(&result)
    );
}

#[test]
fn a_refusal_on_a_full_standard_error_exits_120() {
    let full = fs::File::create("/dev/full").expect("/dev/full opens");
    let result = Command::new(BINARY)
        .arg(top())
        .args(["gate_fixtures", "--bogus"])
        .stderr(full)
        .output()
        .expect("the binary starts");
    assert_eq!(result.status.code(), Some(120));
}

fn committed_trace(writer: &Writer, name: &str) -> Committed {
    committed(writer)
        .into_iter()
        .find(|trace| trace.name == name)
        .unwrap_or_else(|| panic!("{name} is committed"))
}

fn parsed(text: &str) -> Object {
    match json::parse(text) {
        Ok(Value::Object(data)) => data,
        other => panic!("a reply parses as an object: {other:?}"),
    }
}

#[test]
fn an_empty_output_value_exits_1_before_quint_starts_and_writes_nothing() {
    let scratch = Scratch::new();
    let here = scratch.0.join("here");
    fs::create_dir(&here).expect("the working directory is made");
    let marker = scratch.0.join("called");
    let quint = scratch.0.join("quint");
    write_script(
        &quint,
        &format!("#!/bin/sh\n: > '{}'\nexit 1\n", marker.display()),
    );
    let result = Command::new(BINARY)
        .arg(top())
        .args([
            "gate_fixtures".as_ref(),
            "--quint".as_ref(),
            quint.as_os_str(),
        ])
        .arg("--output=--")
        .current_dir(&here)
        .output()
        .expect("the binary starts");
    assert_eq!(result.status.code(), Some(1));
    assert_eq!(
        stderr(&result),
        "gate_fixtures: argument --output: the value `--` leaves no path\n"
    );
    assert_eq!(fs::read_dir(&here).expect("the directory lists").count(), 0);
    assert!(!marker.exists(), "Quint never starts");
}

#[test]
fn the_format_is_copied_from_quints_meta_and_a_missing_one_exits_1() {
    let writer = &WRITERS[1];
    let scratch = Scratch::new();
    let output = scratch.0.join("out");
    let quint = stand_in(&scratch.0, writer, &output, |trace| {
        let mut data = parsed(&reply(trace));
        let Some(Value::Object(meta)) = data.get_mut("#meta") else {
            panic!("a reply has #meta");
        };
        match trace.name.as_str() {
            "passes" => meta.insert("format", Value::String("ITF-x".into())),
            _ => {
                meta.remove("format");
            }
        }
        json::text(&Value::Object(data))
    });
    let result = write_traces(writer, &quint, &output);
    assert_eq!(result.status.code(), Some(1));
    let first = fs::read_to_string(output.join("passes.itf.json")).expect("the first trace reads");
    let expected = String::from_utf8(committed_trace(writer, "passes").bytes)
        .expect("a committed trace is UTF-8")
        .replacen(r#""format":"ITF""#, r#""format":"ITF-x""#, 1);
    assert_eq!(first, expected);
    let file = output.join("busy_then_foreign_registrant.itf.json");
    assert_eq!(
        stderr(&result),
        format!(
            "gate_fixtures: {}: the trace has no '#meta' record with a 'format'\n",
            file.display()
        )
    );
    assert_eq!(
        fs::read(&file).expect("Quint's trace stays"),
        fs::read(scratch.0.join("replies/busy_then_foreign_registrant.reply"))
            .expect("the reply reads")
    );
    assert!(!output.join("acquire_conflict").exists());
}

#[test]
fn a_trace_without_states_exits_1_naming_its_file() {
    let writer = &WRITERS[1];
    let scratch = Scratch::new();
    let output = scratch.0.join("out");
    let quint = stand_in(&scratch.0, writer, &output, |trace| {
        let mut data = parsed(&reply(trace));
        data.remove("states");
        json::text(&Value::Object(data))
    });
    let result = write_traces(writer, &quint, &output);
    assert_eq!(result.status.code(), Some(1));
    assert_eq!(
        stderr(&result),
        format!(
            "gate_fixtures: {}: the trace has no key 'states'\n",
            output.join("passes.itf.json").display()
        )
    );
}

#[test]
fn a_seeded_marklog_step_without_picks_exits_1_naming_its_file() {
    let writer = &WRITERS[2];
    let scratch = Scratch::new();
    let output = scratch.0.join("out");
    let quint = stand_in(&scratch.0, writer, &output, |trace| {
        let mut data = parsed(&reply(trace));
        if trace.name == "step_6b01"
            && let Some(Value::Array(states)) = data.get_mut("states")
            && let Some(Value::Object(state)) = states.get_mut(1)
        {
            state.remove("mbt::nondetPicks");
        }
        json::text(&Value::Object(data))
    });
    let result = write_traces(writer, &quint, &output);
    assert_eq!(result.status.code(), Some(1));
    assert_eq!(
        stderr(&result),
        format!(
            "marklog_fixtures: {}: no key 'mbt::nondetPicks'\n",
            output.join("step_6b01.itf.json").display()
        )
    );
    assert!(!output.join("step_6b02").exists());
}

#[test]
fn a_quint_that_cannot_start_exits_1_naming_the_trace() {
    let scratch = Scratch::new();
    let output = scratch.0.join("out");
    let result = write_traces(&WRITERS[1], Path::new("/nonexistent/quint"), &output);
    assert_eq!(result.status.code(), Some(1));
    assert!(
        stderr(&result).starts_with("gate_fixtures: passes: Quint did not start: "),
        "{}",
        stderr(&result)
    );
    assert!(!output.join("busy_then_foreign_registrant").exists());
}

/// Quint runs in the trace's directory, so a relative `--quint` with a `/` names a file there: from
/// `<scratch>/out/<name>/`, `../../quint` is the stand-in, while from the test's working directory, the
/// crate's directory, it names the checkout's `quint/` directory.
#[test]
fn a_relative_quint_with_a_slash_names_a_file_in_the_trace_directory() {
    let writer = &WRITERS[1];
    let scratch = Scratch::new();
    let output = scratch.0.join("out");
    stand_in(&scratch.0, writer, &output, reply);
    let result = write_traces(writer, Path::new("../../quint"), &output);
    assert_eq!(result.status.code(), Some(0), "{}", stderr(&result));
    assert!(output.join("step_1228.itf.json").exists());
}

/// The stand-in compares the whole argument vector, argument boundaries included, so a recorded call that
/// joins two arguments into one is refused and the writer exits 1 after the stand-in's own line.
#[test]
fn the_stand_in_refuses_a_call_that_differs_from_the_recorded_one() {
    let writer = &WRITERS[1];
    let scratch = Scratch::new();
    let output = scratch.0.join("out");
    let quint = stand_in(&scratch.0, writer, &output, reply);
    let call = scratch.0.join("replies/passes.call");
    let recorded = fs::read_to_string(&call).expect("the call reads");
    let joined = recorded.replacen("--invariant\0safety\0", "--invariant safety\0", 1);
    assert_ne!(joined, recorded);
    fs::write(&call, joined).expect("the call is rewritten");
    let result = write_traces(writer, &quint, &output);
    assert_eq!(result.status.code(), Some(1));
    assert_eq!(
        stderr(&result),
        "stand-in: a call of another trace\ngate_fixtures: passes: Quint ended with exit status: 3\n"
    );
}

/// The state count compares the length of the `states` value, so a string or an object of `steps + 1`
/// characters or members passes the check and is written under the writer's record.
#[test]
fn a_states_value_of_the_right_length_passes_the_count_whatever_its_type() {
    for (writer, name) in [
        (
            &WRITERS[0],
            "an_exact_promise_succeeds_and_a_short_one_refuses",
        ),
        (&WRITERS[1], "passes"),
    ] {
        let scratch = Scratch::new();
        let output = scratch.0.join("out");
        let replace = |data: &mut Object| {
            let Some(Value::Array(states)) = data.get("states") else {
                panic!("a committed trace holds states");
            };
            let count = states.len();
            let value = if writer.model == "escrow" {
                Value::String("s".repeat(count).as_str().into())
            } else {
                let mut members = Object::new();
                for at in 0..count {
                    members.insert(format!("m{at}"), Value::Bool(true));
                }
                Value::Object(members)
            };
            data.insert("states", value);
        };
        let quint = stand_in(&scratch.0, writer, &output, |trace| {
            let mut data = parsed(&reply(trace));
            if trace.name == name {
                replace(&mut data);
            }
            json::text(&Value::Object(data))
        });
        let result = write_traces(writer, &quint, &output);
        assert_eq!(result.status.code(), Some(0), "{}", stderr(&result));
        let mut expected = committed_trace(writer, name).data;
        replace(&mut expected);
        assert_eq!(
            fs::read_to_string(output.join(format!("{name}.itf.json"))).expect("the trace reads"),
            json::dump(&Value::Object(expected)),
            "{}",
            writer.tool
        );
    }
}

#[test]
fn a_read_only_standard_stream_exits_120() {
    let read_only = || fs::File::open("/dev/null").expect("/dev/null opens");
    let help = Command::new(BINARY)
        .arg(top())
        .args(["gate_fixtures", "-h"])
        .stdout(read_only())
        .stderr(Stdio::null())
        .status()
        .expect("the binary starts");
    assert_eq!(help.code(), Some(120));
    let refusal = Command::new(BINARY)
        .arg(top())
        .args(["gate_fixtures", "--bogus"])
        .stderr(read_only())
        .status()
        .expect("the binary starts");
    assert_eq!(refusal.code(), Some(120));
}

/// `reverse_sets` reverses every `#set` array inside `value`.
fn reverse_sets(value: &mut Value) {
    match value {
        Value::Array(items) => items.iter_mut().for_each(reverse_sets),
        Value::Object(object) => {
            if let Some(Value::Array(items)) = object.get_mut("#set") {
                items.reverse();
            }
            let keys: Vec<String> = object
                .iter()
                .map(|(key, _)| key.as_str().to_owned())
                .collect();
            for key in keys {
                if let Some(member) = object.get_mut(&key) {
                    reverse_sets(member);
                }
            }
        }
        Value::String(_) | Value::Integer(_) | Value::Bool(_) => {}
    }
}

/// A seeded marklog `call` lists a set's pages in ascending order whatever order Quint's `#set` holds.
#[test]
fn a_seeded_marklog_call_sorts_the_pages_of_each_set() {
    let writer = &WRITERS[2];
    let scratch = Scratch::new();
    let output = scratch.0.join("out");
    let mut reversed = 0;
    for trace in committed(writer) {
        let mut data = parsed(&reply(&trace));
        let before = json::text(&Value::Object(data.clone()));
        if let Some(states) = data.get_mut("states") {
            reverse_sets(states);
        }
        if json::text(&Value::Object(data)) != before && trace.name.starts_with("step_") {
            reversed += 1;
        }
    }
    assert!(
        reversed > 0,
        "some seeded trace holds a set of two or more pages"
    );
    let quint = stand_in(&scratch.0, writer, &output, |trace| {
        let mut data = parsed(&reply(trace));
        if let Some(states) = data.get_mut("states") {
            reverse_sets(states);
        }
        json::text(&Value::Object(data))
    });
    let result = write_traces(writer, &quint, &output);
    assert_eq!(result.status.code(), Some(0), "{}", stderr(&result));
    for trace in committed(writer)
        .iter()
        .filter(|trace| trace.name.starts_with("step_"))
    {
        let Value::Object(written) = json::parse(
            &fs::read_to_string(output.join(format!("{}.itf.json", trace.name)))
                .expect("the trace reads"),
        )
        .expect("the trace parses") else {
            panic!("the trace is an object");
        };
        let calls = |data: &Object| match data.get("states") {
            Some(Value::Array(states)) => states
                .iter()
                .map(|state| match state {
                    Value::Object(state) => state.get("call").map(json::text),
                    _ => None,
                })
                .collect::<Vec<_>>(),
            _ => panic!("a trace holds states"),
        };
        assert_eq!(calls(&written), calls(&trace.data), "{}", trace.name);
    }
}
