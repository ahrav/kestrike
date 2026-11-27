//! The test runs the fixture writers against a POSIX `sh` script that stands in for `quint`. The script
//! answers each call with a committed trace stripped of what the writer adds, prints one line naming the
//! trace on standard output, and refuses a call whose arguments belong to another trace or that runs in a
//! directory other than `<output>/<name>/`.

use std::ffi::OsStr;
use std::fs::{self, DirBuilder};
use std::io::{self, Write};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

use kestrike_tools::fixtures::Style;
use kestrike_tools::json::{self, Object, Value};

const BINARY: &str = env!("CARGO_BIN_EXE_kestrike-tools");

struct Writer {
    tool: &'static str,
    style: Style,
    model: &'static str,
    fixtures: &'static str,
    directed: (&'static str, &'static str),
    seeded: (&'static str, &'static str),
    count: usize,
    recipes: &'static [&'static str],
}

/// Each `case.qnt` text is the case module of one directed and one seeded trace of the model.
const WRITERS: [Writer; 7] = [
    Writer {
        tool: "escrow_fixtures",
        style: Style::Format,
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
        style: Style::Format,
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
        style: Style::Format,
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
    Writer {
        tool: "grace_fixtures",
        style: Style::Record,
        count: 13,
        recipes: &[
            "readerBeforePass",
            "passBeforeReader",
            "releaseAfterUnpin",
            "terminalRefusesPins",
            "refusals",
            "keptCertificate",
            "closingRetirement",
        ],
        model: "grace",
        fixtures: "crates/kestrike/src/storage/grace_replay_fixtures",
        directed: (
            "releaseAfterUnpin",
            "module graceCase {\n  import grace(BOUND = 16).* from \"./grace\"\n  action recipe = any {\n    all { \
             Set(0).contains(turn), pin(0) },\n    all { Set(1).contains(turn), observe(0) },\n    all { \
             Set(2).contains(turn), remove },\n    all { Set(3).contains(turn), retire },\n    all { Set(4, \
             10).contains(turn), begin },\n    all { Set(5, 6, 11, 12).contains(turn), visit },\n    all { Set(7, \
             13).contains(turn), complete },\n    all { Set(8, 14).contains(turn), release },\n    all { \
             Set(9).contains(turn), unpin(0) },\n    all { Set(15).contains(turn), reuse },\n  }\n}\n",
        ),
        seeded: (
            "step_c",
            "module graceCase {\n  import grace(BOUND = 16).* from \"./grace\"\n}\n",
        ),
    },
    Writer {
        tool: "lookup_fixtures",
        style: Style::Record,
        count: 10,
        recipes: &[
            "replaceUnderLease",
            "removeThenReclaim",
            "expiryAndClose",
            "twoKeys",
        ],
        model: "lookup",
        fixtures: "crates/kestrike/src/storage/lookup_replay_fixtures",
        directed: (
            "twoKeys",
            "module lookupCase {\n  import lookup(BOUND = 13).* from \"./lookup\"\n  action recipe = any {\n    all { \
             Set(0, 9, 11).contains(turn), service },\n    all { Set(1, 2, 8).contains(turn), certify },\n    all { \
             Set(3).contains(turn), publish(0) },\n    all { Set(4).contains(turn), publish(1) },\n    all { \
             Set(5).contains(turn), lookup(1) },\n    all { Set(6).contains(turn), remove(0) },\n    all { \
             Set(7).contains(turn), remove(1) },\n    all { Set(10).contains(turn), drop(2) },\n    all { \
             Set(12).contains(turn), lookup(0) },\n  }\n}\n",
        ),
        seeded: (
            "step_c",
            "module lookupCase {\n  import lookup(BOUND = 16).* from \"./lookup\"\n}\n",
        ),
    },
    Writer {
        tool: "reclaim_fixtures",
        style: Style::Record,
        count: 11,
        recipes: &[
            "anchorLast",
            "rightLast",
            "pinnedReaderHolds",
            "reuse",
            "leases",
        ],
        model: "reclaim",
        fixtures: "crates/kestrike/src/storage/reclaim_replay_fixtures",
        directed: (
            "reuse",
            "module reclaimCase {\n  import reclaim(BOUND = 12).* from \"./reclaim\"\n  action recipe = any {\n    all \
             { Set(0, 6).contains(turn), unlease },\n    all { Set(1, 7).contains(turn), retire },\n    all { Set(2, \
             3, 8, 9).contains(turn), certify },\n    all { Set(4, 10).contains(turn), service },\n    all { Set(5, \
             11).contains(turn), republish },\n  }\n}\n",
        ),
        seeded: (
            "step_c",
            "module reclaimCase {\n  import reclaim(BOUND = 18).* from \"./reclaim\"\n}\n",
        ),
    },
    Writer {
        tool: "register_fixtures",
        style: Style::Record,
        count: 11,
        recipes: &[
            "closeRacesAnEntry",
            "leakedGuardBlocks",
            "limitAndReturn",
            "forgottenHandles",
            "leakedAcrossTheClose",
        ],
        model: "register",
        fixtures: "crates/kestrike/src/storage/register_replay_fixtures",
        directed: (
            "forgottenHandles",
            "module registerCase {\n  import register(BOUND = 8).* from \"./register\"\n  action recipe = any {\n    \
             all { Set(0, 1, 3, 7).contains(turn), register },\n    all { Set(2).contains(turn), forget(1) },\n    \
             all { Set(4).contains(turn), leak(0) },\n    all { Set(5).contains(turn), forget(0) },\n    all { \
             Set(6).contains(turn), close },\n  }\n}\n",
        ),
        seeded: (
            "step_c",
            "module registerCase {\n  import register(BOUND = 14).* from \"./register\"\n}\n",
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
        Some(Value::String(text)) => text.to_str().expect("a committed trace holds no surrogate"),
        _ => panic!("{what} is a JSON string"),
    }
}

/// `reply` gives every trace a `#meta` of Quint's shape. A committed trace of a record writer holds no
/// `format`, and its reply carries Quint's `ITF`.
fn reply(trace: &Committed) -> String {
    let mut data = trace.data.clone();
    let format = object(data.get("#meta"), "#meta")
        .get("format")
        .cloned()
        .unwrap_or_else(|| Value::String("ITF".into()));
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
/// The trace path is relative to the trace directory `<output>/<name>/`, where Quint runs.
fn expected_call(writer: &Writer, trace: &Committed) -> String {
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
    let directed = matches!(record.get("recipe"), Some(Value::Array(recipe)) if !recipe.is_empty());
    if directed {
        call.extend(["--step".to_owned(), "recipe".to_owned()]);
    } else if writer.style == Style::Record {
        call.extend(["--step".to_owned(), "step".to_owned()]);
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
    call.push(format!("../{}.itf.json", trace.name));
    call.iter().map(|arg| format!("{arg}\0")).collect()
}

fn seed(writer: &Writer, trace: &Committed) -> u64 {
    let record = object(
        object(trace.data.get("#meta"), "#meta").get(writer.model),
        "the writer's record",
    );
    let seed = text(record.get("seed"), "seed");
    u64::from_str_radix(seed.strip_prefix("0x").expect("a seed is 0x-prefixed"), 16)
        .expect("a seed is hexadecimal")
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
[ "$(pwd -P)" = "$(cat "$replies/$name.dir")" ] || { echo "stand-in: $name runs outside its own directory" >&2; exit 3; }
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
            expected_call(writer, &trace),
        )
        .expect("the expected call is written");
        fs::write(
            replies.join(format!("{}.dir", trace.name)),
            output.join(&trace.name).as_os_str().as_encoded_bytes(),
        )
        .expect("the trace directory is written");
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
            result.stderr.is_empty(),
            "{} writes nothing to standard error",
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
        let mut seeds: Vec<(u64, String)> = traces
            .iter()
            .filter(|trace| !writer.recipes.contains(&trace.name.as_str()))
            .map(|trace| (seed(writer, trace), trace.name.clone()))
            .collect();
        seeds.sort();
        order.extend(seeds.into_iter().map(|(_, name)| name));
        let calls =
            fs::read_to_string(scratch.0.join("replies/calls")).expect("the calls log reads");
        assert_eq!(
            calls.lines().collect::<Vec<_>>(),
            order,
            "{}: the traces run in order",
            writer.tool
        );
        let printed: String = match writer.style {
            Style::Format => String::new(),
            Style::Record => order
                .iter()
                .map(|name| format!("stand-in: writing {name}\n"))
                .collect(),
        };
        assert_eq!(
            std::str::from_utf8(&result.stdout).expect("standard output is UTF-8"),
            printed,
            "{}: Quint's standard output",
            writer.tool
        );
    }
}

#[test]
fn a_trace_generator_writes_its_traces_under_a_relative_output_directory() {
    for writer in WRITERS
        .iter()
        .filter(|writer| writer.style == Style::Record)
    {
        let scratch = Scratch::new();
        let quint = stand_in(&scratch.0, writer, &scratch.0.join("traces"), reply);
        let result = Command::new(BINARY)
            .arg(top())
            .arg(writer.tool)
            .args([
                "--quint".as_ref(),
                quint.as_os_str(),
                "--output".as_ref(),
                "traces".as_ref(),
            ])
            .current_dir(&scratch.0)
            .output()
            .expect("the binary starts");
        assert_eq!(
            result.status.code(),
            Some(0),
            "{}: {}",
            writer.tool,
            stderr(&result)
        );
        let mut written: Vec<String> = fs::read_dir(scratch.0.join("traces"))
            .expect("the traces directory lists")
            .map(|entry| {
                let name = entry.expect("an entry lists").file_name();
                name.into_string().expect("a trace's name is UTF-8")
            })
            .filter(|name| name.ends_with(".itf.json"))
            .collect();
        written.sort();
        let expected: Vec<String> = committed(writer)
            .into_iter()
            .map(|trace| format!("{}.itf.json", trace.name))
            .collect();
        assert_eq!(written, expected, "{}", writer.tool);
    }
}

#[test]
fn a_reply_without_meta_is_accepted_by_record_writers_and_refused_by_format_writers() {
    for writer in &WRITERS {
        let scratch = Scratch::new();
        let output = scratch.0.join("out");
        let bare = |trace: &Committed| {
            let Ok(Value::Object(mut data)) = json::parse(&reply(trace)) else {
                panic!("a reply is a JSON object");
            };
            data.remove("#meta");
            json::dump(&Value::Object(data))
        };
        let quint = stand_in(&scratch.0, writer, &output, bare);
        let result = write_traces(writer, &quint, &output);
        let first = committed(writer)
            .into_iter()
            .find(|trace| trace.name == writer.recipes[0])
            .expect("the first recipe is committed");
        let file = output.join(format!("{}.itf.json", first.name));
        match writer.style {
            Style::Format => {
                assert_eq!(result.status.code(), Some(1), "{}", writer.tool);
                assert_eq!(
                    stderr(&result),
                    format!(
                        "{}: {}: the trace has no '#meta' record with a 'format'\n",
                        writer.tool,
                        file.display()
                    )
                );
            }
            Style::Record => {
                assert_eq!(
                    result.status.code(),
                    Some(0),
                    "{}: {}",
                    writer.tool,
                    stderr(&result)
                );
                let mut expected = first.data.clone();
                let meta = expected.remove("#meta").expect("the trace holds #meta");
                expected.insert("#meta", meta);
                let written = fs::read_to_string(&file).expect("the trace is written");
                assert_eq!(
                    written,
                    json::dump(&Value::Object(expected)),
                    "{}",
                    writer.tool
                );
            }
        }
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
    let earlier = output.join(format!("{second}.itf.json"));
    fs::write(&earlier, "earlier").expect("the earlier run's trace is written");
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
    assert_eq!(
        fs::read_to_string(&earlier).expect("the earlier run's trace stays"),
        "earlier",
        "the run stops at the second trace before its trace path is cleared"
    );
    assert!(
        !output
            .join("two_builders_interleave_and_each_exit_refunds_once")
            .exists()
    );
}

#[test]
fn a_quint_that_exits_1_ends_the_run_with_exit_1() {
    for writer in &WRITERS {
        let scratch = Scratch::new();
        let quint = scratch.0.join("quint");
        write_script(
            &quint,
            "#!/bin/sh\necho 'quint: on standard output'\necho 'quint: on standard error' >&2\nexit 1\n",
        );
        let output = scratch.0.join("out");
        let result = write_traces(writer, &quint, &output);
        assert_eq!(result.status.code(), Some(1), "{}", writer.tool);
        let first = writer.recipes[0];
        assert_eq!(
            stderr(&result),
            format!(
                "quint: on standard error\n{}: {first}: Quint ended with exit status: 1\n",
                writer.tool
            )
        );
        let printed = match writer.style {
            Style::Format => "",
            Style::Record => "quint: on standard output\n",
        };
        assert_eq!(result.stdout, printed.as_bytes(), "{}", writer.tool);
        assert!(!output.join(format!("{first}.itf.json")).exists());
        assert!(!output.join(writer.recipes[1]).exists(), "{}", writer.tool);
    }
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
fn a_trace_with_null_and_a_float_keeps_both() {
    let writer = &WRITERS[1];
    let scratch = Scratch::new();
    let output = scratch.0.join("out");
    let quint = stand_in(&scratch.0, writer, &output, |trace| {
        reply(trace).replacen("\"vars\"", "\"x\":null,\"y\":1.5e-7,\"vars\"", 1)
    });
    let result = write_traces(writer, &quint, &output);
    assert_eq!(result.status.code(), Some(0), "{}", stderr(&result));
    let written = fs::read_to_string(output.join("passes.itf.json")).expect("the trace is written");
    let expression = "json.dumps(json.loads('{\"x\":null,\"y\":1.5e-7}'), separators=(',', ':'))";
    let python = "{\"x\":null,\"y\":1.5e-07}";
    let passes = committed_trace(writer, "passes");
    let expected = std::str::from_utf8(&passes.bytes)
        .expect("a committed trace is UTF-8")
        .replacen(
            "\"vars\"",
            &format!("{},\"vars\"", &python[1..python.len() - 1]),
            1,
        );
    assert_eq!(written, expected, "{expression}");
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

/// `--quint=--` names the program `--`, which no directory of the test's `PATH` holds: each writer creates
/// the first trace directory, writes the model copy and `case.qnt` there, and exits 1 when the program
/// fails to start.
#[test]
fn a_quint_value_of_two_dashes_names_a_program_that_fails_to_start() {
    for writer in &WRITERS {
        let scratch = Scratch::new();
        let output = scratch.0.join("out");
        let result = Command::new(BINARY)
            .arg(top())
            .args([
                writer.tool.as_ref(),
                "--quint=--".as_ref(),
                "--output".as_ref(),
                output.as_os_str(),
            ])
            .env("PATH", &scratch.0)
            .output()
            .expect("the binary starts");
        let first = writer.recipes[0];
        assert_eq!(result.status.code(), Some(1), "{}", writer.tool);
        assert_eq!(
            stderr(&result),
            format!(
                "{}: {first}: Quint did not start: No such file or directory (os error 2)\n",
                writer.tool
            )
        );
        let directory = output.join(first);
        assert!(
            directory.join(format!("{}.qnt", writer.model)).exists()
                && directory.join("case.qnt").exists(),
            "{}",
            writer.tool
        );
        assert!(!output.join(writer.recipes[1]).exists(), "{}", writer.tool);
    }
}

/// `-h=` is refused with exit 2 and the message of `--help=`, on standard error, by every writer, and an
/// absent output directory stays absent while a present one keeps its entries.
#[test]
fn an_empty_value_attached_to_h_exits_2_and_leaves_the_output_as_it_was() {
    for writer in &WRITERS {
        let scratch = Scratch::new();
        let absent = scratch.0.join("absent");
        let present = scratch.0.join("present");
        fs::create_dir(&present).expect("the present output is made");
        fs::write(present.join("kept"), "kept").expect("the present output holds a file");
        for output in [&absent, &present] {
            let rest: [&OsStr; 4] = [
                "--quint".as_ref(),
                "quint".as_ref(),
                "--output".as_ref(),
                output.as_os_str(),
            ];
            let first: Vec<&OsStr> = std::iter::once("-h=".as_ref()).chain(rest).collect();
            let last: Vec<&OsStr> = rest.into_iter().chain(["-h=".as_ref()]).collect();
            for args in [first, last] {
                let result = run(writer.tool, &args);
                assert_eq!(result.status.code(), Some(2), "{}", writer.tool);
                assert!(result.stdout.is_empty(), "{}", writer.tool);
                assert_eq!(
                    stderr(&result),
                    format!(
                        "usage: {0} [-h] --quint QUINT --output OUTPUT\n{0}: error: argument -h/--help: \
                         ignored explicit argument ''\n",
                        writer.tool
                    )
                );
            }
        }
        assert!(!absent.exists(), "{}", writer.tool);
        let entries: Vec<_> = fs::read_dir(&present)
            .expect("the present output lists")
            .map(|entry| entry.expect("an entry lists").file_name())
            .collect();
        assert_eq!(entries, ["kept"], "{}", writer.tool);
        assert_eq!(
            fs::read_to_string(present.join("kept")).expect("kept reads"),
            "kept"
        );
    }
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

/// `limited` runs `writer` with the file size limit `limit`, soft and hard, and `SIGXFSZ` at `disposition`.
fn limited(
    writer: &Writer,
    quint: &Path,
    output: &Path,
    limit: usize,
    disposition: libc::sighandler_t,
) -> Output {
    let limit = libc::rlim_t::try_from(limit).expect("the limit fits rlim_t");
    let mut command = Command::new(BINARY);
    command.arg(top()).arg(writer.tool).args([
        "--quint".as_ref(),
        quint.as_os_str(),
        "--output".as_ref(),
        output.as_os_str(),
    ]);
    // SAFETY: the closure makes two calls into libc, `setrlimit` and `signal`, each one system call that
    // allocates nothing and takes no lock, and reads only the copied `limit` and `disposition`.
    unsafe {
        command.pre_exec(move || {
            let bound = libc::rlimit {
                rlim_cur: limit,
                rlim_max: limit,
            };
            if libc::setrlimit(libc::RLIMIT_FSIZE, &bound) != 0 {
                return Err(io::Error::last_os_error());
            }
            libc::signal(libc::SIGXFSZ, disposition);
            Ok(())
        });
    }
    command.output().expect("the binary starts")
}

/// A model copy one byte over the file size limit is refused before its write: the writer exits 1 with one
/// line naming the copy, with `SIGXFSZ` at its default action and ignored, and the trace's directory stays
/// empty. At a limit equal to the model's size the copy is written whole.
#[test]
fn a_model_copy_over_the_file_size_limit_exits_1_and_writes_no_byte_of_it() {
    let writer = &WRITERS[1];
    let model =
        fs::read(top().join(format!("quint/{}.qnt", writer.model))).expect("the model reads");
    let first = writer.recipes[0];
    for disposition in [libc::SIG_DFL, libc::SIG_IGN] {
        let scratch = Scratch::new();
        let output = scratch.0.join("out");
        let quint = stand_in(&scratch.0, writer, &output, reply);
        let result = limited(writer, &quint, &output, model.len() - 1, disposition);
        let copy = output.join(format!("{first}/{}.qnt", writer.model));
        assert_eq!(result.status.code(), Some(1), "{result:?}");
        assert_eq!(
            stderr(&result),
            format!(
                "{}: {}: File too large (os error 27)\n",
                writer.tool,
                copy.display()
            )
        );
        let left: Vec<_> = fs::read_dir(output.join(first))
            .expect("the trace's directory stays")
            .collect();
        assert!(left.is_empty(), "{left:?}");
        let listed: Vec<_> = fs::read_dir(&output).expect("the output lists").collect();
        assert_eq!(listed.len(), 1, "{listed:?}");
    }
    let scratch = Scratch::new();
    let output = scratch.0.join("out");
    let quint = stand_in(&scratch.0, writer, &output, reply);
    let result = limited(writer, &quint, &output, model.len(), libc::SIG_DFL);
    let copy =
        fs::read(output.join(format!("{first}/{}.qnt", writer.model))).expect("the copy reads");
    assert!(copy == model, "the copy is whole");
    assert_eq!(result.status.code(), Some(0), "{}", stderr(&result));
}

/// When the rewritten trace exceeds the file size limit, the writer exits 1 with one line naming the rewrite's
/// new file, removes that file, and leaves Quint's trace at the trace path, with `SIGXFSZ` ignored and with
/// its default action.
#[test]
fn a_rewrite_that_passes_the_file_size_limit_exits_1_and_leaves_quints_trace() {
    for (writer, disposition) in [
        (&WRITERS[1], libc::SIG_IGN),
        (&WRITERS[3], libc::SIG_IGN),
        (&WRITERS[1], libc::SIG_DFL),
        (&WRITERS[3], libc::SIG_DFL),
    ] {
        let scratch = Scratch::new();
        let output = scratch.0.join("out");
        let pad = fs::metadata(top().join(format!("quint/{}.qnt", writer.model)))
            .expect("the model reads")
            .len();
        let padded = |trace: &Committed| {
            let Ok(Value::Object(mut data)) = json::parse(&reply(trace)) else {
                panic!("a reply is a JSON object");
            };
            let mut meta = Object::new();
            meta.insert("format", Value::String("ITF".into()));
            data.insert("#meta", Value::Object(meta));
            let pad = "x".repeat(usize::try_from(pad).expect("the model's size fits usize"));
            data.insert("pad", Value::String(pad.as_str().into()));
            json::dump(&Value::Object(data))
        };
        let quint = stand_in(&scratch.0, writer, &output, padded);
        let first = writer.recipes[0];
        let raw =
            fs::read(scratch.0.join(format!("replies/{first}.reply"))).expect("the reply reads");
        let result = limited(writer, &quint, &output, raw.len() + 8, disposition);
        let staged = output.join(format!("{first}/{first}.itf.json.new"));
        assert_eq!(result.status.code(), Some(1), "{}", stderr(&result));
        assert_eq!(
            stderr(&result),
            format!(
                "{}: {}: File too large (os error 27)\n",
                writer.tool,
                staged.display()
            )
        );
        let left = fs::read(output.join(format!("{first}.itf.json"))).expect("the trace stays");
        assert!(left == raw, "{}: Quint's trace stands", writer.tool);
        assert!(!staged.exists(), "{}: the new file is removed", writer.tool);
        assert!(!output.join(writer.recipes[1]).exists());
    }
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

/// `--output=--` names the directory `--` of the working directory, and every writer writes each of its
/// traces there.
#[test]
fn an_output_value_of_two_dashes_names_a_directory_of_the_working_directory() {
    for writer in &WRITERS {
        let scratch = Scratch::new();
        let output = scratch.0.join("--");
        let quint = stand_in(&scratch.0, writer, &output, reply);
        let result = Command::new(BINARY)
            .arg(top())
            .arg(writer.tool)
            .args([
                "--quint".as_ref(),
                quint.as_os_str(),
                "--output=--".as_ref(),
            ])
            .current_dir(&scratch.0)
            .output()
            .expect("the binary starts");
        assert_eq!(
            result.status.code(),
            Some(0),
            "{}: {}",
            writer.tool,
            stderr(&result)
        );
        for trace in committed(writer) {
            let written = fs::read(output.join(format!("{}.itf.json", trace.name)))
                .expect("the trace is written");
            assert!(written == trace.bytes, "{}: {}", writer.tool, trace.name);
        }
    }
}

/// An output path holding Quint's sequence template `{seq}` holds each trace byte for byte, since the
/// stand-in accepts only the call with `--out-itf ../<name>.itf.json` run in `<output>/<name>/`.
#[test]
fn an_output_path_with_a_sequence_template_holds_each_trace_byte_for_byte() {
    for writer in [&WRITERS[1], &WRITERS[3]] {
        let scratch = Scratch::new();
        let output = scratch.0.join("out{seq}");
        let quint = stand_in(&scratch.0, writer, &output, reply);
        let result = write_traces(writer, &quint, &output);
        assert_eq!(
            result.status.code(),
            Some(0),
            "{}: {}",
            writer.tool,
            stderr(&result)
        );
        for trace in committed(writer) {
            let written = fs::read(output.join(format!("{}.itf.json", trace.name)))
                .expect("the trace is written");
            assert!(written == trace.bytes, "{}: {}", writer.tool, trace.name);
        }
    }
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
fn a_trace_the_reader_refuses_exits_1_naming_its_file_and_the_byte() {
    let writer = &WRITERS[1];
    let scratch = Scratch::new();
    let output = scratch.0.join("out");
    let quint = stand_in(&scratch.0, writer, &output, |trace| {
        let mut text = reply(trace);
        text.insert(text.len() - 1, ',');
        text
    });
    let result = write_traces(writer, &quint, &output);
    assert_eq!(result.status.code(), Some(1));
    let shown = stderr(&result);
    let prefix = format!(
        "gate_fixtures: {}: ",
        output.join("passes.itf.json").display()
    );
    assert!(
        shown.starts_with(&prefix) && shown.contains(" at byte ") && shown.ends_with('\n'),
        "json.loads of a trace ending in ',}}' raises JSONDecodeError: {shown}"
    );
    assert_eq!(shown.lines().count(), 1, "{shown}");
}

/// A relative `--output` resolves against the working directory, and the line names the trace by its
/// absolute path.
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
                .map(|(key, _)| {
                    key.to_str()
                        .expect("a trace key holds no surrogate")
                        .to_owned()
                })
                .collect();
            for key in keys {
                if let Some(member) = object.get_mut(&key) {
                    reverse_sets(member);
                }
            }
        }
        Value::String(_) | Value::Integer(_) | Value::Float(_) | Value::Bool(_) | Value::Null => {}
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
