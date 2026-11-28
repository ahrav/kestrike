use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::fixtures::quint::{Failure, run};
use crate::fixtures::{Model, Style, Trace, case, generate, keep, replace};
use crate::json::{Value, parse};
use crate::paths::tests::Scratch;
use crate::tools;

/// Writes the executable stand-in at `path` through a child process, the one process that holds the file open
/// for writing. `execve` refuses a file that any process holds open for writing with `ETXTBSY`, and a child
/// that another test thread forks inherits every descriptor of this process until its own `execve`. No
/// descriptor of the stand-in is open here, so the stand-in starts whatever the other threads fork.
pub(crate) fn script(path: &Path, text: &str) {
    let mut writer = Command::new("sh")
        .args(["-c", r#"cat > "$1" && chmod 755 "$1""#, "sh"])
        .arg(path)
        .stdin(Stdio::piped())
        .spawn()
        .expect("the stand-in's writer starts");
    writer
        .stdin
        .take()
        .expect("the writer's standard input is a pipe")
        .write_all(text.as_bytes())
        .expect("the stand-in's text reaches the writer");
    let status = writer.wait().expect("the stand-in's writer is reaped");
    assert!(status.success(), "the stand-in is written: {status}");
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
        &tools::gate_fixtures::MODEL,
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

/// The models of one writer of each style: `gate` with `Style::Format` and `grace` with `Style::Record`.
fn models() -> [Model; 2] {
    [tools::gate_fixtures::MODEL, tools::grace_fixtures::MODEL]
}

/// A trace of one state whose `#meta` holds Quint's `format`, which a seeded trace of 0 steps accepts.
const ONE_STATE: &str = r##"{"#meta":{"format":"ITF"},"states":[{}]}"##;

/// `writer` returns a stand-in Quint that runs `before`, writes [`ONE_STATE`] to its last argument and runs
/// `after`. The stand-in runs in `<output>/<name>/`, so `../..` is the directory that holds `<output>`.
fn writer(before: &str, after: &str) -> String {
    format!(
        "#!/bin/sh\nfor arg; do out=$arg; done\n{before}\nprintf '%s' '{ONE_STATE}' > \"$out\"\n{after}\n"
    )
}

/// `record` returns the writer's record under `#meta.<model>` of the trace at `file`.
fn record(file: &Path, model: &str) -> crate::json::Object {
    let written = fs::read_to_string(file).expect("the trace reads");
    let Ok(Value::Object(mut data)) = parse(&written) else {
        panic!("the trace is an object: {written}");
    };
    let Some(Value::Object(mut meta)) = data.remove("#meta") else {
        panic!("the trace has #meta: {written}");
    };
    let Some(Value::Object(record)) = meta.remove(model) else {
        panic!("#meta holds the writer's record: {written}");
    };
    record
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// A trace name is one path component without a template: `Trace::new` panics on each name below and
/// accepts the names of the tools' traces.
#[test]
fn a_trace_name_that_is_not_one_plain_component_is_refused() {
    for name in [
        "", ".", "..", "../x", "/abs", "a/b", "a{seq}", "{test}", "a\0b",
    ] {
        let made = std::panic::catch_unwind(|| seeded(name, 0));
        assert!(made.is_err(), "{name:?} is refused");
    }
    for name in ["passes", "readerBeforePass", "step_6b0d", "step_c"] {
        seeded(name, 0);
    }
}

/// A model file that the first trace's Quint run replaces leaves both traces with a copy of the bytes read
/// before the first trace, `\r\n` and a lone `\r` included, and those bytes' digest in `model_sha256`.
#[test]
fn the_model_digest_and_every_copy_come_from_one_read() {
    for model in models() {
        let name = model.name;
        let scratch = Scratch::new("model-race");
        let top = scratch.0.join("top");
        fs::create_dir_all(top.join("quint")).expect("the private top is made");
        let source = top.join(format!("quint/{name}.qnt"));
        let first = format!("module {name} {{\r\n  val a = 1\r}}\n");
        fs::write(&source, &first).expect("the model is written");
        let quint = scratch.0.join("quint");
        let replaced =
            format!("printf 'module {name} {{ val b = 2 }}\\n' > ../../top/quint/{name}.qnt");
        script(&quint, &writer(&replaced, ""));
        let output = scratch.0.join("out");
        let outcome = generate(
            &model,
            &top,
            quint.as_os_str(),
            &output,
            &[seeded("first", 0), seeded("second", 0)],
            keep,
        );
        assert_eq!(outcome, Ok(()), "{name}");
        assert_ne!(
            fs::read_to_string(&source).expect("the model reads"),
            first,
            "{name}: the stand-in replaced the model"
        );
        for trace in ["first", "second"] {
            let copy =
                fs::read(output.join(format!("{trace}/{name}.qnt"))).expect("the copy reads");
            assert_eq!(copy, first.as_bytes(), "{name}: the copy beside {trace}");
            assert_eq!(
                record(&output.join(format!("{trace}.itf.json")), name).get("model_sha256"),
                Some(&Value::String(sha256(&copy).as_str().into())),
                "{name}: the digest of {trace}"
            );
        }
    }
}

/// A model that is not UTF-8 fails at the first trace with one line naming the model: the first trace
/// directory exists and is empty, Quint never starts, and no later trace directory exists.
#[test]
fn a_model_that_is_not_utf_8_fails_at_the_first_trace() {
    let scratch = Scratch::new("model-bytes");
    let top = scratch.0.join("top");
    fs::create_dir_all(top.join("quint")).expect("the private top is made");
    let source = top.join("quint/gate.qnt");
    fs::write(&source, b"module gate { val a = \xff }\n").expect("the model is written");
    let quint = scratch.0.join("quint");
    script(&quint, &writer("touch ../../started", ""));
    let output = scratch.0.join("out");
    let outcome = generate(
        &tools::gate_fixtures::MODEL,
        &top,
        quint.as_os_str(),
        &output,
        &[seeded("first", 0), seeded("second", 0)],
        keep,
    );
    assert_eq!(
        outcome,
        Err(format!(
            "{}: stream did not contain valid UTF-8",
            source.display()
        ))
    );
    let entries = fs::read_dir(output.join("first")).expect("the first trace directory lists");
    assert_eq!(entries.count(), 0);
    assert!(!scratch.0.join("started").exists(), "Quint never starts");
    assert!(!output.join("second").exists());
}

/// An entry at the trace path is removed before Quint starts: a regular file, a link to a file outside the
/// output and a dangling link. The stand-in finds no entry at its `--out-itf` path, exits 0 without writing,
/// and the run fails at the read of the trace; the link's target keeps its bytes.
#[test]
fn an_entry_left_at_the_trace_path_is_removed_and_a_quint_that_writes_none_fails_the_read() {
    for model in models() {
        for entry in ["file", "link", "dangling"] {
            let scratch = Scratch::new("leftover");
            let quint = scratch.0.join("quint");
            script(
                &quint,
                "#!/bin/sh\nfor arg; do out=$arg; done\n\
                 if [ -e \"$out\" ] || [ -L \"$out\" ]; then exit 5; fi\ntouch ../../started\n",
            );
            let output = scratch.0.join("out");
            fs::create_dir_all(&output).expect("the output directory is made");
            let file = output.join("first.itf.json");
            let target = scratch.0.join("target");
            let old = r##"{"#meta":{"format":"ITF","source":"old"},"states":[{"left":"over"}]}"##;
            match entry {
                "file" => fs::write(&file, old).expect("the leftover trace is written"),
                "link" => {
                    fs::write(&target, old).expect("the link's target is written");
                    std::os::unix::fs::symlink(&target, &file).expect("the link is made");
                }
                _ => std::os::unix::fs::symlink(&target, &file).expect("the link is made"),
            }
            let outcome = generate(
                &model,
                &checkout(),
                quint.as_os_str(),
                &output,
                &[seeded("first", 0)],
                keep,
            );
            let what = format!("{} {entry}", model.name);
            assert_eq!(
                outcome,
                Err(format!(
                    "{}: No such file or directory (os error 2)",
                    file.display()
                )),
                "{what}"
            );
            assert!(scratch.0.join("started").exists(), "{what}: Quint ran");
            assert!(
                fs::symlink_metadata(&file).is_err(),
                "{what}: the entry is gone"
            );
            match entry {
                "link" => assert_eq!(fs::read_to_string(&target).expect("the target reads"), old),
                _ => assert!(fs::symlink_metadata(&target).is_err(), "{what}"),
            }
        }
    }
}

/// A directory at the trace path ends the run with one line naming the path before Quint starts; the
/// directory stays and the trace directory holds the model copy and `case.qnt`.
#[test]
fn a_directory_at_the_trace_path_ends_the_run_before_quint_starts() {
    for model in models() {
        let scratch = Scratch::new("trace-directory");
        let quint = scratch.0.join("quint");
        script(&quint, &writer("touch ../../started", ""));
        let output = scratch.0.join("out");
        let file = output.join("first.itf.json");
        fs::create_dir_all(file.join("inner")).expect("the directory is made");
        let outcome = generate(
            &model,
            &checkout(),
            quint.as_os_str(),
            &output,
            &[seeded("first", 0)],
            keep,
        );
        assert_eq!(
            outcome,
            Err(format!("{}: Is a directory (os error 21)", file.display())),
            "{}",
            model.name
        );
        assert!(file.join("inner").is_dir(), "{}", model.name);
        assert!(
            !scratch.0.join("started").exists(),
            "{}: Quint never starts",
            model.name
        );
        assert!(output.join(format!("first/{}.qnt", model.name)).exists());
        assert!(output.join("first/case.qnt").exists());
    }
}

/// Quint receives `--out-itf ../<name>.itf.json` from the trace directory, so an output path holding `{seq}`,
/// which the stand-in expands to `0` as Quint 0.33.0 does, keeps every trace under the path as given, and
/// the directory `out0` beside it stays empty.
#[test]
fn an_output_path_with_a_sequence_template_holds_each_trace() {
    for model in models() {
        let scratch = Scratch::new("template");
        let quint = scratch.0.join("quint");
        let expand = "printf '%s\\n' \"$out\" >> ../../out-itf\nout=$(printf '%s' \"$out\" | sed 's/{seq}/0/g')";
        script(&quint, &writer(expand, ""));
        let expanded = scratch.0.join("out0");
        fs::create_dir(&expanded).expect("the expanded directory is made");
        let output = scratch.0.join("out{seq}");
        let outcome = generate(
            &model,
            &checkout(),
            quint.as_os_str(),
            &output,
            &[seeded("first", 0), seeded("second", 0)],
            keep,
        );
        assert_eq!(
            fs::read_dir(&expanded).expect("out0 lists").count(),
            0,
            "{}: nothing lands in out0",
            model.name
        );
        assert_eq!(outcome, Ok(()), "{}", model.name);
        assert_eq!(
            fs::read_to_string(scratch.0.join("out-itf")).expect("the log reads"),
            "../first.itf.json\n../second.itf.json\n",
            "{}",
            model.name
        );
        for trace in ["first", "second"] {
            let file = output.join(format!("{trace}.itf.json"));
            assert!(record(&file, model.name).get("model_sha256").is_some());
        }
    }
}

/// The rewritten trace takes the permission bits `0o777` of the file Quint wrote, without the sticky bit,
/// and is a new file: a hard link the stand-in made to the raw trace still holds Quint's bytes. The trace
/// directory then holds the model copy and `case.qnt` alone.
#[test]
fn the_rewritten_trace_keeps_the_raw_files_permission_bits() {
    for model in models() {
        for (raw, kept) in [(0o640, 0o640), (0o1640, 0o640)] {
            let what = format!("{} {raw:o}", model.name);
            let scratch = Scratch::new("mode");
            let quint = scratch.0.join("quint");
            let after = format!(
                "chmod {raw:o} \"$out\"\n[ {sticky} = 0 ] || [ -k \"$out\" ] || exit 5\nln \"$out\" ../../kept-raw",
                sticky = raw & 0o1000
            );
            script(&quint, &writer("", &after));
            let output = scratch.0.join("out");
            let outcome = generate(
                &model,
                &checkout(),
                quint.as_os_str(),
                &output,
                &[seeded("first", 0)],
                keep,
            );
            assert_eq!(outcome, Ok(()), "{what}");
            let file = output.join("first.itf.json");
            let mode = fs::metadata(&file)
                .expect("the trace's metadata reads")
                .permissions()
                .mode();
            assert_eq!(mode & 0o7777, kept, "{what}");
            assert!(record(&file, model.name).get("model_sha256").is_some());
            assert_eq!(
                fs::read_to_string(scratch.0.join("kept-raw")).expect("the raw trace's link reads"),
                ONE_STATE,
                "{what}"
            );
            let mut entries: Vec<String> = fs::read_dir(output.join("first"))
                .expect("the trace directory lists")
                .map(|entry| {
                    let name = entry.expect("an entry lists").file_name();
                    name.into_string().expect("a UTF-8 name")
                })
                .collect();
            entries.sort();
            assert_eq!(
                entries,
                ["case.qnt".to_owned(), format!("{}.qnt", model.name)],
                "{what}"
            );
        }
    }
}

/// An entry at the rewrite's new file `<output>/<name>/<name>.itf.json.new` ends the run with one line
/// naming it; the entry stays, and the trace path holds Quint's bytes.
#[test]
fn an_entry_at_the_rewrites_new_file_ends_the_run_and_keeps_quints_trace() {
    for model in models() {
        let scratch = Scratch::new("staged");
        let quint = scratch.0.join("quint");
        script(&quint, &writer("", "printf 'other' > first.itf.json.new"));
        let output = scratch.0.join("out");
        let outcome = generate(
            &model,
            &checkout(),
            quint.as_os_str(),
            &output,
            &[seeded("first", 0), seeded("second", 0)],
            keep,
        );
        let staged = output.join("first/first.itf.json.new");
        assert_eq!(
            outcome,
            Err(format!("{}: File exists (os error 17)", staged.display())),
            "{}",
            model.name
        );
        assert_eq!(
            fs::read_to_string(&staged).expect("the entry stays"),
            "other"
        );
        assert_eq!(
            fs::read_to_string(output.join("first.itf.json")).expect("Quint's trace stays"),
            ONE_STATE,
            "{}",
            model.name
        );
        assert!(!output.join("second").exists(), "{}", model.name);
    }
}

/// A rename that fails once the new file is written and synced, here over a directory that holds a file,
/// returns one line naming the trace path; the new file is removed and the directory keeps its file.
#[test]
fn a_failed_rename_removes_the_new_file_and_names_the_trace() {
    let scratch = Scratch::new("rename");
    let file = scratch.0.join("first.itf.json");
    fs::create_dir_all(&file).expect("the directory at the trace path is made");
    fs::write(file.join("kept"), "kept").expect("the directory holds a file");
    let staged = scratch.0.join("first.itf.json.new");
    assert_eq!(
        replace(&file, &staged, 0o644, ONE_STATE),
        Err(format!("{}: Is a directory (os error 21)", file.display()))
    );
    assert!(
        fs::symlink_metadata(&staged).is_err(),
        "the new file is removed"
    );
    assert_eq!(
        fs::read_to_string(file.join("kept")).expect("the file stays"),
        "kept"
    );
}
