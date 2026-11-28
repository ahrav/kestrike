use std::fs;
use std::path::{Path, PathBuf};

use super::{Judged, check_graph, check_line, judge_case};
use crate::genmc::refusal::{Code, Error, Refusal, read_json};
use crate::json::{Integer, Text, Value, parse};
use crate::paths::tests::Scratch;

pub(crate) const DEPARTURE: &str = "a follower saw the departure without its terminal";
pub(crate) const FREED: &str = "a follower's record was freed or reissued under it";

pub(crate) const POSITIVE: &str = "GenMC v0.19.0 (LLVM 22.1.8)\n*** Compilation complete.\n\
*** Transformation complete.\n*** Verification complete.\nNo errors were detected.\n\
Number of complete executions explored: 3\nTotal wall-clock time: 0.49s\n";

pub(crate) fn violation(line: usize) -> String {
    format!(
        "GenMC v0.19.0 (LLVM 22.1.8)\n*** Compilation complete.\n*** Transformation complete.\n\
Error: Safety violation!\nEvent (0, 4) in graph:\n<-1, 0>:\n\t(0, 4): ERROR join_kernel.rs:{line}\n\
*** Verification unsuccesful.\nNumber of complete executions explored: 0\nTotal wall-clock time: 0.44s\n"
    )
}

pub(crate) fn violation_graph(line: usize) -> String {
    format!(
        "strict digraph {{\n\t\"(0, 4)\" [label=<ERROR <FONT COLOR=\"gray\"> join_kernel.rs:{line}</FONT>>, \
tooltip=\"(0, 4)\"]\n}}\n"
    )
}

pub(crate) const POSITIVE_GRAPH: &str = "strict digraph {\n\n}\n";

pub(crate) fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the checkout resolves")
}

pub(crate) fn declaration() -> Value {
    let text = fs::read_to_string(root().join("verification/genmc/expected.json"))
        .expect("the declaration reads");
    parse(&text).expect("the declaration is JSON")
}

pub(crate) fn case(declared: &Value, name: &str) -> Value {
    let mut declared = declared.clone();
    Value::Object(case_of(&mut declared, name).clone())
}

/// The declaration of case `name` in `declared`, to change in place.
pub(crate) fn case_of<'v>(declared: &'v mut Value, name: &str) -> &'v mut crate::json::Object {
    let Value::Object(declared) = declared else {
        panic!("the declaration is an object");
    };
    let Some(Value::Object(cases)) = declared.get_mut("cases") else {
        panic!("the declaration holds cases");
    };
    let Some(Value::Object(case)) = cases.get_mut(name) else {
        panic!("the case is declared");
    };
    case
}

pub(crate) fn line_of(message: &str) -> usize {
    let file = parse(r#"{"file": "src/join_kernel.rs"}"#).expect("JSON");
    check_line(&root(), &file, &Value::String(message.into())).expect("the check stands once")
}

fn judged(
    name: &str,
    declared: &Value,
    text: &str,
    code: u64,
    graph: &str,
    intrinsics: &[&str],
) -> Result<Judged, Error> {
    let scratch = Scratch::new("judge-case");
    let path = scratch.0.join("graph.dot");
    fs::write(&path, graph).expect("the graph writes");
    let intrinsics: Vec<String> = intrinsics.iter().map(|&name| name.to_owned()).collect();
    judge_case(
        &root(),
        name,
        declared,
        text,
        &Integer::from(code),
        &path,
        &intrinsics,
    )
}

type Refused = (u8, String, &'static str);

fn refusal(result: Result<Judged, Error>) -> Refused {
    match result {
        Err(Error::Refusal(refusal)) => (
            refusal.code().exit(),
            refusal.reason().to_owned(),
            refusal.completion(),
        ),
        other => panic!("a refusal, not {other:?}"),
    }
}

fn with(declared: &Value, key: &str, value: &str) -> Value {
    let Value::Object(mut object) = declared.clone() else {
        panic!("a case is an object");
    };
    object.insert(key, parse(value).expect("JSON"));
    Value::Object(object)
}

#[test]
fn a_positive_run_is_judged_by_its_lines_and_its_exit() {
    let declared = declaration();
    let positive = case(&declared, "join-production");
    let judge = |text: &str, code, intrinsics: &[&str], declared: &Value| {
        refusal(judged(
            "join-production",
            declared,
            text,
            code,
            POSITIVE_GRAPH,
            intrinsics,
        ))
    };
    let pinned = with(&positive, "intrinsics", r#"["llvm.b", "llvm.a"]"#);
    let blocked = format!("{POSITIVE}Number of blocked executions seen: 2\n");
    let twice = format!("{POSITIVE}*** Compilation complete.\n");
    let aborted = format!("Segmentation fault (core dumped)\n{POSITIVE}");
    let errored = format!("{POSITIVE}Error: something\n");
    let zero = POSITIVE.replace("explored: 3", "explored: 0");
    let missing = POSITIVE.replace("No errors were detected.\n", "");
    #[rustfmt::skip]
    let rows: Vec<(Refused, (u8, &str, &str))> = vec![
        (judge(POSITIVE, 130, &[], &positive), (3, "join-production was interrupted (exit 130)", "timeout")),
        (judge(POSITIVE, 143, &[], &positive), (3, "join-production was interrupted (exit 143)", "timeout")),
        (judge(POSITIVE, 0, &["llvm.a"], &pinned),
         (2, "join-production's bitcode calls ['llvm.a'], declared ['llvm.a', 'llvm.b']", "tool failure")),
        (judge(&aborted, 0, &[], &positive), (2, "join-production aborted: 'Segmentation fault (core dumped)'", "tool failure")),
        (judge(&twice, 0, &[], &positive), (2, "join-production prints 2 compilation lines", "tool failure")),
        (judge(&missing, 0, &[], &positive), (2, "join-production prints 0 No errors lines", "tool failure")),
        (judge(&blocked, 0, &[], &positive),
         (1, "join-production pruned executions: 'Number of blocked executions seen: 2'", "completed")),
        (judge(&zero, 0, &[], &positive), (1, "join-production explored no complete execution", "completed")),
        (judge(POSITIVE, 42, &[], &positive), (1, "join-production exited 42, declared positive", "completed")),
        (judge(POSITIVE, 1, &[], &positive), (2, "join-production exited 1, declared positive", "tool failure")),
        (judge(&errored, 0, &[], &positive), (2, "join-production reports an error beside exit 0", "tool failure")),
    ];
    for (found, (code, reason, completion)) in rows {
        assert_eq!(found, (code, reason.to_owned(), completion));
    }
    let accepted = judged(
        "join-production",
        &positive,
        POSITIVE,
        0,
        POSITIVE_GRAPH,
        &[],
    )
    .expect("a positive run passes");
    assert_eq!(
        (accepted.result(), accepted.at(), accepted.executions()),
        ("positive", None, &Integer::from(3_u64))
    );
}

#[test]
fn a_violation_needs_its_one_event_at_a_declared_check_and_its_own_graph() {
    let declared = declaration();
    let violation_case = case(&declared, "join-relaxeddepart");
    let line = line_of(DEPARTURE);
    let text = violation(line);
    let graph = violation_graph(line);
    let judge = |text: &str, code, graph: &str| {
        refusal(judged(
            "join-relaxeddepart",
            &violation_case,
            text,
            code,
            graph,
            &[],
        ))
    };
    let other_line = violation(line_of(FREED));
    let two = text.replace(
        "*** Verification unsuccesful.",
        "\t(0, 5): ERROR join_kernel.rs:1\n*** Verification unsuccesful.",
    );
    let beside = format!("{text}No errors were detected.\n");
    let other_events = graph.replace("}\n", "\t\"(1, 2)\" [label=<W x>]\n}\n");
    let other_error = graph.replace("(0, 4)", "(0, 5)");
    let freed_line = line_of(FREED);
    #[rustfmt::skip]
    let rows: Vec<(Refused, Refused)> = vec![
        (judge(&text, 0, &graph), (1, "join-relaxeddepart exited 0, declared a violation".into(), "completed")),
        (judge(&text, 1, &graph), (2, "join-relaxeddepart exited 1, declared a violation".into(), "tool failure")),
        (judge(&other_line, 42, &graph),
         (1, format!("join-relaxeddepart failed at join_kernel.rs:{freed_line}, declared join_kernel.rs:{line}"), "completed")),
        (judge(&two, 42, &graph), (2, "join-relaxeddepart reports 2 ERROR events".into(), "tool failure")),
        (judge(&beside, 42, &graph), (2, "join-relaxeddepart prints 1 No errors lines beside a violation".into(), "tool failure")),
        (judge(&text, 42, &other_events),
         (2, "join-relaxeddepart's graph holds other events than the run reported".into(), "tool failure")),
        (judge(&text, 42, &other_error),
         (2, format!("join-relaxeddepart's graph marks errors [('0', '5', 'join_kernel.rs', '{line}')], \
the run reported ('0', '4') at join_kernel.rs:{line}"), "tool failure")),
        (judge(&text, 42, ""), (2, "join-relaxeddepart left no error graph".into(), "tool failure")),
    ];
    for (found, (code, reason, completion)) in rows {
        assert_eq!(found, (code, reason, completion));
    }
    let accepted = judged(
        "join-relaxeddepart",
        &violation_case,
        &text,
        42,
        &graph,
        &[],
    )
    .expect("the violation at its check passes");
    let at = format!("join_kernel.rs:{line}");
    assert_eq!(
        (accepted.result(), accepted.at(), accepted.executions()),
        ("violation", Some(at.as_str()), &Integer::from(0_u64))
    );
}

#[test]
fn a_check_line_is_the_line_of_the_check_invocation_around_its_message() {
    let kernel =
        fs::read_to_string(root().join("verification/genmc/packages/kernels/src/join_kernel.rs"))
            .expect("the kernel reads");
    let source: Vec<&str> = kernel.lines().collect();
    for message in [DEPARTURE, FREED] {
        let at = line_of(message);
        let carried = format!("c\"{message}\"");
        let end = (at - 1..source.len())
            .find(|&index| source[index].contains(&carried))
            .expect("the message follows its check");
        assert!(source[at - 1].contains("check!("), "{message}");
        assert!(
            source
                .get(at..end)
                .unwrap_or_default()
                .iter()
                .all(|line| !line.contains("check!(")),
            "{message}"
        );
    }
    let file = parse(r#"{"file": "src/join_kernel.rs"}"#).expect("JSON");
    let absent = Value::String("no kernel check carries this".into());
    match check_line(&root(), &file, &absent) {
        Err(Error::Refusal(refusal)) => assert_eq!(
            (refusal.code(), refusal.reason()),
            (
                Code::ToolFailure,
                "the check 'no kernel check carries this' appears 0 times in src/join_kernel.rs"
            )
        ),
        other => panic!("a refusal, not {other:?}"),
    }
}

#[test]
fn a_graph_is_read_from_the_events_after_the_violation() {
    let line = line_of(DEPARTURE);
    let scratch = Scratch::new("check-graph");
    let path = scratch.0.join("graph.dot");
    let text = format!("(1, 1): W x\n{}", violation(line));
    fs::write(&path, violation_graph(line)).expect("the graph writes");
    let at = Integer::from(line);
    assert!(check_graph("c", &text, &path, ("0", "4"), ("join_kernel.rs", &at)).is_ok());
    let ended = violation_graph(line).replace(
        "}\n",
        "\t\"(1, 3)\" [label=<THREAD_END>]\n\t\"(2, 1)\" [label=<BLOCK>]\n}\n",
    );
    fs::write(&path, ended).expect("the graph writes");
    assert!(check_graph("c", &text, &path, ("0", "4"), ("join_kernel.rs", &at)).is_ok());
}

#[test]
fn a_refusal_takes_the_completion_of_its_code() {
    let completion = |code| Refusal::new(code, String::new()).completion();
    assert_eq!(
        [
            completion(Code::Mismatch),
            completion(Code::ToolFailure),
            completion(Code::Incomplete)
        ],
        ["completed", "tool failure", "exhausted"]
    );
    assert_eq!(
        [Code::Mismatch, Code::ToolFailure, Code::Incomplete].map(Code::exit),
        [1, 2, 3]
    );
    let drift = Refusal::drift(&["a".to_owned(), "b".to_owned()]);
    assert_eq!(
        (drift.reason(), drift.completion(), drift.is_drift()),
        ("correspondence drift: a; b", "correspondence drift", true)
    );
    assert!(!Refusal::new(Code::ToolFailure, String::new()).is_drift());
}

#[test]
fn an_unreadable_json_file_is_a_tool_failure_naming_it() {
    let scratch = Scratch::new("read-json");
    let path = scratch.0.join("x.json");
    for text in [None, Some("{")] {
        if let Some(text) = text {
            fs::write(&path, text).expect("the file writes");
        }
        match read_json(&path) {
            Err(Error::Refusal(refusal)) => {
                assert_eq!(refusal.code(), Code::ToolFailure);
                let prefix = format!("unreadable {}: ", path.display());
                assert!(
                    refusal.reason().starts_with(&prefix),
                    "{}",
                    refusal.reason()
                );
            }
            other => panic!("a refusal, not {other:?}"),
        }
    }
}

#[test]
fn a_message_outside_every_check_invocation_sits_in_none() {
    let scratch = Scratch::new("check-line");
    let package = scratch.0.join("verification/genmc/packages/kernels/src");
    fs::create_dir_all(&package).expect("the package is made");
    fs::write(
        scratch.0.join("verification/genmc/expected.json"),
        r#"{"package": "verification/genmc/packages/kernels"}"#,
    )
    .expect("the declaration writes");
    fs::write(
        package.join("k.rs"),
        "fn f() {\n    let m = c\"lost\";\n}\n",
    )
    .expect("the kernel writes");
    let file = parse(r#"{"file": "src/k.rs"}"#).expect("JSON");
    match check_line(&scratch.0, &file, &Value::String("lost".into())) {
        Err(Error::Refusal(refusal)) => assert_eq!(
            refusal.reason(),
            "the message 'lost' sits in no check! invocation"
        ),
        other => panic!("a refusal, not {other:?}"),
    }
}

#[test]
fn a_graph_that_is_a_fifo_is_no_graph_and_is_read_without_waiting() {
    let scratch = Scratch::new("check-graph-fifo");
    let path = scratch.0.join("graph.dot");
    let made = std::process::Command::new("mkfifo")
        .arg(&path)
        .status()
        .expect("mkfifo starts");
    assert!(made.success());
    let line = Integer::from(line_of(DEPARTURE));
    match check_graph("c", "", &path, ("0", "4"), ("join_kernel.rs", &line)) {
        Err(Error::Refusal(refusal)) => assert_eq!(refusal.reason(), "c left no error graph"),
        other => panic!("a refusal, not {other:?}"),
    }
}

/// A scratch checkout whose kernel `src/k.rs` holds the lines `check_line` reads: a message in a
/// comment beside its check, a form feed, a comment that opens a check inside an invocation and a
/// literal outside every invocation.
fn kernel_root() -> Scratch {
    let scratch = Scratch::new("check-line-rules");
    let package = scratch.0.join("verification/genmc/packages/kernels/src");
    fs::create_dir_all(&package).expect("the package is made");
    fs::write(
        scratch.0.join("verification/genmc/expected.json"),
        r#"{"package": "verification/genmc/packages/kernels"}"#,
    )
    .expect("the declaration writes");
    fs::write(
        package.join("k.rs"),
        "fn f() {\n    check!(a, c\"first\");\n    // c\"first\"\n    \x0c\n    check!(b, c\"second\");\n    \
         check!(\n        // check!(\n        x,\n        c\"third\"\n    );\n    check!(d, c\"fourth\");\n    \
         let m = c\"detached\";\n}\n",
    )
    .expect("the kernel writes");
    scratch
}

/// `check_line` numbers lines as `str.splitlines` does, so the form feed above `second` counts as a
/// line end, and it reads raw lines: a comment that repeats a message counts, a commented `check!(`
/// is the nearest opener, and a literal below an unrelated check takes that check's line.
#[test]
fn a_check_line_reads_raw_lines_numbered_as_splitlines_numbers_them() {
    let scratch = kernel_root();
    let line = |file: &str, message: Value| {
        let file = parse(&format!(r#"{{"file": "{file}"}}"#)).expect("JSON");
        check_line(&scratch.0, &file, &message)
    };
    let text = |message: &str| Value::String(message.into());
    for (message, wanted) in [("second", 6), ("third", 8), ("detached", 12)] {
        assert_eq!(
            line("src/k.rs", text(message)).ok(),
            Some(wanted),
            "{message}"
        );
    }
    for file in ["src/k.rs/", "src/k.rs/."] {
        assert_eq!(line(file, text("second")).ok(), Some(6), "{file}");
    }
    let surrogate = Value::String(Text::from_code_points([0xd800]).expect("a code point"));
    for (message, reason) in [
        (
            text("first"),
            "the check 'first' appears 2 times in src/k.rs",
        ),
        (surrogate, "the check '\\ud800' appears 0 times in src/k.rs"),
    ] {
        match line("src/k.rs", message) {
            Err(Error::Refusal(refusal)) => assert_eq!(refusal.reason(), reason),
            other => panic!("a refusal, not {other:?}"),
        }
    }
}

/// The case rules as the case's own lines give them: `expect` other than `positive` is a violation, an
/// unsuccessful line beside a positive run passes, a graph is compared by its event ids alone, events
/// the graph leaves out stand after the violation line, and every abort phrase refuses in any case.
#[test]
fn a_case_is_judged_by_the_lines_its_rules_read() {
    let declared = declaration();
    let positive = case(&declared, "join-production");
    let violation_case = case(&declared, "join-relaxeddepart");
    let line = line_of(DEPARTURE);
    let (text, graph) = (violation(line), violation_graph(line));
    let with_event = text.replace(
        "*** Verification unsuccesful.",
        "\t(1, 2): W x\n*** Verification unsuccesful.",
    );
    let ended = text.replace(
        "*** Verification unsuccesful.",
        "\t(1, 3): THREAD_END\n\t(2, 1): BLOCK[join]\n*** Verification unsuccesful.",
    );
    let relabeled = graph.replace("}\n", "\t\"(1, 2)\" [label=<R y>]\n}\n");
    let accepted = [
        (
            "join-production",
            positive.clone(),
            format!("{POSITIVE}*** Verification unsuccesful.\n"),
            0,
            POSITIVE_GRAPH.to_owned(),
        ),
        (
            "join-relaxeddepart",
            violation_case.clone(),
            text.clone(),
            42,
            graph.replace("}\n", ""),
        ),
        (
            "join-relaxeddepart",
            violation_case.clone(),
            with_event.clone(),
            42,
            relabeled,
        ),
        (
            "join-relaxeddepart",
            violation_case.clone(),
            ended,
            42,
            graph.clone(),
        ),
    ];
    for (name, declared, text, code, graph) in accepted {
        assert!(
            judged(name, &declared, &text, code, &graph, &[]).is_ok(),
            "{text}"
        );
    }
    let other_file = violation(line).replace("join_kernel.rs", "other_kernel.rs");
    let other_graph = graph.replace("join_kernel.rs", "other_kernel.rs");
    let surrogate = with(&positive, "intrinsics", r#"["\ud800"]"#);
    #[rustfmt::skip]
    let refused: Vec<(Refused, Refused)> = vec![
        (refusal(judged("join-production", &with(&positive, "expect", r#""Positive""#), POSITIVE, 0, POSITIVE_GRAPH, &[])),
         (1, "join-production exited 0, declared a violation".into(), "completed")),
        (refusal(judged("join-production", &with(&positive, "expect", "null"), POSITIVE, 0, POSITIVE_GRAPH, &[])),
         (1, "join-production exited 0, declared a violation".into(), "completed")),
        (refusal(judged("join-relaxeddepart", &violation_case, &with_event, 42, &graph, &[])),
         (2, "join-relaxeddepart's graph holds other events than the run reported".into(), "tool failure")),
        (refusal(judged("join-relaxeddepart", &violation_case, &other_file, 42, &other_graph, &[])),
         (1, format!("join-relaxeddepart failed at other_kernel.rs:{line}, declared join_kernel.rs:{line}"), "completed")),
        (refusal(judged("join-production", &surrogate, POSITIVE, 0, POSITIVE_GRAPH, &[])),
         (2, "join-production's bitcode calls [], declared ['\\ud800']".into(), "tool failure")),
    ];
    for (found, wanted) in refused {
        assert_eq!(found, wanted);
    }
    for phrase in [
        "does not support intrinsic x",
        "Constant unimplemented",
        "LLVM ERROR: y",
        "Aborted",
        "Segmentation fault",
        "terminate called after",
        "internal error",
        "unsupported thing",
        "SEGMENTATION FAULT",
        "Internal Error",
    ] {
        let aborted = format!("{phrase}\n{POSITIVE}");
        assert_eq!(
            refusal(judged(
                "join-production",
                &positive,
                &aborted,
                0,
                POSITIVE_GRAPH,
                &[]
            )),
            (
                2,
                format!("join-production aborted: '{phrase}'"),
                "tool failure"
            )
        );
    }
    let assertion = format!("Assertion `z' failed\n{POSITIVE}");
    assert_eq!(
        refusal(judged(
            "join-production",
            &positive,
            &assertion,
            0,
            POSITIVE_GRAPH,
            &[]
        )),
        (
            2,
            "join-production aborted: \"Assertion `z' failed\"".to_owned(),
            "tool failure"
        )
    );
}
