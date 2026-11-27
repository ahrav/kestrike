//! The readers of a finished command's output: the JSON object of its first or last line, the verdict
//! of a proof rerun and the pins of an archive. Where a reason carries a
//! JSON reader's text, it is this crate's reader's text after the reason's own words.

use std::path::Path;

use kestrike_tools::json::{self, Value};
use kestrike_tools::plants::{
    HelperVerdict, Kind, NoVerdict, Rerun, archive_pins, first_object, judge_rerun, last_object,
};
use kestrike_tools::text::Text;

enum Line {
    First,
    Last,
}

enum Read {
    Object(&'static str),
    Refused(&'static str),
    /// The reader's refusal: the words, `: ` and this crate's JSON reader's text for the line.
    Reader,
}

/// A command's first line, or its last once Python's whitespace is stripped, reads as one object; a
/// line of another JSON value, of no JSON and with a repeated member, at any depth, is no object.
#[test]
fn a_command_line_reads_as_one_json_object() {
    let rows: &[(&str, Line, Read)] = &[
        ("{\"a\": 1}\nmore", Line::First, Read::Object(r#"{"a":1}"#)),
        ("{\"a\": 1}\nmore", Line::Last, Read::Reader),
        (r#" {"a": 1}"#, Line::First, Read::Object(r#"{"a":1}"#)),
        (r#" {"a": 1}"#, Line::Last, Read::Object(r#"{"a":1}"#)),
        (
            r#"[1]"#,
            Line::First,
            Read::Refused(r#"`campaign sweep-status` printed no JSON object"#),
        ),
        (
            r#"[1]"#,
            Line::Last,
            Read::Refused(r#"`campaign sim run` printed no JSON object"#),
        ),
        (r#""#, Line::First, Read::Reader),
        (r#""#, Line::Last, Read::Reader),
        (r#"x"#, Line::First, Read::Reader),
        (r#"x"#, Line::Last, Read::Reader),
        (
            r#"{"a": 1, "a": 2}"#,
            Line::First,
            Read::Refused(r#"`campaign sweep-status` printed no JSON object: repeated member a"#),
        ),
        (
            r#"{"a": 1, "a": 2}"#,
            Line::Last,
            Read::Refused(r#"`campaign sim run` printed no JSON object: repeated member a"#),
        ),
        (
            r#"{"a": {"b": 1, "b": 2}, "a": 3}"#,
            Line::First,
            Read::Refused(r#"`campaign sweep-status` printed no JSON object: repeated member b"#),
        ),
        (
            r#"{"a": {"b": 1, "b": 2}, "a": 3}"#,
            Line::Last,
            Read::Refused(r#"`campaign sim run` printed no JSON object: repeated member b"#),
        ),
        (
            r#"{"a": NaN, "b": -Infinity}"#,
            Line::First,
            Read::Object(r#"{"a":NaN,"b":-Infinity}"#),
        ),
        (
            r#"{"a": NaN, "b": -Infinity}"#,
            Line::Last,
            Read::Object(r#"{"a":NaN,"b":-Infinity}"#),
        ),
        ("\n{\"a\": 1}", Line::First, Read::Reader),
        ("\n{\"a\": 1}", Line::Last, Read::Object(r#"{"a":1}"#)),
        ("{\"a\": 1}\r\n", Line::First, Read::Object(r#"{"a":1}"#)),
        ("{\"a\": 1}\r\n", Line::Last, Read::Object(r#"{"a":1}"#)),
    ];
    for (text, line, read) in rows {
        let (got, what, given) = match line {
            Line::First => (
                first_object(text, "sweep-status"),
                "sweep-status",
                text.split('\n').next(),
            ),
            Line::Last => (
                last_object(text, "sim run"),
                "sim run",
                text.trim().rsplit('\n').next(),
            ),
        };
        let got = got
            .map(|object| json::text(&Value::Object(object)))
            .map_err(|ending| ending.reason().to_string());
        let expected = match read {
            Read::Object(object) => Ok((*object).to_owned()),
            Read::Refused(reason) => Err((*reason).to_owned()),
            Read::Reader => {
                let error = json::parse(given.unwrap_or_default()).expect_err("no JSON");
                Err(format!("`campaign {what}` printed no JSON object: {error}"))
            }
        };
        assert_eq!(got, expected, "{text:?}");
    }
}

/// A rerun is judged in the order lockfile, exit 3, another exit than 0 and 1, then the helper's
/// verdict, which is asked once, for an exit of 0 or 1 alone, with the last line of the output stripped.
#[test]
fn a_proof_rerun_is_judged_in_the_order_of_its_checks() {
    type Ending = Result<u8, (Kind, &'static str)>;
    type Asked = &'static [(i32, &'static str)];
    let rows: &[(bool, i32, &str, bool, Asked, Ending)] = &[
        (
            false,
            0,
            r#"x"#,
            true,
            &[],
            Err((
                Kind::Relocked,
                r#"the rerun of the proof net::the_test left the proof's worktree without the run's Cargo.lock; its output is in proof/head-0.out"#,
            )),
        ),
        (
            false,
            3,
            r#""#,
            true,
            &[],
            Err((
                Kind::Relocked,
                r#"the rerun of the proof net::the_test left the proof's worktree without the run's Cargo.lock; its output is in proof/head-0.out"#,
            )),
        ),
        (
            true,
            3,
            r#""#,
            true,
            &[],
            Err((
                Kind::Unbuilt,
                r#"the rerun of the proof net::the_test exited 3; its verdict is in proof/head-0.out and its build output under proof/artifacts/head-0"#,
            )),
        ),
        (
            true,
            2,
            r#""#,
            true,
            &[],
            Err((
                Kind::Plain,
                r#"the rerun of the proof net::the_test exited 2; its verdict is in proof/head-0.out, its error output in proof/head-0.err and its run's output under proof/artifacts/head-0"#,
            )),
        ),
        (
            true,
            4,
            r#""#,
            true,
            &[],
            Err((
                Kind::Plain,
                r#"the rerun of the proof net::the_test exited 4; its verdict is in proof/head-0.out, its error output in proof/head-0.err and its run's output under proof/artifacts/head-0"#,
            )),
        ),
        (
            true,
            6,
            r#""#,
            true,
            &[],
            Err((
                Kind::Plain,
                r#"the rerun of the proof net::the_test exited 6; its verdict is in proof/head-0.out, its error output in proof/head-0.err and its run's output under proof/artifacts/head-0"#,
            )),
        ),
        (
            true,
            -9,
            r#""#,
            true,
            &[],
            Err((
                Kind::Plain,
                r#"the rerun of the proof net::the_test exited -9; its verdict is in proof/head-0.out, its error output in proof/head-0.err and its run's output under proof/artifacts/head-0"#,
            )),
        ),
        (
            true,
            0,
            "a\nnot reproduced\n\n",
            true,
            &[(0, r#"not reproduced"#)],
            Ok(0),
        ),
        (
            true,
            1,
            "reproduced  \u{2029} ",
            true,
            &[(1, r#"reproduced"#)],
            Ok(1),
        ),
        (
            true,
            0,
            r#""#,
            false,
            &[(0, r#""#)],
            Err((
                Kind::Plain,
                r#"the rerun of the proof net::the_test exited 0 without the verdict `not reproduced`; its output is in proof/head-0.out"#,
            )),
        ),
        (
            true,
            1,
            "a\r\nb\u{1c}",
            false,
            &[(1, r#"b"#)],
            Err((
                Kind::Plain,
                r#"the rerun of the proof net::the_test exited 1 without the verdict `reproduced`; its output is in proof/head-0.out"#,
            )),
        ),
        (true, 0, " \n\t", true, &[(0, r#""#)], Ok(0)),
    ];
    let proof = Text::from("net::the_test");
    for &(holds, code, out, counted, asked, expected) in rows {
        let mut calls = Vec::new();
        let rerun = Rerun {
            proof: &proof,
            log: Path::new("proof/head-0"),
            kept: Path::new("proof/artifacts/head-0"),
            holds_lock: holds,
            code,
            out,
        };
        let expected_line = Text::from(if code == 0 {
            "not reproduced"
        } else {
            "reproduced"
        });
        let got = judge_rerun(&rerun, |exit, line| {
            calls.push((exit, line.to_string()));
            Ok(if counted {
                HelperVerdict::Counted
            } else {
                HelperVerdict::Uncounted {
                    expected: expected_line,
                }
            })
        });
        let got = got.map_err(|ending| (ending.kind(), ending.reason().to_string()));
        let expected = expected.map_err(|(kind, reason)| (kind, reason.to_owned()));
        assert_eq!(got, expected, "{holds} {code} {out:?}");
        let asked: Vec<(i32, String)> = asked
            .iter()
            .map(|&(exit, line)| (exit, line.to_owned()))
            .collect();
        assert_eq!(calls, asked, "{holds} {code} {out:?}");
    }
}

/// The helper's own refusal, which its caller composes, is the rerun's ending.
#[test]
fn a_verdict_the_helper_cannot_give_is_the_reruns_ending() {
    let proof = Text::from("net::the_test");
    let rerun = Rerun {
        proof: &proof,
        log: Path::new("l"),
        kept: Path::new("k"),
        holds_lock: true,
        code: 1,
        out: "reproduced",
    };
    let refused = NoVerdict::plain("the head's verdict check failed");
    assert_eq!(
        judge_rerun(&rerun, |_, _| Err(refused.clone())),
        Err(refused)
    );
}

/// An archive's build exit, its last line and its four pins as text decide its pins.
#[test]
fn an_archive_prints_its_four_pins_as_text() {
    type Pinned = Result<&'static str, Option<&'static str>>;
    let rows: &[(i32, &str, Pinned)] = &[
        (
            3,
            r#""#,
            Err(Some(
                r#"the planted tree does not build: `campaign sim archive` exited 3"#,
            )),
        ),
        (
            2,
            r#""#,
            Err(Some(
                r#"`campaign sim archive` of the planted tree exited 2; its error is in plants/alpha/archive.err"#,
            )),
        ),
        (
            -6,
            r#""#,
            Err(Some(
                r#"`campaign sim archive` of the planted tree exited -6; its error is in plants/alpha/archive.err"#,
            )),
        ),
        (0, "built\n", Err(None)),
        (
            0,
            r#"{"build": "b"}"#,
            Err(Some(r#"`campaign sim archive` printed no pins"#)),
        ),
        (
            0,
            "log\n{\"build\": \"b\", \"executable\": \"e\", \"platform\": \"p\", \"toolchain\": 1}\n",
            Err(Some(r#"`campaign sim archive` printed no pins"#)),
        ),
        (
            0,
            "log\n{\"build\": \"b\", \"executable\": \"e\", \"platform\": \"p\", \"toolchain\": \"t\"}\n  ",
            Ok(r#"{"build":"b","executable":"e","platform":"p","toolchain":"t"}"#),
        ),
        (
            0,
            r#"{"toolchain": "t", "platform": "p", "executable": "e", "build": "b", "more": 1}"#,
            Ok(r#"{"toolchain":"t","platform":"p","executable":"e","build":"b","more":1}"#),
        ),
    ];
    let err = Path::new("plants/alpha/archive.err");
    for &(code, out, expected) in rows {
        let got = archive_pins(code, out, "the planted tree", err);
        match (got, expected) {
            (Ok(pins), Ok(object)) => {
                let json::Value::Object(printed) = json::parse(object).expect("JSON") else {
                    panic!("an object");
                };
                let pin = |name| match printed.get(name) {
                    Some(Value::String(pin)) => pin.repr(),
                    other => panic!("{name}: {other:?}"),
                };
                let named = ["build", "executable", "platform", "toolchain"].map(pin);
                assert_eq!(format!("{pins:?}"), format!("Pins([{}])", named.join(", ")));
                assert_eq!(
                    Value::String(pins.build().clone()),
                    *printed.get("build").expect("a build")
                );
            }
            (Err(ending), Err(Some(reason))) => assert_eq!(ending.reason(), &Text::from(reason)),
            (Err(ending), Err(None)) => {
                let error = json::parse(out.trim()).expect_err("no JSON");
                let reason = format!("`campaign sim archive` printed no JSON object: {error}");
                assert_eq!(ending.reason(), &Text::from(reason.as_str()));
            }
            (got, expected) => panic!("{out:?}: {got:?} where the row expects {expected:?}"),
        }
    }
}
