//! The judgment of the legs through the real runner: each wrong red, the framing that never holds the
//! expected text, the lines it is read from, a runner that leaves a leg undocumented, and the runner
//! bytes both legs run.

use std::fs;
use std::path::PathBuf;

use kestrike_tools::red_green::expected::unframed;
use kestrike_tools::text::Text;

use super::standins::stub_runner;
use super::support::{
    EXPECT, FAILED, Fixture, NO_EVIDENCE, TEST, TWO_LINES, assert_gone, at, has, json_of, keys,
    pid_in, private_dir, root, sha256, text, texts, write,
};

/// Each wrong red is refused by a reason of its own, the receipt's result is that refusal, and the legs
/// that ran are the receipt's and the builds'; a leg that ran no attempt records its own artifact and
/// no attempt output, and a hung test leaves no process behind.
#[test]
fn each_wrong_red_is_refused_by_its_own_reason() {
    let fx = Fixture::new();
    let mut reasons = Vec::new();
    for (name, plan, carry, watchdog, reason) in [
        (
            "passes",
            r#"{"base": {"attempt": "pass"}}"#,
            None,
            None,
            "the test passes on the base: not reproduced",
        ),
        (
            "build",
            r#"{"base": {"build_exit": 101}}"#,
            None,
            None,
            "the base is red for the wrong reason, a build failure: build failure",
        ),
        (
            "absent",
            "{}",
            Some("notes.txt"),
            None,
            "the test is absent on the base: rejected input:",
        ),
        (
            "crash",
            r#"{"base": {"attempt": "crash"}}"#,
            None,
            None,
            "the test crashed on the base: crash",
        ),
        (
            "text",
            r#"{"base": {"attempt": "other-text"}}"#,
            None,
            None,
            "the test failed on the base without the expected text: reproduced",
        ),
        (
            "hang",
            r#"{"base": {"attempt": "hang"}}"#,
            None,
            Some("1"),
            "the test hung on the base: watchdog expiry",
        ),
        (
            "head",
            r#"{"head": {"attempt": "fail"}}"#,
            None,
            None,
            "the test fails on the head: reproduced",
        ),
        (
            "head-build",
            r#"{"head": {"build_exit": 101}}"#,
            None,
            None,
            "the head leg did not pass: exit 3, verdict 'build failure",
        ),
        (
            "head-crash",
            r#"{"head": {"attempt": "crash"}}"#,
            None,
            None,
            "the head leg did not pass: exit 4, verdict 'crash",
        ),
    ] {
        fx.plan(plan);
        fx.clear_builds();
        let done = fx.run(|call| {
            if let Some(carry) = carry {
                call.carry = vec![carry.into()];
            }
            if let Some(watchdog) = watchdog {
                call.watchdog = watchdog.to_owned();
            }
        });
        assert_eq!(done.code, 1, "{name}: {}", done.shown());
        let line = done.line().to_owned();
        assert!(
            line.starts_with(&format!("red-green refused: {reason}")),
            "{name}: {line}"
        );
        if name == "absent" {
            assert!(line.contains("matched 0 listed"), "{line}");
        }
        if name == "hang" {
            assert_gone(pid_in(&fx.state.join("grandchild.pid")));
        }
        let (_, receipt) = fx.receipt(&done);
        assert_eq!(
            text(at(&receipt, "result")),
            line.replacen("red-green refused: ", "refused: ", 1)
        );
        let legs: &[&str] = if name.starts_with("head") {
            &["base", "head"]
        } else {
            &["base"]
        };
        if ["build", "absent", "head-build"].contains(&name) {
            let entry = at(at(&receipt, "legs"), legs[legs.len() - 1]);
            let artifact = PathBuf::from(text(at(entry, "artifact")));
            assert_eq!(text(at(entry, "sha256")), sha256(&artifact), "{name}");
            assert_eq!(json_of(at(entry, "attempt_sha256")), "{}", "{name}");
            assert!(!has(entry, "evidence_error"), "{name}");
        }
        assert_eq!(keys(at(&receipt, "legs")), legs, "{name}");
        assert_eq!(fx.build_legs(), legs, "{name}");
        reasons.push(line);
        fx.assert_checkout_unchanged();
    }
    let mut distinct = reasons.clone();
    distinct.sort();
    distinct.dedup();
    assert_eq!(distinct.len(), reasons.len(), "{reasons:?}");
}

fn kept(output: &str) -> String {
    unframed(output.as_bytes(), &Text::from(TEST)).to_string()
}

/// No framing line holds the expected text: each text libtest or the panic hook prints around a failure,
/// should_panic's echo of the expected substring among them, refuses the run as one without the
/// expected text, and the attempt output holds it only on a framing line. Lines split at LF alone, and a
/// final CR stays on a kept line.
#[test]
fn framing_lines_never_hold_the_expected_text() {
    let fx = Fixture::new();
    let fail: [&str; 10] = [
        "running 1",
        "... FAILED",
        "failures:",
        &format!("---- {}", &TEST[..7]),
        &format!("    {}", &TEST[..7]),
        "panicked at",
        "display a backtrace",
        "table_tests.rs:9:5",
        "table_tests::frame",
        "1 failed",
    ];
    let should_panic = [
        "zzz",
        "should panic",
        "... FAILED",
        "panic did not contain",
        "panic message",
        "Some details",
    ];
    let non_string = ["expected panic with string value", "found non-string value"];
    for (outcome, texts) in [
        ("fail", &fail[..]),
        ("should-panic", &should_panic[..]),
        ("non-string", &non_string[..]),
    ] {
        fx.plan(&format!(r#"{{"base": {{"attempt": "{outcome}"}}}}"#));
        let done = fx.run(|call| call.expect = texts[0].to_owned());
        assert_eq!(done.code, 1, "{outcome}: {}", done.shown());
        assert!(
            done.stdout.starts_with(
                "red-green refused: the test failed on the base without the expected text: reproduced"
            ),
            "{outcome}: {}",
            done.stdout
        );
        let (_, receipt) = fx.receipt(&done);
        let output = fx.attempt_output(&receipt, "stdout");
        let left = kept(&output);
        for text in texts {
            assert!(output.contains(text), "{outcome}: {text}");
            assert!(!left.contains(text), "{outcome}: {text}");
        }
    }
    for separator in ["\u{b}", "\u{2028}", "\u{1c}"] {
        assert!(!kept(&TWO_LINES.replace('\n', separator)).contains(TWO_LINES));
    }
    assert_eq!(
        kept(&format!("running 1 test\r\n{EXPECT}\r\n")),
        format!("\0\n{EXPECT}\r\n")
    );
    let uncaptured = format!(
        "\nrunning 1 test\ntest {TEST} ... a line the test prints\nFAILED\n\nfailures:\n\n\
         failures:\n    {TEST}\n\n{FAILED}\n"
    );
    assert!(!kept(&uncaptured).contains("FAILED"));
}

/// The expected text is read from the lines framing leaves: a should_panic test's note that it did not
/// panic, the test's own message, a line on standard error alone, and two adjacent payload lines prove
/// the base red; a framing location and payload lines split by a framing line do not.
#[test]
fn the_expected_text_is_read_from_the_lines_framing_leaves() {
    let fx = Fixture::new();
    for (outcome, expect, proven) in [
        ("no-panic", "did not panic as expected", true),
        ("test-message", "lost a completion", true),
        ("stderr-text", EXPECT, true),
        ("stderr-text", "stderr_fixture.rs:1:1", false),
        ("adjacent", TWO_LINES, true),
        ("split", TWO_LINES, false),
    ] {
        fx.plan(&format!(r#"{{"base": {{"attempt": "{outcome}"}}}}"#));
        let done = fx.run(|call| call.expect = expect.to_owned());
        assert_eq!(
            done.code,
            if proven { 0 } else { 1 },
            "{outcome}: {}",
            done.shown()
        );
        if !proven {
            assert!(
                done.stdout.starts_with(
                    "red-green refused: the test failed on the base without the expected text"
                ),
                "{}",
                done.stdout
            );
        }
        if outcome == "stderr-text" {
            let (_, receipt) = fx.receipt(&done);
            assert!(!fx.attempt_output(&receipt, "stdout").contains(expect));
            assert!(fx.attempt_output(&receipt, "stderr").contains(expect));
            let streams = texts(at(at(at(&receipt, "legs"), "base"), "expect_streams"));
            assert_eq!(
                streams,
                if proven {
                    vec!["stderr".to_owned()]
                } else {
                    Vec::new()
                }
            );
        }
        if outcome == "adjacent" {
            assert_eq!(
                done.stdout,
                format!(
                    "red-green: {TEST} failed on {} with \"first payload line\\nsecond payload line\" and \
                     passed on {}\n",
                    &fx.base[..12],
                    &fx.head[..12]
                )
            );
        }
    }
}

/// A runner that does not complete a leg, or that leaves a leg's artifact, verdict or attempt output out
/// of the receipt, is refused: a runner of exit 2, then a stub runner under the top's `scripts/` that
/// stops at once, drops the announcement, deletes an attempt output, announces the other leg's artifact
/// or prints no verdict.
#[test]
fn a_runner_that_does_not_complete_or_document_a_leg_is_refused() {
    let fx = Fixture::new();
    fx.plan(r#"{"base": {"metadata_exit": 1}}"#);
    let done = fx.run(|_| {});
    assert_eq!(done.code, 1, "{}", done.shown());
    assert_eq!(
        done.stdout,
        "red-green refused: the runner did not complete the base leg: exit 2, verdict 'rejected input: \
         cargo metadata exited 1'\n"
    );
    let scripts = fx.root.join("scripts");
    private_dir(&scripts);
    fs::copy(
        root().join("scripts/select-tests.py"),
        scripts.join("select-tests.py"),
    )
    .expect("copied");
    write(
        &scripts.join("reproduce-test.py"),
        stub_runner(&root().join("scripts/reproduce-test.py")),
    );
    for (plan, reason, legs) in [
        (
            "{}",
            "the runner did not complete the base leg: exit 1, verdict 'Traceback (most recent call last): \
             the runner stopped'"
                .to_owned(),
            &["base"][..],
        ),
        (
            r#"{"base": {"stub": "no-artifact"}}"#,
            format!("the base leg failed but {NO_EVIDENCE}: reproduced"),
            &["base"],
        ),
        (
            r#"{"base": {"stub": "no-stderr"}}"#,
            format!("the base leg failed but {NO_EVIDENCE}: reproduced"),
            &["base"],
        ),
        (
            r#"{"base": {"stub": "real"}, "head": {"stub": "other-leg"}}"#,
            format!("the head leg passed but {NO_EVIDENCE}: not reproduced"),
            &["base", "head"],
        ),
        (
            r#"{"base": {"stub": "real"}, "head": {"stub": "no-stderr"}}"#,
            format!("the head leg passed but {NO_EVIDENCE}: not reproduced"),
            &["base", "head"],
        ),
        (
            r#"{"base": {"stub": "real"}, "head": {"stub": "no-verdict"}}"#,
            "the head leg did not pass: exit 0, verdict ''".to_owned(),
            &["base", "head"],
        ),
    ] {
        fx.plan(plan);
        let done = fx.run(|call| call.top = Some(fx.root.clone()));
        assert_eq!(done.code, 1, "{plan}: {}", done.shown());
        let line = done.line();
        assert!(line.starts_with(&format!("red-green refused: {reason}")), "{plan}: {line}");
        let (_, receipt) = fx.receipt(&done);
        assert_eq!(keys(at(&receipt, "legs")), legs, "{plan}");
        fx.assert_checkout_unchanged();
    }
}

/// Both legs run the runner read at startup: a base build that replaces the runner under the top
/// changes that file and no leg, and one that replaces the copy beside the leg worktrees changes the
/// base leg's copy alone, since the head leg gets a fresh copy; the receipt digests the bytes read at
/// startup.
#[test]
fn both_legs_run_the_runner_read_at_startup() {
    let fx = Fixture::new();
    let scripts = fx.root.join("scripts");
    private_dir(&scripts);
    fs::copy(
        root().join("scripts/select-tests.py"),
        scripts.join("select-tests.py"),
    )
    .expect("copied");
    let runner = scripts.join("reproduce-test.py");
    let original = sha256(&root().join("scripts/reproduce-test.py"));
    for replaced in [
        runner.to_string_lossy().into_owned(),
        "../scripts/reproduce-test.py".to_owned(),
    ] {
        fs::copy(root().join("scripts/reproduce-test.py"), &runner).expect("copied");
        fx.plan(&format!(
            r#"{{"base": {{"replace": {}}}}}"#,
            json_of(&text_value(&replaced))
        ));
        let done = fx.run(|call| call.top = Some(fx.root.clone()));
        assert_eq!(done.code, 0, "{replaced}: {}", done.shown());
        let read = fs::read_to_string(&runner).expect("the runner reads");
        assert_eq!(
            read.contains("): replaced"),
            replaced.starts_with('/'),
            "{replaced}"
        );
        let (_, receipt) = fx.receipt(&done);
        assert_eq!(
            text(at(at(&receipt, "scripts"), "reproduce-test.py")),
            original
        );
        fx.assert_checkout_unchanged();
    }
}

fn text_value(text: &str) -> kestrike_tools::json::Value {
    kestrike_tools::json::Value::String(Text::from(text))
}
