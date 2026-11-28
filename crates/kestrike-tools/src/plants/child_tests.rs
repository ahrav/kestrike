//! A logged child's output, its endings without a verdict, the question to the staged helper, and the
//! exits of a run's halt.

use std::ffi::OsString;
use std::path::Path;

use super::{Halt, Logged, Stopped, counts, logged, verdict_texts};
use crate::paths::tests::Scratch;
use crate::process::Interrupt;
use crate::text::Text;

fn sh(script: &str) -> Vec<OsString> {
    ["sh", "-c", script].map(OsString::from).to_vec()
}

fn started<'a>(
    log: &'a Path,
    argv: &'a [OsString],
    env: &'a crate::environ::Environ,
    work: &'a Path,
) -> Logged<'a> {
    Logged {
        log,
        argv,
        what: "campaign sweep",
        cwd: None,
        env,
        session: false,
        work,
    }
}

fn host_env() -> crate::environ::Environ {
    std::env::vars_os().collect()
}

/// The output comes back as text with `\r\n` and `\r` read as `\n`, beside the exit, and the error
/// output stands in its own log.
#[test]
fn a_logged_child_returns_its_exit_and_its_output_as_text() {
    let scratch = Scratch::new("logged");
    let (log, env) = (scratch.0.join("sweep"), host_env());
    let argv = sh("printf 'a\\r\\nb\\rc\\n'; printf 'warned' >&2; exit 3");
    let (code, out) =
        logged(&started(&log, &argv, &env, &scratch.0), &Interrupt::new()).expect("the child runs");
    assert_eq!((code, out.as_str()), (3, "a\nb\nc\n"));
    assert_eq!(
        std::fs::read_to_string(scratch.0.join("sweep.err")).expect("reads"),
        "warned"
    );
}

/// Output that is no UTF-8 names the log from the work directory; a log that exists starts no child.
#[test]
fn a_child_without_text_or_without_a_new_log_leaves_no_verdict() {
    let scratch = Scratch::new("logged-ends");
    let (log, env) = (scratch.0.join("sweep"), host_env());
    let argv = sh("printf '\\377'");
    let Err(Stopped::NoVerdict(ending)) =
        logged(&started(&log, &argv, &env, &scratch.0), &Interrupt::new())
    else {
        panic!("output that is no UTF-8 leaves no verdict");
    };
    let reason = ending.reason().to_string();
    assert!(
        reason.starts_with("`campaign sweep` exited 0 and printed no UTF-8 text ("),
        "{reason}"
    );
    assert!(
        reason.ends_with("); its output is in sweep.out"),
        "{reason}"
    );
    let marker = scratch.0.join("ran");
    let argv = sh(&format!("touch '{}'", marker.display()));
    let Err(Stopped::NoVerdict(ending)) =
        logged(&started(&log, &argv, &env, &scratch.0), &Interrupt::new())
    else {
        panic!("a log that exists leaves no verdict");
    };
    assert_eq!(
        ending.reason().to_string(),
        "`campaign sweep` did not run: File exists"
    );
    assert!(!marker.exists(), "no child started");
}

/// A signal recorded before the start ends the run with no child started.
#[test]
fn a_recorded_signal_starts_no_child() {
    let scratch = Scratch::new("logged-signal");
    let (log, env) = (scratch.0.join("sweep"), host_env());
    let marker = scratch.0.join("ran");
    let argv = sh(&format!("touch '{}'", marker.display()));
    let interrupt = Interrupt::new();
    interrupt.record(libc::SIGHUP);
    let Err(Stopped::Halt(halt)) = logged(&started(&log, &argv, &env, &scratch.0), &interrupt)
    else {
        panic!("a recorded signal ends the run");
    };
    assert_eq!(
        (halt.clone(), halt.code()),
        (Halt::Interrupted(libc::SIGHUP), 129)
    );
    assert_eq!(Halt::Failed(crate::text::Text::from("x")).code(), 4);
    assert!(!marker.exists());
}

/// The question reads the answer the `python3` on the given `PATH` prints, and words a missing answer
/// by the last line of that child's error output.
#[test]
fn the_question_reads_the_helper_s_answer_or_its_last_error_line() {
    let scratch = Scratch::new("question");
    let python = scratch.0.join("python3");
    let script = r#"#!/bin/sh
case "$#" in
4) echo '["held", "failed"]' ;;
*) read -r size; read -r line; if [ "$line" = yes ]; then echo true; else echo 'Traceback' >&2; echo 'TypeError: no' >&2; exit 1; fi ;;
esac
"#;
    let written = std::process::Command::new("sh")
        .args([
            "-c",
            "printf '%s' \"$2\" > \"$1\" && chmod 755 \"$1\"",
            "sh",
        ])
        .arg(&python)
        .arg(script)
        .status()
        .expect("the writer starts");
    assert!(
        written.success(),
        "the stand-in is written by a child, the one process that holds it open"
    );
    let env = vec![(OsString::from("PATH"), scratch.0.clone().into_os_string())];
    let helper = scratch.0.join("reproduce-test.py");
    let results = verdict_texts(&env, &helper, b"").expect("an answer");
    assert_eq!(results, [Text::from("held"), Text::from("failed")]);
    let yes = crate::text::Text::from("yes");
    assert_eq!(counts(&env, &helper, b"", 0, &yes), Ok(true));
    let no = crate::text::Text::from("no");
    assert_eq!(
        counts(&env, &helper, b"", 1, &no)
            .expect_err("no answer")
            .to_string(),
        "TypeError: no"
    );
}
