//! A logged child's output, its endings without a verdict, the question to the staged helper, and the
//! exits of a run's halt.

use std::ffi::OsString;
use std::path::Path;

use super::{Halt, Logged, Staged, Stopped, counts, logged, verdict_texts};
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
    let staged = Staged {
        env: &env,
        dir: &scratch.0,
        helper: &helper,
        source: b"",
    };
    let none = Interrupt::new();
    let results = verdict_texts(&staged, &none).expect("an answer");
    assert_eq!(results, [Text::from("held"), Text::from("failed")]);
    let yes = crate::text::Text::from("yes");
    assert_eq!(counts(&staged, 0, &yes, &none), Ok(true));
    let no = crate::text::Text::from("no");
    assert_eq!(
        counts(&staged, 1, &no, &none)
            .expect_err("no answer")
            .to_string(),
        "TypeError: no"
    );
    let names: Vec<_> = std::fs::read_dir(&scratch.0)
        .expect("lists")
        .map(|entry| entry.expect("an entry").file_name())
        .collect();
    assert_eq!(
        names,
        [OsString::from("python3")],
        "the question's streams leave no name"
    );
}

fn stand_in(dir: &Path, script: &str) -> crate::environ::Environ {
    let python = dir.join("python3");
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
    assert!(written.success(), "the stand-in is written by a child");
    vec![(OsString::from("PATH"), dir.as_os_str().to_os_string())]
}

/// `with_tools` puts `/usr/bin` and `/bin` behind the stand-in's directory on the `PATH` of `env`, where
/// the stand-in's script finds `touch` and `sleep`.
fn with_tools(mut env: crate::environ::Environ) -> crate::environ::Environ {
    let mut path = crate::environ::get(&env, "PATH")
        .expect("the stand-in's `PATH`")
        .clone();
    path.push(":/usr/bin:/bin");
    crate::environ::set(&mut env, "PATH", path);
    env
}

/// An answer whose bytes are no UTF-8 is no answer, even inside a JSON string of the right shape; the
/// reason is the last line of the error output.
#[test]
fn an_answer_that_is_no_utf_8_is_no_answer() {
    let scratch = Scratch::new("question-bytes");
    let env = stand_in(
        &scratch.0,
        "#!/bin/sh\nprintf '[\"held\", \"fa\\377iled\"]\\n'; echo 'printed bytes' >&2\n",
    );
    let helper = scratch.0.join("reproduce-test.py");
    let staged = Staged {
        env: &env,
        dir: &scratch.0,
        helper: &helper,
        source: b"",
    };
    assert_eq!(
        verdict_texts(&staged, &Interrupt::new()),
        Err(Text::from("printed bytes"))
    );
}

/// A signal recorded before the question starts no `python3`, and the caller reads the record after.
/// The stand-in leaves a marker each time it starts, which the same question shows first with no signal
/// recorded.
#[test]
fn a_signal_recorded_before_the_question_starts_no_python3() {
    let scratch = Scratch::new("question-signal");
    let marker = scratch.0.join("ran");
    let env = with_tools(stand_in(
        &scratch.0,
        &format!("#!/bin/sh\ntouch '{}'\necho true\n", marker.display()),
    ));
    let helper = scratch.0.join("reproduce-test.py");
    let staged = Staged {
        env: &env,
        dir: &scratch.0,
        helper: &helper,
        source: b"",
    };
    let interrupt = Interrupt::new();
    assert_eq!(
        counts(&staged, 0, &Text::from("line"), &interrupt),
        Ok(true)
    );
    assert!(marker.exists(), "a question that starts leaves the marker");
    std::fs::remove_file(&marker).expect("the marker is removed");
    interrupt.record(libc::SIGTERM);
    assert_eq!(
        counts(&staged, 0, &Text::from("line"), &interrupt),
        Err(Text::from("`python3` did not start: a signal was recorded"))
    );
    assert!(!marker.exists(), "no question started");
}

/// The wait ends when the question exits while a descendant it left holds standard error open and
/// writes to it; an accepted answer is returned without reading that stream. The stand-in answers only
/// where it finds `sleep`, so an answer shows that the descendant sleeps with the streams open.
#[test]
fn a_descendant_holding_the_question_s_streams_does_not_hold_the_answer() {
    let scratch = Scratch::new("question-descendant");
    let env = with_tools(stand_in(
        &scratch.0,
        "#!/bin/sh\nsleep 0 || exit 1\n(sleep 30; echo late >&2) &\necho true\n",
    ));
    let helper = scratch.0.join("reproduce-test.py");
    let staged = Staged {
        env: &env,
        dir: &scratch.0,
        helper: &helper,
        source: b"",
    };
    let start = std::time::Instant::now();
    assert_eq!(
        counts(&staged, 0, &Text::from("line"), &Interrupt::new()),
        Ok(true)
    );
    assert!(
        start.elapsed() < std::time::Duration::from_secs(20),
        "the answer came at the question's exit"
    );
}

/// A logged command with no program creates neither log, so its names stay free for the next.
#[test]
fn an_empty_command_creates_no_log() {
    let scratch = Scratch::new("logged-empty");
    let (log, env) = (scratch.0.join("sweep"), host_env());
    let Err(Stopped::NoVerdict(ending)) =
        logged(&started(&log, &[], &env, &scratch.0), &Interrupt::new())
    else {
        panic!("an empty command leaves no verdict");
    };
    assert_eq!(
        ending.reason().to_string(),
        "`campaign sweep` did not run: the command names no program"
    );
    assert!(!scratch.0.join("sweep.out").exists());
    assert!(!scratch.0.join("sweep.err").exists());
    let argv = sh("exit 0");
    assert!(logged(&started(&log, &argv, &env, &scratch.0), &Interrupt::new()).is_ok());
}

/// A logged child starts with SIGINT, SIGTERM and SIGHUP unblocked even when the thread that starts it
/// holds them blocked.
#[test]
fn a_logged_child_starts_with_the_handled_signals_unblocked() {
    let scratch = Scratch::new("logged-mask");
    let (log, env) = (scratch.0.join("sweep"), host_env());
    let work = scratch.0.clone();
    let blocked = std::thread::spawn(move || {
        let handled = crate::process::handled_set();
        // SAFETY: `handled` is an initialized set and a null old set makes the call write nothing back.
        let status =
            unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &handled, std::ptr::null_mut()) };
        assert_eq!(status, 0, "the thread blocks the three signals");
        let argv = sh("grep '^SigBlk:' /proc/self/status");
        logged(&started(&log, &argv, &env, &work), &Interrupt::new()).expect("the child runs")
    })
    .join()
    .expect("the thread ends");
    let (code, out) = blocked;
    assert_eq!(code, 0);
    let mask = u64::from_str_radix(out.trim().trim_start_matches("SigBlk:").trim(), 16)
        .expect("a hexadecimal mask");
    for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        assert_eq!(
            mask & (1 << (signal - 1)),
            0,
            "signal {signal} is unblocked"
        );
    }
}
