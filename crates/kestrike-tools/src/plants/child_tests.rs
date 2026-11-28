//! A logged child's output, its endings without a verdict, the question to the staged helper, and the
//! exits of a run's halt.

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::{Halt, Logged, Staged, Stopped, counts, logged, verdict_texts};
use crate::paths::tests::Scratch;
use crate::plants::tests::Opens;
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

/// A signal recorded before the start ends the run with no child started: the watch holds no open of
/// the program. The same command with no signal recorded starts the program, which the watch shows
/// first.
#[test]
fn a_recorded_signal_starts_no_child() {
    let scratch = Scratch::new("logged-signal");
    let (first, log, env) = (scratch.0.join("first"), scratch.0.join("sweep"), host_env());
    let program = scratch.0.join("program");
    let opens = Opens::inert(&program);
    let argv = [program.into_os_string()];
    let interrupt = Interrupt::new();
    let ran = logged(&started(&first, &argv, &env, &scratch.0), &interrupt);
    assert_eq!(ran.expect("the child runs"), (0, String::new()));
    assert!(opens.any(), "a child that starts opens its program");
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
    assert!(!opens.any(), "no child started");
}

/// The question reads the answer the `python3` on the given `PATH` prints, and words a missing answer
/// by the last line of that child's error output.
#[test]
fn the_question_reads_the_helper_s_answer_or_its_last_error_line() {
    let scratch = Scratch::new("question");
    let script = r#"#!/bin/sh
case "$#" in
4) echo '["held", "failed"]' ;;
*) read -r size; read -r line; if [ "$line" = yes ]; then echo true; else echo 'Traceback' >&2; echo 'TypeError: no' >&2; exit 1; fi ;;
esac
"#;
    let env = stand_in(&scratch.0, script);
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

/// `stand_in` writes `script` as the `python3` of `dir` and returns an environment whose `PATH` holds
/// `dir` alone, so the question starts that stand-in or no program. A `dir` with a colon is refused,
/// since `PATH` would read it as several directories.
fn stand_in(dir: &Path, script: &str) -> crate::environ::Environ {
    assert!(
        !dir.as_os_str().as_encoded_bytes().contains(&b':'),
        "{} is no single entry of `PATH`",
        dir.display()
    );
    crate::fixtures::tests::script(&dir.join("python3"), script);
    vec![(OsString::from("PATH"), dir.as_os_str().to_os_string())]
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

/// A signal recorded before the question starts no `python3`, and the caller reads the record after:
/// the watch holds no open of the stand-in. The same question with no signal recorded is answered by
/// the stand-in, which the watch shows opened first.
#[test]
fn a_signal_recorded_before_the_question_starts_no_python3() {
    let scratch = Scratch::new("question-signal");
    let env = stand_in(&scratch.0, "#!/bin/sh\necho true\n");
    let opens = Opens::of(&scratch.0.join("python3"));
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
    assert!(opens.any(), "a question that starts opens the stand-in");
    interrupt.record(libc::SIGTERM);
    assert_eq!(
        counts(&staged, 0, &Text::from("line"), &interrupt),
        Err(Text::from("`python3` did not start: a signal was recorded"))
    );
    assert!(!opens.any(), "no question started");
}

/// The longest a test of the descendant waits for a step that a library holding the property takes at
/// once.
const BOUND: Duration = Duration::from_secs(20);

/// The stand-in forks a descendant and answers once that descendant says it is ready. The descendant
/// holds the question's streams, takes its turns through the FIFOs beside the stand-in, and runs shell
/// builtins alone, so it forks no process of its own.
const HELD: &str = r#"#!/bin/sh
at=${0%/*}
(
    exec 4< "$at/release" 3> "$at/done" || exit 1
    echo ready > "$at/ready" || exit 1
    read -r go <&4 || exit 1
    echo late >&2
    echo done >&3
) &
read -r ready < "$at/ready" && [ "$ready" = ready ] || exit 1
echo true
"#;

/// `Turns` holds the three FIFOs through which the descendant of [`HELD`] and its test take turns: the
/// descendant writes a line to `ready`, waits for a line of `release`, and writes a line to `done` as
/// its last act. The test holds both ends of `ready` and `release`, so no open and no write of either
/// side waits for the other. Dropping the value stops both waits and removes the three names before it
/// closes them, so a stand-in at any step ends: a wait that holds its FIFO reads a line, and an open
/// that comes later finds no FIFO to wait on.
struct Turns {
    dir: PathBuf,
    ready: File,
    release: File,
    done: File,
}

impl Turns {
    const NAMES: [&str; 3] = ["ready", "release", "done"];

    fn at(dir: &Path) -> Self {
        for name in Self::NAMES {
            let path = dir.join(name);
            let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).expect("a name");
            // SAFETY: `name` is a NUL-terminated path that outlives the call.
            let made = unsafe { libc::mkfifo(name.as_ptr(), 0o600) };
            assert_eq!(made, 0, "{name:?}: {}", std::io::Error::last_os_error());
        }
        let both = |name| {
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(dir.join(name))
                .expect("a FIFO opens for both ends at once")
        };
        let done = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(dir.join("done"))
            .expect("a FIFO opens for reading without a writer");
        Self {
            dir: dir.to_path_buf(),
            ready: both("ready"),
            release: both("release"),
            done,
        }
    }

    /// `release` lets the descendant go on from its wait.
    fn release(&self) {
        (&self.release)
            .write_all(b"go\n")
            .expect("the release is written");
    }

    /// `stop` ends both waits: the stand-in's for the descendant, without an answer, and the
    /// descendant's for its release.
    fn stop(&self) {
        let _ = (&self.ready).write_all(b"stop\n");
        let _ = (&self.release).write_all(b"go\n");
    }

    /// `ended` returns what the descendant wrote to `done` once its last writer has closed it, which the
    /// descendant does when it exits.
    fn ended(&self) -> Vec<u8> {
        let (mut said, mut part) = (Vec::new(), [0_u8; 64]);
        let end = Instant::now() + BOUND;
        loop {
            match (&self.done).read(&mut part) {
                Ok(0) => return said,
                Ok(count) => said.extend_from_slice(&part[..count]),
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < end =>
                {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("`done` is read to its end: {error}"),
            }
        }
    }
}

impl Drop for Turns {
    fn drop(&mut self) {
        self.stop();
        for name in Self::NAMES {
            let _ = std::fs::remove_file(self.dir.join(name));
        }
    }
}

/// The wait ends when the question exits while a descendant it left holds standard error open; an
/// accepted answer is returned without reading that stream. The answer comes while the descendant
/// waits for its release with the streams open, and the descendant then writes to the stream and ends
/// before the test does.
#[test]
fn a_descendant_holding_the_question_s_streams_does_not_hold_the_answer() {
    let scratch = Scratch::new("question-descendant");
    let turns = Turns::at(&scratch.0);
    let env = stand_in(&scratch.0, HELD);
    let helper = scratch.0.join("reproduce-test.py");
    let staged = Staged {
        env: &env,
        dir: &scratch.0,
        helper: &helper,
        source: b"",
    };
    let (sent, answered) = std::sync::mpsc::channel();
    let answer = std::thread::scope(|scope| {
        scope.spawn(|| {
            let _ = sent.send(counts(&staged, 0, &Text::from("line"), &Interrupt::new()));
        });
        let answer = answered.recv_timeout(BOUND);
        if answer.is_err() {
            turns.stop();
        }
        answer
    });
    assert_eq!(
        answer,
        Ok(Ok(true)),
        "the answer came before the descendant's release"
    );
    turns.release();
    assert_eq!(
        turns.ended(),
        b"done\n",
        "the descendant waited for its release and then ended"
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
