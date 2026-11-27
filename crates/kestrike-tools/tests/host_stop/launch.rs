//! The launch of the `aws` child: its arguments and environment, the output text, a failed call's
//! sentence, the cut, a signal that ends the wait, and the search of the given `PATH`.

use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use kestrike_tools::host_stop::{
    AWS, Call, Delivered, Ended, Interrupted, Record, SLICE, Signal, launch,
};

use super::{MARKER_LIMIT, Scratch, gone, wait_for};

/// The stand-in `aws`: it writes its process id to `$HOST_STOP_PID`, then acts as `$HOST_STOP_MODE`
/// names. It uses shell builtins and programs named by their absolute paths alone, since its `PATH`
/// holds its own directory alone.
pub(super) const STANDIN: &str = r#"#!/bin/sh
echo $$ > "$HOST_STOP_PID"
case "$HOST_STOP_MODE" in
  echo)
    printf '%s|' "$*" "${AWS_MAX_ATTEMPTS-unset}" "${AWS_RETRY_MODE-unset}" "${AWS_PAGER-unset}" \
      "$AWS_CLI_AUTO_PROMPT" "$AWS_IGNORE_CONFIGURED_ENDPOINT_URLS" "${HOME-unset}" "$PATH" \
      "$(/usr/bin/readlink /proc/self/fd/0)"
    printf 'a\r\nb\rc\n' ;;
  fail)
    printf ' \n' >&2
    i=0
    while [ $i -lt 500 ]; do printf x >&2; i=$((i + 1)); done
    printf 'END\n\034 \n' >&2
    echo '{}'
    exit 254 ;;
  killed) printf 'dying\n' >&2; kill -KILL $$ ;;
  hang) exec /bin/sleep 600 ;;
  invalid) printf '\377' ;;
  orphan) /bin/sleep 3 & echo '{}' ;;
  status) exec /bin/cat /proc/self/status ;;
esac
"#;

/// A directory that holds the stand-in as `aws`, and the file it writes its process id to.
pub(super) struct Standin {
    pub(super) scratch: Scratch,
    pub(super) bin: PathBuf,
    pub(super) pid: PathBuf,
}

impl Standin {
    pub(super) fn new(label: &str) -> Self {
        let scratch = Scratch::new(label);
        let bin = scratch.dir("bin");
        let program = bin.join(AWS);
        fs::write(&program, STANDIN).expect("the stand-in is written");
        fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).expect("the mode is set");
        ready(&program);
        let pid = scratch.0.join("pid");
        Self { scratch, bin, pid }
    }

    /// The environment of a call in `mode`: the stand-in's directory as `PATH`, and the caller's own
    /// settings of the four variables the launch sets.
    pub(super) fn env(&self, mode: &str) -> Vec<(OsString, OsString)> {
        [
            ("PATH", self.bin.as_os_str()),
            ("HOST_STOP_MODE", mode.as_ref()),
            ("HOST_STOP_PID", self.pid.as_os_str()),
            ("AWS_PAGER", "less".as_ref()),
            ("AWS_CLI_AUTO_PROMPT", "on".as_ref()),
            ("AWS_RETRY_MODE", "legacy".as_ref()),
            ("AWS_IGNORE_CONFIGURED_ENDPOINT_URLS", "false".as_ref()),
        ]
        .into_iter()
        .map(|(name, value)| (OsString::from(name), value.to_owned()))
        .collect()
    }

    fn started(&self) -> Option<String> {
        fs::read_to_string(&self.pid)
            .ok()
            .map(|pid| pid.trim().to_owned())
    }
}

/// `ready` runs the new stand-in until its start no longer fails with `ETXTBSY`: a process another test
/// thread forks while the stand-in's file is open for writing holds that descriptor until its own
/// `exec`, and the kernel refuses to run a file open for writing.
fn ready(program: &Path) {
    let start = Instant::now();
    loop {
        let started = Command::new(program)
            .env_clear()
            .env("HOST_STOP_MODE", "none")
            .env("HOST_STOP_PID", "/dev/null")
            .status();
        match started {
            Ok(status) => {
                assert!(status.success(), "{status}");
                return;
            }
            Err(error)
                if error.raw_os_error() == Some(libc::ETXTBSY)
                    && start.elapsed() < MARKER_LIMIT =>
            {
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("{}: {error}", program.display()),
        }
    }
}

const IDENTITY: [&str; 2] = ["sts", "get-caller-identity"];

fn call<'a>(
    argv: &'a [&'a str],
    retry: bool,
    cut: Duration,
    env: &'a [(OsString, OsString)],
) -> Call<'a> {
    Call {
        argv,
        retry,
        cut,
        env,
    }
}

fn failed(ended: Result<String, Ended>) -> String {
    match ended {
        Err(Ended::Failed(failed)) => failed.message().to_owned(),
        other => panic!("a failed call: {other:?}"),
    }
}

/// The child gets the given arguments, then `--no-paginate --output json` and both CLI timeouts at the
/// cut in whole seconds rounded up and at least 1. It runs under the given environment and no other,
/// with the pager empty, the prompt off and the configured endpoints ignored; a call without retries
/// also sets one attempt in standard mode. Its standard input is `/dev/null`, and its output reads with
/// `\r\n` and `\r` as `\n`.
#[test]
fn the_child_runs_with_the_arguments_and_the_environment_given() {
    let standin = Standin::new("launch-echo");
    assert!(
        std::env::var_os("HOME").is_some(),
        "the test process has a HOME the child lacks"
    );
    let env = standin.env("echo");
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    let argv = ["ec2", "stop-instances", "--instance-ids", "i-h1"];
    let reply = launch(
        &mut record,
        &call(&argv, false, Duration::from_millis(7500), &env),
    )
    .expect("the stand-in answers");
    let bin = standin.bin.display();
    assert_eq!(
        reply,
        format!(
            "ec2 stop-instances --instance-ids i-h1 --no-paginate --output json --cli-read-timeout 8 \
             --cli-connect-timeout 8|1|standard||off|true|unset|{bin}|/dev/null|a\nb\nc\n"
        )
    );
    let read = launch(
        &mut record,
        &call(&IDENTITY, true, Duration::from_secs(5), &env),
    )
    .expect("the stand-in answers");
    assert_eq!(
        read,
        format!(
            "sts get-caller-identity --no-paginate --output json --cli-read-timeout 5 \
             --cli-connect-timeout 5|unset|legacy||off|true|unset|{bin}|/dev/null|a\nb\nc\n"
        ),
        "a call with retries keeps the caller's retry mode"
    );
    for (cut, seconds) in [
        (Duration::from_millis(999), 1),
        (Duration::from_millis(1001), 2),
        (Duration::from_secs(2), 2),
        (Duration::new(2, 1), 3),
    ] {
        let shown =
            launch(&mut record, &call(&IDENTITY, true, cut, &env)).expect("the stand-in answers");
        assert!(
            shown.contains(&format!(
                "--cli-read-timeout {seconds} --cli-connect-timeout {seconds}|"
            )),
            "{shown}"
        );
    }
}

/// A child that exits other than 0 is a failed call that names the first two arguments, the exit code
/// and the last 400 characters of its standard error with Python's whitespace stripped; a child a
/// signal ended has the signal's number negated as its code.
#[test]
fn a_child_that_exits_other_than_0_is_a_failed_call_with_its_code() {
    let standin = Standin::new("launch-fail");
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    let env = standin.env("fail");
    let message = failed(launch(
        &mut record,
        &call(&IDENTITY, true, Duration::from_secs(5), &env),
    ));
    assert_eq!(
        message,
        format!("sts get-caller-identity exited 254: {}END", "x".repeat(397))
    );
    let env = standin.env("killed");
    let argv = ["ec2", "describe-instances", "--instance-ids", "i-h1"];
    let message = failed(launch(
        &mut record,
        &call(&argv, true, Duration::from_secs(5), &env),
    ));
    assert_eq!(message, "ec2 describe-instances exited -9: dying");
    let env = standin.env("invalid");
    let message = failed(launch(
        &mut record,
        &call(&IDENTITY, true, Duration::from_secs(5), &env),
    ));
    assert!(
        message.starts_with("sts get-caller-identity gave no answer: "),
        "{message}"
    );
}

/// A child past its cut gets SIGKILL and is reaped before the call returns a failed call, within a
/// slice of the cut. The stand-in replaces itself with the sleeper, so the process killed is the one
/// that holds both output pipes.
#[test]
fn a_child_past_its_cut_is_killed_and_reaped() {
    let standin = Standin::new("launch-cut");
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    let env = standin.env("hang");
    let cut = Duration::from_millis(700);
    let start = Instant::now();
    let message = failed(launch(&mut record, &call(&IDENTITY, true, cut, &env)));
    let elapsed = start.elapsed();
    assert!(
        message.starts_with("sts get-caller-identity gave no answer: "),
        "{message}"
    );
    assert!(
        elapsed >= cut && elapsed < cut + SLICE + Duration::from_secs(1),
        "{elapsed:?}"
    );
    let pid = standin
        .started()
        .expect("the stand-in started within its cut");
    assert!(gone(&pid), "the child {pid} is killed and reaped");
}

/// The cut counts until both output pipes close: a child that exits while a process it started holds
/// its standard output is cut there, and the call returns a failed call.
#[test]
fn a_child_whose_output_stays_open_is_cut() {
    let standin = Standin::new("launch-orphan");
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    let env = standin.env("orphan");
    let cut = Duration::from_millis(600);
    let start = Instant::now();
    let message = failed(launch(&mut record, &call(&IDENTITY, true, cut, &env)));
    assert!(
        message.starts_with("sts get-caller-identity gave no answer: "),
        "{message}"
    );
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "the call ends at its cut, not at the output's close"
    );
}

/// A signal delivered to an armed record ends the wait at the next slice: the child gets SIGKILL and is
/// reaped, the call returns the signal, and the record is disarmed.
#[test]
fn a_signal_that_may_raise_ends_the_wait() {
    let standin = Standin::new("launch-signal");
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    record.arm();
    let env = standin.env("hang");
    let (ended, after) = thread::scope(|scope| {
        let signaled = scope.spawn(|| {
            wait_for(&standin.pid);
            delivered.deliver(Signal::Terminate);
            Instant::now()
        });
        let ended = launch(
            &mut record,
            &call(&IDENTITY, true, Duration::from_secs(60), &env),
        );
        let returned = Instant::now();
        (
            ended,
            returned.saturating_duration_since(signaled.join().expect("the thread ends")),
        )
    });
    assert_eq!(
        ended,
        Err(Ended::Interrupted(Interrupted(Signal::Terminate)))
    );
    assert!(after < SLICE + Duration::from_secs(1), "{after:?}");
    let pid = standin.started().expect("the stand-in started");
    assert!(gone(&pid), "the child {pid} is killed and reaped");
    assert!(!record.is_armed());
    assert_eq!(record.pending(), None);
}

/// A signal that may raise before the call raises at once and starts no process; a signal the record
/// keeps waiting, unarmed, leaves the call to its answer.
#[test]
fn a_signal_before_the_call_starts_no_process_and_an_unarmed_one_waits() {
    let standin = Standin::new("launch-before");
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    delivered.deliver(Signal::Hangup);
    let env = standin.env("echo");
    let reply = launch(
        &mut record,
        &call(&IDENTITY, true, Duration::from_secs(5), &env),
    );
    assert!(reply.is_ok(), "{reply:?}");
    assert_eq!(record.pending(), Some(Signal::Hangup));
    fs::remove_file(&standin.pid).expect("the stand-in ran");
    record.arm();
    let ended = launch(
        &mut record,
        &call(&IDENTITY, true, Duration::from_secs(5), &env),
    );
    assert_eq!(ended, Err(Ended::Interrupted(Interrupted(Signal::Hangup))));
    assert!(!standin.pid.exists(), "no process started");
}

/// `aws` is found on the given `PATH` alone, in order, as an executable regular file. With none there,
/// or with no `PATH`, the call fails and starts no process, though another `aws` stands elsewhere.
#[test]
fn no_aws_on_the_path_starts_no_process() {
    let standin = Standin::new("launch-path");
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    let empty = standin.scratch.dir("empty");
    let plain = standin.scratch.dir("plain");
    fs::write(plain.join(AWS), STANDIN).expect("written");
    fs::set_permissions(plain.join(AWS), fs::Permissions::from_mode(0o600))
        .expect("the mode is set");
    let named = standin.scratch.dir("named");
    fs::create_dir(named.join(AWS)).expect("a directory named aws");
    let joined = |dirs: &[&Path]| {
        OsString::from(
            dirs.iter()
                .map(|dir| dir.display().to_string())
                .collect::<Vec<_>>()
                .join(":"),
        )
    };
    for path in [
        Some(joined(&[&empty])),
        Some(joined(&[&plain, &named])),
        None,
    ] {
        let mut env = standin.env("echo");
        env.retain(|(name, _)| name != "PATH");
        env.extend(path.clone().map(|path| (OsString::from("PATH"), path)));
        let message = failed(launch(
            &mut record,
            &call(&IDENTITY, true, Duration::from_secs(5), &env),
        ));
        assert!(
            message.starts_with("sts get-caller-identity gave no answer: "),
            "{path:?}: {message}"
        );
        assert!(standin.started().is_none(), "{path:?}: no process started");
    }
    let mut env = standin.env("echo");
    env.retain(|(name, _)| name != "PATH");
    env.push((
        OsString::from("PATH"),
        joined(&[&empty, &plain, &named, &standin.bin]),
    ));
    let reply = launch(
        &mut record,
        &call(&IDENTITY, true, Duration::from_secs(5), &env),
    );
    assert!(
        reply.is_ok(),
        "the first executable aws on the PATH runs: {reply:?}"
    );
}
