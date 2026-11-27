//! The call through a stand-in `aws`, a fixed `sh` text found on a `PATH` that holds its directory
//! alone, whose mode a variable of the call's environment picks.

use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use kestrike_tools::host_stop::{
    AWS, Call, CallError, Delivered, FailedCall, Failure, Record, System, reply,
};
use kestrike_tools::json::{Object, Value};

use crate::host_stop_support::Scratch;

/// The stand-in: it touches `$FAKE_AWS_STARTED`, then acts as `$FAKE_AWS_MODE` names. It names each
/// program beyond the shell's builtins by its absolute path, since its `PATH` holds its own directory
/// alone.
const PROGRAM: &str = r#"#!/bin/sh
: > "$FAKE_AWS_STARTED"
case "$FAKE_AWS_MODE" in
  echo) format='{"argv": "%s", "attempts": "%s", "mode": "%s", "pager": "%s", "prompt": "%s", "endpoints": "%s"'
        printf "$format"', "home": "%s", "stdin": "%s"}' "$*" "$AWS_MAX_ATTEMPTS" "$AWS_RETRY_MODE" \
          "${AWS_PAGER-unset}" "$AWS_CLI_AUTO_PROMPT" "$AWS_IGNORE_CONFIGURED_ENDPOINT_URLS" "${HOME-unset}" \
          "$(/usr/bin/readlink /proc/self/fd/0)" ;;
  fail) echo "An error occurred (UnauthorizedOperation)" >&2; echo '{"Arn": "a"}'; exit 254 ;;
  list) echo '[]' ;;
  twice) echo '{"Arn": "a", "Arn": "b"}' ;;
  sleep) /usr/bin/sleep 5; echo '{"Arn": "a"}' ;;
esac
"#;

/// A scratch directory whose `bin` holds the stand-in as `aws`, and whose `empty` holds nothing.
struct Standin {
    scratch: Scratch,
    bin: PathBuf,
}

impl Standin {
    fn new(label: &str) -> Self {
        let scratch = Scratch::new(label);
        let bin = scratch.0.join("bin");
        fs::create_dir(&bin).expect("bin is made");
        fs::create_dir(scratch.0.join("empty")).expect("empty is made");
        let program = bin.join(AWS);
        fs::write(&program, PROGRAM).expect("the stand-in is written");
        fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).expect("the mode is set");
        ready(&program);
        Self { scratch, bin }
    }

    fn started(&self) -> PathBuf {
        self.scratch.0.join("started")
    }

    /// The environment of a call in `mode` with `path` as `PATH`, and the caller's own settings of
    /// the variables the call sets.
    fn env(&self, mode: &str, path: &Path) -> Vec<(OsString, OsString)> {
        [
            ("PATH", path.as_os_str()),
            ("FAKE_AWS_MODE", mode.as_ref()),
            ("FAKE_AWS_STARTED", self.started().as_os_str()),
            ("AWS_PAGER", "less".as_ref()),
            ("AWS_CLI_AUTO_PROMPT", "on".as_ref()),
            ("AWS_RETRY_MODE", "legacy".as_ref()),
            ("AWS_IGNORE_CONFIGURED_ENDPOINT_URLS", "false".as_ref()),
            (
                "AWS_ENDPOINT_URL_CLOUDWATCH",
                "https://cloudwatch.example.invalid".as_ref(),
            ),
        ]
        .into_iter()
        .map(|(name, value)| (OsString::from(name), value.to_owned()))
        .collect()
    }

    fn call(
        &self,
        mode: &str,
        argv: &[&str],
        retry: bool,
        cut: Duration,
    ) -> Result<Object, CallError> {
        let env = self.env(mode, &self.bin);
        called(argv, retry, cut, &env)
    }
}

fn called(
    argv: &[&str],
    retry: bool,
    cut: Duration,
    env: &[(OsString, OsString)],
) -> Result<Object, CallError> {
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    let call = Call {
        argv,
        retry,
        cut,
        env,
    };
    reply(&mut System::new(), &mut record, &call)
}

/// `ready` starts the new stand-in until its start no longer fails with `ETXTBSY`, which a fork of
/// another test thread gives while it holds the file's descriptor open for writing until its `exec`.
fn ready(program: &Path) {
    let start = Instant::now();
    loop {
        let started = Command::new(program)
            .env_clear()
            .env("FAKE_AWS_MODE", "none")
            .env("FAKE_AWS_STARTED", "/dev/null")
            .status();
        match started {
            Ok(status) => return assert!(status.success(), "{status}"),
            Err(error) if error.raw_os_error() == Some(libc::ETXTBSY) => {
                assert!(start.elapsed() < Duration::from_secs(30), "{error}");
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("{}: {error}", program.display()),
        }
    }
}

fn text(reply: &Object, key: &str) -> String {
    match reply.get(key) {
        Some(Value::String(text)) => text.to_string(),
        other => panic!("{key} is a text: {other:?}"),
    }
}

const IDENTITY: [&str; 2] = ["sts", "get-caller-identity"];

/// The child runs under the environment the call gives it and no other: the given mode reaches it,
/// and a variable the test process holds and the call does not give is unset there.
#[test]
fn the_cli_runs_under_the_environment_it_is_given() {
    let standin = Standin::new("environment");
    let reply = standin
        .call("echo", &IDENTITY, true, Duration::from_secs(5))
        .expect("the stand-in echoes its call");
    let argv = text(&reply, "argv");
    assert_eq!(
        argv.split_whitespace().take(2).collect::<Vec<_>>(),
        IDENTITY
    );
    assert!(
        std::env::var_os("HOME").is_some(),
        "the test process holds HOME"
    );
    assert_eq!(text(&reply, "home"), "unset");
}

/// A reply is the object the CLI prints: a call without retries carries one attempt in standard
/// mode, a cut of 7.5 s reads as 8 whole seconds, the pager is empty, the prompt off, the configured
/// endpoints ignored and standard input `/dev/null`; a read call keeps the CLI's own retries.
#[test]
fn a_reply_is_the_json_object_the_cli_prints() {
    let standin = Standin::new("reply");
    let argv = ["ec2", "stop-instances", "--instance-ids", "i-h1"];
    let reply = standin
        .call("echo", &argv, false, Duration::from_secs_f64(7.5))
        .expect("the stand-in echoes its call");
    assert_eq!(
        text(&reply, "argv"),
        "ec2 stop-instances --instance-ids i-h1 --no-paginate --output json --cli-read-timeout 8 \
         --cli-connect-timeout 8"
    );
    let fields =
        ["attempts", "mode", "pager", "prompt", "endpoints", "stdin"].map(|key| text(&reply, key));
    assert_eq!(fields, ["1", "standard", "", "off", "true", "/dev/null"]);
    let read = standin
        .call(
            "echo",
            &["cloudwatch", "describe-alarms"],
            true,
            Duration::from_secs(5),
        )
        .expect("the stand-in echoes its call");
    let fields = ["attempts", "mode", "endpoints"].map(|key| text(&read, key));
    assert_eq!(
        fields,
        ["", "legacy", "true"],
        "a read keeps the CLI's own retries"
    );
    assert!(text(&read, "argv").contains("--no-paginate"));
}

/// A failed child, a reply that is no object or no strict JSON, a child cut at its deadline and a
/// `PATH` with no `aws` are each a failed call with its sentence; with no `aws` on the `PATH` no
/// process starts.
#[test]
fn every_other_outcome_is_a_failed_call() {
    let standin = Standin::new("failed");
    let cut = Duration::from_secs(5);
    let sentences = [
        (
            "fail",
            "sts get-caller-identity exited 254: An error occurred (UnauthorizedOperation)",
        ),
        (
            "list",
            "the reply of sts get-caller-identity is no JSON object",
        ),
        (
            "twice",
            "the reply of sts get-caller-identity is not strict JSON: an object repeats a key",
        ),
    ];
    for (mode, sentence) in sentences {
        match standin.call(mode, &IDENTITY, true, cut) {
            Err(CallError::Failed(failed)) => assert_eq!(failed.sentence(), sentence, "{mode}"),
            other => panic!("{mode}: {other:?}"),
        }
    }
    let begun = Instant::now();
    match standin.call("sleep", &IDENTITY, true, Duration::from_millis(20)) {
        Err(CallError::Failed(FailedCall::Launch(failed))) => {
            assert!(
                matches!(failed.failure(), Failure::NoAnswer(reason) if reason.starts_with("timed out"))
            );
        }
        other => panic!("sleep: {other:?}"),
    }
    assert!(
        begun.elapsed() < Duration::from_secs(4),
        "the cut ends the call before the child's sleep"
    );
    fs::remove_file(standin.started()).expect("the stand-in started for each call above");
    let empty = standin.scratch.0.join("empty");
    match called(&IDENTITY, true, cut, &standin.env("echo", &empty)) {
        Err(CallError::Failed(failed)) => assert_eq!(
            failed.sentence(),
            "sts get-caller-identity gave no answer: no directory of PATH holds an executable aws"
        ),
        other => panic!("no aws: {other:?}"),
    }
    assert!(!standin.started().exists(), "no process starts");
}
