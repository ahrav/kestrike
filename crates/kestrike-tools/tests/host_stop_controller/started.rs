//! The built binary started as the tool, under a scratch top with the two files that declare the
//! package's list bounds and a catalog whose GD-2 prerequisites are met, against a stand-in `aws` on
//! a `PATH` that holds its directory alone. Only these cases run the real root, the real clocks and
//! a control plane of processes.
//!
//! The stand-in is a `sh` file named `aws` that starts this test executable for the one test
//! [`stand_in_aws`] by its absolute path, with the call's words in the environment and the reply on
//! descriptor 3, apart from libtest's own output, which goes to `/dev/null`. The test executable
//! cannot stand in under the name `aws` itself: libtest refuses the call's options. In that role the
//! test holds the plane's state in its state directory: the call log, the alarm a case plants in
//! state `ALARM` and the second of the stop. It answers the five calls, stamps the stop's
//! transition second from its own clock, and refuses and logs a call it has no reply for.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use kestrike_tools::json::{Text, Value};
use kestrike_tools::python::hexdigest;

use super::listing;
use super::plane::calendar;
use crate::host_stop_support::{
    Scratch, TARGET, json, met, object, operator, package, rewrite, set, tree, value,
};

const BINARY: &str = env!("CARGO_BIN_EXE_kestrike-tools");
/// The variable that names the stand-in's state directory and puts this test in its role.
const ROLE: &str = "HOST_STOP_AWS_ROLE";
const STAND_IN: &str = "host_stop_controller::started::stand_in_aws";
/// The longest run of the binary in a case.
const LIMIT: Duration = Duration::from_secs(120);
/// The two files that declare the package's list bounds, which the scratch top holds.
const BOUNDS: [&str; 2] = [
    "crates/kestrike/src/failover/zone_loop/directory.rs",
    "crates/kestrike/src/failover/standbys.rs",
];

/// The wall clock's whole second.
fn now() -> i64 {
    let since = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the wall clock reads after the epoch");
    i64::try_from(since.as_secs()).expect("the second fits")
}

fn number(n: i64) -> Value {
    value(&n.to_string())
}

/// A scratch top, the stand-in's directory and state, and the run's files written at its time.
struct Started {
    scratch: Scratch,
    top: PathBuf,
    bin: PathBuf,
    state: PathBuf,
    operator: PathBuf,
    package: PathBuf,
    evidence: PathBuf,
}

impl Started {
    /// The run's files for a start at the wall clock's present: the held package with a baseline
    /// window of 600 s that ends 30 s ago and a run window of 600 s from there, the fixture snapshot
    /// cut and reported 2 s ago, and the fixture operator file approving the package's bytes until
    /// an hour from now, with an observation of 1 s, an effect timeout of 20 s and a deadline of
    /// 60 s.
    fn new(label: &str) -> Self {
        let scratch = Scratch::new(label);
        let top = scratch.0.join("top");
        let catalog = top.join("verification/readiness/gamedays.json");
        fs::create_dir_all(catalog.parent().expect("the catalog has a parent"))
            .expect("the catalog's directory is made");
        fs::write(&catalog, json(&met())).expect("the catalog is written");
        for bound in BOUNDS {
            let path = top.join(bound);
            fs::create_dir_all(path.parent().expect("a bound file has a parent"))
                .expect("the bound file's directory is made");
            fs::copy(tree().join(bound), &path).expect("the bound file is copied");
        }
        let (bin, state) = (scratch.0.join("bin"), scratch.0.join("state"));
        for dir in [&bin, &state] {
            fs::create_dir(dir).expect("the directory is made");
        }
        let start = now();
        let mut held = value(&String::from_utf8(package()).expect("the package is UTF-8"));
        let opens = start - 30;
        set(&mut held, &["baseline", "start"], number(opens - 600));
        set(&mut held, &["baseline", "end"], number(opens));
        set(&mut held, &["run", "start"], number(opens));
        set(&mut held, &["run", "end"], number(opens + 600));
        let bytes = json(&held).into_bytes();
        let package = scratch.write("package.json", &bytes);
        let evidence = scratch.0.join("evidence");
        fs::create_dir(&evidence).expect("the evidence directory is made");
        fs::write(evidence.join("package.json"), &bytes).expect("the copy is written");
        let snapshot = scratch.snapshot();
        let cut = start - 2;
        rewrite(&snapshot.join("shards.jsonl"), |rows| {
            for row in rows {
                set(row, &["time"], number(cut));
            }
        });
        rewrite(&snapshot.join("hosts.jsonl"), |rows| {
            for row in rows {
                set(row, &["report", "time"], number(cut));
            }
        });
        let mut o = operator();
        set(
            &mut o,
            &["approval", "package_sha256"],
            Value::String(Text::from(hexdigest(&bytes))),
        );
        let lapse = format!("{}Z", calendar(start + 3600, 'T'));
        set(
            &mut o,
            &["approval", "not_after"],
            Value::String(Text::from(lapse)),
        );
        for (key, seconds) in [
            ("observe_seconds", 1),
            ("effect_timeout_seconds", 20),
            ("deadline_seconds", 60),
        ] {
            set(&mut o, &[key], number(seconds));
        }
        let operator = scratch.write("operator.json", json(&o).as_bytes());
        let started = Self {
            scratch,
            top,
            bin,
            state,
            operator,
            package,
            evidence,
        };
        started.stand_in();
        started
    }

    /// Writes the stand-in `aws`: a `sh` file that exports the call's words and starts this test
    /// executable for [`stand_in_aws`] alone.
    fn stand_in(&self) {
        let executable = std::env::current_exe().expect("the test executable is named");
        let shown = executable
            .to_str()
            .expect("the test executable's path is UTF-8");
        assert!(!shown.contains('\''), "{shown}");
        let text = format!(
            "#!/bin/sh\ni=0\nfor arg; do\n  i=$((i + 1))\n  export \"HOST_STOP_AWS_ARG_$i=$arg\"\ndone\n\
             export HOST_STOP_AWS_ARGC=$i\nexec '{shown}' --exact {STAND_IN} --nocapture --quiet \
             --test-threads=1 3>&1 4>&2 >/dev/null 2>/dev/null\n"
        );
        let path = self.bin.join("aws");
        fs::write(&path, text).expect("the stand-in is written");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("the stand-in is made executable");
    }

    /// Plants the alarm `name` in state `ALARM`.
    fn alarm(&self, name: &str) {
        fs::write(self.state.join("alarm"), name).expect("the planted alarm is written");
    }

    /// The calls the stand-in answered or refused, each as its first two words.
    fn calls(&self) -> Vec<String> {
        fs::read_to_string(self.state.join("calls"))
            .unwrap_or_default()
            .lines()
            .map(|line| line.split(' ').take(2).collect::<Vec<_>>().join(" "))
            .collect()
    }

    /// Runs the binary as the tool `host-stop-controller` with `args` under `top`, with `PATH`
    /// holding `path` alone and the stand-in's state named.
    fn run(&self, top: &Path, path: &Path, args: &[&Path]) -> Output {
        let mut command = Command::new(BINARY);
        command
            .arg(top)
            .arg("host-stop-controller")
            .args(args)
            .env_clear()
            .env("PATH", path)
            .env(ROLE, &self.state);
        bounded(command)
    }

    fn command(&self, name: &'static str) -> Vec<&Path> {
        let mut args = vec![Path::new(name), Path::new("--operator"), &self.operator];
        if name == "run" {
            args.extend([Path::new("--package"), &self.package]);
        }
        args.extend([Path::new("--evidence"), &self.evidence]);
        args
    }

    fn marks(&self) -> Vec<String> {
        listing(&self.evidence.join("injection"))
    }
}

/// The output of `command`, which must end within [`LIMIT`]; a child past it is killed while the
/// thread that reads its output holds it unreaped.
fn bounded(mut command: Command) -> Output {
    let child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the binary starts");
    let pid = libc::pid_t::try_from(child.id()).expect("a process id fits");
    let (send, receive) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = send.send(child.wait_with_output());
    });
    match receive.recv_timeout(LIMIT) {
        Ok(output) => output.expect("the binary's output reads"),
        Err(_) => {
            // SAFETY: `kill` takes a process id and a signal number and touches no memory of this
            // process.
            unsafe { libc::kill(pid, libc::SIGKILL) };
            panic!("the binary ran past {LIMIT:?}");
        }
    }
}

/// The variable that puts a case in its child process, where its body runs.
const APART: &str = "HOST_STOP_STARTED_APART";

/// Runs `body` in a child process of the test executable that runs the case `name` of this module
/// alone, and passes where the child passes. The cases that start processes start them from that
/// child, so no child of theirs takes a copy of a descriptor another case of this process holds,
/// such as the lock of an evidence directory, in the window between its fork and its exec.
pub(crate) fn apart(module: &str, name: &str, body: impl FnOnce()) {
    if std::env::var_os(APART).is_some() {
        body();
        return;
    }
    let (_, path) = module
        .split_once("::")
        .expect("a case module lies under the test executable");
    let id = format!("{path}::{name}");
    let mut command = Command::new(std::env::current_exe().expect("the test executable is named"));
    command
        .args(["--exact", &id, "--nocapture", "--test-threads", "1"])
        .env(APART, "1");
    let ran = bounded(command);
    assert!(
        ran.status.success() && text(&ran.stdout).contains("1 passed"),
        "{id}: {}\n{}{}",
        ran.status,
        text(&ran.stdout),
        text(&ran.stderr)
    );
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).expect("the output is UTF-8")
}

/// One call's words as the stand-in received them.
fn words() -> Vec<String> {
    let count: usize = std::env::var("HOST_STOP_AWS_ARGC")
        .expect("the stand-in counts the words")
        .parse()
        .expect("the count is a number");
    (1..=count)
        .map(|at| std::env::var(format!("HOST_STOP_AWS_ARG_{at}")).expect("each word is UTF-8"))
        .collect()
}

/// The words after `option` up to the next word that starts with `--`.
fn after<'a>(words: &'a [String], option: &str) -> Vec<&'a str> {
    let at = words
        .iter()
        .position(|word| word == option)
        .map_or(words.len(), |at| at + 1);
    words[at..]
        .iter()
        .take_while(|word| !word.starts_with("--"))
        .map(String::as_str)
        .collect()
}

/// The reply of the call `words` on the plane in `state`, or `None` for a call the stand-in has no
/// reply for.
fn reply(state: &Path, words: &[String]) -> Option<String> {
    let stopped = fs::read_to_string(state.join("stopped")).ok();
    let op = words.iter().take(2).cloned().collect::<Vec<_>>().join(" ");
    let identity = |o: &Value| {
        let Some(Value::String(identity)) = object(o.clone()).get("identity").cloned() else {
            panic!("the operator file names an identity")
        };
        identity.to_string()
    };
    Some(match op.as_str() {
        "sts get-caller-identity" => {
            format!(
                r#"{{"Arn": {}}}"#,
                json(&Value::String(Text::from(identity(&operator()))))
            )
        }
        "ec2 describe-instance-status" => {
            let rows: Vec<String> = after(words, "--instance-ids")
                .iter()
                .map(|id| {
                    let (name, check) = if *id == TARGET && stopped.is_some() {
                        ("stopped", "not-applicable")
                    } else {
                        ("running", "ok")
                    };
                    format!(
                        r#"{{"InstanceId": "{id}", "InstanceState": {{"Code": 16, "Name": "{name}"}}, "InstanceStatus": {{"Status": "{check}"}}, "SystemStatus": {{"Status": "{check}"}}}}"#
                    )
                })
                .collect();
            format!(r#"{{"InstanceStatuses": [{}]}}"#, rows.join(", "))
        }
        "ec2 describe-instances" => {
            let second: i64 = stopped?
                .trim()
                .parse()
                .expect("the stop's second is a number");
            format!(
                r#"{{"Reservations": [{{"Instances": [{{"InstanceId": "{TARGET}", "State": {{"Code": 80, "Name": "stopped"}}, "StateReason": {{"Code": "Client.UserInitiatedShutdown"}}, "StateTransitionReason": "User initiated ({} GMT)", "LaunchTime": "2026-11-24T00:00:00+00:00"}}]}}]}}"#,
                calendar(second, ' ')
            )
        }
        "ec2 stop-instances" => {
            fs::write(state.join("stopped"), now().to_string()).expect("the stop is recorded");
            format!(
                r#"{{"StoppingInstances": [{{"InstanceId": "{TARGET}", "CurrentState": {{"Code": 64, "Name": "stopping"}}}}]}}"#
            )
        }
        "cloudwatch describe-alarms" => {
            let planted = fs::read_to_string(state.join("alarm")).ok();
            let rows: Vec<String> = after(words, "--alarm-names")
                .iter()
                .map(|name| {
                    let value = if planted.as_deref() == Some(*name) { "ALARM" } else { "OK" };
                    format!(
                        r#"{{"AlarmName": "{name}", "StateValue": "{value}", "TreatMissingData": "missing", "StateTransitionedTimestamp": "2026-11-24T00:00:00.000Z"}}"#
                    )
                })
                .collect();
            format!(r#"{{"MetricAlarms": [{}]}}"#, rows.join(", "))
        }
        _ => return None,
    })
}

/// The stand-in `aws` in its role, which the variable [`ROLE`] gives it; with the variable unset
/// the test does nothing. It logs the call, writes its reply to descriptor 3, or refuses a call it
/// has no reply for on descriptor 4 with exit 254, and exits.
#[test]
fn stand_in_aws() {
    let Some(state) = std::env::var_os(ROLE).map(PathBuf::from) else {
        return;
    };
    let words = words();
    let mut log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(state.join("calls"))
        .expect("the call log opens");
    writeln!(log, "{}", words.join(" ")).expect("the call is logged");
    let (code, stream, line) = match reply(&state, &words) {
        Some(reply) => (0, "/dev/fd/3", reply),
        None => (
            254,
            "/dev/fd/4",
            format!("no reply for {}", words.join(" ")),
        ),
    };
    let mut out = OpenOptions::new()
        .write(true)
        .open(stream)
        .expect("the stream opens");
    writeln!(out, "{line}").expect("the reply is written");
    std::process::exit(code);
}

/// A run started at the wall clock's present goes through its seven steps against the stand-in and
/// exits 0 with the restoration pending: the caller's read comes first, the stop request leaves
/// once, after the second alarm read, and the run writes `roles.json`, `stop.json` and
/// `stopped.json`, whose request is `stop.json`'s value.
#[test]
fn a_started_run_goes_clean_through_step_seven_with_exit_0() {
    apart(
        module_path!(),
        "a_started_run_goes_clean_through_step_seven_with_exit_0",
        || {
            let started = Started::new("started-clean");
            let ran = started.run(&started.top, &started.bin, &started.command("run"));
            let (stdout, stderr) = (text(&ran.stdout), text(&ran.stderr));
            assert_eq!(ran.status.code(), Some(0), "{stdout}{stderr}");
            assert_eq!(stderr, "");
            assert_eq!(started.marks(), ["roles.json", "stop.json", "stopped.json"]);
            let calls = started.calls();
            assert_eq!(
                calls.first().map(String::as_str),
                Some("sts get-caller-identity")
            );
            let stop = calls
                .iter()
                .position(|call| call == "ec2 stop-instances")
                .expect("the stop request left");
            assert_eq!(
                calls
                    .iter()
                    .filter(|call| *call == "ec2 stop-instances")
                    .count(),
                1
            );
            let alarms_before = calls[..stop]
                .iter()
                .filter(|call| *call == "cloudwatch describe-alarms")
                .count();
            assert_eq!(alarms_before, 2, "{calls:?}");
            assert!(
                calls[stop..]
                    .iter()
                    .any(|call| call == "ec2 describe-instances"),
                "{calls:?}"
            );
            let read = |name: &str| {
                value(
                    &fs::read_to_string(started.evidence.join("injection").join(name))
                        .expect("the mark reads"),
                )
            };
            let stopped = object(read("stopped.json"));
            assert_eq!(stopped.get("request"), Some(&read("stop.json")));
            assert_eq!(
                stopped.get("state"),
                Some(&Value::String(Text::from("stopped")))
            );
            assert!(stdout.contains("restoration"), "{stdout}");
        },
    );
}

/// A run started against a plane whose third guardrail alarm reads `ALARM` aborts at the first
/// alarm read, ahead of the stop: exit 1, `abort.json` beside `roles.json` with cause `guardrail`
/// and the alarm's text, GD-2's restoration steps printed, and no `ec2 stop-instances` in the call
/// log.
#[test]
fn a_started_run_aborts_on_a_guardrail_alarm_ahead_of_the_stop() {
    apart(
        module_path!(),
        "a_started_run_aborts_on_a_guardrail_alarm_ahead_of_the_stop",
        || {
            let started = Started::new("started-abort");
            started.alarm("gd2-guardrail-3");
            let ran = started.run(&started.top, &started.bin, &started.command("run"));
            let (stdout, stderr) = (text(&ran.stdout), text(&ran.stderr));
            assert_eq!(ran.status.code(), Some(1), "{stdout}{stderr}");
            assert_eq!(started.marks(), ["abort.json", "roles.json"]);
            let calls = started.calls();
            assert!(
                !calls.iter().any(|call| call == "ec2 stop-instances"),
                "{calls:?}"
            );
            assert_eq!(
                calls.last().map(String::as_str),
                Some("cloudwatch describe-alarms")
            );
            let abort = object(value(
                &fs::read_to_string(started.evidence.join("injection/abort.json"))
                    .expect("the mark reads"),
            ));
            assert_eq!(
                abort.get("cause"),
                Some(&Value::String(Text::from("guardrail")))
            );
            assert_eq!(
                abort.get("guardrail"),
                Some(&Value::String(Text::from(
                    "any replacement receipt written by the reconciler principal"
                )))
            );
            assert!(
                format!("{stdout}{stderr}").contains(&super::steps()),
                "{stdout}{stderr}"
            );
        },
    );
}

/// A SIGTERM that stands pending and blocked when the binary starts is delivered at the root's
/// first statement, where the handlers' registration unblocks it, and the record holds it: the run
/// raises it at its first read and ends with exit 2, nothing written and no call made. A process
/// that lost it would run to its end.
#[test]
fn a_signal_delivered_at_the_roots_first_statement_is_recorded() {
    apart(
        module_path!(),
        "a_signal_delivered_at_the_roots_first_statement_is_recorded",
        || {
            let started = Started::new("started-signal");
            let mut command = Command::new(BINARY);
            command
                .arg(&started.top)
                .arg("host-stop-controller")
                .args(started.command("run"))
                .env_clear()
                .env("PATH", &started.bin)
                .env(ROLE, &started.state);
            // SAFETY: the closure runs in the child between fork and exec and calls only `sigemptyset`,
            // `sigaddset`, `pthread_sigmask` and `raise`, which are async-signal-safe, on a set it owns.
            unsafe {
                command.pre_exec(|| {
                    let mut set: libc::sigset_t = std::mem::zeroed();
                    libc::sigemptyset(&mut set);
                    libc::sigaddset(&mut set, libc::SIGTERM);
                    if libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) != 0
                        || libc::raise(libc::SIGTERM) != 0
                    {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let ran = bounded(command);
            assert_eq!(ran.status.code(), Some(2), "{ran:?}");
            assert_eq!(
                text(&ran.stderr),
                "host-stop-controller: signal SIGTERM before any mark; nothing written\n"
            );
            assert_eq!(text(&ran.stdout), "");
            assert_eq!(started.calls(), Vec::<String>::new());
            assert_eq!(listing(&started.evidence), ["package.json"]);
        },
    );
}

/// With no `aws` on its `PATH`, the tool refuses `run` at its first step on the committed tree,
/// whose catalog leaves GD-2's prerequisites unmet, and `restore` of a copy of the held fixture at
/// the caller check, each with exit 2 and nothing written.
#[test]
fn the_tool_without_aws_refuses_run_at_step_one_and_restore_at_the_caller_check() {
    apart(
        module_path!(),
        "the_tool_without_aws_refuses_run_at_step_one_and_restore_at_the_caller_check",
        || {
            let started = Started::new("started-no-aws");
            let empty = started.scratch.0.join("empty");
            fs::create_dir(&empty).expect("the empty directory is made");
            let held = tree().join("scripts/gameday-fixtures/held");
            fs::write(started.evidence.join("package.json"), package())
                .expect("the copy is written");
            let fixture = tree().join("scripts/host-stop-fixtures/operator.json");
            let args: [&Path; 7] = [
                Path::new("run"),
                Path::new("--operator"),
                &fixture,
                Path::new("--package"),
                &held.join("package.json"),
                Path::new("--evidence"),
                &started.evidence,
            ];
            let ran = started.run(&tree(), &empty, &args);
            assert_eq!(ran.status.code(), Some(2), "{ran:?}");
            let stderr = text(&ran.stderr);
            assert!(
                stderr.starts_with(
                    "host-stop-controller: refused: GD-2's prerequisites are not all met"
                ) && stderr.ends_with("; nothing written\n"),
                "{stderr}"
            );
            assert_eq!(listing(&started.evidence), ["package.json"]);
            let copy = started.scratch.0.join("held");
            super::sealing::copy_tree(&held, &copy, &[]);
            for name in ["restoration.json", "collected.json"] {
                fs::remove_file(copy.join("injection").join(name)).expect("the mark is removed");
            }
            let mut o = value(&fs::read_to_string(&fixture).expect("the operator file reads"));
            set(
                &mut o,
                &["identity"],
                Value::String(Text::from("operator-role")),
            );
            let operator = started
                .scratch
                .write("held-operator.json", json(&o).as_bytes());
            let args: [&Path; 5] = [
                Path::new("restore"),
                Path::new("--operator"),
                &operator,
                Path::new("--evidence"),
                &copy,
            ];
            let ran = started.run(&tree(), &empty, &args);
            assert_eq!(ran.status.code(), Some(2), "{ran:?}");
            assert_eq!(
                text(&ran.stderr),
                "host-stop-controller: refused: the caller is unknown: sts get-caller-identity gave no \
         answer: no directory of PATH holds an executable aws; nothing written\n"
            );
            assert_eq!(
                listing(&copy.join("injection")),
                ["roles.json", "stop.json", "stopped.json"]
            );
        },
    );
}
