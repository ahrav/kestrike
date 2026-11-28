//! The launch of the `aws` child: its arguments and environment, the output text, a failed call's
//! sentence, the cut, a signal that ends the wait, and the search of the given `PATH`.

use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use kestrike_tools::host_stop::{
    AWS, Call, CallFailed, Delivered, Ended, Failure, Interrupted, Record, SLICE, Signal, launch,
};

use super::{PLACE, ROLE, Scratch, first_start, gone, no_marker, passed, start_window, starts};

/// The stand-in `aws`: it writes its process id to `$HOST_STOP_PID`, then acts as `$HOST_STOP_MODE`
/// names. It uses shell builtins and programs named by their absolute paths alone, since its `PATH`
/// holds its own directory alone.
pub(super) const STANDIN: &str = r#"#!/bin/sh
[ "$HOST_STOP_MODE" = hang ] && trap '' TERM INT HUP
echo $$ >> "$HOST_STOP_PID"
case "$HOST_STOP_MODE" in
  echo)
    printf '%s|' "$(printf '[%s]' "$@")" "${AWS_MAX_ATTEMPTS-unset}" "${AWS_RETRY_MODE-unset}" "${AWS_PAGER-unset}" \
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
  hang) exec /bin/sleep 5 ;;
  late) /bin/sleep 0.4; echo '{}' ;;
  gate) while [ ! -e "$HOST_STOP_PID.go" ]; do :; done; echo '{}' ;;
  invalid) printf '\377' ;;
  invalid-error) printf '\377' >&2; echo '{}' ;;
  invalid-failed) printf '\377'; exit 254 ;;
  flood|flood-failed)
    /usr/bin/head -c 262144 /dev/zero | /usr/bin/tr '\0' x >&2
    printf 'END\n' >&2
    echo '{}'
    [ "$HOST_STOP_MODE" = flood ] || exit 254 ;;
  flood-out)
    /usr/bin/head -c 262144 /dev/zero | /usr/bin/tr '\0' y
    printf 'refused\n' >&2
    exit 254 ;;
  wide)
    i=0
    while [ $i -lt 500 ]; do printf '\303\251' >&2; i=$((i + 1)); done
    printf 'a\r\nEND\n' >&2
    exit 254 ;;
  group) read -r stat < /proc/$$/stat; set -- $stat; printf '%s' "$5" ;;
  orphan) /bin/sleep 4 & echo $! > "$HOST_STOP_PID.orphan"; echo '{}' ;;
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
        executable(&bin.join(AWS), STANDIN);
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

    fn started(&self) -> Vec<u32> {
        starts(&self.pid)
    }
}

/// The child opens `path` for writing so children forked by other test threads cannot inherit its
/// writable descriptor, which would make `execve` of the stand-in fail with `ETXTBSY`.
fn executable(path: &Path, text: &str) {
    let mut writer = Command::new("/bin/sh")
        .args(["-c", r#"/bin/cat > "$1" && /bin/chmod 700 "$1""#, "sh"])
        .arg(path)
        .stdin(Stdio::piped())
        .spawn()
        .expect("the writer starts");
    writer
        .stdin
        .take()
        .expect("the writer's input is piped")
        .write_all(text.as_bytes())
        .expect("the text reaches the writer");
    let status = writer.wait().expect("the writer ends");
    assert!(status.success(), "{} is written: {status}", path.display());
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
        Err(Ended::Failed(failed)) => failed.to_string(),
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
    let argv = [
        "ec2",
        "stop-instances",
        "--instance-ids",
        "i-h1",
        "--note",
        "a b",
    ];
    let reply = launch(
        &mut record,
        &call(&argv, false, Duration::from_millis(7500), &env),
    )
    .expect("the stand-in answers");
    let bin = standin.bin.display();
    assert_eq!(
        reply,
        format!(
            "[ec2][stop-instances][--instance-ids][i-h1][--note][a b][--no-paginate][--output][json]\
             [--cli-read-timeout][8][--cli-connect-timeout][8]|1|standard||off|true|unset|{bin}|\
             /dev/null|a\nb\nc\n"
        )
    );
    assert_eq!(standin.started().len(), 1, "one call starts one child");
    let read = launch(
        &mut record,
        &call(&IDENTITY, true, Duration::from_secs(5), &env),
    )
    .expect("the stand-in answers");
    assert_eq!(
        read,
        format!(
            "[sts][get-caller-identity][--no-paginate][--output][json][--cli-read-timeout][5]\
             [--cli-connect-timeout][5]|unset|legacy||off|true|unset|{bin}|/dev/null|a\nb\nc\n"
        ),
        "a call with retries keeps the caller's retry mode"
    );
    assert_eq!(standin.started().len(), 2, "one call starts one child");
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
    let env = standin.env("fail");
    let stop = ["ec2", "stop-instances", "--instance-ids", "i-h1"];
    let message = failed(launch(
        &mut record,
        &call(&stop, false, Duration::from_secs(5), &env),
    ));
    assert_eq!(
        message,
        format!("ec2 stop-instances exited 254: {}END", "x".repeat(397))
    );
    let pids = standin.started();
    assert_eq!(pids.len(), 3, "one call starts one child");
    assert!(pids.iter().all(|&pid| gone(pid)));
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
    let cut = Duration::from_millis(1100);
    let start = Instant::now();
    let message = failed(launch(&mut record, &call(&IDENTITY, true, cut, &env)));
    let elapsed = start.elapsed();
    assert_eq!(
        message,
        "sts get-caller-identity gave no answer: timed out after 1.1s"
    );
    assert!(
        elapsed >= cut && elapsed < Duration::from_secs(2),
        "{elapsed:?}"
    );
    let pids = standin.started();
    assert_eq!(pids.len(), 1, "one call starts one child");
    assert!(
        pids.iter().all(|&pid| gone(pid)),
        "{pids:?} are killed and reaped"
    );
}

/// The cut counts until both output pipes close: a child that exits while a process it started holds
/// its standard output is cut there, and the call returns a failed call.
#[test]
fn a_child_whose_output_stays_open_is_cut() {
    let standin = Standin::new("launch-orphan");
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    let env = standin.env("orphan");
    let cut = Duration::from_millis(1100);
    let start = Instant::now();
    let message = failed(launch(&mut record, &call(&IDENTITY, true, cut, &env)));
    let elapsed = start.elapsed();
    assert_eq!(
        message,
        "sts get-caller-identity gave no answer: timed out after 1.1s"
    );
    assert!(elapsed >= cut, "the call waits to its cut");
    assert!(
        elapsed < Duration::from_secs(2),
        "the call ends at its cut, not at the output's close: {elapsed:?}"
    );
    assert_eq!(standin.started().len(), 1, "one call starts one child");
    let orphan = fs::read_to_string(standin.pid.with_extension("orphan"))
        .expect("the stand-in names its descendant");
    let status = Command::new("/bin/kill")
        .args(["-KILL", orphan.trim()])
        .status()
        .expect("kill starts");
    assert!(status.success(), "the descendant is ended");
}

#[test]
fn a_child_that_answers_after_its_cut_gives_no_answer() {
    let standin = Standin::new("launch-late");
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    let env = standin.env("late");
    let cut = Duration::from_millis(200);
    let message = failed(launch(&mut record, &call(&IDENTITY, true, cut, &env)));
    assert_eq!(
        message,
        "sts get-caller-identity gave no answer: timed out after 200ms"
    );
    let pids = standin.started();
    assert_eq!(pids.len(), 1, "one call starts one child");
    assert!(pids.iter().all(|&pid| gone(pid)));
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
    let (ended, after, pid) = thread::scope(|scope| {
        let signaled = scope.spawn(|| {
            let pid = first_start(&standin.pid);
            let at = Instant::now();
            delivered.deliver(Signal::Terminate);
            (at, pid)
        });
        let ended = launch(
            &mut record,
            &call(&IDENTITY, true, Duration::from_secs(60), &env),
        );
        let returned = Instant::now();
        let (at, pid) = signaled.join().expect("the thread ends");
        (ended, returned - at, pid)
    });
    assert_eq!(
        ended,
        Err(Ended::Interrupted(Interrupted(Signal::Terminate)))
    );
    assert!(after < SLICE + Duration::from_secs(1), "{after:?}");
    assert!(gone(pid), "the child {pid} is killed and reaped");
    assert_eq!(standin.started(), [pid], "one call starts one child");
    assert!(!record.is_armed());
    assert_eq!(record.pending(), None);
    assert_eq!(standin.started().len(), 1, "one call starts one child");
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
    assert_eq!(standin.started().len(), 1, "one call starts one child");
    fs::remove_file(&standin.pid).expect("the stand-in ran");
    record.arm();
    let ended = launch(
        &mut record,
        &call(&IDENTITY, true, Duration::from_secs(5), &env),
    );
    assert_eq!(ended, Err(Ended::Interrupted(Interrupted(Signal::Hangup))));
    no_marker(&standin.pid);
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
    let linked = standin.scratch.dir("linked");
    symlink(standin.bin.join(AWS), linked.join(AWS)).expect("the link is made");
    let joined = |dirs: &[&Path]| {
        OsString::from(
            dirs.iter()
                .map(|dir| dir.display().to_string())
                .collect::<Vec<_>>()
                .join(":"),
        )
    };
    let with_path = |paths: &[OsString]| {
        let mut env = standin.env("echo");
        env.retain(|(name, _)| name != "PATH");
        env.extend(
            paths
                .iter()
                .map(|path| (OsString::from("PATH"), path.clone())),
        );
        env
    };
    for paths in [
        vec![joined(&[&empty])],
        vec![joined(&[&plain, &named])],
        vec![],
        vec![joined(&[&empty]), joined(&[&standin.bin])],
    ] {
        let env = with_path(&paths);
        let message = failed(launch(
            &mut record,
            &call(&IDENTITY, true, Duration::from_secs(5), &env),
        ));
        assert_eq!(
            message,
            "sts get-caller-identity gave no answer: no directory of PATH holds an executable aws",
            "{paths:?}"
        );
        no_marker(&standin.pid);
    }
    for paths in [
        vec![joined(&[&standin.bin]), joined(&[&empty])],
        vec![joined(&[&empty, &plain, &named, &standin.bin])],
        vec![joined(&[&linked])],
    ] {
        let env = with_path(&paths);
        let reply = launch(
            &mut record,
            &call(&IDENTITY, true, Duration::from_secs(5), &env),
        )
        .unwrap_or_else(|ended| panic!("{paths:?}: {ended:?}"));
        let first = paths[0].to_str().expect("a UTF-8 PATH");
        assert!(
            reply.contains(&format!("|{first}|/dev/null|")),
            "the child gets the first PATH: {reply}"
        );
    }
    assert_eq!(standin.started().len(), 3, "one call starts one child");
}

#[test]
fn an_aws_the_kernel_refuses_is_a_failed_start() {
    let standin = Standin::new("launch-exec");
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    for (dir, text, reason) in [
        (
            "format",
            "echo $$ >> \"$HOST_STOP_PID\"\n",
            "Exec format error (os error 8)",
        ),
        (
            "interpreter",
            "#!/nonexistent/sh\necho $$ >> \"$HOST_STOP_PID\"\n",
            "No such file or directory (os error 2)",
        ),
    ] {
        let bin = standin.scratch.dir(dir);
        executable(&bin.join(AWS), text);
        let mut env = standin.env("echo");
        env.retain(|(name, _)| name != "PATH");
        env.push((OsString::from("PATH"), bin.into_os_string()));
        let message = failed(launch(
            &mut record,
            &call(&IDENTITY, true, Duration::from_secs(5), &env),
        ));
        assert_eq!(
            message,
            format!("sts get-caller-identity gave no answer: {reason}"),
            "{dir}"
        );
    }
    no_marker(&standin.pid);
}

#[test]
fn the_first_entry_of_a_name_counts_and_a_name_with_equals_is_refused() {
    let standin = Standin::new("launch-names");
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    let mut env = standin.env("echo");
    env.push((OsString::from("HOME"), OsString::from("/first")));
    env.push((OsString::from("HOME"), OsString::from("/second")));
    env.push((OsString::from("HOST_STOP_MODE"), OsString::from("fail")));
    let reply = launch(
        &mut record,
        &call(&IDENTITY, true, Duration::from_secs(5), &env),
    )
    .expect("the stand-in answers in the first mode given");
    assert!(reply.contains("|/first|"), "{reply}");
    let mut env = standin.env("echo");
    env.push((OsString::from("A=B"), OsString::from("c")));
    let message = failed(launch(
        &mut record,
        &call(&IDENTITY, true, Duration::from_secs(5), &env),
    ));
    assert_eq!(
        message,
        "sts get-caller-identity gave no answer: illegal environment variable name"
    );
    assert_eq!(
        standin.started().len(),
        1,
        "the refused call starts nothing"
    );
}

/// Both outputs are read at once: a child that writes 256 KiB to standard error before its reply
/// answers, and when it fails, its call keeps the last 400 characters of that text; a child that
/// writes 256 KiB to standard output before its error text fails with that text.
#[test]
fn a_child_that_floods_standard_error_still_answers() {
    let standin = Standin::new("launch-flood");
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    let env = standin.env("flood");
    let reply = launch(
        &mut record,
        &call(&IDENTITY, true, Duration::from_secs(20), &env),
    );
    assert_eq!(reply, Ok("{}\n".to_owned()));
    let env = standin.env("flood-failed");
    let message = failed(launch(
        &mut record,
        &call(&IDENTITY, true, Duration::from_secs(20), &env),
    ));
    assert_eq!(
        message,
        format!("sts get-caller-identity exited 254: {}END", "x".repeat(397))
    );
    let env = standin.env("flood-out");
    let message = failed(launch(
        &mut record,
        &call(&IDENTITY, true, Duration::from_secs(20), &env),
    ));
    assert_eq!(message, "sts get-caller-identity exited 254: refused");
    assert_eq!(standin.started().len(), 3, "one call starts one child");
}

/// Both outputs decode as UTF-8 before the exit code is read: standard error other than UTF-8 fails
/// a call that exited 0, and standard output other than UTF-8 makes a call that exited 254 give no
/// answer.
#[test]
fn either_output_other_than_utf8_gives_no_answer_whatever_the_code() {
    let standin = Standin::new("launch-utf8");
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    for mode in ["invalid", "invalid-error", "invalid-failed"] {
        let env = standin.env(mode);
        let message = failed(launch(
            &mut record,
            &call(&IDENTITY, true, Duration::from_secs(5), &env),
        ));
        assert!(
            message.starts_with("sts get-caller-identity gave no answer: "),
            "{mode}: {message}"
        );
    }
    assert_eq!(standin.started().len(), 3, "one call starts one child");
}

/// The tail of a failed call counts characters of the decoded text, whose `\r\n` reads as `\n`.
#[test]
fn the_tail_of_a_failed_call_counts_characters_after_newline_translation() {
    let standin = Standin::new("launch-wide");
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    let env = standin.env("wide");
    let message = failed(launch(
        &mut record,
        &call(&IDENTITY, true, Duration::from_secs(5), &env),
    ));
    let text = format!("{}a\nEND", "\u{e9}".repeat(500));
    let tail: String = text.chars().skip(text.chars().count() - 400).collect();
    assert_eq!(
        message,
        format!("sts get-caller-identity exited 254: {tail}")
    );
    assert_eq!(standin.started().len(), 1, "one call starts one child");
}

/// The child stays in the tool's process group.
#[test]
fn the_child_stays_in_the_process_group_of_the_tool() {
    let standin = Standin::new("launch-group");
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    let env = standin.env("group");
    let group = launch(
        &mut record,
        &call(&IDENTITY, true, Duration::from_secs(5), &env),
    )
    .expect("the stand-in answers");
    let own = fs::read_to_string("/proc/self/stat").expect("the status reads");
    let after = own.rsplit_once(") ").expect("a stat line").1;
    let own_group = after.split(' ').nth(2).expect("the process group");
    assert_eq!(group, own_group);
    assert_eq!(standin.started().len(), 1, "one call starts one child");
}

/// A test's seam builds a failed call through the public constructors: the two words are the first two
/// arguments, or the one there is, and an exited call keeps the last 400 characters of its stripped
/// standard error.
#[test]
fn a_failed_call_builds_from_its_parts() {
    let cut = CallFailed::no_answer(&IDENTITY, "timed out after 5 seconds");
    assert_eq!(
        cut.to_string(),
        "sts get-caller-identity gave no answer: timed out after 5 seconds"
    );
    assert_eq!(cut.what(), "sts get-caller-identity");
    let stderr = format!(" \n{}\t", "y".repeat(450));
    let exited = CallFailed::exited(
        &["ec2", "stop-instances", "--instance-ids", "i-1"],
        254,
        &stderr,
    );
    assert_eq!(exited.what(), "ec2 stop-instances");
    assert_eq!(
        exited.failure(),
        &Failure::Exited {
            code: 254,
            tail: "y".repeat(400)
        }
    );
    assert_eq!(CallFailed::no_answer(&["sts"], "x").what(), "sts");
}

/// A signal delivered while the child still runs raises even when the child has exited by the wait's
/// next turn: the wait reads the record after it sees the child's end.
#[test]
fn a_signal_before_the_child_ends_raises_in_place_of_its_answer() {
    let standin = Standin::new("launch-gate");
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    record.arm();
    let env = standin.env("gate");
    let ended = thread::scope(|scope| {
        scope.spawn(|| {
            first_start(&standin.pid);
            delivered.deliver(Signal::Terminate);
            fs::write(standin.pid.with_extension("go"), b"").expect("the gate opens");
        });
        launch(
            &mut record,
            &call(&IDENTITY, true, Duration::from_secs(30), &env),
        )
    });
    assert_eq!(
        ended,
        Err(Ended::Interrupted(Interrupted(Signal::Terminate)))
    );
    assert!(!record.is_armed());
    assert_eq!(record.pending(), None);
    assert_eq!(standin.started().len(), 1, "one call starts one child");
}

const EMPTY_CASE: &str = "host_stop::launch::an_empty_path_entry_names_the_working_directory";

#[test]
fn an_empty_path_entry_names_the_working_directory() {
    if let (Some(_), Some(place)) = (std::env::var_os(ROLE), std::env::var_os(PLACE)) {
        let bin = Path::new(&place);
        let pid = bin
            .parent()
            .expect("the stand-in's directory has a parent")
            .join("pid");
        let delivered = Delivered::new();
        let mut record = Record::new(&delivered);
        for path in ["", ":/nonexistent"] {
            let env: Vec<(OsString, OsString)> = [
                ("PATH", OsString::from(path)),
                ("HOST_STOP_MODE", OsString::from("echo")),
                ("HOST_STOP_PID", pid.clone().into_os_string()),
            ]
            .into_iter()
            .map(|(name, value)| (OsString::from(name), value))
            .collect();
            let reply = launch(
                &mut record,
                &call(&IDENTITY, true, Duration::from_secs(5), &env),
            )
            .unwrap_or_else(|ended| panic!("{path:?}: {ended:?}"));
            assert!(reply.contains(&format!("|{path}|/dev/null|")), "{reply}");
        }
        assert_eq!(starts(&pid).len(), 2, "one call starts one child");
        return;
    }
    let standin = Standin::new("launch-empty");
    let output = start_window(
        EMPTY_CASE,
        "empty",
        &standin.bin,
        "cd \"$HOST_STOP_PLACE\" &&",
    )
    .output()
    .expect("the window starts");
    passed("empty", &output);
    assert_eq!(standin.started().len(), 2, "the window ran its calls");
}
