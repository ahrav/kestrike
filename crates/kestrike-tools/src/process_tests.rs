use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use super::{Interrupt, Interrupted, capture};

#[test]
fn a_recorded_signal_kills_a_captured_child_and_returns_the_interruption() {
    let interrupt = Interrupt::new();
    let scratch = crate::paths::tests::Scratch::new("capture");
    let marker = scratch.0.join("marker");
    let mut command = Command::new("sh");
    command
        .args([
            "-c",
            "echo $$ > \"$1.tmp\" && mv \"$1.tmp\" \"$1\"; exec sleep 600",
            "sh",
        ])
        .arg(&marker);
    let (stop, elapsed) = std::thread::scope(|scope| {
        let signaled = scope.spawn(|| {
            let start = Instant::now();
            while !marker.exists() && start.elapsed() < Duration::from_secs(30) {
                std::thread::sleep(Duration::from_millis(5));
            }
            interrupt.record(libc::SIGTERM);
            interrupt.record(libc::SIGINT);
            Instant::now()
        });
        let stop =
            capture(&mut command, &interrupt).expect_err("the recorded signal ends the capture");
        let returned = Instant::now();
        let signaled = signaled.join().expect("the signalling thread ends");
        (stop, returned.saturating_duration_since(signaled))
    });
    assert_eq!(
        interrupt.recorded(),
        Some(libc::SIGTERM),
        "a later signal changes nothing"
    );
    assert_eq!(stop, Interrupted(libc::SIGTERM));
    let pid = std::fs::read_to_string(&marker).expect("the child wrote its pid");
    let pid = pid.trim();
    assert!(
        !Path::new(&format!("/proc/{pid}")).exists(),
        "the child {pid} is killed and reaped"
    );
    assert!(
        elapsed < Duration::from_secs(1),
        "the capture returned {elapsed:?} after the signal"
    );
}

#[test]
fn a_capture_waits_for_the_child_and_its_output() {
    let interrupt = Interrupt::new();
    let mut command = Command::new("sh");
    command.args(["-c", "printf out; printf err >&2; exit 3"]);
    let output = capture(&mut command, &interrupt)
        .expect("no signal")
        .expect("the child runs");
    assert_eq!(
        (
            output.status.code(),
            output.stdout.as_slice(),
            output.stderr.as_slice()
        ),
        (Some(3), &b"out"[..], &b"err"[..])
    );
}

/// `group_leader` starts `sh -c SCRIPT` leading a process group of its own.
fn group_leader(script: &str) -> std::process::Child {
    use std::os::unix::process::CommandExt;
    Command::new("sh")
        .args(["-c", script])
        .process_group(0)
        .spawn()
        .expect("the leader starts")
}

/// `ignoring_term` starts a group leader that ignores SIGTERM and returns once its status shows SIGTERM
/// ignored.
fn ignoring_term() -> std::process::Child {
    let mut child = group_leader("trap '' TERM; while :; do sleep 1; done");
    let status = format!("/proc/{}/status", child.id());
    let ignores = || {
        let text = std::fs::read_to_string(&status).expect("the status reads");
        let ignored = text
            .lines()
            .find_map(|line| line.strip_prefix("SigIgn:"))
            .and_then(|mask| u64::from_str_radix(mask.trim(), 16).ok())
            .expect("a SigIgn line");
        ignored & (1 << (libc::SIGTERM - 1)) != 0
    };
    let start = Instant::now();
    while !ignores() {
        if start.elapsed() >= WAIT {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the leader ignores SIGTERM within {WAIT:?}");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    child
}

/// `recorded_stop` stops `child`'s group with `stop` and returns each signal sent with the leader's state
/// read just before it, and how the stop left the child.
fn recorded_stop(
    child: &mut std::process::Child,
    stop: &super::GroupStop<'_>,
) -> (Vec<(i32, super::Leader)>, super::Stopped) {
    let pid = child.id();
    let mut sent = Vec::new();
    let mut send = |group: libc::pid_t, signal: i32| {
        sent.push((signal, super::leader(pid).expect("the state reads")));
        super::signal_group(group, signal)
    };
    let stopped = super::stop_with(child, stop, &mut send).expect("the stop runs");
    (sent, stopped)
}

const WAIT: Duration = Duration::from_secs(30);
const PAUSE: Duration = Duration::from_millis(20);

/// The fields are read after the last `)`, so a command name that holds `) Z (` reads as the state that
/// follows it; `Z` is an exited leader only with one thread left, and a stat line of a process that leads
/// no group of its own is refused.
#[test]
fn a_command_name_with_a_parenthesis_and_a_space_is_read() {
    use super::{Leader, parsed};
    let line = |name: &str, state: &str, group: u32, threads: u32| {
        let mut fields = vec![state.to_owned(), "1".to_owned(), group.to_string()];
        fields.extend((3..17).map(|_| "0".to_owned()));
        fields.push(threads.to_string());
        fields.push("0\n".to_owned());
        format!("12 ({name}) {}", fields.join(" ")).into_bytes()
    };
    assert_eq!(
        parsed(&line("a) Z (b", "S", 12, 1), 12),
        Ok(Leader::Running)
    );
    assert_eq!(parsed(&line("sh", "Z", 12, 1), 12), Ok(Leader::Exited));
    assert_eq!(
        parsed(&line("sh", "Z", 12, 2), 12),
        Ok(Leader::Running),
        "a leader whose main thread ended while another runs"
    );
    assert!(
        parsed(&line("sh", "S", 7, 1), 12).is_err(),
        "a member of another group"
    );
    assert!(parsed(b"12 (sh)", 12).is_err());
    assert!(parsed(b"12 sh S", 12).is_err());
    let scratch = crate::paths::tests::Scratch::new("probe-name");
    let program = scratch.0.join("x) Z (y");
    std::os::unix::fs::symlink("/bin/sleep", &program).expect("the link is made");
    let mut child = {
        use std::os::unix::process::CommandExt;
        Command::new(&program)
            .arg("600")
            .process_group(0)
            .spawn()
            .expect("the copy runs")
    };
    let comm = std::fs::read_to_string(format!("/proc/{}/comm", child.id())).expect("comm reads");
    let state = super::leader(child.id()).expect("the state reads");
    child.kill().expect("the child is killed");
    child.wait().expect("the child is reaped");
    assert_eq!(comm, "x) Z (y\n");
    assert_eq!(state, Leader::Running);
}

/// A leader that exits reads as exited and stays unreaped: each signal of the stop is sent while the
/// process table shows it as a zombie, and the reap after the last one gives its exit code.
#[test]
fn an_exited_leader_stays_a_zombie_through_each_signal_and_the_reap_gives_its_code() {
    let mut child = group_leader("exit 7");
    let state = super::leader_left_within(child.id(), WAIT, PAUSE, &|| false);
    assert_eq!(state.expect("the state reads"), super::Leader::Exited);
    let stop = super::GroupStop::new(WAIT, Some(WAIT), PAUSE).with_second_grace();
    let (sent, stopped) = recorded_stop(&mut child, &stop);
    assert_eq!(
        sent,
        [
            (libc::SIGTERM, super::Leader::Exited),
            (libc::SIGKILL, super::Leader::Exited)
        ]
    );
    let super::Stopped::Reaped(status) = stopped else {
        panic!("the leader is reaped: {stopped:?}");
    };
    assert_eq!(status.code(), Some(7));
}

/// A leader that outlives SIGTERM gets SIGKILL and, with a second grace, the closing SIGKILL once it
/// has exited; without one, the closing SIGKILL alone. A check that holds ends a grace at once.
#[test]
fn a_leader_that_outlives_sigterm_is_killed_as_the_stop_s_values_say() {
    let long = Duration::from_secs(2);
    let mut child = ignoring_term();
    let (sent, stopped) = recorded_stop(
        &mut child,
        &super::GroupStop::new(long, Some(WAIT), PAUSE).with_second_grace(),
    );
    assert_eq!(
        sent,
        [
            (libc::SIGTERM, super::Leader::Running),
            (libc::SIGKILL, super::Leader::Running),
            (libc::SIGKILL, super::Leader::Exited)
        ]
    );
    assert!(
        matches!(stopped, super::Stopped::Reaped(status) if status.signal() == Some(libc::SIGKILL))
    );
    let mut child = ignoring_term();
    let ends = || true;
    let stop = super::GroupStop::new(WAIT, None, PAUSE).ended_by(&ends);
    let start = Instant::now();
    let (sent, stopped) = recorded_stop(&mut child, &stop);
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "the check ended the grace"
    );
    assert_eq!(
        sent,
        [
            (libc::SIGTERM, super::Leader::Running),
            (libc::SIGKILL, super::Leader::Running)
        ]
    );
    assert!(matches!(stopped, super::Stopped::Reaped(_)));
}

/// A leader whose state file is gone was reaped by a wait outside the stop, which then sends no signal.
#[test]
fn a_leader_reaped_elsewhere_ends_the_stop_with_no_signal() {
    let mut child = group_leader("exit 0");
    let pid = libc::pid_t::try_from(child.id()).expect("a process id fits pid_t");
    let mut status = 0;
    // SAFETY: `waitpid` writes the status into `status`, a local that outlives the call.
    let reaped = unsafe { libc::waitpid(pid, &mut status, 0) };
    assert_eq!(reaped, pid, "the leader is reaped outside the stop");
    let (sent, stopped) = recorded_stop(
        &mut child,
        &super::GroupStop::new(WAIT, Some(WAIT), PAUSE).with_second_grace(),
    );
    assert_eq!(sent, []);
    assert_eq!(stopped, super::Stopped::ReapedElsewhere);
}

/// A signal that fails ends the stop with its error after SIGKILL to the group and to the child and the
/// reap; a group with no member at SIGTERM goes on to the reap with no further signal; and a leader that
/// outlives the reap's bound stays unreaped as `Running`.
#[test]
fn a_failed_signal_an_empty_group_and_a_reap_past_its_bound() {
    let pid_of = |child: &std::process::Child| libc::pid_t::try_from(child.id()).expect("fits");
    let mut child = ignoring_term();
    let group = pid_of(&child);
    let mut sent = Vec::new();
    let mut failing = |at: libc::pid_t, signal: i32| {
        sent.push(signal);
        if signal == libc::SIGTERM {
            return Err(std::io::Error::from_raw_os_error(libc::EPERM));
        }
        super::signal_group(at, signal)
    };
    let stop = super::GroupStop::new(WAIT, Some(WAIT), PAUSE);
    let error = super::stop_with(&mut child, &stop, &mut failing).expect_err("the signal fails");
    assert_eq!(error.raw_os_error(), Some(libc::EPERM));
    assert_eq!(sent, [libc::SIGTERM, libc::SIGKILL]);
    assert_eq!(
        super::leader(child.id()).expect("the state reads"),
        super::Leader::Reaped
    );
    assert!(
        std::fs::metadata(format!("/proc/{group}")).is_err(),
        "the child is reaped"
    );

    let mut child = group_leader("exit 3");
    let state = super::leader_left_within(child.id(), WAIT, PAUSE, &|| false);
    assert_eq!(state.expect("the state reads"), super::Leader::Exited);
    let mut sent = Vec::new();
    let mut empty = |_: libc::pid_t, signal: i32| {
        sent.push(signal);
        Ok(false)
    };
    let stopped = super::stop_with(&mut child, &stop, &mut empty).expect("the stop runs");
    assert_eq!(sent, [libc::SIGTERM]);
    assert!(matches!(stopped, super::Stopped::Reaped(status) if status.code() == Some(3)));

    let mut child = ignoring_term();
    let mut ignored = |_: libc::pid_t, _: i32| Ok(true);
    let brief = Duration::from_millis(50);
    let stop = super::GroupStop::new(brief, Some(brief), PAUSE);
    let stopped = super::stop_with(&mut child, &stop, &mut ignored).expect("the stop runs");
    let running = super::leader(child.id()).expect("the state reads");
    child.kill().expect("the child is killed");
    child.wait().expect("the child is reaped");
    assert_eq!(stopped, super::Stopped::Running);
    assert_eq!(running, super::Leader::Running);
}
