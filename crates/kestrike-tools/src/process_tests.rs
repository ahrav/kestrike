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
    let child = group_leader("trap '' TERM; while :; do sleep 1; done");
    let status = format!("/proc/{}/status", child.id());
    let start = Instant::now();
    loop {
        let text = std::fs::read_to_string(&status).expect("the status reads");
        let ignored = text
            .lines()
            .find_map(|line| line.strip_prefix("SigIgn:"))
            .and_then(|mask| u64::from_str_radix(mask.trim(), 16).ok())
            .expect("a SigIgn line");
        if ignored & (1 << (libc::SIGTERM - 1)) != 0 {
            return child;
        }
        assert!(start.elapsed() < WAIT, "the leader ignores SIGTERM in time");
        std::thread::sleep(Duration::from_millis(5));
    }
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

/// The state is the field after the last `)`, so a command name that holds `) Z (` reads as the state
/// that follows it.
#[test]
fn a_command_name_with_a_parenthesis_and_a_space_is_read() {
    use super::state_of;
    assert_eq!(state_of(b"12 (a) Z (b) S 1 12"), Some(b'S'));
    assert_eq!(state_of(b"12 (sh) Z 1 12"), Some(b'Z'));
    assert_eq!(state_of(b"12 (sh)"), None);
    assert_eq!(state_of(b"12 sh S"), None);
    let scratch = crate::paths::tests::Scratch::new("probe-name");
    let program = scratch.0.join("x) Z (y");
    std::os::unix::fs::symlink("/bin/sleep", &program).expect("the link is made");
    let mut child = Command::new(&program)
        .arg("600")
        .spawn()
        .expect("the copy runs");
    let comm = std::fs::read_to_string(format!("/proc/{}/comm", child.id())).expect("comm reads");
    let state = super::leader(child.id()).expect("the state reads");
    child.kill().expect("the child is killed");
    child.wait().expect("the child is reaped");
    assert_eq!(comm, "x) Z (y\n");
    assert_eq!(state, super::Leader::Running);
}

/// A leader that exits reads as exited and stays unreaped: each signal of the stop is sent while the
/// process table shows it as a zombie, and the reap after the last one gives its exit code.
#[test]
fn an_exited_leader_stays_a_zombie_through_each_signal_and_the_reap_gives_its_code() {
    let mut child = group_leader("exit 7");
    let state = super::leader_left_within(child.id(), WAIT, PAUSE, &|| false);
    assert_eq!(state.expect("the state reads"), super::Leader::Exited);
    let stop = super::GroupStop::new(WAIT, true, Some(WAIT), PAUSE);
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
    let short = Duration::from_millis(100);
    let mut child = ignoring_term();
    let (sent, stopped) = recorded_stop(
        &mut child,
        &super::GroupStop::new(short, true, Some(WAIT), PAUSE),
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
    let stop = super::GroupStop::new(WAIT, false, None, PAUSE).ended_by(&ends);
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
        &super::GroupStop::new(WAIT, true, Some(WAIT), PAUSE),
    );
    assert_eq!(sent, []);
    assert_eq!(stopped, super::Stopped::ReapedElsewhere);
}
