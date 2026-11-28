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

/// For each `signal_group` call, `recorded_stop` samples the leader's state before the call and records a
/// timestamp after the call returns. Entries at the same index describe the same call.
fn recorded_stop(
    child: &mut std::process::Child,
    stop: &super::GroupStop<'_>,
) -> (Vec<(i32, super::Leader)>, Vec<Instant>, super::GroupStopped) {
    let pid = child.id();
    let mut sent = Vec::new();
    let mut times = Vec::new();
    let mut send = |group: libc::pid_t, signal: i32| {
        sent.push((signal, super::leader(pid).expect("the state reads")));
        let delivered = super::signal_group(group, signal);
        times.push(Instant::now());
        delivered
    };
    let stopped = super::stop_with(child, stop, &mut send).expect("the stop runs");
    (sent, times, stopped)
}

fn reap_outside(pid: libc::pid_t) {
    let mut status = 0;
    // SAFETY: `waitpid` writes the status into `status`, a local that outlives the call.
    let reaped = unsafe { libc::waitpid(pid, &mut status, 0) };
    assert_eq!(reaped, pid, "the leader is reaped outside the stop");
}

fn pid_of(child: &std::process::Child) -> libc::pid_t {
    libc::pid_t::try_from(child.id()).expect("a process id fits pid_t")
}

const WAIT: Duration = Duration::from_secs(30);
const PAUSE: Duration = Duration::from_millis(20);

/// The fields are read after the last `)`, so a command name that holds `) Z (` reads as the state that
/// follows it; `Z` is an exited leader only with one thread left, and a stat line of a process that leads
/// no group of its own is refused.
#[test]
fn a_command_name_with_a_parenthesis_and_a_space_is_read() {
    use super::{Leader, parsed};
    let own = std::process::id();
    let line = |name: &str, state: &str, group: u32, threads: u32| {
        let mut fields = vec![state.to_owned(), own.to_string(), group.to_string()];
        fields.extend((3..17).map(|_| "0".to_owned()));
        fields.push(threads.to_string());
        fields.push("0\n".to_owned());
        format!("12 ({name}) {}", fields.join(" ")).into_bytes()
    };
    assert_eq!(
        parsed(&line("a) Z (b", "S", 12, 1), 12, own),
        Ok(Leader::Running)
    );
    assert_eq!(parsed(&line("sh", "Z", 12, 1), 12, own), Ok(Leader::Exited));
    assert_eq!(
        parsed(&line("sh", "Z", 12, 2), 12, own),
        Ok(Leader::Running),
        "a leader whose main thread ended while another runs"
    );
    assert!(
        parsed(&line("sh", "S", 7, 1), 12, own).is_err(),
        "a member of another group"
    );
    assert!(
        parsed(&line("sh", "S", 12, 1), 12, own + 1).is_err(),
        "a process with another parent"
    );
    assert!(parsed(b"12 (sh)", 12, own).is_err());
    assert!(parsed(b"12 sh S", 12, own).is_err());
    let scratch = crate::paths::tests::Scratch::new("probe-name");
    let program = scratch.0.join("x) Z (y");
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut script = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(&program)
            .expect("the script is made");
        std::io::Write::write_all(&mut script, b"#!/bin/sh\nread line\n").expect("it is written");
    }
    let mut child = {
        use std::os::unix::process::CommandExt;
        Command::new(&program)
            .stdin(std::process::Stdio::piped())
            .process_group(0)
            .spawn()
            .expect("the script runs")
    };
    let comm = std::fs::read_to_string(format!("/proc/{}/comm", child.id()));
    let state = super::leader(child.id());
    child.kill().expect("the child is killed");
    child.wait().expect("the child is reaped");
    let (comm, state) = (comm.expect("comm reads"), state.expect("the state reads"));
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
    let stop = super::GroupStop::new(WAIT, None, Some(WAIT), PAUSE).with_second_grace();
    let (sent, _, stopped) = recorded_stop(&mut child, &stop);
    assert_eq!(
        sent,
        [
            (libc::SIGTERM, super::Leader::Exited),
            (libc::SIGKILL, super::Leader::Exited)
        ]
    );
    let super::GroupStopped::Reaped(status) = stopped else {
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
    let (sent, times, stopped) = recorded_stop(
        &mut child,
        &super::GroupStop::new(long, None, Some(WAIT), PAUSE).with_second_grace(),
    );
    let grace = times[1].saturating_duration_since(times[0]);
    assert!(grace >= long, "SIGKILL followed SIGTERM after {grace:?}");
    assert_eq!(
        sent,
        [
            (libc::SIGTERM, super::Leader::Running),
            (libc::SIGKILL, super::Leader::Running),
            (libc::SIGKILL, super::Leader::Exited)
        ]
    );
    assert!(
        matches!(stopped, super::GroupStopped::Reaped(status) if status.signal() == Some(libc::SIGKILL))
    );
    let mut child = ignoring_term();
    let ends = || true;
    let stop = super::GroupStop::new(WAIT, Some(&ends), None, PAUSE);
    let start = Instant::now();
    let (sent, _, stopped) = recorded_stop(&mut child, &stop);
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
    assert!(matches!(stopped, super::GroupStopped::Reaped(_)));
}

/// A leader whose state file is gone was reaped by a wait outside the stop, which then sends no signal.
#[test]
fn a_leader_reaped_elsewhere_ends_the_stop_with_no_signal() {
    let mut child = group_leader("exit 0");
    reap_outside(pid_of(&child));
    let (sent, _, stopped) = recorded_stop(
        &mut child,
        &super::GroupStop::new(WAIT, None, Some(WAIT), PAUSE).with_second_grace(),
    );
    assert_eq!(sent, []);
    assert_eq!(stopped, super::GroupStopped::ReapedElsewhere);
}

/// A signal that fails ends the stop with its error after SIGKILL to the group and to the child and the
/// reap; a group with no member at SIGTERM goes on to the reap with no further signal; and a leader that
/// outlives the reap's bound stays unreaped as `Running`.
#[test]
fn a_failed_signal_an_empty_group_and_a_reap_past_its_bound() {
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
    let stop = super::GroupStop::new(WAIT, None, Some(WAIT), PAUSE);
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
    assert!(matches!(stopped, super::GroupStopped::Reaped(status) if status.code() == Some(3)));

    let mut child = ignoring_term();
    let mut ignored = |_: libc::pid_t, _: i32| Ok(true);
    let brief = Duration::from_millis(50);
    let stop = super::GroupStop::new(brief, None, Some(brief), PAUSE);
    let stopped = super::stop_with(&mut child, &stop, &mut ignored).expect("the stop runs");
    let running = super::leader(child.id()).expect("the state reads");
    child.kill().expect("the child is killed");
    child.wait().expect("the child is reaped");
    assert_eq!(stopped, super::GroupStopped::Running);
    assert_eq!(running, super::Leader::Running);
}

#[test]
fn a_leader_reaped_outside_the_stop_during_a_grace_ends_the_stop_with_no_further_signal() {
    let mut child = group_leader("while :; do sleep 1; done");
    let pid = pid_of(&child);
    let mut sent = Vec::new();
    let mut send = |group: libc::pid_t, signal: i32| {
        sent.push(signal);
        if signal != libc::SIGTERM {
            return Ok(true);
        }
        let delivered = super::signal_group(group, libc::SIGKILL);
        reap_outside(pid);
        delivered
    };
    let stop = super::GroupStop::new(WAIT, None, Some(WAIT), PAUSE).with_second_grace();
    let stopped = super::stop_with(&mut child, &stop, &mut send);
    assert_eq!(sent, [libc::SIGTERM]);
    assert_eq!(
        stopped.expect("the stop runs"),
        super::GroupStopped::ReapedElsewhere
    );
}

#[test]
fn a_leader_reaped_outside_the_stop_after_its_last_signal_ends_the_stop_with_no_further_signal() {
    let mut child = ignoring_term();
    let pid = pid_of(&child);
    let mut sent = Vec::new();
    let mut send = |group: libc::pid_t, signal: i32| {
        sent.push(signal);
        let delivered = super::signal_group(group, signal);
        if signal == libc::SIGKILL {
            reap_outside(pid);
        }
        delivered
    };
    let brief = Duration::from_millis(50);
    let stop = super::GroupStop::new(brief, None, Some(WAIT), PAUSE);
    let stopped = super::stop_with(&mut child, &stop, &mut send);
    assert_eq!(sent, [libc::SIGTERM, libc::SIGKILL]);
    assert_eq!(
        stopped.expect("the stop runs"),
        super::GroupStopped::ReapedElsewhere
    );
}

#[test]
fn a_failed_read_of_the_state_kills_and_reaps_the_child_itself() {
    let mut child = Command::new("sh")
        .args(["-c", "read line"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .expect("the child starts");
    let pid = pid_of(&child);
    let mut sent = Vec::new();
    let mut undelivered = |group: libc::pid_t, signal: i32| {
        sent.push((group, signal));
        Ok(false)
    };
    let stop = super::GroupStop::new(WAIT, None, Some(WAIT), PAUSE);
    let stopped = super::stop_with(&mut child, &stop, &mut undelivered);
    let status = child.try_wait();
    if !matches!(status, Ok(Some(_))) {
        let _ = child.kill();
        let _ = child.wait();
    }
    let error = stopped.expect_err("the child leads no group, so its state is refused");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert_eq!(sent, [(pid, libc::SIGKILL)]);
    let status = status
        .expect("the wait runs")
        .expect("the stop reaped the child");
    assert_eq!(status.signal(), Some(libc::SIGKILL));
}

/// `running` holds while `pid` names a live process that is no zombie.
fn running(pid: &str) -> bool {
    std::fs::read_to_string(format!("/proc/{}/stat", pid.trim())).is_ok_and(|stat| {
        stat.rsplit_once(')')
            .and_then(|(_, rest)| rest.split_whitespace().next())
            .is_some_and(|state| state != "Z")
    })
}

/// `worker_group` starts a group leader that writes `leader` once a worker of its group, which ignores
/// SIGTERM, has written its pid to `worker`; the leader keeps SIGTERM's default action.
fn worker_group(marker: &Path) -> (std::process::Child, String) {
    let script = "sh -c 'trap \"\" TERM; echo $$ > \"$1/worker\"; exec sleep 120' sh \"$1\" & \
                  while [ ! -s \"$1/worker\" ]; do sleep 0.05; done; echo $$ > \"$1/leader\"; exec sleep 120";
    let child = {
        use std::os::unix::process::CommandExt;
        Command::new("sh")
            .args(["-c", script, "sh"])
            .arg(marker)
            .process_group(0)
            .spawn()
            .expect("the leader starts")
    };
    let start = Instant::now();
    while !marker.join("leader").exists() {
        assert!(start.elapsed() < WAIT, "the group stands within {WAIT:?}");
        std::thread::sleep(Duration::from_millis(5));
    }
    let worker = std::fs::read_to_string(marker.join("worker")).expect("the worker wrote its pid");
    (child, worker)
}

/// A handled signal recorded as the stop begins, after a deadline (no delivery spent) or after the
/// delivery that ended a wait, or recorded just before the stop's SIGKILL, leaves no member of the group
/// running: the worker ignores SIGTERM, so only the SIGKILL ends it. The grace of the stop ends once the
/// deliveries pass the spent ones, and the stop reaps the leader.
#[test]
fn a_signal_during_the_stop_still_ends_the_whole_group() {
    for (at, spent) in [("stop", 0), ("stop", 1), ("kill", 0)] {
        let scratch = crate::paths::tests::Scratch::new("stop-signal");
        let (mut child, worker) = worker_group(&scratch.0);
        let interrupt = Interrupt::new();
        if spent == 1 {
            interrupt.record(libc::SIGINT);
        }
        let ends = || interrupt.deliveries() > spent;
        let mut fired = false;
        let mut send = |group: libc::pid_t, signal: i32| {
            let begins = at == "stop" && signal == libc::SIGTERM;
            let kills = at == "kill" && signal == libc::SIGKILL;
            if !fired && (begins || kills) {
                fired = true;
                interrupt.record(libc::SIGTERM);
            }
            super::signal_group(group, signal)
        };
        let stop = super::GroupStop::new(Duration::from_secs(45), Some(&ends), None, PAUSE);
        let start = Instant::now();
        let stopped = super::stop_with(&mut child, &stop, &mut send).expect("the stop runs");
        assert!(fired, "{at}: the signal was delivered");
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "{at}: the stop took {:?}",
            start.elapsed()
        );
        assert!(
            matches!(stopped, super::GroupStopped::Reaped(_)),
            "{at}: {stopped:?}"
        );
        let start = Instant::now();
        while running(&worker) && start.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            !running(&worker),
            "{at}, {spent}: the worker {worker} is gone"
        );
    }
}

/// The record keeps the first signal and counts each delivery; a hold nests, only the outermost
/// release reports a recorded signal, and a dropped hold ends as a released one does.
#[test]
fn a_hold_nests_and_its_outermost_release_reports_the_first_signal() {
    let interrupt = Interrupt::new();
    {
        let quiet = interrupt.hold();
        assert!(interrupt.held());
        assert_eq!(quiet.release(), Ok(()));
    }
    assert!(!interrupt.held());
    let outer = interrupt.hold();
    let inner = interrupt.hold();
    interrupt.record(libc::SIGTERM);
    assert_eq!(inner.release(), Ok(()), "a nested release reports nothing");
    assert!(interrupt.held());
    interrupt.record(libc::SIGHUP);
    assert_eq!(interrupt.deliveries(), 2);
    assert_eq!(outer.release(), Err(Interrupted(libc::SIGTERM)));
    assert!(!interrupt.held());
    drop(interrupt.hold());
    assert!(!interrupt.held(), "a dropped hold ends");
}

/// A signal delivered while the handled signals are blocked stays pending, so the handler records it
/// only once the mask is set back, and the thread's mask is the one it held before.
#[test]
fn a_blocked_signal_is_recorded_once_the_mask_is_set_back() {
    let own = |set: &mut libc::sigset_t| {
        // SAFETY: a null new set makes `pthread_sigmask` only write the current mask into `set`.
        let status = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), set) };
        assert_eq!(status, 0);
    };
    // SAFETY: all-zero bytes are a valid `sigset_t` that `own` overwrites.
    let (mut before, mut inside, mut after): (libc::sigset_t, libc::sigset_t, libc::sigset_t) =
        unsafe { (std::mem::zeroed(), std::mem::zeroed(), std::mem::zeroed()) };
    own(&mut before);
    let value = super::blocked(|| {
        own(&mut inside);
        7
    })
    .expect("the mask changes");
    own(&mut after);
    assert_eq!(value, 7);
    for signal in super::SIGNALS {
        // SAFETY: each set is initialized and `signal` is a valid number.
        let (was, held, is) = unsafe {
            (
                libc::sigismember(&before, signal),
                libc::sigismember(&inside, signal),
                libc::sigismember(&after, signal),
            )
        };
        assert_eq!((held, is), (1, was), "signal {signal}");
    }
}
