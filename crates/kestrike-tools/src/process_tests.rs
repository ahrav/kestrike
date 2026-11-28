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

/// `stat_fields` is the fields after the command name of a `/proc/<pid>/stat` line whose parent is
/// `parent`, whose process group is `group` and whose thread count is `threads`.
fn stat_fields(state: &str, parent: u32, group: u32, threads: u32) -> Vec<String> {
    let mut fields = vec![state.to_owned(), parent.to_string(), group.to_string()];
    fields.extend((3..17).map(|_| "0".to_owned()));
    fields.push(threads.to_string());
    fields.push("0\n".to_owned());
    fields
}

/// `stat_line` is the `/proc/12/stat` line of the command `name` holding `fields`.
fn stat_line(name: &str, fields: &[String]) -> Vec<u8> {
    format!("12 ({name}) {}", fields.join(" ")).into_bytes()
}

/// The fields are read after the last `)`, so a command name that holds `) Z (` reads as the state that
/// follows it; `Z` is an exited leader only with one thread left, and a stat line of a process that leads
/// no group of its own is refused.
///
/// `spawn` can return before `/proc/<pid>/comm` shows the script's name `NAME`, whose `) Z ` resembles
/// the command-name terminator followed by the zombie state in `/proc/<pid>/stat`. The test waits for
/// `comm` to show `NAME` so the `Leader::Running` assertion exercises the embedded `Z`.
#[test]
fn a_command_name_with_a_parenthesis_and_a_space_is_read() {
    use super::{Leader, parsed};
    const NAME: &str = "x) Z (y";
    let own = std::process::id();
    let line = |name: &str, state: &str, group: u32, threads: u32| {
        stat_line(name, &stat_fields(state, own, group, threads))
    };
    assert_eq!(
        parsed(&line("a) Z (b", "S", 12, 1), 12, own),
        Ok(Leader::Running)
    );
    assert_eq!(
        parsed(&line("a) Z (b", "Z", 12, 1), 12, own),
        Ok(Leader::Exited),
        "the state after the name decides, whatever the name holds"
    );
    assert_eq!(parsed(&line("sh", "Z", 12, 1), 12, own), Ok(Leader::Exited));
    assert_eq!(
        parsed(&line("sh", "Z", 12, 2), 12, own),
        Ok(Leader::Running),
        "a leader whose main thread ended while another runs"
    );
    assert_eq!(
        parsed(&line("sh", "S", 7, 1), 12, own),
        Err("names the process group 7, so the child leads no group of its own".to_owned()),
        "a member of another group"
    );
    assert_eq!(
        parsed(&line("sh", "S", 12, 1), 12, own + 1),
        Ok(Leader::Reaped),
        "a process with another parent holds an id taken again after a reap elsewhere"
    );
    let cut = |count: usize| {
        let mut fields = stat_fields("S", own, 12, 1);
        fields.truncate(count);
        stat_line("sh", &fields)
    };
    for (stat, refusal) in [
        (b"12 (sh)".to_vec(), "holds no state field"),
        (b"12 sh S".to_vec(), "holds no command name"),
        (
            stat_line("sh", &stat_fields("SS", own, 12, 1)),
            "holds no state field",
        ),
        (cut(1), "holds no parent"),
        (cut(2), "holds no process group"),
        (cut(17), "holds no thread count"),
    ] {
        assert_eq!(
            parsed(&stat, 12, own),
            Err(refusal.to_owned()),
            "{}",
            String::from_utf8_lossy(&stat)
        );
    }
    let scratch = crate::paths::tests::Scratch::new("probe-name");
    let program = scratch.0.join(NAME);
    crate::fixtures::tests::script(&program, "#!/bin/sh\nread line\n");
    let mut child = {
        use std::os::unix::process::CommandExt;
        Command::new(&program)
            .stdin(std::process::Stdio::piped())
            .process_group(0)
            .spawn()
            .expect("the script runs")
    };
    let comm = format!("/proc/{}/comm", child.id());
    let mut last = String::new();
    let state = super::polled(WAIT, PAUSE, &|| false, || {
        last = std::fs::read_to_string(&comm)?;
        if last.strip_suffix('\n') != Some(NAME) {
            return Ok(None);
        }
        super::leader(child.id()).map(Some)
    });
    child.kill().expect("the child is killed");
    child.wait().expect("the child is reaped");
    let state = state
        .expect("the name and the state read")
        .unwrap_or_else(|| {
            panic!("the name is {last:?} {WAIT:?} after the start, where {NAME:?} is expected")
        });
    assert_eq!(state, Leader::Running);
}

/// The probe reads a procfs whose `self/status` holds an `NStgid` line of this process's id alone, before
/// it reads the leader's record: a view that names another id, more than one id or none ends each read
/// with an error that names `self/status`, whether the leader's record is present or gone; in the
/// process's own view a gone record is a reaped leader, and a failed read of either file keeps its kind
/// and names its own path.
#[test]
fn a_procfs_of_another_pid_namespace_is_refused_and_each_error_names_its_path() {
    use super::{Leader, leader_under};
    use std::io::ErrorKind;
    let scratch = crate::paths::tests::Scratch::new("procfs");
    let root = &scratch.0;
    let own = 40;
    std::fs::create_dir(root.join("self")).expect("made");
    std::fs::create_dir(root.join("12")).expect("made");
    std::fs::write(
        root.join("12/stat"),
        stat_line("sh", &stat_fields("S", own, 12, 1)),
    )
    .expect("written");
    let status = root.join("self/status");
    let view = |text: &str| std::fs::write(&status, text).expect("written");
    view("Name:\tsh\nNStgid:\t40\nNSpid:\t40\n");
    assert_eq!(leader_under(root, 12, own).expect("read"), Leader::Running);
    assert_eq!(leader_under(root, 13, own).expect("read"), Leader::Reaped);
    std::fs::create_dir(root.join("15")).expect("made");
    std::fs::write(
        root.join("15/stat"),
        stat_line("sh", &stat_fields("S", own + 1, 15, 1)),
    )
    .expect("written");
    assert_eq!(
        leader_under(root, 15, own).expect("read"),
        Leader::Reaped,
        "a present record that names another parent reads as a reap elsewhere"
    );
    for text in [
        "NStgid:\t41\n",
        "NStgid:\t7\t40\n",
        "NStgid:\t40\t7\n",
        "NStgid:\n",
        "Name:\tsh\n",
    ] {
        view(text);
        for pid in [12, 13] {
            let error = leader_under(root, pid, own).expect_err(text);
            assert_eq!(error.kind(), ErrorKind::InvalidData, "{text}");
            assert!(error.to_string().contains("self/status"), "{error}");
        }
    }
    std::fs::remove_file(&status).expect("removed");
    let error = leader_under(root, 13, own).expect_err("no view");
    assert_eq!(error.kind(), ErrorKind::NotFound);
    assert!(error.to_string().contains("self/status"), "{error}");
    view("NStgid:\t40\n");
    std::fs::create_dir_all(root.join("14/stat")).expect("made");
    let error = leader_under(root, 14, own).expect_err("a directory reads as no record");
    assert_eq!(error.kind(), ErrorKind::IsADirectory);
    let text = error.to_string();
    assert!(
        text.contains("14/stat") && !text.contains("self/status"),
        "{text}"
    );
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
    let mut times = Vec::new();
    let mut ignored = |_: libc::pid_t, signal: i32| {
        times.push((signal, Instant::now()));
        Ok(true)
    };
    let (grace, bound) = (Duration::from_millis(200), Duration::from_millis(400));
    let stop = super::GroupStop::new(grace, None, Some(bound), PAUSE).with_second_grace();
    let stopped = super::stop_with(&mut child, &stop, &mut ignored);
    let returned = Instant::now();
    let running = super::leader(child.id());
    child.kill().expect("the child is killed");
    child.wait().expect("the child is reaped");
    assert_eq!(
        stopped.expect("the stop runs"),
        super::GroupStopped::Running
    );
    assert_eq!(running.expect("the state reads"), super::Leader::Running);
    let signals: Vec<i32> = times.iter().map(|&(signal, _)| signal).collect();
    assert_eq!(signals, [libc::SIGTERM, libc::SIGKILL, libc::SIGKILL]);
    let second = times[2].1.saturating_duration_since(times[1].1);
    assert!(second >= grace, "the second grace lasted {second:?}");
    let reap = returned.saturating_duration_since(times[2].1);
    assert!(reap >= bound, "the reap waited {reap:?}");
}

/// A signal that fails after a wait outside the stop reaped the leader ends the stop with that error and
/// no further signal: the leader's id may by then name another group.
#[test]
fn a_failed_signal_after_a_reap_elsewhere_sends_no_further_signal() {
    let mut child = group_leader("exit 0");
    let pid = pid_of(&child);
    let state = super::leader_left_within(child.id(), WAIT, PAUSE, &|| false);
    assert_eq!(state.expect("the state reads"), super::Leader::Exited);
    let mut sent = Vec::new();
    let mut send = |_: libc::pid_t, signal: i32| {
        sent.push(signal);
        if signal == libc::SIGTERM {
            reap_outside(pid);
            return Err(std::io::Error::from_raw_os_error(libc::EPERM));
        }
        Ok(true)
    };
    let stop = super::GroupStop::new(WAIT, None, Some(WAIT), PAUSE);
    let error = super::stop_with(&mut child, &stop, &mut send).expect_err("the signal fails");
    assert_eq!(error.raw_os_error(), Some(libc::EPERM));
    assert_eq!(sent, [libc::SIGTERM]);
}

/// A signal that fails while the exited leader is held unreaped still sends SIGKILL to its group before
/// any wait, so a member that ignores SIGTERM is killed by the time the stop returns.
#[test]
fn a_failed_signal_while_the_leader_is_a_zombie_still_kills_its_group() {
    let scratch = crate::paths::tests::Scratch::new("zombie-group");
    let marker = scratch.0.join("member");
    let mut child = {
        use std::os::unix::process::CommandExt;
        Command::new("sh")
            .args([
                "-c",
                "trap '' TERM; sleep 600 & echo $! > \"$1.tmp\" && mv \"$1.tmp\" \"$1\"",
                "sh",
            ])
            .arg(&marker)
            .process_group(0)
            .spawn()
            .expect("the leader starts")
    };
    let pid = child.id();
    let state = super::leader_left_within(pid, WAIT, PAUSE, &|| false);
    assert_eq!(state.expect("the state reads"), super::Leader::Exited);
    let member: libc::pid_t = std::fs::read_to_string(&marker)
        .expect("the leader wrote its member")
        .trim()
        .parse()
        .expect("a process id");
    let mut sent = Vec::new();
    let mut send = |group: libc::pid_t, signal: i32| {
        sent.push((signal, super::leader(pid).expect("the state reads")));
        if signal == libc::SIGTERM {
            return Err(std::io::Error::from_raw_os_error(libc::EPERM));
        }
        super::signal_group(group, signal)
    };
    let stop = super::GroupStop::new(WAIT, None, Some(WAIT), PAUSE);
    let error = super::stop_with(&mut child, &stop, &mut send).expect_err("the signal fails");
    let ended = || {
        std::fs::read(format!("/proc/{member}/stat")).map_or(true, |stat| {
            let state = stat
                .iter()
                .rposition(|&byte| byte == b')')
                .map(|at| stat.get(at + 2));
            state == Some(Some(&b'Z'))
        })
    };
    let start = Instant::now();
    while !ended() && start.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(5));
    }
    let killed = ended();
    if !killed {
        // SAFETY: `kill` takes two integers and touches no memory of the caller.
        unsafe { libc::kill(member, libc::SIGKILL) };
    }
    assert_eq!(error.raw_os_error(), Some(libc::EPERM));
    assert_eq!(
        sent,
        [
            (libc::SIGTERM, super::Leader::Exited),
            (libc::SIGKILL, super::Leader::Exited)
        ]
    );
    assert!(killed, "the member {member} is killed");
    assert!(
        matches!(child.try_wait(), Ok(Some(status)) if status.code() == Some(0)),
        "the stop reaped the leader"
    );
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
    let reaped = !Path::new(&format!("/proc/{pid}")).exists();
    let status = child.try_wait();
    if !matches!(status, Ok(Some(_))) {
        let _ = child.kill();
        let _ = child.wait();
    }
    let error = stopped.expect_err("the child leads no group, so its state is refused");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert_eq!(sent, [(pid, libc::SIGKILL)]);
    assert!(reaped, "the stop reaped the child before it returned");
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
fn worker_group(marker: &Path, leader_ignores_term: bool) -> (std::process::Child, String) {
    let trap = if leader_ignores_term {
        "trap '' TERM; "
    } else {
        ""
    };
    let script = format!(
        "{trap}sh -c 'trap \"\" TERM; echo $$ > \"$1/worker\"; exec sleep 120' sh \"$1\" & \
         while [ ! -s \"$1/worker\" ]; do sleep 0.05; done; echo $$ > \"$1/leader\"; exec sleep 120"
    );
    let child = {
        use std::os::unix::process::CommandExt;
        Command::new("sh")
            .args(["-c", &script, "sh"])
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
/// running: the worker ignores SIGTERM, so only the SIGKILL ends it. Where the signal is recorded as the
/// stop begins the leader ignores SIGTERM too, so only the deliveries passing the spent ones end the 45 s
/// grace before 20 s; the stop reaps the leader.
#[test]
fn a_signal_during_the_stop_still_ends_the_whole_group() {
    for (at, spent) in [("stop", 0), ("stop", 1), ("kill", 0)] {
        let scratch = crate::paths::tests::Scratch::new("stop-signal");
        let (mut child, worker) = worker_group(&scratch.0, at == "stop");
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
        while running(&worker) && start.elapsed() < Duration::from_secs(30) {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            !running(&worker),
            "{at}, {spent}: the worker {} stays: {:?}",
            worker.trim(),
            std::fs::read_to_string(format!("/proc/{}/status", worker.trim()))
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

const BLOCKED_ROLE: &str = "KESTRIKE_PROCESS_BLOCKED_ROLE";

/// `pending` holds where `signal` is pending for the calling thread or the process.
fn pending(signal: i32) -> bool {
    // SAFETY: all-zero bytes are a valid `sigset_t`, which `sigpending` overwrites; `set` outlives both calls.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        assert_eq!(libc::sigpending(&mut set), 0);
        libc::sigismember(&set, signal) == 1
    }
}

/// `mask_holds` holds where `signal` is blocked in the calling thread.
fn mask_holds(signal: i32) -> bool {
    // SAFETY: a null new set makes `pthread_sigmask` only write the current mask into `set`, which all-zero
    // bytes initialize and which outlives the calls.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        assert_eq!(
            libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &mut set),
            0
        );
        libc::sigismember(&set, signal) == 1
    }
}

/// A SIGHUP sent to the thread while the handled signals are blocked stays pending and unrecorded, and the
/// handler records it once the mask is set back; the mask set back is the one the thread held before, so
/// SIGINT, blocked before, stays blocked. The handlers stand in this test executable started again in a
/// role with SIGHUP at its default, so the other tests keep their dispositions; the role's own exit code
/// tells its checks from a filter that matched no test.
#[test]
fn a_blocked_signal_is_recorded_once_the_mask_is_set_back() {
    if std::env::var_os(BLOCKED_ROLE).is_some() {
        super::install_handlers().expect("the handlers stand");
        // SAFETY: `sigemptyset` initializes the set before `sigaddset` and `pthread_sigmask` read it.
        unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGINT);
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()),
                0
            );
        }
        let inside = super::blocked(|| {
            // SAFETY: `pthread_kill` sends a signal to the calling thread, which runs.
            let sent = unsafe { libc::pthread_kill(libc::pthread_self(), libc::SIGHUP) };
            (
                sent,
                pending(libc::SIGHUP),
                super::INTERRUPT.deliveries(),
                mask_holds(libc::SIGHUP),
            )
        })
        .expect("the mask changes");
        let after = (
            super::INTERRUPT.deliveries(),
            super::INTERRUPT.recorded(),
            mask_holds(libc::SIGHUP),
            mask_holds(libc::SIGINT),
        );
        let held = inside == (0, true, 0, true) && after == (1, Some(libc::SIGHUP), false, true);
        if !held {
            eprintln!("inside the block {inside:?}, after it {after:?}");
        }
        std::process::exit(if held { 42 } else { 3 });
    }
    let name = module_path!()
        .split_once("::")
        .map_or("", |(_, rest)| rest)
        .to_owned()
        + "::a_blocked_signal_is_recorded_once_the_mask_is_set_back";
    let mut role = Command::new(std::env::current_exe().expect("the test executable"));
    role.args([name.as_str(), "--exact", "--nocapture", "--test-threads=1"])
        .env(BLOCKED_ROLE, "1");
    // SAFETY: the hook runs in the forked child before `exec` and calls only `signal`, `sigemptyset`,
    // `sigaddset` and `pthread_sigmask`, which are async-signal-safe, on a local set.
    unsafe {
        use std::os::unix::process::CommandExt;
        role.pre_exec(|| {
            libc::signal(libc::SIGHUP, libc::SIG_DFL);
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGHUP);
            libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
            Ok(())
        });
    }
    let status = role.status().expect("the role runs");
    assert_eq!(
        status.code(),
        Some(42),
        "the role ran and its checks held: {status:?}"
    );
}

/// A read of the state that fails while the exited child is held unreaped sends SIGKILL to the child's
/// group before the wait that reaps it, so no member outlives a stop that returns the read's error.
#[test]
fn a_failed_read_of_the_state_of_an_exited_child_kills_its_group_before_the_reap() {
    let mut child = Command::new("sh")
        .args(["-c", "exit 3"])
        .spawn()
        .expect("the child starts");
    let pid = pid_of(&child);
    let stat = format!("/proc/{pid}/stat");
    let zombie = || {
        std::fs::read(&stat).is_ok_and(|stat| {
            let close = stat.iter().rposition(|&byte| byte == b')');
            close.and_then(|at| stat.get(at + 2)) == Some(&b'Z')
        })
    };
    let start = Instant::now();
    while !zombie() && start.elapsed() < WAIT {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(zombie(), "the child exits within {WAIT:?}");
    let mut sent = Vec::new();
    let mut undelivered = |group: libc::pid_t, signal: i32| {
        sent.push((group, signal, zombie()));
        Ok(false)
    };
    let stop = super::GroupStop::new(WAIT, None, Some(WAIT), PAUSE);
    let stopped = super::stop_with(&mut child, &stop, &mut undelivered);
    let reaped = !Path::new(&stat).exists();
    let status = child.try_wait();
    let error = stopped.expect_err("the child leads no group, so its state is refused");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert_eq!(sent, [(pid, libc::SIGKILL, true)]);
    assert!(reaped, "the stop reaped the child before it returned");
    let status = status.expect("the wait runs").expect("the stop reaped it");
    assert_eq!(status.code(), Some(3));
}

/// Holds released out of the order they started end as nested holds do: the release that ends the last
/// standing hold reports the recorded signal, and the earlier release reports nothing.
#[test]
fn the_release_that_ends_the_last_hold_reports_the_signal() {
    let interrupt = Interrupt::new();
    let outer = interrupt.hold();
    let inner = interrupt.hold();
    interrupt.record(libc::SIGTERM);
    assert_eq!(outer.release(), Ok(()), "a hold still stands");
    assert!(interrupt.held());
    assert_eq!(inner.release(), Err(Interrupted(libc::SIGTERM)));
    assert!(!interrupt.held());
}

/// A body that panics under the block leaves the calling thread's mask as it was before the block.
#[test]
fn a_panic_under_the_block_sets_the_mask_back() {
    let before = mask_holds(libc::SIGHUP);
    let unwound = std::panic::catch_unwind(|| super::blocked(|| panic!("the body panics")));
    assert!(unwound.is_err());
    assert_eq!(mask_holds(libc::SIGHUP), before);
    assert!(!before, "the test thread starts with SIGHUP unblocked");
}

/// A wait whose cutoff has passed reads the leader's state once and returns at once, whatever budget a
/// fresh clock would grant, so a budget counted from an earlier reading adds no time back.
#[test]
fn a_wait_to_a_passed_cutoff_returns_at_once() {
    use std::os::unix::process::CommandExt;
    let mut child = Command::new("sleep")
        .arg("30")
        .process_group(0)
        .spawn()
        .expect("the child starts");
    let cutoff = Instant::now().checked_sub(Duration::from_secs(1));
    let start = Instant::now();
    let state = super::leader_left_by(child.id(), cutoff, PAUSE, &|| false);
    let took = start.elapsed();
    child.kill().expect("the child is killed");
    child.wait().expect("the child is reaped");
    assert_eq!(state.expect("the state reads"), super::Leader::Running);
    assert!(took < Duration::from_secs(1), "{took:?}");
}

/// A wait to a passed cutoff calls its step once and returns that step's `None` without consulting its
/// `ended` predicate.
#[test]
fn a_wait_to_a_passed_cutoff_calls_its_step_once() {
    let calls = std::cell::Cell::new(0);
    let cutoff = Instant::now().checked_sub(Duration::from_secs(1));
    let ended = || -> bool { panic!("the predicate is consulted past the cutoff") };
    let got: std::io::Result<Option<()>> = super::polled_until(cutoff, PAUSE, &ended, || {
        calls.set(calls.get() + 1);
        Ok(None)
    });
    assert!(matches!(got, Ok(None)), "{got:?}");
    assert_eq!(calls.get(), 1);
}
