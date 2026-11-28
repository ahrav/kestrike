use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::Ordering;
use std::sync::{Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use super::{RECORD, Unwaited, wait};

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    let guard = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    RECORD.store(0, Ordering::SeqCst);
    guard
}

/// `pair` starts a leader that reads one line of its standard input and exits 0, in a process group of
/// its own, and then a `sleep 600` in that group as this process's own child, so the sleeper's end reads
/// from its own wait status while the leader still runs.
fn pair() -> (Child, Child) {
    let leader = Command::new("sh")
        .args(["-c", "read line; exit 0"])
        .process_group(0)
        .stdin(Stdio::piped())
        .spawn()
        .expect("the leader starts");
    let group = libc::pid_t::try_from(leader.id()).expect("a process id fits pid_t");
    let sleeper = Command::new("sleep")
        .arg("600")
        .process_group(group)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("the sleeper joins the leader's group");
    (leader, sleeper)
}

/// `end` closes the leader's standard input and returns once the leader has exited, leaving it unreaped.
fn end(leader: &mut Child) {
    drop(leader.stdin.take());
    let pid = libc::id_t::from(leader.id());
    // SAFETY: `info` is a zeroed `siginfo_t` that outlives the call, and `waitid` without `WNOHANG` returns
    // once the leader has exited.
    let status = unsafe {
        let mut info: libc::siginfo_t = std::mem::zeroed();
        libc::waitid(libc::P_PID, pid, &mut info, libc::WEXITED | libc::WNOWAIT)
    };
    assert_eq!(status, 0, "{}", std::io::Error::last_os_error());
}

/// `terminated` sends SIGTERM to `sleeper`, reaps it and returns the signal its status names. A sleeper
/// that an earlier SIGKILL ended names SIGKILL.
fn terminated(mut sleeper: Child) -> Option<i32> {
    let pid = libc::pid_t::try_from(sleeper.id()).expect("a process id fits pid_t");
    // SAFETY: `kill` takes only scalar arguments, and `sleeper` is this process's unreaped child.
    unsafe { libc::kill(pid, libc::SIGTERM) };
    sleeper.wait().expect("the sleeper is reaped").signal()
}

/// `stopped` waits up to ten seconds for `sleeper` to end and returns the signal its status names. A
/// sleeper still running then is killed and reaped, and `stopped` returns `None`.
fn stopped(mut sleeper: Child) -> Option<i32> {
    let start = Instant::now();
    loop {
        if let Some(status) = sleeper.try_wait().expect("the sleeper is polled") {
            return status.signal();
        }
        if start.elapsed() >= Duration::from_secs(10) {
            let _ = sleeper.kill();
            let _ = sleeper.wait();
            return None;
        }
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn an_ended_leader_with_a_record_has_its_group_stopped_before_the_reap() {
    let _serial = serial();
    let (mut child, sleeper) = pair();
    end(&mut child);
    RECORD.store(libc::SIGTERM, Ordering::SeqCst);
    let waited = wait(&mut child);
    RECORD.store(0, Ordering::SeqCst);
    let ended = stopped(sleeper);
    assert!(
        matches!(waited, Err(Unwaited::Cancelled(143))),
        "the wait is cancelled"
    );
    assert_eq!(
        ended,
        Some(libc::SIGKILL),
        "the sleeper the leader left ends"
    );
}

#[test]
fn an_ended_leader_without_a_record_is_reaped_and_its_group_left_running() {
    let _serial = serial();
    let (mut child, sleeper) = pair();
    end(&mut child);
    let waited = wait(&mut child);
    let ended = terminated(sleeper);
    assert!(
        waited.is_ok_and(|status| status.success()),
        "the leader's status is read"
    );
    assert_eq!(ended, Some(libc::SIGTERM), "wait sent the group no signal");
}

#[test]
fn a_leader_another_reaper_took_fails_the_wait_and_its_group_gets_no_signal() {
    let _serial = serial();
    let (mut child, sleeper) = pair();
    drop(child.stdin.take());
    let pid = libc::pid_t::try_from(child.id()).expect("a process id fits pid_t");
    // SAFETY: `waitpid` accepts a null status pointer to discard the status.
    assert_eq!(unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) }, pid);
    RECORD.store(libc::SIGTERM, Ordering::SeqCst);
    let waited = wait(&mut child);
    RECORD.store(0, Ordering::SeqCst);
    let ended = terminated(sleeper);
    assert!(
        matches!(&waited, Err(Unwaited::Failed(error)) if error.raw_os_error() == Some(libc::ECHILD)),
        "the poll fails with ECHILD"
    );
    assert_eq!(ended, Some(libc::SIGTERM), "wait sent the group no signal");
}

#[test]
fn a_running_leader_with_a_record_has_its_group_stopped() {
    let _serial = serial();
    let (mut child, sleeper) = pair();
    RECORD.store(libc::SIGTERM, Ordering::SeqCst);
    let waited = wait(&mut child);
    RECORD.store(0, Ordering::SeqCst);
    let ended = stopped(sleeper);
    assert!(
        matches!(waited, Err(Unwaited::Cancelled(143))),
        "the wait is cancelled"
    );
    assert_eq!(ended, Some(libc::SIGKILL), "the leader's sleeper ends");
}
