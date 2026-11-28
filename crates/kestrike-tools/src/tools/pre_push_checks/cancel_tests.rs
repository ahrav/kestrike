use std::io::{BufRead, BufReader};
use std::os::unix::process::CommandExt;
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

fn leader(script: &str) -> (Child, libc::pid_t) {
    let mut child = Command::new("sh")
        .args(["-c", script])
        .process_group(0)
        .stdout(Stdio::piped())
        .spawn()
        .expect("the leader starts");
    let mut line = String::new();
    BufReader::new(child.stdout.take().expect("standard output is piped"))
        .read_line(&mut line)
        .expect("the leader prints its sleeper");
    let sleeper = line.trim().parse().expect("the line holds a process id");
    (child, sleeper)
}

fn exited(child: &Child) {
    let pid = libc::id_t::from(child.id());
    // SAFETY: `info` is a zeroed `siginfo_t` that outlives the call, and `waitid` fills it.
    let status = unsafe {
        let mut info: libc::siginfo_t = std::mem::zeroed();
        libc::waitid(libc::P_PID, pid, &mut info, libc::WEXITED | libc::WNOWAIT)
    };
    assert_eq!(status, 0, "{}", std::io::Error::last_os_error());
}

fn alive(pid: libc::pid_t) -> bool {
    // SAFETY: `waitpid` accepts a null status pointer to discard the status; `kill` takes only scalar
    // arguments.
    unsafe {
        libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG);
        libc::kill(pid, 0) == 0
    }
}

fn gone(pid: libc::pid_t) -> bool {
    let start = Instant::now();
    while alive(pid) {
        if start.elapsed() >= Duration::from_secs(10) {
            return false;
        }
        thread::sleep(Duration::from_millis(5));
    }
    true
}

fn kill(pid: libc::pid_t) {
    // SAFETY: `kill` takes only scalar arguments.
    unsafe { libc::kill(pid, libc::SIGKILL) };
    assert!(gone(pid), "the sleeper {pid} ends");
}

#[test]
fn an_ended_leader_with_a_record_has_its_group_stopped_before_the_reap() {
    let _serial = serial();
    let (mut child, sleeper) = leader("sleep 600 & echo $!");
    exited(&child);
    RECORD.store(libc::SIGTERM, Ordering::SeqCst);
    let waited = wait(&mut child);
    RECORD.store(0, Ordering::SeqCst);
    assert!(
        matches!(waited, Err(Unwaited::Cancelled(143))),
        "the wait is cancelled"
    );
    assert!(gone(sleeper), "the sleeper the leader left ends");
}

#[test]
fn an_ended_leader_without_a_record_is_reaped_and_its_group_left_running() {
    let _serial = serial();
    let (mut child, sleeper) = leader("sleep 600 & echo $!");
    exited(&child);
    let waited = wait(&mut child);
    let running = alive(sleeper);
    kill(sleeper);
    assert!(
        waited.is_ok_and(|status| status.success()),
        "the leader's status is read"
    );
    assert!(running, "the sleeper the leader left runs on");
}

#[test]
fn a_leader_another_reaper_took_fails_the_wait_and_its_group_gets_no_signal() {
    let _serial = serial();
    let (mut child, sleeper) = leader("sleep 600 & echo $!");
    let pid = libc::pid_t::try_from(child.id()).expect("a process id fits pid_t");
    // SAFETY: `waitpid` accepts a null status pointer to discard the status.
    assert_eq!(unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) }, pid);
    RECORD.store(libc::SIGTERM, Ordering::SeqCst);
    let waited = wait(&mut child);
    RECORD.store(0, Ordering::SeqCst);
    let running = alive(sleeper);
    kill(sleeper);
    assert!(
        matches!(&waited, Err(Unwaited::Failed(error)) if error.raw_os_error() == Some(libc::ECHILD)),
        "the poll fails with ECHILD"
    );
    assert!(running, "the sleeper of the reaped leader runs on");
}

#[test]
fn a_running_leader_with_a_record_has_its_group_stopped() {
    let _serial = serial();
    let (mut child, sleeper) = leader("sleep 600 & echo $!; wait");
    RECORD.store(libc::SIGTERM, Ordering::SeqCst);
    let waited = wait(&mut child);
    RECORD.store(0, Ordering::SeqCst);
    assert!(
        matches!(waited, Err(Unwaited::Cancelled(143))),
        "the wait is cancelled"
    );
    assert!(gone(sleeper), "the leader's sleeper ends");
}
