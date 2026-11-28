use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::atomic::Ordering;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use super::{RECORD, Unwaited, terminal, wait, waited};

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    let guard = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    RECORD.store(0, Ordering::SeqCst);
    guard
}

/// The longest a row waits for [`wait`] to return.
const LIMIT: Duration = Duration::from_secs(10);

/// `bounded` runs `waiting` on `child` on a thread of its own and returns the child and the result. Where
/// `waiting` has not returned within [`LIMIT`], `bounded` stores a record and closes `stdin`, the leader's
/// standard input that the row took, so a wait that reads the record or the leader's exit can return, and
/// then fails the row; a wait still running [`LIMIT`] later is left on its thread.
fn bounded(
    mut child: Child,
    stdin: Option<ChildStdin>,
    waiting: impl FnOnce(&mut Child) -> Result<ExitStatus, Unwaited> + Send + 'static,
) -> (Child, Result<ExitStatus, Unwaited>) {
    let (sent, received) = mpsc::channel();
    thread::spawn(move || {
        let result = waiting(&mut child);
        let _ = sent.send((child, result));
    });
    match received.recv_timeout(LIMIT) {
        Ok(returned) => returned,
        Err(RecvTimeoutError::Timeout) => {
            RECORD.store(libc::SIGTERM, Ordering::SeqCst);
            drop(stdin);
            let released = received.recv_timeout(LIMIT).is_ok();
            panic!(
                "the wait did not return within {LIMIT:?}; it returned once released: {released}"
            );
        }
        Err(RecvTimeoutError::Disconnected) => panic!("the wait panicked"),
    }
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

/// The order of the group's SIGKILL before the leader's reap is held by `stop`'s code; this row observes
/// that the group of an ended, unreaped leader gets SIGKILL on a record.
#[test]
fn an_ended_unreaped_leader_with_a_record_has_its_group_stopped() {
    let _serial = serial();
    let (mut child, sleeper) = pair();
    end(&mut child);
    RECORD.store(libc::SIGTERM, Ordering::SeqCst);
    let (_child, waited) = bounded(child, None, |child| wait(child, || true));
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
    let (_child, waited) = bounded(child, None, |child| wait(child, || true));
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
    let (_child, waited) = bounded(child, None, |child| wait(child, || true));
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
    let stdin = child.stdin.take();
    RECORD.store(libc::SIGTERM, Ordering::SeqCst);
    let (_child, waited) = bounded(child, stdin, |child| wait(child, || true));
    RECORD.store(0, Ordering::SeqCst);
    let ended = stopped(sleeper);
    assert!(
        matches!(waited, Err(Unwaited::Cancelled(143))),
        "the wait is cancelled"
    );
    assert_eq!(ended, Some(libc::SIGKILL), "the leader's sleeper ends");
}

#[test]
fn a_failed_probe_other_than_echild_stops_the_group_and_reaps_the_leader() {
    let _serial = serial();
    let (child, sleeper) = pair();
    let stdin = None::<ChildStdin>;
    let (mut child, waited) = bounded(child, stdin, |child| {
        waited(
            child,
            |_| Err(std::io::Error::from_raw_os_error(libc::EPERM)),
            || true,
        )
    });
    let ended = stopped(sleeper);
    assert!(
        matches!(&waited, Err(Unwaited::Failed(error)) if error.raw_os_error() == Some(libc::EPERM)),
        "the probe's error is the wait's"
    );
    assert_eq!(ended, Some(libc::SIGKILL), "the leader's sleeper ends");
    assert!(
        child.try_wait().is_ok_and(|status| status.is_some()),
        "the leader is reaped"
    );
}

#[test]
fn a_failed_probe_with_a_record_is_cancelled() {
    let _serial = serial();
    let (child, sleeper) = pair();
    RECORD.store(libc::SIGTERM, Ordering::SeqCst);
    let (_child, waited) = bounded(child, None, |child| {
        waited(
            child,
            |_| Err(std::io::Error::from_raw_os_error(libc::EINVAL)),
            || true,
        )
    });
    RECORD.store(0, Ordering::SeqCst);
    let ended = stopped(sleeper);
    assert!(
        matches!(waited, Err(Unwaited::Cancelled(143))),
        "the wait is cancelled"
    );
    assert_eq!(ended, Some(libc::SIGKILL), "the leader's sleeper ends");
}

#[test]
fn an_ended_leader_is_reaped_only_once_its_predicate_holds() {
    let _serial = serial();
    let (mut child, sleeper) = pair();
    end(&mut child);
    let (_child, waited) = bounded(child, None, |child| {
        let mut asked = 0;
        let status = wait(child, || {
            asked += 1;
            asked == 3
        });
        assert_eq!(asked, 3, "the predicate is asked until it holds");
        status
    });
    let ended = terminated(sleeper);
    assert!(
        waited.is_ok_and(|status| status.success()),
        "the leader's status is read"
    );
    assert_eq!(ended, Some(libc::SIGTERM), "wait sent the group no signal");
}

#[test]
fn a_record_while_the_predicate_does_not_hold_stops_the_group() {
    let _serial = serial();
    let (mut child, sleeper) = pair();
    end(&mut child);
    let (_child, waited) = bounded(child, None, |child| {
        let mut asked = 0;
        wait(child, || {
            asked += 1;
            if asked == 2 {
                RECORD.store(libc::SIGTERM, Ordering::SeqCst);
            }
            false
        })
    });
    RECORD.store(0, Ordering::SeqCst);
    let ended = stopped(sleeper);
    assert!(
        matches!(waited, Err(Unwaited::Cancelled(143))),
        "the wait is cancelled"
    );
    assert_eq!(ended, Some(libc::SIGKILL), "the leader's sleeper ends");
}

#[test]
fn a_leader_killed_by_a_signal_without_a_record_is_reaped_and_its_group_left_running() {
    let _serial = serial();
    let (child, sleeper) = pair();
    let pid = libc::pid_t::try_from(child.id()).expect("a process id fits pid_t");
    // SAFETY: `kill` takes only scalar arguments, and the leader is this process's unreaped child.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGUSR1) }, 0);
    let (_child, waited) = bounded(child, None, |child| wait(child, || true));
    let ended = terminated(sleeper);
    assert_eq!(
        waited.ok().and_then(|status| status.signal()),
        Some(libc::SIGUSR1),
        "the leader's status names its signal"
    );
    assert_eq!(ended, Some(libc::SIGTERM), "wait sent the group no signal");
}

#[test]
fn only_an_exit_or_a_death_by_signal_ends_a_leader() {
    for (code, ends) in [
        (libc::CLD_EXITED, true),
        (libc::CLD_KILLED, true),
        (libc::CLD_DUMPED, true),
        (libc::CLD_STOPPED, false),
        (libc::CLD_TRAPPED, false),
        (libc::CLD_CONTINUED, false),
    ] {
        assert_eq!(terminal(code), ends, "si_code {code}");
    }
}

/// `pipe` returns the read and write ends of a new pipe.
fn pipe() -> (std::os::fd::OwnedFd, std::os::fd::OwnedFd) {
    let mut ends = [0; 2];
    // SAFETY: `pipe` writes two descriptors into `ends`, which outlives the call.
    assert_eq!(unsafe { libc::pipe(ends.as_mut_ptr()) }, 0);
    // SAFETY: each descriptor is open and owned by nothing else.
    unsafe {
        use std::os::fd::FromRawFd;
        (
            std::os::fd::OwnedFd::from_raw_fd(ends[0]),
            std::os::fd::OwnedFd::from_raw_fd(ends[1]),
        )
    }
}

/// `nonblocking` sets or clears `O_NONBLOCK` on the row's own descriptor `fd`.
fn nonblocking(fd: &std::os::fd::OwnedFd, set: bool) {
    use std::os::fd::AsRawFd;
    // SAFETY: `fcntl` takes the open descriptor and integer flags.
    unsafe {
        let flags = libc::fcntl(fd.as_raw_fd(), libc::F_GETFL);
        let flags = if set {
            flags | libc::O_NONBLOCK
        } else {
            flags & !libc::O_NONBLOCK
        };
        assert_eq!(libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags), 0);
    }
}

/// `drained` reads every byte `read` holds now, through a nonblocking read end.
fn drained(read: &std::os::fd::OwnedFd) -> usize {
    use std::io::Read;
    nonblocking(read, true);
    let mut file = std::fs::File::from(read.try_clone().expect("the read end is duplicated"));
    let mut total = 0;
    let mut buffer = [0u8; 4096];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => return total,
            Ok(read) => total += read,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return total,
            Err(error) => panic!("the pipe is read: {error}"),
        }
    }
}

/// On Linux a pipe takes a write while one of its buffer slots is free. The row fills every slot, frees
/// one, and writes a line of three slices with a record stored: the first slice takes the free slot, and
/// the wait before the second ends on the record while the pipe's reader stays open and unread.
#[cfg(target_os = "linux")]
#[test]
fn a_recorded_signal_ends_the_wait_for_room_between_slices_of_a_line() {
    use std::io::{Read, Write};
    use std::os::fd::AsFd;
    let _serial = serial();
    let (read, write) = pipe();
    nonblocking(&write, true);
    let mut writer = std::fs::File::from(write.try_clone().expect("the write end is duplicated"));
    let mut filled = 0;
    loop {
        match writer.write(&[b'x'; 4096]) {
            Ok(written) => filled += written,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => panic!("the pipe is filled: {error}"),
        }
    }
    nonblocking(&write, false);
    let mut page = [0u8; 4096];
    std::fs::File::from(read.try_clone().expect("the read end is duplicated"))
        .read_exact(&mut page)
        .expect("one slot is freed");
    RECORD.store(libc::SIGTERM, Ordering::SeqCst);
    let line = "y".repeat(1200);
    let (sent, received) = mpsc::channel();
    let stream = write.try_clone().expect("the write end is duplicated");
    thread::spawn(move || {
        let _ = sent.send(super::super::said(stream.as_fd(), &line));
    });
    let said = received.recv_timeout(LIMIT);
    RECORD.store(0, Ordering::SeqCst);
    assert_eq!(said, Ok(Err(143)), "the wait for the second slice ends");
    assert_eq!(
        drained(&read),
        filled - 4096 + super::super::SLICE,
        "the first slice alone is written"
    );
}

#[test]
fn a_stream_with_room_takes_a_line_with_a_record_stored() {
    use std::os::fd::AsFd;
    let _serial = serial();
    let (read, write) = pipe();
    RECORD.store(libc::SIGTERM, Ordering::SeqCst);
    let said = super::super::said(write.as_fd(), &format!("{}\n", "é".repeat(400)));
    RECORD.store(0, Ordering::SeqCst);
    assert_eq!(said, Ok(()), "the line is written");
    assert_eq!(drained(&read), 801, "every byte is written");
}

#[test]
fn a_stream_without_a_reader_fails_the_line_with_120() {
    use std::os::fd::AsFd;
    let _serial = serial();
    let (read, write) = pipe();
    drop(read);
    assert_eq!(super::super::said(write.as_fd(), "line\n"), Err(120));
}

#[test]
fn a_record_stored_by_the_time_a_failure_line_is_written_outranks_its_code() {
    let _serial = serial();
    RECORD.store(libc::SIGHUP, Ordering::SeqCst);
    let failed = super::super::fail("pre-push: a failure line of a unit row", 2);
    RECORD.store(0, Ordering::SeqCst);
    assert_eq!(failed, 129);
    assert_eq!(
        super::super::fail("pre-push: a failure line of a unit row", 2),
        2
    );
}

#[test]
fn a_failed_batch_read_is_refused_with_exit_1() {
    let _serial = serial();
    let failure = crate::hook::Failure::Git(crate::git::GitError::Io(std::io::Error::other(
        "a batch read of a unit row",
    )));
    assert_eq!(super::super::refused(&failure), 1);
}

/// Git that cannot start for a reason that is no system error, as the standard library reports an
/// argument it refuses, is a refusal of the push and not a failed step of the tool's own.
#[test]
fn a_start_error_with_no_system_code_is_refused_with_exit_2() {
    let _serial = serial();
    let failure = crate::hook::Failure::Git(crate::git::GitError::Start(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "a start error of a unit row",
    )));
    assert_eq!(super::super::refused(&failure), 2);
}

/// A signal recorded by the time the scratch parent's status is read outranks what the read gave: a
/// parent that passes, one that is refused and one whose status cannot be read each end as cancelled
/// with the signal's code, and with no record each gives its own result.
#[test]
fn a_record_outranks_every_result_of_the_scratch_parent_s_read() {
    use std::os::unix::fs::PermissionsExt;

    use super::super::worktree::{Exposure, Unusable, checked};
    let _serial = serial();
    let scratch = crate::paths::tests::Scratch::new("scratch-parent");
    let (private, shared, closed) = (
        scratch.0.join("private"),
        scratch.0.join("shared"),
        scratch.0.join("closed"),
    );
    for (directory, mode) in [(&private, 0o700), (&shared, 0o777), (&closed, 0o000)] {
        std::fs::create_dir(directory).expect("the directory is made");
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(mode))
            .expect("the mode is set");
    }
    let unread = closed.join("below");
    // SAFETY: `geteuid` takes no argument and touches no memory.
    let root = unsafe { libc::geteuid() } == 0;
    let results = |recorded: bool| {
        RECORD.store(if recorded { libc::SIGTERM } else { 0 }, Ordering::SeqCst);
        let results = [&private, &shared, &unread].map(|path| checked(path.as_os_str()));
        RECORD.store(0, Ordering::SeqCst);
        results
    };
    let [passed, refused, faulted] = results(false);
    assert_eq!(passed, Ok(private.clone()));
    assert_eq!(
        refused,
        Err(Unusable::Exposed {
            parent: shared.clone(),
            at: shared.clone(),
            exposure: Exposure::Writable
        })
    );
    if !root {
        assert!(matches!(faulted, Err(Unusable::Fault(_))), "{faulted:?}");
    }
    for result in results(true) {
        assert_eq!(result, Err(Unusable::Cancelled(143)));
    }
    std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o700))
        .expect("the mode is restored");
}
