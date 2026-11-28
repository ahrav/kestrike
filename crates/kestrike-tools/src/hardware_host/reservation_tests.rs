//! Each case reserves its own scratch directory. A reservation taken again right after a holder drops
//! can meet a copy of the descriptor that another case's fork holds until its exec, so a case that
//! expects the lock free looks for it over a bounded time, and each attempt expected to be refused runs
//! under [`within`], so a blocking lock fails the case where it would hang the run.

use std::ffi::OsStr;
use std::fs;
use std::io::{BufRead, BufReader};
use std::os::fd::AsRawFd;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use super::{Reservation, reserve_host};
use crate::hardware_host::within::within;
use crate::hardware_host::{Observer, ObserverError, System};
use crate::host_stop::{Delivered, Record};
use crate::json::{Object, Text};
use crate::paths::tests::Scratch;

/// The reservation of `directory` taken within two seconds, or none.
fn taken_soon(directory: &Path) -> Option<Reservation> {
    let end = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(reservation) = reserve_host(directory).expect("the lock opens") {
            return Some(reservation);
        }
        if Instant::now() >= end {
            return None;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

/// Whether an attempt at the reservation of `directory`, run under [`within`], is refused.
fn refused(directory: &Path) -> bool {
    let directory = directory.to_owned();
    within("an attempt at the reservation", move || {
        reserve_host(&directory).expect("the lock opens").is_none()
    })
}

/// A child that is killed and reaped when the value drops.
struct Reaped(Child);

impl Drop for Reaped {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn sleeper() -> Command {
    let mut command = Command::new("/usr/bin/sleep");
    command.arg("60");
    command
}

/// The close-on-exec flag of descriptor `fd` of process `pid`, from its `fdinfo` record.
fn cloexec(pid: &str, fd: i32) -> bool {
    let fdinfo = fs::read_to_string(format!("/proc/{pid}/fdinfo/{fd}"))
        .expect("the process holds the descriptor");
    let flags = fdinfo
        .lines()
        .find_map(|line| line.strip_prefix("flags:"))
        .and_then(|flags| u32::from_str_radix(flags.trim(), 8).ok())
        .expect("the record names the flags");
    flags & libc::O_CLOEXEC as u32 != 0
}

/// A second holder of the host gets none while the first holds it, and the reservation is taken again
/// once the first drops.
#[test]
fn a_second_holder_gets_none() {
    let scratch = Scratch::new("reserve-second");
    let first = reserve_host(&scratch.0)
        .expect("the lock opens")
        .expect("the first holder takes it");
    assert!(refused(&scratch.0));
    drop(first);
    assert!(taken_soon(&scratch.0).is_some());
}

/// A child started with the reservation holds the lock after the parent's value drops, until the child
/// ends, while the parent's own descriptor keeps its close-on-exec flag; a child started without it
/// holds nothing once the parent's value drops.
#[test]
fn a_child_started_with_the_reservation_holds_it() {
    let scratch = Scratch::new("reserve-child");
    let reservation = reserve_host(&scratch.0)
        .expect("the lock opens")
        .expect("the reservation is taken");
    let fd = reservation.file.as_raw_fd();
    let child = Reaped(
        reservation
            .spawn_holding(sleeper())
            .expect("the child starts"),
    );
    assert!(!cloexec(&child.0.id().to_string(), fd));
    assert!(cloexec("self", fd));
    drop(reservation);
    assert!(refused(&scratch.0));
    thread::sleep(Duration::from_millis(200));
    assert!(refused(&scratch.0));
    drop(child);
    let reservation = taken_soon(&scratch.0).expect("the reservation frees with the child");

    let _plain = Reaped(sleeper().spawn().expect("the child starts"));
    drop(reservation);
    assert!(taken_soon(&scratch.0).is_some());
}

/// A link at the lock's name and an absent directory refuse the open.
#[test]
fn a_failed_open_passes_out() {
    let scratch = Scratch::new("reserve-open");
    symlink("elsewhere", scratch.0.join("fis.lock")).expect("linked");
    let error = reserve_host(&scratch.0).expect_err("the link is refused");
    assert_eq!(error.raw_os_error(), Some(libc::ELOOP));
    assert!(!scratch.0.join("elsewhere").exists());
    let error = reserve_host(&scratch.0.join("absent")).expect_err("no directory");
    assert_eq!(error.raw_os_error(), Some(libc::ENOENT));
}

/// A child Python that holds `fcntl.flock(LOCK_EX)` of `path` from the line it prints until it is
/// killed and reaped.
fn python_holder(path: &Path) -> Reaped {
    let mut child = Command::new("/usr/bin/python3")
        .args([
            "-c",
            "import fcntl, sys, time\n\
             f = open(sys.argv[1], 'a')\n\
             fcntl.flock(f, fcntl.LOCK_EX)\n\
             print('held', flush=True)\n\
             time.sleep(60)",
        ])
        .arg(path)
        .stdout(Stdio::piped())
        .spawn()
        .expect("python3 starts");
    let stdout = child.stdout.take().expect("a pipe");
    let holder = Reaped(child);
    let mut line = String::new();
    BufReader::new(stdout)
        .read_line(&mut line)
        .expect("the holder's line reads");
    assert_eq!(line, "held\n");
    holder
}

fn observer(directory: &Path, limit: Duration) -> Observer {
    Observer::new(
        directory.as_os_str(),
        OsStr::new("e"),
        Text::from("prof"),
        Text::from("fis"),
        limit,
    )
}

fn append(directory: PathBuf, limit: Duration) -> Result<Option<Object>, ObserverError> {
    within("an append", move || {
        let delivered = Delivered::new();
        let mut record = Record::new(&delivered);
        observer(&directory, limit).append(&mut System, &mut record, "x", Object::new())
    })
}

/// A `flock` that another program takes through `flock(2)`, a Python child here, refuses the
/// reservation and holds off an append until its limit, and each is taken once that holder ends.
#[test]
fn a_lock_another_program_holds_excludes_the_reservation_and_the_append() {
    let scratch = Scratch::new("reserve-python");
    let lock = python_holder(&scratch.0.join("fis.lock"));
    assert!(refused(&scratch.0));
    drop(lock);
    assert!(taken_soon(&scratch.0).is_some());

    let log = python_holder(&scratch.0.join("e.jsonl"));
    assert!(matches!(
        append(scratch.0.clone(), Duration::from_millis(200)),
        Err(ObserverError::Held { .. })
    ));
    assert_eq!(
        fs::read_to_string(scratch.0.join("e.jsonl")).expect("reads"),
        ""
    );
    drop(log);
    append(scratch.0.clone(), Duration::from_secs(5))
        .expect("the append succeeds once the holder ends")
        .expect("a log stands");
}
