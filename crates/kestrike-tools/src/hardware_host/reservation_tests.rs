//! Each case reserves its own scratch directory. A reservation taken again right after a holder drops
//! can meet a copy of the descriptor that another case's fork holds until its exec, so a case that
//! expects the lock free looks for it over a bounded time.

use std::os::unix::fs::symlink;
use std::path::Path;
use std::process::{Child, Command};
use std::thread;
use std::time::{Duration, Instant};

use super::reserve_host;
use crate::paths::tests::Scratch;

/// Whether a reservation of `directory` is taken within two seconds.
fn taken_soon(directory: &Path) -> bool {
    let end = Instant::now() + Duration::from_secs(2);
    loop {
        if reserve_host(directory).expect("the lock opens").is_some() {
            return true;
        }
        if Instant::now() >= end {
            return false;
        }
        thread::sleep(Duration::from_millis(10));
    }
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

/// A second holder of the host gets none while the first holds it, and the reservation is taken again
/// once the first drops.
#[test]
fn a_second_holder_gets_none() {
    let scratch = Scratch::new("reserve-second");
    let first = reserve_host(&scratch.0)
        .expect("the lock opens")
        .expect("the first holder takes it");
    assert!(reserve_host(&scratch.0).expect("the lock opens").is_none());
    drop(first);
    assert!(taken_soon(&scratch.0));
}

/// A child started with the reservation holds the lock after the parent's value drops, until the child
/// ends; a child started without it holds nothing once the parent's value drops.
#[test]
fn a_child_started_with_the_reservation_holds_it() {
    let scratch = Scratch::new("reserve-child");
    let reservation = reserve_host(&scratch.0)
        .expect("the lock opens")
        .expect("the reservation is taken");
    let child = Reaped(
        reservation
            .spawn_holding(sleeper())
            .expect("the child starts"),
    );
    drop(reservation);
    assert!(reserve_host(&scratch.0).expect("the lock opens").is_none());
    drop(child);
    assert!(taken_soon(&scratch.0));

    let reservation = reserve_host(&scratch.0)
        .expect("the lock opens")
        .expect("the reservation is taken");
    let _plain = Reaped(sleeper().spawn().expect("the child starts"));
    drop(reservation);
    assert!(taken_soon(&scratch.0));
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
