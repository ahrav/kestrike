use std::cell::{Cell, RefCell};
use std::fs::{self, File};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;
use std::time::Duration;

use super::{Clock, FIRST_PAUSE, LONGEST_PAUSE, Unheld, attempt, open, waited};
use crate::paths::tests::Scratch;

struct Stepped<'a> {
    now: Duration,
    pauses: Vec<Duration>,
    at_pause: Box<dyn FnMut(usize) + 'a>,
}

impl<'a> Stepped<'a> {
    fn new(at_pause: impl FnMut(usize) + 'a) -> Self {
        Self {
            now: Duration::ZERO,
            pauses: Vec::new(),
            at_pause: Box::new(at_pause),
        }
    }
}

impl Clock for Stepped<'_> {
    fn elapsed(&self) -> Duration {
        self.now
    }

    fn pause(&mut self, span: Duration) {
        (self.at_pause)(self.pauses.len());
        self.pauses.push(span);
        self.now += span;
    }
}

fn holder(path: &Path) -> File {
    let file = open(path).expect("the lock file opens");
    assert_eq!(attempt(&file).ok(), Some(true), "the lock is free");
    file
}

fn running() -> Result<(), u8> {
    Ok(())
}

fn unlock(file: &File) {
    // SAFETY: `flock` takes an open descriptor and integer flags and touches no memory of the caller.
    assert_eq!(unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) }, 0);
}

fn freed(file: &File) -> bool {
    let start = std::time::Instant::now();
    loop {
        if attempt(file).ok() == Some(true) {
            return true;
        }
        if start.elapsed() >= Duration::from_secs(10) {
            return false;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn a_lock_that_stays_held_is_refused_once_the_limit_has_passed_since_the_first_attempt() {
    let scratch = Scratch::new("lock-limit");
    let path = scratch.0.join("lock");
    let _held = holder(&path);
    let waiter = open(&path).expect("the lock file opens again");
    let limit = Duration::from_millis(1_000);
    let notes = Cell::new(0);
    let mut clock = Stepped::new(|_| {});
    let refused = waited(&waiter, &path, limit, &mut clock, running, || {
        notes.set(notes.get() + 1);
        Ok(())
    });
    assert_eq!(
        refused,
        Err(Unheld::Refused(format!(
            "another push held the lock {} for 1 seconds",
            path.display()
        )))
    );
    assert_eq!(notes.get(), 1);
    assert_eq!(clock.pauses.iter().sum::<Duration>(), limit);
    assert_eq!(clock.pauses[0], FIRST_PAUSE);
    assert_eq!(clock.pauses[1], FIRST_PAUSE * 2);
    assert!(clock.pauses.contains(&LONGEST_PAUSE), "{:?}", clock.pauses);
    assert!(
        clock.pauses.iter().all(|pause| *pause <= LONGEST_PAUSE),
        "{:?}",
        clock.pauses
    );
}

#[test]
fn a_lock_released_during_the_wait_is_taken_and_held_until_its_descriptor_closes() {
    let scratch = Scratch::new("lock-release");
    let path = scratch.0.join("lock");
    let held = RefCell::new(Some(holder(&path)));
    let waiter = open(&path).expect("the lock file opens again");
    let mut clock = Stepped::new(|index| {
        if index == 3 {
            unlock(
                &held
                    .borrow_mut()
                    .take()
                    .expect("the holder is released once"),
            );
        }
    });
    let limit = Duration::from_secs(600);
    let taken = waited(&waiter, &path, limit, &mut clock, running, running);
    assert_eq!(taken, Ok(()));
    assert_eq!(clock.pauses.len(), 4, "{:?}", clock.pauses);
    let third = open(&path).expect("the lock file opens a third time");
    assert_eq!(
        attempt(&third).ok(),
        Some(false),
        "the waiter holds the lock"
    );
    drop(waiter);
    assert!(freed(&third), "the close released it");
    unlock(&third);
    let free = open(&path).expect("the lock file opens");
    let mut clock = Stepped::new(|_| {});
    let noted = Cell::new(false);
    let taken = waited(&free, &path, limit, &mut clock, running, || {
        noted.set(true);
        Ok(())
    });
    assert_eq!(taken, Ok(()));
    assert!(clock.pauses.is_empty() && !noted.get());
}

#[test]
fn a_recorded_signal_or_a_failed_note_ends_the_wait_before_any_pause() {
    let scratch = Scratch::new("lock-cancel");
    let path = scratch.0.join("lock");
    let _held = holder(&path);
    let waiter = open(&path).expect("the lock file opens again");
    let limit = Duration::from_secs(600);
    let mut clock = Stepped::new(|_| {});
    let noted = Cell::new(false);
    let cancelled = waited(
        &waiter,
        &path,
        limit,
        &mut clock,
        || Err(143),
        || {
            noted.set(true);
            Ok(())
        },
    );
    assert_eq!(cancelled, Err(Unheld::Cancelled(143)));
    assert!(!noted.get() && clock.pauses.is_empty());
    let signal = Cell::new(0);
    let during = waited(
        &waiter,
        &path,
        limit,
        &mut clock,
        || match signal.get() {
            0 => Ok(()),
            code => Err(code),
        },
        || {
            signal.set(130);
            Err(120)
        },
    );
    assert_eq!(during, Err(Unheld::Cancelled(130)));
    let unsaid = waited(&waiter, &path, limit, &mut clock, running, || Err(120));
    assert_eq!(unsaid, Err(Unheld::Unsaid(120)));
    assert!(clock.pauses.is_empty());
}

#[test]
fn the_open_uses_a_regular_file_as_it_stands_and_refuses_a_link_and_any_other_entry() {
    let scratch = Scratch::new("lock-open");
    let path = scratch.0.join("lock");
    let made = open(&path).expect("an absent lock file is made");
    let mode = made.metadata().expect("the status reads").permissions();
    assert_eq!(mode.mode() & 0o7177, 0, "{:o}", mode.mode());
    // SAFETY: `fcntl` with `F_GETFD` reads the flags of an open descriptor.
    let flags = unsafe { libc::fcntl(made.as_raw_fd(), libc::F_GETFD) };
    assert_ne!(flags & libc::FD_CLOEXEC, 0, "the descriptor closes on exec");
    drop(made);
    fs::write(&path, "kept\n").expect("the file is written");
    drop(open(&path).expect("a standing lock file opens"));
    assert_eq!(fs::read(&path).expect("the file reads"), b"kept\n");
    let shown = |name: &str| scratch.0.join(name).display().to_string();
    symlink(&path, scratch.0.join("link")).expect("the link is made");
    symlink("absent", scratch.0.join("dangling")).expect("the link is made");
    fs::create_dir(scratch.0.join("directory")).expect("the directory is made");
    let fifo = std::ffi::CString::new(shown("fifo")).expect("the path holds no NUL");
    // SAFETY: `mkfifo` reads the NUL-terminated path, which outlives the call.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    for (name, state) in [
        ("link", "is a link"),
        ("dangling", "is a link"),
        ("directory", "is no regular file"),
        ("fifo", "is no regular file"),
    ] {
        assert_eq!(
            open(&scratch.0.join(name)).err(),
            Some(Unheld::Refused(format!("the lock {} {state}", shown(name)))),
            "{name}"
        );
    }
    assert!(
        !scratch.0.join("absent").exists(),
        "a dangling link's target is not made"
    );
    fs::set_permissions(&scratch.0, fs::Permissions::from_mode(0o500)).expect("the mode is set");
    let sealed = open(&scratch.0.join("new"));
    fs::set_permissions(&scratch.0, fs::Permissions::from_mode(0o700)).expect("the mode is set");
    if crate::ownership::real_uid() != 0 {
        assert!(
            matches!(&sealed, Err(Unheld::Fault(text)) if text.starts_with(&shown("new"))),
            "{sealed:?}"
        );
    }
}
