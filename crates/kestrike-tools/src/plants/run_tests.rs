//! `listed` splits the listing at a form feed as at a line feed, so a worktree path that holds a form
//! feed matches no line of `git worktree list --porcelain`.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;

use super::{listed, lock_bytes, open_lock};

/// The listing is split at each of Python's line breaks, a form feed included, so a worktree whose path
/// holds a form feed matches no line, while the plain path matches its line.
#[test]
fn a_listed_path_with_a_form_feed_matches_no_line() {
    let plain = Path::new("/work/plants/p-a/tree");
    assert!(listed("worktree /work/plants/p-a/tree\nHEAD 0\n", plain));
    let fed = Path::new("/work/plants/p-\u{c}a/tree");
    assert!(!listed(
        "worktree /work/plants/p-\u{c}a/tree\nHEAD 0\n",
        fed
    ));
}

/// The lockfile check opens a FIFO with no writer without blocking, refuses a link, and reads a file of
/// a tebibyte's length only one byte past the run's lockfile.
#[test]
fn the_lockfile_check_reads_one_regular_file_through_one_descriptor_and_a_bound() {
    let scratch = crate::paths::tests::Scratch::new("lock-check");
    let lock = b"# the run's resolution\n";
    let fifo = scratch.0.join("fifo");
    let name = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).expect("a name");
    // SAFETY: `name` is a NUL-terminated path that outlives the call.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    let (sent, opened) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = sent.send(open_lock(&fifo).and_then(|file| lock_bytes(file, lock)));
    });
    let read = opened
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("the open of a FIFO with no writer returns within 10 s");
    assert_eq!(read.expect("its status reads"), None);
    let regular = scratch.0.join("regular");
    std::fs::write(&regular, lock).expect("written");
    let link = scratch.0.join("link");
    std::os::unix::fs::symlink(&regular, &link).expect("linked");
    assert_eq!(
        open_lock(&link)
            .expect_err("a link is refused")
            .raw_os_error(),
        Some(libc::ELOOP)
    );
    let read = lock_bytes(open_lock(&regular).expect("opens"), lock).expect("reads");
    assert_eq!(read.as_deref(), Some(&lock[..]));
    let long = scratch.0.join("long");
    std::fs::File::create(&long)
        .and_then(|file| file.set_len(1 << 40))
        .expect("a sparse file is made");
    let read = lock_bytes(open_lock(&long).expect("opens"), lock).expect("reads");
    assert_eq!(read.map(|bytes| bytes.len()), Some(lock.len() + 1));
}

/// `Opens` watches one file for opens. An `exec` of the file opens it, and the start of a child returns
/// only after that `exec`, so the queue shows every start of the file, also the start of a child that a
/// signal kills before it runs an instruction.
struct Opens(OwnedFd);

impl Opens {
    fn of(path: &Path) -> Self {
        let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).expect("a name");
        // SAFETY: the call takes two flags and no pointer.
        let queue = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        assert!(queue >= 0, "the kernel grants an inotify instance");
        // SAFETY: `queue` is an open descriptor that this value alone owns.
        let queue = unsafe { OwnedFd::from_raw_fd(queue) };
        // SAFETY: `queue` is open and `name` is a NUL-terminated path that outlives the call.
        let watch =
            unsafe { libc::inotify_add_watch(queue.as_raw_fd(), name.as_ptr(), libc::IN_OPEN) };
        assert!(watch >= 0, "the kernel adds the watch");
        Self(queue)
    }

    /// `any` takes the queued events and holds when the file was opened since the last call.
    fn any(&self) -> bool {
        let mut events = [0_u8; 4096];
        // SAFETY: `events` is valid for writes of its length and the descriptor is open.
        let read =
            unsafe { libc::read(self.0.as_raw_fd(), events.as_mut_ptr().cast(), events.len()) };
        if read > 0 {
            return true;
        }
        assert_eq!(
            std::io::Error::last_os_error().kind(),
            std::io::ErrorKind::WouldBlock,
            "an empty queue is the one read without an event"
        );
        false
    }
}

/// A signal recorded before a Git step starts no Git: the step returns the interruption, and the `git`
/// first on `PATH` is never opened. The same step with no signal recorded starts that `git`, which the
/// watch shows first.
#[test]
fn a_signal_recorded_before_a_git_step_starts_no_git() {
    let scratch = crate::paths::tests::Scratch::new("git-signal");
    let git = scratch.0.join("git");
    let written = std::process::Command::new("sh")
        .args([
            "-c",
            "printf '%s' \"$2\" > \"$1\" && chmod 755 \"$1\"",
            "sh",
        ])
        .arg(&git)
        .arg("#!/bin/sh\n")
        .status()
        .expect("the writer starts");
    assert!(written.success());
    let env = vec![(
        std::ffi::OsString::from("PATH"),
        scratch.0.clone().into_os_string(),
    )];
    let opens = Opens::of(&git);
    let interrupt = crate::process::Interrupt::new();
    let args = [std::ffi::OsStr::new("status")];
    let called = super::git::text_until(&env, &scratch.0, &args, &interrupt);
    assert!(
        matches!(called, Ok(ref done) if done.code == 0),
        "{called:?}"
    );
    assert!(opens.any(), "a Git that starts is opened");
    interrupt.record(libc::SIGINT);
    let called = super::git::text_until(&env, &scratch.0, &args, &interrupt);
    assert!(
        matches!(
            called,
            Err(super::git::CallError::Interrupted(crate::process::Interrupted(signal)))
                if signal == libc::SIGINT
        ),
        "{called:?}"
    );
    assert!(!opens.any(), "no Git started");
}
