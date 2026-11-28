//! The build lock: a run waits for another that holds it before any worktree, holds it through both
//! legs and hands each leg the emptied lock file as standard input; a lock file that another user owns
//! or can write, or that is no regular file, is refused.

use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::symlink;
use std::process::Stdio;
use std::sync::mpsc;
use std::time::Duration;

use kestrike_tools::red_green::run::lock_problem;

use super::support::{Call, Fixture, at, chmod, text, write};

fn me() -> u32 {
    // SAFETY: `getuid` takes no argument and always succeeds.
    unsafe { libc::getuid() }
}

/// A run started while another holds the lock prints the waiting line once, makes no worktree, no
/// temporary directory and no build until the lock is released, then holds it through both builds.
#[test]
fn a_run_waits_for_the_build_lock_before_any_worktree_and_holds_it_through_both_legs() {
    let fx = Fixture::new();
    let target = fx.repo.join("target/red-green/build");
    fs::create_dir_all(&target).expect("made");
    let lock = OpenOptions::new()
        .append(true)
        .create(true)
        .open(target.join("red-green.lock"))
        .expect("the lock opens");
    // SAFETY: `flock` takes the descriptor `lock` owns and a flag.
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) }, 0);
    let mut child = fx
        .start(&Call::default())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the run starts");
    let stderr = child.stderr.take().expect("piped");
    let (sent, received) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut lines = BufReader::new(stderr);
        let mut line = String::new();
        let _ = lines.read_line(&mut line);
        let _ = sent.send(line);
        let mut rest = String::new();
        let _ = std::io::Read::read_to_string(&mut lines, &mut rest);
        rest
    });
    let first = received.recv_timeout(Duration::from_secs(30));
    let waiting = format!(
        "red-green: waiting for another run that builds in {}\n",
        target.display()
    );
    if first.as_deref() != Ok(waiting.as_str()) {
        let _ = child.kill();
        let _ = child.wait();
        panic!("the first line is {first:?}");
    }
    assert!(fx.builds().is_empty());
    assert_eq!(fs::read_dir(&fx.tmp).expect("lists").count(), 0);
    assert_eq!(fx.worktrees(), 1);
    drop(lock);
    let output = child.wait_with_output().expect("the run ends");
    let rest = reader.join().expect("the reader ends");
    assert!(
        output.status.success(),
        "{}{rest}",
        String::from_utf8_lossy(&output.stdout)
    );
    let held: Vec<String> = fx
        .builds()
        .iter()
        .map(|build| kestrike_tools::json::text(at(build, "lock_held")))
        .collect();
    assert_eq!(held, ["true", "true"]);
}

/// A lock file that an earlier run left with content reaches each leg as empty standard input.
#[test]
fn a_lock_file_with_content_reaches_each_leg_as_empty_standard_input() {
    let fx = Fixture::new();
    let target = fx.repo.join("target/red-green/build");
    fs::create_dir_all(&target).expect("made");
    write(&target.join("red-green.lock"), "left by an earlier run\n");
    let done = fx.red_green(&Call::default());
    assert_eq!(done.code, 0, "{}", done.shown());
    let stdin: Vec<String> = fx
        .builds()
        .iter()
        .map(|build| text(at(build, "stdin")))
        .collect();
    assert_eq!(stdin, ["", ""]);
}

/// A lock file all users can write is refused before any build; a lock file judged by another user ID
/// is one another user owns, and the same file judged by its owner's is accepted.
#[test]
fn a_build_lock_another_user_can_write_is_refused() {
    let fx = Fixture::new();
    let target = fx.repo.join("target/red-green/build");
    fs::create_dir_all(&target).expect("made");
    let lock = target.join("red-green.lock");
    write(&lock, "");
    chmod(&lock, 0o666);
    let done = fx.red_green(&Call::default());
    assert_eq!(done.code, 1, "{}", done.shown());
    assert!(
        done.stdout.starts_with(&format!(
            "red-green refused: the build lock {} cannot be opened: another user owns or can write it",
            lock.display()
        )),
        "{}",
        done.stdout
    );
    assert!(fx.builds().is_empty());
    fx.assert_checkout_unchanged();
    chmod(&lock, 0o644);
    let status = File::open(&lock)
        .and_then(|file| file.metadata())
        .expect("the lock stats");
    assert_eq!(
        lock_problem(&status, me() + 1),
        Some("another user owns or can write it")
    );
    assert_eq!(lock_problem(&status, me()), None);
    // The control: the lock file of mode 0644 that its owner judges lets both legs build.
    let done = fx.red_green(&Call::default());
    assert_eq!(done.code, 0, "{}", done.shown());
    assert_eq!(fx.build_legs(), ["base", "head"]);
}

/// A FIFO in the lock's place is refused as no regular file, and a link there is refused at its open
/// with the link's target left uncreated.
#[test]
fn a_build_lock_that_is_not_a_regular_file_is_refused() {
    let fx = Fixture::new();
    let target = fx.repo.join("target/red-green/build");
    fs::create_dir_all(&target).expect("made");
    let lock = target.join("red-green.lock");
    let aim = fx.root.join("lock-target");
    for kind in ["fifo", "symlink"] {
        let _ = fs::remove_file(&lock);
        if kind == "fifo" {
            let name = CString::new(lock.as_os_str().as_bytes()).expect("no NUL");
            // SAFETY: `name` is a NUL-terminated path that outlives the call.
            assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o644) }, 0);
        } else {
            symlink(&aim, &lock).expect("linked");
        }
        let done = fx.red_green(&Call::default());
        assert_eq!(done.code, 1, "{kind}: {}", done.shown());
        assert!(
            done.stdout.starts_with(&format!(
                "red-green refused: the build lock {} cannot be opened",
                lock.display()
            )),
            "{kind}: {}",
            done.stdout
        );
        assert_eq!(
            done.stdout.contains("it is not a regular file"),
            kind == "fifo",
            "{}",
            done.stdout
        );
        assert!(fx.builds().is_empty(), "{kind}");
        assert!(!aim.exists(), "{kind}");
        fx.assert_checkout_unchanged();
    }
    // The control: an open that follows the link and creates its target makes the file the run left
    // uncreated.
    OpenOptions::new()
        .append(true)
        .create(true)
        .open(&lock)
        .expect("the link's target is made");
    assert!(aim.exists());
}
