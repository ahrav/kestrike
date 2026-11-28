use std::fs;
use std::io;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use super::{
    Call, CallFailed, Ended, Reader, TAIL, Waited, finish, read_all, run, tail, wait, whole_seconds,
};
use crate::host_stop::{Delivered, Interrupted, Record, SLICE, Signal};

/// `whole_seconds` supplies the CLI's timeout values.
#[test]
fn the_cut_rounds_up_to_whole_seconds_and_at_least_1() {
    for (cut, seconds) in [
        (Duration::ZERO, 1),
        (Duration::from_nanos(1), 1),
        (Duration::from_secs(1), 1),
        (Duration::new(1, 1), 2),
        (Duration::from_millis(999), 1),
        (Duration::from_millis(1001), 2),
        (Duration::from_secs(2), 2),
        (Duration::new(2, 1), 3),
        (Duration::from_millis(7500), 8),
        (Duration::from_secs(u64::MAX), u128::from(u64::MAX)),
        (Duration::MAX, u128::from(u64::MAX) + 1),
    ] {
        assert_eq!(whole_seconds(cut), seconds, "{cut:?}");
    }
}

/// The tail counts Unicode scalar values, so a text of multi-byte characters keeps 400 of them.
#[test]
fn the_tail_keeps_the_last_400_characters() {
    assert_eq!(TAIL, 400);
    for length in [0, 399, 400, 401, 800] {
        let text = "\u{e9}".repeat(length);
        assert_eq!(tail(&text).chars().count(), length.min(TAIL), "{length}");
    }
    let text = format!("{}END", "a\u{e9}".repeat(300));
    let expected: String = text.chars().skip(603 - TAIL).collect();
    assert_eq!(tail(&text), expected);
    assert!(expected.starts_with('\u{e9}') && expected.ends_with("END"));
}

struct Watched {
    child: Child,
    out: Reader,
    err: Reader,
    abandoned: Arc<AtomicBool>,
}

fn watched(program: &str, args: &[&str]) -> Watched {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the child starts");
    let abandoned = Arc::new(AtomicBool::new(false));
    let out = read_all(child.stdout.take().expect("piped"), Arc::clone(&abandoned))
        .expect("a reader starts");
    let err = read_all(child.stderr.take().expect("piped"), Arc::clone(&abandoned))
        .expect("a reader starts");
    Watched {
        child,
        out,
        err,
        abandoned,
    }
}

fn hanging() -> Watched {
    watched(
        "/bin/sh",
        &["-c", "trap '' TERM INT HUP; exec /bin/sleep 5"],
    )
}

fn ended(watched: &Watched) {
    let stat = format!("/proc/{}/stat", watched.child.id());
    let start = Instant::now();
    while !(watched.out.is_finished()
        && watched.err.is_finished()
        && fs::read_to_string(&stat).is_ok_and(|text| text.contains(") Z ")))
    {
        assert!(start.elapsed() < Duration::from_secs(30), "the child ends");
        thread::sleep(Duration::from_millis(5));
    }
}

fn gone(child: &Child) -> bool {
    match fs::symlink_metadata(Path::new("/proc").join(child.id().to_string())) {
        Ok(_) => false,
        Err(error) if error.kind() == io::ErrorKind::NotFound => true,
        Err(error) => panic!("/proc/{}: {error}", child.id()),
    }
}

#[test]
fn a_signal_after_the_child_ends_and_its_outputs_close_raises_in_the_wait() {
    let mut watched = watched("/bin/true", &[]);
    ended(&watched);
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    record.arm();
    delivered.deliver(Signal::Terminate);
    let Watched {
        child,
        out,
        err,
        abandoned,
    } = &mut watched;
    let waited = wait(
        &mut record,
        child,
        abandoned,
        [out, err],
        Instant::now(),
        SLICE * 600,
    );
    assert!(matches!(
        waited,
        Err(Waited::Raised(Interrupted(Signal::Terminate)))
    ));
    assert!(gone(child), "the wait reaps the child");
}

#[test]
fn an_answer_seen_at_or_after_the_cut_is_a_cut() {
    let mut watched = watched("/bin/true", &[]);
    ended(&watched);
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    let started = Instant::now() - Duration::from_secs(2);
    let Watched {
        child,
        out,
        err,
        abandoned,
    } = &mut watched;
    let waited = wait(
        &mut record,
        child,
        abandoned,
        [out, err],
        started,
        Duration::from_secs(1),
    );
    assert!(matches!(waited, Err(Waited::Cut(Ok(())))));
    assert!(gone(child));
}

#[test]
fn the_cut_and_a_raise_each_end_a_child_that_ignores_term_with_sigkill() {
    for raise in [false, true] {
        let mut watched = hanging();
        let delivered = Delivered::new();
        let mut record = Record::new(&delivered);
        record.arm();
        thread::sleep(Duration::from_millis(100));
        if raise {
            delivered.deliver(Signal::Terminate);
        }
        let Watched {
            child,
            out,
            err,
            abandoned,
        } = &mut watched;
        let cut = Duration::from_millis(if raise { 30_000 } else { 200 });
        let waited = wait(
            &mut record,
            child,
            abandoned,
            [out, err],
            Instant::now(),
            cut,
        );
        match (raise, &waited) {
            (true, Err(Waited::Raised(Interrupted(Signal::Terminate))))
            | (false, Err(Waited::Cut(Ok(())))) => {}
            (_, _) => panic!("raise {raise}: the wait ended otherwise"),
        }
        assert!(gone(child), "raise {raise}: reaped before the test waits");
        assert!(abandoned.load(Ordering::SeqCst));
        let status = child.try_wait().expect("cached").expect("reaped");
        assert_eq!(status.signal(), Some(libc::SIGKILL), "raise {raise}");
    }
}

#[test]
fn a_failed_wait_abandons_the_readers_and_fails() {
    let mut watched = watched("/bin/true", &[]);
    let pid = libc::pid_t::try_from(watched.child.id()).expect("a process id");
    let mut status = 0;
    // SAFETY: `&mut status` provides writable storage for the duration of `waitpid`.
    let reaped = unsafe { libc::waitpid(pid, &mut status, 0) };
    assert_eq!(reaped, pid);
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    let Watched {
        child,
        out,
        err,
        abandoned,
    } = &mut watched;
    let waited = wait(
        &mut record,
        child,
        abandoned,
        [out, err],
        Instant::now(),
        SLICE * 600,
    );
    match waited {
        Err(Waited::Failed(error)) => assert_eq!(error.raw_os_error(), Some(libc::ECHILD)),
        _ => panic!("the wait fails"),
    }
    assert!(abandoned.load(Ordering::SeqCst));
}

#[test]
fn a_signal_during_the_search_starts_no_process() {
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    record.arm();
    let env = [];
    let call = Call {
        argv: &["sts", "get-caller-identity"],
        retry: true,
        cut: Duration::from_secs(5),
        env: &env,
    };
    let ended = run(&mut record, &call, |_| {
        delivered.deliver(Signal::Terminate);
        Some(PathBuf::from("/dev/null"))
    });
    assert_eq!(
        ended,
        Err(Ended::Interrupted(Interrupted(Signal::Terminate)))
    );
    assert!(!record.is_armed());
    assert_eq!(record.pending(), None);
    let failed = run(&mut record, &call, |_| Some(PathBuf::from("/dev/null")));
    assert!(
        matches!(failed, Err(Ended::Failed(_))),
        "the same search with no signal reaches the spawn: {failed:?}"
    );
}

#[test]
fn the_pause_between_turns_stays_within_a_slice() {
    let mut watched = hanging();
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    record.arm();
    let Watched {
        child,
        out,
        err,
        abandoned,
    } = &mut watched;
    let (waited, late) = thread::scope(|scope| {
        let sender = scope.spawn(|| {
            thread::sleep(Duration::from_millis(1100));
            let at = Instant::now();
            delivered.deliver(Signal::Terminate);
            at
        });
        let waited = wait(
            &mut record,
            child,
            abandoned,
            [out, err],
            Instant::now(),
            SLICE * 600,
        );
        let returned = Instant::now();
        (waited, returned - sender.join().expect("the sender ends"))
    });
    assert!(matches!(
        waited,
        Err(Waited::Raised(Interrupted(Signal::Terminate)))
    ));
    assert!(late < Duration::from_millis(500), "{late:?}");
    assert!(gone(child));
}

#[test]
fn the_last_read_raises_in_place_of_any_result_and_keeps_a_raised_one() {
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    for ended in [
        Ok(String::from("{}")),
        Err(Ended::Failed(CallFailed::no_answer(&["sts", "x"], "cut"))),
    ] {
        record.arm();
        delivered.deliver(Signal::Hangup);
        assert_eq!(
            finish(&mut record, ended),
            Err(Ended::Interrupted(Interrupted(Signal::Hangup)))
        );
        assert!(!record.is_armed());
    }
    let raised = Err(Ended::Interrupted(Interrupted(Signal::Terminate)));
    delivered.deliver(Signal::Interrupt);
    assert_eq!(finish(&mut record, raised.clone()), raised);
    assert_eq!(record.pending(), Some(Signal::Interrupt));
    assert_eq!(finish(&mut record, Ok(String::new())), Ok(String::new()));
}
