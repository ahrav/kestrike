use std::fs;
use std::io::{self, PipeWriter};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use super::{
    Call, CallFailed, EXIT_PAUSE, Ended, Finished, READERS, Reader, TAIL, Waited, finish, read_all,
    run, tail, wait, whole_seconds,
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
    finished: Arc<Finished>,
}

fn spawned(program: &str, args: &[&str], stdin: Stdio) -> Child {
    Command::new(program)
        .args(args)
        .stdin(stdin)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the child starts")
}

/// The child with a reader of its standard output and a reader of `stderr`.
fn read_by(mut child: Child, stderr: impl io::Read + Send + 'static) -> Watched {
    let abandoned = Arc::new(AtomicBool::new(false));
    let finished = Arc::new(Finished::default());
    let out = read_all(
        child.stdout.take().expect("piped"),
        Arc::clone(&abandoned),
        Arc::clone(&finished),
    )
    .expect("a reader starts");
    let err =
        read_all(stderr, Arc::clone(&abandoned), Arc::clone(&finished)).expect("a reader starts");
    Watched {
        child,
        out,
        err,
        abandoned,
        finished,
    }
}

fn watched(program: &str, args: &[&str]) -> Watched {
    let mut child = spawned(program, args, Stdio::null());
    let stderr = child.stderr.take().expect("piped");
    read_by(child, stderr)
}

fn hanging() -> Watched {
    watched(
        "/bin/sh",
        &["-c", "trap '' TERM INT HUP; exec /bin/sleep 5"],
    )
}

/// A shell that runs `script` with its standard input open: the script's `read` returns once the
/// input is dropped.
fn gated(script: &str) -> (Watched, ChildStdin) {
    let mut child = spawned("/bin/sh", &["-c", script], Stdio::piped());
    let gate = child.stdin.take().expect("piped");
    let stderr = child.stderr.take().expect("piped");
    (read_by(child, stderr), gate)
}

/// A child that has exited and whose standard output has closed, with the second reader on a pipe
/// that stays open until the writer returned here is dropped.
fn held_open() -> (Watched, PipeWriter) {
    let (reader, writer) = io::pipe().expect("a pipe opens");
    let mut child = spawned("/bin/true", &[], Stdio::null());
    drop(child.stderr.take());
    let watched = read_by(child, reader);
    exited(&watched.child);
    closed(&[&watched.out]);
    (watched, writer)
}

fn within_limit(start: Instant, what: &str) {
    assert!(start.elapsed() < Duration::from_secs(30), "{what}");
    thread::sleep(Duration::from_millis(1));
}

/// Returns once the process whose state `stat` holds has exited and waits to be reaped.
fn zombie(stat: &Path) {
    let start = Instant::now();
    while !fs::read_to_string(stat).is_ok_and(|text| text.contains(") Z ")) {
        within_limit(start, "the child exits");
    }
}

fn exited(child: &Child) {
    zombie(&PathBuf::from(format!("/proc/{}/stat", child.id())));
}

/// Returns once each reader's thread has ended.
fn closed(readers: &[&Reader]) {
    let start = Instant::now();
    while !readers.iter().all(|reader| reader.is_finished()) {
        within_limit(start, "the readers finish");
    }
}

fn ended(watched: &Watched) {
    exited(&watched.child);
    closed(&[&watched.out, &watched.err]);
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
        abandoned,
        finished,
        ..
    } = &mut watched;
    let waited = wait(
        &mut record,
        child,
        abandoned,
        finished,
        Instant::now(),
        SLICE * 600,
        Instant::now,
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
        abandoned,
        finished,
        ..
    } = &mut watched;
    let waited = wait(
        &mut record,
        child,
        abandoned,
        finished,
        started,
        Duration::from_secs(1),
        Instant::now,
    );
    assert!(matches!(waited, Err(Waited::Cut(Ok(())))));
    assert!(gone(child));
}

#[test]
fn a_signal_that_may_raise_wins_over_the_cut() {
    let mut watched = watched("/bin/true", &[]);
    ended(&watched);
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    record.arm();
    delivered.deliver(Signal::Hangup);
    let started = Instant::now() - Duration::from_secs(2);
    let Watched {
        child,
        abandoned,
        finished,
        ..
    } = &mut watched;
    let waited = wait(
        &mut record,
        child,
        abandoned,
        finished,
        started,
        Duration::from_secs(1),
        Instant::now,
    );
    assert!(matches!(
        waited,
        Err(Waited::Raised(Interrupted(Signal::Hangup)))
    ));
    assert!(gone(child));
}

/// Turns the wait makes with its end an hour off before the clock of a case moves.
const EARLY: usize = 6;

/// The end of every wait with a scripted clock stands this long after its start.
const HOUR: Duration = Duration::from_secs(3600);

/// Waits on a shell that runs `script` to the `read` that the gate holds, and returns what the wait
/// gave. The clock reads one [`SLICE`] before the end at the turn after the early ones. During that
/// reading the gate opens and the reply completes: the child exits and both readers finish. From the
/// completed reply on, the clock runs with real time.
///
/// A case on this wait rests on real time in one stretch: from the completed reply to the wait's next
/// reading of the clock, which must come within one `SLICE`. The stretch holds the end of one turn,
/// one block and one look. The child's exit and the readers' finish stand outside it, since the clock
/// starts at the completed reply. A host fails such a case only by keeping the waiting thread off its
/// processor for the rest of a `SLICE` inside that stretch.
fn completed_in_the_last_interval(script: &str) -> Result<Option<i32>, Waited> {
    let (mut watched, gate) = gated(script);
    if script.starts_with("exec >&- 2>&-;") {
        closed(&[&watched.out, &watched.err]);
    }
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    let Watched {
        child,
        out,
        err,
        abandoned,
        finished,
    } = &mut watched;
    let started = Instant::now();
    let end = started + HOUR;
    let stat = PathBuf::from(format!("/proc/{}/stat", child.id()));
    let mut gate = Some(gate);
    let mut turns = 0;
    let mut completed = None;
    let waited = wait(
        &mut record,
        child,
        abandoned,
        finished,
        started,
        HOUR,
        || {
            turns += 1;
            if turns <= EARLY {
                return started;
            }
            let completed = completed.get_or_insert_with(|| {
                drop(gate.take());
                zombie(&stat);
                closed(&[&*out, &*err]);
                Instant::now()
            });
            end - SLICE + completed.elapsed()
        },
    );
    assert!(gone(child), "the wait reaps the child");
    assert_eq!(finished.count(), READERS);
    assert_eq!(abandoned.load(Ordering::SeqCst), waited.is_err());
    waited.map(|status| status.code())
}

/// A reply that completes inside the last interval before the end is an answer: the child holds its
/// pipes to its exit, and the readers' finish ends the wait's block before the end.
#[test]
fn a_reply_complete_inside_the_last_interval_is_an_answer() {
    match completed_in_the_last_interval("read line; exit 7") {
        Ok(code) => assert_eq!(code, Some(7)),
        Err(_) => panic!("a reply {SLICE:?} before the end is cut"),
    }
}

/// A child that closed both pipes at its start and exits inside the last interval is an answer: its
/// exit is the reply's last event, and the wait reads it one [`EXIT_PAUSE`] later, where a block of
/// one [`SLICE`] would run to the end.
#[test]
fn an_exit_after_both_outputs_closed_is_read_within_an_exit_pause() {
    assert!(EXIT_PAUSE * 10 <= SLICE);
    match completed_in_the_last_interval("exec >&- 2>&-; read line; exit 7") {
        Ok(code) => assert_eq!(code, Some(7)),
        Err(_) => panic!("an exit {SLICE:?} before the end is cut"),
    }
}

/// A reply whose last reader finishes at the end is a cut, though the clock read before the end at
/// the turn's reading: the reader finishes during that reading, after which the clock reads the end.
#[test]
fn a_reply_whose_last_reader_finishes_at_the_end_is_a_cut() {
    let (mut watched, held) = held_open();
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    let Watched {
        child,
        err,
        abandoned,
        finished,
        ..
    } = &mut watched;
    let started = Instant::now();
    let end = started + HOUR;
    let mut held = Some(held);
    let waited = wait(
        &mut record,
        child,
        abandoned,
        finished,
        started,
        HOUR,
        || match held.take() {
            Some(writer) => {
                drop(writer);
                closed(&[&*err]);
                end - Duration::from_nanos(1)
            }
            None => end,
        },
    );
    assert!(matches!(waited, Err(Waited::Cut(Ok(())))));
    assert_eq!(finished.count(), READERS, "both readers had finished");
    assert!(gone(child));
    assert!(abandoned.load(Ordering::SeqCst));
}

/// One part of a reply is no answer. A child that has exited while one output stays open, and a
/// child that runs on after both outputs closed, are each cut at the end, after turns that found
/// the part and waited on.
#[test]
fn an_exit_alone_and_two_closed_outputs_alone_are_no_answer() {
    let (exit_alone, held) = held_open();
    let outputs_alone = watched("/bin/sh", &["-c", "exec >&- 2>&-; exec /bin/sleep 30"]);
    closed(&[&outputs_alone.out, &outputs_alone.err]);
    for (mut watched, killed) in [(exit_alone, false), (outputs_alone, true)] {
        let delivered = Delivered::new();
        let mut record = Record::new(&delivered);
        let Watched {
            child,
            abandoned,
            finished,
            ..
        } = &mut watched;
        let started = Instant::now();
        let mut turns = 0;
        let waited = wait(
            &mut record,
            child,
            abandoned,
            finished,
            started,
            HOUR,
            || {
                turns += 1;
                if turns <= EARLY {
                    started
                } else {
                    started + HOUR
                }
            },
        );
        assert!(
            matches!(waited, Err(Waited::Cut(Ok(())))),
            "killed {killed}"
        );
        assert_eq!(
            turns,
            EARLY + 1,
            "killed {killed}: each turn reads the clock"
        );
        assert!(gone(child), "killed {killed}");
        assert!(abandoned.load(Ordering::SeqCst));
        let status = child.try_wait().expect("cached").expect("reaped");
        let signal = killed.then_some(libc::SIGKILL);
        assert_eq!(status.signal(), signal, "killed {killed}");
    }
    drop(held);
}

/// A finish counted after the wait's look ends its block at once, and a finish counted during the
/// block wakes it: each block returns long before its timeout of 60 seconds.
#[test]
fn a_finish_ends_the_block_whether_it_comes_before_or_during_it() {
    let timeout = Duration::from_secs(60);
    let finished = Finished::default();
    let seen = finished.count();
    finished.add();
    let start = Instant::now();
    finished.wait(seen, timeout);
    assert!(start.elapsed() < timeout / 2, "{:?}", start.elapsed());
    let seen = finished.count();
    assert_eq!(seen, 1);
    let start = Instant::now();
    thread::scope(|scope| {
        scope.spawn(|| {
            thread::sleep(Duration::from_millis(100));
            finished.add();
        });
        finished.wait(seen, timeout);
    });
    assert!(start.elapsed() < timeout / 2, "{:?}", start.elapsed());
    assert_eq!(finished.count(), READERS);
    let start = Instant::now();
    finished.wait(READERS, SLICE);
    assert!(
        start.elapsed() >= SLICE,
        "no finish: the block lasts its timeout"
    );
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
            abandoned,
            finished,
            ..
        } = &mut watched;
        let cut = Duration::from_millis(if raise { 30_000 } else { 200 });
        let waited = wait(
            &mut record,
            child,
            abandoned,
            finished,
            Instant::now(),
            cut,
            Instant::now,
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
        abandoned,
        finished,
        ..
    } = &mut watched;
    let waited = wait(
        &mut record,
        child,
        abandoned,
        finished,
        Instant::now(),
        SLICE * 600,
        Instant::now,
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
        abandoned,
        finished,
        ..
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
            finished,
            Instant::now(),
            SLICE * 600,
            Instant::now,
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
