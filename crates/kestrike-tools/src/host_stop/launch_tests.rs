use std::fs;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::thread;
use std::time::{Duration, Instant};

use super::{CallFailed, Ended, TAIL, Waited, finish, read_all, tail, wait, whole_seconds};
use crate::host_stop::{Delivered, Interrupted, Record, Signal};

/// The CLI's timeouts are the cut in whole seconds rounded up and at least 1, saturating at the
/// largest count.
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
        (Duration::MAX, u64::MAX),
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

#[test]
fn a_signal_after_the_child_ends_and_its_outputs_close_raises_in_the_wait() {
    let mut child = Command::new("/bin/true")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the child starts");
    let abandoned = Arc::new(AtomicBool::new(false));
    let out = read_all(child.stdout.take(), Arc::clone(&abandoned)).expect("a reader starts");
    let err = read_all(child.stderr.take(), Arc::clone(&abandoned)).expect("a reader starts");
    let stat = format!("/proc/{}/stat", child.id());
    let start = Instant::now();
    while !(out.is_finished()
        && err.is_finished()
        && fs::read_to_string(&stat).is_ok_and(|text| text.contains(") Z ")))
    {
        assert!(start.elapsed() < Duration::from_secs(30), "the child ends");
        thread::sleep(Duration::from_millis(5));
    }
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    record.arm();
    delivered.deliver(Signal::Terminate);
    let waited = wait(
        &mut record,
        &mut child,
        &abandoned,
        [&out, &err],
        Instant::now(),
        Duration::from_secs(30),
    );
    assert!(
        matches!(waited, Err(Waited::Raised(Interrupted(Signal::Terminate)))),
        "the wait reads the record before it takes the child's end"
    );
    assert!(
        child.try_wait().expect("waited").is_some(),
        "the child is reaped"
    );
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
