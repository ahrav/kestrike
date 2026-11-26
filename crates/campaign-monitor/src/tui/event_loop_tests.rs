//! Run-loop tests: signal delivery under a full queue, batch bounds, the
//! frame schedule for input against snapshots, and paste sanitizing.

use super::*;

/// With the queue full, the listener returns at once so it can act on
/// a repeat signal, and the first signal still reaches the loop once
/// space frees up, so the session restores the terminal.
#[test]
fn a_signal_with_a_full_queue_returns_at_once_and_is_delivered_later() {
    let (tx, rx) = mpsc::sync_channel(1);
    tx.try_send(Msg::Terminate(0)).unwrap();
    let (done_tx, done_rx) = mpsc::channel();
    thread::spawn(move || {
        let mut seen = false;
        let first = on_signal(&tx, &mut seen, 15);
        let second = on_signal(&tx, &mut seen, 15);
        done_tx.send((first, second)).unwrap();
    });
    let (first, second) = done_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("on_signal returned within 2 s with the queue full");
    assert_eq!(first, None, "the first signal is queued, not an exit");
    assert_eq!(second, Some(128 + 15));
    assert!(matches!(rx.recv(), Ok(Msg::Terminate(0))));
    assert!(
        matches!(
            rx.recv_timeout(Duration::from_secs(2)),
            Ok(Msg::Terminate(15))
        ),
        "the first signal is delivered once the queue has space"
    );
}

/// A frame handles at most `CHANNEL_CAPACITY` messages; the rest stay
/// queued, so a producer that refills the channel while the loop drains
/// it cannot postpone the draw.
#[test]
fn a_batch_is_bounded_by_the_channel_capacity() {
    let (tx, rx) = mpsc::sync_channel(CHANNEL_CAPACITY);
    for _ in 0..CHANNEL_CAPACITY {
        tx.try_send(Msg::Terminate(0)).unwrap();
    }
    assert_eq!(batch(Msg::Terminate(0), &rx).count(), CHANNEL_CAPACITY);
    assert!(
        matches!(rx.try_recv(), Ok(Msg::Terminate(0))),
        "one message waits for the next frame"
    );
}

/// Input draws at once; a snapshot within `MIN_FRAME` of the last
/// frame waits for it; a quiet batch draws only when the age tick or a
/// deferred frame is due; nothing scheduled means no draw.
#[test]
fn input_draws_at_once_and_snapshots_wait_for_the_frame_budget() {
    let now = Instant::now();
    let last = now - Duration::from_millis(5);
    assert_eq!(schedule(true, true, None, last, now), Frame::Now);
    assert_eq!(
        schedule(true, false, None, last, now),
        Frame::At(last + MIN_FRAME)
    );
    let old = now - MIN_FRAME;
    assert_eq!(schedule(true, false, None, old, now), Frame::Now);
    let passed = Some(now - Duration::from_millis(1));
    assert_eq!(schedule(false, false, passed, last, now), Frame::Now);
    let later = now + Duration::from_secs(1);
    assert_eq!(
        schedule(false, false, Some(later), last, now),
        Frame::At(later)
    );
    assert_eq!(schedule(false, false, None, last, now), Frame::Idle);
}

#[test]
fn the_first_signal_is_queued_and_a_second_exits() {
    let (tx, rx) = mpsc::sync_channel(CHANNEL_CAPACITY);
    let mut seen = false;
    assert_eq!(on_signal(&tx, &mut seen, 15), None);
    assert!(matches!(rx.try_recv(), Ok(Msg::Terminate(15))));
    assert_eq!(on_signal(&tx, &mut seen, 2), Some(130));
}

#[test]
fn a_paste_drops_whole_escape_sequences_and_joins_lines() {
    assert_eq!(sanitize_paste("\x1b[31mfoo\x1b[0m bar"), "foo bar");
    assert_eq!(sanitize_paste("a\x1b]0;title\x07b"), "ab");
    assert_eq!(sanitize_paste("a\x1b]0;title\x1b\\b"), "ab");
    assert_eq!(sanitize_paste("x\x1b(By"), "xy");
    assert_eq!(sanitize_paste("x\x1b$(Cy"), "xy");
    assert_eq!(sanitize_paste("a\x1bPq#0;2;0;0;0~-\x1b\\b"), "ab");
    assert_eq!(sanitize_paste("a\x1b_Ga=T,f=100;AAAA\x1b\\b"), "ab");
    assert_eq!(sanitize_paste("a\x1bXsos\x1b\\b\x1b^pm\x1b\\c"), "abc");
    assert_eq!(sanitize_paste("one\ttwo\nthree\x07"), "one two three");
}
