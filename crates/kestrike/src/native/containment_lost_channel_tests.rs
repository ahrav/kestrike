//! A lost controller channel parks every caller of `contain`.
//!
//! The first `contain` call sends the request; every call returns only after the controller acknowledges
//! it. A lost channel parks each calling thread for the life of the process.
//!
//! The tests build a `ControllerSupervisor` over an in-memory channel the test drives as the
//! controller: a writer that keeps the request bytes, and a reader that blocks until the test feeds it
//! frames, ends it, or fails it. Two threads call `contain`. The first makes the exchange; the second
//! enters once the first has sent the request. The test then loses the channel in one of five ways and
//! unparks both callers every 10 ms for 300 ms. Through that interval neither caller may return, and
//! `acknowledged()` and `verified()` must stay false; at most one request line was written.
//!
//! The control runs the same steps and delivers `contained <id>` instead of the loss: no caller returns
//! before the acknowledgement, each returns after it, `verified()` is true and the channel holds one
//! request. A last test drops a watchdog before its deadline and observes that its supervisor was never
//! called.
//!
//! "For the life of the process" is observed for the 300 ms of unparks only. A caller left parked at the
//! end of a test stays parked until the test process exits.
//!
//! Each test gathers what it saw into plain values and asserts last.

use std::io::{self, BufReader, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::containment::ControllerSupervisor;
use super::watchdog::{Supervisor, Watchdog};

const ENDPOINT: &str = "endpoint-0";
/// How long the parked callers are unparked and watched.
const OBSERVED: Duration = Duration::from_millis(300);
/// The pause between two unparks.
const STEP: Duration = Duration::from_millis(10);
/// The longest a step that must happen may take before the test gives up on it.
const PATIENCE: Duration = Duration::from_secs(30);

/// The controller's end of the request channel: it keeps every byte the supervisor wrote where the
/// test can read it, or refuses every write when `broken`.
#[derive(Clone, Default)]
struct Wire {
    bytes: Arc<Mutex<Vec<u8>>>,
    broken: bool,
    refused: Arc<AtomicBool>,
}

impl Wire {
    /// The whole lines written so far, each without its line break.
    fn lines(&self) -> Vec<String> {
        let bytes = self.bytes.lock().unwrap();
        bytes
            .split_inclusive(|byte| *byte == b'\n')
            .filter(|line| line.ends_with(b"\n"))
            .map(|line| String::from_utf8_lossy(&line[..line.len() - 1]).into_owned())
            .collect()
    }

    /// Whether a write was refused.
    fn refused(&self) -> bool {
        self.refused.load(Ordering::Acquire)
    }
}

impl Write for Wire {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.broken {
            self.refused.store(true, Ordering::Release);
            return Err(io::Error::from(io::ErrorKind::BrokenPipe));
        }
        self.bytes.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// What the test, as the controller, puts on the acknowledgement stream: bytes, or a read error.
type Feed = Sender<io::Result<Vec<u8>>>;

/// The acknowledgement stream. A read blocks until the test feeds bytes or an error, and reports the
/// end of the stream once the test dropped its [`Feed`].
struct Stream {
    feed: Receiver<io::Result<Vec<u8>>>,
    pending: Vec<u8>,
    at: usize,
}

impl Read for Stream {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        while self.at == self.pending.len() {
            match self.feed.recv() {
                Ok(Ok(bytes)) => (self.pending, self.at) = (bytes, 0),
                Ok(Err(error)) => return Err(error),
                Err(_) => return Ok(0),
            }
        }
        let take = out.len().min(self.pending.len() - self.at);
        out[..take].copy_from_slice(&self.pending[self.at..self.at + take]);
        self.at += take;
        Ok(take)
    }
}

type Supervised = Arc<ControllerSupervisor<Wire, BufReader<Stream>>>;

/// A supervisor of [`ENDPOINT`] over a channel the test drives, whose writer refuses when `broken`.
fn supervised(broken: bool) -> (Supervised, Wire, Feed) {
    let wire = Wire {
        broken,
        ..Wire::default()
    };
    let (feed, stream) = mpsc::channel();
    let stream = Stream {
        feed: stream,
        pending: Vec::new(),
        at: 0,
    };
    let supervisor = ControllerSupervisor::new(ENDPOINT, wire.clone(), BufReader::new(stream));
    (Arc::new(supervisor.unwrap()), wire, feed)
}

/// A thread that calls `contain` and then reports `name` on `returned`.
fn caller(
    supervisor: &Supervised,
    returned: &Sender<&'static str>,
    name: &'static str,
) -> JoinHandle<()> {
    let (supervisor, returned) = (supervisor.clone(), returned.clone());
    thread::spawn(move || {
        supervisor.contain();
        // The receiver is gone when a caller returns after its test ended.
        let _ = returned.send(name);
    })
}

/// Whether `reached` became true within [`PATIENCE`].
fn reaches(mut reached: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    while !reached() {
        if start.elapsed() >= PATIENCE {
            return false;
        }
        thread::sleep(Duration::from_millis(1));
    }
    true
}

/// What [`OBSERVED`] of unparks showed.
#[derive(Debug, PartialEq, Eq)]
struct Watched {
    /// The first caller that returned from `contain`, if one did.
    returned: Option<&'static str>,
    /// Whether `acknowledged()` or `verified()` was true at any unpark.
    acknowledged: bool,
}

/// Unparks both callers every [`STEP`] for [`OBSERVED`], or until one returns.
fn watch(
    supervisor: &Supervised,
    callers: [&JoinHandle<()>; 2],
    returns: &Receiver<&'static str>,
) -> Watched {
    let mut watched = Watched {
        returned: None,
        acknowledged: false,
    };
    let start = Instant::now();
    while start.elapsed() < OBSERVED && watched.returned.is_none() {
        for caller in callers {
            caller.thread().unpark();
        }
        watched.returned = match returns.recv_timeout(STEP) {
            Ok(name) => Some(name),
            Err(RecvTimeoutError::Timeout) => None,
            Err(RecvTimeoutError::Disconnected) => Some("a caller that dropped its report"),
        };
        watched.acknowledged |= supervisor.acknowledged() || supervisor.verified();
    }
    watched
}

/// The ways a test loses the channel before `contained <id>` arrives.
#[derive(Debug, Clone, Copy)]
enum Loss {
    /// The acknowledgement stream ends with no frame on it.
    End,
    /// The stream carries frames that are not this endpoint's acknowledgement, then ends.
    OtherFrames,
    /// The stream ends inside the acknowledgement, before its line break.
    Unterminated,
    /// The read of the stream fails.
    ReadError,
    /// The request write fails, while the stream holds an acknowledgement nothing asked for.
    Write,
}

/// Two callers of `contain` over a channel lost by `loss`: through [`OBSERVED`] of unparks neither
/// returns and nothing is acknowledged, and the channel holds at most the one request.
fn both_callers_stay_parked_over_a_channel_lost_by(loss: Loss) {
    let write_fails = matches!(loss, Loss::Write);
    let (supervisor, wire, feed) = supervised(write_fails);
    let (returned, returns) = mpsc::channel();
    if write_fails {
        feed.send(Ok(format!("contained {ENDPOINT}\n").into_bytes()))
            .unwrap();
    }

    let first = caller(&supervisor, &returned, "the first caller");
    // The first caller is inside its exchange once the request is flushed, or once its write failed.
    let sent = reaches(|| supervisor.requested() || wire.refused());
    let second = caller(&supervisor, &returned, "the second caller");

    match loss {
        Loss::End | Loss::Write => {}
        Loss::OtherFrames => {
            for frame in [
                "contained endpoint-1\n".to_owned(),
                format!("contain {ENDPOINT}\n"),
                format!("contained {ENDPOINT} \n"),
                "\n".to_owned(),
            ] {
                feed.send(Ok(frame.into_bytes())).unwrap();
            }
        }
        Loss::Unterminated => feed
            .send(Ok(format!("contained {ENDPOINT}").into_bytes()))
            .unwrap(),
        Loss::ReadError => feed
            .send(Err(io::Error::from(io::ErrorKind::BrokenPipe)))
            .unwrap(),
    }
    drop(feed);
    // A call counts itself under the channel lock, which the first caller holds through its exchange, so two counted calls mean the exchange ended and both callers are at, or about to reach, their park.
    let entered = reaches(|| supervisor.calls() == 2);

    let watched = watch(&supervisor, [&first, &second], &returns);
    let finished = (first.is_finished(), second.is_finished());
    let (requested, acknowledged, verified, calls) = (
        supervisor.requested(),
        supervisor.acknowledged(),
        supervisor.verified(),
        supervisor.calls(),
    );
    let lines = wire.lines();

    assert!(sent, "{loss:?}: the first call makes the exchange");
    assert!(entered, "{loss:?}: both calls entered `contain`");
    assert_eq!(
        watched,
        Watched {
            returned: None,
            acknowledged: false
        },
        "{loss:?}: a caller returned from `contain`, or the supervisor reported an acknowledgement, over a lost channel"
    );
    assert_eq!(
        finished,
        (false, false),
        "{loss:?}: both callers stay parked"
    );
    assert!(
        !acknowledged && !verified,
        "{loss:?}: the controller acknowledged nothing"
    );
    assert_eq!(calls, 2, "{loss:?}: each call is counted once");
    if write_fails {
        assert!(!requested, "{loss:?}: a refused write sends no request");
        assert!(
            lines.is_empty(),
            "{loss:?}: no request line was written: {lines:?}"
        );
    } else {
        assert!(requested, "{loss:?}: the first call sent the request");
        assert_eq!(
            lines,
            [format!("contain {ENDPOINT}")],
            "{loss:?}: only the first call sends a request"
        );
    }
}

/// The acknowledgement stream ends before any frame: the request went out and nothing answers it.
#[test]
fn a_stream_that_ends_with_no_frame_keeps_both_callers_parked_through_every_wake() {
    both_callers_stay_parked_over_a_channel_lost_by(Loss::End);
}

/// Frames that name another endpoint, repeat the request, or differ from the acknowledgement by one
/// byte acknowledge nothing; the stream then ends.
#[test]
fn a_stream_that_ends_after_other_frames_keeps_both_callers_parked_through_every_wake() {
    both_callers_stay_parked_over_a_channel_lost_by(Loss::OtherFrames);
}

/// `contained <id>` with no line break at the end of the stream is not a frame, so it acknowledges
/// nothing.
#[test]
fn a_stream_that_ends_inside_the_acknowledgement_keeps_both_callers_parked_through_every_wake() {
    both_callers_stay_parked_over_a_channel_lost_by(Loss::Unterminated);
}

/// A read error loses the channel as its end does.
#[test]
fn a_stream_whose_read_fails_keeps_both_callers_parked_through_every_wake() {
    both_callers_stay_parked_over_a_channel_lost_by(Loss::ReadError);
}

/// A request that was never written cannot be acknowledged: the supervisor leaves the stream unread,
/// although it holds `contained <id>`.
#[test]
fn a_request_write_that_fails_keeps_both_callers_parked_through_every_wake() {
    both_callers_stay_parked_over_a_channel_lost_by(Loss::Write);
}

/// The control: the same two callers over a channel that carries the acknowledgement. Unparks before the
/// acknowledgement release neither caller; after it each returns, a later call returns at once, the
/// supervisor reports the containment verified and the channel holds the one request.
#[test]
fn each_caller_returns_once_the_controller_acknowledges_and_not_before() {
    let (supervisor, wire, feed) = supervised(false);
    let (returned, returns) = mpsc::channel();

    let first = caller(&supervisor, &returned, "the first caller");
    let sent = reaches(|| supervisor.requested());
    let second = caller(&supervisor, &returned, "the second caller");

    let before = watch(&supervisor, [&first, &second], &returns);
    let calls_before = supervisor.calls();

    feed.send(Ok(b"contained endpoint-1\n".to_vec())).unwrap();
    feed.send(Ok(format!("contained {ENDPOINT}\n").into_bytes()))
        .unwrap();
    let mut after = [
        returns.recv_timeout(PATIENCE).ok(),
        returns.recv_timeout(PATIENCE).ok(),
    ];
    after.sort_unstable();
    let third = caller(&supervisor, &returned, "the third caller");
    let later = returns.recv_timeout(PATIENCE).ok();
    let (acknowledged, verified, calls) = (
        supervisor.acknowledged(),
        supervisor.verified(),
        supervisor.calls(),
    );
    let lines = wire.lines();
    // The stream stays open until here, so no caller returned because it ended.
    drop(feed);
    drop(third);

    assert!(sent, "the first call sends the request");
    assert_eq!(
        before,
        Watched {
            returned: None,
            acknowledged: false
        },
        "no call returns, and nothing is acknowledged, before the controller's acknowledgement"
    );
    assert_eq!(
        calls_before, 1,
        "the second call waits for the first call's exchange"
    );
    assert_eq!(
        after,
        [Some("the first caller"), Some("the second caller")],
        "each caller returns once the controller acknowledged"
    );
    assert_eq!(
        later,
        Some("the third caller"),
        "a call after the acknowledgement returns"
    );
    assert!(
        acknowledged && verified,
        "the acknowledgement is the containment the supervisor verifies"
    );
    assert_eq!(calls, 3, "each call is counted once");
    assert_eq!(
        lines,
        [format!("contain {ENDPOINT}")],
        "only the first call sends a request"
    );
}

/// A watchdog dropped before its deadline never calls its supervisor: the drop returns, no call is
/// counted and the channel holds no request.
#[test]
fn a_watchdog_dropped_before_its_deadline_never_calls_its_supervisor() {
    let (supervisor, wire, feed) = supervised(false);
    let (dropped, drops) = mpsc::channel();
    let owner = {
        let supervisor: Arc<dyn Supervisor> = supervisor.clone();
        thread::spawn(move || {
            let armed = Watchdog::arm(Duration::from_secs(3600), supervisor).map(drop);
            let _ = dropped.send(armed.is_ok());
        })
    };
    // The drop joins the watchdog's worker; a worker that entered `contain` would wait on the open stream and the drop would not return.
    let disarmed = drops.recv_timeout(PATIENCE).ok();
    let (calls, requested, lines) = (supervisor.calls(), supervisor.requested(), wire.lines());
    drop(feed);
    drop(owner);

    assert_eq!(
        disarmed,
        Some(true),
        "the watchdog arms, and its drop before the deadline returns"
    );
    assert_eq!(calls, 0, "a disarmed watchdog never calls its supervisor");
    assert!(
        !requested && lines.is_empty(),
        "a disarmed watchdog sends no request: {lines:?}"
    );
}
