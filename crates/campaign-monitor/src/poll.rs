//! The watch poll schedule: one fetch at a time, each followed by a pause
//! of at least the interval and at least four times the fetch. The poller
//! thread owns the history and derives every snapshot it fetches, so the
//! terminal loop only swaps results in.

use std::sync::Arc;
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender};
use std::time::{Duration, Instant, SystemTime};

use crate::history::History;
use crate::snapshot::Snapshot;
use crate::state::derived::Derived;

/// One poller result: the derived snapshot or the fetch error, how long
/// the fetch took, and when it returned on the monotonic and the wall
/// clock. The wall clock keeps counting while the machine sleeps, which the
/// monotonic clock does not on Linux and Apple targets.
pub struct Fetch {
    pub result: Result<Arc<Derived>, String>,
    pub elapsed: Duration,
    pub completed: Instant,
    pub completed_wall: SystemTime,
}

impl Fetch {
    /// A result whose fetch returned now.
    pub fn now(result: Result<Arc<Derived>, String>, elapsed: Duration) -> Self {
        Self {
            result,
            elapsed,
            completed: Instant::now(),
            completed_wall: SystemTime::now(),
        }
    }
}

/// The pause after a fetch that took `elapsed`: at least `interval`, and at
/// least four times the fetch so a slow source is polled less often.
pub fn poll_wait(interval: Duration, elapsed: Duration) -> Duration {
    interval.max(elapsed.saturating_mul(4))
}

/// Waits after a fetch that took `elapsed` until the next fetch is due:
/// [`poll_wait`] of `interval`, or only four times the fetch once a refresh
/// is `asked` or a request arrives on `requested`. The interval counts the
/// larger of the monotonic and wall clock readings, checked at least once a
/// second, so time the machine slept counts; the four-fetch floor counts
/// monotonic time. Returns `false` when every request sender is gone.
pub fn pause(
    requested: &Receiver<Instant>,
    interval: Duration,
    elapsed: Duration,
    asked: bool,
) -> bool {
    let (done, wall) = (Instant::now(), SystemTime::now());
    let floor = poll_wait(Duration::ZERO, elapsed);
    let wait = poll_wait(interval, elapsed);
    let mut asked = asked;
    loop {
        // The 4T floor counts only monotonic time, so a forward wall-clock
        // step cannot cut it short; the interval also counts slept time.
        let monotonic = done.elapsed();
        let left = if asked {
            floor.checked_sub(monotonic)
        } else {
            let slept = monotonic.max(wall.elapsed().unwrap_or_default());
            floor.checked_sub(monotonic).max(wait.checked_sub(slept))
        };
        let Some(left) = left.filter(|left| !left.is_zero()) else {
            return true;
        };
        match requested.recv_timeout(left.min(Duration::from_secs(1))) {
            Ok(_) => asked = true,
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return false,
        }
    }
}

/// Runs the watch poller until either channel closes: fetches with
/// `fetch`, derives each snapshot against `history` with
/// [`Derived::observe`], sends each result through `wrap` on `results`,
/// and pauses with [`pause`]. A result's completion time is when its fetch
/// returned, before the derivation. A refresh request on `requested` made
/// before a fetch returned is answered by it and leaves the channel before
/// the derivation; a later one, including one made during the derivation
/// or while the send waits for room, shortens the next pause. The fetch time is the larger of the monotonic and wall
/// clock readings, so time the machine slept during it counts.
pub fn poll<E>(
    mut fetch: impl FnMut() -> Result<Snapshot, String>,
    mut history: History,
    results: &SyncSender<E>,
    wrap: impl Fn(Fetch) -> E,
    requested: &Receiver<Instant>,
    interval: Duration,
) {
    loop {
        let (started, wall) = (Instant::now(), SystemTime::now());
        let fetched = fetch();
        let elapsed = started.elapsed().max(wall.elapsed().unwrap_or_default());
        let (returned, returned_wall) = (Instant::now(), SystemTime::now());
        let mut asked = false;
        while let Ok(at) = requested.try_recv() {
            asked |= at > returned;
        }
        let result = fetched.map(|snapshot| Arc::new(Derived::observe(snapshot, &mut history)));
        let done = Fetch {
            result,
            elapsed,
            completed: returned,
            completed_wall: returned_wall,
        };
        if results.send(wrap(done)).is_err() || !pause(requested, interval, elapsed, asked) {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_poll_waits_for_the_interval_or_four_fetches_whichever_is_longer() {
        let second = Duration::from_secs(1);
        assert_eq!(poll_wait(15 * second, 2 * second), 15 * second);
        assert_eq!(poll_wait(15 * second, 10 * second), 40 * second);
        assert_eq!(poll_wait(second, Duration::MAX), Duration::MAX);
    }

    #[test]
    fn a_refresh_request_cuts_the_pause_to_four_fetches_and_a_closed_channel_ends_it() {
        let (refresh, requested) = std::sync::mpsc::sync_channel(1);
        refresh.send(Instant::now()).unwrap();
        let started = Instant::now();
        assert!(pause(
            &requested,
            Duration::from_secs(600),
            Duration::from_millis(10),
            false
        ));
        let waited = started.elapsed();
        assert!(waited >= Duration::from_millis(40), "{waited:?}");
        assert!(waited < Duration::from_secs(5), "{waited:?}");
        let started = Instant::now();
        assert!(pause(
            &requested,
            Duration::from_millis(10),
            Duration::from_millis(15),
            false
        ));
        assert!(started.elapsed() >= Duration::from_millis(60));
        drop(refresh);
        assert!(!pause(
            &requested,
            Duration::from_secs(600),
            Duration::ZERO,
            false
        ));
    }

    /// A request made during the fetch is answered by it and leaves the
    /// one-slot channel before the derivation, so a request made during
    /// the derivation is queued and cuts the next pause.
    #[test]
    fn a_refresh_asked_during_the_derivation_cuts_the_next_pause() {
        use std::os::unix::fs::OpenOptionsExt;
        let dir = std::env::temp_dir().join(format!(
            "campaign-monitor-poll-derive-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("history.jsonl");
        let holder = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .open(dir.join("history.jsonl.lock"))
            .unwrap();
        holder.lock().unwrap();
        let (snapshots, received) = std::sync::mpsc::sync_channel(1);
        let (refresh, requested) = std::sync::mpsc::sync_channel(1);
        let fetches = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = fetches.clone();
        let mut during_fetch = Some(refresh.clone());
        let history = History::open(&path).unwrap();
        let poller = std::thread::spawn(move || {
            poll(
                || {
                    counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    // The sender is dropped after the first fetch, so closing
                    // the test's sender ends the poller.
                    if let Some(sender) = during_fetch.take() {
                        sender.send(Instant::now()).unwrap();
                    }
                    Ok(crate::state::tests::parsed(serde_json::json!({})))
                },
                history,
                &snapshots,
                |fetch| fetch,
                &requested,
                Duration::from_secs(600),
            );
        });
        let count = || fetches.load(std::sync::atomic::Ordering::SeqCst);
        while count() < 1 {
            std::thread::sleep(Duration::from_millis(5));
        }
        // The fetch returned and the derivation waits for the history lock.
        std::thread::sleep(Duration::from_millis(200));
        assert!(
            refresh.try_send(Instant::now()).is_ok(),
            "the request made during the fetch still holds the slot"
        );
        holder.unlock().unwrap();
        received.recv_timeout(Duration::from_secs(5)).unwrap();
        received.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(count(), 2);
        drop(received);
        drop(refresh);
        poller.join().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_refresh_asked_during_a_blocked_send_cuts_the_next_pause() {
        let (snapshots, received) = std::sync::mpsc::sync_channel(1);
        let (refresh, requested) = std::sync::mpsc::sync_channel(1);
        let fetches = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = fetches.clone();
        let poller = std::thread::spawn(move || {
            poll(
                || {
                    counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Err("no source".into())
                },
                History::in_memory(),
                &snapshots,
                |fetch| fetch,
                &requested,
                Duration::from_secs(600),
            );
        });
        let count = || fetches.load(std::sync::atomic::Ordering::SeqCst);
        while count() < 1 {
            std::thread::sleep(Duration::from_millis(5));
        }
        // A refresh ends the first pause; the second result then waits on a
        // full buffer, and a refresh asked during that wait must survive it.
        refresh.send(Instant::now()).unwrap();
        while count() < 2 {
            std::thread::sleep(Duration::from_millis(5));
        }
        std::thread::sleep(Duration::from_millis(20));
        refresh.send(Instant::now()).unwrap();
        assert!(received.recv().unwrap().result.is_err());
        received.recv_timeout(Duration::from_secs(5)).unwrap();
        received.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(count(), 3);
        drop(received);
        drop(refresh);
        poller.join().unwrap();
    }
}
