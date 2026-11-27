//! The record's states against each event, the sleep's two ends and the clocks of the seam.

use std::io;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use kestrike_tools::host_stop::{
    Delivered, Interrupted, Record, SLICE, Seam, Signal, System, sleep,
};

/// An armed record raises the delivered signal at its next read and is then disarmed; an armed record
/// whose hold ends raises the signal that waited during the hold and is then disarmed.
#[test]
fn a_raised_signal_disarms_the_controller() {
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    record.arm();
    delivered.deliver(Signal::Terminate);
    assert_eq!(record.read(), Err(Interrupted(Signal::Terminate)));
    assert!(!record.is_armed());
    assert_eq!(record.pending(), None, "the raised signal is cleared");
    record.arm();
    record.hold();
    delivered.deliver(Signal::Interrupt);
    assert_eq!(record.read(), Ok(()), "a held record raises nothing");
    assert_eq!(record.release(), Err(Interrupted(Signal::Interrupt)));
    assert!(!record.is_armed());
    assert!(!record.is_held());
}

/// An unarmed record keeps a delivered signal waiting through any number of reads, and raises it at
/// the first read once armed.
#[test]
fn an_unarmed_record_keeps_the_signal_until_it_is_armed() {
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    assert_eq!(record.read(), Ok(()), "nothing is delivered");
    delivered.deliver(Signal::Hangup);
    for _ in 0..3 {
        assert_eq!(record.read(), Ok(()));
        assert!(!record.may_raise());
    }
    assert_eq!(record.pending(), Some(Signal::Hangup));
    record.arm();
    assert!(record.may_raise());
    assert_eq!(record.read(), Err(Interrupted(Signal::Hangup)));
    assert_eq!(record.read(), Ok(()), "a signal raises once");
}

/// An armed record with nothing delivered reads clean and stays armed; a disarmed one keeps a later
/// signal waiting.
#[test]
fn an_armed_record_with_no_signal_stays_armed() {
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    record.arm();
    assert_eq!(record.read(), Ok(()));
    assert!(record.is_armed());
    record.disarm();
    delivered.deliver(Signal::Terminate);
    assert_eq!(record.read(), Ok(()));
    assert_eq!(record.pending(), Some(Signal::Terminate));
}

/// The record keeps the first of two signals delivered before a read and names it when it raises;
/// once the first is raised, a signal delivered after the raise is stored again.
#[test]
fn the_first_of_two_signals_is_the_one_raised() {
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    delivered.deliver(Signal::Terminate);
    delivered.deliver(Signal::Interrupt);
    record.arm();
    assert_eq!(record.read(), Err(Interrupted(Signal::Terminate)));
    assert_eq!(record.pending(), None);
    delivered.deliver(Signal::Interrupt);
    assert_eq!(record.pending(), Some(Signal::Interrupt));
    assert_eq!(Interrupted(Signal::Interrupt).to_string(), "SIGINT");
}

/// A signal delivered during a write that succeeds raises at the write's end; one delivered during a
/// write that fails stays waiting, and the write's own error is returned.
#[test]
fn a_held_signal_waits_for_the_write_and_a_failed_write_raises_nothing() {
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    record.arm();
    let written = record.holding(|| {
        delivered.deliver(Signal::Terminate);
        Ok::<_, io::Error>(7)
    });
    assert_eq!(written.map(|_| ()), Err(Interrupted(Signal::Terminate)));
    assert!(!record.is_armed() && !record.is_held());
    record.arm();
    let failed = record.holding(|| {
        delivered.deliver(Signal::Hangup);
        Err::<(), _>(io::Error::from_raw_os_error(libc::EIO))
    });
    let error = failed
        .expect("a failed write raises no signal")
        .expect_err("the write's error is returned");
    assert_eq!(error.raw_os_error(), Some(libc::EIO));
    assert!(record.is_armed() && !record.is_held());
    assert_eq!(record.pending(), Some(Signal::Hangup));
    let quiet = record.holding(|| Ok::<_, io::Error>(()));
    assert!(matches!(quiet, Err(Interrupted(Signal::Hangup))));
    let mut unarmed = Record::new(&delivered);
    delivered.deliver(Signal::Interrupt);
    let kept = unarmed.holding(|| Ok::<_, io::Error>(3));
    assert!(
        matches!(kept, Ok(Ok(3))),
        "an unarmed record raises nothing"
    );
    assert_eq!(unarmed.pending(), Some(Signal::Interrupt));
}

/// The sleep runs its full length when no signal may raise: with nothing delivered, with a signal and
/// the record unarmed, and with a signal and the record held.
#[test]
fn a_sleep_with_no_signal_that_may_raise_runs_its_full_length() {
    let length = Duration::from_millis(120);
    for (armed, held, signal) in [
        (true, false, None),
        (false, false, Some(Signal::Terminate)),
        (true, true, Some(Signal::Interrupt)),
    ] {
        let delivered = Delivered::new();
        let mut record = Record::new(&delivered);
        if armed {
            record.arm();
        }
        if held {
            record.hold();
        }
        if let Some(signal) = signal {
            delivered.deliver(signal);
        }
        let start = Instant::now();
        assert_eq!(sleep(&mut record, length), Ok(()));
        assert!(start.elapsed() >= length, "{:?}", start.elapsed());
        assert_eq!(record.pending(), signal, "the signal stays waiting");
    }
}

/// A signal delivered to an armed record during a sleep ends the sleep at the end of the slice in which
/// it arrived and raises; the record is then disarmed.
#[test]
fn a_signal_that_may_raise_ends_the_sleep_at_a_slice_end() {
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    record.arm();
    let delay = Duration::from_millis(150);
    let (ended, elapsed) = thread::scope(|scope| {
        scope.spawn(|| {
            thread::sleep(delay);
            delivered.deliver(Signal::Terminate);
        });
        let start = Instant::now();
        let ended = System::new().sleep(&mut record, Duration::from_secs(60));
        (ended, start.elapsed())
    });
    assert_eq!(ended, Err(Interrupted(Signal::Terminate)));
    assert!(elapsed >= delay, "{elapsed:?}");
    assert!(
        elapsed < delay + SLICE + Duration::from_millis(500),
        "{elapsed:?}"
    );
    assert!(!record.is_armed());
}

/// Every `System` reads one monotonic clock, which never steps back; the wall clock
/// reads the seconds since the epoch.
#[test]
fn the_clocks_read_monotonic_and_wall_seconds() {
    let seam = System::new();
    let first = seam.monotonic();
    let other = System::new().monotonic();
    assert!(first >= 0.0 && other >= first, "{first} {other}");
    assert!(
        other - first < 1.0,
        "two values read one clock: {first} {other}"
    );
    let mut last = first;
    for _ in 0..100 {
        let now = seam.monotonic();
        assert!(now >= last);
        last = now;
    }
    let before = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs_f64();
    let wall = seam.wall();
    let after = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs_f64();
    assert!(before <= wall && wall <= after, "{before} {wall} {after}");
}

/// A signal that may raise when a write is about to be held raises before the write, which does not
/// run; the record is then disarmed and not held. A record already held writes first and raises at
/// the release.
#[test]
fn a_signal_that_may_raise_before_the_hold_raises_before_the_write() {
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    record.arm();
    delivered.deliver(Signal::Terminate);
    let mut ran = false;
    let ended = record.holding(|| {
        ran = true;
        Ok::<_, io::Error>(())
    });
    assert!(matches!(ended, Err(Interrupted(Signal::Terminate))));
    assert!(!ran, "the write does not run");
    assert!(!record.is_armed() && !record.is_held());
    record.arm();
    record.hold();
    delivered.deliver(Signal::Interrupt);
    let mut wrote = false;
    let held = record.holding(|| {
        wrote = true;
        Ok::<_, io::Error>(1)
    });
    assert!(matches!(held, Err(Interrupted(Signal::Interrupt))));
    assert!(
        wrote,
        "an already held record writes, then raises at the release"
    );
}
