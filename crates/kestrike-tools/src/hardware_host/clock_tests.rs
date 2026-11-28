use std::process::Command;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::{Clocks, System};

/// The monotonic reading advances at least as far as a sleep between two readings, and no further than
/// the time `Instant` counts around them.
#[test]
fn the_monotonic_reading_counts_nanoseconds() {
    let outer = Instant::now();
    let first = System.monotonic_ns().expect("the clock reads");
    thread::sleep(Duration::from_millis(20));
    let second = System.monotonic_ns().expect("the clock reads");
    let around = outer.elapsed();
    let between = Duration::from_nanos(second - first);
    assert!(between >= Duration::from_millis(20), "{between:?}");
    assert!(between <= around, "{between:?} within {around:?}");
}

/// The wall reading is the epoch's seconds.
#[test]
fn the_wall_reading_is_seconds_since_the_epoch() {
    let before = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("after the epoch");
    let wall = System.wall();
    let after = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("after the epoch");
    assert!(before.as_secs_f64() - 1e-6 <= wall && wall <= after.as_secs_f64() + 1e-6);
}

/// A reading of `time.monotonic_ns()` in a child Python, which shares the test's time namespace, lies
/// between two readings taken around the child, so the child and the test read one clock.
#[test]
fn the_monotonic_reading_is_the_clock_other_processes_read() {
    let before = System.monotonic_ns().expect("the clock reads");
    let output = Command::new("/usr/bin/python3")
        .args(["-c", "import time; print(time.monotonic_ns())"])
        .output()
        .expect("python3 starts");
    let after = System.monotonic_ns().expect("the clock reads");
    assert!(output.status.success());
    let child: u64 = String::from_utf8(output.stdout)
        .expect("UTF-8")
        .trim()
        .parse()
        .expect("a number");
    assert!(
        before <= child && child <= after,
        "{before} <= {child} <= {after}"
    );
}
