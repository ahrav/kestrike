use std::process::Command;
use std::time::{Duration, Instant};

use super::process::{Interrupt, capture};

#[test]
fn a_recorded_signal_kills_a_captured_child_and_returns_the_interruption() {
    let interrupt = Interrupt::new();
    interrupt.record(libc::SIGTERM);
    interrupt.record(libc::SIGINT);
    assert_eq!(
        interrupt.recorded(),
        Some(libc::SIGTERM),
        "a later signal changes nothing"
    );
    let start = Instant::now();
    let mut command = Command::new("sleep");
    command.arg("600");
    let stop = capture(&mut command, &interrupt).expect_err("the recorded signal ends the capture");
    assert_eq!(
        stop.reason().to_string(),
        format!("interrupted by signal {}", libc::SIGTERM)
    );
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "SIGKILL ends the child: {:?}",
        start.elapsed()
    );
}
