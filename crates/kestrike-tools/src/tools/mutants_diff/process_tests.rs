use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use super::process::{Interrupt, capture};

#[test]
fn a_recorded_signal_kills_a_captured_child_and_returns_the_interruption() {
    let interrupt = Interrupt::new();
    let marker =
        std::env::temp_dir().join(format!("kestrike-tools-capture-{}", std::process::id()));
    let _ = std::fs::remove_file(&marker);
    let script = format!(
        "echo $$ > '{}.tmp' && mv '{0}.tmp' '{0}'; exec sleep 600",
        marker.display()
    );
    let mut command = Command::new("sh");
    command.args(["-c", &script]);
    let (stop, elapsed) = std::thread::scope(|scope| {
        scope.spawn(|| {
            let start = Instant::now();
            while !marker.exists() && start.elapsed() < Duration::from_secs(30) {
                std::thread::sleep(Duration::from_millis(5));
            }
            interrupt.record(libc::SIGTERM);
            interrupt.record(libc::SIGINT);
        });
        let stop =
            capture(&mut command, &interrupt).expect_err("the recorded signal ends the capture");
        (stop, Instant::now())
    });
    assert_eq!(
        interrupt.recorded(),
        Some(libc::SIGTERM),
        "a later signal changes nothing"
    );
    assert_eq!(
        stop.reason().to_string(),
        format!("interrupted by signal {}", libc::SIGTERM)
    );
    let pid = std::fs::read_to_string(&marker).expect("the child wrote its pid");
    let pid = pid.trim();
    assert!(
        !Path::new(&format!("/proc/{pid}")).exists(),
        "the child {pid} is killed and reaped"
    );
    assert!(elapsed.elapsed() < Duration::from_secs(1));
    std::fs::remove_file(&marker).expect("the marker is removed");
}

#[test]
fn a_capture_waits_for_the_child_and_its_output() {
    let interrupt = Interrupt::new();
    let mut command = Command::new("sh");
    command.args(["-c", "printf out; printf err >&2; exit 3"]);
    let output = capture(&mut command, &interrupt)
        .expect("no signal")
        .expect("the child runs");
    assert_eq!(
        (
            output.status.code(),
            output.stdout.as_slice(),
            output.stderr.as_slice()
        ),
        (Some(3), &b"out"[..], &b"err"[..])
    );
}
