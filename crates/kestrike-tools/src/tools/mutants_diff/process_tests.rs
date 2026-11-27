use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use super::process::{Interrupt, capture};

#[test]
fn a_recorded_signal_kills_a_captured_child_and_returns_the_interruption() {
    let interrupt = Interrupt::new();
    let scratch = crate::paths_tests::Scratch::new("capture");
    let marker = scratch.0.join("marker");
    let mut command = Command::new("sh");
    command
        .args([
            "-c",
            "echo $$ > \"$1.tmp\" && mv \"$1.tmp\" \"$1\"; exec sleep 600",
            "sh",
        ])
        .arg(&marker);
    let (stop, elapsed) = std::thread::scope(|scope| {
        let signaled = scope.spawn(|| {
            let start = Instant::now();
            while !marker.exists() && start.elapsed() < Duration::from_secs(30) {
                std::thread::sleep(Duration::from_millis(5));
            }
            interrupt.record(libc::SIGTERM);
            interrupt.record(libc::SIGINT);
            Instant::now()
        });
        let stop =
            capture(&mut command, &interrupt).expect_err("the recorded signal ends the capture");
        let returned = Instant::now();
        let signaled = signaled.join().expect("the signalling thread ends");
        (stop, returned.saturating_duration_since(signaled))
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
    assert!(
        elapsed < Duration::from_secs(1),
        "the capture returned {elapsed:?} after the signal"
    );
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

#[test]
fn an_empty_command_fails_and_leaves_both_output_files_unchanged() {
    let scratch = crate::paths_tests::Scratch::new("empty-command");
    let (stdout, stderr) = (scratch.0.join("out"), scratch.0.join("err"));
    std::fs::write(&stdout, "out before").expect("written");
    std::fs::write(&stderr, "err before").expect("written");
    let stop = super::process::supervise(&Interrupt::new(), &[], &stdout, &stderr, None, &[])
        .expect_err("an empty command fails");
    assert_eq!(stop.code(), 1);
    assert_eq!(
        (
            std::fs::read_to_string(&stdout).expect("read"),
            std::fs::read_to_string(&stderr).expect("read")
        ),
        ("out before".to_owned(), "err before".to_owned())
    );
}
