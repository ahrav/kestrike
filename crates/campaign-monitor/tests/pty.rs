//! Tests that run the built binary. The terminal tests use a pseudo-terminal
//! because raw mode, the alternate screen, bracketed paste and their restore
//! paths require a terminal; the argument tests read the exit code and
//! stderr.

mod common;

use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

use common::{Harness, snapshot};

const BIN: &str = env!("CARGO_BIN_EXE_campaign-monitor");

fn monitor(name: &str, env: &[(&str, &str)]) -> (Harness, std::path::PathBuf) {
    let path = snapshot(name);
    let file = path.to_str().unwrap().to_owned();
    let harness = Harness::spawn(BIN, &["--file", &file, "--no-history"], env);
    (harness, path)
}

#[test]
fn startup_then_2_shows_signals_and_q_exits_cleanly() {
    let (mut h, path) = monitor("round-trip", &[]);
    h.wait_until("the first snapshot", |s| s.contains("settled by outcome"));
    assert!(h.parser.screen().alternate_screen());
    assert!(h.parser.screen().bracketed_paste());
    h.send(b"2");
    h.wait_until("the Signals tab", |s| {
        s.contains(" detail ") && !s.contains("settled by outcome")
    });
    h.send(b"q");
    let status = h.wait_exit();
    assert!(status.success(), "{status:?}");
    h.assert_restored();
    std::fs::remove_file(path).unwrap();
}

#[test]
fn sigterm_restores_the_terminal() {
    let (mut h, path) = monitor("sigterm", &[]);
    h.wait_until("the first snapshot", |s| s.contains("settled by outcome"));
    let pid = h.child.process_id().expect("pid");
    let killed = std::process::Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status()
        .unwrap();
    assert!(killed.success());
    assert_eq!(h.wait_exit().exit_code(), 128 + 15);
    h.assert_restored();
    std::fs::remove_file(path).unwrap();
}

#[test]
fn a_panic_restores_the_terminal() {
    let (mut h, path) = monitor("panic", &[("CAMPAIGN_MONITOR_PANIC", "1")]);
    h.wait_until("the first snapshot", |s| s.contains("settled by outcome"));
    h.send(b"j");
    let status = h.wait_exit();
    assert_eq!(status.exit_code(), 101, "{status:?}");
    h.assert_restored();
    let raw = String::from_utf8_lossy(&h.raw);
    assert!(raw.contains("\x1b[?2004l"), "bracketed paste left enabled");
    let begins = raw.matches("\x1b[?2026h").count();
    let ends = raw.matches("\x1b[?2026l").count();
    assert!(begins >= 1 && ends > begins, "{begins} begins, {ends} ends");
    assert!(
        h.parser
            .screen()
            .contents()
            .contains("CAMPAIGN_MONITOR_PANIC"),
        "{}",
        h.parser.screen().contents()
    );
    std::fs::remove_file(path).unwrap();
}

/// Polls `pid` with a 5 s deadline, treating zombies as exited.
fn alive(pid: i32) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    // SAFETY: `kill` takes scalar arguments; signal 0 checks process
    // existence and permissions.
    while unsafe { libc::kill(pid, 0) } == 0 {
        let state = std::process::Command::new("ps")
            .args(["-o", "stat=", "-p", &pid.to_string()])
            .output()
            .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
            .unwrap_or_default();
        if state.starts_with('Z') {
            return false;
        }
        if Instant::now() > deadline {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

#[test]
fn a_panic_kills_the_snapshot_command_in_flight() {
    let dir = std::env::temp_dir().join(format!(
        "campaign-monitor-pty-inflight-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let pid_file = dir.join("pid");
    let campaign = dir.join("campaign");
    std::fs::write(
        &campaign,
        format!(
            "#!/bin/sh\n/bin/sleep 30 & echo $! > '{}'; wait\n",
            pid_file.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&campaign, std::fs::Permissions::from_mode(0o755)).unwrap();
    let state = dir.to_str().unwrap().to_owned();
    let mut h = Harness::spawn(
        BIN,
        &[
            "--state",
            &state,
            "--campaign",
            campaign.to_str().unwrap(),
            "--no-history",
        ],
        &[("CAMPAIGN_MONITOR_PANIC", "1")],
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    let pid = loop {
        let text = std::fs::read_to_string(&pid_file).unwrap_or_default();
        if let Ok(pid) = text.trim().parse::<i32>() {
            break pid;
        }
        assert!(
            Instant::now() < deadline,
            "the snapshot command did not start"
        );
        h.pump(Duration::from_millis(20));
    };
    h.send(b"j");
    assert_eq!(h.wait_exit().exit_code(), 101);
    h.assert_restored();
    assert!(!alive(pid), "the snapshot command outlived the monitor");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_usage_error_echoes_its_argument_without_control_characters() {
    let output = std::process::Command::new(BIN)
        .arg("--bogus\u{1b}[31mX\u{7}")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(64));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unknown option --bogus"), "{stderr}");
    assert!(
        !stderr.contains('\u{1b}') && !stderr.contains('\u{7}'),
        "{stderr:?}"
    );
}

#[test]
fn an_argument_that_is_not_utf8_is_a_usage_error_rather_than_a_panic() {
    use std::os::unix::ffi::OsStrExt;
    let output = std::process::Command::new(BIN)
        .args(["--file"])
        .arg(std::ffi::OsStr::from_bytes(b"/tmp/\xff.json"))
        .arg("--no-history")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(64), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("UTF-8"), "{stderr}");
}
