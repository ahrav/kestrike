//! A surviving `/proc/<pid>` entry detects both a live child and a zombie.

use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::run::{Failure, OUTPUT_BOUND, Stderr, run};
use crate::store::fixture::{Case, processes};

fn shell(script: &str) -> Command {
    let mut command = Command::new("/bin/sh");
    command.args(["-c", script]);
    command
}

fn reaped(pid: &Path) {
    let pid = fs::read_to_string(pid).expect("the child wrote its pid");
    assert!(
        !Path::new(&format!("/proc/{}", pid.trim())).exists(),
        "the direct child is reaped"
    );
}

fn stop_descendant(pid: &Path) {
    let pid = fs::read_to_string(pid).expect("the descendant pid is recorded");
    Command::new("kill")
        .args(["-KILL", pid.trim()])
        .status()
        .expect("kill runs");
}

/// Counting pipes isolates the reader-closed check from the files and
/// directories other threads' tests open concurrently.
fn pipes() -> usize {
    fs::read_dir("/proc/self/fd")
        .expect("fds list")
        .filter_map(|entry| fs::read_link(entry.ok()?.path()).ok())
        .filter(|target| target.to_string_lossy().starts_with("pipe:"))
        .count()
}

#[test]
fn a_stream_past_its_bound_is_oversize() {
    let _processes = processes();
    let case = Case::new();
    let pid = case.root.join("pid");
    let bytes = |count: u64| format!("head -c {count} /dev/zero");
    for script in [bytes(OUTPUT_BOUND), format!("{} >&2", bytes(OUTPUT_BOUND))] {
        let ran = run(&mut shell(&script), Stderr::Capture, None).expect("the bound is admitted");
        assert!(ran.status.success());
        assert_eq!((ran.stdout.len() + ran.stderr.len()) as u64, OUTPUT_BOUND);
    }
    for script in [
        bytes(OUTPUT_BOUND + 1),
        format!("{} >&2", bytes(OUTPUT_BOUND + 1)),
        format!("{}; exec sleep 30", bytes(OUTPUT_BOUND + 1)),
    ] {
        let started = Instant::now();
        let script = format!("echo $$ > {pid:?}; {script}");
        let failed = run(&mut shell(&script), Stderr::Capture, None);
        assert!(
            matches!(failed, Err(Failure::Oversize)),
            "{script}: {failed:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(10));
        reaped(&pid);
    }
}

#[test]
fn a_child_or_stream_past_its_deadline_is_stopped() {
    let _processes = processes();
    let case = Case::new();
    let pid = case.root.join("pid");
    let descendant = case.root.join("descendant");
    let deadline = Duration::from_millis(100);
    for script in [
        "exec sleep 30".to_owned(),
        format!("sleep 30 & echo $! > {descendant:?}; exit 0"),
        format!("sleep 30 >/dev/null & echo $! > {descendant:?}; exit 0"),
    ] {
        let started = Instant::now();
        let script = format!("echo $$ > {pid:?}; {script}");
        let before = pipes();
        let failed = run(&mut shell(&script), Stderr::Capture, Some(deadline));
        assert!(
            matches!(failed, Err(Failure::Deadline)),
            "{script}: {failed:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(10), "{script}");
        reaped(&pid);
        assert_eq!(pipes(), before);
        if descendant.exists() {
            stop_descendant(&descendant);
            fs::remove_file(&descendant).expect("pid removed");
        }
    }
}

#[test]
fn an_oversize_stream_is_observed_while_the_other_stream_stays_open() {
    let _processes = processes();
    let case = Case::new();
    let descendant = case.root.join("descendant");
    for (held, overflowing) in [(">/dev/null", ""), ("2>/dev/null", ">&2")] {
        let script = format!(
            "sleep 30 {held} & echo $! > {descendant:?}; head -c {} /dev/zero {overflowing}",
            OUTPUT_BOUND + 1
        );
        let started = Instant::now();
        let failed = run(&mut shell(&script), Stderr::Capture, None);
        stop_descendant(&descendant);
        assert!(matches!(failed, Err(Failure::Oversize)), "{failed:?}");
        assert!(started.elapsed() < Duration::from_secs(10));
    }
}

#[test]
fn inherited_stderr_overrides_a_preconfigured_pipe() {
    let _processes = processes();
    let mut command = shell("echo done; echo err >&2");
    command.stderr(Stdio::piped());
    let ran = run(&mut command, Stderr::Inherit, Some(Duration::from_secs(10)))
        .expect("the quick child finishes");
    assert_eq!(ran.stdout, b"done\n");
    assert!(ran.stderr.is_empty());
}
