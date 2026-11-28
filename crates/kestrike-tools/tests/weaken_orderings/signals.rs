//! The run under a handled signal, the progress it leaves, and the mode of its two report files.

use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

use super::fixture::*;

#[test]
fn an_interrupted_run_restores_the_plant_and_keeps_the_finished_results() {
    let fixture = Fixture::new("interrupted");
    fixture.commit();
    let tests = run_tests();
    for number in [libc::SIGTERM, libc::SIGHUP] {
        let name = format!("interrupted-{number}");
        let mut child = fixture.start(
            &[CREDIT_ROW, RUN_FENCE],
            &fixture.work(&name),
            plan(&[(&tests[1], &[("planted", "sleep")])]),
        );
        fixture.wait_for(".sleeping");
        let started = Instant::now();
        child.signal(number);
        let status = child.wait(Duration::from_secs(120));
        assert!(started.elapsed() < Duration::from_secs(50));
        assert!(ended_by(status, libc::SIGINT), "{status:?}");
        assert_eq!(
            fixture.halt_line(),
            format!("weaken-orderings: signal {number}")
        );
        assert!(
            fixture.exists(".stopped"),
            "the sleeping test received SIGTERM"
        );
        let work = fixture.resolved(&name);
        assert!(!work.join("report.json").exists());
        let progress = read_json(&work.join("progress.json"));
        assert_eq!(string(get(&progress, "active")), RUN_FENCE);
        assert_eq!(results(&progress, CREDIT_ROW), ["survived"; 4]);
        let fence: Vec<String> = row_results(&progress, RUN_FENCE)
            .iter()
            .map(|entry| string(get(entry, "test")))
            .collect();
        assert_eq!(fence, tests[..1]);
        assert!(!has(get(get(&progress, "rows"), RUN_FENCE), "agrees"));
        fixture.assert_restored(&work);
    }
}

#[test]
fn progress_records_each_finished_baseline_test_and_skipped_row() {
    let fixture = Fixture::new("progress");
    fixture.commit();
    let tests = run_tests();
    assert!(tests[1] < tests[0]);
    let work = fixture.work("baseline-progress");
    let mut child = fixture.start(
        &[RUN_FENCE],
        &work,
        plan(&[(&tests[0], &[("clean", "sleep")])]),
    );
    fixture.wait_for(".sleeping");
    let progress = read_json(&fixture.resolved("baseline-progress").join("progress.json"));
    child.signal(libc::SIGTERM);
    let status = child.wait(Duration::from_secs(120));
    assert!(ended_by(status, libc::SIGINT), "{status:?}");
    assert_eq!(fixture.halt_line(), "weaken-orderings: signal 15");
    assert_eq!(string(get(&progress, "active")), "baseline");
    let baseline: Vec<String> = items(get(&progress, "baseline"))
        .iter()
        .map(|entry| string(get(entry, "test")))
        .collect();
    assert_eq!(baseline, tests[1..]);
    let ran = fixture.run_with(
        &["word-install"],
        Opts {
            work: Some(fixture.work("skipped")),
            ..Opts::default()
        },
    );
    assert_eq!(ran.code(), Some(0), "{}", ran.stderr);
    let progress = read_json(&fixture.resolved("skipped").join("progress.json"));
    assert_eq!(get(&progress, "active"), &kestrike_tools::json::Value::Null);
    assert_eq!(
        string(get(get(get(&progress, "rows"), "word-install"), "result")),
        "skipped"
    );
}

/// Both JSON files take mode 0666 less the run's umask, as each is given once written; in a directory
/// whose default ACL grants every class read and write, where a plain create keeps 0666 under umask 077,
/// they still take 0600. Where the filesystem refuses the default ACL the ACL row is left out with a line
/// that says so.
#[test]
fn report_files_take_the_umask_mode() {
    let fixture = Fixture::new("umask");
    fixture.commit();
    for (umask, mode) in [(0o022, 0o644), (0o077, 0o600)] {
        let name = format!("umask-{umask:o}");
        let ran = fixture.run_with(
            &[RUN_FENCE],
            Opts {
                work: Some(fixture.work(&name)),
                umask: Some(umask),
                ..Opts::default()
            },
        );
        assert_eq!(ran.code(), Some(0), "{}", ran.stderr);
        for file in ["report.json", "progress.json"] {
            let status = std::fs::metadata(fixture.resolved(&name).join(file)).expect("a status");
            assert_eq!(status.permissions().mode() & 0o777, mode, "{file}");
        }
    }
    let shared = fixture.resolved("acl");
    std::fs::create_dir(&shared).expect("made");
    let set = std::process::Command::new("setfacl")
        .args(["-d", "-m", "u::rwx,g::rwx,o::rwx"])
        .arg(&shared)
        .status();
    if !matches!(&set, Ok(status) if status.success()) {
        eprintln!("the default ACL row is left out: setfacl gave {set:?}");
        return;
    }
    let control = shared.join("control");
    let made = std::process::Command::new("sh")
        .args(["-c", "umask 077 && : > \"$1\"", "sh"])
        .arg(&control)
        .status()
        .expect("sh starts");
    assert!(made.success());
    assert_eq!(
        std::fs::metadata(&control)
            .expect("stats")
            .permissions()
            .mode()
            & 0o777,
        0o666,
        "the default ACL sets a plain create's mode"
    );
    let ran = fixture.run_with(
        &[RUN_FENCE],
        Opts {
            work: Some(fixture.work("acl/work")),
            umask: Some(0o077),
            ..Opts::default()
        },
    );
    assert_eq!(ran.code(), Some(0), "{}", ran.stderr);
    for file in ["report.json", "progress.json"] {
        let status = std::fs::metadata(shared.join("work").join(file)).expect("a status");
        assert_eq!(
            status.permissions().mode() & 0o777,
            0o600,
            "{file} under the ACL"
        );
    }
}

/// A planted test that outlives SIGTERM keeps running through the stop's grace; once it has received
/// that SIGTERM the case sends the run SIGHUP, a second delivery, which alone can end the stop's 45 s grace
/// before 30 s. The run then kills the test's group, writes the plant back, leaves no staging file and
/// ends by SIGINT.
#[test]
fn a_second_signal_during_the_stop_of_a_planted_test_still_restores_the_plant() {
    let fixture = Fixture::new("second-signal");
    fixture.commit();
    let tests = run_tests();
    let work = fixture.work("second-signal");
    let mut child = fixture.start(
        &[RUN_FENCE],
        &work,
        plan(&[(&tests[1], &[("planted", "sleep-twice")])]),
    );
    fixture.wait_for(".sleeping");
    let started = Instant::now();
    child.signal(libc::SIGTERM);
    fixture.wait_for(".stopped");
    child.signal(libc::SIGHUP);
    let status = child.wait(Duration::from_secs(120));
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "the second delivery ended the 45 s grace: {:?}",
        started.elapsed()
    );
    assert!(ended_by(status, libc::SIGINT), "{status:?}");
    assert_eq!(fixture.halt_line(), "weaken-orderings: signal 15");
    assert!(
        fixture.exists(".stopped"),
        "the sleeping test received SIGTERM"
    );
    let work = fixture.resolved("second-signal");
    assert!(!work.join("report.json").exists());
    fixture.assert_restored(&work);
}
