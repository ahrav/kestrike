//! The run's exit 4: a test that changes a scoped file, under the baseline or under a plant, and the
//! restore of the plant it replaced.

use std::fs;
use std::os::unix::fs::PermissionsExt;

use super::fixture::*;
use super::standins::scoped_files;

fn privileged() -> bool {
    // SAFETY: `geteuid` takes no argument and touches no memory of the caller.
    unsafe { libc::geteuid() == 0 }
}

#[test]
fn a_changed_scoped_file_stops_the_run_with_exit_4() {
    let fixture = Fixture::new("changed");
    fixture.commit();
    let files = scoped_files(&fixture.repo);
    let mut catalog = fixture.catalog.clone();
    let path = string(row(&mut catalog, RUN_FENCE).get("path").expect("a path"));
    assert_ne!(files[0], path);
    assert_eq!(files[3], path);
    let differ = format!(
        "the scoped files ['{}'] differ from the unweakened copy",
        files[0]
    );
    let mut modes = vec![
        ("drift", differ.clone()),
        ("link", differ.clone()),
        ("gone-other", differ.clone()),
        ("dir-other", differ.clone()),
    ];
    if !privileged() {
        modes.push(("unreadable-other", differ.clone()));
    }
    modes.push(("drift-own", format!("the plant of {} changed", files[3])));
    modes.push((
        "dir-own",
        format!("the unweakened {} cannot be written back", files[3]),
    ));
    let tests = run_tests();
    for (mode, wanted) in modes {
        let name = format!("changed-{mode}");
        let ran = fixture.run_with(
            &[RUN_FENCE],
            Opts {
                work: Some(fixture.work(&name)),
                plan: Some(plan(&[(&tests[0], &[("planted", mode)])])),
                ..Opts::default()
            },
        );
        assert_eq!(ran.code(), Some(4), "{mode}: {}", ran.stderr);
        assert!(ran.stderr.contains(&wanted), "{mode}: {}", ran.stderr);
        assert_eq!(ran.stderr.lines().count(), 2, "{}", ran.stderr);
        assert!(ran.report.is_none());
        let progress = read_json(&fixture.resolved(&name).join("progress.json"));
        assert_eq!(string(get(&progress, "active")), RUN_FENCE, "{mode}");
    }
}

#[test]
fn a_baseline_test_that_changes_a_scoped_file_stops_the_run_with_exit_4() {
    let fixture = Fixture::new("baseline-drift");
    fixture.commit();
    let changed = scoped_files(&fixture.repo)[0].clone();
    let tests = run_tests();
    let mut sorted = tests.to_vec();
    sorted.sort();
    let until = sorted
        .iter()
        .position(|test| *test == tests[0])
        .expect("listed");
    let ran_tests = sorted[..=until].to_vec();
    for mode in ["drift", "gone-other"] {
        let name = format!("baseline-{mode}");
        let ran = fixture.run_with(
            &[RUN_FENCE],
            Opts {
                work: Some(fixture.work(&name)),
                plan: Some(plan(&[(&tests[0], &[("clean", mode)])])),
                ..Opts::default()
            },
        );
        assert_eq!(ran.code(), Some(4), "{mode}: {}", ran.stderr);
        let wanted = format!(
            "the scoped files ['{changed}'] differ from the unweakened copy after the baseline test {}",
            tests[0]
        );
        assert!(ran.stderr.contains(&wanted), "{mode}: {}", ran.stderr);
        assert_eq!(ran.stderr.lines().count(), 2, "{}", ran.stderr);
        assert_eq!(fixture.logged("clean"), ran_tests);
        assert_eq!(fixture.lines(".log").len(), ran_tests.len());
        let progress = read_json(&fixture.resolved(&name).join("progress.json"));
        let baseline: Vec<String> = items(get(&progress, "baseline"))
            .iter()
            .map(|entry| string(get(entry, "test")))
            .collect();
        assert_eq!(baseline, ran_tests);
        assert_eq!(get(&progress, "rows"), &object(&[]));
        assert!(ran.report.is_none());
    }
}

#[test]
fn a_planted_file_a_test_removed_or_replaced_with_an_unreadable_link_is_written_back_with_exit_4() {
    let fixture = Fixture::new("replaced");
    fixture.commit();
    let files = scoped_files(&fixture.repo);
    let mut catalog = fixture.catalog.clone();
    let name = string(row(&mut catalog, RUN_FENCE).get("path").expect("a path"));
    assert_eq!(files[3], name);
    let mut modes = vec!["gone", "dangling", "loop"];
    if !privileged() {
        modes.push("unreadable");
    }
    let tests = run_tests();
    for mode in modes {
        let work = format!("replaced-{mode}");
        let ran = fixture.run_with(
            &[RUN_FENCE],
            Opts {
                work: Some(fixture.work(&work)),
                plan: Some(plan(&[(&tests[0], &[("planted", mode)])])),
                ..Opts::default()
            },
        );
        assert_eq!(ran.code(), Some(4), "{mode}: {}", ran.stderr);
        assert!(
            ran.stderr.contains(&format!("the plant of {name} changed")),
            "{mode}: {}",
            ran.stderr
        );
        assert_eq!(ran.stderr.lines().count(), 2, "{}", ran.stderr);
        let copy = fixture.resolved(&work).join("copy");
        let restored = copy.join(&name);
        assert!(!restored.is_symlink(), "{mode}");
        assert_eq!(
            fs::read(&restored).expect("reads"),
            fs::read(fixture.repo.join(&name)).expect("reads")
        );
        let mode_of =
            |path: &std::path::Path| fs::metadata(path).expect("a status").permissions().mode();
        assert_eq!(mode_of(&restored), mode_of(&copy.join(&files[0])), "{mode}");
        assert!(ran.report.is_none());
    }
}
