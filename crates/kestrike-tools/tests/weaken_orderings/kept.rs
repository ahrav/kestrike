//! The run's behaviors that the script's own statements give and that stand as kept defects, each pinned
//! as the run gives it, and the fixture's own writes into a clone that tracks links.

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;
use std::process::Command;

use kestrike_tools::json::{self, Value};
use kestrike_tools::orderings::check::{CATALOG, GENMC};

use super::fixture::*;

fn git(repo: &Path, args: &[&str]) {
    let done = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args([
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(["-c", "core.hooksPath=/dev/null"])
        .args(args)
        .status()
        .expect("git starts");
    assert!(done.success(), "git {args:?}");
}

/// The fixture replaces the lane script and the catalog of a clone that tracks a link at each by a new
/// regular file renamed over the link, so each link's target keeps its bytes.
#[test]
fn the_fixture_replaces_a_tracked_link_and_its_target_keeps_its_bytes() {
    let outside = super::Scratch::new("kept-outside");
    let (lane, catalog) = (outside.0.join("lane"), outside.0.join("catalog"));
    let outside_lane = b"#!/bin/sh\nexit 0\n".to_vec();
    let outside_catalog = fs::read(super::top().join(CATALOG)).expect("reads");
    fs::write(&lane, &outside_lane).expect("written");
    fs::write(&catalog, &outside_catalog).expect("written");
    let fixture = Fixture::prepared("kept-links", |repo| {
        for (name, target) in [("scripts/rust-lane.sh", &lane), (CATALOG, &catalog)] {
            fs::remove_file(repo.join(name)).expect("removed");
            symlink(target, repo.join(name)).expect("linked");
        }
        git(repo, &["add", "-A"]);
        git(repo, &["commit", "-qm", "links"]);
    });
    fixture.commit();
    assert_eq!(fs::read(&lane).expect("reads"), outside_lane);
    assert_eq!(fs::read(&catalog).expect("reads"), outside_catalog);
    for name in ["scripts/rust-lane.sh", CATALOG] {
        let status = fs::symlink_metadata(fixture.repo.join(name)).expect("stats");
        assert!(status.is_file(), "{name} is a regular file");
    }
}

/// A declared GenMC case whose name holds path parts reaches the lane's command line as the declaration
/// spells it: the run derives the lane's arguments and the case's evidence names from it, and the lane
/// stand-in records the arguments and writes nothing for such a case.
#[test]
fn a_genmc_case_name_with_path_parts_reaches_the_lane_as_declared() {
    let fixture = Fixture::new("kept-case-name");
    let declaration = fixture.repo.join(GENMC);
    let mut declared = read_json(&declaration);
    let case = get(get(&declared, "cases"), "join-production").clone();
    let Value::Object(object) = &mut declared else {
        panic!("the declaration is an object");
    };
    let Some(Value::Object(cases)) = object.get_mut("cases") else {
        panic!("the declaration holds cases");
    };
    cases.insert("join/../../escape", case);
    replace_entry(&fixture.repo, GENMC, json::line(&declared).as_bytes());
    fixture.commit_with(|catalog| {
        needing(
            catalog,
            JOIN_ROW,
            vec![entry("genmc", &["join/../../escape"], JOIN_FREED)],
        );
    });
    let ran = fixture.run_rows(&[JOIN_ROW]);
    assert_eq!(
        ran.code(),
        Some(3),
        "the baseline case has no verdict: {}",
        ran.stderr
    );
    let calls = fixture.lines(".lane");
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert!(
        calls[0].ends_with(" genmc scheduled join/../../escape"),
        "{calls:?}"
    );
    for directory in [fixture.resolved("work"), fixture.base.clone()] {
        let names: Vec<String> = fs::read_dir(&directory)
            .expect("lists")
            .map(|entry| {
                entry
                    .expect("lists")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .filter(|name| name.contains("escape"))
            .collect();
        assert_eq!(names, Vec::<String>::new(), "{}", directory.display());
    }
}

/// A tracked `.gitattributes` that marks a file `export-ignore` leaves that file out of the copy, which
/// `git archive` makes, while the report names the revision that holds it.
#[test]
fn an_export_ignore_attribute_leaves_a_tracked_file_out_of_the_copy() {
    let fixture = Fixture::new("kept-attributes");
    replace_entry(
        &fixture.repo,
        ".gitattributes",
        b"SECURITY.md export-ignore\n",
    );
    let revision = fixture.commit();
    let ran = fixture.run_rows(&[RUN_FENCE]);
    assert_eq!(ran.code(), Some(0), "{}", ran.stderr);
    assert_eq!(string(get(ran.report(), "revision")), revision);
    assert!(fixture.repo.join("SECURITY.md").is_file());
    assert!(!fixture.resolved("work/copy/SECURITY.md").exists());
}

/// An existing empty work directory that every user may write is taken as the run's scratch.
#[test]
fn an_empty_work_directory_others_may_write_is_taken() {
    let fixture = Fixture::new("kept-shared-work");
    fixture.commit();
    let work = fixture.base.join("shared");
    fs::create_dir(&work).expect("made");
    fs::set_permissions(&work, fs::Permissions::from_mode(0o777)).expect("moded");
    let ran = fixture.run_with(
        &[RUN_FENCE],
        Opts {
            work: Some(work.clone()),
            ..Opts::default()
        },
    );
    assert_eq!(ran.code(), Some(0), "{}", ran.stderr);
    assert_eq!(
        fs::metadata(&work).expect("stats").permissions().mode() & 0o777,
        0o777
    );
}

/// A committed catalog that is a link to a file outside the checkout is read through the link, by name and
/// whole, by the copy's check and the run.
#[test]
fn a_catalog_committed_as_a_link_is_read_through_it() {
    let fixture = Fixture::new("kept-catalog-link");
    fixture.commit();
    let outside = fixture.base.join("catalog.json");
    fs::copy(fixture.repo.join(CATALOG), &outside).expect("copied");
    fs::remove_file(fixture.repo.join(CATALOG)).expect("removed");
    symlink(&outside, fixture.repo.join(CATALOG)).expect("linked");
    git(&fixture.repo, &["add", "-A"]);
    git(&fixture.repo, &["commit", "-qm", "a linked catalog"]);
    let ran = fixture.run_rows(&[RUN_FENCE]);
    assert_eq!(ran.code(), Some(0), "{}", ran.stderr);
    let copied = fixture.resolved("work/copy").join(CATALOG);
    assert!(
        fs::symlink_metadata(&copied)
            .expect("stats")
            .file_type()
            .is_symlink()
    );
    assert_eq!(results(ran.report(), RUN_FENCE), ["survived"; 2]);
}

/// A loom test's output is read and digested whole: a planted output of 16 MiB stands in the evidence
/// with the digest of all its bytes.
#[test]
fn a_loom_output_is_read_and_digested_whole() {
    let fixture = Fixture::new("kept-big-output");
    fixture.commit();
    let tests = run_tests();
    let ran = fixture.run_with(
        &[RUN_FENCE],
        Opts {
            plan: Some(plan(&[(&tests[0], &[("planted", "big")])])),
            ..Opts::default()
        },
    );
    assert_eq!(ran.code(), Some(0), "{}", ran.stderr);
    let entry = &row_results(ran.report(), RUN_FENCE)[0];
    let output = string(get(entry, "output"));
    assert!(fs::metadata(&output).expect("stats").len() > 16 << 20);
    assert_eq!(string(get(entry, "digest")), sha256_of(Path::new(&output)));
}
