//! The cases of `seal` and of `restore` over a sealed copy of the held fixture, which holds a
//! case's marks in place of the fixture's. A case that judges a sealed copy asserts `seal`'s
//! exit, the judge's load of the copy or its refusal, and the fact the judge's verdict rests on:
//! whether the restoration ends observation, or which marks stand. With `HOST_STOP_KEEP` set, a
//! case keeps one copy for each run of the judge it stands for, a run that refuses the evidence
//! included, under the case's name and that run's ordinal; a case that only loads a copy keeps
//! none.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;

use kestrike_tools::host_stop::{Disk, Interrupted, LockError, Record, Signal, lock};
use kestrike_tools::host_stop_controller::Halt;
use kestrike_tools::host_stop_controller::{Command, entry};
use kestrike_tools::json::{Text, Value};
use kestrike_tools::python::{hexdigest, repr_float};

use super::after_stop::flip;
use super::restoring::{digest, dumps};
use super::sealing::{
    copy_tree, ends, held, indented_one, judged, marks_in, parse, standing_marks, syncs_at,
    window_end,
};
use super::steps::{Step, errno, free_lock, links};
use super::stop_run::time;
use super::{CHILD, Case, child, killed_run, member, set};
use crate::host_stop_support::{Scratch, TARGET, remove, value};

const SKEW: f64 = 5.0;

/// The marks a sealed copy holds beside the seal after a run that ends with `names`.
fn sealed_with(names: &[&str]) -> Vec<String> {
    let mut all: Vec<String> = names.iter().map(|name| format!("{name}.json")).collect();
    all.push("collected.json".to_owned());
    all.sort();
    all
}

/// The SHA-256 of `collected.json` for this fixture's clean run, restored after the run window and
/// sealed at 430.0 under the fake clock: a known answer taken from outside this crate.
const CLEAN_SEAL: &str = "ca116abda338449ddce105e4f5835c77ca7566bfef5bc0542468d17aea0968dc";

/// A clean run restored after the run window loads, and its restoration ends no observation. The
/// seal's bytes hash to [`CLEAN_SEAL`].
#[test]
fn a_clean_run_and_its_restoration_keep_the_fixture_held() {
    let mut case = Case::new("judged-clean");
    assert_eq!(case.run(), 0, "{}", case.output());
    case.restore_after_the_run_window(1);
    let (root, evidence) = case.judge("a_clean_run_and_its_restoration_keep_the_fixture_held-1");
    assert_eq!(
        marks_in(&root),
        sealed_with(&["restoration", "roles", "stop", "stopped"])
    );
    assert!(!ends(&evidence));
    assert_eq!(time(&parse(&root.join("injection/collected.json"))), 430.0);
    assert_eq!(digest(&root.join("injection/collected.json")), CLEAN_SEAL);
    assert!(
        case.stdout().ends_with(&format!(
            "host-stop-controller: sealed 16 files at 430.0; injection/collected.json sha256 \
             {CLEAN_SEAL}\n"
        )),
        "{}",
        case.stdout()
    );
}

/// The restoration is dated by the target's launch, whenever `restore` runs and reads it ready: a
/// target started inside the run window and restored after it ends observation inside the window.
#[test]
fn a_target_started_inside_the_run_window_and_restored_after_it_leaves_the_run_inconclusive() {
    let mut case = Case::new("judged-started-inside");
    let end = window_end().0;
    assert_eq!(case.run(), 0, "{}", case.output());
    case.start_target(1);
    let started = case.plane.borrow().t;
    assert!(started < end, "{started}");
    case.advance_to(end + 20.0);
    assert_eq!(case.restore(None), 0, "{}", case.output());
    let restored = time(&case.marks()["restoration"]);
    assert!((restored - (started - SKEW)).abs() < 1e-6, "{restored}");
    let (_, evidence) = case.judge(
        "a_target_started_inside_the_run_window_and_restored_after_it_leaves_the_run_inconclusive-1",
    );
    assert!(ends(&evidence));
}

/// The control plane's clock may read the skew ahead of the controller's, so a launch it dates
/// less than the skew after the run window's end may lie inside the window. With a clock error of
/// 0 and a run window ending at 400, a launch at 404 dates the restoration at 399, which ends
/// observation, and a launch at 405 dates it at 400, which does not.
#[test]
fn a_launch_the_skew_admits_inside_the_run_window_ends_observation_there() {
    let (end, error) = window_end();
    assert_eq!((end, error), (400.0, 0.0));
    for (at, (launched, ending)) in [(end + SKEW - 1.0, true), (end + SKEW, false)]
        .into_iter()
        .enumerate()
    {
        let mut case = Case::new("judged-skew");
        assert_eq!(case.run(), 0, "{}", case.output());
        case.advance_to(end + 20.0);
        case.start_target(0);
        case.plane
            .borrow_mut()
            .instances
            .get_mut(TARGET)
            .expect("the target")
            .launched = launched;
        assert_eq!(case.restore(None), 0, "{}", case.output());
        assert_eq!(time(&case.marks()["restoration"]), launched - SKEW);
        let name = format!(
            "a_launch_the_skew_admits_inside_the_run_window_ends_observation_there-{}",
            at + 1
        );
        let (_, evidence) = case.judge(&name);
        assert_eq!(ends(&evidence), ending, "{launched}");
    }
}

/// A restoration inside the run window ends observation there, so the rules read over the whole
/// window stand unobserved.
#[test]
fn a_restoration_inside_the_run_window_leaves_the_run_inconclusive() {
    let mut case = Case::new("judged-inside");
    assert_eq!(case.run(), 0, "{}", case.output());
    case.start_target(1);
    assert_eq!(case.restore(None), 0, "{}", case.output());
    assert!(time(&case.marks()["restoration"]) < window_end().0);
    let (_, evidence) =
        case.judge("a_restoration_inside_the_run_window_leaves_the_run_inconclusive-1");
    assert!(ends(&evidence));
}

/// An attempts-only commit of s5 after the snapshot's cut and before `roles.json` was written:
/// `roles.json` carries the cut, and the sealed copy loads with its restoration ending no
/// observation.
#[test]
fn a_version_committed_after_the_snapshots_cut_keeps_the_run_judged() {
    let mut case = Case::new("judged-version");
    assert_eq!(case.run(), 0, "{}", case.output());
    case.restore_after_the_run_window(0);
    assert_eq!(time(&case.marks()["roles"]), 100.0);
    let later = value(
        r#"{"time": 102, "owner": "h3", "standby": "h4", "generation": 5, "volume": "vol-s5", "attempts": 2}"#,
    );
    let root = case.copy(&[], &[("s5", vec![later])]);
    let evidence = case.judge_copy(
        &root,
        "a_version_committed_after_the_snapshots_cut_keeps_the_run_judged-1",
    );
    assert!(!ends(&evidence));
    let rows = fs::read_to_string(root.join("records/s5.jsonl")).expect("s5 reads");
    assert!(
        rows.lines().any(|row| row.contains("\"time\": 102")),
        "{rows}"
    );
}

/// Too few roles abort the run before the stop: the sealed copy holds no stop mark.
#[test]
fn too_few_roles_fail_to_inject() {
    let mut case = Case::new("judged-roles");
    case.snapshot("shards.jsonl", |rows| {
        set(&mut rows[3], &["standby"], Value::String(Text::from("h3")));
    });
    assert_eq!(case.run(), 1, "{}", case.output());
    let change = value(r#"{"standby": "h3"}"#);
    let root = case.copy(&[("s4", change)], &[]);
    case.judge_copy(&root, "too_few_roles_fail_to_inject-1");
    assert_eq!(marks_in(&root), sealed_with(&["abort", "roles"]));
}

/// A stop never shown aborts the run with no stopped mark.
#[test]
fn a_stop_never_shown_fails_to_inject() {
    let mut case = Case::new("judged-never-shown");
    case.plane.borrow_mut().stop_after = None;
    assert_eq!(case.run(), 1, "{}", case.output());
    let (root, _) = case.judge("a_stop_never_shown_fails_to_inject-1");
    assert_eq!(marks_in(&root), sealed_with(&["abort", "roles", "stop"]));
}

/// An abort before the stop is shown leaves no stopped mark.
#[test]
fn an_abort_before_the_stop_is_shown_fails_to_inject() {
    let mut case = Case::new("judged-abort-before");
    case.plane.borrow_mut().stop_after = None;
    case.faulted(flip("gd2-guardrail-1", "ALARM"), true);
    assert_eq!(case.run(), 1, "{}", case.output());
    let (root, _) = case.judge("an_abort_before_the_stop_is_shown_fails_to_inject-1");
    assert_eq!(marks_in(&root), sealed_with(&["abort", "roles", "stop"]));
}

/// An abort after the stop is shown, restored with the reviewed record of that abort: the copy
/// holds the abort beside the stopped mark, and the restoration names the review's digest.
#[test]
fn an_abort_after_the_stop_and_its_reviewed_restoration_read_halted() {
    let mut case = Case::new("judged-halted");
    case.faulted(flip("gd2-guardrail-1", "ALARM"), false);
    assert_eq!(case.run(), 1, "{}", case.output());
    let names: Vec<String> = case.marks().keys().cloned().collect();
    assert_eq!(names, ["abort", "roles", "stop", "stopped"]);
    case.start_target(0);
    let path = case.scratch.0.join("reviewed.json");
    fs::write(&path, dumps(&case.review())).expect("the review is written");
    assert_eq!(case.restore(Some(&path)), 0, "{}", case.output());
    let restoration = &case.marks()["restoration"];
    assert_eq!(
        super::text_of(restoration, "reviewed_sha256"),
        digest(&path)
    );
    let (root, _) =
        case.judge("an_abort_after_the_stop_and_its_reviewed_restoration_read_halted-1");
    assert_eq!(
        marks_in(&root),
        sealed_with(&["abort", "restoration", "roles", "stop", "stopped"])
    );
}

const KILLED: &str = "sealed::a_run_killed_during_the_observation_is_not_held";

/// A run killed by SIGKILL inside an alarm read of the observation leaves the roles and stop marks
/// alone: the sealed copy loads with neither a stopped nor an abort mark, and `restore` refuses the
/// run as one that ended unrecorded. The kill ends a process of the case's own, which names its
/// evidence directory in the file `evidence` of the parent's scratch directory.
#[test]
fn a_run_killed_during_the_observation_is_not_held() {
    let (_place, evidence) = killed_run(KILLED, "judged-killed");
    let mut case = Case::new("judged-killed");
    copy_tree(
        &evidence.join("injection"),
        &case.evidence.join("injection"),
        &[],
    );
    let (root, _) = case.judge("a_run_killed_during_the_observation_is_not_held-1");
    assert_eq!(marks_in(&root), sealed_with(&["roles", "stop"]));
    let calls = case.log().len();
    assert_eq!(case.restore(None), 2, "{}", case.output());
    assert!(
        case.output()
            .contains("the run ended with neither stopped.json nor abort.json"),
        "{}",
        case.output()
    );
    assert_eq!(case.log().len(), calls);
}

/// A signal during the sync of the evidence directory, after `injection/` is made, aborts the run
/// before the stop: the sealed copy holds the roles and abort marks alone.
#[test]
fn a_signal_during_the_evidence_directory_sync_fails_to_inject() {
    let mut case = Case::new("judged-sync-signal");
    let evidence = case.evidence.clone();
    case.signal_at(
        Signal::Terminate,
        move |step| matches!(step, Step::FsyncDirectory(path) if *path == evidence),
    );
    assert_eq!(case.run(), 1, "{}", case.output());
    let (root, _) = case.judge("a_signal_during_the_evidence_directory_sync_fails_to_inject-1");
    assert_eq!(marks_in(&root), sealed_with(&["abort", "roles"]));
}

/// The seal names every collected file, `coverage.json` and each standing mark by the SHA-256 of
/// its bytes, makes no call and prints its own digest, which the judge's load reports. A second
/// seal is refused, and a row removed from a collection after the seal, with its count lowered
/// to match, is refused by the judge's load.
#[test]
fn the_seal_names_each_collected_file_and_a_row_removed_after_it_is_refused() {
    let mut case = Case::new("seal-names");
    let root = case.restored_copy();
    let (calls, seen) = (case.log().len(), case.output().len());
    assert_eq!(case.seal_at(&root), 0, "{}", case.output());
    assert_eq!(case.log().len(), calls, "the seal makes no call");
    let seal = root.join("injection/collected.json");
    let mark = parse(&seal);
    let sha = digest(&seal);
    let output = case.output();
    assert!(
        output[seen..].contains(&format!("injection/collected.json sha256 {sha}\n")),
        "{output}"
    );
    let name = "the_seal_names_each_collected_file_and_a_row_removed_after_it_is_refused";
    case.keep_tree(&root, &format!("{name}-1"));
    let evidence = judged(&root).expect("the sealed copy loads");
    assert_eq!(evidence.seal_sha256(), sha);
    let now = case.plane.borrow().wall();
    assert_eq!(time(&mark), now);
    let sealed = evidence
        .file("injection/collected.json")
        .expect("the load holds the seal");
    assert_eq!(time(sealed), now);
    let Value::Object(named) = member(&mark, "files") else {
        panic!("the seal's files")
    };
    let line = format!(
        "host-stop-controller: sealed {} files at {}; injection/collected.json sha256 {sha}\n",
        named.len(),
        repr_float(now)
    );
    assert!(case.stdout().ends_with(&line), "{}", case.stdout());
    let coverage = parse(&root.join("coverage.json"));
    let mut expected: Vec<String> = match &coverage {
        Value::Object(coverage) => coverage.iter().map(|(key, _)| key.to_string()).collect(),
        other => panic!("{other:?} is the coverage"),
    };
    expected.push("coverage.json".to_owned());
    expected.extend(standing_marks(&root));
    expected.sort();
    let Value::Object(files) = member(&mark, "files") else {
        panic!("the seal's files")
    };
    let named: Vec<String> = files.iter().map(|(key, _)| key.to_string()).collect();
    assert_eq!(named, expected);
    for (rel, sealed) in files.iter() {
        let rel = rel.to_string();
        assert_eq!(super::plain(sealed), digest(&root.join(&rel)), "{rel}");
    }
    case.assert_seal_refused(&root, "injection/collected.json exists");
    let path = root.join("provider.jsonl");
    let rows = fs::read_to_string(&path).expect("the provider rows read");
    let kept: Vec<&str> = rows.split_inclusive('\n').collect();
    fs::write(&path, kept[..kept.len() - 1].concat()).expect("a row is removed");
    let mut coverage = coverage;
    let lines = super::stop_run::seconds(member(member(&coverage, "provider.jsonl"), "lines"));
    set(
        &mut coverage,
        &["provider.jsonl", "lines"],
        value(&format!("{}", lines as i64 - 1)),
    );
    fs::write(root.join("coverage.json"), indented_one(&coverage)).expect("written");
    case.keep_tree(&root, &format!("{name}-2"));
    let refused = judged(&root).expect_err("the judge refuses the changed collection");
    assert!(
        refused.contains("provider.jsonl differs from the bytes injection/collected.json seals"),
        "{refused}"
    );
}

/// Rewrites the JSON file `rel` of `root` with `change` applied, as `json.dumps(value, indent=1)`
/// writes it, and returns its bytes before the change.
fn rewrite_json(root: &Path, rel: &str, change: impl FnOnce(&mut Value)) -> Vec<u8> {
    let path = root.join(rel);
    let original = fs::read(&path).expect("the file reads");
    let mut changed = parse(&path);
    change(&mut changed);
    fs::write(&path, indented_one(&changed)).expect("the file is written");
    original
}

/// A seal before the run window ends is refused, and so is one over collections the judge's load
/// refuses with the seal it would write: a count or a span `coverage.json` misstates, a coverage
/// off the observed files, a `roles.json` of another package, which is refused before any
/// collection is read, a missing collection and a package of other bytes than the approval's.
#[test]
fn a_seal_before_the_window_ends_or_off_its_collections_is_refused() {
    let mut case = Case::new("seal-early");
    let root = case.restored_copy();
    let end = window_end().0;
    case.plane.borrow_mut().t = end - 1.0;
    let start = case.plants.borrow().len();
    case.plant(Box::new(|state, step| {
        if matches!(step, Step::TryLock | Step::Fsync(_)) {
            state.t += 5.0;
        }
        None
    }));
    case.assert_seal_refused(&root, "its collections may still grow");
    case.plants.borrow_mut().truncate(start);
    case.plane.borrow_mut().t = end - 1.0;
    assert!(
        case.stderr().ends_with(
            "host-stop-controller: refused: the run window ends at 400, after the seal's time \
             399.0, so its collections may still grow; nothing written\n"
        ),
        "{}",
        case.stderr()
    );
    case.plane.borrow_mut().t += 31.0;
    type Change = Box<dyn FnOnce(&mut Value)>;
    let cases: Vec<(&str, Change, String)> = vec![
        (
            "coverage.json",
            Box::new(|c| set(c, &["provider.jsonl", "lines"], value("2"))),
            "coverage.json spans provider.jsonl backwards or counts 2 lines, not its 3".to_owned(),
        ),
        (
            "coverage.json",
            Box::new(|c| set(c, &["origin.jsonl", "to"], value("460"))),
            "coverage.json spans origin.jsonl to 460, after the seal's time".to_owned(),
        ),
        (
            "coverage.json",
            Box::new(|c| drop(remove(c, &["witness.jsonl"]))),
            "not exactly the observeds".to_owned(),
        ),
        (
            "injection/roles.json",
            Box::new(|r| {
                set(
                    r,
                    &["package_sha256"],
                    Value::String(Text::from("0".repeat(64))),
                )
            }),
            "names another package".to_owned(),
        ),
    ];
    for (rel, change, reason) in cases {
        let original = rewrite_json(&root, rel, change);
        let start = case.plants.borrow().len();
        let read = case.reads_under(&root);
        case.assert_seal_refused(&root, &reason);
        if rel == "injection/roles.json" {
            assert_eq!(*read.borrow(), ["package.json", "injection/roles.json"]);
        }
        case.plants.borrow_mut().truncate(start);
        fs::write(root.join(rel), original).expect("the file is restored");
    }
    fs::remove_file(root.join("blockers.jsonl")).expect("removed");
    case.assert_seal_refused(&root, "blockers.jsonl is missing");
    let mut package = fs::read(held().join("package.json")).expect("the package reads");
    package.push(b' ');
    fs::write(root.join("package.json"), package).expect("written");
    case.assert_seal_refused(
        &root,
        "package.json holds other bytes than the approval's package",
    );
}

/// A seal whose wall reading equals the run window's end is written with that time. A seal that
/// finds no mark at its lookup but one in its listing is refused, and so is one whose link finds
/// a mark another seal linked after its listing; each leaves the standing seal's bytes.
#[test]
fn a_seal_at_the_run_windows_end_is_written_and_a_second_racing_seal_is_refused() {
    let mut case = Case::new("seal-at-end");
    let root = case.restored_copy();
    let end = window_end().0;
    case.plane.borrow_mut().t = end;
    assert_eq!(case.plane.borrow().wall(), end);
    assert_eq!(case.seal_at(&root), 0, "{}", case.output());
    let seal = root.join("injection/collected.json");
    assert_eq!(time(&parse(&seal)), end);
    let first = fs::read(&seal).expect("the seal reads");
    let start = case.plants.borrow().len();
    let looked = seal.clone();
    case.plant(Box::new(move |_, step| {
        matches!(step, Step::Lstat(path) if *path == looked).then(|| errno(libc::ENOENT))
    }));
    let read = case.reads_under(&root);
    case.assert_seal_refused(
        &root,
        "injection/collected.json exists: the seal is written once",
    );
    assert_eq!(
        *read.borrow(),
        ["package.json"],
        "the listing refuses, after the package's read"
    );
    assert_eq!(fs::read(&seal).expect("the seal reads"), first);
    case.plants.borrow_mut().truncate(start);
    fs::remove_file(&seal).expect("the seal is removed");
    let (raced, bytes) = (seal.clone(), first.clone());
    case.plant(Box::new(move |_, step| {
        if links(step, "collected.json") {
            fs::write(&raced, &bytes).expect("another seal links its mark");
        }
        None
    }));
    let seen = case.stderr().len();
    assert_eq!(case.seal_at(&root), 2, "{}", case.output());
    assert_eq!(
        case.stderr()[seen..],
        *"host-stop-controller: refused: injection/collected.json exists: the seal is written \
          once; nothing written\n"
    );
    assert_eq!(fs::read(&seal).expect("the seal reads"), first);
}

/// A `records/` that is a link, an evidence root that is a link and an `injection/` that is a link
/// write no seal, and neither does an approved simulation package, which its export seals.
#[test]
fn a_linked_root_records_or_injection_or_a_simulation_package_writes_no_seal() {
    let mut case = Case::new("seal-linked");
    let root = case.restored_copy();
    let twin = case.scratch.0.join("twin");
    copy_tree(&root, &twin, &[]);
    fs::remove_dir_all(root.join("records")).expect("records is removed");
    symlink(twin.join("records"), root.join("records")).expect("records links");
    case.assert_seal_refused(&root, "records is no directory");
    let linked = case.scratch.0.join("linked");
    symlink(&twin, &linked).expect("the root links");
    case.assert_seal_refused(&linked, &format!("{} is no directory;", linked.display()));
    assert!(!twin.join("injection/collected.json").exists());
    fs::remove_dir_all(twin.join("injection")).expect("injection is removed");
    symlink(root.join("injection"), twin.join("injection")).expect("injection links");
    assert_eq!(case.seal_at(&twin), 2, "{}", case.output());
    assert!(
        case.output().contains("is no directory: no run to seal"),
        "{}",
        case.output()
    );
    let sim = case.scratch.0.join("sim");
    copy_tree(&root, &sim, &["records"]);
    copy_tree(&twin.join("records"), &sim.join("records"), &[]);
    let mut package = parse(&sim.join("package.json"));
    set(
        &mut package,
        &["kind"],
        Value::String(Text::from("simulation")),
    );
    set(&mut package, &["clock_error_seconds"], value("0"));
    let data = indented_one(&package);
    fs::write(sim.join("package.json"), &data).expect("the package is written");
    let approved = Value::String(Text::from(hexdigest(data.as_bytes())));
    set(
        &mut case.operator,
        &["approval", "package_sha256"],
        approved.clone(),
    );
    let mut roles = parse(&sim.join("injection/roles.json"));
    set(&mut roles, &["package_sha256"], approved);
    fs::write(sim.join("injection/roles.json"), dumps(&roles)).expect("roles are written");
    case.assert_seal_refused(&sim, "package.json is of kind simulation");
}

/// A coverage span that runs backwards and a row off its schema are refused before the seal; the
/// copy restored seals.
#[test]
fn a_backwards_span_or_an_off_schema_row_is_refused_before_the_seal() {
    let mut case = Case::new("seal-span");
    let root = case.restored_copy();
    let original = rewrite_json(&root, "coverage.json", |c| {
        set(c, &["blockers.jsonl", "from"], value("401"));
    });
    case.assert_seal_refused(&root, "coverage.json spans blockers.jsonl backwards");
    fs::write(root.join("coverage.json"), original).expect("restored");
    let path = root.join("blockers.jsonl");
    let rows = fs::read_to_string(&path).expect("the rows read");
    fs::write(&path, rows.replacen("\"name\"", "\"label\"", 1)).expect("written");
    case.assert_seal_refused(&root, "blockers.jsonl line 1 holds the keys");
    fs::write(&path, rows).expect("restored");
    assert_eq!(case.seal_at(&root), 0, "{}", case.output());
}

/// A signal delivered during the read of the last collection, `witness.jsonl`, raises at the next
/// read of the record, ahead of the mark's write: the seal exits 2, writes nothing and leaves the
/// lock free.
#[test]
fn a_signal_during_the_collection_reads_ends_the_seal_with_nothing_written() {
    let mut case = Case::new("seal-signal-reads");
    let root = case.restored_copy();
    for rel in ["coverage.json", "witness.jsonl"] {
        let start = case.plants.borrow().len();
        let read = case.reads_under(&root);
        let signalled = root.join(rel);
        case.signal_at(Signal::Terminate, move |step| syncs_at(step, &signalled));
        let seen = case.output().len();
        assert_eq!(case.seal_at(&root), 2, "{}", case.output());
        let output = case.output();
        assert!(
            output[seen..].contains("signal SIGTERM before any mark; nothing written"),
            "{output}"
        );
        assert_eq!(read.borrow().last().map(String::as_str), Some(rel), "{rel}");
        assert!(!root.join("injection/collected.json").exists());
        drop(free_lock(&root.join("injection")));
        case.plants.borrow_mut().truncate(start);
    }
}

/// A signal that stands when the seal arms its record raises at the read that follows, ahead of
/// the lookup of a standing seal: the seal exits 2 with the signal's line in place of the
/// refusal of the standing mark.
#[test]
fn a_signal_standing_at_the_seals_start_raises_before_the_lookup_of_a_standing_seal() {
    let mut case = Case::new("seal-signal-start");
    let root = case.restored_copy();
    case.advance_to(window_end().0 + 30.0);
    assert_eq!(case.seal_at(&root), 0, "{}", case.output());
    let lookups = std::rc::Rc::new(std::cell::Cell::new(0));
    let (counted, seal) = (
        std::rc::Rc::clone(&lookups),
        root.join("injection/collected.json"),
    );
    case.plant(Box::new(move |_, step| {
        if matches!(step, Step::Lstat(path) if *path == seal) {
            counted.set(counted.get() + 1);
        }
        None
    }));
    case.delivered.deliver(Signal::Terminate);
    let seen = case.output().len();
    assert_eq!(case.seal_at(&root), 2, "{}", case.output());
    let output = case.output();
    assert_eq!(
        &output[seen..],
        "host-stop-controller: signal SIGTERM before any mark; nothing written\n"
    );
    assert_eq!(lookups.get(), 0, "the signal raised before the lookup");
}

/// A signal delivered during the mark's write waits for it: the seal exits 0 with its mark.
#[test]
fn a_signal_during_the_marks_write_waits_for_it() {
    let mut case = Case::new("seal-signal-write");
    let root = case.restored_copy();
    case.signal_at(Signal::Terminate, |step| links(step, "collected.json"));
    assert_eq!(case.seal_at(&root), 0, "{}", case.output());
    assert!(root.join("injection/collected.json").exists());
    assert_eq!(case.delivered.stored(), Some(Signal::Terminate));
}

/// A signal delivered at the last file step before the mark's write, the sync of the evidence
/// directory, raises at the read ahead of the write: the seal exits 2 and writes nothing.
#[test]
fn a_signal_just_before_the_marks_write_is_held_ends_the_seal_with_nothing_written() {
    let mut case = Case::new("seal-signal-hold");
    let root = case.restored_copy();
    let synced = root.clone();
    case.signal_at(Signal::Terminate, move |step| syncs_at(step, &synced));
    assert_eq!(case.seal_at(&root), 2, "{}", case.output());
    assert!(
        case.output().contains("signal SIGTERM"),
        "{}",
        case.output()
    );
    assert!(!root.join("injection/collected.json").exists());
    drop(free_lock(&root.join("injection")));
}

/// An entry outside the judge's layout in the evidence root or `records/` writes no seal, since
/// the judge refuses the directory as it stands: an unlisted record file, an unlisted file, an
/// extra directory and a link. The copy restored seals.
#[test]
fn an_entry_outside_the_layout_in_the_root_or_records_writes_no_seal() {
    let mut case = Case::new("seal-layout");
    let root = case.restored_copy();
    for (rel, reason) in [
        (
            "records/unlisted.jsonl",
            "records/unlisted.jsonl is no file of the layout",
        ),
        ("notes.txt", "notes.txt is no file of the layout"),
    ] {
        fs::write(root.join(rel), b"").expect("the entry is made");
        let refused = judged(&root).expect_err("the judge refuses the directory");
        assert!(refused.contains(reason), "{refused}");
        case.assert_seal_refused(&root, reason);
        fs::remove_file(root.join(rel)).expect("the entry is removed");
    }
    fs::create_dir(root.join("spare")).expect("the directory is made");
    case.assert_seal_refused(&root, "spare is no directory of the layout");
    fs::remove_dir(root.join("spare")).expect("removed");
    let linked = root.join("records/linked.jsonl");
    symlink(root.join("records/receipts.jsonl"), &linked).expect("the link is made");
    case.assert_seal_refused(&root, "records/linked.jsonl is a link or a special file");
    fs::remove_file(&linked).expect("removed");
    assert_eq!(case.seal_at(&root), 0, "{}", case.output());
}

/// A signal delivered while a seal's refusal is printed leaves the refusal as printed, with exit
/// 2: the entry disarmed the record before it printed, and the record stays disarmed with the
/// signal stored.
#[test]
fn a_signal_while_a_seals_refusal_is_printed_leaves_the_refusal() {
    let mut case = Case::new("seal-signal-print");
    let root = case.restored_copy();
    fs::remove_file(root.join("blockers.jsonl")).expect("removed");
    let delivered = case.delivered;
    let mut record = Record::new(delivered);
    let armed = std::rc::Rc::new(std::cell::Cell::new(None));
    let seen_armed = std::rc::Rc::clone(&armed);
    case.writes = Some(std::rc::Rc::new(move |bytes: &[u8]| {
        if String::from_utf8_lossy(bytes).contains("refused") {
            delivered.deliver(Signal::Terminate);
            seen_armed.set(Some(delivered.stored().is_some()));
        }
        None
    }));
    let command = Command::Seal {
        operator: case.write_operator(),
        evidence: root.as_os_str().to_owned(),
    };
    let seen = case.output().len();
    let calls = (case.log().len(), case.plane.borrow().envs.len());
    assert_eq!(case.in_context_on(&mut record, |cx| entry(&command, cx)), 2);
    assert_eq!(
        (case.log().len(), case.plane.borrow().envs.len()),
        calls,
        "the seal makes no call"
    );
    let output = case.output();
    assert_eq!(
        &output[seen..],
        "host-stop-controller: refused: blockers.jsonl is missing; nothing written\n"
    );
    assert_eq!(
        armed.get(),
        Some(true),
        "the signal was delivered during the print"
    );
    assert!(
        !record.is_armed(),
        "the entry disarmed the record before it printed"
    );
    assert_eq!(
        record.pending(),
        Some(Signal::Terminate),
        "the signal stays stored"
    );
}

/// A failed sync of a collection, of `records/` or of the evidence directory writes no seal, and
/// each is refused by its name; the copy restored seals.
///
/// The same restored copy remains sealable after the injected sync failures.
#[test]
fn a_failed_sync_of_a_collection_or_its_directory_writes_no_seal() {
    let mut case = Case::new("seal-sync");
    let root = case.restored_copy();
    let shown = root.display().to_string();
    for (rel, reason) in [
        (
            "witness.jsonl",
            "witness.jsonl cannot be read and synced".to_owned(),
        ),
        (
            "records/receipts.jsonl",
            "records/receipts.jsonl cannot be read and synced".to_owned(),
        ),
        (
            "injection/roles.json",
            "injection/roles.json cannot be read and synced".to_owned(),
        ),
        ("records", "records cannot be synced".to_owned()),
        ("injection", "injection cannot be synced".to_owned()),
        ("", format!("{shown} cannot be synced")),
    ] {
        let failed = if rel.is_empty() {
            root.clone()
        } else {
            root.join(rel)
        };
        let start = case.plants.borrow().len();
        case.plant(Box::new(move |_, step| {
            syncs_at(step, &failed).then(|| errno(libc::EIO))
        }));
        case.assert_seal_refused(&root, &reason);
        case.plants.borrow_mut().truncate(start);
    }
    let steps = case.steps_under(&root);
    assert_eq!(case.seal_at(&root), 0, "{}", case.output());
    let steps = steps.borrow();
    let link = steps
        .iter()
        .position(|step| step == "link collected.json")
        .expect("the mark is linked");
    let reads: Vec<&str> = steps[..link]
        .iter()
        .filter_map(|step| step.strip_prefix("file "))
        .collect();
    let Value::Object(files) =
        member(&parse(&root.join("injection/collected.json")), "files").clone()
    else {
        panic!("the seal's files")
    };
    let mut expected = vec!["package.json".to_owned(), "injection/roles.json".to_owned()];
    expected.extend(
        files
            .iter()
            .map(|(key, _)| key.to_string())
            .filter(|rel| rel != "injection/roles.json"),
    );
    assert_eq!(
        reads, expected,
        "each file the seal names is read and synced, in order"
    );
    let last_read = steps[..link]
        .iter()
        .rposition(|step| step.starts_with("file "))
        .expect("a file is read");
    let dirs: Vec<&str> = steps[last_read..link]
        .iter()
        .filter_map(|step| step.strip_prefix("directory "))
        .collect();
    assert_eq!(dirs[..3], ["records", "injection", ""], "{steps:?}");
}

/// A seal while another holds the evidence's lock is refused. A write that fails before the link
/// exits 1 and prints no digest. A sync after the link that fails, with the mark removed and the
/// removal unsynced, exits 1 and prints the digest of the mark it linked. A sync and a removal
/// that both fail leave the seal standing, exit 1 with its digest, and a second seal is refused.
#[test]
fn a_seal_held_by_a_restore_is_refused_and_one_unwritten_or_left_standing_ends_with_exit_1() {
    let mut case = Case::new("seal-held");
    let root = case.restored_copy();
    case.advance_to(window_end().0 + 30.0);
    let injection = root.join("injection");
    let held = lock(&Disk, &injection).expect("the lock is taken");
    case.contended.set(true);
    case.assert_seal_refused(
        &root,
        "is held by a run, restore or seal that has not ended",
    );
    case.contended.set(false);
    drop(held);
    let mark = injection.join("collected.json");
    let start = case.plants.borrow().len();
    case.fail_once(libc::EIO, |step| matches!(step, Step::Write));
    let (seen, out, err) = (
        case.output().len(),
        case.stdout().len(),
        case.stderr().len(),
    );
    assert_eq!(case.seal_at(&root), 1, "{}", case.output());
    let output = case.output();
    assert_eq!(
        case.stderr()[err..],
        *"host-stop-controller: collected.json is unwritten: [Errno 5] Input/output error\n"
    );
    assert_eq!(case.stdout()[out..], *"");
    assert!(!output[seen..].contains("sha256"), "{output}");
    assert!(!mark.exists());
    case.plants.borrow_mut().truncate(start);
    let linked = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let (named, at) = (std::rc::Rc::clone(&linked), mark.clone());
    let mut after = false;
    case.plant(Box::new(move |_, step| {
        after |= links(step, "collected.json");
        if after && matches!(step, Step::FsyncDirectory(_)) {
            if let Ok(bytes) = fs::read(&at) {
                named.borrow_mut().push(hexdigest(&bytes));
            }
            return Some(errno(libc::EIO));
        }
        None
    }));
    let (out, err) = (case.stdout().len(), case.stderr().len());
    assert_eq!(case.seal_at(&root), 1, "{}", case.output());
    let sha = linked
        .borrow()
        .last()
        .cloned()
        .expect("the linked mark was read");
    assert_eq!(
        case.stderr()[err..],
        *format!(
            "host-stop-controller: {} cannot be synced (Input/output error), so it is removed; the \
             removal is unsynced, so the mark may stand again after a crash\n",
            mark.display()
        )
    );
    assert_eq!(
        case.stdout()[out..],
        *format!(
            "host-stop-controller: the mark this seal linked: injection/collected.json sha256 \
             {sha}\n"
        )
    );
    assert!(!mark.exists());
    case.plants.borrow_mut().truncate(start);
    let mut after = false;
    case.plant(Box::new(move |_, step| {
        after |= links(step, "collected.json");
        (after && matches!(step, Step::FsyncDirectory(_) | Step::Unlink(_)))
            .then(|| errno(libc::EIO))
    }));
    let seen = case.output().len();
    assert_eq!(case.seal_at(&root), 1, "{}", case.output());
    let output = case.output();
    assert!(
        output[seen..].contains("collected.json stands, but it cannot be synced"),
        "{output}"
    );
    let stderr = case.stderr();
    let unwritten = stderr.lines().last().expect("the unwritten line");
    assert!(
        unwritten.starts_with("host-stop-controller: ")
            && unwritten.contains("collected.json stands, but it cannot be synced"),
        "{stderr}"
    );
    let sha = digest(&mark);
    let linked = format!(
        "host-stop-controller: the mark this seal linked: injection/collected.json sha256 {sha}\n"
    );
    assert!(output[seen..].contains(&linked), "{output}");
    assert!(case.stdout().ends_with(&linked), "{}", case.stdout());
    case.plants.borrow_mut().truncate(start);
    let Value::Object(files) = member(&parse(&mark), "files").clone() else {
        panic!("the seal's files")
    };
    let named: Vec<String> = files.iter().map(|(key, _)| key.to_string()).collect();
    let Value::Object(coverage) = parse(&root.join("coverage.json")) else {
        panic!("the coverage")
    };
    let mut expected: Vec<String> = coverage.iter().map(|(key, _)| key.to_string()).collect();
    expected.push("coverage.json".to_owned());
    expected.extend(standing_marks(&root));
    expected.sort();
    assert_eq!(named, expected);
    case.assert_seal_refused(
        &root,
        "injection/collected.json exists: the seal is written once",
    );
    assert_eq!(
        judged(&root)
            .expect("the standing seal loads")
            .seal_sha256(),
        sha
    );
}

/// The descriptors of this process that name a path under `root`.
fn open_under(root: &Path) -> usize {
    fs::read_dir("/proc/self/fd")
        .expect("the descriptors list")
        .filter_map(|entry| fs::read_link(entry.ok()?.path()).ok())
        .filter(|path| path.starts_with(root))
        .count()
}

type Make = fn(&Path, &Path);

/// An entry outside the layout, or a missing collection, is refused once `package.json` is read
/// and before any other file is read. A `package.json` that is a directory is refused by that name,
/// and the seal leaves no descriptor of the copy open. The copy restored seals.
#[test]
fn an_entry_of_injection_outside_the_layout_is_refused_before_it_is_read() {
    let mut case = Case::new("seal-injection-layout");
    let root = case.restored_copy();
    let read = case.reads_under(&root);
    let makes: [(Make, &str, &str); 6] = [
        (
            |p, _| fs::write(p, b"{}").expect("made"),
            "injection/notes.json",
            "is no file of the layout",
        ),
        (
            |p, _| fs::write(p, b"{}").expect("made"),
            "notes.json",
            "is no file of the layout",
        ),
        (
            |p, _| fs::write(p, b"").expect("made"),
            "records/s9.jsonl",
            "is no file of the layout",
        ),
        (
            |p, _| fs::remove_file(p).expect("removed"),
            "blockers.jsonl",
            "is missing",
        ),
        (
            |p, _| fs::create_dir(p).expect("made"),
            "injection/spare",
            "is no directory of the layout",
        ),
        (
            |p, root| symlink(root.join("injection/roles.json"), p).expect("made"),
            "injection/linked.json",
            "is a link or a special file",
        ),
    ];
    for (make, rel, reason) in makes {
        read.borrow_mut().clear();
        let path = root.join(rel);
        make(&path, &root);
        case.assert_seal_refused(&root, &format!("{rel} {reason}"));
        assert_eq!(*read.borrow(), ["package.json"], "{rel}");
        if rel == "blockers.jsonl" {
            fs::copy(held().join(rel), &path).expect("restored");
        } else if fs::symlink_metadata(&path).is_ok_and(|found| found.is_dir()) {
            fs::remove_dir(&path).expect("removed");
        } else {
            fs::remove_file(&path).expect("removed");
        }
    }
    let package = fs::read(root.join("package.json")).expect("the package reads");
    fs::remove_file(root.join("package.json")).expect("removed");
    fs::create_dir(root.join("package.json")).expect("made");
    let opened = open_under(&root);
    let read = case.reads_under(&root);
    case.assert_seal_refused(&root, "package.json is no regular file");
    assert_eq!(
        *read.borrow(),
        ["package.json"],
        "the refused read is attempted"
    );
    assert_eq!(open_under(&root), opened);
    fs::remove_dir(root.join("package.json")).expect("removed");
    fs::write(root.join("package.json"), package).expect("restored");
    assert_eq!(case.seal_at(&root), 0, "{}", case.output());
}

const EMPTY: &str =
    "sealed::an_empty_evidence_path_seals_and_restores_nothing_in_the_working_directory";

/// An empty evidence path names no directory: `seal` and `restore` refuse it with no call and
/// write nothing in the working directory, and an explicit `.` names that directory. The case
/// changes the working directory, so it runs in a process of its own.
#[test]
fn an_empty_evidence_path_seals_and_restores_nothing_in_the_working_directory() {
    if std::env::var_os(CHILD).is_none() {
        let place = Scratch::new("seal-empty-child");
        let (status, shown) = child(EMPTY, &place.0, &[]);
        assert!(status.success(), "{shown}");
        assert!(shown.contains("1 passed"), "{shown}");
        return;
    }
    let mut case = Case::new("seal-empty");
    let root = case.restored_copy();
    case.advance_to(window_end().0 + 30.0);
    std::env::set_current_dir(&root).expect("the working directory is the copy");
    let (calls, seen) = (case.log().len(), case.output().len());
    assert_eq!(case.seal_at(Path::new("")), 2, "{}", case.output());
    assert!(case.output()[seen..].contains("no evidence directory is named"));
    assert!(!root.join("injection/collected.json").exists());
    fs::remove_file(root.join("injection/restoration.json")).expect("removed");
    let seen = case.output().len();
    assert_eq!(case.restore_at(Path::new(""), None), 2, "{}", case.output());
    assert!(case.output()[seen..].contains("no evidence directory is named"));
    let restored = root.join("injection/restoration.json").exists();
    assert_eq!((case.log().len(), restored), (calls, false));
    assert_eq!(
        case.restore_at(Path::new("."), None),
        0,
        "{}",
        case.output()
    );
    assert_eq!(case.seal_at(Path::new(".")), 0, "{}", case.output());
}

/// The seal names each mark that stands in `injection/`, the abort and the restoration included,
/// so the judge's load refuses a copy whose abort was removed after the seal, though the
/// restoration was rewritten to name no review.
#[test]
fn the_seal_names_each_mark_and_the_judge_refuses_one_removed_after_it() {
    let mut case = Case::new("seal-marks");
    case.faulted(flip("gd2-guardrail-1", "ALARM"), false);
    assert_eq!(case.run(), 1, "{}", case.output());
    case.start_target(0);
    let path = case.scratch.0.join("reviewed.json");
    fs::write(&path, dumps(&case.review())).expect("the review is written");
    assert_eq!(case.restore(Some(&path)), 0, "{}", case.output());
    let root = case.copy(&[], &[]);
    case.advance_to(window_end().0 + 30.0);
    assert_eq!(case.seal_at(&root), 0, "{}", case.output());
    let Value::Object(files) =
        member(&parse(&root.join("injection/collected.json")), "files").clone()
    else {
        panic!("the seal's files")
    };
    let marks: Vec<String> = files
        .iter()
        .map(|(key, _)| key.to_string())
        .filter(|rel| rel.starts_with("injection/"))
        .collect();
    let expected: Vec<String> = ["abort", "restoration", "roles", "stop", "stopped"]
        .iter()
        .map(|name| format!("injection/{name}.json"))
        .collect();
    assert_eq!(marks, expected);
    fs::remove_file(root.join("injection/abort.json")).expect("the abort is removed");
    let restoration = root.join("injection/restoration.json");
    let mut rewritten = parse(&restoration);
    set(&mut rewritten, &["reviewed_sha256"], Value::Null);
    fs::write(&restoration, indented_one(&rewritten)).expect("the restoration is rewritten");
    case.keep_tree(
        &root,
        "the_seal_names_each_mark_and_the_judge_refuses_one_removed_after_it-1",
    );
    let refused = judged(&root).expect_err("the judge refuses the copy");
    assert!(
        refused.contains("injection/collected.json seals injection/abort.json, which is missing"),
        "{refused}"
    );
}

/// A restore after the seal writes its restoration dated by the launch. One that ends observation,
/// a launch inside the run window, exits 1 and says the judge refuses the evidence while the mark
/// stands, which the judge's load does; one dated after the window's end, before or after the
/// seal's time, exits 0 and the copy loads.
#[test]
fn a_restore_after_the_seal_writes_its_restoration_and_exits_1_when_it_may_end_observation() {
    let end = window_end().0;
    let name =
        "a_restore_after_the_seal_writes_its_restoration_and_exits_1_when_it_may_end_observation";
    let launches = [
        (end - 10.0, 1),
        (end + SKEW + 5.0, 0),
        (end + 40.0 + SKEW, 0),
    ];
    for (at, (launched, code)) in launches.into_iter().enumerate() {
        let mut case = Case::new("seal-then-restore");
        assert_eq!(case.run(), 0, "{}", case.output());
        let root = case.copy(&[], &[]);
        case.advance_to(end + 30.0);
        assert_eq!(case.seal_at(&root), 0, "{}", case.output());
        case.advance_to(launched + SKEW + 1.0);
        case.start_target(0);
        case.plane
            .borrow_mut()
            .instances
            .get_mut(TARGET)
            .expect("the target")
            .launched = launched;
        let seen = case.output().len();
        assert_eq!(case.restore_at(&root, None), code, "{}", case.output());
        let restoration = parse(&root.join("injection/restoration.json"));
        assert_eq!(time(&restoration), launched - SKEW);
        case.keep_tree(&root, &format!("{name}-{}", at + 1));
        if code == 1 {
            let output = case.output();
            let line = format!(
                "host-stop-controller: the restoration dates {}, less than the clock error after \
                 the run window's end 400, and the seal does not name it, so the judge refuses \
                 this evidence while the mark stands\n",
                repr_float(launched - SKEW)
            );
            assert!(output[seen..].contains(&line), "{output}");
            assert!(case.stdout().ends_with(&line), "{}", case.stdout());
            let refused = judged(&root).expect_err("the judge refuses the copy");
            assert!(
                refused.contains("injection/restoration.json stands unsealed"),
                "{refused}"
            );
            continue;
        }
        let evidence = judged(&root).expect("the copy loads");
        assert!(!ends(&evidence), "{launched}");
    }
}

/// Rewrites the seal of `root` with `change` applied, as `json.dumps(value)` writes it.
fn reseal(root: &Path, change: impl FnOnce(&mut Value)) {
    let path = root.join("injection/collected.json");
    let mut seal = parse(&path);
    change(&mut seal);
    fs::write(&path, dumps(&seal)).expect("the seal is rewritten");
}

fn unnamed(root: &Path, rel: &str) {
    reseal(root, |seal| {
        let Value::Object(seal) = seal else {
            panic!("the seal is an object")
        };
        let Some(files) = seal.get_mut("files") else {
            panic!("the seal names its files")
        };
        drop(remove(files, &[rel]));
    });
}

type Changed = fn(&Path);

/// A restore after the seal refuses, before any call and with the marks as they stood, each
/// change the judge's load refuses of the directory as it stands: a standing mark the seal does
/// not name, a coverage or a collection it does not name, a sealed mark removed or changed, a seal
/// without its files, a collection changed or removed, a file outside the layout, and a package of
/// other bytes than the approval's.
#[test]
fn a_restore_after_the_seal_refuses_a_sealed_mark_missing_or_changed_before_any_call() {
    let end = window_end().0;
    let changes: [(&str, Changed, &str); 12] = [
        (
            "a seal that names no stop",
            |r| unnamed(r, "injection/stop.json"),
            "injection/stop.json stands unsealed",
        ),
        (
            "a seal that names no stopped report",
            |r| unnamed(r, "injection/stopped.json"),
            "injection/stopped.json stands unsealed",
        ),
        (
            "a seal that names no coverage",
            |r| unnamed(r, "coverage.json"),
            "injection/collected.json seals no coverage.json",
        ),
        (
            "a seal that names no witness collection",
            |r| unnamed(r, "witness.jsonl"),
            "injection/collected.json seals no witness.jsonl",
        ),
        (
            "restoration",
            |r| fs::remove_file(r.join("injection/restoration.json")).expect("removed"),
            "injection/collected.json seals injection/restoration.json, which is missing",
        ),
        (
            "abort",
            |r| fs::remove_file(r.join("injection/abort.json")).expect("removed"),
            "injection/collected.json seals injection/abort.json, which is missing",
        ),
        (
            "roles",
            |r| {
                let path = r.join("injection/roles.json");
                let mut roles = parse(&path);
                let later = time(&roles) + 1.0;
                set(&mut roles, &["time"], value(&format!("{later}")));
                fs::write(&path, indented_one(&roles)).expect("rewritten");
            },
            "injection/roles.json differs from the bytes injection/collected.json seals",
        ),
        (
            "files",
            |r| reseal(r, |seal| drop(remove(seal, &["files"]))),
            "injection/collected.json holds the keys ['time'], not ['files', 'time']",
        ),
        (
            "coverage changed after the seal",
            |r| {
                let mut bytes = fs::read(r.join("coverage.json")).expect("reads");
                bytes.push(b'\n');
                fs::write(r.join("coverage.json"), bytes).expect("written");
            },
            "coverage.json differs from the bytes injection/collected.json seals",
        ),
        (
            "a collection removed after the seal",
            |r| fs::remove_file(r.join("witness.jsonl")).expect("removed"),
            "witness.jsonl is missing",
        ),
        (
            "a file outside the layout",
            |r| fs::write(r.join("notes.txt"), "a note").expect("written"),
            "notes.txt is no file of the layout",
        ),
        (
            "package",
            |r| {
                let mut package = fs::read(held().join("package.json")).expect("reads");
                package.push(b' ');
                fs::write(r.join("package.json"), package).expect("written");
            },
            "package.json holds other bytes than the approval's package",
        ),
    ];
    for (name, change, reason) in changes {
        let mut case = Case::new("restore-sealed");
        if name == "abort" {
            case.faulted(flip("gd2-guardrail-1", "ALARM"), false);
        }
        let code = if name == "abort" { 1 } else { 0 };
        assert_eq!(case.run(), code, "{name}: {}", case.output());
        if name == "restoration" {
            case.restore_after_the_run_window(0);
        }
        let root = case.copy(&[], &[]);
        case.advance_to(end + 30.0);
        assert_eq!(case.seal_at(&root), 0, "{name}: {}", case.output());
        change(&root);
        case.start_target(0);
        let (calls, seen, before) = (case.log().len(), case.output().len(), marks_in(&root));
        assert_eq!(case.restore_at(&root, None), 2, "{name}: {}", case.output());
        let output = case.output();
        assert!(
            output[seen..].contains(reason),
            "{name}: {reason:?} in {output}"
        );
        assert_eq!(
            (case.log().len(), marks_in(&root)),
            (calls, before),
            "{name}"
        );
    }
}

/// An `injection/` that takes no unnamed file and a `records` that is a regular file are refused
/// before the seal's lock and before any file is read, respectively; the copy restored seals.
#[test]
fn a_seal_refuses_an_injection_that_takes_no_unnamed_file_or_a_records_file() {
    let mut case = Case::new("seal-probe");
    let root = case.restored_copy();
    case.advance_to(window_end().0 + 30.0);
    let start = case.plants.borrow().len();
    let held = lock(&Disk, &root.join("injection")).expect("the lock is taken");
    case.contended.set(true);
    case.fail_once(libc::EACCES, |step| matches!(step, Step::OpenUnnamed(_)));
    case.assert_seal_refused(
        &root,
        "injection takes no unnamed file, so no mark can be written there: Permission denied",
    );
    case.contended.set(false);
    drop(held);
    case.plants.borrow_mut().truncate(start);
    let records = case.scratch.0.join("records-kept");
    fs::rename(root.join("records"), &records).expect("records is moved aside");
    fs::write(root.join("records"), b"").expect("a file named records");
    let read = case.reads_under(&root);
    case.assert_seal_refused(&root, "records is no directory: Not a directory");
    assert!(read.borrow().is_empty(), "{:?}", read.borrow());
    fs::remove_file(root.join("records")).expect("removed");
    fs::rename(&records, root.join("records")).expect("records is restored");
    assert_eq!(case.seal_at(&root), 0, "{}", case.output());
}

/// A record that an earlier command left held, with a signal stored, raises at the first read of
/// `restore` and of `seal` after arming: each ends its hold there. `restore` exits 1 with no call
/// and no mark, and `seal` ends with the signal before it reads a file.
#[test]
fn restore_and_seal_end_a_hold_an_earlier_command_left_on_their_record() {
    let mut case = Case::new("stale-hold-restore-seal");
    let root = case.restored_copy();
    case.advance_to(window_end().0 + 30.0);
    fs::remove_file(root.join("injection/restoration.json")).expect("removed");
    let mut record = Record::new(case.delivered);
    record.hold();
    case.delivered.deliver(Signal::Terminate);
    let calls = case.log().len();
    let restored = case.owned_on(&mut record, Vec::new(), |mut controller| {
        controller.restore(root.as_os_str(), None)
    });
    assert!(matches!(restored, Ok(1)), "{restored:?}");
    assert!(!record.is_held());
    assert_eq!(case.log().len(), calls, "no call");
    assert!(!root.join("injection/restoration.json").exists());
    record.hold();
    case.delivered.deliver(Signal::Terminate);
    let read = case.reads_under(&root);
    let calls = (case.log().len(), case.plane.borrow().envs.len());
    let sealed = case.owned_on(&mut record, Vec::new(), |mut controller| {
        controller.seal(root.as_os_str())
    });
    assert_eq!(
        (case.log().len(), case.plane.borrow().envs.len()),
        calls,
        "the seal makes no call"
    );
    assert!(
        matches!(
            sealed,
            Err(Halt::Interrupted(Interrupted(Signal::Terminate)))
        ),
        "{sealed:?}"
    );
    assert!(!record.is_held());
    assert!(read.borrow().is_empty(), "{:?}", read.borrow());
    assert!(!root.join("injection/collected.json").exists());
}

/// A signal delivered during the lookup of a standing seal, after the read that follows arming,
/// raises at the end of the seal's armed span: the seal exits 2 with the signal's line in place of
/// the refusal of the standing mark, and the standing mark keeps its bytes.
#[test]
fn a_signal_during_the_lookup_of_a_standing_seal_ends_the_seal_with_the_signals_line() {
    let mut case = Case::new("seal-signal-lookup");
    let root = case.restored_copy();
    case.advance_to(window_end().0 + 30.0);
    assert_eq!(case.seal_at(&root), 0, "{}", case.output());
    let seal = root.join("injection/collected.json");
    let first = fs::read(&seal).expect("the seal reads");
    let looked = seal.clone();
    case.signal_at(
        Signal::Terminate,
        move |step| matches!(step, Step::Lstat(path) if *path == looked),
    );
    let seen = case.stderr().len();
    assert_eq!(case.seal_at(&root), 2, "{}", case.output());
    assert_eq!(
        case.stderr()[seen..],
        *"host-stop-controller: signal SIGTERM before any mark; nothing written\n"
    );
    assert_eq!(fs::read(&seal).expect("the seal reads"), first);
}

/// A lookup of the evidence root or of its `injection/` that fails reads as no directory: `seal`
/// and `restore` each exit 2 with the refusal of that directory and make no call.
#[test]
fn a_failed_lookup_of_the_root_or_injection_reads_as_no_directory() {
    let mut case = Case::new("lookup-dirs");
    let root = case.restored_copy();
    case.advance_to(window_end().0 + 30.0);
    for (looked, shown) in [
        (root.clone(), format!("{} is no directory", root.display())),
        (
            root.join("injection"),
            format!("{} is no directory: ", root.join("injection").display()),
        ),
    ] {
        for command in ["seal", "restore"] {
            let failed = looked.clone();
            case.fail_once(
                libc::EIO,
                move |step| matches!(step, Step::Lstat(path) if *path == failed),
            );
            let (calls, seen) = (case.log().len(), case.stderr().len());
            let code = if command == "seal" {
                case.seal_at(&root)
            } else {
                case.restore_at(&root, None)
            };
            assert_eq!(code, 2, "{command}: {}", case.output());
            assert!(
                case.stderr()[seen..].contains(&shown),
                "{command}: {}",
                &case.stderr()[seen..]
            );
            assert_eq!(case.log().len(), calls, "{command}");
            assert!(!root.join("injection/collected.json").exists(), "{command}");
        }
    }
}

/// The seal's time is the one wall reading it takes at its start: a clock that moves at each file
/// sync of the seal leaves the mark and the printed line at that reading.
#[test]
fn the_seal_dates_its_mark_by_the_one_wall_reading_at_its_start() {
    let mut case = Case::new("seal-one-reading");
    let root = case.restored_copy();
    case.advance_to(window_end().0 + 30.0);
    let before = case.plane.borrow().wall();
    case.plant(Box::new(|state, step| {
        if matches!(step, Step::Fsync(_)) {
            state.t += 1.0;
        }
        None
    }));
    let seen = case.stdout().len();
    assert_eq!(case.seal_at(&root), 0, "{}", case.output());
    assert_eq!(time(&parse(&root.join("injection/collected.json"))), before);
    assert!(
        case.stdout()[seen..].contains(&format!(" files at {}; ", repr_float(before))),
        "{}",
        &case.stdout()[seen..]
    );
    assert!(case.plane.borrow().wall() > before);
}

/// A seal whose mark would hold more bytes than the mark limit is refused before the judge's load,
/// with no mark linked.
#[test]
fn a_seal_beyond_the_mark_limit_is_refused() {
    let mut case = Case::new("seal-mark-limit");
    let root = case.restored_copy();
    case.advance_to(window_end().0 + 30.0);
    case.mark_limit = 100;
    case.assert_seal_refused(&root, "injection/collected.json would hold ");
    assert!(
        case.stderr().contains("more than the judge reads (100)"),
        "{}",
        case.stderr()
    );
    assert!(!root.join("injection/collected.json").exists());
}

/// `seal` holds the evidence lock through its reads and its mark's write: another descriptor that
/// tries the lock at the sync of `coverage.json` and at the link of `collected.json` finds it
/// taken, and finds it free once the seal returns.
#[test]
fn the_seal_holds_the_evidence_lock_through_its_reads_and_its_mark() {
    let mut case = Case::new("seal-lock-held");
    let root = case.restored_copy();
    case.advance_to(window_end().0 + 30.0);
    let injection = root.join("injection");
    let probes = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let (seen, dir, coverage) = (
        std::rc::Rc::clone(&probes),
        injection.clone(),
        root.join("coverage.json"),
    );
    let failing = std::rc::Rc::new(std::cell::Cell::new(false));
    let fail = std::rc::Rc::clone(&failing);
    let linked = std::rc::Rc::new(std::cell::Cell::new(false));
    let after_link = std::rc::Rc::clone(&linked);
    case.plant(Box::new(move |_, step| {
        let at = if syncs_at(step, &coverage) {
            Some("coverage")
        } else if links(step, "collected.json") {
            after_link.set(true);
            Some("link")
        } else if after_link.get() && matches!(step, Step::FsyncDirectory(synced) if *synced == dir)
        {
            Some("sync")
        } else if after_link.get() && matches!(step, Step::Unlink(_)) {
            Some("unlink")
        } else {
            None
        };
        let at = at?;
        seen.borrow_mut().push((at, taken_now(&dir)));
        if at == "sync" && fail.get() {
            fail.set(false);
            return Some(errno(libc::EIO));
        }
        None
    }));
    failing.set(true);
    assert_eq!(case.seal_at(&root), 1, "{}", case.output());
    assert_eq!(
        *probes.borrow(),
        [
            ("coverage", true),
            ("link", true),
            ("sync", true),
            ("unlink", true),
            ("sync", true)
        ]
    );
    drop(free_lock(&injection));
    probes.borrow_mut().clear();
    linked.set(false);
    assert_eq!(case.seal_at(&root), 0, "{}", case.output());
    assert_eq!(
        *probes.borrow(),
        [("coverage", true), ("link", true), ("sync", true)]
    );
    drop(free_lock(&injection));
}

/// Whether another descriptor finds the lock of `directory` taken, refused with `EWOULDBLOCK`.
pub(crate) fn taken_now(directory: &Path) -> bool {
    matches!(lock(&Disk, directory), Err(LockError::Taken(error))
        if error.raw_os_error() == Some(libc::EWOULDBLOCK))
}

/// Under a package approved with a clock error of 2 s and a run window ending at 400, `restore`
/// over a sealed copy dates a launch at 406 at 401, which ends observation: it exits 1 with the
/// mark standing, and the judge's load refuses the copy while that mark stands unsealed. A launch
/// at 407 dates it at 402, which ends no observation: it exits 0, and the load admits the copy.
#[test]
fn a_restoration_within_the_clock_error_after_the_window_ends_a_sealed_runs_observation() {
    let end = window_end().0;
    for (launched, code) in [(end + SKEW + 1.0, 1), (end + SKEW + 2.0, 0)] {
        let mut case = Case::new("sealed-clock-error");
        case.repackage(|p| set(p, &["clock_error_seconds"], value("2")));
        assert_eq!(case.run(), 0, "{}", case.output());
        let root = case.copy(&[], &[]);
        let package = fs::read(&case.package).expect("the package reads");
        fs::write(root.join("package.json"), package).expect("the approved package is copied");
        case.advance_to(end + 30.0);
        assert_eq!(case.seal_at(&root), 0, "{}", case.output());
        judged(&root).expect("the sealed copy loads under a clock error of 2 s");
        case.start_target(0);
        case.plane
            .borrow_mut()
            .instances
            .get_mut(TARGET)
            .expect("the target")
            .launched = launched;
        assert_eq!(case.restore_at(&root, None), code, "{}", case.output());
        let mark = parse(&root.join("injection/restoration.json"));
        assert_eq!(time(&mark), launched - SKEW, "{launched}");
        let loaded = judged(&root);
        if code == 1 {
            let refused = loaded.expect_err("the load refuses the unsealed restoration");
            assert!(
                refused.contains("injection/restoration.json stands unsealed"),
                "{refused}"
            );
        } else {
            loaded.expect("the load admits a restoration that ends no observation");
        }
    }
}

/// A run that makes `injection/` and then loses its lock to another command of the same directory
/// removes that directory while the other command still holds the lock: the run exits 2 with the
/// lock's refusal and `... is removed`, and the holder is left with a lock on a directory that no
/// longer stands. The run removes the directory it made whenever no `roles.json` counts as
/// written, whether or not it ever held the lock.
#[test]
fn a_run_that_loses_the_lock_of_its_new_injection_removes_it_while_another_holds_the_lock() {
    let mut case = Case::new("lost-lock");
    case.contended.set(true);
    let injection = case.evidence.join("injection");
    let holder = std::rc::Rc::new(std::cell::RefCell::new(None));
    let (held, at) = (std::rc::Rc::clone(&holder), injection.clone());
    case.plant(Box::new(move |_, step| {
        if matches!(step, Step::TryLock) && held.borrow().is_none() {
            *held.borrow_mut() = Some(lock(&Disk, &at).expect("the other command locks first"));
        }
        None
    }));
    assert_eq!(case.run(), 2, "{}", case.output());
    let stderr = case.stderr();
    assert!(
        stderr.contains("is held by a run, restore or seal that has not ended"),
        "{stderr}"
    );
    assert!(
        stderr.contains(&format!(
            "before roles.json stood; {} is removed",
            injection.display()
        )),
        "{stderr}"
    );
    assert!(!injection.exists(), "the run removed the directory it made");
    assert!(
        holder.borrow().is_some(),
        "the other command still holds its lock"
    );
}

/// A lookup of a standing seal that fails other than by a missing entry is refused before any
/// file of the copy is read, with no call and no mark.
#[test]
fn a_failed_lookup_of_the_seal_is_refused_before_any_read() {
    let mut case = Case::new("seal-lookup-fails");
    let root = case.restored_copy();
    case.advance_to(window_end().0 + 30.0);
    let seal = root.join("injection/collected.json");
    let looked = seal.clone();
    case.fail_once(
        libc::EIO,
        move |step| matches!(step, Step::Lstat(path) if *path == looked),
    );
    let read = case.reads_under(&root);
    case.assert_seal_refused(
        &root,
        "injection/collected.json cannot be looked up: Input/output error",
    );
    assert!(read.borrow().is_empty(), "{:?}", read.borrow());
    assert!(!seal.exists());
}

/// A seal called on its own that refuses a standing seal leaves the record it was given unarmed
/// and unheld, the lock free and the standing seal's bytes as they were.
#[test]
fn a_seal_refused_on_its_own_leaves_its_record_unarmed_and_the_lock_free() {
    let mut case = Case::new("seal-direct-refused");
    let root = case.restored_copy();
    case.advance_to(window_end().0 + 30.0);
    assert_eq!(case.seal_at(&root), 0, "{}", case.output());
    let seal = root.join("injection/collected.json");
    let first = fs::read(&seal).expect("the seal reads");
    let mut record = Record::new(case.delivered);
    let sealed = case.owned_on(&mut record, Vec::new(), |mut controller| {
        controller.seal(root.as_os_str())
    });
    match sealed {
        Err(Halt::Refused { sentence, .. }) => assert_eq!(
            sentence.to_string(),
            "injection/collected.json exists: the seal is written once"
        ),
        other => panic!("{other:?}"),
    }
    assert!(!record.is_armed() && !record.is_held());
    assert_eq!(record.pending(), None);
    assert!(!taken_now(&root.join("injection")));
    assert_eq!(fs::read(&seal).expect("the seal reads"), first);
}

/// A `package.json` past a lowered file limit is refused by its size before any other file is
/// read, and a seal whose time is NaN is refused at the run window's check before the listing.
#[test]
fn a_seal_over_the_file_limit_or_at_an_unordered_time_is_refused() {
    let mut case = Case::new("seal-file-limit");
    let root = case.restored_copy();
    case.advance_to(window_end().0 + 30.0);
    let size = fs::metadata(root.join("package.json"))
        .expect("the package stands")
        .len();
    case.file_limit = size - 1;
    let read = case.reads_under(&root);
    let sealed = case.controlled(|controller| controller.seal(root.as_os_str()));
    case.file_limit = kestrike_tools::gameday::FILE_LIMIT;
    match sealed {
        Err(Halt::Refused { sentence, .. }) => assert_eq!(
            sentence.to_string(),
            format!("package.json holds more than {} bytes", size - 1)
        ),
        other => panic!("{other:?}"),
    }
    assert_eq!(*read.borrow(), ["package.json"]);
    assert!(!root.join("injection/collected.json").exists());

    read.borrow_mut().clear();
    case.plane.borrow_mut().step = f64::NAN;
    let end = window_end().0;
    case.assert_seal_refused(
        &root,
        &format!(
            "the run window ends at {}, after the seal's time nan, so its collections may still \
             grow",
            end as i64
        ),
    );
    case.plane.borrow_mut().step = 0.0;
    assert_eq!(*read.borrow(), ["package.json"]);
    assert!(!root.join("injection/collected.json").exists());
}

/// A kept copy holds each file under its own bytes of name, a name that is no UTF-8 beside the
/// name its lossy reading gives, and a directory that cannot be read fails the copy.
#[test]
fn a_kept_copy_holds_each_name_as_it_stands_and_fails_on_an_unreadable_directory() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    let place = Scratch::new("copy-tree");
    let from = place.0.join("from");
    fs::create_dir(&from).expect("the source is made");
    let raw = OsStr::from_bytes(b"raw-\xff");
    fs::write(from.join(raw), b"raw").expect("written");
    fs::write(from.join("raw-\u{fffd}"), b"replaced").expect("written");
    fs::create_dir(from.join("skipped")).expect("made");
    fs::write(from.join("skipped/inner"), b"inner").expect("written");
    let to = place.0.join("to");
    copy_tree(&from, &to, &["skipped"]);
    assert_eq!(fs::read(to.join(raw)).expect("the raw name reads"), b"raw");
    assert_eq!(
        fs::read(to.join("raw-\u{fffd}")).expect("the replaced name reads"),
        b"replaced"
    );
    assert!(!to.join("skipped").exists());
    let locked = from.join("locked");
    fs::create_dir(&locked).expect("made");
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).expect("locked");
    let readable = fs::read_dir(&locked).is_ok();
    let copied = std::panic::catch_unwind(|| copy_tree(&from, &place.0.join("again"), &[]));
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).expect("unlocked");
    if !readable {
        assert!(copied.is_err(), "an unreadable directory fails the copy");
    }
}
