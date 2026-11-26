//! Failure intake, the record repair, the key bound, the planted control
//! and the counter gate. A test that runs workers needs a delegated
//! cgroup-v2 scope named by `CAMPAIGN_CGROUP_ROOT`; every worker is a
//! shell script, so the tests show how the supervisor handles exits and
//! files.

use std::time::Duration;

use super::super::super::pen_tests::Delegation;
use super::super::super::tests::failing_gate;
use super::super::super::{KEYS, OTHER, claim};
use super::super::tests::{
    COPYING, PASSING, PEN, awaited, json, names, plan, started, worker, worker_with,
};
use super::super::{
    BOUNDS, Bounds, Control, Ended, FAILED, MISSED, Plan, Ran, Session, Worker, ending, missed,
    opened, read, reports_counters, store, uncounted, unstarted,
};
use super::*;
use crate::store::fixture::{Case, processes, snapshot};

/// The claim of the planted control.
const PLANTED: &str = "planted: complete violation of the wrong byte";

/// A shell snippet that keeps `input` and `claim` as the worker keeps a
/// failure, then exits 1.
fn failing(input: &str, claim: &str) -> String {
    format!(
        "printf '%s' '{input}' > \"$artifacts/first-failure.input\"\n\
         printf '%s\\n' '{claim}' > \"$artifacts/first-failure.claim\"\nexit 1"
    )
}

/// The line libFuzzer prints at the start of a worker built with
/// coverage counters.
macro_rules! report {
    () => {
        "INFO: Loaded 1 modules   (7 inline 8-bit counters)"
    };
}
const REPORT: &str = report!();

/// Shell lines that write past a 1 MiB output bound and stay until the
/// run kills the pen.
const FLOOD: &str = "head -c 2000000 /dev/zero >&2\nsleep 60";

/// A shell line that prints [`REPORT`] to standard error.
const COUNTED: &str = concat!("echo '", report!(), "' >&2");

/// A line that names other counters than [`REPORT`] does.
const NEAR: &str = "INFO: Loaded 1 modules   (7 inline counters)";

/// A control worker and control rerun that print a counters line and fail
/// with the planted claim, the control's input and a bundle kept.
fn planted() -> String {
    format!(
        "{COUNTED}\necho \"argv: $target $artifacts $input\" >&2\n\
         cp \"$input\" \"$artifacts/first-failure.input\"\n\
         printf one > \"$artifacts/first-failure.bundle\"\n\
         printf '%s\\n' '{PLANTED}' > \"$artifacts/first-failure.claim\"\nexit 1"
    )
}

/// Files, under `control/` and with no pen, a failure of the run of
/// `session` that kept the claim `key` and no input: the first failure
/// of a key has the rerun `not run`.
fn claimed(session: &Session<'_>, key: &str) -> Filed {
    let artifacts = left(session, "probe", &[("first-failure.claim", key)]);
    let failure = Failure {
        target: "planted",
        artifacts: &artifacts,
        log: &artifacts.with_extension("stderr"),
        arguments: &[],
        killed: false,
        memory: false,
    };
    let base = session.plan.root.join("control");
    session
        .intake(&base, &session.origin(), &failure, None)
        .unwrap()
}

/// The control counts and the alarm `fuzz.json` under `root` holds.
fn controls(root: &Path) -> (u64, u64, bool) {
    let record = read(root).unwrap().unwrap();
    (record.control.caught, record.control.missed, record.alarm)
}

/// An artifact directory `name` under the run of `session` that holds
/// each `(file, bytes)` of `files`.
fn left(session: &Session<'_>, name: &str, files: &[(&str, &str)]) -> PathBuf {
    left_at(&session.directory.join(name), files)
}

fn left_at(artifacts: &Path, files: &[(&str, &str)]) -> PathBuf {
    std::fs::create_dir_all(artifacts).unwrap();
    for (file, bytes) in files {
        std::fs::write(artifacts.join(file), bytes).unwrap();
    }
    artifacts.to_owned()
}

/// Files the artifact directory `artifacts` under the root of `session`
/// with no pen, so no rerun runs.
fn filed(session: &Session<'_>, artifacts: &Path) -> Result<Filed, Error> {
    let failure = Failure {
        target: "campaign",
        artifacts,
        log: &artifacts.with_extension("stderr"),
        arguments: &["--fuzz".into()],
        killed: false,
        memory: false,
    };
    session.intake(&session.plan.root, &session.origin(), &failure, None)
}

/// The lines of `findings.jsonl` under `base`.
fn findings(base: &Path) -> Vec<Value> {
    std::fs::read_to_string(base.join("findings.jsonl"))
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

/// The count `fuzz.json` under `root` holds for `key`.
fn count(root: &Path, key: &str) -> Option<u64> {
    read(root).unwrap().unwrap().keys.get(key).copied()
}

/// Claims a root and starts a run with a passing worker. `session!`
/// acquires the [`processes`] guard before creating the root because the
/// seed writer inherits the test process's descriptors until exec.
macro_rules! session {
    ($case:ident, $plan:ident, $worker:ident, $session:ident) => {
        let _processes = processes();
        let $case = Case::new();
        let $plan = plan(&$case, 1);
        let $worker = worker(&$case, "worker.sh", PASSING, COPYING);
        let _claimed = claim(&$plan.root).unwrap();
        let $session = started(&$plan, &$worker, PEN).unwrap();
    };
}

/// A failed worker has exactly one key, the first that applies: its
/// claim without the trailing newline, cut at the key bound; an input
/// kept without a claim; the kind of file libFuzzer wrote, or `other
/// artifact` for another prefix; a kill at a bound; a kill for memory;
/// else an end without an input. An ending that left an input is never
/// keyed as one without, whatever the kill flags say.
#[test]
fn a_failed_worker_has_the_first_key_that_applies() {
    session!(case, plan, worker, session);
    let key = |files: &[(&str, &str)], killed, memory| {
        let artifacts = left(&session, "probe", files);
        let found = evidence(&artifacts, killed, memory).unwrap();
        std::fs::remove_dir_all(&artifacts).unwrap();
        (
            found.key,
            found
                .input
                .map(|input| input.file_name().unwrap().to_owned()),
        )
    };
    let long = "x".repeat(300);
    let claimed = [
        ("first-failure.claim", "a claim\n"),
        ("first-failure.input", "i"),
        ("crash-0", "c"),
    ];
    assert_eq!(
        key(&claimed, true, true),
        ("a claim".into(), Some("first-failure.input".into()))
    );
    assert_eq!(
        key(&[("first-failure.claim", &long)], false, false).0,
        "x".repeat(256)
    );
    let unclaimed = [("first-failure.input", "i"), ("timeout-0", "t")];
    assert_eq!(
        key(&unclaimed, true, true),
        (
            "worker: input without a claim".into(),
            Some("first-failure.input".into())
        )
    );
    for (file, expected) in [
        ("timeout-ab", "libfuzzer: timeout"),
        ("oom-ab", "libfuzzer: oom"),
        ("crash-ab", "libfuzzer: crash"),
        ("leak-ab", "libfuzzer: other artifact"),
    ] {
        assert_eq!(
            key(&[(file, "i"), ("slow-unit-0", "s")], true, true),
            (expected.into(), Some(file.into()))
        );
    }
    // A `slow-unit-` file records a completed input.
    let slow = [("slow-unit-0", "s")];
    assert_eq!(
        key(&slow, true, true),
        ("worker: killed at a bound".into(), None)
    );
    assert_eq!(
        key(&slow, false, true),
        ("worker: out of memory".into(), None)
    );
    assert_eq!(
        key(&slow, false, false),
        ("worker: ended without an input".into(), None)
    );
    let slow = [("slow-unit-0", "s"), ("timeout-9", "t"), ("crash-5", "c")];
    assert_eq!(
        key(&slow, false, false),
        ("libfuzzer: timeout".into(), Some("timeout-9".into()))
    );
    assert_eq!(
        key(&[], true, true),
        ("worker: killed at a bound".into(), None)
    );
    assert_eq!(
        key(&[], false, true),
        ("worker: out of memory".into(), None)
    );
    assert_eq!(
        key(&[], false, false),
        ("worker: ended without an input".into(), None)
    );
}

/// Intake removes a directory's files with the file its key rests on
/// last, so a removal a kill cut leaves a directory with the same key:
/// the claim after the input, the input after every other file, and the
/// file libFuzzer wrote for the failing input after its other files.
#[test]
fn the_file_a_key_rests_on_is_removed_last() {
    session!(case, plan, worker, session);
    let order = |files: &[(&str, &str)]| {
        let artifacts = left(&session, "probe", files);
        let found = evidence(&artifacts, false, false).unwrap();
        std::fs::remove_dir_all(&artifacts).unwrap();
        let names = found
            .files
            .iter()
            .map(|file| file.file_name().unwrap().to_owned());
        names.collect::<Vec<_>>()
    };
    let kept = [
        "first-failure.bundle",
        "first-failure.input",
        "first-failure.claim",
    ];
    assert_eq!(
        order(&[("first-failure.claim", "c"), ("crash-0", "x")])[..1],
        ["crash-0"]
    );
    assert_eq!(order(&[("first-failure.claim", "c")]), kept);
    assert_eq!(
        order(&[("slow-unit-0", "s"), ("timeout-9", "t"), ("crash-5", "c")])[..3],
        ["slow-unit-0", "crash-5", "timeout-9"]
    );
}

/// Two bundles have one digest when they differ only in diagnostic and
/// checkpoint records, which carry a run's timings, and another when a
/// semantic record or the bytes after the last whole record differ.
#[test]
fn a_bundles_digest_passes_over_diagnostics_and_checkpoints() {
    let record = |tag: u8, fill: u8| {
        let mut record = [fill; 48];
        record[0] = tag;
        record
    };
    let bundle = |records: &[[u8; 48]], rest: &[u8]| [records.concat(), rest.to_vec()].concat();
    let first = bundle(
        &[record(1, 0), record(10, 1), record(8, 2), record(9, 3)],
        b"",
    );
    let timed = bundle(
        &[record(1, 0), record(10, 7), record(8, 2), record(9, 8)],
        b"",
    );
    assert_eq!(semantic(&first), semantic(&timed));
    let changed = bundle(
        &[record(1, 0), record(10, 1), record(8, 4), record(9, 3)],
        b"",
    );
    assert_ne!(semantic(&first), semantic(&changed));
    let cut = bundle(&[record(1, 0), record(10, 1), record(8, 2)], b"\x09rest");
    assert_ne!(semantic(&first), semantic(&cut));
    assert_ne!(
        semantic(&cut),
        semantic(&bundle(&[record(1, 0), record(8, 2)], b"\x09tail"))
    );
}

/// Two failures with one claim are one finding: one directory, one line
/// and a count of 2, and the second leaves no artifact file.
#[test]
fn two_failures_with_one_claim_are_one_line_and_a_count_of_two() {
    session!(case, plan, worker, session);
    let files = [
        ("first-failure.input", "i"),
        ("first-failure.claim", "one claim\n"),
    ];
    for (name, rerun) in [("w0", Some("not run")), ("w1", None)] {
        let artifacts = left(&session, name, &files);
        let filed = filed(&session, &artifacts).unwrap();
        assert_eq!((filed.key.as_str(), filed.rerun), ("one claim", rerun));
        assert!(names(&artifacts).is_empty());
    }
    assert_eq!(names(&plan.root.join("failures")), [id("one claim")]);
    let lines = findings(&plan.root);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["key"], "one claim");
    assert_eq!(
        lines[0]["directory"],
        format!("failures/{}", id("one claim"))
    );
    assert_eq!(count(&plan.root, "one claim"), Some(2));
}

/// Concurrent filings of the same key must agree on which filing is
/// first. With one key slot left, exactly one distinct key gets the
/// slot; filings for the remaining keys count toward `OTHER`.
#[test]
fn failures_filed_at_once_keep_one_line_per_key_and_the_key_bound() {
    session!(case, plan, worker, session);
    let at_once = |claims: &[String]| {
        let left: Vec<PathBuf> = claims
            .iter()
            .enumerate()
            .map(|(number, claim)| {
                let files = [
                    ("first-failure.input", "i"),
                    ("first-failure.claim", claim.as_str()),
                ];
                left(&session, &format!("w{number}"), &files)
            })
            .collect();
        std::thread::scope(|scope| {
            let threads: Vec<_> = left
                .iter()
                .map(|artifacts| scope.spawn(|| filed(&session, artifacts).unwrap()))
                .collect();
            let filed = threads.into_iter().map(|thread| thread.join().unwrap());
            filed.collect::<Vec<Filed>>()
        })
    };
    let equal = at_once(&vec!["one claim\n".to_owned(); 8]);
    let first = equal.iter().filter(|filed| filed.rerun.is_some()).count();
    assert_eq!(first, 1);
    assert_eq!(names(&plan.root.join("failures")), [id("one claim")]);
    assert_eq!(findings(&plan.root).len(), 1);
    assert_eq!(count(&plan.root, "one claim"), Some(8));

    for number in 0..KEYS - 2 {
        let mut filing = session.filing.lock().unwrap();
        filing.record.keys.insert(format!("key {number}"), 1);
    }
    let claims: Vec<String> = (0..4).map(|number| format!("new {number}\n")).collect();
    let named = at_once(&claims);
    let named = named.iter().filter(|filed| filed.key != OTHER).count();
    assert_eq!(named, 1);
    assert_eq!(count(&plan.root, OTHER), Some(3));
    assert_eq!(findings(&plan.root).len(), 3);
    assert_eq!(session.stop.get(), Some(&"key table full"));
}

/// A finding's directory holds the input, the claim, the bundle, the end
/// of the worker's output and a record that names the run, the build
/// digest and the archive build record's revision, toolchain, cargo,
/// environment, `dirty` and `untracked`. The environment here is the
/// fixture record's, which holds a variable this process's environment
/// lacks, so a record read from the host's environment would differ.
#[test]
fn a_finding_holds_its_evidence_and_names_the_archives_build() {
    let _processes = processes();
    let case = Case::new();
    let plan = plan(&case, 1);
    let mut worker = worker(&case, "worker.sh", PASSING, COPYING);
    let text = |text: &str| Text::new(text).unwrap();
    worker
        .provenance
        .environment
        .insert(text("FIXTURE_FLAGS"), text("-Zfixture"));
    assert!(std::env::var_os("FIXTURE_FLAGS").is_none());
    let _claimed = claim(&plan.root).unwrap();
    let session = started(&plan, &worker, PEN).unwrap();
    let files = [
        ("first-failure.input", "the input"),
        ("first-failure.claim", "a claim\n"),
        ("first-failure.bundle", "the bundle"),
    ];
    let artifacts = left(&session, "w0", &files);
    std::fs::write(
        session.directory.join("w0.stderr"),
        "the worker's last words\n",
    )
    .unwrap();
    filed(&session, &artifacts).unwrap();
    let directory = plan.root.join("failures").join(id("a claim"));
    let file = |name: &str| std::fs::read_to_string(directory.join(name)).unwrap();
    assert_eq!(file("input"), "the input");
    assert_eq!(file("claim"), "a claim\n");
    assert_eq!(file("bundle"), "the bundle");
    assert_eq!(file("stderr.tail"), "the worker's last words\n");
    let record = json(&directory.join("record.json"));
    let provenance = &worker.provenance;
    assert_eq!(record["key"], "a claim");
    assert_eq!(record["run"], 0);
    assert_eq!(record["build"], worker.build.as_str());
    assert_eq!(record["revision"], provenance.revision.as_str());
    assert_eq!(record["toolchain"], provenance.toolchain.as_str());
    assert_eq!(record["cargo"], provenance.cargo.as_str());
    assert_eq!(record["environment"], json!({"FIXTURE_FLAGS": "-Zfixture"}));
    assert_eq!(
        (&record["dirty"], &record["untracked"]),
        (&json!(true), &json!(2))
    );
    assert_eq!(record["worker"], json!(["--fuzz"]));
    assert_eq!(record["rerun"], "not run");
    let rerun: Vec<&str> = record["rerun_arguments"]
        .as_array()
        .unwrap()
        .iter()
        .map(|word| word.as_str().unwrap())
        .collect();
    let (rerun_dir, input) = (directory.join("rerun"), directory.join("input"));
    assert_eq!(
        rerun,
        [
            "--fuzz",
            "campaign",
            "--artifacts",
            rerun_dir.to_str().unwrap(),
            "--",
            input.to_str().unwrap()
        ]
    );
}

/// After intake no corpus file has the failing input's bytes, in the
/// corpus and in a merge's new corpus, and files with other bytes stay.
#[test]
fn the_failing_input_leaves_the_corpus() {
    session!(case, plan, worker, session);
    std::fs::create_dir(plan.root.join("corpus.new")).unwrap();
    for (file, bytes) in [
        ("corpus/same", "the input"),
        ("corpus/longer", "the input."),
        ("corpus/other", "the 1nput"),
        ("corpus.new/same", "the input"),
        ("corpus.new/other", "another"),
    ] {
        std::fs::write(plan.root.join(file), bytes).unwrap();
    }
    let files = [
        ("first-failure.input", "the input"),
        ("first-failure.claim", "a claim\n"),
    ];
    filed(&session, &left(&session, "w0", &files)).unwrap();
    assert_eq!(names(&plan.root.join("corpus")), ["longer", "other"]);
    assert_eq!(names(&plan.root.join("corpus.new")), ["other"]);
    let repeat = [
        ("first-failure.input", "a repeat"),
        ("first-failure.claim", "a claim\n"),
    ];
    std::fs::write(plan.root.join("corpus/again"), "a repeat").unwrap();
    let filed = filed(&session, &left(&session, "w1", &repeat)).unwrap();
    assert_eq!(filed.rerun, None);
    assert_eq!(names(&plan.root.join("corpus")), ["longer", "other"]);
}

#[test]
fn a_slow_unit_file_alone_is_no_failures_file() {
    session!(case, plan, worker, session);
    for (file, expected) in [
        ("first-failure.claim", true),
        ("first-failure.input", true),
        ("crash-0", true),
        ("leak-0", true),
        ("slow-unit-0", false),
    ] {
        let artifacts = left(&session, file, &[(file, "bytes")]);
        assert_eq!(super::failing(&artifacts).unwrap(), expected, "{file}");
    }
    assert!(!super::failing(&left(&session, "empty", &[])).unwrap());
}

/// The first failure is stored before anything is removed: when the
/// count cannot be stored, as a process killed there would leave it, the
/// directory holds the input, the claim and the bundle, the line is
/// written, and the worker's files and the corpus copy are all still
/// there. `fuzz.json` is a directory here, so its replacement fails.
#[test]
fn a_failure_is_stored_before_its_files_are_removed() {
    session!(case, plan, worker, session);
    std::fs::write(plan.root.join("corpus/same"), "the input").unwrap();
    let files = [
        ("first-failure.bundle", "the bundle"),
        ("first-failure.claim", "a claim\n"),
        ("first-failure.input", "the input"),
    ];
    let artifacts = left(&session, "w0", &files);
    std::fs::remove_file(plan.root.join("fuzz.json")).unwrap();
    std::fs::create_dir(plan.root.join("fuzz.json")).unwrap();
    let filed = filed(&session, &artifacts);
    assert!(matches!(filed, Err(Error::Held(_))), "{filed:?}");
    let directory = plan.root.join("failures").join(id("a claim"));
    for name in ["input", "claim", "bundle", "record.json"] {
        assert!(directory.join(name).is_file(), "{name}");
    }
    assert_eq!(findings(&plan.root).len(), 1);
    assert_eq!(names(&artifacts), files.map(|(file, _)| file));
    assert_eq!(names(&plan.root.join("corpus")), ["same"]);
}

/// A corpus that intake cannot list may still hold the failing input, so
/// the intake is held with the worker's files kept for the next start.
/// `corpus` is a regular file here, so its listing fails; `corpus.new`,
/// which only a merge creates, is absent and passed over.
#[test]
fn a_corpus_that_cannot_be_listed_holds_intake_with_the_workers_files_kept() {
    session!(case, plan, worker, session);
    let files = [
        ("first-failure.claim", "a claim\n"),
        ("first-failure.input", "the input"),
    ];
    let artifacts = left(&session, "w0", &files);
    std::fs::remove_dir(plan.root.join("corpus")).unwrap();
    std::fs::write(plan.root.join("corpus"), "no directory").unwrap();
    let filed = filed(&session, &artifacts);
    assert!(matches!(filed, Err(Error::Held(_))), "{filed:?}");
    assert_eq!(names(&artifacts), files.map(|(file, _)| file));
}

/// A corpus entry that intake cannot read may be the failing input, so
/// the intake is held with the worker's files kept. The entry here is a
/// directory, which no worker puts in a corpus.
#[test]
fn a_corpus_entry_that_cannot_be_read_holds_intake_with_the_workers_files_kept() {
    session!(case, plan, worker, session);
    let files = [
        ("first-failure.claim", "a claim\n"),
        ("first-failure.input", "the input"),
    ];
    let artifacts = left(&session, "w0", &files);
    std::fs::create_dir(plan.root.join("corpus/entry")).unwrap();
    let filed = filed(&session, &artifacts);
    assert!(matches!(filed, Err(Error::Unreadable(_))), "{filed:?}");
    assert_eq!(names(&artifacts), files.map(|(file, _)| file));
}

/// Each rename of a new key's storage is followed by the sync of the
/// directory that holds the renamed entry: the four files staged for the
/// key, the rename that gives its directory its name, and `fuzz.json`.
/// So the directory's name outlasts a power loss before the line that
/// names it is appended.
#[test]
fn each_rename_of_a_new_keys_storage_is_followed_by_its_directorys_sync() {
    use crate::step::Step;
    session!(case, plan, worker, session);
    let files = [
        ("first-failure.claim", "a claim\n"),
        ("first-failure.input", "i"),
    ];
    let artifacts = left(&session, "w0", &files);
    let prior = crate::step::install(Some(crate::step::Script::default()));
    let filed = filed(&session, &artifacts);
    let reached = crate::step::install(prior).unwrap().reached;
    filed.unwrap();
    let renames: Vec<usize> = (0..reached.len())
        .filter(|&at| reached[at] == Step::Rename)
        .collect();
    assert_eq!(renames.len(), 6);
    for at in renames {
        assert_eq!(reached[at + 1..at + 3], [Step::Open, Step::Sync], "{at}");
    }
}

/// A kill at each point of a new key's storage leaves exactly one
/// complete line per key after the next start. A kill between the
/// directory's rename and the append leaves a directory with no line,
/// which gains its line; a kill during the append leaves a line without
/// its newline, which is cut; a kill between the append and the count
/// leaves a key with no count, which gets the count 1. After each, the
/// same worker files taken in again are a repeat that adds no line. A
/// kill during a rerun leaves a staged directory, which a start passes
/// over and the key's next intake replaces, stale rerun files included.
#[test]
fn a_kill_at_each_point_of_storage_leaves_one_line_per_key() {
    let _processes = processes();
    let case = Case::new();
    let plan = plan(&case, 1);
    let worker = worker(&case, "worker.sh", PASSING, COPYING);
    let _claimed = claim(&plan.root).unwrap();
    let files = [
        ("first-failure.input", "i"),
        ("first-failure.claim", "a claim\n"),
    ];
    let session = started(&plan, &worker, PEN).unwrap();
    filed(&session, &left(&session, "w0", &files)).unwrap();
    let list = plan.root.join("findings.jsonl");
    let line = std::fs::read_to_string(&list).unwrap();
    let uncounted = || {
        let mut record = read(&plan.root).unwrap().unwrap();
        record.keys.clear();
        super::super::store(&plan.root, &record).unwrap();
    };
    for (kill, torn) in [
        ("no line", ""),
        ("torn line", &line[..line.len() / 2]),
        ("no count", &line),
    ] {
        std::fs::write(&list, torn).unwrap();
        uncounted();
        let session = started(&plan, &worker, PEN).unwrap();
        assert_eq!(std::fs::read_to_string(&list).unwrap(), line, "{kill}");
        assert_eq!(count(&plan.root, "a claim"), Some(1), "{kill}");
        filed(&session, &left(&session, "w0", &files)).unwrap();
        assert_eq!(std::fs::read_to_string(&list).unwrap(), line, "{kill}");
        assert_eq!(count(&plan.root, "a claim"), Some(2), "{kill}");
    }
    let staged = plan
        .root
        .join("failures")
        .join(format!("{}.tmp", id("staged")));
    std::fs::create_dir_all(staged.join("rerun")).unwrap();
    std::fs::write(staged.join("rerun/first-failure.claim"), "stale").unwrap();
    let session = started(&plan, &worker, PEN).unwrap();
    assert_eq!(std::fs::read_to_string(&list).unwrap(), line);
    let files = [
        ("first-failure.input", "i"),
        ("first-failure.claim", "staged\n"),
    ];
    filed(&session, &left(&session, "w0", &files)).unwrap();
    assert!(!staged.exists());
    assert!(names(&plan.root.join("failures").join(id("staged")).join("rerun")).is_empty());
}

/// A root keys 256 keys, each under its own name. The first failure
/// with a new key past them is counted under `other` and stored with a directory, a line and its
/// whole claim, and it stops the run. A later one is counted and its
/// files stay. The next start is held before it takes in a file, takes a
/// number or prunes a run directory: every file of the root reads as it
/// did.
#[test]
fn the_257th_key_is_stored_under_other_and_pauses_the_root() {
    session!(case, plan, worker, session);
    let files = [
        ("first-failure.input", "i"),
        ("first-failure.claim", "the first\n"),
    ];
    let first = |name: &str| filed(&session, &left(&session, name, &files)).unwrap().key;
    assert_eq!(first("w8"), "the first");
    for number in 0..KEYS - 2 {
        let mut filing = session.filing.lock().unwrap();
        filing.record.keys.insert(format!("key {number}"), 1);
    }
    // The 256th key keeps its own name, and so does a repeat of a stored
    // key on the full table.
    let last = [
        ("first-failure.input", "j"),
        ("first-failure.claim", "the 256th\n"),
    ];
    let last = filed(&session, &left(&session, "w9", &last)).unwrap();
    assert_eq!((last.key.as_str(), session.stop.get()), ("the 256th", None));
    assert_eq!(
        (first("w8").as_str(), session.stop.get()),
        ("the first", None)
    );
    let claim_of = |name: &str| format!("the claim of {name}\n");
    let files = |name: &str| {
        let claim = claim_of(name);
        left(
            &session,
            name,
            &[
                ("first-failure.input", name),
                ("first-failure.claim", &claim),
            ],
        )
    };
    let first = files("w0");
    let stored = filed(&session, &first).unwrap();
    assert_eq!(
        (stored.key.as_str(), stored.rerun),
        (OTHER, Some("not run"))
    );
    assert_eq!(session.stop.get(), Some(&"key table full"));
    let directory = plan.root.join("failures").join(id(OTHER));
    assert_eq!(
        std::fs::read_to_string(directory.join("claim")).unwrap(),
        claim_of("w0")
    );
    assert_eq!(findings(&plan.root)[2]["key"], OTHER);
    assert!(names(&first).is_empty());
    let second = files("w1");
    assert_eq!(filed(&session, &second).unwrap().rerun, None);
    assert_eq!(count(&plan.root, OTHER), Some(2));
    assert_eq!(
        names(&second),
        ["first-failure.claim", "first-failure.input"]
    );
    assert_eq!(findings(&plan.root).len(), 3);
    drop(session);
    let before = snapshot(&plan.root);
    let next = opened(&plan, &worker, PEN);
    assert!(
        matches!(&next, Err(Error::Held(reason)) if reason.contains("256 keys")),
        "{:?}",
        next.as_ref().err()
    );
    assert_eq!(snapshot(&plan.root), before);
}

/// A run killed between a worker's failure and its intake leaves the
/// worker's files, and the next start files them as a finding of the
/// killed run before it takes its number. A directory that holds only a
/// file libFuzzer wrote for another cause, as a slow input of a worker
/// that passed leaves, is no failure and stays, and so does an empty
/// directory with its worker's output file. With the same
/// build the record names the build's revision. With another build the
/// current archive cannot rerun the failure, so the finding has `not
/// run`, the killed run's build digest and no build-record field.
#[test]
fn a_killed_runs_failure_files_are_filed_at_the_next_start() {
    let _processes = processes();
    let case = Case::new();
    let plan = plan(&case, 1);
    let worker = worker(&case, "worker.sh", PASSING, COPYING);
    let mut newer = worker_with(&case, "newer.sh", PASSING, COPYING, "exit 0");
    newer.build = Text::new(&"c".repeat(64)).unwrap();
    let _claimed = claim(&plan.root).unwrap();
    let files =
        |claim: &'static str| [("first-failure.input", "i"), ("first-failure.claim", claim)];
    let killed = started(&plan, &worker, PEN).unwrap();
    left(&killed, "w0", &files("same build\n"));
    left(&killed, "merge", &files("in the merge\n"));
    left(&killed, "w1", &[("slow-unit-0", "s")]);
    left(&killed, "w0.keep", &files("a copy\n"));
    left(&killed, "w2", &[("leak-0", "the leak")]);
    left(
        &killed,
        "w3",
        &[("first-failure.claim", "worker: ended without an input\n")],
    );
    let outside = case.root.join("outside");
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(outside.join("first-failure.claim"), "outside\n").unwrap();
    std::os::unix::fs::symlink(&outside, killed.directory.join("w4")).unwrap();
    left(&killed, "w5", &[]);
    std::fs::write(killed.directory.join("w5.stderr"), "exit 1").unwrap();
    drop(killed);
    let next = started(&plan, &worker, PEN).unwrap();
    assert!(names(&plan.root.join("runs/0/w5")).is_empty());
    assert!(plan.root.join("runs/0/w5.stderr").is_file());
    assert_eq!(count(&plan.root, "worker: ended without an input"), None);
    let record = |key: &str| json(&plan.root.join("failures").join(id(key)).join("record.json"));
    let leak = plan
        .root
        .join("failures")
        .join(id("libfuzzer: other artifact"));
    assert_eq!(std::fs::read(leak.join("input")).unwrap(), b"the leak");
    assert_eq!(record("claim: worker: ended without an input")["run"], 0);
    assert_eq!(names(&outside), ["first-failure.claim"]);
    assert!(!plan.root.join("failures").join(id("outside")).exists());
    for key in ["same build", "in the merge"] {
        assert_eq!(record(key)["run"], 0, "{key}");
        assert_eq!(record(key)["build"], worker.build.as_str(), "{key}");
        assert_eq!(
            record(key)["revision"],
            worker.provenance.revision.as_str(),
            "{key}"
        );
    }
    left(&next, "w0", &files("another build\n"));
    drop(next);
    started(&plan, &newer, PEN).unwrap();
    let record = record("another build");
    assert_eq!(record["run"], 1);
    assert_eq!(record["build"], worker.build.as_str());
    assert_eq!(record["rerun"], "not run");
    for field in [
        "revision",
        "toolchain",
        "cargo",
        "environment",
        "dirty",
        "untracked",
    ] {
        assert!(record.get(field).is_none(), "{field}");
    }
    assert_eq!(findings(&plan.root).len(), 5);
    assert_eq!(names(&plan.root.join("runs/0/w1")), ["slow-unit-0"]);
    assert_eq!(names(&plan.root.join("runs/0/w0.keep")).len(), 2);
}

/// A control is caught only when its failure is the planted violation,
/// its rerun reproduced it, and its directory and line are stored under
/// the control's base. A directory or a list whose state cannot be read
/// is an error. Intake under the control's base sets no stop, also for a
/// claim with the text `other`, whose key is `claim: other`, and keeps
/// the root's records as they are.
#[test]
fn a_control_is_caught_only_by_the_planted_claim_reproduced_and_stored() {
    session!(case, plan, worker, session);
    let base = plan.root.join("control");
    let filed = |key: &str, rerun| Filed {
        key: key.to_owned(),
        rerun,
        cut: false,
    };
    // A claim that shares the prefix `planted: ` and is another one.
    let near = "planted: infrastructure defect";
    for (claim, key) in [
        (PLANTED, PLANTED),
        ("another claim", "another claim"),
        (near, near),
        (OTHER, "claim: other"),
    ] {
        let stored = claimed(&session, claim);
        assert_eq!((stored.key.as_str(), stored.cut), (key, false));
        assert_eq!(session.stop.get(), None, "{claim}");
    }
    let caught = |filed: &Filed| caught(&base, filed).unwrap();
    assert!(caught(&filed(PLANTED, Some("reproduced"))));
    for rerun in [
        Some("unreproduced"),
        Some("diverged"),
        Some("not run"),
        None,
    ] {
        assert!(!caught(&filed(PLANTED, rerun)), "{rerun:?}");
    }
    for key in ["another claim", near] {
        assert!(known(&base, key).unwrap());
        assert!(!caught(&filed(key, Some("reproduced"))), "{key}");
    }
    let unstored = format!("{PLANTED} elsewhere");
    assert!(!caught(&filed(&unstored, Some("reproduced"))));
    // The line alone, its directory moved away, is no stored control.
    let (directory, aside) = (
        base.join("failures").join(id(PLANTED)),
        case.root.join("aside"),
    );
    std::fs::rename(&directory, &aside).unwrap();
    assert!(!caught(&filed(PLANTED, Some("reproduced"))));
    std::fs::rename(&aside, &directory).unwrap();
    assert!(caught(&filed(PLANTED, Some("reproduced"))));
    // The directory alone, its line gone, is none either.
    let list = base.join("findings.jsonl");
    std::fs::write(&list, "").unwrap();
    assert!(!caught(&filed(PLANTED, Some("reproduced"))));
    // A list that cannot be read is an error, never a miss.
    std::fs::remove_file(&list).unwrap();
    std::fs::create_dir(&list).unwrap();
    let unread = super::caught(&base, &filed(PLANTED, Some("reproduced")));
    assert!(matches!(unread, Err(Error::Unreadable(_))), "{unread:?}");
    // The control's base keeps the root's records as they are.
    assert!(!plan.root.join("failures").exists() && !plan.root.join("findings.jsonl").exists());
    assert_eq!(read(&plan.root).unwrap().unwrap().keys.len(), 0);
}

/// A control that ran to its end is counted whatever stop came after
/// it. With a signal holding the run's stop, a worker that exited 0 is
/// a miss that sets the alarm, and so is a failure that kept no input,
/// whose rerun no stop cut. The planted failure stored and reproduced is
/// caught and leaves the alarm set. A count at `u64::MAX` stays there.
#[test]
fn a_control_that_ended_is_counted_whatever_stop_came_after_it() {
    session!(case, plan, worker, session);
    let base = plan.root.join("control");
    session.stop.set("signal").unwrap();
    assert_eq!(session.judged(&base, None).unwrap(), Control::Missed);
    assert_eq!(controls(&plan.root), (0, 1, true));
    let mut filed = claimed(&session, PLANTED);
    assert_eq!((filed.rerun, filed.cut), (Some("not run"), false));
    assert_eq!(
        session.judged(&base, Some(&filed)).unwrap(),
        Control::Missed
    );
    filed.rerun = Some("reproduced");
    assert_eq!(
        session.judged(&base, Some(&filed)).unwrap(),
        Control::Caught
    );
    assert_eq!(controls(&plan.root), (1, 2, true));
    assert_eq!(session.stop.get(), Some(&"signal"));
    {
        let mut filing = session.filing.lock().unwrap();
        let record = &mut filing.record;
        (record.control.caught, record.control.missed) = (u64::MAX, u64::MAX);
        store(&plan.root, record).unwrap();
    }
    assert_eq!(
        session.judged(&base, Some(&filed)).unwrap(),
        Control::Caught
    );
    assert_eq!(session.judged(&base, None).unwrap(), Control::Missed);
    assert_eq!(controls(&plan.root), (u64::MAX, u64::MAX, true));
}

/// [`Session::controlled`] clears `control/` for each run's control, so
/// a run after a miss would discard the finding that miss stored there.
#[test]
fn a_root_whose_control_was_missed_is_held_at_the_next_start() {
    session!(case, plan, worker, session);
    let base = plan.root.join("control");
    let filed = claimed(&session, PLANTED);
    assert_eq!(
        session.judged(&base, Some(&filed)).unwrap(),
        Control::Missed
    );
    assert_eq!(controls(&plan.root), (0, 1, true));
    drop(session);
    assert_eq!(names(&base.join("failures")), [id(PLANTED)]);
    let before = snapshot(&plan.root);
    let next = started(&plan, &worker, PEN).map(|session| session.number);
    assert!(
        matches!(&next, Err(Error::Held(reason)) if reason.contains("control was missed")),
        "{next:?}"
    );
    assert_eq!(snapshot(&plan.root), before);
}

/// A control whose stored finding cannot be checked changes no count,
/// no alarm and no stop: a list that cannot be read, then a `failures`
/// that is a file. Counting a control sets no stop either, and the
/// record of a run that ends as its missed control ends is the one the
/// command exits 1 for.
#[test]
fn an_unchecked_control_changes_no_count_and_a_counted_one_sets_no_stop() {
    session!(case, plan, worker, session);
    let base = plan.root.join("control");
    let mut filed = claimed(&session, PLANTED);
    filed.rerun = Some("reproduced");
    let (list, aside) = (base.join("findings.jsonl"), case.root.join("aside"));
    std::fs::rename(&list, &aside).unwrap();
    std::fs::create_dir(&list).unwrap();
    let unread = session.judged(&base, Some(&filed));
    assert!(matches!(unread, Err(Error::Unreadable(_))), "{unread:?}");
    std::fs::remove_dir(&list).unwrap();
    std::fs::rename(&aside, &list).unwrap();
    let failures = base.join("failures");
    std::fs::rename(&failures, &aside).unwrap();
    std::fs::write(&failures, "").unwrap();
    let unread = session.judged(&base, Some(&filed));
    assert!(matches!(unread, Err(Error::Held(_))), "{unread:?}");
    std::fs::remove_file(&failures).unwrap();
    std::fs::rename(&aside, &failures).unwrap();
    assert_eq!(controls(&plan.root), (0, 0, false));
    assert_eq!(session.stop.get(), None);
    assert_eq!(
        session.judged(&base, Some(&filed)).unwrap(),
        Control::Caught
    );
    assert_eq!(controls(&plan.root), (1, 0, false));
    let control = session.judged(&base, None).unwrap();
    assert_eq!(control, Control::Missed);
    assert_eq!(controls(&plan.root), (1, 1, true));
    assert_eq!(session.stop.get(), None);
    let ran = Ran {
        ending: ending(&control, None).unwrap().unwrap(),
        workers: Vec::new(),
        after: 0,
        merge: None,
    };
    let record = session.closed(&ran, Ok(())).unwrap();
    assert_eq!(record["ending"], "control missed");
    assert!(missed(&record));
}

/// A missed control ends its run as missed, also when a signal holds
/// the stop. A caught control lets the workers start only with no stop,
/// and else the run ends with the stop's cause, as an interrupted
/// control's run does. An interrupted control with no stop is an error.
#[test]
fn a_run_ends_by_its_control_and_its_stop() {
    for stop in [None, Some("signal"), Some("key table full")] {
        let missed = ending(&Control::Missed, stop).unwrap();
        assert_eq!(missed, Some("control missed"), "{stop:?}");
        assert_eq!(ending(&Control::Caught, stop).unwrap(), stop);
        let interrupted = ending(&Control::Interrupted, stop);
        match stop {
            Some(_) => assert_eq!(interrupted.unwrap(), stop),
            None => assert!(matches!(interrupted, Err(Error::Held(_)))),
        }
    }
}

/// The counter gate reads the first 1 MiB of the control worker's
/// output: a counters line there is found under more output than the
/// tail holds, one that starts past it is passed over, and so is a line
/// that names other counters. An output it cannot open is refused with
/// the store's own sentence for the cause.
#[test]
fn the_counter_gate_reads_the_start_of_the_output() {
    let case = Case::new();
    let log = case.root.join("w.stderr");
    let filler = "x".repeat(1 << 20);
    let written = |text: String| {
        std::fs::write(&log, text).unwrap();
        reports_counters(&log).unwrap()
    };
    assert!(written(format!("{REPORT}\n{filler}")));
    let edge = &filler[..(1 << 20) - REPORT.len() - 1];
    assert!(written(format!("{edge}{REPORT}\n")));
    assert!(!written(format!("{filler}{REPORT}\n")));
    assert!(!written(format!("{NEAR}\n")));
    std::fs::remove_file(&log).unwrap();
    assert!(reports_counters(&log).is_err());
    std::fs::create_dir(&log).unwrap();
    let refused = reports_counters(&log).unwrap_err().to_string();
    assert_eq!(refused, crate::store::Unreadable::NotRegular.to_string());
}

/// The counter gate's refusal names the output file and how the worker
/// ended: its exit status alone, or with the bound the run killed its
/// pen at and the pen's out-of-memory kill.
#[test]
fn the_counter_gates_refusal_states_how_the_worker_ended() {
    use std::os::unix::process::ExitStatusExt;

    let log = Path::new("/root/control/w.stderr");
    let refusal = |killed, memory| {
        let ended = Ended {
            status: Some(std::process::ExitStatus::from_raw(9)),
            killed,
            out_of_memory: memory,
            counts: None,
            output: "w.stderr".into(),
            stopped: false,
            filed: None,
        };
        match uncounted(log, &ended) {
            Error::Rejected(reason) => reason,
            other => panic!("{other:?}"),
        }
    };
    let (time, memory) = ("the time bound", "out-of-memory kill");
    let plain = refusal(None, false);
    assert!(plain.contains("/root/control/w.stderr") && plain.contains("signal: 9"));
    assert!(!plain.contains("bound") && !plain.contains(memory));
    let killed = refusal(Some("time"), false);
    assert!(killed.contains(time) && !killed.contains(memory));
    assert!(refusal(Some("output"), false).contains("the output bound"));
    let both = refusal(Some("time"), true);
    assert!(both.contains(time) && both.contains(memory));
    let starved = refusal(None, true);
    assert!(!starved.contains("bound") && starved.contains(memory));
}

/// A control whose gate exited 125 with its own line at the start of the
/// output never started the worker, so it is held as a worker that cannot
/// start. Exit 125 under other output, and the gate's line under another
/// status, are workers that ran.
#[test]
fn a_control_whose_gate_failed_before_the_worker_started_is_held() {
    use std::os::unix::process::ExitStatusExt;

    let case = Case::new();
    let log = case.root.join("w.stderr");
    let ended = |raw| Ended {
        status: Some(std::process::ExitStatus::from_raw(raw)),
        killed: None,
        out_of_memory: false,
        counts: None,
        output: "w.stderr".into(),
        stopped: false,
        filed: None,
    };
    let gate = format!(
        "{}No such file or directory (os error 2)\n",
        crate::exit::GATE_LINE
    );
    std::fs::write(&log, &gate).unwrap();
    match unstarted(&log, &ended(125 << 8)).unwrap() {
        Some(Error::Held(reason)) => assert!(reason.contains("os error 2"), "{reason}"),
        other => panic!("{other:?}"),
    }
    assert!(unstarted(&log, &ended(1 << 8)).unwrap().is_none());
    std::fs::write(&log, format!("INFO: Seed: 1\n{gate}")).unwrap();
    assert!(unstarted(&log, &ended(125 << 8)).unwrap().is_none());
}

/// `started` returns `Error::Held` and preserves the root's entries and
/// file contents when it meets malformed state: a `fuzz.json` that lacks
/// `next` or `failed_merges`, a `record.json` that lacks a `key` or holds
/// the key of another directory, a `failures` entry that is a file, and a
/// last run's entry that is a file. A `fuzz.json` that holds `next` and
/// `failed_merges` alone reads with an empty key table.
#[test]
fn a_start_holds_a_root_whose_records_it_cannot_read() {
    session!(case, plan, worker, session);
    let files = [
        ("first-failure.input", "i"),
        ("first-failure.claim", "a claim\n"),
    ];
    filed(&session, &left(&session, "w0", &files)).unwrap();
    drop(session);
    let root = &plan.root;
    let held = |context: &str| {
        let before = snapshot(root);
        let next = started(&plan, &worker, PEN);
        assert!(matches!(next, Err(Error::Held(_))), "{context}");
        assert_eq!(snapshot(root), before, "{context}");
    };
    let record = std::fs::read(root.join("fuzz.json")).unwrap();
    for partial in [r#"{"failed_merges":0}"#, r#"{"next":1}"#] {
        std::fs::write(root.join("fuzz.json"), partial).unwrap();
        held(partial);
    }
    std::fs::write(root.join("fuzz.json"), r#"{"next":7,"failed_merges":2}"#).unwrap();
    let old = read(root).unwrap().unwrap();
    assert_eq!((old.next, old.failed_merges, old.last), (7, 2, None));
    assert!(old.keys.is_empty());
    std::fs::write(root.join("fuzz.json"), &record).unwrap();
    let stored = root
        .join("failures")
        .join(id("a claim"))
        .join("record.json");
    let bytes = std::fs::read(&stored).unwrap();
    for unkeyed in ["{}", r#"{"key":"another claim"}"#, r#"{"key":"a claim"}"#] {
        std::fs::write(&stored, unkeyed).unwrap();
        held(unkeyed);
    }
    std::fs::write(&stored, bytes).unwrap();
    for entry in ["failures", "runs/0"] {
        let away = case.root.join("away");
        std::fs::rename(root.join(entry), &away).unwrap();
        std::fs::write(root.join(entry), "a file").unwrap();
        held(entry);
        std::fs::remove_file(root.join(entry)).unwrap();
        std::fs::rename(&away, root.join(entry)).unwrap();
    }
    let outside = case.root.join("outside");
    left_at(&outside.join("w0"), &files);
    let away = case.root.join("away");
    std::fs::rename(root.join("runs/0"), &away).unwrap();
    std::os::unix::fs::symlink(&outside, root.join("runs/0")).unwrap();
    held("a linked run");
    assert_eq!(names(&outside.join("w0")).len(), 2);
    std::fs::remove_file(root.join("runs/0")).unwrap();
    let next = started(&plan, &worker, PEN).unwrap();
    assert_eq!(next.number, 1);
    assert_eq!(count(root, "a claim"), Some(1));
}

/// Intake returns `Error::Held` and preserves the submitted artifacts
/// when a kept file's path names a directory and when a symlink stands
/// at the path of a key's directory.
#[test]
fn intake_holds_on_evidence_it_cannot_inspect() {
    session!(case, plan, worker, session);
    let files = [
        ("first-failure.input", "i"),
        ("first-failure.claim", "a claim\n"),
    ];
    let artifacts = left(&session, "w0", &files);
    std::fs::create_dir(artifacts.join("first-failure.bundle")).unwrap();
    let refused = filed(&session, &artifacts);
    assert!(matches!(refused, Err(Error::Held(_))), "{refused:?}");
    assert!(!plan.root.join("failures").join(id("a claim")).exists());
    assert!(findings(&plan.root).is_empty());
    assert_eq!(names(&artifacts).len(), 3);
    std::fs::remove_dir(artifacts.join("first-failure.bundle")).unwrap();
    let linked = plan.root.join("failures").join(id("a claim"));
    std::fs::create_dir_all(plan.root.join("failures")).unwrap();
    std::os::unix::fs::symlink(&case.root, &linked).unwrap();
    let refused = filed(&session, &artifacts);
    assert!(matches!(refused, Err(Error::Held(_))), "{refused:?}");
    assert_eq!(names(&artifacts).len(), 2);
    assert_eq!(count(&plan.root, "a claim"), None);
}

/// An artifact directory that is a symlink is held before intake reads
/// through it: the files of the directory it names stay, and nothing is
/// filed. One that becomes a symlink after its evidence is read, as a
/// rerun's process can make it, is held before a file is removed.
#[test]
fn intake_holds_on_an_artifact_directory_that_is_a_symlink() {
    session!(case, plan, worker, session);
    let files = [
        ("crash-1", "i"),
        ("first-failure.claim", "outside\n"),
        ("first-failure.input", "i"),
    ];
    let outside = left_at(&case.root.join("outside"), &files);
    let linked = session.directory.join("w0");
    std::os::unix::fs::symlink(&outside, &linked).unwrap();
    let refused = filed(&session, &linked);
    assert!(matches!(refused, Err(Error::Held(_))), "{refused:?}");
    let refused = super::failing(&linked);
    assert!(matches!(refused, Err(Error::Held(_))), "{refused:?}");
    assert_eq!(names(&outside), files.map(|(file, _)| file));
    assert!(findings(&plan.root).is_empty());
    let (inside, moved) = (
        session.directory.join("w1"),
        session.directory.join("moved"),
    );
    left_at(&inside, &files);
    let (from, to, target) = (inside.clone(), moved.clone(), outside.clone());
    let mut swap = Some(move || {
        std::fs::rename(&from, &to).unwrap();
        std::os::unix::fs::symlink(&target, &from).unwrap();
    });
    let prior = crate::step::install(Some(crate::step::Script {
        observe: Some(Box::new(move |step| {
            if step == crate::step::Step::Rename
                && let Some(swap) = swap.take()
            {
                swap();
            }
        })),
        ..Default::default()
    }));
    let refused = filed(&session, &inside);
    crate::step::install(prior);
    assert!(matches!(refused, Err(Error::Held(_))), "{refused:?}");
    assert_eq!(names(&outside), files.map(|(file, _)| file));
    assert_eq!(names(&moved), files.map(|(file, _)| file));
}

/// An artifact directory swapped for a symlink during a new key's
/// staging is held before the corpus scan: the scan would read the
/// input through the link and remove the corpus files of those bytes.
#[test]
fn a_swapped_artifact_directory_is_held_before_the_corpus_scan() {
    session!(case, plan, worker, session);
    let corpus = plan.root.join("corpus");
    std::fs::write(corpus.join("keep"), "o").unwrap();
    std::fs::write(corpus.join("same"), "i").unwrap();
    let claim = ("first-failure.claim", "a claim\n");
    let outside = left_at(
        &case.root.join("outside"),
        &[claim, ("first-failure.input", "o")],
    );
    let inside = left(&session, "w0", &[claim, ("first-failure.input", "i")]);
    let (from, to) = (inside.clone(), session.directory.join("moved"));
    let mut swap = Some(move || {
        std::fs::rename(&from, &to).unwrap();
        std::os::unix::fs::symlink(&outside, &from).unwrap();
    });
    let prior = crate::step::install(Some(crate::step::Script {
        observe: Some(Box::new(move |step| {
            if step == crate::step::Step::Rename
                && let Some(swap) = swap.take()
            {
                swap();
            }
        })),
        ..Default::default()
    }));
    let refused = filed(&session, &inside);
    crate::step::install(prior);
    assert!(matches!(refused, Err(Error::Held(_))), "{refused:?}");
    assert_eq!(names(&corpus), ["keep", "same"]);
}

/// A repeat is held on a kept file it cannot inspect before its count
/// rises, as a new key is: the bundle here is a directory.
#[test]
fn a_repeat_with_a_kept_file_it_cannot_inspect_is_held_uncounted() {
    session!(case, plan, worker, session);
    let files = [
        ("first-failure.claim", "a claim\n"),
        ("first-failure.input", "i"),
    ];
    filed(&session, &left(&session, "w0", &files)).unwrap();
    let artifacts = left(&session, "w1", &files);
    std::fs::create_dir(artifacts.join("first-failure.bundle")).unwrap();
    let refused = filed(&session, &artifacts);
    assert!(matches!(refused, Err(Error::Held(_))), "{refused:?}");
    assert_eq!(count(&plan.root, "a claim"), Some(1));
    assert_eq!(names(&artifacts).len(), 3);
}

/// A repeat is held on an input it cannot read before its count rises:
/// a libFuzzer-named entry that is a directory, a symlink or a FIFO, and
/// a kept input past the read bound.
#[test]
fn a_repeat_with_an_input_it_cannot_read_is_held_uncounted() {
    session!(case, plan, worker, session);
    filed(&session, &left(&session, "w0", &[("crash-1", "i")])).unwrap();
    let key = "libfuzzer: crash";
    let target = case.root.join("target");
    std::fs::write(&target, "i").unwrap();
    for (name, kind) in [("w1", "directory"), ("w2", "symlink"), ("w3", "fifo")] {
        let artifacts = left(&session, name, &[]);
        let at = artifacts.join("crash-2");
        match kind {
            "directory" => std::fs::create_dir(&at).unwrap(),
            "symlink" => std::os::unix::fs::symlink(&target, &at).unwrap(),
            _ => {
                let made = std::process::Command::new("mkfifo").arg(&at).status();
                assert!(made.unwrap().success());
            }
        }
        let refused = filed(&session, &artifacts);
        assert!(
            matches!(refused, Err(Error::Held(_))),
            "{name}: {refused:?}"
        );
        assert_eq!(count(&plan.root, key), Some(1), "{name}");
        assert_eq!(names(&artifacts), ["crash-2"], "{name}");
    }
    let files = [
        ("first-failure.claim", "a claim\n"),
        ("first-failure.input", "i"),
    ];
    filed(&session, &left(&session, "w4", &files)).unwrap();
    let artifacts = left(&session, "w5", &files);
    let input = std::fs::OpenOptions::new()
        .write(true)
        .open(artifacts.join("first-failure.input"))
        .unwrap();
    input.set_len(super::ARTIFACT_BOUND + 1).unwrap();
    let refused = filed(&session, &artifacts);
    assert!(matches!(refused, Err(Error::Unreadable(_))), "{refused:?}");
    assert_eq!(count(&plan.root, "a claim"), Some(1));
    assert_eq!(names(&artifacts).len(), 2);
}

/// Intake reads a repeat's input before it stores the count. A repeat
/// whose first read fails with `EIO` is held with its count and its file
/// unchanged, and a repeat that files makes each read before the store
/// of `fuzz.json`.
#[test]
fn a_repeat_whose_input_read_fails_is_held_uncounted() {
    use crate::step::{Outcome, Script, Step};

    session!(case, plan, worker, session);
    filed(&session, &left(&session, "w0", &[("crash-1", "i")])).unwrap();
    let key = "libfuzzer: crash";
    let scripted = |artifacts: &Path, nth| {
        crate::step::install(Some(Script {
            nth,
            ..Default::default()
        }));
        let filed = filed(&session, artifacts);
        (filed, crate::step::install(None).unwrap().reached)
    };
    let artifacts = left(&session, "w1", &[("crash-2", "i")]);
    let fault = (Step::Read, 0, Outcome::Errno(libc::EIO));
    let (refused, _) = scripted(&artifacts, Some(fault));
    assert!(matches!(refused, Err(Error::Held(_))), "{refused:?}");
    assert_eq!(count(&plan.root, key), Some(1));
    assert_eq!(names(&artifacts), ["crash-2"]);
    let (filed, reached) = scripted(&artifacts, None);
    filed.unwrap();
    assert_eq!(count(&plan.root, key), Some(2));
    let stored = reached.iter().position(|step| *step == Step::Rename);
    assert!(
        !reached[stored.unwrap()..].contains(&Step::Read),
        "{reached:?}"
    );
}

/// A claim whose text reads as a key intake derives from a worker's end
/// or a libFuzzer file has a key of its own, so a failure with that
/// derived key is stored beside it.
#[test]
fn a_claim_that_reads_as_a_derived_key_has_its_own_key() {
    session!(case, plan, worker, session);
    for (name, claim) in [
        ("w0", "worker: ended without an input"),
        ("w1", "libfuzzer: crash"),
    ] {
        let text = format!("{claim}\n");
        let files = [("first-failure.claim", text.as_str())];
        let filed = filed(&session, &left(&session, name, &files)).unwrap();
        assert_eq!(filed.key, format!("claim: {claim}"));
    }
    let bare = filed(&session, &left(&session, "w2", &[])).unwrap();
    assert_eq!(bare.key, "worker: ended without an input");
    assert_eq!(bare.rerun, Some("not run"));
    assert_eq!(findings(&plan.root).len(), 3);
}

/// A repair syncs `failures/` before it appends the line of a directory
/// that has none, so the directory's name outlasts a power loss with the
/// line, as at the directory's first filing.
#[test]
fn a_repair_syncs_the_failures_directory_before_it_appends_a_line() {
    use crate::step::Step;
    session!(case, plan, worker, session);
    let files = [
        ("first-failure.claim", "a claim\n"),
        ("first-failure.input", "i"),
    ];
    filed(&session, &left(&session, "w0", &files)).unwrap();
    std::fs::write(plan.root.join("findings.jsonl"), "").unwrap();
    let prior = crate::step::install(Some(crate::step::Script::default()));
    let repaired = repaired(&plan.root, &mut BTreeMap::new());
    let reached = crate::step::install(prior).unwrap().reached;
    repaired.unwrap();
    let at = |step| reached.iter().position(|reached| *reached == step).unwrap();
    assert!(at(Step::Sync) < at(Step::Write), "{reached:?}");
    assert_eq!(findings(&plan.root).len(), 1);
}

/// A corpus that is a symlink is held before intake lists or removes
/// through it: the file of the directory it names stays, though it holds
/// the failing input's bytes, and the worker's files stay.
#[test]
fn intake_holds_on_a_corpus_that_is_a_symlink() {
    session!(case, plan, worker, session);
    let files = [
        ("first-failure.claim", "a claim\n"),
        ("first-failure.input", "the input"),
    ];
    let artifacts = left(&session, "w0", &files);
    let outside = left_at(&case.root.join("outside"), &[("same", "the input")]);
    std::fs::remove_dir(plan.root.join("corpus")).unwrap();
    std::os::unix::fs::symlink(&outside, plan.root.join("corpus")).unwrap();
    let refused = filed(&session, &artifacts);
    assert!(matches!(refused, Err(Error::Held(_))), "{refused:?}");
    assert_eq!(names(&outside), ["same"]);
    assert_eq!(names(&artifacts), files.map(|(file, _)| file));
}

/// A libFuzzer file whose name is no UTF-8 is read and removed under its
/// own name: its bytes are stored as the finding's input and the
/// directory is left empty.
#[test]
fn an_artifact_whose_name_is_no_utf8_is_filed_under_its_own_name() {
    use std::os::unix::ffi::OsStringExt;
    session!(case, plan, worker, session);
    let artifacts = left(&session, "w0", &[]);
    let name = OsString::from_vec(b"crash-\xff".to_vec());
    std::fs::write(artifacts.join(&name), "the input").unwrap();
    let filed = filed(&session, &artifacts).unwrap();
    assert_eq!(filed.key, "libfuzzer: crash");
    let stored = plan.root.join("failures").join(id("libfuzzer: crash"));
    assert_eq!(std::fs::read(stored.join("input")).unwrap(), b"the input");
    assert!(names(&artifacts).is_empty());
}

/// Each failing input of one artifact directory gets its own filing. A
/// merge's processes share a directory: the worker keeps a claim for the
/// first failing input alone, and libFuzzer writes a file for each. The
/// first intake files the claim and removes the files of its input; the
/// file of another input stays, with its corpus copy, and the next
/// intake files it under its libFuzzer key. A file that is no failing
/// input stays.
#[test]
fn each_failing_input_of_a_directory_gets_its_own_filing() {
    session!(case, plan, worker, session);
    let corpus = plan.root.join("corpus");
    std::fs::write(corpus.join("x"), "a").unwrap();
    std::fs::write(corpus.join("y"), "b").unwrap();
    let files = [
        ("crash-1", "a"),
        ("crash-2", "b"),
        ("first-failure.claim", "a claim\n"),
        ("first-failure.input", "a"),
        ("slow-unit-0", "s"),
    ];
    let artifacts = left(&session, "merge", &files);
    assert_eq!(filed(&session, &artifacts).unwrap().key, "a claim");
    assert_eq!(names(&artifacts), ["crash-2", "slow-unit-0"]);
    assert_eq!(names(&corpus), ["y"]);
    assert_eq!(filed(&session, &artifacts).unwrap().key, "libfuzzer: crash");
    let stored = plan.root.join("failures").join(id("libfuzzer: crash"));
    assert_eq!(std::fs::read(stored.join("input")).unwrap(), b"b");
    assert_eq!(names(&artifacts), ["slow-unit-0"]);
    assert!(names(&corpus).is_empty());
    assert_eq!(findings(&plan.root).len(), 2);
}

/// A claim is paired with the worker's kept input alone. A kill between
/// the removal of a filed input and of its claim leaves the claim beside
/// another input's libFuzzer file: the claim is then a repeat with no
/// input, which removes the claim alone, and the other input keeps its
/// file and its corpus copy for a filing of its own.
#[test]
fn a_claim_whose_input_is_gone_leaves_another_inputs_file_to_its_own_filing() {
    session!(case, plan, worker, session);
    let whole = [
        ("first-failure.claim", "a claim\n"),
        ("first-failure.input", "a"),
    ];
    filed(&session, &left(&session, "w0", &whole)).unwrap();
    let corpus = plan.root.join("corpus");
    std::fs::write(corpus.join("y"), "b").unwrap();
    let cut = [("crash-2", "b"), ("first-failure.claim", "a claim\n")];
    let artifacts = left(&session, "merge", &cut);
    assert_eq!(filed(&session, &artifacts).unwrap().key, "a claim");
    assert_eq!(count(&plan.root, "a claim"), Some(2));
    assert_eq!(names(&artifacts), ["crash-2"]);
    assert_eq!(names(&corpus), ["y"]);
    assert_eq!(filed(&session, &artifacts).unwrap().key, "libfuzzer: crash");
    let stored = plan.root.join("failures").join(id("libfuzzer: crash"));
    assert_eq!(std::fs::read(stored.join("input")).unwrap(), b"b");
    assert!(names(&corpus).is_empty());
}

/// The next start files every failing input a killed run's directory
/// holds, before it prunes. On a full key table the first is stored
/// under `other` and the second is counted with its file left in place,
/// which ends the directory's intake.
#[test]
fn a_start_files_every_failing_input_of_a_killed_runs_directory() {
    let _processes = processes();
    let case = Case::new();
    let plan = plan(&case, 1);
    let worker = worker(&case, "worker.sh", PASSING, COPYING);
    let _claimed = claim(&plan.root).unwrap();
    let files = [("crash-2", "y"), ("timeout-1", "x")];
    let killed = started(&plan, &worker, PEN).unwrap();
    let merge = left(&killed, "merge", &files);
    drop(killed);
    let killed = started(&plan, &worker, PEN).unwrap();
    assert!(names(&merge).is_empty());
    let keys: Vec<Value> = findings(&plan.root)
        .iter()
        .map(|line| line["key"].clone())
        .collect();
    assert_eq!(keys, ["libfuzzer: timeout", "libfuzzer: crash"]);
    let merge = left(&killed, "merge", &[("leak-3", "z"), ("oom-4", "w")]);
    drop(killed);
    let next = opened(&plan, &worker, PEN).unwrap();
    for number in 0..KEYS - 2 {
        let mut filing = next.filing.lock().unwrap();
        filing.record.keys.insert(format!("key {number}"), 1);
    }
    next.advance(None).unwrap();
    assert_eq!(count(&plan.root, OTHER), Some(2));
    assert_eq!(names(&merge), ["leak-3"]);
    assert_eq!(next.stop.get(), Some(&"key table full"));
}

/// Opening a FIFO read-only in blocking mode waits for a writer. If
/// intake stalls there, opening and dropping the writer lets intake
/// observe EOF and the test join its thread. Following a claim symlink
/// can import bytes from outside the artifact directory.
#[test]
fn intake_rejects_a_fifo_a_symlink_and_an_oversize_file_as_a_claim() {
    use std::os::unix::fs::OpenOptionsExt;
    let mut accepted = Vec::new();
    for kind in ["FIFO", "symlink", "oversize"] {
        session!(case, plan, worker, session);
        let artifacts = left(&session, "w0", &[("first-failure.input", "i")]);
        let claim = artifacts.join("first-failure.claim");
        match kind {
            "FIFO" => {
                let directory = std::fs::File::open(&artifacts).unwrap();
                crate::sys::mkfifo(&directory, c"first-failure.claim").unwrap();
            }
            "symlink" => {
                // The linked text is a stored key, so reading through
                // the link makes this failure a repeat.
                let stored = [
                    ("first-failure.input", "i"),
                    ("first-failure.claim", "outside\n"),
                ];
                filed(&session, &left(&session, "w1", &stored)).unwrap();
                let outside = case.root.join("outside");
                std::fs::write(&outside, "outside\n").unwrap();
                std::os::unix::fs::symlink(&outside, &claim).unwrap();
            }
            _ => {
                let file = std::fs::File::create(&claim).unwrap();
                file.set_len(ARTIFACT_BOUND + 1).unwrap();
            }
        }
        let records = || {
            let counts = std::fs::read(plan.root.join("fuzz.json")).unwrap();
            (findings(&plan.root), counts)
        };
        let before = records();
        let (refused, waited) = std::thread::scope(|scope| {
            let intake = scope.spawn(|| filed(&session, &artifacts));
            let deadline = Instant::now() + Duration::from_secs(10);
            while !intake.is_finished() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            let waited = !intake.is_finished();
            // The writer's open fails until a reader holds the FIFO, so it
            // is tried until the intake thread ends.
            while waited && !intake.is_finished() {
                let mut writer = std::fs::OpenOptions::new();
                let writer = writer.write(true).custom_flags(libc::O_NONBLOCK);
                drop(writer.open(&claim));
                std::thread::sleep(Duration::from_millis(10));
            }
            (intake.join().unwrap(), waited)
        });
        let kept = names(&artifacts) == ["first-failure.claim", "first-failure.input"];
        if waited || refused.is_ok() || records() != before || !kept {
            accepted.push((kind, waited, format!("{refused:?}")));
        }
    }
    assert!(accepted.is_empty(), "{accepted:?}");
}

/// `other` doubles as the overflow key.
#[test]
fn a_claim_of_other_has_its_own_key_and_pauses_no_root() {
    session!(case, plan, worker, session);
    let files = [
        ("first-failure.input", "i"),
        ("first-failure.claim", "other\n"),
    ];
    for failures in [1, 2] {
        let artifacts = left(&session, "w0", &files);
        assert_eq!(filed(&session, &artifacts).unwrap().key, "claim: other");
        assert_eq!(session.stop.get(), None, "{failures}");
        assert!(names(&artifacts).is_empty(), "{failures}");
        assert_eq!(count(&plan.root, "claim: other"), Some(failures));
    }
    assert_eq!(count(&plan.root, OTHER), None);
    // The second `claim:` prefix distinguishes the literal claim
    // `claim: other` from the escaped key for `other`.
    let escaped = [
        ("first-failure.input", "i"),
        ("first-failure.claim", "claim: other\n"),
    ];
    let artifacts = left(&session, "w1", &escaped);
    assert_eq!(
        filed(&session, &artifacts).unwrap().key,
        "claim: claim: other"
    );
    assert_eq!(count(&plan.root, "claim: other"), Some(2));
    drop(session);
    let next = started(&plan, &worker, PEN).map(|next| next.number);
    assert_eq!(next.ok(), Some(1));
}

/// Intake recovers from a partial trailing record in `findings.jsonl`:
/// a new key's line follows the last complete line.
#[test]
fn a_new_line_follows_a_complete_line() {
    session!(case, plan, worker, session);
    let files =
        |claim: &'static str| [("first-failure.input", "i"), ("first-failure.claim", claim)];
    filed(&session, &left(&session, "w0", &files("the first\n"))).unwrap();
    let list = plan.root.join("findings.jsonl");
    let whole = std::fs::read_to_string(&list).unwrap();
    std::fs::write(&list, format!("{whole}{{\"id\":\"to")).unwrap();
    filed(&session, &left(&session, "w1", &files("the second\n"))).unwrap();
    let keys: Vec<Value> = findings(&plan.root)
        .into_iter()
        .map(|line| line["key"].clone())
        .collect();
    assert_eq!(keys, ["the first", "the second"]);
}

/// A repeat of a key whose count is `u64::MAX` keeps that count and
/// removes the submitted artifacts.
#[test]
fn a_full_count_stays_full() {
    session!(case, plan, worker, session);
    let files = [
        ("first-failure.input", "i"),
        ("first-failure.claim", "a claim\n"),
    ];
    filed(&session, &left(&session, "w0", &files)).unwrap();
    let full = ("a claim".to_owned(), u64::MAX);
    session.filing.lock().unwrap().record.keys.extend([full]);
    let artifacts = left(&session, "w1", &files);
    filed(&session, &artifacts).unwrap();
    assert_eq!(count(&plan.root, "a claim"), Some(u64::MAX));
    assert!(names(&artifacts).is_empty());
}

/// One run of `worker` on the root of `plan`, in pens under `host`, held
/// to `bounds`: the run's record.
fn fuzzed<'a>(plan: &'a Plan, worker: &'a Worker, host: &Delegation, bounds: Bounds) -> Value {
    super::super::tests::run(plan, worker, host, bounds)
}

/// Two workers that fail with one claim give one line and a count of 2,
/// each rerun runs alone in a fresh process into an empty directory and
/// reproduces the claim, and each failed worker is replaced for the time
/// left. Workers 0 and 1 fail here, and their replacements pass. The
/// rerun's script exits 3 unless its artifact directory is empty, and
/// the stored `rerun/` must hold the rerun's own claim and input, so a
/// rerun into a directory that holds the first run's files fails.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn two_workers_failing_alike_are_one_finding_and_each_is_replaced() {
    let _processes = processes();
    let host = Delegation::new("intake-alike");
    let case = Case::new();
    let mut plan = plan(&case, 2);
    plan.seconds = 30;
    let fail = failing("the input", "one claim");
    let fuzz = format!("case $artifacts in */w0|*/w1) {fail};; esac\n{PASSING}");
    let single = format!("[ -z \"$(ls \"$artifacts\")\" ] || exit 3\n{fail}");
    let worker = worker_with(&case, "worker.sh", &fuzz, COPYING, &single);
    let record = fuzzed(&plan, &worker, &host, BOUNDS);
    assert_eq!(record["ending"], "deadline");
    assert_eq!(record["failed"], 2);
    let workers = record["workers"].as_array().unwrap();
    assert_eq!(workers.len(), 4);
    let keyed = workers
        .iter()
        .filter(|worker| worker["key"] == "one claim")
        .count();
    let passed = workers.iter().filter(|worker| worker["code"] == 0).count();
    assert_eq!((keyed, passed), (2, 2));
    // Only the output filenames for each exit code matter; worker order
    // is irrelevant.
    let outputs = |code: i64| {
        let ended = workers.iter().filter(|worker| worker["code"] == code);
        let mut outputs: Vec<&str> = ended
            .map(|worker| worker["output"].as_str().unwrap_or_default())
            .collect();
        outputs.sort_unstable();
        outputs
    };
    assert_eq!(outputs(1), ["w0.stderr", "w1.stderr"]);
    assert_eq!(outputs(0), ["w2.stderr", "w3.stderr"]);
    let lines = findings(&plan.root);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["rerun"], "reproduced");
    assert_eq!(count(&plan.root, "one claim"), Some(2));
    let directory = plan.root.join("failures").join(id("one claim"));
    assert_eq!(
        names(&directory.join("rerun")),
        ["first-failure.claim", "first-failure.input"]
    );
}

/// Worker 0's rerun notes its start and polls for a nonempty
/// `findings.jsonl`, and worker 1 fails with its claim only once that
/// rerun is up, so the filing order distinguishes concurrent intake from
/// serialized intake.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn another_keys_intake_proceeds_during_a_rerun() {
    let _processes = processes();
    let host = Delegation::new("intake-parallel");
    let case = Case::new();
    let mut plan = plan(&case, 2);
    plan.seconds = 30;
    let (slow, quick) = (
        failing("slow", "a slow claim"),
        failing("quick", "a quick claim"),
    );
    let up = case.root.join("up");
    let fuzz = format!(
        "case $artifacts in\n*/w0) {slow};;\n*/w1) n=0\n\
         while [ ! -e '{up}' ] && [ $n -lt 100 ]; do sleep 0.1; n=$((n + 1)); done\n\
         [ -e '{up}' ] || exit 3\n{quick};;\n\
         esac\n{PASSING}",
        up = up.display()
    );
    let single = format!(
        "case $(cat \"$input\") in\nslow) : > '{}'; n=0\n\
         while [ ! -s '{}' ] && [ $n -lt 100 ]; do sleep 0.1; n=$((n + 1)); done\n{slow};;\n\
         esac\n{quick}",
        up.display(),
        plan.root.join("findings.jsonl").display()
    );
    let worker = worker_with(&case, "worker.sh", &fuzz, COPYING, &single);
    fuzzed(&plan, &worker, &host, BOUNDS);
    let filed: Vec<(Value, Value)> = findings(&plan.root)
        .into_iter()
        .map(|line| (line["key"].clone(), line["rerun"].clone()))
        .collect();
    assert_eq!(
        filed,
        [
            (json!("a quick claim"), json!("reproduced")),
            (json!("a slow claim"), json!("reproduced"))
        ]
    );
}

/// A run ends after 16 failed workers with the ending in its record and
/// no merge. The one worker here fails each time with its own claim.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_run_ends_after_sixteen_failed_workers() {
    let _processes = processes();
    let host = Delegation::new("intake-sixteen");
    let case = Case::new();
    let mut plan = plan(&case, 1);
    plan.seconds = 120;
    let fuzz = failing("$artifacts", "$artifacts").replace('\'', "\"");
    let worker = worker(&case, "worker.sh", &fuzz, COPYING);
    let record = fuzzed(&plan, &worker, &host, BOUNDS);
    assert_eq!(record["ending"], "failed workers");
    assert_eq!(record["failed"], FAILED);
    assert_eq!(record["workers"].as_array().unwrap().len(), FAILED as usize);
    assert_eq!(record["merge"], Value::Null);
    let lines = findings(&plan.root);
    assert_eq!(lines.len(), FAILED as usize);
    // The 16th failure's own rerun runs before its filing stops the run.
    assert!(lines.iter().all(|line| line["rerun"] == "unreproduced"));
}

/// A failed worker counts when it ends, before its rerun, and no worker
/// starts once 16 have failed. Worker 0 fails first and its rerun waits
/// for the run's stop. The other thread's worker and each replacement
/// fail with one claim once that rerun is up. The 15th of them is the
/// 16th failed worker: its filing stops the run, which ends worker 0's
/// rerun as `not run`, and no 17th worker starts.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn no_worker_starts_once_sixteen_have_failed() {
    let _processes = processes();
    let host = Delegation::new("intake-counted");
    let case = Case::new();
    let mut plan = plan(&case, 2);
    plan.seconds = 120;
    let up = case.root.join("up");
    let (slow, quick) = (
        failing("slow", "a slow claim"),
        failing("quick", "a quick claim"),
    );
    let fuzz = format!(
        "case $artifacts in\n*/w0) {slow};;\nesac\nn=0\n\
         while [ ! -e '{}' ] && [ $n -lt 100 ]; do sleep 0.1; n=$((n + 1)); done\n{quick}",
        up.display()
    );
    let single = format!(
        "case $(cat \"$input\") in\nslow) : > '{}'; while :; do sleep 0.05; done;;\nesac\n{quick}",
        up.display()
    );
    let worker = worker_with(&case, "worker.sh", &fuzz, COPYING, &single);
    let grace = Bounds {
        grace: Duration::from_secs(1),
        ..BOUNDS
    };
    let record = fuzzed(&plan, &worker, &host, grace);
    assert_eq!(record["ending"], "failed workers");
    assert_eq!(record["failed"], FAILED);
    assert_eq!(record["workers"].as_array().unwrap().len(), FAILED as usize);
    let filed: Vec<(Value, Value)> = findings(&plan.root)
        .into_iter()
        .map(|line| (line["key"].clone(), line["rerun"].clone()))
        .collect();
    assert_eq!(
        filed,
        [
            (json!("a quick claim"), json!("reproduced")),
            (json!("a slow claim"), json!("not run"))
        ]
    );
}

/// A rerun that passes is `unreproduced`, and a rerun with another claim
/// or, under the same claim, a bundle of another digest is `diverged`;
/// each failure is stored. A rerun whose bundle differs from the first
/// only in a diagnostic record is `reproduced`. Worker 0's rerun exits
/// 0, worker 1's fails with another claim, worker 2's keeps a bundle
/// with another semantic record, and worker 3's a bundle with its own
/// process ID in a diagnostic record.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_passing_rerun_is_unreproduced_and_another_claim_diverged() {
    let _processes = processes();
    let host = Delegation::new("intake-rerun");
    let case = Case::new();
    let mut plan = plan(&case, 3);
    plan.seconds = 30;
    // A bundle of one semantic record, then a diagnostic record whose
    // payload is the run's own.
    let bundled = |semantic: &str| {
        let fail = failing("bundled", "claim d");
        format!(
            "{{ printf '\\001%047d' {semantic}; printf '\\012%047d' $$; }} \\\n\
             > \"$artifacts/first-failure.bundle\"\n{fail}"
        )
    };
    let timed = |claim: &str| {
        let fail = failing("timed", claim);
        format!(
            "{{ printf '\\001%047d' 5; printf '\\012%047d' $$; }} \\\n\
             > \"$artifacts/first-failure.bundle\"\n{fail}"
        )
    };
    let fuzz = format!(
        "case $artifacts in\n*/w0) {};;\n*/w1) {};;\n*/w2) {};;\n*/w3) {};;\nesac\n{PASSING}",
        failing("passes", "claim a"),
        failing("differs", "claim b"),
        bundled("1"),
        timed("claim e")
    );
    let single = format!(
        "case $(cat \"$input\") in\npasses) exit 0;;\nbundled) {};;\ntimed) {};;\nesac\n{}",
        bundled("2"),
        timed("claim e"),
        failing("differs", "claim c")
    );
    let worker = worker_with(&case, "worker.sh", &fuzz, COPYING, &single);
    fuzzed(&plan, &worker, &host, BOUNDS);
    let mut reruns: Vec<(String, String)> = findings(&plan.root)
        .iter()
        .map(|line| {
            (
                line["key"].as_str().unwrap().into(),
                line["rerun"].as_str().unwrap().into(),
            )
        })
        .collect();
    reruns.sort();
    assert_eq!(
        reruns,
        [
            ("claim a".into(), "unreproduced".into()),
            ("claim b".into(), "diverged".into()),
            ("claim d".into(), "diverged".into()),
            ("claim e".into(), "reproduced".into())
        ]
    );
    for key in ["claim a", "claim b"] {
        assert!(
            plan.root
                .join("failures")
                .join(id(key))
                .join("input")
                .is_file()
        );
    }
}

/// A pen the kernel killed for memory gives the key `worker: out of
/// memory`, with no rerun since no input exists, and its record names
/// the archive's revision, toolchain, `dirty` and `untracked`. Worker 0
/// here reads zeroes past its pen's 64 MiB.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_pen_killed_for_memory_is_keyed_out_of_memory() {
    let _processes = processes();
    let host = Delegation::new("intake-memory");
    let case = Case::new();
    let mut plan = plan(&case, 1);
    plan.seconds = 30;
    let fuzz = format!("case $artifacts in */w0) exec tail /dev/zero;; esac\n{PASSING}");
    let worker = worker(&case, "worker.sh", &fuzz, COPYING);
    let record = fuzzed(&plan, &worker, &host, BOUNDS);
    assert_eq!(record["workers"][0]["key"], "worker: out of memory");
    let stored = plan.root.join("failures").join(id("worker: out of memory"));
    let stored = json(&stored.join("record.json"));
    assert_eq!(stored["rerun"], "not run");
    assert_eq!(stored["revision"], worker.provenance.revision.as_str());
    assert_eq!(stored["toolchain"], worker.provenance.toolchain.as_str());
    assert_eq!(
        (&stored["dirty"], &stored["untracked"]),
        (&json!(true), &json!(2))
    );
}

/// An input with no claim file, a pen the run killed at a bound and a
/// libFuzzer file with another prefix each give their own key. Worker 0
/// keeps an input alone, worker 1 writes past the output bound of 1 MiB
/// and worker 2 writes a `leak-` file and exits 1.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn an_unclaimed_input_a_bound_kill_and_another_artifact_have_their_own_keys() {
    let _processes = processes();
    let host = Delegation::new("intake-keys");
    let case = Case::new();
    let mut plan = plan(&case, 3);
    plan.seconds = 30;
    let fuzz = format!(
        "case $artifacts in\n\
         */w0) printf i > \"$artifacts/first-failure.input\"; exit 1;;\n\
         */w1) head -c 2000000 /dev/zero >&2; sleep 60;;\n\
         */w2) printf l > \"$artifacts/leak-0\"; exit 1;;\n\
         esac\n{PASSING}"
    );
    let worker = worker_with(&case, "worker.sh", &fuzz, COPYING, "exit 1");
    let bounds = Bounds {
        output: 1 << 20,
        ..BOUNDS
    };
    let record = fuzzed(&plan, &worker, &host, bounds);
    let mut keys: Vec<String> = record["workers"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|worker| worker["key"].as_str().map(str::to_owned))
        .collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "libfuzzer: other artifact",
            "worker: input without a claim",
            "worker: killed at a bound"
        ]
    );
    let mut reruns: Vec<(String, String)> = findings(&plan.root)
        .iter()
        .map(|line| {
            let text = |field: &str| line[field].as_str().unwrap().to_owned();
            (text("key"), text("rerun"))
        })
        .collect();
    reruns.sort();
    // A key without a claim is reproduced by a rerun that ends nonzero
    // without a claim, and a failure without an input has no rerun.
    let expected = [
        ("libfuzzer: other artifact", "reproduced"),
        ("worker: input without a claim", "reproduced"),
        ("worker: killed at a bound", "not run"),
    ];
    assert_eq!(
        reruns,
        expected.map(|(key, rerun)| (key.to_owned(), rerun.to_owned()))
    );
}

/// A worker the run's forwarded stop ended is no failure: it gives no
/// finding and no count, whatever it exits with. The worker here exits 1
/// on SIGTERM; the test marks the run stopped once the worker started,
/// and leaves SIGTERM unblocked so the script takes it.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_worker_the_forwarded_stop_ended_gives_no_finding() {
    let _processes = processes();
    let host = Delegation::new("intake-stop");
    let case = Case::new();
    let mut plan = plan(&case, 1);
    plan.seconds = 30;
    let fuzz = "trap 'exit 1' TERM\nprintf x > \"$artifacts.up\"\nwhile :; do sleep 0.05; done";
    let worker = worker(&case, "worker.sh", fuzz, COPYING);
    let _claimed = claim(&plan.root).unwrap();
    let session = started(&plan, &worker, PEN).unwrap();
    let up = session.directory.join("w0.up");
    let ran = std::thread::scope(|scope| {
        scope.spawn(|| {
            awaited(std::slice::from_ref(&up), &session.stop);
            session.stop.set("signal").unwrap();
        });
        session.fuzzed(&host.root()).unwrap()
    });
    assert_eq!(ran.workers.len(), 1);
    assert_eq!(
        ran.workers[0].status.and_then(|status| status.code()),
        Some(1)
    );
    assert!(ran.workers[0].filed.is_none());
    assert!(!plan.root.join("failures").exists());
    assert!(findings(&plan.root).is_empty());
}

/// A rerun a stop interrupts stores its failure with `not run`. The
/// rerun here notes its start and waits; the test marks the run stopped
/// once it has started, and leaves SIGTERM unblocked so the script
/// takes it.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn an_interrupted_rerun_stores_its_failure_as_not_run() {
    let _processes = processes();
    let host = Delegation::new("intake-interrupted");
    let case = Case::new();
    let mut plan = plan(&case, 1);
    plan.seconds = 30;
    let single = "printf x > \"$artifacts.up\"\nwhile :; do sleep 0.05; done";
    let worker = worker_with(
        &case,
        "worker.sh",
        &failing("i", "a claim"),
        COPYING,
        single,
    );
    let _claimed = claim(&plan.root).unwrap();
    let session = started(&plan, &worker, PEN).unwrap();
    let up = plan
        .root
        .join("failures")
        .join(format!("{}.tmp/rerun.up", id("a claim")));
    std::thread::scope(|scope| {
        scope.spawn(|| {
            awaited(std::slice::from_ref(&up), &session.stop);
            session.stop.set("signal").unwrap();
        });
        session.fuzzed(&host.root()).unwrap()
    });
    let lines = findings(&plan.root);
    assert_eq!(lines.len(), 1);
    assert_eq!(
        (&lines[0]["key"], &lines[0]["rerun"]),
        (&json!("a claim"), &json!("not run"))
    );
    assert!(
        plan.root
            .join("failures")
            .join(id("a claim"))
            .join("input")
            .is_file()
    );
}

/// A failing input in the merge's artifact directory becomes a finding
/// when the merge exits 0, the merge is still adopted, and the run's
/// record holds the attempt count of the merge's `MERGE-OUTER` line. A
/// second failing input, which has a libFuzzer file and no claim, becomes
/// a finding under that file's key; the record keeps the first key. Its
/// rerun keeps a claim, so it reads `diverged`.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_failure_a_merge_retains_is_a_finding_and_its_attempts_are_recorded() {
    let _processes = processes();
    let host = Delegation::new("intake-merge");
    let case = Case::new();
    let plan = plan(&case, 1);
    let merge = format!(
        "printf m > \"$new/merged\"\nprintf other > \"$artifacts/crash-2\"\n\
         echo 'MERGE-OUTER: successful in 3 attempt(s)' >&2\n{}",
        failing("in the merge", "a merge claim").replace("exit 1", "exit 0")
    );
    let worker = worker_with(
        &case,
        "worker.sh",
        PASSING,
        &merge,
        &failing("i", "a merge claim"),
    );
    let record = fuzzed(&plan, &worker, &host, BOUNDS);
    assert_eq!(record["merge"]["adopted"], true);
    assert_eq!(record["merge"]["attempts"], 3);
    assert_eq!(record["merge"]["key"], "a merge claim");
    let lines = findings(&plan.root);
    let filed: Vec<_> = lines
        .iter()
        .map(|line| (&line["key"], &line["rerun"]))
        .collect();
    assert_eq!(
        filed,
        [
            (&json!("a merge claim"), &json!("reproduced")),
            (&json!("libfuzzer: crash"), &json!("diverged")),
        ]
    );
    assert!(names(&plan.root.join("runs/0/merge")).is_empty());
}

/// The failure files a killed run left are rerun in a pen at the next
/// start when the archive is the same build, and stored with `not run`
/// when it is another build.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_killed_runs_failure_is_rerun_at_the_next_start_of_its_build() {
    let _processes = processes();
    let host = Delegation::new("intake-leftover");
    let case = Case::new();
    let plan = plan(&case, 1);
    let single = failing("i", "a claim");
    let worker = worker_with(&case, "worker.sh", PASSING, COPYING, &single);
    let mut newer = worker_with(&case, "newer.sh", PASSING, COPYING, &single);
    newer.build = Text::new(&"c".repeat(64)).unwrap();
    let _claimed = claim(&plan.root).unwrap();
    for (run, (archive, claim, rerun)) in [
        (&worker, "a claim\n", "reproduced"),
        (&newer, "another\n", "not run"),
    ]
    .into_iter()
    .enumerate()
    {
        let killed = started(&plan, &worker, PEN).unwrap();
        left(
            &killed,
            "w0",
            &[("first-failure.input", "i"), ("first-failure.claim", claim)],
        );
        drop(killed);
        let next = opened(&plan, archive, PEN).unwrap();
        next.watched(&host.root(), 1, |_, pen, slot| {
            next.advance(Some((pen, slot)))
        })
        .unwrap();
        let line = &findings(&plan.root)[run];
        assert_eq!(
            (&line["run"], &line["rerun"]),
            (&json!(2 * run), &json!(rerun))
        );
    }
}

/// The control of a started run of `single`, the script of the control
/// worker and its rerun: how the control ended, or its error, and the
/// cause of the run's stop when one is set.
fn controlled(
    case: &Case,
    plan: &Plan,
    host: &Delegation,
    name: &str,
    single: &str,
) -> (Result<Control, Error>, Option<&'static str>) {
    let worker = worker_with(case, name, PASSING, COPYING, single);
    let mut session = started(plan, &worker, PEN).unwrap();
    session.bounds.output = 1 << 20;
    let caught = session.controlled(&host.root());
    (caught, session.stop.get().copied())
}

fn rooted() -> (Case, Plan, Worker, crate::store::PrivateDir) {
    let case = Case::new();
    let plan = plan(&case, 1);
    let claimed = claim(&plan.root).unwrap();
    let prior = worker(&case, "prior.sh", PASSING, COPYING);
    let session = started(&plan, &prior, PEN).unwrap();
    let files = [
        ("first-failure.input", "i"),
        ("first-failure.claim", "a claim\n"),
    ];
    filed(&session, &left(&session, "w0", &files)).unwrap();
    drop(session);
    std::fs::write(plan.root.join("corpus/seed"), "seed").unwrap();
    (case, plan, prior, claimed)
}

/// A control run must preserve this snapshot of `root`.
fn records(root: &Path) -> impl PartialEq + std::fmt::Debug {
    let keys = read(root).unwrap().unwrap().keys;
    let list = std::fs::read(root.join("findings.jsonl")).unwrap();
    (
        snapshot(&root.join("failures")),
        list,
        keys,
        names(&root.join("corpus")),
    )
}

/// A caught control adds to the caught count and leaves the root's
/// `failures/` and `findings.jsonl` as they were, with its own finding
/// under `control/`; its worker and its rerun ran the `planted` target,
/// the worker on this run's `upload` seed. Then each control the checks
/// let through is missed: one whose rerun passes, which comes here
/// straight after the caught run, so nothing that run left under
/// `control/` satisfies the check; a planted worker that exits 0, with
/// no evidence and with the planted evidence kept; one that fails with
/// another `planted: ` claim; one whose claim is the text `other`; one
/// whose rerun keeps another bundle; and one the run killed at its output
/// bound after it kept the planted evidence, with a rerun that fails on
/// its own and with a rerun killed alike. The root's finding, list,
/// counts and corpus stay as they were throughout. Each miss sets no
/// stop, sets the alarm, which stays, and adds to the missed count.
/// Each miss case uses a separate root, and the alarm holds the next
/// start of that root.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_caught_control_is_counted_and_each_other_result_is_missed() {
    let _processes = processes();
    let host = Delegation::new("control");
    let (case, plan, _prior, _claimed) = rooted();
    let before = records(&plan.root);
    let (caught, stop) = controlled(&case, &plan, &host, "caught.sh", &planted());
    assert_eq!((caught.unwrap(), stop), (Control::Caught, None));
    assert_eq!(records(&plan.root), before);
    assert_eq!(controls(&plan.root), (1, 0, false));
    let control = plan.root.join("control");
    assert_eq!(names(&control.join("failures")), [id(PLANTED)]);
    assert_eq!(findings(&control)[0]["rerun"], "reproduced");
    // The control worker ran `--fuzz planted --artifacts control/w --
    // runs/1/seeds/upload.input`, each path under the root, and its
    // rerun ran the same target on the staged input.
    let stored = control.join("failures").join(id(PLANTED));
    let seed = plan.root.join("runs/1/seeds/upload.input");
    let record = json(&stored.join("record.json"));
    let (artifacts, input) = (control.join("w"), seed.display().to_string());
    assert_eq!(
        record["worker"],
        json!(["--fuzz", "planted", "--artifacts", artifacts, "--", input])
    );
    let argv = |log: &Path| {
        let log = std::fs::read_to_string(log).unwrap();
        let line = log.lines().find(|line| line.starts_with("argv: "));
        line.unwrap().to_owned()
    };
    assert_eq!(
        argv(&stored.join("stderr.tail")),
        format!(
            "argv: planted {} {}",
            control.join("w").display(),
            seed.display()
        )
    );
    let staged = control
        .join("failures")
        .join(format!("{}.tmp", id(PLANTED)));
    assert_eq!(
        argv(&stored.join("rerun.stderr")),
        format!(
            "argv: planted {} {}",
            staged.join("rerun").display(),
            staged.join("input").display()
        )
    );
    let passes_rerun = format!(
        "case $artifacts in */rerun) {COUNTED}; exit 0;; esac\n{}",
        planted()
    );
    let other_bundle = planted().replace(
        "printf one",
        "case $artifacts in */rerun) printf two;; *) printf one;; esac",
    );
    let misses = [
        ("unreproduced.sh", passes_rerun, "unreproduced"),
        ("passing.sh", format!("{COUNTED}\nexit 0"), ""),
        // It keeps the planted evidence and exits 0; its rerun would fail.
        (
            "kept.sh",
            planted().replace(
                "exit 1",
                "case $artifacts in */rerun) exit 1;; esac\nexit 0",
            ),
            "",
        ),
        (
            "other.sh",
            planted().replace(PLANTED, "planted: infrastructure defect"),
            "reproduced",
        ),
        (
            "literal.sh",
            planted().replace(PLANTED, OTHER),
            "reproduced",
        ),
        ("diverged.sh", other_bundle, "diverged"),
        // It keeps the planted evidence, then writes past the output
        // bound and stays, so the run kills its pen; its rerun fails on
        // its own.
        (
            "flooded.sh",
            planted().replace(
                "exit 1",
                &format!("case $artifacts in */rerun) exit 1;; esac\n{FLOOD}"),
            ),
            "reproduced",
        ),
        // Its rerun is killed at the bound too.
        ("hung.sh", planted().replace("exit 1", FLOOD), "reproduced"),
    ];
    for (name, single, rerun) in misses {
        let (case, plan, prior, _claimed) = rooted();
        let before = records(&plan.root);
        let (caught, _) = controlled(&case, &plan, &host, "caught.sh", &planted());
        assert_eq!(caught.unwrap(), Control::Caught, "{name}");
        let (caught, stop) = controlled(&case, &plan, &host, name, &single);
        assert_eq!((caught.unwrap(), stop), (Control::Missed, None), "{name}");
        assert_eq!(controls(&plan.root), (1, 1, true), "{name}");
        // The earlier run's directory and line were replaced by this
        // run's own.
        let lines = findings(&plan.root.join("control"));
        if rerun.is_empty() {
            assert!(lines.is_empty(), "{name}");
        } else {
            assert_eq!(lines.len(), 1, "{name}");
            assert_eq!(
                (&lines[0]["run"], &lines[0]["rerun"]),
                (&json!(2), &json!(rerun)),
                "{name}"
            );
        }
        assert_eq!(records(&plan.root), before, "{name}");
        let stored = snapshot(&plan.root);
        let next = started(&plan, &prior, PEN).map(|session| session.number);
        assert!(
            matches!(&next, Err(Error::Held(reason)) if reason.contains("control was missed")),
            "{name}: {next:?}"
        );
        assert_eq!(snapshot(&plan.root), stored, "{name}");
    }
}

/// A control worker with no counters line is a refusal with the control
/// counts unchanged, whatever the control's result: one that would be
/// caught and one that passes.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_control_worker_without_counters_is_refused_whatever_its_result() {
    let _processes = processes();
    let host = Delegation::new("control-counters");
    let case = Case::new();
    let plan = plan(&case, 1);
    let _claimed = claim(&plan.root).unwrap();
    let uncounted = planted().replace(REPORT, NEAR);
    for (name, single, status) in [
        ("caught.sh", uncounted.as_str(), "exit status: 1"),
        ("passing.sh", "exit 0", "exit status: 0"),
    ] {
        let (caught, _) = controlled(&case, &plan, &host, name, single);
        // The refusal names the output file and how the worker ended.
        assert!(
            matches!(&caught, Err(Error::Rejected(reason)) if reason.contains("coverage counters")
                && reason.contains("control/w.stderr") && reason.contains(status)),
            "{name}: {caught:?}"
        );
        assert_eq!(controls(&plan.root), (0, 0, false));
    }
}

/// A control a stop interrupts is neither caught nor missed: no count
/// changes, the alarm stays as it was and the last control's files stay
/// in place. The SIGINT here is pending at the call's start, after a
/// run whose control was caught.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn an_interrupted_control_changes_no_count_and_sets_no_alarm() {
    let _processes = processes();
    let host = Delegation::new("control-interrupted");
    let case = Case::new();
    let plan = plan(&case, 1);
    let _claimed = claim(&plan.root).unwrap();
    let (caught, _) = controlled(&case, &plan, &host, "caught.sh", &planted());
    assert_eq!(caught.unwrap(), Control::Caught);
    let last = snapshot(&plan.root.join("control"));
    crate::sys::block_interruptions().unwrap();
    crate::sys::interrupt(libc::SIGINT).unwrap();
    let (caught, stop) = controlled(&case, &plan, &host, "worker.sh", &planted());
    assert_eq!(
        (caught.unwrap(), stop),
        (Control::Interrupted, Some("signal"))
    );
    assert_eq!(controls(&plan.root), (1, 0, false));
    assert_eq!(snapshot(&plan.root.join("control")), last);
}

/// A stop that ends the running control worker, or the control's rerun,
/// leaves the control neither caught nor missed. The worker here waits
/// before its counters line and the rerun waits in place of failing; the
/// test marks the run stopped once each has started, and leaves SIGTERM
/// unblocked so the scripts take it. The stopped worker files nothing,
/// and the failure whose rerun was stopped is stored under `control/` as
/// `not run`.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_stop_during_the_control_or_its_rerun_changes_no_count() {
    let _processes = processes();
    let host = Delegation::new("control-stopped");
    let case = Case::new();
    let plan = plan(&case, 1);
    let _claimed = claim(&plan.root).unwrap();
    let waits = "printf x > \"$artifacts.up\"\nwhile :; do sleep 0.05; done";
    let rerun_waits = format!("case $artifacts in */rerun) {waits};; esac\n{}", planted());
    let rerun_up = format!("control/failures/{}.tmp/rerun.up", id(PLANTED));
    for (name, single, up) in [
        ("worker.sh", waits, "control/w.up"),
        ("rerun.sh", rerun_waits.as_str(), rerun_up.as_str()),
    ] {
        let worker = worker_with(&case, name, PASSING, COPYING, single);
        let session = started(&plan, &worker, PEN).unwrap();
        let up = plan.root.join(up);
        let (caught, seen) = std::thread::scope(|scope| {
            // The stop comes once the script is up, or after a minute
            // without it, which fails the test below.
            let stopper = scope.spawn(|| {
                let limit = std::time::Instant::now() + Duration::from_secs(60);
                while !up.exists() && std::time::Instant::now() < limit {
                    std::thread::sleep(Duration::from_millis(10));
                }
                let seen = up.exists();
                let _ = session.stop.set("signal");
                seen
            });
            (session.controlled(&host.root()), stopper.join().unwrap())
        });
        assert!(seen, "{name}: {} never appeared", up.display());
        assert_eq!(caught.unwrap(), Control::Interrupted, "{name}");
        assert_eq!(controls(&plan.root), (0, 0, false), "{name}");
        let control = plan.root.join("control");
        if name == "worker.sh" {
            assert!(!control.join("failures").exists());
            continue;
        }
        let lines = findings(&control);
        assert_eq!(lines.len(), 1);
        assert_eq!(
            (&lines[0]["key"], &lines[0]["run"], &lines[0]["rerun"]),
            (&json!(PLANTED), &json!(session.number), &json!("not run"))
        );
        assert_eq!(names(&control.join("failures")), [id(PLANTED)]);
        assert!(!plan.root.join("findings.jsonl").exists());
    }
}

/// A run starts its fuzz workers only after a caught control. A missed
/// control gives a run with no worker and no merge whose record ends
/// `control missed`, the ending the command exits 1 for, and counts the
/// corpus as the run leaves it. A control worker with no counters line
/// is a refusal that starts no fuzz worker. A run whose control a
/// pending SIGINT keeps from starting ends `signal` with no worker, no
/// merge and the control counts as they were.
/// The missed control's run comes last on the root, because the alarm
/// holds every later start.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn the_workers_start_only_after_a_caught_control() {
    let _processes = processes();
    let host = Delegation::new("control-first");
    let case = Case::new();
    let plan = plan(&case, 1);
    let _claimed = claim(&plan.root).unwrap();
    let run = |name: &str, single: &str| {
        let worker = worker_with(&case, name, PASSING, COPYING, single);
        let session = started(&plan, &worker, PEN).unwrap();
        let directory = session.directory.clone();
        // A corpus file that arrives after the run counted its start.
        std::fs::write(plan.root.join("corpus").join(name), name).unwrap();
        let ran = session.ran(&host.root());
        (
            ran.map(|ran| session.closed(&ran, Ok(())).unwrap()),
            directory,
        )
    };
    let (record, directory) = run("caught.sh", &planted());
    let record = record.unwrap();
    assert_eq!(record["ending"], "deadline");
    assert_eq!(record["workers"].as_array().unwrap().len(), 1);
    assert!(directory.join("w0").is_dir());
    let (refused, directory) = run("uncounted.sh", "exit 1");
    assert!(matches!(refused, Err(Error::Rejected(_))), "{refused:?}");
    assert_eq!(names(&directory), ["seeds"]);
    let counts = controls(&plan.root);
    crate::sys::block_interruptions().unwrap();
    crate::sys::interrupt(libc::SIGINT).unwrap();
    let (record, directory) = run("interrupted.sh", &planted());
    let record = record.unwrap();
    assert_eq!(record["ending"], "signal");
    assert_eq!(
        (&record["workers"], &record["merge"]),
        (&json!([]), &Value::Null)
    );
    assert_eq!(names(&directory), ["run.json", "seeds"]);
    assert_eq!(controls(&plan.root), counts);
    let (record, directory) = run("missed.sh", &format!("{COUNTED}\nexit 0"));
    let record = record.unwrap();
    assert_eq!(record["ending"], MISSED);
    assert_eq!(
        (&record["workers"], &record["merge"]),
        (&json!([]), &Value::Null)
    );
    let before = record["corpus"]["before"].as_u64().unwrap();
    assert_eq!(record["corpus"]["after"], json!(before + 1));
    assert_eq!(json(&directory.join("run.json")), record);
    assert_eq!(names(&directory), ["run.json", "seeds"]);
}

/// A gate that fails before it starts the control's rerun holds the run.
/// The rerun's worker never ran, so the control counts and the alarm stay
/// as they were and `control/` lists no finding.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_control_rerun_whose_gate_failed_is_held_uncounted() {
    let _processes = processes();
    let host = Delegation::new("control-gate");
    let (case, plan, _prior, _claimed) = rooted();
    let worker = worker_with(&case, "caught.sh", PASSING, COPYING, &planted());
    std::fs::write(&worker.gate, failing_gate("*/rerun\\ *")).unwrap();
    let mut session = started(&plan, &worker, PEN).unwrap();
    session.bounds.output = 1 << 20;
    let held = session.controlled(&host.root());
    assert!(
        matches!(&held, Err(Error::Held(reason)) if reason.contains("os error 2")),
        "{held:?}"
    );
    assert_eq!(controls(&plan.root), (0, 0, false));
    assert!(findings(&plan.root.join("control")).is_empty());
}
