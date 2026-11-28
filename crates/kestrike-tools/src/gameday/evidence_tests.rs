//! `read_evidence` loads the held fixture with its digests and indices.

use std::fs;
use std::os::fd::AsFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::symlink;
use std::path::Path;

use super::{Evidence, load_evidence, read_evidence};
use crate::gameday::constants::FILE_LIMIT;
use crate::gameday::order::ends_observation;
use crate::gameday::package::FleetBounds;
use crate::gameday::read::ReadError;
use crate::gameday::test_support::{held, object, patched, tree, value};
use crate::json::{Object, Value, dump};
use crate::paths::tests::Scratch;
use crate::python::hexdigest;
use crate::text::Text;

#[derive(Clone, Copy, Debug)]
enum Op {
    Replace(&'static str, &'static str, &'static str),
    Remove(&'static str),
    Write(&'static str, &'static str),
    Link(&'static str, &'static str),
    Fifo(&'static str),
    Mkdir(&'static str),
    Unseal(&'static str),
    Fill(&'static str, usize),
}

const REVIEWED: Op = Op::Replace(
    "injection/restoration.json",
    "\"reviewed_sha256\": null",
    "\"reviewed_sha256\": \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
);

fn bounds() -> FleetBounds {
    FleetBounds::new(&tree(), FILE_LIMIT).expect("the top holds no NUL")
}

fn listed(root: &Path) -> Vec<String> {
    let mut names = Vec::new();
    for dir in ["", "injection", "records"] {
        for entry in fs::read_dir(root.join(dir)).expect("the directory lists") {
            let entry = entry.expect("the directory lists");
            if entry.file_type().expect("the type reads").is_file() {
                let name = Path::new(dir).join(entry.file_name());
                names.push(name.to_str().expect("a fixture name is UTF-8").to_owned());
            }
        }
    }
    names.sort();
    names
}

fn copy() -> Scratch {
    let scratch = Scratch::new("gameday-evidence");
    let from = tree().join("scripts/gameday-fixtures/held");
    for dir in ["injection", "records"] {
        fs::create_dir(scratch.0.join(dir)).expect("the directory is made");
    }
    for name in listed(&from) {
        fs::copy(from.join(&name), scratch.0.join(&name)).expect("the file copies");
    }
    scratch
}

fn apply(root: &Path, op: Op) {
    match op {
        Op::Replace(rel, old, new) => {
            let text = fs::read_to_string(root.join(rel)).expect("the file reads");
            assert_eq!(text.matches(old).count(), 1, "{rel} holds {old} once");
            fs::write(root.join(rel), text.replace(old, new)).expect("the file writes");
        }
        Op::Remove(rel) => fs::remove_file(root.join(rel)).expect("the file is removed"),
        Op::Write(rel, text) => fs::write(root.join(rel), text).expect("the file writes"),
        Op::Link(rel, target) => symlink(target, root.join(rel)).expect("the link is made"),
        Op::Fifo(rel) => {
            let made = std::process::Command::new("mkfifo")
                .arg(root.join(rel))
                .status();
            assert!(made.expect("mkfifo starts").success(), "the fifo is made");
        }
        Op::Mkdir(rel) => fs::create_dir(root.join(rel)).expect("the directory is made"),
        Op::Fill(rel, size) => {
            let made = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(root.join(rel));
            let mut file = made.expect("the file is made");
            std::io::Write::write_all(&mut file, &vec![b'x'; size]).expect("the file writes");
        }
        Op::Unseal(rel) => {
            let seal = root.join("injection/collected.json");
            let text = fs::read_to_string(&seal).expect("the seal reads");
            let mut unsealed = object(&value(&text)).clone();
            match unsealed.get_mut("files") {
                Some(Value::Object(files)) => files.remove(rel).expect("the seal names the file"),
                other => panic!("the seal's files are an object, not {other:?}"),
            };
            fs::write(seal, dump(&Value::Object(unsealed))).expect("the seal writes");
        }
    }
}

/// `reseal` records the fixture payloads' SHA-256 digests in the `files` field of
/// `injection/collected.json`.
fn reseal(root: &Path) {
    let rel = "injection/collected.json";
    let mut files = Object::new();
    for name in listed(root) {
        if name == "package.json" || name == rel {
            continue;
        }
        let digest = hexdigest(&fs::read(root.join(&name)).expect("the file reads"));
        files.insert(name, Value::String(Text::from(digest)));
    }
    let text = fs::read_to_string(root.join(rel)).expect("the seal reads");
    let mut seal = object(&value(&text)).clone();
    seal.insert("files", Value::Object(files));
    fs::write(root.join(rel), dump(&Value::Object(seal))).expect("the seal writes");
}

fn load(ops: &[Op], sealed: bool) -> Result<Evidence, ReadError> {
    load_within(ops, sealed, FILE_LIMIT)
}

fn load_within(ops: &[Op], sealed: bool, limit: u64) -> Result<Evidence, ReadError> {
    let scratch = copy();
    let (unseal, change): (Vec<Op>, Vec<Op>) =
        ops.iter().partition(|op| matches!(op, Op::Unseal(_)));
    for op in change {
        apply(&scratch.0, op);
    }
    if sealed {
        reseal(&scratch.0);
    }
    for op in unseal {
        apply(&scratch.0, op);
    }
    read_evidence(&scratch.0, limit, &bounds())
}

fn refusal(ops: &[Op], sealed: bool) -> String {
    match load(ops, sealed) {
        Err(ReadError::Refused(refusal)) => refusal.message().to_string(),
        other => panic!("the changed copy is refused, not {other:?}"),
    }
}

fn held_lines(rel: &str) -> Value {
    let path = tree().join("scripts/gameday-fixtures/held").join(rel);
    let text = fs::read_to_string(path).expect("the fixture reads");
    Value::Array(text.lines().map(value).collect())
}

#[test]
fn the_marks_are_the_files_of_injection_but_the_seal_in_the_layouts_order() {
    let marks: Vec<&str> = crate::gameday::LAYOUT
        .iter()
        .map(|(rel, _, _)| *rel)
        .filter(|rel| rel.starts_with("injection/") && *rel != "injection/collected.json")
        .collect();
    assert_eq!(marks, crate::gameday::constants::MARKS);
}

#[test]
fn held_directory_loads_with_its_digests_and_indices() {
    let root = tree().join("scripts/gameday-fixtures/held");
    let evidence: Evidence = read_evidence(&root, FILE_LIMIT, &bounds()).expect("held loads");
    assert_eq!(
        evidence.package_sha256(),
        "30759c81708af91aa8ad1e953f902fb6001cb6465e84e2231726463af9292056"
    );
    assert_eq!(
        evidence.seal_sha256(),
        "7979ade2516adcd9b854b9d5776bc492ecf487b60acfe02de21911b78bfc1e5c"
    );
    let anchors: Vec<(String, Option<usize>)> = evidence
        .anchors()
        .iter()
        .map(|(shard, at)| (shard.to_string(), *at))
        .collect();
    let expected: Vec<(String, Option<usize>)> = ["s1", "s2", "s3", "s4", "s5"]
        .iter()
        .map(|shard| ((*shard).to_owned(), Some(0)))
        .collect();
    assert_eq!(anchors, expected);
    assert_eq!(evidence.package(), object(&held("package.json")));
    assert_eq!(
        evidence.file("witness.jsonl"),
        Some(&held_lines("witness.jsonl"))
    );
    assert_eq!(evidence.file("injection/abort.json"), None);
}

#[test]
fn each_entry_off_the_layout_and_a_sealed_file_of_other_bytes_are_refused() {
    let rows: [(&str, &[Op], &str); 7] = [
        (
            "link",
            &[
                Op::Remove("origin.jsonl"),
                Op::Link("origin.jsonl", "provider.jsonl"),
            ],
            "origin.jsonl is a link or a special file",
        ),
        (
            "named pipe",
            &[
                Op::Remove("injection/stop.json"),
                Op::Fifo("injection/stop.json"),
            ],
            "injection/stop.json is a link or a special file",
        ),
        (
            "directory inside records",
            &[Op::Mkdir("records/extra")],
            "records/extra is no directory of the layout",
        ),
        (
            "unlisted file",
            &[Op::Write("notes.txt", "{}\n")],
            "notes.txt is no file of the layout",
        ),
        (
            "missing required file",
            &[Op::Remove("blockers.jsonl")],
            "blockers.jsonl is missing",
        ),
        (
            "observation outside the world",
            &[
                Op::Replace(
                    "package.json",
                    "\"kind\": \"staging\"",
                    "\"kind\": \"simulation\"",
                ),
                Op::Replace(
                    "package.json",
                    "\"outside\": {}",
                    "\"outside\": {\"origin\": \"no origin in this world\"}",
                ),
            ],
            "origin.jsonl stands, but the package names its observation outside its world",
        ),
        (
            "sealed file of other bytes",
            &[Op::Replace(
                "origin.jsonl",
                "{\"time\": 2, \"key\": \"img/other-2\"}\n",
                "{\"time\": 2, \"key\": \"img/other-two\"}\n",
            )],
            "origin.jsonl differs from the bytes injection/collected.json seals: it holds SHA-256 \
             9c55ce6ddfd7e42a70366cdd19459142e67116671d58a7f83abe03781ba9b929, the seal \
             65443fad683c3daa9659ca7c0a6d830ed26027f9b8f5c0202b1d777e88e55a5c",
        ),
    ];
    for (row, ops, expected) in rows {
        assert_eq!(refusal(ops, false), expected, "{row}");
    }
}

/// `reseal` updates each modified copy's digests so `refusal` reports the violated order rule.
#[test]
fn each_order_refusal_names_its_rule() {
    const R: fn(&'static str, &'static str, &'static str) -> Op = Op::Replace;
    let roles = "injection/roles.json";
    let stop = "injection/stop.json";
    let restoration = "injection/restoration.json";
    let abort = "{\"cause\": \"deadline\", \"guardrail\": \"any generation change\", \"time\": 200, \
                 \"detail\": null}\n";
    let hit = "\"time\": 140, \"outcome\": \"hit\", \"sha256\": \
               \"2a3cea95b4092de8543406854a74486a6510c938c8357f5052b93e018e3c818a\"}";
    let rows: Vec<(Vec<Op>, &str)> = vec![
        (
            vec![R("records/s4.jsonl", "{\"time\": 180,", "{\"time\": 40,")],
            "records/s4.jsonl is not in commit order",
        ),
        (
            vec![R(roles, "\"generation\": 5,", "\"generation\": 6,")],
            "injection/roles.json reads shard s5 other than its last version committed before the \
             read or one within the clock error of it",
        ),
        (
            vec![R(stop, "\"time\": 110,", "\"time\": 90,")],
            "the baseline window ends after the stop",
        ),
        (
            vec![R(stop, "\"time\": 110,", "\"time\": 400,")],
            "the run window does not hold the stop",
        ),
        (
            vec![REVIEWED],
            "injection/restoration.json names a reviewed record without an abort mark, or none \
             after one",
        ),
        (
            vec![R(
                restoration,
                "\"instance\": \"i-h1\"",
                "\"instance\": \"i-h2\"",
            )],
            "injection/restoration.json names another instance than the stop request's",
        ),
        (
            vec![R(
                restoration,
                "\"state\": \"running\"",
                "\"state\": \"stopped\"",
            )],
            "injection/restoration.json reads a state other than running",
        ),
        (
            vec![R(restoration, "\"time\": 420,", "\"time\": 111,")],
            "injection/restoration.json precedes the stop request, the stopped report or the abort \
             mark",
        ),
        (
            vec![R("witness.jsonl", "\"time\": 115,", "\"time\": 150,")],
            "witness.jsonl is not in send order",
        ),
        (
            vec![Op::Replace(
                "witness.jsonl",
                hit,
                "\"time\": 140, \"outcome\": \"hit\", \"sha256\": null}",
            )],
            "witness.jsonl line 2 is a hit with no digest (a hit needs one; another outcome may \
             read null)",
        ),
        (
            vec![R("witness.jsonl", "\"time\": 115,", "\"time\": 105,")],
            "witness.jsonl line 1 precedes the stop",
        ),
        (
            vec![R(
                "injection/collected.json",
                "\"time\": 430",
                "\"time\": 390",
            )],
            "injection/collected.json seals the collections at 390, before the run window's end \
             400",
        ),
        (
            vec![R(
                "activations.jsonl",
                "{\"host\": \"h4\",",
                "{\"host\": \"h3\",",
            )],
            "activations.jsonl repeats a host",
        ),
        (
            vec![Op::Write("injection/abort.json", abort), REVIEWED],
            "injection/abort.json guardrail is not a GD-2 guardrail text with cause guardrail and \
             null otherwise",
        ),
    ];
    assert_eq!(rows.len(), 14);
    for (ops, expected) in rows {
        assert_eq!(refusal(&ops, true), expected, "{ops:?}");
    }
}

#[test]
fn ends_observation_holds_from_the_run_start_to_less_than_the_clock_error_past_its_end() {
    let package = held("package.json");
    let with_error =
        |error: &str| object(&patched(&package, &[("clock_error_seconds", Some(error))])).clone();
    let rows: [(&str, &str, Option<&str>, bool); 4] = [
        ("at the run window's start", "0", Some("100"), true),
        ("at its end with no clock error", "0", Some("400"), false),
        (
            "at its end with a clock error of one second",
            "1",
            Some("400"),
            true,
        ),
        ("for no mark", "0", None, false),
    ];
    for (row, error, time, expected) in rows {
        let time = time.map(value);
        assert_eq!(
            ends_observation(&with_error(error), time.as_ref()),
            expected,
            "{row}"
        );
    }
}

#[test]
fn the_seal_names_each_mark_that_stands_but_a_restoration_after_observation() {
    let ends = Op::Replace(
        "injection/restoration.json",
        "\"time\": 420,",
        "\"time\": 390,",
    );
    let refused: [(&[Op], &str); 2] = [
        (
            &[Op::Unseal("injection/stop.json")],
            "injection/stop.json stands unsealed, and only a restoration may: the seal names each \
             mark that stands when it is written",
        ),
        (
            &[ends, Op::Unseal("injection/restoration.json")],
            "injection/restoration.json stands unsealed and dates 390, less than the clock error \
             after the run window's end 400, so it may end observation",
        ),
    ];
    for (ops, expected) in refused {
        assert_eq!(refusal(ops, true), expected, "{ops:?}");
    }
    let after = load(&[Op::Unseal("injection/restoration.json")], true);
    assert!(
        after.is_ok(),
        "a restoration after observation stands unsealed: {after:?}"
    );
}

#[test]
fn an_abort_mark_needs_a_reviewed_record() {
    let abort = "{\"cause\": \"deadline\", \"guardrail\": null, \"time\": 200, \"detail\": null}\n";
    assert_eq!(
        refusal(&[Op::Write("injection/abort.json", abort)], true),
        "injection/restoration.json names a reviewed record without an abort mark, or none after one"
    );
}

#[test]
fn the_roles_read_anchors_at_a_version_within_the_clock_error_or_at_none() {
    let ops = [
        Op::Replace(
            "package.json",
            "\"clock_error_seconds\": 0",
            "\"clock_error_seconds\": 30",
        ),
        Op::Replace(
            "injection/roles.json",
            "\"owner\": \"h1\",\n   \"standby\": \"h2\",\n   \"generation\": 7,\n   \"volume\": \
             \"vol-s1\",\n   \"attempts\": 1",
            "\"owner\": \"h2\",\n   \"standby\": null,\n   \"generation\": 7,\n   \"volume\": \
             \"vol-s1\",\n   \"attempts\": 2",
        ),
        Op::Replace("records/s5.jsonl", "{\"time\": 50,", "{\"time\": 300,"),
        Op::Replace(
            "records/s1.jsonl",
            "{\"time\": 150, \"owner\": \"h2\", \"standby\": \"h4\",",
            "{\"time\": 130, \"owner\": \"h2\", \"standby\": null,",
        ),
    ];
    let evidence = load(&ops, true).expect("the copy loads");
    let anchors: Vec<(String, Option<usize>)> = evidence
        .anchors()
        .iter()
        .map(|(shard, at)| (shard.to_string(), *at))
        .collect();
    let expected = [
        ("s1", Some(1)),
        ("s2", Some(0)),
        ("s3", Some(0)),
        ("s4", Some(0)),
        ("s5", None),
    ]
    .map(|(shard, at)| (shard.to_owned(), at));
    assert_eq!(anchors, expected);
}

#[test]
fn later_is_unknown_within_the_clock_error_and_exact_without_one() {
    let number = |text: &str| value(text);
    let rows: [(&str, &str, &str, Option<bool>); 6] = [
        ("110", "100", "10", None),
        ("111", "100", "10", Some(true)),
        ("89", "100", "10", Some(false)),
        ("90", "100", "10", None),
        ("100", "100", "0", Some(true)),
        ("99", "100", "0", Some(false)),
    ];
    for (t, mark, error, expected) in rows {
        let error = crate::gameday::exact(&number(error)).expect("a number");
        assert_eq!(
            crate::gameday::later(&number(t), &number(mark), &error),
            expected,
            "later({t}, {mark}, {error:?})"
        );
    }
}

#[test]
fn an_empty_root_and_a_load_without_a_seal_are_refused() {
    match read_evidence(Path::new(""), FILE_LIMIT, &bounds()) {
        Err(ReadError::Refused(refusal)) => {
            assert_eq!(*refusal.message(), "no evidence directory is named");
        }
        other => panic!("an empty root is refused, not {other:?}"),
    }
    let root = tree().join("scripts/gameday-fixtures/held");
    let mut files = std::collections::BTreeMap::new();
    for name in listed(&root) {
        let data = fs::read(root.join(&name)).expect("the file reads");
        files.insert(Text::from(name.as_str()), data);
    }
    let loaded = load_evidence(&files, &bounds()).expect("the held bytes load");
    assert_eq!(
        loaded.seal_sha256(),
        "7979ade2516adcd9b854b9d5776bc492ecf487b60acfe02de21911b78bfc1e5c"
    );
    files.remove(&Text::from("injection/collected.json"));
    let refused = load_evidence(&files, &bounds()).expect_err("a load without the seal");
    assert_eq!(*refused.message(), "injection/collected.json is missing");
    files.remove(&Text::from("package.json"));
    let refused = load_evidence(&files, &bounds()).expect_err("a load without the package");
    assert_eq!(*refused.message(), "package.json is missing");
}

#[test]
fn a_record_line_holds_its_time_and_then_the_versions_fields() {
    let crate::gameday::Schema::Object(fields) = crate::gameday::layout::RECORD else {
        panic!("a record line is an object");
    };
    let keys: Vec<&str> = fields.iter().map(|(key, _)| *key).collect();
    let mut expected = vec!["time"];
    expected.extend(crate::gameday::VERSION_FIELDS.iter().map(|(key, _)| *key));
    assert_eq!(keys, expected);
}

/// A directory that lists without search permission refuses its first entry, whose `lstat` fails.
#[test]
fn an_entry_whose_type_cannot_be_read_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    struct Mode<'a>(&'a Path);
    impl Drop for Mode<'_> {
        fn drop(&mut self) {
            let _ = fs::set_permissions(self.0, fs::Permissions::from_mode(0o755));
        }
    }
    for (dir, first, expected) in [
        (
            "",
            "activations.jsonl",
            "activations.jsonl cannot be read: Permission denied",
        ),
        (
            "injection",
            "collected.json",
            "injection/collected.json cannot be read: Permission denied",
        ),
    ] {
        let scratch = copy();
        let at = scratch.0.join(dir);
        fs::set_permissions(&at, fs::Permissions::from_mode(0o444)).expect("the mode is set");
        let _mode = Mode(&at);
        if fs::symlink_metadata(at.join(first)).is_ok() {
            std::io::Write::write_all(
                &mut std::io::stderr(),
                b"skipped: this process reads an entry of a directory without search permission\n",
            )
            .expect("the notice writes");
            return;
        }
        match read_evidence(&scratch.0, FILE_LIMIT, &bounds()) {
            Err(ReadError::Refused(refusal)) => assert_eq!(*refusal.message(), expected),
            other => panic!("the copy is refused, not {other:?}"),
        }
    }
}

#[test]
fn an_empty_name_in_an_open_directory_is_no_directory() {
    let root = tree().join("scripts/gameday-fixtures/held");
    let what = Text::from("the name");
    let top = crate::gameday::open_dir(&root, None, &what).expect("the fixture opens");
    match crate::gameday::open_dir(Path::new(""), Some(std::os::fd::AsFd::as_fd(&top)), &what) {
        Err(ReadError::Refused(refusal)) => assert_eq!(
            *refusal.message(),
            "the name is no directory: No such file or directory"
        ),
        other => panic!("an empty name is refused, not {other:?}"),
    }
}

/// With no stop request the restoration's instance is compared with the package's target, and the
/// refusal names the stop request's instance.
#[test]
fn a_restoration_of_another_instance_than_the_target_is_refused_without_a_stop() {
    let ops = [
        Op::Remove("injection/stop.json"),
        Op::Remove("injection/stopped.json"),
        Op::Replace(
            "injection/restoration.json",
            "\"instance\": \"i-h1\"",
            "\"instance\": \"i-h2\"",
        ),
    ];
    assert_eq!(
        refusal(&ops, true),
        "injection/restoration.json names another instance than the stop request's"
    );
}

const STOP_OF_H2: Op = Op::Replace(
    "injection/stop.json",
    "\"instance\": \"i-h1\"",
    "\"instance\": \"i-h2\"",
);

const ABORT_AT_200: Op = Op::Write(
    "injection/abort.json",
    "{\"cause\": \"deadline\", \"guardrail\": null, \"time\": 200, \"detail\": null}\n",
);

fn restoration_at(time: &'static str) -> Op {
    Op::Replace("injection/restoration.json", "\"time\": 420,", time)
}

#[test]
fn each_order_rule_reads_each_mark_it_names() {
    let precedes = "injection/restoration.json precedes the stop request, the stopped report or the \
                    abort mark";
    let refused: [(&str, Vec<Op>, &str); 4] = [
        (
            "a restoration of the target after a stop of another instance",
            vec![STOP_OF_H2],
            "injection/restoration.json names another instance than the stop request's",
        ),
        (
            "a restoration before the stop with no stopped report",
            vec![
                Op::Remove("injection/stopped.json"),
                restoration_at("\"time\": 105,"),
            ],
            precedes,
        ),
        (
            "a reviewed restoration before the abort mark",
            vec![ABORT_AT_200, REVIEWED, restoration_at("\"time\": 150,")],
            precedes,
        ),
        (
            "an abort of cause guardrail with no guardrail",
            vec![
                Op::Write(
                    "injection/abort.json",
                    "{\"cause\": \"guardrail\", \"guardrail\": null, \"time\": 200, \"detail\": \
                     null}\n",
                ),
                REVIEWED,
            ],
            "injection/abort.json guardrail is not a GD-2 guardrail text with cause guardrail and \
             null otherwise",
        ),
    ];
    for (row, ops, expected) in refused {
        assert_eq!(refusal(&ops, true), expected, "{row}");
    }
    let loaded: [(&str, Vec<Op>); 4] = [
        (
            "a restoration of the stop's instance before a stopped report of another",
            vec![
                STOP_OF_H2,
                Op::Replace(
                    "injection/restoration.json",
                    "\"instance\": \"i-h1\"",
                    "\"instance\": \"i-h2\"",
                ),
                restoration_at("\"time\": 111,"),
            ],
        ),
        (
            "a reviewed restoration after the abort mark",
            vec![ABORT_AT_200, REVIEWED],
        ),
        (
            "a restoration before a stopped report at the run window's end",
            vec![
                Op::Replace("injection/stopped.json", "\"time\": 112,", "\"time\": 400,"),
                restoration_at("\"time\": 300,"),
            ],
        ),
        (
            "witness rows of equal stamps",
            vec![Op::Replace(
                "witness.jsonl",
                "\"time\": 141,",
                "\"time\": 140,",
            )],
        ),
    ];
    for (row, ops) in loaded {
        let outcome = load(&ops, true);
        assert!(outcome.is_ok(), "{row}: {outcome:?}");
    }
}

#[test]
fn ends_observation_is_false_before_the_run_and_at_its_end_plus_the_error() {
    let package = held("package.json");
    for (error, time) in [("0", "99"), ("1", "401")] {
        let p = object(&patched(&package, &[("clock_error_seconds", Some(error))])).clone();
        assert!(
            !ends_observation(&p, Some(&value(time))),
            "{time} with {error}"
        );
    }
    let error = crate::gameday::exact(&value("0.1")).expect("a number");
    assert_eq!(
        crate::gameday::later(&value("0.4"), &value("0.3"), &error),
        None
    );
}

#[test]
fn a_simulation_loads_without_the_file_of_an_observation_outside_its_world() {
    let ops = [
        Op::Replace(
            "package.json",
            "\"kind\": \"staging\"",
            "\"kind\": \"simulation\"",
        ),
        Op::Replace(
            "package.json",
            "\"outside\": {}",
            "\"outside\": {\"origin\": \"no origin in this world\"}",
        ),
        Op::Remove("origin.jsonl"),
        Op::Replace(
            "coverage.json",
            " \"origin.jsonl\": {\n  \"from\": 0,\n  \"to\": 400,\n  \"lines\": 27\n },\n",
            "",
        ),
    ];
    let evidence = load(&ops, true).expect("the simulation loads");
    assert_eq!(evidence.file("origin.jsonl"), None);
    assert_eq!(
        evidence.file("provider.jsonl"),
        Some(&held_lines("provider.jsonl"))
    );
}

#[test]
fn the_first_refusal_of_two_is_the_earlier_rule() {
    let stop_at_90 = Op::Replace("injection/stop.json", "\"time\": 110,", "\"time\": 90,");
    let outcome = load_within(&[Op::Fill("notes.txt", 2001)], false, 2000);
    match outcome {
        Err(ReadError::Refused(refusal)) => {
            assert_eq!(*refusal.message(), "notes.txt is no file of the layout");
        }
        other => panic!("an unlisted file past the limit is refused, not {other:?}"),
    }
    let rows: [(&str, Vec<Op>, bool, &str); 3] = [
        (
            "the seal before the order",
            vec![stop_at_90],
            false,
            "injection/stop.json differs from the bytes injection/collected.json seals: it holds \
             SHA-256 0995733600fe6cf376f597f15dcc9a8497c8174ad36ad8d0b59d6c0c89cfbd3f, the seal \
             4fd88bc07a91fc888696762333d98b38ded82da8bfcbe5eec181a135795eb236",
        ),
        (
            "a shard's order before the stop",
            vec![
                Op::Replace("records/s4.jsonl", "{\"time\": 180,", "{\"time\": 40,"),
                stop_at_90,
            ],
            true,
            "records/s4.jsonl is not in commit order",
        ),
        (
            "a record's schema before a mark's, in the layout's order",
            vec![
                Op::Replace(
                    "records/s1.jsonl",
                    "{\"time\": 125, \"owner\": \"h2\",",
                    "{\"time\": 125, \"owner\": \"h9\",",
                ),
                Op::Replace(
                    "injection/stopped.json",
                    "\"time\": 112,",
                    "\"time\": \"112\",",
                ),
            ],
            true,
            "records/s1.jsonl line 2 owner is no host of the layout: 'h9'",
        ),
    ];
    for (row, ops, sealed, expected) in rows {
        assert_eq!(refusal(&ops, sealed), expected, "{row}");
    }
    assert_eq!(
        refusal(
            &[Op::Replace(
                "injection/stopped.json",
                "\"time\": 112,",
                "\"time\": \"112\","
            )],
            true
        ),
        "injection/stopped.json time is no time of the layout: '112'"
    );
}

#[test]
fn a_sealed_file_whose_line_ends_change_is_of_other_bytes() {
    let ops = [Op::Replace(
        "origin.jsonl",
        "{\"time\": 2, \"key\": \"img/other-2\"}\n",
        "{\"time\": 2, \"key\": \"img/other-2\"}\r\n",
    )];
    assert_eq!(
        refusal(&ops, false),
        "origin.jsonl differs from the bytes injection/collected.json seals: it holds SHA-256 \
         b849a07e3537c283df0d1d18ffa024df41e27829b08e14330f0cc5b8a5f6a0fb, the seal \
         65443fad683c3daa9659ca7c0a6d830ed26027f9b8f5c0202b1d777e88e55a5c"
    );
}

#[test]
fn a_missing_package_a_package_of_another_type_and_a_root_of_no_directory_are_refused() {
    let rows: [(&[Op], &str); 2] = [
        (&[Op::Remove("package.json")], "package.json is missing"),
        (
            &[
                Op::Remove("package.json"),
                Op::Write("package.json", "[]\n"),
            ],
            "package.json is no object",
        ),
    ];
    for (ops, expected) in rows {
        assert_eq!(refusal(ops, false), expected, "{ops:?}");
    }
    let nul = std::ffi::OsStr::from_bytes(b"held\0copy");
    assert!(matches!(
        read_evidence(Path::new(nul), FILE_LIMIT, &bounds()),
        Err(ReadError::Nul)
    ));
    let file = tree().join("scripts/gameday-fixtures/held/package.json");
    match read_evidence(&file, FILE_LIMIT, &bounds()) {
        Err(ReadError::Refused(refusal)) => assert_eq!(
            refusal.message().to_string(),
            format!("{} is no directory: Not a directory", file.display())
        ),
        other => panic!("a file as the root is refused, not {other:?}"),
    }
    let open = fs::File::open(&file).expect("the package opens");
    for (prefix, expected) in [
        (
            "",
            "the evidence directory cannot be listed: Not a directory",
        ),
        ("x/", "x/ cannot be listed: Not a directory"),
    ] {
        let listed = crate::gameday::entries(open.as_fd(), &Text::from(prefix));
        assert_eq!(
            *listed.expect_err("a file lists no names").message(),
            expected
        );
    }
}

#[test]
fn a_root_that_names_a_link_is_refused_in_each_spelling() {
    let target = copy();
    let place = Scratch::new("gameday-link");
    let link = place.0.join("link");
    symlink(&target.0, &link).expect("the link is made");
    assert!(read_evidence(&target.0, FILE_LIMIT, &bounds()).is_ok());
    for suffix in ["", "/", "/.", "//.", "/./"] {
        let mut spelling = link.clone().into_os_string();
        spelling.push(suffix);
        match read_evidence(Path::new(&spelling), FILE_LIMIT, &bounds()) {
            Err(ReadError::Refused(refusal)) => assert_eq!(
                refusal.message().to_string(),
                format!(
                    "{} is no directory: Not a directory",
                    spelling.to_string_lossy()
                )
            ),
            other => panic!("{spelling:?} is refused, not {other:?}"),
        }
    }
}

#[test]
fn a_root_is_spelled_with_its_empty_and_dot_components_dropped() {
    for (root, expected) in [
        ("./x", "x"),
        ("//x", "//x"),
        ("///x", "/x"),
        ("a/../b", "a/../b"),
        (".", "."),
        ("./", "."),
        ("x/.", "x"),
        ("a//b/", "a/b"),
        ("x/./y", "x/y"),
        ("/", "/"),
        ("//", "//"),
        ("///", "/"),
        ("//./x", "//x"),
    ] {
        assert_eq!(
            super::spelled(Path::new(root)).as_os_str().as_bytes(),
            expected.as_bytes(),
            "{root}"
        );
    }
}

#[test]
fn each_file_is_read_through_the_directory_that_listed_it() {
    let place = Scratch::new("gameday-deep");
    let mut deep = place.0.clone();
    while deep.as_os_str().len() < 4080 - 201 {
        deep.push("d".repeat(200));
        fs::create_dir(&deep).expect("the directory is made");
    }
    let last = 4080 - deep.as_os_str().len() - 1;
    deep.push("e".repeat(last));
    let held = copy();
    fs::rename(&held.0, &deep).expect("the copy moves");
    assert_eq!(deep.as_os_str().len(), 4080);
    let evidence = read_evidence(&deep, FILE_LIMIT, &bounds());
    let evidence = evidence.expect("the deep copy loads");
    assert_eq!(
        evidence.seal_sha256(),
        "7979ade2516adcd9b854b9d5776bc492ecf487b60acfe02de21911b78bfc1e5c"
    );
    assert!(deep.join("injection/collected.json").as_os_str().len() > 4095);
}

/// Each copy keeps the held seal's digests, so `refusal` reports the name the seal leaves out or the
/// sealed name that no file holds.
#[test]
fn a_seal_that_leaves_out_a_collected_file_or_names_a_missing_mark_is_refused() {
    let rows: [(&[Op], &str); 3] = [
        (
            &[Op::Unseal("witness.jsonl")],
            "injection/collected.json seals no witness.jsonl",
        ),
        (
            &[Op::Unseal("coverage.json")],
            "injection/collected.json seals no coverage.json",
        ),
        (
            &[Op::Remove("injection/restoration.json")],
            "injection/collected.json seals injection/restoration.json, which is missing",
        ),
    ];
    for (ops, expected) in rows {
        assert_eq!(refusal(ops, false), expected, "{ops:?}");
    }
}

/// `reseal` updates each modified copy's digests so `refusal` reports the span of `origin.jsonl`, which
/// holds 27 lines under a seal dated 430.
#[test]
fn a_coverage_span_that_runs_backwards_miscounts_or_passes_the_seals_time_is_refused() {
    const SPAN: &str = "\"from\": 0,\n  \"to\": 400,\n  \"lines\": 27";
    let span = |changed| Op::Replace("coverage.json", SPAN, changed);
    let refused = [
        (
            span("\"from\": 0,\n  \"to\": 400,\n  \"lines\": 3"),
            "coverage.json spans origin.jsonl backwards or counts 3 lines, not its 27",
        ),
        (
            span("\"from\": 401,\n  \"to\": 400,\n  \"lines\": 27"),
            "coverage.json spans origin.jsonl backwards or counts 27 lines, not its 27",
        ),
        (
            span("\"from\": 0,\n  \"to\": 431,\n  \"lines\": 27"),
            "coverage.json spans origin.jsonl to 431, after the seal's time 430",
        ),
    ];
    for (op, expected) in refused {
        assert_eq!(refusal(&[op], true), expected, "{op:?}");
    }
    let loaded = [
        span("\"from\": 400,\n  \"to\": 400,\n  \"lines\": 27"),
        span("\"from\": 0,\n  \"to\": 430,\n  \"lines\": 27"),
    ];
    for op in loaded {
        let evidence = load(&[op], true);
        assert!(
            evidence.is_ok(),
            "a span of one instant, and one to the seal's time, load: {op:?} {evidence:?}"
        );
    }
}
