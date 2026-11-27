//! `read_evidence` loads the held fixture with its digests and indices.

use std::fs;
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
}

const REVIEWED: Op = Op::Replace(
    "injection/restoration.json",
    "\"reviewed_sha256\": null",
    "\"reviewed_sha256\": \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
);

fn bounds() -> FleetBounds {
    FleetBounds::new(&tree(), FILE_LIMIT).expect("the top holds no NUL")
}

fn copy() -> Scratch {
    let scratch = Scratch::new("gameday-evidence");
    let from = tree().join("scripts/gameday-fixtures/held");
    for dir in ["", "injection", "records"] {
        fs::create_dir_all(scratch.0.join(dir)).expect("the directory is made");
        for entry in fs::read_dir(from.join(dir)).expect("the fixture lists") {
            let entry = entry.expect("the fixture lists");
            if entry.file_type().expect("the type reads").is_file() {
                let to = scratch.0.join(dir).join(entry.file_name());
                fs::copy(entry.path(), to).expect("the file copies");
            }
        }
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
    let mut names = Vec::new();
    for dir in ["", "injection", "records"] {
        for entry in fs::read_dir(root.join(dir)).expect("the copy lists") {
            let entry = entry.expect("the copy lists");
            let name = Path::new(dir).join(entry.file_name());
            let name = name.to_str().expect("a fixture name is UTF-8").to_owned();
            let kind = entry.file_type().expect("the type reads");
            if kind.is_file() && name != "package.json" && name != rel {
                names.push(name);
            }
        }
    }
    names.sort();
    let mut files = Object::new();
    for name in names {
        let digest = hexdigest(&fs::read(root.join(&name)).expect("the file reads"));
        files.insert(name, Value::String(Text::from(digest)));
    }
    let text = fs::read_to_string(root.join(rel)).expect("the seal reads");
    let mut seal = object(&value(&text)).clone();
    seal.insert("files", Value::Object(files));
    fs::write(root.join(rel), dump(&Value::Object(seal))).expect("the seal writes");
}

fn load(ops: &[Op], sealed: bool) -> Result<Evidence, ReadError> {
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
    read_evidence(&scratch.0, FILE_LIMIT, &bounds())
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
    for dir in ["", "injection", "records"] {
        for entry in fs::read_dir(root.join(dir)).expect("the fixture lists") {
            let entry = entry.expect("the fixture lists");
            if entry.file_type().expect("the type reads").is_file() {
                let name = Path::new(dir).join(entry.file_name());
                let name = Text::from(name.to_str().expect("a fixture name is UTF-8"));
                files.insert(name, fs::read(entry.path()).expect("the file reads"));
            }
        }
    }
    let loaded = load_evidence(&files, &bounds()).expect("the held bytes load");
    assert_eq!(
        loaded.seal_sha256(),
        "7979ade2516adcd9b854b9d5776bc492ecf487b60acfe02de21911b78bfc1e5c"
    );
    files.remove(&Text::from("injection/collected.json"));
    let refused = load_evidence(&files, &bounds()).expect_err("a load without the seal");
    assert_eq!(*refused.message(), "injection/collected.json is missing");
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
            eprintln!(
                "skipped: this process reads an entry of a directory without search permission"
            );
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
