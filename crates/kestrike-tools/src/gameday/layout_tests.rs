//! Each expected result is the judge's own function's at the base under Python 3.9.25, as the expression
//! beside it gives it: its `conform` over the held fixture's files with the names its `load_evidence`
//! builds, and its `LAYOUT` flags.

use std::collections::BTreeSet;

use super::{LAYOUT, VERSION_FIELDS, layout};
use crate::gameday::constants::FILE_LIMIT;
use crate::gameday::schema::{Each, Names, Scalar, Schema};
use crate::gameday::test_support::{held, object, patched, tree};
use crate::gameday::{FleetBounds, check_package, conform, parsed};
use crate::json::Value;
use crate::text::Text;

/// `{"time": "time", **VERSION}`, the schema of a line of `records/<shard>.jsonl`.
const RECORD: Schema = Schema::Object(&[
    ("time", Schema::scalar(Scalar::Time)),
    VERSION_FIELDS[0],
    VERSION_FIELDS[1],
    VERSION_FIELDS[2],
    VERSION_FIELDS[3],
    VERSION_FIELDS[4],
]);

/// The held package's names with `observed` and `sealed` as the judge's `load_evidence` sets them.
fn held_names() -> Names {
    let bounds = FleetBounds::new(&tree(), FILE_LIMIT).expect("the top holds no NUL");
    let mut names =
        check_package(object(&held("package.json")), &bounds).expect("the held package passes");
    let set = |items: &[&str]| {
        items
            .iter()
            .map(|item| Text::from(*item))
            .collect::<BTreeSet<_>>()
    };
    let observed = [
        "activations.jsonl",
        "blockers.jsonl",
        "origin.jsonl",
        "provider.jsonl",
        "records/receipts.jsonl",
        "records/s1.jsonl",
        "records/s2.jsonl",
        "records/s3.jsonl",
        "records/s4.jsonl",
        "records/s5.jsonl",
        "witness.jsonl",
    ];
    let marks = [
        "coverage.json",
        "injection/abort.json",
        "injection/restoration.json",
        "injection/roles.json",
        "injection/stop.json",
        "injection/stopped.json",
    ];
    names.insert("observed", set(&observed));
    names.insert("sealed", set(&[&observed[..], &marks[..]].concat()));
    names
}

fn file(rel: &str) -> Option<Value> {
    let data = std::fs::read(tree().join("scripts/gameday-fixtures/held").join(rel)).ok()?;
    Some(parsed(&data, &Text::from(rel)).expect("the held file is strict JSON"))
}

#[test]
fn every_file_of_the_held_fixture_conforms_to_its_schema() {
    let names = held_names();
    let records = (1..=5).map(|at| (format!("records/s{at}.jsonl"), &RECORD));
    let files = records.chain(
        LAYOUT
            .iter()
            .map(|(rel, schema, _)| ((*rel).to_owned(), schema)),
    );
    let mut read = 0;
    for (rel, schema) in files {
        let Some(value) = file(&rel) else {
            assert_eq!(
                rel, "injection/abort.json",
                "the held fixture holds every file but the abort mark"
            );
            continue;
        };
        let lines = match value {
            Value::Array(lines) if rel.ends_with(".jsonl") => lines,
            value => vec![value],
        };
        for line in &lines {
            let found = conform(line, schema, &Text::from(rel.as_str()), &names);
            assert_eq!(found, Ok(()), "conform of {rel} under the judge's names");
        }
        read += 1;
    }
    assert_eq!(read, 17, "five records, twelve files of the layout");
}

#[test]
fn each_file_of_the_layout_is_optional_as_the_judge_states() {
    #[rustfmt::skip]
    let judged = [
        ("injection/roles.json", false), ("injection/stop.json", true), ("injection/stopped.json", true),
        ("injection/abort.json", true), ("injection/restoration.json", true), ("injection/collected.json", false),
        ("records/receipts.jsonl", false), ("activations.jsonl", false), ("witness.jsonl", false),
        ("origin.jsonl", false), ("provider.jsonl", false), ("blockers.jsonl", false), ("coverage.json", false),
    ];
    let ours: Vec<(&str, bool)> = LAYOUT
        .iter()
        .map(|(rel, _, optional)| (*rel, *optional))
        .collect();
    assert_eq!(
        ours, judged,
        "[(rel, optional) for rel, (_, optional) in gj.LAYOUT.items()]"
    );
    assert!(layout("package.json").is_none());
}

/// A 64-digit digest as JSON.
const DIGEST: &str = r#""aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa""#;

/// Type aliases keep the rows' columns readable: a file, its changes, and the judge's result.
type Row = (
    &'static str,
    &'static [(&'static str, Option<&'static str>)],
    Result<(), &'static str>,
);

#[test]
fn the_marks_refuse_each_changed_copy_with_the_judges_sentence() {
    let names = held_names();
    #[rustfmt::skip]
    let rows: &[Row] = &[
        ("injection/stop.json", &[("identity", None)], Err("injection/stop.json holds the keys ['instance', 'time'], not ['identity', 'instance', 'time']")),
        ("injection/stopped.json", &[("request/time", Some(r#""x""#))], Err("injection/stopped.json request time is no time of the layout: 'x'")),
        ("injection/stopped.json", &[("request", Some("1"))], Err("injection/stopped.json request is no object")),
        ("injection/restoration.json", &[("reviewed_sha256", Some(r#""x""#))], Err("injection/restoration.json reviewed_sha256 is no digest of the layout: 'x'")),
        ("injection/restoration.json", &[("reviewed_sha256", Some(DIGEST))], Ok(())),
        ("injection/collected.json", &[("files/x", Some(DIGEST))], Err("injection/collected.json files names ['activations.jsonl', 'blockers.jsonl', 'coverage.json', 'injection/restoration.json', 'injection/roles.json', 'injection/stop.json', 'injection/stopped.json', 'origin.jsonl', 'provider.jsonl', 'records/receipts.jsonl', 'records/s1.jsonl', 'records/s2.jsonl', 'records/s3.jsonl', 'records/s4.jsonl', 'records/s5.jsonl', 'witness.jsonl', 'x'], not only the sealeds ['activations.jsonl', 'blockers.jsonl', 'coverage.json', 'injection/abort.json', 'injection/restoration.json', 'injection/roles.json', 'injection/stop.json', 'injection/stopped.json', 'origin.jsonl', 'provider.jsonl', 'records/receipts.jsonl', 'records/s1.jsonl', 'records/s2.jsonl', 'records/s3.jsonl', 'records/s4.jsonl', 'records/s5.jsonl', 'witness.jsonl']")),
    ];
    for &(rel, patches, expected) in rows {
        let changed = patched(&file(rel).expect("a held mark"), patches);
        let (schema, _) = layout(rel).expect("a file of the layout");
        let found = conform(&changed, schema, &Text::from(rel), &names)
            .map_err(|refusal| refusal.to_string());
        assert_eq!(
            found,
            expected.map_err(str::to_owned),
            "conform of {rel} changed at {patches:?}"
        );
    }
}

/// The kinds a later caller supplies are the judge's: each object schema names each key once, each
/// one-of holds an object, and each kind a schema reads is one the judge builds.
#[test]
fn every_schema_has_distinct_keys_and_reads_only_the_judges_kinds() {
    fn walk(schema: &Schema, kinds: &mut BTreeSet<&'static str>) {
        let fields = |fields: &[(&'static str, Schema)], kinds: &mut BTreeSet<&'static str>| {
            let keys: BTreeSet<&str> = fields.iter().map(|(key, _)| *key).collect();
            assert_eq!(keys.len(), fields.len(), "an object schema repeats no key");
            for (_, field) in fields {
                walk(field, kinds);
            }
        };
        match *schema {
            Schema::Scalar(Scalar::Host, _) => drop(kinds.insert("host")),
            Schema::Scalar(Scalar::Shard, _) => drop(kinds.insert("shard")),
            Schema::Scalar(Scalar::Key, _) => drop(kinds.insert("key")),
            Schema::Scalar(..) | Schema::Member(_) => {}
            Schema::Object(object) => fields(object, kinds),
            Schema::OneOf(options) => {
                assert!(!options.is_empty(), "a one-of holds an object");
                for option in options {
                    fields(option, kinds);
                }
            }
            Schema::List(item) => walk(item, kinds),
            Schema::Each(Each { keys, value, .. }) => {
                kinds.insert(keys);
                walk(value, kinds);
            }
        }
    }
    let mut kinds = BTreeSet::new();
    walk(&crate::gameday::layout::PACKAGE_SCHEMA, &mut kinds);
    for (_, schema, _) in &LAYOUT {
        walk(schema, &mut kinds);
    }
    let judged: BTreeSet<&str> = [
        "budget",
        "host",
        "key",
        "observation",
        "observed",
        "sealed",
        "shard",
    ]
    .into();
    assert_eq!(kinds, judged);
}
