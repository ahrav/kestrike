//! A run's first step through its readers: the table of refusals, the committed fixtures, the values at
//! their bounds and the roles mark built from the snapshot.

use std::fs;

use kestrike_tools::gameday::{FILE_LIMIT, Refusal, check_package};
use kestrike_tools::host_stop::{
    ALARM_NAME_MAX, MAX_INSTANCES, Number, build_roles, check_run, encoded, gd2_of, read_bytes,
    read_operator, read_snapshot,
};
use kestrike_tools::json::{Object, Text, Value};
use kestrike_tools::python::hexdigest;

use crate::host_stop_support::step_one::{Change, ROWS, Reader, TEXTS};
use crate::host_stop_support::{
    START, Scratch, TARGET, bounds, gd2_mut, json, met, object, operator, package, rewrite, set,
    value,
};

/// The refusal the row's reader returns for its change, read in a scratch directory that holds the
/// operator file beside a copy of the snapshot.
fn read_row(change: Change, reader: Reader) -> Result<(), Refusal> {
    let scratch = Scratch::new("step-one");
    scratch.snapshot();
    let mut catalog = met();
    let (mut o, mut raw) = (operator(), package());
    let mut text = None;
    match change {
        Change::OperatorText(written) => text = Some(written()),
        Change::Operator(change) => change(&mut o),
        Change::Package(change) => {
            let mut p = value(std::str::from_utf8(&raw).expect("the package is UTF-8"));
            change(&mut p);
            raw = json(&p).into_bytes();
            set(
                &mut o,
                &["approval", "package_sha256"],
                Value::String(Text::from(hexdigest(&raw))),
            );
        }
        Change::PackageBytes(bytes) => raw = bytes.as_bytes().to_vec(),
        Change::Catalog(change) => change(gd2_mut(&mut catalog)),
        Change::PackagePastLimit(limit) => {
            raw.extend(std::iter::repeat_n(
                b' ',
                usize::try_from(limit).expect("a limit fits"),
            ));
            let path = scratch.write("package.json", &raw);
            return read_bytes(&path, &Text::from("the package"), limit).map(drop);
        }
        Change::Evidence(evidence) => unreachable!("the run decides the row {evidence:?}"),
    }
    assert_ne!(reader, Reader::Run, "a reader decides the row");
    let gd2 = gd2_of(&catalog)?;
    let path = scratch.write("operator.json", text.unwrap_or_else(|| json(&o)).as_bytes());
    let operator = read_operator(&path, gd2, FILE_LIMIT)?;
    check_run(&raw, &operator, START, &bounds()).map(drop)
}

/// Each row a reader decides is refused by that reader with the sentence the row records, which holds
/// the part of the line the self-test checks.
#[test]
fn each_refusal_of_step_1_a_reader_decides_is_the_readers_sentence() {
    let mut read = 0;
    for row in ROWS.iter().filter(|row| row.reader != Reader::Run) {
        let refusal = read_row(row.change, row.reader)
            .expect_err(row.name)
            .message()
            .clone();
        let sentence = row.sentence.expect("a reader's row records its sentence");
        assert_eq!(refusal, sentence, "{}", row.name);
        let line = format!("refused: {refusal}");
        assert!(line.contains(row.reason), "{}: {line}", row.name);
        read += 1;
    }
    assert_eq!(read, 41, "the rows the readers decide");
}

#[test]
fn the_committed_fixtures_say_they_are_synthetic() {
    let gd2 = met();
    let gd2 = gd2_of(&gd2).expect("the catalog's GD-2 is the one written for");
    let path = crate::host_stop_support::fixtures().join("operator.json");
    let o = read_operator(&path, gd2, FILE_LIMIT).expect("the fixture is admitted");
    assert!(
        o.approval()
            .approver()
            .to_string()
            .contains("synthetic fixture")
    );
}

/// Every bound a reader checks admits a value exactly at it: 100 instances, an alarm name of 255
/// characters, a run from the baseline's end to the run window's end, a snapshot read at either end of
/// its age, a cut at the baseline's start, the counters at the ends of their ranges, a file of exactly
/// the size limit and a mark of exactly the mark size limit. One past each size limit is refused.
#[test]
fn values_exactly_at_their_bounds_are_admitted() {
    let scratch = Scratch::new("bounds");
    let snapshot = scratch.snapshot();
    let catalog = met();
    let gd2 = gd2_of(&catalog).expect("GD-2 is the one written for");
    let mut o = operator();
    let ids: Vec<Value> = (0..MAX_INSTANCES)
        .map(|n| Value::String(Text::from(format!("i-{n:x}"))))
        .collect();
    set(&mut o, &["instances"], Value::Array(ids));
    let alarm = format!("gd2 guardrail {}", "a".repeat(ALARM_NAME_MAX - 14));
    set(
        &mut o,
        &["alarms", TEXTS[2]],
        Value::String(Text::from(alarm)),
    );
    let path = scratch.write("operator.json", json(&o).as_bytes());
    let read = read_operator(&path, gd2, FILE_LIMIT).expect("the bounds are admitted");
    let named = read
        .alarm(&Text::from(TEXTS[2]))
        .expect("the guardrail has its alarm");
    assert_eq!(
        (read.instances().len(), named.len()),
        (MAX_INSTANCES, ALARM_NAME_MAX)
    );

    let raw = package();
    let mut admitted = operator();
    set(&mut admitted, &["deadline_seconds"], value("300"));
    let absolute = Text::from(snapshot.to_str().expect("a UTF-8 path"));
    set(&mut admitted, &["snapshot"], Value::String(absolute));
    let path = scratch.write("admitted.json", json(&admitted).as_bytes());
    let admitted = read_operator(&path, gd2, FILE_LIMIT).expect("the operator file is admitted");
    assert_eq!(
        admitted.snapshot(),
        snapshot.as_path(),
        "an absolute snapshot path stands"
    );
    let run = check_run(&raw, &admitted, 100.0, &bounds())
        .expect("a start at the baseline's end with the deadline at the run window's end");
    assert_eq!(*run.instance(), TARGET);
    let (package, names) = (run.package(), run.names());
    for now in [100.0, 160.0] {
        let read = read_snapshot(&admitted, package, names, now, FILE_LIMIT)
            .expect("a snapshot read at its age bounds");
        assert_eq!(
            (read.cut().to_string(), read.oldest().to_string()),
            ("100".into(), "100".into())
        );
    }
    let mut opening = package.clone();
    opening.insert("baseline", value(r#"{"start": 100, "end": 100}"#));
    let read = read_snapshot(&admitted, &opening, names, 100.0, FILE_LIMIT)
        .expect("a cut at the baseline's start");
    assert_eq!(read.cut(), Number::from(100));

    rewrite(&snapshot.join("shards.jsonl"), |rows| {
        set(&mut rows[3], &["generation"], value("1"));
        set(&mut rows[3], &["attempts"], value("0"));
        set(
            &mut rows[4],
            &["generation"],
            value(&((1_u64 << 32) - 1).to_string()),
        );
        set(
            &mut rows[4],
            &["attempts"],
            value(&((1_u64 << 31) - 2).to_string()),
        );
    });
    let read = read_snapshot(&admitted, package, names, 100.0, FILE_LIMIT)
        .expect("the counters at the ends of their ranges");
    let counters: Vec<(Value, Value)> = ["s4", "s5"]
        .iter()
        .map(|shard| {
            let version = read.records().get(shard).expect("the shard's version");
            let Value::Object(version) = version else {
                panic!("a version is an object")
            };
            (
                version.get("generation").cloned().unwrap(),
                version.get("attempts").cloned().unwrap(),
            )
        })
        .collect();
    let limits = [
        (value("1"), value("0")),
        (value("4294967295"), value("2147483646")),
    ];
    assert_eq!(counters, limits);

    let limit = u64::try_from(raw.len()).expect("a length fits");
    let path = scratch.write("package.json", &raw);
    let what = Text::from("the package");
    assert_eq!(
        read_bytes(&path, &what, limit).expect("a file of the limit"),
        raw
    );
    let past = read_bytes(&path, &what, limit - 1).expect_err("a file past the limit");
    assert_eq!(
        *past.message(),
        format!("the package holds more than {} bytes", limit - 1).as_str()
    );

    let identity = "arn:aws:sts::account:assumed-role/gameday-operator/gd2-run";
    let mark = value(&format!(
        r#"{{"instance": "{TARGET}", "time": {START:?}, "identity": "{identity}"}}"#
    ));
    let what = Text::from("a mark");
    let data = encoded(&mark, &what, FILE_LIMIT).expect("a mark within the judge's size");
    let size = u64::try_from(data.len()).expect("a length fits");
    assert_eq!(
        encoded(&mark, &what, size).expect("a mark of the limit"),
        data
    );
    let past = encoded(&mark, &what, size - 1).expect_err("a mark past the limit");
    let words = format!(
        "a mark would hold {size} bytes, more than the judge reads ({})",
        size - 1
    );
    assert_eq!(*past.message(), words.as_str());
}

/// The roles mark built from the committed snapshot with no host lines and no statuses names no
/// standby; one whose version is off the judge's layout is refused as it is built.
#[test]
fn a_roles_mark_off_the_judges_layout_is_refused_when_it_is_built() {
    let Value::Object(package) = value(std::str::from_utf8(&package()).expect("UTF-8")) else {
        panic!("the package is an object")
    };
    let names = check_package(&package, &bounds()).expect("the held package is admitted");
    let lines =
        fs::read_to_string(crate::host_stop_support::fixtures().join("snapshot/shards.jsonl"))
            .expect("the shard lines read");
    let mut records = Object::new();
    for line in lines.lines() {
        let mut row = object(value(line));
        let shard = row.remove("shard").expect("a line names its shard");
        row.remove("time");
        let Value::String(shard) = shard else {
            panic!("a shard is a text")
        };
        records.insert(shard, Value::Object(row));
    }
    let digest = "30759c81708af91aa8ad1e953f902fb6001cb6465e84e2231726463af9292056";
    let none = std::collections::BTreeMap::<Text, kestrike_tools::host_stop::Status>::new();
    let reports = std::collections::BTreeMap::new();
    let cut = Number::from(100);
    let roles = build_roles(&package, &names, digest, &records, &reports, &none, cut)
        .expect("the committed records are on the layout");
    let Value::Object(roles) = roles else {
        panic!("the mark is an object")
    };
    assert_eq!(roles.get("standbys"), Some(&Value::Object(Object::new())));
    let mut wrong = Value::Object(records);
    set(&mut wrong, &["s1", "generation"], value("-1"));
    let Value::Object(records) = wrong else {
        unreachable!("an object stays one")
    };
    let refusal = build_roles(&package, &names, digest, &records, &reports, &none, cut)
        .expect_err("a generation of -1 is off the layout");
    let sentence = "injection/roles.json shards s1 generation is no generation of the layout: -1";
    assert_eq!(*refusal.message(), sentence);
}

/// A relative operator path is made absolute against the working directory, which a case runs in at
/// the package's directory, and normalized, so the snapshot stands beside the committed operator file.
#[test]
fn a_relative_operator_path_names_the_snapshot_beside_it() {
    let catalog = met();
    let gd2 = gd2_of(&catalog).expect("GD-2 is the one written for");
    let relative = std::path::Path::new("../../scripts/./host-stop-fixtures//operator.json");
    let o = read_operator(relative, gd2, FILE_LIMIT).expect("the fixture is admitted");
    let beside = crate::host_stop_support::fixtures().join("snapshot");
    assert_eq!(o.snapshot(), beside.as_path());
}
