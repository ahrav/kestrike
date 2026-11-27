//! A run's first step through its readers: the table of refusals, the committed fixtures, the values at
//! their bounds and the roles mark built from the snapshot.

use std::fs;

use kestrike_tools::gameday::{FILE_LIMIT, Refusal, check_package};
use kestrike_tools::host_stop::{
    ALARM_NAME_MAX, MAX_INSTANCES, Number, build_roles, check_run, encoded, gd2_of, read_bytes,
    read_operator, read_snapshot, read_statuses,
};
use kestrike_tools::json::{Object, Text, Value};
use kestrike_tools::python::hexdigest;

use crate::host_stop_support::step_one::{Change, ROWS, Reader, TEXTS};
use crate::host_stop_support::{
    START, Scratch, TARGET, bounds, gd2_mut, json, met, object, operator, package, past_limit,
    rewrite, set, value,
};

/// The outcome of the readers of a run's first step for a row's change: GD-2's entry, the operator
/// file and the package's check, or the package's read past the limit, read in a scratch directory
/// that holds the operator file beside a copy of the snapshot.
fn read_row(change: Change) -> Result<(), Refusal> {
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
        Change::PackagePastLimit => {
            let limit = past_limit();
            raw.extend(std::iter::repeat_n(
                b' ',
                usize::try_from(limit).expect("a limit fits"),
            ));
            let path = scratch.write("package.json", &raw);
            return read_bytes(&path, &Text::from("the package"), limit).map(drop);
        }
        Change::Evidence(evidence) => unreachable!("the run decides the row {evidence:?}"),
    }
    let gd2 = gd2_of(&catalog)?;
    let path = scratch.write("operator.json", text.unwrap_or_else(|| json(&o)).as_bytes());
    let operator = read_operator(&path, &gd2, FILE_LIMIT)?;
    check_run(&raw, &operator, Number::from(START), &bounds()).map(drop)
}

/// Each row a reader decides is refused by that reader with the sentence the row records, which holds
/// the part of the line the self-test checks; each catalog row the run decides passes the readers, so
/// they refuse nothing more than the script's readers do.
#[test]
fn each_refusal_of_step_1_a_reader_decides_is_the_readers_sentence() {
    assert_eq!(ROWS.len(), 48, "the self-test's rows");
    let mut read = 0;
    for row in ROWS.iter().filter(|row| row.reader != Reader::Run) {
        let refusal = read_row(row.change).expect_err(row.name).message().clone();
        let past = format!("the package holds more than {} bytes", past_limit());
        let sentence = row.sentence.unwrap_or(&past);
        assert_eq!(refusal, sentence, "{}", row.name);
        let line = format!("refused: {refusal}");
        assert!(line.contains(row.reason), "{}: {line}", row.name);
        read += 1;
    }
    assert_eq!(read, 41, "the rows the readers decide");
    let mut passed = 0;
    for row in ROWS.iter().filter(|row| row.reader == Reader::Run) {
        if let Change::Catalog(_) = row.change {
            read_row(row.change).unwrap_or_else(|refusal| panic!("{}: {refusal}", row.name));
            passed += 1;
        }
    }
    assert_eq!(passed, 3, "the prerequisite rows");
}

/// The fixture operator file as the controller's read returned it, its snapshot path standing for the
/// fixture's own directory.
const FIXTURE_OPERATOR: &str = r#"{"region":"us-west-2","identity":"arn:aws:sts::account:assumed-role/gameday-operator/gd2-run","approval":{"approver":"synthetic fixture of scripts/test-host-stop-controller.py: no owner approved a run","package_sha256":"30759c81708af91aa8ad1e953f902fb6001cb6465e84e2231726463af9292056","instance":"i-h1","not_after":"1970-01-01T01:00:00Z"},"instances":["i-h1","i-h2","i-h3","i-h4"],"snapshot":"SNAPSHOT","snapshot_max_age_seconds":60,"alarms":{"any generation change":"gd2-guardrail-1","any CreateVolume by the reconciler principal":"gd2-guardrail-2","any replacement receipt written by the reconciler principal":"gd2-guardrail-3","a takeover of a shard with no role on the stopped host":"gd2-guardrail-4","a shard that changes hands twice":"gd2-guardrail-5","the zone's origin request rate above its baseline past the origin-load budget":"gd2-guardrail-6","a shard without a standby or a named blocker past the re-enrollment drain":"gd2-guardrail-7","two hosts activating one tenure of a shard":"gd2-guardrail-8"},"effect_timeout_seconds":60,"observe_seconds":45,"deadline_seconds":290}"#;

/// The committed operator file says it is a synthetic fixture, and it reads as the controller's read
/// returned it: every field, each bound of its kind, and the snapshot beside the file. The held package
/// is admitted at the run's start with its digest, its target and the names the package check gives.
#[test]
fn the_committed_fixtures_say_they_are_synthetic() {
    let catalog = met();
    let gd2 = gd2_of(&catalog).expect("the catalog's GD-2 is the one written for");
    let path = crate::host_stop_support::fixtures().join("operator.json");
    let o = read_operator(&path, &gd2, FILE_LIMIT).expect("the fixture is admitted");
    assert!(
        o.approval()
            .approver()
            .to_string()
            .contains("synthetic fixture")
    );
    let mut read = Object::new();
    let text = |text: &Text| Value::String(text.clone());
    read.insert("region", text(o.region()));
    read.insert("identity", text(o.identity()));
    let approval = o.approval();
    let fields = [
        ("approver", approval.approver()),
        ("package_sha256", approval.package_sha256()),
        ("instance", approval.instance()),
        ("not_after", approval.not_after()),
    ];
    let mut approved = Object::new();
    for (key, value) in fields {
        approved.insert(key, text(value));
    }
    read.insert("approval", Value::Object(approved));
    read.insert(
        "instances",
        Value::Array(o.instances().iter().map(text).collect()),
    );
    let beside = crate::host_stop_support::fixtures().join("snapshot");
    assert_eq!(o.snapshot(), beside.as_path());
    read.insert("snapshot", value(r#""SNAPSHOT""#));
    read.insert(
        "snapshot_max_age_seconds",
        o.snapshot_max_age_seconds().value(),
    );
    let mut alarms = Object::new();
    for (guardrail, alarm) in o.alarms() {
        alarms.insert(guardrail.clone(), text(alarm));
    }
    read.insert("alarms", Value::Object(alarms));
    read.insert("effect_timeout_seconds", o.effect_timeout_seconds().value());
    read.insert("observe_seconds", o.observe_seconds().value());
    read.insert("deadline_seconds", o.deadline_seconds().value());
    assert_eq!(json(&Value::Object(read)), FIXTURE_OPERATOR);

    let raw = package();
    let run =
        check_run(&raw, &o, Number::from(START), &bounds()).expect("the held package is admitted");
    let digest = "30759c81708af91aa8ad1e953f902fb6001cb6465e84e2231726463af9292056";
    assert_eq!(
        (run.package_sha256(), run.instance().to_string()),
        (digest, TARGET.to_owned())
    );
    let names = check_package(run.package(), &bounds()).expect("the package check admits it");
    assert_eq!(*run.names(), names);
}

/// Every bound a reader checks admits a value exactly at it: 100 instances, an alarm name of 255
/// characters, a run from the baseline's end to the run window's end, a snapshot read at either end of
/// its age, a cut at the baseline's start, the counters at the ends of their ranges, a file of exactly
/// the size limit and a mark of exactly the mark size limit. One past each size limit is refused, and a
/// path with a NUL byte is refused with the library's words for it.
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
    let read = read_operator(&path, &gd2, FILE_LIMIT).expect("the bounds are admitted");
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
    let admitted = read_operator(&path, &gd2, FILE_LIMIT).expect("the operator file is admitted");
    assert_eq!(
        admitted.snapshot(),
        snapshot.as_path(),
        "an absolute snapshot path stands"
    );
    let run = check_run(&raw, &admitted, Number::from(100), &bounds())
        .expect("a start at the baseline's end with the deadline at the run window's end");
    assert_eq!(*run.instance(), TARGET);
    let (package, names) = (run.package(), run.names());
    for now in [100, 160].map(Number::from) {
        let read = read_snapshot(&admitted, package, names, now, FILE_LIMIT)
            .expect("a snapshot read at its age bounds");
        assert_eq!(
            (read.cut().to_string(), read.oldest().to_string()),
            ("100".into(), "100".into())
        );
    }
    let mut opening = package.clone();
    opening.insert("baseline", value(r#"{"start": 100, "end": 100}"#));
    let read = read_snapshot(&admitted, &opening, names, Number::from(100), FILE_LIMIT)
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
    let read = read_snapshot(&admitted, package, names, Number::from(100), FILE_LIMIT)
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
    let nul = read_bytes(
        std::path::Path::new("a\0b"),
        &Text::from("the package"),
        FILE_LIMIT,
    )
    .expect_err("a path with a NUL byte");
    let words =
        "the package has a path no file can have: file name contained an unexpected NUL byte";
    assert_eq!(*nul.message(), words);
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
    let none = std::collections::BTreeMap::new();
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
    let o = read_operator(relative, &gd2, FILE_LIMIT).expect("the fixture is admitted");
    let beside = crate::host_stop_support::fixtures().join("snapshot");
    assert_eq!(o.snapshot(), beside.as_path());
}

/// The operator file's names at their edges, each through the readers with the outcome the
/// controller's read gave: an instance ID of 17 characters after `i-` is admitted and one of 18, none
/// or a capital is refused; an approval instance is an ID; an alarm name with outer white space as
/// Python's `str.strip` removes it is refused; a DEL is a control character; and an alarm name's length
/// counts code points.
#[test]
fn values_exactly_at_their_bounds_are_admitted_and_one_past_each_is_refused() {
    let alarm = "the alarm of 'any replacement receipt written by the reconciler principal'";
    let long = "é".repeat(256);
    let rows: [(&str, &[&str], String, Option<String>); 11] = [
        (
            "17 characters",
            &["instances"],
            format!(r#"["i-h1", "i-{}"]"#, "a".repeat(17)),
            None,
        ),
        (
            "18 characters",
            &["instances"],
            format!(r#"["i-h1", "i-{}"]"#, "a".repeat(18)),
            Some(format!(
                "instances[1] is no instance ID: 'i-{}'",
                "a".repeat(18)
            )),
        ),
        (
            "no characters",
            &["instances"],
            r#"["i-h1", "i-"]"#.into(),
            Some("instances[1] is no instance ID: 'i-'".into()),
        ),
        (
            "a capital",
            &["instances"],
            r#"["i-h1", "i-H1"]"#.into(),
            Some("instances[1] is no instance ID: 'i-H1'".into()),
        ),
        (
            "an approval instance",
            &["approval", "instance"],
            r#""--x""#.into(),
            Some("approval instance is no instance ID: '--x'".into()),
        ),
        (
            "a leading space",
            &["alarms", TEXTS[2]],
            r#"" gd2-x""#.into(),
            Some(format!("{alarm} is no alarm name: ' gd2-x'")),
        ),
        (
            "an ideographic space",
            &["alarms", TEXTS[2]],
            r#""gd2-x\u3000""#.into(),
            Some(format!("{alarm} is no alarm name: 'gd2-x\\u3000'")),
        ),
        (
            "a unit separator",
            &["alarms", TEXTS[2]],
            r#""gd2-x\u001f""#.into(),
            Some(format!("{alarm} is no alarm name: 'gd2-x\\x1f'")),
        ),
        (
            "a delete",
            &["alarms", TEXTS[2]],
            r#""gd2\u007fx""#.into(),
            Some(format!(
                "{alarm} holds a control character or text with no UTF-8 form: 'gd2\\x7fx'"
            )),
        ),
        (
            "255 non-ASCII characters",
            &["alarms", TEXTS[2]],
            format!(r#""{}""#, "é".repeat(255)),
            None,
        ),
        (
            "256 non-ASCII characters",
            &["alarms", TEXTS[2]],
            format!(r#""{long}""#),
            Some(format!("{alarm} is no alarm name: '{long}'")),
        ),
    ];
    let catalog = met();
    let gd2 = gd2_of(&catalog).expect("GD-2 is the one written for");
    for (name, path, new, expected) in rows {
        let scratch = Scratch::new("edges");
        let mut o = operator();
        set(&mut o, path, value(&new));
        let file = scratch.write("operator.json", json(&o).as_bytes());
        let found = read_operator(&file, &gd2, FILE_LIMIT)
            .and_then(|o| check_run(&package(), &o, Number::from(START), &bounds()));
        match (found, expected) {
            (Ok(run), None) => assert_eq!(*run.instance(), TARGET, "{name}"),
            (Err(refusal), Some(expected)) => {
                assert_eq!(*refusal.message(), expected.as_str(), "{name}")
            }
            (found, expected) => panic!(
                "{name}: {:?} against {expected:?}",
                found.map(|run| run.instance().clone())
            ),
        }
    }
}

/// The roles mark names each standby of a shard the target owns whose instance the statuses hold,
/// with that status's state and its host's report word, `no report` for a null report; a standby whose
/// instance the statuses lack is left out. The values are the controller's for the same snapshot.
#[test]
fn too_few_roles_or_an_unhealthy_or_unread_standby_aborts_on_reach_with_no_stop() {
    let scratch = Scratch::new("standbys");
    let snapshot = scratch.snapshot();
    rewrite(&snapshot.join("hosts.jsonl"), |rows| {
        set(&mut rows[1], &["report"], Value::Null)
    });
    let catalog = met();
    let gd2 = gd2_of(&catalog).expect("GD-2 is the one written for");
    let path = scratch.write("operator.json", json(&operator()).as_bytes());
    let o = read_operator(&path, &gd2, FILE_LIMIT).expect("the fixture is admitted");
    let run = check_run(&package(), &o, Number::from(START), &bounds()).expect("admitted");
    let read = read_snapshot(
        &o,
        run.package(),
        run.names(),
        Number::from(START + 0.2),
        FILE_LIMIT,
    )
    .expect("the snapshot is admitted");
    let reply = object(value(
        r#"{"InstanceStatuses": [{"InstanceId": "i-h2", "InstanceState": {"Name": "running"}},
            {"InstanceId": "i-h3", "InstanceState": {"Name": "stopping"}}]}"#,
    ));
    let asked = [Text::from("i-h2"), Text::from("i-h3")];
    let mut states = read_statuses(&reply, &asked).expect("the statuses read");
    let rows = [
        r#"{"h2":{"instance":"i-h2","instance_state":"running","host_report":"no report"},"h3":{"instance":"i-h3","instance_state":"stopping","host_report":"healthy"}}"#,
        r#"{"h3":{"instance":"i-h3","instance_state":"stopping","host_report":"healthy"}}"#,
    ];
    for expected in rows {
        let roles = build_roles(
            run.package(),
            run.names(),
            &"0".repeat(64),
            read.records(),
            read.reports(),
            &states,
            read.cut(),
        )
        .expect("the mark is on the layout");
        let Value::Object(roles) = roles else {
            panic!("the mark is an object")
        };
        assert_eq!(json(roles.get("standbys").expect("standbys")), expected);
        states.remove(&Text::from("i-h2"));
    }
}
