//! The snapshot through `read_snapshot`, read at the caller check's return (the run's start and one
//! call of 0.2 s): each state of a shard line and of a host line, each refused with the row's
//! sentence, and the values an admitted snapshot returns.

use std::fs;
use std::os::unix::fs::symlink;

use kestrike_tools::gameday::{FILE_LIMIT, Refusal};
use kestrike_tools::host_stop::{
    Number, Snapshot, check_run, gd2_of, read_operator, read_snapshot,
};
use kestrike_tools::json::Value;

use crate::host_stop_support::{
    START, Scratch, at_mut, bounded, bounds, items_mut, json, met, operator, package, rewrite, set,
    value,
};

/// The wall time of the read: the caller's call returns 0.2 s after the run's start.
const NOW: f64 = START + 0.2;

type Lines = fn(&mut Vec<Value>);

/// Reads the committed snapshot with `change` applied to the lines of `file`, for the held package
/// or the package `change_package` makes of it.
fn read(file: &str, change: Lines, change_package: fn(&mut Value)) -> Result<Snapshot, Refusal> {
    let scratch = Scratch::new("snapshot");
    let snapshot = scratch.snapshot();
    rewrite(&snapshot.join(file), change);
    read_at(&scratch, change_package)
}

fn read_at(scratch: &Scratch, change_package: fn(&mut Value)) -> Result<Snapshot, Refusal> {
    let catalog = met();
    let gd2 = gd2_of(&catalog).expect("GD-2 is the one written for");
    let path = scratch.write("operator.json", json(&operator()).as_bytes());
    let o = read_operator(&path, &gd2, FILE_LIMIT).expect("the fixture operator file is admitted");
    let run = check_run(&package(), &o, Number::from(START), &bounds())
        .expect("the held package is admitted");
    let mut p = Value::Object(run.package().clone());
    change_package(&mut p);
    let Value::Object(p) = p else {
        unreachable!("an object stays one")
    };
    read_snapshot(&o, &p, run.names(), Number::from(NOW), FILE_LIMIT)
}

fn held(_: &mut Value) {}

fn each(rows: &mut [Value], key: &str, new: &str) {
    for row in rows {
        set(row, &[key], value(new));
    }
}

/// Each row: its name, the file it changes, the change and the sentence of the refusal.
const REFUSED: &[(&str, &str, Lines, &str)] = &[
    (
        "a stale shard record",
        "shards.jsonl",
        |rows| each(rows, "time", "43.0"),
        "shards.jsonl line 1 time 43.0 lies outside [44.2, 104.2]: the snapshot is stale or ahead",
    ),
    (
        "a host report ahead of the clock",
        "hosts.jsonl",
        |rows| set(&mut rows[1], &["report", "time"], value("105.0")),
        "hosts.jsonl line 2 report time 105.0 lies outside [44.2, 104.2]: the snapshot is stale or ahead",
    ),
    (
        "shard lines read at two times",
        "shards.jsonl",
        |rows| set(&mut rows[4], &["time"], value("101")),
        "shards.jsonl holds read times [100, 101], not one cut",
    ),
    (
        "a missing shard",
        "shards.jsonl",
        |rows| drop(rows.pop()),
        "shards.jsonl misses shards ['s5']",
    ),
    (
        "a missing shard and shard lines read at two times",
        "shards.jsonl",
        |rows| {
            rows.pop();
            set(&mut rows[0], &["time"], value("101"));
        },
        "shards.jsonl misses shards ['s5']",
    ),
    (
        "a repeated shard",
        "shards.jsonl",
        |rows| rows.push(rows[0].clone()),
        "shards.jsonl line 6 repeats shard s1",
    ),
    (
        "an owner outside the package",
        "shards.jsonl",
        |rows| set(&mut rows[3], &["owner"], value(r#""h9""#)),
        "shards.jsonl line 4 owner is no host of the layout: 'h9'",
    ),
    (
        "an extra key",
        "shards.jsonl",
        |rows| set(&mut rows[0], &["note"], value(r#""x""#)),
        "shards.jsonl line 1 holds the keys ['attempts', 'generation', 'note', 'owner', 'shard', 'standby', \
      'time', 'volume'], not ['attempts', 'generation', 'owner', 'shard', 'standby', 'time', 'volume']",
    ),
    (
        "a generation of 0",
        "shards.jsonl",
        |rows| set(&mut rows[4], &["generation"], value("0")),
        "shards.jsonl line 5 generation is no generation of the layout: 0",
    ),
    (
        "a generation of 2^32",
        "shards.jsonl",
        |rows| set(&mut rows[4], &["generation"], value("4294967296")),
        "shards.jsonl line 5 generation is no generation of the layout: 4294967296",
    ),
    (
        "attempts below 0",
        "shards.jsonl",
        |rows| set(&mut rows[4], &["attempts"], value("-1")),
        "shards.jsonl line 5 attempts is no attempts of the layout: -1",
    ),
    (
        "attempts past the judge's ATTEMPTS_MAX",
        "shards.jsonl",
        |rows| set(&mut rows[4], &["attempts"], value("2147483647")),
        "shards.jsonl line 5 attempts is no attempts of the layout: 2147483647",
    ),
    (
        "an extra key in a host line",
        "hosts.jsonl",
        |rows| set(&mut rows[1], &["note"], value(r#""x""#)),
        "hosts.jsonl line 2 holds other keys than host, instance and report",
    ),
    (
        "a health that is no boolean",
        "hosts.jsonl",
        |rows| set(&mut rows[1], &["report", "healthy"], value(r#""yes""#)),
        "hosts.jsonl line 2 report is neither null nor {time, healthy}",
    ),
    (
        "another target instance",
        "hosts.jsonl",
        |rows| set(&mut rows[0], &["instance"], value(r#""i-h9""#)),
        "hosts.jsonl does not name the package's target instance for the target host",
    ),
    (
        "one instance for two hosts",
        "hosts.jsonl",
        |rows| set(&mut rows[2], &["instance"], value(r#""i-h2""#)),
        "hosts.jsonl names one instance twice",
    ),
    (
        "a host outside the package",
        "hosts.jsonl",
        |rows| set(&mut rows[2], &["host"], value(r#""h9""#)),
        "hosts.jsonl line 3 names no host of the package or repeats one",
    ),
    (
        "a repeated host line",
        "hosts.jsonl",
        |rows| {
            let mut again = rows[2].clone();
            set(&mut again, &["instance"], value(r#""i-h4""#));
            rows.push(again);
        },
        "hosts.jsonl line 5 names no host of the package or repeats one",
    ),
    (
        "a host that is no text",
        "hosts.jsonl",
        |rows| set(&mut rows[2], &["host"], value(r#"["h3"]"#)),
        "hosts.jsonl line 3 names no host of the package or repeats one",
    ),
    (
        "an owned shard with no witness key",
        "shards.jsonl",
        |rows| {
            set(&mut rows[3], &["owner"], value(r#""h1""#));
            set(&mut rows[3], &["standby"], value(r#""h2""#));
        },
        "owned shards ['s4'] have no witness key in the package, so the judge would refuse the run's evidence",
    ),
    (
        "a witness key of a shard the target does not own",
        "shards.jsonl",
        |rows| set(&mut rows[2], &["owner"], value(r#""h4""#)),
        "the package's witness keys name shards ['s3'] the target does not own, so the judge would refuse the \
      run's evidence",
    ),
    (
        "a report time that is no number",
        "hosts.jsonl",
        |rows| set(&mut rows[1], &["report", "time"], value(r#""100""#)),
        "hosts.jsonl line 2 report is neither null nor {time, healthy}",
    ),
    (
        "a report with another key",
        "hosts.jsonl",
        |rows| set(&mut rows[1], &["report", "note"], value("1")),
        "hosts.jsonl line 2 report is neither null nor {time, healthy}",
    ),
    (
        "an instance that is no ID",
        "hosts.jsonl",
        |rows| set(&mut rows[1], &["instance"], value(r#""h2""#)),
        "hosts.jsonl line 2 instance is no instance ID: 'h2'",
    ),
    (
        "a shard line that is no object",
        "shards.jsonl",
        |rows| rows.push(value("[1]")),
        "shards.jsonl line 6 is no object",
    ),
    (
        "a host line that is no object",
        "hosts.jsonl",
        |rows| rows.push(Value::Null),
        "hosts.jsonl line 5 holds other keys than host, instance and report",
    ),
    (
        "a report time that is a boolean",
        "hosts.jsonl",
        |rows| set(&mut rows[1], &["report", "time"], value("true")),
        "hosts.jsonl line 2 report is neither null nor {time, healthy}",
    ),
    (
        "a report time past 2^53",
        "hosts.jsonl",
        |rows| set(&mut rows[1], &["report", "time"], value("9007199254740993")),
        "hosts.jsonl line 2 report is neither null nor {time, healthy}",
    ),
    (
        "a health of 1",
        "hosts.jsonl",
        |rows| set(&mut rows[1], &["report", "healthy"], value("1")),
        "hosts.jsonl line 2 report is neither null nor {time, healthy}",
    ),
    (
        "a shard record ahead of the clock",
        "shards.jsonl",
        |rows| each(rows, "time", "104.5"),
        "shards.jsonl line 1 time 104.5 lies outside [44.2, 104.2]: the snapshot is stale or ahead",
    ),
    (
        "no host lines",
        "hosts.jsonl",
        Vec::clear,
        "hosts.jsonl does not name the package's target instance for the target host",
    ),
];

/// Each stale, malformed or inconsistent snapshot is refused with its sentence; a cut before the
/// baseline window starts is refused for a package whose baseline starts after it, and a shard line
/// of a shard outside the package's list for a package that lists one shard fewer than its names.
#[test]
fn a_stale_malformed_or_inconsistent_snapshot_is_refused_after_the_caller() {
    for &(name, file, change, sentence) in REFUSED {
        let refusal = read(file, change, held)
            .err()
            .unwrap_or_else(|| panic!("{name} is refused"));
        assert_eq!(*refusal.message(), sentence, "{name}");
    }
    let refusal = read(
        "shards.jsonl",
        |rows| each(rows, "time", "98"),
        |p| set(p, &["baseline", "start"], value("99")),
    )
    .expect_err("a fresh cut before the baseline window starts");
    let sentence = "shards.jsonl's cut 98 lies before the baseline window starts";
    assert_eq!(*refusal.message(), sentence);
    let refusal = read(
        "shards.jsonl",
        |_| {},
        |p| items_mut(at_mut(p, &["shards"])).retain(|shard| *shard != value(r#""s5""#)),
    )
    .expect_err("a shard line outside the package's list");
    assert_eq!(*refusal.message(), "shards.jsonl misses shards []");
}

/// A named pipe is refused as no regular file without waiting for a writer, a link at the last
/// component is refused as unreadable, and a last line with no newline as cut short.
#[test]
fn an_input_that_is_a_named_pipe_or_a_link_is_refused_without_waiting() {
    let scratch = Scratch::new("pipe");
    let hosts = scratch.snapshot().join("hosts.jsonl");
    fs::remove_file(&hosts).expect("the host lines go");
    let made = mkfifo(&hosts);
    assert!(made, "the pipe is made");
    let refusal = bounded("the read of a pipe", move || {
        let refusal = read_at(&scratch, held).expect_err("a pipe is refused");
        refusal.message().to_string()
    });
    assert_eq!(refusal, "hosts.jsonl is no regular file");

    let scratch = Scratch::new("link");
    let shards = scratch.snapshot().join("shards.jsonl");
    let elsewhere = scratch.0.join("shards-elsewhere.jsonl");
    fs::rename(&shards, &elsewhere).expect("the shard lines move");
    symlink(&elsewhere, &shards).expect("the link is made");
    let refusal = read_at(&scratch, held).expect_err("a link is refused");
    assert_eq!(
        *refusal.message(),
        "shards.jsonl cannot be read: Too many levels of symbolic links"
    );

    let scratch = Scratch::new("cut-short");
    fs::write(
        scratch.snapshot().join("shards.jsonl"),
        br#"{"shard": "s1"}"#,
    )
    .expect("written");
    let refusal = read_at(&scratch, held).expect_err("a cut line is refused");
    let sentence = "shards.jsonl ends in a line with no newline: it may be truncated";
    assert_eq!(*refusal.message(), sentence);
}

/// Makes a named pipe at `path` with the system's `mkfifo` program.
fn mkfifo(path: &std::path::Path) -> bool {
    std::process::Command::new("mkfifo")
        .arg(path)
        .status()
        .is_ok_and(|status| status.success())
}

/// The committed snapshot's versions as the reader returns them.
const RECORDS: &str = r#"{"s1":{"owner":"h1","standby":"h2","generation":7,"volume":"vol-s1","attempts":1},"s2":{"owner":"h1","standby":"h3","generation":4,"volume":"vol-s2","attempts":2},"s3":{"owner":"h1","standby":"h2","generation":9,"volume":"vol-s3","attempts":1},"s4":{"owner":"h2","standby":"h1","generation":3,"volume":"vol-s4","attempts":1},"s5":{"owner":"h3","standby":"h4","generation":5,"volume":"vol-s5","attempts":1}}"#;

/// The committed snapshot reads as its versions in line order with the layout's keys, its host lines,
/// the cut and the earliest time; an equal time of another kind keeps the first line's kind, a null
/// report holds none, an older report is the earliest time, and of two equal earliest reports of
/// two kinds the earlier line's kind stays.
#[test]
fn a_snapshot_reads_as_its_versions_lines_cut_and_earliest_time() {
    let got = read("shards.jsonl", |_| {}, held).expect("the committed snapshot is admitted");
    let shards: Vec<String> = got
        .records()
        .iter()
        .map(|(shard, _)| shard.to_string())
        .collect();
    assert_eq!(shards, ["s1", "s2", "s3", "s4", "s5"]);
    assert_eq!(json(&Value::Object(got.records().clone())), RECORDS);
    let hosts: Vec<(String, String, Option<String>)> = got
        .reports()
        .iter()
        .map(|(host, line)| {
            let report = line
                .report()
                .map(|report| format!("{} {}", report.time(), report.healthy()));
            (host.to_string(), line.instance().to_string(), report)
        })
        .collect();
    let expected: Vec<(String, String, Option<String>)> = (1..=4)
        .map(|n| {
            (
                format!("h{n}"),
                format!("i-h{n}"),
                Some("100 true".to_owned()),
            )
        })
        .collect();
    assert_eq!(hosts, expected);
    assert_eq!(
        (got.cut().to_string(), got.oldest().to_string()),
        ("100".into(), "100".into())
    );

    let got = read(
        "shards.jsonl",
        |rows| set(&mut rows[0], &["time"], value("100.0")),
        held,
    )
    .expect("a float time equal to the integer cut");
    assert_eq!(
        (got.cut().to_string(), got.oldest().to_string()),
        ("100.0".into(), "100.0".into())
    );
    let got = read(
        "hosts.jsonl",
        |rows| set(&mut rows[1], &["report"], Value::Null),
        held,
    )
    .expect("a null report");
    let h2 = got.reports().get(&"h2".into()).expect("h2 has a line");
    assert_eq!(h2.report(), None);
    let got = read(
        "hosts.jsonl",
        |rows| set(&mut rows[3], &["report", "time"], value("50.5")),
        held,
    )
    .expect("an older report");
    assert_eq!(
        (got.cut().to_string(), got.oldest().to_string()),
        ("100".into(), "50.5".into())
    );
    for (first, second) in [("99", "99.0"), ("99.0", "99")] {
        let scratch = Scratch::new("equal-oldest");
        rewrite(&scratch.snapshot().join("hosts.jsonl"), |rows| {
            set(&mut rows[1], &["report", "time"], value(first));
            set(&mut rows[2], &["report", "time"], value(second));
        });
        let got = read_at(&scratch, held).expect("two equal earliest reports");
        assert_eq!(got.oldest().to_string(), first, "{first} then {second}");
    }
}
