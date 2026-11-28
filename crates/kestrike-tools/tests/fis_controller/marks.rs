//! The marks: each mark's bytes, the ordinal it records in `effect_window`, the event it appends,
//! and a mark whose append or write fails; and [`event`] over a log of three roles. Each row's
//! values are the mark's on the same log.

use std::ffi::OsStr;
use std::fs;
use std::path::Path;

use kestrike_tools::fis_controller::{Failure, Marks, Opening, Section, event, observer};
use kestrike_tools::hardware_host::Observer;
use kestrike_tools::host_stop::{Delivered, Disk, Record};
use kestrike_tools::json::{self, Integer, Object, Text, Value};
use kestrike_tools::python::repr;

use crate::fis_support::Scratch;
use crate::fis_support::clock::Clock;

fn text(value: &str) -> Text {
    Text::from(value)
}

fn integer(value: u64) -> Value {
    Value::Integer(Integer::from(value))
}

fn section() -> Section {
    Section::new(Opening {
        profile: text("fis-read-latency"),
        episode: text("e1"),
        action: Value::Null,
        attachment: Value::Null,
        targets: Value::Null,
        test_timeout_io_us: Value::Null,
        production_timeout_io_us: Value::Null,
        kernel_nvme_io_timeout: None,
    })
}

#[derive(Clone, Copy, PartialEq)]
enum Which {
    Started,
    Ended,
    Abandoned,
}

/// One mark's arrangement: the log's lines before it, the `effect_window` before it, whether the
/// episode has a log, and whether a directory stands at the mark's name.
struct Arranged {
    which: Which,
    logged: bool,
    prior: u64,
    window: Option<&'static [(&'static str, Option<u64>)]>,
    blocked: bool,
}

/// What a mark left: its error's kind and text, the section's `effect_window`, the mark's text and
/// each event of the log with a `kind` as `kind ordinal experiment role profile`.
#[derive(Debug, PartialEq)]
struct Marked {
    error: Option<String>,
    window: Option<String>,
    mark: Option<String>,
    events: Vec<String>,
}

fn marked(scratch: &Scratch, name: &str, arranged: &Arranged) -> (Marked, usize) {
    let directory = scratch.path().join(format!("marks-{name}"));
    fs::create_dir(&directory).expect("the directory is made");
    let log = directory.join("obs");
    if arranged.prior > 0 {
        fs::create_dir(&log).expect("the log's directory is made");
        let lines: String = (0..arranged.prior)
            .map(|n| format!("{{\"n\": {n}}}\n"))
            .collect();
        fs::write(log.join("e1.jsonl"), lines).expect("the log is written");
    }
    let observer = observer(
        if arranged.logged {
            log.as_os_str()
        } else {
            OsStr::new("")
        },
        OsStr::new("e1"),
        text("p"),
    );
    let marks = Marks::new(&directory.join("art"), OsStr::new("e1")).expect("the marks resolve");
    let mark = match arranged.which {
        Which::Started => marks.started(),
        Which::Ended => marks.ended(),
        Which::Abandoned => marks.abandoned(),
    }
    .to_path_buf();
    if arranged.blocked {
        fs::create_dir_all(&mark).expect("the directory is made");
    }
    let mut section = section();
    if let Some(window) = arranged.window {
        let mut members = Object::new();
        for (key, value) in window {
            members.insert(*key, value.map_or(Value::Null, integer));
        }
        section
            .insert("effect_window", Value::Object(members))
            .expect("effect_window is the caller's");
    }
    let clock = Clock::at(100.0);
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    let experiment = text("EXP1");
    let result = match arranged.which {
        Which::Started => marks
            .start(
                &Disk,
                &observer,
                &mut clock.clone(),
                &mut record,
                &mut section,
                &experiment,
            )
            .map(drop),
        Which::Ended => marks
            .end(
                &Disk,
                &observer,
                &mut clock.clone(),
                &mut record,
                &mut section,
                &experiment,
            )
            .map(drop),
        Which::Abandoned => marks.abandon(&Disk).map_err(Failure::System),
    };
    let error = result.err().map(|error| match error {
        Failure::System(error) => format!("system: {}", scratch.norm(&error.to_string())),
        Failure::Unreadable(_) => "unreadable".to_owned(),
        other => panic!("{other:?} is no failure of a mark"),
    });
    if !arranged.logged {
        assert!(
            !log.exists(),
            "{name}: with no log the append makes nothing"
        );
    }
    let events = read_events(&log.join("e1.jsonl"));
    let marked = Marked {
        error,
        window: section.get("effect_window").map(json::line_sorted),
        mark: mark
            .is_file()
            .then(|| fs::read_to_string(&mark).expect("the mark reads")),
        events,
    };
    (marked, clock.readings())
}

fn read_events(log: &Path) -> Vec<String> {
    let Ok(text) = fs::read_to_string(log) else {
        return Vec::new();
    };
    text.lines()
        .filter_map(
            |line| match json::parse(line).expect("a line of the log is JSON") {
                Value::Object(event) if event.get("kind").is_some() => Some(
                    ["kind", "ordinal", "experiment", "role", "profile"]
                        .iter()
                        .map(|key| event.get(key).map_or_else(|| "None".to_owned(), repr))
                        .collect::<Vec<_>>()
                        .join(" "),
                ),
                _ => None,
            },
        )
        .collect()
}

fn expected(
    error: Option<&str>,
    window: Option<&str>,
    mark: Option<&str>,
    events: &[&str],
) -> Marked {
    Marked {
        error: error.map(str::to_owned),
        window: window.map(str::to_owned),
        mark: mark.map(str::to_owned),
        events: events.iter().map(|event| (*event).to_owned()).collect(),
    }
}

const fn arranged(
    which: Which,
    prior: u64,
    window: Option<&'static [(&'static str, Option<u64>)]>,
) -> Arranged {
    Arranged {
        which,
        logged: true,
        prior,
        window,
        blocked: false,
    }
}

/// A mark appends its event, records its ordinal in `effect_window`, then writes the ordinal: the
/// start's mark replaces any window that stood, the end's adds `end_ordinal` to it, and the abandon
/// mark holds `abandoned`. An append reads the clock twice.
#[test]
fn each_mark_appends_its_event_then_records_and_writes_its_ordinal() {
    let scratch = Scratch::new("marks");
    let started = |ordinal: u64| format!("'fault-start' {ordinal} 'EXP1' 'fis' 'p'");
    let ended = |ordinal: u64| format!("'fault-end' {ordinal} 'EXP1' 'fis' 'p'");
    for (name, arrangement, want, readings) in [
        (
            "start",
            arranged(Which::Started, 0, None),
            expected(
                None,
                Some(r#"{"start_ordinal": 1}"#),
                Some("1"),
                &[&started(1)],
            ),
            2,
        ),
        (
            "start-after-two",
            arranged(Which::Started, 2, None),
            expected(
                None,
                Some(r#"{"start_ordinal": 3}"#),
                Some("3"),
                &[&started(3)],
            ),
            2,
        ),
        (
            "start-again",
            arranged(
                Which::Started,
                4,
                Some(&[("start_ordinal", Some(1)), ("end_ordinal", Some(2))]),
            ),
            expected(
                None,
                Some(r#"{"start_ordinal": 5}"#),
                Some("5"),
                &[&started(5)],
            ),
            2,
        ),
        (
            "end",
            arranged(
                Which::Ended,
                3,
                Some(&[("start_ordinal", Some(2)), ("start_time", None)]),
            ),
            expected(
                None,
                Some(r#"{"end_ordinal": 4, "start_ordinal": 2, "start_time": null}"#),
                Some("4"),
                &[&ended(4)],
            ),
            2,
        ),
        (
            "abandon",
            arranged(Which::Abandoned, 0, None),
            expected(None, None, Some("abandoned"), &[]),
            0,
        ),
    ] {
        let (got, read) = marked(&scratch, name, &arrangement);
        assert_eq!(got, want, "{name}");
        assert_eq!(read, readings, "{name}: the clock's readings");
    }
}

/// A mark whose append gives no event, as an episode with no observer log gives none, fails before
/// `effect_window` changes; an end with no window fails after its event was appended; and a write
/// that fails returns its system error with the ordinal recorded.
#[test]
fn a_mark_that_fails_leaves_the_section_as_its_steps_left_it() {
    let scratch = Scratch::new("marks-failing");
    let blocked = |which, prior, window| Arranged {
        blocked: true,
        ..arranged(which, prior, window)
    };
    let unlogged = |which, window| Arranged {
        logged: false,
        ..arranged(which, 0, window)
    };
    let rename = |name: &str, mark: &str| {
        format!(
            "system: [Errno 21] Is a directory: '<d>/marks-{name}/art/fis-e1.{mark}.partial' -> \
             '<d>/marks-{name}/art/fis-e1.{mark}'"
        )
    };
    for (name, arrangement, want) in [
        (
            "start-unlogged",
            unlogged(Which::Started, Some(&[("start_ordinal", Some(9))][..])),
            expected(
                Some("unreadable"),
                Some(r#"{"start_ordinal": 9}"#),
                None,
                &[],
            ),
        ),
        (
            "start-blocked",
            blocked(Which::Started, 0, None),
            expected(
                Some(&rename("start-blocked", "started")),
                Some(r#"{"start_ordinal": 1}"#),
                None,
                &["'fault-start' 1 'EXP1' 'fis' 'p'"],
            ),
        ),
        (
            "end-no-window",
            arranged(Which::Ended, 1, None),
            expected(
                Some("unreadable"),
                None,
                None,
                &["'fault-end' 2 'EXP1' 'fis' 'p'"],
            ),
        ),
        (
            "end-unlogged",
            unlogged(Which::Ended, Some(&[("start_ordinal", Some(2))][..])),
            expected(
                Some("unreadable"),
                Some(r#"{"start_ordinal": 2}"#),
                None,
                &[],
            ),
        ),
        (
            "end-blocked",
            blocked(Which::Ended, 1, Some(&[("start_ordinal", Some(1))][..])),
            expected(
                Some(&rename("end-blocked", "ended")),
                Some(r#"{"end_ordinal": 2, "start_ordinal": 1}"#),
                None,
                &["'fault-end' 2 'EXP1' 'fis' 'p'"],
            ),
        ),
    ] {
        let (got, _) = marked(&scratch, name, &arrangement);
        assert_eq!(got, want, "{name}");
    }
}

/// The log of three roles, `fis`, `r` and `w`, under the profiles `p` and `q`, as JSON lines.
const LOG: &[&str] = &[
    r#"{"name": "timeout", "ordinal": 1, "profile": "p", "role": "fis"}"#,
    r#"{"name": "timeout", "ordinal": 2, "profile": "p", "role": "r"}"#,
    r#"{"name": "timeout", "ordinal": 3, "profile": "p", "role": "w"}"#,
    r#"{"name": "restored", "ordinal": 4, "profile": "p", "role": "r"}"#,
    r#"{"name": "timeout", "ordinal": 5, "profile": "q", "role": "r"}"#,
    r#"{"name": "timeout", "ordinal": 6.5, "profile": "p", "role": "r"}"#,
    r#"{"name": "restored", "ordinal": true, "profile": "p", "role": "w"}"#,
    r#"{"kind": "ready", "ordinal": 8, "profile": "p", "role": "r"}"#,
    r#"{"name": "late", "profile": "p", "role": "r"}"#,
];

/// The ordinal of each query's event as Python's `repr` writes it, `None` for no event and `error`
/// for a refusal, with the count of the clock's readings.
fn found(
    scratch: &Scratch,
    name: &str,
    lines: &[&str],
    queries: &[(&str, i64, &str)],
) -> (Vec<String>, usize) {
    let directory = scratch.path().join(format!("event-{name}"));
    fs::create_dir_all(directory.join("obs")).expect("the directory is made");
    let log: String = lines.iter().map(|line| format!("{line}\n")).collect();
    fs::write(directory.join("obs/e1.jsonl"), log).expect("the log is written");
    let observer: Observer = observer(
        directory.join("obs").as_os_str(),
        OsStr::new("e1"),
        text("p"),
    );
    let mut clock = Clock::at(100.0);
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    let mut got = Vec::new();
    for (query, after, role) in queries {
        let after =
            Integer::from_digits(*after < 0, &after.unsigned_abs().to_string()).expect("digits");
        let read = event(
            &observer,
            &mut clock,
            &mut record,
            query,
            &after,
            &text("p"),
            &text(role),
        );
        got.push(match read {
            Ok(Some(event)) => repr(event.get("ordinal").expect("a found event has an ordinal")),
            Ok(None) => "None".to_owned(),
            Err(Failure::Unreadable(_)) => "error".to_owned(),
            Err(other) => panic!("{other:?} is no refusal of an event"),
        });
    }
    (got, clock.readings())
}

/// Each query finds its event: the first of its name past the ordinal, of the lane's
/// profile and role, an event of another role or profile passed over; a boolean ordinal counts as 0
/// or 1 and a fraction compares by its value; each query reads the log anew, with one reading of the
/// clock.
#[test]
fn an_event_is_the_first_of_its_name_past_the_ordinal_of_the_lane_s_role() {
    let scratch = Scratch::new("event");
    let queries = [
        ("timeout", 0, "r"),
        ("timeout", 2, "r"),
        ("timeout", 6, "r"),
        ("timeout", 7, "r"),
        ("timeout", 0, "w"),
        ("timeout", 0, "fis"),
        ("restored", 0, "r"),
        ("restored", 4, "r"),
        ("restored", 0, "w"),
        ("restored", 1, "w"),
        ("ready", 0, "r"),
        ("late", 0, "w"),
    ];
    let (got, readings) = found(&scratch, "three-roles", LOG, &queries);
    assert_eq!(
        got,
        [
            "2", "6.5", "6.5", "None", "3", "1", "4", "None", "True", "None", "None", "error"
        ]
    );
    assert_eq!(readings, queries.len(), "one reading per read of the log");
    let fraction = [
        r#"{"name": "timeout", "ordinal": 2.5, "profile": "p", "role": "r"}"#,
        r#"{"name": "timeout", "ordinal": -0.5, "profile": "p", "role": "r"}"#,
    ];
    let (got, _) = found(
        &scratch,
        "fraction",
        &fraction,
        &[
            ("timeout", 2, "r"),
            ("timeout", 3, "r"),
            ("timeout", -1, "r"),
        ],
    );
    assert_eq!(got, ["2.5", "None", "2.5"]);
}

/// An event up to the one found that is no object, and one of the name with no ordinal or with one
/// of no order, is refused; the same shapes past the event found, or under another name, are not
/// read.
#[test]
fn an_event_of_another_shape_before_the_one_found_is_refused() {
    let scratch = Scratch::new("event-refused");
    let mut listed = vec!["[1]"];
    listed.extend_from_slice(LOG);
    let (got, _) = found(
        &scratch,
        "not-object-first",
        &listed,
        &[("timeout", 0, "r")],
    );
    assert_eq!(got, ["error"]);
    let after = [LOG[0], LOG[1], "[1]"];
    let (got, _) = found(
        &scratch,
        "not-object-after",
        &after,
        &[("timeout", 0, "r"), ("timeout", 2, "r")],
    );
    assert_eq!(got, ["2", "error"]);
    let (got, _) = found(&scratch, "late-without-ordinal", LOG, &[("late", 0, "r")]);
    assert_eq!(got, ["error"]);
    let texted = [r#"{"name": "timeout", "ordinal": "3", "role": "r", "profile": "p"}"#];
    let (got, _) = found(
        &scratch,
        "text-ordinal",
        &texted,
        &[("timeout", 0, "r"), ("restored", 0, "r")],
    );
    assert_eq!(got, ["error", "None"]);
    let other = [r#"{"name": "x", "ordinal": null}"#, LOG[1]];
    let (got, _) = found(&scratch, "null-ordinal", &other, &[("timeout", 0, "r")]);
    assert_eq!(got, ["2"]);
}

/// An append that fails changes nothing of the section: a signal stored under an armed record ends
/// it in the wait for a lock another holder keeps, and a regular file in place of the log's directory fails its
/// making. Control: the same mark with neither appends and records its window.
#[test]
fn a_failed_append_leaves_the_section_and_the_mark_as_they_were() {
    let scratch = Scratch::new("marks-append");
    for arm in ["signal", "file", "control"] {
        let directory = scratch.path().join(format!("append-{arm}"));
        fs::create_dir(&directory).expect("the directory is made");
        let log = directory.join("obs");
        if arm == "file" {
            fs::write(&log, "x").expect("the file is written");
        }
        let observer = observer(log.join("deeper").as_os_str(), OsStr::new("e1"), text("p"));
        let marks = Marks::new(&directory.join("art"), OsStr::new("e1")).expect("resolves");
        let store = crate::fis_support::delivered();
        let mut record = Record::new(store);
        record.arm();
        let mut clock = Clock::at(100.0);
        let held = (arm == "signal").then(|| {
            store.deliver(kestrike_tools::host_stop::Signal::Terminate);
            fs::create_dir_all(log.join("deeper")).expect("the directory is made");
            let holder = fs::File::create(log.join("deeper/e1.jsonl")).expect("the log is made");
            holder.lock().expect("the lock is held");
            holder
        });
        let mut section = section();
        let marked = marks.start(
            &Disk,
            &observer,
            &mut clock,
            &mut record,
            &mut section,
            &text("EXP1"),
        );
        match arm {
            "signal" => assert!(matches!(marked, Err(Failure::Interrupted(_))), "{marked:?}"),
            "file" => assert!(matches!(marked, Err(Failure::System(_))), "{marked:?}"),
            _ => assert_eq!(marked, Ok(Integer::from(1u64))),
        }
        assert_eq!(section.contains("effect_window"), arm == "control", "{arm}");
        assert_eq!(marks.started().exists(), arm == "control", "{arm}");
        drop(held);
    }
}

/// The marks stand under the artifacts directory with its links resolved, and a link at a mark's
/// own name stays a link: the start's write refuses it with `ELOOP`, its window recorded.
#[test]
fn the_marks_stand_under_the_resolved_directory_and_a_link_at_a_mark_is_refused() {
    let scratch = Scratch::new("marks-resolved");
    let real = scratch.path().join("real");
    fs::create_dir(&real).expect("the directory is made");
    let via = scratch.path().join("via");
    std::os::unix::fs::symlink(&real, &via).expect("linked");
    let marks = Marks::new(&via, OsStr::new("e1")).expect("resolves");
    assert_eq!(marks.started(), real.join("fis-e1.started"));
    assert_eq!(marks.ended(), real.join("fis-e1.ended"));
    assert_eq!(marks.abandoned(), real.join("fis-e1.abandoned"));
    std::os::unix::fs::symlink(real.join("elsewhere"), marks.started()).expect("linked");
    let observer = observer(
        scratch.path().join("obs").as_os_str(),
        OsStr::new("e1"),
        text("p"),
    );
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    let mut section = section();
    let marked = marks.start(
        &Disk,
        &observer,
        &mut Clock::at(100.0),
        &mut record,
        &mut section,
        &text("EXP1"),
    );
    let Err(Failure::System(error)) = marked else {
        panic!("{marked:?} is a system error");
    };
    assert_eq!(
        scratch.norm(&error.to_string()),
        "[Errno 40] Too many levels of symbolic links: '<d>/real/fis-e1.started'"
    );
    assert_eq!(
        section
            .get("effect_window")
            .map(json::line_sorted)
            .as_deref(),
        Some(r#"{"start_ordinal": 1}"#)
    );
    assert!(
        fs::symlink_metadata(marks.started())
            .expect("lstat")
            .file_type()
            .is_symlink()
    );
    assert!(
        !real.join("elsewhere").exists(),
        "the link's target is not made"
    );
}
