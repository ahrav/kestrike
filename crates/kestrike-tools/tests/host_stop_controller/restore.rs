use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;

use kestrike_tools::gameday::ends_observation;
use kestrike_tools::host_stop::{
    Number, Request, Signal, System, check_reviewed, check_stopped, launch_time,
};
use kestrike_tools::json::{Object, Text, Value};

use super::plane::{Action, CALLER, CHANGES, RECORD, STATUS, Shape, State, calendar, string};
use super::restoring::{digest, replace_mark, restore_alone, write_json};
use super::steps::{Step, errno, links};
use super::stop_run::{operator_seconds, seconds, time};
use super::{COPY, Case, guardrails, listing, member, set, tail, text_of};
use crate::host_stop_support::{START, TARGET, object, value};

const POLL: f64 = 5.0;
const SKEW: f64 = 5.0;

fn shorten_bounds(case: &mut Case, deadline: i64) {
    for (key, seconds) in [
        ("effect_timeout_seconds", 5),
        ("observe_seconds", 5),
        ("deadline_seconds", deadline),
    ] {
        set(&mut case.operator, &[key], value(&seconds.to_string()));
    }
}

pub(crate) fn flip_first_guardrail() -> Action {
    Action::Hook(Box::new(|state: &mut State| {
        state.flip("gd2-guardrail-1", "ALARM");
        Action::Answer
    }))
}

fn shapes(count: usize, shape: impl Fn(Value) -> Value + Clone + 'static) -> Vec<Shape> {
    (0..count)
        .map(|_| Box::new(shape.clone()) as Shape)
        .collect()
}

fn instance_row(reply: &mut Value) -> &mut Object {
    let Value::Object(reply) = reply else {
        panic!("a reply is an object")
    };
    let Some(Value::Array(reservations)) = reply.get_mut("Reservations") else {
        panic!("a record reply holds its reservations")
    };
    let Some(Value::Object(reservation)) = reservations.first_mut() else {
        panic!("a reservation")
    };
    let Some(Value::Array(rows)) = reservation.get_mut("Instances") else {
        panic!("a reservation holds its instances")
    };
    match rows.first_mut() {
        Some(Value::Object(row)) => row,
        other => panic!("{other:?} is an instance row"),
    }
}

#[test]
fn restore_writes_restoration_once_the_target_runs_with_both_checks_ok() {
    let mut case = Case::new("restore-clean");
    assert_eq!(case.run(), 0, "{}", case.output());
    let period = POLL + case.plane.borrow().call_seconds;
    let deadline = operator_seconds(&case, "deadline_seconds");
    let last = (deadline / period).floor() as usize;
    case.start_target(last);
    let (launched, start) = (case.plane.borrow().t, case.log().len());
    assert_eq!(case.restore(None), 0, "{}", case.output());
    case.keep("restore-clean");
    let marks = case.marks();
    let restoration = &marks["restoration"];
    assert_eq!(text_of(restoration, "instance"), TARGET);
    assert_eq!(text_of(restoration, "state"), "running");
    assert_eq!(member(restoration, "reviewed_sha256"), &Value::Null);
    let mut expected = vec![CALLER.to_owned()];
    expected.extend(std::iter::repeat_n(STATUS.to_owned(), last + 1));
    expected.push(RECORD.to_owned());
    assert_eq!(case.ops()[start..], expected[..]);
    let log = case.log();
    let last_status = &log[log.len() - 2];
    assert_eq!(last_status.op, STATUS);
    assert!(
        last_status.start + period > log[start + 1].start + deadline,
        "a read one period later starts past the deadline"
    );
    let restored = time(restoration);
    assert!(
        (restored - (launched - SKEW)).abs() < 1e-6,
        "{restored} {launched}"
    );
    assert!(restored > time(&marks["stopped"]));
    assert!(restored < log[start].start, "before restore's start");
    case.assert_restore_refused(None, "restoration.json exists");
}

#[test]
fn a_start_at_the_bound_a_run_prints_ends_no_observation_under_a_clock_error() {
    let mut case = Case::new("restore-bound");
    case.repackage(|p| set(p, &["clock_error_seconds"], value("2")));
    let package = object(value(
        &fs::read_to_string(&case.package).expect("the package reads"),
    ));
    assert_eq!(case.run(), 0, "{}", case.output());
    let output = case.output();
    let printed: Vec<&str> = output
        .split("A start before ")
        .skip(1)
        .map(|rest| rest.split(' ').next().expect("a bound"))
        .collect();
    assert_eq!(printed.len(), 1, "{output}");
    assert!(output.contains(&format!(
        "A start before {} may end the judge's observation",
        printed[0]
    )));
    let late: f64 = printed[0].parse().expect("the bound is a number");
    {
        let mut plane = case.plane.borrow_mut();
        plane.t = late;
    }
    case.start_target(0);
    {
        let mut plane = case.plane.borrow_mut();
        let launched = (plane.t - SKEW).floor();
        plane
            .instances
            .get_mut(TARGET)
            .expect("the target")
            .launched = launched;
    }
    assert_eq!(case.restore(None), 0, "{}", case.output());
    let restoration = case.marks()["restoration"].clone();
    assert_eq!(time(&restoration), late - 2.0 * SKEW);
    assert!(!ends_observation(
        &package,
        Some(member(&restoration, "time"))
    ));
    let run_end = seconds(member(
        member(&Value::Object(package.clone()), "run"),
        "end",
    ));
    assert_eq!(late, run_end + 2.0 * SKEW + 1.0 + 2.0);
    let earliest = late - 2.0 * SKEW - 1.0;
    assert!(!ends_observation(&package, Some(&Value::Float(earliest))));
    assert!(ends_observation(
        &package,
        Some(&Value::Float(earliest - 1.0))
    ));
}

type Dating = fn(f64, f64) -> f64;

type StoppedRow<'a> = (&'a str, Option<(&'a str, Value)>, &'a str);

#[test]
fn the_restoration_is_dated_by_the_targets_launch_between_the_marks_and_the_ready_read() {
    let step = 0.25;
    let rows: [(&str, Dating, Option<Dating>, usize); 5] = [
        (
            "a launch after the marks",
            |s, _| s + 20.0,
            Some(|s, _| s + 20.0 - SKEW),
            1,
        ),
        (
            "a launch the skew before the stopped report",
            |s, _| s - SKEW,
            Some(|s, _| s),
            1,
        ),
        (
            "a launch more than the skew before the stopped report",
            |s, _| s - SKEW - 0.25,
            None,
            0,
        ),
        (
            "a launch the skew after the ready read",
            |_, r| r + SKEW,
            Some(|_, r| r),
            1,
        ),
        (
            "a launch more than the skew after the ready read",
            |_, r| r + SKEW + 0.25,
            Some(|_, r| r + 0.25),
            2,
        ),
    ];
    for (name, launched, dated, records) in rows {
        let mut case = Case::new("restore-dated");
        case.plane.borrow_mut().call_seconds = step;
        assert_eq!(case.run(), 0, "{name}: {}", case.output());
        case.start_target(0);
        let stopped = time(&case.marks()["stopped"]);
        let ready = case.plane.borrow().t + 2.0 * step;
        assert_eq!(case.floor(), stopped, "{name}");
        case.plane
            .borrow_mut()
            .instances
            .get_mut(TARGET)
            .expect("the target")
            .launched = launched(stopped, ready);
        let start = case.log().len();
        shorten_bounds(&mut case, 15);
        match dated {
            None => {
                assert_eq!(case.restore(None), 1, "{name}: {}", case.output());
                assert!(!case.marks().contains_key("restoration"), "{name}");
                let output = case.output();
                assert!(
                    output.contains("before the stopped report"),
                    "{name}: {output}"
                );
                assert!(
                    output.contains("the evidence is not to be judged as it stands"),
                    "{name}: {output}"
                );
                assert_eq!(
                    case.ops().last().map(String::as_str),
                    Some(RECORD),
                    "{name}"
                );
            }
            Some(dated) => {
                assert_eq!(case.restore(None), 0, "{name}: {}", case.output());
                assert_eq!(
                    time(&case.marks()["restoration"]),
                    dated(stopped, ready),
                    "{name}"
                );
                let mut expected = vec![CALLER.to_owned()];
                for _ in 0..records {
                    expected.extend([STATUS.to_owned(), RECORD.to_owned()]);
                }
                assert_eq!(case.ops()[start..], expected[..], "{name}");
            }
        }
        assert!(
            !case.ops()[start..]
                .iter()
                .any(|op| CHANGES.contains(&op.as_str())),
            "{name}"
        );
    }
}

fn launch_shape(launch: Option<Value>) -> impl Fn(Value) -> Value + Clone + 'static {
    move |mut reply: Value| {
        let row = instance_row(&mut reply);
        match &launch {
            None => {
                row.remove("LaunchTime");
            }
            Some(launch) => row.insert("LaunchTime", launch.clone()),
        }
        reply
    }
}

#[test]
fn a_record_that_shows_no_usable_launch_leaves_the_restoration_unshown() {
    let mut case = Case::new("restore-launch");
    assert_eq!(case.run(), 0, "{}", case.output());
    shorten_bounds(&mut case, 15);
    let second = case.plane.borrow().t.floor() as i64;
    let now = calendar(second, 'T');
    let zoned = Text::from(format!("{now}Z"));
    assert_eq!(
        launch_time(Some(&zoned)).expect("a UTC time"),
        Number::from(second)
    );
    let form = "is no UTC time";
    let text = |shown: String| Some(string(&shown));
    let pending = |mut reply: Value| {
        let row = instance_row(&mut reply);
        row.insert("State", value(r#"{"Code": 0, "Name": "pending"}"#));
        reply
    };
    let partial = |mut reply: Value| {
        if let Value::Object(reply) = &mut reply {
            reply.insert("NextToken", string("more"));
        }
        reply
    };
    let rows: Vec<(&str, Vec<Shape>, &str)> = vec![
        ("no launch time", shapes(200, launch_shape(None)), form),
        (
            "a launch time that is no text",
            shapes(200, launch_shape(Some(value("104")))),
            "is no str",
        ),
        (
            "another offset",
            shapes(200, launch_shape(text(format!("{now}+01:00")))),
            form,
        ),
        (
            "no zone",
            shapes(200, launch_shape(text(now.clone()))),
            form,
        ),
        (
            "a zone in small letters",
            shapes(200, launch_shape(text(format!("{now}z")))),
            form,
        ),
        (
            "a space for the T",
            shapes(
                200,
                launch_shape(text(format!("{}Z", now.replace('T', " ")))),
            ),
            form,
        ),
        (
            "seconds of 60",
            shapes(
                200,
                launch_shape(text(format!("{}60Z", &now[..now.len() - 2]))),
            ),
            form,
        ),
        (
            "a fraction of ten digits",
            shapes(200, launch_shape(text(format!("{now}.0000000000Z")))),
            form,
        ),
        (
            "text after the zone",
            shapes(200, launch_shape(text(format!("{now}Z ")))),
            form,
        ),
        (
            "a date alone",
            shapes(200, launch_shape(text(now[..10].to_owned()))),
            form,
        ),
        (
            "a day no month holds",
            shapes(200, launch_shape(text("1970-02-30T00:00:00Z".to_owned()))),
            "is no calendar time",
        ),
        (
            "a record of a target not yet running",
            shapes(200, pending),
            "record reads pending",
        ),
        ("a partial listing", shapes(200, partial), "NextToken"),
    ];
    for (name, shaped, reason) in rows {
        case.start_target(0);
        case.plane.borrow_mut().shape(RECORD, shaped);
        let (seen, start) = (case.output().len(), case.log().len());
        assert_eq!(case.restore(None), 1, "{name}: {}", &case.output()[seen..]);
        let output = case.output();
        assert!(
            output[seen..].contains(reason),
            "{name}: {}",
            &output[seen..]
        );
        assert!(
            output[seen..].contains("the evidence is not to be judged as it stands"),
            "{name}"
        );
        assert!(!case.marks().contains_key("restoration"), "{name}");
        let records = case.ops()[start..]
            .iter()
            .filter(|op| *op == RECORD)
            .count();
        assert!(records > 1, "{name}: the poll goes on to its deadline");
    }
    case.plane.borrow_mut().shape(RECORD, Vec::new());
    case.start_target(0);
    case.plane
        .borrow_mut()
        .script(RECORD, (0..200).map(|_| Action::Lose).collect());
    assert_eq!(case.restore(None), 1, "{}", case.output());
    assert!(!case.marks().contains_key("restoration"));
    case.plane.borrow_mut().script(RECORD, Vec::new());
    case.start_target(0);
    assert_eq!(case.restore(None), 0, "{}", case.output());
    assert!(case.marks().contains_key("restoration"));
}

#[test]
fn a_launch_time_reads_in_both_utc_forms_with_or_without_a_fraction() {
    let at = |text: &str| launch_time(Some(&Text::from(text))).expect("a UTC time");
    let origin = at("2026-11-24T00:00:00Z");
    for (text, seconds) in [
        ("2026-11-24T00:00:10+00:00", 10.0),
        ("2026-11-24T00:00:10Z", 10.0),
        ("2026-11-24T00:00:10.250+00:00", 10.25),
        ("2026-11-24T00:00:10.250Z", 10.25),
    ] {
        assert_eq!(at(text).minus(origin), Number::from(seconds), "{text}");
    }
    assert_eq!(at("1970-01-01T00:01:44Z"), Number::from(START));
}

#[test]
fn a_record_read_that_runs_to_the_deadline_is_cut_there_and_writes_no_restoration() {
    let mut case = Case::new("restore-cut");
    assert_eq!(case.run(), 0, "{}", case.output());
    let period = POLL + case.plane.borrow().call_seconds;
    let deadline = operator_seconds(&case, "deadline_seconds");
    case.start_target((deadline / period).floor() as usize);
    case.plane
        .borrow_mut()
        .script(RECORD, vec![Action::Delay(60.0)]);
    let start = case.log().len();
    assert_eq!(case.restore(None), 1, "{}", case.output());
    let ops = case.ops();
    assert_eq!(ops[ops.len() - 2..], [STATUS, RECORD]);
    let log = case.log();
    let record = log.last().expect("a call");
    assert!(record.cut, "{record:?}");
    let cut = record.time.expect("a cut call has its time");
    assert!(
        (cut - (log[start + 1].start + deadline)).abs() < 1e-6,
        "{cut}"
    );
    assert!(!case.marks().contains_key("restoration"));
}

#[test]
fn restore_is_refused_without_a_stop_mark() {
    let mut case = Case::new("restore-no-stop");
    case.assert_restore_refused(None, "no stop to restore from");
    assert_eq!(listing(&case.evidence), [COPY]);
    case.snapshot("shards.jsonl", |rows| {
        set(&mut rows[3], &["standby"], string("h3"));
    });
    assert_eq!(case.run(), 1, "{}", case.output());
    case.assert_restore_refused(None, "injection/stop.json cannot be read");
}

fn merged(review: &Value, change: &[(&str, Value)]) -> Value {
    let mut merged = review.clone();
    for (key, new) in change {
        match &mut merged {
            Value::Object(object) => object.insert(*key, new.clone()),
            other => panic!("{other:?} is an object"),
        }
    }
    merged
}

fn reviewed_again(path: &Path, review: &Value, abort: &Path) {
    write_json(
        path,
        &merged(review, &[("abort_sha256", string(&digest(abort)))]),
    );
}

#[test]
fn after_an_abort_restore_needs_the_reviewed_record_of_that_abort() {
    let mut case = Case::new("restore-reviewed");
    let (path, review) = case.aborted_run();
    case.assert_restore_refused(None, "an abort stands: restore needs --reviewed");
    let aborted_at = time(&case.marks()["abort"]);
    let now = case.plane.borrow().wall();
    let rows: [(&str, (&str, Value), &str); 5] = [
        (
            "another abort",
            ("abort_sha256", string(&"0".repeat(64))),
            "names another abort",
        ),
        (
            "other steps",
            ("steps", string("restart it")),
            "steps other than",
        ),
        ("an extra key", ("note", string("x")), "refused: "),
        (
            "a review dated before the abort",
            ("time", Value::Float(aborted_at - 1.0)),
            "before the abort",
        ),
        (
            "a review dated after restore's start",
            ("time", Value::Float(now + 1.0)),
            "after restore's start",
        ),
    ];
    for (name, change, reason) in rows {
        write_json(&path, &merged(&review, &[change]));
        let seen = case.output().len();
        case.assert_restore_refused(Some(&path), reason);
        assert!(!case.output()[seen..].is_empty(), "{name}");
    }
    let text = super::restoring::dumps(&review);
    let repeated = format!("{}, \"reviewer\": \"another\"}}", &text[..text.len() - 1]);
    fs::write(&path, repeated).expect("the review is written");
    case.assert_restore_refused(Some(&path), "repeats a key");
    let inside = case.evidence.join("reviewed.json");
    write_json(&inside, &review);
    case.assert_restore_refused(Some(&inside), "inside the evidence directory");
    fs::remove_file(&inside).expect("the review inside is removed");
    let pipe = case.scratch.0.join("pipe.json");
    let name = std::ffi::CString::new(pipe.to_str().expect("UTF-8").as_bytes()).expect("no NUL");
    // SAFETY: `name` is a NUL-terminated path that outlives the call.
    assert_eq!(
        unsafe { libc::mkfifo(name.as_ptr(), 0o600) },
        0,
        "the pipe is made"
    );
    let before = listing(&case.evidence);
    let (operator, catalog, evidence) = (
        case.write_operator(),
        case.catalog.clone(),
        case.evidence.clone(),
    );
    let reviewed = pipe.clone();
    let (code, output, ops) =
        crate::host_stop_support::bounded("restore over a named pipe", move || {
            restore_alone(&operator, &catalog, &evidence, Some(&reviewed))
        });
    assert_eq!(code, 2, "{output}");
    assert!(output.contains("no regular file"), "{output}");
    assert_eq!(ops, Vec::<String>::new());
    assert_eq!(listing(&case.evidence), before);
    let injection = case.evidence.join("injection");
    write_json(
        &path,
        &merged(&review, &[("time", Value::Float(aborted_at))]),
    );
    let stop = merged(
        &value(&fs::read_to_string(injection.join("stop.json")).expect("stop.json reads")),
        &[("time", Value::Float(aborted_at))],
    );
    let stop = Request::checked(&stop, &Text::from("injection/stop.json")).expect("a request");
    let found = check_reviewed(
        Some(&path),
        &injection.join("abort.json"),
        &case.evidence,
        Number::from(now),
        &stop,
        kestrike_tools::gameday::FILE_LIMIT,
    )
    .expect("a review dated at the abort's time");
    assert_eq!(found, (digest(&path), Number::from(aborted_at)));
    write_json(&path, &review);
    assert_eq!(case.restore(Some(&path)), 0, "{}", case.output());
    case.keep("restore-reviewed");
    let reviewed_digest = digest(&path);
    assert!(case.output().contains(&format!(
        "host-stop-controller: reviewed record sha256 {reviewed_digest}\n"
    )));
    let restoration = case.marks()["restoration"].clone();
    assert_eq!(text_of(&restoration, "instance"), TARGET);
    assert_eq!(text_of(&restoration, "reviewed_sha256"), reviewed_digest);
}

#[test]
fn after_an_abort_with_no_stop_shown_an_older_launch_dates_the_restoration_at_the_abort() {
    let mut case = Case::new("restore-older");
    let (path, review) = case.aborted_run();
    write_json(&path, &review);
    case.plane
        .borrow_mut()
        .instances
        .get_mut(TARGET)
        .expect("the target")
        .launched = 0.0;
    case.plane
        .borrow_mut()
        .shape(RECORD, shapes(200, launch_shape(None)));
    assert_eq!(case.restore(Some(&path)), 1, "{}", case.output());
    assert!(!case.marks().contains_key("restoration"));
    case.plane.borrow_mut().shape(RECORD, Vec::new());
    assert_eq!(case.restore(Some(&path)), 0, "{}", case.output());
    let marks = case.marks();
    assert!(!marks.contains_key("stopped"));
    assert_eq!(time(&marks["restoration"]), time(&marks["abort"]));
    assert_eq!(
        text_of(&marks["restoration"], "reviewed_sha256"),
        digest(&path)
    );
}

#[test]
fn restore_refuses_an_abort_mark_the_judge_refuses() {
    let mut case = Case::new("restore-abort-judged");
    let (path, review) = case.aborted_run();
    let injection = case.evidence.join("injection");
    let abort = case.marks()["abort"].clone();
    assert_eq!(text_of(&abort, "cause"), "stop-not-shown");
    assert_eq!(member(&abort, "guardrail"), &Value::Null);
    for change in [
        ("cause", string("guardrail")),
        ("guardrail", string(&guardrails()[0])),
    ] {
        replace_mark(&injection, "abort.json", &merged(&abort, &[change]));
        reviewed_again(&path, &review, &injection.join("abort.json"));
        case.assert_restore_refused(Some(&path), "names a guardrail without cause guardrail");
    }
}

#[test]
fn a_review_names_the_steps_the_aborted_run_printed_whatever_the_catalog_holds_at_restore() {
    let mut case = Case::new("restore-steps");
    let (path, review) = case.aborted_run();
    let mut later = crate::host_stop_support::met();
    let gd2 = crate::host_stop_support::gd2_mut(&mut later);
    match gd2.get_mut("restoration") {
        Some(Value::Object(restoration)) => {
            restoration.insert("steps", string("start the instance"));
        }
        other => panic!("{other:?} is the restoration"),
    }
    fs::write(&case.catalog, super::json(&later)).expect("the catalog is written");
    write_json(
        &path,
        &merged(&review, &[("steps", string("start the instance"))]),
    );
    case.assert_restore_refused(
        Some(&path),
        "steps other than those the aborted run printed",
    );
    write_json(&path, &review);
    assert_eq!(case.restore(Some(&path)), 0, "{}", case.output());
    assert_eq!(
        text_of(&case.marks()["restoration"], "reviewed_sha256"),
        digest(&path)
    );
}

#[test]
fn restore_refuses_an_abort_mark_whose_detail_does_not_end_with_its_runs_steps_digest() {
    let mut case = Case::new("restore-detail");
    let (path, review) = case.aborted_run();
    let injection = case.evidence.join("injection");
    let abort = case.marks()["abort"].clone();
    let detail = text_of(&abort, "detail");
    let steps_tail = tail();
    assert!(detail.ends_with(&steps_tail), "{detail}");
    let other = format!(
        "; restoration steps sha256 {}",
        kestrike_tools::python::hexdigest(b"start the instance")
    );
    let unpinned = "does not end with the digest of the restoration steps";
    let others = "steps other than those the aborted run printed";
    let head = &detail[..detail.len() - steps_tail.len()];
    let digits = &detail[detail.len() - 64..];
    let rows: [(&str, Value, &str); 7] = [
        ("no detail", Value::Null, unpinned),
        ("a detail without the digest", string(head), unpinned),
        (
            "the digest before the detail's end",
            string(&format!("{detail} and more")),
            unpinned,
        ),
        (
            "a digest cut short",
            string(&detail[..detail.len() - 1]),
            unpinned,
        ),
        (
            "a digest in capitals",
            string(&format!(
                "{}{}",
                &detail[..detail.len() - 64],
                digits.to_uppercase()
            )),
            unpinned,
        ),
        (
            "the digest of other steps",
            string(&format!("{head}{other}")),
            others,
        ),
        (
            "the digest of other steps after the run's",
            string(&format!("{detail}{other}")),
            others,
        ),
    ];
    for (name, detail, reason) in rows {
        replace_mark(
            &injection,
            "abort.json",
            &merged(&abort, &[("detail", detail)]),
        );
        reviewed_again(&path, &review, &injection.join("abort.json"));
        let seen = case.output().len();
        case.assert_restore_refused(Some(&path), reason);
        assert!(case.output().len() > seen, "{name}");
    }
}

#[test]
fn restore_waits_for_the_system_check_as_well_as_the_instance_check() {
    let mut case = Case::new("restore-system");
    assert_eq!(case.run(), 0, "{}", case.output());
    {
        let mut plane = case.plane.borrow_mut();
        let target = plane.instances.get_mut(TARGET).expect("the target");
        target.state = "running".to_owned();
        target.checks = "ok".to_owned();
        target.system = "impaired".to_owned();
        plane.stopping = None;
    }
    assert_eq!(case.restore(None), 1, "{}", case.output());
    assert!(!case.marks().contains_key("restoration"));
}

#[test]
fn restore_refuses_an_unrecorded_end_and_an_undeclared_instance() {
    let mut case = Case::new("restore-unrecorded");
    let injection = case.evidence.join("injection");
    fs::create_dir(&injection).expect("injection/ is made");
    let identity = text_of(&case.operator, "identity");
    let stop = value(&format!(
        r#"{{"instance": "{TARGET}", "time": {}, "identity": "{identity}"}}"#,
        kestrike_tools::json::text(&Value::Float(START + 1.0))
    ));
    write_json(
        &injection.join("stop.json"),
        &merged(&stop, &[("note", string("x"))]),
    );
    case.assert_restore_refused(None, "injection/stop.json holds the keys");
    replace_mark(&injection, "stop.json", &stop);
    case.assert_restore_refused(None, "neither stopped.json nor abort.json");
    fs::write(injection.join("stopped.json"), "{}").expect("stopped.json is written");
    match crate::host_stop_support::at_mut(&mut case.operator, &["instances"]) {
        Value::Array(instances) => instances.retain(|id| *id != string(TARGET)),
        other => panic!("{other:?} is the declared set"),
    }
    case.assert_restore_refused(None, "outside the declared set");
}

#[test]
fn restore_refuses_a_stopped_mark_that_does_not_show_the_stop() {
    let mut case = Case::new("restore-stopped");
    assert_eq!(case.run(), 0, "{}", case.output());
    case.start_target(0);
    let injection = case.evidence.join("injection");
    let stopped = case.marks()["stopped"].clone();
    let request = member(&stopped, "request").clone();
    let requested = time(&request);
    let at_the_request = case.scratch.0.join("stopped.json");
    write_json(
        &at_the_request,
        &merged(&stopped, &[("time", Value::Float(requested))]),
    );
    let stop = Request::checked(&request, &Text::from("injection/stop.json")).expect("a request");
    assert_eq!(
        check_stopped(
            &at_the_request,
            &stop,
            Number::from(requested),
            kestrike_tools::gameday::FILE_LIMIT
        )
        .expect("a read at the request's time, which is restore's start"),
        Number::from(requested)
    );
    let no_stop = "shows no stop of injection/stop.json's request";
    let now = case.plane.borrow().wall();
    let rows: [StoppedRow<'_>; 6] = [
        ("a malformed mark", None, "refused: "),
        (
            "a report of another request",
            Some((
                "request",
                merged(&request, &[("time", Value::Float(START))]),
            )),
            no_stop,
        ),
        (
            "a report of another state",
            Some(("state", string("stopping"))),
            no_stop,
        ),
        (
            "a report of another instance",
            Some(("instance", string("i-h2"))),
            no_stop,
        ),
        (
            "a report read before the request",
            Some(("time", Value::Float(requested - 1.0))),
            no_stop,
        ),
        (
            "a report read after restore's start",
            Some(("time", Value::Float(now + 1.0))),
            "after restore's start",
        ),
    ];
    for (name, change, reason) in rows {
        let new = change.map_or_else(|| value("{}"), |change| merged(&stopped, &[change]));
        replace_mark(&injection, "stopped.json", &new);
        let seen = case.output().len();
        case.assert_restore_refused(None, reason);
        assert!(case.output().len() > seen, "{name}");
    }
}

#[test]
fn restore_refuses_an_abort_before_the_stop_and_a_package_or_caller_other_than_the_approvals() {
    let mut case = Case::new("restore-identity");
    let (path, review) = case.aborted_run();
    let injection = case.evidence.join("injection");
    let abort = case.marks()["abort"].clone();
    replace_mark(
        &injection,
        "abort.json",
        &merged(&abort, &[("time", Value::Float(START))]),
    );
    reviewed_again(&path, &review, &injection.join("abort.json"));
    case.assert_restore_refused(Some(&path), "dated before the stop it would close");
    set(
        &mut case.operator,
        &["approval", "package_sha256"],
        string(&"0".repeat(64)),
    );
    case.assert_restore_refused(Some(&path), "another package than the approval's");
    let mut case = Case::new("restore-caller");
    assert_eq!(case.run(), 0, "{}", case.output());
    case.start_target(0);
    case.plane.borrow_mut().arn =
        "arn:aws:sts::account:assumed-role/another-role/gd2-run".to_owned();
    assert_eq!(case.restore(None), 2, "{}", case.output());
    assert_eq!(case.ops().last().map(String::as_str), Some(CALLER));
    assert!(!case.marks().contains_key("restoration"));
}

#[test]
fn restore_after_an_abort_checks_a_stopped_mark_that_stands() {
    let mut case = Case::new("restore-stopped-abort");
    case.faulted(flip_first_guardrail(), false);
    assert_eq!(case.run(), 1, "{}", case.output());
    case.start_target(0);
    let injection = case.evidence.join("injection");
    case.assert_restore_refused(None, "an abort stands: restore needs --reviewed");
    replace_mark(&injection, "stopped.json", &value("{}"));
    let path = case.scratch.0.join("reviewed.json");
    write_json(&path, &case.review());
    case.assert_restore_refused(Some(&path), "refused: ");
}

#[test]
fn a_restoration_reaches_a_stopped_report_dated_after_the_abort_mark() {
    let mut case = Case::new("restore-reaches");
    case.plane.borrow_mut().call_seconds = 0.25;
    case.faulted(flip_first_guardrail(), false);
    assert_eq!(case.run(), 1, "{}", case.output());
    let injection = case.evidence.join("injection");
    let marks = case.marks();
    let (stop_at, stopped_at) = (time(&marks["stop"]), time(&marks["stopped"]));
    assert!(stop_at < stopped_at);
    replace_mark(
        &injection,
        "abort.json",
        &merged(&marks["abort"], &[("time", Value::Float(stop_at))]),
    );
    case.start_target(0);
    case.plane
        .borrow_mut()
        .instances
        .get_mut(TARGET)
        .expect("the target")
        .launched = stopped_at - SKEW;
    let path = case.scratch.0.join("reviewed.json");
    write_json(&path, &case.review());
    assert_eq!(case.restore(Some(&path)), 0, "{}", case.output());
    case.keep("restore-reaches");
    assert_eq!(time(&case.marks()["restoration"]), stopped_at);
}

#[test]
fn restore_refuses_a_stop_mark_of_another_instance_or_identity_than_the_approvals() {
    for (key, other) in [("instance", "i-h2"), ("identity", "")] {
        let mut case = Case::new("restore-another");
        assert_eq!(case.run(), 0, "{}", case.output());
        let injection = case.evidence.join("injection");
        let marks = case.marks();
        let other = if other.is_empty() {
            format!("{}-2", text_of(&case.operator, "identity"))
        } else {
            other.to_owned()
        };
        let stop = merged(&marks["stop"], &[(key, string(&other))]);
        let stopped = merged(
            &marks["stopped"],
            &[
                ("instance", member(&stop, "instance").clone()),
                ("request", stop.clone()),
            ],
        );
        replace_mark(&injection, "stop.json", &stop);
        replace_mark(&injection, "stopped.json", &stopped);
        case.assert_restore_refused(None, "another instance or identity than the approval's");
    }
}

#[test]
fn restore_refuses_a_linked_evidence_root_or_injection_directory() {
    let mut case = Case::new("restore-linked");
    assert_eq!(case.run(), 0, "{}", case.output());
    case.start_target(0);
    let real = case.scratch.0.join("real");
    fs::rename(&case.evidence, &real).expect("the evidence directory is moved aside");
    let before = listing(&real);
    for name in ["root", "injection"] {
        if fs::symlink_metadata(&case.evidence).is_ok_and(|found| found.file_type().is_symlink()) {
            fs::remove_file(&case.evidence).expect("the link is removed");
        }
        if name == "root" {
            symlink(&real, &case.evidence).expect("the root is linked");
        } else {
            fs::create_dir(&case.evidence).expect("the root is made");
            symlink(real.join("injection"), case.evidence.join("injection"))
                .expect("injection/ is linked");
        }
        let (start, seen) = (case.log().len(), case.output().len());
        assert_eq!(case.restore(None), 2, "{name}: {}", case.output());
        assert!(case.output()[seen..].contains("is no directory"), "{name}");
        assert_eq!(case.ops()[start..], [] as [String; 0], "{name}");
        assert_eq!(listing(&real), before, "{name}");
    }
}

#[test]
fn a_signal_during_the_restoration_write_keeps_its_exit_0() {
    let mut case = Case::new("restore-signal-write");
    assert_eq!(case.run(), 0, "{}", case.output());
    case.start_target(0);
    case.signal_at(Signal::Terminate, |step| links(step, "restoration.json"));
    assert_eq!(case.restore(None), 0, "{}", case.output());
    assert!(case.marks().contains_key("restoration"));
}

fn delivering(case: &Case, signal: Signal) -> Action {
    let delivered = case.delivered;
    Action::Hook(Box::new(move |state: &mut State| {
        delivered.deliver(signal);
        state.interrupt = true;
        Action::Answer
    }))
}

#[test]
fn a_signal_before_or_during_the_poll_ends_restore_with_exit_1_and_no_mark() {
    for (name, op, signal) in [
        ("during the caller's read", CALLER, Signal::Terminate),
        ("during a status read", STATUS, Signal::Hangup),
        ("during the record read", RECORD, Signal::Interrupt),
    ] {
        let mut case = Case::new("restore-signal-poll");
        assert_eq!(case.run(), 0, "{}", case.output());
        case.start_target(3);
        let mut planted = Some(delivering(&case, signal));
        case.plane.borrow_mut().fault =
            Some(Box::new(
                move |_, called| {
                    if called == op { planted.take() } else { None }
                },
            ));
        assert_eq!(case.restore(None), 1, "{name}: {}", case.output());
        let line = format!("signal {}: the restoration is unwritten", signal.name());
        assert!(case.output().contains(&line), "{name}: {}", case.output());
        assert_eq!(case.after_fault(), Vec::<String>::new(), "{name}");
        assert!(!case.marks().contains_key("restoration"), "{name}");
    }
}

#[test]
fn a_signal_during_restores_checks_ends_it_before_any_call() {
    for name in [
        "ahead of the entry",
        "at the lookup ahead of the stopped mark's check",
    ] {
        let mut case = Case::new("restore-signal-checks");
        assert_eq!(case.run(), 0, "{}", case.output());
        case.start_target(0);
        if name == "ahead of the entry" {
            case.delivered.deliver(Signal::Terminate);
        } else {
            let mut lookups = 0;
            case.signal_at(Signal::Terminate, move |step| {
                lookups += usize::from(matches!(step, Step::Lstat(_)));
                lookups == 4
            });
        }
        let start = case.log().len();
        assert_eq!(case.restore(None), 1, "{name}: {}", case.output());
        assert!(
            case.output()
                .contains("host-stop-controller: signal SIGTERM: the restoration is unwritten: no status read was made\n"),
            "{name}: {}",
            case.output()
        );
        assert_eq!(case.ops()[start..], [] as [String; 0], "{name}");
        assert!(!case.marks().contains_key("restoration"), "{name}");
    }
}

#[test]
fn a_restoration_whose_directory_sync_fails_is_removed_and_can_run_again() {
    let mut case = Case::new("restore-sync");
    assert_eq!(case.run(), 0, "{}", case.output());
    case.start_target(0);
    case.fail_once(libc::EIO, |step| matches!(step, Step::FsyncDirectory(_)));
    assert_eq!(case.restore(None), 1, "{}", case.output());
    let removed = format!(
        "host-stop-controller: {} cannot be synced, so the mark is removed: Input/output error\n",
        case.evidence.join("injection/restoration.json").display()
    );
    assert!(case.stderr().contains(&removed), "{}", case.stderr());
    assert!(!case.marks().contains_key("restoration"));
    case.start_target(0);
    assert_eq!(case.restore(None), 0, "{}", case.output());
    assert!(case.marks().contains_key("restoration"));
}

type When = fn(&Step<'_>) -> bool;

#[test]
fn a_restoration_that_fails_before_its_link_is_unwritten_with_exit_1_and_can_run_again() {
    let mut case = Case::new("restore-unlinked");
    assert_eq!(case.run(), 0, "{}", case.output());
    let rows: [(&str, When, i32, &str); 3] = [
        (
            "its unnamed file cannot be made",
            |step| matches!(step, Step::OpenUnnamed(path) if path.starts_with("/proc/self/fd")),
            libc::ENOSPC,
            "[Errno 28] No space left on device",
        ),
        (
            "its write fails",
            |step| matches!(step, Step::Write),
            libc::ENOSPC,
            "[Errno 28] No space left on device",
        ),
        (
            "its sync before the link fails",
            |step| matches!(step, Step::Fsync(_)),
            libc::EIO,
            "[Errno 5] Input/output error",
        ),
    ];
    for (name, when, code, shown) in rows {
        case.start_target(0);
        let seen = case.stderr().len();
        case.fail_once(code, when);
        assert_eq!(case.restore(None), 1, "{name}: {}", case.output());
        let line = format!("host-stop-controller: restoration.json is unwritten: {shown}\n");
        assert_eq!(case.stderr()[seen..], line, "{name}");
        assert!(!case.marks().contains_key("restoration"), "{name}");
    }
    case.start_target(0);
    assert_eq!(case.restore(None), 0, "{}", case.output());
    assert!(case.marks().contains_key("restoration"));
}

#[test]
fn a_review_with_no_abort_is_refused() {
    let mut case = Case::new("restore-no-abort");
    assert_eq!(case.run(), 0, "{}", case.output());
    let path = case.scratch.write("reviewed.json", b"{}");
    case.assert_restore_refused(Some(&path), "no abort stands");
}

#[test]
fn a_target_never_shown_ready_ends_restore_with_exit_1_and_no_mark() {
    let mut case = Case::new("restore-never");
    assert_eq!(case.run(), 0, "{}", case.output());
    let stopping = |mut reply: Value| {
        if let Value::Object(reply) = &mut reply
            && let Some(Value::Array(rows)) = reply.get_mut("InstanceStatuses")
        {
            for row in rows {
                if let Value::Object(row) = row {
                    row.insert(
                        "InstanceState",
                        value(r#"{"Code": 64, "Name": "stopping"}"#),
                    );
                    row.insert("InstanceStatus", value(r#"{"Status": "ok"}"#));
                    row.insert("SystemStatus", value(r#"{"Status": "ok"}"#));
                }
            }
        }
        reply
    };
    {
        let mut plane = case.plane.borrow_mut();
        let target = plane.instances.get_mut(TARGET).expect("the target");
        target.state = "running".to_owned();
        target.checks = "impaired".to_owned();
        plane.stopping = None;
        plane.script(STATUS, vec![Action::Lose]);
        let alternating: Vec<Shape> = (0..200)
            .map(|n| {
                if n % 2 == 1 {
                    Box::new(stopping) as Shape
                } else {
                    Box::new(|reply| reply) as Shape
                }
            })
            .collect();
        plane.shape(STATUS, alternating);
    }
    let begin = case.plane.borrow().t;
    assert_eq!(case.restore(None), 1, "{}", case.output());
    assert!(!case.marks().contains_key("restoration"));
    let deadline = operator_seconds(&case, "deadline_seconds");
    assert!(case.plane.borrow().t <= begin + deadline + 1.0);
    assert!(
        case.output()
            .contains("the target reads {'state': 'stopping', 'instance': 'ok', 'system': 'ok'}"),
        "{}",
        case.output()
    );
}

#[test]
fn a_ready_read_dated_before_restores_start_writes_no_restoration() {
    let mut case = Case::new("restore-stepped");
    assert_eq!(case.run(), 0, "{}", case.output());
    case.start_target(0);
    shorten_bounds(&mut case, 10);
    let mut planted = Some(Action::Hook(Box::new(|state: &mut State| {
        state.step -= 3600.0;
        Action::Answer
    })));
    case.plane.borrow_mut().fault = Some(Box::new(move |_, called| {
        if called == CALLER {
            planted.take()
        } else {
            None
        }
    }));
    let start = case.log().len();
    assert_eq!(case.restore(None), 1, "{}", case.output());
    assert_eq!(case.ops()[start..], [CALLER, STATUS, STATUS]);
    assert!(!case.marks().contains_key("restoration"));
    assert!(
        case.output().contains("before restore's start"),
        "{}",
        case.output()
    );
    case.plane.borrow_mut().step = 0.0;
    case.start_target(0);
    assert_eq!(case.restore(None), 0, "{}", case.output());
    let marks = case.marks();
    assert!(time(&marks["restoration"]) >= time(&marks["stopped"]));
}

#[test]
fn restore_refuses_a_mark_whose_lookup_fails() {
    let mut case = Case::new("restore-lookup");
    case.faulted(flip_first_guardrail(), false);
    assert_eq!(case.run(), 1, "{}", case.output());
    case.start_target(0);
    let names: Vec<String> = case.marks().keys().cloned().collect();
    assert_eq!(names, ["abort", "roles", "stop", "stopped"]);
    for (lookup, name) in [(1, "restoration"), (2, "stopped"), (3, "abort")] {
        let mut seen = 0;
        let mut failed = false;
        case.plant(Box::new(move |_, step| {
            seen += usize::from(matches!(step, Step::Lstat(_)));
            (!failed && seen == lookup).then(|| {
                failed = true;
                errno(libc::EIO)
            })
        }));
        case.assert_restore_refused(None, &format!("injection/{name}.json cannot be looked up"));
    }
}

#[test]
fn a_restore_during_the_observation_is_refused() {
    let mut case = Case::new("restore-observation");
    let refusals = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let (operator, catalog, evidence) = (
        case.write_operator(),
        case.catalog.clone(),
        case.evidence.clone(),
    );
    let kept = std::rc::Rc::clone(&refusals);
    case.faulted(
        Action::Hook(Box::new(move |_| {
            kept.borrow_mut()
                .push(restore_alone(&operator, &catalog, &evidence, None));
            Action::Answer
        })),
        false,
    );
    assert_eq!(case.run(), 0, "{}", case.output());
    let refusals = refusals.borrow();
    assert_eq!(refusals.len(), 1);
    let (code, output, ops) = &refusals[0];
    assert_eq!(*code, 2, "{output}");
    assert!(
        output.contains("is held by a run, restore or seal that has not ended"),
        "{output}"
    );
    assert_eq!(*ops, Vec::<String>::new());
}

#[test]
fn a_restore_with_no_aws_on_its_path_exits_2_at_the_caller_check() {
    let mut case = Case::new("restore-no-aws");
    assert_eq!(case.run(), 0, "{}", case.output());
    let empty = case.scratch.0.join("empty");
    fs::create_dir(&empty).expect("the directory is made");
    let env = vec![(std::ffi::OsString::from("PATH"), empty.into_os_string())];
    let command = kestrike_tools::host_stop_controller::Command::Restore {
        operator: case.write_operator(),
        evidence: case.evidence.clone().into_os_string(),
        reviewed: None,
    };
    let delivered: &'static kestrike_tools::host_stop::Delivered =
        Box::leak(Box::new(kestrike_tools::host_stop::Delivered::new()));
    let mut record = kestrike_tools::host_stop::Record::new(delivered);
    let output = super::Output::default();
    let (mut out, mut err) = (output.clone(), output.clone());
    let mut seam = System;
    let top = crate::host_stop_support::tree();
    let mut cx = kestrike_tools::host_stop_controller::Context {
        seam: &mut seam,
        files: &kestrike_tools::host_stop::Disk,
        record: &mut record,
        env: &env,
        out: &mut out,
        err: &mut err,
        catalog: &case.catalog,
        top: &top,
        file_limit: kestrike_tools::gameday::FILE_LIMIT,
        mark_limit: kestrike_tools::gameday::FILE_LIMIT,
    };
    let code = kestrike_tools::host_stop_controller::entry(&command, &mut cx);
    let shown = output.text();
    assert_eq!(code, 2, "{shown}");
    assert_eq!(
        shown,
        "host-stop-controller: refused: the caller is unknown: sts get-caller-identity gave no \
         answer: no directory of PATH holds an executable aws; nothing written\n"
    );
    assert!(!case.marks().contains_key("restoration"));
}
