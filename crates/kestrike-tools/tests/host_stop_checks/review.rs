//! The marks `restore` reads, through `check_reviewed` and `check_stopped`: each state of a reviewed
//! record, of its abort mark and of `stopped.json`, refused with the controller's sentence, and the
//! values an admitted one returns.

use std::path::PathBuf;

use kestrike_tools::gameday::{FILE_LIMIT, Refusal};
use kestrike_tools::host_stop::{
    Number, Request, check_reviewed, check_stopped, encoded, steps_tail,
};
use kestrike_tools::json::{Object, Text, Value};
use kestrike_tools::python::hexdigest;

use crate::host_stop_support::{Scratch, gd2_mut, json, met, set, value};

/// The stop request the marks close.
const STOP: &str = r#"{"instance": "i-h1", "time": 105.0, "identity": "arn:aws:sts::account:assumed-role/gameday-operator/gd2-run"}"#;
fn stop() -> Request {
    Request::checked(&value(STOP), &Text::from("injection/stop.json"))
        .expect("the request is on the layout")
}

/// Restore's start.
const NOW: f64 = 200.0;

/// GD-2's restoration steps in the committed catalog.
fn steps() -> String {
    let mut catalog = met();
    let gd2 = gd2_mut(&mut catalog);
    let Some(Value::Object(restoration)) = gd2.get("restoration") else {
        panic!("GD-2 has its restoration")
    };
    let Some(Value::String(steps)) = restoration.get("steps") else {
        panic!("its steps")
    };
    steps.to_string()
}

fn abort_mark() -> Value {
    let detail = format!(
        "the stop request was sent and answered; the stop was not shown{}",
        steps_tail(&steps())
    );
    let mut abort = value(r#"{"cause": "stop-not-shown", "guardrail": null, "time": 110.25}"#);
    set(&mut abort, &["detail"], Value::String(Text::from(detail)));
    abort
}

/// Where a case puts its record.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Place {
    Outside,
    Inside,
    /// The record is not given.
    None,
    /// The record's path names no file.
    NoRecord,
    /// The abort mark's path names no file.
    NoAbort,
}

/// The outcome of `check_reviewed` with the abort mark changed by `abort` and the record by
/// `review`, the record kept at `place`, with the record's digest the outcome must name.
fn reviewed(
    abort: fn(&mut Value),
    review: fn(&mut Value),
    place: Place,
) -> (Result<(String, Number), Refusal>, String) {
    let scratch = Scratch::new("reviewed");
    let injection = scratch.0.join("evidence/injection");
    std::fs::create_dir_all(&injection).expect("the evidence directory is made");
    let mut mark = abort_mark();
    abort(&mut mark);
    let abort_path = injection.join("abort.json");
    let data = encoded(&mark, &Text::from("abort.json"), FILE_LIMIT).expect("the mark encodes");
    std::fs::write(&abort_path, &data).expect("the mark is written");
    let mut record = value(r#"{"reviewer": "the operator", "time": 150.5}"#);
    set(
        &mut record,
        &["abort_sha256"],
        Value::String(Text::from(hexdigest(&data))),
    );
    set(&mut record, &["steps"], Value::String(Text::from(steps())));
    review(&mut record);
    let path: PathBuf = match place {
        Place::Inside => scratch.0.join("evidence/reviewed.json"),
        _ => scratch.0.join("reviewed.json"),
    };
    let raw = json(&record).into_bytes();
    if place != Place::NoRecord {
        std::fs::write(&path, &raw).expect("the record is written");
    }
    if place == Place::NoAbort {
        std::fs::remove_file(&abort_path).expect("the mark goes");
    }
    let given = (place != Place::None).then_some(path.as_path());
    let found = check_reviewed(
        given,
        &abort_path,
        &scratch.0.join("evidence"),
        Number::from(NOW),
        &stop(),
        FILE_LIMIT,
    );
    (found, hexdigest(&raw))
}

fn same(_: &mut Value) {}

fn detail(abort: &mut Value, change: fn(&str) -> String) {
    let Value::Object(mark) = &*abort else {
        panic!("a mark is an object")
    };
    let Some(Value::String(old)) = mark.get("detail") else {
        panic!("the mark has its detail")
    };
    let new = change(&old.to_string());
    set(abort, &["detail"], Value::String(Text::from(new)));
}

const OTHER: &str =
    "; restoration steps sha256 b5a9bbc6577f2b7290f9d1675004d5caba552ad74256233d6b4b380b73d4378c";

/// The sentence that refuses a detail not ending with a steps digest.
const UNPINNED: &str = "injection/abort.json's detail does not end with the digest of the restoration steps its run \
                        printed, so no review can be compared with it";
/// The sentence that refuses a review of other steps.
const OTHERS: &str = "the reviewed record names steps other than those the aborted run printed";
/// The sentence that refuses a guardrail off its cause.
const GUARDRAIL: &str = "injection/abort.json names a guardrail without cause guardrail, or none with it, which the \
                         judge refuses";

type Refused = (
    &'static str,
    fn(&mut Value),
    fn(&mut Value),
    Place,
    &'static str,
);

/// A record admitted: its name, the changes of the mark and of the record, and the abort's time.
type Admitted = (&'static str, fn(&mut Value), fn(&mut Value), &'static str);
/// A `stopped.json` row: its name, the member it changes and its new value, restore's start and the
/// time or the sentence.
type Stopped = (
    &'static str,
    &'static str,
    &'static str,
    f64,
    Result<&'static str, &'static str>,
);

const REFUSED: &[Refused] = &[
    (
        "no reviewed record",
        same,
        same,
        Place::None,
        "an abort stands: restore needs --reviewed, the operator's record that GD-2's restoration steps were done",
    ),
    (
        "a review kept inside DIR",
        same,
        same,
        Place::Inside,
        "the reviewed record lies inside the evidence directory, where the judge admits no file outside its \
      layout; keep it outside",
    ),
    (
        "a missing review",
        same,
        same,
        Place::NoRecord,
        "the reviewed record cannot be read: No such file or directory",
    ),
    (
        "a missing abort",
        same,
        same,
        Place::NoAbort,
        "abort.json cannot be read: No such file or directory",
    ),
    (
        "another abort",
        same,
        |r| {
            set(
                r,
                &["abort_sha256"],
                Value::String(Text::from("0".repeat(64))),
            )
        },
        Place::Outside,
        "the reviewed record names another abort",
    ),
    (
        "other steps",
        same,
        |r| set(r, &["steps"], value(r#""restart it""#)),
        Place::Outside,
        OTHERS,
    ),
    (
        "an extra key",
        same,
        |r| set(r, &["note"], value(r#""x""#)),
        Place::Outside,
        "the reviewed record holds the keys ['abort_sha256', 'note', 'reviewer', 'steps', 'time'], not \
      ['abort_sha256', 'reviewer', 'steps', 'time']",
    ),
    (
        "a review dated before the abort",
        same,
        |r| set(r, &["time"], value("110")),
        Place::Outside,
        "the reviewed record is dated before the abort it reviews",
    ),
    (
        "a review dated after restore's start",
        same,
        |r| set(r, &["time"], value("200.5")),
        Place::Outside,
        "the reviewed record is dated 200.5, after restore's start 200.0",
    ),
    (
        "an abort off the layout",
        |a| set(a, &["note"], value(r#""x""#)),
        same,
        Place::Outside,
        "injection/abort.json holds the keys ['cause', 'detail', 'guardrail', 'note', 'time'], not ['cause', \
      'detail', 'guardrail', 'time']",
    ),
    (
        "cause guardrail with no guardrail",
        |a| set(a, &["cause"], value(r#""guardrail""#)),
        same,
        Place::Outside,
        GUARDRAIL,
    ),
    (
        "a guardrail with another cause",
        |a| set(a, &["guardrail"], value(r#""any generation change""#)),
        same,
        Place::Outside,
        GUARDRAIL,
    ),
    (
        "no detail",
        |a| set(a, &["detail"], Value::Null),
        same,
        Place::Outside,
        UNPINNED,
    ),
    (
        "a detail without the digest",
        |a| detail(a, |d| d[..d.len() - 91].to_owned()),
        same,
        Place::Outside,
        UNPINNED,
    ),
    (
        "the digest before the detail's end",
        |a| detail(a, |d| format!("{d} and more")),
        same,
        Place::Outside,
        UNPINNED,
    ),
    (
        "a digest cut short",
        |a| detail(a, |d| d[..d.len() - 1].to_owned()),
        same,
        Place::Outside,
        UNPINNED,
    ),
    (
        "a digest in capitals",
        |a| {
            detail(a, |d| {
                format!("{}{}", &d[..d.len() - 64], d[d.len() - 64..].to_uppercase())
            })
        },
        same,
        Place::Outside,
        UNPINNED,
    ),
    (
        "the digest of other steps",
        |a| detail(a, |d| format!("{}{OTHER}", &d[..d.len() - 91])),
        same,
        Place::Outside,
        OTHERS,
    ),
    (
        "the digest of other steps after the run's",
        |a| detail(a, |d| format!("{d}{OTHER}")),
        same,
        Place::Outside,
        OTHERS,
    ),
    (
        "an abort dated before the stop",
        |a| set(a, &["time"], value("104.5")),
        |r| set(r, &["time"], value("150")),
        Place::Outside,
        "injection/abort.json is dated before the stop it would close",
    ),
];

/// A review needs the record of the abort that stands: each other record, abort mark or place is
/// refused with its sentence; an admitted record returns its digest and the abort's time, of the kind
/// the mark writes it, an integer equal to the stop's float time included.
#[test]
fn after_an_abort_restore_needs_the_reviewed_record_of_that_abort() {
    for &(name, abort, review, place, sentence) in REFUSED {
        let (found, _) = reviewed(abort, review, place);
        let refusal = found.err().unwrap_or_else(|| panic!("{name} is refused"));
        assert_eq!(*refusal.message(), sentence, "{name}");
    }
    let admitted: [Admitted; 4] = [
        ("admitted", same, same, "110.25"),
        (
            "an integer abort time equal to the stop's",
            |a| set(a, &["time"], value("105")),
            |r| set(r, &["time"], value("105")),
            "105",
        ),
        (
            "a review at restore's start",
            same,
            |r| set(r, &["time"], value("200")),
            "110.25",
        ),
        (
            "a detail that is the digest alone",
            |a| detail(a, |d| d[d.len() - 91..].to_owned()),
            same,
            "110.25",
        ),
    ];
    for (name, abort, review, time) in admitted {
        let (found, digest) = reviewed(abort, review, Place::Outside);
        let (sha256, aborted) = found.unwrap_or_else(|refusal| panic!("{name}: {refusal}"));
        assert_eq!(
            (sha256, aborted.to_string()),
            (digest, time.to_owned()),
            "{name}"
        );
    }
}

/// `stopped.json` shows the stop only as a report of the stop's instance, state `stopped`, the
/// request whole and a time from the request's to restore's start; a request time of another kind and
/// one value is the same request.
#[test]
fn restore_refuses_a_stopped_mark_that_does_not_show_the_stop() {
    let no_stop =
        "injection/stopped.json shows no stop of injection/stop.json's request read at or after it";
    let rows: [Stopped; 10] = [
        ("admitted", "time", "108.5", NOW, Ok("108.5")),
        (
            "a read at the request's time, which is restore's start",
            "time",
            "105.0",
            105.0,
            Ok("105.0"),
        ),
        (
            "a request time of another kind and one value",
            "request/time",
            "105",
            NOW,
            Ok("108.5"),
        ),
        (
            "a malformed mark",
            "",
            "",
            NOW,
            Err(
                "injection/stopped.json holds the keys [], not ['instance', 'request', 'state', 'time']",
            ),
        ),
        (
            "a report of another request",
            "request/time",
            "104.0",
            NOW,
            Err(no_stop),
        ),
        (
            "a report of another identity",
            "request/identity",
            r#""arn:other""#,
            NOW,
            Err(no_stop),
        ),
        (
            "a report of another state",
            "state",
            r#""stopping""#,
            NOW,
            Err(no_stop),
        ),
        (
            "a report of another instance",
            "instance",
            r#""i-h2""#,
            NOW,
            Err(no_stop),
        ),
        (
            "a report read before the request",
            "time",
            "104",
            NOW,
            Err(no_stop),
        ),
        (
            "a report read after restore's start",
            "time",
            "201",
            NOW,
            Err("injection/stopped.json is dated 201, after restore's start 200.0"),
        ),
    ];
    let stop = stop();
    for (name, key, new, now, expected) in rows {
        let scratch = Scratch::new("stopped");
        let mut mark = value(r#"{"instance": "i-h1", "state": "stopped", "time": 108.5}"#);
        set(&mut mark, &["request"], value(STOP));
        if key.is_empty() {
            mark = Value::Object(Object::new());
        } else {
            set(&mut mark, &key.split('/').collect::<Vec<_>>(), value(new));
        }
        let path = scratch.write("stopped.json", json(&mark).as_bytes());
        match (
            check_stopped(&path, &stop, Number::from(now), FILE_LIMIT),
            expected,
        ) {
            (Ok(time), Ok(expected)) => assert_eq!(time.to_string(), expected, "{name}"),
            (Err(refusal), Err(expected)) => assert_eq!(*refusal.message(), expected, "{name}"),
            (got, expected) => panic!("{name}: {got:?} against {expected:?}"),
        }
    }
}

/// A record that reaches the evidence directory through a link is inside it, as is one inside an
/// evidence directory named through a link; a record whose path is a link loop cannot be resolved; a
/// record with a repeated key, a named pipe, a malformed abort mark and an unreadable or malformed
/// `stopped.json` are refused with their sentences, the pipe without waiting for a writer.
#[test]
fn an_input_that_is_a_named_pipe_or_a_link_is_refused_without_waiting() {
    use std::os::unix::fs::symlink;
    let scratch = Scratch::new("review-links");
    let evidence = scratch.0.join("evidence");
    let injection = evidence.join("injection");
    std::fs::create_dir_all(&injection).expect("the evidence directory is made");
    let data = encoded(&abort_mark(), &Text::from("abort.json"), FILE_LIMIT).expect("encodes");
    let abort_path = injection.join("abort.json");
    std::fs::write(&abort_path, &data).expect("the mark is written");
    let mut record = value(r#"{"reviewer": "the operator", "time": 150.5}"#);
    set(
        &mut record,
        &["abort_sha256"],
        Value::String(Text::from(hexdigest(&data))),
    );
    set(&mut record, &["steps"], Value::String(Text::from(steps())));
    let inside = evidence.join("reviewed.json");
    std::fs::write(&inside, json(&record)).expect("the record is written");
    let outside = scratch.0.join("reviewed.json");
    symlink(&inside, &outside).expect("the link is made");
    let linked_evidence = scratch.0.join("linked");
    symlink(&evidence, &linked_evidence).expect("the link is made");
    let loop_a = scratch.0.join("loop-a");
    symlink(scratch.0.join("loop-b"), &loop_a).expect("the link is made");
    symlink(&loop_a, scratch.0.join("loop-b")).expect("the link is made");
    let repeated = scratch.write("repeated.json", br#"{"reviewer": "a", "reviewer": "b"}"#);
    let pipe = scratch.0.join("pipe.json");
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&pipe)
            .status()
            .is_ok_and(|status| status.success()),
        "the pipe is made"
    );
    let within = "the reviewed record lies inside the evidence directory, where the judge admits no file \
                  outside its layout; keep it outside";
    let rows: [(&str, &std::path::Path, &std::path::Path, &str); 5] = [
        (
            "a record linked into the evidence directory",
            &outside,
            &evidence,
            within,
        ),
        (
            "an evidence directory named through a link",
            &inside,
            &linked_evidence,
            within,
        ),
        (
            "a record whose path is a link loop",
            &loop_a,
            &evidence,
            "the reviewed record cannot be resolved: symlink loop from ",
        ),
        (
            "a repeated key",
            &repeated,
            &evidence,
            "the reviewed record is not strict JSON: an object repeats a key",
        ),
        (
            "a named pipe",
            &pipe,
            &evidence,
            "the reviewed record is no regular file",
        ),
    ];
    for (name, path, root, sentence) in rows {
        let refusal = check_reviewed(
            Some(path),
            &abort_path,
            root,
            Number::from(NOW),
            &stop(),
            FILE_LIMIT,
        )
        .expect_err(name);
        assert!(
            refusal.message().to_string().starts_with(sentence),
            "{name}: {refusal}"
        );
        assert!(
            name.contains("loop") || *refusal.message() == sentence,
            "{name}: {refusal}"
        );
    }
    std::fs::write(&abort_path, b"{").expect("the mark is rewritten");
    let away = scratch.write("away.json", json(&record).as_bytes());
    let refusal = check_reviewed(
        Some(&away),
        &abort_path,
        &evidence,
        Number::from(NOW),
        &stop(),
        FILE_LIMIT,
    )
    .expect_err("a malformed abort mark");
    assert_eq!(
        *refusal.message(),
        "injection/abort.json is not strict JSON: expected a key at byte 1"
    );
    let stopped = injection.join("stopped.json");
    let refusal =
        check_stopped(&stopped, &stop(), Number::from(NOW), FILE_LIMIT).expect_err("no mark");
    assert_eq!(
        *refusal.message(),
        "injection/stopped.json cannot be read: No such file or directory"
    );
    std::fs::write(&stopped, b"not json").expect("the mark is written");
    let refusal =
        check_stopped(&stopped, &stop(), Number::from(NOW), FILE_LIMIT).expect_err("no JSON");
    assert_eq!(
        *refusal.message(),
        "injection/stopped.json is not strict JSON: expected a value at byte 0"
    );
}
