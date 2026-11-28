//! The abort path before the stop request: the reach condition, the alarms, the check before the
//! stop leaves, a stop request that never leaves, and a failed stop mark. No case sends a stop
//! request.

use kestrike_tools::host_stop::{LIMIT_SECONDS, Number, SKEW_SECONDS};
use kestrike_tools::host_stop_controller::{Halt, Preflight};
use kestrike_tools::json::{Object, Value};

use super::plane::{ALARMS, Action, CALLER, STATUS, State, string};
use super::steps::{Step, errno, links};
use super::{Case, guardrails, member, set, text_of};
use crate::host_stop_support::{START, object, value};

fn number(text: &str) -> Value {
    value(text)
}

/// The caller's read ends one second after the run's start, which puts the snapshot's oldest time
/// exactly at its age bound: the snapshot is read, and the check before the stop finds it past the
/// bound, so the run aborts on reach with the roles mark dated at that time and no stop request.
#[test]
fn a_snapshot_exactly_at_its_age_bound_is_read_and_is_too_old_when_the_stop_would_leave() {
    let mut case = Case::new("age-bound");
    case.plane
        .borrow_mut()
        .script(CALLER, vec![Action::Delay(0.8)]);
    let oldest = START + 1.0 - 60.0;
    case.snapshot("shards.jsonl", |rows| {
        for row in rows.iter_mut() {
            set(row, &["time"], Value::Float(oldest));
        }
    });
    let found = case.assert_aborted(
        "reach",
        &["roles", "abort"],
        None,
        Some("passed its age bound"),
    );
    assert_eq!(member(&found["roles"], "time"), &Value::Float(oldest));
    assert!(case.stops().is_empty());
}

type Rows = fn(&mut Vec<Value>);

/// Each unmet reach condition ahead of the stop aborts on reach after the caller and the status
/// read, with the condition in the detail: too few shards stood by for or owned, an owned shard with
/// no standby or the target as its standby, a standby unhealthy, unreported, without a snapshot line
/// or outside the declared set.
#[test]
fn too_few_roles_or_an_unhealthy_or_unread_standby_aborts_on_reach_with_no_stop() {
    let changes: [(&str, Rows, &str); 5] = [
        (
            "shards.jsonl",
            |rows| set(&mut rows[3], &["standby"], string("h3")),
            "stands by for 0",
        ),
        (
            "shards.jsonl",
            |rows| set(&mut rows[0], &["standby"], Value::Null),
            "names no standby",
        ),
        (
            "hosts.jsonl",
            |rows| set(&mut rows[1], &["report", "healthy"], Value::Bool(false)),
            "reads running and unhealthy",
        ),
        (
            "hosts.jsonl",
            |rows| set(&mut rows[2], &["report"], Value::Null),
            "reads running and no report",
        ),
        (
            "hosts.jsonl",
            |rows| {
                rows.remove(2);
            },
            "has no instance state",
        ),
    ];
    for (file, change, detail) in changes {
        let mut case = Case::new("reach");
        case.snapshot(file, change);
        case.assert_aborted("reach", &["roles", "abort"], None, Some(detail));
        assert_eq!(case.ops(), [CALLER, STATUS]);
    }
    let mut case = Case::new("one-owned");
    case.repackage(|p| {
        let Value::Array(witness) = member(p, "witness").clone() else {
            panic!("the package lists witness keys")
        };
        set(p, &["witness"], Value::Array(witness[..1].to_vec()));
    });
    case.snapshot("shards.jsonl", |rows| {
        for i in [1, 2] {
            set(&mut rows[i], &["owner"], string("h4"));
        }
    });
    case.assert_aborted("reach", &["roles", "abort"], None, Some("owns 1 shards"));
    assert!(case.stops().is_empty());

    let mut case = Case::new("outside");
    let Value::Array(mut instances) = member(&case.operator, "instances").clone() else {
        panic!("declared instances")
    };
    instances.retain(|id| *id != string("i-h3"));
    set(&mut case.operator, &["instances"], Value::Array(instances));
    case.plane.borrow_mut().instances.remove("i-h3");
    let marks = case.assert_aborted("reach", &["roles", "abort"], None, Some("standby host h3"));
    assert!(
        object(member(&marks["roles"], "standbys").clone())
            .get("h3")
            .is_none()
    );
    assert!(case.stops().is_empty());

    let mut case = Case::new("self-standby");
    case.snapshot("shards.jsonl", |rows| {
        set(&mut rows[0], &["standby"], string("h1"))
    });
    let marks = case.assert_aborted(
        "reach",
        &["roles", "abort"],
        None,
        Some("names no standby other than the target"),
    );
    let standbys = object(member(&marks["roles"], "standbys").clone());
    let names: Vec<String> = standbys.iter().map(|(name, _)| name.to_string()).collect();
    assert_eq!(names, ["h2", "h3"]);
    assert!(case.stops().is_empty());
}

fn row(state: &mut State, name: &str, field: &str, new: Option<Value>) {
    state.row(name, field, new);
}

/// Applies `change` to each metric alarm row of the first alarm reply.
fn reshape(state: &mut State, change: fn(&mut Object, &mut Vec<Value>)) {
    state.shape(
        ALARMS,
        vec![Box::new(move |reply| {
            let mut reply = object(reply);
            let Some(Value::Array(mut rows)) = reply.remove("MetricAlarms") else {
                panic!("the reply lists metric alarms")
            };
            change(&mut reply, &mut rows);
            let mut shaped = Object::new();
            shaped.insert("MetricAlarms", Value::Array(rows));
            for (key, field) in reply.iter() {
                shaped.insert(key.clone(), field.clone());
            }
            Value::Object(shaped)
        })],
    );
}

fn each(rows: &mut [Value], key: &str, new: Value) {
    for row in rows {
        set(row, &[key], new.clone());
    }
}

/// Each alarm shown other than quiet before the stop, and each failed alarm read, aborts on the
/// guardrail it names with no stop request sent.
#[test]
fn an_alarm_not_quiet_or_unread_before_the_stop_aborts_with_no_stop() {
    type Change = Box<dyn Fn(&mut State)>;
    let rows: Vec<(&str, Change, usize, &str)> = vec![
        (
            "in ALARM",
            Box::new(|s| s.flip("gd2-guardrail-4", "ALARM")),
            3,
            "reads ALARM",
        ),
        (
            "without data",
            Box::new(|s| s.flip("gd2-guardrail-6", "INSUFFICIENT_DATA")),
            5,
            "reads INSUFFICIENT_DATA",
        ),
        (
            "unanswered",
            Box::new(|s| {
                s.alarms.remove("gd2-guardrail-8");
            }),
            7,
            "reads no answer",
        ),
        (
            "a lost reply",
            Box::new(|s| s.script(ALARMS, vec![Action::Lose])),
            0,
            "the alarms are unread",
        ),
        (
            "a refused read",
            Box::new(|s| s.script(ALARMS, vec![Action::Refuse])),
            0,
            "the alarms are unread",
        ),
        (
            "missing data read as not breaching",
            Box::new(|s| {
                row(
                    s,
                    "gd2-guardrail-3",
                    "TreatMissingData",
                    Some(string("notBreaching")),
                );
            }),
            2,
            "treats missing data as notBreaching",
        ),
        (
            "missing data ignored",
            Box::new(|s| {
                row(
                    s,
                    "gd2-guardrail-7",
                    "TreatMissingData",
                    Some(string("ignore")),
                );
            }),
            6,
            "treats missing data as ignore",
        ),
        (
            "missing data left to its default",
            Box::new(|s| {
                row(s, "gd2-guardrail-2", "TreatMissingData", None);
            }),
            1,
            "treats missing data as None",
        ),
        (
            "missing data stated as null",
            Box::new(|s| {
                reshape(s, |_, rows| {
                    for alarm in rows.iter_mut() {
                        if text_of(alarm, "AlarmName") == "gd2-guardrail-5" {
                            set(alarm, &["TreatMissingData"], Value::Null);
                        }
                    }
                })
            }),
            4,
            "treats missing data as None",
        ),
        (
            "an evaluation that is partial",
            Box::new(|s| {
                row(
                    s,
                    "gd2-guardrail-1",
                    "EvaluationState",
                    Some(string("PARTIAL_DATA")),
                );
            }),
            0,
            "evaluation state PARTIAL_DATA",
        ),
        (
            "an evaluation state of a kind not yet named",
            Box::new(|s| {
                row(
                    s,
                    "gd2-guardrail-2",
                    "EvaluationState",
                    Some(string("LATER")),
                );
            }),
            1,
            "evaluation state LATER",
        ),
        (
            "an evaluation state that is no text",
            Box::new(|s| {
                row(s, "gd2-guardrail-2", "EvaluationState", Some(number("3")));
            }),
            0,
            "EvaluationState is no str",
        ),
        (
            "a PromQL alarm",
            Box::new(|s| {
                row(
                    s,
                    "gd2-guardrail-6",
                    "EvaluationCriteria",
                    Some(value(r#"{"PromQLCriteria": {"Query": "up"}}"#)),
                );
            }),
            5,
            "a PromQL alarm",
        ),
        (
            "a Metrics Insights alarm",
            Box::new(|s| {
                row(
                    s,
                    "gd2-guardrail-8",
                    "Metrics",
                    Some(value(
                        r#"[{"Id": "q", "Expression": " select AVG(Errors) FROM SCHEMA(\"Kestrike/GameDay\", Host)"}]"#,
                    )),
                );
            }),
            7,
            "a metric query expression",
        ),
        (
            "a metric math sum",
            Box::new(|s| {
                row(
                    s,
                    "gd2-guardrail-3",
                    "Metrics",
                    Some(value(r#"[{"Id": "e", "Expression": "m1 + m2"}]"#)),
                );
            }),
            2,
            "a metric query expression",
        ),
        (
            "a FILL expression",
            Box::new(|s| {
                row(
                    s,
                    "gd2-guardrail-3",
                    "Metrics",
                    Some(value(r#"[{"Id": "e", "Expression": "FILL(m1, 0)"}]"#)),
                );
            }),
            2,
            "a metric query expression",
        ),
        (
            "a percentile that ignores a low sample count",
            Box::new(|s| {
                row(
                    s,
                    "gd2-guardrail-5",
                    "EvaluateLowSampleCountPercentile",
                    Some(string("ignore")),
                );
            }),
            4,
            "low sample count",
        ),
        (
            "an evaluation state stated as null",
            Box::new(|s| {
                reshape(s, |_, rows| {
                    each(rows, "EvaluationState", Value::Null);
                })
            }),
            0,
            "EvaluationState is no",
        ),
        (
            "an expression stated as null",
            Box::new(|s| {
                reshape(s, |_, rows| {
                    each(
                        rows,
                        "Metrics",
                        value(r#"[{"Id": "e", "Expression": null}]"#),
                    );
                })
            }),
            0,
            "Expression is no",
        ),
        (
            "a composite list stated as null",
            Box::new(|s| {
                reshape(s, |reply, _| {
                    reply.insert("CompositeAlarms", Value::Null);
                })
            }),
            0,
            "CompositeAlarms is no",
        ),
        (
            "a row with no transition timestamp",
            Box::new(|s| {
                row(s, "gd2-guardrail-4", "StateTransitionedTimestamp", None);
            }),
            0,
            "StateTransitionedTimestamp is no str",
        ),
        (
            "a composite alarm",
            Box::new(|s| {
                reshape(s, |reply, _| {
                    reply.insert(
                        "CompositeAlarms",
                        value(r#"[{"AlarmName": "gd2-guardrail-1", "StateValue": "OK"}]"#),
                    );
                })
            }),
            0,
            "composite alarm",
        ),
        (
            "an alarm named twice",
            Box::new(|s| {
                reshape(s, |_, rows| {
                    let mut first = rows[0].clone();
                    set(&mut first, &["StateValue"], string("ALARM"));
                    rows.insert(0, first);
                })
            }),
            0,
            "twice",
        ),
        (
            "an alarm not asked for",
            Box::new(|s| {
                reshape(s, |_, rows| {
                    rows.push(value(r#"{"AlarmName": "other", "StateValue": "OK"}"#));
                })
            }),
            0,
            "unasked",
        ),
        (
            "a partial alarm listing",
            Box::new(|s| {
                reshape(s, |reply, _| {
                    reply.insert("NextToken", string("t"));
                })
            }),
            0,
            "NextToken",
        ),
    ];
    assert_eq!(rows.len(), 25);
    let texts = guardrails();
    for (name, change, text, detail) in rows {
        let mut case = Case::new("alarm");
        change(&mut case.plane.borrow_mut());
        let found = case.assert_aborted(
            "guardrail",
            &["roles", "abort"],
            Some(&texts[text]),
            Some(detail),
        );
        assert!(case.stops().is_empty(), "{name}");
        assert!(
            text_of(&found["abort"], "detail").contains("no stop request was sent"),
            "{name}"
        );
    }
}

/// A hook on the first alarm read that sets the wall clock's step and delays the answer.
fn step_then(case: &mut Case, step: f64, delay: f64) {
    case.plane.borrow_mut().script(
        ALARMS,
        vec![Action::Hook(Box::new(move |state| {
            state.step = step;
            if delay == 0.0 {
                Action::Answer
            } else {
                Action::Delay(delay)
            }
        }))],
    );
}

/// Applies `change` to the plane's state at the link of the stop mark.
fn at_stop_link(case: &mut Case, change: fn(&mut State)) {
    case.plant(Box::new(move |state, step| {
        if links(step, "stop.json") {
            change(state);
        }
        None
    }));
}

/// Each check before the stop request that fails aborts before it: the snapshot's age on the
/// monotonic clock, during the stop mark's write and on a wall clock that steps forward or back; too
/// little time for the observation; the two clocks apart by more than the skew either way; an alarm
/// that fires during the stop mark's write; and exactly the observation and one poll left.
#[test]
fn a_stop_that_may_not_leave_aborts_before_the_request() {
    let mut case = Case::new("age-at-stop");
    case.plane
        .borrow_mut()
        .script(ALARMS, vec![Action::Delay(57.0)]);
    case.assert_aborted(
        "reach",
        &["roles", "abort"],
        None,
        Some("passed its age bound"),
    );
    assert!(case.stops().is_empty());

    let mut case = Case::new("age-during-mark");
    at_stop_link(&mut case, |state| state.t += 60.0);
    let found = case.assert_aborted(
        "reach",
        &["roles", "stop", "abort"],
        None,
        Some("no stop request was sent"),
    );
    assert!(case.stops().is_empty());
    assert!(text_of(&found["abort"], "detail").contains("passed its age bound"));

    let mut case = Case::new("too-little-time");
    set(&mut case.operator, &["deadline_seconds"], number("110"));
    set(
        &mut case.operator,
        &["snapshot_max_age_seconds"],
        number(&LIMIT_SECONDS.to_string()),
    );
    case.plane
        .borrow_mut()
        .script(CALLER, vec![Action::Delay(30.0)]);
    case.plane
        .borrow_mut()
        .script(ALARMS, vec![Action::Delay(40.0)]);
    case.assert_aborted(
        "deadline",
        &["roles", "abort"],
        None,
        Some("cannot hold the observation of 45 s"),
    );
    assert!(case.stops().is_empty());

    let skew = SKEW_SECONDS as f64;
    for (label, step, delay, cause, detail) in [
        ("suspend", 3600.0, 0.0, "reach", "passed its age bound"),
        (
            "ahead",
            skew + 5.0,
            0.0,
            "deadline",
            "apart from the monotonic clock",
        ),
        (
            "behind",
            -skew - 3.0,
            10.0,
            "deadline",
            "apart from the monotonic clock",
        ),
        ("behind-aged", -3.0, 57.0, "reach", "passed its age bound"),
    ] {
        let mut case = Case::new(label);
        step_then(&mut case, step, delay);
        case.assert_aborted(cause, &["roles", "abort"], None, Some(detail));
        assert!(case.stops().is_empty(), "{label}");
    }

    let mut case = Case::new("fires-during-mark");
    at_stop_link(&mut case, |state| state.flip("gd2-guardrail-2", "ALARM"));
    case.assert_aborted(
        "guardrail",
        &["roles", "stop", "abort"],
        Some(&guardrails()[1]),
        Some("no stop request was sent"),
    );
    assert!(case.stops().is_empty());

    let mut case = Case::new("exactly-left");
    set(&mut case.operator, &["deadline_seconds"], number("110"));
    set(
        &mut case.operator,
        &["snapshot_max_age_seconds"],
        number(&LIMIT_SECONDS.to_string()),
    );
    let t = case.plane.borrow().t;
    case.plane.borrow_mut().script(
        ALARMS,
        vec![Action::Delay(START + 110.0 - 50.0 - t - 0.4 - 0.2)],
    );
    case.assert_aborted(
        "deadline",
        &["roles", "abort"],
        None,
        Some("cannot hold the observation"),
    );
    assert!(case.stops().is_empty());
}

/// A stop mark whose write leaves too little of the stop call's half of the effect timeout gives
/// the request no time: it never leaves, the run aborts with cause `stop-not-shown` and no poll
/// follows the alarms' second read.
#[test]
fn a_stop_request_that_never_left_aborts_with_no_poll() {
    let mut case = Case::new("never-left");
    set(
        &mut case.operator,
        &["snapshot_max_age_seconds"],
        number(&LIMIT_SECONDS.to_string()),
    );
    at_stop_link(&mut case, |state| state.t += 60.0 / 2.0 + 1.0);
    let found = case.assert_aborted(
        "stop-not-shown",
        &["roles", "stop", "abort"],
        None,
        Some("never left"),
    );
    assert!(case.stops().is_empty());
    assert!(text_of(&found["abort"], "detail").contains("no stop request was sent"));
    assert_eq!(case.ops().last().map(String::as_str), Some(ALARMS));
}

/// The check before the stop, called alone, admits a wall reading exactly the skew before the
/// approval's lapse, and refuses with cause `deadline` one less than the skew before it, one at the
/// snapshot's cut and one at the run window's end.
#[test]
fn the_check_before_the_stop_holds_the_approvals_lapse_and_the_run_windows_end() {
    let ready = |lapse: &str, end: f64, cut: f64| {
        let mut case = Case::new("ready");
        set(
            &mut case.operator,
            &["approval", "not_after"],
            string(lapse),
        );
        let mut package = object(value(
            &std::fs::read_to_string(&case.package).expect("the package reads"),
        ));
        package.insert(
            "baseline",
            value(&format!(r#"{{"start": 0, "end": {START:?}}}"#)),
        );
        package.insert(
            "run",
            value(&format!(r#"{{"start": {START:?}, "end": {end:?}}}"#)),
        );
        let (wall, monotonic) = {
            let plane = case.plane.borrow();
            (plane.wall(), plane.t + super::plane::MONOTONIC)
        };
        case.controlled(|controller| {
            controller.set_preflight(Preflight::new(
                package,
                Number::from(cut),
                Number::from(100),
                (wall, monotonic),
                monotonic + 56.0,
            ));
            controller.set_deadline(monotonic + 290.0);
            controller.ready()
        })
    };
    assert_eq!(
        ready("1970-01-01T00:01:49Z", 400.0, 100.0).expect("admitted"),
        START
    );
    for (name, lapse, end, cut) in [
        (
            "less than the skew before the approval's lapse",
            "1970-01-01T00:01:48Z",
            400.0,
            100.0,
        ),
        (
            "at the snapshot's cut",
            "1970-01-01T01:00:00Z",
            400.0,
            START,
        ),
        (
            "at the run window's end",
            "1970-01-01T01:00:00Z",
            START,
            100.0,
        ),
    ] {
        match ready(lapse, end, cut) {
            Err(Halt::Aborted(aborted)) => assert_eq!(aborted.cause(), "deadline", "{name}"),
            other => panic!("{name}: {other:?}"),
        }
    }
}

/// A wall clock stepped back to or before the snapshot's cut, or into the baseline window after the
/// cut and the run window's start, aborts with cause `deadline` before the request.
#[test]
fn a_request_dated_at_or_before_the_snapshots_cut_or_inside_the_baseline_is_not_sent() {
    let mut case = Case::new("before-cut");
    case.snapshot("shards.jsonl", |rows| {
        for row in rows.iter_mut() {
            set(row, &["time"], number("103"));
        }
    });
    step_then(&mut case, -2.0, 0.0);
    case.assert_aborted(
        "deadline",
        &["roles", "abort"],
        None,
        Some("at or before the snapshot's cut"),
    );
    assert!(case.stops().is_empty());

    let mut case = Case::new("inside-baseline");
    case.repackage(|p| set(p, &["run", "start"], number("70")));
    case.snapshot("shards.jsonl", |rows| {
        for row in rows.iter_mut() {
            set(row, &["time"], number("90"));
        }
    });
    step_then(&mut case, -4.9, 0.0);
    case.assert_aborted(
        "deadline",
        &["roles", "abort"],
        None,
        Some("at or before the snapshot's cut"),
    );
    assert!(case.stops().is_empty());
}

/// A stop mark that cannot be written takes the abort path with cause `exception` before any stop
/// request: a link that fails with ENOSPC, and a mark whose sync after its link fails, which is then
/// removed.
#[test]
fn a_failed_stop_mark_sends_no_stop() {
    let mut case = Case::new("stop-unwritten");
    case.fail_once(libc::ENOSPC, |step| links(step, "stop.json"));
    case.assert_aborted(
        "exception",
        &["roles", "abort"],
        None,
        Some("OSError: [Errno 28] No space left on device"),
    );
    assert!(case.stops().is_empty());

    let mut case = Case::new("stop-removed");
    let mut linked = false;
    case.plant(Box::new(move |_, step| {
        if links(step, "stop.json") {
            linked = true;
            return None;
        }
        if linked && matches!(step, Step::Fsync(_)) {
            linked = false;
            return Some(errno(libc::EIO));
        }
        None
    }));
    case.assert_aborted("exception", &["roles", "abort"], None, Some("Unwritten: "));
    assert!(case.stops().is_empty());
}
