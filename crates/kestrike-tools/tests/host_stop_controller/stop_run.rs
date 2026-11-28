//! Runs that send a stop request: the clean run, the evidence directory's copy, the window of the
//! request, the effect timeout, the observation's end, the run's environment and its bounds.

use std::cell::RefCell;
use std::fs;
use std::os::unix::fs::symlink;
use std::rc::Rc;

use kestrike_tools::host_stop::{Disk, Lock, SKEW_SECONDS, lock};
use kestrike_tools::json::{Object, Value};

use super::plane::{ALARMS, Action, CALLER, RECORD, STATUS, STOP, string};
use super::steps::{Step, errno, links, syncs};
use super::{CHILD, COPY, Case, child, guardrails, listing, member, set, text_of};
use crate::host_stop_support::{TARGET, object, package, value};

pub(crate) fn int(n: i64) -> Value {
    value(&n.to_string())
}

pub(crate) fn seconds(number: &Value) -> f64 {
    match number {
        Value::Float(seconds) => *seconds,
        Value::Integer(_) => kestrike_tools::json::text(number)
            .parse()
            .expect("an integer reads as seconds"),
        other => panic!("{other:?} is a number"),
    }
}

pub(crate) fn time(mark: &Value) -> f64 {
    seconds(member(mark, "time"))
}

pub(crate) fn operator_seconds(case: &Case, key: &str) -> f64 {
    seconds(member(&case.operator, key))
}

/// Rewrites the one instance row of each of the next 100 record replies with `change`.
pub(crate) fn record_rows(case: &Case, change: fn(&mut Object)) {
    let shapes: Vec<super::plane::Shape> = (0..100)
        .map(|_| {
            Box::new(move |reply: Value| {
                let mut reply = reply;
                let Value::Object(top) = &mut reply else {
                    panic!("the reply is an object")
                };
                let Some(Value::Array(reservations)) = top.get_mut("Reservations") else {
                    panic!("the reply lists reservations")
                };
                let Value::Object(reservation) = &mut reservations[0] else {
                    panic!("a reservation is an object")
                };
                let Some(Value::Array(instances)) = reservation.get_mut("Instances") else {
                    panic!("a reservation lists instances")
                };
                let Value::Object(row) = &mut instances[0] else {
                    panic!("an instance row is an object")
                };
                change(row);
                reply
            }) as super::plane::Shape
        })
        .collect();
    case.plane.borrow_mut().shape(RECORD, shapes);
}

fn names(case: &Case) -> Vec<String> {
    case.marks().keys().cloned().collect()
}

/// A clean run makes the caller's call, the status read, the alarm reads, one stop request with the
/// CLI's retries off and the record read, in that order of their first calls; writes the roles,
/// stop and stopped marks; shows the stop by a status read after the request; observes the alarms
/// for `observe_seconds` after it; and exits 0 with the restoration pending.
#[test]
fn a_clean_run_sends_the_five_calls_in_order_writes_three_marks_and_exits_0() {
    let mut case = Case::new("clean");
    let code = case.run();
    let output = case.output();
    assert_eq!(code, 0, "{output}");
    let package_value = value(&String::from_utf8(package()).expect("the package is UTF-8"));
    let run_end = seconds(member(member(&package_value, "run"), "end"));
    let bound = format!(
        "A start before {} may end the judge's observation",
        run_end as i64 + 2 * SKEW_SECONDS + 1
    );
    assert!(output.contains(&bound), "{bound:?} in {output}");
    let ops = case.ops();
    let mut first: Vec<&str> = Vec::new();
    for op in &ops {
        if !first.contains(&op.as_str()) {
            first.push(op);
        }
    }
    assert_eq!(first, [CALLER, STATUS, ALARMS, STOP, RECORD]);
    let stops = case.stops();
    let asked: Vec<(Vec<String>, bool)> = stops.iter().map(|s| (s.args.clone(), s.retry)).collect();
    assert_eq!(
        asked,
        [(vec!["--instance-ids".to_owned(), TARGET.to_owned()], false)]
    );
    case.assert_retries();
    let marks = case.marks();
    assert_eq!(names(&case), ["roles", "stop", "stopped"]);
    assert_eq!(
        fs::read(case.evidence.join(COPY)).expect("the copy reads"),
        package(),
        "the run leaves the package's copy as it was"
    );
    let (stop, stopped) = (&marks["stop"], &marks["stopped"]);
    assert_eq!(text_of(stop, "instance"), TARGET);
    assert_eq!(
        text_of(stop, "identity"),
        text_of(&case.operator, "identity")
    );
    assert!(time(&marks["roles"]) < time(stop));
    assert_eq!(
        time(&marks["roles"]),
        100.0,
        "roles.json carries the snapshot's cut"
    );
    assert_eq!(text_of(stopped, "instance"), TARGET);
    assert_eq!(text_of(stopped, "state"), "stopped");
    assert_eq!(member(stopped, "request"), stop);
    let log = case.log();
    let first_alarms = log.iter().find(|l| l.op == ALARMS).expect("an alarm read");
    assert!(
        first_alarms.marks.iter().any(|m| m == "roles"),
        "{first_alarms:?}"
    );
    assert_eq!(stops[0].marks, ["roles", "stop"]);
    let stop_at = stops[0].time.expect("the stop request answered");
    let reads: Vec<_> = log
        .iter()
        .filter(|l| l.op == STATUS && l.time.is_some_and(|t| t > stop_at))
        .collect();
    assert_eq!(
        reads.last().and_then(|l| l.time),
        Some(time(stopped)),
        "{log:?}"
    );
    let declared: Vec<String> = match member(&case.operator, "instances") {
        Value::Array(ids) => ids.iter().map(super::plain).collect(),
        other => panic!("{other:?} are the instances"),
    };
    let polled: Vec<Vec<String>> = log
        .iter()
        .filter(|l| l.op == STATUS)
        .map(|l| l.args[2..].to_vec())
        .collect();
    let mut expected = vec![declared];
    expected.extend(std::iter::repeat_n(vec![TARGET.to_owned()], reads.len()));
    assert_eq!(polled, expected, "each poll names the target alone");
    let standbys: Vec<String> = object(member(&marks["roles"], "standbys").clone())
        .iter()
        .map(|(name, _)| name.to_string())
        .collect();
    assert_eq!(standbys, ["h2", "h3"]);
    assert!(output.contains("restoration is pending"), "{output}");
    let last = log.last().expect("a call");
    assert_eq!(last.op, ALARMS);
    assert!(last.start >= time(stopped) + operator_seconds(&case, "observe_seconds"));
    assert_eq!(
        stops[0].stop_json.as_ref(),
        Some(stop),
        "stop.json stood whole at the request"
    );
    assert!(!last.marks.iter().any(|m| m == "stopped"), "{last:?}");
}

fn mkfifo(path: &std::path::Path) {
    use std::os::unix::ffi::OsStrExt;
    let name = std::ffi::CString::new(path.as_os_str().as_bytes()).expect("no NUL in the path");
    // SAFETY: `name` is a NUL-terminated path that outlives the call.
    let status = unsafe { libc::mkfifo(name.as_ptr(), 0o600) };
    assert_eq!(status, 0, "{}", std::io::Error::last_os_error());
}

type Change = fn(&std::path::Path, &std::path::Path);

/// An evidence directory whose `package.json` is missing, holds other bytes, is cut short, is a link
/// to the package, is a named pipe or is a directory is refused before any call, and the directory
/// stays as it was; the copy itself named as the package runs to its end.
#[test]
fn an_evidence_directory_that_does_not_hold_the_packages_bytes_is_refused_with_no_call() {
    let rows: [(&str, Change, &str); 6] = [
        (
            "no copy",
            |copied, _| fs::remove_file(copied).expect("the copy goes"),
            "package.json cannot be read: No such file or directory",
        ),
        (
            "a copy of other bytes",
            |copied, _| {
                let mut data = package();
                data.push(b'\n');
                fs::write(copied, data).expect("the copy is written");
            },
            "holds other bytes than",
        ),
        (
            "a copy cut short",
            |copied, _| {
                let data = package();
                fs::write(copied, &data[..data.len() - 1]).expect("the copy is written");
            },
            "holds other bytes than",
        ),
        (
            "a link to the package",
            |copied, package| {
                fs::remove_file(copied).expect("the copy goes");
                symlink(package, copied).expect("the link is made");
            },
            "package.json cannot be read",
        ),
        (
            "a named pipe",
            |copied, _| {
                fs::remove_file(copied).expect("the copy goes");
                mkfifo(copied);
            },
            "package.json is no regular file",
        ),
        (
            "a directory",
            |copied, _| {
                fs::remove_file(copied).expect("the copy goes");
                fs::create_dir(copied).expect("the directory is made");
            },
            "package.json is no regular file",
        ),
    ];
    for (name, change, reason) in rows {
        let mut case = Case::new("copy");
        let copied = case.evidence.join(COPY);
        change(&copied, &case.package);
        let bytes = |path: &std::path::Path| {
            fs::symlink_metadata(path)
                .is_ok_and(|meta| meta.is_file())
                .then(|| fs::read(path).expect("the copy reads"))
        };
        let before = (listing(&case.evidence), bytes(&copied));
        let code = case.run();
        let output = case.output();
        assert_eq!(code, 2, "{name}: {output}");
        assert!(output.contains("refused: "), "{name}: {output}");
        assert!(output.contains(reason), "{name}: {reason:?} in {output}");
        assert_eq!(
            case.ops(),
            Vec::<String>::new(),
            "{name}: no call beside a refused package"
        );
        assert_eq!((listing(&case.evidence), bytes(&copied)), before, "{name}");
    }
    let mut case = Case::new("copy-named");
    case.package = case.evidence.join(COPY);
    let code = case.run();
    assert_eq!(code, 0, "{}", case.output());
    assert_eq!(names(&case), ["roles", "stop", "stopped"]);
    assert_eq!(fs::read(&case.package).expect("the copy reads"), package());
}

/// A record read whose instance row names no `LaunchTime` still shows the stop, read once.
#[test]
fn a_record_that_names_no_launch_time_still_shows_the_stop() {
    let mut case = Case::new("no-launch");
    record_rows(&case, |row| {
        row.remove("LaunchTime");
    });
    let code = case.run();
    assert_eq!(code, 0, "{}", case.output());
    assert_eq!(case.ops().iter().filter(|op| *op == RECORD).count(), 1);
}

/// An approval that lapses at 399 s, the skew past the run's deadline at 394 s, admits the run.
#[test]
fn an_approval_that_lapses_the_skew_after_the_deadline_admits_the_run() {
    let mut case = Case::new("lapse");
    set(
        &mut case.operator,
        &["approval", "not_after"],
        string("1970-01-01T00:06:39Z"),
    );
    let code = case.run();
    assert_eq!(code, 0, "{}", case.output());
}

/// Plants one failure between the making of `injection/` and the roles mark on `case`, and returns
/// the refusal's text and what the case drops once its first run ends.
fn window_plant(case: &Case, name: &str) -> (&'static str, Rc<RefCell<Option<Lock>>>) {
    let holder = Rc::new(RefCell::new(None));
    let reason = match name {
        "a lock another descriptor holds" => {
            let (held, injection) = (Rc::clone(&holder), case.evidence.join("injection"));
            let mut taken = false;
            case.plant(Box::new(move |_, step| {
                if !taken && matches!(step, Step::TryLock) && injection.exists() {
                    taken = true;
                    let lock = lock(&Disk, &injection).expect("another descriptor takes the lock");
                    *held.borrow_mut() = Some(lock);
                }
                None
            }));
            "is held by a run, restore or seal that has not ended"
        }
        "the evidence directory's sync" => {
            let evidence = case.evidence.clone();
            case.fail_once(
                libc::EIO,
                move |step| matches!(step, Step::FsyncDirectory(path) if *path == evidence),
            );
            "OSError: [Errno 5] Input/output error"
        }
        "the roles mark's write" => {
            case.fail_once(libc::ENOSPC, |step| links(step, "roles.json"));
            "No space left on device"
        }
        "a roles mark that stands under another's hand" => {
            case.fail_once(libc::EEXIST, |step| links(step, "roles.json"));
            "FileExistsError"
        }
        _ => {
            let mut count = 0;
            case.plant(Box::new(move |_, step| {
                if syncs(step) {
                    count += 1;
                    if count == 3 {
                        return Some(errno(libc::EIO));
                    }
                }
                None
            }));
            "so the mark is removed"
        }
    };
    (reason, holder)
}

/// Each failure between the making of `injection/` and the roles mark (a lock another descriptor
/// holds, a failed sync of the evidence directory, a failed roles write, a roles mark that stands
/// under another's hand, a roles mark removed after its sync failed) is a refusal after the caller
/// and the status read that removes `injection/` again; the failure is planted once, so the same
/// directory takes the next run to its end. The evidence directory's sync is the first sync and the
/// roles mark's sync once linked the third.
#[test]
fn a_failure_before_the_roles_mark_stands_is_a_refusal_that_removes_injection() {
    for name in [
        "a lock another descriptor holds",
        "the evidence directory's sync",
        "the roles mark's write",
        "a roles mark that stands under another's hand",
        "a roles mark removed after its sync failed",
    ] {
        let mut case = Case::new("window");
        let (reason, holder) = window_plant(&case, name);
        case.assert_refused(&[CALLER, STATUS], reason);
        let output = case.output();
        assert!(
            output.contains("before roles.json stood"),
            "{name}: {output}"
        );
        assert!(
            output.contains("is removed; nothing written"),
            "{name}: {output}"
        );
        assert!(!output.contains("aborted on"), "{name}: {output}");
        drop(holder.borrow_mut().take());
        let code = case.run();
        assert_eq!(code, 0, "{name}: {}", case.output());
        assert_eq!(names(&case), ["roles", "stop", "stopped"], "{name}");
    }
}

/// Alarms that treat missing data as `breaching`, and an alarm on a metric query of one metric,
/// leave the run to its stop and its end.
#[test]
fn alarms_that_state_missing_data_as_missing_or_breaching_on_one_metric_allow_the_stop() {
    let mut case = Case::new("missing-data");
    {
        let mut plane = case.plane.borrow_mut();
        plane.row(
            "gd2-guardrail-2",
            "TreatMissingData",
            Some(string("breaching")),
        );
        plane.row(
            "gd2-guardrail-3",
            "Metrics",
            Some(value(r#"[{"Id": "m1", "MetricStat": {"Stat": "Sum"}}]"#)),
        );
    }
    let code = case.run();
    assert_eq!(code, 0, "{}", case.output());
}

type PlaneChange = fn(&Case);

/// Each stop request accepted and never shown stopped aborts with cause `stop-not-shown` at the
/// effect timeout, counted from the request, with no stopped mark: a reply that reads `stopped`, a
/// record of another cause, a refused request, a record of another state, with no transition time
/// or with text after it, a record of another instance, a request answered after 10 s, and a record
/// at second 60. After the last poll's alarm read the abort path's status read follows, after the
/// poll's own status read or record read.
#[test]
fn a_stop_accepted_and_never_shown_stopped_aborts_with_no_stopped_mark() {
    let refused = "a stop request may have left and its outcome is unknown: ec2 stop-instances gave \
                   no answer: refused";
    let rows: [(&str, PlaneChange); 9] = [
        ("a reply that reads stopped", |case| {
            let mut plane = case.plane.borrow_mut();
            plane.stop_after = None;
            "stopped".clone_into(&mut plane.stop_reply);
        }),
        ("a record of another cause", |case| {
            "Server.InternalError".clone_into(&mut case.plane.borrow_mut().stop_code);
        }),
        ("a refused request", |case| {
            case.plane.borrow_mut().script(STOP, vec![Action::Refuse]);
        }),
        ("a record that reads another state", |case| {
            record_rows(case, |row| {
                row.insert("State", value(r#"{"Code": 64, "Name": "stopping"}"#));
            });
        }),
        ("a record with no transition time", |case| {
            record_rows(case, |row| {
                row.insert("StateTransitionReason", string("User initiated"));
            });
        }),
        ("a record with text after its transition time", |case| {
            record_rows(case, |row| {
                let reason = super::plain(row.get("StateTransitionReason").expect("a reason"));
                row.insert(
                    "StateTransitionReason",
                    string(&format!("{reason} and more")),
                );
            });
        }),
        ("a record of another instance", |case| {
            record_rows(case, |row| {
                row.insert("InstanceId", string("i-h2"));
            });
        }),
        ("a request answered after 10 s", |case| {
            let mut plane = case.plane.borrow_mut();
            plane.stop_after = None;
            plane.script(STOP, vec![Action::Delay(10.0)]);
        }),
        ("a record at second 60", |case| {
            record_rows(case, |row| {
                row.insert(
                    "StateTransitionReason",
                    string("User initiated (1970-01-01 00:01:60 GMT)"),
                );
            });
        }),
    ];
    for (name, change) in rows {
        let mut case = Case::new("never-shown");
        change(&case);
        let found = case.assert_aborted("stop-not-shown", &["roles", "stop", "abort"], None, None);
        assert_eq!(case.stops().len(), 1, "{name}");
        let effect = operator_seconds(&case, "effect_timeout_seconds");
        let (abort, stop) = (time(&found["abort"]), time(&found["stop"]));
        assert!(abort >= stop + effect - 1e-6, "{name}: {abort} {stop}");
        assert!(
            abort <= stop + effect + 1.0,
            "{name}: the effect timeout runs from the request"
        );
        let detail = text_of(&found["abort"], "detail");
        let sent = name == "a refused request";
        let said = if sent {
            refused
        } else {
            "the stop request was sent and answered"
        };
        assert!(detail.contains(said), "{name}: {detail}");
        assert_eq!(
            detail
                .matches("ec2 stop-instances gave no answer: refused")
                .count(),
            usize::from(sent),
            "{name}: {detail}"
        );
        let ops = case.ops();
        let last = ops
            .iter()
            .rposition(|op| op == ALARMS)
            .expect("an alarm read");
        let tail: Vec<&str> = ops[last + 1..].iter().map(String::as_str).collect();
        assert!(
            [&[STATUS][..], &[STATUS, STATUS], &[STATUS, RECORD, STATUS]]
                .contains(&tail.as_slice()),
            "{name}: {ops:?}"
        );
    }
}

/// A record whose transition lies more than the skew before the request, more than the skew after
/// the stop call's end, or in a second that ends past the stop call's end and the skew, and a record
/// that names two instances, show no stop; a transition within the skew before the request or after
/// the stop call's end shows it.
#[test]
fn a_record_outside_the_request_and_the_stop_calls_end_or_of_two_instances_shows_no_stop() {
    for offset in [-SKEW_SECONDS - 1, SKEW_SECONDS + 1, SKEW_SECONDS] {
        let mut case = Case::new("outside");
        case.plane.borrow_mut().transition_offset = offset;
        case.assert_aborted("stop-not-shown", &["roles", "stop", "abort"], None, None);
    }
    let mut case = Case::new("two-instances");
    let shapes: Vec<super::plane::Shape> = (0..100)
        .map(|_| {
            Box::new(|reply: Value| {
                let mut reply = object(reply);
                let Some(Value::Array(reservations)) = reply.remove("Reservations") else {
                    panic!("the reply lists reservations")
                };
                let doubled = [reservations.clone(), reservations].concat();
                reply.insert("Reservations", Value::Array(doubled));
                Value::Object(reply)
            }) as super::plane::Shape
        })
        .collect();
    case.plane.borrow_mut().shape(RECORD, shapes);
    case.assert_aborted("stop-not-shown", &["roles", "stop", "abort"], None, None);
    for offset in [-SKEW_SECONDS + 1, SKEW_SECONDS - 1] {
        let mut case = Case::new("within");
        case.plane.borrow_mut().transition_offset = offset;
        let code = case.run();
        assert_eq!(code, 0, "{offset}: {}", case.output());
    }
}

/// A status read or a record read that runs past the effect timeout is cut there and shows no stop;
/// a record read that answers past it shows none either. An alarm read still unanswered at the
/// effect timeout is cut there, and the abort's status read alone follows it; an alarm read lost
/// before it aborts on the first guardrail as unread; an alarm read that answers ALARM past it aborts
/// on that guardrail.
#[test]
fn a_stop_shown_by_reads_that_end_past_the_effect_timeout_is_not_shown() {
    let slow: [(&'static str, Vec<Action>); 2] = [
        (
            STATUS,
            vec![Action::Answer, Action::Answer, Action::Delay(59.0)],
        ),
        (RECORD, vec![Action::Delay(59.0)]),
    ];
    for (op, script) in slow {
        let mut case = Case::new("past-effect");
        case.plane.borrow_mut().script(op, script);
        let found = case.assert_aborted(
            "stop-not-shown",
            &["roles", "stop", "abort"],
            None,
            Some("timed out"),
        );
        let log = case.log();
        let cut = log.iter().find(|l| l.cut).expect("a cut call");
        let effect = operator_seconds(&case, "effect_timeout_seconds");
        let at = cut.time.expect("the cut is dated");
        assert!(
            (at - (time(&found["stop"]) + effect)).abs() <= 0.5,
            "{op}: {cut:?}"
        );
    }
    let mut case = Case::new("record-late");
    case.plane.borrow_mut().script(RECORD, vec![Action::Late]);
    case.assert_aborted(
        "stop-not-shown",
        &["roles", "stop", "abort"],
        None,
        Some("answered past the effect timeout"),
    );

    let mut case = Case::new("alarms-stall");
    case.faulted(Action::Stall, true);
    let found = case.assert_aborted(
        "stop-not-shown",
        &["roles", "stop", "abort"],
        None,
        Some("cloudwatch describe-alarms gave no answer"),
    );
    let effect = operator_seconds(&case, "effect_timeout_seconds");
    let cut = case.log()[case.fault_index()].clone();
    assert_eq!((cut.op.as_str(), cut.cut), (ALARMS, true));
    assert_eq!(case.after_fault(), [STATUS]);
    let stop = time(&found["stop"]);
    assert!(
        cut.time.expect("dated") <= stop + effect + 1e-6,
        "the read is cut at the timeout"
    );
    assert!(time(&found["abort"]) <= stop + effect + 1e-6);

    let mut case = Case::new("alarms-lost");
    case.faulted(Action::Lose, true);
    let first = guardrails()[0].clone();
    case.assert_aborted(
        "guardrail",
        &["roles", "stop", "abort"],
        Some(&first),
        Some("the alarms are unread"),
    );

    let mut case = Case::new("alarms-late");
    case.faulted(
        Action::Hook(Box::new(|state| {
            state.flip("gd2-guardrail-3", "ALARM");
            Action::Late
        })),
        true,
    );
    let third = guardrails()[2].clone();
    case.assert_aborted(
        "guardrail",
        &["roles", "stop", "abort"],
        Some(&third),
        Some("reads ALARM"),
    );
}

/// A status read that shows `stopped` dated exactly at the run window's end shows no stop. Calls of
/// a quarter second keep every time exact in binary, so the wall clock reads the end exactly.
#[test]
fn a_stopped_read_at_the_run_windows_end_shows_no_stop() {
    let mut case = Case::new("window-end");
    let package_value = value(&String::from_utf8(package()).expect("the package is UTF-8"));
    let end = seconds(member(member(&package_value, "run"), "end"));
    {
        let mut plane = case.plane.borrow_mut();
        plane.call_seconds = 0.25;
        plane.script(
            STATUS,
            vec![
                Action::Answer,
                Action::Answer,
                Action::Hook(Box::new(move |state| {
                    state.step = end - (state.t + 0.25);
                    Action::Answer
                })),
            ],
        );
    }
    case.assert_aborted(
        "stop-not-shown",
        &["roles", "stop", "abort"],
        None,
        Some("outside [the stop request"),
    );
    let log = case.log();
    let read = log
        .iter()
        .filter(|l| l.op == STATUS)
        .nth(2)
        .expect("a third status read");
    let step = case.plane.borrow().step;
    assert_eq!(
        read.time.expect("dated") + step,
        end,
        "the read that showed stopped is dated at the end"
    );
}

/// The time of the record read that showed the stop, from the log.
fn record_time(log: &[super::plane::Logged]) -> Option<f64> {
    log.iter().find(|l| l.op == RECORD).and_then(|l| l.time)
}

/// An alarm read that starts before the observation's end and answers after it does not end the
/// observation; the run's last call is an alarm read that starts at or after the end.
#[test]
fn the_observation_ends_with_an_alarm_read_that_starts_at_or_after_its_end() {
    let mut case = Case::new("observation-end");
    let observe = operator_seconds(&case, "observe_seconds");
    case.plane.borrow_mut().fault = Some(Box::new(move |state, op| {
        let shown = record_time(&state.log)?;
        let left = shown + observe - state.t;
        (op == ALARMS && 0.0 < left && left < 4.0).then_some(Action::Delay(4.0))
    }));
    let code = case.run();
    assert_eq!(code, 0, "{}", case.output());
    let log = case.log();
    let end = record_time(&log).expect("the record read") + observe;
    let spanned = &log[case.fault_index()];
    assert!(
        spanned.start < end && end < spanned.time.expect("dated"),
        "{spanned:?}"
    );
    assert!(log.last().expect("a call").start >= end);
}

/// A lost stop reply, a lost status read and a refused status read are never sent again, and the
/// polls show the stop.
#[test]
fn a_lost_stop_reply_or_status_read_is_never_resent_and_the_polls_show_the_stop() {
    let mut case = Case::new("lost");
    {
        let mut plane = case.plane.borrow_mut();
        plane.script(STOP, vec![Action::Lose]);
        plane.script(STATUS, vec![Action::Answer, Action::Lose, Action::Refuse]);
    }
    let code = case.run();
    assert_eq!(code, 0, "{}", case.output());
    assert_eq!(case.stops().len(), 1);
    assert_eq!(names(&case), ["roles", "stop", "stopped"]);
    let line = "host-stop-controller: the stop request's outcome is unknown: ec2 stop-instances \
                gave no answer: the reply was lost; the polls decide\n";
    assert!(case.stdout().contains(line), "{}", case.stdout());
}

/// A stop call cut at half the effect timeout, counted from the reading after the first quiet alarm
/// read, leaves the polls the other half: the first poll's alarm read starts as the stop call ends,
/// and its status read follows.
#[test]
fn a_stop_call_that_runs_to_its_cut_leaves_the_polls_half_the_effect_timeout() {
    let mut case = Case::new("stop-stall");
    case.plane.borrow_mut().script(STOP, vec![Action::Stall]);
    let code = case.run();
    assert_eq!(code, 0, "{}", case.output());
    let [stop] = case.stops().try_into().expect("one stop request");
    let effect = operator_seconds(&case, "effect_timeout_seconds");
    let call = case.plane.borrow().call_seconds;
    assert!(
        (stop.timeout - (effect / 2.0 - call)).abs() < 1e-9,
        "{stop:?}"
    );
    assert!(stop.cut, "{stop:?}");
    let log = case.log();
    let at = log
        .iter()
        .position(|l| l.op == STOP)
        .expect("the stop request");
    assert_eq!(
        (log[at + 1].op.as_str(), log[at + 1].start),
        (ALARMS, stop.time.expect("dated"))
    );
    assert_eq!(log[at + 2].op, STATUS);
    assert_eq!(names(&case), ["roles", "stop", "stopped"]);
    let line = format!(
        "host-stop-controller: the stop request's outcome is unknown: ec2 stop-instances gave no \
         answer: timed out after {} seconds; the polls decide\n",
        stop.timeout
    );
    assert!(case.stdout().contains(&line), "{}", case.stdout());
}

/// A stop shown at the eighth status read, within the effect timeout, writes the stopped mark.
#[test]
fn a_stop_shown_late_within_the_effect_timeout_writes_stopped() {
    let mut case = Case::new("late-shown");
    case.plane.borrow_mut().stop_after = Some(8);
    let code = case.run();
    assert_eq!(code, 0, "{}", case.output());
    let marks = case.marks();
    let effect = operator_seconds(&case, "effect_timeout_seconds");
    assert!(time(&marks["stopped"]) <= time(&marks["stop"]) + effect);
}

/// The window of the stop runs from the stop call's launch to its return: a stop call that answers
/// after 10 s shows the stop by its own transition. A shutdown that another hand recorded 8 s
/// before the stop call's launch, with the request then refused, shows no stop.
#[test]
fn the_window_runs_from_the_stop_calls_launch_to_its_return() {
    let mut case = Case::new("slow-stop");
    case.plane
        .borrow_mut()
        .script(STOP, vec![Action::Delay(10.0)]);
    let code = case.run();
    assert_eq!(code, 0, "{}", case.output());

    let mut case = Case::new("foreign-stop");
    case.plane.borrow_mut().script(STOP, vec![Action::Refuse]);
    let (injection, mut done) = (case.evidence.join("injection"), false);
    case.plant(Box::new(move |state, step| {
        let at_end = matches!(step, Step::FsyncDirectory(path) if *path == injection);
        if !done && at_end && injection.join("stop.json").exists() {
            done = true;
            let args = ["--instance-ids".to_owned(), TARGET.to_owned()];
            state
                .stop_instances(&args)
                .expect("the foreign stop is made");
            state.t += 8.0;
        }
        None
    }));
    case.assert_aborted("stop-not-shown", &["roles", "stop", "abort"], None, None);
    assert_eq!(case.stops().len(), 1);
}

/// A run with every time at its bound stops the target: the snapshot's age equals
/// `snapshot_max_age_seconds` at the stop call's start, and the transition's second is the earliest
/// the skew admits. Binary floating point holds a quarter second exactly.
#[test]
fn a_run_exactly_at_its_bounds_stops_the_target() {
    let mut case = Case::new("at-bounds");
    {
        let mut plane = case.plane.borrow_mut();
        plane.call_seconds = 0.25;
        plane.transition_offset = -SKEW_SECONDS;
        plane.script(ALARMS, vec![Action::Delay(55.0)]);
    }
    let code = case.run();
    assert_eq!(code, 0, "{}", case.output());
    let [stop] = case.stops().try_into().expect("one stop request");
    assert_eq!(
        stop.start,
        100.0 + operator_seconds(&case, "snapshot_max_age_seconds")
    );
    assert_eq!(
        case.plane.borrow().instances[TARGET].transition,
        "User initiated (1970-01-01 00:02:35 GMT)"
    );
}

/// A wall clock exactly the skew ahead of the monotonic one admits the stop, and the stop mark is
/// dated by the wall clock.
#[test]
fn a_wall_clock_exactly_the_skew_ahead_admits_the_stop() {
    let mut case = Case::new("skew-ahead");
    {
        let mut plane = case.plane.borrow_mut();
        plane.call_seconds = 0.25;
        plane.transition_offset = SKEW_SECONDS;
        plane.script(
            ALARMS,
            vec![Action::Hook(Box::new(|state| {
                state.step = SKEW_SECONDS as f64;
                Action::Answer
            }))],
        );
    }
    let code = case.run();
    assert_eq!(code, 0, "{}", case.output());
    let stop = time(&case.marks()["stop"]);
    assert_eq!(stop, case.stops()[0].start - 0.25 + SKEW_SECONDS as f64);
}

const ENVIRONMENT: &str =
    "stop_run::an_environment_changed_after_the_caller_check_does_not_reach_the_stop";

/// The child's body: the environment read at the run's start, which holds a planted secret, is the
/// one every call carries, though the alarm read's hook changes the process's environment.
fn changed_environment() {
    let mut case = Case::new("environment");
    case.env = std::env::vars_os().collect();
    let before = case.env.clone();
    case.plane.borrow_mut().script(
        ALARMS,
        vec![Action::Hook(Box::new(|_| {
            // SAFETY: the child runs this case alone on one thread, so no thread reads the
            // environment while it changes.
            unsafe {
                std::env::set_var("AWS_PROFILE", "another-profile");
                std::env::set_var("AWS_ACCESS_KEY_ID", "another-key");
            }
            Action::Answer
        }))],
    );
    let code = case.run();
    assert_eq!(code, 0, "{}", case.output());
    let log = case.log();
    let envs = case.plane.borrow().envs.clone();
    let secret = ("AWS_SECRET_ACCESS_KEY".into(), "a-planted-secret".into());
    assert!(
        envs[0].contains(&secret),
        "the snapshot carries the run's starting environment"
    );
    assert!(
        !case.output().contains("a-planted-secret"),
        "a line holds an environment value"
    );
    assert_eq!((log[0].op.as_str(), envs.len()), (CALLER, log.len()));
    assert_eq!(
        envs[0], before,
        "the caller check runs under the environment read at the start"
    );
    assert!(
        envs.iter().all(|env| *env == envs[0]),
        "every call carries the one snapshot"
    );
    assert!(
        !envs[0].iter().any(|(_, value)| value == "another-profile"),
        "the changed profile reached a call"
    );
    assert_eq!(
        std::env::var("AWS_PROFILE").as_deref(),
        Ok("another-profile"),
        "the hook changed the process's environment"
    );
}

/// An environment changed after the caller's check reaches no call: the case runs in a process of
/// its own, since it changes that process's environment.
#[test]
fn an_environment_changed_after_the_caller_check_does_not_reach_the_stop() {
    if std::env::var_os(CHILD).is_some() {
        changed_environment();
        return;
    }
    let place = crate::host_stop_support::Scratch::new("environment-child");
    let (status, shown) = child(
        ENVIRONMENT,
        &place.0,
        &[("AWS_SECRET_ACCESS_KEY", "a-planted-secret")],
    );
    assert!(status.success(), "{shown}");
    assert!(shown.contains("1 passed"), "{shown}");
}
