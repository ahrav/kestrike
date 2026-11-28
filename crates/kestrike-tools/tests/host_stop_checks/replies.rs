//! Each AWS reply through its reader against the row's literal outcome: a reply off its request or
//! off its types is a failed call with the row's sentence, and an admitted reply reads as the row's
//! fields. A `LaunchTime` and an ISO time read as the row's seconds or its refusal.

use std::collections::BTreeMap;

use kestrike_tools::host_stop::{
    Alarm, FailedCall, USER_STOP, caller_arn, iso_time, launch_time, read_alarms, read_record,
    read_statuses,
};
use kestrike_tools::json::{Object, Text, Value, text};

use crate::host_stop_support::{object, value};

fn texts(items: &[&str]) -> Vec<Text> {
    items.iter().map(|item| Text::from(*item)).collect()
}

/// The JSON text of a reader's map, its entries in key order and each entry as `entry` writes it.
fn written<T>(map: &BTreeMap<Text, T>, entry: impl Fn(&T) -> Value) -> String {
    let mut out = Object::new();
    for (key, item) in map {
        out.insert(key.clone(), entry(item));
    }
    text(&Value::Object(out))
}

fn alarm_value(alarm: &Alarm) -> Value {
    let optional =
        |text: Option<&Text>| text.map_or(Value::Null, |text| Value::String(text.clone()));
    let mut out = Object::new();
    out.insert("state", Value::String(alarm.state().clone()));
    out.insert("missing", optional(alarm.missing()));
    out.insert("evaluation", optional(alarm.evaluation()));
    out.insert("kind", optional(alarm.kind().map(Text::from).as_ref()));
    out.insert("transitioned", Value::String(alarm.transitioned().clone()));
    Value::Object(out)
}

/// Asserts each row's outcome: the JSON text of the admitted value, or the failed call's sentence.
fn check<T>(
    name: &str,
    got: Result<T, FailedCall>,
    expected: Result<&str, &str>,
    shown: impl Fn(&T) -> String,
) {
    match (got, expected) {
        (Ok(got), Ok(expected)) => assert_eq!(shown(&got), text(&value(expected)), "{name}"),
        (Err(FailedCall::Reply(sentence)), Err(expected)) => {
            assert_eq!(sentence, expected, "{name}")
        }
        (got, expected) => panic!(
            "{name}: {:?} against {expected:?}",
            got.map(|got| shown(&got))
        ),
    }
}

/// A status reply names exactly the instances asked, each with a state and its two checks or none;
/// each check reads as its own field of its own instance.
#[test]
fn a_declared_instance_not_running_or_an_unread_set_is_a_run_left_open() {
    let asked = texts(&["i-h1", "i-h2"]);
    for &(name, reply, expected) in STATUSES {
        let got = read_statuses(&object(value(reply)), &asked);
        check(name, got, expected, |map| {
            written(map, |status| status.to_value())
        });
    }
    let read = read_statuses(&object(value(BOTH)), &asked).expect("the reply is admitted");
    let fields: Vec<(&str, Option<&str>, Option<&str>)> = ["i-h1", "i-h2"]
        .iter()
        .map(|id| {
            let status = &read[&Text::from(*id)];
            (
                status.state().to_str().expect("ASCII"),
                status.instance().and_then(Text::to_str),
                status.system().and_then(Text::to_str),
            )
        })
        .collect();
    assert_eq!(
        fields,
        [
            ("stopped", Some("initializing"), Some("ok")),
            ("running", Some("ok"), Some("impaired")),
        ]
    );
}

/// The caller's `Arn` is read as a text; an `Arn` absent or of another type is a failed call.
#[test]
fn the_callers_arn_is_a_text() {
    let rows: [(&str, Result<&str, &str>); 3] = [
        (
            r#"{"Arn": "arn:aws:sts::account:assumed-role/gameday-operator/gd2-run", "UserId": "u"}"#,
            Ok("arn:aws:sts::account:assumed-role/gameday-operator/gd2-run"),
        ),
        (r#"{"UserId": "u"}"#, Err("Arn is no str: None")),
        (r#"{"Arn": 1}"#, Err("Arn is no str: 1")),
    ];
    for (reply, expected) in rows {
        let reply = object(value(reply));
        match (caller_arn(&reply), expected) {
            (Ok(arn), Ok(expected)) => assert_eq!(*arn, expected),
            (Err(FailedCall::Reply(sentence)), Err(expected)) => assert_eq!(sentence, expected),
            (got, expected) => panic!("{got:?} against {expected:?}"),
        }
    }
}

/// A stop's transition reason matches the whole text `User initiated (<second> GMT)` alone.
#[test]
fn a_user_stop_reason_is_the_whole_text() {
    let rows = [
        ("User initiated (2026-11-27 10:15:30 GMT)", true),
        ("xUser initiated (2026-11-27 10:15:30 GMT)", false),
        ("User initiated (2026-11-27 10:15:30 GMT)x", false),
        ("User initiated (2026-11-27 10:15:60 GMT)", false),
    ];
    for (reason, expected) in rows {
        assert_eq!(USER_STOP.is_match(reason), expected, "{reason}");
    }
}

/// A record reply names one instance and the one asked, with its fields of their types.
#[test]
fn a_record_outside_the_request_and_the_stop_calls_end_or_of_two_instances_shows_no_stop() {
    for &(name, reply, expected) in RECORDS {
        let got = read_record(&object(value(reply)), &Text::from("i-h1"));
        check(name, got, expected, |record| text(&record.to_value()));
    }
}

/// An alarm reply names no alarm twice or unasked and no composite alarm; an alarm it leaves out is
/// absent from the result.
#[test]
fn an_alarm_not_quiet_or_unread_before_the_stop_aborts_with_no_stop() {
    let asked = texts(&["gd2-guardrail-1", "gd2-guardrail-2"]);
    for &(name, reply, expected) in ALARMS {
        let got = read_alarms(&object(value(reply)), &asked);
        check(name, got, expected, |map| written(map, alarm_value));
    }
}

/// A `LaunchTime` reads in both UTC forms with or without a fraction of up to nine digits, as a
/// float; any other text, none and a second the calendar lacks are failed calls.
#[test]
fn a_launch_time_reads_in_both_utc_forms_with_or_without_a_fraction() {
    for &(launch, expected) in LAUNCHES {
        let launch = launch.map(Text::from);
        let got = launch_time(launch.as_ref());
        check(&format!("{launch:?}"), got, expected, |seconds| {
            seconds.to_string()
        });
    }
}

/// An ISO time is a calendar second `YYYY-MM-DDTHH:MM:SSZ` from year 1 to 9999, as an integer.
#[test]
fn an_iso_time_is_a_calendar_second() {
    let what = Text::from("approval not_after");
    for &(time, expected) in ISOS {
        match (iso_time(&value(time), &what), expected) {
            (Ok(seconds), Ok(expected)) => assert_eq!(seconds.to_string(), expected, "{time}"),
            (Err(refusal), Err(expected)) => assert_eq!(*refusal.message(), expected, "{time}"),
            (got, expected) => panic!("{time}: {got:?} against {expected:?}"),
        }
    }
}

/// A status reply whose instance and system checks differ on each instance.
const BOTH: &str = r#"{"InstanceStatuses": [{"InstanceId": "i-h2", "InstanceState": {"Code": 16, "Name": "running"}, "InstanceStatus": {"Status": "ok"}, "SystemStatus": {"Status": "impaired"}}, {"InstanceId": "i-h1", "InstanceState": {"Code": 16, "Name": "stopped"}, "InstanceStatus": {"Status": "initializing"}, "SystemStatus": {"Status": "ok"}}]}"#;

const STATUSES: &[(&str, &str, Result<&str, &str>)] = &[
    (
        "both",
        BOTH,
        Ok(
            r#"{"i-h1": {"state": "stopped", "instance": "initializing", "system": "ok"}, "i-h2": {"state": "running", "instance": "ok", "system": "impaired"}}"#,
        ),
    ),
    (
        "checks left out",
        r#"{"InstanceStatuses": [{"InstanceId": "i-h1", "InstanceState": {"Name": "stopped"}}, {"InstanceId": "i-h2", "InstanceState": {"Name": "running"}, "InstanceStatus": null}]}"#,
        Ok(
            r#"{"i-h1": {"state": "stopped", "instance": null, "system": null}, "i-h2": {"state": "running", "instance": null, "system": null}}"#,
        ),
    ),
    (
        "a NextToken",
        r#"{"InstanceStatuses": [], "NextToken": "t"}"#,
        Err("describe-instance-status holds a NextToken, so its listing is partial"),
    ),
    (
        "a null NextToken",
        r#"{"InstanceStatuses": [{"InstanceId": "i-h1", "InstanceState": {"Code": 16, "Name": "running"}, "InstanceStatus": {"Status": "ok"}, "SystemStatus": {"Status": "ok"}}, {"InstanceId": "i-h2", "InstanceState": {"Code": 16, "Name": "running"}, "InstanceStatus": {"Status": "ok"}, "SystemStatus": {"Status": "ok"}}], "NextToken": null}"#,
        Ok(
            r#"{"i-h1": {"state": "running", "instance": "ok", "system": "ok"}, "i-h2": {"state": "running", "instance": "ok", "system": "ok"}}"#,
        ),
    ),
    ("no list", r#"{}"#, Err("InstanceStatuses is no list: None")),
    (
        "a row that is no object",
        r#"{"InstanceStatuses": ["i-h1"]}"#,
        Err("an instance status is no dict: 'i-h1'"),
    ),
    (
        "an id that is no text",
        r#"{"InstanceStatuses": [{"InstanceId": 1, "InstanceState": {"Code": 16, "Name": "running"}, "InstanceStatus": {"Status": "ok"}, "SystemStatus": {"Status": "ok"}}]}"#,
        Err("InstanceId is no str: 1"),
    ),
    (
        "an instance twice",
        r#"{"InstanceStatuses": [{"InstanceId": "i-h1", "InstanceState": {"Code": 16, "Name": "running"}, "InstanceStatus": {"Status": "ok"}, "SystemStatus": {"Status": "ok"}}, {"InstanceId": "i-h1", "InstanceState": {"Code": 16, "Name": "running"}, "InstanceStatus": {"Status": "ok"}, "SystemStatus": {"Status": "ok"}}]}"#,
        Err("describe-instance-status names i-h1 twice"),
    ),
    (
        "another set",
        r#"{"InstanceStatuses": [{"InstanceId": "i-h1", "InstanceState": {"Code": 16, "Name": "running"}, "InstanceStatus": {"Status": "ok"}, "SystemStatus": {"Status": "ok"}}, {"InstanceId": "i-h3", "InstanceState": {"Code": 16, "Name": "running"}, "InstanceStatus": {"Status": "ok"}, "SystemStatus": {"Status": "ok"}}]}"#,
        Err("describe-instance-status names ['i-h1', 'i-h3'], not ['i-h1', 'i-h2']"),
    ),
    (
        "a strict superset",
        r#"{"InstanceStatuses": [{"InstanceId": "i-h1", "InstanceState": {"Name": "running"}}, {"InstanceId": "i-h2", "InstanceState": {"Name": "running"}}, {"InstanceId": "i-h9", "InstanceState": {"Name": "running"}}]}"#,
        Err("describe-instance-status names ['i-h1', 'i-h2', 'i-h9'], not ['i-h1', 'i-h2']"),
    ),
    (
        "one left out",
        r#"{"InstanceStatuses": [{"InstanceId": "i-h2", "InstanceState": {"Code": 16, "Name": "running"}, "InstanceStatus": {"Status": "ok"}, "SystemStatus": {"Status": "ok"}}]}"#,
        Err("describe-instance-status names ['i-h2'], not ['i-h1', 'i-h2']"),
    ),
    (
        "a state left out",
        r#"{"InstanceStatuses": [{"InstanceId": "i-h1"}, {"InstanceId": "i-h2", "InstanceState": {"Code": 16, "Name": "running"}, "InstanceStatus": {"Status": "ok"}, "SystemStatus": {"Status": "ok"}}]}"#,
        Err("InstanceState is no dict: None"),
    ),
    (
        "a state name that is no text",
        r#"{"InstanceStatuses": [{"InstanceId": "i-h1", "InstanceState": {"Name": 16}, "InstanceStatus": {"Status": "ok"}, "SystemStatus": {"Status": "ok"}}]}"#,
        Err("InstanceState.Name is no str: 16"),
    ),
    (
        "a check off its type",
        r#"{"InstanceStatuses": [{"InstanceId": "i-h1", "InstanceState": {"Code": 16, "Name": "running"}, "InstanceStatus": {"Status": "ok"}, "SystemStatus": {"Status": ["ok"]}}]}"#,
        Err("SystemStatus.Status is no str: ['ok']"),
    ),
    (
        "a check that is no object",
        r#"{"InstanceStatuses": [{"InstanceId": "i-h1", "InstanceState": {"Code": 16, "Name": "running"}, "InstanceStatus": "ok", "SystemStatus": {"Status": "ok"}}]}"#,
        Err("InstanceStatus is no dict: 'ok'"),
    ),
    (
        "a long value",
        r#"{"InstanceStatuses": [{"InstanceId": ["xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"], "InstanceState": {"Code": 16, "Name": "running"}, "InstanceStatus": {"Status": "ok"}, "SystemStatus": {"Status": "ok"}}]}"#,
        Err(
            "InstanceId is no str: ['xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        ),
    ),
];

const RECORDS: &[(&str, &str, Result<&str, &str>)] = &[
    (
        "one",
        r#"{"Reservations": [{"Instances": [{"InstanceId": "i-h1", "State": {"Code": 80, "Name": "stopped"}, "StateReason": {"Code": "Client.UserInitiatedShutdown"}, "StateTransitionReason": "User initiated (1970-01-01 00:01:45 GMT)", "LaunchTime": "1970-01-01T00:00:10.5Z"}]}]}"#,
        Ok(
            r#"{"state": "stopped", "code": "Client.UserInitiatedShutdown", "transition": "User initiated (1970-01-01 00:01:45 GMT)", "launch": "1970-01-01T00:00:10.5Z"}"#,
        ),
    ),
    (
        "fields left out",
        r#"{"Reservations": [{"Instances": [{"InstanceId": "i-h1", "State": {"Code": 80, "Name": "stopped"}}]}]}"#,
        Ok(r#"{"state": "stopped", "code": null, "transition": "", "launch": null}"#),
    ),
    (
        "a null state reason",
        r#"{"Reservations": [{"Instances": [{"InstanceId": "i-h1", "State": {"Code": 80, "Name": "stopped"}, "StateReason": null, "StateTransitionReason": "User initiated (1970-01-01 00:01:45 GMT)", "LaunchTime": "1970-01-01T00:00:10.5Z"}]}]}"#,
        Ok(
            r#"{"state": "stopped", "code": null, "transition": "User initiated (1970-01-01 00:01:45 GMT)", "launch": "1970-01-01T00:00:10.5Z"}"#,
        ),
    ),
    (
        "a NextToken",
        r#"{"Reservations": [], "NextToken": "t"}"#,
        Err("describe-instances holds a NextToken, so its listing is partial"),
    ),
    (
        "no reservations",
        r#"{}"#,
        Err("Reservations is no list: None"),
    ),
    (
        "a reservation that is no object",
        r#"{"Reservations": [[]]}"#,
        Err("a reservation is no dict: []"),
    ),
    (
        "no instances",
        r#"{"Reservations": [{}]}"#,
        Err("Instances is no list: None"),
    ),
    (
        "two instances",
        r#"{"Reservations": [{"Instances": [{"InstanceId": "i-h1", "State": {"Code": 80, "Name": "stopped"}, "StateReason": {"Code": "Client.UserInitiatedShutdown"}, "StateTransitionReason": "User initiated (1970-01-01 00:01:45 GMT)", "LaunchTime": "1970-01-01T00:00:10.5Z"}]}, {"Instances": [{"InstanceId": "i-h2", "State": {"Code": 80, "Name": "stopped"}, "StateReason": {"Code": "Client.UserInitiatedShutdown"}, "StateTransitionReason": "User initiated (1970-01-01 00:01:45 GMT)", "LaunchTime": "1970-01-01T00:00:10.5Z"}]}]}"#,
        Err("describe-instances names 2 instances, not i-h1 alone"),
    ),
    (
        "none",
        r#"{"Reservations": []}"#,
        Err("describe-instances names 0 instances, not i-h1 alone"),
    ),
    (
        "another instance",
        r#"{"Reservations": [{"Instances": [{"InstanceId": "i-h2", "State": {"Code": 80, "Name": "stopped"}, "StateReason": {"Code": "Client.UserInitiatedShutdown"}, "StateTransitionReason": "User initiated (1970-01-01 00:01:45 GMT)", "LaunchTime": "1970-01-01T00:00:10.5Z"}]}]}"#,
        Err("describe-instances names 1 instances, not i-h1 alone"),
    ),
    (
        "an instance that is no object",
        r#"{"Reservations": [{"Instances": ["i-h1"]}]}"#,
        Err("an instance is no dict: 'i-h1'"),
    ),
    (
        "a state name that is no text",
        r#"{"Reservations": [{"Instances": [{"InstanceId": "i-h1", "State": {"Name": null}, "StateReason": {"Code": "Client.UserInitiatedShutdown"}, "StateTransitionReason": "User initiated (1970-01-01 00:01:45 GMT)", "LaunchTime": "1970-01-01T00:00:10.5Z"}]}]}"#,
        Err("State.Name is no str: None"),
    ),
    (
        "a null transition",
        r#"{"Reservations": [{"Instances": [{"InstanceId": "i-h1", "State": {"Code": 80, "Name": "stopped"}, "StateReason": {"Code": "Client.UserInitiatedShutdown"}, "StateTransitionReason": null, "LaunchTime": "1970-01-01T00:00:10.5Z"}]}]}"#,
        Err("StateTransitionReason is no str: None"),
    ),
    (
        "a null launch time",
        r#"{"Reservations": [{"Instances": [{"InstanceId": "i-h1", "State": {"Code": 80, "Name": "stopped"}, "StateReason": {"Code": "Client.UserInitiatedShutdown"}, "StateTransitionReason": "User initiated (1970-01-01 00:01:45 GMT)", "LaunchTime": null}]}]}"#,
        Err("LaunchTime is no str: None"),
    ),
    (
        "a code that is no text",
        r#"{"Reservations": [{"Instances": [{"InstanceId": "i-h1", "State": {"Code": 80, "Name": "stopped"}, "StateReason": {"Code": 1}, "StateTransitionReason": "User initiated (1970-01-01 00:01:45 GMT)", "LaunchTime": "1970-01-01T00:00:10.5Z"}]}]}"#,
        Err("StateReason.Code is no str: 1"),
    ),
];

const ALARMS: &[(&str, &str, Result<&str, &str>)] = &[
    (
        "both",
        r#"{"MetricAlarms": [{"AlarmName": "gd2-guardrail-2", "StateValue": "ALARM", "TreatMissingData": "missing", "StateTransitionedTimestamp": "1970-01-01T00:00:00.000Z"}, {"AlarmName": "gd2-guardrail-1", "StateValue": "OK", "TreatMissingData": "missing", "StateTransitionedTimestamp": "1970-01-01T00:00:00.000Z"}]}"#,
        Ok(
            r#"{"gd2-guardrail-1": {"state": "OK", "missing": "missing", "evaluation": null, "kind": null, "transitioned": "1970-01-01T00:00:00.000Z"}, "gd2-guardrail-2": {"state": "ALARM", "missing": "missing", "evaluation": null, "kind": null, "transitioned": "1970-01-01T00:00:00.000Z"}}"#,
        ),
    ),
    (
        "one left out",
        r#"{"MetricAlarms": [{"AlarmName": "gd2-guardrail-1", "StateValue": "OK", "TreatMissingData": "missing", "StateTransitionedTimestamp": "1970-01-01T00:00:00.000Z"}], "CompositeAlarms": []}"#,
        Ok(
            r#"{"gd2-guardrail-1": {"state": "OK", "missing": "missing", "evaluation": null, "kind": null, "transitioned": "1970-01-01T00:00:00.000Z"}}"#,
        ),
    ),
    ("none", r#"{}"#, Ok(r#"{}"#)),
    (
        "a NextToken",
        r#"{"MetricAlarms": [], "NextToken": "t"}"#,
        Err("describe-alarms holds a NextToken, so its listing is partial"),
    ),
    (
        "a composite alarm",
        r#"{"MetricAlarms": [], "CompositeAlarms": [{"AlarmName": "c"}]}"#,
        Err(
            "describe-alarms names a composite alarm, which can read OK while its children have no data",
        ),
    ),
    (
        "composite alarms that are no list",
        r#"{"CompositeAlarms": null}"#,
        Err("CompositeAlarms is no list: None"),
    ),
    (
        "metric alarms that are no list",
        r#"{"MetricAlarms": {}}"#,
        Err("MetricAlarms is no list: {}"),
    ),
    (
        "a row that is no object",
        r#"{"MetricAlarms": [1]}"#,
        Err("an alarm is no dict: 1"),
    ),
    (
        "a name that is no text",
        r#"{"MetricAlarms": [{"AlarmName": null, "StateValue": "OK", "TreatMissingData": "missing", "StateTransitionedTimestamp": "1970-01-01T00:00:00.000Z"}]}"#,
        Err("AlarmName is no str: None"),
    ),
    (
        "a name twice",
        r#"{"MetricAlarms": [{"AlarmName": "gd2-guardrail-1", "StateValue": "OK", "TreatMissingData": "missing", "StateTransitionedTimestamp": "1970-01-01T00:00:00.000Z"}, {"AlarmName": "gd2-guardrail-1", "StateValue": "OK", "TreatMissingData": "missing", "StateTransitionedTimestamp": "1970-01-01T00:00:00.000Z"}]}"#,
        Err("describe-alarms names gd2-guardrail-1 twice or unasked"),
    ),
    (
        "a name unasked",
        r#"{"MetricAlarms": [{"AlarmName": "gd2-guardrail-9", "StateValue": "OK", "TreatMissingData": "missing", "StateTransitionedTimestamp": "1970-01-01T00:00:00.000Z"}]}"#,
        Err("describe-alarms names gd2-guardrail-9 twice or unasked"),
    ),
    (
        "a state that is no text",
        r#"{"MetricAlarms": [{"AlarmName": "gd2-guardrail-1", "StateValue": null, "TreatMissingData": "missing", "StateTransitionedTimestamp": "1970-01-01T00:00:00.000Z"}]}"#,
        Err("StateValue is no str: None"),
    ),
    (
        "missing data left out",
        r#"{"MetricAlarms": [{"AlarmName": "gd2-guardrail-1", "StateValue": "OK", "StateTransitionedTimestamp": "1970-01-01T00:00:00.000Z"}]}"#,
        Ok(
            r#"{"gd2-guardrail-1": {"state": "OK", "missing": null, "evaluation": null, "kind": null, "transitioned": "1970-01-01T00:00:00.000Z"}}"#,
        ),
    ),
    (
        "missing data null",
        r#"{"MetricAlarms": [{"AlarmName": "gd2-guardrail-1", "StateValue": "OK", "TreatMissingData": null, "StateTransitionedTimestamp": "1970-01-01T00:00:00.000Z"}]}"#,
        Ok(
            r#"{"gd2-guardrail-1": {"state": "OK", "missing": null, "evaluation": null, "kind": null, "transitioned": "1970-01-01T00:00:00.000Z"}}"#,
        ),
    ),
    (
        "missing data that is no text",
        r#"{"MetricAlarms": [{"AlarmName": "gd2-guardrail-1", "StateValue": "OK", "TreatMissingData": 0, "StateTransitionedTimestamp": "1970-01-01T00:00:00.000Z"}]}"#,
        Err("TreatMissingData is no str: 0"),
    ),
    (
        "an evaluation state",
        r#"{"MetricAlarms": [{"AlarmName": "gd2-guardrail-1", "StateValue": "OK", "TreatMissingData": "missing", "StateTransitionedTimestamp": "1970-01-01T00:00:00.000Z", "EvaluationState": "PARTIAL_DATA"}]}"#,
        Ok(
            r#"{"gd2-guardrail-1": {"state": "OK", "missing": "missing", "evaluation": "PARTIAL_DATA", "kind": null, "transitioned": "1970-01-01T00:00:00.000Z"}}"#,
        ),
    ),
    (
        "a null evaluation state",
        r#"{"MetricAlarms": [{"AlarmName": "gd2-guardrail-1", "StateValue": "OK", "TreatMissingData": "missing", "StateTransitionedTimestamp": "1970-01-01T00:00:00.000Z", "EvaluationState": null}]}"#,
        Err("EvaluationState is no str: None"),
    ),
    (
        "a PromQL alarm",
        r#"{"MetricAlarms": [{"AlarmName": "gd2-guardrail-1", "StateValue": "OK", "TreatMissingData": "missing", "StateTransitionedTimestamp": "1970-01-01T00:00:00.000Z", "EvaluationCriteria": null}]}"#,
        Ok(
            r#"{"gd2-guardrail-1": {"state": "OK", "missing": "missing", "evaluation": null, "kind": "a PromQL alarm", "transitioned": "1970-01-01T00:00:00.000Z"}}"#,
        ),
    ),
    (
        "a metric query expression",
        r#"{"MetricAlarms": [{"AlarmName": "gd2-guardrail-1", "StateValue": "OK", "TreatMissingData": "missing", "StateTransitionedTimestamp": "1970-01-01T00:00:00.000Z", "Metrics": [{"Id": "m"}, {"Expression": "FILL(m, 0)"}]}]}"#,
        Ok(
            r#"{"gd2-guardrail-1": {"state": "OK", "missing": "missing", "evaluation": null, "kind": "an alarm on a metric query expression", "transitioned": "1970-01-01T00:00:00.000Z"}}"#,
        ),
    ),
    (
        "metric queries without an expression",
        r#"{"MetricAlarms": [{"AlarmName": "gd2-guardrail-1", "StateValue": "OK", "TreatMissingData": "missing", "StateTransitionedTimestamp": "1970-01-01T00:00:00.000Z", "Metrics": [{"Id": "m"}]}]}"#,
        Ok(
            r#"{"gd2-guardrail-1": {"state": "OK", "missing": "missing", "evaluation": null, "kind": null, "transitioned": "1970-01-01T00:00:00.000Z"}}"#,
        ),
    ),
    (
        "metrics that are no list",
        r#"{"MetricAlarms": [{"AlarmName": "gd2-guardrail-1", "StateValue": "OK", "TreatMissingData": "missing", "StateTransitionedTimestamp": "1970-01-01T00:00:00.000Z", "Metrics": null}]}"#,
        Err("Metrics is no list: None"),
    ),
    (
        "a metric query that is no object",
        r#"{"MetricAlarms": [{"AlarmName": "gd2-guardrail-1", "StateValue": "OK", "TreatMissingData": "missing", "StateTransitionedTimestamp": "1970-01-01T00:00:00.000Z", "Metrics": ["m"]}]}"#,
        Err("a metric query is no dict: 'm'"),
    ),
    (
        "an expression that is no text",
        r#"{"MetricAlarms": [{"AlarmName": "gd2-guardrail-1", "StateValue": "OK", "TreatMissingData": "missing", "StateTransitionedTimestamp": "1970-01-01T00:00:00.000Z", "Metrics": [{"Expression": null}]}]}"#,
        Err("Expression is no str: None"),
    ),
    (
        "a percentile that ignores",
        r#"{"MetricAlarms": [{"AlarmName": "gd2-guardrail-1", "StateValue": "OK", "TreatMissingData": "missing", "StateTransitionedTimestamp": "1970-01-01T00:00:00.000Z", "EvaluateLowSampleCountPercentile": "ignore"}]}"#,
        Ok(
            r#"{"gd2-guardrail-1": {"state": "OK", "missing": "missing", "evaluation": null, "kind": "a percentile alarm that ignores a low sample count", "transitioned": "1970-01-01T00:00:00.000Z"}}"#,
        ),
    ),
    (
        "a percentile that evaluates",
        r#"{"MetricAlarms": [{"AlarmName": "gd2-guardrail-1", "StateValue": "OK", "TreatMissingData": "missing", "StateTransitionedTimestamp": "1970-01-01T00:00:00.000Z", "EvaluateLowSampleCountPercentile": "evaluate"}]}"#,
        Ok(
            r#"{"gd2-guardrail-1": {"state": "OK", "missing": "missing", "evaluation": null, "kind": null, "transitioned": "1970-01-01T00:00:00.000Z"}}"#,
        ),
    ),
    (
        "a percentile that is no text",
        r#"{"MetricAlarms": [{"AlarmName": "gd2-guardrail-1", "StateValue": "OK", "TreatMissingData": "missing", "StateTransitionedTimestamp": "1970-01-01T00:00:00.000Z", "EvaluateLowSampleCountPercentile": null}]}"#,
        Err("EvaluateLowSampleCountPercentile is no str: None"),
    ),
    (
        "no transition time",
        r#"{"MetricAlarms": [{"AlarmName": "gd2-guardrail-1", "StateValue": "OK", "TreatMissingData": "missing"}]}"#,
        Err("StateTransitionedTimestamp is no str: None"),
    ),
    (
        "a state off its type before a bad expression",
        r#"{"MetricAlarms": [{"AlarmName": "gd2-guardrail-1", "StateValue": 1, "TreatMissingData": "missing", "StateTransitionedTimestamp": "1970-01-01T00:00:00.000Z", "Metrics": null}]}"#,
        Err("StateValue is no str: 1"),
    ),
    (
        "metric alarms stated as null",
        r#"{"MetricAlarms": null}"#,
        Err("MetricAlarms is no list: None"),
    ),
    (
        "an evaluation state stated as null before metrics stated as null",
        r#"{"MetricAlarms": [{"AlarmName": "gd2-guardrail-1", "StateValue": "OK", "TreatMissingData": "missing", "StateTransitionedTimestamp": "t", "EvaluationState": null, "Metrics": null}]}"#,
        Err("EvaluationState is no str: None"),
    ),
    (
        "metrics stated as null before no transition time",
        r#"{"MetricAlarms": [{"AlarmName": "gd2-guardrail-1", "StateValue": "OK", "TreatMissingData": "missing", "Metrics": null}]}"#,
        Err("Metrics is no list: None"),
    ),
    (
        "evaluation criteria before metrics stated as null",
        r#"{"MetricAlarms": [{"AlarmName": "gd2-guardrail-1", "StateValue": "OK", "TreatMissingData": "missing", "StateTransitionedTimestamp": "t", "EvaluationCriteria": 1, "Metrics": null}]}"#,
        Ok(
            r#"{"gd2-guardrail-1": {"state": "OK", "missing": "missing", "evaluation": null, "kind": "a PromQL alarm", "transitioned": "t"}}"#,
        ),
    ),
];

const LAUNCHES: &[(Option<&str>, Result<&str, &str>)] = &[
    (
        Some("x1970-01-01T00:00:10Z"),
        Err(
            "LaunchTime 'x1970-01-01T00:00:10Z' is no UTC time YYYY-MM-DDTHH:MM:SS[.fraction] ending in Z or +00:00",
        ),
    ),
    (
        Some("1970-01-01T00:00:10Zx"),
        Err(
            "LaunchTime '1970-01-01T00:00:10Zx' is no UTC time YYYY-MM-DDTHH:MM:SS[.fraction] ending in Z or +00:00",
        ),
    ),
    (
        None,
        Err("LaunchTime None is no UTC time YYYY-MM-DDTHH:MM:SS[.fraction] ending in Z or +00:00"),
    ),
    (
        Some(""),
        Err("LaunchTime '' is no UTC time YYYY-MM-DDTHH:MM:SS[.fraction] ending in Z or +00:00"),
    ),
    (Some("1970-01-01T00:00:10Z"), Ok("10.0")),
    (Some("1970-01-01T00:00:10+00:00"), Ok("10.0")),
    (Some("2026-11-27T10:15:30.123Z"), Ok("1795774530.123")),
    (
        Some("2026-11-27T10:15:30.123456789+00:00"),
        Ok("1795774530.1234567"),
    ),
    (
        Some("2026-11-27T10:15:30.1234567890Z"),
        Err(
            "LaunchTime '2026-11-27T10:15:30.1234567890Z' is no UTC time YYYY-MM-DDTHH:MM:SS[.fraction] ending in Z or +00:00",
        ),
    ),
    (
        Some("2026-11-27T10:15:30.Z"),
        Err(
            "LaunchTime '2026-11-27T10:15:30.Z' is no UTC time YYYY-MM-DDTHH:MM:SS[.fraction] ending in Z or +00:00",
        ),
    ),
    (
        Some("2026-11-27 10:15:30Z"),
        Err(
            "LaunchTime '2026-11-27 10:15:30Z' is no UTC time YYYY-MM-DDTHH:MM:SS[.fraction] ending in Z or +00:00",
        ),
    ),
    (
        Some("2026-11-27T10:15:60Z"),
        Err(
            "LaunchTime '2026-11-27T10:15:60Z' is no UTC time YYYY-MM-DDTHH:MM:SS[.fraction] ending in Z or +00:00",
        ),
    ),
    (
        Some("2026-02-29T00:00:00Z"),
        Err("LaunchTime '2026-02-29T00:00:00Z' is no calendar time"),
    ),
    (Some("2024-02-29T00:00:00Z"), Ok("1709164800.0")),
    (
        Some("0000-01-01T00:00:00Z"),
        Err("LaunchTime '0000-01-01T00:00:00Z' is no calendar time"),
    ),
    (Some("0001-01-01T00:00:00Z"), Ok("-62135596800.0")),
    (Some("9999-12-31T23:59:59.999999999Z"), Ok("253402300800.0")),
    (
        Some("2026-11-27T24:00:00Z"),
        Err("LaunchTime '2026-11-27T24:00:00Z' is no calendar time"),
    ),
    (
        Some("2026-11-27T23:60:00Z"),
        Err("LaunchTime '2026-11-27T23:60:00Z' is no calendar time"),
    ),
    (
        Some("2026-13-01T00:00:00Z"),
        Err("LaunchTime '2026-13-01T00:00:00Z' is no calendar time"),
    ),
    (
        Some("2026-00-01T00:00:00Z"),
        Err("LaunchTime '2026-00-01T00:00:00Z' is no calendar time"),
    ),
    (
        Some("2026-01-00T00:00:00Z"),
        Err("LaunchTime '2026-01-00T00:00:00Z' is no calendar time"),
    ),
    (
        Some("1900-02-29T00:00:00Z"),
        Err("LaunchTime '1900-02-29T00:00:00Z' is no calendar time"),
    ),
    (Some("2000-02-29T00:00:00Z"), Ok("951782400.0")),
    (
        Some("2026-11-27T10:15:30-01:00"),
        Err(
            "LaunchTime '2026-11-27T10:15:30-01:00' is no UTC time YYYY-MM-DDTHH:MM:SS[.fraction] ending in Z or +00:00",
        ),
    ),
];

const ISOS: &[(&str, Result<&str, &str>)] = &[
    (
        r#""1970-01-01T01:00:00Z x""#,
        Err("approval not_after '1970-01-01T01:00:00Z x' is no time YYYY-MM-DDTHH:MM:SSZ"),
    ),
    (
        r#""x1970-01-01T01:00:00Z""#,
        Err("approval not_after 'x1970-01-01T01:00:00Z' is no time YYYY-MM-DDTHH:MM:SSZ"),
    ),
    (r#""1970-01-01T01:00:00Z""#, Ok("3600")),
    (r#""1970-01-01T00:00:00Z""#, Ok("0")),
    (r#""1969-12-31T23:59:59Z""#, Ok("-1")),
    (r#""0001-01-01T00:00:00Z""#, Ok("-62135596800")),
    (r#""9999-12-31T23:59:59Z""#, Ok("253402300799")),
    (
        r#""0000-06-01T00:00:00Z""#,
        Err("approval not_after '0000-06-01T00:00:00Z' is no calendar time"),
    ),
    (
        r#""2100-02-29T00:00:00Z""#,
        Err("approval not_after '2100-02-29T00:00:00Z' is no calendar time"),
    ),
    (r#""2400-02-29T12:00:00Z""#, Ok("13574606400")),
    (
        r#""2026-04-31T00:00:00Z""#,
        Err("approval not_after '2026-04-31T00:00:00Z' is no calendar time"),
    ),
    (
        r#""2026-11-27T10:15:30.5Z""#,
        Err("approval not_after '2026-11-27T10:15:30.5Z' is no time YYYY-MM-DDTHH:MM:SSZ"),
    ),
    (
        r#""2026-11-27t10:15:30Z""#,
        Err("approval not_after '2026-11-27t10:15:30Z' is no time YYYY-MM-DDTHH:MM:SSZ"),
    ),
    (
        r#"3600"#,
        Err("approval not_after 3600 is no time YYYY-MM-DDTHH:MM:SSZ"),
    ),
    (
        r#"null"#,
        Err("approval not_after None is no time YYYY-MM-DDTHH:MM:SSZ"),
    ),
    (
        r#""\uff11970-01-01T00:00:00Z""#,
        Err("approval not_after '１970-01-01T00:00:00Z' is no time YYYY-MM-DDTHH:MM:SSZ"),
    ),
];
