//! The four read calls' replies, each read by the fields the controller uses and matched to its
//! request. A reply off its request or off its types is a failed call, whose outcome is unknown: a
//! listing that holds a `NextToken`, an instance or alarm named twice or outside the request, a
//! composite alarm, and a read field of another JSON type, named with Python's type word (`list`,
//! `dict`, `str`) and `repr` and cut at 400 characters.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use super::calendar::posix_seconds;
use super::constants::LAUNCH;
use super::launch::CallFailed;
use super::number::Number;
use super::words::{sentence, sorted_texts};
use crate::json::{Object, Value};
use crate::python::repr;
use crate::text::Text;

/// The characters of a field's failed call that the sentence keeps.
const CUT: usize = 400;

/// A failed call: the launch's own failure, or a reply that is no JSON object of the shape the
/// request asks for, with its sentence. [`FailedCall::sentence`] is the sentence as a text, which
/// keeps a lone surrogate of a reply's name for a mark's detail; `Display` writes it as a line does,
/// each surrogate as `\udXXX`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FailedCall {
    Launch(CallFailed),
    Reply(Text),
}

impl FailedCall {
    /// The sentence that names the failure.
    pub fn sentence(&self) -> Text {
        match self {
            Self::Launch(failed) => Text::from(failed.to_string()),
            Self::Reply(sentence) => sentence.clone(),
        }
    }
}

impl fmt::Display for FailedCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Launch(failed) => failed.fmt(f),
            Self::Reply(sentence) => sentence.fmt(f),
        }
    }
}

impl std::error::Error for FailedCall {}

/// `<what> is no <kind>: <repr>`, cut at [`CUT`] characters; an absent value reads `None`.
fn off_type(value: Option<&Value>, kind: &str, what: &str) -> FailedCall {
    let shown = value.map_or_else(|| "None".to_owned(), repr);
    let sentence: String = format!("{what} is no {kind}: {shown}")
        .chars()
        .take(CUT)
        .collect();
    FailedCall::Reply(Text::from(sentence))
}

fn list<'a>(value: Option<&'a Value>, what: &str) -> Result<&'a [Value], FailedCall> {
    match value {
        Some(Value::Array(items)) => Ok(items),
        _ => Err(off_type(value, "list", what)),
    }
}

fn dict<'a>(value: Option<&'a Value>, what: &str) -> Result<&'a Object, FailedCall> {
    match value {
        Some(Value::Object(object)) => Ok(object),
        _ => Err(off_type(value, "dict", what)),
    }
}

fn text<'a>(value: Option<&'a Value>, what: &str) -> Result<&'a Text, FailedCall> {
    match value {
        Some(Value::String(text)) => Ok(text),
        _ => Err(off_type(value, "str", what)),
    }
}

/// The list `row[key]`, an empty list when `row` holds no `key`.
fn listed<'a>(row: &'a Object, key: &str) -> Result<&'a [Value], FailedCall> {
    match row.get(key) {
        None => Ok(&[]),
        value => list(value, key),
    }
}

/// The text `row[key]`, or `None` when `row` holds no `key`; a key present with another value fails.
fn optional_text<'a>(row: &'a Object, key: &str) -> Result<Option<&'a Text>, FailedCall> {
    match row.get(key) {
        None => Ok(None),
        value => text(value, key).map(Some),
    }
}

/// The text `row[outer][inner]`.
fn nested(row: &Object, outer: &str, inner: &str) -> Result<Text, FailedCall> {
    let object = dict(row.get(outer), outer)?;
    text(object.get(inner), &format!("{outer}.{inner}")).cloned()
}

/// The text `row[outer][inner]`, or `None` when `row[outer]` is absent or null.
fn nested_optional(row: &Object, outer: &str, inner: &str) -> Result<Option<Text>, FailedCall> {
    match row.get(outer) {
        None | Some(Value::Null) => Ok(None),
        _ => nested(row, outer, inner).map(Some),
    }
}

/// The text `row[key]`, or `None` when `row[key]` is absent or null.
fn text_or_null<'a>(row: &'a Object, key: &str) -> Result<Option<&'a Text>, FailedCall> {
    match row.get(key) {
        None | Some(Value::Null) => Ok(None),
        value => text(value, key).map(Some),
    }
}

/// The text `row[key]`, or `default` when `row` holds no `key`.
fn text_or<'a>(row: &'a Object, key: &str, default: &'a Text) -> Result<&'a Text, FailedCall> {
    match row.get(key) {
        None => Ok(default),
        value => text(value, key),
    }
}

fn whole(reply: &Object, what: &str) -> Result<(), FailedCall> {
    if matches!(reply.get("NextToken"), None | Some(Value::Null)) {
        Ok(())
    } else {
        Err(FailedCall::Reply(sentence!(
            what,
            " holds a NextToken, so its listing is partial"
        )))
    }
}

/// An instance's status: its state, and its instance and system checks, each `None` when the reply
/// leaves it out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    state: Text,
    instance: Option<Text>,
    system: Option<Text>,
}

impl Status {
    pub fn state(&self) -> &Text {
        &self.state
    }

    /// The instance check's status.
    pub fn instance(&self) -> Option<&Text> {
        self.instance.as_ref()
    }

    /// The system check's status.
    pub fn system(&self) -> Option<&Text> {
        self.system.as_ref()
    }

    /// `{state, instance, system}`, a check left out as null, whose `repr` is Python's of the status.
    pub fn to_value(&self) -> Value {
        let mut value = Object::new();
        value.insert("state", Value::String(self.state.clone()));
        value.insert("instance", optional(self.instance.as_ref()));
        value.insert("system", optional(self.system.as_ref()));
        Value::Object(value)
    }
}

fn optional(text: Option<&Text>) -> Value {
    text.map_or(Value::Null, |text| Value::String(text.clone()))
}

/// `read_statuses` is `{instance: status}` of a `describe-instance-status` reply that names exactly
/// `instances`.
///
/// # Errors
///
/// A failed call, in the reply's order: a `NextToken`; `InstanceStatuses` no list; a row no object, or
/// an `InstanceId`, `InstanceState.Name`, `InstanceStatus.Status` or `SystemStatus.Status` off its type;
/// an instance named twice; then another set of instances than `instances`.
pub fn read_statuses(
    reply: &Object,
    instances: &[Text],
) -> Result<BTreeMap<Text, Status>, FailedCall> {
    whole(reply, "describe-instance-status")?;
    let mut found = BTreeMap::new();
    for row in list(reply.get("InstanceStatuses"), "InstanceStatuses")? {
        let row = dict(Some(row), "an instance status")?;
        let instance = text(row.get("InstanceId"), "InstanceId")?;
        if found.contains_key(instance) {
            return Err(FailedCall::Reply(sentence!(
                "describe-instance-status names ",
                instance,
                " twice"
            )));
        }
        let status = Status {
            state: nested(row, "InstanceState", "Name")?,
            instance: nested_optional(row, "InstanceStatus", "Status")?,
            system: nested_optional(row, "SystemStatus", "Status")?,
        };
        found.insert(instance.clone(), status);
    }
    let asked: BTreeSet<&Text> = instances.iter().collect();
    if !found.keys().eq(asked.iter().copied()) {
        return Err(FailedCall::Reply(sentence!(
            "describe-instance-status names ",
            sorted_texts(found.keys()),
            ", not ",
            sorted_texts(instances)
        )));
    }
    Ok(found)
}

/// The record of one instance: its state, its state reason code, its transition reason (empty when
/// left out) and its `LaunchTime` text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstanceRecord {
    state: Text,
    code: Option<Text>,
    transition: Text,
    launch: Option<Text>,
}

impl InstanceRecord {
    pub fn state(&self) -> &Text {
        &self.state
    }

    /// `StateReason.Code`, or `None` when the record holds no state reason.
    pub fn code(&self) -> Option<&Text> {
        self.code.as_ref()
    }

    /// `StateTransitionReason`.
    pub fn transition(&self) -> &Text {
        &self.transition
    }

    /// `LaunchTime`, or `None` when the record names none.
    pub fn launch(&self) -> Option<&Text> {
        self.launch.as_ref()
    }

    /// `{state, code, transition, launch}`, an absent value as null, whose `repr` is Python's of the
    /// record.
    pub fn to_value(&self) -> Value {
        let mut value = Object::new();
        value.insert("state", Value::String(self.state.clone()));
        value.insert("code", optional(self.code.as_ref()));
        value.insert("transition", Value::String(self.transition.clone()));
        value.insert("launch", optional(self.launch.as_ref()));
        Value::Object(value)
    }
}

/// `read_record` is the record of the one instance a `describe-instances` reply names, which must be
/// `instance`.
///
/// # Errors
///
/// A failed call: a `NextToken`; `Reservations` no list, or a reservation no object or its `Instances`
/// no list; other than one instance, or one other than `instance`; then `State.Name`,
/// `StateReason.Code`, `StateTransitionReason` or `LaunchTime` off its type.
pub fn read_record(reply: &Object, instance: &Text) -> Result<InstanceRecord, FailedCall> {
    whole(reply, "describe-instances")?;
    let mut rows = Vec::new();
    for reservation in list(reply.get("Reservations"), "Reservations")? {
        let reservation = dict(Some(reservation), "a reservation")?;
        rows.extend(list(reservation.get("Instances"), "Instances")?);
    }
    let row = match rows.as_slice() {
        [row] => Some(dict(Some(row), "an instance")?),
        _ => None,
    };
    let row = row
        .filter(|row| matches!(row.get("InstanceId"), Some(Value::String(id)) if id == instance));
    let Some(row) = row else {
        return Err(FailedCall::Reply(sentence!(
            "describe-instances names ",
            rows.len().to_string(),
            " instances, not ",
            instance,
            " alone"
        )));
    };
    Ok(InstanceRecord {
        state: nested(row, "State", "Name")?,
        code: nested_optional(row, "StateReason", "Code")?,
        transition: text_or(row, "StateTransitionReason", &Text::new())?.clone(),
        launch: optional_text(row, "LaunchTime")?.cloned(),
    })
}

/// `launch_time` is the POSIX seconds of a record's `LaunchTime` `text`, a UTC time
/// `YYYY-MM-DDTHH:MM:SS` with an optional fraction of up to nine digits and then `Z` or `+00:00`, as a
/// float: the whole second plus the fraction's nearest double.
///
/// # Errors
///
/// `LaunchTime <repr> is no UTC time YYYY-MM-DDTHH:MM:SS[.fraction] ending in Z or +00:00` for a text
/// off that form or none, `None` standing for none; `LaunchTime <repr> is no calendar time` for a
/// second the calendar lacks.
pub fn launch_time(text: Option<&Text>) -> Result<Number, FailedCall> {
    let shown = text.map_or_else(|| "None".to_owned(), Text::repr);
    let found = text
        .and_then(Text::to_str)
        .and_then(|text| LAUNCH.captures(text));
    let Some(found) = found else {
        return Err(FailedCall::Reply(sentence!(
            "LaunchTime ",
            shown,
            " is no UTC time YYYY-MM-DDTHH:MM:SS[.fraction] ending in Z or +00:00"
        )));
    };
    let second = found
        .get(1)
        .expect("the pattern captures the second")
        .as_str();
    let Some(seconds) = posix_seconds(second) else {
        return Err(FailedCall::Reply(sentence!(
            "LaunchTime ",
            shown,
            " is no calendar time"
        )));
    };
    let fraction = found.get(2).map_or(Ok(0.0), |fraction| {
        format!("0{}", fraction.as_str()).parse::<f64>()
    });
    let fraction = fraction.expect("a point and digits parse as a float");
    Ok(Number::from(seconds).plus(Number::from(fraction)))
}

/// A metric alarm's state and the fields that tell whether it can read `OK` without data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Alarm {
    state: Text,
    missing: Option<Text>,
    evaluation: Option<Text>,
    kind: Option<&'static str>,
    transitioned: Text,
}

impl Alarm {
    /// `StateValue`.
    pub fn state(&self) -> &Text {
        &self.state
    }

    /// `TreatMissingData`, `None` when absent or null.
    pub fn missing(&self) -> Option<&Text> {
        self.missing.as_ref()
    }

    /// `EvaluationState`, `None` when absent.
    pub fn evaluation(&self) -> Option<&Text> {
        self.evaluation.as_ref()
    }

    /// What makes the alarm one that can read `OK` while its source is silent, whatever it treats
    /// missing data as: `a PromQL alarm`, `an alarm on a metric query expression` or
    /// `a percentile alarm that ignores a low sample count`; `None` for none of them.
    pub fn kind(&self) -> Option<&'static str> {
        self.kind
    }

    /// `StateTransitionedTimestamp`.
    pub fn transitioned(&self) -> &Text {
        &self.transitioned
    }
}

/// The kind [`Alarm::kind`] names, read from the alarm's row: an `EvaluationCriteria` key, then a
/// metric query with an `Expression`, then `EvaluateLowSampleCountPercentile` `ignore`.
fn query_kind(row: &Object) -> Result<Option<&'static str>, FailedCall> {
    if row.get("EvaluationCriteria").is_some() {
        return Ok(Some("a PromQL alarm"));
    }
    for query in listed(row, "Metrics")? {
        if optional_text(dict(Some(query), "a metric query")?, "Expression")?.is_some() {
            return Ok(Some("an alarm on a metric query expression"));
        }
    }
    if optional_text(row, "EvaluateLowSampleCountPercentile")?.is_some_and(|text| *text == "ignore")
    {
        return Ok(Some("a percentile alarm that ignores a low sample count"));
    }
    Ok(None)
}

/// `read_alarms` is `{alarm name: alarm}` of a `describe-alarms` reply's metric alarms, none named
/// twice or outside `names`; an alarm the reply leaves out is absent from the result.
///
/// # Errors
///
/// A failed call: a `NextToken`; `CompositeAlarms` no list, or one that is not empty; `MetricAlarms`
/// no list; a row no object or its `AlarmName` no text; a name twice or unasked; then, for that row,
/// `StateValue`, `TreatMissingData`, `EvaluationState`, `Metrics` and its entries'
/// `Expression`, `EvaluateLowSampleCountPercentile` and `StateTransitionedTimestamp` off their types.
pub fn read_alarms(reply: &Object, names: &[Text]) -> Result<BTreeMap<Text, Alarm>, FailedCall> {
    whole(reply, "describe-alarms")?;
    if !listed(reply, "CompositeAlarms")?.is_empty() {
        return Err(FailedCall::Reply(sentence!(
            "describe-alarms names a composite alarm, which can read OK while its children have no data"
        )));
    }
    let mut alarms = BTreeMap::new();
    for row in listed(reply, "MetricAlarms")? {
        let row = dict(Some(row), "an alarm")?;
        let name = text(row.get("AlarmName"), "AlarmName")?;
        if alarms.contains_key(name) || !names.contains(name) {
            return Err(FailedCall::Reply(sentence!(
                "describe-alarms names ",
                name,
                " twice or unasked"
            )));
        }
        let state = text(row.get("StateValue"), "StateValue")?.clone();
        let missing = text_or_null(row, "TreatMissingData")?.cloned();
        let evaluation = optional_text(row, "EvaluationState")?.cloned();
        let kind = query_kind(row)?;
        let transitioned = text(
            row.get("StateTransitionedTimestamp"),
            "StateTransitionedTimestamp",
        )?
        .clone();
        alarms.insert(
            name.clone(),
            Alarm {
                state,
                missing,
                evaluation,
                kind,
                transitioned,
            },
        );
    }
    Ok(alarms)
}
